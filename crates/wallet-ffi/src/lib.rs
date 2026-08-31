//! C-ABI bridge exposing `wallet-core` to the Flutter frontend over a
//! single JSON-in/JSON-out `invoke` entry point.
//!
//! This crate never implements cryptography itself — every request here
//! is a thin translation to an existing `wallet-core`/`wallet-crypto`
//! call. That keeps the one place in this workspace that legitimately
//! needs `unsafe` (raw C-ABI pointers can't be avoided at an FFI
//! boundary) as small and auditable as possible.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::Value;
use zeroize::Zeroizing;

use wallet_core::evm::{self as core_evm, address_from_public_key, to_checksummed_hex, EvmCeremonyError};
use wallet_core::wallet::{self, create_wallet, load_public_key, WalletError};
use wallet_rpc::evm::JsonRpcClient;
use wallet_rpc::Endpoint;

/// Entry point called from Dart. Takes ownership of nothing — `request_ptr`
/// is borrowed for the duration of this call only. The returned pointer is
/// owned by the caller, who must pass it to `free_string` exactly once.
///
/// # Safety
/// `request_ptr` must be a valid pointer to a NUL-terminated C string (or
/// null), as produced by Dart's `toNativeUtf8()`. This is upheld by the
/// only caller, `rust_bridge_service.dart`.
///
/// # Panics
/// Never — a panic anywhere inside `process_request` (this crate's own
/// bugs, or a dependency's, like the `rustls` TLS-setup panic that once
/// slipped through here) is caught at this boundary and converted to a
/// normal `{"error": ...}` response instead of propagating. A panic
/// crossing an `extern "C"` boundary is undefined behavior — Rust
/// aborts the whole host process rather than let it unwind through, so
/// without this, one bad RPC response could take down the entire
/// Flutter app instead of failing just the one request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn invoke(request_ptr: *const c_char) -> *mut c_char {
    if request_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(request_ptr) };
    let Ok(req_str) = c_str.to_str() else {
        return CString::new("{\"error\": \"Invalid UTF-8\"}").expect("literal has no interior NUL").into_raw();
    };

    let result = std::panic::catch_unwind(|| process_request(req_str)).unwrap_or_else(|panic| json_error(&format!("internal error: {}", describe_panic(&panic))));
    let res_c_string = CString::new(result)
        .unwrap_or_else(|_| CString::new("{\"error\": \"Null byte in response\"}").expect("literal has no interior NUL"));

    res_c_string.into_raw()
}

/// Reclaims a string previously returned by `invoke`. Must be called
/// exactly once per `invoke` call, from the Dart side, never from
/// anywhere else — this is the only way a Rust-allocated `CString` gets
/// freed, and the only correct allocator to free it with.
///
/// # Safety
/// `ptr` must be a pointer previously returned by `invoke`, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// ---------------------------------------------------------------------------
// Fix 3: Input size limits — prevent OOM from malicious Dart payloads.
// ---------------------------------------------------------------------------

/// Maximum JSON request body size accepted from the frontend.
const MAX_REQUEST_LEN: usize = 64 * 1024; // 64 KiB — generous for any legitimate request

/// Maximum number of shares accepted in a single request.
const MAX_SHARES: usize = 255; // u8::MAX, matching Shamir's index range

/// Maximum size of a single base64-encoded share string.
const MAX_SHARE_B64_LEN: usize = 1024; // A sealed share is ~75 bytes; 1 KiB is 13× headroom

// ---------------------------------------------------------------------------
// Fix 4: Directory sandboxing — prevent path traversal from the frontend.
// ---------------------------------------------------------------------------

/// The app's sandboxed data directory, set once at startup by `set_base_dir`.
/// All wallet operations must use paths under this directory.
static BASE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Called once at app startup from Dart with the app's sandboxed data
/// directory (the result of `getApplicationDocumentsDirectory()`). All
/// subsequent wallet operations must use paths under this directory.
///
/// # Safety
/// `path_ptr` must be a valid pointer to a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn set_base_dir(path_ptr: *const c_char) {
    if path_ptr.is_null() {
        return;
    }
    let c_str = unsafe { CStr::from_ptr(path_ptr) };
    if let Ok(s) = c_str.to_str() {
        let _ = BASE_DIR.set(PathBuf::from(s));
    }
}

/// Validate that `dir` is a subdirectory of the configured `BASE_DIR`.
/// Returns the canonicalized path on success, or an error message
/// suitable for `json_error` on failure.
fn validate_dir(dir: &std::path::Path) -> Result<PathBuf, String> {
    let base = BASE_DIR.get().ok_or_else(|| "base directory not set — call set_base_dir first".to_string())?;
    // Create the directory first so canonicalize doesn't fail on a
    // not-yet-existing path (create_wallet needs this).
    let _ = std::fs::create_dir_all(dir);
    let canonical = dir.canonicalize().map_err(|e| format!("invalid path: {e}"))?;
    let base_canonical = base.canonicalize().map_err(|e| format!("invalid base path: {e}"))?;
    if !canonical.starts_with(&base_canonical) {
        return Err("path escapes the wallet sandbox".to_string());
    }
    Ok(canonical)
}

fn process_request(req_str: &str) -> String {
    // Fix 3: reject oversized payloads before parsing JSON.
    if req_str.len() > MAX_REQUEST_LEN {
        return json_error(&format!("request too large: {} bytes exceeds {MAX_REQUEST_LEN} byte limit", req_str.len()));
    }

    let req: Result<Value, _> = serde_json::from_str(req_str);
    match req {
        Ok(json) => {
            let method = json["method"].as_str().unwrap_or("");
            match method {
                "ping" => "{\"status\": \"ok\", \"message\": \"pong from rust\"}".to_string(),
                "get_version" => "{\"version\": \"0.1.0\"}".to_string(),
                "create_wallet" => handle_create_wallet(&json["params"]),
                "get_address" => handle_get_address(&json["params"]),
                "get_balance" => handle_get_balance(&json["params"]),
                "unlock_wallet" => handle_unlock_wallet(&json["params"]),
                "import_wallet" => handle_import_wallet(&json["params"]),
                "get_erc20_balance" => handle_get_erc20_balance(&json["params"]),
                "send_transaction" => handle_send_transaction(&json["params"]),
                "send_erc20_transaction" => handle_send_erc20_transaction(&json["params"]),
                _ => json_error(&format!("Unknown method: {method}")),
            }
        }
        Err(e) => json_error(&format!("Failed to parse JSON: {e}")),
    }
}

/// Best-effort extraction of a panic's message — `catch_unwind`'s payload
/// is `Box<dyn Any>`, which covers the two shapes `panic!`/`.unwrap()`/
/// `.expect()` actually produce (`&str` and `String`) but nothing is
/// guaranteed beyond that, so anything else falls back to a fixed string
/// rather than failing to report the panic at all.
fn describe_panic(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "panicked with a non-string payload".to_string()
    }
}

fn json_error(message: &str) -> String {
    // serde_json::to_string can't fail on a plain string-valued object.
    serde_json::to_string(&serde_json::json!({ "error": message })).unwrap()
}

/// Handles `{"method": "create_wallet", "params": {"dir", "passphrase",
/// "threshold", "n"}}`. Every failure path returns `{"error": ...}` and
/// never leaks the passphrase itself into an error message.
fn handle_create_wallet(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    // Fix 4: validate the directory is within the sandbox.
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    // Fix 2: copy passphrase into a zeroizable buffer immediately.
    let passphrase = match params["passphrase"].as_str() {
        Some(p) => Zeroizing::new(p.to_string()),
        None => return json_error("missing required field: passphrase"),
    };
    let Some(threshold) = params["threshold"].as_u64().and_then(|v| u8::try_from(v).ok()) else {
        return json_error("missing or out-of-range field: threshold");
    };
    let Some(n) = params["n"].as_u64().and_then(|v| u8::try_from(v).ok()) else {
        return json_error("missing or out-of-range field: n");
    };

    match create_wallet(&dir, &passphrase, threshold, n) {
        Ok((public_key, external_shares)) => {
            let address = to_checksummed_hex(&address_from_public_key(&public_key));
            let shares: Vec<String> = external_shares.iter().map(|s| BASE64.encode(s)).collect();
            serde_json::to_string(&serde_json::json!({
                "status": "ok",
                "address": address,
                "shares": shares,
            }))
            .unwrap_or_else(|_| json_error("failed to serialize response"))
        }
        Err(e) => json_error(&describe_wallet_error(&e)),
    }
}

/// Handles `{"method": "get_address", "params": {"dir"}}` — no network
/// I/O, just loads the stored (unencrypted) public key and derives the
/// checksummed address from it.
fn handle_get_address(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    // Fix 4: validate the directory is within the sandbox.
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };

    match load_public_key(&dir) {
        Ok(public_key) => {
            let address = to_checksummed_hex(&address_from_public_key(&public_key));
            serde_json::to_string(&serde_json::json!({ "status": "ok", "address": address })).unwrap_or_else(|_| json_error("failed to serialize response"))
        }
        Err(e) => json_error(&describe_wallet_error(&e)),
    }
}

/// Handles `{"method": "get_balance", "params": {"dir", "rpc_urls":
/// [...], "chain_id"}}`. Mirrors `wallet-cli`'s `cmd_balance`: every
/// configured endpoint must agree on both the chain ID and the balance
/// (`Untrusted::try_cross_check`) before either is trusted — a single
/// lying or misconfigured node must not be able to show a wrong balance
/// or let a caller act as if it queried a different chain. Balance is
/// returned as a decimal string, not a JSON number, so large wei values
/// don't lose precision going through JSON.
fn handle_get_balance(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    // Fix 4: validate the directory is within the sandbox.
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    let Some(rpc_urls) = params["rpc_urls"].as_array() else {
        return json_error("missing required field: rpc_urls");
    };
    let rpc_urls: Vec<String> = rpc_urls.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    if rpc_urls.is_empty() {
        return json_error("rpc_urls must contain at least one endpoint");
    }
    let Some(chain_id) = params["chain_id"].as_u64() else {
        return json_error("missing or out-of-range field: chain_id");
    };

    let public_key = match load_public_key(&dir) {
        Ok(pk) => pk,
        Err(e) => return json_error(&describe_wallet_error(&e)),
    };
    let address = address_from_public_key(&public_key);

    let endpoints: Vec<Endpoint> = rpc_urls.into_iter().map(Endpoint).collect();
    let (primary, rest) = endpoints.split_first().expect("checked non-empty above");

    let chain_client = JsonRpcClient::new(primary.clone());
    let reported_chain_id = match chain_client.chain_id() {
        Ok(c) => c,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_chain_id = match reported_chain_id.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).chain_id().map(wallet_rpc::Untrusted::trust)) {
        Ok(c) => c,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };
    if verified_chain_id != chain_id {
        return json_error(&format!("chain_id {chain_id} was requested, but the RPC endpoint(s) report chain ID {verified_chain_id}"));
    }

    let balance_client = JsonRpcClient::new(primary.clone());
    let balance = match balance_client.balance(&address) {
        Ok(b) => b,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_balance = match balance.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).balance(&address).map(wallet_rpc::Untrusted::trust)) {
        Ok(b) => b,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };

    let checksummed = to_checksummed_hex(&address);
    serde_json::to_string(&serde_json::json!({
        "status": "ok",
        "address": checksummed,
        "balance_wei": verified_balance.to_string(),
    }))
    .unwrap_or_else(|_| json_error("failed to serialize response"))
}

/// Handles `{"method": "unlock_wallet", "params": {"dir", "passphrase"}}`
/// — the "log back in" flow for a wallet already created on this device.
/// Succeeds only if `passphrase` actually decrypts the locally stored
/// share (AEAD-authenticated, so a wrong passphrase fails closed here
/// rather than silently unlocking), then returns the address the same way
/// `get_address` does.
fn handle_unlock_wallet(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    // Fix 4: validate the directory is within the sandbox.
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    // Fix 2: copy passphrase into a zeroizable buffer immediately.
    let passphrase = match params["passphrase"].as_str() {
        Some(p) => Zeroizing::new(p.to_string()),
        None => return json_error("missing required field: passphrase"),
    };

    if let Err(e) = wallet::load_shares(&dir, &passphrase, &[1]) {
        return json_error(&describe_wallet_error(&e));
    }

    match load_public_key(&dir) {
        Ok(public_key) => {
            let address = to_checksummed_hex(&address_from_public_key(&public_key));
            serde_json::to_string(&serde_json::json!({ "status": "ok", "address": address })).unwrap_or_else(|_| json_error("failed to serialize response"))
        }
        Err(e) => json_error(&describe_wallet_error(&e)),
    }
}

/// Handles `{"method": "import_wallet", "params": {"dir", "passphrase",
/// "shares": [base64...]}}` — restoring a wallet onto a device that
/// doesn't already have it, from `threshold`-many externally held shares.
/// See `wallet_core::wallet::import_wallet`'s docs for what this can and
/// cannot verify.
fn handle_import_wallet(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    // Fix 4: validate the directory is within the sandbox.
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    // Fix 2: copy passphrase into a zeroizable buffer immediately.
    let passphrase = match params["passphrase"].as_str() {
        Some(p) => Zeroizing::new(p.to_string()),
        None => return json_error("missing required field: passphrase"),
    };
    let Some(shares) = params["shares"].as_array() else {
        return json_error("missing required field: shares");
    };
    if shares.len() < 2 {
        return json_error("at least 2 shares are required to import a wallet");
    }
    // Fix 3: reject oversized share arrays.
    if shares.len() > MAX_SHARES {
        return json_error(&format!("too many shares: {} exceeds limit of {MAX_SHARES}", shares.len()));
    }
    let mut sealed_shares = Vec::with_capacity(shares.len());
    for share in shares {
        let Some(encoded) = share.as_str() else {
            return json_error("each share must be a base64-encoded string");
        };
        // Fix 3: reject oversized individual share strings.
        if encoded.len() > MAX_SHARE_B64_LEN {
            return json_error(&format!("share string too large: {} bytes exceeds limit of {MAX_SHARE_B64_LEN}", encoded.len()));
        }
        match BASE64.decode(encoded) {
            Ok(bytes) => sealed_shares.push(bytes),
            Err(_) => return json_error("a share was not valid base64"),
        }
    }

    match wallet::import_wallet(&dir, &passphrase, &sealed_shares) {
        Ok(public_key) => {
            let address = to_checksummed_hex(&address_from_public_key(&public_key));
            serde_json::to_string(&serde_json::json!({ "status": "ok", "address": address })).unwrap_or_else(|_| json_error("failed to serialize response"))
        }
        Err(e) => json_error(&describe_wallet_error(&e)),
    }
}

/// Handles `{"method": "send_transaction", "params": {"dir", "passphrase",
/// "chain_id", "rpc_urls": [...], "to", "value_wei", "shares":
/// [base64...] (external shares beyond the local one, optional),
/// "gas_limit" (optional, default 21000)}}`. Mirrors `wallet-cli`'s
/// `cmd_send`: cross-checks chain ID, nonce, and (implicitly) the
/// broadcast result across every configured endpoint before signing, and
/// signs with NO spending-policy gate — see `sign_evm_transfer`'s docs for
/// why a fresh policy engine per FFI call wouldn't provide a meaningful
/// protection anyway. Returns the broadcast transaction hash.
#[allow(clippy::too_many_lines)]
fn handle_send_transaction(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    // Fix 4: validate the directory is within the sandbox.
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    // Fix 2: copy passphrase into a zeroizable buffer immediately.
    let passphrase = match params["passphrase"].as_str() {
        Some(p) => Zeroizing::new(p.to_string()),
        None => return json_error("missing required field: passphrase"),
    };
    let Some(chain_id) = params["chain_id"].as_u64() else {
        return json_error("missing or out-of-range field: chain_id");
    };
    let Some(rpc_urls) = params["rpc_urls"].as_array() else {
        return json_error("missing required field: rpc_urls");
    };
    let rpc_urls: Vec<String> = rpc_urls.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    if rpc_urls.is_empty() {
        return json_error("rpc_urls must contain at least one endpoint");
    }
    let Some(to) = params["to"].as_str() else {
        return json_error("missing required field: to");
    };
    let Ok(to_address) = parse_address_hex(to) else {
        return json_error("`to` must be a 0x-prefixed 20-byte address");
    };
    let Some(value) = params["value_wei"].as_str().and_then(|s| s.parse::<u128>().ok()) else {
        return json_error("missing or invalid field: value_wei (must be a decimal string)");
    };
    let gas_limit = params["gas_limit"].as_u64().unwrap_or(21_000);

    let external_shares: Vec<Vec<u8>> = match params["shares"].as_array() {
        Some(shares) => {
            // Fix 3: reject oversized share arrays.
            if shares.len() > MAX_SHARES {
                return json_error(&format!("too many shares: {} exceeds limit of {MAX_SHARES}", shares.len()));
            }
            let mut decoded = Vec::with_capacity(shares.len());
            for share in shares {
                let Some(encoded) = share.as_str() else {
                    return json_error("each share must be a base64-encoded string");
                };
                // Fix 3: reject oversized individual share strings.
                if encoded.len() > MAX_SHARE_B64_LEN {
                    return json_error(&format!("share string too large: {} bytes exceeds limit of {MAX_SHARE_B64_LEN}", encoded.len()));
                }
                match BASE64.decode(encoded) {
                    Ok(bytes) => decoded.push(bytes),
                    Err(_) => return json_error("a share was not valid base64"),
                }
            }
            decoded
        }
        None => Vec::new(),
    };

    let public_key = match load_public_key(&dir) {
        Ok(pk) => pk,
        Err(e) => return json_error(&describe_wallet_error(&e)),
    };
    let our_address = address_from_public_key(&public_key);

    let endpoints: Vec<Endpoint> = rpc_urls.into_iter().map(Endpoint).collect();
    let (primary, rest) = endpoints.split_first().expect("checked non-empty above");

    let chain_client = JsonRpcClient::new(primary.clone());
    let reported_chain_id = match chain_client.chain_id() {
        Ok(c) => c,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_chain_id = match reported_chain_id.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).chain_id().map(wallet_rpc::Untrusted::trust)) {
        Ok(c) => c,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };
    if verified_chain_id != chain_id {
        return json_error(&format!("chain_id {chain_id} was requested, but the RPC endpoint(s) report chain ID {verified_chain_id}"));
    }

    let primary_client = JsonRpcClient::new(primary.clone());
    let nonce = match primary_client.transaction_count(&our_address) {
        Ok(n) => n,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_nonce = match nonce.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).transaction_count(&our_address).map(wallet_rpc::Untrusted::trust)) {
        Ok(n) => n,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };

    let fees = match primary_client.fee_suggestion() {
        Ok(f) => f.trust(),
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };

    let tx = match core_evm::build_unsigned_transfer(chain_id, to_address, value, verified_nonce, fees.max_fee_per_gas, fees.max_priority_fee_per_gas, gas_limit) {
        Ok(t) => t,
        Err(e) => return json_error(&format!("transaction build error: {e}")),
    };

    let mut shares = Vec::new();
    match wallet::load_shares(&dir, &passphrase, &[1]) {
        Ok(mut s) => shares.append(&mut s),
        Err(e) => {
            if external_shares.is_empty() {
                return json_error(&describe_wallet_error(&e));
            }
            // If we have external shares, a missing local share is okay (imported wallet).
            // If the error was actually a wrong passphrase, the loop below will catch it.
        }
    }
    for sealed in &external_shares {
        match wallet::load_external_share(&passphrase, sealed) {
            Ok(share) => shares.push(share),
            Err(e) => return json_error(&describe_wallet_error(&e)),
        }
    }

    let raw = match core_evm::sign_evm_transfer(tx, &shares, &public_key) {
        Ok(r) => r,
        Err(e) => return json_error(&describe_ceremony_error(&e)),
    };

    match primary_client.send_raw_transaction(&raw) {
        Ok(tx_hash) => {
            let tx_hash = tx_hash.trust();
            serde_json::to_string(&serde_json::json!({ "status": "ok", "tx_hash": format!("0x{}", hex_encode(&tx_hash)) })).unwrap_or_else(|_| json_error("failed to serialize response"))
        }
        Err(e) => json_error(&format!("RPC error: {e}")),
    }
}

/// Parse a `0x`-prefixed 20-byte address as typed/pasted into the UI.
/// Case-insensitive — this does not verify an EIP-55 checksum on input.
fn parse_address_hex(s: &str) -> Result<[u8; 20], ()> {
    let stripped = s.strip_prefix("0x").ok_or(())?;
    if stripped.len() != 40 {
        return Err(());
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn describe_ceremony_error(e: &EvmCeremonyError) -> String {
    match e {
        EvmCeremonyError::Ceremony(_) => "signing failed: invalid or insufficient shares".to_string(),
        EvmCeremonyError::UnrepresentableRecoveryId => "signing failed: unrepresentable recovery id (astronomically unlikely — try again)".to_string(),
    }
}

fn describe_cross_check_error(e: &wallet_rpc::CrossCheckError<wallet_rpc::evm::RpcError>) -> String {
    match e {
        wallet_rpc::CrossCheckError::Query(endpoint, rpc_err) => format!("RPC query to {} failed: {rpc_err}", endpoint.0),
        wallet_rpc::CrossCheckError::Disagreement(d) => {
            format!("RPC endpoints disagree: {} and {} returned different values for the same query — refusing to proceed", d.primary.0, d.disagreeing.0)
        }
    }
}

/// Human-readable, passphrase-free description of a `WalletError`, safe
/// to hand back to the UI layer.
fn describe_wallet_error(e: &WalletError) -> String {
    match e {
        WalletError::Ceremony(_) => "invalid threshold/share configuration".to_string(),
        WalletError::Storage(storage_err) => describe_storage_error(storage_err),
        WalletError::Io(io_err) => format!("filesystem error: {io_err}"),
        WalletError::InvalidPublicKey => "internal error: generated an invalid public key".to_string(),
    }
}

fn describe_storage_error(e: &wallet_core::wallet::StorageError) -> String {
    match e {
        wallet_core::wallet::StorageError::DecryptionFailed => "wrong passphrase — the passphrase you entered does not match the one used to create this wallet".to_string(),
        wallet_core::wallet::StorageError::WeakPassphrase => "passphrase too short — must be at least 12 characters".to_string(),
        wallet_core::wallet::StorageError::Truncated => "wallet file is corrupted or truncated".to_string(),
        wallet_core::wallet::StorageError::InvalidKeyBytes => "wallet file contains invalid key data".to_string(),
        wallet_core::wallet::StorageError::UnsupportedVersion(v) => format!("wallet file uses unsupported format version {v}"),
        wallet_core::wallet::StorageError::Io(io_err) => format!("filesystem error: {io_err}"),
    }
}

fn construct_balance_of_data(address: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(address);
    data
}

fn construct_transfer_data(to: &[u8; 20], value: u128) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(to);
    let mut value_bytes = [0u8; 32];
    value_bytes[16..].copy_from_slice(&value.to_be_bytes());
    data.extend_from_slice(&value_bytes);
    data
}

fn decode_uint256_result(result: &[u8]) -> Result<u128, String> {
    if result.len() < 32 {
        return Ok(0);
    }
    for b in &result[0..16] {
        if *b != 0 {
            return Err("balance exceeds u128 capacity".to_string());
        }
    }
    let mut value_bytes = [0u8; 16];
    value_bytes.copy_from_slice(&result[16..32]);
    Ok(u128::from_be_bytes(value_bytes))
}

fn handle_get_erc20_balance(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    let Some(rpc_urls) = params["rpc_urls"].as_array() else {
        return json_error("missing required field: rpc_urls");
    };
    let rpc_urls: Vec<String> = rpc_urls.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    if rpc_urls.is_empty() {
        return json_error("rpc_urls must contain at least one endpoint");
    }
    let Some(chain_id) = params["chain_id"].as_u64() else {
        return json_error("missing or out-of-range field: chain_id");
    };
    let Some(token) = params["token_address"].as_str() else {
        return json_error("missing required field: token_address");
    };
    let Ok(token_address) = parse_address_hex(token) else {
        return json_error("`token_address` must be a 0x-prefixed 20-byte address");
    };

    let public_key = match load_public_key(&dir) {
        Ok(pk) => pk,
        Err(e) => return json_error(&describe_wallet_error(&e)),
    };
    let address = address_from_public_key(&public_key);

    let endpoints: Vec<Endpoint> = rpc_urls.into_iter().map(Endpoint).collect();
    let (primary, rest) = endpoints.split_first().expect("checked non-empty above");

    let chain_client = JsonRpcClient::new(primary.clone());
    let reported_chain_id = match chain_client.chain_id() {
        Ok(c) => c,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_chain_id = match reported_chain_id.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).chain_id().map(wallet_rpc::Untrusted::trust)) {
        Ok(c) => c,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };
    if verified_chain_id != chain_id {
        return json_error(&format!("chain_id {chain_id} was requested, but the RPC endpoint(s) report chain ID {verified_chain_id}"));
    }

    let data = construct_balance_of_data(&address);
    let balance_client = JsonRpcClient::new(primary.clone());
    let result = match balance_client.call_contract(&token_address, &data) {
        Ok(b) => b,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_result = match result.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).call_contract(&token_address, &data).map(wallet_rpc::Untrusted::trust)) {
        Ok(b) => b,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };

    let verified_balance = match decode_uint256_result(&verified_result) {
        Ok(b) => b,
        Err(e) => return json_error(&e),
    };

    let checksummed = to_checksummed_hex(&address);
    serde_json::to_string(&serde_json::json!({
        "status": "ok",
        "address": checksummed,
        "balance_wei": verified_balance.to_string(),
    }))
    .unwrap_or_else(|_| json_error("failed to serialize response"))
}

#[allow(clippy::too_many_lines)]
fn handle_send_erc20_transaction(params: &Value) -> String {
    let dir = match params["dir"].as_str() {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return json_error("missing or empty required field: dir"),
    };
    let dir = match validate_dir(&dir) {
        Ok(d) => d,
        Err(e) => return json_error(&e),
    };
    let passphrase = match params["passphrase"].as_str() {
        Some(p) => Zeroizing::new(p.to_string()),
        None => return json_error("missing required field: passphrase"),
    };
    let Some(chain_id) = params["chain_id"].as_u64() else {
        return json_error("missing or out-of-range field: chain_id");
    };
    let Some(rpc_urls) = params["rpc_urls"].as_array() else {
        return json_error("missing required field: rpc_urls");
    };
    let rpc_urls: Vec<String> = rpc_urls.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    if rpc_urls.is_empty() {
        return json_error("rpc_urls must contain at least one endpoint");
    }
    let Some(token) = params["token_address"].as_str() else {
        return json_error("missing required field: token_address");
    };
    let Ok(token_address) = parse_address_hex(token) else {
        return json_error("`token_address` must be a 0x-prefixed 20-byte address");
    };
    let Some(to) = params["to"].as_str() else {
        return json_error("missing required field: to");
    };
    let Ok(to_address) = parse_address_hex(to) else {
        return json_error("`to` must be a 0x-prefixed 20-byte address");
    };
    let Some(value) = params["value_wei"].as_str().and_then(|s| s.parse::<u128>().ok()) else {
        return json_error("missing or invalid field: value_wei (must be a decimal string)");
    };
    // ERC20 transfers usually take ~65000 gas, 100k is safe.
    let gas_limit = params["gas_limit"].as_u64().unwrap_or(100_000);

    let external_shares: Vec<Vec<u8>> = match params["shares"].as_array() {
        Some(shares) => {
            if shares.len() > MAX_SHARES {
                return json_error(&format!("too many shares: {} exceeds limit of {MAX_SHARES}", shares.len()));
            }
            let mut decoded = Vec::with_capacity(shares.len());
            for share in shares {
                let Some(encoded) = share.as_str() else { return json_error("each share must be a base64-encoded string"); };
                if encoded.len() > MAX_SHARE_B64_LEN { return json_error(&format!("share string too large: {} bytes exceeds limit of {MAX_SHARE_B64_LEN}", encoded.len())); }
                match BASE64.decode(encoded) {
                    Ok(bytes) => decoded.push(bytes),
                    Err(_) => return json_error("a share was not valid base64"),
                }
            }
            decoded
        }
        None => Vec::new(),
    };

    let public_key = match load_public_key(&dir) {
        Ok(pk) => pk,
        Err(e) => return json_error(&describe_wallet_error(&e)),
    };
    let our_address = address_from_public_key(&public_key);

    let endpoints: Vec<Endpoint> = rpc_urls.into_iter().map(Endpoint).collect();
    let (primary, rest) = endpoints.split_first().expect("checked non-empty above");

    let chain_client = JsonRpcClient::new(primary.clone());
    let reported_chain_id = match chain_client.chain_id() {
        Ok(c) => c,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_chain_id = match reported_chain_id.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).chain_id().map(wallet_rpc::Untrusted::trust)) {
        Ok(c) => c,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };
    if verified_chain_id != chain_id {
        return json_error(&format!("chain_id {chain_id} was requested, but the RPC endpoint(s) report chain ID {verified_chain_id}"));
    }

    let primary_client = JsonRpcClient::new(primary.clone());
    let nonce = match primary_client.transaction_count(&our_address) {
        Ok(n) => n,
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };
    let verified_nonce = match nonce.try_cross_check(rest, |e| JsonRpcClient::new(e.clone()).transaction_count(&our_address).map(wallet_rpc::Untrusted::trust)) {
        Ok(n) => n,
        Err(e) => return json_error(&describe_cross_check_error(&e)),
    };

    let fees = match primary_client.fee_suggestion() {
        Ok(f) => f.trust(),
        Err(e) => return json_error(&format!("RPC error: {e}")),
    };

    let data = construct_transfer_data(&to_address, value);
    let tx = match core_evm::build_unsigned_contract_call(chain_id, token_address, 0, data, verified_nonce, fees.max_fee_per_gas, fees.max_priority_fee_per_gas, gas_limit) {
        Ok(t) => t,
        Err(e) => return json_error(&format!("transaction build error: {e}")),
    };

    let mut shares = Vec::new();
    match wallet::load_shares(&dir, &passphrase, &[1]) {
        Ok(mut s) => shares.append(&mut s),
        Err(e) => {
            if external_shares.is_empty() {
                return json_error(&describe_wallet_error(&e));
            }
        }
    }
    for sealed in &external_shares {
        match wallet::load_external_share(&passphrase, sealed) {
            Ok(share) => shares.push(share),
            Err(e) => return json_error(&describe_wallet_error(&e)),
        }
    }

    let raw = match core_evm::sign_evm_transfer(tx, &shares, &public_key) {
        Ok(r) => r,
        Err(e) => return json_error(&describe_ceremony_error(&e)),
    };

    match primary_client.send_raw_transaction(&raw) {
        Ok(tx_hash) => {
            let tx_hash = tx_hash.trust();
            serde_json::to_string(&serde_json::json!({ "status": "ok", "tx_hash": format!("0x{}", hex_encode(&tx_hash)) })).unwrap_or_else(|_| json_error("failed to serialize response"))
        }
        Err(e) => json_error(&format!("RPC error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set `BASE_DIR` to the system temp directory so all `tempfile::tempdir()`
    /// paths pass the sandbox validation. `OnceLock::set` is idempotent after
    /// the first call, so this is safe to call from every test.
    fn init_base_dir_for_tests() {
        let _ = BASE_DIR.set(std::env::temp_dir());
    }

    #[test]
    fn a_panicking_request_handler_is_caught_not_propagated() {
        // Exercises the exact catch_unwind + describe_panic pattern
        // `invoke()` uses, standing in for `process_request` panicking —
        // this is what a "WebPki is disabled" style bug deep in a
        // dependency looks like from here: some panic reaches this
        // boundary and must turn into a normal error response, not an
        // aborted process.
        let result = std::panic::catch_unwind(|| -> String { panic!("simulated internal bug") });
        let response = result.unwrap_or_else(|panic| json_error(&format!("internal error: {}", describe_panic(&panic))));
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert!(parsed["error"].as_str().unwrap().contains("simulated internal bug"));
    }

    #[test]
    fn describe_panic_extracts_str_and_string_payloads() {
        let str_panic: Box<dyn std::any::Any + Send> = Box::new("a static str panic");
        assert_eq!(describe_panic(&str_panic), "a static str panic");

        let string_panic: Box<dyn std::any::Any + Send> = Box::new(String::from("an owned String panic"));
        assert_eq!(describe_panic(&string_panic), "an owned String panic");

        let other_panic: Box<dyn std::any::Any + Send> = Box::new(42i32);
        assert_eq!(describe_panic(&other_panic), "panicked with a non-string payload");
    }

    #[test]
    fn ping_returns_expected_shape() {
        let res = process_request(r#"{"method": "ping"}"#);
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert_eq!(parsed["message"], "pong from rust");
    }

    #[test]
    fn unknown_method_is_an_error_not_a_panic() {
        let res = process_request(r#"{"method": "does_not_exist"}"#);
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let res = process_request("not json at all");
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn create_wallet_produces_a_checksummed_address_and_external_shares() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let req = serde_json::json!({
            "method": "create_wallet",
            "params": {
                "dir": dir.path().to_str().unwrap(),
                "passphrase": "correct horse battery staple",
                "threshold": 2,
                "n": 3,
            }
        });
        let res = process_request(&req.to_string());
        let parsed: Value = serde_json::from_str(&res).unwrap();

        let address = parsed["address"].as_str().expect("address present");
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);

        let shares = parsed["shares"].as_array().expect("shares present");
        // n=3 total, 1 stays local, 2 are external.
        assert_eq!(shares.len(), 2);
        for share in shares {
            assert!(BASE64.decode(share.as_str().unwrap()).is_ok());
        }
    }

    #[test]
    fn create_wallet_rejects_missing_fields() {
        let req = serde_json::json!({"method": "create_wallet", "params": {}});
        let res = process_request(&req.to_string());
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn get_address_matches_the_address_from_create_wallet() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let create_request = serde_json::json!({
            "method": "create_wallet",
            "params": { "dir": dir.path().to_str().unwrap(), "passphrase": "correct horse battery staple", "threshold": 2, "n": 3 }
        });
        let created: Value = serde_json::from_str(&process_request(&create_request.to_string())).unwrap();
        let created_address = created["address"].as_str().unwrap();

        let get_request = serde_json::json!({"method": "get_address", "params": {"dir": dir.path().to_str().unwrap()}});
        let fetched: Value = serde_json::from_str(&process_request(&get_request.to_string())).unwrap();
        assert_eq!(fetched["address"].as_str().unwrap(), created_address);
    }

    #[test]
    fn get_address_on_missing_wallet_is_an_error_not_a_panic() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let req = serde_json::json!({"method": "get_address", "params": {"dir": dir.path().to_str().unwrap()}});
        let res = process_request(&req.to_string());
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn get_balance_rejects_empty_rpc_urls() {
        init_base_dir_for_tests();
        let req = serde_json::json!({"method": "get_balance", "params": {"dir": "/tmp/whatever", "rpc_urls": [], "chain_id": 1}});
        let res = process_request(&req.to_string());
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn get_balance_rejects_missing_fields() {
        let req = serde_json::json!({"method": "get_balance", "params": {}});
        let res = process_request(&req.to_string());
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn unlock_wallet_with_correct_passphrase_returns_the_address() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let pass = "correct horse battery staple";
        let create_req = serde_json::json!({"method": "create_wallet", "params": {"dir": dir.path().to_str().unwrap(), "passphrase": pass, "threshold": 2, "n": 3}});
        let created: Value = serde_json::from_str(&process_request(&create_req.to_string())).unwrap();

        let unlock_req = serde_json::json!({"method": "unlock_wallet", "params": {"dir": dir.path().to_str().unwrap(), "passphrase": pass}});
        let unlocked: Value = serde_json::from_str(&process_request(&unlock_req.to_string())).unwrap();
        assert_eq!(unlocked["address"].as_str().unwrap(), created["address"].as_str().unwrap());
    }

    #[test]
    fn unlock_wallet_with_wrong_passphrase_is_an_error_not_a_panic() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let create_req = serde_json::json!({"method": "create_wallet", "params": {"dir": dir.path().to_str().unwrap(), "passphrase": "correct horse battery staple", "threshold": 2, "n": 3}});
        process_request(&create_req.to_string());

        let unlock_req = serde_json::json!({"method": "unlock_wallet", "params": {"dir": dir.path().to_str().unwrap(), "passphrase": "wrong but long enough"}});
        let res: Value = serde_json::from_str(&process_request(&unlock_req.to_string())).unwrap();
        assert!(res["error"].is_string());
    }

    #[test]
    fn import_wallet_reconstructs_the_same_address_on_a_new_device() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let pass = "correct horse battery staple";
        let create_req = serde_json::json!({"method": "create_wallet", "params": {"dir": dir.path().to_str().unwrap(), "passphrase": pass, "threshold": 2, "n": 3}});
        let created: Value = serde_json::from_str(&process_request(&create_req.to_string())).unwrap();
        let shares = created["shares"].as_array().unwrap().clone();

        let new_device_dir = tempfile::tempdir().unwrap();
        let import_req = serde_json::json!({"method": "import_wallet", "params": {"dir": new_device_dir.path().to_str().unwrap(), "passphrase": pass, "shares": shares}});
        let imported: Value = serde_json::from_str(&process_request(&import_req.to_string())).unwrap();
        assert_eq!(imported["address"].as_str().unwrap(), created["address"].as_str().unwrap());
    }

    #[test]
    fn import_wallet_rejects_fewer_than_two_shares() {
        init_base_dir_for_tests();
        let req = serde_json::json!({"method": "import_wallet", "params": {"dir": "/tmp/whatever", "passphrase": "x", "shares": ["aGVsbG8="]}});
        let res: Value = serde_json::from_str(&process_request(&req.to_string())).unwrap();
        assert!(res["error"].is_string());
    }

    #[test]
    fn send_transaction_rejects_a_malformed_address() {
        init_base_dir_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let pass = "correct horse battery staple";
        let create_req = serde_json::json!({"method": "create_wallet", "params": {"dir": dir.path().to_str().unwrap(), "passphrase": pass, "threshold": 2, "n": 3}});
        process_request(&create_req.to_string());

        let req = serde_json::json!({
            "method": "send_transaction",
            "params": {
                "dir": dir.path().to_str().unwrap(),
                "passphrase": pass,
                "chain_id": 1,
                "rpc_urls": ["http://localhost:1"],
                "to": "not-an-address",
                "value_wei": "1000",
            }
        });
        let res: Value = serde_json::from_str(&process_request(&req.to_string())).unwrap();
        assert!(res["error"].is_string());
    }

    #[test]
    fn send_transaction_rejects_missing_fields() {
        let req = serde_json::json!({"method": "send_transaction", "params": {}});
        let res: Value = serde_json::from_str(&process_request(&req.to_string())).unwrap();
        assert!(res["error"].is_string());
    }

    // -----------------------------------------------------------------------
    // New security tests for fixes 3 and 4.
    // -----------------------------------------------------------------------

    #[test]
    fn oversized_request_is_rejected_before_json_parsing() {
        let huge = "x".repeat(MAX_REQUEST_LEN + 1);
        let res = process_request(&huge);
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].as_str().unwrap().contains("request too large"));
    }

    #[test]
    fn path_outside_sandbox_is_rejected() {
        init_base_dir_for_tests();
        let evil_path = std::env::current_dir().unwrap();
        let req = serde_json::json!({
            "method": "create_wallet",
            "params": {
                "dir": evil_path.to_str().unwrap(),
                "passphrase": "correct horse battery staple",
                "threshold": 2,
                "n": 3,
            }
        });
        let res = process_request(&req.to_string());
        let parsed: Value = serde_json::from_str(&res).unwrap();
        assert!(parsed["error"].as_str().unwrap().contains("escapes the wallet sandbox"));
    }
}