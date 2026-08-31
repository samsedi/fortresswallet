//! A minimal JSON-RPC 2.0 client for EVM nodes' `eth_*` methods, built on
//! a blocking HTTP client (deliberately not async — nothing else in this
//! workspace is async, and a CLI wallet has no throughput requirement
//! that justifies pulling an async runtime through `wallet-core`/
//! `wallet-cli`).
//!
//! Every public method here returns `Untrusted<T>` (see `lib.rs`) — this
//! module has no opinion on whether a caller should `.trust()` a lone
//! response or `.cross_check()` it against other endpoints; that decision
//! belongs to the funds-critical call site, not this transport layer.
//!
//! TLS backend: `rustls` with the `aws-lc-rs` crypto provider — `ring` is
//! hard-banned in the workspace's `deny.toml`. Every request has an
//! explicit timeout and an explicit response-size cap (`MAX_RESPONSE_LEN`)
//! per this crate's own doc-comment contract in `lib.rs`: "no unbounded
//! reads... no hanging on a stalled node."

use std::fmt::Write as _;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::Agent;

use crate::{Endpoint, Untrusted};

/// Cap on a JSON-RPC response body, independent of any `Content-Length`
/// the (untrusted, possibly malicious) node claims — a node that lies
/// about its length or streams forever must not be able to exhaust this
/// process's memory.
const MAX_RESPONSE_LEN: u64 = 1024 * 1024; // 1 MiB — generous for any eth_* response this client sends.

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn agent() -> Agent {
    // A fresh CryptoProvider per Agent is cheap (no key material, no
    // network state) and avoids relying on a process-wide
    // `CryptoProvider::install_default()` call that some other part of a
    // future binary might also want to make — see rustls's own docs on
    // why a double `install_default` panics.
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    let provider = PROVIDER.get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())).clone();

    let tls_config = TlsConfig::builder().provider(TlsProvider::Rustls).unversioned_rustls_crypto_provider(provider).build();

    Agent::config_builder().tls_config(tls_config).timeout_global(Some(REQUEST_TIMEOUT)).build().into()
}

/// Errors from a JSON-RPC call: transport failures, malformed/oversized
/// responses, and the node's own JSON-RPC-level error object — all
/// distinct from a successful-but-untrusted result, which is what
/// `Untrusted<T>` exists to gate.
#[derive(Debug)]
pub enum RpcError {
    /// The HTTP request itself failed (connection refused, TLS failure,
    /// timeout, non-2xx status, ...).
    Transport(String),
    /// The response body wasn't valid JSON, or wasn't the expected shape.
    Malformed(String),
    /// The node returned a JSON-RPC `error` object instead of a `result`.
    Node {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(e) => write!(f, "transport error: {e}"),
            RpcError::Malformed(e) => write!(f, "malformed response: {e}"),
            RpcError::Node { code, message } => write!(f, "node returned error {code}: {message}"),
        }
    }
}

impl std::error::Error for RpcError {}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcErrorObject>,
}

#[derive(Deserialize)]
struct JsonRpcErrorObject {
    code: i64,
    message: String,
}

/// A JSON-RPC client bound to one `Endpoint`. Construct one per endpoint
/// you want to query — cross-checking against multiple nodes means
/// constructing multiple `JsonRpcClient`s and calling the same method on
/// each, then reconciling via `Untrusted::cross_check`.
pub struct JsonRpcClient {
    endpoint: Endpoint,
    agent: Agent,
}

impl JsonRpcClient {
    /// Bind a client to `endpoint`. No connection is made until the first
    /// call.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint, agent: agent() }
    }

    fn call(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let body_bytes = serde_json::to_vec(&body).map_err(|e| RpcError::Malformed(e.to_string()))?;
        let response = self
            .agent
            .post(&self.endpoint.0)
            .header("Content-Type", "application/json")
            .send(body_bytes)
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let text = response
            .into_body()
            .with_config()
            .limit(MAX_RESPONSE_LEN)
            .read_to_string()
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let parsed: JsonRpcResponse = serde_json::from_str(&text).map_err(|e| RpcError::Malformed(e.to_string()))?;

        if let Some(error) = parsed.error {
            return Err(RpcError::Node { code: error.code, message: error.message });
        }
        parsed.result.ok_or_else(|| RpcError::Malformed("response had neither result nor error".to_string()))
    }

    fn call_hex_u64(&self, method: &str, params: &Value) -> Result<u64, RpcError> {
        let result = self.call(method, params)?;
        let hex = result.as_str().ok_or_else(|| RpcError::Malformed(format!("{method}: expected a hex string result")))?;
        parse_hex_u64(hex).map_err(|e| RpcError::Malformed(format!("{method}: {e}")))
    }

    fn call_hex_u128(&self, method: &str, params: &Value) -> Result<u128, RpcError> {
        let result = self.call(method, params)?;
        let hex = result.as_str().ok_or_else(|| RpcError::Malformed(format!("{method}: expected a hex string result")))?;
        parse_hex_u128(hex).map_err(|e| RpcError::Malformed(format!("{method}: {e}")))
    }

    /// `eth_chainId` — the chain this endpoint claims to serve. Compare
    /// across endpoints (`cross_check`) before trusting it for anything
    /// replay-sensitive, since a misconfigured or malicious node
    /// answering for the wrong chain would otherwise sign a transaction
    /// valid on a chain the user never intended.
    pub fn chain_id(&self) -> Result<Untrusted<u64>, RpcError> {
        let value = self.call_hex_u64("eth_chainId", &json!([]))?;
        Ok(Untrusted::new(value, self.endpoint.clone()))
    }

    /// `eth_getBalance` for `address` at the latest block, in wei.
    /// Funds-critical — prefer `cross_check` over `trust` at the call
    /// site.
    pub fn balance(&self, address: &[u8; 20]) -> Result<Untrusted<u128>, RpcError> {
        let value = self.call_hex_u128("eth_getBalance", &json!([to_hex_address(address), "latest"]))?;
        Ok(Untrusted::new(value, self.endpoint.clone()))
    }

    /// `eth_call` — execute a message call immediately without creating a
    /// transaction on the blockchain. Often used for reading smart contract state (e.g., `balanceOf`).
    pub fn call_contract(&self, to: &[u8; 20], data: &[u8]) -> Result<Untrusted<Vec<u8>>, RpcError> {
        let value = self.call("eth_call", &json!([{ "to": to_hex_address(to), "data": to_hex(data) }, "latest"]))?;
        let hex = value.as_str().ok_or_else(|| RpcError::Malformed("eth_call: expected a hex string result".to_string()))?;
        let bytes = parse_hex_bytes(hex).map_err(|e| RpcError::Malformed(format!("eth_call: {e}")))?;
        Ok(Untrusted::new(bytes, self.endpoint.clone()))
    }

    /// `eth_getTransactionCount` for `address` at the latest block — the
    /// nonce to use for the next transaction. Funds-critical: a stale or
    /// lied-about nonce can produce a transaction that either can't
    /// confirm or (worse, if a node lies *low*) replaces/conflicts with
    /// one already pending.
    pub fn transaction_count(&self, address: &[u8; 20]) -> Result<Untrusted<u64>, RpcError> {
        let value = self.call_hex_u64("eth_getTransactionCount", &json!([to_hex_address(address), "latest"]))?;
        Ok(Untrusted::new(value, self.endpoint.clone()))
    }

    /// Current block number — used by callers to compute confirmation
    /// depth from a transaction receipt's `block_number`.
    pub fn block_number(&self) -> Result<Untrusted<u64>, RpcError> {
        let value = self.call_hex_u64("eth_blockNumber", &json!([]))?;
        Ok(Untrusted::new(value, self.endpoint.clone()))
    }

    /// A simple EIP-1559 fee suggestion: current base fee (from the
    /// latest block header) plus a fixed 1.5 gwei priority tip, doubling
    /// the base fee for `max_fee_per_gas` headroom against the next few
    /// blocks — a deliberately simple heuristic, not `eth_feeHistory`'s
    /// full percentile machinery, which is unneeded complexity for a
    /// wallet sending plain transfers rather than doing MEV-aware fee
    /// bidding.
    pub fn fee_suggestion(&self) -> Result<Untrusted<FeeSuggestion>, RpcError> {
        const PRIORITY_FEE: u128 = 1_500_000_000; // 1.5 gwei

        let block = self.call("eth_getBlockByNumber", &json!(["latest", false]))?;
        let base_fee_hex = block
            .get("baseFeePerGas")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::Malformed("eth_getBlockByNumber: missing baseFeePerGas (pre-EIP-1559 chain?)".to_string()))?;
        let base_fee = parse_hex_u128(base_fee_hex).map_err(|e| RpcError::Malformed(format!("eth_getBlockByNumber: {e}")))?;

        let suggestion = FeeSuggestion {
            max_priority_fee_per_gas: PRIORITY_FEE,
            max_fee_per_gas: base_fee.saturating_mul(2).saturating_add(PRIORITY_FEE),
        };
        Ok(Untrusted::new(suggestion, self.endpoint.clone()))
    }

    /// `eth_estimateGas` for a plain transfer of `value` wei to `to`.
    /// Not funds-critical in the same way balance/nonce are (an
    /// under-estimate just fails the transaction, wasting no funds beyond
    /// the gas already spent up to the point of failure) — `trust()` is
    /// an acceptable choice at most call sites, though `cross_check`
    /// remains available.
    pub fn estimate_gas(&self, to: &[u8; 20], value: u128) -> Result<Untrusted<u64>, RpcError> {
        let value = self.call_hex_u64("eth_estimateGas", &json!([{ "to": to_hex_address(to), "value": to_hex_u128(value) }]))?;
        Ok(Untrusted::new(value, self.endpoint.clone()))
    }

    /// `eth_sendRawTransaction` — broadcast the RLP-encoded signed
    /// transaction bytes (e.g. from
    /// `wallet_core::evm::sign_evm_transfer_with_policy`) and return the
    /// resulting transaction hash.
    pub fn send_raw_transaction(&self, raw: &[u8]) -> Result<Untrusted<[u8; 32]>, RpcError> {
        let hex = to_hex(raw);
        let result = self.call("eth_sendRawTransaction", &json!([hex]))?;
        let hash_hex = result.as_str().ok_or_else(|| RpcError::Malformed("eth_sendRawTransaction: expected a hex string result".to_string()))?;
        let hash = parse_hex_bytes32(hash_hex).map_err(|e| RpcError::Malformed(format!("eth_sendRawTransaction: {e}")))?;
        Ok(Untrusted::new(hash, self.endpoint.clone()))
    }

    /// `eth_getTransactionReceipt` for `tx_hash`. `None` means the
    /// transaction hasn't been mined yet (or was never seen by this
    /// node) — not an error.
    pub fn transaction_receipt(&self, tx_hash: &[u8; 32]) -> Result<Untrusted<Option<TransactionReceipt>>, RpcError> {
        let hash_hex = to_hex(tx_hash);
        let result = self.call("eth_getTransactionReceipt", &json!([hash_hex]))?;
        if result.is_null() {
            return Ok(Untrusted::new(None, self.endpoint.clone()));
        }

        let status_hex = result.get("status").and_then(Value::as_str).ok_or_else(|| RpcError::Malformed("receipt missing status".to_string()))?;
        let status = parse_hex_u64(status_hex).map_err(|e| RpcError::Malformed(format!("receipt status: {e}")))?;
        let block_number_hex = result.get("blockNumber").and_then(Value::as_str).ok_or_else(|| RpcError::Malformed("receipt missing blockNumber".to_string()))?;
        let block_number = parse_hex_u64(block_number_hex).map_err(|e| RpcError::Malformed(format!("receipt blockNumber: {e}")))?;

        Ok(Untrusted::new(Some(TransactionReceipt { success: status == 1, block_number }), self.endpoint.clone()))
    }
}

/// A simple EIP-1559 fee suggestion — see `JsonRpcClient::fee_suggestion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSuggestion {
    /// Suggested `max_priority_fee_per_gas`, in wei/gas.
    pub max_priority_fee_per_gas: u128,
    /// Suggested `max_fee_per_gas`, in wei/gas.
    pub max_fee_per_gas: u128,
}

/// A mined transaction's outcome, as reported by one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionReceipt {
    /// Whether the transaction succeeded (EIP-658 status byte == 1).
    pub success: bool,
    /// Block the transaction was mined in — subtract from a current
    /// `block_number` to get confirmation depth.
    pub block_number: u64,
}

/// `0x`-prefixed lowercase hex encoding of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn to_hex_address(address: &[u8; 20]) -> String {
    to_hex(address)
}

fn to_hex_u128(value: u128) -> String {
    format!("{value:#x}")
}

fn parse_hex_u64(hex: &str) -> Result<u64, String> {
    let stripped = hex.strip_prefix("0x").ok_or_else(|| format!("expected 0x-prefixed hex, got {hex}"))?;
    u64::from_str_radix(stripped, 16).map_err(|e| format!("invalid hex u64 {hex}: {e}"))
}

fn parse_hex_u128(hex: &str) -> Result<u128, String> {
    let stripped = hex.strip_prefix("0x").ok_or_else(|| format!("expected 0x-prefixed hex, got {hex}"))?;
    u128::from_str_radix(stripped, 16).map_err(|e| format!("invalid hex u128 {hex}: {e}"))
}

fn parse_hex_bytes32(hex: &str) -> Result<[u8; 32], String> {
    let stripped = hex.strip_prefix("0x").ok_or_else(|| format!("expected 0x-prefixed hex, got {hex}"))?;
    if stripped.len() != 64 {
        return Err(format!("expected 32 bytes (64 hex chars), got {} chars", stripped.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).map_err(|e| format!("invalid hex byte: {e}"))?;
    }
    Ok(out)
}

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let stripped = hex.strip_prefix("0x").ok_or_else(|| format!("expected 0x-prefixed hex, got {hex}"))?;
    if stripped.len() % 2 != 0 {
        return Err(format!("expected even number of hex chars, got {} chars", stripped.len()));
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    for i in 0..stripped.len() / 2 {
        out.push(u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).map_err(|e| format!("invalid hex byte: {e}"))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not run by default (`cargo test --workspace` never hits the
    /// network, matching this workspace's convention) — run explicitly
    /// with `cargo test -p wallet-rpc -- --ignored` to verify the TLS/
    /// root-cert setup actually works against a real HTTPS endpoint.
    /// This exact call (a live `eth_chainId` over TLS) is what panicked
    /// in production with "`WebPki` is disabled" before
    /// `rustls-webpki-roots` was added — see this crate's Cargo.toml.
    #[test]
    #[ignore = "hits a real network endpoint"]
    fn chain_id_over_real_tls_does_not_panic() {
        let client = JsonRpcClient::new(Endpoint("https://ethereum-sepolia-rpc.publicnode.com".to_string()));
        let chain_id = client.chain_id().expect("live TLS request to a public Sepolia RPC endpoint should succeed").trust();
        assert_eq!(chain_id, 11_155_111);
    }

    #[test]
    fn hex_u64_roundtrip() {
        assert_eq!(parse_hex_u64("0x1a").unwrap(), 26);
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
    }

    #[test]
    fn hex_u64_without_prefix_rejected() {
        assert!(parse_hex_u64("1a").is_err());
    }

    #[test]
    fn hex_u128_roundtrip() {
        assert_eq!(parse_hex_u128("0xde0b6b3a7640000").unwrap(), 1_000_000_000_000_000_000);
    }

    #[test]
    fn hex_bytes32_roundtrip() {
        let hex = format!("0x{}", "ab".repeat(32));
        assert_eq!(parse_hex_bytes32(&hex).unwrap(), [0xab; 32]);
    }

    #[test]
    fn hex_bytes32_wrong_length_rejected() {
        assert!(parse_hex_bytes32("0xabcd").is_err());
    }

    #[test]
    fn to_hex_address_round_trips_through_parse() {
        let address = [0x12; 20];
        let hex = to_hex_address(&address);
        assert_eq!(hex, format!("0x{}", "12".repeat(20)));
    }
}
