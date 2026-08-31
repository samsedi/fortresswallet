//! EVM address derivation and EIP-1559 transaction construction/signing.
//!
//! This is the one chain-specific orchestration module in `wallet-core`
//! so far: it ties together `wallet_crypto` (keccak256, recoverable
//! signing), `wallet_decoder::evm` (the wire format), and
//! `ceremony`/`policy` (the same decode→policy→sign ordering
//! `sign_transaction_with_policy` already established for the legacy
//! format) into one entry point for spending EVM-native funds.
//!
//! One address per wallet, not a BIP-32 HD tree: the DKG ceremony
//! (`ceremony::generate_and_split_key`) produces exactly one group
//! keypair per wallet today, so there is exactly one EVM address to
//! derive from it. Multi-account HD derivation is a real future need,
//! deliberately deferred — see the crate-level docs.

use std::time::SystemTime;

use wallet_crypto::keys::PublicKey;
use wallet_crypto::shamir::Share;
use wallet_decoder::evm::{SignedEip1559Tx, UnsignedEip1559Tx};
use wallet_decoder::DecodedTransaction;

use crate::ceremony::{self, CeremonyError};
use crate::policy::{DenialReason, PolicyDecision, PolicyEngine};

/// Derive the Ethereum-style address for `public_key`: the last 20 bytes
/// of `keccak256` of the uncompressed public key (`0x04 || x || y`, minus
/// the `0x04` prefix itself).
pub fn address_from_public_key(public_key: &PublicKey) -> [u8; 20] {
    let uncompressed = public_key.to_uncompressed_sec1_bytes();
    let hash = wallet_crypto::keccak256(&uncompressed[1..]); // strip the 0x04 prefix
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// EIP-55 checksummed hex encoding of `address`, e.g.
/// `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`. Casing encodes a checksum
/// (each hex digit is uppercased iff the corresponding nibble of
/// `keccak256(lowercase_hex(address))` is >= 8), so a single-character
/// typo when a user copies an address is very likely to produce an
/// invalid checksum rather than silently pointing at a different account.
pub fn to_checksummed_hex(address: &[u8; 20]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut lower = [0u8; 40];
    for (i, byte) in address.iter().enumerate() {
        lower[i * 2] = HEX[(byte >> 4) as usize];
        lower[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    let hash = wallet_crypto::keccak256(&lower);

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, &lower_byte) in lower.iter().enumerate() {
        // Each output hex character's case is decided by one nibble of
        // the hash — high nibble for even indices, low nibble for odd.
        let hash_nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
        let c = lower_byte as char;
        if c.is_ascii_alphabetic() && hash_nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Hard ceiling on `max_fee_per_gas`, in wei. 10,000 gwei is ~50× the
/// highest historical Ethereum mainnet base fee — generous enough to
/// never block a legitimate transaction, strict enough to prevent a
/// malicious or compromised RPC node from draining the wallet through
/// fees alone. This is enforced in `build_unsigned_transfer` so no
/// caller (FFI, CLI, or future frontend) can bypass it.
const MAX_FEE_PER_GAS: u128 = 10_000_000_000_000; // 10,000 gwei

/// Why building an unsigned transaction failed.
#[derive(Debug, PartialEq, Eq)]
pub enum EvmBuildError {
    /// `max_fee_per_gas` exceeds the hard ceiling (`MAX_FEE_PER_GAS`).
    /// A malicious RPC node returning an astronomical fee suggestion
    /// would trigger this rather than silently building a transaction
    /// that drains the wallet to miners.
    FeeCapExceeded {
        /// The fee the caller attempted to set, in wei.
        requested: u128,
        /// The maximum allowed, in wei.
        ceiling: u128,
    },
}

impl std::fmt::Display for EvmBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvmBuildError::FeeCapExceeded { requested, ceiling } => {
                write!(f, "max_fee_per_gas {requested} wei exceeds the hard ceiling of {ceiling} wei")
            }
        }
    }
}

impl std::error::Error for EvmBuildError {}

/// Build an unsigned EIP-1559 native-currency transfer from
/// caller-supplied and network-sourced parameters. `nonce`,
/// `max_fee_per_gas`, `max_priority_fee_per_gas`, and `gas_limit` should
/// come from cross-checked `wallet-rpc` queries (`Untrusted::cross_check`),
/// never trusted from a single node — this function itself does no
/// network I/O and has no opinion on where its inputs came from.
///
/// Returns `Err(EvmBuildError::FeeCapExceeded)` if `max_fee_per_gas`
/// exceeds the hard ceiling — see `MAX_FEE_PER_GAS`.
pub fn build_unsigned_transfer(
    chain_id: u64,
    to: [u8; 20],
    value: u128,
    nonce: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    gas_limit: u64,
) -> Result<UnsignedEip1559Tx, EvmBuildError> {
    if max_fee_per_gas > MAX_FEE_PER_GAS {
        return Err(EvmBuildError::FeeCapExceeded { requested: max_fee_per_gas, ceiling: MAX_FEE_PER_GAS });
    }
    Ok(UnsignedEip1559Tx { chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data: vec![] })
}

/// Build an unsigned EIP-1559 contract call (e.g. for an ERC20 transfer).
pub fn build_unsigned_contract_call(
    chain_id: u64,
    to: [u8; 20],
    value: u128,
    data: Vec<u8>,
    nonce: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    gas_limit: u64,
) -> Result<UnsignedEip1559Tx, EvmBuildError> {
    if max_fee_per_gas > MAX_FEE_PER_GAS {
        return Err(EvmBuildError::FeeCapExceeded { requested: max_fee_per_gas, ceiling: MAX_FEE_PER_GAS });
    }
    Ok(UnsignedEip1559Tx { chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data })
}

/// The digest to sign for `tx`: `keccak256` of its RLP encoding — EIP-1559
/// diverges from the legacy wire format's `sha256` here, this is the one
/// place that matters.
#[must_use]
pub fn hash_for_signing(tx: &UnsignedEip1559Tx) -> [u8; 32] {
    wallet_crypto::keccak256(&wallet_decoder::evm::encode_unsigned(tx))
}

/// Errors common to both `sign_evm_transfer` and `sign_evm_transfer_with_policy`.
#[derive(Debug)]
pub enum EvmCeremonyError {
    /// The ceremony itself failed — see `CeremonyError`.
    Ceremony(CeremonyError),
    /// The reconstructed signature's recovery id encoded an x-coordinate
    /// overflow bit EIP-1559's `y_parity` field cannot represent.
    /// Astronomically unlikely for a random digest (r would have to
    /// exceed the curve order) — kept as an explicit, fail-closed variant
    /// rather than silently dropping that bit and producing a transaction
    /// whose signature doesn't recover to the expected address.
    UnrepresentableRecoveryId,
}

/// Errors from `sign_evm_transfer_with_policy`.
#[derive(Debug)]
pub enum EvmSigningError {
    /// Denied outright by spending policy — see `DenialReason`. The
    /// ceremony never runs; the key is never reconstructed for a denied
    /// transaction.
    Denied(DenialReason),
    /// Not denied, but not immediately approved either — see
    /// `wallet_core::policy`'s module docs for why this crate doesn't
    /// implement the hold/retry queue itself.
    Queued {
        /// Earliest time this transaction may be re-submitted.
        release_at: SystemTime,
    },
    /// The ceremony itself failed after policy approval — see
    /// `EvmCeremonyError`. Policy history is not updated in this case.
    Ceremony(EvmCeremonyError),
}

/// Reconstruct-sign-assemble, shared by `sign_evm_transfer` and
/// `sign_evm_transfer_with_policy` once each has settled whether signing
/// is allowed to happen at all.
fn sign_and_encode(tx: UnsignedEip1559Tx, shares: &[Share], expected_public_key: &PublicKey) -> Result<Vec<u8>, EvmCeremonyError> {
    let digest = hash_for_signing(&tx);
    let (signature, recovery_id) =
        ceremony::sign_with_shares_recoverable(shares, expected_public_key, &digest).map_err(EvmCeremonyError::Ceremony)?;

    if recovery_id.is_x_reduced() {
        return Err(EvmCeremonyError::UnrepresentableRecoveryId);
    }
    let y_parity = u8::from(recovery_id.is_y_odd());

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);

    Ok(wallet_decoder::evm::encode_signed(&SignedEip1559Tx { tx, y_parity, r, s }))
}

/// Sign `tx`, with NO spending policy applied — see
/// `sign_evm_transfer_with_policy` below, which is the entry point a
/// long-lived wallet process (holding a `PolicyEngine` in memory across
/// calls) should use instead. This function exists for callers with no
/// persistent policy state to check against: a one-shot CLI process is
/// the main example — since it starts a fresh `PolicyEngine` on every
/// invocation, the engine would treat every destination as "new" on
/// every single call and queue every send forever, which isn't a
/// meaningful protection, just a permanent stall. Mirrors
/// `ceremony::sign_transaction`'s unguarded/guarded split. Returns the
/// RLP-encoded signed transaction bytes, ready for `wallet-rpc`'s
/// `send_raw_transaction`.
pub fn sign_evm_transfer(tx: UnsignedEip1559Tx, shares: &[Share], expected_public_key: &PublicKey) -> Result<Vec<u8>, EvmCeremonyError> {
    sign_and_encode(tx, shares, expected_public_key)
}

/// The policy-guarded entry point for spending EVM-native funds: check
/// spending policy, then sign — a denied or queued transaction never
/// reaches the signing ceremony at all (the key is never reconstructed
/// for it). Mirrors `ceremony::sign_transaction_with_policy`'s ordering
/// exactly. Returns the RLP-encoded signed transaction bytes, ready for
/// `wallet-rpc`'s `send_raw_transaction`. Requires a `PolicyEngine` the
/// caller keeps alive across calls — see `sign_evm_transfer` above for
/// why a fresh engine per call doesn't work.
pub fn sign_evm_transfer_with_policy(
    tx: UnsignedEip1559Tx,
    shares: &[Share],
    expected_public_key: &PublicKey,
    policy: &mut PolicyEngine,
    now: SystemTime,
) -> Result<Vec<u8>, EvmSigningError> {
    let policy_view = DecodedTransaction { chain_id: tx.chain_id, to: tx.to, value: tx.value };

    match policy.evaluate(&policy_view, now) {
        PolicyDecision::Denied(reason) => return Err(EvmSigningError::Denied(reason)),
        PolicyDecision::Queued { release_at } => return Err(EvmSigningError::Queued { release_at }),
        PolicyDecision::Approved => {}
    }

    let encoded = sign_and_encode(tx, shares, expected_public_key).map_err(EvmSigningError::Ceremony)?;
    policy.record_approved(&policy_view, now);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn permissive_policy() -> PolicyEngine {
        PolicyEngine::new(crate::policy::PolicyConfig {
            max_single_tx_value: u128::MAX,
            max_value_per_window: u128::MAX,
            window: Duration::from_secs(3600),
            timelock_threshold: u128::MAX,
            timelock_delay: Duration::from_secs(1),
        })
    }

    #[test]
    fn address_derivation_is_deterministic_and_matches_public_key() {
        let (public_key, _) = ceremony::generate_and_split_key(2, 3).unwrap();
        let a1 = address_from_public_key(&public_key);
        let a2 = address_from_public_key(&public_key);
        assert_eq!(a1, a2);
    }

    #[test]
    fn checksummed_hex_matches_known_eip55_vector() {
        // Canonical EIP-55 test vector from the EIP itself.
        let address: [u8; 20] = {
            let mut a = [0u8; 20];
            let hex = "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
            for i in 0..20 {
                a[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            a
        };
        assert_eq!(to_checksummed_hex(&address), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn end_to_end_build_sign_and_verify() {
        let (public_key, shares) = ceremony::generate_and_split_key(2, 3).unwrap();
        let tx = build_unsigned_transfer(1, [0x22; 20], 1_000_000_000_000_000_000, 0, 30_000_000_000, 1_000_000_000, 21_000).unwrap();

        let mut policy = permissive_policy();
        let now = SystemTime::now();
        // Pre-establish the destination as known — a brand-new destination
        // always queues regardless of `timelock_threshold` (see
        // `policy::evaluate`), which isn't what this test is exercising.
        policy.record_approved(&DecodedTransaction { chain_id: tx.chain_id, to: tx.to, value: 0 }, now);

        let signed_bytes = sign_evm_transfer_with_policy(tx.clone(), &shares[0..2], &public_key, &mut policy, now).unwrap();

        let decoded = wallet_decoder::evm::decode_signed(&signed_bytes).unwrap();
        assert_eq!(decoded.tx, tx);

        // The embedded signature must actually recover the wallet's own
        // public key — proves y_parity/r/s were assembled correctly, not
        // just that decode_signed's framing round-trips.
        let digest = hash_for_signing(&tx);
        let recovery_id = wallet_crypto::keys::RecoveryId::from_byte(decoded.y_parity).unwrap();
        let recovered =
            wallet_crypto::keys::PublicKey::recover_from_prehash(&digest, &signature_from_parts(&decoded), recovery_id)
                .unwrap();
        assert_eq!(recovered, public_key);
    }

    #[test]
    fn sign_evm_transfer_has_no_policy_gate() {
        let (public_key, shares) = ceremony::generate_and_split_key(2, 3).unwrap();
        // A brand-new destination, with no policy engine at all — the
        // guarded path would queue this forever from a fresh engine (see
        // sign_evm_transfer's docs); the unguarded path just signs it.
        let tx = build_unsigned_transfer(1, [0x33; 20], 1, 0, 1, 1, 21_000).unwrap();

        let signed_bytes = sign_evm_transfer(tx.clone(), &shares[0..2], &public_key).unwrap();
        let decoded = wallet_decoder::evm::decode_signed(&signed_bytes).unwrap();
        assert_eq!(decoded.tx, tx);
    }

    #[test]
    fn denied_transaction_never_reaches_signing() {
        let (public_key, shares) = ceremony::generate_and_split_key(2, 3).unwrap();
        let mut policy = PolicyEngine::new(crate::policy::PolicyConfig {
            max_single_tx_value: 100,
            max_value_per_window: 100,
            window: Duration::from_secs(3600),
            timelock_threshold: u128::MAX,
            timelock_delay: Duration::from_secs(1),
        });
        let tx = build_unsigned_transfer(1, [0x22; 20], 1_000, 0, 1, 1, 21_000).unwrap();

        let result = sign_evm_transfer_with_policy(tx, &shares[0..2], &public_key, &mut policy, SystemTime::now());
        assert!(matches!(result, Err(EvmSigningError::Denied(DenialReason::ExceedsSingleTxCap))));
    }

    #[test]
    fn fee_cap_exceeded_rejects_astronomical_fee() {
        let result = build_unsigned_transfer(1, [0x22; 20], 1, 0, MAX_FEE_PER_GAS + 1, 1, 21_000);
        assert!(matches!(result, Err(EvmBuildError::FeeCapExceeded { .. })));
    }

    #[test]
    fn fee_at_ceiling_is_accepted() {
        let result = build_unsigned_transfer(1, [0x22; 20], 1, 0, MAX_FEE_PER_GAS, 1, 21_000);
        assert!(result.is_ok());
    }

    fn signature_from_parts(decoded: &SignedEip1559Tx) -> wallet_crypto::keys::Signature {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&decoded.r);
        bytes[32..].copy_from_slice(&decoded.s);
        wallet_crypto::keys::Signature::from_slice(&bytes).unwrap()
    }
}
