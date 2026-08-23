//! Untrusted-input parsing: decodes a raw transaction into a
//! human-reviewable summary before it's allowed anywhere near signing.
//!
//! Contract for this crate: on any unrecognized structure, malformed
//! input, or parse ambiguity, return an error — never fall back to "sign
//! the raw hex". A failure here must block signing, not bypass it. This
//! crate has no dependency on `wallet-crypto`; it never needs key
//! material, only the untrusted bytes it's decoding.
//!
//! Scope note: this decodes one minimal, self-defined wire format for a
//! plain native-currency transfer with no calldata — not real Ethereum
//! RLP/EIP-1559 transactions, and not EIP-712 typed data. Those are
//! substantial, chain-specific parsers in their own right and are
//! deliberately out of scope for this pass; hand-rolling RLP correctly
//! under time pressure is exactly the kind of rushed code this project
//! has been trying to avoid. What's real here, and what actually matters
//! for the security property this crate exists for, is the fail-closed
//! behavior: any calldata this decoder doesn't specifically recognize —
//! which today means *any* non-empty calldata at all — is rejected, not
//! silently passed through. That behavior doesn't change when real
//! chain-specific formats are added later; only the set of things this
//! decoder recognizes grows.
//!
//! Wire format: `version(1) || chain_id(8, BE) || to(20) || value(16, BE)
//! || data_len(2, BE) || data(data_len bytes)`.

use std::fmt;

const CURRENT_VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + 8 + 20 + 16 + 2; // version + chain_id + to + value + data_len
/// Sanity cap on total input size, independent of the `data_len` field
/// (which is itself bounded to 65535 by its `u16` width) — belt-and-
/// suspenders against a caller passing something absurd before any
/// parsing happens at all.
const MAX_INPUT_LEN: usize = 64 * 1024;

/// A transaction decoded into a form safe to display to a user and hand
/// to the signing layer — the only thing `wallet-core` should ever sign,
/// never raw bytes it hasn't run through `decode` first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTransaction {
    /// Chain this transaction is meant for — display this to the user so
    /// a cross-chain replay/confusion attempt is visible, not silent.
    pub chain_id: u64,
    /// Recipient address.
    pub to: [u8; 20],
    /// Amount of native currency to transfer.
    pub value: u128,
}

impl DecodedTransaction {
    /// Deterministic byte serialization of the validated fields, for the
    /// caller to hash before signing. Kept separate from hashing itself
    /// (this crate has no hash-function dependency, deliberately minimal)
    /// — `wallet-core` hashes this via `wallet_crypto::sha256`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 20 + 16);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.value.to_be_bytes());
        out
    }
}

/// Why decoding failed. Every variant means "do not sign this" — there is
/// no variant that means "sign it anyway."
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input is empty.
    Empty,
    /// Input exceeds `MAX_INPUT_LEN`.
    Oversized,
    /// Input is shorter than the fixed header, or `data_len` claims more
    /// bytes than are actually present.
    Truncated,
    /// The version byte doesn't match `CURRENT_VERSION`.
    UnsupportedVersion(u8),
    /// Calldata is present. This decoder doesn't understand any calldata
    /// semantics yet (no ERC-20 `transfer`/`approve`, no arbitrary
    /// contract calls) — fail closed rather than sign something whose
    /// meaning isn't understood. This is the direct analogue of
    /// "unknown function selector" for a real ABI decoder.
    UnrecognizedCalldata,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Empty => write!(f, "empty input"),
            DecodeError::Oversized => write!(f, "input exceeds maximum size"),
            DecodeError::Truncated => write!(f, "input truncated"),
            DecodeError::UnsupportedVersion(v) => write!(f, "unsupported version byte: {v}"),
            DecodeError::UnrecognizedCalldata => write!(f, "calldata present but not recognized by any decoder"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode raw transaction bytes into a `DecodedTransaction`, or refuse.
/// See the module docs for the fail-closed contract and current scope.
///
/// # Panics
/// Never in practice: the length checks above guarantee each field's
/// slice is exactly the right width before the internal
/// `try_into().unwrap()` calls run.
pub fn decode(raw: &[u8]) -> Result<DecodedTransaction, DecodeError> {
    if raw.is_empty() {
        return Err(DecodeError::Empty);
    }
    if raw.len() > MAX_INPUT_LEN {
        return Err(DecodeError::Oversized);
    }
    if raw.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }

    let version = raw[0];
    if version != CURRENT_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let mut offset = 1;
    let chain_id = u64::from_be_bytes(raw[offset..offset + 8].try_into().unwrap());
    offset += 8;
    let to: [u8; 20] = raw[offset..offset + 20].try_into().unwrap();
    offset += 20;
    let value = u128::from_be_bytes(raw[offset..offset + 16].try_into().unwrap());
    offset += 16;
    let data_len = u16::from_be_bytes(raw[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    // checked_add rather than relying on the MAX_INPUT_LEN guard above to
    // implicitly keep this addition in range: if that cap is ever raised
    // (or removed) later, this line must not silently start assuming
    // non-overflow again — CWE-190.
    let expected_len = offset.checked_add(data_len).ok_or(DecodeError::Truncated)?;
    if raw.len() != expected_len {
        return Err(DecodeError::Truncated);
    }
    if data_len > 0 {
        return Err(DecodeError::UnrecognizedCalldata);
    }

    Ok(DecodedTransaction { chain_id, to, value })
}

/// Encode a plain transfer into this decoder's wire format. Exists so
/// callers/tests can construct valid input without hand-assembling byte
/// offsets — the inverse of `decode` for the one shape it accepts.
pub fn encode_transfer(chain_id: u64, to: [u8; 20], value: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.push(CURRENT_VERSION);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&to);
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // data_len = 0
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_well_formed_transfer() {
        let to = [0xAB; 20];
        let raw = encode_transfer(1, to, 42);

        let decoded = decode(&raw).unwrap();
        assert_eq!(decoded, DecodedTransaction { chain_id: 1, to, value: 42 });
    }

    #[test]
    fn empty_input_rejected() {
        assert_eq!(decode(&[]).unwrap_err(), DecodeError::Empty);
    }

    #[test]
    fn truncated_header_rejected() {
        let raw = encode_transfer(1, [0xAB; 20], 42);
        assert_eq!(decode(&raw[..HEADER_LEN - 1]).unwrap_err(), DecodeError::Truncated);
    }

    #[test]
    fn truncated_calldata_rejected() {
        // Claims 10 bytes of calldata via data_len but doesn't include them.
        let mut raw = encode_transfer(1, [0xAB; 20], 42);
        let len = raw.len();
        raw[len - 2..].copy_from_slice(&10u16.to_be_bytes());
        // no calldata bytes actually appended

        assert_eq!(decode(&raw).unwrap_err(), DecodeError::Truncated);
    }

    #[test]
    fn unrecognized_calldata_rejected() {
        let mut raw = encode_transfer(1, [0xAB; 20], 42);
        let len = raw.len();
        raw[len - 2..].copy_from_slice(&4u16.to_be_bytes());
        raw.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(decode(&raw).unwrap_err(), DecodeError::UnrecognizedCalldata);
    }

    #[test]
    fn oversized_input_rejected() {
        let huge = vec![0u8; MAX_INPUT_LEN + 1];
        assert_eq!(decode(&huge).unwrap_err(), DecodeError::Oversized);
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut raw = encode_transfer(1, [0xAB; 20], 42);
        raw[0] = 0xFF;
        assert_eq!(decode(&raw).unwrap_err(), DecodeError::UnsupportedVersion(0xFF));
    }

    #[test]
    fn a_failed_decode_never_returns_a_transaction() {
        // Every DecodeError variant means "don't sign this" — proven here
        // by checking decode()'s type signature can't partially succeed:
        // Result<DecodedTransaction, DecodeError> is either fully Ok or
        // fully Err, never both. This test documents that guarantee
        // explicitly rather than leaving it implicit in the type.
        for raw in [&b""[..], &[0xFF; 1][..], &vec![0u8; MAX_INPUT_LEN + 1][..]] {
            assert!(decode(raw).is_err());
        }
    }
}
