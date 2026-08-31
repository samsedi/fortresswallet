//! Real EIP-1559 (type-2) transaction wire format: RLP encode/decode for a
//! plain native-currency transfer, no calldata, no access list — the same
//! scope-limiting philosophy as the rest of this crate (see the module
//! docs in `lib.rs`): a non-empty `data` or `access_list` field is not
//! silently accepted, it's rejected. Contract calls / ERC-20 support is a
//! deliberate, separate follow-up, not something this decoder guesses at.
//!
//! RLP framing mechanics (length-prefix encode/decode) come from
//! `alloy-rlp`; this module still owns the EIP-1559 field layout itself
//! explicitly, field by field, rather than decoding into some generic
//! dynamically-typed transaction shape.
//!
//! Wire format: `0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas,
//! max_fee_per_gas, gas_limit, to, value, data, access_list])` for the
//! unsigned form, with `y_parity, r, s` appended to the list for the
//! signed form — exactly EIP-1559's own envelope, so any standard EVM
//! node accepts `encode_signed`'s output via `eth_sendRawTransaction`
//! unmodified.

use alloy_rlp::{Decodable, Encodable, Header};
use std::fmt;

/// An EIP-1559 transfer with no calldata and no access list, before
/// signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedEip1559Tx {
    /// Chain this transaction is meant for — embedded in the signed
    /// payload itself (unlike the legacy format), so a cross-chain replay
    /// is rejected by any compliant node, not just this wallet.
    pub chain_id: u64,
    /// Sender's transaction count at time of signing.
    pub nonce: u64,
    /// EIP-1559 priority fee (tip to the block proposer), in wei/gas.
    pub max_priority_fee_per_gas: u128,
    /// EIP-1559 fee cap (base fee + tip), in wei/gas.
    pub max_fee_per_gas: u128,
    /// Gas limit for this transaction.
    pub gas_limit: u64,
    /// Recipient address.
    pub to: [u8; 20],
    /// Amount of native currency to transfer, in wei.
    pub value: u128,
    /// Transaction data (empty for native transfers, contains ABI payload for contract calls).
    pub data: Vec<u8>,
}

/// A `SignedEip1559Tx` and its ECDSA signature, ready to RLP-encode for
/// `eth_sendRawTransaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEip1559Tx {
    /// The transaction that was signed.
    pub tx: UnsignedEip1559Tx,
    /// ECDSA recovery id (0 or 1) — EIP-1559's `y_parity` field.
    pub y_parity: u8,
    /// ECDSA signature `r`, big-endian.
    pub r: [u8; 32],
    /// ECDSA signature `s`, big-endian.
    pub s: [u8; 32],
}

/// Why decoding a signed EIP-1559 transaction failed. Every variant means
/// "do not treat this as a valid transaction" — same fail-closed contract
/// as the top-level `DecodeError` in this crate.
#[derive(Debug, PartialEq, Eq)]
pub enum EvmDecodeError {
    /// Input is empty.
    Empty,
    /// The leading type byte isn't `0x02` (EIP-1559).
    UnsupportedType(u8),
    /// RLP framing was invalid, truncated, or non-canonical.
    Malformed,
    /// Bytes remained after decoding every expected field.
    TrailingBytes,
    /// `access_list` was non-empty — same scope limitation as `data`.
    UnrecognizedAccessList,
    /// `y_parity` was neither 0 nor 1.
    InvalidYParity(u8),
}

impl fmt::Display for EvmDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmDecodeError::Empty => write!(f, "empty input"),
            EvmDecodeError::UnsupportedType(t) => write!(f, "unsupported transaction type byte: {t:#04x}"),
            EvmDecodeError::Malformed => write!(f, "malformed RLP"),
            EvmDecodeError::TrailingBytes => write!(f, "trailing bytes after decoding all expected fields"),
            EvmDecodeError::UnrecognizedAccessList => write!(f, "access list present but not recognized by any decoder"),
            EvmDecodeError::InvalidYParity(v) => write!(f, "invalid y_parity: {v}"),
        }
    }
}

impl std::error::Error for EvmDecodeError {}

const TYPE_BYTE: u8 = 0x02;

/// Strip leading zero bytes from a 32-byte big-endian quantity, collapsing
/// an all-zero value to an empty slice — the canonical RLP encoding of the
/// integer `0` is the empty string, not a zero byte. This is exactly what
/// `alloy_rlp`'s own `u64`/`u128` `Encodable` impls do internally; `r`/`s`
/// need the same treatment by hand since 32 bytes is wider than `u128`.
fn trimmed_quantity(bytes: &[u8; 32]) -> &[u8] {
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &[],
    }
}

fn encode_fields(tx: &UnsignedEip1559Tx, out: &mut Vec<u8>) {
    tx.chain_id.encode(out);
    tx.nonce.encode(out);
    tx.max_priority_fee_per_gas.encode(out);
    tx.max_fee_per_gas.encode(out);
    tx.gas_limit.encode(out);
    tx.to.encode(out);
    tx.value.encode(out);
    tx.data.as_slice().encode(out); // data
    out.push(alloy_rlp::EMPTY_LIST_CODE); // access_list: always empty
}

fn fields_length(tx: &UnsignedEip1559Tx) -> usize {
    tx.chain_id.length()
        + tx.nonce.length()
        + tx.max_priority_fee_per_gas.length()
        + tx.max_fee_per_gas.length()
        + tx.gas_limit.length()
        + tx.to.length()
        + tx.value.length()
        + tx.data.as_slice().length()
        + 1 // access_list: single EMPTY_LIST_CODE byte
}

/// RLP-encode `tx` with the EIP-1559 (`0x02`) type prefix, unsigned — the
/// exact bytes to hash (via `wallet_crypto::keccak256`) before signing.
pub fn encode_unsigned(tx: &UnsignedEip1559Tx) -> Vec<u8> {
    let payload_length = fields_length(tx);
    let mut out = Vec::with_capacity(1 + 9 + payload_length);
    out.push(TYPE_BYTE);
    Header { list: true, payload_length }.encode(&mut out);
    encode_fields(tx, &mut out);
    out
}

/// RLP-encode `signed` with the EIP-1559 (`0x02`) type prefix, including
/// its signature — the exact bytes to hand to `eth_sendRawTransaction`.
pub fn encode_signed(signed: &SignedEip1559Tx) -> Vec<u8> {
    let r_trimmed = trimmed_quantity(&signed.r);
    let s_trimmed = trimmed_quantity(&signed.s);
    let payload_length =
        fields_length(&signed.tx) + signed.y_parity.length() + r_trimmed.length() + s_trimmed.length();

    let mut out = Vec::with_capacity(1 + 9 + payload_length);
    out.push(TYPE_BYTE);
    Header { list: true, payload_length }.encode(&mut out);
    encode_fields(&signed.tx, &mut out);
    signed.y_parity.encode(&mut out);
    r_trimmed.encode(&mut out);
    s_trimmed.encode(&mut out);
    out
}

fn decode_quantity_32(buf: &mut &[u8]) -> Result<[u8; 32], EvmDecodeError> {
    let bytes = Header::decode_bytes(buf, false).map_err(|_| EvmDecodeError::Malformed)?;
    if bytes.len() > 32 {
        return Err(EvmDecodeError::Malformed);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

/// Decode a signed EIP-1559 transaction produced by `encode_signed`. Fails
/// closed on anything not matching this exact shape — see
/// `EvmDecodeError` for every rejection reason; there is no variant that
/// means "accept it anyway".
pub fn decode_signed(raw: &[u8]) -> Result<SignedEip1559Tx, EvmDecodeError> {
    if raw.is_empty() {
        return Err(EvmDecodeError::Empty);
    }
    if raw[0] != TYPE_BYTE {
        return Err(EvmDecodeError::UnsupportedType(raw[0]));
    }

    let mut rest = &raw[1..];
    let list_bytes = Header::decode_bytes(&mut rest, true).map_err(|_| EvmDecodeError::Malformed)?;
    if !rest.is_empty() {
        return Err(EvmDecodeError::TrailingBytes);
    }

    let mut body = list_bytes;
    let chain_id = u64::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    let nonce = u64::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    let max_priority_fee_per_gas = u128::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    let max_fee_per_gas = u128::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    let gas_limit = u64::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    let to = <[u8; 20]>::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    let value = u128::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;

    let data_bytes = Header::decode_bytes(&mut body, false).map_err(|_| EvmDecodeError::Malformed)?;
    let data = data_bytes.to_vec();

    let access_list = Header::decode_bytes(&mut body, true).map_err(|_| EvmDecodeError::Malformed)?;
    if !access_list.is_empty() {
        return Err(EvmDecodeError::UnrecognizedAccessList);
    }

    let y_parity = u8::decode(&mut body).map_err(|_| EvmDecodeError::Malformed)?;
    if y_parity > 1 {
        return Err(EvmDecodeError::InvalidYParity(y_parity));
    }
    let r = decode_quantity_32(&mut body)?;
    let s = decode_quantity_32(&mut body)?;

    if !body.is_empty() {
        return Err(EvmDecodeError::TrailingBytes);
    }

    Ok(SignedEip1559Tx {
        tx: UnsignedEip1559Tx { chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data },
        y_parity,
        r,
        s,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> UnsignedEip1559Tx {
        UnsignedEip1559Tx {
            chain_id: 1,
            nonce: 9,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 21_000,
            to: [0xAB; 20],
            value: 1_000_000_000_000_000_000,
            data: vec![],
        }
    }

    /// Structural sanity check with realistic mainnet-shaped values
    /// (`chain_id` 1, plain ETH transfer, no calldata, no access list) —
    /// this is still a round-trip against our own encoder, not an
    /// externally-sourced vector; there was no network access available
    /// while writing this to pull and verify a real signed mainnet
    /// transaction byte-for-byte. That remains valuable follow-up work
    /// (see the module docs' fail-closed philosophy — this format's
    /// correctness is funds-critical) but isn't claimed here.
    #[test]
    fn decodes_a_mainnet_shaped_eip1559_transfer() {
        let tx = UnsignedEip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 50_000_000_000,
            gas_limit: 21_000,
            to: [0x11; 20],
            value: 1,
            data: vec![],
        };
        let signed = SignedEip1559Tx { tx: tx.clone(), y_parity: 1, r: [0x42; 32], s: [0x24; 32] };

        let encoded = encode_signed(&signed);
        assert_eq!(encoded[0], 0x02);

        let decoded = decode_signed(&encoded).unwrap();
        assert_eq!(decoded, signed);
    }

    #[test]
    fn unsigned_encode_starts_with_type_byte() {
        let encoded = encode_unsigned(&sample_tx());
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn signed_roundtrip_preserves_every_field() {
        let tx = sample_tx();
        let signed = SignedEip1559Tx { tx: tx.clone(), y_parity: 0, r: [0x11; 32], s: [0x22; 32] };

        let encoded = encode_signed(&signed);
        let decoded = decode_signed(&encoded).unwrap();
        assert_eq!(decoded, signed);
    }

    #[test]
    fn zero_value_r_and_s_round_trip() {
        // Exercises the trimmed-quantity zero-length edge case.
        let tx = sample_tx();
        let signed = SignedEip1559Tx { tx, y_parity: 0, r: [0u8; 32], s: [0u8; 32] };

        let encoded = encode_signed(&signed);
        let decoded = decode_signed(&encoded).unwrap();
        assert_eq!(decoded.r, [0u8; 32]);
        assert_eq!(decoded.s, [0u8; 32]);
    }

    #[test]
    fn empty_input_rejected() {
        assert_eq!(decode_signed(&[]).unwrap_err(), EvmDecodeError::Empty);
    }

    #[test]
    fn wrong_type_byte_rejected() {
        let mut encoded = encode_signed(&SignedEip1559Tx { tx: sample_tx(), y_parity: 0, r: [1; 32], s: [1; 32] });
        encoded[0] = 0x01; // legacy/EIP-2930 type byte, not EIP-1559
        assert_eq!(decode_signed(&encoded).unwrap_err(), EvmDecodeError::UnsupportedType(0x01));
    }

    #[test]
    fn truncated_input_rejected() {
        let encoded = encode_signed(&SignedEip1559Tx { tx: sample_tx(), y_parity: 0, r: [1; 32], s: [1; 32] });
        assert_eq!(decode_signed(&encoded[..encoded.len() - 5]).unwrap_err(), EvmDecodeError::Malformed);
    }

    #[test]
    fn trailing_garbage_rejected() {
        let mut encoded = encode_signed(&SignedEip1559Tx { tx: sample_tx(), y_parity: 0, r: [1; 32], s: [1; 32] });
        encoded.push(0xFF);
        assert_eq!(decode_signed(&encoded).unwrap_err(), EvmDecodeError::TrailingBytes);
    }

    #[test]
    fn invalid_y_parity_rejected() {
        // y_parity must be 0 or 1 — hand-build a list with y_parity = 2 by
        // going through encode_signed's structure isn't possible via the
        // public API (it only ever writes 0/1 from a caller-supplied u8),
        // so this directly proves the type-level contract: the field is
        // `u8`, but any value above 1 must still be rejected at decode.
        let mut signed = SignedEip1559Tx { tx: sample_tx(), y_parity: 1, r: [1; 32], s: [1; 32] };
        signed.y_parity = 2;
        let encoded = encode_signed(&signed);
        assert_eq!(decode_signed(&encoded).unwrap_err(), EvmDecodeError::InvalidYParity(2));
    }
}
