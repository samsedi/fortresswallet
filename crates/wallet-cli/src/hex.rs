//! `0x`-prefixed hex parsing/formatting for addresses and transaction
//! hashes typed at the command line — kept local to the CLI rather than
//! added to any library crate, since this is purely a user-input
//! convenience with no reuse need elsewhere in the workspace.

use std::fmt;

/// A `0x`-prefixed hex string didn't decode to the expected byte length.
#[derive(Debug)]
pub(crate) struct HexParseError(String);

impl fmt::Display for HexParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HexParseError {}

fn parse_fixed<const N: usize>(s: &str, what: &str) -> Result<[u8; N], HexParseError> {
    let parsed = parse_hex(s)?;
    if parsed.len() != N {
        return Err(HexParseError(format!("{what} must be {} bytes ({} hex chars), got {} chars", N, N * 2, parsed.len() * 2)));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&parsed);
    Ok(out)
}

/// Parse a `0x`-prefixed arbitrary length hex string.
pub(crate) fn parse_hex(s: &str) -> Result<Vec<u8>, HexParseError> {
    let stripped = s.strip_prefix("0x").ok_or_else(|| HexParseError(format!("must be 0x-prefixed hex, got {s}")))?;
    if stripped.len() % 2 != 0 {
        return Err(HexParseError("hex string must have an even number of characters".to_string()));
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    for i in 0..(stripped.len() / 2) {
        let byte = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).map_err(|e| HexParseError(format!("invalid hex byte: {e}")))?;
        out.push(byte);
    }
    Ok(out)
}

/// Parse a `0x`-prefixed 20-byte address (case-insensitive — this does
/// not verify an EIP-55 checksum on input, only produces one on output
/// via `wallet_core::evm::to_checksummed_hex`).
pub(crate) fn parse_address(s: &str) -> Result<[u8; 20], HexParseError> {
    parse_fixed::<20>(s, "address")
}

/// Parse a `0x`-prefixed 32-byte transaction hash.
pub(crate) fn parse_tx_hash(s: &str) -> Result<[u8; 32], HexParseError> {
    parse_fixed::<32>(s, "transaction hash")
}

/// `0x`-prefixed lowercase hex encoding, for printing a tx hash.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_address() {
        let hex = format!("0x{}", "ab".repeat(20));
        assert_eq!(parse_address(&hex).unwrap(), [0xab; 20]);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(parse_address(&"ab".repeat(20)).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse_address("0xabcd").is_err());
    }

    #[test]
    fn hash_roundtrips_through_to_hex() {
        let hex = format!("0x{}", "cd".repeat(32));
        let hash = parse_tx_hash(&hex).unwrap();
        assert_eq!(to_hex(&hash), hex);
    }
}
