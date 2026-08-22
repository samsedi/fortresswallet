//! Contract: the decoder must REJECT (return Err) on any input that is:
//! - Truncated
//! - Ambiguous (could be interpreted multiple ways)
//! - Unrecognized (unknown function selector / data format)
//!
//! It must NEVER silently pass through raw bytes for signing.
//!
//! Each test is `#[ignore]`d, not an empty no-op — see the note in
//! `wallet-core/tests/architecture.rs` for why that distinction matters.
//! When `wallet_decoder::decode` exists, un-ignore each test and fill in
//! the real assertion; that's also the point to add `cargo-fuzz` against
//! this same entry point, since it's the highest-value fuzz target in the
//! wallet (it parses fully untrusted input, one call away from signing).

#[test]
#[ignore = "wallet_decoder::decode does not exist yet"]
fn empty_input_rejected() {
    // assert!(wallet_decoder::decode(b"").is_err());
}

#[test]
#[ignore = "wallet_decoder::decode does not exist yet"]
fn truncated_calldata_rejected() {
    // A valid function selector (4 bytes) but missing arguments
    // assert!(wallet_decoder::decode(&[0xa9, 0x05, 0x9c, 0xbb]).is_err());
}

#[test]
#[ignore = "wallet_decoder::decode does not exist yet"]
fn unknown_function_selector_rejected() {
    // Random 4 bytes that don't match any known ABI
    // assert!(wallet_decoder::decode(&[0xde, 0xad, 0xbe, 0xef]).is_err());
}

#[test]
#[ignore = "wallet_decoder::decode does not exist yet"]
fn oversized_input_rejected() {
    // 100 KB of data — should be rejected, not parsed forever
    // let huge = vec![0u8; 100_000];
    // assert!(wallet_decoder::decode(&huge).is_err());
}
