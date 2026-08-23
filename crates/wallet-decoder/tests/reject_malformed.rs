//! Contract: the decoder must REJECT (return Err) on any input that is:
//! - Truncated
//! - Ambiguous (could be interpreted multiple ways)
//! - Unrecognized (unknown function selector / data format)
//!
//! It must NEVER silently pass through raw bytes for signing.
//!
//! These were `#[ignore]`d skeletons until `wallet_decoder::decode`
//! existed — see `src/lib.rs`'s unit tests for the fuller coverage
//! (truncated header, truncated calldata, unsupported version, exact
//! error variants). These four are kept as the original external-API
//! sanity check: proof the public `decode` function itself, called from
//! outside the crate, rejects each category the module doc promises to.
//!
//! `cargo-fuzz` against this same entry point is still open follow-up
//! work — it's the highest-value fuzz target in the wallet (fully
//! untrusted input, one call away from signing) and hasn't been set up
//! yet.

use wallet_decoder::decode;

#[test]
fn empty_input_rejected() {
    assert!(decode(b"").is_err());
}

#[test]
fn truncated_calldata_rejected() {
    // Fewer bytes than the fixed header requires.
    assert!(decode(&[0xa9, 0x05, 0x9c, 0xbb]).is_err());
}

#[test]
fn unknown_function_selector_rejected() {
    // This decoder doesn't parse function selectors (it isn't an ABI
    // decoder — see the scope note in src/lib.rs), so the equivalent
    // "unrecognized" case is any non-empty calldata at all: build a
    // well-formed header, then append 4 bytes of calldata this decoder
    // has no understanding of.
    let mut raw = wallet_decoder::encode_transfer(1, [0xAB; 20], 42);
    let len = raw.len();
    raw[len - 2..].copy_from_slice(&4u16.to_be_bytes());
    raw.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    assert!(decode(&raw).is_err());
}

#[test]
fn oversized_input_rejected() {
    let huge = vec![0u8; 100_000];
    assert!(decode(&huge).is_err());
}
