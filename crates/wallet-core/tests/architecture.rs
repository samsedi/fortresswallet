//! Integration tests that verify the security contracts between crates.
//! These are not unit tests — they test the *boundaries*, not the internals.
//!
//! Both tests below are `#[ignore]`d rather than empty no-ops: an empty
//! `#[test] fn` body compiles, runs, and reports green with zero actual
//! coverage, which is worse than no test at all — it's a false signal
//! that the contract is verified when it isn't. `#[ignore]` makes that
//! honest: `cargo test` shows these as skipped, not passed, until the
//! real assertions replace the TODO comments below.

/// wallet-core must be the ONLY orchestrator that connects crypto ↔ storage.
/// No other crate should import both.
#[test]
#[ignore = "wallet-core has no signing/decoding API yet — fill in once it does"]
fn signing_requires_decoded_transaction() {
    // When wallet-decoder is implemented, this test should verify:
    // 1. You cannot call sign_prehash without first successfully decoding
    //    the transaction through wallet-decoder
    // 2. A failed decode MUST prevent signing — no "sign raw hex" fallback
    //
    // let raw_tx = b"\xff\xff\xff"; // garbage
    // let decode_result = wallet_decoder::decode(raw_tx);
    // assert!(decode_result.is_err());
    // // There should be no API path to sign without a successful decode
}

/// Passphrase must never be stored or logged — only passed transiently.
#[test]
#[ignore = "wallet-core has no Wallet struct yet — fill in once it does"]
fn passphrase_is_not_stored_in_wallet_state() {
    // When wallet-core has a Wallet struct, verify it does NOT hold
    // the passphrase as a field. It should only accept it as a
    // function parameter when needed (unlock/sign), then drop it.
}
