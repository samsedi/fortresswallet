//! Integration tests that verify the security contracts between crates.
//! These are not unit tests — they test the *boundaries*, not the internals.

use wallet_core::ceremony::{generate_and_split_key, sign_transaction, TransactionSigningError};

/// wallet-core must be the ONLY orchestrator that connects crypto ↔ storage.
/// No other crate should import both.
///
/// This is no longer a skeleton: `wallet_decoder::decode` and
/// `wallet_core::ceremony::sign_transaction` both exist now (see
/// `crates/wallet-decoder/src/lib.rs` and `ceremony.rs`), so this checks
/// the real contract — garbage bytes that fail to decode must never
/// reach signing, regardless of how many valid shares are supplied.
#[test]
fn signing_requires_decoded_transaction() {
    let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
    let garbage = b"\xff\xff\xff"; // not a valid encoded transaction

    let result = sign_transaction(garbage, &shares[0..2], &public_key);
    assert!(
        matches!(result, Err(TransactionSigningError::Decode(_))),
        "a failed decode must block signing, not fall back to signing the raw bytes"
    );
}

/// Passphrase must never be stored or logged — only passed transiently.
#[test]
#[ignore = "wallet-core has no Wallet struct yet — fill in once it does"]
fn passphrase_is_not_stored_in_wallet_state() {
    // When wallet-core has a Wallet struct, verify it does NOT hold
    // the passphrase as a field. It should only accept it as a
    // function parameter when needed (unlock/sign), then drop it.
}
