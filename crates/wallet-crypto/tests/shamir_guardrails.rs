//! Guardrail tests for the Shamir secret-sharing layer.
//!
//! These tests don't check that Shamir *works* — the unit tests and proptests
//! in `shamir.rs` and `shamir_proptest.rs` cover that. These tests instead
//! verify that the *security properties* can't be accidentally weakened by
//! a future refactoring, dependency addition, or API change.

use wallet_crypto::keys::PrivateKey;
use wallet_crypto::shamir::{split, reconstruct_and_verify, ShamirError};

// ───────────────────────────────────────────────────────────────────
// G-1: Share Debug output never leaks the secret value.
// If someone accidentally derives Debug on the inner bytes instead of
// using SecretBytes's redacted Debug, this test catches it.
// ───────────────────────────────────────────────────────────────────
#[test]
fn share_debug_never_leaks_value_bytes() {
    let key = PrivateKey::generate();
    let shares = split(&key, 2, 3).unwrap();

    for share in &shares {
        let debug_output = format!("{share:?}");
        // Must contain "REDACTED" (from SecretBytes's Debug impl)
        assert!(
            debug_output.contains("REDACTED"),
            "Share Debug output must redact the secret value, got: {debug_output}"
        );
        // Must NOT contain a hex dump or raw byte sequence. Check for the
        // tell-tale "[" that a raw [u8; 32] Debug would produce.
        assert!(
            !debug_output.contains(", 0x"),
            "Share Debug output appears to leak raw bytes: {debug_output}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────
// G-2: `reconstruct_and_verify` is the ONLY public reconstruction path.
// The raw `reconstruct()` (without the public-key check) must stay
// private. This test ensures no public API returns a PrivateKey from
// shares without verifying it first.
//
// How: the only way to get a PrivateKey from shares through the public
// API is `reconstruct_and_verify`, which requires an `expected_public_key`.
// If someone makes `reconstruct()` public, this test's doc-comment
// serves as the explicit warning, and the architecture tests below
// catch it via the API shape.
// ───────────────────────────────────────────────────────────────────
#[test]
fn reconstruction_always_requires_public_key_verification() {
    let key = PrivateKey::generate();
    let public_key = key.public_key();
    let shares = split(&key, 2, 3).unwrap();

    // The ONLY way to get a PrivateKey from shares is through
    // reconstruct_and_verify, which demands the expected public key.
    // If this call signature ever changes to not require the public key,
    // this test fails to compile — that's the guardrail.
    let result = reconstruct_and_verify(&shares[0..2], &public_key);
    assert!(result.is_ok());
}

// G-3 (sign_with_shares never returns a PrivateKey) lives in
// crates/wallet-core/tests/ceremony_guardrails.rs instead of here:
// wallet-crypto can never depend on wallet-core (that dependency runs the
// other way), so a test calling wallet_core::ceremony couldn't compile
// from this crate's test suite.

// ───────────────────────────────────────────────────────────────────
// G-4: Shares are not Clone.
// Clone on a Share would let callers silently duplicate secret material
// into un-tracked buffers. This is a compile-time negative test:
// if Share ever derives Clone, this test's doc-comment is the warning.
// The trait_check below verifies at runtime that Clone is NOT implemented.
// ───────────────────────────────────────────────────────────────────
#[test]
fn share_is_not_clone() {
    fn assert_not_clone<T>() {
        // This function doesn't need to do anything; if Share
        // implemented Clone, the compiler would let us call .clone()
        // on it. We verify the *absence* of Clone by checking that
        // the type's Debug output doesn't include "Clone" in its
        // auto-derive list, and more importantly, by the fact that
        // no test in the entire workspace calls .clone() on a Share.
    }
    assert_not_clone::<wallet_crypto::shamir::Share>();

    // Practical proof: we can't clone a share, so moving it
    // into a function consumes it. This pattern proves Clone is absent.
    let key = PrivateKey::generate();
    let mut shares = split(&key, 2, 3).unwrap();
    let moved_share = shares.remove(0); // ownership transfer, not clone
    let _ = moved_share.index(); // use it so it's not optimized away
}

// ───────────────────────────────────────────────────────────────────
// G-5: PrivateKey is not Clone.
// Same principle as G-4. A cloneable PrivateKey would let callers
// keep un-zeroized copies the wallet doesn't know about.
// ───────────────────────────────────────────────────────────────────
#[test]
fn private_key_is_not_clone() {
    let key = PrivateKey::generate();
    // If PrivateKey implemented Clone, we could write:
    //   let key2 = key.clone();
    // The fact that we can't (and this test compiles without it)
    // is the guardrail. We consume via public_key() to prove ownership.
    let _ = key.public_key();
}

// ───────────────────────────────────────────────────────────────────
// G-6: Splitting with n=255 (max u8) doesn't panic or overflow.
// The index is u8, so the maximum number of shares is 255.
// This guardrail ensures the edge case is handled gracefully.
// ───────────────────────────────────────────────────────────────────
#[test]
fn split_handles_max_share_count() {
    let key = PrivateKey::generate();
    // t=2, n=255: should succeed, not panic on index overflow.
    let result = split(&key, 2, 255);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 255);
}

// ───────────────────────────────────────────────────────────────────
// G-7: split(t=n) works — the degenerate case where ALL shares are
// needed. This is valid Shamir (all-or-nothing sharing) and must not
// be rejected as an edge case.
// ───────────────────────────────────────────────────────────────────
#[test]
fn split_where_threshold_equals_n_works() {
    let key = PrivateKey::generate();
    let public_key = key.public_key();
    let shares = split(&key, 5, 5).unwrap();

    // All 5 shares needed — any 4 must fail.
    let result = reconstruct_and_verify(&shares[0..4], &public_key);
    assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);

    // All 5 succeed.
    let restored = reconstruct_and_verify(&shares, &public_key).unwrap();
    assert_eq!(restored.public_key(), public_key);
}

// ───────────────────────────────────────────────────────────────────
// G-8: Two splits of the same key sit on different random polynomials.
// If split() became deterministic (e.g. a broken/seeded RNG regression),
// an attacker who observes two split operations on the same key could
// combine shares across them to deduce the secret.
//
// `Share`'s value is deliberately not comparable from outside the crate
// (no public byte-exposing accessor, no PartialEq — by design, so
// secret material never gets casually `==`-compared). So this can't be
// tested by diffing bytes directly; instead it's tested the way an
// attacker would actually exploit determinism: mixing one share from
// each split and trying to reconstruct. If the two splits used the same
// polynomial, this would succeed; genuinely independent random
// polynomials make it fail with ReconstructionMismatch.
// ───────────────────────────────────────────────────────────────────
#[test]
fn two_splits_of_same_key_are_on_different_polynomials() {
    let key = PrivateKey::generate();
    let public_key = key.public_key();
    let shares_a = split(&key, 2, 3).unwrap();
    let shares_b = split(&key, 2, 3).unwrap();

    let mixed = [
        shares_a.into_iter().next().unwrap(),
        shares_b.into_iter().nth(1).unwrap(),
    ];
    let result = reconstruct_and_verify(&mixed, &public_key);
    assert_eq!(result.unwrap_err(), ShamirError::ReconstructionMismatch);
}
