//! Guardrail tests for the threshold-signing ceremony.
//!
//! Like `wallet-crypto/tests/shamir_guardrails.rs`, these don't check that
//! signing *works* (the unit tests in `ceremony.rs` cover that) — they
//! check that a future refactor can't accidentally weaken the ceremony's
//! security shape.
//!
//! This file lives in `wallet-core`, not `wallet-crypto`, because it
//! exercises `wallet_core::ceremony` — `wallet-crypto` can never depend on
//! `wallet-core` (that dependency runs the other way), so a test calling
//! `sign_with_shares` cannot live in `wallet-crypto`'s test suite.

use wallet_core::ceremony::sign_with_shares;
use wallet_crypto::keys::{PrivateKey, Signature};
use wallet_crypto::shamir::split;

// ───────────────────────────────────────────────────────────────────
// G-3: sign_with_shares returns a Signature, never a PrivateKey.
// The ceremony API must never expose the reconstructed key to callers.
// This is a compile-time guardrail: if the return type ever changes to
// include the key, this stops compiling.
// ───────────────────────────────────────────────────────────────────
#[test]
fn ceremony_never_returns_private_key() {
    let key = PrivateKey::generate();
    let public_key = key.public_key();
    let shares = split(&key, 2, 3).unwrap();
    let digest = [0xABu8; 32];

    let result = sign_with_shares(&shares[0..2], &public_key, &digest);

    // This binding enforces the return type at compile time: if
    // sign_with_shares ever returns (Signature, PrivateKey) or similar,
    // this won't compile.
    let _sig: Signature = result.unwrap();
}
