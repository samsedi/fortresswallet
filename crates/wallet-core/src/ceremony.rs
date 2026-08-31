//! Threshold ECDSA signing ceremony: takes `threshold`-many shares of a
//! Shamir-split key, reconstructs it just long enough to produce one
//! signature, and destroys the reconstructed key immediately afterward.
//!
//! This is the Phase 3 protocol tradeoff made explicit at the
//! orchestration layer: the full private key does exist, briefly, in one
//! place during this call — never before it, never after it returns.
//! `PrivateKey`'s own zeroize-on-drop / mlock-pinned-memory guarantees
//! (from `wallet-crypto`) bound how protected that window is; this
//! function's only added job is to make the window itself as small as
//! possible: reconstruct, sign, drop the key, *then* verify the result —
//! nothing after the drop still touches the reconstructed key.

use std::time::SystemTime;

use wallet_crypto::keys::{PrivateKey, PublicKey, RecoveryId, Signature};
use wallet_crypto::shamir::{self, reconstruct_and_verify, Share, ShamirError};

use crate::policy::{DenialReason, PolicyDecision, PolicyEngine};

/// Generate a fresh private key and immediately split it into `n` Shamir
/// shares, returning only the group public key and the shares.
///
/// This is the trusted-dealer DKG ceremony, and this function *is* the
/// dealer: the full private key is created, split, and dropped (zeroized,
/// unlocked) inside this one call — it is never returned to the caller.
/// This closes a real gap in just calling `PrivateKey::generate()` then
/// `split()` separately: nothing would stop a caller from holding onto
/// that full key for a while before splitting it (or forgetting to split
/// it at all), which defeats the entire point of the threshold model.
/// Routing key generation through this function instead means the full
/// key's lifetime is provably bounded to one function call, not left to
/// caller discipline.
pub fn generate_and_split_key(threshold: u8, n: u8) -> Result<(PublicKey, Vec<Share>), ShamirError> {
    let key = PrivateKey::generate();
    let public_key = key.public_key();
    let shares = shamir::split(&key, threshold, n)?;
    // `key` drops here — zeroized, unlocked — before returning.
    Ok((public_key, shares))
}

/// Errors from a threshold signing ceremony.
#[derive(Debug)]
pub enum CeremonyError {
    /// The shares didn't reconstruct to the expected group key — see
    /// `wallet_crypto::shamir::ShamirError` for why (wrong count,
    /// corrupted share, shares from a different split, ...).
    Reconstruction(ShamirError),
    /// The reconstructed key signed the digest, but the resulting
    /// signature failed to verify against the group public key. Should be
    /// unreachable — RFC 6979 signing is deterministic and correct by
    /// construction — kept as a fail-closed belt-and-suspenders check
    /// rather than trusting `sign_prehash` blindly.
    SignatureSelfCheckFailed,
}

/// Sign `digest` using exactly `threshold` shares of a Shamir-split key.
/// The reconstructed private key exists only for the span of one
/// `sign_prehash` call inside this function — see the module docs.
///
/// This is a low-level primitive: it signs whatever 32 bytes it's given,
/// with no requirement that they came from a decoded transaction. That's
/// deliberate — protocol-internal code, tests, and non-transaction
/// signing needs all go through this. It is NOT the entry point for
/// spending funds; a real wallet frontend should call `sign_transaction`
/// instead, which enforces decode-before-sign. See the module docs.
pub fn sign_with_shares(shares: &[Share], expected_public_key: &PublicKey, digest: &[u8; 32]) -> Result<Signature, CeremonyError> {
    let key = reconstruct_and_verify(shares, expected_public_key).map_err(CeremonyError::Reconstruction)?;
    let signature = key.sign_prehash(digest);
    drop(key);

    if expected_public_key.verify_prehash(digest, &signature) {
        Ok(signature)
    } else {
        Err(CeremonyError::SignatureSelfCheckFailed)
    }
}

/// Same contract as `sign_with_shares`, additionally returning the
/// recovery id — needed for chains (EVM) whose signed transaction format
/// embeds it instead of the signer's public key. See `wallet_core::evm`.
pub fn sign_with_shares_recoverable(
    shares: &[Share],
    expected_public_key: &PublicKey,
    digest: &[u8; 32],
) -> Result<(Signature, RecoveryId), CeremonyError> {
    let key = reconstruct_and_verify(shares, expected_public_key).map_err(CeremonyError::Reconstruction)?;
    let (signature, recovery_id) = key.sign_prehash_recoverable(digest);
    drop(key);

    if expected_public_key.verify_prehash(digest, &signature) {
        Ok((signature, recovery_id))
    } else {
        Err(CeremonyError::SignatureSelfCheckFailed)
    }
}

/// Errors from `sign_transaction`.
#[derive(Debug)]
pub enum TransactionSigningError {
    /// `raw_tx` failed to decode — see `wallet_decoder::DecodeError`.
    /// This is the fail-closed path: a failed decode never reaches
    /// signing, there is no "sign the raw bytes anyway" fallback.
    Decode(wallet_decoder::DecodeError),
    /// Decoding succeeded, but the ceremony itself failed — see
    /// `CeremonyError`.
    Ceremony(CeremonyError),
}

/// Decode-then-sign, with NO spending policy applied — see
/// `sign_transaction_with_policy` below, which is the entry point a real
/// wallet frontend letting a user initiate a transaction should call
/// instead. This function exists for cases with no policy requirement
/// (protocol-internal signing, tests) and deliberately bypasses the
/// per-tx cap, velocity limit, and timelock — a caller that has spending
/// policy configured but calls this instead of `sign_transaction_with_policy`
/// gets none of those protections, silently. `sign_transaction_bypasses_policy_by_design`
/// in this module's tests demonstrates and guards this distinction.
///
/// Decodes `raw_tx` first (fail closed on anything unrecognized — see
/// `wallet_decoder`'s module docs), then signs the canonical hash of what
/// was actually decoded, never the caller-supplied raw bytes directly.
/// There is no code path in this function that reaches `sign_with_shares`
/// without a successful decode.
pub fn sign_transaction(raw_tx: &[u8], shares: &[Share], expected_public_key: &PublicKey) -> Result<Signature, TransactionSigningError> {
    let decoded = wallet_decoder::decode(raw_tx).map_err(TransactionSigningError::Decode)?;
    let digest = wallet_crypto::sha256(&decoded.canonical_bytes());
    sign_with_shares(shares, expected_public_key, &digest).map_err(TransactionSigningError::Ceremony)
}

/// Errors from `sign_transaction_with_policy`.
#[derive(Debug)]
pub enum PolicyGuardedSigningError {
    /// `raw_tx` failed to decode — same fail-closed path as
    /// `TransactionSigningError::Decode`.
    Decode(wallet_decoder::DecodeError),
    /// Denied outright by spending policy — see `DenialReason`. The
    /// ceremony never runs; the key is never reconstructed for a denied
    /// transaction.
    Denied(DenialReason),
    /// Not denied, but not immediately approved either — the caller must
    /// hold this transaction and retry no earlier than `release_at`. See
    /// `wallet_core::policy`'s module docs for why this crate doesn't
    /// implement that queue/retry itself.
    Queued {
        /// Earliest time this transaction may be re-submitted.
        release_at: SystemTime,
    },
    /// Policy approved, but the ceremony itself failed — see
    /// `CeremonyError`. Policy history is not updated in this case (see
    /// `PolicyEngine::record_approved`'s contract).
    Ceremony(CeremonyError),
}

/// The policy-guarded entry point for spending funds: decode, then check
/// spending policy, then sign — in that order, so a denied or queued
/// transaction never reaches the signing ceremony at all (the key is
/// never reconstructed for it). Policy history (`PolicyEngine::
/// record_approved`) is only updated after a real signature is produced,
/// not on policy approval alone — a ceremony failure after approval
/// doesn't consume velocity budget for a transaction that never signed.
pub fn sign_transaction_with_policy(
    raw_tx: &[u8],
    shares: &[Share],
    expected_public_key: &PublicKey,
    policy: &mut PolicyEngine,
    now: SystemTime,
) -> Result<Signature, PolicyGuardedSigningError> {
    let decoded = wallet_decoder::decode(raw_tx).map_err(PolicyGuardedSigningError::Decode)?;

    match policy.evaluate(&decoded, now) {
        PolicyDecision::Denied(reason) => return Err(PolicyGuardedSigningError::Denied(reason)),
        PolicyDecision::Queued { release_at } => return Err(PolicyGuardedSigningError::Queued { release_at }),
        PolicyDecision::Approved => {}
    }

    let digest = wallet_crypto::sha256(&decoded.canonical_bytes());
    let signature = sign_with_shares(shares, expected_public_key, &digest).map_err(PolicyGuardedSigningError::Ceremony)?;

    policy.record_approved(&decoded, now);
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wallet_crypto::shamir::split;

    fn permissive_policy() -> crate::policy::PolicyEngine {
        crate::policy::PolicyEngine::new(crate::policy::PolicyConfig {
            max_single_tx_value: u128::MAX,
            max_value_per_window: u128::MAX,
            window: Duration::from_secs(3600),
            timelock_threshold: u128::MAX, // never queue
            timelock_delay: Duration::from_secs(1),
        })
    }

    /// Not a real hash — just a deterministic, distinct 32-byte stand-in
    /// for "the thing being signed." These tests only check reconstruction
    /// and signature-agreement behavior, not hash-function properties, so
    /// pulling in a real SHA-256 dependency here isn't warranted — and
    /// would defeat the point of keeping `k256` contained to
    /// `wallet-crypto` (see the `Signature` re-export doc comment there).
    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, b) in bytes.iter().enumerate() {
            d[i % 32] ^= *b;
        }
        d
    }

    #[test]
    fn sign_with_shares_produces_valid_signature() {
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let shares = split(&key, 2, 3).unwrap();
        let d = digest(b"send 1 BTC to alice");

        let sig = sign_with_shares(&shares[0..2], &public_key, &d).unwrap();
        assert!(public_key.verify_prehash(&d, &sig));
    }

    #[test]
    fn ceremony_signature_matches_direct_single_party_signature() {
        // RFC 6979 determinism, end to end: signing the same digest with
        // the reconstructed key must be byte-identical to signing it
        // directly with the original, unsplit key.
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let d = digest(b"same digest, two signing paths");
        let direct_sig = key.sign_prehash(&d);

        let shares = split(&key, 2, 3).unwrap();
        let ceremony_sig = sign_with_shares(&shares[0..2], &public_key, &d).unwrap();

        assert_eq!(direct_sig, ceremony_sig);
    }

    #[test]
    fn different_share_subsets_produce_identical_signatures() {
        // sign_with_shares only borrows (`&[Share]`), so the same split()
        // output can back two different contiguous-slice subsets without
        // needing to clone/copy any Share (which deliberately has no
        // public Clone, since it holds secret material).
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let d = digest(b"any qualifying subset should agree");
        let shares = split(&key, 2, 3).unwrap();

        let sig_a = sign_with_shares(&shares[0..2], &public_key, &d).unwrap();
        let sig_b = sign_with_shares(&shares[1..3], &public_key, &d).unwrap();

        assert_eq!(sig_a, sig_b);
    }

    #[test]
    fn below_threshold_shares_refuse_to_sign() {
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let shares = split(&key, 3, 5).unwrap();
        let d = digest(b"attacker with too few shares");

        let result = sign_with_shares(&shares[0..2], &public_key, &d);
        assert!(matches!(result, Err(CeremonyError::Reconstruction(ShamirError::WrongShareCount))));
    }

    #[test]
    fn corrupted_share_refuses_to_sign() {
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let mut shares = split(&key, 2, 3).unwrap();
        let d = digest(b"attacker with a tampered share");

        // Corrupt one share by swapping in a completely different key's
        // share at the same (index, threshold) shape — an ownership move
        // via Vec::remove, no Clone needed.
        let other_key = PrivateKey::generate();
        let mut other_shares = split(&other_key, 2, 3).unwrap();
        shares[0] = other_shares.remove(0);

        let result = sign_with_shares(&shares[0..2], &public_key, &d);
        assert!(matches!(result, Err(CeremonyError::Reconstruction(ShamirError::ReconstructionMismatch))));
    }

    #[test]
    fn generated_and_split_key_can_sign_through_the_ceremony() {
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let d = digest(b"dkg-generated key signs fine");

        let sig = sign_with_shares(&shares[0..2], &public_key, &d).unwrap();
        assert!(public_key.verify_prehash(&d, &sig));
    }

    #[test]
    fn generate_and_split_key_propagates_threshold_validation() {
        assert_eq!(generate_and_split_key(1, 3).unwrap_err(), ShamirError::ThresholdTooSmall);
        assert_eq!(generate_and_split_key(4, 3).unwrap_err(), ShamirError::ThresholdExceedsParties);
    }

    #[test]
    fn two_dkg_ceremonies_produce_independent_keys() {
        let (public_key_a, _) = generate_and_split_key(2, 3).unwrap();
        let (public_key_b, _) = generate_and_split_key(2, 3).unwrap();
        assert_ne!(public_key_a, public_key_b);
    }

    #[test]
    fn sign_transaction_signs_a_well_formed_transfer() {
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let raw_tx = wallet_decoder::encode_transfer(1, [0xAB; 20], 42);

        let sig = sign_transaction(&raw_tx, &shares[0..2], &public_key).unwrap();

        let decoded = wallet_decoder::decode(&raw_tx).unwrap();
        let digest = wallet_crypto::sha256(&decoded.canonical_bytes());
        assert!(public_key.verify_prehash(&digest, &sig));
    }

    #[test]
    fn sign_transaction_refuses_garbage_bytes() {
        // The core guarantee: garbage that fails to decode must never
        // reach signing, regardless of how many valid shares are handed
        // to this call.
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let garbage = b"\xff\xff\xff not a real transaction";

        let result = sign_transaction(garbage, &shares[0..2], &public_key);
        assert!(matches!(result, Err(TransactionSigningError::Decode(_))));
    }

    #[test]
    fn sign_transaction_refuses_transactions_with_calldata() {
        // Same fail-closed path, exercised through the transaction
        // signing entry point rather than calling wallet_decoder directly.
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let mut raw_tx = wallet_decoder::encode_transfer(1, [0xAB; 20], 42);
        let len = raw_tx.len();
        raw_tx[len - 2..].copy_from_slice(&4u16.to_be_bytes());
        raw_tx.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let result = sign_transaction(&raw_tx, &shares[0..2], &public_key);
        assert!(matches!(result, Err(TransactionSigningError::Decode(_))));
    }

    #[test]
    fn sign_transaction_bypasses_policy_by_design() {
        // O-2: sign_transaction has no policy parameter at all, so it
        // cannot enforce spending limits — demonstrated here rather than
        // just asserted in a doc comment, so a future change to either
        // function's behavior breaks this test instead of silently
        // drifting. A real wallet frontend must call
        // sign_transaction_with_policy, never this one, when a user is
        // initiating a spend.
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let raw_tx = wallet_decoder::encode_transfer(1, [0xAB; 20], 1_000_000);

        // A policy that would deny this transaction outright...
        let mut policy = crate::policy::PolicyEngine::new(crate::policy::PolicyConfig {
            max_single_tx_value: 0,
            max_value_per_window: u128::MAX,
            window: Duration::from_secs(3600),
            timelock_threshold: u128::MAX,
            timelock_delay: Duration::from_secs(1),
        });
        let guarded = sign_transaction_with_policy(&raw_tx, &shares[0..2], &public_key, &mut policy, SystemTime::now());
        assert!(matches!(guarded, Err(PolicyGuardedSigningError::Denied(_))));

        // ...but sign_transaction (no policy parameter to pass one to)
        // signs it anyway.
        let unguarded = sign_transaction(&raw_tx, &shares[0..2], &public_key);
        assert!(unguarded.is_ok(), "sign_transaction has no policy to enforce and must not accidentally gain one silently");
    }

    #[test]
    fn policy_guarded_signs_when_approved() {
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let dest = [0xAB; 20];
        let raw_tx = wallet_decoder::encode_transfer(1, dest, 42);
        let mut policy = permissive_policy();
        let now = SystemTime::now();

        // A brand-new destination always queues on first contact, by
        // design (see PolicyEngine) — pre-seed it as known so this test
        // isolates "policy approved => signs", not the new-destination
        // timelock rule (that's covered by the policy module's own tests
        // and by policy_history_updates_only_after_a_real_signature).
        let decoded = wallet_decoder::decode(&raw_tx).unwrap();
        policy.record_approved(&decoded, now);

        let sig = sign_transaction_with_policy(&raw_tx, &shares[0..2], &public_key, &mut policy, now).unwrap();
        let digest = wallet_crypto::sha256(&decoded.canonical_bytes());
        assert!(public_key.verify_prehash(&digest, &sig));
    }

    #[test]
    fn policy_denial_never_reaches_the_ceremony() {
        // A single-tx cap of 0 denies any positive-value transaction —
        // proven by passing shares that DON'T even match a real split,
        // which would fail the ceremony differently (Reconstruction
        // error) if policy hadn't already blocked it first.
        let (public_key, real_shares) = generate_and_split_key(2, 3).unwrap();
        let (_, wrong_shares) = generate_and_split_key(2, 3).unwrap();
        let _ = real_shares; // unused: proving the wrong shares never get far enough to matter

        let raw_tx = wallet_decoder::encode_transfer(1, [0xAB; 20], 1);
        let mut policy = crate::policy::PolicyEngine::new(crate::policy::PolicyConfig {
            max_single_tx_value: 0,
            max_value_per_window: u128::MAX,
            window: Duration::from_secs(3600),
            timelock_threshold: u128::MAX,
            timelock_delay: Duration::from_secs(1),
        });

        let result = sign_transaction_with_policy(&raw_tx, &wrong_shares[0..2], &public_key, &mut policy, SystemTime::now());
        assert!(matches!(
            result,
            Err(PolicyGuardedSigningError::Denied(crate::policy::DenialReason::ExceedsSingleTxCap))
        ));
    }

    #[test]
    fn policy_queue_never_reaches_the_ceremony() {
        let (public_key, wrong_shares) = generate_and_split_key(2, 3).unwrap();
        let raw_tx = wallet_decoder::encode_transfer(1, [0xAB; 20], 1);
        // Default-permissive except timelock_threshold: 0 means every tx queues.
        let mut policy = crate::policy::PolicyEngine::new(crate::policy::PolicyConfig {
            max_single_tx_value: u128::MAX,
            max_value_per_window: u128::MAX,
            window: Duration::from_secs(3600),
            timelock_threshold: 0,
            timelock_delay: Duration::from_secs(1),
        });

        let result = sign_transaction_with_policy(&raw_tx, &wrong_shares[0..2], &public_key, &mut policy, SystemTime::now());
        assert!(matches!(result, Err(PolicyGuardedSigningError::Queued { .. })));
    }

    #[test]
    fn policy_history_updates_only_after_a_real_signature() {
        let (public_key, shares) = generate_and_split_key(2, 3).unwrap();
        let dest = [0xAB; 20];
        let now = SystemTime::now();
        let mut policy = permissive_policy();

        // First transfer to this destination: new destination, but the
        // permissive policy's timelock_threshold is u128::MAX so value
        // alone never triggers it — the destination itself being new
        // does, per PolicyEngine's rule. Use a policy with
        // timelock_threshold high enough but the destination check still
        // applies... to isolate velocity behavior here, use a policy
        // where every destination is effectively pre-approved by giving
        // it a single call first.
        let raw_tx = wallet_decoder::encode_transfer(1, dest, 10);
        // This queues (new destination) with the permissive policy since
        // new-destination timelocking isn't bypassed by value alone.
        let first = sign_transaction_with_policy(&raw_tx, &shares[0..2], &public_key, &mut policy, now);
        assert!(matches!(first, Err(PolicyGuardedSigningError::Queued { .. })));

        // A signature was never produced, so history must be untouched:
        // signing the exact same transaction again should queue again,
        // not suddenly succeed as if it were now a known destination.
        let second = sign_transaction_with_policy(&raw_tx, &shares[0..2], &public_key, &mut policy, now);
        assert!(matches!(second, Err(PolicyGuardedSigningError::Queued { .. })));
    }

    #[test]
    fn wrong_expected_public_key_refuses_to_sign() {
        let key = PrivateKey::generate();
        let wrong_public_key = PrivateKey::generate().public_key();
        let shares = split(&key, 2, 3).unwrap();
        let d = digest(b"caller passed the wrong group public key");

        let result = sign_with_shares(&shares[0..2], &wrong_public_key, &d);
        assert!(matches!(result, Err(CeremonyError::Reconstruction(ShamirError::ReconstructionMismatch))));
    }
}
