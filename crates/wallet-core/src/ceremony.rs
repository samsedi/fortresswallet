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

use wallet_crypto::keys::{PublicKey, Signature};
use wallet_crypto::shamir::{reconstruct_and_verify, Share, ShamirError};

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

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_crypto::keys::PrivateKey;
    use wallet_crypto::shamir::split;

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
    fn wrong_expected_public_key_refuses_to_sign() {
        let key = PrivateKey::generate();
        let wrong_public_key = PrivateKey::generate().public_key();
        let shares = split(&key, 2, 3).unwrap();
        let d = digest(b"caller passed the wrong group public key");

        let result = sign_with_shares(&shares[0..2], &wrong_public_key, &d);
        assert!(matches!(result, Err(CeremonyError::Reconstruction(ShamirError::ReconstructionMismatch))));
    }
}
