






//! Share recovery: replacing a lost Shamir share without ever creating a
//! new single point of failure, and without a separate "recovery admin"
//! or guardian group to manage or attack.
//!
//! The mechanism is proactive re-sharing: reconstruct the key from
//! `threshold`-many of the *existing* shares (the exact same quorum
//! required to sign a transaction — see `ceremony::sign_with_shares`),
//! then immediately re-split that same key into a fresh set of shares,
//! dropping the reconstructed key before returning. This directly avoids
//! the centralization risk an early threat-model pass on this project
//! flagged: "who holds the recovery share? If it's a single admin/server,
//! that bypasses the whole threshold model." Here, recovery requires the
//! same quorum signing does — there is no separate, weaker path.
//!
//! # Critical distinction: lost vs. compromised
//!
//! `rotate_shares` re-splits the **same underlying key** — the group
//! public key (the wallet's address) does not change. This is correct
//! and safe for a **lost** share: a device destroyed, a share-holder who
//! can no longer participate, a share file that's simply gone.
//!
//! It does **NOT** help against a **compromised** share: if an attacker
//! copied a share before it went missing, that copy is still a fully
//! valid Shamir share of the same key, forever — re-splitting the key
//! doesn't invalidate it, because the key itself hasn't changed. Old
//! shares from before a rotation remain cryptographically valid; this
//! module has no revocation mechanism for them (Shamir shares aren't
//! natively revocable). If a share may have been copied by an attacker,
//! the only correct response is a full key rotation — call
//! `generate_and_split_key` for a brand-new keypair (a new address) and
//! migrate funds from the old address to the new one. Treating
//! `rotate_shares` as sufficient recovery for a suspected compromise
//! would be actively wrong guidance, not just incomplete.

use wallet_crypto::keys::PublicKey;
use wallet_crypto::shamir::{self, reconstruct_and_verify, Share, ShamirError};

/// Reconstruct the key from `threshold`-many of `shares`, then
/// immediately re-split it into `new_n` fresh shares requiring
/// `new_threshold` of them to reconstruct. The group public key (wallet
/// address) is unchanged — this replaces missing shares, it does not
/// rotate to a new key. See the module docs for when this is (and is
/// not) the correct recovery response.
///
/// `new_threshold`/`new_n` may differ from the original split entirely —
/// e.g. recovering from 2-of-3 into 3-of-5 to add redundancy at the same
/// time as replacing a lost share.
pub fn rotate_shares(shares: &[Share], expected_public_key: &PublicKey, new_threshold: u8, new_n: u8) -> Result<Vec<Share>, ShamirError> {
    let key = reconstruct_and_verify(shares, expected_public_key)?;
    let new_shares = shamir::split(&key, new_threshold, new_n)?;
    // `key` drops here — zeroized, unlocked — before returning.
    Ok(new_shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_core_test_support::*;

    #[test]
    fn rotated_shares_preserve_the_same_public_key() {
        let (public_key, shares) = crate::ceremony::generate_and_split_key(2, 3).unwrap();

        let new_shares = rotate_shares(&shares[0..2], &public_key, 2, 3).unwrap();

        let restored = reconstruct_and_verify(&new_shares[0..2], &public_key).unwrap();
        assert_eq!(restored.public_key(), public_key);
    }

    #[test]
    fn rotated_shares_can_sign_through_the_normal_ceremony() {
        let (public_key, shares) = crate::ceremony::generate_and_split_key(2, 3).unwrap();
        let new_shares = rotate_shares(&shares[0..2], &public_key, 2, 3).unwrap();

        let sig = crate::ceremony::sign_with_shares(&new_shares[0..2], &public_key, &[0x42; 32]).unwrap();
        assert!(public_key.verify_prehash(&[0x42; 32], &sig));
    }

    #[test]
    fn recovery_can_change_threshold_and_party_count() {
        // 2-of-3 -> 3-of-5: replacing a lost share while also adding
        // redundancy, in one rotation.
        let (public_key, shares) = crate::ceremony::generate_and_split_key(2, 3).unwrap();
        let new_shares = rotate_shares(&shares[0..2], &public_key, 3, 5).unwrap();

        assert_eq!(new_shares.len(), 5);
        let restored = reconstruct_and_verify(&new_shares[0..3], &public_key).unwrap();
        assert_eq!(restored.public_key(), public_key);

        // Below the NEW threshold must still fail, proving the new split
        // actually took effect rather than just returning the old shares.
        let result = reconstruct_and_verify(&new_shares[0..2], &public_key);
        assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);
    }

    #[test]
    fn rotation_refuses_below_threshold_input_shares() {
        let (public_key, shares) = crate::ceremony::generate_and_split_key(3, 5).unwrap();

        let result = rotate_shares(&shares[0..2], &public_key, 2, 3);
        assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);
    }

    #[test]
    fn rotation_refuses_corrupted_input_shares() {
        let (public_key, mut shares) = crate::ceremony::generate_and_split_key(2, 3).unwrap();
        let (_, mut other_shares) = crate::ceremony::generate_and_split_key(2, 3).unwrap();
        shares[0] = other_shares.remove(0);

        let result = rotate_shares(&shares[0..2], &public_key, 2, 3);
        assert_eq!(result.unwrap_err(), ShamirError::ReconstructionMismatch);
    }

    #[test]
    fn old_shares_still_work_after_rotation_by_design() {
        // Documents the compromise caveat concretely, not just in prose:
        // rotation does NOT invalidate the shares it rotated away from.
        // If any of those old shares might have been copied by an
        // attacker, rotate_shares alone is not sufficient remediation —
        // see the module docs.
        let (public_key, shares) = crate::ceremony::generate_and_split_key(2, 3).unwrap();
        let _new_shares = rotate_shares(&shares[0..2], &public_key, 2, 3).unwrap();

        // The OLD shares, from before rotation, still reconstruct the
        // exact same key — proving they remain valid.
        let still_valid = reconstruct_and_verify(&shares[0..2], &public_key).unwrap();
        assert_eq!(still_valid.public_key(), public_key);
    }
}

/// Test-only re-export shim so the tests above can call
/// PublicKey::verify_prehash without a separate import line per test.
#[cfg(test)]
mod wallet_core_test_support {
    pub use wallet_crypto::keys::PublicKey;
}
