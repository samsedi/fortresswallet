//! t-of-n Shamir Secret Sharing over the secp256k1 scalar field.
//!
//! Threat model this closes: a single stolen device/file no longer yields
//! the private key — only `threshold` or more independently-held shares
//! do, and any `threshold - 1` shares reveal nothing about it
//! (information-theoretic, not just computational, secrecy below the
//! threshold).
//!
//! What it deliberately does NOT close: the full key IS transiently
//! reconstructed, in one locked/zeroized buffer, at signing time. A true
//! MPC scheme (FROST/GG20) never reconstructs it anywhere. This is the
//! documented scope tradeoff from the Phase 3 protocol decision — full
//! threshold ECDSA without reconstruction was judged too much complexity
//! to implement *and* rigorously verify correctly in this project.
//!
//! Plain Shamir has no built-in integrity check: feeding it the wrong
//! number of shares, or shares from two different splits, doesn't error —
//! it silently produces a different, wrong secret. `reconstruct_and_verify`
//! is what turns that into a loud, caught failure: it checks the
//! reconstructed key's public key against the group's known (non-secret)
//! public key before returning it.

use std::collections::HashSet;

use k256::elliptic_curve::ops::Reduce;
use k256::{Scalar, U256};

use crate::keys::{PrivateKey, PublicKey};
use crate::{SecretBytes, SecureRng, SecretScalar};

/// Errors from splitting or reconstructing a Shamir-shared key.
#[derive(Debug, PartialEq, Eq)]
pub enum ShamirError {
    /// `threshold` must be at least 2 — a threshold of 1 isn't sharing.
    ThresholdTooSmall,
    /// `threshold` can't exceed the number of shares being created.
    ThresholdExceedsParties,
    /// Two shares passed to `reconstruct` have the same index.
    DuplicateShareIndex,
    /// The number of shares passed doesn't equal their declared threshold.
    WrongShareCount,
    /// The shares passed don't all declare the same threshold — they're
    /// not from the same split.
    ThresholdMismatch,
    /// Share index 0 is reserved (it's where the secret itself lives on
    /// the polynomial); a share can never legitimately carry it.
    ZeroIndexReserved,
    /// Reconstruction produced a key that doesn't match the expected
    /// public key — wrong/corrupted/mismatched shares. The reconstructed
    /// bytes are discarded, not returned.
    ReconstructionMismatch,
}

/// One party's share of a split private key. Only `value` is secret;
/// `index`/`threshold` are metadata safe to store or transmit alongside
/// the (separately encrypted) share value. `Debug` is safe to derive —
/// `SecretBytes`'s own `Debug` impl redacts `value`.
#[derive(Debug)]
pub struct Share {
    index: u8,
    threshold: u8,
    value: SecretBytes<32>,
}

impl Share {
    /// This share's position on the polynomial (1..=n; 0 is reserved).
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The threshold this share was created under.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Raw share value bytes, for encrypted storage. Same `_dangerous`
    /// convention as `PrivateKey::to_bytes_dangerous` — hand the result
    /// straight to an AEAD-encrypting sink, never to a log or plain file.
    pub fn to_bytes_dangerous(&self) -> [u8; 32] {
        *self.value.expose()
    }

    /// Reconstruct a share from its public metadata plus raw value bytes
    /// (e.g. decrypted from storage). No validation beyond byte length is
    /// possible here — `reconstruct_and_verify`'s public-key check is
    /// what ultimately catches a corrupted or wrong share.
    pub fn from_parts_dangerous(index: u8, threshold: u8, bytes: [u8; 32]) -> Self {
        Self { index, threshold, value: SecretBytes::from_array(bytes) }
    }
}

/// Split `key` into `n` shares such that any `threshold` of them
/// reconstruct it, but `threshold - 1` reveal nothing about it. The
/// original key is not retained by this function beyond its own stack
/// frame — only the shares are returned.
pub fn split(key: &PrivateKey, threshold: u8, n: u8) -> Result<Vec<Share>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::ThresholdTooSmall);
    }
    if threshold > n {
        return Err(ShamirError::ThresholdExceedsParties);
    }

    let secret: SecretScalar = bytes_to_scalar(&key.to_bytes_dangerous());

    let mut rng = SecureRng::new();
    // Random polynomial f(x) = secret + a_1*x + ... + a_{threshold-1}*x^{threshold-1}.
    // Coefficients are as sensitive as the private key itself: any one of
    // them plus any one share point is enough to derive the secret. Held
    // as `SecretScalar` so they zeroize on drop automatically at the end
    // of this function — no manual cleanup call to forget.
    let coeffs: Vec<SecretScalar> = (1..threshold).map(|_| SecretScalar::from(Scalar::generate_vartime(&mut rng))).collect();

    let shares = (1..=n)
        .map(|i| {
            let x = small_scalar(i);
            let mut y = secret.expose();
            let mut x_pow = x;
            for c in &coeffs {
                y += c.expose() * x_pow;
                x_pow *= x;
            }
            Share {
                index: i,
                threshold,
                value: SecretBytes::from_array(y.to_bytes().into()),
            }
        })
        .collect();

    Ok(shares)
}

/// Reconstruct the private key from exactly `threshold`-many shares and
/// verify it against the group's known public key before trusting it.
/// Fails closed with `ReconstructionMismatch` rather than returning a
/// silently-wrong key on bad input — see the module docs for why that
/// check is necessary for plain Shamir.
pub fn reconstruct_and_verify(shares: &[Share], expected_public_key: &PublicKey) -> Result<PrivateKey, ShamirError> {
    let key = reconstruct(shares)?;
    if key.public_key() != *expected_public_key {
        return Err(ShamirError::ReconstructionMismatch);
    }
    Ok(key)
}

fn reconstruct(shares: &[Share]) -> Result<PrivateKey, ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::WrongShareCount);
    }
    let threshold = shares[0].threshold;
    if shares.len() != usize::from(threshold) {
        return Err(ShamirError::WrongShareCount);
    }

    let mut seen = HashSet::new();
    for s in shares {
        if s.threshold != threshold {
            return Err(ShamirError::ThresholdMismatch);
        }
        if s.index == 0 {
            return Err(ShamirError::ZeroIndexReserved);
        }
        if !seen.insert(s.index) {
            return Err(ShamirError::DuplicateShareIndex);
        }
    }

    let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
    let mut acc = Scalar::from(0u64);
    for s in shares {
        let yi: SecretScalar = bytes_to_scalar(s.value.expose());
        let li = lagrange_coefficient(s.index, &indices); // public: derived only from indices
        acc += yi.expose() * li;
    }
    // Wrapped immediately so the reconstructed secret zeroizes on drop at
    // the end of this function — no manual cleanup call to forget.
    let secret = SecretScalar::from(acc);

    // A `PrivateKey` can never be the zero scalar; interpolation landing
    // on zero is astronomically unlikely for real shares and indicates
    // garbage input either way, so treat it as a mismatch, not a panic.
    PrivateKey::from_bytes_dangerous(&secret.expose().to_bytes().into()).map_err(|_| ShamirError::ReconstructionMismatch)
}

fn lagrange_coefficient(index: u8, all_indices: &[u8]) -> Scalar {
    let xi = small_scalar(index);
    let mut num = small_scalar(1);
    let mut den = small_scalar(1);
    for &j in all_indices {
        if j == index {
            continue;
        }
        let xj = small_scalar(j);
        num *= xj;
        den *= xj - xi;
    }
    num * den.invert().unwrap()
}

fn small_scalar(n: u8) -> Scalar {
    Scalar::from(u64::from(n))
}

/// The single choke point where raw bytes become a secret scalar in this
/// module — returning `SecretScalar` here means every caller gets the
/// zeroize-on-drop guarantee without having to opt in per call site.
fn bytes_to_scalar(bytes: &[u8; 32]) -> SecretScalar {
    SecretScalar::from(<Scalar as Reduce<U256>>::reduce_bytes(bytes.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_rejects_threshold_below_two() {
        let key = PrivateKey::generate();
        assert_eq!(split(&key, 1, 3).unwrap_err(), ShamirError::ThresholdTooSmall);
    }

    #[test]
    fn split_rejects_threshold_above_party_count() {
        let key = PrivateKey::generate();
        assert_eq!(split(&key, 4, 3).unwrap_err(), ShamirError::ThresholdExceedsParties);
    }

    #[test]
    fn reconstruct_with_exact_threshold_recovers_original_key() {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, 2, 3).unwrap();

        let restored = reconstruct_and_verify(&shares[0..2], &expected).unwrap();
        assert_eq!(restored.public_key(), expected);
    }

    #[test]
    fn any_qualifying_subset_recovers_the_same_key() {
        // t=2, n=3: every pair of the three shares must independently
        // reconstruct the identical key — not just one hardcoded pair.
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, 2, 3).unwrap();

        for pair in [[0, 1], [0, 2], [1, 2]] {
            let subset = [&shares[pair[0]], &shares[pair[1]]];
            let subset: Vec<Share> = subset
                .into_iter()
                .map(|s| Share {
                    index: s.index,
                    threshold: s.threshold,
                    value: SecretBytes::from_array(*s.value.expose()),
                })
                .collect();
            let restored = reconstruct_and_verify(&subset, &expected).unwrap();
            assert_eq!(restored.public_key(), expected);
        }
    }

    #[test]
    fn below_threshold_share_count_is_rejected_not_silently_wrong() {
        // The core Shamir footgun this module guards against: handing it
        // one share short of the threshold must error, never return a
        // plausible-looking but wrong key.
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, 3, 5).unwrap();

        let result = reconstruct_and_verify(&shares[0..2], &expected);
        assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);
    }

    #[test]
    fn too_many_shares_is_rejected() {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, 2, 4).unwrap();

        let result = reconstruct_and_verify(&shares[0..3], &expected);
        assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);
    }

    #[test]
    fn duplicate_share_index_is_rejected() {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, 2, 3).unwrap();

        let duplicated = [
            Share {
                index: shares[0].index,
                threshold: shares[0].threshold,
                value: SecretBytes::from_array(*shares[0].value.expose()),
            },
            Share {
                index: shares[0].index,
                threshold: shares[0].threshold,
                value: SecretBytes::from_array(*shares[0].value.expose()),
            },
        ];
        let result = reconstruct_and_verify(&duplicated, &expected);
        assert_eq!(result.unwrap_err(), ShamirError::DuplicateShareIndex);
    }

    #[test]
    fn shares_from_different_splits_are_rejected() {
        let key_a = PrivateKey::generate();
        let key_b = PrivateKey::generate();
        let shares_a = split(&key_a, 2, 3).unwrap();
        let shares_b = split(&key_b, 2, 3).unwrap();

        // Mixing shares from two unrelated keys: same (threshold, index)
        // shape, completely different secrets underneath.
        let mixed = [
            Share {
                index: shares_a[0].index,
                threshold: shares_a[0].threshold,
                value: SecretBytes::from_array(*shares_a[0].value.expose()),
            },
            Share {
                index: shares_b[1].index,
                threshold: shares_b[1].threshold,
                value: SecretBytes::from_array(*shares_b[1].value.expose()),
            },
        ];
        let result = reconstruct_and_verify(&mixed, &key_a.public_key());
        assert_eq!(result.unwrap_err(), ShamirError::ReconstructionMismatch);
    }

    #[test]
    fn corrupted_share_value_is_caught_by_public_key_check() {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let mut shares = split(&key, 2, 3).unwrap();

        // Flip a bit in one share's value, simulating bit-rot or a
        // malicious/faulty co-holder.
        let mut corrupted_bytes = *shares[0].value.expose();
        corrupted_bytes[0] ^= 0x01;
        shares[0].value = SecretBytes::from_array(corrupted_bytes);

        let result = reconstruct_and_verify(&shares[0..2], &expected);
        assert_eq!(result.unwrap_err(), ShamirError::ReconstructionMismatch);
    }

    #[test]
    fn shares_are_not_the_secret_itself() {
        let key = PrivateKey::generate();
        let shares = split(&key, 2, 3).unwrap();
        for s in &shares {
            assert_ne!(s.value.expose(), &key.to_bytes_dangerous());
        }
    }

    #[test]
    fn threshold_mismatched_shares_are_rejected() {
        let key = PrivateKey::generate();
        let shares_2of3 = split(&key, 2, 3).unwrap();
        let shares_3of5 = split(&key, 3, 5).unwrap();

        let mixed = [
            Share {
                index: shares_2of3[0].index,
                threshold: shares_2of3[0].threshold,
                value: SecretBytes::from_array(*shares_2of3[0].value.expose()),
            },
            Share {
                index: shares_3of5[0].index,
                threshold: shares_3of5[0].threshold,
                value: SecretBytes::from_array(*shares_3of5[0].value.expose()),
            },
        ];
        let result = reconstruct_and_verify(&mixed, &key.public_key());
        assert_eq!(result.unwrap_err(), ShamirError::ThresholdMismatch);
    }
}
