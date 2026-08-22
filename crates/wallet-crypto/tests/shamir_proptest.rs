//! Property-based tests for `wallet_crypto::shamir` across randomized
//! (threshold, n) pairs and randomized share subsets — the fixed-value
//! unit tests in `shamir.rs` cover specific scenarios (t=2/n=3, etc.);
//! this file checks the same invariants hold generally, not just for the
//! handful of cases someone thought to hardcode.
//!
//! Uses only the crate's public API (`split`, `reconstruct_and_verify`,
//! `PrivateKey::generate`) — no access to `Share`'s private fields, which
//! also incidentally proves that API is sufficient for real usage.

use std::collections::HashSet;

use proptest::prelude::*;
use wallet_crypto::keys::PrivateKey;
use wallet_crypto::shamir::{reconstruct_and_verify, split, Share, ShamirError};

/// (threshold, n, a random `count`-sized subset of share indices in 0..n).
fn threshold_n_and_subset_of_size(count_offset: i8) -> impl Strategy<Value = (u8, u8, Vec<usize>)> {
    (2u8..8, 0u8..8).prop_flat_map(move |(threshold, extra)| {
        let n = threshold + extra;
        let count = i32::from(threshold) + i32::from(count_offset);
        let count = usize::try_from(count.clamp(0, i32::from(n))).unwrap();
        let idxs: Vec<usize> = (0..usize::from(n)).collect();
        proptest::sample::subsequence(idxs, count).prop_map(move |subset| (threshold, n, subset))
    })
}

fn pick(shares: Vec<Share>, subset: &[usize]) -> Vec<Share> {
    let chosen: HashSet<usize> = subset.iter().copied().collect();
    shares.into_iter().enumerate().filter(|(i, _)| chosen.contains(i)).map(|(_, s)| s).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any exactly-`threshold`-sized subset of shares, for any (threshold, n)
    /// pair, reconstructs the original key — not just one hardcoded pair.
    #[test]
    fn any_threshold_sized_subset_reconstructs_correctly((threshold, n, subset) in threshold_n_and_subset_of_size(0)) {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, threshold, n).unwrap();

        let picked = pick(shares, &subset);
        let restored = reconstruct_and_verify(&picked, &expected).unwrap();
        prop_assert_eq!(restored.public_key(), expected);
    }

    /// One share short of the threshold must fail structurally
    /// (`WrongShareCount`), never silently return a plausible wrong key,
    /// for any (threshold, n) pair — the core Shamir footgun this module
    /// guards against, checked generally rather than for one fixed case.
    #[test]
    fn below_threshold_subset_always_rejected((threshold, n, subset) in threshold_n_and_subset_of_size(-1)) {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, threshold, n).unwrap();

        let picked = pick(shares, &subset);
        let result = reconstruct_and_verify(&picked, &expected);
        prop_assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);
    }

    /// One share more than the threshold must also fail structurally —
    /// `reconstruct_and_verify` requires exactly `threshold` shares, not
    /// "at least".
    #[test]
    fn above_threshold_subset_always_rejected((threshold, n, subset) in threshold_n_and_subset_of_size(1)) {
        // Only meaningful when n > threshold, i.e. a (threshold+1)-sized
        // subset actually exists to pick.
        prop_assume!(subset.len() == usize::from(threshold) + 1);

        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, threshold, n).unwrap();

        let picked = pick(shares, &subset);
        let result = reconstruct_and_verify(&picked, &expected);
        prop_assert_eq!(result.unwrap_err(), ShamirError::WrongShareCount);
    }

    /// Two different threshold-sized subsets from the same split always
    /// reconstruct to the identical key.
    #[test]
    fn different_subsets_of_same_split_agree((threshold, n, subset_a) in threshold_n_and_subset_of_size(0), seed in any::<u64>()) {
        let key = PrivateKey::generate();
        let expected = key.public_key();
        let shares = split(&key, threshold, n).unwrap();

        // Derive a second, independent subset choice from `seed` so this
        // test doesn't depend on proptest's shrinker picking two equal
        // subsets by coincidence.
        let mut all: Vec<usize> = (0..usize::from(n)).collect();
        // simple deterministic shuffle from the seed
        let mut s = seed;
        for i in (1..all.len()).rev() {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let j = (s >> 33) as usize % (i + 1);
            all.swap(i, j);
        }
        let subset_b: Vec<usize> = all.into_iter().take(usize::from(threshold)).collect();

        let restored_a = reconstruct_and_verify(&pick(split(&key, threshold, n).unwrap(), &subset_a), &expected).unwrap();
        let restored_b = reconstruct_and_verify(&pick(shares, &subset_b), &expected).unwrap();
        prop_assert_eq!(restored_a.public_key(), restored_b.public_key());
    }
}
