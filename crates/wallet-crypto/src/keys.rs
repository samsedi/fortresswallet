//! secp256k1 keypair generation and RFC 6979 deterministic ECDSA signing.
//!
//! Nonce generation is deterministic (RFC 6979): the `ecdsa` crate derives
//! the per-signature nonce `k` from HMAC(private key, message digest), so
//! the same digest always yields the same nonce, and different digests
//! yield unrelated, unpredictable nonces. This closes the single most
//! common real-world ECDSA-breaking bug — reusing (or predictably
//! generating) `k` across two signatures lets anyone solve for the private
//! key with two linear equations. See `tests::nonce_reuse_recovers_key`
//! below for why that math holds, and why determinism prevents it here.
//!
//! `sign_prehash` takes an already-hashed 32-byte digest, not raw message
//! bytes — callers (Bitcoin/EVM tx construction) hash the transaction
//! themselves with the chain's actual hash function before calling this.
//!
//! Signature malleability (BIP-62): k256's `ecdsa` crate normalizes `s` to
//! the low half of the curve order by default on every signature it
//! produces, so this code does not need to (and does not) do it manually.
//! Constant-time execution of the underlying scalar/field arithmetic is
//! provided by k256 but is not formally verified for exotic/embedded
//! targets — an accepted risk on the mainstream desktop/server
//! architectures this wallet targets.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::SecureRng;

/// Best-effort: pin the pages backing `value` in RAM so the OS cannot
/// write them to swap. Not available in every environment (containers or
/// CI sandboxes with `ulimit -l` set to 0) — failure here is silent and
/// non-fatal, since a wallet that refuses to run without `mlock` would be
/// a worse outcome than one that runs with this documented residual risk.
/// `value` must be heap-allocated (`Box`) rather than a stack local: a
/// stack address is not stable (moves, reuse across calls), so locking it
/// would protect the wrong pages the moment the value moves — this is the
/// same shadow-copy limitation noted on `PrivateKey` below.
fn lock_secret_memory<T>(value: &T) -> Option<region::LockGuard> {
    let ptr = std::ptr::from_ref(value).cast::<u8>();
    let len = std::mem::size_of::<T>();
    region::lock(ptr, len).ok()
}

/// A secp256k1 private key, heap-allocated so its address is stable enough
/// for `mlock` to mean something, with those pages pinned against swap for
/// the key's lifetime. The inner `SigningKey` zeroizes its scalar on drop;
/// `Debug` here is redacted so a stray `{:?}` can never print it.
///
/// Residual, accepted risk: Rust moves are bitwise copies, so temporaries
/// created while constructing this value (e.g. the `SigningKey::random`
/// return before it's boxed) can leave unzeroized, unlocked shadow copies
/// on the stack until that stack space is reused. This is an inherent
/// limitation of software-level zeroization/locking, not specific to this
/// code, and is mitigated by keeping those temporaries' scopes as short as
/// possible rather than eliminated outright.
pub struct PrivateKey {
    key: Box<SigningKey>,
    _lock: Option<region::LockGuard>,
}

/// The secp256k1 public key corresponding to a `PrivateKey`. Not secret —
/// safe to log, display, and transmit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(VerifyingKey);

impl PrivateKey {
    /// The only constructor: draws the scalar from the OS CSPRNG via
    /// `SecureRng`. There is no seeded/deterministic key-generation path.
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::random(&mut SecureRng::new()))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let key = Box::new(signing_key);
        let lock = lock_secret_memory(key.as_ref());
        Self { key, _lock: lock }
    }

    /// Derive the public key. Cheap — no signing/randomness involved.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.key.verifying_key())
    }

    /// Sign a 32-byte precomputed digest with a deterministic (RFC 6979)
    /// nonce. Same digest in, same signature out — verified in
    /// `tests::signing_is_deterministic`.
    ///
    /// # Panics
    /// Never in practice: the only failure mode of the underlying signer
    /// is a wrong-length digest, and `digest` is fixed at 32 bytes here.
    pub fn sign_prehash(&self, digest: &[u8; 32]) -> Signature {
        self.key
            .sign_prehash(digest)
            .expect("prehash signing over a fixed-length digest cannot fail")
    }

    /// Raw scalar bytes, for encrypted storage. `pub(crate)` isn't usable
    /// here — `wallet-storage` is a *different* crate and needs to call
    /// this to seal the key — so the "don't reach for this casually"
    /// signal is the `_dangerous` name instead, matching k256/ecdsa's own
    /// `hazmat` convention. Callers must hand the result straight to an
    /// AEAD-encrypting sink, never to a log or plain file.
    pub fn to_bytes_dangerous(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Reconstruct a key from raw scalar bytes (e.g. decrypted from
    /// storage). See the `_dangerous` note on `to_bytes_dangerous`.
    ///
    /// # Errors
    /// Returns `InvalidKeyBytes` if `bytes` isn't a valid secp256k1 scalar
    /// (zero, or `>=` the curve order).
    pub fn from_bytes_dangerous(bytes: &[u8; 32]) -> Result<Self, InvalidKeyBytes> {
        SigningKey::from_bytes(bytes.into())
            .map(Self::from_signing_key)
            .map_err(|_| InvalidKeyBytes)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey(REDACTED)")
    }
}

/// The given bytes are not a valid secp256k1 private key scalar.
#[derive(Debug)]
pub struct InvalidKeyBytes;

impl PublicKey {
    /// Verify a signature over a 32-byte precomputed digest.
    pub fn verify_prehash(&self, digest: &[u8; 32], sig: &Signature) -> bool {
        self.0.verify_prehash(digest, sig).is_ok()
    }

    /// SEC1-encoded (compressed) public key bytes.
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0.to_sec1_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        use k256::sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let d = digest(b"transfer 1 BTC to alice");

        let sig = sk.sign_prehash(&d);
        assert!(pk.verify_prehash(&d, &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let sk = PrivateKey::generate();
        let other_pk = PrivateKey::generate().public_key();
        let d = digest(b"transfer 1 BTC to alice");

        let sig = sk.sign_prehash(&d);
        assert!(!other_pk.verify_prehash(&d, &sig));
    }

    #[test]
    fn tampered_digest_fails_verification() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let sig = sk.sign_prehash(&digest(b"send 1 BTC to alice"));

        // Attacker flips one byte of what gets signed-over after the fact.
        assert!(!pk.verify_prehash(&digest(b"send 9 BTC to alice"), &sig));
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC 6979: same key + same digest must always produce the exact
        // same (r, s), proving no fresh/weak randomness enters per-signing.
        let sk = PrivateKey::generate();
        let d = digest(b"same message, signed twice");

        let sig1 = sk.sign_prehash(&d);
        let sig2 = sk.sign_prehash(&d);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_messages_get_different_signatures() {
        let sk = PrivateKey::generate();
        let sig1 = sk.sign_prehash(&digest(b"message A"));
        let sig2 = sk.sign_prehash(&digest(b"message B"));
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn key_bytes_roundtrip() {
        let sk = PrivateKey::generate();
        let bytes = sk.to_bytes_dangerous();
        let restored = PrivateKey::from_bytes_dangerous(&bytes).unwrap();
        assert_eq!(sk.public_key(), restored.public_key());
    }

    /// Adversarial test: prove *why* nonce reuse is catastrophic for
    /// ECDSA, by manually reimplementing naive (non-deterministic) signing
    /// with a fixed nonce `k` across two different messages, then running
    /// the standard nonce-reuse key-recovery algebra an attacker would use.
    ///
    /// Given signatures (r, s1) over digest d1 and (r, s2) over digest d2
    /// that share the same r (i.e. same nonce k):
    ///   s1 = k^-1 (d1 + r*x)   s2 = k^-1 (d2 + r*x)
    /// Subtracting:  s1 - s2 = k^-1 (d1 - d2)  =>  k = (d1 - d2) / (s1 - s2)
    /// Then:         x = (s1*k - d1) / r
    /// This is exactly the bug RFC 6979 determinism prevents in
    /// `sign_prehash` above — different digests there always yield
    /// different, unrelated nonces.
    #[test]
    fn nonce_reuse_recovers_key() {
        use k256::elliptic_curve::ops::Reduce;
        use k256::elliptic_curve::point::AffineCoordinates;
        use k256::{ProjectivePoint, Scalar, U256};

        let mut rng = SecureRng::new();

        // The secret we're going to recover, as if we didn't know it.
        let x = Scalar::generate_vartime(&mut rng);

        // A single nonce, reused (the bug) across two different messages.
        let k = Scalar::generate_vartime(&mut rng);
        let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
        let r = <Scalar as Reduce<U256>>::reduce_bytes(&r_point.x());

        let d1 = Scalar::generate_vartime(&mut rng);
        let d2 = Scalar::generate_vartime(&mut rng);

        let k_inv = k.invert().unwrap();
        let s1 = k_inv * (d1 + r * x);
        let s2 = k_inv * (d2 + r * x);

        // --- attacker, given only (r, s1, d1), (r, s2, d2) ---
        let s_diff_inv = (s1 - s2).invert().unwrap();
        let recovered_k = (d1 - d2) * s_diff_inv;
        let recovered_x = (s1 * recovered_k - d1) * r.invert().unwrap();

        assert_eq!(recovered_k, k, "attacker recovers the reused nonce");
        assert_eq!(recovered_x, x, "attacker recovers the private key");
    }
}
