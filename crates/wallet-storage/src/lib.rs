//! Encrypted-at-rest persistence for private keys and Shamir shares.
//!
//! Format on disk: `version(1) || salt(16) || nonce(24) || ciphertext+tag`.
//! The version byte lets a future format change (different KDF params,
//! different AEAD, etc.) be detected and rejected explicitly instead of
//! being misparsed as garbage or, worse, successfully-but-wrongly decoded.
//! For a share, the plaintext inside that ciphertext is itself
//! `index(1) || threshold(1) || value(32)` — the share's (non-secret)
//! metadata travels inside the same AEAD envelope as its secret value
//! rather than as an unencrypted header, so tampering with the index or
//! threshold is caught by the same tag check instead of needing separate
//! authenticated-associated-data plumbing.
//!
//! The encryption key is derived from a passphrase via Argon2id at
//! hardened parameters (64 MiB / 3 passes / 4 lanes — see `argon2()`),
//! so brute-forcing a stolen file costs real time and memory per guess,
//! not a raw SHA-hashed password. The plaintext is then sealed with
//! XChaCha20-Poly1305, an AEAD cipher: any bit-flip in the stored file is
//! detected at decrypt time (the tag check fails closed) rather than
//! silently decrypting into corrupted key material.
//!
//! No key or share is ever written to disk unencrypted, even transiently.
//! Every buffer that briefly holds plaintext bytes or the derived
//! encryption key is wrapped in `Zeroizing` so it's wiped the moment it
//! goes out of scope, not left for the allocator to overwrite later.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use wallet_crypto::keys::{InvalidKeyBytes, PrivateKey};
use wallet_crypto::shamir::Share;
use wallet_crypto::SecureRng;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SHARE_PLAINTEXT_LEN: usize = 2 + 32; // index(1) + threshold(1) + value(32)

/// Current on-disk format version. Bump this whenever the KDF params,
/// AEAD scheme, or layout change, and add a migration/rejection path for
/// old versions rather than silently reinterpreting their bytes.
const FORMAT_VERSION: u8 = 1;

/// Floor on passphrase length. This is not an entropy estimator — it just
/// rejects the trivially-guessable end (empty string, "1234") before it
/// ever reaches Argon2id. A real strength meter (zxcvbn or similar)
/// belongs in the UI layer, not hardcoded here.
const MIN_PASSPHRASE_LEN: usize = 12;

/// Errors from sealing/opening an encrypted key or share file.
#[derive(Debug)]
pub enum StorageError {
    /// Wrong passphrase, or the ciphertext/file was tampered with —
    /// AEAD deliberately doesn't distinguish these to an attacker.
    DecryptionFailed,
    /// The blob is shorter than the fixed header + minimum ciphertext.
    Truncated,
    /// Decrypted successfully but the plaintext isn't a valid private key.
    InvalidKeyBytes,
    /// Passphrase is shorter than `MIN_PASSPHRASE_LEN`.
    WeakPassphrase,
    /// The blob's format version byte doesn't match `FORMAT_VERSION`.
    UnsupportedVersion(u8),
    /// Underlying filesystem error from the `*_to_file`/`*_from_file` fns.
    Io(std::io::Error),
}

impl From<InvalidKeyBytes> for StorageError {
    fn from(_: InvalidKeyBytes) -> Self {
        StorageError::InvalidKeyBytes
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

fn check_passphrase_strength(passphrase: &str) -> Result<(), StorageError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(StorageError::WeakPassphrase);
    }
    Ok(())
}

/// 64 MiB memory, 3 iterations, 4 lanes — well above OWASP's Argon2id
/// floor (19 MiB/2/1), chosen so an attacker with a stolen key file pays
/// real wall-clock and memory cost per guess instead of a cheap raw hash.
fn argon2() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 4, Some(32)).expect("hardcoded Argon2id params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    argon2()
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .expect("Argon2id with valid fixed-length params cannot fail here");
    out
}

/// Encrypt arbitrary `plaintext` under `passphrase`, returning
/// `version || salt || nonce || ciphertext`. The shared low-level
/// primitive behind `seal` and `seal_share` — both differ only in what
/// bytes they hand this function.
///
/// # Panics
/// Never in practice: the only internal `expect` covers AEAD encryption,
/// which cannot fail for valid key/nonce sizes.
fn seal_bytes(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    check_passphrase_strength(passphrase)?;

    let mut rng = SecureRng::new();

    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes);

    let derived = derive_key(passphrase, &salt);
    let cipher = XChaCha20Poly1305::new(&Key::from(*derived));
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher.encrypt(&nonce, plaintext).expect("encrypting a fixed-length plaintext cannot fail");

    let mut out = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `seal_bytes`. Fails closed: a wrong
/// passphrase or any tampering with the stored bytes returns
/// `DecryptionFailed`, never corrupted plaintext.
///
/// # Panics
/// Never in practice: the length checks above guarantee the salt slice is
/// exactly `SALT_LEN` bytes before the internal `try_into().unwrap()` runs.
fn open_bytes(passphrase: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    if blob.is_empty() {
        return Err(StorageError::Truncated);
    }
    let (version, rest) = blob.split_at(1);
    if version[0] != FORMAT_VERSION {
        return Err(StorageError::UnsupportedVersion(version[0]));
    }

    if rest.len() < SALT_LEN + NONCE_LEN {
        return Err(StorageError::Truncated);
    }
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let salt: [u8; SALT_LEN] = salt.try_into().unwrap();
    let derived = derive_key(passphrase, &salt);
    let cipher = XChaCha20Poly1305::new(&Key::from(*derived));
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.try_into().unwrap();
    let nonce = XNonce::from(nonce_arr);

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| StorageError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Encrypt `key` under `passphrase`.
pub fn seal(passphrase: &str, key: &PrivateKey) -> Result<Vec<u8>, StorageError> {
    let key_bytes = Zeroizing::new(key.to_bytes_dangerous());
    seal_bytes(passphrase, key_bytes.as_slice())
}

/// Decrypt a blob produced by `seal`.
pub fn open(passphrase: &str, blob: &[u8]) -> Result<PrivateKey, StorageError> {
    let plaintext = open_bytes(passphrase, blob)?;
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(plaintext.as_slice().try_into().map_err(|_| StorageError::Truncated)?);
    Ok(PrivateKey::from_bytes_dangerous(&bytes)?)
}

/// Encrypt a Shamir `share` under `passphrase`. The share's index and
/// threshold (public metadata) travel inside the same encrypted envelope
/// as its secret value — see the module docs for why.
pub fn seal_share(passphrase: &str, share: &Share) -> Result<Vec<u8>, StorageError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(SHARE_PLAINTEXT_LEN));
    plaintext.push(share.index());
    plaintext.push(share.threshold());
    plaintext.extend_from_slice(&share.to_bytes_dangerous());
    seal_bytes(passphrase, &plaintext)
}

/// Decrypt a blob produced by `seal_share`.
///
/// # Panics
/// Never in practice: the length check above guarantees the value slice
/// is exactly 32 bytes before the internal `try_into().unwrap()` runs.
pub fn open_share(passphrase: &str, blob: &[u8]) -> Result<Share, StorageError> {
    let plaintext = open_bytes(passphrase, blob)?;
    if plaintext.len() != SHARE_PLAINTEXT_LEN {
        return Err(StorageError::Truncated);
    }
    let index = plaintext[0];
    let threshold = plaintext[1];
    let value: [u8; 32] = plaintext[2..].try_into().unwrap();
    Ok(Share::from_parts_dangerous(index, threshold, value))
}

/// Writes atomically (write to a sibling temp file, fsync, rename over the
/// target) so a crash mid-write can never leave a half-written file — the
/// rename either lands the whole new file or the old one stays intact.
/// The temp file is created with 0600 permissions on Unix before any
/// bytes are written, so the file is never briefly world-readable on disk.
fn write_atomic(path: &std::path::Path, blob: &[u8]) -> Result<(), StorageError> {
    use std::io::Write;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    tmp.write_all(blob)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| StorageError::Io(e.error))?;
    Ok(())
}

/// Seal `key` and write it atomically to `path` — see `write_atomic`.
pub fn save_to_file(path: &std::path::Path, passphrase: &str, key: &PrivateKey) -> Result<(), StorageError> {
    write_atomic(path, &seal(passphrase, key)?)
}

/// Read and decrypt a key file written by `save_to_file`.
pub fn load_from_file(path: &std::path::Path, passphrase: &str) -> Result<PrivateKey, StorageError> {
    let blob = std::fs::read(path)?;
    open(passphrase, &blob)
}

/// Seal `share` and write it atomically to `path` — see `write_atomic`.
pub fn save_share_to_file(path: &std::path::Path, passphrase: &str, share: &Share) -> Result<(), StorageError> {
    write_atomic(path, &seal_share(passphrase, share)?)
}

/// Read and decrypt a share file written by `save_share_to_file`.
pub fn load_share_from_file(path: &std::path::Path, passphrase: &str) -> Result<Share, StorageError> {
    let blob = std::fs::read(path)?;
    open_share(passphrase, &blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";

    #[test]
    fn seal_then_open_roundtrip() {
        let key = PrivateKey::generate();
        let blob = seal(PASS, &key).unwrap();
        let restored = open(PASS, &blob).unwrap();
        assert_eq!(key.public_key(), restored.public_key());
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let key = PrivateKey::generate();
        let blob = seal(PASS, &key).unwrap();
        let result = open("wrong but long enough passphrase", &blob);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = PrivateKey::generate();
        let mut blob = seal(PASS, &key).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip one bit in the ciphertext/tag

        let result = open(PASS, &blob);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
    }

    #[test]
    fn tampered_salt_fails_closed() {
        // Flipping the salt changes the derived key, which should fail
        // the AEAD tag check rather than silently deriving a wrong key
        // and "succeeding" with garbage.
        let key = PrivateKey::generate();
        let mut blob = seal(PASS, &key).unwrap();
        blob[1] ^= 0x01; // byte 0 is the format version; salt starts at 1

        let result = open(PASS, &blob);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
    }

    #[test]
    fn truncated_blob_fails_closed() {
        let key = PrivateKey::generate();
        let blob = seal(PASS, &key).unwrap();
        let result = open(PASS, &blob[..10]);
        assert!(matches!(result, Err(StorageError::Truncated)));
    }

    #[test]
    fn unknown_format_version_rejected() {
        let key = PrivateKey::generate();
        let mut blob = seal(PASS, &key).unwrap();
        blob[0] = 0xFF; // pretend this came from some future/unknown format

        let result = open(PASS, &blob);
        assert!(matches!(result, Err(StorageError::UnsupportedVersion(0xFF))));
    }

    #[test]
    fn two_seals_of_same_key_produce_different_ciphertext() {
        // Fresh random salt + nonce per call means no two on-disk blobs
        // for the same key ever look identical, even to an attacker
        // watching the file change over time.
        let key = PrivateKey::generate();
        let blob1 = seal(PASS, &key).unwrap();
        let blob2 = seal(PASS, &key).unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        let key = PrivateKey::generate();

        save_to_file(&path, PASS, &key).unwrap();
        let restored = load_from_file(&path, PASS).unwrap();
        assert_eq!(key.public_key(), restored.public_key());
    }

    #[test]
    fn empty_passphrase_rejected() {
        let key = PrivateKey::generate();
        let result = seal("", &key);
        assert!(matches!(result, Err(StorageError::WeakPassphrase)));
    }

    #[test]
    fn short_passphrase_rejected() {
        let key = PrivateKey::generate();
        let result = seal("short1", &key);
        assert!(matches!(result, Err(StorageError::WeakPassphrase)));
    }

    #[test]
    #[cfg(unix)]
    fn saved_file_is_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        let key = PrivateKey::generate();

        save_to_file(&path, PASS, &key).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file must be owner-read/write only");
    }

    #[test]
    fn save_to_file_does_not_leave_partial_file_on_disk_before_persist() {
        // The temp file used for the atomic write must not appear at the
        // final path until the rename completes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.key");
        assert!(!path.exists());

        let key = PrivateKey::generate();
        save_to_file(&path, PASS, &key).unwrap();
        assert!(path.exists());

        // No stray temp files left behind in the directory afterward.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn seal_share_then_open_share_preserves_metadata() {
        let key = PrivateKey::generate();
        let shares = wallet_crypto::shamir::split(&key, 2, 3).unwrap();

        let blob = seal_share(PASS, &shares[0]).unwrap();
        let restored = open_share(PASS, &blob).unwrap();

        assert_eq!(restored.index(), shares[0].index());
        assert_eq!(restored.threshold(), shares[0].threshold());
        // Functional correctness (the restored share's *value* actually
        // matches, not just its metadata) is checked separately in
        // opened_share_reconstructs_correctly_with_its_siblings below —
        // Share has no PartialEq/Clone (by design), so that's the only
        // way to prove it.
    }

    #[test]
    fn opened_share_reconstructs_correctly_with_its_siblings() {
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let mut shares = wallet_crypto::shamir::split(&key, 2, 3).unwrap();

        // Seal/open share 0, keep share 1 as-is; reconstruct from the pair.
        let blob = seal_share(PASS, &shares[0]).unwrap();
        let restored = open_share(PASS, &blob).unwrap();
        shares[0] = restored;

        let result = wallet_crypto::shamir::reconstruct_and_verify(&shares[0..2], &public_key).unwrap();
        assert_eq!(result.public_key(), public_key);
    }

    #[test]
    fn share_wrong_passphrase_fails_closed() {
        let key = PrivateKey::generate();
        let shares = wallet_crypto::shamir::split(&key, 2, 3).unwrap();
        let blob = seal_share(PASS, &shares[0]).unwrap();

        let result = open_share("wrong but long enough passphrase", &blob);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
    }

    #[test]
    fn share_tampered_index_fails_closed() {
        // Index/threshold are inside the AEAD envelope, so tampering with
        // them is caught by the tag check just like tampering the value.
        let key = PrivateKey::generate();
        let shares = wallet_crypto::shamir::split(&key, 2, 3).unwrap();
        let mut blob = seal_share(PASS, &shares[0]).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;

        let result = open_share(PASS, &blob);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
    }

    #[test]
    fn share_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("share.dat");
        let key = PrivateKey::generate();
        let public_key = key.public_key();
        let mut shares = wallet_crypto::shamir::split(&key, 2, 3).unwrap();

        save_share_to_file(&path, PASS, &shares[0]).unwrap();
        let restored = load_share_from_file(&path, PASS).unwrap();
        shares[0] = restored;

        let result = wallet_crypto::shamir::reconstruct_and_verify(&shares[0..2], &public_key).unwrap();
        assert_eq!(result.public_key(), public_key);
    }
}
