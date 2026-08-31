//! Wallet creation and reloading: the piece that was missing before any
//! chain-specific work could be used end to end — nothing previously let
//! a caller create a wallet, persist it, and load it back.
//!
//! # This is a dev/single-operator convenience, not the production
//! threshold model
//!
//! Real deployment of a threshold wallet means each Shamir share is held
//! by a *different* party or device — that's the entire point of
//! threshold signing (see `ceremony`'s module docs: no single point of
//! failure, no recovery admin). `create_wallet` here writes **all** `n`
//! shares as sibling files under one directory, encrypted under one
//! passphrase, so a single operator can run the CLI end to end during
//! this phase of development. That is explicitly not how this should be
//! deployed for real funds: distributing shares to separate holders
//! (with separate passphrases, on separate storage) is out of scope for
//! this module and left to a future multi-party CLI/protocol.

use std::fs;
use std::path::Path;

use wallet_crypto::keys::{InvalidKeyBytes, PublicKey};
use wallet_crypto::shamir::{Share, ShamirError};
use wallet_storage::StorageError;

use crate::ceremony;

const PUBKEY_FILE_NAME: &str = "pubkey";

fn share_file_name(index: u8) -> String {
    format!("share_{index}.dat")
}

/// Errors from creating or loading a wallet.
#[derive(Debug)]
pub enum WalletError {
    /// DKG ceremony / Shamir split failed — see `ShamirError`.
    Ceremony(ShamirError),
    /// Sealing or opening a share/pubkey file failed — see `StorageError`.
    Storage(StorageError),
    /// Underlying filesystem error (creating the wallet directory,
    /// reading/writing the plaintext pubkey file).
    Io(std::io::Error),
    /// The stored pubkey file's bytes aren't a valid public key.
    InvalidPublicKey,
}

impl From<ShamirError> for WalletError {
    fn from(e: ShamirError) -> Self {
        WalletError::Ceremony(e)
    }
}

impl From<StorageError> for WalletError {
    fn from(e: StorageError) -> Self {
        WalletError::Storage(e)
    }
}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        WalletError::Io(e)
    }
}

impl From<InvalidKeyBytes> for WalletError {
    fn from(_: InvalidKeyBytes) -> Self {
        WalletError::InvalidPublicKey
    }
}

/// Run the DKG ceremony and persist share index 1 under `dir`, encrypted
/// under `passphrase`. Every other share is returned as sealed
/// (encrypted, `wallet_storage::seal_share`) bytes for the caller to
/// distribute to separate holders — see the module docs for why only one
/// share lands on local disk. Returns the wallet's group public key
/// alongside those external shares.
pub fn create_wallet(dir: &Path, passphrase: &str, threshold: u8, n: u8) -> Result<(PublicKey, Vec<Vec<u8>>), WalletError> {
    fs::create_dir_all(dir)?;

    let (public_key, shares) = ceremony::generate_and_split_key(threshold, n)?;

    let mut external_shares = Vec::new();

    for share in &shares {
        if share.index() == 1 {
            let path = dir.join(share_file_name(share.index()));
            wallet_storage::save_share_to_file(&path, passphrase, share)?;
        } else {
            let sealed = wallet_storage::seal_share(passphrase, share)?;
            external_shares.push(sealed);
        }
    }

    fs::write(dir.join(PUBKEY_FILE_NAME), public_key.to_sec1_bytes())?;

    Ok((public_key, external_shares))
}

/// Load an external share from its encrypted bytes.
pub fn load_external_share(passphrase: &str, ciphertext: &[u8]) -> Result<Share, WalletError> {
    wallet_storage::open_share(passphrase, ciphertext).map_err(WalletError::from)
}

/// Load the wallet's public key from `dir` — no passphrase or shares
/// needed, since the public key is stored unencrypted.
pub fn load_public_key(dir: &Path) -> Result<PublicKey, WalletError> {
    let bytes = fs::read(dir.join(PUBKEY_FILE_NAME))?;
    Ok(PublicKey::from_sec1_bytes(&bytes)?)
}

/// Import a wallet onto a new device from `threshold`-many externally
/// held Shamir shares, all sealed under `passphrase`. Reconstructs the
/// group private key just long enough to derive its public key, persists
/// that (unencrypted, as `create_wallet` does) under `dir`, and drops the
/// private key — no share is written to disk here, since these shares
/// live with their external holders, not this device; signing later
/// still needs `threshold`-many of them supplied again. See the module
/// docs' caveat: a wrong passphrase fails closed (AEAD), but shares from
/// an unrelated wallet reconstruct silently into a wrong key, since there
/// is no known-good public key yet to check against on first import.
pub fn import_wallet(dir: &Path, passphrase: &str, sealed_shares: &[Vec<u8>]) -> Result<PublicKey, WalletError> {
    fs::create_dir_all(dir)?;

    let shares: Vec<Share> = sealed_shares
        .iter()
        .map(|s| wallet_storage::open_share(passphrase, s).map_err(WalletError::from))
        .collect::<Result<_, _>>()?;

    let private_key = wallet_crypto::shamir::reconstruct_unverified(&shares)?;
    let public_key = private_key.public_key();

    fs::write(dir.join(PUBKEY_FILE_NAME), public_key.to_sec1_bytes())?;
    Ok(public_key)
}

/// Load and decrypt the shares at `indices` under `dir`, all sealed under
/// the same `passphrase` — see the module docs' caveat about this being a
/// single-operator convenience. Callers should pass at least `threshold`-
/// many indices; a short count is only caught later, when reconstruction
/// itself fails.
pub fn load_shares(dir: &Path, passphrase: &str, indices: &[u8]) -> Result<Vec<Share>, WalletError> {
    indices
        .iter()
        .map(|&i| wallet_storage::load_share_from_file(&dir.join(share_file_name(i)), passphrase).map_err(WalletError::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_wallet_can_be_reloaded_and_reconstructed() {
        let dir = tempfile::tempdir().unwrap();
        let pass = "correct horse battery staple";

        let (public_key, external_shares) = create_wallet(dir.path(), pass, 2, 3).unwrap();

        let reloaded_pubkey = load_public_key(dir.path()).unwrap();
        assert_eq!(reloaded_pubkey, public_key);

        let mut shares = load_shares(dir.path(), pass, &[1]).unwrap();
        let external_share = load_external_share(pass, &external_shares[0]).unwrap();
        shares.push(external_share);

        let reconstructed = wallet_crypto::shamir::reconstruct_and_verify(&shares, &public_key).unwrap();
        assert_eq!(reconstructed.public_key(), public_key);
    }

    #[test]
    fn wrong_passphrase_fails_closed_on_load() {
        let dir = tempfile::tempdir().unwrap();
        create_wallet(dir.path(), "correct horse battery staple", 2, 3).unwrap();

        let result = load_shares(dir.path(), "wrong but long enough passphrase", &[1]);
        assert!(matches!(result, Err(WalletError::Storage(StorageError::DecryptionFailed))));
    }

    #[test]
    fn imported_wallet_derives_the_same_address_from_external_shares() {
        let dir = tempfile::tempdir().unwrap();
        let pass = "correct horse battery staple";
        let (public_key, external_shares) = create_wallet(dir.path(), pass, 2, 3).unwrap();

        let new_device_dir = tempfile::tempdir().unwrap();
        let imported_public_key = import_wallet(new_device_dir.path(), pass, &external_shares[..2]).unwrap();
        assert_eq!(imported_public_key, public_key);

        let reloaded = load_public_key(new_device_dir.path()).unwrap();
        assert_eq!(reloaded, public_key);
    }

    #[test]
    fn import_wallet_wrong_passphrase_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (_, external_shares) = create_wallet(dir.path(), "correct horse battery staple", 2, 3).unwrap();

        let new_device_dir = tempfile::tempdir().unwrap();
        let result = import_wallet(new_device_dir.path(), "wrong but long enough passphrase", &external_shares[..2]);
        assert!(matches!(result, Err(WalletError::Storage(StorageError::DecryptionFailed))));
    }

    #[test]
    fn loaded_shares_can_sign_through_the_normal_ceremony() {
        let dir = tempfile::tempdir().unwrap();
        let pass = "correct horse battery staple";

        let (public_key, external_shares) = create_wallet(dir.path(), pass, 2, 3).unwrap();
        let mut shares = load_shares(dir.path(), pass, &[1]).unwrap();
        shares.push(load_external_share(pass, &external_shares[0]).unwrap());

        let sig = ceremony::sign_with_shares(&shares, &public_key, &[0x11; 32]).unwrap();
        assert!(public_key.verify_prehash(&[0x11; 32], &sig));
    }
}
