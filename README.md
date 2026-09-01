# FortressWallet (Rust Core)

A highly secure, threshold-cryptography-backed Ethereum wallet engine written in Rust. This repository serves as the core backend for the Fortress Wallet ecosystem (e.g., the Flutter application), providing robust key management, transaction signing, and network RPC capabilities while strictly isolating cryptographic secrets from the frontend UI.

There is no backend database and no centralized key custody. Mnemonic generation, address derivation, transaction construction, and signing all happen purely on the device using a 2-of-3 Shamir's Secret Sharing scheme.

## 📱 Download

[**Download Fortress Wallet APK (Android)**](./fortress.apk)

## Contents
- [Features](#features)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Threat model](#threat-model)
- [Local development](#local-development)
- [Testing & Validation](#testing--validation)
- [License](#license)

## Features

- **Shamir's Secret Sharing (SSS)** — Securely splits the deterministic root key into a 2-of-3 threshold backup system. 
- **Pure Cryptographic Primitives** — Implements `secp256k1` ECDSA signing, and Argon2id + XChaCha20-Poly1305 for secure local vault encryption.
- **BIP39 & BIP44/BIP32** — Standardized 12-word recovery phrase support with EVM path derivation (`m/44'/60'/0'/0/0`).
- **Direct RPC Layer** — Directly interacts with EVM JSON-RPC endpoints to fetch balances, nonces, and broadcast raw signed transactions without proprietary middlemen.
- **FFI Bridge** — A C-ABI bridge (`wallet-ffi`) exposing the engine to external UI consumers (like Dart/Flutter) via a safe, unified JSON string-based `invoke` pattern.
- **Strict Execution Boundaries** — Enforced boundaries ensure that the frontend can never extract plaintext private keys from the engine memory.

## Architecture

The project is structured as a Rust workspace with distinct, modular crates:

| Crate | Responsibility | May not |
|---|---|---|
| `wallet-core` | The domain orchestrator. Handles recovery ceremonies, address derivation, and building EIP-1559 transactions. | Perform unverified I/O or persist keys. |
| `wallet-crypto` | Pure cryptography (`secp256k1`, `argon2`, `xchacha20poly1305`). | Hold secrets beyond a single function scope. |
| `wallet-storage` | Local filesystem I/O. Secure sealing and opening of encrypted key material. | Leak ciphertext or metadata to external networks. |
| `wallet-rpc` | The network layer. Fetches network gas fees, nonces, and broadcasts RLP-encoded TXs. | Be trusted; all RPC responses must be validated. |
| `wallet-ffi` | C-ABI dynamic library boundary for Flutter (`dart:ffi`). | Expose private key strings to the UI consumer. |
| `wallet-cli` | Command-line interface for headless testing. | Bypass core validation checks. |

## Security model

### What secrets exist
The root BIP39 seed and the resulting ECDSA private key. These are ephemeral in memory. 
At rest, the keys are translated into Shamir shares, and securely encrypted.

### Where they live
Private keys are never stored in plaintext on disk. The shares are encrypted using an AEAD (`XChaCha20-Poly1305`) with a key derived via `Argon2id` from the user's passcode. The resulting ciphertext is stored via local file storage. A wrong passcode results in a GCM authentication failure—offline guessing requires paying the full Argon2id computational cost.

### What is trusted
- The device's underlying OS filesystem (assumed sandboxed/unrooted).
- The audited Rust cryptographic libraries: `k256`, `argon2`, `chacha20poly1305`, `rand`. 
- The platform CSPRNG (via `getrandom`).

### What is not trusted
- **The Frontend (UI)**: The UI can request transaction signatures but cannot ask the core engine to dump the private key in plaintext.
- **The RPC Node**: The node can lie about balances and withhold data, but it cannot forge ECDSA signatures or steal funds, because the raw transaction is entirely assembled, hashed, and signed locally by `wallet-core` before transmission.

### How transactions are protected
- **RLP Encoding**: Transactions are serialized according to standard Ethereum RLP rules.
- **EIP-155** Replay protection via explicit Chain IDs.
- **Memory Scrubbing**: Sensitive variables are explicitly zeroed out of memory (`zeroize`) as soon as the signature is produced and verification succeeds.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Attacker extracts the local vault files | Ciphertext is protected by Argon2id and XChaCha20-Poly1305. | An attacker with a weak passcode can still brute-force the vault offline. |
| Malicious RPC / Block Explorer | `wallet-core` builds and signs the transaction locally. | Can deny service or feed inflated gas estimates. |
| Compromised UI Frontend | `wallet-ffi` does not expose endpoints to retrieve plaintext private keys. | A compromised UI can trick the user into authorizing a transaction to an attacker's address. |
| Memory dumping (Cold boot / malware) | `zeroize` is used to scrub critical secrets immediately after use. | A memory dump at the exact millisecond of a transaction signing could theoretically capture the key. |

## Local development

### Prerequisites
- Rust toolchain (`cargo`)
- OpenSSL (required for some networking/crypto dependencies depending on the platform)

### Build the workspace
To build all crates in the workspace:
```bash
cargo build --release
```

### Testing & Validation
The suite covers derivation paths, transaction planning, threshold cryptography, and memory guardrails.
```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
bash scripts/check_boundaries.sh
```

## License

MIT — see [LICENSE](LICENSE).
