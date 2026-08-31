# FortressWallet (Core)

FortressWallet is a secure, threshold-cryptography-backed Ethereum wallet engine written in Rust. It serves as the core backend for the Fortress Flutter application, providing robust key management, transaction signing, and network RPC capabilities while enforcing strict architectural boundaries.

## Architecture

The project is structured as a Rust workspace with several distinct, modular crates:

- **`wallet-crypto`**: Pure cryptographic primitives. Implements Shamir's Secret Sharing (SSS) for distributed key recovery, `secp256k1` ECDSA signing, and Argon2id + XChaCha20-Poly1305 for secure local data encryption.
- **`wallet-core`**: The domain orchestrator. Handles wallet creation, recovery ceremonies (reconstructing a key from Shamir shares), and building EIP-1559 transactions. Contains pure logic with no direct I/O.
- **`wallet-storage`**: Handles all local filesystem I/O. Provides secure sealing and opening of encrypted key material and metadata.
- **`wallet-rpc`**: The network layer. Interacts with EVM-compatible JSON-RPC endpoints to fetch balances, nonces, network gas fees, and broadcast signed transactions.
- **`wallet-decoder`**: Minimal ABI encoding/decoding utilities for interacting with smart contracts (e.g., ERC-20 transfers).
- **`wallet-ffi`**: A C-ABI bridge exposing the wallet's capabilities to external consumers (like Dart/Flutter). Exposes a unified JSON string-based `invoke` pattern.
- **`wallet-cli`**: A command-line interface for testing and interacting with the wallet directly from the terminal without the Flutter frontend.

## Security Features

- **No Plaintext Keys**: Private keys are never stored in plaintext on disk. They are encrypted using an AEAD (XChaCha20-Poly1305) with a key derived via Argon2id.
- **Shamir's Secret Sharing**: Key generation produces $n$ cryptographically secure shares (requiring a threshold $t$ to reconstruct). This eliminates single points of failure in backup and recovery.
- **Strict Boundaries**: The crate structure enforces that the FFI/CLI layers cannot bypass the domain logic in `wallet-core` to directly manipulate storage or cryptographic secrets. Dependency boundaries are enforced via CI scripts (`check_boundaries.sh`).

## Building & Developing

### Prerequisites
- Rust toolchain (`cargo`)
- OpenSSL (required for some networking/crypto dependencies depending on the platform)

### Build the workspace
To build all crates in the workspace:
```bash
cargo build --release
```

### Run Tests
```bash
cargo test
```

### Linting & Boundary Checks
Ensure all code complies with the project's lints and architectural boundaries before committing:
```bash
cargo clippy --all-targets --all-features -- -D warnings
bash scripts/check_boundaries.sh
```

## FFI Integration (Flutter/Dart)

The `wallet-ffi` crate compiles into a dynamic library (`.dylib`, `.so`, or `.xcframework` depending on the platform). The Flutter application bundles this native asset and interacts with it using `dart:ffi`.

To communicate with the Rust backend, the frontend passes JSON-encoded strings to the `invoke` function, which routes the request to the appropriate domain logic and returns a JSON-encoded response or error.
