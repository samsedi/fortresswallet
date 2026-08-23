//! Wallet domain logic: key generation orchestration, DKG/threshold-signing
//! ceremonies, nonce-commitment protocol state machines, transaction
//! construction. Pure logic — no direct file/network I/O (that belongs in
//! `wallet-storage` / `wallet-rpc`), so it stays unit-testable without mocks.

pub mod ceremony;
pub mod policy;
