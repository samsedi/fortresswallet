//! Untrusted-input parsing: raw calldata and EIP-712/typed-data decoding
//! into a human-reviewable transaction summary.
//!
//! Contract for this crate: on any unrecognized structure, malformed input,
//! or parse ambiguity, return an error — never fall back to "sign the raw
//! hex". A failure here must block signing, not bypass it. This crate has
//! no dependency on `wallet-crypto`; it never needs key material, only the
//! untrusted bytes it's decoding.
