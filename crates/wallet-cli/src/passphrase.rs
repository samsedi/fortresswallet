//! Passphrase input rules for this CLI:
//!
//! 1. NEVER accept a passphrase as a CLI argument (`--passphrase "..."`)
//!    — it would appear in `ps aux`, shell history, and process logs.
//!    There is deliberately no such flag anywhere in this crate.
//!
//! 2. Read the passphrase interactively from the terminal with echo
//!    disabled, via `rpassword`.
//!
//! 3. Wrap it in `Zeroizing<String>` immediately after reading, so it's
//!    wiped the moment it goes out of scope rather than lingering in a
//!    heap-allocated `String` until the allocator happens to reuse that
//!    memory.
//!
//! 4. Never log, print, or include the passphrase in an error message —
//!    every error type it can flow into (`wallet_core`/`wallet_storage`)
//!    must not embed the passphrase itself, only describe the failure.

use zeroize::Zeroizing;

/// Prompt on the terminal with echo disabled and return the passphrase
/// wrapped for automatic zeroization on drop.
///
/// `#[expect(dead_code)]` rather than `#[allow(dead_code)]`: this is
/// unused only until the CLI grows an unlock/sign command that calls it —
/// `expect` will itself start erroring (unfulfilled expectation) the
/// moment that wiring lands and this suppression is no longer needed,
/// so it can't be forgotten and left stale.
#[expect(dead_code)]
pub(crate) fn read_passphrase(prompt: &str) -> Zeroizing<String> {
    let pass = rpassword::prompt_password(prompt).expect("failed to read passphrase from terminal");
    Zeroizing::new(pass)
}
