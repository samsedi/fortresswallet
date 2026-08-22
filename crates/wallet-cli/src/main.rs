//! Command-line entry point for fortresswallet. Talks to `wallet-core`
//! only — never links `wallet-crypto`/`wallet-storage` directly (enforced
//! by `scripts/check_boundaries.sh`).

mod passphrase;

fn main() {
    println!("fortresswallet scaffold — no wallet functionality yet");
}
