//! Command-line entry point for fortresswallet. Talks to `wallet-core`
//! (and `wallet-rpc` for network I/O — `wallet-core` deliberately has
//! none) only — never links `wallet-crypto`/`wallet-storage` directly
//! (enforced by `scripts/check_boundaries.sh`).
//!
//! Every command here is a fresh, one-shot process: there is no
//! persistent spending-policy state across invocations, so `send` uses
//! `wallet_core::evm::sign_evm_transfer` (unguarded) rather than the
//! policy-guarded entry point — see that function's doc comment for why
//! a fresh `PolicyEngine` per process can't provide a meaningful
//! protection. A wallet daemon wanting persistent policy should hold a
//! long-lived engine in memory and call `sign_evm_transfer_with_policy`
//! instead.
//!
//! Every Shamir share for a wallet created by `init` lands as a sibling
//! file under one directory, encrypted under one passphrase — a
//! dev/single-operator convenience, not the production threshold model.
//! See `wallet_core::wallet`'s module docs.

mod hex;
mod passphrase;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use wallet_core::evm as core_evm;
use wallet_core::wallet;
use wallet_rpc::evm::{JsonRpcClient, RpcError};
use wallet_rpc::{CrossCheckError, Endpoint};

#[derive(Parser)]
#[command(name = "fortresswallet", about = "A threshold-signature EVM wallet")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet: run the DKG ceremony and write `n` encrypted
    /// Shamir shares plus the public key under `dir`.
    Init {
        /// Directory to create the wallet in.
        #[arg(long)]
        dir: PathBuf,
        /// Number of shares required to sign.
        #[arg(long)]
        threshold: u8,
        /// Total number of shares to create.
        #[arg(long)]
        n: u8,
    },
    /// Print the wallet's checksummed EVM address.
    Address {
        /// Wallet directory created by `init`.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Query the wallet's balance on one chain, cross-checked across
    /// every `--rpc` endpoint given.
    Balance {
        /// Wallet directory created by `init`.
        #[arg(long)]
        dir: PathBuf,
        /// Chain ID to query.
        #[arg(long)]
        chain: u64,
        /// RPC endpoint URL. Repeat for cross-checking against multiple
        /// independent nodes — recommended for anything funds-critical.
        #[arg(long, required = true)]
        rpc: Vec<String>,
    },
    /// Build, sign, and broadcast a plain native-currency transfer.
    Send {
        /// Wallet directory created by `init`.
        #[arg(long)]
        dir: PathBuf,
        /// Chain ID to send on.
        #[arg(long)]
        chain: u64,
        /// Recipient address, `0x`-prefixed.
        #[arg(long)]
        to: String,
        /// Amount to send, in wei.
        #[arg(long)]
        value: u128,
        /// RPC endpoint URL. Repeat for cross-checking against multiple
        /// independent nodes. The first is also used to broadcast.
        #[arg(long, required = true)]
        rpc: Vec<String>,
        /// Share index to use for signing (per `init`'s `--threshold`,
        /// e.g. `--share 1 --share 2` for a 2-of-n wallet). Must supply
        /// at least `threshold`-many.
        #[arg(long, required = true)]
        share: Vec<u8>,
        /// Gas limit. Defaults to 21000 (a plain transfer's fixed cost —
        /// this wallet only ever sends transfers with no calldata).
        #[arg(long, default_value_t = 21_000)]
        gas_limit: u64,
    },
    /// Check a transaction's confirmation status.
    Status {
        /// Transaction hash, `0x`-prefixed.
        #[arg(long)]
        tx: String,
        /// RPC endpoint URL to query.
        #[arg(long)]
        rpc: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Init { dir, threshold, n } => cmd_init(&dir, threshold, n),
        Command::Address { dir } => cmd_address(&dir),
        Command::Balance { dir, chain, rpc } => cmd_balance(&dir, chain, &rpc),
        Command::Send { dir, chain, to, value, rpc, share, gas_limit } => cmd_send(&dir, chain, &to, value, &rpc, &share, gas_limit),
        Command::Status { tx, rpc } => cmd_status(&tx, &rpc),
    }
}

fn cmd_init(dir: &std::path::Path, threshold: u8, n: u8) -> Result<(), CliError> {
    let pass = passphrase::read_passphrase("Enter a passphrase to encrypt the wallet shares: ");
    let confirm = passphrase::read_passphrase("Confirm passphrase: ");
    if *pass != *confirm {
        return Err(CliError::Message("passphrases did not match".to_string()));
    }

    let (public_key, external_shares) = wallet::create_wallet(dir, &pass, threshold, n)?;
    let address = core_evm::address_from_public_key(&public_key);
    println!("Wallet created at {}", dir.display());
    println!("Address: {}", core_evm::to_checksummed_hex(&address));
    println!("Share 1 (Device Share) has been saved securely to {}", dir.display());
    
    println!("\n========================================================");
    println!("CRITICAL: EXTERNAL SHARES");
    println!("These shares were NOT saved to disk to protect your funds.");
    println!("Store these shares securely on separate devices or paper.");
    println!("========================================================");
    for (i, sealed) in external_shares.iter().enumerate() {
        println!("Share {}: {}", i + 2, hex::to_hex(sealed));
    }
    println!("========================================================");
    Ok(())
}

fn cmd_address(dir: &std::path::Path) -> Result<(), CliError> {
    let public_key = wallet::load_public_key(dir)?;
    let address = core_evm::address_from_public_key(&public_key);
    println!("{}", core_evm::to_checksummed_hex(&address));
    Ok(())
}

fn endpoints(urls: &[String]) -> Vec<Endpoint> {
    urls.iter().map(|u| Endpoint(u.clone())).collect()
}

fn cmd_balance(dir: &std::path::Path, chain: u64, rpc_urls: &[String]) -> Result<(), CliError> {
    let public_key = wallet::load_public_key(dir)?;
    let address = core_evm::address_from_public_key(&public_key);

    let endpoints = endpoints(rpc_urls);
    let (primary, rest) = endpoints.split_first().expect("clap enforces at least one --rpc");

    verify_chain_id(primary, rest, chain)?;

    let primary_client = JsonRpcClient::new(primary.clone());
    let balance = primary_client.balance(&address)?;
    let verified = balance.try_cross_check(rest, |endpoint| JsonRpcClient::new(endpoint.clone()).balance(&address).map(wallet_rpc::Untrusted::trust))?;

    println!("{verified} wei");
    Ok(())
}

/// Every configured endpoint must agree it's serving `expected_chain` —
/// a misconfigured or malicious node answering for the wrong chain would
/// otherwise let a transaction be built/signed as if for a chain the
/// user never intended.
fn verify_chain_id(primary: &Endpoint, rest: &[Endpoint], expected_chain: u64) -> Result<(), CliError> {
    let client = JsonRpcClient::new(primary.clone());
    let chain_id = client.chain_id()?;
    let verified = chain_id.try_cross_check(rest, |endpoint| JsonRpcClient::new(endpoint.clone()).chain_id().map(wallet_rpc::Untrusted::trust))?;
    if verified != expected_chain {
        return Err(CliError::Message(format!("--chain {expected_chain} was requested, but the RPC endpoint(s) report chain ID {verified}")));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_send(dir: &std::path::Path, chain: u64, to: &str, value: u128, rpc_urls: &[String], share_indices: &[u8], gas_limit: u64) -> Result<(), CliError> {
    use std::io::Write as _;

    let to_address = hex::parse_address(to)?;
    let public_key = wallet::load_public_key(dir)?;

    let endpoints = endpoints(rpc_urls);
    let (primary, rest) = endpoints.split_first().expect("clap enforces at least one --rpc");
    verify_chain_id(primary, rest, chain)?;

    let primary_client = JsonRpcClient::new(primary.clone());
    let our_address = core_evm::address_from_public_key(&public_key);

    let nonce = primary_client.transaction_count(&our_address)?;
    let nonce = nonce.try_cross_check(rest, |endpoint| JsonRpcClient::new(endpoint.clone()).transaction_count(&our_address).map(wallet_rpc::Untrusted::trust))?;

    let fees = primary_client.fee_suggestion()?.trust(); // not funds-critical: an under/over-estimate fails or overpays gas, doesn't lose funds to a lying node the way balance/nonce would.

    let tx = core_evm::build_unsigned_transfer(chain, to_address, value, nonce, fees.max_fee_per_gas, fees.max_priority_fee_per_gas, gas_limit)?;

    let pass = passphrase::read_passphrase("Enter the wallet passphrase to load signing shares: ");
    
    let mut shares = Vec::new();
    
    if share_indices.contains(&1) {
        let local_shares = wallet::load_shares(dir, &pass, &[1])?;
        shares.extend(local_shares);
    }
    
    for &idx in share_indices {
        if idx == 1 { continue; }

        print!("Paste the hex string for Share {idx}: ");
        std::io::stdout().flush().unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        
        let share_bytes = hex::parse_hex(input.trim())?;
        let share = wallet::load_external_share(&pass, &share_bytes)?;
        shares.push(share);
    }

    let raw = core_evm::sign_evm_transfer(tx, &shares, &public_key)?;

    let tx_hash = primary_client.send_raw_transaction(&raw)?.trust();
    println!("Broadcast: {}", hex::to_hex(&tx_hash));
    Ok(())
}

fn cmd_status(tx: &str, rpc_url: &str) -> Result<(), CliError> {
    let tx_hash = hex::parse_tx_hash(tx)?;
    let client = JsonRpcClient::new(Endpoint(rpc_url.to_string()));

    let receipt = client.transaction_receipt(&tx_hash)?.trust();
    match receipt {
        None => println!("pending (not yet mined)"),
        Some(r) => {
            let current_block = client.block_number()?.trust();
            let confirmations = current_block.saturating_sub(r.block_number).saturating_add(1);
            println!("mined in block {}, {} confirmation(s), status: {}", r.block_number, confirmations, if r.success { "success" } else { "reverted" });
        }
    }
    Ok(())
}

#[derive(Debug)]
enum CliError {
    Message(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Message(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<wallet::WalletError> for CliError {
    fn from(e: wallet::WalletError) -> Self {
        CliError::Message(format!("wallet error: {e:?}"))
    }
}

impl From<RpcError> for CliError {
    fn from(e: RpcError) -> Self {
        CliError::Message(format!("RPC error: {e}"))
    }
}

impl<E: std::fmt::Debug> From<CrossCheckError<E>> for CliError {
    fn from(e: CrossCheckError<E>) -> Self {
        match e {
            CrossCheckError::Query(endpoint, err) => CliError::Message(format!("RPC query to {} failed: {err:?}", endpoint.0)),
            CrossCheckError::Disagreement(d) => CliError::Message(format!(
                "RPC endpoints disagree: {} and {} returned different values for the same query — refusing to proceed",
                d.primary.0, d.disagreeing.0
            )),
        }
    }
}

impl From<core_evm::EvmCeremonyError> for CliError {
    fn from(e: core_evm::EvmCeremonyError) -> Self {
        CliError::Message(format!("signing failed: {e:?}"))
    }
}

impl From<hex::HexParseError> for CliError {
    fn from(e: hex::HexParseError) -> Self {
        CliError::Message(e.to_string())
    }
}

impl From<core_evm::EvmBuildError> for CliError {
    fn from(e: core_evm::EvmBuildError) -> Self {
        CliError::Message(format!("transaction build error: {e}"))
    }
}
