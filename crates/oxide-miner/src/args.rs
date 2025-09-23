// OxideMiner/crates/oxide-miner/src/args.rs

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "OxideMiner - Rust Monero RandomX CPU miner (CLI MVP)"
)]
pub struct Args {
    /// pool like "pool.supportxmr.com:5555"
    #[arg(short = 'o', long = "url", required_unless_present = "benchmark")]
    pub pool: Option<String>,

    /// Your XMR wallet address
    #[arg(short = 'u', long = "user", required_unless_present = "benchmark")]
    pub wallet: Option<String>,

    /// Pool password (often 'x')
    #[arg(short = 'p', long = "pass", default_value = "x")]
    pub pass: String,

    /// Number of threads (omit for auto)
    #[arg(short = 't', long = "threads")]
    pub threads: Option<usize>,

    /// Disable dev fee (testing builds only)
    #[arg(long = "no-devfee")]
    pub no_devfee: bool,

    /// Enable TLS for pool connection
    #[arg(long = "tls")]
    pub tls: bool,

    /// Expose a simple HTTP API on this port
    #[arg(long = "api-port")]
    pub api_port: Option<u16>,

    /// Serve dashboard files from this directory instead of embedded assets
    #[arg(long = "dashboard-dir")]
    pub dashboard_dir: Option<PathBuf>,

    /// Pin worker threads to CPU cores
    #[arg(long = "affinity")]
    pub affinity: bool,

    /// Request huge pages for RandomX dataset
    #[arg(long = "huge-pages")]
    pub huge_pages: bool,

    /// Number of hashes per batch in mining loop
    #[arg(long = "batch-size", default_value_t = 10_000)]
    pub batch_size: usize,

    /// Disable cooperative yields between hash batches
    #[arg(long = "no-yield")]
    pub no_yield: bool,

    /// Enable verbose debug logs; when set, also writes to ./logs/ (daily rotation)
    #[arg(long = "debug")]
    pub debug: bool,

    /// Run a local RandomX benchmark and exit
    #[arg(long = "benchmark")]
    pub benchmark: bool,
}

#[cfg(test)]
mod tests {
    use super::Args;
    use clap::Parser;

    #[test]
    fn benchmark_mode_parses_without_pool_or_wallet() {
        assert!(Args::try_parse_from(["test", "--benchmark"]).is_ok());
    }

    #[test]
    fn mining_mode_parses_with_pool_and_wallet() {
        assert!(Args::try_parse_from(["test", "-o", "pool:5555", "-u", "wallet"]).is_ok());
    }

    #[test]
    fn mining_mode_missing_pool_or_wallet_fails() {
        assert!(Args::try_parse_from(["test"]).is_err());
        assert!(Args::try_parse_from(["test", "-o", "pool:5555"]).is_err());
        assert!(Args::try_parse_from(["test", "-u", "wallet"]).is_err());
    }
}
