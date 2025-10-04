// OxideMiner/crates/oxide-miner/src/args.rs

use clap::{
    {Parser, ValueHint},
    {builder::TypedValueParser}
};
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
    #[arg(
        short = 't',
        long  = "threads",
        value_parser = clap::value_parser!(u64)
            .range(1..)
            .try_map(|n| usize::try_from(n)
                .map_err(|_| String::from("threads too large for usize on this platform")))
    )]
    pub threads: Option<usize>,

    /// Enable TLS for pool connection
    #[arg(long = "tls")]
    pub tls: bool,

    /// Path to additional PEM/DER CA certificate to trust when using TLS
    #[arg(long = "tls-ca-cert", value_name = "PATH", requires = "tls")]
    pub tls_ca_cert: Option<PathBuf>,

    /// SHA-256 fingerprint of the expected TLS server certificate (hex)
    #[arg(long = "tls-cert-sha256", value_name = "HEX", requires = "tls")]
    pub tls_cert_sha256: Option<String>,

    /// Expose a simple HTTP API on this port
    #[arg(long = "api-port", value_parser = clap::value_parser!(u16).range(1..=65535))]
    pub api_port: Option<u16>,

    /// Serve dashboard files from this directory instead of embedded assets
    #[arg(long = "dashboard-dir", value_name = "DIR", value_hint = ValueHint::DirPath)]
    pub dashboard_dir: Option<PathBuf>,

    /// Pin worker threads to CPU cores
    #[arg(long = "affinity")]
    pub affinity: bool,

    /// Request huge pages for RandomX dataset
    #[arg(long = "huge-pages")]
    pub huge_pages: bool,

    /// Number of hashes per batch in the mining loop.
    /// Omit this flag to auto-tune based on your CPU/cache profile (recommended).
    #[arg(
        long = "batch-size",
        value_name = "N",
        value_parser = clap::value_parser!(u64)
            .range(1..)
            .try_map(|n| usize::try_from(n)
                .map_err(|_| String::from("batch-size too large for usize on this platform")))
    )]
    pub batch_size: Option<usize>,

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

    #[test]
    fn batch_size_parses_as_some_when_flag_present() {
        let args = Args::try_parse_from(["test", "--batch-size", "20000"]).unwrap();
        assert_eq!(args.batch_size, Some(20_000));
    }

    #[test]
    fn batch_size_is_none_when_flag_missing() {
        let args = Args::try_parse_from(["test"]).unwrap();
        assert_eq!(args.batch_size, None);
    }

    #[test]
    fn threads_zero_rejected() {
        assert!(Args::try_parse_from(["test", "--threads", "0"]).is_err());
    }

    #[test]
    fn batch_size_zero_rejected() {
        assert!(Args::try_parse_from(["test", "--batch-size", "0"]).is_err());
    }

}
