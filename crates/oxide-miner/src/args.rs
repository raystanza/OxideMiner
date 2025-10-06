// OxideMiner/crates/oxide-miner/src/args.rs

use clap::{builder::TypedValueParser, Parser, ValueHint};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

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

    /// Path to a configuration file (default: ./config.toml)
    #[arg(
        long = "config",
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        default_value = "config.toml"
    )]
    pub config: PathBuf,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ConfigFile {
    pub pool: Option<String>,
    pub wallet: Option<String>,
    pub pass: Option<String>,
    pub threads: Option<usize>,
    pub tls: Option<bool>,
    pub tls_ca_cert: Option<PathBuf>,
    pub tls_cert_sha256: Option<String>,
    pub api_port: Option<u16>,
    pub dashboard_dir: Option<PathBuf>,
    pub affinity: Option<bool>,
    pub huge_pages: Option<bool>,
    pub batch_size: Option<usize>,
    pub no_yield: Option<bool>,
    pub debug: Option<bool>,
    pub no_devfee: Option<bool>,
}

impl ConfigFile {
    fn as_cli_args(&self, cli_args: &[OsString]) -> Vec<OsString> {
        let mut args = Vec::new();

        if let Some(pool) = &self.pool {
            if !contains_arg(cli_args, "--url", Some('o')) {
                args.push(OsString::from("--url"));
                args.push(OsString::from(pool));
            }
        }

        if let Some(wallet) = &self.wallet {
            if !contains_arg(cli_args, "--user", Some('u')) {
                args.push(OsString::from("--user"));
                args.push(OsString::from(wallet));
            }
        }

        if let Some(pass) = &self.pass {
            if !contains_arg(cli_args, "--pass", Some('p')) {
                args.push(OsString::from("--pass"));
                args.push(OsString::from(pass));
            }
        }

        if let Some(threads) = self.threads {
            if !contains_arg(cli_args, "--threads", Some('t')) {
                args.push(OsString::from("--threads"));
                args.push(threads.to_string().into());
            }
        }

        if self.tls.unwrap_or(false) && !contains_arg(cli_args, "--tls", None) {
            args.push(OsString::from("--tls"));
        }

        if let Some(path) = &self.tls_ca_cert {
            if !contains_arg(cli_args, "--tls-ca-cert", None) {
                args.push(OsString::from("--tls-ca-cert"));
                args.push(path.clone().into());
            }
        }

        if let Some(fingerprint) = &self.tls_cert_sha256 {
            if !contains_arg(cli_args, "--tls-cert-sha256", None) {
                args.push(OsString::from("--tls-cert-sha256"));
                args.push(OsString::from(fingerprint));
            }
        }

        if let Some(port) = self.api_port {
            if !contains_arg(cli_args, "--api-port", None) {
                args.push(OsString::from("--api-port"));
                args.push(port.to_string().into());
            }
        }

        if let Some(dir) = &self.dashboard_dir {
            if !contains_arg(cli_args, "--dashboard-dir", None) {
                args.push(OsString::from("--dashboard-dir"));
                args.push(dir.clone().into());
            }
        }

        if self.affinity.unwrap_or(false) && !contains_arg(cli_args, "--affinity", None) {
            args.push(OsString::from("--affinity"));
        }

        if self.huge_pages.unwrap_or(false) && !contains_arg(cli_args, "--huge-pages", None) {
            args.push(OsString::from("--huge-pages"));
        }

        if let Some(batch) = self.batch_size {
            if !contains_arg(cli_args, "--batch-size", None) {
                args.push(OsString::from("--batch-size"));
                args.push(batch.to_string().into());
            }
        }

        if self.no_yield.unwrap_or(false) && !contains_arg(cli_args, "--no-yield", None) {
            args.push(OsString::from("--no-yield"));
        }

        if self.debug.unwrap_or(false) && !contains_arg(cli_args, "--debug", None) {
            args.push(OsString::from("--debug"));
        }

        if self.no_devfee.unwrap_or(false) && !contains_arg(cli_args, "--no-devfee", None) {
            args.push(OsString::from("--no-devfee"));
        }

        args
    }
}

pub fn load_args() -> Args {
    let (args, warning) = load_args_from_iter(std::env::args_os());

    if let Some(message) = warning {
        if args.debug {
            eprintln!("warning: {}", message);
        }
    }

    args
}

fn load_args_from_iter<I>(iter: I) -> (Args, Option<String>)
where
    I: IntoIterator<Item = OsString>,
{
    let mut raw_args: Vec<OsString> = iter.into_iter().collect();
    if raw_args.is_empty() {
        raw_args.push(OsString::from("oxide-miner"));
    }

    let program = raw_args[0].clone();
    let cli_args = raw_args[1..].to_vec();
    let config_path = resolve_config_path(&cli_args);
    let (config_args, warning) = load_config_cli_args(&config_path, &cli_args);

    let mut final_args =
        Vec::with_capacity(1 + config_args.len() + raw_args.len().saturating_sub(1));
    final_args.push(program);
    final_args.extend(config_args);
    final_args.extend(raw_args.into_iter().skip(1));

    let args = Args::parse_from(final_args);
    (args, warning)
}

fn resolve_config_path(cli_args: &[OsString]) -> PathBuf {
    let default_path = PathBuf::from("config.toml");

    let mut iter = cli_args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--config" {
            if let Some(value) = iter.next() {
                if !value.is_empty() {
                    return PathBuf::from(value);
                }
            }
        } else if let Some(stripped) = arg.to_str().and_then(|s| s.strip_prefix("--config=")) {
            if !stripped.is_empty() {
                return PathBuf::from(stripped);
            }
        }
    }

    default_path
}

fn load_config_cli_args(path: &Path, cli_args: &[OsString]) -> (Vec<OsString>, Option<String>) {
    if path.as_os_str().is_empty() {
        return (Vec::new(), None);
    }

    match fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<ConfigFile>(&contents) {
            Ok(config) => (config.as_cli_args(cli_args), None),
            Err(err) => (
                Vec::new(),
                Some(format!(
                    "failed to parse config file '{}': {}",
                    path.display(),
                    err
                )),
            ),
        },
        Err(err) => {
            if err.kind() == ErrorKind::NotFound {
                return (
                    Vec::new(),
                    Some(format!(
                        "config file '{}' not found; continuing with CLI arguments",
                        path.display()
                    )),
                );
            }

            (
                Vec::new(),
                Some(format!(
                    "failed to read config file '{}': {}",
                    path.display(),
                    err
                )),
            )
        }
    }
}

fn contains_arg(cli_args: &[OsString], long: &str, short: Option<char>) -> bool {
    for arg in cli_args {
        if let Some(value) = arg.to_str() {
            if value == long || value.starts_with(&format!("{}=", long)) {
                return true;
            }

            if let Some(short_flag) = short {
                let prefix = format!("-{}", short_flag);
                if value == prefix || value.starts_with(&prefix) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{load_args_from_iter, Args};
    use clap::Parser;
    use std::ffi::OsString;
    use std::fs;
    use tempfile::tempdir;

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
        let args = Args::try_parse_from([
            "test",
            "--batch-size",
            "20000",
            "-o",
            "pool:5555",
            "-u",
            "wallet",
        ])
        .unwrap();
        assert_eq!(args.batch_size, Some(20_000));
    }

    #[test]
    fn batch_size_is_none_when_flag_missing() {
        let args = Args::try_parse_from(["test", "-o", "pool:5555", "-u", "wallet"]).unwrap();
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

    #[test]
    fn config_file_supplies_defaults_when_cli_omits_values() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(
            &config_path,
            r#"
pool = "pool.example.com:9000"
wallet = "wallet_address"
pass = "from_config"
threads = 8
debug = true
"#,
        )
        .unwrap();

        let (args, warning) = load_args_from_iter([
            OsString::from("test"),
            OsString::from("--config"),
            config_path.into_os_string(),
        ]);

        assert!(warning.is_none());
        assert_eq!(args.pool.as_deref(), Some("pool.example.com:9000"));
        assert_eq!(args.wallet.as_deref(), Some("wallet_address"));
        assert_eq!(args.pass, "from_config");
        assert_eq!(args.threads, Some(8));
        assert!(args.debug);
    }

    #[test]
    fn cli_arguments_override_config_file_values() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("miner.toml");
        fs::write(
            &config_path,
            r#"
pool = "pool.config:1234"
wallet = "wallet_config"
pass = "config_pass"
threads = 16
huge_pages = true
"#,
        )
        .unwrap();

        let (args, warning) = load_args_from_iter([
            OsString::from("test"),
            OsString::from("--config"),
            config_path.into_os_string(),
            OsString::from("--threads"),
            OsString::from("4"),
            OsString::from("--pass"),
            OsString::from("cli_pass"),
        ]);

        assert!(warning.is_none());
        assert_eq!(args.threads, Some(4));
        assert_eq!(args.pass, "cli_pass");
        assert_eq!(args.pool.as_deref(), Some("pool.config:1234"));
        assert!(args.huge_pages);
    }

    #[test]
    fn missing_config_file_produces_warning() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing.toml");

        let (_args, warning) = load_args_from_iter([
            OsString::from("test"),
            OsString::from("--benchmark"),
            OsString::from("--config"),
            missing.into_os_string(),
        ]);

        let message = warning.expect("expected warning for missing config");
        assert!(message.contains("not found"));
    }
}
