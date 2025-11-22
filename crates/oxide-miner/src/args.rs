// OxideMiner/crates/oxide-miner/src/args.rs

use clap::{builder::TypedValueParser, Parser, ValueHint};
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser, Debug, Clone)]
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

    /// Path to configuration file (defaults to ./config.toml)
    #[arg(long = "config", value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub config: Option<PathBuf>,

    /// Run a local RandomX benchmark and exit
    #[arg(long = "benchmark")]
    pub benchmark: bool,

    /// Route pool connections through a SOCKS5 proxy (socks5://[user:pass@]host:port)
    #[arg(long = "proxy", value_name = "URL", value_hint = ValueHint::Url)]
    pub proxy: Option<String>,

    /// Enable Tari merge mining via minotari_merge_mining_proxy
    #[arg(long = "tari-merge-mining")]
    pub tari_merge_mining: bool,

    /// URL of the minotari merge mining proxy (e.g. http://127.0.0.1:18089)
    #[arg(long = "tari-proxy-url", value_hint = ValueHint::Url, default_value = "http://127.0.0.1:18089")]
    pub tari_proxy_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(alias = "url")]
    pub pool: Option<String>,
    #[serde(alias = "user")]
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
    pub proxy: Option<String>,
    pub tari_merge_mining: Option<bool>,
    pub tari_proxy_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConfigWarning {
    message: String,
    debug_only: bool,
}

impl ConfigWarning {
    fn new(message: String, debug_only: bool) -> Self {
        Self {
            message,
            debug_only,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn should_print(&self, debug: bool) -> bool {
        debug || !self.debug_only
    }
}

#[derive(Debug, Clone)]
pub struct ParsedArgs {
    pub args: Args,
    pub warnings: Vec<ConfigWarning>,
}

pub fn parse_with_config() -> ParsedArgs {
    parse_with_config_from(env::args_os()).unwrap_or_else(|err| err.exit())
}

pub fn parse_with_config_from<I, T>(raw_args: I) -> Result<ParsedArgs, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut args_vec: Vec<OsString> = raw_args.into_iter().map(Into::into).collect();
    if args_vec.is_empty() {
        args_vec.push(OsString::from("oxide-miner"));
    }

    let original_args = args_vec.clone();
    let (config_path, explicit_config) = determine_config_path(&original_args);

    let mut warnings = Vec::new();
    if let Some(cfg) = load_config_file(&config_path, explicit_config, &mut warnings) {
        apply_config_defaults(&cfg, &original_args, &mut args_vec);
    }

    match Args::try_parse_from(args_vec) {
        Ok(args) => Ok(ParsedArgs { args, warnings }),
        Err(err) => Err(err),
    }
}

fn determine_config_path(args: &[OsString]) -> (PathBuf, bool) {
    let mut explicit = false;
    let mut path = PathBuf::from("config.toml");

    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if let Some(s) = arg.to_str() {
            if let Some(value) = s.strip_prefix("--config=") {
                path = PathBuf::from(value);
                explicit = true;
                continue;
            }
            if s == "--config" {
                if let Some(next) = iter.next() {
                    path = PathBuf::from(next);
                    explicit = true;
                }
                continue;
            }
        }
    }

    (path, explicit)
}

fn load_config_file(
    path: &Path,
    explicit: bool,
    warnings: &mut Vec<ConfigWarning>,
) -> Option<ConfigFile> {
    let debug_only = !explicit;

    if !explicit && !path.exists() {
        warnings.push(ConfigWarning::new(
            format!("config file not found at {}", path.display()),
            debug_only,
        ));
        return None;
    }

    match fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<ConfigFile>(&contents) {
            Ok(cfg) => Some(cfg),
            Err(err) => {
                warnings.push(ConfigWarning::new(
                    format!("failed to parse config file {}: {err}", path.display()),
                    debug_only,
                ));
                None
            }
        },
        Err(err) => {
            warnings.push(ConfigWarning::new(
                format!("failed to read config file {}: {err}", path.display()),
                debug_only,
            ));
            None
        }
    }
}

fn apply_config_defaults(
    config: &ConfigFile,
    original_args: &[OsString],
    args: &mut Vec<OsString>,
) {
    if let Some(pool) = config.pool.as_ref() {
        if !has_arg(original_args, Some("o"), Some("url")) {
            push_value(args, "--url", pool.as_str());
        }
    }

    if let Some(wallet) = config.wallet.as_ref() {
        if !has_arg(original_args, Some("u"), Some("user")) {
            push_value(args, "--user", wallet.as_str());
        }
    }

    if let Some(pass) = config.pass.as_ref() {
        if !has_arg(original_args, Some("p"), Some("pass")) {
            push_value(args, "--pass", pass.as_str());
        }
    }

    if let Some(tari) = config.tari_merge_mining {
        if tari && !has_arg(original_args, None, Some("tari-merge-mining")) {
            args.push(OsString::from("--tari-merge-mining"));
        }
    }

    if let Some(proxy_url) = config.tari_proxy_url.as_ref() {
        if !has_arg(original_args, None, Some("tari-proxy-url")) {
            push_value(args, "--tari-proxy-url", proxy_url.as_str());
        }
    }

    if let Some(threads) = config.threads {
        if !has_arg(original_args, Some("t"), Some("threads")) {
            push_value(args, "--threads", threads.to_string());
        }
    }

    if config.tls == Some(true) && !has_arg(original_args, None, Some("tls")) {
        push_flag(args, "--tls");
    }

    if let Some(cert) = config.tls_ca_cert.as_ref() {
        if !has_arg(original_args, None, Some("tls-ca-cert")) {
            push_value_os(args, "--tls-ca-cert", cert.as_os_str());
        }
    }

    if let Some(fingerprint) = config.tls_cert_sha256.as_ref() {
        if !has_arg(original_args, None, Some("tls-cert-sha256")) {
            push_value(args, "--tls-cert-sha256", fingerprint.as_str());
        }
    }

    if let Some(port) = config.api_port {
        if !has_arg(original_args, None, Some("api-port")) {
            push_value(args, "--api-port", port.to_string());
        }
    }

    if let Some(dir) = config.dashboard_dir.as_ref() {
        if !has_arg(original_args, None, Some("dashboard-dir")) {
            push_value_os(args, "--dashboard-dir", dir.as_os_str());
        }
    }

    if config.affinity == Some(true) && !has_arg(original_args, None, Some("affinity")) {
        push_flag(args, "--affinity");
    }

    if config.huge_pages == Some(true) && !has_arg(original_args, None, Some("huge-pages")) {
        push_flag(args, "--huge-pages");
    }

    if let Some(batch_size) = config.batch_size {
        if !has_arg(original_args, None, Some("batch-size")) {
            push_value(args, "--batch-size", batch_size.to_string());
        }
    }

    if config.no_yield == Some(true) && !has_arg(original_args, None, Some("no-yield")) {
        push_flag(args, "--no-yield");
    }

    if config.debug == Some(true) && !has_arg(original_args, None, Some("debug")) {
        push_flag(args, "--debug");
    }

    if let Some(proxy) = config.proxy.as_ref() {
        if !has_arg(original_args, None, Some("proxy")) {
            push_value(args, "--proxy", proxy.as_str());
        }
    }
}

fn has_arg(args: &[OsString], short: Option<&str>, long: Option<&str>) -> bool {
    let long_flag = long.map(|name| OsString::from(format!("--{name}")));
    let long_prefix = long.map(|name| format!("--{name}="));
    let short_flag = short.map(|name| OsString::from(format!("-{name}")));

    for arg in args.iter().skip(1) {
        if let Some(ref flag) = long_flag {
            if arg == flag {
                return true;
            }
        }
        if let Some(ref prefix) = long_prefix {
            if arg.to_string_lossy().starts_with(prefix) {
                return true;
            }
        }
        if let Some(ref flag) = short_flag {
            if arg == flag {
                return true;
            }
            let arg_str = arg.to_string_lossy();
            if arg_str.starts_with(flag.to_string_lossy().as_ref()) && arg_str.len() > flag.len() {
                return true;
            }
        }
    }

    false
}

fn push_flag(args: &mut Vec<OsString>, flag: &str) {
    args.push(OsString::from(flag));
}

fn push_value<S: AsRef<str>>(args: &mut Vec<OsString>, flag: &str, value: S) {
    args.push(OsString::from(flag));
    args.push(OsString::from(value.as_ref()));
}

fn push_value_os(args: &mut Vec<OsString>, flag: &str, value: &OsStr) {
    args.push(OsString::from(flag));
    args.push(value.to_os_string());
}

#[cfg(test)]
mod tests {
    use super::{parse_with_config_from, Args};
    use clap::Parser;
    use std::{ffi::OsString, fs};
    use tempfile::NamedTempFile;

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
            "-o",
            "pool:5555",
            "-u",
            "wallet",
            "--batch-size",
            "20000",
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
        assert!(Args::try_parse_from([
            "test",
            "-o",
            "pool:5555",
            "-u",
            "wallet",
            "--threads",
            "0"
        ])
        .is_err());
    }

    #[test]
    fn batch_size_zero_rejected() {
        assert!(Args::try_parse_from([
            "test",
            "-o",
            "pool:5555",
            "-u",
            "wallet",
            "--batch-size",
            "0"
        ])
        .is_err());
    }

    #[test]
    fn config_file_supplies_defaults() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            "pool = \"configpool:5555\"\nwallet = \"configwallet\"\npass = \"configpass\"\nthreads = 8\ndebug = true\n",
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.pool.as_deref(), Some("configpool:5555"));
        assert_eq!(parsed.args.wallet.as_deref(), Some("configwallet"));
        assert_eq!(parsed.args.pass, "configpass");
        assert_eq!(parsed.args.threads, Some(8));
        assert!(parsed.args.debug);
    }

    #[test]
    fn cli_overrides_config_values() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            r#"
pool = "configpool:5555"
wallet = "configwallet"
pass = "configpass"
threads = 2
batch_size = 5000
        "#,
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
            OsString::from("--threads"),
            OsString::from("4"),
            OsString::from("--pass"),
            OsString::from("cli-pass"),
            OsString::from("--batch-size"),
            OsString::from("7500"),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.threads, Some(4));
        assert_eq!(parsed.args.pass, "cli-pass");
        assert_eq!(parsed.args.batch_size, Some(7_500));
        assert_eq!(parsed.args.pool.as_deref(), Some("configpool:5555"));
        assert_eq!(parsed.args.wallet.as_deref(), Some("configwallet"));
    }

    #[test]
    fn invalid_config_emits_warning() {
        let config = NamedTempFile::new().unwrap();
        fs::write(config.path(), "threads = \"oops\"").unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("-o"),
            OsString::from("pool:5555"),
            OsString::from("-u"),
            OsString::from("wallet"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].message().contains("failed to parse"));
        assert!(parsed.warnings[0].should_print(false));
    }
}
