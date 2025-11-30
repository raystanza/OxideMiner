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
    #[arg(short = 'o', long = "monero-url", alias = "url")]
    pub monero_pool: Option<String>,

    /// Your XMR wallet address
    #[arg(short = 'u', long = "monero-wallet", alias = "user")]
    pub monero_wallet: Option<String>,

    /// Pool password (often 'x')
    #[arg(short = 'p', long = "monero-pass", alias = "pass", default_value = "x")]
    pub monero_pass: String,

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

    /// Tari backend selection: none, proxy, or pool
    #[arg(long = "tari-mode", value_name = "MODE", value_parser = ["none", "proxy", "pool"], default_value = "none")]
    pub tari_mode: String,

    /// Tari algorithm when in Tari pool mode (randomx or sha3x)
    #[arg(long = "tari-algorithm", short = 'A', value_name = "ALGO", value_parser = ["randomx", "sha3x"])]
    pub tari_algorithm: Option<String>,

    /// URL of the minotari merge mining proxy (e.g. http://127.0.0.1:18081)
    #[arg(long = "tari-proxy-url", value_hint = ValueHint::Url, default_value = "http://127.0.0.1:18081")]
    pub tari_proxy_url: String,

    /// Monero address to supply when the merge-mining proxy expects a Monero-compatible
    /// get_block_template fallback.
    #[arg(long = "tari-monero-wallet", value_name = "XMR_ADDRESS")]
    pub tari_monero_wallet: Option<String>,

    /// Tari pool stratum URL (e.g. stratum+tcp://tarirx.pool:port)
    #[arg(long = "tari-pool", alias = "tari-pool-url", value_name = "URL")]
    pub tari_pool: Option<String>,

    /// Tari wallet address for pool payouts
    #[arg(
        long = "tari-wallet",
        alias = "tari-wallet-address",
        value_name = "TARI_ADDRESS"
    )]
    pub tari_wallet: Option<String>,

    /// Optional worker/rig identifier for Tari pool mining
    #[arg(long = "tari-rig-id", value_name = "NAME")]
    pub tari_rig_id: Option<String>,

    /// Optional login/username for Tari pool mining
    #[arg(long = "tari-login", value_name = "LOGIN")]
    pub tari_login: Option<String>,

    /// Optional password for Tari pool mining
    #[arg(long = "tari-password", value_name = "PASSWORD")]
    pub tari_password: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(alias = "url", alias = "pool")]
    pub monero_pool: Option<String>,
    #[serde(alias = "user", alias = "wallet")]
    pub monero_wallet: Option<String>,
    #[serde(alias = "pass")]
    pub monero_pass: Option<String>,
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
    pub tari_mode: Option<String>,
    pub tari_proxy_url: Option<String>,
    pub tari_monero_wallet: Option<String>,
    #[serde(alias = "tari_pool_url", alias = "pool_url")]
    pub tari_pool: Option<String>,
    #[serde(alias = "tari_wallet_address", alias = "wallet_address")]
    pub tari_wallet: Option<String>,
    pub tari_rig_id: Option<String>,
    pub tari_login: Option<String>,
    pub tari_password: Option<String>,
    pub tari: Option<TariFileConfig>,
    pub tari_algorithm: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TariFileConfig {
    pub mode: Option<String>,
    #[serde(alias = "pool_url")]
    pub tari_pool: Option<String>,
    #[serde(alias = "wallet_address")]
    pub tari_wallet: Option<String>,
    pub rig_id: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    pub proxy_url: Option<String>,
    pub tari_monero_wallet: Option<String>,
    pub algorithm: Option<String>,
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
    if let Some(pool) = config.monero_pool.as_ref() {
        if !has_arg(original_args, Some("o"), Some("monero-url"))
            && !has_arg(original_args, Some("o"), Some("url"))
        {
            push_value(args, "--monero-url", pool.as_str());
        }
    }

    if let Some(wallet) = config.monero_wallet.as_ref() {
        if !has_arg(original_args, Some("u"), Some("monero-wallet"))
            && !has_arg(original_args, Some("u"), Some("user"))
        {
            push_value(args, "--monero-wallet", wallet.as_str());
        }
    }

    if let Some(pass) = config.monero_pass.as_ref() {
        if !has_arg(original_args, Some("p"), Some("monero-pass"))
            && !has_arg(original_args, Some("p"), Some("pass"))
        {
            push_value(args, "--monero-pass", pass.as_str());
        }
    }

    if let Some(tari) = config.tari_merge_mining {
        if tari && !has_arg(original_args, None, Some("tari-merge-mining")) {
            args.push(OsString::from("--tari-merge-mining"));
        }
    }

    if let Some(tari_cfg) = config.tari.as_ref() {
        if let Some(mode) = tari_cfg.mode.as_ref() {
            if !has_arg(original_args, None, Some("tari-mode")) {
                push_value(args, "--tari-mode", mode.as_str());
            }
        }

        if let Some(pool) = tari_cfg.tari_pool.as_ref() {
            if !has_arg(original_args, None, Some("tari-pool"))
                && !has_arg(original_args, None, Some("tari-pool-url"))
            {
                push_value(args, "--tari-pool", pool.as_str());
            }
        }

        if let Some(wallet) = tari_cfg.tari_wallet.as_ref() {
            if !has_arg(original_args, None, Some("tari-wallet"))
                && !has_arg(original_args, None, Some("tari-wallet-address"))
            {
                push_value(args, "--tari-wallet", wallet.as_str());
            }
        }

        if let Some(rig) = tari_cfg.rig_id.as_ref() {
            if !has_arg(original_args, None, Some("tari-rig-id")) {
                push_value(args, "--tari-rig-id", rig.as_str());
            }
        }

        if let Some(login) = tari_cfg.login.as_ref() {
            if !has_arg(original_args, None, Some("tari-login")) {
                push_value(args, "--tari-login", login.as_str());
            }
        }

        if let Some(password) = tari_cfg.password.as_ref() {
            if !has_arg(original_args, None, Some("tari-password")) {
                push_value(args, "--tari-password", password.as_str());
            }
        }

        if let Some(algorithm) = tari_cfg.algorithm.as_ref() {
            if !has_arg(original_args, None, Some("tari-algorithm")) {
                push_value(args, "--tari-algorithm", algorithm.as_str());
            }
        }

        if let Some(proxy_url) = tari_cfg.proxy_url.as_ref() {
            if !has_arg(original_args, None, Some("tari-proxy-url")) {
                push_value(args, "--tari-proxy-url", proxy_url.as_str());
            }
        }

        if let Some(wallet) = tari_cfg.tari_monero_wallet.as_ref() {
            if !has_arg(original_args, None, Some("tari-monero-wallet")) {
                push_value(args, "--tari-monero-wallet", wallet.as_str());
            }
        }
    }

    if let Some(mode) = config.tari_mode.as_ref() {
        if !has_arg(original_args, None, Some("tari-mode")) {
            push_value(args, "--tari-mode", mode.as_str());
        }
    }

    if let Some(algo) = config.tari_algorithm.as_ref() {
        if !has_arg(original_args, None, Some("tari-algorithm")) {
            push_value(args, "--tari-algorithm", algo.as_str());
        }
    }

    if let Some(proxy_url) = config.tari_proxy_url.as_ref() {
        if !has_arg(original_args, None, Some("tari-proxy-url")) {
            push_value(args, "--tari-proxy-url", proxy_url.as_str());
        }
    }

    if let Some(wallet) = config.tari_monero_wallet.as_ref() {
        if !has_arg(original_args, None, Some("tari-monero-wallet")) {
            push_value(args, "--tari-monero-wallet", wallet.as_str());
        }
    }

    if let Some(pool) = config.tari_pool.as_ref() {
        if !has_arg(original_args, None, Some("tari-pool"))
            && !has_arg(original_args, None, Some("tari-pool-url"))
        {
            push_value(args, "--tari-pool", pool.as_str());
        }
    }

    if let Some(wallet) = config.tari_wallet.as_ref() {
        if !has_arg(original_args, None, Some("tari-wallet"))
            && !has_arg(original_args, None, Some("tari-wallet-address"))
        {
            push_value(args, "--tari-wallet", wallet.as_str());
        }
    }

    if let Some(rig) = config.tari_rig_id.as_ref() {
        if !has_arg(original_args, None, Some("tari-rig-id")) {
            push_value(args, "--tari-rig-id", rig.as_str());
        }
    }

    if let Some(login) = config.tari_login.as_ref() {
        if !has_arg(original_args, None, Some("tari-login")) {
            push_value(args, "--tari-login", login.as_str());
        }
    }

    if let Some(password) = config.tari_password.as_ref() {
        if !has_arg(original_args, None, Some("tari-password")) {
            push_value(args, "--tari-password", password.as_str());
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

    fn write_temp_config(contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("oxide-config-{nanos}.toml"));
        fs::write(&path, contents).expect("write config");
        path
    }

    #[test]
    fn benchmark_mode_parses_without_pool_or_wallet() {
        assert!(Args::try_parse_from(["test", "--benchmark"]).is_ok());
    }

    #[test]
    fn mining_mode_parses_with_or_without_pool_fields() {
        let parsed = Args::try_parse_from(["test", "-o", "pool:5555", "-u", "wallet"]).unwrap();
        assert_eq!(parsed.monero_pool.as_deref(), Some("pool:5555"));
        assert_eq!(parsed.monero_wallet.as_deref(), Some("wallet"));

        let parsed = Args::try_parse_from(["test"]).unwrap();
        assert!(parsed.monero_pool.is_none());
        assert!(parsed.monero_wallet.is_none());
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
    fn config_file_sets_tari_algorithm() {
        let path = write_temp_config(
            r#"
[tari]
mode = "pool"
algorithm = "sha3x"
"#,
        );

        let args = vec![
            "oxide-miner",
            "--config",
            path.to_str().unwrap(),
            "--monero-url",
            "pool:1234",
            "--monero-wallet",
            "wallet",
            "--tari-mode",
            "pool",
            "--tari-pool",
            "stratum+tcp://tari.pool:4000",
            "--tari-wallet",
            "tari_wallet",
        ];

        let parsed = parse_with_config_from(args).expect("args parse");
        assert_eq!(parsed.args.tari_algorithm.as_deref(), Some("sha3x"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn cli_overrides_tari_algorithm() {
        let path = write_temp_config(
            r#"
[tari]
mode = "pool"
algorithm = "sha3x"
"#,
        );

        let args = vec![
            "oxide-miner",
            "--config",
            path.to_str().unwrap(),
            "--monero-url",
            "pool:1234",
            "--monero-wallet",
            "wallet",
            "--tari-mode",
            "pool",
            "--tari-pool",
            "stratum+tcp://tari.pool:4000",
            "--tari-wallet",
            "tari_wallet",
            "--tari-algorithm",
            "randomx",
        ];

        let parsed = parse_with_config_from(args).expect("args parse");
        assert_eq!(parsed.args.tari_algorithm.as_deref(), Some("randomx"));

        let _ = fs::remove_file(path);
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
            "monero_pool = \"configpool:5555\"\nmonero_wallet = \"configwallet\"\nmonero_pass = \"configpass\"\nthreads = 8\ndebug = true\n",
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.monero_pool.as_deref(), Some("configpool:5555"));
        assert_eq!(parsed.args.monero_wallet.as_deref(), Some("configwallet"));
        assert_eq!(parsed.args.monero_pass, "configpass");
        assert_eq!(parsed.args.threads, Some(8));
        assert!(parsed.args.debug);
    }

    #[test]
    fn cli_overrides_config_values() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            r#"
monero_pool = "configpool:5555"
monero_wallet = "configwallet"
monero_pass = "configpass"
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
            OsString::from("--monero-pass"),
            OsString::from("cli-pass"),
            OsString::from("--batch-size"),
            OsString::from("7500"),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.threads, Some(4));
        assert_eq!(parsed.args.monero_pass, "cli-pass");
        assert_eq!(parsed.args.batch_size, Some(7_500));
        assert_eq!(parsed.args.monero_pool.as_deref(), Some("configpool:5555"));
        assert_eq!(parsed.args.monero_wallet.as_deref(), Some("configwallet"));
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
