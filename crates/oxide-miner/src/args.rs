// OxideMiner/crates/oxide-miner/src/args.rs

use clap::{
    builder::TypedValueParser, error::ErrorKind, CommandFactory, Parser, ValueEnum, ValueHint,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum MiningMode {
    Pool,
    Solo,
}

impl MiningMode {
    pub fn as_str(self) -> &'static str {
        match self {
            MiningMode::Pool => "pool",
            MiningMode::Solo => "solo",
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "OxideMiner - Rust Monero RandomX CPU miner (CLI MVP)"
)]
pub struct Args {
    /// Mining backend mode (pool or solo)
    #[arg(long = "mode", value_enum, default_value_t = MiningMode::Pool)]
    pub mode: MiningMode,

    /// pool like "pool.supportxmr.com:5555"
    #[arg(short = 'o', long = "url")]
    pub pool: Option<String>,

    /// Your XMR wallet address
    #[arg(short = 'u', long = "user")]
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

    /// Bind the HTTP API to this address (default 127.0.0.1)
    /// Only used when --api-port is set.
    #[arg(
        long = "api-bind",
        value_parser = clap::value_parser!(IpAddr),
        default_value = "127.0.0.1"
    )]
    pub api_bind: IpAddr,

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

    /// Monerod JSON-RPC URL for solo mining
    #[arg(
        long = "node-rpc-url",
        value_name = "URL",
        value_hint = ValueHint::Url,
        default_value = "http://127.0.0.1:18081"
    )]
    pub node_rpc_url: String,

    /// Monerod JSON-RPC username (HTTP basic auth)
    #[arg(long = "node-rpc-user", value_name = "USER")]
    pub node_rpc_user: Option<String>,

    /// Monerod JSON-RPC password (HTTP basic auth)
    #[arg(long = "node-rpc-pass", value_name = "PASS")]
    pub node_rpc_pass: Option<String>,

    /// Wallet address for solo mining (used in get_block_template)
    #[arg(long = "solo-wallet", value_name = "ADDRESS")]
    pub solo_wallet: Option<String>,

    /// Reserve size (bytes) for get_block_template
    #[arg(
        long = "solo-reserve-size",
        value_name = "BYTES",
        default_value_t = 60,
        value_parser = clap::value_parser!(u32).range(0..=255)
    )]
    pub solo_reserve_size: u32,

    /// ZMQ endpoint for monerod new-block notifications (optional)
    #[arg(long = "solo-zmq", value_name = "URL", value_hint = ValueHint::Url)]
    pub solo_zmq: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(alias = "url")]
    pub pool: Option<String>,
    #[serde(alias = "user")]
    pub wallet: Option<String>,
    pub pass: Option<String>,
    pub threads: Option<usize>,
    pub tls: Option<bool>,
    #[serde(alias = "tls-ca-cert")]
    pub tls_ca_cert: Option<PathBuf>,
    #[serde(alias = "tls-cert-sha256")]
    pub tls_cert_sha256: Option<String>,
    #[serde(alias = "api-port")]
    pub api_port: Option<u16>,
    #[serde(alias = "api-bind")]
    pub api_bind: Option<IpAddr>,
    #[serde(alias = "dashboard-dir")]
    pub dashboard_dir: Option<PathBuf>,
    pub affinity: Option<bool>,
    #[serde(alias = "huge-pages")]
    pub huge_pages: Option<bool>,
    #[serde(alias = "batch-size")]
    pub batch_size: Option<usize>,
    #[serde(alias = "no-yield")]
    pub no_yield: Option<bool>,
    pub debug: Option<bool>,
    pub proxy: Option<String>,
    pub mode: Option<MiningMode>,
    pub solo: Option<SoloConfigFile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloConfigFile {
    #[serde(alias = "node-rpc-url", alias = "node_rpc_url", alias = "rpc-url")]
    pub rpc_url: Option<String>,
    #[serde(alias = "node-rpc-user", alias = "node_rpc_user", alias = "rpc-user")]
    pub rpc_user: Option<String>,
    #[serde(
        alias = "node-rpc-pass",
        alias = "node_rpc_pass",
        alias = "rpc-pass",
        skip_serializing
    )]
    pub rpc_pass: Option<String>,
    #[serde(alias = "solo-wallet", alias = "solo_wallet")]
    pub wallet: Option<String>,
    #[serde(alias = "reserve-size", alias = "reserve_size")]
    pub reserve_size: Option<u32>,
    #[serde(alias = "solo-zmq", alias = "zmq")]
    pub zmq: Option<String>,
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
    pub config: Option<LoadedConfigFile>,
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
    let config = load_config_file(&config_path, explicit_config, &mut warnings)?.map(|mut cfg| {
        apply_config_defaults(&cfg.values, &original_args, &mut args_vec, &mut cfg.applied);
        cfg
    });

    let args = Args::try_parse_from(args_vec)?;
    validate_args(&args)?;
    if should_warn_unused_api_bind(&args, &original_args, config.as_ref()) {
        warnings.push(ConfigWarning::new(
            "api_bind is set but api_port is not set; HTTP API will not start".to_string(),
            false,
        ));
    }

    Ok(ParsedArgs {
        args,
        warnings,
        config,
    })
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
) -> Result<Option<LoadedConfigFile>, clap::Error> {
    let debug_only = !explicit;

    if !explicit && !path.exists() {
        warnings.push(ConfigWarning::new(
            format!("config file not found at {}", path.display()),
            debug_only,
        ));
        return Ok(None);
    }

    let contents = fs::read_to_string(path).map_err(|err| {
        config_error(
            Args::command(),
            format!("failed to read config file {}: {err}", path.display()),
        )
    })?;

    let value: toml::Value = contents.parse().map_err(|err: toml::de::Error| {
        config_error(
            Args::command(),
            format_toml_error(path, &err.to_string(), None),
        )
    })?;

    if let Some(table) = value.as_table() {
        let mut unknown_keys = Vec::new();
        for key in table.keys() {
            if !VALID_CONFIG_KEYS.contains(&key.as_str()) {
                unknown_keys.push(key.as_str().to_owned());
            }
        }
        if !unknown_keys.is_empty() {
            return Err(config_error(
                Args::command(),
                format!(
                    "unrecognized {} in config file {}: {}. Valid keys: {}",
                    if unknown_keys.len() == 1 {
                        "key"
                    } else {
                        "keys"
                    },
                    path.display(),
                    unknown_keys.join(", "),
                    VALID_CONFIG_KEYS.join(", "),
                ),
            ));
        }
    }

    let values: ConfigFile = value.try_into().map_err(|err: toml::de::Error| {
        config_error(
            Args::command(),
            format_toml_error(path, &err.to_string(), None),
        )
    })?;

    Ok(Some(LoadedConfigFile {
        path: path.to_path_buf(),
        values,
        applied: ConfigApplied::default(),
    }))
}

fn apply_config_defaults(
    config: &ConfigFile,
    original_args: &[OsString],
    args: &mut Vec<OsString>,
    applied: &mut ConfigApplied,
) {
    if let Some(pool) = config.pool.as_ref() {
        if !has_arg(original_args, Some("o"), Some("url")) {
            push_value(args, "--url", pool.as_str());
            applied.pool = true;
        }
    }

    if let Some(wallet) = config.wallet.as_ref() {
        if !has_arg(original_args, Some("u"), Some("user")) {
            push_value(args, "--user", wallet.as_str());
            applied.wallet = true;
        }
    }

    if let Some(pass) = config.pass.as_ref() {
        if !has_arg(original_args, Some("p"), Some("pass")) {
            push_value(args, "--pass", pass.as_str());
            applied.pass = true;
        }
    }

    if let Some(threads) = config.threads {
        if !has_arg(original_args, Some("t"), Some("threads")) {
            push_value(args, "--threads", threads.to_string());
            applied.threads = true;
        }
    }

    if config.tls == Some(true) && !has_arg(original_args, None, Some("tls")) {
        push_flag(args, "--tls");
        applied.tls = true;
    }

    if let Some(cert) = config.tls_ca_cert.as_ref() {
        if !has_arg(original_args, None, Some("tls-ca-cert")) {
            push_value_os(args, "--tls-ca-cert", cert.as_os_str());
            applied.tls_ca_cert = true;
        }
    }

    if let Some(fingerprint) = config.tls_cert_sha256.as_ref() {
        if !has_arg(original_args, None, Some("tls-cert-sha256")) {
            push_value(args, "--tls-cert-sha256", fingerprint.as_str());
            applied.tls_cert_sha256 = true;
        }
    }

    if let Some(port) = config.api_port {
        if !has_arg(original_args, None, Some("api-port")) {
            push_value(args, "--api-port", port.to_string());
            applied.api_port = true;
        }
    }

    if let Some(bind) = config.api_bind.as_ref() {
        if !has_arg(original_args, None, Some("api-bind")) {
            push_value(args, "--api-bind", bind.to_string());
            applied.api_bind = true;
        }
    }

    if let Some(dir) = config.dashboard_dir.as_ref() {
        if !has_arg(original_args, None, Some("dashboard-dir")) {
            push_value_os(args, "--dashboard-dir", dir.as_os_str());
            applied.dashboard_dir = true;
        }
    }

    if config.affinity == Some(true) && !has_arg(original_args, None, Some("affinity")) {
        push_flag(args, "--affinity");
        applied.affinity = true;
    }

    if config.huge_pages == Some(true) && !has_arg(original_args, None, Some("huge-pages")) {
        push_flag(args, "--huge-pages");
        applied.huge_pages = true;
    }

    if let Some(batch_size) = config.batch_size {
        if !has_arg(original_args, None, Some("batch-size")) {
            push_value(args, "--batch-size", batch_size.to_string());
            applied.batch_size = true;
        }
    }

    if config.no_yield == Some(true) && !has_arg(original_args, None, Some("no-yield")) {
        push_flag(args, "--no-yield");
        applied.no_yield = true;
    }

    if config.debug == Some(true) && !has_arg(original_args, None, Some("debug")) {
        push_flag(args, "--debug");
        applied.debug = true;
    }

    if let Some(proxy) = config.proxy.as_ref() {
        if !has_arg(original_args, None, Some("proxy")) {
            push_value(args, "--proxy", proxy.as_str());
            applied.proxy = true;
        }
    }

    if let Some(mode) = config.mode {
        if !has_arg(original_args, None, Some("mode")) {
            push_value(args, "--mode", mode.as_str());
            applied.mode = true;
        }
    }

    if let Some(solo) = config.solo.as_ref() {
        if let Some(url) = solo.rpc_url.as_ref() {
            if !has_arg(original_args, None, Some("node-rpc-url")) {
                push_value(args, "--node-rpc-url", url.as_str());
                applied.solo_rpc_url = true;
            }
        }
        if let Some(user) = solo.rpc_user.as_ref() {
            if !has_arg(original_args, None, Some("node-rpc-user")) {
                push_value(args, "--node-rpc-user", user.as_str());
                applied.solo_rpc_user = true;
            }
        }
        if let Some(pass) = solo.rpc_pass.as_ref() {
            if !has_arg(original_args, None, Some("node-rpc-pass")) {
                push_value(args, "--node-rpc-pass", pass.as_str());
                applied.solo_rpc_pass = true;
            }
        }
        if let Some(wallet) = solo.wallet.as_ref() {
            if !has_arg(original_args, None, Some("solo-wallet")) {
                push_value(args, "--solo-wallet", wallet.as_str());
                applied.solo_wallet = true;
            }
        }
        if let Some(reserve_size) = solo.reserve_size {
            if !has_arg(original_args, None, Some("solo-reserve-size")) {
                push_value(args, "--solo-reserve-size", reserve_size.to_string());
                applied.solo_reserve_size = true;
            }
        }
        if let Some(zmq) = solo.zmq.as_ref() {
            if !has_arg(original_args, None, Some("solo-zmq")) {
                push_value(args, "--solo-zmq", zmq.as_str());
                applied.solo_zmq = true;
            }
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

fn should_warn_unused_api_bind(
    args: &Args,
    original_args: &[OsString],
    config: Option<&LoadedConfigFile>,
) -> bool {
    if args.benchmark || args.api_port.is_some() {
        return false;
    }

    let cli_set = has_arg(original_args, None, Some("api-bind"));
    let config_set = config
        .map(|cfg| cfg.values.api_bind.is_some())
        .unwrap_or(false);

    cli_set || config_set
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

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConfigApplied {
    pub pool: bool,
    pub wallet: bool,
    pub pass: bool,
    pub threads: bool,
    pub tls: bool,
    pub tls_ca_cert: bool,
    pub tls_cert_sha256: bool,
    pub api_port: bool,
    pub api_bind: bool,
    pub dashboard_dir: bool,
    pub affinity: bool,
    pub huge_pages: bool,
    pub batch_size: bool,
    pub no_yield: bool,
    pub debug: bool,
    pub proxy: bool,
    pub mode: bool,
    pub solo_rpc_url: bool,
    pub solo_rpc_user: bool,
    pub solo_rpc_pass: bool,
    pub solo_wallet: bool,
    pub solo_reserve_size: bool,
    pub solo_zmq: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadedConfigFile {
    pub path: PathBuf,
    pub values: ConfigFile,
    pub applied: ConfigApplied,
}

const VALID_CONFIG_KEYS: &[&str] = &[
    "pool",
    "url",
    "wallet",
    "user",
    "pass",
    "threads",
    "tls",
    "tls_ca_cert",
    "tls-ca-cert",
    "tls_cert_sha256",
    "tls-cert-sha256",
    "api_port",
    "api-port",
    "api_bind",
    "api-bind",
    "dashboard_dir",
    "dashboard-dir",
    "affinity",
    "huge_pages",
    "huge-pages",
    "batch_size",
    "batch-size",
    "no_yield",
    "no-yield",
    "debug",
    "proxy",
    "mode",
    "solo",
];

fn config_error(mut cmd: clap::Command, msg: String) -> clap::Error {
    let mut err = clap::Error::raw(ErrorKind::InvalidValue, msg);
    err.insert(
        clap::error::ContextKind::Usage,
        clap::error::ContextValue::StyledStr(cmd.render_usage()),
    );
    err
}

fn args_error(mut cmd: clap::Command, msg: String) -> clap::Error {
    let mut err = clap::Error::raw(ErrorKind::InvalidValue, msg);
    err.insert(
        clap::error::ContextKind::Usage,
        clap::error::ContextValue::StyledStr(cmd.render_usage()),
    );
    err
}

fn validate_args(args: &Args) -> Result<(), clap::Error> {
    if args.benchmark {
        return Ok(());
    }

    if args.node_rpc_pass.is_some() && args.node_rpc_user.is_none() {
        return Err(args_error(
            Args::command(),
            "--node-rpc-pass requires --node-rpc-user".to_string(),
        ));
    }

    match args.mode {
        MiningMode::Pool => {
            if args.pool.as_deref().unwrap_or_default().is_empty() {
                return Err(args_error(
                    Args::command(),
                    "missing pool URL (use --url or set pool in config)".to_string(),
                ));
            }
            if args.wallet.as_deref().unwrap_or_default().is_empty() {
                return Err(args_error(
                    Args::command(),
                    "missing wallet address (use --user or set wallet in config)".to_string(),
                ));
            }
        }
        MiningMode::Solo => {
            if args.solo_wallet.as_deref().unwrap_or_default().is_empty() {
                return Err(args_error(
                    Args::command(),
                    "missing solo wallet address (use --solo-wallet or [solo].wallet in config)"
                        .to_string(),
                ));
            }
        }
    }

    if matches!(args.mode, MiningMode::Pool)
        && !args.tls
        && (args.tls_ca_cert.is_some() || args.tls_cert_sha256.is_some())
    {
        return Err(args_error(
            Args::command(),
            "--tls-ca-cert and --tls-cert-sha256 require --tls to be enabled".to_string(),
        ));
    }

    Ok(())
}

fn format_toml_error(path: &Path, message: &str, line_col: Option<(usize, usize)>) -> String {
    let location = line_col
        .map(|(line, col)| format!(" at line {}, column {}", line + 1, col + 1))
        .unwrap_or_default();
    format!(
        "failed to parse config file {}{}: {}",
        path.display(),
        location,
        message
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_with_config_from, validate_args, Args, MiningMode};
    use clap::Parser;
    use std::{
        env,
        ffi::OsString,
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };
    use tempfile::NamedTempFile;

    #[test]
    fn benchmark_mode_parses_without_pool_or_wallet() {
        assert!(Args::try_parse_from(["test", "--benchmark"]).is_ok());
    }

    #[test]
    fn mining_mode_parses_with_pool_and_wallet() {
        let args = Args::try_parse_from(["test", "-o", "pool:5555", "-u", "wallet"]).unwrap();
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn mining_mode_missing_pool_or_wallet_fails() {
        let args = Args::try_parse_from(["test"]).unwrap();
        assert!(validate_args(&args).is_err());
        let args = Args::try_parse_from(["test", "-o", "pool:5555"]).unwrap();
        assert!(validate_args(&args).is_err());
        let args = Args::try_parse_from(["test", "-u", "wallet"]).unwrap();
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn solo_mode_parses_without_pool_wallet() {
        let args = Args::try_parse_from(["test", "--mode", "solo", "--solo-wallet", "solo-wallet"])
            .unwrap();
        assert_eq!(args.mode, MiningMode::Solo);
        assert!(validate_args(&args).is_ok());
    }

    #[test]
    fn solo_mode_requires_wallet() {
        let args = Args::try_parse_from(["test", "--mode", "solo"]).unwrap();
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn config_file_supplies_solo_defaults() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            r#"
mode = "solo"
[solo]
wallet = "solo-wallet"
rpc_url = "http://127.0.0.1:18081"
reserve_size = 64
"#,
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.mode, MiningMode::Solo);
        assert_eq!(parsed.args.solo_wallet.as_deref(), Some("solo-wallet"));
        assert_eq!(parsed.args.node_rpc_url.as_str(), "http://127.0.0.1:18081");
        assert_eq!(parsed.args.solo_reserve_size, 64);
    }

    #[test]
    fn solo_rpc_pass_requires_user() {
        let args = Args::try_parse_from([
            "test",
            "--mode",
            "solo",
            "--solo-wallet",
            "wallet",
            "--node-rpc-pass",
            "secret",
        ])
        .unwrap();
        assert!(validate_args(&args).is_err());
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
    fn api_bind_defaults_to_loopback() {
        let args = Args::try_parse_from(["test", "-o", "pool:5555", "-u", "wallet"]).unwrap();
        assert_eq!(args.api_bind, IpAddr::from(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn api_bind_parses_ipv4_unspecified() {
        let args = Args::try_parse_from([
            "test",
            "-o",
            "pool:5555",
            "-u",
            "wallet",
            "--api-bind",
            "0.0.0.0",
        ])
        .unwrap();
        assert_eq!(args.api_bind, IpAddr::from(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn api_bind_parses_ipv6_loopback() {
        let args = Args::try_parse_from([
            "test",
            "-o",
            "pool:5555",
            "-u",
            "wallet",
            "--api-bind",
            "::1",
        ])
        .unwrap();
        assert_eq!(args.api_bind, IpAddr::from(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn api_bind_rejects_invalid_values() {
        let err = Args::try_parse_from([
            "test",
            "-o",
            "pool:5555",
            "-u",
            "wallet",
            "--api-bind",
            "not-an-ip",
        ])
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("--api-bind"));
        assert!(message.to_lowercase().contains("invalid"));
    }

    #[test]
    fn config_overrides_api_bind_when_flag_absent() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            r#"
pool = "pool:5555"
wallet = "wallet"
api_bind = "0.0.0.0"
"#,
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.api_bind, IpAddr::from(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn config_kebab_case_api_bind_is_accepted() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            r#"
pool = "pool:5555"
wallet = "wallet"
api-bind = "0.0.0.0"
"#,
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(parsed.args.api_bind, IpAddr::from(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn cli_overrides_config_api_bind() {
        let config = NamedTempFile::new().unwrap();
        fs::write(
            config.path(),
            r#"
pool = "pool:5555"
wallet = "wallet"
api_bind = "0.0.0.0"
"#,
        )
        .unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("--config"),
            config.path().as_os_str().to_os_string(),
            OsString::from("--api-bind"),
            OsString::from("127.0.0.2"),
        ];

        let parsed = parse_with_config_from(args).unwrap();
        assert_eq!(
            parsed.args.api_bind,
            IpAddr::from(Ipv4Addr::new(127, 0, 0, 2))
        );
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
    fn invalid_config_is_an_error() {
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

        assert!(parse_with_config_from(args).is_err());
    }

    #[test]
    fn invalid_default_config_is_an_error() {
        let tempdir = tempfile::tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        env::set_current_dir(tempdir.path()).unwrap();

        fs::write(tempdir.path().join("config.toml"), "threads = \"oops\"").unwrap();

        let args = vec![
            OsString::from("test"),
            OsString::from("-o"),
            OsString::from("pool:5555"),
            OsString::from("-u"),
            OsString::from("wallet"),
        ];

        assert!(parse_with_config_from(args).is_err());
        env::set_current_dir(original_dir).unwrap();
    }
}
