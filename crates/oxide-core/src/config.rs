// OxideMiner/crates/oxide-core/src/config.rs

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_BATCH_SIZE: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// pool like "pool.example.com:3333"
    pub pool: String,
    /// Monero wallet address (primary)
    pub wallet: String,
    /// optional password; many pools accept "x"
    pub pass: Option<String>,
    /// number of mining threads (None = auto decide later using CPU/cache heuristics)
    pub threads: Option<usize>,
    /// fixed 1% dev fee (always enabled)
    pub enable_devfee: bool,
    /// enable TLS when connecting to the stratum pool
    pub tls: bool,
    /// optional custom CA certificate to add to the trust store when TLS is enabled
    pub tls_ca_cert: Option<PathBuf>,
    /// optional pinned server certificate fingerprint (SHA-256)
    pub tls_cert_sha256: Option<[u8; 32]>,
    /// optional HTTP API port for metrics (None disables)
    pub api_port: Option<u16>,
    /// pin worker threads to specific CPU cores
    pub affinity: bool,
    /// request huge/large pages for RandomX dataset
    pub huge_pages: bool,
    /// number of hashes computed per batch in the hot mining loop
    pub batch_size: usize,
    /// yield to Tokio scheduler between hash batches
    pub yield_between_batches: bool,
    pub agent: String,
    /// optional SOCKS5 proxy URL (socks5://[user:pass@]host:port)
    pub proxy: Option<String>,
    /// optional Tari merge mining support
    pub tari: TariMergeMiningConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TariMergeMiningConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_proxy_url")]
    pub proxy_url: String,
    /// Optional Monero address passed to the merge-mining proxy when it expects a Monero-compatible
    /// `get_block_template` call (used as a fallback if the Tari JSON-RPC method is unavailable).
    #[serde(default)]
    pub monero_wallet_address: Option<String>,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_backoff_secs")]
    pub backoff_secs: u64,
}

fn default_proxy_url() -> String {
    "http://127.0.0.1:18081".to_string()
}

fn default_request_timeout_secs() -> u64 {
    10
}

fn default_backoff_secs() -> u64 {
    5
}

impl Default for TariMergeMiningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_url: default_proxy_url(),
            monero_wallet_address: None,
            request_timeout_secs: default_request_timeout_secs(),
            backoff_secs: default_backoff_secs(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pool: "pool.example.com:3333".into(),
            wallet: "<YOUR_XMR_ADDRESS>".into(),
            pass: Some("x".into()),
            threads: None,
            enable_devfee: true,
            tls: false,
            tls_ca_cert: None,
            tls_cert_sha256: None,
            api_port: None,
            affinity: false,
            huge_pages: false,
            batch_size: DEFAULT_BATCH_SIZE,
            yield_between_batches: true,
            agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
            proxy: None,
            tari: TariMergeMiningConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = Config::default();
        assert_eq!(cfg.pool, "pool.example.com:3333");
        assert_eq!(cfg.wallet, "<YOUR_XMR_ADDRESS>");
        assert_eq!(cfg.pass.as_deref(), Some("x"));
        assert!(cfg.enable_devfee);
        assert!(!cfg.tls);
        assert!(cfg.tls_ca_cert.is_none());
        assert!(cfg.tls_cert_sha256.is_none());
        assert_eq!(cfg.api_port, None);
        assert!(!cfg.affinity);
        assert!(!cfg.huge_pages);
        assert_eq!(cfg.batch_size, DEFAULT_BATCH_SIZE);
        assert!(cfg.yield_between_batches);
        assert!(cfg.agent.starts_with("OxideMiner/"));
        assert!(cfg.proxy.is_none());
        assert!(!cfg.tari.enabled);
        assert_eq!(cfg.tari.proxy_url, "http://127.0.0.1:18081");
    }
}
