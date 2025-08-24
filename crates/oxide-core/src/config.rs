use serde::{Deserialize, Serialize};

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
    /// fixed 1% dev fee (can allow --no-devfee for testing builds only)
    pub enable_devfee: bool,
    /// (future) enable TLS, http api, affinity, huge pages, etc.
    pub tls: bool,
    pub agent: String,
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
            agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}
