// OxideMiner/crates/oxide-core/src/config.rs

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_BATCH_SIZE: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RandomXMode {
    Light,
    #[default]
    Fast,
}

impl RandomXMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Fast => "fast",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RandomXRuntimeProfile {
    #[serde(rename = "interpreter")]
    #[value(name = "interpreter")]
    Interpreter,
    #[serde(rename = "jit-conservative")]
    #[value(name = "jit-conservative")]
    JitConservative,
    #[serde(rename = "jit-fastregs")]
    #[value(name = "jit-fastregs")]
    #[default]
    JitFastRegs,
}

impl RandomXRuntimeProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interpreter => "interpreter",
            Self::JitConservative => "jit-conservative",
            Self::JitFastRegs => "jit-fastregs",
        }
    }

    pub const fn jit_requested(self) -> bool {
        !matches!(self, Self::Interpreter)
    }

    pub const fn jit_fast_regs_requested(self) -> bool {
        matches!(self, Self::JitFastRegs)
    }

    pub const fn effective_from_jit_active(self, jit_active: bool) -> Self {
        if jit_active {
            self
        } else {
            Self::Interpreter
        }
    }

    pub fn fallback_reason(self, jit_active: bool) -> Option<String> {
        let effective = self.effective_from_jit_active(jit_active);
        if effective == self {
            None
        } else {
            Some("jit_requested_but_not_active".to_string())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandomXRuntimeConfig {
    pub mode: RandomXMode,
    pub runtime_profile: RandomXRuntimeProfile,
    pub large_pages: bool,
    pub use_1gb_pages: bool,
    pub prefetch_calibration_path: Option<PathBuf>,
}

impl Default for RandomXRuntimeConfig {
    fn default() -> Self {
        Self {
            mode: RandomXMode::Fast,
            runtime_profile: RandomXRuntimeProfile::JitFastRegs,
            large_pages: false,
            use_1gb_pages: false,
            prefetch_calibration_path: None,
        }
    }
}

impl RandomXRuntimeConfig {
    pub fn requested_status(&self) -> RandomXRequestedRuntimeStatus {
        RandomXRequestedRuntimeStatus {
            mode: self.mode,
            runtime_profile: self.runtime_profile,
            large_pages: self.large_pages,
            use_1gb_pages: self.use_1gb_pages,
            prefetch_calibration_path: self
                .prefetch_calibration_path
                .as_ref()
                .map(|path| path.display().to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct RandomXRequestedRuntimeStatus {
    pub mode: RandomXMode,
    pub runtime_profile: RandomXRuntimeProfile,
    pub large_pages: bool,
    pub use_1gb_pages: bool,
    pub prefetch_calibration_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct RandomXRuntimeRealization {
    pub mode: RandomXMode,
    pub requested_runtime_profile: RandomXRuntimeProfile,
    pub effective_runtime_profile: RandomXRuntimeProfile,
    pub fallback_reason: Option<String>,
    pub jit_requested: bool,
    pub jit_fast_regs_requested: bool,
    pub jit_active: bool,
    pub large_pages_requested: bool,
    pub use_1gb_pages_requested: bool,
    pub scratchpad_large_pages: bool,
    pub scratchpad_huge_page_size: Option<usize>,
    pub scratchpad_page_description: String,
    pub scratchpad_page_realization: String,
    pub dataset_large_pages: Option<bool>,
    pub dataset_huge_page_size: Option<usize>,
    pub dataset_page_description: Option<String>,
    pub dataset_page_realization: Option<String>,
    pub prefetch_distance: u8,
    pub prefetch_auto_tune: bool,
    pub scratchpad_prefetch_distance: u8,
    pub calibration_status: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct RandomXRuntimeStatus {
    pub requested: RandomXRequestedRuntimeStatus,
    pub realized: Option<RandomXRuntimeRealization>,
}

impl RandomXRuntimeStatus {
    pub fn new(config: &RandomXRuntimeConfig) -> Self {
        Self {
            requested: config.requested_status(),
            realized: None,
        }
    }

    pub fn set_realized(&mut self, realized: RandomXRuntimeRealization) {
        self.realized = Some(realized);
    }
}

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
    /// supported RandomX mode selection (`light` or `fast`)
    pub randomx_mode: RandomXMode,
    /// supported RandomX runtime profile selection
    pub randomx_runtime_profile: RandomXRuntimeProfile,
    /// request Linux 1GB huge pages for the Fast-mode dataset when available
    pub use_1gb_pages: bool,
    /// optional host-local prefetch calibration CSV to apply through oxide-randomx
    pub randomx_prefetch_calibration: Option<PathBuf>,
    /// number of hashes computed per batch in the hot mining loop
    pub batch_size: usize,
    /// yield to Tokio scheduler between hash batches
    pub yield_between_batches: bool,
    pub agent: String,
    /// optional SOCKS5 proxy URL (socks5://[user:pass@]host:port)
    pub proxy: Option<String>,
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
            randomx_mode: RandomXMode::Fast,
            randomx_runtime_profile: RandomXRuntimeProfile::JitFastRegs,
            use_1gb_pages: false,
            randomx_prefetch_calibration: None,
            batch_size: DEFAULT_BATCH_SIZE,
            yield_between_batches: true,
            agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
            proxy: None,
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
        assert_eq!(cfg.randomx_mode, RandomXMode::Fast);
        assert_eq!(
            cfg.randomx_runtime_profile,
            RandomXRuntimeProfile::JitFastRegs
        );
        assert!(!cfg.use_1gb_pages);
        assert!(cfg.randomx_prefetch_calibration.is_none());
        assert_eq!(cfg.batch_size, DEFAULT_BATCH_SIZE);
        assert!(cfg.yield_between_batches);
        assert!(cfg.agent.starts_with("OxideMiner/"));
        assert!(cfg.proxy.is_none());
    }

    #[test]
    fn runtime_profile_falls_back_to_interpreter_when_jit_is_inactive() {
        assert_eq!(
            RandomXRuntimeProfile::JitFastRegs.effective_from_jit_active(false),
            RandomXRuntimeProfile::Interpreter
        );
        assert_eq!(
            RandomXRuntimeProfile::JitConservative.effective_from_jit_active(true),
            RandomXRuntimeProfile::JitConservative
        );
    }

    #[test]
    fn runtime_status_starts_with_requested_settings_only() {
        let runtime = RandomXRuntimeConfig {
            mode: RandomXMode::Light,
            runtime_profile: RandomXRuntimeProfile::Interpreter,
            large_pages: true,
            use_1gb_pages: false,
            prefetch_calibration_path: Some(PathBuf::from("prefetch.csv")),
        };

        let status = RandomXRuntimeStatus::new(&runtime);

        assert_eq!(status.requested.mode, RandomXMode::Light);
        assert_eq!(
            status.requested.runtime_profile,
            RandomXRuntimeProfile::Interpreter
        );
        assert!(status.requested.large_pages);
        assert_eq!(
            status.requested.prefetch_calibration_path.as_deref(),
            Some("prefetch.csv")
        );
        assert!(status.realized.is_none());
    }
}
