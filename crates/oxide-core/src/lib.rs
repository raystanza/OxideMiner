// // OxideMiner/crates/oxide-core/src/lib.rs

pub mod benchmark;
pub mod config;
pub mod devfee;
pub mod stratum;
pub mod system;
pub mod worker;

pub use benchmark::run_benchmark;
pub use config::Config;
pub use devfee::{DevFeeScheduler, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS};
pub use stratum::{PoolJob, ProxyConfig, StratumClient};
pub use system::{
    autotune_snapshot, cache_hierarchy, cpu_features, cpu_has_aes, cpu_has_avx2, cpu_has_avx512f,
    cpu_has_ssse3, huge_page_status, huge_pages_enabled, numa_nodes, recommended_thread_count,
    AutoTuneSnapshot, CacheHierarchy, CacheLevel, CpuFeatures, HugePageStatus,
};
pub use worker::{spawn_workers, Share, WorkItem, WorkerOptions};
