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
pub use stratum::{PoolJob, StratumClient};
pub use system::{
    autotune_snapshot, cpu_has_aes, huge_page_status, huge_pages_enabled, recommended_thread_count,
    AutoTuneSnapshot, HugePageStatus,
};
pub use worker::{spawn_workers, Share, WorkItem};
