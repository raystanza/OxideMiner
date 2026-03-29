#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate self as oxide_randomx;

mod aes;
mod argon2d;
mod blake;
mod cache;
mod config;
mod constants;
mod dataset;
#[doc(hidden)]
#[path = "superscalar_tools.rs"]
pub mod diagnostics;
mod errors;
mod flags;
pub mod full_features_capture;
mod generators;
pub mod oxideminer_integration;
#[doc(hidden)]
pub mod oxideminer_supported_build_contract;
mod perf;
pub mod prefetch_calibration;
mod superscalar;
mod threading;
mod util;
mod vm;

pub use crate::cache::RandomXCache;
pub use crate::config::RandomXConfig;
#[cfg(feature = "unsafe-config")]
pub use crate::config::RandomXConfigBuilder;
pub use crate::dataset::DatasetInitOptions;
pub use crate::dataset::RandomXDataset;
pub use crate::errors::{RandomXError, Result};
pub use crate::flags::RandomXFlags;
pub use crate::perf::PerfStats;
pub use crate::threading::AffinitySpec;
pub use crate::util::{print_huge_page_diagnostics, HugePageStatus};
pub use crate::vm::RandomXVm;

/// CPU detection for auto-tuning optimizations.
#[cfg(target_arch = "x86_64")]
pub mod cpu_detect {
    pub use crate::flags::cpu_detect::{detect_cpu_family, CpuFamily};
}

#[cfg(feature = "jit")]
#[doc(hidden)]
pub mod jit {
    pub use crate::vm::jit::ExecutableBuffer;
    pub use crate::vm::jit::JitStats;
}

#[cfg(test)]
mod conformance;
