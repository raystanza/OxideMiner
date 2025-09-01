//! System inspection utilities for tuning RandomX.
//!
//! Provides cross-platform helpers to detect CPU features,
//! available memory, and huge page support so the miner can
//! automatically choose sensible defaults.

use raw_cpuid::CpuId;
use sysinfo::{System, SystemExt};

/// Size of the RandomX dataset when operating in `FLAG_FULL_MEM` mode.
pub const RANDOMX_DATASET_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Collected system properties relevant for tuning the miner.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// Number of physical CPU cores.
    pub physical_cores: usize,
    /// Total system memory in bytes.
    pub total_memory: u64,
    /// Available system memory in bytes.
    pub available_memory: u64,
    /// Whether the operating system currently has huge/large pages enabled.
    pub huge_pages: bool,
    /// Whether AES-NI instructions are supported.
    pub has_aes: bool,
    /// Whether AVX2 instructions are supported.
    pub has_avx2: bool,
}

impl SystemInfo {
    /// Gather a snapshot of the system's capabilities.
    pub fn gather() -> Self {
        let mut sys = System::new();
        sys.refresh_memory();

        let physical_cores = num_cpus::get_physical();
        let total_memory = sys.total_memory() * 1024; // KiB -> bytes
        let available_memory = sys.available_memory() * 1024; // KiB -> bytes

        let cpuid = CpuId::new();
        let has_aes = cpuid
            .get_feature_info()
            .map(|f| f.has_aesni())
            .unwrap_or(false);
        let has_avx2 = cpuid
            .get_extended_feature_info()
            .map(|f| f.has_avx2())
            .unwrap_or(false);

        let huge_pages = huge_pages_available();

        Self {
            physical_cores,
            total_memory,
            available_memory,
            huge_pages,
            has_aes,
            has_avx2,
        }
    }

    /// Determine a recommended number of mining threads based on
    /// physical cores and available memory. Ensures at least one thread.
    pub fn recommended_thread_count(&self) -> usize {
        let mem_based = (self.available_memory / RANDOMX_DATASET_BYTES) as usize;
        let mem_based = mem_based.max(1);
        let cores = self.physical_cores.max(1);
        std::cmp::min(mem_based, cores)
    }
}

/// Check whether huge/large pages are available on the current host.
pub fn huge_pages_available() -> bool {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            // Parse /proc/meminfo for HugePages_* entries.
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                let mut total = 0u64;
                let mut free = 0u64;
                for line in meminfo.lines() {
                    if line.starts_with("HugePages_Total:") {
                        total = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                    } else if line.starts_with("HugePages_Free:") {
                        free = line.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                    }
                }
                return total > 0 && free > 0;
            }
            false
        } else if #[cfg(target_os = "windows")] {
            use windows::Win32::System::Memory::GetLargePageMinimum;
            unsafe { GetLargePageMinimum() > 0 }
        } else {
            false
        }
    }
}
