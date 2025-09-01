use raw_cpuid::CpuId;
use sysinfo::{System, SystemExt};

#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    pub aes: bool,
    pub sse2: bool,
    pub sse41: bool,
    pub avx2: bool,
}

/// Detect CPU features relevant to RandomX optimizations.
pub fn detect_cpu_features() -> CpuFeatures {
    let cpuid = CpuId::new();
    let fi = cpuid.get_feature_info();
    let ext = cpuid.get_extended_feature_info();

    CpuFeatures {
        aes: fi.map(|f| f.has_aesni()).unwrap_or(false),
        sse2: fi.map(|f| f.has_sse2()).unwrap_or(false),
        sse41: fi.map(|f| f.has_sse41()).unwrap_or(false),
        avx2: ext.map(|f| f.has_avx2()).unwrap_or(false),
    }
}

/// Check if the operating system currently has huge pages enabled.
#[cfg(target_os = "linux")]
pub fn huge_pages_available() -> bool {
    use std::fs;
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("HugePages_Total:") {
                return rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|v| v > 0)
                    .unwrap_or(false);
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
pub fn huge_pages_available() -> bool {
    use windows::Win32::System::SystemInformation::GetLargePageMinimum;
    // SAFETY: calling a Windows API that returns 0 when large pages are unavailable
    unsafe { GetLargePageMinimum() > 0 }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn huge_pages_available() -> bool {
    false
}

pub const RANDOMX_DATASET_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const RANDOMX_PER_THREAD_BYTES: u64 = 2 * 1024 * 1024;

/// Total available system memory in bytes.
pub fn available_memory_bytes() -> u64 {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.available_memory() * 1024 // sysinfo reports KiB
}

/// Estimated memory usage for the given number of worker threads.
pub fn memory_usage_for_threads(threads: usize) -> u64 {
    RANDOMX_DATASET_BYTES + RANDOMX_PER_THREAD_BYTES * threads as u64
}

/// Determine an appropriate number of worker threads based on CPU and memory.
/// If `user` is Some, that value is clamped to at least 1 and returned.
/// Otherwise the number of physical CPUs is capped by available memory.
pub fn recommended_thread_count(user: Option<usize>) -> usize {
    if let Some(t) = user {
        return t.max(1);
    }

    let cpus = num_cpus::get_physical().max(1);
    let avail = available_memory_bytes();
    let mem_limit = if avail > RANDOMX_DATASET_BYTES {
        ((avail - RANDOMX_DATASET_BYTES) / RANDOMX_PER_THREAD_BYTES).max(1) as usize
    } else {
        1
    };
    std::cmp::min(cpus, mem_limit)
}
