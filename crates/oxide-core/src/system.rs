// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory
//
// Compatible with sysinfo >= 0.30 (methods are inherent on `System`).

use once_cell::sync::OnceCell;
use sysinfo::System;
use thiserror::Error;

/// Check if operating system has huge pages / large pages available.
/// On Linux this inspects `/proc/meminfo`'s `HugePages_Total` value.
/// On Windows it queries `GetLargePageMinimum`.
pub fn huge_pages_enabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            return parse_hugepages_total(&meminfo);
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        // windows-sys with feature Win32_System_Memory
        use windows_sys::Win32::System::Memory::GetLargePageMinimum;
        unsafe { GetLargePageMinimum() > 0 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Error returned when attempting to enable huge/large pages fails.
#[derive(Debug, Clone, Error)]
pub enum LargePageError {
    /// Wrapper around a failing Windows API call.
    #[error("{operation} failed with Windows error {code:#010X}")]
    WindowsApi {
        /// API that returned an error.
        operation: &'static str,
        /// Error code returned from `GetLastError`.
        code: u32,
    },
    /// The process token does not hold SeLockMemoryPrivilege.
    #[error("SeLockMemoryPrivilege is not assigned to this process token")]
    PrivilegeNotAssigned,
    /// Catch-all for platforms without huge/large page support.
    #[error("large/huge pages are unsupported on this platform")]
    Unsupported,
}

static LARGE_PAGE_INIT: OnceCell<Result<(), LargePageError>> = OnceCell::new();

/// Attempt to enable large/huge pages for the current process.
///
/// On Windows this enables the SeLockMemoryPrivilege privilege so that
/// `VirtualAlloc(..., MEM_LARGE_PAGES, ...)` succeeds. Linux does not require
/// additional preparation beyond reserving HugeTLB pages ahead of time, so the
/// function is a no-op there. On other targets it returns `Unsupported`.
pub fn try_enable_large_pages() -> Result<(), LargePageError> {
    LARGE_PAGE_INIT
        .get_or_init(|| enable_large_pages_once())
        .clone()
}

#[cfg(target_os = "linux")]
fn parse_hugepages_total(meminfo: &str) -> bool {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("HugePages_Total:") {
            if let Some(total) = rest.trim().split_whitespace().next() {
                if let Ok(v) = total.parse::<u64>() {
                    return v > 0;
                }
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn enable_large_pages_once() -> Result<(), LargePageError> {
    use windows_sys::core::w;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(win32_error("OpenProcessToken"));
        }

        let result = {
            let mut luid = windows_sys::Win32::Foundation::LUID {
                LowPart: 0,
                HighPart: 0,
            };
            if LookupPrivilegeValueW(std::ptr::null(), w!("SeLockMemoryPrivilege"), &mut luid) == 0
            {
                Err(win32_error("LookupPrivilegeValueW"))
            } else {
                let privileges = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };

                let adjust_result = AdjustTokenPrivileges(
                    token,
                    0,
                    &privileges,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                let last_error = GetLastError();
                if adjust_result == 0 {
                    Err(LargePageError::WindowsApi {
                        operation: "AdjustTokenPrivileges",
                        code: last_error,
                    })
                } else if last_error == ERROR_NOT_ALL_ASSIGNED {
                    Err(LargePageError::PrivilegeNotAssigned)
                } else {
                    Ok(())
                }
            }
        };

        CloseHandle(token);
        result
    }
}

#[cfg(target_os = "windows")]
fn win32_error(operation: &'static str) -> LargePageError {
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    LargePageError::WindowsApi { operation, code }
}

#[cfg(target_os = "linux")]
fn enable_large_pages_once() -> Result<(), LargePageError> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn enable_large_pages_once() -> Result<(), LargePageError> {
    Err(LargePageError::Unsupported)
}

/// Determine whether the current CPU supports AES instructions (x86/x86_64).
/// RandomX benefits from AES for the HARD_AES flag.
pub fn cpu_has_aes() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Return the size of the L3 cache in bytes if detectable via CPUID(0x4).
fn l3_cache_bytes() -> Option<usize> {
    let cpuid = raw_cpuid::CpuId::new();
    if let Some(cparams) = cpuid.get_cache_parameters() {
        for cache in cparams {
            if cache.level() == 3 && matches!(cache.cache_type(), raw_cpuid::CacheType::Unified) {
                // CPUID leaf 0x4 size formula:
                // size = associativity * partitions * line_size * sets
                let ways = cache.associativity() as usize;
                let parts = cache.physical_line_partitions() as usize;
                let line = cache.coherency_line_size() as usize;
                let sets = cache.sets() as usize;
                return Some(ways * parts * line * sets);
            }
        }
    }
    None
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn l3_cache_bytes() -> Option<usize> {
    None
}

#[derive(Debug, Clone)]
pub struct AutoTuneSnapshot {
    pub physical_cores: usize,
    pub l3_bytes: Option<usize>,
    pub available_bytes: u64,
    pub dataset_bytes: u64,
    pub scratch_per_thread_bytes: u64,
    pub suggested_threads: usize,
}

/// Compute a snapshot of system resources and the suggested mining thread count.
/// Heuristics:
/// - Start with physical cores.
/// - Clamp by L3 cache (~2 MiB per thread).
/// - Clamp by available memory: ~2 GiB RandomX dataset + ~2 MiB per thread.
pub fn autotune_snapshot() -> AutoTuneSnapshot {
    // sysinfo >= 0.30 reports BYTES
    let mut sys = System::new_all();
    sys.refresh_memory();

    let physical = num_cpus::get_physical().max(1);
    let l3 = l3_cache_bytes();
    let avail_bytes = sys.available_memory();

    // RandomX "fast" dataset and per-thread scratchpad estimates
    let dataset = 2_u64 * 1024 * 1024 * 1024; // ~2 GiB
    let scratch = 2_u64 * 1024 * 1024; // ~2 MiB per thread

    let mut threads = physical;

    // L3 clamp (~2 MiB per thread)
    if let Some(l3b) = l3 {
        let l3_per_thread = if l3b > 64 * 1024 * 1024 {
            4 * 1024 * 1024
        } else {
            2 * 1024 * 1024
        };
        let cache_threads = (l3b / l3_per_thread).max(1);
        threads = threads.min(cache_threads);
    }

    // Memory clamp (dataset + N * scratch must fit into available)
    if avail_bytes > dataset {
        let max_threads_mem = ((avail_bytes - dataset) / scratch) as usize;
        threads = threads.min(max_threads_mem.max(1));
    } else {
        threads = 1;
    }

    AutoTuneSnapshot {
        physical_cores: physical,
        l3_bytes: l3,
        available_bytes: avail_bytes,
        dataset_bytes: dataset,
        scratch_per_thread_bytes: scratch,
        suggested_threads: threads.max(1),
    }
}

/// Legacy helper used elsewhere; delegates to the snapshot.
pub fn recommended_thread_count() -> usize {
    autotune_snapshot().suggested_threads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_hugepages_total() {
        let enabled = "HugePages_Total:       5\nOther: 0";
        assert!(parse_hugepages_total(enabled));
        let disabled = "HugePages_Total:       0\nOther: 0";
        assert!(!parse_hugepages_total(disabled));
        let missing = "SomethingElse: 1";
        assert!(!parse_hugepages_total(missing));
    }

    #[test]
    fn recommended_matches_snapshot() {
        let snap = autotune_snapshot();
        assert_eq!(recommended_thread_count(), snap.suggested_threads);
    }

    #[test]
    fn feature_checks_do_not_panic() {
        let _ = cpu_has_aes();
        let _ = huge_pages_enabled();
        let _ = try_enable_large_pages();
    }
}
