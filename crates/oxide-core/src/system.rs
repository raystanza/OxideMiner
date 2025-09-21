// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory
//
// Compatible with sysinfo >= 0.30 (methods are inherent on `System`).

use sysinfo::System;

/// Check if operating system has huge pages / large pages available.
/// On Linux this inspects `/proc/meminfo`'s `HugePages_Total` value.
/// On Windows it attempts to enable the SeLockMemoryPrivilege and query
/// `GetLargePageMinimum()`.
pub fn huge_pages_enabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        return linux_huge_pages_enabled();
    }
    #[cfg(target_os = "windows")]
    {
        return windows_large_pages::huge_pages_enabled();
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        return false;
    }
}

#[cfg(target_os = "linux")]
fn linux_huge_pages_enabled() -> bool {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        return parse_hugepages_total(&meminfo);
    }
    false
}

#[cfg(target_os = "windows")]
mod windows_large_pages {
    use std::{
        error::Error, ffi::OsStr, fmt, iter, os::windows::ffi::OsStrExt, ptr, sync::OnceLock,
    };

    use tracing::{debug, warn};

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, ERROR_PRIVILEGE_NOT_HELD, HANDLE,
        },
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        System::{
            Memory::GetLargePageMinimum,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    const SE_LOCK_MEMORY_PRIVILEGE: &str = "SeLockMemoryPrivilege";

    #[derive(Debug)]
    enum LargePageError {
        WinApi { func: &'static str, code: u32 },
        PrivilegeNotAssigned,
        Unsupported,
    }

    impl fmt::Display for LargePageError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                LargePageError::WinApi { func, code } => {
                    write!(f, "{func} failed with error code {code}")
                }
                LargePageError::PrivilegeNotAssigned => write!(
                    f,
                    "SeLockMemoryPrivilege is not assigned to the current process",
                ),
                LargePageError::Unsupported => {
                    write!(f, "Windows large pages are not supported on this system")
                }
            }
        }
    }

    impl Error for LargePageError {}

    struct TokenHandle(HANDLE);

    impl TokenHandle {
        fn new(handle: HANDLE) -> Self {
            Self(handle)
        }

        fn handle(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn huge_pages_enabled() -> bool {
        static RESULT: OnceLock<bool> = OnceLock::new();
        *RESULT.get_or_init(|| match large_page_minimum() {
            Ok(bytes) => {
                debug!(large_page_minimum_bytes = bytes, "Windows large pages enabled");
                true
            }
            Err(LargePageError::PrivilegeNotAssigned) => {
                warn!(
                    "Windows large pages disabled: SeLockMemoryPrivilege is not held by this process"
                );
                false
            }
            Err(LargePageError::Unsupported) => {
                debug!("Windows large pages unsupported on this system");
                false
            }
            Err(LargePageError::WinApi { func, code }) => {
                warn!(
                    windows_error = code,
                    func,
                    "Failed to query Windows large pages support"
                );
                false
            }
        })
    }

    fn large_page_minimum() -> Result<usize, LargePageError> {
        enable_lock_memory_privilege()?;
        let minimum = unsafe { GetLargePageMinimum() };
        if minimum == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_PRIVILEGE_NOT_HELD || code == ERROR_NOT_ALL_ASSIGNED {
                return Err(LargePageError::PrivilegeNotAssigned);
            }
            if code != 0 {
                return Err(LargePageError::WinApi {
                    func: "GetLargePageMinimum",
                    code,
                });
            }
            return Err(LargePageError::Unsupported);
        }
        Ok(minimum as usize)
    }

    fn enable_lock_memory_privilege() -> Result<(), LargePageError> {
        unsafe {
            let mut token_raw: HANDLE = 0;
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token_raw,
            ) == 0
            {
                return Err(last_os_error("OpenProcessToken"));
            }
            let token = TokenHandle::new(token_raw);

            let mut luid = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            let privilege_name = wide_string(SE_LOCK_MEMORY_PRIVILEGE);
            if LookupPrivilegeValueW(ptr::null(), privilege_name.as_ptr(), &mut luid) == 0 {
                return Err(last_os_error("LookupPrivilegeValueW"));
            }

            let mut privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            if AdjustTokenPrivileges(
                token.handle(),
                0,
                &mut privileges,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            ) == 0
            {
                return Err(last_os_error("AdjustTokenPrivileges"));
            }

            let status = unsafe { GetLastError() };
            if status == ERROR_NOT_ALL_ASSIGNED {
                return Err(LargePageError::PrivilegeNotAssigned);
            }
            if status != 0 {
                return Err(LargePageError::WinApi {
                    func: "AdjustTokenPrivileges",
                    code: status,
                });
            }
            Ok(())
        }
    }

    fn wide_string(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>()
    }

    fn last_os_error(func: &'static str) -> LargePageError {
        let code = unsafe { GetLastError() };
        LargePageError::WinApi { func, code }
    }
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
    }
}
