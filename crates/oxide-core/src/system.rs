// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory
//
// Compatible with sysinfo >= 0.30 (methods are inherent on `System`).

use sysinfo::System;

/// Snapshot of the platform huge/large page configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugePageStatus {
    pub supported: bool,
    pub page_size: Option<u64>,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

impl HugePageStatus {
    const fn unsupported() -> Self {
        Self {
            supported: false,
            page_size: None,
            total_bytes: None,
            available_bytes: None,
        }
    }
}

/// Query the operating system for huge/large page availability and capacity.
pub fn huge_page_status() -> HugePageStatus {
    #[cfg(target_os = "linux")]
    {
        return linux_huge_page_status();
    }
    #[cfg(target_os = "windows")]
    {
        return windows_large_page_status();
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        HugePageStatus::unsupported()
    }
}

/// Check if operating system currently has usable huge pages / large pages available.
pub fn huge_pages_enabled() -> bool {
    huge_page_status().supported
}

/// Given a huge page status snapshot, determine how many RandomX worker threads can fit
/// into the huge page memory pool. Returns `Some(0)` when the dataset cannot fit at all,
/// `Some(n)` when at most `n` threads fit, or `None` when capacity information is unavailable.
pub fn huge_page_thread_capacity(
    status: &HugePageStatus,
    dataset_bytes: u64,
    scratch_per_thread_bytes: u64,
) -> Option<usize> {
    if !status.supported {
        return None;
    }
    let available = status.available_bytes?;
    if dataset_bytes == 0 || scratch_per_thread_bytes == 0 {
        return None;
    }
    let required = dataset_bytes.saturating_add(scratch_per_thread_bytes);
    if available < required {
        return Some(0);
    }
    let extra = available - dataset_bytes;
    let max_threads = extra / scratch_per_thread_bytes;
    let max_threads = max_threads.min(usize::MAX as u64);
    Some(max_threads.max(1) as usize)
}

#[cfg(target_os = "linux")]
fn linux_huge_page_status() -> HugePageStatus {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(info) = parse_linux_hugepage_info(&meminfo) {
            let page_size = info.page_size_kb.saturating_mul(1024);
            let total_bytes = page_size.saturating_mul(info.total);
            let free_bytes = page_size.saturating_mul(info.free);
            return HugePageStatus {
                supported: info.total > 0 && info.free > 0,
                page_size: Some(page_size),
                total_bytes: Some(total_bytes),
                available_bytes: Some(free_bytes),
            };
        }
    }
    HugePageStatus::unsupported()
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct LinuxHugePageInfo {
    total: u64,
    free: u64,
    page_size_kb: u64,
}

#[cfg(target_os = "linux")]
fn parse_linux_hugepage_info(meminfo: &str) -> Option<LinuxHugePageInfo> {
    let mut total: Option<u64> = None;
    let mut free: Option<u64> = None;
    let mut page_size_kb: Option<u64> = None;

    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("HugePages_Total:") {
            if let Some(value) = rest.trim().split_whitespace().next() {
                total = value.parse::<u64>().ok();
            }
        } else if let Some(rest) = line.strip_prefix("HugePages_Free:") {
            if let Some(value) = rest.trim().split_whitespace().next() {
                free = value.parse::<u64>().ok();
            }
        } else if let Some(rest) = line.strip_prefix("Hugepagesize:") {
            if let Some(value) = rest.trim().split_whitespace().next() {
                page_size_kb = value.parse::<u64>().ok();
            }
        }
    }

    match (total, page_size_kb) {
        (Some(total), Some(page_size_kb)) => Some(LinuxHugePageInfo {
            total,
            free: free.unwrap_or(0),
            page_size_kb,
        }),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn windows_large_page_status() -> HugePageStatus {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, LUID, LUID_AND_ATTRIBUTES,
        SE_LOCK_MEMORY_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Memory::GetLargePageMinimum;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let minimum = GetLargePageMinimum();
        if minimum == 0 {
            return HugePageStatus::unsupported();
        }

        let mut privilege_enabled = false;
        let mut token_handle = 0isize;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        ) != 0
        {
            let mut luid: LUID = zeroed();
            if LookupPrivilegeValueW(0, SE_LOCK_MEMORY_NAME, &mut luid) != 0 {
                let mut privileges = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };

                let adjust_result = AdjustTokenPrivileges(
                    token_handle,
                    0,
                    &mut privileges,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                let last_error = GetLastError();
                privilege_enabled = adjust_result != 0 && last_error != ERROR_NOT_ALL_ASSIGNED;
            }
            let _ = CloseHandle(token_handle);
        }

        let mut status = MEMORYSTATUSEX {
            dwLength: size_of::<MEMORYSTATUSEX>() as u32,
            ..zeroed()
        };
        let available_bytes = if GlobalMemoryStatusEx(&mut status) != 0 {
            Some(status.ullAvailPhys)
        } else {
            None
        };

        HugePageStatus {
            supported: privilege_enabled,
            page_size: Some(minimum as u64),
            total_bytes: None,
            available_bytes,
        }
    }
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
    pub huge_page_status: HugePageStatus,
    pub huge_page_thread_cap: Option<usize>,
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

    let hp_status = huge_page_status();
    let hp_cap = huge_page_thread_capacity(&hp_status, dataset, scratch);

    AutoTuneSnapshot {
        physical_cores: physical,
        l3_bytes: l3,
        available_bytes: avail_bytes,
        dataset_bytes: dataset,
        scratch_per_thread_bytes: scratch,
        huge_page_status: hp_status,
        huge_page_thread_cap: hp_cap,
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
    fn parses_linux_hugepage_info() {
        let enabled = "HugePages_Total: 5\nHugePages_Free: 3\nHugepagesize: 2048 kB\n";
        let info = parse_linux_hugepage_info(enabled).expect("parsed info");
        assert_eq!(info.total, 5);
        assert_eq!(info.free, 3);
        assert_eq!(info.page_size_kb, 2048);

        let missing = "SomethingElse: 1";
        assert!(parse_linux_hugepage_info(missing).is_none());
    }

    #[test]
    fn recommended_matches_snapshot() {
        let snap = autotune_snapshot();
        assert_eq!(recommended_thread_count(), snap.suggested_threads);
    }

    #[test]
    fn huge_page_thread_capacity_bounds() {
        let status = HugePageStatus {
            supported: true,
            page_size: Some(2 * 1024 * 1024),
            total_bytes: None,
            available_bytes: Some(4 * 1024 * 1024 + 3 * 2 * 1024 * 1024),
        };
        let cap = huge_page_thread_capacity(&status, 4 * 1024 * 1024, 2 * 1024 * 1024)
            .expect("capacity available");
        assert_eq!(cap, 3);

        let limited = HugePageStatus {
            supported: true,
            page_size: Some(2 * 1024 * 1024),
            total_bytes: None,
            available_bytes: Some(3 * 1024 * 1024),
        };
        assert_eq!(
            huge_page_thread_capacity(&limited, 4 * 1024 * 1024, 2 * 1024 * 1024),
            Some(0)
        );

        let unsupported = HugePageStatus {
            supported: false,
            ..Default::default()
        };
        assert!(huge_page_thread_capacity(&unsupported, 1, 1).is_none());
    }

    #[test]
    fn feature_checks_do_not_panic() {
        let _ = cpu_has_aes();
        let _ = huge_pages_enabled();
    }
}
