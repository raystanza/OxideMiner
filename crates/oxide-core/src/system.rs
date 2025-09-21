// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory
//
// Compatible with sysinfo >= 0.30 (methods are inherent on `System`).

use sysinfo::System;

#[cfg(target_os = "windows")]
use once_cell::sync::OnceCell;

/// Size of the RandomX "fast" dataset (~2 GiB).
pub const RANDOMX_DATASET_BYTES: u64 = 2_u64 * 1024 * 1024 * 1024;
/// Approximate scratchpad memory used per mining thread (~2 MiB).
pub const RANDOMX_SCRATCH_PER_THREAD_BYTES: u64 = 2_u64 * 1024 * 1024;

/// Summary of the system's large/huge page capabilities.
#[derive(Debug, Clone)]
pub struct HugePageInfo {
    /// Operating system large/huge page size in bytes.
    pub page_size: u64,
    /// Total amount of memory backed by large/huge pages when known.
    pub total_bytes: Option<u64>,
    /// Currently free large/huge page memory when known.
    pub free_bytes: Option<u64>,
}

/// Query operating system support for large/huge pages.
pub fn huge_page_info() -> Option<HugePageInfo> {
    detect_huge_page_info()
}

/// Check if operating system has huge pages / large pages available.
/// On Linux this inspects `/proc/meminfo`'s `HugePages_Total` value.
/// On Windows it queries `GetLargePageMinimum`.
pub fn huge_pages_enabled() -> bool {
    match huge_page_info() {
        Some(info) => match info.free_bytes {
            // When the OS exposes a free counter ensure the RandomX dataset (~2 GiB) fits.
            Some(bytes) => bytes >= RANDOMX_DATASET_BYTES,
            // On Windows we verify availability by probing an allocation, but do not know
            // the remaining capacity. Assume availability if the probe succeeded.
            None => true,
        },
        None => false,
    }
}

#[cfg(target_os = "linux")]
fn detect_huge_page_info() -> Option<HugePageInfo> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let total_pages = parse_meminfo_value(&meminfo, "HugePages_Total")?;
    if total_pages == 0 {
        return None;
    }
    let free_pages = parse_meminfo_value(&meminfo, "HugePages_Free").unwrap_or(0);
    if free_pages == 0 {
        return None;
    }
    let page_kib = parse_meminfo_value(&meminfo, "Hugepagesize")?;
    if page_kib == 0 {
        return None;
    }

    let page_size = page_kib * 1024;

    // Ensure we have sufficient privilege by probing an anonymous huge page mapping.
    if !try_linux_huge_page_alloc(page_size as usize) {
        return None;
    }

    Some(HugePageInfo {
        page_size: page_size as u64,
        total_bytes: Some(total_pages as u64 * page_size as u64),
        free_bytes: Some(free_pages as u64 * page_size as u64),
    })
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(meminfo: &str, key: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(value) = rest
                .split_whitespace()
                .find_map(|tok| tok.parse::<u64>().ok())
            {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn try_linux_huge_page_alloc(size: usize) -> bool {
    use libc::{
        mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_PRIVATE, PROT_READ, PROT_WRITE,
    };

    unsafe {
        let ptr = mmap(
            std::ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
            -1,
            0,
        );
        if ptr == MAP_FAILED {
            return false;
        }
        if munmap(ptr, size) != 0 {
            tracing::warn!(
                "failed to munmap test huge page mapping; continuing without huge pages"
            );
            return false;
        }
    }
    true
}

#[cfg(target_os = "windows")]
fn detect_huge_page_info() -> Option<HugePageInfo> {
    use windows_sys::Win32::System::Memory::{
        GetLargePageMinimum, VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_LARGE_PAGES, MEM_RELEASE,
        MEM_RESERVE, PAGE_READWRITE,
    };

    let size = unsafe { GetLargePageMinimum() };
    if size == 0 {
        return None;
    }

    if !enable_lock_memory_privilege() {
        return None;
    }

    let ptr = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            size as usize,
            MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
            PAGE_READWRITE,
        )
    };
    if ptr.is_null() {
        return None;
    }

    unsafe {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }

    Some(HugePageInfo {
        page_size: size as u64,
        total_bytes: None,
        free_bytes: None,
    })
}

#[cfg(target_os = "windows")]
fn enable_lock_memory_privilege() -> bool {
    static RESULT: OnceCell<bool> = OnceCell::new();
    *RESULT.get_or_init(|| unsafe { adjust_lock_memory_privilege() })
}

#[cfg(target_os = "windows")]
unsafe fn adjust_lock_memory_privilege() -> bool {
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, LUID, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut token: isize = 0;
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    ) == 0
    {
        return false;
    }

    let name: Vec<u16> = "SeLockMemoryPrivilege\0".encode_utf16().collect();
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
        CloseHandle(token);
        return false;
    }

    let mut privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    if AdjustTokenPrivileges(
        token,
        0,
        &mut privileges,
        size_of::<TOKEN_PRIVILEGES>() as u32,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) == 0
    {
        CloseHandle(token);
        return false;
    }

    let assigned = GetLastError();
    CloseHandle(token);
    assigned != ERROR_NOT_ALL_ASSIGNED
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn detect_huge_page_info() -> Option<HugePageInfo> {
    None
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
    let dataset = RANDOMX_DATASET_BYTES;
    let scratch = RANDOMX_SCRATCH_PER_THREAD_BYTES;

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
    fn parses_hugepages_entries() {
        let enabled =
            "HugePages_Total:       5\nHugePages_Free:       3\nHugepagesize:       2048 kB";
        assert_eq!(parse_meminfo_value(enabled, "HugePages_Total"), Some(5));
        assert_eq!(parse_meminfo_value(enabled, "HugePages_Free"), Some(3));
        assert_eq!(parse_meminfo_value(enabled, "Hugepagesize"), Some(2048));
        assert_eq!(
            parse_meminfo_value("SomethingElse: 1", "HugePages_Total"),
            None
        );
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
