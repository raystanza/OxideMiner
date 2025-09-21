// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory
//
// Compatible with sysinfo >= 0.30 (methods are inherent on `System`).

use sysinfo::System;

/// Details about the platform huge/large page configuration.
#[derive(Debug, Clone, Copy)]
pub struct HugePageState {
    pub page_size_bytes: u64,
    pub total_pages: Option<u64>,
    pub free_pages: Option<u64>,
    pub can_allocate: bool,
}

impl HugePageState {
    pub fn free_bytes(&self) -> Option<u64> {
        self.free_pages
            .map(|pages| pages.saturating_mul(self.page_size_bytes))
    }
}

/// Return the current huge/large page configuration visible to the process.
pub fn huge_page_state() -> Option<HugePageState> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            return parse_huge_page_state(&meminfo);
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        windows_huge_page_state()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

/// Check if operating system has huge pages / large pages available for this process.
pub fn huge_pages_enabled() -> bool {
    huge_page_state()
        .map(|state| platform_huge_pages_enabled(&state))
        .unwrap_or(false)
}

fn platform_huge_pages_enabled(state: &HugePageState) -> bool {
    #[cfg(target_os = "windows")]
    {
        return state.can_allocate;
    }
    #[cfg(target_os = "linux")]
    {
        return state.can_allocate;
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        return false;
    }
}

#[cfg(target_os = "linux")]
fn parse_huge_page_state(meminfo: &str) -> Option<HugePageState> {
    let total = parse_meminfo_value(meminfo, "HugePages_Total")?;
    let free = parse_meminfo_value(meminfo, "HugePages_Free")?;
    let size_kb = parse_meminfo_value(meminfo, "Hugepagesize")?;
    let page_size_bytes = size_kb.saturating_mul(1024);

    let can_allocate = if free > 0 {
        probe_hugetlb_allocation(page_size_bytes as usize)
    } else {
        false
    };

    Some(HugePageState {
        page_size_bytes,
        total_pages: Some(total),
        free_pages: Some(free),
        can_allocate,
    })
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(meminfo: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}:");
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix(&needle) {
            if let Some(val) = rest.trim().split_whitespace().next() {
                if let Ok(parsed) = val.parse::<u64>() {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn probe_hugetlb_allocation(page_size: usize) -> bool {
    use std::ptr;

    unsafe {
        let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB;
        if let Some(extra) = huge_page_flag(page_size) {
            flags |= extra;
        }
        let ptr = libc::mmap(
            ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return false;
        }
        libc::munmap(ptr, page_size);
        true
    }
}

#[cfg(target_os = "linux")]
fn huge_page_flag(page_size: usize) -> Option<i32> {
    if !page_size.is_power_of_two() || page_size < (1 << 10) {
        return None;
    }
    let log = page_size.trailing_zeros() as i32;
    let shift = libc::MAP_HUGE_SHIFT as i32;
    Some(((log - 10) << shift) as i32)
}

#[cfg(target_os = "windows")]
fn windows_huge_page_state() -> Option<HugePageState> {
    use windows_sys::Win32::System::Memory::GetLargePageMinimum;

    let page_size = unsafe { GetLargePageMinimum() };
    if page_size == 0 {
        return None;
    }
    let can_allocate = has_lock_memory_privilege();
    Some(HugePageState {
        page_size_bytes: page_size as u64,
        total_pages: None,
        free_pages: None,
        can_allocate,
    })
}

#[cfg(target_os = "windows")]
fn has_lock_memory_privilege() -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, LUID,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupPrivilegeValueW, OpenProcessToken, TokenPrivileges,
        LUID_AND_ATTRIBUTES, SE_LOCK_MEMORY_NAME, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(ptr::null(), SE_LOCK_MEMORY_NAME, &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }

        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenPrivileges, ptr::null_mut(), 0, &mut needed);
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            CloseHandle(token);
            return false;
        }

        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenPrivileges,
            buffer.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        ) == 0
        {
            CloseHandle(token);
            return false;
        }

        let tp = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = tp.PrivilegeCount as usize;
        let privs_ptr = tp.Privileges.as_ptr();
        let privs = std::slice::from_raw_parts(privs_ptr, count);
        let has = privs
            .iter()
            .any(|p| p.Luid.LowPart == luid.LowPart && p.Luid.HighPart == luid.HighPart);

        CloseHandle(token);
        has
    }
}

#[cfg(target_os = "windows")]
fn enable_lock_memory_privilege() -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, OpenProcessToken, LUID_AND_ATTRIBUTES,
        SE_LOCK_MEMORY_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let mut token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(ptr::null(), SE_LOCK_MEMORY_NAME, &mut luid) == 0 {
            CloseHandle(token);
            return false;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let adjust_ok = AdjustTokenPrivileges(
            token,
            0,
            &mut tp,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let error = GetLastError();
        CloseHandle(token);
        if adjust_ok == 0 || error == ERROR_NOT_ALL_ASSIGNED {
            return false;
        }
        true
    }
}

#[cfg(target_os = "windows")]
pub fn ensure_lock_memory_privilege() -> bool {
    use std::ptr;
    use windows_sys::Win32::System::Memory::{
        GetLargePageMinimum, VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_LARGE_PAGES, MEM_RELEASE,
        MEM_RESERVE, PAGE_READWRITE,
    };

    if !enable_lock_memory_privilege() {
        return false;
    }

    unsafe {
        let page_size = GetLargePageMinimum();
        if page_size == 0 {
            return false;
        }
        let ptr = VirtualAlloc(
            ptr::null_mut(),
            page_size,
            MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
            PAGE_READWRITE,
        );
        if ptr.is_null() {
            return false;
        }
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
    true
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

const RANDOMX_DATASET_BYTES: u64 = 2_u64 * 1024 * 1024 * 1024; // ~2 GiB
const RANDOMX_SCRATCH_PER_THREAD_BYTES: u64 = 2_u64 * 1024 * 1024; // ~2 MiB

#[derive(Debug, Clone)]
pub struct AutoTuneSnapshot {
    pub physical_cores: usize,
    pub l3_bytes: Option<usize>,
    pub available_bytes: u64,
    pub dataset_bytes: u64,
    pub scratch_per_thread_bytes: u64,
    pub huge_page_free_bytes: Option<u64>,
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
    let huge_page_bytes = huge_page_state().and_then(|state| state.free_bytes());

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
        huge_page_free_bytes: huge_page_bytes,
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
    fn parses_huge_page_state() {
        let meminfo =
            "HugePages_Total:       5\nHugePages_Free:        3\nHugepagesize:       2048 kB\n";
        let state = parse_huge_page_state(meminfo).expect("state");
        assert_eq!(state.total_pages, Some(5));
        assert_eq!(state.free_pages, Some(3));
        assert_eq!(state.page_size_bytes, 2048 * 1024);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_huge_page_state_missing_values() {
        assert!(parse_huge_page_state("SomethingElse: 1").is_none());
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
        let _ = huge_page_state();
    }
}
