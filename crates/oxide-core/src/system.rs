// OxideMiner/crates/oxide-core/src/system.rs

// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory

use crate::config::DEFAULT_BATCH_SIZE;
use sysinfo::System;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use raw_cpuid::{CacheType, CpuId};

#[cfg(target_os = "windows")]
use std::{mem, ptr, slice};

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED,
        ERROR_SUCCESS, HANDLE, LUID,
    },
    Security::{
        AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges,
        LUID_AND_ATTRIBUTES, SE_LOCK_MEMORY_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::{
        Memory::GetLargePageMinimum,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

/// Size of the RandomX dataset in bytes when running in fast (full memory) mode.
pub const RANDOMX_DATASET_BYTES: u64 = 2_u64 * 1024 * 1024 * 1024; // ~2 GiB
/// Approximate per-thread scratchpad size required by RandomX.
pub const RANDOMX_SCRATCHPAD_BYTES: u64 = 2_u64 * 1024 * 1024; // ~2 MiB

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheLevel {
    pub size_bytes: usize,
    pub line_size: usize,
    pub shared_cores: usize,
}

impl CacheLevel {
    pub fn per_thread_bytes(&self) -> usize {
        let share = self.shared_cores.max(1);
        let size = self.size_bytes.max(share);
        size / share
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheHierarchy {
    pub l1_data: Option<CacheLevel>,
    pub l2: Option<CacheLevel>,
    pub l3: Option<CacheLevel>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub ssse3: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub sse2: bool,
    pub prefetch_sse: bool,
    pub fpu: bool,
    pub out_of_order: bool,
    pub branch_prediction: bool,
    pub ilp: bool,
}

/// Information about the system's huge/large page configuration.
#[derive(Debug, Clone, Default)]
pub struct HugePageStatus {
    pub supported: bool,
    pub has_privilege: bool,
    pub page_size_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
}

impl HugePageStatus {
    /// Whether the operating system reports that huge/large pages can be used right now.
    pub fn enabled(&self) -> bool {
        if !self.supported || !self.has_privilege {
            return false;
        }
        match self.free_bytes {
            Some(0) => false,
            _ => true,
        }
    }

    /// Check whether the supplied allocation size can fit entirely within the available huge pages.
    pub fn dataset_fits(&self, bytes: u64) -> bool {
        if !self.enabled() {
            return false;
        }
        if let Some(page) = self.page_size_bytes {
            if bytes % page != 0 {
                return false;
            }
        }
        match self.free_bytes {
            Some(available) => available >= bytes,
            None => true, // capacity unknown (Windows does not expose a simple query)
        }
    }
}

/// Return the current huge/large page status for the host platform.
pub fn huge_page_status() -> HugePageStatus {
    #[cfg(target_os = "linux")]
    {
        return linux_huge_page_status();
    }
    #[cfg(target_os = "windows")]
    {
        return windows_huge_page_status();
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        HugePageStatus::default()
    }
}

/// Check if operating system has huge pages / large pages available and ready for use.
pub fn huge_pages_enabled() -> bool {
    huge_page_status().enabled()
}

#[cfg(target_os = "linux")]
fn linux_huge_page_status() -> HugePageStatus {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(mut status) = parse_huge_page_info(&meminfo) {
            // When HugePages_Total == 0 we still want to expose the page size (if available).
            if status.page_size_bytes.is_none() {
                status.page_size_bytes = parse_meminfo_value(&meminfo, "Hugepagesize:")
                    .map(|kb| kb.saturating_mul(1024));
            }
            return status;
        }
    }
    HugePageStatus::default()
}

#[cfg(target_os = "linux")]
fn parse_huge_page_info(meminfo: &str) -> Option<HugePageStatus> {
    let total = parse_meminfo_value(meminfo, "HugePages_Total:")?;
    let free = parse_meminfo_value(meminfo, "HugePages_Free:").unwrap_or(0);
    let reserved = parse_meminfo_value(meminfo, "HugePages_Rsvd:").unwrap_or(0);
    let size_kb = parse_meminfo_value(meminfo, "Hugepagesize:")?;
    let page_bytes = size_kb.saturating_mul(1024);
    let free_pages = free.saturating_sub(reserved);
    Some(HugePageStatus {
        supported: total > 0,
        has_privilege: true,
        page_size_bytes: Some(page_bytes),
        total_bytes: Some(total.saturating_mul(page_bytes)),
        free_bytes: Some(free_pages.saturating_mul(page_bytes)),
    })
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(meminfo: &str, needle: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix(needle) {
            if let Some(value) = rest.trim().split_whitespace().next() {
                if let Ok(parsed) = value.parse::<u64>() {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_huge_page_status() -> HugePageStatus {
    unsafe {
        let page_min = GetLargePageMinimum();
        if page_min == 0 {
            return HugePageStatus::default();
        }
        // Try to enable privilege (no harm if already enabled)
        let _ = enable_lock_memory_privilege();

        HugePageStatus {
            supported: true,
            has_privilege: has_lock_memory_privilege(),
            page_size_bytes: Some(page_min as u64),
            total_bytes: None,
            free_bytes: None,
        }
    }
}

/// Attempt to ensure the process token has the SeLockMemoryPrivilege enabled on Windows.
/// On non-Windows platforms this is a no-op that returns true.
pub fn enable_large_page_privilege() -> bool {
    #[cfg(target_os = "windows")]
    {
        enable_lock_memory_privilege()
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

#[cfg(target_os = "windows")]
fn enable_lock_memory_privilege() -> bool {
    unsafe {
        if has_lock_memory_privilege() {
            return true;
        }

        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return false;
        }

        let mut luid: LUID = mem::zeroed();
        if LookupPrivilegeValueW(ptr::null(), SE_LOCK_MEMORY_NAME, &mut luid) == 0 {
            let _ = CloseHandle(token);
            return false;
        }

        let mut privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // Request enable
        if AdjustTokenPrivileges(
            token,
            0,
            &mut privileges,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0
        {
            let _ = CloseHandle(token);
            return false; // API call failed
        }

        // Succeeded, but did it actually enable?
        let gle = GetLastError();
        let _ = CloseHandle(token);

        if gle == ERROR_NOT_ALL_ASSIGNED {
            // Account doesn't have SeLockMemoryPrivilege in User Rights Assignment
            return false;
        }
        if gle != ERROR_SUCCESS {
            // Defensive: unexpected last-error after success path
            return false;
        }

        // Confirm it shows as enabled now
        has_lock_memory_privilege()
    }
}

#[cfg(target_os = "windows")]
fn has_lock_memory_privilege() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut luid: LUID = mem::zeroed();
        if LookupPrivilegeValueW(ptr::null(), SE_LOCK_MEMORY_NAME, &mut luid) == 0 {
            let _ = CloseHandle(token);
            return false;
        }

        let mut required_len: u32 = 0;
        GetTokenInformation(
            token,
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &mut required_len,
        );
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            let _ = CloseHandle(token);
            return false;
        }

        let mut buffer = vec![0u8; required_len as usize];
        if GetTokenInformation(
            token,
            TokenPrivileges,
            buffer.as_mut_ptr().cast(),
            required_len,
            &mut required_len,
        ) == 0
        {
            let _ = CloseHandle(token);
            return false;
        }

        let token_privileges = buffer.as_ptr() as *const TOKEN_PRIVILEGES;
        let count = (*token_privileges).PrivilegeCount as usize;
        let privileges_ptr = (*token_privileges).Privileges.as_ptr();
        let privileges = slice::from_raw_parts(privileges_ptr, count);

        let mut enabled = false;
        for p in privileges {
            if p.Luid.LowPart == luid.LowPart && p.Luid.HighPart == luid.HighPart {
                // Only accept 'enabled now'
                if (p.Attributes & SE_PRIVILEGE_ENABLED) != 0 {
                    enabled = true;
                }
                break;
            }
        }

        let _ = CloseHandle(token);
        enabled
    }
}

pub fn cpu_features() -> CpuFeatures {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        CpuFeatures {
            aes_ni: std::is_x86_feature_detected!("aes"),
            ssse3: std::is_x86_feature_detected!("ssse3"),
            avx2: std::is_x86_feature_detected!("avx2"),
            avx512f: std::is_x86_feature_detected!("avx512f"),
            sse2: std::is_x86_feature_detected!("sse2"),
            prefetch_sse: std::is_x86_feature_detected!("sse"),
            fpu: true,
            out_of_order: true,
            branch_prediction: true,
            ilp: true,
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        CpuFeatures {
            fpu: true,
            out_of_order: true,
            branch_prediction: true,
            ilp: true,
            ..CpuFeatures::default()
        }
    }
}

/// Determine whether the current CPU supports AES instructions (x86/x86_64).
/// RandomX benefits from AES for the HARD_AES flag.
pub fn cpu_has_aes() -> bool {
    cpu_features().aes_ni
}

pub fn cpu_has_ssse3() -> bool {
    cpu_features().ssse3
}

pub fn cpu_has_avx2() -> bool {
    cpu_features().avx2
}

pub fn cpu_has_avx512f() -> bool {
    cpu_features().avx512f
}

pub fn cache_hierarchy() -> CacheHierarchy {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let cpuid = CpuId::new();
        let mut info = CacheHierarchy::default();
        if let Some(cparams) = cpuid.get_cache_parameters() {
            for cache in cparams {
                let size = cache.associativity()
                    * cache.physical_line_partitions()
                    * cache.coherency_line_size()
                    * cache.sets();
                if size == 0 {
                    continue;
                }
                let level = CacheLevel {
                    size_bytes: size,
                    line_size: cache.coherency_line_size(),
                    shared_cores: cache.max_cores_for_cache().max(1),
                };
                match cache.level() {
                    1 if matches!(cache.cache_type(), CacheType::Data | CacheType::Unified) => {
                        if info
                            .l1_data
                            .map(|existing| existing.size_bytes < level.size_bytes)
                            .unwrap_or(true)
                        {
                            info.l1_data = Some(level);
                        }
                    }
                    2 if matches!(cache.cache_type(), CacheType::Data | CacheType::Unified) => {
                        if info
                            .l2
                            .map(|existing| existing.size_bytes < level.size_bytes)
                            .unwrap_or(true)
                        {
                            info.l2 = Some(level);
                        }
                    }
                    3 if matches!(cache.cache_type(), CacheType::Unified) => {
                        if info
                            .l3
                            .map(|existing| existing.size_bytes < level.size_bytes)
                            .unwrap_or(true)
                        {
                            info.l3 = Some(level);
                        }
                    }
                    _ => {}
                }
            }
        }
        info
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        CacheHierarchy::default()
    }
}

pub fn numa_nodes() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        linux_numa_nodes()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_numa_nodes() -> Option<usize> {
    let data = std::fs::read_to_string("/sys/devices/system/node/online").ok()?;
    parse_numa_nodes(&data)
}

#[cfg(target_os = "linux")]
fn parse_numa_nodes(spec: &str) -> Option<usize> {
    let mut total = 0usize;
    let mut saw_entry = false;
    for part in spec.trim().split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        saw_entry = true;
        if let Some((start, end)) = token.split_once('-') {
            let start: usize = start.parse().ok()?;
            let end: usize = end.parse().ok()?;
            if end < start {
                return None;
            }
            total = total.checked_add(end - start + 1)?;
        } else {
            token.parse::<usize>().ok()?;
            total = total.checked_add(1)?;
        }
    }
    if !saw_entry {
        None
    } else {
        Some(total.max(1))
    }
}

#[derive(Debug, Clone)]
pub struct AutoTuneSnapshot {
    pub physical_cores: usize,
    pub cache: CacheHierarchy,
    pub l3_bytes: Option<usize>,
    pub available_bytes: u64,
    pub dataset_bytes: u64,
    pub scratch_per_thread_bytes: u64,
    pub huge_page_status: HugePageStatus,
    pub cpu_features: CpuFeatures,
    pub numa_nodes: Option<usize>,
    pub suggested_threads: usize,
    pub recommended_batch_size: usize,
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
    let cache = cache_hierarchy();
    let l3 = cache.l3.map(|lvl| lvl.size_bytes);
    let features = cpu_features();
    let numa = numa_nodes();
    let avail_bytes = sys.available_memory();

    // RandomX "fast" dataset and per-thread scratchpad estimates
    let dataset = RANDOMX_DATASET_BYTES;
    let scratch = RANDOMX_SCRATCHPAD_BYTES;
    let huge_pages = huge_page_status();

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

    let recommended_batch_size = recommended_batch_size_from_cache(&cache);

    AutoTuneSnapshot {
        physical_cores: physical,
        cache,
        l3_bytes: l3,
        available_bytes: avail_bytes,
        dataset_bytes: dataset,
        scratch_per_thread_bytes: scratch,
        huge_page_status: huge_pages,
        cpu_features: features,
        numa_nodes: numa,
        suggested_threads: threads.max(1),
        recommended_batch_size,
    }
}

/// Legacy helper used elsewhere; delegates to the snapshot.
pub fn recommended_thread_count() -> usize {
    autotune_snapshot().suggested_threads
}

fn recommended_batch_size_from_cache(cache: &CacheHierarchy) -> usize {
    const MIN_BATCH: usize = 2_048;
    const MAX_BATCH: usize = 65_536;

    let mut recommended = DEFAULT_BATCH_SIZE;

    if let Some(l1) = cache.l1_data {
        let per_thread = l1.per_thread_bytes();
        let l1_hashes = (per_thread.max(64) / 64).clamp(MIN_BATCH, MAX_BATCH);
        recommended = l1_hashes;
    }

    if let Some(l2) = cache.l2 {
        let per_thread = l2.per_thread_bytes();
        let l2_hashes = (per_thread.max(128) / 128).clamp(MIN_BATCH, MAX_BATCH);
        recommended = recommended.max(l2_hashes);
    }

    recommended
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_hugepage_info() {
        let enabled = "HugePages_Total:       5\nHugePages_Free:        3\nHugePages_Rsvd:        1\nHugepagesize:       2048 kB";
        let status = parse_huge_page_info(enabled).expect("hugepage info");
        assert!(status.supported);
        assert_eq!(status.page_size_bytes, Some(2048 * 1024));
        // free_pages = 3 - 1 = 2 -> bytes = 2 * 2048 KiB
        assert_eq!(status.free_bytes, Some(2 * 2048 * 1024));

        let disabled =
            "HugePages_Total:       0\nHugePages_Free:        0\nHugepagesize:       2048 kB";
        let status = parse_huge_page_info(disabled).expect("hugepage info");
        assert!(!status.supported);

        let missing = "SomethingElse: 1";
        assert!(parse_huge_page_info(missing).is_none());
    }

    #[test]
    fn recommended_matches_snapshot() {
        let snap = autotune_snapshot();
        assert_eq!(recommended_thread_count(), snap.suggested_threads);
    }

    #[test]
    fn feature_checks_do_not_panic() {
        let _ = cpu_features();
        let _ = cache_hierarchy();
        let _ = cpu_has_aes();
        let _ = cpu_has_ssse3();
        let _ = cpu_has_avx2();
        let _ = cpu_has_avx512f();
        let _ = numa_nodes();
        let _ = huge_pages_enabled();
        let _ = huge_page_status();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_numa_ranges() {
        assert_eq!(parse_numa_nodes("0"), Some(1));
        assert_eq!(parse_numa_nodes("0-1"), Some(2));
        assert_eq!(parse_numa_nodes("0,2,4"), Some(3));
        assert!(parse_numa_nodes("2-1").is_none());
    }

    #[test]
    fn huge_page_status_enabled_logic() {
        let mut status = HugePageStatus {
            supported: false,
            has_privilege: true,
            page_size_bytes: Some(2048),
            total_bytes: Some(4096),
            free_bytes: Some(4096),
        };
        assert!(!status.enabled());
        status.supported = true;
        assert!(status.enabled());
        status.has_privilege = false;
        assert!(!status.enabled());
        status.has_privilege = true;
        status.free_bytes = Some(0);
        assert!(!status.enabled());
    }

    #[test]
    fn dataset_fits_respects_alignment() {
        let mut status = HugePageStatus {
            supported: true,
            has_privilege: true,
            page_size_bytes: Some(1024),
            total_bytes: Some(8192),
            free_bytes: Some(4096),
        };
        assert!(status.dataset_fits(2048));
        assert!(!status.dataset_fits(3000));
        status.free_bytes = Some(1024);
        assert!(!status.dataset_fits(2048));
        status.free_bytes = None;
        assert!(status.dataset_fits(2048));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_value_extracts_numbers() {
        let meminfo = "HugePages_Total:       8 kB\nOther: 123";
        assert_eq!(parse_meminfo_value(meminfo, "HugePages_Total:"), Some(8));
        assert_eq!(parse_meminfo_value(meminfo, "Missing:"), None);
    }
}
