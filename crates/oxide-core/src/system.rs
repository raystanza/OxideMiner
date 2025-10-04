// OxideMiner/crates/oxide-core/src/system.rs

// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory

use once_cell::sync::Lazy;
use sysinfo::System;

use std::path::Path;

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

/// CPU feature information relevant for RandomX tuning.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    pub aes: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub ssse3: bool,
    pub sse2: bool,
}

impl CpuFeatures {
    pub fn hardware_aes(self) -> bool {
        self.aes
    }

    pub fn uses_simd(self) -> bool {
        self.avx2 || self.ssse3 || self.sse2
    }
}

/// Cache hierarchy information derived from CPUID when available.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheHierarchy {
    pub l1_data_bytes: Option<usize>,
    pub l1_instruction_bytes: Option<usize>,
    pub l2_bytes: Option<usize>,
    pub l3_bytes: Option<usize>,
}

static CPU_FEATURES: Lazy<CpuFeatures> = Lazy::new(detect_cpu_features);
static CACHE_HIERARCHY: Lazy<CacheHierarchy> = Lazy::new(detect_cache_hierarchy);

pub fn cpu_features() -> CpuFeatures {
    *CPU_FEATURES
}

pub fn cpu_cache_hierarchy() -> CacheHierarchy {
    *CACHE_HIERARCHY
}

fn detect_cpu_features() -> CpuFeatures {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        CpuFeatures {
            aes: std::is_x86_feature_detected!("aes"),
            avx2: std::is_x86_feature_detected!("avx2"),
            avx512f: std::is_x86_feature_detected!("avx512f"),
            ssse3: std::is_x86_feature_detected!("ssse3"),
            sse2: std::is_x86_feature_detected!("sse2"),
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        CpuFeatures::default()
    }
}

fn detect_cache_hierarchy() -> CacheHierarchy {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        use raw_cpuid::CacheType;

        let cpuid = raw_cpuid::CpuId::new();
        let mut hierarchy = CacheHierarchy::default();

        if let Some(params) = cpuid.get_cache_parameters() {
            for cache in params {
                let cache_type = cache.cache_type();
                if matches!(cache_type, CacheType::Null) {
                    continue;
                }

                let size = (cache.associativity() as usize)
                    * (cache.physical_line_partitions() as usize)
                    * (cache.coherency_line_size() as usize)
                    * (cache.sets() as usize);

                match (cache.level(), cache_type) {
                    (1, CacheType::Data) => assign_cache_size(&mut hierarchy.l1_data_bytes, size),
                    (1, CacheType::Instruction) => {
                        assign_cache_size(&mut hierarchy.l1_instruction_bytes, size)
                    }
                    (1, CacheType::Unified) => {
                        assign_cache_size(&mut hierarchy.l1_data_bytes, size);
                        assign_cache_size(&mut hierarchy.l1_instruction_bytes, size);
                    }
                    (2, CacheType::Unified | CacheType::Data) => {
                        assign_cache_size(&mut hierarchy.l2_bytes, size)
                    }
                    (3, CacheType::Unified) => assign_cache_size(&mut hierarchy.l3_bytes, size),
                    _ => {}
                }
            }
        }

        hierarchy
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        CacheHierarchy::default()
    }
}

fn assign_cache_size(slot: &mut Option<usize>, size: usize) {
    match slot {
        Some(existing) => {
            if size > *existing {
                *existing = size;
            }
        }
        None => *slot = Some(size),
    }
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

/// Determine whether the current CPU supports AES instructions (x86/x86_64).
/// RandomX benefits from AES for the HARD_AES flag.
pub fn cpu_has_aes() -> bool {
    cpu_features().hardware_aes()
}

#[derive(Debug, Clone)]
pub struct AutoTuneSnapshot {
    pub physical_cores: usize,
    pub l1_data_bytes: Option<usize>,
    pub l2_bytes: Option<usize>,
    pub l3_bytes: Option<usize>,
    pub available_bytes: u64,
    pub dataset_bytes: u64,
    pub scratch_per_thread_bytes: u64,
    pub huge_page_status: HugePageStatus,
    pub suggested_threads: usize,
    pub numa_nodes: Option<usize>,
    pub features: CpuFeatures,
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
    let features = cpu_features();
    let caches = cpu_cache_hierarchy();
    let l3 = caches.l3_bytes;
    let numa_nodes = detect_numa_nodes();
    let recommended_batch_size = recommended_batch_size_from_cache(&caches);
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

    AutoTuneSnapshot {
        physical_cores: physical,
        l1_data_bytes: caches.l1_data_bytes,
        l2_bytes: caches.l2_bytes,
        l3_bytes: l3,
        available_bytes: avail_bytes,
        dataset_bytes: dataset,
        scratch_per_thread_bytes: scratch,
        huge_page_status: huge_pages,
        suggested_threads: threads.max(1),
        numa_nodes,
        features,
        recommended_batch_size,
    }
}

/// Legacy helper used elsewhere; delegates to the snapshot.
pub fn recommended_thread_count() -> usize {
    autotune_snapshot().suggested_threads
}

fn detect_numa_nodes() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        let node_path = Path::new("/sys/devices/system/node");
        if let Ok(entries) = std::fs::read_dir(node_path) {
            let mut count = 0usize;
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(name) = name.to_str() {
                    if let Some(index) = name.strip_prefix("node") {
                        if !index.is_empty() && index.chars().all(|c| c.is_ascii_digit()) {
                            count += 1;
                        }
                    }
                }
            }
            if count > 0 {
                Some(count)
            } else {
                None
            }
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn recommended_batch_size_from_cache(cache: &CacheHierarchy) -> usize {
    const DEFAULT_BATCH: usize = 10_000;
    const MIN_BATCH: usize = 256;
    const MAX_BATCH: usize = 8_192;

    let mut batch = DEFAULT_BATCH;
    let mut tuned = false;

    if let Some(l1d) = cache.l1_data_bytes {
        let mut l1_based = l1d / 64;
        if l1_based == 0 {
            l1_based = 1;
        }
        if l1_based < MIN_BATCH {
            l1_based = MIN_BATCH;
        }
        if l1_based > MAX_BATCH {
            l1_based = MAX_BATCH;
        }
        batch = batch.min(l1_based);
        tuned = true;
    }

    if let Some(l2) = cache.l2_bytes {
        let mut l2_based = l2 / 128;
        if l2_based == 0 {
            l2_based = 1;
        }
        if l2_based < MIN_BATCH {
            l2_based = MIN_BATCH;
        }
        if l2_based > MAX_BATCH {
            l2_based = MAX_BATCH;
        }
        batch = batch.min(l2_based);
        tuned = true;
    }

    if tuned {
        batch
    } else {
        DEFAULT_BATCH
    }
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
        let _ = cpu_has_aes();
        let _ = cpu_features();
        let _ = cpu_cache_hierarchy();
        let _ = huge_pages_enabled();
        let _ = huge_page_status();
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
