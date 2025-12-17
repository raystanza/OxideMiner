// OxideMiner/crates/oxide-core/src/system.rs

// Cross-platform system capability helpers for OxideMiner.
// - Huge/large pages detection (Linux/Windows)
// - CPU feature probes (AES for RandomX HARD_AES)
// - Heuristics for recommended thread count based on cores/L3/memory

use crate::config::DEFAULT_BATCH_SIZE;
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "linux")]
use std::path::Path;
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
        SystemInformation::{
            CacheData, CacheInstruction, CacheUnified, GetLogicalProcessorInformationEx,
            RelationCache, CACHE_RELATIONSHIP, GROUP_AFFINITY,
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
        },
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

#[derive(Debug, Clone, Default)]
pub struct L3Instance {
    pub size_bytes: usize,
    pub shared_logical_cpus: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheSource {
    LinuxSysfs,
    WindowsApi,
    RawCpuid,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct CacheHierarchy {
    pub l1_data: Option<CacheLevel>,
    pub l1_instruction: Option<CacheLevel>,
    pub l2: Option<CacheLevel>,
    pub l3: Option<CacheLevel>,
    pub l3_total_bytes: Option<usize>,
    pub l3_instances: Vec<L3Instance>,
    pub source: CacheSource,
    pub warnings: Vec<String>,
}

impl CacheHierarchy {
    pub fn l3_total(&self) -> Option<usize> {
        if let Some(total) = self.l3_total_bytes {
            return Some(total);
        }
        if !self.l3_instances.is_empty() {
            return Some(self.l3_instances.iter().map(|i| i.size_bytes).sum());
        }
        self.l3.map(|lvl| lvl.size_bytes)
    }

    pub fn max_l3_instance_size(&self) -> Option<usize> {
        self.l3_instances
            .iter()
            .map(|inst| inst.size_bytes)
            .max()
            .or_else(|| self.l3.map(|lvl| lvl.size_bytes))
    }

    pub fn l3_summary(&self) -> Option<String> {
        let total = self.l3_total()?;
        if self.l3_instances.is_empty() {
            return Some(format!("{} total (reported shared)", format_bytes(total)));
        }

        let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
        for inst in &self.l3_instances {
            *counts.entry(inst.size_bytes).or_insert(0) += 1;
        }

        let mut parts = Vec::new();
        for (size, count) in counts {
            if count == 1 {
                parts.push(format_bytes(size).to_string());
            } else {
                parts.push(format!("{} x {}", count, format_bytes(size)));
            }
        }

        let domain_label = "shared per cache domain";
        let per_domain = if parts.len() == 1 {
            parts[0].clone()
        } else {
            parts.join(", ")
        };
        Some(format!(
            "{} ({}), {} total",
            per_domain,
            domain_label,
            format_bytes(total)
        ))
    }

    pub fn l3_instance_debug(&self) -> Vec<String> {
        self.l3_instances
            .iter()
            .enumerate()
            .map(|(idx, inst)| {
                format!(
                    "L3[{}]: {} shared by CPUs {}",
                    idx,
                    format_bytes(inst.size_bytes),
                    format_cpu_list(&inst.shared_logical_cpus)
                )
            })
            .collect()
    }

    pub fn debug_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("cache_source={:?}", self.source));

        if let Some(l1d) = self.l1_data {
            lines.push(format!(
                "L1d: {} (line {} B, shared across {} logical CPUs)",
                format_bytes(l1d.size_bytes),
                l1d.line_size,
                l1d.shared_cores
            ));
        }
        if let Some(l1i) = self.l1_instruction {
            lines.push(format!(
                "L1i: {} (line {} B, shared across {} logical CPUs)",
                format_bytes(l1i.size_bytes),
                l1i.line_size,
                l1i.shared_cores
            ));
        }
        if let Some(l2) = self.l2 {
            lines.push(format!(
                "L2: {} (line {} B, shared across {} logical CPUs)",
                format_bytes(l2.size_bytes),
                l2.line_size,
                l2.shared_cores
            ));
        }

        for detail in self.l3_instance_debug() {
            lines.push(detail);
        }
        if let Some(total) = self.l3_total() {
            lines.push(format!("L3 total: {}", format_bytes(total)));
        }
        if let Some(summary) = self.l3_summary() {
            lines.push(format!("L3 summary: {}", summary));
        }
        for warning in &self.warnings {
            lines.push(format!("warning: {}", warning));
        }
        lines
    }
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
        !matches!(self.free_bytes, Some(0))
    }

    /// Check whether the supplied allocation size can fit entirely within the available huge pages.
    pub fn dataset_fits(&self, bytes: u64) -> bool {
        if !self.enabled() {
            return false;
        }
        if let Some(page) = self.page_size_bytes {
            if !bytes.is_multiple_of(page) {
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
        linux_huge_page_status()
    }
    #[cfg(target_os = "windows")]
    {
        windows_huge_page_status()
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
            if let Some(value) = rest.split_whitespace().next() {
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
    // SAFETY: `GetLargePageMinimum` performs no memory access and the helper functions invoked
    // below only operate on OS-managed handles. We do not pass any invalid pointers.
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
    // SAFETY: All raw handles are obtained from Win32 APIs and closed on every exit path. The
    // buffer we pass to `AdjustTokenPrivileges` is stack-allocated and lives for the duration of
    // the call, so pointer arguments remain valid.
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

        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // Request enable
        if AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut()) == 0 {
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
    // SAFETY: All pointers and buffer lengths originate from Win32 APIs. The token handle is
    // closed before returning, and we validate the size of the returned privilege list before
    // creating typed slices from it.
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

        if required_len == 0 {
            let _ = CloseHandle(token);
            return false;
        }

        let word_size = mem::size_of::<usize>();
        let len_words = (required_len as usize).div_ceil(word_size);
        let mut buffer = vec![0usize; len_words];
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

        let base = mem::size_of::<TOKEN_PRIVILEGES>();
        let extra = count
            .saturating_sub(1)
            .saturating_mul(mem::size_of::<LUID_AND_ATTRIBUTES>());
        let needed = match base.checked_add(extra) {
            Some(n) => n,
            None => {
                let _ = CloseHandle(token);
                return false;
            }
        };
        if needed > len_words * word_size {
            let _ = CloseHandle(token);
            return false;
        }

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
    #[cfg(target_os = "linux")]
    {
        if let Some(h) = linux_cache_hierarchy(Path::new("/sys/devices/system/cpu")) {
            return h;
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(h) = unsafe { windows_cache_hierarchy() } {
            return h;
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        return cpuid_cache_hierarchy(CacheSource::RawCpuid);
    }

    #[allow(unreachable_code)]
    CacheHierarchy::default()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpuid_cache_hierarchy(source: CacheSource) -> CacheHierarchy {
    let cpuid = CpuId::new();
    let mut info = CacheHierarchy {
        source,
        ..CacheHierarchy::default()
    };
    let mut l3_descriptors: Vec<(usize, usize)> = Vec::new(); // (size_bytes, shared_cores)

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
                1 if matches!(cache.cache_type(), CacheType::Instruction) => {
                    if info
                        .l1_instruction
                        .map(|existing| existing.size_bytes < level.size_bytes)
                        .unwrap_or(true)
                    {
                        info.l1_instruction = Some(level);
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
                    let shared = cache.max_cores_for_cache().max(1);
                    if info
                        .l3
                        .map(|existing| existing.size_bytes < level.size_bytes)
                        .unwrap_or(true)
                    {
                        info.l3 = Some(level);
                    }
                    l3_descriptors.push((size, shared));
                }
                _ => {}
            }
        }
    }

    if let Some((size_bytes, shared_cores)) =
        l3_descriptors.into_iter().max_by_key(|(size, _)| *size)
    {
        let logical_cpus = num_cpus::get().max(1);
        info.l3_instances.extend(synthesize_l3_instances(
            size_bytes,
            shared_cores,
            logical_cpus,
        ));
        info.l3_total_bytes = Some(info.l3_instances.iter().map(|c| c.size_bytes).sum());
    }

    if matches!(source, CacheSource::RawCpuid) && info.warnings.is_empty() {
        info.warnings.push(
            "using CPUID cache topology fallback; OS-specific cache grouping unavailable".into(),
        );
    }

    info
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpuid_cache_hierarchy(_source: CacheSource) -> CacheHierarchy {
    CacheHierarchy::default()
}

#[cfg_attr(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    allow(dead_code)
)]
fn synthesize_l3_instances(
    size_bytes: usize,
    shared_cores: usize,
    logical_cpus: usize,
) -> Vec<L3Instance> {
    let shared = shared_cores.max(1);
    let logical = logical_cpus.max(1);
    let instance_count = logical.div_ceil(shared);
    let mut next_cpu = 0usize;
    let mut instances = Vec::new();

    for _ in 0..instance_count.max(1) {
        if next_cpu >= logical {
            break;
        }
        let end = (next_cpu + shared).min(logical);
        let cpus: Vec<usize> = (next_cpu..end).collect();
        instances.push(L3Instance {
            size_bytes,
            shared_logical_cpus: cpus,
        });
        next_cpu = end;
    }

    if instances.is_empty() {
        instances.push(L3Instance {
            size_bytes,
            shared_logical_cpus: (0..shared).collect(),
        });
    }

    instances
}

#[cfg(target_os = "linux")]
fn linux_cache_hierarchy(base: &Path) -> Option<CacheHierarchy> {
    let mut warnings = Vec::new();
    let candidate = base.join("cpu");
    let cpu_dir = if candidate.is_dir() {
        candidate
    } else {
        base.to_path_buf()
    };
    let entries = std::fs::read_dir(&cpu_dir).ok()?;
    let mut caches: HashMap<(u32, CacheKind, String), SysfsCacheEntry> = HashMap::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("cpu") {
            continue;
        }
        let idx: usize = match name_str[3..].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let cache_root = entry.path().join("cache");
        let Ok(cache_dirs) = std::fs::read_dir(cache_root) else {
            continue;
        };

        for cache_dir in cache_dirs.flatten() {
            let path = cache_dir.path();
            let level: u32 = match read_trimmed(path.join("level")).and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => continue,
            };
            let kind = match read_trimmed(path.join("type")).and_then(|s| CacheKind::from_str(&s)) {
                Some(v) => v,
                None => continue,
            };
            let size_bytes =
                match read_trimmed(path.join("size")).and_then(|s| parse_size_bytes(&s)) {
                    Some(v) => v,
                    None => {
                        warnings.push(format!(
                            "cpu{}: unable to parse cache size for {:?}",
                            idx, path
                        ));
                        continue;
                    }
                };
            let shared_cpu_list = match read_trimmed(path.join("shared_cpu_list"))
                .and_then(|s| parse_shared_cpu_list(&s))
            {
                Some(list) => list,
                None => {
                    warnings.push(format!(
                        "cpu{}: missing shared_cpu_list for {:?}",
                        idx, path
                    ));
                    continue;
                }
            };
            let line_size = read_trimmed(path.join("coherency_line_size"))
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);

            let canonical = format_cpu_list(&shared_cpu_list);
            let key = (level, kind, canonical);
            let entry = SysfsCacheEntry {
                level,
                kind,
                size_bytes,
                line_size,
                shared_cpu_list,
            };

            caches
                .entry(key)
                .and_modify(|existing| {
                    if existing.size_bytes != entry.size_bytes {
                        warnings.push(format!(
                            "conflicting cache sizes for level {} {:?} between CPUs {} and {}",
                            level,
                            kind,
                            format_cpu_list(&existing.shared_cpu_list),
                            idx
                        ));
                    }
                })
                .or_insert(entry);
        }
    }

    if caches.is_empty() {
        return None;
    }

    let mut info = CacheHierarchy {
        source: CacheSource::LinuxSysfs,
        warnings,
        ..CacheHierarchy::default()
    };

    for entry in caches.into_values() {
        match (entry.level, entry.kind) {
            (1, CacheKind::Data) | (1, CacheKind::Unified) => {
                let level = CacheLevel {
                    size_bytes: entry.size_bytes,
                    line_size: entry.line_size,
                    shared_cores: entry.shared_cpu_list.len().max(1),
                };
                if info
                    .l1_data
                    .map(|existing| existing.size_bytes < level.size_bytes)
                    .unwrap_or(true)
                {
                    info.l1_data = Some(level);
                }
            }
            (1, CacheKind::Instruction) => {
                let level = CacheLevel {
                    size_bytes: entry.size_bytes,
                    line_size: entry.line_size,
                    shared_cores: entry.shared_cpu_list.len().max(1),
                };
                if info
                    .l1_instruction
                    .map(|existing| existing.size_bytes < level.size_bytes)
                    .unwrap_or(true)
                {
                    info.l1_instruction = Some(level);
                }
            }
            (2, CacheKind::Data) | (2, CacheKind::Unified) => {
                let level = CacheLevel {
                    size_bytes: entry.size_bytes,
                    line_size: entry.line_size,
                    shared_cores: entry.shared_cpu_list.len().max(1),
                };
                if info
                    .l2
                    .map(|existing| existing.size_bytes < level.size_bytes)
                    .unwrap_or(true)
                {
                    info.l2 = Some(level);
                }
            }
            (3, CacheKind::Unified) => {
                let level = CacheLevel {
                    size_bytes: entry.size_bytes,
                    line_size: entry.line_size,
                    shared_cores: entry.shared_cpu_list.len().max(1),
                };
                if info
                    .l3
                    .map(|existing| existing.size_bytes < level.size_bytes)
                    .unwrap_or(true)
                {
                    info.l3 = Some(level);
                }
                info.l3_instances.push(L3Instance {
                    size_bytes: entry.size_bytes,
                    shared_logical_cpus: entry.shared_cpu_list,
                });
            }
            _ => {}
        }
    }

    if !info.l3_instances.is_empty() {
        info.l3_total_bytes = Some(info.l3_instances.iter().map(|i| i.size_bytes).sum());
        info.l3_instances
            .iter_mut()
            .for_each(|inst| inst.shared_logical_cpus.sort_unstable());
    }

    Some(info)
}

#[cfg(target_os = "windows")]
#[allow(non_upper_case_globals)]
unsafe fn windows_cache_hierarchy() -> Option<CacheHierarchy> {
    let mut len: u32 = 0;
    let mut res = GetLogicalProcessorInformationEx(RelationCache, std::ptr::null_mut(), &mut len);
    if res != 0 {
        return None;
    }
    let err = GetLastError();
    if err != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    let mut buf = vec![0u8; len as usize];
    res = GetLogicalProcessorInformationEx(
        RelationCache,
        buf.as_mut_ptr() as *mut SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
        &mut len,
    );
    if res == 0 {
        return None;
    }

    let mut offset = 0usize;
    let mut info = CacheHierarchy {
        source: CacheSource::WindowsApi,
        ..CacheHierarchy::default()
    };
    let mut l3_map: HashMap<(u8, usize, Vec<usize>), L3Instance> = HashMap::new();

    while offset < len as usize {
        let ptr = buf.as_ptr().add(offset) as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
        let size = (*ptr).Size as usize;
        if (*ptr).Relationship == RelationCache {
            let cache: &CACHE_RELATIONSHIP = unsafe { &(*ptr).Anonymous.Cache };
            let masks = cache_group_masks(cache, size);
            let mut cpus: Vec<usize> = masks.iter().flat_map(affinity_mask_to_cpus).collect();
            cpus.sort_unstable();
            cpus.dedup();
            let shared = cpus.len().max(1);
            let level = CacheLevel {
                size_bytes: cache.CacheSize as usize,
                line_size: cache.LineSize as usize,
                shared_cores: shared,
            };
            match cache.Level {
                1 if matches!(cache.Type, CacheData | CacheUnified) => {
                    if info
                        .l1_data
                        .map(|existing| existing.size_bytes < level.size_bytes)
                        .unwrap_or(true)
                    {
                        info.l1_data = Some(level);
                    }
                }
                1 if cache.Type == CacheInstruction => {
                    if info
                        .l1_instruction
                        .map(|existing| existing.size_bytes < level.size_bytes)
                        .unwrap_or(true)
                    {
                        info.l1_instruction = Some(level);
                    }
                }
                2 if matches!(cache.Type, CacheData | CacheUnified) => {
                    if info
                        .l2
                        .map(|existing| existing.size_bytes < level.size_bytes)
                        .unwrap_or(true)
                    {
                        info.l2 = Some(level);
                    }
                }
                3 if cache.Type == CacheUnified => {
                    if info
                        .l3
                        .map(|existing| existing.size_bytes < level.size_bytes)
                        .unwrap_or(true)
                    {
                        info.l3 = Some(level);
                    }
                    let key = (cache.Level, cache.CacheSize as usize, cpus.clone());
                    l3_map.entry(key).or_insert_with(|| L3Instance {
                        size_bytes: cache.CacheSize as usize,
                        shared_logical_cpus: cpus.clone(),
                    });
                }
                _ => {}
            }
        }
        offset += size.max(1);
    }

    if !l3_map.is_empty() {
        info.l3_instances = l3_map.into_values().collect();
        info.l3_instances
            .iter_mut()
            .for_each(|inst| inst.shared_logical_cpus.sort_unstable());
        info.l3_total_bytes = Some(info.l3_instances.iter().map(|i| i.size_bytes).sum());
    }

    Some(info)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CacheKind {
    Data,
    Instruction,
    Unified,
    Other,
}

#[cfg(target_os = "linux")]
impl CacheKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "data" => Some(CacheKind::Data),
            "instruction" => Some(CacheKind::Instruction),
            "unified" => Some(CacheKind::Unified),
            _ => Some(CacheKind::Other),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct SysfsCacheEntry {
    level: u32,
    kind: CacheKind,
    size_bytes: usize,
    line_size: usize,
    shared_cpu_list: Vec<usize>,
}

#[cfg(target_os = "windows")]
fn cache_group_masks(cache: &CACHE_RELATIONSHIP, record_size: usize) -> Vec<GROUP_AFFINITY> {
    // CACHE_RELATIONSHIP is variable-length; GroupCount tells us how many GROUP_AFFINITY
    // records follow. Clamp to what fits inside the current record to avoid overreads.
    let requested = cache.GroupCount as usize;
    let capacity = ((record_size.saturating_sub(mem::size_of::<CACHE_RELATIONSHIP>()))
        / mem::size_of::<GROUP_AFFINITY>())
    .saturating_add(1)
    .max(1);
    let len = requested.max(1).min(capacity);
    unsafe { slice::from_raw_parts(cache.Anonymous.GroupMasks.as_ptr(), len).to_vec() }
}

#[cfg(target_os = "windows")]
fn affinity_mask_to_cpus(mask: &GROUP_AFFINITY) -> Vec<usize> {
    let mut cpus = Vec::new();
    let mut bits = mask.Mask;
    let mut idx = 0usize;
    while bits != 0 {
        if bits & 1 != 0 {
            let cpu_id = (mask.Group as usize) * 64 + idx;
            cpus.push(cpu_id);
        }
        bits >>= 1;
        idx += 1;
    }
    cpus
}

#[cfg(target_os = "linux")]
fn parse_size_bytes(spec: &str) -> Option<usize> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut split = trimmed.len();
    for (idx, ch) in trimmed.chars().enumerate() {
        if !ch.is_ascii_digit() {
            split = idx;
            break;
        }
    }

    let (digits, suffix) = trimmed.split_at(split);
    let value: usize = digits.parse().ok()?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "k" | "kb" => 1024usize,
        "m" | "mb" => 1024usize * 1024,
        "g" | "gb" => 1024usize * 1024 * 1024,
        "" => 1usize,
        other => {
            if let Some(stripped) = other.strip_prefix('k') {
                if stripped.is_empty() {
                    1024
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    };

    value.checked_mul(multiplier)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_shared_cpu_list(spec: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in spec.trim().split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start, end)) = token.split_once('-') {
            let start: usize = start.parse().ok()?;
            let end: usize = end.parse().ok()?;
            if end < start {
                return None;
            }
            cpus.extend(start..=end);
        } else if let Ok(cpu) = token.parse::<usize>() {
            cpus.push(cpu);
        } else {
            return None;
        }
    }
    if cpus.is_empty() {
        None
    } else {
        cpus.sort_unstable();
        cpus.dedup();
        Some(cpus)
    }
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    let data = std::fs::read_to_string(path).ok()?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn format_bytes(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes)
    }
}

fn format_cpu_list(cpus: &[usize]) -> String {
    if cpus.is_empty() {
        return "".into();
    }
    let mut ranges = Vec::new();
    let mut start = cpus[0];
    let mut prev = cpus[0];

    for &cpu in cpus.iter().skip(1) {
        if cpu == prev + 1 {
            prev = cpu;
            continue;
        }
        if start == prev {
            ranges.push(format!("{}", start));
        } else {
            ranges.push(format!("{}-{}", start, prev));
        }
        start = cpu;
        prev = cpu;
    }

    if start == prev {
        ranges.push(format!("{}", start));
    } else {
        ranges.push(format!("{}-{}", start, prev));
    }

    ranges.join(",")
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
    let l3 = cache.l3_total();
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
        let instance_max = cache.max_l3_instance_size().unwrap_or(l3b);
        let l3_per_thread = if instance_max > 64 * 1024 * 1024 {
            4 * 1024 * 1024
        } else {
            2 * 1024 * 1024
        };
        let cache_threads = if cache.l3_instances.is_empty() {
            (l3b / l3_per_thread).max(1)
        } else {
            cache
                .l3_instances
                .iter()
                .map(|inst| {
                    let capacity = (inst.size_bytes / l3_per_thread).max(1);
                    let cpu_cap = inst.shared_logical_cpus.len().max(1);
                    capacity.min(cpu_cap)
                })
                .sum::<usize>()
                .max(1)
        };
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

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_sysfs_cache_topology_fixture() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sysfs_cpu_cache/ryzen_5950x_like");
        let topo = linux_cache_hierarchy(&fixture).expect("linux sysfs cache");

        assert_eq!(topo.source, CacheSource::LinuxSysfs);
        assert_eq!(topo.l3_instances.len(), 2);
        assert_eq!(topo.l3_total(), Some(64 * 1024 * 1024));

        let sizes: Vec<usize> = topo.l3_instances.iter().map(|i| i.size_bytes).collect();
        assert!(sizes.iter().all(|s| *s == 32 * 1024 * 1024));

        let cpu_sets: Vec<String> = topo
            .l3_instances
            .iter()
            .map(|i| format_cpu_list(&i.shared_logical_cpus))
            .collect();
        assert!(cpu_sets.contains(&"0-7".to_string()));
        assert!(cpu_sets.contains(&"8-15".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_sysfs_cache_when_base_is_cpu_root() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sysfs_cpu_cache/ryzen_5950x_like/cpu");
        let topo = linux_cache_hierarchy(&fixture).expect("linux sysfs cache");
        assert_eq!(topo.l3_instances.len(), 2);
        assert_eq!(topo.l3_total(), Some(64 * 1024 * 1024));
    }

    #[test]
    fn parses_cpu_lists() {
        assert_eq!(
            parse_shared_cpu_list("0-3,8,10-11"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_shared_cpu_list(""), None);
        assert_eq!(parse_shared_cpu_list("4-2"), None);
    }

    #[test]
    fn l3_summary_reports_domains_and_total() {
        let mut topo = CacheHierarchy::default();
        topo.l3_instances = vec![
            L3Instance {
                size_bytes: 32 * 1024 * 1024,
                shared_logical_cpus: (0..16).collect(),
            },
            L3Instance {
                size_bytes: 32 * 1024 * 1024,
                shared_logical_cpus: (16..32).collect(),
            },
        ];
        topo.l3_total_bytes = Some(64 * 1024 * 1024);

        assert_eq!(
            topo.l3_summary().as_deref(),
            Some("2 x 32 MiB (shared per cache domain), 64 MiB total")
        );
    }

    #[test]
    fn synthesizes_l3_instances_for_cpuid_fallback() {
        let instances = synthesize_l3_instances(32 * 1024 * 1024, 16, 32);
        assert_eq!(instances.len(), 2);
        assert_eq!(
            instances[0].shared_logical_cpus,
            (0..16).collect::<Vec<_>>()
        );
        assert_eq!(
            instances[1].shared_logical_cpus,
            (16..32).collect::<Vec<_>>()
        );
        assert!(instances.iter().all(|i| i.size_bytes == 32 * 1024 * 1024));
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
