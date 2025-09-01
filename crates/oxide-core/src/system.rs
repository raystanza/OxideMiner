use sysinfo::{System, SystemExt};

/// Check if operating system has huge pages/large pages available.
/// On Linux this inspects `/proc/meminfo`'s `HugePages_Total` value.
/// On Windows it queries `GetLargePageMinimum`.
pub fn huge_pages_enabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if let Some(rest) = line.strip_prefix("HugePages_Total:") {
                    if let Some(total) = rest.trim().split_whitespace().next() {
                        if let Ok(v) = total.parse::<u64>() {
                            return v > 0;
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Memory::GetLargePageMinimum;
        unsafe { GetLargePageMinimum() > 0 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Determine whether the current CPU supports AES instructions.
/// RandomX benefits from AES for the `FLAG_HARD_AES` option.
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

/// Return the size of the L3 cache in bytes if detectable.
fn l3_cache_bytes() -> Option<usize> {
    use raw_cpuid::CpuId;
    let cpuid = CpuId::new();
    if let Some(cparams) = cpuid.get_cache_parameters() {
        for cache in cparams {
            if cache.level() == 3 && cache.is_unified() {
                let ways = cache.associativity() as usize;
                let line = cache.coherency_line_size() as usize;
                let sets = cache.sets() as usize;
                return Some(ways * line * sets);
            }
        }
    }
    None
}

/// Recommend a worker thread count based on CPU and memory heuristics.
/// Prefers physical cores but also considers L3 cache size (2 MiB per thread)
/// and available memory (roughly 2 GiB dataset + 16 MiB per thread).
pub fn recommended_thread_count() -> usize {
    let physical = num_cpus::get_physical();
    let mut threads = physical.max(1);

    if let Some(l3) = l3_cache_bytes() {
        let cache_threads = (l3 / (2 * 1024 * 1024)).max(1);
        threads = threads.min(cache_threads);
    }

    let mut sys = System::new();
    sys.refresh_memory();
    let avail_bytes = sys.available_memory() * 1024; // sysinfo reports in KiB
    let dataset = 2_u64 * 1024 * 1024 * 1024; // RandomX full dataset
    let scratch_per_thread = 16_u64 * 1024 * 1024; // approx scratchpad
    if avail_bytes > dataset {
        let max_threads_mem = ((avail_bytes - dataset) / scratch_per_thread) as usize;
        if max_threads_mem > 0 {
            threads = threads.min(max_threads_mem);
        } else {
            threads = 1;
        }
    } else {
        threads = 1;
    }

    threads.max(1)
}
