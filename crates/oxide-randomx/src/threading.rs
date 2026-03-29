//! Thread affinity utilities for dataset initialization.

use std::sync::Once;

/// Thread affinity policy for dataset initialization workers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AffinitySpec {
    /// Pack threads onto nearby cores.
    Compact,
    /// Spread threads across available cores.
    Spread,
    /// Explicit list of core indices to cycle through.
    Explicit(Vec<usize>),
}

impl AffinitySpec {
    /// Parse an affinity specification from a string.
    ///
    /// Supported values: `compact`, `spread`, or a comma-separated list of core IDs.
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.eq_ignore_ascii_case("compact") {
            return Ok(Self::Compact);
        }
        if trimmed.eq_ignore_ascii_case("spread") {
            return Ok(Self::Spread);
        }
        let mut cores = Vec::new();
        for part in trimmed.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let value = part
                .parse::<usize>()
                .map_err(|_| format!("invalid core id: {part}"))?;
            cores.push(value);
        }
        if cores.is_empty() {
            return Err("affinity list is empty".to_string());
        }
        Ok(Self::Explicit(cores))
    }

    fn core_for_thread(&self, thread_idx: usize, thread_count: usize) -> Option<usize> {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0);
        if cores == 0 {
            return None;
        }
        Some(match self {
            AffinitySpec::Compact => thread_idx % cores,
            AffinitySpec::Spread => {
                if thread_count == 0 {
                    thread_idx % cores
                } else {
                    ((thread_idx * cores) / thread_count).min(cores.saturating_sub(1))
                }
            }
            AffinitySpec::Explicit(list) => list[thread_idx % list.len()],
        })
    }
}

impl std::fmt::Display for AffinitySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AffinitySpec::Compact => write!(f, "compact"),
            AffinitySpec::Spread => write!(f, "spread"),
            AffinitySpec::Explicit(list) => {
                for (idx, core) in list.iter().enumerate() {
                    if idx > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{core}")?;
                }
                Ok(())
            }
        }
    }
}

/// Apply the affinity policy for a specific thread index.
///
/// This is best-effort; failures are logged once and then ignored.
pub fn apply_affinity(spec: &AffinitySpec, thread_idx: usize, thread_count: usize) {
    let Some(core) = spec.core_for_thread(thread_idx, thread_count) else {
        warn_affinity_once("unable to read available cores");
        return;
    };
    if let Err(err) = set_thread_affinity(core) {
        warn_affinity_once(&err);
    }
}

fn warn_affinity_once(message: &str) {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!("warning: thread affinity requested but unavailable ({message})");
    });
}

#[cfg(target_os = "linux")]
fn set_thread_affinity(core: usize) -> Result<(), String> {
    if core >= CPU_SET_BITS {
        return Err("core id too large for cpu set".to_string());
    }
    let mut set = CpuSet {
        bits: [0u64; CPU_SET_WORDS],
    };
    set.bits[core / 64] |= 1u64 << (core % 64);
    let rc = unsafe { sched_setaffinity(0, core::mem::size_of::<CpuSet>(), &set) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_thread_affinity(core: usize) -> Result<(), String> {
    if core >= (usize::BITS as usize) {
        return Err("core id too large for affinity mask".to_string());
    }
    let mask = 1usize << core;
    let rc = unsafe { SetThreadAffinityMask(GetCurrentThread(), mask) };
    if rc == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn set_thread_affinity(_core: usize) -> Result<(), String> {
    Err("unsupported platform".to_string())
}

#[cfg(target_os = "linux")]
const CPU_SET_WORDS: usize = 16;
#[cfg(target_os = "linux")]
const CPU_SET_BITS: usize = CPU_SET_WORDS * 64;

#[cfg(target_os = "linux")]
#[repr(C)]
struct CpuSet {
    bits: [u64; CPU_SET_WORDS],
}

#[cfg(target_os = "linux")]
extern "C" {
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const CpuSet) -> i32;
}

#[cfg(target_os = "windows")]
extern "system" {
    fn SetThreadAffinityMask(thread: *mut core::ffi::c_void, mask: usize) -> usize;
    fn GetCurrentThread() -> *mut core::ffi::c_void;
}

#[cfg(test)]
mod tests {
    use super::AffinitySpec;

    #[test]
    fn parse_affinity_compact() {
        assert_eq!(
            AffinitySpec::parse("compact").unwrap(),
            AffinitySpec::Compact
        );
    }

    #[test]
    fn parse_affinity_spread() {
        assert_eq!(AffinitySpec::parse("spread").unwrap(), AffinitySpec::Spread);
    }

    #[test]
    fn parse_affinity_list() {
        assert_eq!(
            AffinitySpec::parse("0,2,4").unwrap(),
            AffinitySpec::Explicit(vec![0, 2, 4])
        );
    }

    #[test]
    fn parse_affinity_invalid() {
        assert!(AffinitySpec::parse("invalid").is_err());
    }
}
