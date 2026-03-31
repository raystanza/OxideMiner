//! Runtime flags and CPU auto-tuning.

/// Runtime feature flags that influence hashing behavior.
#[derive(Clone, Debug)]
pub struct RandomXFlags {
    /// Use hardware AES if available (x86_64).
    pub aes_ni: bool,
    /// Force software AES even if hardware AES is available.
    pub soft_aes: bool,
    /// Enable dataset prefetching.
    pub prefetch: bool,
    /// Prefetch distance in cachelines (64 bytes each).
    /// 0 = disabled, 1-8 = cachelines ahead.
    /// Default: 2 (optimal for most modern CPUs)
    pub prefetch_distance: u8,
    /// Auto-tune prefetch distance based on detected CPU.
    /// If true, overrides prefetch_distance with CPU-optimal value.
    pub prefetch_auto_tune: bool,
    /// Prefetch distance for scratchpad accesses in cachelines (64 bytes each).
    /// 0 = disabled. Defaults to 0 (off).
    pub scratchpad_prefetch_distance: u8,
    /// Enable large pages for scratchpad allocations.
    pub large_pages_plumbing: bool,
    /// Request 1GB huge pages for dataset allocation (Linux only).
    ///
    /// Requires kernel configuration: `hugepagesz=1G hugepages=3`
    /// Falls back to 2MB huge pages if 1GB pages are unavailable.
    /// Set `OXIDE_RANDOMX_HUGE_1G=1` to enable via environment.
    pub use_1gb_pages: bool,
    #[cfg(feature = "jit")]
    /// Enable the JIT backend (requires `jit` feature).
    pub jit: bool,
    #[cfg(feature = "jit")]
    /// Enable fast-register JIT variant (requires `jit-fastregs`).
    pub jit_fast_regs: bool,
}

impl Default for RandomXFlags {
    fn default() -> Self {
        Self {
            aes_ni: default_aes_ni(),
            soft_aes: false,
            prefetch: true,
            prefetch_distance: 2,
            prefetch_auto_tune: false,
            scratchpad_prefetch_distance: 0,
            large_pages_plumbing: false,
            use_1gb_pages: false,
            #[cfg(feature = "jit")]
            jit: false,
            #[cfg(feature = "jit")]
            jit_fast_regs: false,
        }
    }
}

impl RandomXFlags {
    /// Create flags from environment variables.
    ///
    /// Supported environment variables:
    /// - `OXIDE_RANDOMX_PREFETCH_DISTANCE`: Set prefetch distance (0-8)
    /// - `OXIDE_RANDOMX_PREFETCH_AUTO`: Enable CPU auto-tuning (any value)
    /// - `OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE`: Set scratchpad prefetch distance (0-32)
    /// - `OXIDE_RANDOMX_HUGE_1G`: Request 1GB huge pages (Linux only)
    pub fn from_env() -> Self {
        let mut flags = Self::default();

        // Prefetch distance: OXIDE_RANDOMX_PREFETCH_DISTANCE=0-8
        if let Ok(val) = std::env::var("OXIDE_RANDOMX_PREFETCH_DISTANCE") {
            if let Ok(dist) = val.parse::<u8>() {
                if dist <= 8 {
                    flags.prefetch_distance = dist;
                    // If distance is 0, also disable prefetch entirely
                    if dist == 0 {
                        flags.prefetch = false;
                    }
                }
            }
        }

        // Auto-tune: OXIDE_RANDOMX_PREFETCH_AUTO=1
        if std::env::var("OXIDE_RANDOMX_PREFETCH_AUTO").is_ok() {
            flags.prefetch_auto_tune = true;
        }

        // Apply auto-tune if enabled
        if flags.prefetch_auto_tune {
            #[cfg(target_arch = "x86_64")]
            {
                let family = cpu_detect::detect_cpu_family();
                flags.prefetch_distance = family.optimal_prefetch_distance();
            }
        }

        // Scratchpad prefetch distance: OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE=0-32
        if let Ok(val) = std::env::var("OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE") {
            if let Ok(dist) = val.parse::<u8>() {
                if dist <= 32 {
                    flags.scratchpad_prefetch_distance = dist;
                }
            }
        }

        // 1GB huge pages: OXIDE_RANDOMX_HUGE_1G=1 (Linux only)
        if std::env::var("OXIDE_RANDOMX_HUGE_1G").is_ok() {
            flags.use_1gb_pages = true;
        }

        flags
    }
}

fn default_aes_ni() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// CPU detection for prefetch auto-tuning.
#[cfg(target_arch = "x86_64")]
pub mod cpu_detect {
    use std::sync::OnceLock;

    /// Detected CPU family for prefetch optimization.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CpuFamily {
        /// Intel 6th-10th gen (Skylake, Kaby Lake, Coffee Lake, etc.)
        IntelSkylake,
        /// Intel Ice Lake (10th gen mobile, 3rd gen Xeon Scalable)
        IntelIceLake,
        /// Intel Alder Lake and newer (12th gen+, hybrid architecture)
        IntelAlderLake,
        /// AMD Zen 2 (Ryzen 3000 series, EPYC Rome)
        AmdZen2,
        /// AMD Zen 3 (Ryzen 5000 series, EPYC Milan)
        AmdZen3,
        /// AMD Zen 4 (Ryzen 7000 series, EPYC Genoa)
        AmdZen4,
        /// Unknown CPU, use conservative defaults
        Unknown,
    }

    impl CpuFamily {
        /// Returns the optimal prefetch distance for this CPU family.
        ///
        /// Values are tuned based on cache hierarchy characteristics:
        /// - Intel aggressive prefetchers: prefer shorter distance (1-2)
        /// - AMD Zen 2/3: prefer longer distance (3)
        /// - AMD Zen 4: improved prefetcher, similar to Intel (2)
        #[must_use]
        pub const fn optimal_prefetch_distance(self) -> u8 {
            match self {
                CpuFamily::IntelSkylake => 2,
                CpuFamily::IntelIceLake => 1, // Aggressive HW prefetcher
                CpuFamily::IntelAlderLake => 2,
                CpuFamily::AmdZen2 => 3,
                CpuFamily::AmdZen3 => 3,
                CpuFamily::AmdZen4 => 2,
                CpuFamily::Unknown => 2,
            }
        }

        /// Returns a human-readable name for this CPU family.
        #[must_use]
        #[allow(dead_code)] // Provided for user diagnostics
        pub const fn name(self) -> &'static str {
            match self {
                CpuFamily::IntelSkylake => "Intel Skylake-era",
                CpuFamily::IntelIceLake => "Intel Ice Lake",
                CpuFamily::IntelAlderLake => "Intel Alder Lake+",
                CpuFamily::AmdZen2 => "AMD Zen 2",
                CpuFamily::AmdZen3 => "AMD Zen 3",
                CpuFamily::AmdZen4 => "AMD Zen 4",
                CpuFamily::Unknown => "Unknown",
            }
        }
    }

    /// Detects the CPU family using CPUID.
    ///
    /// The result is cached after the first call.
    #[must_use]
    pub fn detect_cpu_family() -> CpuFamily {
        static FAMILY: OnceLock<CpuFamily> = OnceLock::new();
        *FAMILY.get_or_init(detect_cpu_family_impl)
    }

    #[cfg(miri)]
    fn detect_cpu_family_impl() -> CpuFamily {
        CpuFamily::Unknown
    }

    #[cfg(not(miri))]
    fn detect_cpu_family_impl() -> CpuFamily {
        // Use CPUID to detect vendor and family/model
        // Note: We use __cpuid intrinsic which handles RBX preservation
        use std::arch::x86_64::__cpuid;

        // SAFETY: This code only compiles on x86_64, where CPUID is a stable
        // userspace instruction. Leaves 0 and 1 only read processor identity.
        let (cpuid0, cpuid1) = unsafe { (__cpuid(0), __cpuid(1)) };

        // Vendor string: EBX, EDX, ECX (in that order)
        let mut vendor_bytes = [0u8; 12];
        vendor_bytes[..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor_bytes[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor_bytes[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());
        let vendor = String::from_utf8_lossy(&vendor_bytes).into_owned();

        let eax = cpuid1.eax;

        // Family = BaseFamily + ExtFamily (if BaseFamily == 15)
        let base_family = (eax >> 8) & 0xF;
        let ext_family = (eax >> 20) & 0xFF;
        let family = if base_family == 15 {
            base_family + ext_family
        } else {
            base_family
        };

        // Model = BaseModel | (ExtModel << 4) (if BaseFamily == 6 or 15)
        let base_model = (eax >> 4) & 0xF;
        let ext_model = (eax >> 16) & 0xF;
        let model = if base_family == 6 || base_family == 15 {
            base_model | (ext_model << 4)
        } else {
            base_model
        };

        if vendor.contains("GenuineIntel") {
            classify_intel(family, model)
        } else if vendor.contains("AuthenticAMD") {
            classify_amd(family, model)
        } else {
            CpuFamily::Unknown
        }
    }

    #[cfg_attr(miri, allow(dead_code))]
    fn classify_intel(family: u32, model: u32) -> CpuFamily {
        // Current Intel desktop/server lineages all fall under family 6.
        if family != 6 {
            return CpuFamily::Unknown;
        }

        match model {
            // Ice Lake client
            0x7D | 0x7E => CpuFamily::IntelIceLake,
            // Ice Lake server
            0x6A | 0x6C => CpuFamily::IntelIceLake,
            // Tiger Lake
            0x8C | 0x8D => CpuFamily::IntelIceLake,
            // Alder Lake
            0x97 | 0x9A => CpuFamily::IntelAlderLake,
            // Raptor Lake
            0xB7 | 0xBA | 0xBF => CpuFamily::IntelAlderLake,
            // Meteor Lake
            0xAA | 0xAC => CpuFamily::IntelAlderLake,
            // Arrow Lake
            0xC5 | 0xC6 => CpuFamily::IntelAlderLake,
            // Skylake and derivatives (most common)
            _ => CpuFamily::IntelSkylake,
        }
    }

    #[cfg_attr(miri, allow(dead_code))]
    fn classify_amd(family: u32, model: u32) -> CpuFamily {
        match family {
            // Zen, Zen+ (Family 17h / 0x17)
            0x17 => {
                // Zen 2 starts at model 0x31
                if model >= 0x31 {
                    CpuFamily::AmdZen2
                } else {
                    // Zen / Zen+ - treat as Zen2 for prefetch purposes
                    CpuFamily::AmdZen2
                }
            }
            // Zen 3, Zen 4 (Family 19h / 0x19)
            0x19 => {
                // Zen 4 models start around 0x60
                if model >= 0x60 {
                    CpuFamily::AmdZen4
                } else {
                    CpuFamily::AmdZen3
                }
            }
            // Zen 4+ (Family 1Ah / 0x1A)
            0x1A => CpuFamily::AmdZen4,
            _ => CpuFamily::Unknown,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cpu_family_optimal_prefetch_values() {
            // Verify all CPU families have valid prefetch distances (1-8)
            let families = [
                CpuFamily::IntelSkylake,
                CpuFamily::IntelIceLake,
                CpuFamily::IntelAlderLake,
                CpuFamily::AmdZen2,
                CpuFamily::AmdZen3,
                CpuFamily::AmdZen4,
                CpuFamily::Unknown,
            ];

            for family in families {
                let dist = family.optimal_prefetch_distance();
                assert!(
                    (1..=8).contains(&dist),
                    "{:?} has invalid prefetch distance {}",
                    family,
                    dist
                );
            }
        }

        #[test]
        fn detect_cpu_family_succeeds() {
            // Just verify detection doesn't panic
            let family = detect_cpu_family();
            println!("Detected CPU: {:?} ({})", family, family.name());
            println!(
                "Optimal prefetch distance: {}",
                family.optimal_prefetch_distance()
            );
        }

        #[test]
        fn classify_intel_known_models() {
            // Ice Lake
            assert_eq!(classify_intel(6, 0x7D), CpuFamily::IntelIceLake);
            assert_eq!(classify_intel(6, 0x7E), CpuFamily::IntelIceLake);
            // Tiger Lake
            assert_eq!(classify_intel(6, 0x8C), CpuFamily::IntelIceLake);
            // Alder Lake
            assert_eq!(classify_intel(6, 0x97), CpuFamily::IntelAlderLake);
            assert_eq!(classify_intel(6, 0x9A), CpuFamily::IntelAlderLake);
            // Raptor Lake
            assert_eq!(classify_intel(6, 0xB7), CpuFamily::IntelAlderLake);
            // Unknown model defaults to Skylake
            assert_eq!(classify_intel(6, 0x55), CpuFamily::IntelSkylake);
            // Non-family-6 is unknown
            assert_eq!(classify_intel(5, 0), CpuFamily::Unknown);
        }

        #[test]
        fn classify_amd_known_families() {
            // Zen 2
            assert_eq!(classify_amd(0x17, 0x31), CpuFamily::AmdZen2);
            assert_eq!(classify_amd(0x17, 0x71), CpuFamily::AmdZen2);
            // Zen / Zen+ treated as Zen2
            assert_eq!(classify_amd(0x17, 0x01), CpuFamily::AmdZen2);
            // Zen 3
            assert_eq!(classify_amd(0x19, 0x21), CpuFamily::AmdZen3);
            assert_eq!(classify_amd(0x19, 0x50), CpuFamily::AmdZen3);
            // Zen 4
            assert_eq!(classify_amd(0x19, 0x60), CpuFamily::AmdZen4);
            assert_eq!(classify_amd(0x19, 0x70), CpuFamily::AmdZen4);
            assert_eq!(classify_amd(0x1A, 0x00), CpuFamily::AmdZen4);
            // Unknown family
            assert_eq!(classify_amd(0x15, 0), CpuFamily::Unknown);
        }
    }
}
