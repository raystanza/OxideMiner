//! RandomX virtual machine implementation.

use crate::blake::{hash256, hash512};
use crate::cache::RandomXCache;
use crate::config::{InstructionFrequencies, RandomXConfig};
use crate::dataset::{compute_item_words, DatasetInitOptions, RandomXDataset};
use crate::errors::{RandomXError, Result};
use crate::flags::RandomXFlags;
use crate::generators::{aes_hash_1r, AesGenerator1R, AesGenerator4R};
use crate::perf::PerfStats;
use crate::util::{AlignedBuf, LargePageRequest};
use core::ptr;
#[cfg(feature = "bench-instrument")]
use std::time::Instant;
use std::{ops::Deref, sync::Arc};

#[cfg(feature = "jit")]
pub(crate) mod jit;

// SIMD block I/O module for AVX2-accelerated scratchpad/XOR operations
#[cfg(all(
    any(feature = "simd-blockio", feature = "simd-xor-paths"),
    target_arch = "x86_64"
))]
mod simd_block_io {
    use core::sync::atomic::{AtomicU8, Ordering};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    // 0 = unchecked, 1 = not supported, 2 = supported
    static AVX2_SUPPORT: AtomicU8 = AtomicU8::new(0);

    /// Check if AVX2 is available at runtime (cached after first check)
    #[inline]
    pub fn has_avx2() -> bool {
        match AVX2_SUPPORT.load(Ordering::Relaxed) {
            2 => true,
            1 => false,
            _ => {
                let supported = is_x86_feature_detected!("avx2");
                AVX2_SUPPORT.store(if supported { 2 } else { 1 }, Ordering::Relaxed);
                supported
            }
        }
    }

    /// Load 64 bytes (8 u64s) from memory using AVX2.
    /// On x86_64 little-endian, no byte swap is needed.
    ///
    /// # Safety
    /// - Caller must ensure ptr points to at least 64 readable bytes
    /// - Caller must verify AVX2 is available before calling
    #[cfg(feature = "simd-blockio")]
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn load_block_64(ptr: *const u8) -> [u64; 8] {
        unsafe {
            let aligned = (ptr as usize) & 31 == 0;
            // Load two 256-bit (32-byte) chunks
            let lo = if aligned {
                _mm256_load_si256(ptr as *const __m256i)
            } else {
                _mm256_loadu_si256(ptr as *const __m256i)
            };
            let hi = if aligned {
                _mm256_load_si256(ptr.add(32) as *const __m256i)
            } else {
                _mm256_loadu_si256(ptr.add(32) as *const __m256i)
            };

            // Extract to array - on little-endian x86_64, bytes are in correct order
            let mut result = [0u64; 8];
            _mm256_storeu_si256(result.as_mut_ptr() as *mut __m256i, lo);
            _mm256_storeu_si256(result.as_mut_ptr().add(4) as *mut __m256i, hi);
            result
        }
    }

    /// Store 64 bytes (8 u64s) to memory using AVX2.
    ///
    /// # Safety
    /// - Caller must ensure ptr points to at least 64 writable bytes
    /// - Caller must verify AVX2 is available before calling
    #[cfg(feature = "simd-blockio")]
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn store_block_64(ptr: *mut u8, data: &[u64; 8]) {
        unsafe {
            let lo = _mm256_loadu_si256(data.as_ptr() as *const __m256i);
            let hi = _mm256_loadu_si256(data.as_ptr().add(4) as *const __m256i);
            let aligned = (ptr as usize) & 31 == 0;
            if aligned {
                _mm256_store_si256(ptr as *mut __m256i, lo);
                _mm256_store_si256(ptr.add(32) as *mut __m256i, hi);
            } else {
                _mm256_storeu_si256(ptr as *mut __m256i, lo);
                _mm256_storeu_si256(ptr.add(32) as *mut __m256i, hi);
            }
        }
    }

    /// XOR a 64-byte block from memory into the destination array using AVX2.
    ///
    /// # Safety
    /// - Caller must ensure src_ptr points to at least 64 readable bytes
    /// - Caller must verify AVX2 is available before calling
    #[cfg(feature = "simd-blockio")]
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor_block_from_mem(dst: &mut [u64; 8], src_ptr: *const u8) {
        unsafe {
            let aligned = (src_ptr as usize) & 31 == 0;
            // Load source block
            let src_lo = if aligned {
                _mm256_load_si256(src_ptr as *const __m256i)
            } else {
                _mm256_loadu_si256(src_ptr as *const __m256i)
            };
            let src_hi = if aligned {
                _mm256_load_si256(src_ptr.add(32) as *const __m256i)
            } else {
                _mm256_loadu_si256(src_ptr.add(32) as *const __m256i)
            };

            // Load destination
            let dst_lo = _mm256_loadu_si256(dst.as_ptr() as *const __m256i);
            let dst_hi = _mm256_loadu_si256(dst.as_ptr().add(4) as *const __m256i);

            // XOR
            let result_lo = _mm256_xor_si256(dst_lo, src_lo);
            let result_hi = _mm256_xor_si256(dst_hi, src_hi);

            // Store back
            _mm256_storeu_si256(dst.as_mut_ptr() as *mut __m256i, result_lo);
            _mm256_storeu_si256(dst.as_mut_ptr().add(4) as *mut __m256i, result_hi);
        }
    }

    /// XOR eight u64 values from `src_ptr` into `dst_ptr` using AVX2.
    ///
    /// # Safety
    /// - Caller must ensure both pointers reference at least 64 bytes.
    /// - Caller must verify AVX2 is available before calling.
    #[cfg(feature = "simd-xor-paths")]
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor_u64x8_in_place_ptr(dst_ptr: *mut u64, src_ptr: *const u64) {
        unsafe {
            let dst_lo = _mm256_loadu_si256(dst_ptr as *const __m256i);
            let dst_hi = _mm256_loadu_si256(dst_ptr.add(4) as *const __m256i);
            let src_lo = _mm256_loadu_si256(src_ptr as *const __m256i);
            let src_hi = _mm256_loadu_si256(src_ptr.add(4) as *const __m256i);
            let out_lo = _mm256_xor_si256(dst_lo, src_lo);
            let out_hi = _mm256_xor_si256(dst_hi, src_hi);
            _mm256_storeu_si256(dst_ptr as *mut __m256i, out_lo);
            _mm256_storeu_si256(dst_ptr.add(4) as *mut __m256i, out_hi);
        }
    }

    /// Clear upper YMM state to avoid AVX->SSE transition penalties.
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn vzeroupper() {
        _mm256_zeroupper();
    }
}

#[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
const SIMD_BLOCKIO_FORCE_ENV: &str = "OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE";
#[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
const SIMD_BLOCKIO_DISABLE_ENV: &str = "OXIDE_RANDOMX_SIMD_BLOCKIO_DISABLE";
#[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
const SIMD_XOR_FORCE_ENV: &str = "OXIDE_RANDOMX_SIMD_XOR_PATHS_FORCE";
#[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
const SIMD_XOR_DISABLE_ENV: &str = "OXIDE_RANDOMX_SIMD_XOR_PATHS_DISABLE";
#[cfg(feature = "threaded-interp")]
const THREADED_INTERP_ENV: &str = "OXIDE_RANDOMX_THREADED_INTERP";

#[cfg(any(
    feature = "threaded-interp",
    all(feature = "simd-blockio", target_arch = "x86_64"),
    all(feature = "simd-xor-paths", target_arch = "x86_64")
))]
fn env_var_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
#[inline]
fn simd_blockio_is_blocked_cpu(vendor: &[u8], family: u32, model: u32) -> bool {
    // Runtime mitigation: measured Intel Family 6 Model 45 (Sandy Bridge-EP)
    // shows reproducible fast-mode regression with simd-blockio.
    vendor == b"GenuineIntel" && family == 6 && model == 45
}

#[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
fn simd_blockio_runtime_enabled() -> bool {
    // Escape hatch for scalar baseline capture in single-binary evidence tools.
    if std::env::var_os(SIMD_BLOCKIO_DISABLE_ENV).is_some() {
        return false;
    }

    if !simd_block_io::has_avx2() {
        return false;
    }

    // Escape hatch for local experiments.
    if std::env::var_os(SIMD_BLOCKIO_FORCE_ENV).is_some() {
        return true;
    }

    #[cfg(not(miri))]
    {
        use std::arch::x86_64::__cpuid;

        // CPUID(0): vendor string in EBX, EDX, ECX order.
        let cpuid0 = __cpuid(0);
        let mut vendor = [0u8; 12];
        vendor[..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

        // CPUID(1): decode family/model.
        let cpuid1 = __cpuid(1);
        let eax = cpuid1.eax;
        let base_family = (eax >> 8) & 0xF;
        let ext_family = (eax >> 20) & 0xFF;
        let family = if base_family == 15 {
            base_family + ext_family
        } else {
            base_family
        };
        let base_model = (eax >> 4) & 0xF;
        let ext_model = (eax >> 16) & 0xF;
        let model = if base_family == 6 || base_family == 15 {
            base_model | (ext_model << 4)
        } else {
            base_model
        };

        return !simd_blockio_is_blocked_cpu(&vendor, family, model);
    }

    #[cfg(miri)]
    {
        true
    }
}

#[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
fn simd_xor_runtime_enabled() -> bool {
    if env_var_truthy(SIMD_XOR_DISABLE_ENV) {
        return false;
    }

    if !simd_block_io::has_avx2() {
        return false;
    }

    if env_var_truthy(SIMD_XOR_FORCE_ENV) {
        return true;
    }

    true
}

#[cfg(feature = "threaded-interp")]
fn threaded_interp_runtime_enabled() -> bool {
    env_var_truthy(THREADED_INTERP_ENV)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FpReg {
    lo: f64,
    hi: f64,
}

impl FpReg {
    fn from_u64_pair(raw: u64) -> Self {
        let lo = raw as u32 as i32 as f64;
        let hi = (raw >> 32) as u32 as i32 as f64;
        Self { lo, hi }
    }

    fn from_u64_pair_e(raw: u64, mask_low: &EMask, mask_high: &EMask) -> Self {
        let base = Self::from_u64_pair(raw);
        let lo = apply_e_mask(base.lo, mask_low);
        let hi = apply_e_mask(base.hi, mask_high);
        Self { lo, hi }
    }

    #[cfg(all(test, feature = "jit"))]
    fn from_i32_pair(raw: &[u8; 8]) -> Self {
        Self::from_u64_pair(u64::from_le_bytes(*raw))
    }

    #[cfg(all(test, feature = "jit"))]
    fn from_i32_pair_e(raw: &[u8; 8], mask_low: &EMask, mask_high: &EMask) -> Self {
        Self::from_u64_pair_e(u64::from_le_bytes(*raw), mask_low, mask_high)
    }

    fn xor_inplace(&mut self, other: FpReg) {
        let lo = self.lo.to_bits() ^ other.lo.to_bits();
        let hi = self.hi.to_bits() ^ other.hi.to_bits();
        self.lo = f64::from_bits(lo);
        self.hi = f64::from_bits(hi);
    }

    fn fscal(&mut self) {
        self.lo = f64::from_bits(self.lo.to_bits() ^ 0x80F0_0000_0000_0000);
        self.hi = f64::from_bits(self.hi.to_bits() ^ 0x80F0_0000_0000_0000);
    }

    fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.lo.to_bits().to_le_bytes());
        out[8..].copy_from_slice(&self.hi.to_bits().to_le_bytes());
        out
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct EMask {
    fraction: u32,
    exponent: u8,
}

fn apply_e_mask(value: f64, mask: &EMask) -> f64 {
    let mut bits = value.to_bits();
    bits &= !(1u64 << 63);
    let exponent = (bits >> 52) & 0x7ff;
    let upper = exponent & !0x7f;
    let new_exp = upper | 0b011 | ((mask.exponent as u64) << 3);
    bits = (bits & !(0x7ffu64 << 52)) | (new_exp << 52);
    let frac_mask = (1u64 << 22) - 1;
    let frac = bits & ((1u64 << 52) - 1);
    let new_frac = (frac & !frac_mask) | (mask.fraction as u64 & frac_mask);
    bits = (bits & !((1u64 << 52) - 1)) | new_frac;
    f64::from_bits(bits)
}

#[derive(Clone, Copy, Debug)]
struct ScratchpadMasks {
    #[cfg(feature = "jit")]
    l1_8: u64,
    #[cfg(feature = "jit")]
    l2_8: u64,
    #[cfg(feature = "jit")]
    l3_8: u64,
    l3_64: u64,
    levels_8: [u64; 3],
    fp_read_8: [u64; 2],
}

#[cfg(feature = "jit")]
#[repr(C)]
struct VmJitContext {
    r: *mut u64,
    f: *mut FpReg,
    e: *mut FpReg,
    a: *const FpReg,
    scratchpad: *mut u8,
    vm_ptr: *mut RandomXVm,
    mask_l1: u64,
    mask_l2: u64,
    mask_l3: u64,
    e_mask_low: EMask,
    e_mask_high: EMask,
    fprc: u32,
    saved_mxcsr: u32,
    jump_bits: u32,
    jump_offset: u32,
    last_modified: [i32; 8],
    ip: u32,
    program_len: u32,
    program_iters: u32,
    sp_addr0: u32,
    sp_addr1: u32,
    mx_ptr: *mut u32,
    ma_ptr: *mut u32,
    dataset_ptr: *const u8,
    dataset_items: u64,
    dataset_base: u64,
    dataset_offset: u64,
    prefetch: u32,
    prefetch_scratchpad: u32,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_spill_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_reload_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_sync_to_ctx_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_sync_from_ctx_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_call_boundary_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_call_boundary_float_nomem: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_call_boundary_float_mem: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_call_boundary_prepare_finish: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_preserve_spill_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_preserve_reload_count: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_prepare_ns: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_finish_ns: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_light_cache_item_helper_calls: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_light_cache_item_helper_ns: u64,
    #[cfg(feature = "bench-instrument")]
    jit_fastregs_stage_start_ns: u64,
}

#[cfg(feature = "jit")]
impl VmJitContext {
    fn new(vm: &mut RandomXVm) -> Self {
        let (dataset_ptr, dataset_items) = if let Some(dataset) = &vm.dataset {
            let items = dataset.item_count();
            let ptr = if items > 0 {
                dataset.item_bytes(0).as_ptr()
            } else {
                ptr::null()
            };
            (ptr, items as u64)
        } else {
            (ptr::null(), 0)
        };
        Self {
            r: vm.r.as_mut_ptr(),
            f: vm.f.as_mut_ptr(),
            e: vm.e.as_mut_ptr(),
            a: vm.a.as_ptr(),
            scratchpad: vm.scratchpad.as_mut_slice().as_mut_ptr(),
            vm_ptr: vm as *mut RandomXVm,
            mask_l1: vm.masks.l1_8,
            mask_l2: vm.masks.l2_8,
            mask_l3: vm.masks.l3_8,
            e_mask_low: vm.e_mask_low,
            e_mask_high: vm.e_mask_high,
            fprc: vm.fprc,
            saved_mxcsr: 0,
            jump_bits: vm.cfg.jump_bits(),
            jump_offset: vm.cfg.jump_offset(),
            last_modified: [-1; 8],
            ip: 0,
            program_len: vm.program.len() as u32,
            program_iters: 0,
            sp_addr0: vm.mx,
            sp_addr1: vm.ma,
            mx_ptr: &mut vm.mx,
            ma_ptr: &mut vm.ma,
            dataset_ptr,
            dataset_items,
            dataset_base: vm.cfg.dataset_base_size(),
            dataset_offset: vm.dataset_offset,
            // Store prefetch_distance directly: 0 = disabled, 1-8 = cachelines ahead
            prefetch: if vm.flags.prefetch {
                vm.flags.prefetch_distance.max(1) as u32
            } else {
                0
            },
            prefetch_scratchpad: vm.flags.scratchpad_prefetch_distance.saturating_mul(64) as u32,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_spill_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_reload_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_sync_to_ctx_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_sync_from_ctx_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_call_boundary_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_call_boundary_float_nomem: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_call_boundary_float_mem: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_call_boundary_prepare_finish: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_preserve_spill_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_preserve_reload_count: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_prepare_ns: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_finish_ns: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_light_cache_item_helper_calls: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_light_cache_item_helper_ns: 0,
            #[cfg(feature = "bench-instrument")]
            jit_fastregs_stage_start_ns: 0,
        }
    }
}

impl ScratchpadMasks {
    fn new(cfg: &RandomXConfig) -> Self {
        let l1 = cfg.scratchpad_l1() as u64;
        let l2 = cfg.scratchpad_l2() as u64;
        let l3 = cfg.scratchpad_l3() as u64;
        let l1_8 = (l1 - 1) & !7;
        let l2_8 = (l2 - 1) & !7;
        let l3_8 = (l3 - 1) & !7;
        Self {
            #[cfg(feature = "jit")]
            l1_8,
            #[cfg(feature = "jit")]
            l2_8,
            #[cfg(feature = "jit")]
            l3_8,
            l3_64: (l3 - 1) & !63,
            levels_8: [l1_8, l2_8, l3_8],
            fp_read_8: [l2_8, l1_8],
        }
    }
}

enum CacheBacking {
    Owned(RandomXCache),
    Shared(Arc<RandomXCache>),
}

impl Deref for CacheBacking {
    type Target = RandomXCache;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(cache) => cache,
            Self::Shared(cache) => cache,
        }
    }
}

enum DatasetBacking {
    Owned(RandomXDataset),
    Shared(Arc<RandomXDataset>),
}

impl Deref for DatasetBacking {
    type Target = RandomXDataset;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(dataset) => dataset,
            Self::Shared(dataset) => dataset,
        }
    }
}

/// RandomX virtual machine instance.
///
/// A VM can run in light mode (cache only) or fast mode (cache + dataset).
pub struct RandomXVm {
    cfg: RandomXConfig,
    flags: RandomXFlags,
    cache: CacheBacking,
    dataset: Option<DatasetBacking>,
    dataset_options: DatasetInitOptions,
    scratchpad: AlignedBuf,
    masks: ScratchpadMasks,
    opcode_table: [InstructionKind; 256],
    program: Vec<Instruction>,
    program_bytes: Vec<u8>,
    r: [u64; 8],
    f: [FpReg; 4],
    e: [FpReg; 4],
    a: [FpReg; 4],
    ma: u32,
    mx: u32,
    fprc: u32,
    read_regs: [usize; 4],
    dataset_offset: u64,
    e_mask_low: EMask,
    e_mask_high: EMask,
    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    simd_blockio_avx2: bool,
    #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
    simd_xor_avx2: bool,
    #[cfg(feature = "threaded-interp")]
    threaded_interp_active: bool,
    #[cfg(feature = "jit")]
    jit_engine: jit::JitEngine,
    #[cfg(feature = "jit")]
    jit_active: bool,
    #[cfg(feature = "bench-instrument")]
    perf: PerfStats,
}

impl RandomXVm {
    const USE_BLOCK_SCRATCHPAD_IO: bool = true; // Flip to false for quick A/B comparisons.

    fn new_with_backing(
        cache: CacheBacking,
        dataset: Option<DatasetBacking>,
        dataset_options: DatasetInitOptions,
        cfg: RandomXConfig,
        flags: RandomXFlags,
    ) -> Result<Self> {
        cfg.validate()?;
        if !cfg!(target_arch = "x86_64") {
            return Err(RandomXError::Unsupported(
                "floating point rounding control requires x86_64",
            ));
        }
        let scratchpad_request = if flags.large_pages_plumbing {
            LargePageRequest::enabled("scratchpad")
        } else {
            LargePageRequest::disabled()
        };
        let scratchpad =
            AlignedBuf::new_with_large_pages(cfg.scratchpad_l3(), 64, scratchpad_request)?;
        let masks = ScratchpadMasks::new(&cfg);
        let opcode_table = build_opcode_table(cfg.instruction_frequencies());
        #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
        let simd_blockio_avx2 = simd_blockio_runtime_enabled();
        #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
        let simd_xor_avx2 = simd_xor_runtime_enabled();
        #[cfg(feature = "threaded-interp")]
        let threaded_interp_active = threaded_interp_runtime_enabled();
        #[cfg(feature = "jit")]
        let jit_engine = jit::JitEngine::new();
        #[cfg(feature = "jit")]
        let jit_active = flags.jit && jit_engine.is_supported();
        Ok(Self {
            cfg,
            flags,
            cache,
            dataset,
            dataset_options,
            scratchpad,
            masks,
            opcode_table,
            program: Vec::new(),
            program_bytes: Vec::new(),
            r: [0u64; 8],
            f: [FpReg::default(); 4],
            e: [FpReg::default(); 4],
            a: [FpReg::default(); 4],
            ma: 0,
            mx: 0,
            fprc: 0,
            read_regs: [0, 2, 4, 6],
            dataset_offset: 0,
            e_mask_low: EMask {
                fraction: 0,
                exponent: 0,
            },
            e_mask_high: EMask {
                fraction: 0,
                exponent: 0,
            },
            #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
            simd_blockio_avx2,
            #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
            simd_xor_avx2,
            #[cfg(feature = "threaded-interp")]
            threaded_interp_active,
            #[cfg(feature = "jit")]
            jit_engine,
            #[cfg(feature = "jit")]
            jit_active,
            #[cfg(feature = "bench-instrument")]
            perf: PerfStats::default(),
        })
    }

    /// Create a light-mode VM backed by a cache.
    pub fn new_light(cache: RandomXCache, cfg: RandomXConfig, flags: RandomXFlags) -> Result<Self> {
        Self::new_with_backing(
            CacheBacking::Owned(cache),
            None,
            DatasetInitOptions::new(1),
            cfg,
            flags,
        )
    }

    /// Create a fast-mode VM backed by a precomputed dataset.
    pub fn new_fast(
        cache: RandomXCache,
        dataset: RandomXDataset,
        cfg: RandomXConfig,
        flags: RandomXFlags,
    ) -> Result<Self> {
        let dataset_options = dataset.options().clone();
        Self::new_with_backing(
            CacheBacking::Owned(cache),
            Some(DatasetBacking::Owned(dataset)),
            dataset_options,
            cfg,
            flags,
        )
    }

    /// Create a fast-mode VM backed by shared cache and dataset handles.
    ///
    /// This is the parent-oriented Fast-mode constructor for multi-worker hosts:
    /// build the cache and dataset once, wrap them in `Arc`, and create one VM
    /// per worker without copying the dataset backing.
    pub fn new_fast_shared(
        cache: Arc<RandomXCache>,
        dataset: Arc<RandomXDataset>,
        cfg: RandomXConfig,
        flags: RandomXFlags,
    ) -> Result<Self> {
        let dataset_options = dataset.options().clone();
        Self::new_with_backing(
            CacheBacking::Shared(cache),
            Some(DatasetBacking::Shared(dataset)),
            dataset_options,
            cfg,
            flags,
        )
    }

    /// Returns true if the JIT backend is active for this VM.
    pub fn is_jit_active(&self) -> bool {
        #[cfg(feature = "jit")]
        {
            self.jit_active
        }
        #[cfg(not(feature = "jit"))]
        {
            false
        }
    }

    #[cfg(feature = "jit")]
    /// Returns JIT cache statistics.
    pub fn jit_stats(&self) -> crate::jit::JitStats {
        self.jit_engine.stats()
    }

    /// Returns a snapshot of performance counters.
    pub fn perf_stats(&self) -> PerfStats {
        #[cfg(feature = "bench-instrument")]
        {
            self.perf
        }
        #[cfg(not(feature = "bench-instrument"))]
        {
            PerfStats::default()
        }
    }

    /// Reset performance counters to zero.
    pub fn reset_perf_stats(&mut self) {
        #[cfg(feature = "bench-instrument")]
        {
            self.perf.reset();
        }
    }

    /// Hash an input using the RandomX VM.
    pub fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        #[cfg(feature = "bench-instrument")]
        {
            self.perf.hashes = self.perf.hashes.saturating_add(1);
        }
        let seed = hash512(input);
        let mut gen1 = AesGenerator1R::new(seed);
        fill_scratchpad(self.scratchpad.as_mut_slice(), &mut gen1, &self.flags);
        let mut gen4 = AesGenerator4R::new(gen1.state());
        self.fprc = 0;

        let program_count = self.cfg.program_count() as usize;
        for i in 0..program_count {
            self.program_vm(&mut gen4);
            self.execute_vm();
            if i + 1 < program_count {
                let reg_file = self.register_file();
                let new_seed = hash512(&reg_file);
                gen4.set_state(new_seed);
            }
        }

        let fingerprint = aes_hash_1r(self.scratchpad.as_slice(), &self.flags);
        let mut reg_file = self.register_file();
        reg_file[192..256].copy_from_slice(&fingerprint);
        hash256(&reg_file)
    }

    /// Rekey the VM in-place using a new cache key.
    ///
    /// Light mode rebuilds the cache. Fast mode rebuilds both the cache and
    /// the dataset using the original `DatasetInitOptions`.
    pub fn rekey(&mut self, new_key: &[u8]) -> Result<()> {
        let new_cache = RandomXCache::new(new_key, &self.cfg)?;
        let new_dataset = if self.dataset.is_some() {
            let options = self.dataset_options.clone();
            Some(DatasetBacking::Owned(RandomXDataset::new_with_options(
                &new_cache, &self.cfg, options,
            )?))
        } else {
            None
        };
        self.cache = CacheBacking::Owned(new_cache);
        self.dataset = new_dataset;
        Ok(())
    }

    /// Returns true if the scratchpad uses large pages.
    pub fn scratchpad_uses_large_pages(&self) -> bool {
        self.scratchpad.uses_large_pages()
    }

    /// Returns the scratchpad huge page size in bytes, if any.
    pub fn scratchpad_huge_page_size(&self) -> Option<usize> {
        self.scratchpad.huge_page_size()
    }

    fn program_vm(&mut self, gen4: &mut AesGenerator4R) {
        #[cfg(feature = "bench-instrument")]
        let start = Instant::now();

        let program_len = self.cfg.program_size() as usize;
        let byte_len = 128 + program_len * 8;
        if self.program_bytes.len() != byte_len {
            self.program_bytes.resize(byte_len, 0);
        }
        generate_bytes(&mut self.program_bytes, gen4, &self.flags);

        // docs/randomx-refs/specs.md §4.5
        let config_words = Self::decode_config_words(&self.program_bytes[..128]);

        for reg in 0..4 {
            let low = config_words[reg * 2];
            let high = config_words[reg * 2 + 1];
            self.a[reg] = FpReg {
                lo: a_register_value(low),
                hi: a_register_value(high),
            };
        }

        self.ma = config_words[8] as u32;
        self.mx = config_words[10] as u32;

        let selector = config_words[12] as u8;
        self.read_regs = [
            if selector & 0x1 == 0 { 0 } else { 1 },
            if selector & 0x2 == 0 { 2 } else { 3 },
            if selector & 0x4 == 0 { 4 } else { 5 },
            if selector & 0x8 == 0 { 6 } else { 7 },
        ];

        let extra = self.cfg.dataset_extra_size();
        let modulo = extra / 64 + 1;
        self.dataset_offset = (config_words[13] % modulo) * 64;

        let low_mask = config_words[14];
        let high_mask = config_words[15];
        self.e_mask_low = EMask {
            fraction: (low_mask & ((1u64 << 22) - 1)) as u32,
            exponent: ((low_mask >> 60) & 0x0f) as u8,
        };
        self.e_mask_high = EMask {
            fraction: (high_mask & ((1u64 << 22) - 1)) as u32,
            exponent: ((high_mask >> 60) & 0x0f) as u8,
        };

        self.program.clear();
        if self.program.capacity() < program_len {
            self.program.reserve(program_len - self.program.capacity());
        }
        Self::decode_instructions(
            &self.program_bytes[128..],
            &self.opcode_table,
            &mut self.program,
        );

        #[cfg(feature = "bench-instrument")]
        {
            let elapsed = start.elapsed().as_nanos() as u64;
            self.perf.program_gen_ns = self.perf.program_gen_ns.saturating_add(elapsed);
        }
    }

    /// Decode 16 config words from 128 bytes.
    /// Uses chunks_exact with fast-decode feature (default), or byte-copy fallback.
    #[inline]
    fn decode_config_words(bytes: &[u8]) -> [u64; 16] {
        debug_assert!(bytes.len() >= 128);
        let mut config_words = [0u64; 16];

        #[cfg(feature = "fast-decode")]
        {
            for (word, chunk) in config_words.iter_mut().zip(bytes[..128].chunks_exact(8)) {
                let chunk: &[u8; 8] = chunk.try_into().expect("config word chunk");
                *word = u64::from_le_bytes(*chunk);
            }
        }

        #[cfg(not(feature = "fast-decode"))]
        {
            for (i, word) in config_words.iter_mut().enumerate() {
                let offset = i * 8;
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[offset..offset + 8]);
                *word = u64::from_le_bytes(buf);
            }
        }

        config_words
    }

    /// Decode instructions from program bytes into the instruction vector.
    /// Uses chunks_exact with fast-decode feature (default), or byte-copy fallback.
    #[inline]
    fn decode_instructions(
        bytes: &[u8],
        opcode_table: &[InstructionKind; 256],
        program: &mut Vec<Instruction>,
    ) {
        #[cfg(feature = "fast-decode")]
        {
            for chunk in bytes.chunks_exact(8) {
                let chunk: &[u8; 8] = chunk.try_into().expect("instruction chunk");
                let word = u64::from_le_bytes(*chunk);
                program.push(Instruction::decode(word, opcode_table));
            }
        }

        #[cfg(not(feature = "fast-decode"))]
        {
            let mut offset = 0;
            let count = bytes.len() / 8;
            for _ in 0..count {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[offset..offset + 8]);
                let word = u64::from_le_bytes(buf);
                program.push(Instruction::decode(word, opcode_table));
                offset += 8;
            }
        }
    }

    fn prepare_iteration(&mut self, sp_addr0: &mut u32, sp_addr1: &mut u32) {
        #[cfg(feature = "bench-instrument")]
        let start = Instant::now();
        let xor = self.r[self.read_regs[0]] ^ self.r[self.read_regs[1]];
        *sp_addr0 ^= xor as u32;
        *sp_addr1 ^= (xor >> 32) as u32;

        let sp0_idx = (*sp_addr0 as u64 & self.masks.l3_64) as usize;
        let sp1_idx = (*sp_addr1 as u64 & self.masks.l3_64) as usize;
        let scratchpad = self.scratchpad.as_slice();
        // Safety: mask-derived indices keep the reads within the scratchpad buffer.
        unsafe {
            let sp0_ptr = scratchpad.as_ptr().add(sp0_idx);
            let sp1_ptr = scratchpad.as_ptr().add(sp1_idx);

            #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
            if self.simd_blockio_avx2 {
                self.prepare_iteration_simd(sp0_ptr, sp1_ptr);
            } else {
                self.prepare_iteration_scalar(sp0_ptr, sp1_ptr);
            }

            #[cfg(not(all(feature = "simd-blockio", target_arch = "x86_64")))]
            self.prepare_iteration_scalar(sp0_ptr, sp1_ptr);
        }
        #[cfg(feature = "bench-instrument")]
        {
            let elapsed = start.elapsed().as_nanos() as u64;
            self.perf.prepare_iteration_ns = self.perf.prepare_iteration_ns.saturating_add(elapsed);
            self.perf.scratchpad_read_bytes = self.perf.scratchpad_read_bytes.saturating_add(128);
        }
    }

    #[inline(always)]
    unsafe fn xor_regs_from_block_scalar(&mut self, ptr: *const u8) {
        if Self::USE_BLOCK_SCRATCHPAD_IO {
            // Safety: caller guarantees 64 readable bytes.
            let words = unsafe { ptr::read_unaligned(ptr as *const [u64; 8]) };
            self.r[0] ^= u64::from_le(words[0]);
            self.r[1] ^= u64::from_le(words[1]);
            self.r[2] ^= u64::from_le(words[2]);
            self.r[3] ^= u64::from_le(words[3]);
            self.r[4] ^= u64::from_le(words[4]);
            self.r[5] ^= u64::from_le(words[5]);
            self.r[6] ^= u64::from_le(words[6]);
            self.r[7] ^= u64::from_le(words[7]);
        } else {
            for (i, reg) in self.r.iter_mut().enumerate() {
                // Safety: caller guarantees 64 readable bytes.
                let word = unsafe { read_u64_unaligned(ptr.add(i * 8)) };
                *reg ^= word;
            }
        }
    }

    #[inline(always)]
    fn xor_regs_with_words_scalar(&mut self, words: &[u64; 8]) {
        for (reg, word) in self.r.iter_mut().zip(words.iter()) {
            *reg ^= *word;
        }
    }

    #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
    #[inline(always)]
    unsafe fn xor_regs_with_words_simd(&mut self, words: &[u64; 8]) {
        unsafe {
            simd_block_io::xor_u64x8_in_place_ptr(self.r.as_mut_ptr(), words.as_ptr());
        }
    }

    #[inline(always)]
    fn xor_f_with_e_scalar(&mut self) {
        for i in 0..4 {
            self.f[i].xor_inplace(self.e[i]);
        }
    }

    #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
    #[inline(always)]
    unsafe fn xor_f_with_e_simd(&mut self) {
        unsafe {
            let dst = self.f.as_mut_ptr() as *mut u64;
            let src = self.e.as_ptr() as *const u64;
            simd_block_io::xor_u64x8_in_place_ptr(dst, src);
        }
    }

    #[inline(always)]
    unsafe fn load_fp_regs_from_block_scalar(&mut self, ptr: *const u8) {
        if Self::USE_BLOCK_SCRATCHPAD_IO {
            // Safety: caller guarantees 64 readable bytes.
            let words = unsafe { ptr::read_unaligned(ptr as *const [u64; 8]) };
            let w0 = u64::from_le(words[0]);
            let w1 = u64::from_le(words[1]);
            let w2 = u64::from_le(words[2]);
            let w3 = u64::from_le(words[3]);
            let w4 = u64::from_le(words[4]);
            let w5 = u64::from_le(words[5]);
            let w6 = u64::from_le(words[6]);
            let w7 = u64::from_le(words[7]);
            self.f[0] = FpReg::from_u64_pair(w0);
            self.f[1] = FpReg::from_u64_pair(w1);
            self.f[2] = FpReg::from_u64_pair(w2);
            self.f[3] = FpReg::from_u64_pair(w3);
            self.e[0] = FpReg::from_u64_pair_e(w4, &self.e_mask_low, &self.e_mask_high);
            self.e[1] = FpReg::from_u64_pair_e(w5, &self.e_mask_low, &self.e_mask_high);
            self.e[2] = FpReg::from_u64_pair_e(w6, &self.e_mask_low, &self.e_mask_high);
            self.e[3] = FpReg::from_u64_pair_e(w7, &self.e_mask_low, &self.e_mask_high);
        } else {
            for (i, reg) in self.f.iter_mut().enumerate() {
                // Safety: caller guarantees 64 readable bytes.
                let word = unsafe { read_u64_unaligned(ptr.add(i * 8)) };
                *reg = FpReg::from_u64_pair(word);
            }
            for (i, reg) in self.e.iter_mut().enumerate() {
                // Safety: caller guarantees 64 readable bytes.
                let word = unsafe { read_u64_unaligned(ptr.add((4 + i) * 8)) };
                *reg = FpReg::from_u64_pair_e(word, &self.e_mask_low, &self.e_mask_high);
            }
        }
    }

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    #[inline(always)]
    unsafe fn prepare_iteration_simd(&mut self, sp0_ptr: *const u8, sp1_ptr: *const u8) {
        unsafe {
            simd_block_io::xor_block_from_mem(&mut self.r, sp0_ptr);
            let words = simd_block_io::load_block_64(sp1_ptr);
            self.f[0] = FpReg::from_u64_pair(words[0]);
            self.f[1] = FpReg::from_u64_pair(words[1]);
            self.f[2] = FpReg::from_u64_pair(words[2]);
            self.f[3] = FpReg::from_u64_pair(words[3]);
            self.e[0] = FpReg::from_u64_pair_e(words[4], &self.e_mask_low, &self.e_mask_high);
            self.e[1] = FpReg::from_u64_pair_e(words[5], &self.e_mask_low, &self.e_mask_high);
            self.e[2] = FpReg::from_u64_pair_e(words[6], &self.e_mask_low, &self.e_mask_high);
            self.e[3] = FpReg::from_u64_pair_e(words[7], &self.e_mask_low, &self.e_mask_high);
            // Most FP instructions are emitted as SSE2 on baseline targets.
            simd_block_io::vzeroupper();
        }
    }

    /// Scalar implementation of prepare_iteration block reads.
    /// Used as fallback when SIMD is not available.
    #[inline(always)]
    unsafe fn prepare_iteration_scalar(&mut self, sp0_ptr: *const u8, sp1_ptr: *const u8) {
        // Safety: caller guarantees both pointers reference 64-byte scratchpad windows.
        unsafe {
            self.xor_regs_from_block_scalar(sp0_ptr);
            self.load_fp_regs_from_block_scalar(sp1_ptr);
        }
    }

    fn finish_iteration(&mut self, sp_addr0: &mut u32, sp_addr1: &mut u32) {
        #[cfg(feature = "bench-instrument")]
        let finish_start = Instant::now();
        let rr2 = self.r[self.read_regs[2]] as u32;
        let rr3 = self.r[self.read_regs[3]] as u32;
        self.mx ^= rr2 ^ rr3;
        let dataset_idx = self.dataset_item_index(self.ma);
        #[cfg(feature = "bench-instrument")]
        {
            let elapsed = finish_start.elapsed().as_nanos() as u64;
            self.perf.finish_addr_select_ns =
                self.perf.finish_addr_select_ns.saturating_add(elapsed);
        }

        if self.flags.prefetch {
            #[cfg(feature = "bench-instrument")]
            let prefetch_start = Instant::now();
            self.prefetch_dataset_index(dataset_idx);
            #[cfg(feature = "bench-instrument")]
            {
                let elapsed = prefetch_start.elapsed().as_nanos() as u64;
                self.perf.finish_prefetch_ns = self.perf.finish_prefetch_ns.saturating_add(elapsed);
            }
        }

        if let Some(dataset) = &self.dataset {
            #[cfg(feature = "bench-instrument")]
            {
                self.perf.dataset_item_loads = self.perf.dataset_item_loads.saturating_add(1);
            }
            #[cfg(feature = "bench-instrument")]
            let load_start = Instant::now();
            let item = dataset.item_bytes(dataset_idx);
            #[cfg(feature = "bench-instrument")]
            {
                let elapsed = load_start.elapsed().as_nanos() as u64;
                self.perf.finish_dataset_item_load_ns = self
                    .perf
                    .finish_dataset_item_load_ns
                    .saturating_add(elapsed);
            }
            #[cfg(feature = "bench-instrument")]
            let xor_start = Instant::now();
            // Safety: dataset items are 64 bytes, read as eight u64 values.
            unsafe {
                let ptr = item.as_ptr();

                #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
                if self.simd_blockio_avx2 {
                    simd_block_io::xor_block_from_mem(&mut self.r, ptr);
                } else {
                    self.xor_regs_from_block_scalar(ptr);
                }

                #[cfg(not(all(feature = "simd-blockio", target_arch = "x86_64")))]
                {
                    self.xor_regs_from_block_scalar(ptr);
                }
            }
            #[cfg(feature = "bench-instrument")]
            {
                let elapsed = xor_start.elapsed().as_nanos() as u64;
                self.perf.finish_r_xor_ns = self.perf.finish_r_xor_ns.saturating_add(elapsed);
            }
        } else {
            #[cfg(feature = "bench-instrument")]
            let light_start = Instant::now();
            let item_words = compute_item_words(&self.cache, &self.cfg, dataset_idx as u64);
            #[cfg(feature = "bench-instrument")]
            {
                let elapsed = light_start.elapsed().as_nanos() as u64;
                self.perf.finish_light_cache_item_ns =
                    self.perf.finish_light_cache_item_ns.saturating_add(elapsed);
            }
            #[cfg(feature = "bench-instrument")]
            let xor_start = Instant::now();
            #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
            if self.simd_xor_avx2 {
                unsafe { self.xor_regs_with_words_simd(&item_words) };
            } else {
                self.xor_regs_with_words_scalar(&item_words);
            }
            #[cfg(not(all(feature = "simd-xor-paths", target_arch = "x86_64")))]
            self.xor_regs_with_words_scalar(&item_words);
            #[cfg(feature = "bench-instrument")]
            {
                let elapsed = xor_start.elapsed().as_nanos() as u64;
                self.perf.finish_r_xor_ns = self.perf.finish_r_xor_ns.saturating_add(elapsed);
            }
        }

        #[cfg(feature = "bench-instrument")]
        let store_int_start = Instant::now();
        std::mem::swap(&mut self.mx, &mut self.ma);
        let regs = self.r;
        #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
        if self.simd_blockio_avx2 {
            self.write_scratchpad64_simd(*sp_addr1 as u64, &regs);
        } else {
            self.write_scratchpad64_scalar(*sp_addr1 as u64, &regs);
        }
        #[cfg(not(all(feature = "simd-blockio", target_arch = "x86_64")))]
        self.write_scratchpad64_scalar(*sp_addr1 as u64, &regs);
        #[cfg(feature = "bench-instrument")]
        {
            let elapsed = store_int_start.elapsed().as_nanos() as u64;
            self.perf.finish_store_int_ns = self.perf.finish_store_int_ns.saturating_add(elapsed);
        }

        #[cfg(feature = "bench-instrument")]
        let xor_fp_start = Instant::now();
        #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
        if self.simd_xor_avx2 {
            unsafe { self.xor_f_with_e_simd() };
        } else {
            self.xor_f_with_e_scalar();
        }
        #[cfg(not(all(feature = "simd-xor-paths", target_arch = "x86_64")))]
        self.xor_f_with_e_scalar();
        #[cfg(feature = "bench-instrument")]
        {
            let elapsed = xor_fp_start.elapsed().as_nanos() as u64;
            self.perf.finish_f_xor_e_ns = self.perf.finish_f_xor_e_ns.saturating_add(elapsed);
        }

        #[cfg(feature = "bench-instrument")]
        let store_fp_start = Instant::now();
        #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
        if self.simd_blockio_avx2 {
            self.write_scratchpad_fp_simd(*sp_addr0 as u64);
        } else {
            self.write_scratchpad_fp_scalar(*sp_addr0 as u64);
        }
        #[cfg(not(all(feature = "simd-blockio", target_arch = "x86_64")))]
        self.write_scratchpad_fp_scalar(*sp_addr0 as u64);

        *sp_addr0 = 0;
        *sp_addr1 = 0;
        #[cfg(feature = "bench-instrument")]
        {
            let store_fp_elapsed = store_fp_start.elapsed().as_nanos() as u64;
            self.perf.finish_store_fp_ns = self
                .perf
                .finish_store_fp_ns
                .saturating_add(store_fp_elapsed);
            let finish_elapsed = finish_start.elapsed().as_nanos() as u64;
            self.perf.finish_iteration_ns =
                self.perf.finish_iteration_ns.saturating_add(finish_elapsed);
            self.perf.scratchpad_write_bytes = self.perf.scratchpad_write_bytes.saturating_add(128);
        }
    }

    fn execute_vm(&mut self) {
        #[cfg(feature = "jit")]
        if self.jit_active {
            #[cfg(feature = "bench-instrument")]
            {
                self.perf.jit_get_or_compile_calls =
                    self.perf.jit_get_or_compile_calls.saturating_add(1);
            }
            if let Ok(program) =
                self.jit_engine
                    .get_or_compile(&self.program_bytes, &self.program, &self.flags)
            {
                self.execute_vm_jit(&program);
                self.finish_simd_blockio_epoch();
                return;
            }
            self.jit_active = false;
        }
        self.execute_vm_interpreter();
        self.finish_simd_blockio_epoch();
    }

    #[inline(always)]
    fn finish_simd_blockio_epoch(&self) {
        #[cfg(all(
            any(feature = "simd-blockio", feature = "simd-xor-paths"),
            target_arch = "x86_64"
        ))]
        {
            let mut simd_used = false;
            #[cfg(feature = "simd-blockio")]
            {
                simd_used |= self.simd_blockio_avx2;
            }
            #[cfg(feature = "simd-xor-paths")]
            {
                simd_used |= self.simd_xor_avx2;
            }
            if simd_used {
                unsafe { simd_block_io::vzeroupper() };
            }
        }
    }

    fn execute_vm_interpreter(&mut self) {
        let mut ic = self.cfg.program_iterations();
        let mut sp_addr0 = self.mx;
        let mut sp_addr1 = self.ma;
        self.r = [0u64; 8];

        while ic > 0 {
            self.prepare_iteration(&mut sp_addr0, &mut sp_addr1);
            self.execute_program_interpreter();
            self.finish_iteration(&mut sp_addr0, &mut sp_addr1);
            ic -= 1;
        }
    }

    #[cfg(feature = "jit")]
    fn execute_vm_jit(&mut self, program: &jit::JitProgram) {
        self.r = [0u64; 8];
        self.execute_program_jit_iters(program, self.cfg.program_iterations());
    }

    /// Execute a single instruction at the given instruction pointer.
    /// Used by the match-based interpreter and tests.
    #[cfg_attr(feature = "threaded-interp", allow(dead_code))]
    #[allow(dead_code)]
    fn execute_instruction(
        &mut self,
        ip: usize,
        last_modified: &mut [i32; 8],
        rounding: &mut RoundingModeState,
    ) -> Option<usize> {
        let instr = self.program[ip];
        self.execute_instruction_decoded(ip, instr, last_modified, rounding)
    }

    #[inline(always)]
    fn select_base_zero_when_src_eq_dst(&self, src: usize, dst: usize) -> u64 {
        // Branchless: base is 0 when src == dst, otherwise r[src].
        let use_src_mask = ((src != dst) as u64).wrapping_neg();
        self.r[src] & use_src_mask
    }

    #[inline(always)]
    fn select_src_or_imm(&self, src: usize, dst: usize, imm: u32) -> u64 {
        // Branchless select for paths where src==dst maps to immediate.
        let use_src_mask = ((src != dst) as u64).wrapping_neg();
        let src_val = self.r[src];
        let imm_val = imm32_signed(imm);
        (src_val & use_src_mask) | (imm_val & !use_src_mask)
    }

    #[inline(always)]
    fn select_rot_src_or_imm(&self, src: usize, dst: usize, imm: u32) -> u32 {
        // Branchless select for rotate amount where src==dst maps to immediate.
        let use_src_mask = ((src != dst) as u32).wrapping_neg();
        let src_rot = (self.r[src] & 63) as u32;
        let imm_rot = imm & 63;
        (src_rot & use_src_mask) | (imm_rot & !use_src_mask)
    }

    #[inline(always)]
    fn execute_instruction_decoded(
        &mut self,
        ip: usize,
        instr: Instruction,
        last_modified: &mut [i32; 8],
        rounding: &mut RoundingModeState,
    ) -> Option<usize> {
        match instr.kind {
            InstructionKind::IAddRs => {
                let dst = instr.dst;
                let src_val = self.r[instr.src];
                let mut val = self.r[dst].wrapping_add(src_val << instr.mod_shift());
                if dst == 5 {
                    val = val.wrapping_add(imm32_signed(instr.imm));
                }
                self.r[dst] = val;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IAddM => {
                let dst = instr.dst;
                let base = self.select_base_zero_when_src_eq_dst(instr.src, dst);
                let mem = self.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
                self.r[dst] = self.r[dst].wrapping_add(mem);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::ISubR => {
                let dst = instr.dst;
                let src_val = self.select_src_or_imm(instr.src, dst, instr.imm);
                self.r[dst] = self.r[dst].wrapping_sub(src_val);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::ISubM => {
                let dst = instr.dst;
                let base = self.select_base_zero_when_src_eq_dst(instr.src, dst);
                let mem = self.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
                self.r[dst] = self.r[dst].wrapping_sub(mem);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IMulR => {
                let dst = instr.dst;
                let src_val = self.select_src_or_imm(instr.src, dst, instr.imm);
                self.r[dst] = self.r[dst].wrapping_mul(src_val);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IMulM => {
                let dst = instr.dst;
                let base = self.select_base_zero_when_src_eq_dst(instr.src, dst);
                let mem = self.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
                self.r[dst] = self.r[dst].wrapping_mul(mem);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IMulH_R => {
                let dst = instr.dst;
                let src_val = self.r[instr.src];
                let prod = (self.r[dst] as u128) * (src_val as u128);
                self.r[dst] = (prod >> 64) as u64;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IMulH_M => {
                let dst = instr.dst;
                let base = self.select_base_zero_when_src_eq_dst(instr.src, dst);
                let mem = self.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
                let prod = (self.r[dst] as u128) * (mem as u128);
                self.r[dst] = (prod >> 64) as u64;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::ISMulH_R => {
                let dst = instr.dst;
                let src_val = self.r[instr.src] as i64;
                let prod = (self.r[dst] as i64 as i128) * (src_val as i128);
                self.r[dst] = (prod >> 64) as u64;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::ISMulH_M => {
                let dst = instr.dst;
                let base = self.select_base_zero_when_src_eq_dst(instr.src, dst);
                let mem = self.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
                let prod = (self.r[dst] as i64 as i128) * (mem as i64 as i128);
                self.r[dst] = (prod >> 64) as u64;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IMulRcp => {
                let dst = instr.dst;
                let imm = instr.imm as u64;
                if imm == 0 || imm.is_power_of_two() {
                    return None;
                }
                let rcp = reciprocal_u64(imm);
                self.r[dst] = self.r[dst].wrapping_mul(rcp);
                if !(imm == 0 || imm.is_power_of_two()) {
                    last_modified[dst] = ip as i32;
                }
                None
            }
            InstructionKind::INegR => {
                let dst = instr.dst;
                self.r[dst] = self.r[dst].wrapping_neg();
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IXorR => {
                let dst = instr.dst;
                let src_val = self.select_src_or_imm(instr.src, dst, instr.imm);
                self.r[dst] ^= src_val;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IXorM => {
                let dst = instr.dst;
                let base = self.select_base_zero_when_src_eq_dst(instr.src, dst);
                let mem = self.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
                self.r[dst] ^= mem;
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IRorR => {
                let dst = instr.dst;
                let rot = self.select_rot_src_or_imm(instr.src, dst, instr.imm);
                self.r[dst] = self.r[dst].rotate_right(rot);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::IRolR => {
                let dst = instr.dst;
                let rot = self.select_rot_src_or_imm(instr.src, dst, instr.imm);
                self.r[dst] = self.r[dst].rotate_left(rot);
                last_modified[dst] = ip as i32;
                None
            }
            InstructionKind::ISwapR => {
                let dst = instr.dst;
                let src = instr.src;
                if dst != src {
                    self.r.swap(dst, src);
                    last_modified[dst] = ip as i32;
                    last_modified[src] = ip as i32;
                }
                None
            }
            InstructionKind::FSwapR => {
                let idx = instr.dst;
                if idx < 4 {
                    self.f[idx] = FpReg {
                        lo: self.f[idx].hi,
                        hi: self.f[idx].lo,
                    };
                } else {
                    let eidx = idx - 4;
                    self.e[eidx] = FpReg {
                        lo: self.e[eidx].hi,
                        hi: self.e[eidx].lo,
                    };
                }
                None
            }
            InstructionKind::FAddR => {
                let dst = instr.dst & 3;
                let src = instr.src & 3;
                self.f[dst].lo += self.a[src].lo;
                self.f[dst].hi += self.a[src].hi;
                None
            }
            InstructionKind::FAddM => {
                let dst = instr.dst & 3;
                let src = instr.src;
                let mem = self.read_mem_fp(src, instr.imm, instr.mod_mem(), false);
                self.f[dst].lo += mem.lo;
                self.f[dst].hi += mem.hi;
                None
            }
            InstructionKind::FSubR => {
                let dst = instr.dst & 3;
                let src = instr.src & 3;
                self.f[dst].lo -= self.a[src].lo;
                self.f[dst].hi -= self.a[src].hi;
                None
            }
            InstructionKind::FSubM => {
                let dst = instr.dst & 3;
                let src = instr.src;
                let mem = self.read_mem_fp(src, instr.imm, instr.mod_mem(), false);
                self.f[dst].lo -= mem.lo;
                self.f[dst].hi -= mem.hi;
                None
            }
            InstructionKind::FScalR => {
                let dst = instr.dst & 3;
                self.f[dst].fscal();
                None
            }
            InstructionKind::FMulR => {
                let dst = instr.dst & 3;
                let src = instr.src & 3;
                self.e[dst].lo *= self.a[src].lo;
                self.e[dst].hi *= self.a[src].hi;
                None
            }
            InstructionKind::FDivM => {
                let dst = instr.dst & 3;
                let src = instr.src;
                let mem = self.read_mem_fp(src, instr.imm, instr.mod_mem(), true);
                fdiv_execute(&mut self.e[dst].lo, &mut self.e[dst].hi, mem.lo, mem.hi);
                None
            }
            InstructionKind::FSqrtR => {
                let dst = instr.dst & 3;
                fsqrt_execute(&mut self.e[dst].lo, &mut self.e[dst].hi);
                None
            }
            InstructionKind::CFround => {
                let src = self.r[instr.src];
                let rot = src.rotate_right(instr.imm & 63);
                self.fprc = (rot & 3) as u32;
                rounding.update(self.fprc);
                None
            }
            InstructionKind::CBranch => {
                let dst = instr.dst;
                let b = instr.mod_cond() as u32 + self.cfg.jump_offset();
                let cimm = cbranch_cimm(instr.imm, b);
                self.r[dst] = self.r[dst].wrapping_add(cimm);
                let mask = ((1u64 << self.cfg.jump_bits()) - 1) << b;
                let jump = (self.r[dst] & mask) == 0;
                let target = if last_modified[dst] >= 0 {
                    last_modified[dst] as usize + 1
                } else {
                    0
                };
                for reg in last_modified.iter_mut() {
                    *reg = ip as i32;
                }
                if jump {
                    Some(target)
                } else {
                    None
                }
            }
            InstructionKind::IStore => {
                let dst = instr.dst;
                let src = instr.src;
                let base = self.r[dst];
                let level = instr.mem_level_write();
                let addr = base.wrapping_add(imm32_signed(instr.imm));
                self.write_mem_u64(addr, self.r[src], level);
                None
            }
        }
    }

    // =========================================================================
    // Threaded Interpreter Implementation
    // =========================================================================
    //
    // When the `threaded-interp` feature is enabled, instructions can be dispatched
    // via a function pointer table instead of a large match statement.
    // Experimental: disabled unless OXIDE_RANDOMX_THREADED_INTERP=1 is set.

    /// Execute program using threaded dispatch (function pointer table).
    #[cfg(feature = "threaded-interp")]
    fn execute_program_threaded(&mut self, last_modified: &mut [i32; 8]) {
        let mut rounding = RoundingModeState::new(self.fprc);
        let mut ip = 0usize;
        let program_len = self.program.len();

        while ip < program_len {
            let instr = self.program[ip];
            let handler = DISPATCH_TABLE[instr.kind as usize];

            #[cfg(feature = "bench-instrument")]
            self.record_instr(instr.kind);

            if let Some(target) = handler(self, instr, last_modified, &mut rounding, ip) {
                ip = target;
            } else {
                ip += 1;
            }
        }
    }

    #[cfg(feature = "bench-instrument")]
    fn record_instr(&mut self, kind: InstructionKind) {
        match instr_category(kind) {
            InstrCategory::Mem => {
                self.perf.instr_mem = self.perf.instr_mem.saturating_add(1);
            }
            InstrCategory::Store => {
                self.perf.instr_store = self.perf.instr_store.saturating_add(1);
            }
            InstrCategory::Ctrl => {
                self.perf.instr_ctrl = self.perf.instr_ctrl.saturating_add(1);
            }
            InstrCategory::Float => {
                self.perf.instr_float = self.perf.instr_float.saturating_add(1);
            }
            InstrCategory::Int => {
                self.perf.instr_int = self.perf.instr_int.saturating_add(1);
            }
        }
    }

    #[cfg(feature = "bench-instrument")]
    fn record_mem_read(&mut self, level: ScratchpadLevel) {
        self.perf.scratchpad_read_bytes = self.perf.scratchpad_read_bytes.saturating_add(8);
        match level {
            ScratchpadLevel::L1 => {
                self.perf.mem_read_l1 = self.perf.mem_read_l1.saturating_add(1);
            }
            ScratchpadLevel::L2 => {
                self.perf.mem_read_l2 = self.perf.mem_read_l2.saturating_add(1);
            }
            ScratchpadLevel::L3 => {
                self.perf.mem_read_l3 = self.perf.mem_read_l3.saturating_add(1);
            }
        }
    }

    #[cfg(feature = "bench-instrument")]
    fn record_mem_write(&mut self, level: ScratchpadLevel) {
        self.perf.scratchpad_write_bytes = self.perf.scratchpad_write_bytes.saturating_add(8);
        match level {
            ScratchpadLevel::L1 => {
                self.perf.mem_write_l1 = self.perf.mem_write_l1.saturating_add(1);
            }
            ScratchpadLevel::L2 => {
                self.perf.mem_write_l2 = self.perf.mem_write_l2.saturating_add(1);
            }
            ScratchpadLevel::L3 => {
                self.perf.mem_write_l3 = self.perf.mem_write_l3.saturating_add(1);
            }
        }
    }

    fn execute_program_interpreter(&mut self) {
        #[cfg(feature = "bench-instrument")]
        let start = Instant::now();
        #[cfg(feature = "bench-instrument")]
        {
            self.perf.program_execs = self.perf.program_execs.saturating_add(1);
        }

        let mut last_modified = [-1i32; 8];

        #[cfg(feature = "threaded-interp")]
        {
            if self.threaded_interp_active {
                self.execute_program_threaded(&mut last_modified);
            } else {
                self.execute_program_match(&mut last_modified);
            }
        }

        #[cfg(not(feature = "threaded-interp"))]
        {
            self.execute_program_match(&mut last_modified);
        }

        #[cfg(feature = "bench-instrument")]
        {
            let elapsed = start.elapsed().as_nanos() as u64;
            self.perf.vm_exec_ns_interpreter =
                self.perf.vm_exec_ns_interpreter.saturating_add(elapsed);
        }
    }

    fn execute_program_match(&mut self, last_modified: &mut [i32; 8]) {
        let mut rounding = RoundingModeState::new(self.fprc);
        let mut ip = 0usize;
        let program_len = self.program.len();
        let program_ptr = self.program.as_ptr();
        while ip < program_len {
            // Safety: loop condition guarantees ip < program_len.
            let instr = unsafe { *program_ptr.add(ip) };
            #[cfg(feature = "bench-instrument")]
            self.record_instr(instr.kind);
            if let Some(target) =
                self.execute_instruction_decoded(ip, instr, last_modified, &mut rounding)
            {
                ip = target;
            } else {
                ip += 1;
            }
        }
    }

    #[cfg(feature = "jit")]
    fn execute_program_jit_iters(&mut self, program: &jit::JitProgram, program_iters: u32) {
        #[cfg(feature = "bench-instrument")]
        let start = Instant::now();
        let mut ctx = VmJitContext::new(self);
        ctx.program_iters = program_iters;
        if program_iters == 0 {
            ctx.sp_addr0 = 0;
            ctx.sp_addr1 = 0;
        } else {
            ctx.sp_addr0 = self.mx;
            ctx.sp_addr1 = self.ma;
        }
        #[cfg(feature = "bench-instrument")]
        {
            self.perf.jit_exec_calls = self.perf.jit_exec_calls.saturating_add(1);
            let execs = if program_iters == 0 {
                1
            } else {
                program_iters as u64
            };
            self.perf.program_execs = self.perf.program_execs.saturating_add(execs);
            self.perf.jit_program_execs = self.perf.jit_program_execs.saturating_add(execs);
            program.add_instr_counts(&mut self.perf, execs);
        }
        unsafe {
            program.exec(&mut ctx);
        }
        self.fprc = ctx.fprc;
        #[cfg(feature = "bench-instrument")]
        {
            self.perf.jit_fastregs_spill_count = self
                .perf
                .jit_fastregs_spill_count
                .saturating_add(ctx.jit_fastregs_spill_count);
            self.perf.jit_fastregs_reload_count = self
                .perf
                .jit_fastregs_reload_count
                .saturating_add(ctx.jit_fastregs_reload_count);
            self.perf.jit_fastregs_sync_to_ctx_count = self
                .perf
                .jit_fastregs_sync_to_ctx_count
                .saturating_add(ctx.jit_fastregs_sync_to_ctx_count);
            self.perf.jit_fastregs_sync_from_ctx_count = self
                .perf
                .jit_fastregs_sync_from_ctx_count
                .saturating_add(ctx.jit_fastregs_sync_from_ctx_count);
            self.perf.jit_fastregs_call_boundary_count = self
                .perf
                .jit_fastregs_call_boundary_count
                .saturating_add(ctx.jit_fastregs_call_boundary_count);
            self.perf.jit_fastregs_call_boundary_float_nomem = self
                .perf
                .jit_fastregs_call_boundary_float_nomem
                .saturating_add(ctx.jit_fastregs_call_boundary_float_nomem);
            self.perf.jit_fastregs_call_boundary_float_mem = self
                .perf
                .jit_fastregs_call_boundary_float_mem
                .saturating_add(ctx.jit_fastregs_call_boundary_float_mem);
            self.perf.jit_fastregs_call_boundary_prepare_finish = self
                .perf
                .jit_fastregs_call_boundary_prepare_finish
                .saturating_add(ctx.jit_fastregs_call_boundary_prepare_finish);
            self.perf.jit_fastregs_preserve_spill_count = self
                .perf
                .jit_fastregs_preserve_spill_count
                .saturating_add(ctx.jit_fastregs_preserve_spill_count);
            self.perf.jit_fastregs_preserve_reload_count = self
                .perf
                .jit_fastregs_preserve_reload_count
                .saturating_add(ctx.jit_fastregs_preserve_reload_count);
            self.perf.prepare_iteration_ns = self
                .perf
                .prepare_iteration_ns
                .saturating_add(ctx.jit_fastregs_prepare_ns);
            self.perf.finish_iteration_ns = self
                .perf
                .finish_iteration_ns
                .saturating_add(ctx.jit_fastregs_finish_ns);
            self.perf.jit_fastregs_prepare_ns = self
                .perf
                .jit_fastregs_prepare_ns
                .saturating_add(ctx.jit_fastregs_prepare_ns);
            self.perf.jit_fastregs_finish_ns = self
                .perf
                .jit_fastregs_finish_ns
                .saturating_add(ctx.jit_fastregs_finish_ns);
            self.perf.jit_fastregs_light_cache_item_helper_calls = self
                .perf
                .jit_fastregs_light_cache_item_helper_calls
                .saturating_add(ctx.jit_fastregs_light_cache_item_helper_calls);
            self.perf.jit_fastregs_light_cache_item_helper_ns = self
                .perf
                .jit_fastregs_light_cache_item_helper_ns
                .saturating_add(ctx.jit_fastregs_light_cache_item_helper_ns);
            let elapsed = start.elapsed().as_nanos() as u64;
            self.perf.vm_exec_ns_jit = self.perf.vm_exec_ns_jit.saturating_add(elapsed);
        }
    }

    #[cfg(all(test, feature = "jit"))]
    fn execute_program_jit(&mut self, program: &jit::JitProgram) {
        self.execute_program_jit_iters(program, 0);
    }

    #[inline(always)]
    fn read_mem_u64(&mut self, base: u64, imm: u32, level: ScratchpadLevel) -> u64 {
        #[cfg(feature = "bench-instrument")]
        self.record_mem_read(level);
        let addr = base.wrapping_add(imm32_signed(imm));
        let mask = self.masks.levels_8[level as usize];
        self.prefetch_scratchpad(addr, mask);
        let idx = (addr & mask) as usize;
        let scratchpad = self.scratchpad.as_slice();
        // Safety: mask-derived indices keep the read within the scratchpad buffer.
        unsafe { read_u64_unaligned(scratchpad.as_ptr().add(idx)) }
    }

    #[inline(always)]
    fn write_mem_u64(&mut self, addr: u64, value: u64, level: ScratchpadLevel) {
        #[cfg(feature = "bench-instrument")]
        self.record_mem_write(level);
        let mask = self.masks.levels_8[level as usize];
        let idx = (addr & mask) as usize;
        let scratchpad = self.scratchpad.as_mut_slice();
        // Safety: mask-derived indices keep the write within the scratchpad buffer.
        unsafe {
            write_u64_unaligned(scratchpad.as_mut_ptr().add(idx), value);
        }
    }

    #[inline(always)]
    fn read_mem_fp(&mut self, src: usize, imm: u32, mod_mem: u8, use_e: bool) -> FpReg {
        #[cfg(feature = "bench-instrument")]
        {
            let level = if mod_mem == 0 {
                ScratchpadLevel::L2
            } else {
                ScratchpadLevel::L1
            };
            self.record_mem_read(level);
        }
        let base = self.r[src];
        let addr = base.wrapping_add(imm32_signed(imm));
        let mask = self.masks.fp_read_8[(mod_mem != 0) as usize];
        self.prefetch_scratchpad(addr, mask);
        let idx = (addr & mask) as usize;
        let scratchpad = self.scratchpad.as_slice();
        // Safety: mask-derived indices keep the read within the scratchpad buffer.
        let raw = unsafe { read_u64_unaligned(scratchpad.as_ptr().add(idx)) };
        if use_e {
            FpReg::from_u64_pair_e(raw, &self.e_mask_low, &self.e_mask_high)
        } else {
            FpReg::from_u64_pair(raw)
        }
    }

    #[cfg(all(test, feature = "jit"))]
    fn read_scratchpad64(&self, addr: u64) -> [u8; 64] {
        let idx = (addr & self.masks.l3_64) as usize;
        let mut out = [0u8; 64];
        let scratchpad = self.scratchpad.as_slice();
        // Safety: mask-derived indices keep the copy within the scratchpad buffer.
        unsafe {
            ptr::copy_nonoverlapping(scratchpad.as_ptr().add(idx), out.as_mut_ptr(), 64);
        }
        out
    }

    #[allow(dead_code)]
    fn write_scratchpad64(&mut self, addr: u64, regs: &[u64; 8]) {
        #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
        if self.simd_blockio_avx2 {
            self.write_scratchpad64_simd(addr, regs);
            return;
        }
        self.write_scratchpad64_scalar(addr, regs);
    }

    #[inline(always)]
    fn write_scratchpad64_scalar(&mut self, addr: u64, regs: &[u64; 8]) {
        let idx = (addr & self.masks.l3_64) as usize;
        let scratchpad = self.scratchpad.as_mut_slice();
        // Safety: mask-derived indices keep the writes within the scratchpad buffer.
        unsafe {
            let ptr = scratchpad.as_mut_ptr().add(idx);
            if Self::USE_BLOCK_SCRATCHPAD_IO {
                let words = [
                    regs[0].to_le(),
                    regs[1].to_le(),
                    regs[2].to_le(),
                    regs[3].to_le(),
                    regs[4].to_le(),
                    regs[5].to_le(),
                    regs[6].to_le(),
                    regs[7].to_le(),
                ];
                ptr::write_unaligned(ptr as *mut [u64; 8], words);
            } else {
                for (i, reg) in regs.iter().enumerate() {
                    write_u64_unaligned(ptr.add(i * 8), *reg);
                }
            }
        }
    }

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    #[inline(always)]
    fn write_scratchpad64_simd(&mut self, addr: u64, regs: &[u64; 8]) {
        let idx = (addr & self.masks.l3_64) as usize;
        let scratchpad = self.scratchpad.as_mut_slice();
        // Safety: mask-derived indices keep the writes within the scratchpad buffer.
        unsafe {
            let ptr = scratchpad.as_mut_ptr().add(idx);
            // On x86_64 little-endian, to_le() is a no-op.
            simd_block_io::store_block_64(ptr, regs);
        }
    }

    #[allow(dead_code)]
    fn write_scratchpad_fp(&mut self, addr: u64) {
        #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
        if self.simd_blockio_avx2 {
            self.write_scratchpad_fp_simd(addr);
            return;
        }
        self.write_scratchpad_fp_scalar(addr);
    }

    #[inline(always)]
    fn write_scratchpad_fp_scalar(&mut self, addr: u64) {
        let idx = (addr & self.masks.l3_64) as usize;
        let scratchpad = self.scratchpad.as_mut_slice();
        // Safety: mask-derived indices keep the writes within the scratchpad buffer.
        unsafe {
            let ptr = scratchpad.as_mut_ptr().add(idx);
            if Self::USE_BLOCK_SCRATCHPAD_IO {
                let words = [
                    self.f[0].lo.to_bits().to_le(),
                    self.f[0].hi.to_bits().to_le(),
                    self.f[1].lo.to_bits().to_le(),
                    self.f[1].hi.to_bits().to_le(),
                    self.f[2].lo.to_bits().to_le(),
                    self.f[2].hi.to_bits().to_le(),
                    self.f[3].lo.to_bits().to_le(),
                    self.f[3].hi.to_bits().to_le(),
                ];
                ptr::write_unaligned(ptr as *mut [u64; 8], words);
            } else {
                for (i, reg) in self.f.iter().enumerate() {
                    let lo = reg.lo.to_bits();
                    let hi = reg.hi.to_bits();
                    let base = i * 16;
                    write_u64_unaligned(ptr.add(base), lo);
                    write_u64_unaligned(ptr.add(base + 8), hi);
                }
            }
        }
    }

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    #[inline(always)]
    fn write_scratchpad_fp_simd(&mut self, addr: u64) {
        let idx = (addr & self.masks.l3_64) as usize;
        let scratchpad = self.scratchpad.as_mut_slice();
        // Safety: mask-derived indices keep the writes within the scratchpad buffer.
        unsafe {
            let ptr = scratchpad.as_mut_ptr().add(idx);
            // On x86_64 little-endian, to_le() is a no-op.
            let words = [
                self.f[0].lo.to_bits(),
                self.f[0].hi.to_bits(),
                self.f[1].lo.to_bits(),
                self.f[1].hi.to_bits(),
                self.f[2].lo.to_bits(),
                self.f[2].hi.to_bits(),
                self.f[3].lo.to_bits(),
                self.f[3].hi.to_bits(),
            ];
            simd_block_io::store_block_64(ptr, &words);
        }
    }

    #[inline]
    fn dataset_base_mask(&self) -> u64 {
        let base = self.cfg.dataset_base_size();
        debug_assert!(
            base.is_power_of_two(),
            "dataset_base_size must be power of two"
        );
        base - 1
    }

    #[inline(always)]
    fn dataset_item_index(&self, ma: u32) -> usize {
        let offset = self.dataset_offset + (u64::from(ma) & self.dataset_base_mask());
        debug_assert!(
            offset < self.cfg.dataset_size(),
            "dataset byte offset must stay within the allocated dataset"
        );
        let idx = (offset >> 6) as usize;
        if let Some(dataset) = &self.dataset {
            debug_assert!(
                idx < dataset.item_count(),
                "dataset item index must be in range"
            );
        }
        idx
    }

    /// Prefetch scratchpad address at the given base+imm address.
    ///
    /// The prefetch distance is controlled by `flags.scratchpad_prefetch_distance`:
    /// - 0 = disabled
    /// - 1-32 = prefetch N cachelines (64 bytes each) ahead
    #[inline(always)]
    fn prefetch_scratchpad(&self, addr: u64, mask: u64) {
        let distance = self.flags.scratchpad_prefetch_distance;
        if distance == 0 {
            return;
        }
        let distance_bytes = (distance as u64) * 64;
        let prefetch_idx = (addr.wrapping_add(distance_bytes) & mask) as usize;
        let scratchpad = self.scratchpad.as_slice();

        #[cfg(all(target_arch = "x86_64", not(miri)))]
        unsafe {
            use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
            let ptr = scratchpad.as_ptr().add(prefetch_idx);
            _mm_prefetch(ptr as *const i8, _MM_HINT_T0);
        }
        #[cfg(any(not(target_arch = "x86_64"), miri))]
        {
            let _ = (scratchpad, prefetch_idx);
        }
    }

    /// Prefetch dataset item at the given dataset index.
    ///
    /// The prefetch distance is controlled by `flags.prefetch_distance`:
    /// - 0 = disabled (but this function shouldn't be called if prefetch is false)
    /// - 1-8 = prefetch N cachelines (64 bytes each) ahead
    fn prefetch_dataset_index(&self, index: usize) {
        if let Some(dataset) = &self.dataset {
            debug_assert!(
                index < dataset.item_count(),
                "dataset item index must be in range"
            );
            let ptr = dataset.item_bytes(index).as_ptr();

            // Apply prefetch distance: prefetch N cachelines ahead
            // The distance is in cachelines (64 bytes each)
            let distance_bytes = self.flags.prefetch_distance as usize * 64;

            #[cfg(all(target_arch = "x86_64", not(miri)))]
            unsafe {
                use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
                // Prefetch the computed address plus the distance offset
                // This helps hide memory latency for the next iteration
                let prefetch_ptr = ptr.wrapping_add(distance_bytes);
                _mm_prefetch(prefetch_ptr as *const i8, _MM_HINT_T0);
            }
            #[cfg(any(not(target_arch = "x86_64"), miri))]
            {
                let _ = (ptr, distance_bytes);
            }
        }
    }

    fn register_file(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        let mut offset = 0;
        for reg in self.r.iter() {
            out[offset..offset + 8].copy_from_slice(&reg.to_le_bytes());
            offset += 8;
        }
        for reg in self.f.iter() {
            let bytes = (*reg).to_bytes();
            out[offset..offset + 16].copy_from_slice(&bytes);
            offset += 16;
        }
        for reg in self.e.iter() {
            let bytes = (*reg).to_bytes();
            out[offset..offset + 16].copy_from_slice(&bytes);
            offset += 16;
        }
        for reg in self.a.iter() {
            let bytes = (*reg).to_bytes();
            out[offset..offset + 16].copy_from_slice(&bytes);
            offset += 16;
        }
        out
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum ScratchpadLevel {
    L1 = 0,
    L2 = 1,
    L3 = 2,
}

#[derive(Clone, Copy, Debug)]
struct Instruction {
    kind: InstructionKind,
    dst: usize,
    src: usize,
    mod_flags: u8,
    imm: u32,
}

impl Instruction {
    const USE_MEM_LEVEL_LUT: bool = true; // Flip to false for quick A/B comparisons.
    const MEM_LEVEL_READ_LUT: [[ScratchpadLevel; 2]; 256] = Self::build_mem_level_read_lut();
    const MEM_LEVEL_WRITE_LUT: [ScratchpadLevel; 256] = Self::build_mem_level_write_lut();

    fn new(kind: InstructionKind, dst: usize, src: usize, mod_flags: u8, imm: u32) -> Self {
        Self {
            kind,
            dst,
            src,
            mod_flags,
            imm,
        }
    }

    fn decode(word: u64, table: &[InstructionKind; 256]) -> Self {
        let opcode = word as u8;
        let dst = ((word >> 8) & 0x7) as usize;
        let src = ((word >> 16) & 0x7) as usize;
        let mod_flags = ((word >> 24) & 0xFF) as u8;
        let imm = (word >> 32) as u32;
        Self::new(table[opcode as usize], dst, src, mod_flags, imm)
    }

    const fn build_mem_level_read_lut() -> [[ScratchpadLevel; 2]; 256] {
        let mut lut = [[ScratchpadLevel::L1; 2]; 256];
        let mut idx = 0;
        while idx < 256 {
            let mod_flags = idx as u8;
            let mod_mem = mod_flags & 0x3;
            let level = if mod_mem == 0 {
                ScratchpadLevel::L2
            } else {
                ScratchpadLevel::L1
            };
            lut[idx][0] = level;
            lut[idx][1] = ScratchpadLevel::L3;
            idx += 1;
        }
        lut
    }

    const fn build_mem_level_write_lut() -> [ScratchpadLevel; 256] {
        let mut lut = [ScratchpadLevel::L1; 256];
        let mut idx = 0;
        while idx < 256 {
            let mod_flags = idx as u8;
            let mod_cond = (mod_flags >> 4) & 0xF;
            let mod_mem = mod_flags & 0x3;
            lut[idx] = if mod_cond >= 14 {
                ScratchpadLevel::L3
            } else if mod_mem == 0 {
                ScratchpadLevel::L2
            } else {
                ScratchpadLevel::L1
            };
            idx += 1;
        }
        lut
    }

    fn mod_mem(self) -> u8 {
        self.mod_flags & 0x3
    }

    fn mod_shift(self) -> u32 {
        ((self.mod_flags >> 2) & 0x3) as u32
    }

    fn mod_cond(self) -> u8 {
        (self.mod_flags >> 4) & 0xF
    }

    #[inline(always)]
    fn mem_level_read(self, dst_is_r: bool) -> ScratchpadLevel {
        if Self::USE_MEM_LEVEL_LUT {
            let same = (dst_is_r && self.dst == self.src) as usize;
            Self::MEM_LEVEL_READ_LUT[self.mod_flags as usize][same]
        } else if dst_is_r && self.dst == self.src {
            ScratchpadLevel::L3
        } else if self.mod_mem() == 0 {
            ScratchpadLevel::L2
        } else {
            ScratchpadLevel::L1
        }
    }

    #[inline(always)]
    fn mem_level_write(self) -> ScratchpadLevel {
        if Self::USE_MEM_LEVEL_LUT {
            Self::MEM_LEVEL_WRITE_LUT[self.mod_flags as usize]
        } else if self.mod_cond() >= 14 {
            ScratchpadLevel::L3
        } else if self.mod_mem() == 0 {
            ScratchpadLevel::L2
        } else {
            ScratchpadLevel::L1
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum InstructionKind {
    IAddRs = 0,
    IAddM = 1,
    ISubR = 2,
    ISubM = 3,
    IMulR = 4,
    IMulM = 5,
    IMulH_R = 6,
    IMulH_M = 7,
    ISMulH_R = 8,
    ISMulH_M = 9,
    IMulRcp = 10,
    INegR = 11,
    IXorR = 12,
    IXorM = 13,
    IRorR = 14,
    IRolR = 15,
    ISwapR = 16,
    FSwapR = 17,
    FAddR = 18,
    FAddM = 19,
    FSubR = 20,
    FSubM = 21,
    FScalR = 22,
    FMulR = 23,
    FDivM = 24,
    FSqrtR = 25,
    CFround = 26,
    CBranch = 27,
    IStore = 28,
}

/// Total number of instruction kinds for dispatch table sizing
#[cfg(feature = "threaded-interp")]
const INSTR_KIND_COUNT: usize = 29;

#[cfg(feature = "bench-instrument")]
#[derive(Clone, Copy, Debug)]
enum InstrCategory {
    Int,
    Float,
    Mem,
    Ctrl,
    Store,
}

#[cfg(feature = "bench-instrument")]
fn instr_category(kind: InstructionKind) -> InstrCategory {
    match kind {
        InstructionKind::IAddM
        | InstructionKind::ISubM
        | InstructionKind::IMulM
        | InstructionKind::IMulH_M
        | InstructionKind::ISMulH_M
        | InstructionKind::IXorM => InstrCategory::Mem,
        InstructionKind::IStore => InstrCategory::Store,
        InstructionKind::CFround | InstructionKind::CBranch => InstrCategory::Ctrl,
        InstructionKind::FSwapR
        | InstructionKind::FAddR
        | InstructionKind::FAddM
        | InstructionKind::FSubR
        | InstructionKind::FSubM
        | InstructionKind::FScalR
        | InstructionKind::FMulR
        | InstructionKind::FDivM
        | InstructionKind::FSqrtR => InstrCategory::Float,
        _ => InstrCategory::Int,
    }
}

// =============================================================================
// Threaded Interpreter Dispatch Table and Handlers
// =============================================================================

/// Handler function signature for threaded interpreter dispatch.
/// Returns Some(jump_target) for control flow changes, None to advance to next instruction.
#[cfg(feature = "threaded-interp")]
type InstrHandler = fn(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize>;

/// Dispatch table mapping instruction kinds to their handler functions.
#[cfg(feature = "threaded-interp")]
static DISPATCH_TABLE: [InstrHandler; INSTR_KIND_COUNT] = [
    handle_iadd_rs,  // 0: IAddRs
    handle_iadd_m,   // 1: IAddM
    handle_isub_r,   // 2: ISubR
    handle_isub_m,   // 3: ISubM
    handle_imul_r,   // 4: IMulR
    handle_imul_m,   // 5: IMulM
    handle_imulh_r,  // 6: IMulH_R
    handle_imulh_m,  // 7: IMulH_M
    handle_ismulh_r, // 8: ISMulH_R
    handle_ismulh_m, // 9: ISMulH_M
    handle_imul_rcp, // 10: IMulRcp
    handle_ineg_r,   // 11: INegR
    handle_ixor_r,   // 12: IXorR
    handle_ixor_m,   // 13: IXorM
    handle_iror_r,   // 14: IRorR
    handle_irol_r,   // 15: IRolR
    handle_iswap_r,  // 16: ISwapR
    handle_fswap_r,  // 17: FSwapR
    handle_fadd_r,   // 18: FAddR
    handle_fadd_m,   // 19: FAddM
    handle_fsub_r,   // 20: FSubR
    handle_fsub_m,   // 21: FSubM
    handle_fscal_r,  // 22: FScalR
    handle_fmul_r,   // 23: FMulR
    handle_fdiv_m,   // 24: FDivM
    handle_fsqrt_r,  // 25: FSqrtR
    handle_cfround,  // 26: CFround
    handle_cbranch,  // 27: CBranch
    handle_istore,   // 28: IStore
];

// Integer instruction handlers

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_iadd_rs(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src_val = if instr.src == dst {
        vm.r[dst]
    } else {
        vm.r[instr.src]
    };
    let mut val = vm.r[dst].wrapping_add(src_val << instr.mod_shift());
    if dst == 5 {
        val = val.wrapping_add(imm32_signed(instr.imm));
    }
    vm.r[dst] = val;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_iadd_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let base = if instr.src == dst { 0 } else { vm.r[instr.src] };
    let mem = vm.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
    vm.r[dst] = vm.r[dst].wrapping_add(mem);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_isub_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src_val = if instr.src == dst {
        imm32_signed(instr.imm)
    } else {
        vm.r[instr.src]
    };
    vm.r[dst] = vm.r[dst].wrapping_sub(src_val);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_isub_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let base = if instr.src == dst { 0 } else { vm.r[instr.src] };
    let mem = vm.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
    vm.r[dst] = vm.r[dst].wrapping_sub(mem);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_imul_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src_val = if instr.src == dst {
        imm32_signed(instr.imm)
    } else {
        vm.r[instr.src]
    };
    vm.r[dst] = vm.r[dst].wrapping_mul(src_val);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_imul_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let base = if instr.src == dst { 0 } else { vm.r[instr.src] };
    let mem = vm.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
    vm.r[dst] = vm.r[dst].wrapping_mul(mem);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_imulh_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src_val = vm.r[instr.src];
    let prod = (vm.r[dst] as u128) * (src_val as u128);
    vm.r[dst] = (prod >> 64) as u64;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_imulh_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let base = if instr.src == dst { 0 } else { vm.r[instr.src] };
    let mem = vm.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
    let prod = (vm.r[dst] as u128) * (mem as u128);
    vm.r[dst] = (prod >> 64) as u64;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_ismulh_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src_val = vm.r[instr.src] as i64;
    let prod = (vm.r[dst] as i64 as i128) * (src_val as i128);
    vm.r[dst] = (prod >> 64) as u64;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_ismulh_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let base = if instr.src == dst { 0 } else { vm.r[instr.src] };
    let mem = vm.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
    let prod = (vm.r[dst] as i64 as i128) * (mem as i64 as i128);
    vm.r[dst] = (prod >> 64) as u64;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_imul_rcp(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let imm = instr.imm as u64;
    if imm == 0 || imm.is_power_of_two() {
        return None;
    }
    let rcp = reciprocal_u64(imm);
    vm.r[dst] = vm.r[dst].wrapping_mul(rcp);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_ineg_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    vm.r[dst] = vm.r[dst].wrapping_neg();
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_ixor_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src_val = if instr.src == dst {
        imm32_signed(instr.imm)
    } else {
        vm.r[instr.src]
    };
    vm.r[dst] ^= src_val;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_ixor_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let base = if instr.src == dst { 0 } else { vm.r[instr.src] };
    let mem = vm.read_mem_u64(base, instr.imm, instr.mem_level_read(true));
    vm.r[dst] ^= mem;
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_iror_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let rot = if instr.src == dst {
        instr.imm & 63
    } else {
        (vm.r[instr.src] & 63) as u32
    };
    vm.r[dst] = vm.r[dst].rotate_right(rot);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_irol_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let rot = if instr.src == dst {
        instr.imm & 63
    } else {
        (vm.r[instr.src] & 63) as u32
    };
    vm.r[dst] = vm.r[dst].rotate_left(rot);
    last_modified[dst] = ip as i32;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_iswap_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src = instr.src;
    if dst != src {
        vm.r.swap(dst, src);
        last_modified[dst] = ip as i32;
        last_modified[src] = ip as i32;
    }
    None
}

// Floating point instruction handlers

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fswap_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let idx = instr.dst;
    if idx < 4 {
        vm.f[idx] = FpReg {
            lo: vm.f[idx].hi,
            hi: vm.f[idx].lo,
        };
    } else {
        let eidx = idx - 4;
        vm.e[eidx] = FpReg {
            lo: vm.e[eidx].hi,
            hi: vm.e[eidx].lo,
        };
    }
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fadd_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    vm.f[dst].lo += vm.a[src].lo;
    vm.f[dst].hi += vm.a[src].hi;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fadd_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    let src = instr.src;
    let mem = vm.read_mem_fp(src, instr.imm, instr.mod_mem(), false);
    vm.f[dst].lo += mem.lo;
    vm.f[dst].hi += mem.hi;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fsub_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    vm.f[dst].lo -= vm.a[src].lo;
    vm.f[dst].hi -= vm.a[src].hi;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fsub_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    let src = instr.src;
    let mem = vm.read_mem_fp(src, instr.imm, instr.mod_mem(), false);
    vm.f[dst].lo -= mem.lo;
    vm.f[dst].hi -= mem.hi;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fscal_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    vm.f[dst].fscal();
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fmul_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    let src = instr.src & 3;
    vm.e[dst].lo *= vm.a[src].lo;
    vm.e[dst].hi *= vm.a[src].hi;
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fdiv_m(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    let src = instr.src;
    let mem = vm.read_mem_fp(src, instr.imm, instr.mod_mem(), true);
    fdiv_execute(&mut vm.e[dst].lo, &mut vm.e[dst].hi, mem.lo, mem.hi);
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_fsqrt_r(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst & 3;
    fsqrt_execute(&mut vm.e[dst].lo, &mut vm.e[dst].hi);
    None
}

// Control instruction handlers

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_cfround(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let src = vm.r[instr.src];
    let rot = src.rotate_right(instr.imm & 63);
    vm.fprc = (rot & 3) as u32;
    rounding.update(vm.fprc);
    None
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_cbranch(
    vm: &mut RandomXVm,
    instr: Instruction,
    last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let b = instr.mod_cond() as u32 + vm.cfg.jump_offset();
    let cimm = cbranch_cimm(instr.imm, b);
    vm.r[dst] = vm.r[dst].wrapping_add(cimm);
    let mask = ((1u64 << vm.cfg.jump_bits()) - 1) << b;
    let jump = (vm.r[dst] & mask) == 0;
    let target = if last_modified[dst] >= 0 {
        last_modified[dst] as usize + 1
    } else {
        0
    };
    for reg in last_modified.iter_mut() {
        *reg = ip as i32;
    }
    if jump {
        Some(target)
    } else {
        None
    }
}

#[cfg(feature = "threaded-interp")]
#[inline(always)]
fn handle_istore(
    vm: &mut RandomXVm,
    instr: Instruction,
    _last_modified: &mut [i32; 8],
    _rounding: &mut RoundingModeState,
    _ip: usize,
) -> Option<usize> {
    let dst = instr.dst;
    let src = instr.src;
    let base = vm.r[dst];
    let level = instr.mem_level_write();
    let addr = base.wrapping_add(imm32_signed(instr.imm));
    vm.write_mem_u64(addr, vm.r[src], level);
    None
}

fn build_opcode_table(freqs: &InstructionFrequencies) -> [InstructionKind; 256] {
    let mut table = [InstructionKind::IAddRs; 256];
    let mut idx = 0usize;
    let mut push = |kind: InstructionKind, count: u8| {
        for _ in 0..count {
            table[idx] = kind;
            idx += 1;
        }
    };

    // Integer instructions (docs/randomx-refs/specs.md §5.2 Table 5.2.1).
    push(InstructionKind::IAddRs, freqs.iadd_rs);
    push(InstructionKind::IAddM, freqs.iadd_m);
    push(InstructionKind::ISubR, freqs.isub_r);
    push(InstructionKind::ISubM, freqs.isub_m);
    push(InstructionKind::IMulR, freqs.imul_r);
    push(InstructionKind::IMulM, freqs.imul_m);
    push(InstructionKind::IMulH_R, freqs.imulh_r);
    push(InstructionKind::IMulH_M, freqs.imulh_m);
    push(InstructionKind::ISMulH_R, freqs.ismulh_r);
    push(InstructionKind::ISMulH_M, freqs.ismulh_m);
    push(InstructionKind::IMulRcp, freqs.imul_rcp);
    push(InstructionKind::INegR, freqs.ineg_r);
    push(InstructionKind::IXorR, freqs.ixor_r);
    push(InstructionKind::IXorM, freqs.ixor_m);
    push(InstructionKind::IRorR, freqs.iror_r);
    push(InstructionKind::IRolR, freqs.irol_r);
    push(InstructionKind::ISwapR, freqs.iswap_r);

    // Floating point instructions (docs/randomx-refs/specs.md §5.3 Table 5.3.1).
    push(InstructionKind::FSwapR, freqs.fswap_r);
    push(InstructionKind::FAddR, freqs.fadd_r);
    push(InstructionKind::FAddM, freqs.fadd_m);
    push(InstructionKind::FSubR, freqs.fsub_r);
    push(InstructionKind::FSubM, freqs.fsub_m);
    push(InstructionKind::FScalR, freqs.fscal_r);
    push(InstructionKind::FMulR, freqs.fmul_r);
    push(InstructionKind::FDivM, freqs.fdiv_m);
    push(InstructionKind::FSqrtR, freqs.fsqrt_r);

    // Control instructions (docs/randomx-refs/specs.md §5.4 Table 5.4.1).
    push(InstructionKind::CFround, freqs.cfround);
    push(InstructionKind::CBranch, freqs.cbranch);

    // Store instruction (docs/randomx-refs/specs.md §5.5 Table 5.5.1).
    push(InstructionKind::IStore, freqs.istore);
    debug_assert_eq!(idx, 256);
    table
}

fn generate_bytes(out: &mut [u8], gen: &mut AesGenerator4R, flags: &RandomXFlags) {
    let mut offset = 0;
    while offset < out.len() {
        let block = gen.next(flags);
        let take = (out.len() - offset).min(64);
        out[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
}

fn fill_scratchpad(buf: &mut [u8], gen: &mut AesGenerator1R, flags: &RandomXFlags) {
    let mut offset = 0;
    while offset < buf.len() {
        let block = gen.next(flags);
        let take = (buf.len() - offset).min(64);
        buf[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
    }
}

fn a_register_value(qword: u64) -> f64 {
    let fraction = qword & ((1u64 << 52) - 1);
    let exponent = (qword >> 59) & 0x1f;
    let exponent_bits = (1023u64 + exponent) << 52;
    let bits = exponent_bits | fraction;
    f64::from_bits(bits)
}

#[inline(always)]
fn imm32_signed(imm: u32) -> u64 {
    let signed = imm as i32 as i64;
    signed as u64
}

#[inline(always)]
unsafe fn read_u64_unaligned(ptr: *const u8) -> u64 {
    u64::from_le(unsafe { ptr::read_unaligned(ptr as *const u64) })
}

#[inline(always)]
unsafe fn write_u64_unaligned(ptr: *mut u8, value: u64) {
    unsafe { ptr::write_unaligned(ptr as *mut u64, value.to_le()) };
}

#[inline(always)]
fn cbranch_cimm(imm: u32, b: u32) -> u64 {
    let mut value = imm as i32 as i64 as u64;
    if b > 0 {
        value &= !(1u64 << (b - 1));
    }
    value | (1u64 << b)
}

/// Cold helper for FDivM instruction - floating-point division is rare.
#[cold]
#[inline(never)]
fn fdiv_execute(e_lo: &mut f64, e_hi: &mut f64, mem_lo: f64, mem_hi: f64) {
    *e_lo /= mem_lo;
    *e_hi /= mem_hi;
}

/// Cold helper for FSqrtR instruction - floating-point sqrt is rare.
#[cold]
#[inline(never)]
fn fsqrt_execute(e_lo: &mut f64, e_hi: &mut f64) {
    *e_lo = e_lo.sqrt();
    *e_hi = e_hi.sqrt();
}

fn reciprocal_u64(value: u64) -> u64 {
    let msb = 63 - value.leading_zeros();
    let shift = 63 + msb;
    let rcp = (1u128 << shift) / value as u128;
    rcp as u64
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
struct RoundingModeGuard {
    prev: u32,
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
#[allow(deprecated)]
impl RoundingModeGuard {
    fn new(mode: u32) -> Self {
        use core::arch::x86_64::{_mm_getcsr, _mm_setcsr};
        let prev = unsafe { _mm_getcsr() };
        let mut next = prev & !0x6000;
        next |= (mode & 0x3) << 13;
        unsafe { _mm_setcsr(next) };
        Self { prev }
    }

    fn set_mode(&self, mode: u32) {
        use core::arch::x86_64::{_mm_getcsr, _mm_setcsr};
        let current = unsafe { _mm_getcsr() };
        let mut next = current & !0x6000;
        next |= (mode & 0x3) << 13;
        unsafe { _mm_setcsr(next) };
    }
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
#[allow(deprecated)]
impl Drop for RoundingModeGuard {
    fn drop(&mut self) {
        use core::arch::x86_64::_mm_setcsr;
        unsafe { _mm_setcsr(self.prev) };
    }
}

struct RoundingModeState {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    guard: RoundingModeGuard,
    current: u32,
}

impl RoundingModeState {
    fn new(mode: u32) -> Self {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        {
            Self {
                guard: RoundingModeGuard::new(mode),
                current: mode,
            }
        }
        #[cfg(any(not(target_arch = "x86_64"), miri))]
        {
            Self { current: mode }
        }
    }

    fn update(&mut self, mode: u32) {
        if mode == self.current {
            return;
        }
        self.current = mode;
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        self.guard.set_mode(mode);
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::{
        build_opcode_table, fill_scratchpad, AesGenerator1R, AesGenerator4R, EMask, Instruction,
        InstructionKind, RandomXVm, RoundingModeState, ScratchpadLevel,
    };
    use crate::blake::hash256;
    use crate::cache::RandomXCache;
    use crate::config::RandomXConfig;
    use crate::flags::RandomXFlags;

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    fn with_simd_blockio_env<R>(force: bool, disable: bool, f: impl FnOnce() -> R) -> R {
        use std::ffi::OsString;
        use std::sync::{Mutex, OnceLock};

        struct EnvRestore {
            force_prev: Option<OsString>,
            disable_prev: Option<OsString>,
        }

        impl Drop for EnvRestore {
            fn drop(&mut self) {
                if let Some(value) = &self.force_prev {
                    std::env::set_var(super::SIMD_BLOCKIO_FORCE_ENV, value);
                } else {
                    std::env::remove_var(super::SIMD_BLOCKIO_FORCE_ENV);
                }
                if let Some(value) = &self.disable_prev {
                    std::env::set_var(super::SIMD_BLOCKIO_DISABLE_ENV, value);
                } else {
                    std::env::remove_var(super::SIMD_BLOCKIO_DISABLE_ENV);
                }
            }
        }

        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _env_guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("simd env lock poisoned");

        let _restore = EnvRestore {
            force_prev: std::env::var_os(super::SIMD_BLOCKIO_FORCE_ENV),
            disable_prev: std::env::var_os(super::SIMD_BLOCKIO_DISABLE_ENV),
        };

        if force {
            std::env::set_var(super::SIMD_BLOCKIO_FORCE_ENV, "1");
        } else {
            std::env::remove_var(super::SIMD_BLOCKIO_FORCE_ENV);
        }

        if disable {
            std::env::set_var(super::SIMD_BLOCKIO_DISABLE_ENV, "1");
        } else {
            std::env::remove_var(super::SIMD_BLOCKIO_DISABLE_ENV);
        }

        f()
    }

    #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
    fn with_simd_xor_env<R>(force: bool, disable: bool, f: impl FnOnce() -> R) -> R {
        use std::ffi::OsString;
        use std::sync::{Mutex, OnceLock};

        struct EnvRestore {
            force_prev: Option<OsString>,
            disable_prev: Option<OsString>,
        }

        impl Drop for EnvRestore {
            fn drop(&mut self) {
                if let Some(value) = &self.force_prev {
                    std::env::set_var(super::SIMD_XOR_FORCE_ENV, value);
                } else {
                    std::env::remove_var(super::SIMD_XOR_FORCE_ENV);
                }
                if let Some(value) = &self.disable_prev {
                    std::env::set_var(super::SIMD_XOR_DISABLE_ENV, value);
                } else {
                    std::env::remove_var(super::SIMD_XOR_DISABLE_ENV);
                }
            }
        }

        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _env_guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("simd xor env lock poisoned");

        let _restore = EnvRestore {
            force_prev: std::env::var_os(super::SIMD_XOR_FORCE_ENV),
            disable_prev: std::env::var_os(super::SIMD_XOR_DISABLE_ENV),
        };

        if force {
            std::env::set_var(super::SIMD_XOR_FORCE_ENV, "1");
        } else {
            std::env::remove_var(super::SIMD_XOR_FORCE_ENV);
        }

        if disable {
            std::env::set_var(super::SIMD_XOR_DISABLE_ENV, "1");
        } else {
            std::env::remove_var(super::SIMD_XOR_DISABLE_ENV);
        }

        f()
    }

    #[cfg(feature = "threaded-interp")]
    fn with_threaded_interp_env<R>(enabled: bool, f: impl FnOnce() -> R) -> R {
        use std::ffi::OsString;
        use std::sync::{Mutex, OnceLock};

        struct EnvRestore {
            prev: Option<OsString>,
        }

        impl Drop for EnvRestore {
            fn drop(&mut self) {
                if let Some(value) = &self.prev {
                    std::env::set_var(super::THREADED_INTERP_ENV, value);
                } else {
                    std::env::remove_var(super::THREADED_INTERP_ENV);
                }
            }
        }

        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _env_guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("threaded interp env lock poisoned");

        let _restore = EnvRestore {
            prev: std::env::var_os(super::THREADED_INTERP_ENV),
        };

        if enabled {
            std::env::set_var(super::THREADED_INTERP_ENV, "1");
        } else {
            std::env::remove_var(super::THREADED_INTERP_ENV);
        }

        f()
    }

    fn test_vm() -> RandomXVm {
        let cfg = RandomXConfig::new();
        let cache = RandomXCache::new_dummy(&cfg);
        let flags = RandomXFlags::default();
        RandomXVm::new_light(cache, cfg, flags).expect("vm")
    }

    #[test]
    fn isub_r_src_eq_dst_uses_imm() {
        let mut vm = test_vm();
        vm.r[0] = 10;
        vm.program = vec![Instruction::new(InstructionKind::ISubR, 0, 0, 0, 3)];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        assert_eq!(vm.r[0], 7);
    }

    #[test]
    fn iadd_rs_r5_adds_imm32() {
        let mut vm = test_vm();
        vm.r[5] = 1;
        vm.r[2] = 4;
        vm.program = vec![Instruction::new(
            InstructionKind::IAddRs,
            5,
            2,
            0b00_01_00,
            5,
        )];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        // r5 + (r2 << 1) + imm
        assert_eq!(vm.r[5], 1 + (4 << 1) + 5);
    }

    #[test]
    fn cfround_sets_fprc() {
        let mut vm = test_vm();
        vm.r[0] = 0b1011;
        vm.program = vec![Instruction::new(InstructionKind::CFround, 0, 0, 0, 1)];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        let rot = vm.r[0].rotate_right(1);
        assert_eq!(vm.fprc, (rot & 3) as u32);
    }

    #[test]
    fn cfround_rotation_edges() {
        let mut vm = test_vm();
        vm.r[0] = 0b1001;
        let expected_zero = (vm.r[0] & 3) as u32;

        vm.fprc = 0;
        vm.program = vec![Instruction::new(InstructionKind::CFround, 0, 0, 0, 0)];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        assert_eq!(vm.fprc, expected_zero);

        vm.fprc = 0;
        vm.program = vec![Instruction::new(InstructionKind::CFround, 0, 0, 0, 64)];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        assert_eq!(vm.fprc, expected_zero);

        vm.fprc = 0;
        vm.program = vec![Instruction::new(InstructionKind::CFround, 0, 0, 0, 63)];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        vm.execute_instruction(0, &mut last, &mut rounding);
        let rot = vm.r[0].rotate_right(63);
        assert_eq!(vm.fprc, (rot & 3) as u32);
    }

    #[test]
    fn cbranch_jump_offset_edges() {
        let cfg = RandomXConfig::new();
        let imm = 0x1234_5678;

        for mod_cond in [0u8, 15u8] {
            let instr = Instruction::new(InstructionKind::CBranch, 0, 0, mod_cond << 4, imm);
            let b = instr.mod_cond() as u32 + cfg.jump_offset();
            let cimm = super::cbranch_cimm(instr.imm, b);

            let mut vm = test_vm();
            vm.r[0] = 0;
            vm.program = vec![instr];
            let mut last = [-1; 8];
            last[0] = 1;
            let mut rounding = RoundingModeState::new(vm.fprc);
            let target = vm.execute_instruction(0, &mut last, &mut rounding);
            assert_eq!(target, None, "mod_cond {mod_cond} should not jump");

            let mut vm = test_vm();
            vm.r[0] = 0u64.wrapping_sub(cimm);
            vm.program = vec![instr];
            let mut last = [-1; 8];
            last[0] = 1;
            let mut rounding = RoundingModeState::new(vm.fprc);
            let target = vm.execute_instruction(0, &mut last, &mut rounding);
            assert_eq!(target, Some(2), "mod_cond {mod_cond} should jump");
        }
    }

    #[test]
    fn cbranch_cimm_boundary_bits() {
        let imm = 0x89ab_cdef;
        let cimm_b0 = super::cbranch_cimm(imm, 0);
        assert_eq!(cimm_b0 & 1, 1);

        let cimm_b1 = super::cbranch_cimm(imm, 1);
        assert_eq!(cimm_b1 & 1, 0);
        assert_eq!(cimm_b1 & 2, 2);

        let cimm_b63 = super::cbranch_cimm(imm, 63);
        assert_eq!(cimm_b63 & (1u64 << 63), 1u64 << 63);
        assert_eq!(cimm_b63 & (1u64 << 62), 0);
    }

    #[test]
    fn cbranch_uses_last_modified_target() {
        let mut vm = test_vm();
        vm.r[0] = 0xFF00;
        vm.program = vec![Instruction::new(InstructionKind::CBranch, 0, 0, 0, 0)];
        let mut last = [-1; 8];
        last[0] = 2;
        let mut rounding = RoundingModeState::new(vm.fprc);
        let target = vm.execute_instruction(0, &mut last, &mut rounding);
        assert_eq!(target, Some(3));
        for entry in last.iter() {
            assert_eq!(*entry, 0);
        }
    }

    #[test]
    fn mem_level_read_src_eq_dst_is_l3() {
        let instr = Instruction::new(InstructionKind::IAddM, 1, 1, 0b01, 0);
        assert!(matches!(instr.mem_level_read(true), ScratchpadLevel::L3));
    }

    #[test]
    fn mem_level_read_mod_mem_zero_is_l2() {
        let instr = Instruction::new(InstructionKind::IAddM, 1, 2, 0b00, 0);
        assert!(matches!(instr.mem_level_read(true), ScratchpadLevel::L2));
    }

    #[test]
    fn mem_level_read_mod_mem_nonzero_is_l1() {
        let instr = Instruction::new(InstructionKind::IAddM, 1, 2, 0b01, 0);
        assert!(matches!(instr.mem_level_read(true), ScratchpadLevel::L1));
    }

    #[test]
    fn mem_level_write_cond_ge_14_is_l3() {
        let instr = Instruction::new(InstructionKind::IStore, 0, 1, 0b1110_0000, 0);
        assert!(matches!(instr.mem_level_write(), ScratchpadLevel::L3));
    }

    #[test]
    fn mem_level_write_mod_mem_zero_is_l2() {
        let instr = Instruction::new(InstructionKind::IStore, 0, 1, 0b0000_0000, 0);
        assert!(matches!(instr.mem_level_write(), ScratchpadLevel::L2));
    }

    #[test]
    fn mem_level_write_mod_mem_nonzero_is_l1() {
        let instr = Instruction::new(InstructionKind::IStore, 0, 1, 0b0000_0001, 0);
        assert!(matches!(instr.mem_level_write(), ScratchpadLevel::L1));
    }

    /// Comprehensive LUT validation: verify the lookup table produces correct results
    /// for ALL 256 possible mod_flags values according to RandomX specification.
    ///
    /// Memory level read rules (from RandomX spec Table 5.1.4):
    /// - If dst == src (and dst_is_r): L3
    /// - If mod_mem == 0: L2
    /// - Otherwise: L1
    #[test]
    fn mem_level_read_lut_exhaustive_validation() {
        // Helper to compute expected level per spec (without using LUT)
        fn expected_read_level(mod_flags: u8, dst_eq_src: bool) -> ScratchpadLevel {
            if dst_eq_src {
                ScratchpadLevel::L3
            } else {
                let mod_mem = mod_flags & 0x3;
                if mod_mem == 0 {
                    ScratchpadLevel::L2
                } else {
                    ScratchpadLevel::L1
                }
            }
        }

        // Test all 256 mod_flags values with dst != src
        for mod_flags in 0..=255u8 {
            let instr = Instruction::new(InstructionKind::IAddM, 1, 2, mod_flags, 0);
            let actual = instr.mem_level_read(true);
            let expected = expected_read_level(mod_flags, false);
            assert_eq!(
                actual as u8, expected as u8,
                "mem_level_read mismatch for mod_flags={:#04x} dst!=src: got {:?}, expected {:?}",
                mod_flags, actual, expected
            );
        }

        // Test all 256 mod_flags values with dst == src
        for mod_flags in 0..=255u8 {
            let instr = Instruction::new(InstructionKind::IAddM, 3, 3, mod_flags, 0);
            let actual = instr.mem_level_read(true);
            let expected = expected_read_level(mod_flags, true);
            assert_eq!(
                actual as u8, expected as u8,
                "mem_level_read mismatch for mod_flags={:#04x} dst==src: got {:?}, expected {:?}",
                mod_flags, actual, expected
            );
        }

        // Test all dst/src register combinations (0-7) to ensure register comparison works
        for mod_flags in [0u8, 1, 2, 3, 0x10, 0x80, 0xE0, 0xFF] {
            for dst in 0..8usize {
                for src in 0..8usize {
                    let instr = Instruction::new(InstructionKind::IAddM, dst, src, mod_flags, 0);
                    let actual = instr.mem_level_read(true);
                    let expected = expected_read_level(mod_flags, dst == src);
                    assert_eq!(
                        actual as u8, expected as u8,
                        "mem_level_read mismatch for mod={:#04x} dst={} src={}: got {:?}, expected {:?}",
                        mod_flags, dst, src, actual, expected
                    );
                }
            }
        }
    }

    /// Comprehensive LUT validation for write operations.
    ///
    /// Memory level write rules (from RandomX spec Table 5.1.4):
    /// - If mod_cond >= 14: L3
    /// - If mod_mem == 0: L2
    /// - Otherwise: L1
    #[test]
    fn mem_level_write_lut_exhaustive_validation() {
        // Helper to compute expected level per spec (without using LUT)
        fn expected_write_level(mod_flags: u8) -> ScratchpadLevel {
            let mod_cond = (mod_flags >> 4) & 0xF;
            let mod_mem = mod_flags & 0x3;
            if mod_cond >= 14 {
                ScratchpadLevel::L3
            } else if mod_mem == 0 {
                ScratchpadLevel::L2
            } else {
                ScratchpadLevel::L1
            }
        }

        // Test all 256 mod_flags values
        for mod_flags in 0..=255u8 {
            let instr = Instruction::new(InstructionKind::IStore, 0, 1, mod_flags, 0);
            let actual = instr.mem_level_write();
            let expected = expected_write_level(mod_flags);
            assert_eq!(
                actual as u8, expected as u8,
                "mem_level_write mismatch for mod_flags={:#04x}: got {:?}, expected {:?}",
                mod_flags, actual, expected
            );
        }

        // Verify boundary conditions for mod_cond
        // mod_cond is bits 4-7, so mod_cond=14 starts at mod_flags=0xE0
        for base in 0..16u8 {
            // mod_cond = 13 (0xD0..0xDF) should NOT be L3
            let mod_flags_13 = 0xD0 | base;
            let instr13 = Instruction::new(InstructionKind::IStore, 0, 1, mod_flags_13, 0);
            assert!(
                !matches!(instr13.mem_level_write(), ScratchpadLevel::L3),
                "mod_cond=13 should not produce L3, got L3 for mod_flags={:#04x}",
                mod_flags_13
            );

            // mod_cond = 14 (0xE0..0xEF) should be L3
            let mod_flags_14 = 0xE0 | base;
            let instr14 = Instruction::new(InstructionKind::IStore, 0, 1, mod_flags_14, 0);
            assert!(
                matches!(instr14.mem_level_write(), ScratchpadLevel::L3),
                "mod_cond=14 should produce L3, got {:?} for mod_flags={:#04x}",
                instr14.mem_level_write(),
                mod_flags_14
            );

            // mod_cond = 15 (0xF0..0xFF) should be L3
            let mod_flags_15 = 0xF0 | base;
            let instr15 = Instruction::new(InstructionKind::IStore, 0, 1, mod_flags_15, 0);
            assert!(
                matches!(instr15.mem_level_write(), ScratchpadLevel::L3),
                "mod_cond=15 should produce L3, got {:?} for mod_flags={:#04x}",
                instr15.mem_level_write(),
                mod_flags_15
            );
        }
    }

    /// Verify that the LUT entries are actually computed correctly at compile time.
    /// This test directly inspects the LUT arrays.
    #[test]
    fn mem_level_lut_static_entries_correct() {
        // Verify read LUT structure
        // Index [mod_flags][dst_eq_src]: [0] = dst != src, [1] = dst == src
        for mod_flags in 0..=255u8 {
            let entry = Instruction::MEM_LEVEL_READ_LUT[mod_flags as usize];
            let mod_mem = mod_flags & 0x3;

            // [1] should always be L3 (dst == src case)
            assert_eq!(
                entry[1] as u8,
                ScratchpadLevel::L3 as u8,
                "READ_LUT[{}][1] should be L3",
                mod_flags
            );

            // [0] depends on mod_mem
            let expected_0 = if mod_mem == 0 {
                ScratchpadLevel::L2
            } else {
                ScratchpadLevel::L1
            };
            assert_eq!(
                entry[0] as u8, expected_0 as u8,
                "READ_LUT[{}][0] mismatch",
                mod_flags
            );
        }

        // Verify write LUT structure
        for mod_flags in 0..=255u8 {
            let actual = Instruction::MEM_LEVEL_WRITE_LUT[mod_flags as usize];
            let mod_cond = (mod_flags >> 4) & 0xF;
            let mod_mem = mod_flags & 0x3;

            let expected = if mod_cond >= 14 {
                ScratchpadLevel::L3
            } else if mod_mem == 0 {
                ScratchpadLevel::L2
            } else {
                ScratchpadLevel::L1
            };

            assert_eq!(
                actual as u8, expected as u8,
                "WRITE_LUT[{}] mismatch",
                mod_flags
            );
        }
    }

    #[test]
    fn scratchpad_iteration_layout_is_stable() {
        let cfg = RandomXConfig::test_small();
        let cache = RandomXCache::new_dummy(&cfg);
        let flags = RandomXFlags::default();
        let mut vm = RandomXVm::new_light(cache, cfg, flags).expect("vm");

        let seed = [0x42u8; 64];
        let mut gen = AesGenerator1R::new(seed);
        fill_scratchpad(vm.scratchpad.as_mut_slice(), &mut gen, &vm.flags);

        for i in 0..8 {
            vm.r[i] = 0x0123_4567_89ab_cdefu64.wrapping_add((i as u64) * 0x1111_1111_1111_1111);
        }
        vm.read_regs = [0, 1, 2, 3];
        vm.e_mask_low = EMask {
            fraction: 0x15555,
            exponent: 0x5,
        };
        vm.e_mask_high = EMask {
            fraction: 0x2aaaa,
            exponent: 0x9,
        };

        let mut sp_addr0 = 0x40u32;
        let mut sp_addr1 = 0x80u32;
        vm.prepare_iteration(&mut sp_addr0, &mut sp_addr1);
        for i in 0..4 {
            vm.f[i].xor_inplace(vm.e[i]);
        }
        let regs = vm.r;
        vm.write_scratchpad64(sp_addr1 as u64, &regs);
        vm.write_scratchpad_fp(sp_addr0 as u64);

        let digest = hash256(vm.scratchpad.as_slice());
        assert_eq!(
            hex(&digest),
            "716ba8c5a3db1a7883eda06044cf595d24d3378bca26fa2db10efadf8e8a6ab8"
        );
    }

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    #[test]
    fn simd_prepare_finish_matches_scalar() {
        if !super::simd_block_io::has_avx2() {
            eprintln!("simd_prepare_finish_matches_scalar skipped: AVX2 unavailable");
            return;
        }

        let cfg = RandomXConfig::test_small();
        let mut vm_simd = RandomXVm::new_light(
            RandomXCache::new_dummy(&cfg),
            cfg.clone(),
            RandomXFlags::default(),
        )
        .expect("vm simd");
        let mut vm_scalar = RandomXVm::new_light(
            RandomXCache::new_dummy(&cfg),
            cfg.clone(),
            RandomXFlags::default(),
        )
        .expect("vm scalar");

        vm_simd.simd_blockio_avx2 = true;
        vm_scalar.simd_blockio_avx2 = false;

        let seed = [0x24u8; 64];
        let mut gen1_simd = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_simd.scratchpad.as_mut_slice(),
            &mut gen1_simd,
            &vm_simd.flags,
        );
        let mut gen1_scalar = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_scalar.scratchpad.as_mut_slice(),
            &mut gen1_scalar,
            &vm_scalar.flags,
        );

        let mut gen4_simd = AesGenerator4R::new(gen1_simd.state());
        let mut gen4_scalar = AesGenerator4R::new(gen1_scalar.state());
        vm_simd.program_vm(&mut gen4_simd);
        vm_scalar.program_vm(&mut gen4_scalar);
        assert_eq!(vm_simd.program_bytes, vm_scalar.program_bytes);

        vm_simd.r = [0u64; 8];
        vm_scalar.r = [0u64; 8];
        let mut sp_addr0_simd = vm_simd.mx;
        let mut sp_addr1_simd = vm_simd.ma;
        let mut sp_addr0_scalar = vm_scalar.mx;
        let mut sp_addr1_scalar = vm_scalar.ma;

        for _ in 0..3 {
            vm_simd.prepare_iteration(&mut sp_addr0_simd, &mut sp_addr1_simd);
            vm_scalar.prepare_iteration(&mut sp_addr0_scalar, &mut sp_addr1_scalar);
            vm_simd.execute_program_interpreter();
            vm_scalar.execute_program_interpreter();
            vm_simd.finish_iteration(&mut sp_addr0_simd, &mut sp_addr1_simd);
            vm_scalar.finish_iteration(&mut sp_addr0_scalar, &mut sp_addr1_scalar);
        }

        assert_eq!(vm_simd.r, vm_scalar.r);
        assert_eq!(vm_simd.mx, vm_scalar.mx);
        assert_eq!(vm_simd.ma, vm_scalar.ma);
        for i in 0..4 {
            assert_eq!(vm_simd.f[i].lo.to_bits(), vm_scalar.f[i].lo.to_bits());
            assert_eq!(vm_simd.f[i].hi.to_bits(), vm_scalar.f[i].hi.to_bits());
            assert_eq!(vm_simd.e[i].lo.to_bits(), vm_scalar.e[i].lo.to_bits());
            assert_eq!(vm_simd.e[i].hi.to_bits(), vm_scalar.e[i].hi.to_bits());
        }
        assert_eq!(
            hash256(vm_simd.scratchpad.as_slice()),
            hash256(vm_scalar.scratchpad.as_slice())
        );
    }

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    #[test]
    fn simd_blockio_blocked_cpu_classifier_targets_xeon_model_45() {
        assert!(super::simd_blockio_is_blocked_cpu(b"GenuineIntel", 6, 45));
        assert!(!super::simd_blockio_is_blocked_cpu(b"GenuineIntel", 6, 85));
        assert!(!super::simd_blockio_is_blocked_cpu(b"AuthenticAMD", 23, 8));
    }

    #[cfg(all(feature = "simd-blockio", target_arch = "x86_64"))]
    #[test]
    fn simd_blockio_disable_env_overrides_force_env() {
        if !super::simd_block_io::has_avx2() {
            eprintln!("simd_blockio_disable_env_overrides_force_env skipped: AVX2 unavailable");
            return;
        }

        with_simd_blockio_env(true, true, || {
            assert!(!super::simd_blockio_runtime_enabled());
        });
    }

    #[cfg(all(feature = "simd-xor-paths", target_arch = "x86_64"))]
    #[test]
    fn simd_xor_disable_env_overrides_force_env() {
        if !super::simd_block_io::has_avx2() {
            eprintln!("simd_xor_disable_env_overrides_force_env skipped: AVX2 unavailable");
            return;
        }

        with_simd_xor_env(true, true, || {
            assert!(!super::simd_xor_runtime_enabled());
        });
    }

    #[cfg(feature = "threaded-interp")]
    #[test]
    fn threaded_interp_env_is_read_per_vm_construction() {
        let cfg = RandomXConfig::test_small();
        let flags = RandomXFlags::default();

        with_threaded_interp_env(false, || {
            let vm =
                RandomXVm::new_light(RandomXCache::new_dummy(&cfg), cfg.clone(), flags.clone())
                    .expect("vm off");
            assert!(!vm.threaded_interp_active);
        });

        with_threaded_interp_env(true, || {
            let vm =
                RandomXVm::new_light(RandomXCache::new_dummy(&cfg), cfg.clone(), flags.clone())
                    .expect("vm on");
            assert!(vm.threaded_interp_active);
        });
    }

    #[cfg(all(
        feature = "simd-blockio",
        feature = "simd-xor-paths",
        target_arch = "x86_64"
    ))]
    #[test]
    fn simd_xor_finish_matches_scalar() {
        if !super::simd_block_io::has_avx2() {
            eprintln!("simd_xor_finish_matches_scalar skipped: AVX2 unavailable");
            return;
        }

        let cfg = RandomXConfig::test_small();
        let mut vm_simd = RandomXVm::new_light(
            RandomXCache::new_dummy(&cfg),
            cfg.clone(),
            RandomXFlags::default(),
        )
        .expect("vm simd");
        let mut vm_scalar = RandomXVm::new_light(
            RandomXCache::new_dummy(&cfg),
            cfg.clone(),
            RandomXFlags::default(),
        )
        .expect("vm scalar");

        // Isolate XOR-path parity by forcing scalar block I/O in both variants.
        vm_simd.simd_blockio_avx2 = false;
        vm_scalar.simd_blockio_avx2 = false;
        vm_simd.simd_xor_avx2 = true;
        vm_scalar.simd_xor_avx2 = false;

        let seed = [0x5au8; 64];
        let mut gen1_simd = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_simd.scratchpad.as_mut_slice(),
            &mut gen1_simd,
            &vm_simd.flags,
        );
        let mut gen1_scalar = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_scalar.scratchpad.as_mut_slice(),
            &mut gen1_scalar,
            &vm_scalar.flags,
        );

        let mut gen4_simd = AesGenerator4R::new(gen1_simd.state());
        let mut gen4_scalar = AesGenerator4R::new(gen1_scalar.state());
        vm_simd.program_vm(&mut gen4_simd);
        vm_scalar.program_vm(&mut gen4_scalar);
        assert_eq!(vm_simd.program_bytes, vm_scalar.program_bytes);

        vm_simd.r = [0u64; 8];
        vm_scalar.r = [0u64; 8];
        let mut sp_addr0_simd = vm_simd.mx;
        let mut sp_addr1_simd = vm_simd.ma;
        let mut sp_addr0_scalar = vm_scalar.mx;
        let mut sp_addr1_scalar = vm_scalar.ma;

        for _ in 0..3 {
            vm_simd.prepare_iteration(&mut sp_addr0_simd, &mut sp_addr1_simd);
            vm_scalar.prepare_iteration(&mut sp_addr0_scalar, &mut sp_addr1_scalar);
            vm_simd.execute_program_interpreter();
            vm_scalar.execute_program_interpreter();
            vm_simd.finish_iteration(&mut sp_addr0_simd, &mut sp_addr1_simd);
            vm_scalar.finish_iteration(&mut sp_addr0_scalar, &mut sp_addr1_scalar);
        }

        assert_eq!(vm_simd.r, vm_scalar.r);
        assert_eq!(vm_simd.mx, vm_scalar.mx);
        assert_eq!(vm_simd.ma, vm_scalar.ma);
        for i in 0..4 {
            assert_eq!(vm_simd.f[i].lo.to_bits(), vm_scalar.f[i].lo.to_bits());
            assert_eq!(vm_simd.f[i].hi.to_bits(), vm_scalar.f[i].hi.to_bits());
            assert_eq!(vm_simd.e[i].lo.to_bits(), vm_scalar.e[i].lo.to_bits());
            assert_eq!(vm_simd.e[i].hi.to_bits(), vm_scalar.e[i].hi.to_bits());
        }
        assert_eq!(
            hash256(vm_simd.scratchpad.as_slice()),
            hash256(vm_scalar.scratchpad.as_slice())
        );
    }

    #[test]
    fn cbranch_jump_when_mask_zero() {
        let mut vm = test_vm();
        vm.r[0] = 0xffff_ffff_ffff_ff00;
        vm.program = vec![Instruction::new(InstructionKind::CBranch, 0, 0, 0, 0)];
        let mut last = [-1; 8];
        let mut rounding = RoundingModeState::new(vm.fprc);
        let target = vm.execute_instruction(0, &mut last, &mut rounding);
        assert_eq!(target, Some(0));
        for entry in last.iter() {
            assert_eq!(*entry, 0);
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    #[allow(deprecated)]
    fn rounding_guard_updates_mxcsr() {
        use core::arch::x86_64::_mm_getcsr;
        let before = unsafe { _mm_getcsr() };
        {
            let _guard = super::RoundingModeGuard::new(2);
            let current = unsafe { _mm_getcsr() };
            assert_eq!((current >> 13) & 0x3, 2);
        }
        let after = unsafe { _mm_getcsr() };
        assert_eq!(after, before);
    }

    fn hex(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(LUT[(b >> 4) as usize] as char);
            out.push(LUT[(b & 0x0f) as usize] as char);
        }
        out
    }

    /// Helper: decode config words using the fast (chunks_exact) method.
    fn decode_config_words_fast(bytes: &[u8]) -> [u64; 16] {
        let mut config_words = [0u64; 16];
        for (word, chunk) in config_words.iter_mut().zip(bytes[..128].chunks_exact(8)) {
            let chunk: &[u8; 8] = chunk.try_into().expect("config word chunk");
            *word = u64::from_le_bytes(*chunk);
        }
        config_words
    }

    /// Helper: decode config words using the fallback (copy) method.
    fn decode_config_words_fallback(bytes: &[u8]) -> [u64; 16] {
        let mut config_words = [0u64; 16];
        for (i, word) in config_words.iter_mut().enumerate() {
            let offset = i * 8;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[offset..offset + 8]);
            *word = u64::from_le_bytes(buf);
        }
        config_words
    }

    /// Helper: decode instructions using the fast (chunks_exact) method.
    fn decode_instructions_fast(
        bytes: &[u8],
        opcode_table: &[InstructionKind; 256],
    ) -> Vec<Instruction> {
        let mut program = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            let chunk: &[u8; 8] = chunk.try_into().expect("instruction chunk");
            let word = u64::from_le_bytes(*chunk);
            program.push(Instruction::decode(word, opcode_table));
        }
        program
    }

    /// Helper: decode instructions using the fallback (copy) method.
    fn decode_instructions_fallback(
        bytes: &[u8],
        opcode_table: &[InstructionKind; 256],
    ) -> Vec<Instruction> {
        let count = bytes.len() / 8;
        let mut program = Vec::with_capacity(count);
        let mut offset = 0;
        for _ in 0..count {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[offset..offset + 8]);
            let word = u64::from_le_bytes(buf);
            program.push(Instruction::decode(word, opcode_table));
            offset += 8;
        }
        program
    }

    /// Verify that both config word decode implementations produce identical results.
    #[test]
    fn decode_config_words_fast_matches_fallback() {
        // Test with deterministic byte patterns
        let test_patterns: &[&[u8; 128]] = &[
            &[0u8; 128],
            &[0xFFu8; 128],
            &{
                let mut arr = [0u8; 128];
                for (i, b) in arr.iter_mut().enumerate() {
                    *b = i as u8;
                }
                arr
            },
            &{
                let mut arr = [0u8; 128];
                for (i, b) in arr.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(17).wrapping_add(53);
                }
                arr
            },
        ];

        for (pattern_idx, bytes) in test_patterns.iter().enumerate() {
            let fast = decode_config_words_fast(*bytes);
            let fallback = decode_config_words_fallback(*bytes);

            for i in 0..16 {
                assert_eq!(
                    fast[i], fallback[i],
                    "Config word {} mismatch in pattern {}: fast={:#018x} fallback={:#018x}",
                    i, pattern_idx, fast[i], fallback[i]
                );
            }
        }
    }

    /// Verify that both instruction decode implementations produce identical results.
    #[test]
    fn decode_instructions_fast_matches_fallback() {
        use crate::config::RandomXConfig;
        let cfg = RandomXConfig::default();
        let opcode_table = build_opcode_table(cfg.instruction_frequencies());

        // Generate test bytes covering various instruction patterns
        let test_sizes = [8, 64, 256, 2048]; // 1, 8, 32, 256 instructions

        for &size in &test_sizes {
            let bytes: Vec<u8> = (0..size)
                .map(|i| ((i as u8).wrapping_mul(31)).wrapping_add(i as u8))
                .collect();

            let fast = decode_instructions_fast(&bytes, &opcode_table);
            let fallback = decode_instructions_fallback(&bytes, &opcode_table);

            assert_eq!(
                fast.len(),
                fallback.len(),
                "Instruction count mismatch for size {}: fast={} fallback={}",
                size,
                fast.len(),
                fallback.len()
            );

            for (i, (f, b)) in fast.iter().zip(fallback.iter()).enumerate() {
                assert_eq!(
                    f.kind as u8, b.kind as u8,
                    "Instruction {} kind mismatch: fast={:?} fallback={:?}",
                    i, f.kind, b.kind
                );
                assert_eq!(
                    f.dst, b.dst,
                    "Instruction {} dst mismatch: fast={} fallback={}",
                    i, f.dst, b.dst
                );
                assert_eq!(
                    f.src, b.src,
                    "Instruction {} src mismatch: fast={} fallback={}",
                    i, f.src, b.src
                );
                assert_eq!(
                    f.mod_flags, b.mod_flags,
                    "Instruction {} mod_flags mismatch: fast={:#04x} fallback={:#04x}",
                    i, f.mod_flags, b.mod_flags
                );
                assert_eq!(
                    f.imm, b.imm,
                    "Instruction {} imm mismatch: fast={:#010x} fallback={:#010x}",
                    i, f.imm, b.imm
                );
            }
        }
    }

    /// Verify instruction decode extracts all fields correctly.
    #[test]
    fn instruction_decode_field_extraction() {
        use crate::config::RandomXConfig;
        let cfg = RandomXConfig::default();
        let opcode_table = build_opcode_table(cfg.instruction_frequencies());

        // Test specific bit patterns to verify field extraction
        // Actual instruction layout (from Instruction::decode):
        //   opcode:    bits 0-7   (word as u8)
        //   dst:       bits 8-10  ((word >> 8) & 0x7)
        //   src:       bits 16-18 ((word >> 16) & 0x7)
        //   mod_flags: bits 24-31 ((word >> 24) & 0xFF)
        //   imm:       bits 32-63 ((word >> 32))
        let test_cases: &[(u64, u8, usize, usize, u8, u32)] = &[
            // (word, expected_opcode, dst, src, mod_flags, imm)
            (0x0000_0000_0000_0000, 0x00, 0, 0, 0x00, 0x0000_0000),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFF, 7, 7, 0xFF, 0xFFFF_FFFF),
            // 0x1234_5678_9ABC_DEF0: opcode=0xF0, dst=6 (0xDE&7), src=4 (0xBC&7), mod=0x9A, imm=0x12345678
            (0x1234_5678_9ABC_DEF0, 0xF0, 6, 4, 0x9A, 0x1234_5678),
            // 0xDEAD_BEEF_CAFE_BABE: opcode=0xBE, dst=2 (0xBA&7=010), src=6 (0xFE&7=110), mod=0xCA, imm=0xDEADBEEF
            (0xDEAD_BEEF_CAFE_BABE, 0xBE, 2, 6, 0xCA, 0xDEAD_BEEF),
            // Edge cases for dst/src (3-bit fields at specific byte positions)
            (0x0000_0000_0007_0700, 0x00, 7, 7, 0x00, 0x0000_0000),
            (0x0000_0000_0001_0101, 0x01, 1, 1, 0x00, 0x0000_0000),
        ];

        for &(word, _opcode, expected_dst, expected_src, expected_mod, expected_imm) in test_cases {
            let instr = Instruction::decode(word, &opcode_table);

            assert_eq!(
                instr.dst, expected_dst,
                "dst mismatch for word {:#018x}: got {} expected {}",
                word, instr.dst, expected_dst
            );
            assert_eq!(
                instr.src, expected_src,
                "src mismatch for word {:#018x}: got {} expected {}",
                word, instr.src, expected_src
            );
            assert_eq!(
                instr.mod_flags, expected_mod,
                "mod_flags mismatch for word {:#018x}: got {:#04x} expected {:#04x}",
                word, instr.mod_flags, expected_mod
            );
            assert_eq!(
                instr.imm, expected_imm,
                "imm mismatch for word {:#018x}: got {:#010x} expected {:#010x}",
                word, instr.imm, expected_imm
            );
        }
    }

    /// Integration test: verify full program decode produces stable results.
    #[test]
    fn program_decode_deterministic() {
        use crate::cache::RandomXCache;
        use crate::config::RandomXConfig;
        use crate::flags::RandomXFlags;

        let cfg = RandomXConfig::test_small();
        let cache = RandomXCache::new_dummy(&cfg);
        let flags = RandomXFlags::default();
        let mut vm = RandomXVm::new_light(cache, cfg, flags).expect("vm");

        // Use deterministic seed
        let seed = [0x42u8; 64];
        let mut gen4 = AesGenerator4R::new(seed);

        // Program the VM
        vm.program_vm(&mut gen4);

        // Verify program was decoded
        assert!(!vm.program.is_empty());
        assert_eq!(vm.program.len(), vm.cfg.program_size() as usize);

        // Compute a simple checksum of the decoded program for stability
        let mut checksum: u64 = 0;
        for (i, instr) in vm.program.iter().enumerate() {
            checksum = checksum.wrapping_add((instr.kind as u64).wrapping_mul(i as u64 + 1));
            checksum = checksum.wrapping_add((instr.dst as u64).wrapping_mul(7));
            checksum = checksum.wrapping_add((instr.src as u64).wrapping_mul(11));
            checksum = checksum.wrapping_add((instr.mod_flags as u64).wrapping_mul(13));
            checksum = checksum.wrapping_add((instr.imm as u64).wrapping_mul(17));
        }

        // This checksum should be stable across implementations
        // Value computed from the fast-decode implementation
        assert_eq!(
            checksum, 2222472875672,
            "Program decode checksum changed - potential decode regression"
        );
    }
}

#[cfg(all(test, feature = "jit", target_arch = "x86_64"))]
mod jit_tests {
    use super::{
        fill_scratchpad, AesGenerator1R, AesGenerator4R, Instruction, InstructionKind, RandomXVm,
        RoundingModeState, VmJitContext,
    };
    use crate::blake::hash256;
    use crate::cache::RandomXCache;
    use crate::config::RandomXConfig;
    use crate::dataset::RandomXDataset;
    use crate::flags::RandomXFlags;
    use serde::Deserialize;
    use std::fmt::Write;

    #[derive(Deserialize)]
    struct ConformanceCases {
        cases: Vec<ConformanceCase>,
    }

    #[derive(Deserialize)]
    struct ConformanceCase {
        key_hex: String,
        input_hex: String,
    }

    #[derive(Deserialize)]
    struct OracleExpected {
        cases: Vec<OracleCase>,
    }

    #[derive(Deserialize)]
    struct OracleCase {
        key_hex: String,
        input_hex: String,
        mode: String,
        hash_hex: String,
    }

    fn make_vm(cfg: &RandomXConfig, jit: bool, fast_regs: bool) -> RandomXVm {
        let cache = RandomXCache::new_dummy(cfg);
        let flags = RandomXFlags {
            jit,
            jit_fast_regs: fast_regs,
            ..Default::default()
        };
        RandomXVm::new_light(cache, cfg.clone(), flags).expect("vm")
    }

    fn make_vm_with_key(cfg: &RandomXConfig, jit: bool, fast_regs: bool, key: &[u8]) -> RandomXVm {
        let cache = RandomXCache::new(key, cfg).expect("cache");
        let flags = RandomXFlags {
            jit,
            jit_fast_regs: fast_regs,
            ..Default::default()
        };
        RandomXVm::new_light(cache, cfg.clone(), flags).expect("vm")
    }

    fn load_cases() -> Vec<ConformanceCase> {
        let json = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/conformance_cases.json"
        ));
        let cases: ConformanceCases = serde_json::from_str(json).expect("parse conformance cases");
        cases.cases
    }

    fn load_oracle_expected() -> OracleExpected {
        let json = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/oracle_expected.json"
        ));
        let expected: OracleExpected = serde_json::from_str(json).expect("parse oracle expected");
        assert!(
            !expected.cases.is_empty(),
            "oracle_expected.json must contain cases"
        );
        expected
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2), "hex length must be even");
        let mut out = Vec::with_capacity(hex.len() / 2);
        let mut iter = hex.as_bytes().iter().copied();
        while let (Some(hi), Some(lo)) = (iter.next(), iter.next()) {
            out.push((from_hex(hi) << 4) | from_hex(lo));
        }
        out
    }

    fn from_hex(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }

    struct VmDigest {
        hash: [u8; 32],
        reg_hash: [u8; 32],
        scratchpad_hash: [u8; 32],
        fprc: u32,
    }

    fn digest_vm(vm: &mut RandomXVm, input: &[u8]) -> VmDigest {
        let hash = vm.hash(input);
        let reg_file = vm.register_file();
        let reg_hash = hash256(&reg_file);
        let scratchpad_hash = hash256(vm.scratchpad.as_slice());
        let fprc = vm.fprc;
        VmDigest {
            hash,
            reg_hash,
            scratchpad_hash,
            fprc,
        }
    }

    fn digest_summary(digest: &VmDigest) -> String {
        format!(
            "hash={} reg_hash={} scratchpad_hash={} fprc={}",
            bytes_to_hex(&digest.hash),
            bytes_to_hex(&digest.reg_hash),
            bytes_to_hex(&digest.scratchpad_hash),
            digest.fprc
        )
    }

    fn assert_digests_equal(label: &str, interp: &VmDigest, other: &VmDigest, variant: &str) {
        if interp.hash != other.hash
            || interp.reg_hash != other.reg_hash
            || interp.scratchpad_hash != other.scratchpad_hash
            || interp.fprc != other.fprc
        {
            panic!(
                "{variant} mismatch {label}: interp={} other={}",
                digest_summary(interp),
                digest_summary(other)
            );
        }
    }

    fn make_vm_with_key_mode(
        cfg: &RandomXConfig,
        jit: bool,
        fast_regs: bool,
        key: &[u8],
        mode: &str,
    ) -> RandomXVm {
        let cache = RandomXCache::new(key, cfg).expect("cache");
        let flags = RandomXFlags {
            jit,
            jit_fast_regs: fast_regs,
            ..Default::default()
        };
        match mode {
            "light" => RandomXVm::new_light(cache, cfg.clone(), flags).expect("vm"),
            "fast" => {
                let dataset = RandomXDataset::new(&cache, cfg, 1).expect("dataset");
                RandomXVm::new_fast(cache, dataset, cfg.clone(), flags).expect("vm")
            }
            other => panic!("unknown oracle mode {other}"),
        }
    }

    fn prepare_iteration(vm: &mut RandomXVm) {
        let mut sp_addr0 = vm.mx;
        let mut sp_addr1 = vm.ma;
        vm.r = [0u64; 8];

        let xor = vm.r[vm.read_regs[0]] ^ vm.r[vm.read_regs[1]];
        sp_addr0 ^= xor as u32;
        sp_addr1 ^= (xor >> 32) as u32;

        let sp0_block = vm.read_scratchpad64(sp_addr0 as u64);
        for i in 0..8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&sp0_block[i * 8..i * 8 + 8]);
            vm.r[i] ^= u64::from_le_bytes(bytes);
        }

        let sp1_block = vm.read_scratchpad64(sp_addr1 as u64);
        for i in 0..4 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&sp1_block[i * 8..i * 8 + 8]);
            vm.f[i] = super::FpReg::from_i32_pair(&bytes);
        }
        for i in 0..4 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&sp1_block[(4 + i) * 8..(5 + i) * 8]);
            vm.e[i] = super::FpReg::from_i32_pair_e(&bytes, &vm.e_mask_low, &vm.e_mask_high);
        }
    }

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    fn fill_random_bytes(state: &mut u64, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = (lcg_next(state) >> 56) as u8;
        }
    }

    fn make_random_program(
        len: usize,
        state: &mut u64,
        table: &[InstructionKind; 256],
    ) -> (Vec<Instruction>, Vec<u8>) {
        let mut bytes = vec![0u8; 128 + len * 8];
        fill_random_bytes(state, &mut bytes);
        let mut program = Vec::with_capacity(len);
        for chunk in bytes[128..].chunks_exact(8) {
            let chunk: &[u8; 8] = chunk.try_into().expect("program chunk");
            let word = u64::from_le_bytes(*chunk);
            program.push(Instruction::decode(word, table));
        }
        (program, bytes)
    }

    fn run_program_interpreter(vm: &mut RandomXVm, last_modified: &mut [i32; 8]) {
        let mut rounding = RoundingModeState::new(vm.fprc);
        let mut ip = 0usize;
        while ip < vm.program.len() {
            if let Some(target) = vm.execute_instruction(ip, last_modified, &mut rounding) {
                ip = target;
            } else {
                ip += 1;
            }
        }
    }

    fn run_program_jit(
        vm: &mut RandomXVm,
        program: &super::jit::JitProgram,
        last_modified: &mut [i32; 8],
    ) {
        let mut ctx = VmJitContext::new(vm);
        ctx.program_iters = 0;
        ctx.sp_addr0 = 0;
        ctx.sp_addr1 = 0;
        ctx.last_modified = *last_modified;
        unsafe {
            program.exec(&mut ctx);
        }
        vm.fprc = ctx.fprc;
        *last_modified = ctx.last_modified;
    }

    const VALIDATE_ITERS: u32 = 3;
    const VALIDATE_SEEDS: [u64; 2] = [0x9e37_79b9_7f4a_7c15, 0x6a09_e667_f3bc_c909];

    fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }

    fn seed_bytes(seed: u64) -> [u8; 64] {
        let mut state = seed;
        let mut out = [0u8; 64];
        fill_random_bytes(&mut state, &mut out);
        out
    }

    fn init_vm_for_seed(vm: &mut RandomXVm, seed: u64) {
        let seed = seed_bytes(seed);
        let mut gen1 = AesGenerator1R::new(seed);
        fill_scratchpad(vm.scratchpad.as_mut_slice(), &mut gen1, &vm.flags);
        let gen4_seed = gen1.state();
        let mut gen4 = AesGenerator4R::new(gen4_seed);
        vm.program_vm(&mut gen4);
    }

    fn scratchpad_first_diff(
        left: &RandomXVm,
        right: &RandomXVm,
    ) -> Option<(usize, String, String)> {
        let left_bytes = left.scratchpad.as_slice();
        let right_bytes = right.scratchpad.as_slice();
        if left_bytes.len() != right_bytes.len() {
            return Some((
                0,
                format!("len={}", left_bytes.len()),
                format!("len={}", right_bytes.len()),
            ));
        }
        let mut idx = 0usize;
        while idx < left_bytes.len() {
            if left_bytes[idx] != right_bytes[idx] {
                let end = (idx + 16).min(left_bytes.len());
                let left_hex = bytes_to_hex(&left_bytes[idx..end]);
                let right_hex = bytes_to_hex(&right_bytes[idx..end]);
                return Some((idx, left_hex, right_hex));
            }
            idx += 1;
        }
        None
    }

    fn diff_vm_state(left: &RandomXVm, right: &RandomXVm) -> Option<String> {
        for idx in 0..left.r.len() {
            if left.r[idx] != right.r[idx] {
                return Some(format!(
                    "r[{idx}] {:#018x} != {:#018x}",
                    left.r[idx], right.r[idx]
                ));
            }
        }
        for idx in 0..left.f.len() {
            let left_lo = left.f[idx].lo.to_bits();
            let right_lo = right.f[idx].lo.to_bits();
            if left_lo != right_lo {
                return Some(format!("f[{idx}].lo 0x{left_lo:016x} != 0x{right_lo:016x}"));
            }
            let left_hi = left.f[idx].hi.to_bits();
            let right_hi = right.f[idx].hi.to_bits();
            if left_hi != right_hi {
                return Some(format!("f[{idx}].hi 0x{left_hi:016x} != 0x{right_hi:016x}"));
            }
        }
        for idx in 0..left.e.len() {
            let left_lo = left.e[idx].lo.to_bits();
            let right_lo = right.e[idx].lo.to_bits();
            if left_lo != right_lo {
                return Some(format!("e[{idx}].lo 0x{left_lo:016x} != 0x{right_lo:016x}"));
            }
            let left_hi = left.e[idx].hi.to_bits();
            let right_hi = right.e[idx].hi.to_bits();
            if left_hi != right_hi {
                return Some(format!("e[{idx}].hi 0x{left_hi:016x} != 0x{right_hi:016x}"));
            }
        }
        if left.fprc != right.fprc {
            return Some(format!("fprc {} != {}", left.fprc, right.fprc));
        }
        if left.mx != right.mx || left.ma != right.ma {
            return Some(format!(
                "mx/ma 0x{:08x}/0x{:08x} != 0x{:08x}/0x{:08x}",
                left.mx, left.ma, right.mx, right.ma
            ));
        }
        let hash_left = hash256(left.scratchpad.as_slice());
        let hash_right = hash256(right.scratchpad.as_slice());
        if hash_left != hash_right {
            let (offset, left_hex, right_hex) = scratchpad_first_diff(left, right).unwrap_or((
                0,
                "<no-diff>".to_string(),
                "<no-diff>".to_string(),
            ));
            return Some(format!(
                "scratchpad hash {} != {}; first diff at {}: {} != {}",
                bytes_to_hex(&hash_left),
                bytes_to_hex(&hash_right),
                offset,
                left_hex,
                right_hex
            ));
        }
        None
    }

    fn run_iters_interpreter(vm: &mut RandomXVm, iters: u32) {
        vm.r = [0u64; 8];
        let mut sp_addr0 = vm.mx;
        let mut sp_addr1 = vm.ma;
        for _ in 0..iters {
            vm.prepare_iteration(&mut sp_addr0, &mut sp_addr1);
            vm.execute_program_interpreter();
            vm.finish_iteration(&mut sp_addr0, &mut sp_addr1);
        }
    }

    fn run_iters_lockstep(
        vm_interp: &mut RandomXVm,
        vm_jit: &mut RandomXVm,
        program: &super::jit::JitProgram,
        iters: u32,
        label: &str,
        seed: u64,
        program_idx: usize,
    ) {
        vm_interp.r = [0u64; 8];
        vm_jit.r = [0u64; 8];
        let mut sp_addr0_interp = vm_interp.mx;
        let mut sp_addr1_interp = vm_interp.ma;
        let mut sp_addr0_jit = vm_jit.mx;
        let mut sp_addr1_jit = vm_jit.ma;
        for iter in 0..iters {
            vm_interp.prepare_iteration(&mut sp_addr0_interp, &mut sp_addr1_interp);
            vm_jit.prepare_iteration(&mut sp_addr0_jit, &mut sp_addr1_jit);
            vm_interp.execute_program_interpreter();
            vm_jit.execute_program_jit(program);
            vm_interp.finish_iteration(&mut sp_addr0_interp, &mut sp_addr1_interp);
            vm_jit.finish_iteration(&mut sp_addr0_jit, &mut sp_addr1_jit);
            if let Some(diff) = diff_vm_state(vm_interp, vm_jit) {
                panic!("{label} mismatch seed={seed:#x} program={program_idx} iter={iter}: {diff}");
            }
        }
    }

    fn run_iters_jit_loop(
        vm_interp: &mut RandomXVm,
        vm_jit: &mut RandomXVm,
        program: &super::jit::JitProgram,
        iters: u32,
        label: &str,
        seed: u64,
        program_idx: usize,
    ) {
        run_iters_interpreter(vm_interp, iters);
        vm_jit.r = [0u64; 8];
        vm_jit.execute_program_jit_iters(program, iters);
        if let Some(diff) = diff_vm_state(vm_interp, vm_jit) {
            panic!("{label}-loop mismatch seed={seed:#x} program={program_idx} iter=final: {diff}");
        }
    }

    fn validate_program_iters(cfg: &RandomXConfig, seeds: &[u64], iters: u32, fast_regs: bool) {
        let label = if fast_regs { "jit-fastregs" } else { "jit" };

        for (program_idx, seed) in seeds.iter().enumerate() {
            let mut vm_interp = make_vm(cfg, false, false);
            let mut vm_jit = make_vm(cfg, true, fast_regs);
            assert!(vm_jit.is_jit_active(), "{label} requested but not active");

            init_vm_for_seed(&mut vm_interp, *seed);
            init_vm_for_seed(&mut vm_jit, *seed);
            assert_eq!(
                vm_interp.program_bytes, vm_jit.program_bytes,
                "program bytes mismatch for seed {seed:#x}"
            );

            let program = vm_jit
                .jit_engine
                .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
                .expect("jit compile");

            run_iters_lockstep(
                &mut vm_interp,
                &mut vm_jit,
                &program,
                iters,
                label,
                *seed,
                program_idx,
            );

            let mut vm_interp_loop = make_vm(cfg, false, false);
            let mut vm_jit_loop = make_vm(cfg, true, fast_regs);
            assert!(
                vm_jit_loop.is_jit_active(),
                "{label} requested but not active"
            );

            init_vm_for_seed(&mut vm_interp_loop, *seed);
            init_vm_for_seed(&mut vm_jit_loop, *seed);

            let program_loop = vm_jit_loop
                .jit_engine
                .get_or_compile(
                    &vm_jit_loop.program_bytes,
                    &vm_jit_loop.program,
                    &vm_jit_loop.flags,
                )
                .expect("jit compile");

            run_iters_jit_loop(
                &mut vm_interp_loop,
                &mut vm_jit_loop,
                &program_loop,
                iters,
                label,
                *seed,
                program_idx,
            );
        }
    }

    fn find_cbranch_r(cimm: u64, mask: u64, want_jump: bool) -> u64 {
        if mask == 0 {
            return 0;
        }
        let mut value = 0u64;
        for _ in 0..65536 {
            let jump = (value.wrapping_add(cimm) & mask) == 0;
            if jump == want_jump {
                return value;
            }
            value = value.wrapping_add(0x0001_0001_0001_0001);
        }
        panic!("unable to find cbranch input");
    }

    #[test]
    fn jit_matches_interpreter_hashes() {
        let cfg = RandomXConfig::test_small();
        let cases = load_cases();

        for case in cases.iter() {
            let key = hex_to_bytes(&case.key_hex);
            let input = hex_to_bytes(&case.input_hex);

            let mut vm_interp = make_vm_with_key(&cfg, false, false, &key);
            let mut vm_jit = make_vm_with_key(&cfg, true, false, &key);
            assert!(vm_jit.is_jit_active());

            let hash_interp = vm_interp.hash(&input);
            let hash_jit = vm_jit.hash(&input);
            assert_eq!(hash_interp, hash_jit);
        }
    }

    #[test]
    fn jit_oracle_vectors_match_interpreter_state() {
        let cfg = RandomXConfig::test_small();
        let expected = load_oracle_expected();

        for (idx, entry) in expected.cases.iter().enumerate() {
            let label = format!(
                "case {idx} mode={} key={} input={}",
                entry.mode, entry.key_hex, entry.input_hex
            );
            let key = hex_to_bytes(&entry.key_hex);
            let input = hex_to_bytes(&entry.input_hex);

            let mut vm_interp = make_vm_with_key_mode(&cfg, false, false, &key, &entry.mode);
            let mut vm_jit = make_vm_with_key_mode(&cfg, true, false, &key, &entry.mode);
            assert!(
                vm_jit.is_jit_active(),
                "jit requested but not active ({label})"
            );

            let interp_digest = digest_vm(&mut vm_interp, &input);
            assert_eq!(
                bytes_to_hex(&interp_digest.hash),
                entry.hash_hex,
                "oracle mismatch {label}"
            );
            let jit_digest = digest_vm(&mut vm_jit, &input);
            assert_digests_equal(&label, &interp_digest, &jit_digest, "jit");

            #[cfg(feature = "jit-fastregs")]
            {
                let mut vm_fast = make_vm_with_key_mode(&cfg, true, true, &key, &entry.mode);
                assert!(
                    vm_fast.is_jit_active(),
                    "jit-fastregs requested but not active ({label})"
                );
                let fast_digest = digest_vm(&mut vm_fast, &input);
                assert_digests_equal(&label, &interp_digest, &fast_digest, "jit-fastregs");
            }
        }
    }

    #[test]
    fn jit_matches_program_state() {
        let cfg = RandomXConfig::test_small();
        let mut vm_interp = make_vm(&cfg, false, false);
        let mut vm_jit = make_vm(&cfg, true, false);
        assert!(vm_jit.is_jit_active());

        let seed = [0x42u8; 64];
        let mut gen1_a = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_interp.scratchpad.as_mut_slice(),
            &mut gen1_a,
            &vm_interp.flags,
        );
        let mut gen1_b = AesGenerator1R::new(seed);
        fill_scratchpad(vm_jit.scratchpad.as_mut_slice(), &mut gen1_b, &vm_jit.flags);

        let gen4_seed = gen1_a.state();
        let mut gen4_a = AesGenerator4R::new(gen4_seed);
        let mut gen4_b = AesGenerator4R::new(gen4_seed);

        vm_interp.program_vm(&mut gen4_a);
        vm_jit.program_vm(&mut gen4_b);

        prepare_iteration(&mut vm_interp);
        prepare_iteration(&mut vm_jit);

        vm_interp.execute_program_interpreter();
        let program = vm_jit
            .jit_engine
            .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
            .expect("jit compile");
        vm_jit.execute_program_jit(&program);

        assert_eq!(vm_interp.register_file(), vm_jit.register_file());
        assert_eq!(
            hash256(vm_interp.scratchpad.as_slice()),
            hash256(vm_jit.scratchpad.as_slice())
        );
        assert_eq!(vm_interp.fprc, vm_jit.fprc);
    }

    #[test]
    fn jit_program_iters_match_interpreter_state() {
        let cfg = RandomXConfig::test_small();
        validate_program_iters(&cfg, &VALIDATE_SEEDS, VALIDATE_ITERS, false);
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_program_iters_match_interpreter_state() {
        let cfg = RandomXConfig::test_small();
        validate_program_iters(&cfg, &VALIDATE_SEEDS, VALIDATE_ITERS, true);
    }

    #[test]
    fn jit_fast_dataset_matches_interpreter_state() {
        let cfg = RandomXConfig::test_small();
        let mut key = [0u8; 32];
        for (idx, byte) in key.iter_mut().enumerate() {
            *byte = idx as u8;
        }

        let mut vm_interp = make_vm_with_key_mode(&cfg, false, false, &key, "fast");
        let mut vm_jit = make_vm_with_key_mode(&cfg, true, false, &key, "fast");
        assert!(vm_jit.is_jit_active(), "jit requested but not active");

        let seed = VALIDATE_SEEDS[0];
        init_vm_for_seed(&mut vm_interp, seed);
        init_vm_for_seed(&mut vm_jit, seed);
        assert_eq!(
            vm_interp.program_bytes, vm_jit.program_bytes,
            "program bytes mismatch for seed {seed:#x}"
        );

        let program = vm_jit
            .jit_engine
            .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
            .expect("jit compile");
        run_iters_lockstep(
            &mut vm_interp,
            &mut vm_jit,
            &program,
            3,
            "jit-fast-dataset",
            seed,
            0,
        );
    }

    fn run_random_programs(cfg: &RandomXConfig, fast_regs: bool) {
        let cases = 16usize;
        let program_len = 64usize;
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;

        for _ in 0..cases {
            let mut vm_interp = make_vm(cfg, false, false);
            let mut vm_jit = make_vm(cfg, true, fast_regs);
            assert!(vm_jit.is_jit_active());

            let seed = [0x42u8; 64];
            let mut gen1_a = AesGenerator1R::new(seed);
            fill_scratchpad(
                vm_interp.scratchpad.as_mut_slice(),
                &mut gen1_a,
                &vm_interp.flags,
            );
            let mut gen1_b = AesGenerator1R::new(seed);
            fill_scratchpad(vm_jit.scratchpad.as_mut_slice(), &mut gen1_b, &vm_jit.flags);

            let gen4_seed = gen1_a.state();
            let mut gen4_a = AesGenerator4R::new(gen4_seed);
            let mut gen4_b = AesGenerator4R::new(gen4_seed);

            vm_interp.program_vm(&mut gen4_a);
            vm_jit.program_vm(&mut gen4_b);

            let (program, program_bytes) =
                make_random_program(program_len, &mut rng, &vm_interp.opcode_table);
            vm_interp.program = program.clone();
            vm_jit.program = program;
            vm_interp.program_bytes = program_bytes.clone();
            vm_jit.program_bytes = program_bytes;

            prepare_iteration(&mut vm_interp);
            prepare_iteration(&mut vm_jit);

            let mut last_interp = [-1; 8];
            run_program_interpreter(&mut vm_interp, &mut last_interp);

            let program = vm_jit
                .jit_engine
                .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
                .expect("jit compile");
            let mut last_jit = [-1i32; 8];
            run_program_jit(&mut vm_jit, &program, &mut last_jit);

            assert_eq!(vm_interp.r, vm_jit.r);
            assert_eq!(
                hash256(vm_interp.scratchpad.as_slice()),
                hash256(vm_jit.scratchpad.as_slice())
            );
            assert_eq!(last_interp, last_jit);
            assert_eq!(vm_interp.fprc, vm_jit.fprc);
        }
    }

    #[test]
    fn jit_small_random_programs_match_interpreter() {
        let cfg = RandomXConfig::test_small();
        run_random_programs(&cfg, false);
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_small_random_programs_match_interpreter() {
        let cfg = RandomXConfig::test_small();
        run_random_programs(&cfg, true);
    }

    #[test]
    fn jit_handles_cfround_and_cbranch() {
        let cfg = RandomXConfig::test_small();
        let mut vm_interp = make_vm(&cfg, false, false);
        let mut vm_jit = make_vm(&cfg, true, false);
        assert!(vm_jit.is_jit_active());

        vm_interp.program = vec![
            Instruction::new(InstructionKind::INegR, 0, 0, 0, 0),
            Instruction::new(InstructionKind::CFround, 0, 0, 0, 1),
            Instruction::new(InstructionKind::CBranch, 0, 0, 0, 0),
        ];
        vm_jit.program = vm_interp.program.clone();
        vm_interp.program_bytes = vec![0u8; 128 + vm_interp.program.len() * 8];
        vm_jit.program_bytes = vec![0x11u8; 128 + vm_jit.program.len() * 8];
        vm_interp.r[0] = 0;
        vm_jit.r[0] = 0;

        vm_interp.execute_program_interpreter();
        let program = vm_jit
            .jit_engine
            .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
            .expect("jit compile");
        vm_jit.execute_program_jit(&program);

        assert_eq!(vm_interp.r, vm_jit.r);
        assert_eq!(vm_interp.fprc, vm_jit.fprc);
    }

    fn run_cbranch_case(cfg: &RandomXConfig, fast_regs: bool, want_jump: bool) {
        let mut vm_interp = make_vm(cfg, false, false);
        let mut vm_jit = make_vm(cfg, true, fast_regs);
        assert!(vm_jit.is_jit_active());

        let inst = Instruction::new(InstructionKind::CBranch, 0, 0, 0, 0);
        vm_interp.program = vec![inst];
        vm_jit.program = vm_interp.program.clone();
        let bytes = vec![0u8; 128 + vm_interp.program.len() * 8];
        vm_interp.program_bytes = bytes.clone();
        vm_jit.program_bytes = bytes;

        let b = inst.mod_cond() as u32 + cfg.jump_offset();
        let cimm = super::cbranch_cimm(inst.imm, b);
        let mask = ((1u64 << cfg.jump_bits()) - 1) << b;
        let r0 = find_cbranch_r(cimm, mask, want_jump);
        vm_interp.r[0] = r0;
        vm_jit.r[0] = r0;

        let mut last_interp = [-1; 8];
        last_interp[0] = 0;
        let mut last_jit = [-1i32; 8];
        last_jit[0] = 0;

        run_program_interpreter(&mut vm_interp, &mut last_interp);
        let program = vm_jit
            .jit_engine
            .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
            .expect("jit compile");
        run_program_jit(&mut vm_jit, &program, &mut last_jit);

        assert_eq!(vm_interp.r, vm_jit.r);
        assert_eq!(last_interp, last_jit);
    }

    #[cfg(feature = "jit-fastregs")]
    fn init_fastregs_float_state(vm: &mut RandomXVm, fprc: u32) {
        let seed = [0x42u8; 64];
        let mut gen = AesGenerator1R::new(seed);
        fill_scratchpad(vm.scratchpad.as_mut_slice(), &mut gen, &vm.flags);
        vm.fprc = fprc;
        for i in 0..8 {
            vm.r[i] = 0x0123_4567_89ab_cdefu64.wrapping_add((i as u64) * 0x1111_1111_1111_1111);
        }
        for i in 0..4 {
            let idx = i as f64;
            vm.f[i] = super::FpReg {
                lo: 1.25 + idx,
                hi: -2.5 - idx,
            };
            vm.e[i] = super::FpReg {
                lo: 4.0 + idx,
                hi: 9.0 + idx,
            };
            vm.a[i] = super::FpReg {
                lo: 0.5 + (idx * 0.25),
                hi: 1.5 + (idx * 0.125),
            };
        }
        vm.e_mask_low = super::EMask {
            fraction: 0x15555,
            exponent: 0x5,
        };
        vm.e_mask_high = super::EMask {
            fraction: 0x2aaaa,
            exponent: 0x9,
        };
    }

    #[cfg(feature = "jit-fastregs")]
    fn float_case_tag(instr: &Instruction, fprc: u32) -> u8 {
        let kind_tag = match instr.kind {
            InstructionKind::FSwapR => 0x11,
            InstructionKind::FAddR => 0x22,
            InstructionKind::FSubR => 0x33,
            InstructionKind::FScalR => 0x44,
            InstructionKind::FMulR => 0x55,
            InstructionKind::FSqrtR => 0x66,
            InstructionKind::FAddM => 0x77,
            InstructionKind::FSubM => 0x88,
            InstructionKind::FDivM => 0x99,
            _ => 0x0f,
        };
        kind_tag
            ^ (instr.dst as u8).wrapping_mul(3)
            ^ (instr.src as u8).wrapping_mul(5)
            ^ instr.mod_flags.wrapping_mul(7)
            ^ (instr.imm as u8)
            ^ (fprc as u8)
    }

    #[cfg(feature = "jit-fastregs")]
    fn run_fastregs_float_case(instr: Instruction, fprc: u32) {
        let cfg = RandomXConfig::test_small();
        let mut vm_interp = make_vm(&cfg, false, false);
        let mut vm_fast = make_vm(&cfg, true, true);
        assert!(vm_fast.is_jit_active());

        init_fastregs_float_state(&mut vm_interp, fprc);
        init_fastregs_float_state(&mut vm_fast, fprc);

        vm_interp.program = vec![instr];
        vm_fast.program = vm_interp.program.clone();
        let tag = float_case_tag(&instr, fprc);
        let mut bytes = vec![tag; 128 + vm_interp.program.len() * 8];
        bytes[0] = tag.wrapping_add(1);
        vm_interp.program_bytes = bytes.clone();
        vm_fast.program_bytes = bytes;

        vm_interp.execute_program_interpreter();
        let program = vm_fast
            .jit_engine
            .get_or_compile(&vm_fast.program_bytes, &vm_fast.program, &vm_fast.flags)
            .expect("jit compile");
        vm_fast.execute_program_jit(&program);

        assert_eq!(vm_interp.register_file(), vm_fast.register_file());
        assert_eq!(
            hash256(vm_interp.scratchpad.as_slice()),
            hash256(vm_fast.scratchpad.as_slice())
        );
        assert_eq!(vm_interp.fprc, vm_fast.fprc);
    }

    #[test]
    fn jit_cbranch_jump_taken_matches_interpreter() {
        let cfg = RandomXConfig::test_small();
        run_cbranch_case(&cfg, false, true);
    }

    #[test]
    fn jit_cbranch_no_jump_matches_interpreter() {
        let cfg = RandomXConfig::test_small();
        run_cbranch_case(&cfg, false, false);
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_cbranch_jump_taken_matches_interpreter() {
        let cfg = RandomXConfig::test_small();
        run_cbranch_case(&cfg, true, true);
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_cbranch_no_jump_matches_interpreter() {
        let cfg = RandomXConfig::test_small();
        run_cbranch_case(&cfg, true, false);
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_float_ops_match_interpreter() {
        let mem_mods = [0u8, 1u8];
        for fprc in 0..4u32 {
            run_fastregs_float_case(Instruction::new(InstructionKind::FSwapR, 1, 0, 0, 0), fprc);
            run_fastregs_float_case(Instruction::new(InstructionKind::FSwapR, 5, 0, 0, 0), fprc);
            run_fastregs_float_case(Instruction::new(InstructionKind::FAddR, 2, 1, 0, 0), fprc);
            run_fastregs_float_case(Instruction::new(InstructionKind::FSubR, 3, 2, 0, 0), fprc);
            run_fastregs_float_case(Instruction::new(InstructionKind::FScalR, 0, 0, 0, 0), fprc);
            run_fastregs_float_case(Instruction::new(InstructionKind::FMulR, 1, 3, 0, 0), fprc);
            run_fastregs_float_case(Instruction::new(InstructionKind::FSqrtR, 2, 0, 0, 0), fprc);
            for mod_mem in mem_mods {
                run_fastregs_float_case(
                    Instruction::new(InstructionKind::FAddM, 1, 2, mod_mem, 0x1234_5678),
                    fprc,
                );
                run_fastregs_float_case(
                    Instruction::new(InstructionKind::FSubM, 2, 3, mod_mem, 0x2345_6789),
                    fprc,
                );
                run_fastregs_float_case(
                    Instruction::new(InstructionKind::FDivM, 3, 4, mod_mem, 0x3456_789a),
                    fprc,
                );
            }
        }
    }

    #[test]
    fn jit_cfround_sequence_matches_interpreter() {
        let cfg = RandomXConfig::test_small();
        let half_ulp = f64::from_bits(0x3ca0_0000_0000_0000);
        let next_up = f64::from_bits(0x3ff0_0000_0000_0001);

        for mode in 0..4u64 {
            let mut vm_interp = make_vm(&cfg, false, false);
            let mut vm_jit = make_vm(&cfg, true, false);
            assert!(vm_jit.is_jit_active());

            vm_interp.r[0] = mode;
            vm_jit.r[0] = mode;
            vm_interp.f[0] = super::FpReg { lo: 1.0, hi: 1.0 };
            vm_jit.f[0] = vm_interp.f[0];
            vm_interp.a[0] = super::FpReg {
                lo: half_ulp,
                hi: half_ulp,
            };
            vm_jit.a[0] = vm_interp.a[0];

            vm_interp.program = vec![
                Instruction::new(InstructionKind::CFround, 0, 0, 0, 0),
                Instruction::new(InstructionKind::FAddR, 0, 0, 0, 0),
            ];
            vm_jit.program = vm_interp.program.clone();
            vm_interp.program_bytes = vec![0u8; 128 + vm_interp.program.len() * 8];
            vm_jit.program_bytes = vec![0u8; 128 + vm_jit.program.len() * 8];

            vm_interp.execute_program_interpreter();
            let program = vm_jit
                .jit_engine
                .get_or_compile(&vm_jit.program_bytes, &vm_jit.program, &vm_jit.flags)
                .expect("jit compile");
            vm_jit.execute_program_jit(&program);

            let expected = if mode == 2 { next_up } else { 1.0 };
            assert_eq!(vm_interp.f[0].lo.to_bits(), expected.to_bits());
            assert_eq!(vm_interp.f[0].hi.to_bits(), expected.to_bits());
            assert_eq!(vm_interp.f[0].lo.to_bits(), vm_jit.f[0].lo.to_bits());
            assert_eq!(vm_interp.f[0].hi.to_bits(), vm_jit.f[0].hi.to_bits());
            assert_eq!(vm_interp.fprc, vm_jit.fprc);
        }
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_cfround_sequence_matches_interpreter() {
        let cfg = RandomXConfig::test_small();
        let half_ulp = f64::from_bits(0x3ca0_0000_0000_0000);
        let next_up = f64::from_bits(0x3ff0_0000_0000_0001);

        for mode in 0..4u64 {
            let mut vm_interp = make_vm(&cfg, false, false);
            let mut vm_fast = make_vm(&cfg, true, true);
            assert!(vm_fast.is_jit_active());

            vm_interp.r[0] = mode;
            vm_fast.r[0] = mode;
            vm_interp.f[0] = super::FpReg { lo: 1.0, hi: 1.0 };
            vm_fast.f[0] = vm_interp.f[0];
            vm_interp.a[0] = super::FpReg {
                lo: half_ulp,
                hi: half_ulp,
            };
            vm_fast.a[0] = vm_interp.a[0];

            vm_interp.program = vec![
                Instruction::new(InstructionKind::CFround, 0, 0, 0, 0),
                Instruction::new(InstructionKind::FAddR, 0, 0, 0, 0),
            ];
            vm_fast.program = vm_interp.program.clone();
            vm_interp.program_bytes = vec![0u8; 128 + vm_interp.program.len() * 8];
            vm_fast.program_bytes = vec![0u8; 128 + vm_fast.program.len() * 8];

            vm_interp.execute_program_interpreter();
            let program = vm_fast
                .jit_engine
                .get_or_compile(&vm_fast.program_bytes, &vm_fast.program, &vm_fast.flags)
                .expect("jit compile");
            vm_fast.execute_program_jit(&program);

            let expected = if mode == 2 { next_up } else { 1.0 };
            assert_eq!(vm_interp.f[0].lo.to_bits(), expected.to_bits());
            assert_eq!(vm_interp.f[0].hi.to_bits(), expected.to_bits());
            assert_eq!(vm_interp.f[0].lo.to_bits(), vm_fast.f[0].lo.to_bits());
            assert_eq!(vm_interp.f[0].hi.to_bits(), vm_fast.f[0].hi.to_bits());
            assert_eq!(vm_interp.fprc, vm_fast.fprc);
        }
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_matches_interpreter_hashes() {
        let cfg = RandomXConfig::test_small();
        let cases = load_cases();

        for case in cases.iter() {
            let key = hex_to_bytes(&case.key_hex);
            let input = hex_to_bytes(&case.input_hex);

            let mut vm_interp = make_vm_with_key(&cfg, false, false, &key);
            let mut vm_jit = make_vm_with_key(&cfg, true, false, &key);
            let mut vm_fast = make_vm_with_key(&cfg, true, true, &key);
            assert!(vm_jit.is_jit_active());
            assert!(vm_fast.is_jit_active());

            let hash_interp = vm_interp.hash(&input);
            let hash_jit = vm_jit.hash(&input);
            let hash_fast = vm_fast.hash(&input);
            assert_eq!(hash_interp, hash_jit);
            assert_eq!(hash_interp, hash_fast);
        }
    }

    #[cfg(feature = "jit-fastregs")]
    #[test]
    fn jit_fast_regs_matches_program_state() {
        let cfg = RandomXConfig::test_small();
        let mut vm_interp = make_vm(&cfg, false, false);
        let mut vm_fast = make_vm(&cfg, true, true);
        assert!(vm_fast.is_jit_active());

        let seed = [0x42u8; 64];
        let mut gen1_a = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_interp.scratchpad.as_mut_slice(),
            &mut gen1_a,
            &vm_interp.flags,
        );
        let mut gen1_b = AesGenerator1R::new(seed);
        fill_scratchpad(
            vm_fast.scratchpad.as_mut_slice(),
            &mut gen1_b,
            &vm_fast.flags,
        );

        let gen4_seed = gen1_a.state();
        let mut gen4_a = AesGenerator4R::new(gen4_seed);
        let mut gen4_b = AesGenerator4R::new(gen4_seed);

        vm_interp.program_vm(&mut gen4_a);
        vm_fast.program_vm(&mut gen4_b);

        prepare_iteration(&mut vm_interp);
        prepare_iteration(&mut vm_fast);

        vm_interp.execute_program_interpreter();
        let program = vm_fast
            .jit_engine
            .get_or_compile(&vm_fast.program_bytes, &vm_fast.program, &vm_fast.flags)
            .expect("jit compile");
        vm_fast.execute_program_jit(&program);

        assert_eq!(vm_interp.register_file(), vm_fast.register_file());
        assert_eq!(
            hash256(vm_interp.scratchpad.as_slice()),
            hash256(vm_fast.scratchpad.as_slice())
        );
        assert_eq!(vm_interp.fprc, vm_fast.fprc);
    }
}
