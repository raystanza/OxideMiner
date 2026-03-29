//! Internal diagnostics helpers for focused SuperscalarHash benchmarking.
//!
//! These are intentionally exported via `oxide_randomx::diagnostics` as
//! `#[doc(hidden)]` to support local harnesses and differential validation.

use crate::cache::RandomXCache;
use crate::config::RandomXConfig;
use crate::dataset;
use crate::superscalar::SuperscalarProgram;

/// Compute one cache-item word block using the scalar superscalar path.
#[inline]
pub fn compute_item_words_in_place(
    cache: &RandomXCache,
    cfg: &RandomXConfig,
    item_number: u64,
    regs: &mut [u64; 8],
) {
    dataset::compute_item_words_in_place(cache, cfg, item_number, regs);
}

/// Compute one cache-item word block using the scalar superscalar path explicitly.
#[inline]
pub fn compute_item_words_in_place_scalar(
    cache: &RandomXCache,
    cfg: &RandomXConfig,
    item_number: u64,
    regs: &mut [u64; 8],
) {
    compute_item_words_with_exec(cache, cfg, item_number, regs, execute_program_scalar);
}

/// Execute one generated superscalar program and return the selected register.
#[inline]
pub fn execute_superscalar_program(
    cache: &RandomXCache,
    program_index: usize,
    regs: &mut [u64; 8],
) -> usize {
    let program = cache.superscalar_programs().program(program_index);
    program.execute(regs);
    program.select_register()
}

/// Execute one generated superscalar program using scalar instruction dispatch.
#[inline]
pub fn execute_superscalar_program_scalar(
    cache: &RandomXCache,
    program_index: usize,
    regs: &mut [u64; 8],
) -> usize {
    let program = cache.superscalar_programs().program(program_index);
    program.execute_scalar(regs);
    program.select_register()
}

/// Copy one cache item into `out` as eight words.
#[inline]
pub fn copy_cache_item_words(cache: &RandomXCache, cache_item_index: usize, out: &mut [u64; 8]) {
    let item_count = cache.cache_item_count();
    debug_assert!(item_count > 0);
    let idx = cache_item_index % item_count;
    out.copy_from_slice(cache.cache_item_slice(idx));
}

/// Number of cache items available for superscalar synthesis.
#[inline]
pub fn cache_item_count(cache: &RandomXCache) -> usize {
    cache.cache_item_count()
}

type ProgramExec = fn(&SuperscalarProgram, &mut [u64; 8]);

fn compute_item_words_with_exec(
    cache: &RandomXCache,
    cfg: &RandomXConfig,
    item_number: u64,
    regs: &mut [u64; 8],
    exec: ProgramExec,
) {
    let constants = dataset::superscalar_constants();
    let programs = cache.superscalar_programs();
    let cache_items = cache.cache_item_count() as u64;
    debug_assert!(cache_items.is_power_of_two());
    let cache_mask = cache_items - 1;
    let accesses = cfg.cache_accesses() as usize;

    let r0 = (item_number + 1).wrapping_mul(6364136223846793005u64);
    *regs = [
        r0,
        r0 ^ constants[0],
        r0 ^ constants[1],
        r0 ^ constants[2],
        r0 ^ constants[3],
        r0 ^ constants[4],
        r0 ^ constants[5],
        r0 ^ constants[6],
    ];

    let mut cache_index = item_number;
    for i in 0..accesses {
        let program = programs.program(i);
        let idx = (cache_index & cache_mask) as usize;
        let cache_words = cache.cache_item_slice(idx);
        exec(program, regs);
        for (reg, word) in regs.iter_mut().zip(cache_words.iter()) {
            *reg ^= *word;
        }
        cache_index = regs[program.select_register()];
    }
}

#[inline(always)]
fn execute_program_scalar(program: &SuperscalarProgram, regs: &mut [u64; 8]) {
    program.execute_scalar(regs);
}
