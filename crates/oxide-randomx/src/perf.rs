//! Performance counters and instrumentation.

/// Aggregated performance counters collected during hashing.
#[derive(Clone, Copy, Debug, Default)]
pub struct PerfStats {
    pub hashes: u64,
    pub program_execs: u64,
    pub program_gen_ns: u64,
    pub prepare_iteration_ns: u64,
    pub finish_iteration_ns: u64,
    pub finish_addr_select_ns: u64,
    pub finish_prefetch_ns: u64,
    pub finish_dataset_item_load_ns: u64,
    pub finish_light_cache_item_ns: u64,
    pub finish_r_xor_ns: u64,
    pub finish_store_int_ns: u64,
    pub finish_f_xor_e_ns: u64,
    pub finish_store_fp_ns: u64,
    pub jit_fastregs_prepare_ns: u64,
    pub jit_fastregs_finish_ns: u64,
    pub scratchpad_read_bytes: u64,
    pub scratchpad_write_bytes: u64,
    pub dataset_item_loads: u64,
    pub mem_read_l1: u64,
    pub mem_read_l2: u64,
    pub mem_read_l3: u64,
    pub mem_write_l1: u64,
    pub mem_write_l2: u64,
    pub mem_write_l3: u64,
    pub vm_exec_ns_interpreter: u64,
    pub vm_exec_ns_jit: u64,
    pub jit_compile_ns: u64,
    pub jit_get_or_compile_calls: u64,
    pub jit_exec_calls: u64,
    pub jit_program_execs: u64,
    pub jit_helper_calls_float: u64,
    pub jit_helper_calls_cbranch: u64,
    pub jit_fastregs_spill_count: u64,
    pub jit_fastregs_reload_count: u64,
    pub jit_fastregs_sync_to_ctx_count: u64,
    pub jit_fastregs_sync_from_ctx_count: u64,
    pub jit_fastregs_call_boundary_count: u64,
    pub jit_fastregs_call_boundary_float_nomem: u64,
    pub jit_fastregs_call_boundary_float_mem: u64,
    pub jit_fastregs_call_boundary_prepare_finish: u64,
    pub jit_fastregs_preserve_spill_count: u64,
    pub jit_fastregs_preserve_reload_count: u64,
    pub jit_fastregs_light_cache_item_helper_calls: u64,
    pub jit_fastregs_light_cache_item_helper_ns: u64,
    pub instr_int: u64,
    pub instr_float: u64,
    pub instr_mem: u64,
    pub instr_ctrl: u64,
    pub instr_store: u64,
}

impl PerfStats {
    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(all(
    test,
    feature = "jit",
    feature = "bench-instrument",
    target_arch = "x86_64"
))]
mod tests {
    use crate::cache::RandomXCache;
    use crate::config::RandomXConfig;
    use crate::flags::RandomXFlags;
    use crate::vm::RandomXVm;

    #[test]
    fn conservative_jit_does_not_use_float_helpers() {
        let cfg = RandomXConfig::test_small();
        let cache = RandomXCache::new_dummy(&cfg);
        let mut flags = RandomXFlags::default();
        flags.jit = true;
        flags.jit_fast_regs = false;

        let mut vm = RandomXVm::new_light(cache, cfg, flags).expect("vm");
        if !vm.is_jit_active() {
            return;
        }

        vm.reset_perf_stats();
        let input = [0u8; 32];
        vm.hash(&input);

        let perf = vm.perf_stats();
        assert_eq!(
            perf.jit_helper_calls_float, 0,
            "conservative jit used float helpers"
        );
    }
}
