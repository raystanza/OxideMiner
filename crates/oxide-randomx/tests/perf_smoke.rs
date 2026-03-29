#[cfg(feature = "bench-instrument")]
mod perf_smoke {
    use oxide_randomx::{RandomXCache, RandomXConfig, RandomXFlags, RandomXVm};
    use std::time::Instant;

    #[test]
    fn perf_smoke_light() {
        if std::env::var("OXIDE_RANDOMX_PERF_SMOKE").ok().as_deref() != Some("1") {
            eprintln!("perf smoke disabled; set OXIDE_RANDOMX_PERF_SMOKE=1 to enable");
            return;
        }

        let cfg = RandomXConfig::new();
        let mut key = [0u8; 32];
        for (idx, byte) in key.iter_mut().enumerate() {
            *byte = idx as u8;
        }
        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let flags = RandomXFlags::default();
        let mut vm = RandomXVm::new_light(cache, cfg, flags).expect("vm");

        let inputs = make_workload();
        for _ in 0..2 {
            for input in inputs.iter() {
                let out = vm.hash(std::hint::black_box(input));
                std::hint::black_box(out);
            }
        }

        vm.reset_perf_stats();
        let iters = 4u64;
        let start = Instant::now();
        for _ in 0..iters {
            for input in inputs.iter() {
                let out = vm.hash(std::hint::black_box(input));
                std::hint::black_box(out);
            }
        }
        let elapsed = start.elapsed();
        let hashes = iters.saturating_mul(inputs.len() as u64);
        let ns_per_hash = if hashes > 0 {
            (elapsed.as_nanos() / hashes as u128) as u64
        } else {
            0
        };

        let perf = vm.perf_stats();
        let instr_total =
            perf.instr_int + perf.instr_float + perf.instr_mem + perf.instr_ctrl + perf.instr_store;

        assert!(hashes > 0);
        assert!(
            ns_per_hash < 2_000_000_000,
            "ns/hash too high: {ns_per_hash}"
        );
        assert!(perf.program_execs > 0);
        assert!(perf.program_gen_ns > 0);
        assert!(perf.prepare_iteration_ns > 0);
        assert!(perf.finish_iteration_ns > 0);
        assert!(perf.vm_exec_ns_interpreter > 0);
        assert!(perf.scratchpad_read_bytes > 0);
        assert!(perf.scratchpad_write_bytes > 0);
        assert!(instr_total > 0);
    }

    fn make_workload() -> Vec<Vec<u8>> {
        let sizes = [0usize, 1, 32, 64];
        let mut inputs = Vec::with_capacity(sizes.len());
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for size in sizes.iter().copied() {
            let mut input = Vec::with_capacity(size);
            for _ in 0..size {
                state = lcg_next(&mut state);
                input.push((state >> 56) as u8);
            }
            inputs.push(input);
        }
        inputs
    }

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }
}
