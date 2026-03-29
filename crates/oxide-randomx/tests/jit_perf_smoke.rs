#![cfg(all(feature = "bench-instrument", feature = "jit", target_arch = "x86_64"))]

use oxide_randomx::{RandomXCache, RandomXConfig, RandomXFlags, RandomXVm};

#[test]
fn jit_perf_smoke_light() {
    let cfg = RandomXConfig::test_small();
    let mut key = [0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let cache = RandomXCache::new(&key, &cfg).expect("cache");
    let mut flags = RandomXFlags::default();
    flags.jit = true;
    let mut vm = RandomXVm::new_light(cache, cfg, flags).expect("vm");

    if !vm.is_jit_active() {
        eprintln!("jit requested but not active; skipping");
        return;
    }
    assert!(vm.is_jit_active());

    vm.reset_perf_stats();
    let inputs: [&[u8]; 3] = [b"", b"jit", b"perf"];
    for &input in inputs.iter() {
        let out = vm.hash(std::hint::black_box(input));
        std::hint::black_box(out);
    }

    let perf = vm.perf_stats();
    assert!(perf.jit_exec_calls > 0);
    assert!(perf.jit_program_execs > 0);
    assert!(perf.jit_get_or_compile_calls > 0);
}
