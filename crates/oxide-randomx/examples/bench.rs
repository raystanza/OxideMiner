use oxide_randomx::{
    AffinitySpec, DatasetInitOptions, PerfStats, RandomXCache, RandomXConfig, RandomXDataset,
    RandomXFlags, RandomXVm,
};
use std::env;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
enum Mode {
    Light,
    Fast,
}

#[derive(Clone, Copy, Debug)]
enum JitMode {
    Off,
    On,
    Both,
}

#[derive(Clone, Copy, Debug)]
enum OutputFormat {
    Human,
    Csv,
    Json,
}

const ONE_GB: usize = 1024 * 1024 * 1024;

struct Options {
    mode: Mode,
    jit: JitMode,
    jit_fast_regs: bool,
    iters: u64,
    warmup: u64,
    threads: usize,
    large_pages: bool,
    use_1gb_pages: bool,
    thread_names: bool,
    affinity: Option<AffinitySpec>,
    report: bool,
    format: OutputFormat,
    validate: bool,
    validate_iters: u64,
    validate_seed: Option<u64>,
}

struct BenchResult {
    mode: Mode,
    jit: bool,
    jit_fast_regs: bool,
    jit_active: bool,
    iters: u64,
    warmup: u64,
    threads: usize,
    large_pages_requested: bool,
    large_pages_1gb_requested: bool,
    large_pages_dataset: Option<bool>,
    large_pages_1gb_dataset: Option<bool>,
    large_pages_scratchpad: bool,
    large_pages_1gb_scratchpad: bool,
    prefetch: bool,
    prefetch_distance: u8,
    prefetch_auto_tune: bool,
    scratchpad_prefetch_distance: u8,
    thread_names: bool,
    affinity: Option<String>,
    inputs: usize,
    hashes: u64,
    elapsed: Duration,
    ns_per_hash: u128,
    perf: PerfStats,
    perf_measured: PerfStats,
    jit_compiles: u64,
    jit_compiles_measured: u64,
    jit_cache_hits: u64,
    jit_cache_hits_measured: u64,
    jit_cache_misses: u64,
    jit_cache_misses_measured: u64,
    jit_cache_evictions: u64,
    jit_cache_evictions_measured: u64,
    jit_compile_ns: u64,
    jit_compile_ns_measured: u64,
}

fn main() {
    let opts = parse_args();
    let mut results = Vec::new();

    if matches!(opts.jit, JitMode::On | JitMode::Both) && !cfg!(feature = "jit") {
        eprintln!("JIT requested but not compiled; rebuild with --features jit");
        if opts.validate {
            std::process::exit(1);
        }
        if matches!(opts.jit, JitMode::On) {
            return;
        }
    }
    if opts.jit_fast_regs && !cfg!(feature = "jit-fastregs") {
        eprintln!("jit-fast-regs requested but not compiled; rebuild with --features jit-fastregs");
        if opts.validate {
            std::process::exit(1);
        }
    }

    if opts.validate {
        match run_validate(&opts) {
            Ok(()) => return,
            Err(err) => {
                eprintln!("validate failed: {err}");
                std::process::exit(1);
            }
        }
    }

    let run_list = match opts.jit {
        JitMode::Off => vec![false],
        JitMode::On => vec![true],
        JitMode::Both => vec![false, true],
    };

    for jit_on in run_list {
        let fast_regs = opts.jit_fast_regs && jit_on && cfg!(feature = "jit-fastregs");
        match run_bench(&opts, jit_on, fast_regs) {
            Ok(result) => results.push(result),
            Err(err) => {
                eprintln!("bench failed: {err}");
                return;
            }
        }
    }

    emit_results(&results, opts.format, opts.report);
}

fn parse_args() -> Options {
    let mut mode = Mode::Light;
    let mut jit = JitMode::Both;
    let mut jit_fast_regs = false;
    let mut iters = 50u64;
    let mut warmup = 5u64;
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let large_pages = env_flag("OXIDE_RANDOMX_LARGE_PAGES");
    let use_1gb_pages = env_flag("OXIDE_RANDOMX_HUGE_1G");
    let thread_names = env_flag("OXIDE_RANDOMX_THREAD_NAMES");
    let affinity = parse_affinity_env();
    let mut report = false;
    let mut format = OutputFormat::Human;
    let mut validate = false;
    let mut validate_iters = 3u64;
    let mut validate_seed = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                mode = match args.next().as_deref() {
                    Some("light") => Mode::Light,
                    Some("fast") => Mode::Fast,
                    _ => usage_and_exit(),
                };
            }
            "--jit" => {
                jit = match args.next().as_deref() {
                    Some("on") => JitMode::On,
                    Some("off") => JitMode::Off,
                    Some("both") => JitMode::Both,
                    _ => usage_and_exit(),
                };
            }
            "--jit-fast-regs" => {
                jit_fast_regs = match args.next().as_deref() {
                    Some("on") => true,
                    Some("off") => false,
                    _ => usage_and_exit(),
                };
            }
            "--iters" => {
                iters = parse_u64(args.next().as_deref());
            }
            "--warmup" => {
                warmup = parse_u64(args.next().as_deref());
            }
            "--threads" => {
                threads = parse_usize(args.next().as_deref());
            }
            "--report" => {
                report = true;
            }
            "--format" => {
                format = match args.next().as_deref() {
                    Some("human") => OutputFormat::Human,
                    Some("csv") => OutputFormat::Csv,
                    Some("json") => OutputFormat::Json,
                    _ => usage_and_exit(),
                };
            }
            "--validate" => {
                validate = true;
            }
            "--validate-iters" => {
                validate_iters = parse_u64(args.next().as_deref());
            }
            "--validate-seed" => {
                validate_seed = Some(parse_u64(args.next().as_deref()));
            }
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }

    if let Some(env_threads) = env_usize("OXIDE_RANDOMX_THREADS") {
        threads = env_threads;
    }

    Options {
        mode,
        jit,
        jit_fast_regs,
        iters,
        warmup,
        threads,
        large_pages,
        use_1gb_pages,
        thread_names,
        affinity,
        report,
        format,
        validate,
        validate_iters,
        validate_seed,
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage: bench [--mode light|fast] [--jit on|off|both] [--jit-fast-regs on|off]\n\
                [--iters N] [--warmup N] [--threads N] [--report] [--format human|csv|json]\n\
                [--validate] [--validate-iters N] [--validate-seed N]"
    );
    std::process::exit(1);
}

fn parse_u64(input: Option<&str>) -> u64 {
    input
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn parse_usize(input: Option<&str>) -> usize {
    input
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn run_bench(opts: &Options, jit_on: bool, jit_fast_regs: bool) -> Result<BenchResult, String> {
    let (key, inputs) = make_workload();
    let cfg = match opts.mode {
        Mode::Light => RandomXConfig::new(),
        Mode::Fast => fast_config()?,
    };

    let flags = build_flags(jit_on, jit_fast_regs, opts.large_pages);
    let prefetch = flags.prefetch;
    let prefetch_distance = flags.prefetch_distance;
    let prefetch_auto_tune = flags.prefetch_auto_tune;
    let scratchpad_prefetch_distance = flags.scratchpad_prefetch_distance;
    let cache = RandomXCache::new(&key, &cfg).map_err(|e| format!("{e:?}"))?;

    let mut dataset_large_pages = None;
    let mut dataset_large_pages_1gb = None;
    let mut vm = match opts.mode {
        Mode::Light => RandomXVm::new_light(cache, cfg, flags).map_err(|e| format!("{e:?}"))?,
        Mode::Fast => {
            if env::var("OXIDE_RANDOMX_FAST_BENCH").ok().as_deref() != Some("1") {
                return Err("fast mode requires OXIDE_RANDOMX_FAST_BENCH=1".to_string());
            }
            let mut ds_opts = DatasetInitOptions::new(opts.threads)
                .with_large_pages(opts.large_pages)
                .with_1gb_pages(opts.use_1gb_pages)
                .with_thread_names(opts.thread_names);
            if let Some(spec) = opts.affinity.clone() {
                ds_opts = ds_opts.with_affinity(spec);
            }
            let dataset = RandomXDataset::new_with_options(&cache, &cfg, ds_opts)
                .map_err(|e| format!("{e:?}"))?;
            dataset_large_pages = Some(dataset.uses_large_pages());
            dataset_large_pages_1gb = dataset.huge_page_size().map(|size| size >= ONE_GB);
            RandomXVm::new_fast(cache, dataset, cfg, flags).map_err(|e| format!("{e:?}"))?
        }
    };

    let scratchpad_large_pages = vm.scratchpad_uses_large_pages();
    let scratchpad_large_pages_1gb = vm
        .scratchpad_huge_page_size()
        .map(|size| size >= ONE_GB)
        .unwrap_or(false);

    if jit_on && !vm.is_jit_active() {
        eprintln!("JIT requested but not active on this platform; using interpreter");
    }

    for _ in 0..opts.warmup {
        for input in inputs.iter() {
            let out = vm.hash(std::hint::black_box(input));
            std::hint::black_box(out);
        }
    }

    let perf_after_warmup = vm.perf_stats();
    #[cfg(feature = "jit")]
    let jit_stats_after_warmup = vm.jit_stats();

    let start = Instant::now();
    for _ in 0..opts.iters {
        for input in inputs.iter() {
            let out = vm.hash(std::hint::black_box(input));
            std::hint::black_box(out);
        }
    }
    let elapsed = start.elapsed();

    let hashes = opts.iters.saturating_mul(inputs.len() as u64);
    let ns_per_hash = if hashes > 0 {
        elapsed.as_nanos() / hashes as u128
    } else {
        0
    };

    let perf = vm.perf_stats();
    let perf_measured = perf_delta(perf, perf_after_warmup);
    #[cfg(feature = "jit")]
    let mut result = BenchResult {
        mode: opts.mode,
        jit: jit_on,
        jit_fast_regs,
        jit_active: vm.is_jit_active(),
        iters: opts.iters,
        warmup: opts.warmup,
        threads: opts.threads,
        large_pages_requested: opts.large_pages,
        large_pages_1gb_requested: opts.use_1gb_pages,
        large_pages_dataset: dataset_large_pages,
        large_pages_1gb_dataset: dataset_large_pages_1gb,
        large_pages_scratchpad: scratchpad_large_pages,
        large_pages_1gb_scratchpad: scratchpad_large_pages_1gb,
        prefetch,
        prefetch_distance,
        prefetch_auto_tune,
        scratchpad_prefetch_distance,
        thread_names: opts.thread_names,
        affinity: opts.affinity.as_ref().map(|spec| spec.to_string()),
        inputs: inputs.len(),
        hashes,
        elapsed,
        ns_per_hash,
        perf,
        perf_measured,
        jit_compiles: 0,
        jit_compiles_measured: 0,
        jit_cache_hits: 0,
        jit_cache_hits_measured: 0,
        jit_cache_misses: 0,
        jit_cache_misses_measured: 0,
        jit_cache_evictions: 0,
        jit_cache_evictions_measured: 0,
        jit_compile_ns: 0,
        jit_compile_ns_measured: 0,
    };
    #[cfg(not(feature = "jit"))]
    let result = BenchResult {
        mode: opts.mode,
        jit: jit_on,
        jit_fast_regs,
        jit_active: vm.is_jit_active(),
        iters: opts.iters,
        warmup: opts.warmup,
        threads: opts.threads,
        large_pages_requested: opts.large_pages,
        large_pages_1gb_requested: opts.use_1gb_pages,
        large_pages_dataset: dataset_large_pages,
        large_pages_1gb_dataset: dataset_large_pages_1gb,
        large_pages_scratchpad: scratchpad_large_pages,
        large_pages_1gb_scratchpad: scratchpad_large_pages_1gb,
        prefetch,
        prefetch_distance,
        prefetch_auto_tune,
        scratchpad_prefetch_distance,
        thread_names: opts.thread_names,
        affinity: opts.affinity.as_ref().map(|spec| spec.to_string()),
        inputs: inputs.len(),
        hashes,
        elapsed,
        ns_per_hash,
        perf,
        perf_measured,
        jit_compiles: 0,
        jit_compiles_measured: 0,
        jit_cache_hits: 0,
        jit_cache_hits_measured: 0,
        jit_cache_misses: 0,
        jit_cache_misses_measured: 0,
        jit_cache_evictions: 0,
        jit_cache_evictions_measured: 0,
        jit_compile_ns: 0,
        jit_compile_ns_measured: 0,
    };

    #[cfg(feature = "jit")]
    {
        let stats = vm.jit_stats();
        result.jit_compiles = stats.compiles;
        result.jit_cache_hits = stats.cache_hits;
        result.jit_cache_misses = stats.cache_misses;
        result.jit_cache_evictions = stats.cache_evictions;
        result.jit_compile_ns = stats.compile_ns;
        result.jit_compiles_measured = stats
            .compiles
            .saturating_sub(jit_stats_after_warmup.compiles);
        result.jit_cache_hits_measured = stats
            .cache_hits
            .saturating_sub(jit_stats_after_warmup.cache_hits);
        result.jit_cache_misses_measured = stats
            .cache_misses
            .saturating_sub(jit_stats_after_warmup.cache_misses);
        result.jit_cache_evictions_measured = stats
            .cache_evictions
            .saturating_sub(jit_stats_after_warmup.cache_evictions);
        result.jit_compile_ns_measured = stats
            .compile_ns
            .saturating_sub(jit_stats_after_warmup.compile_ns);
    }

    Ok(result)
}

fn run_validate(opts: &Options) -> Result<(), String> {
    let seed = opts.validate_seed.unwrap_or(0x243f_6a88_85a3_08d3);
    let (key, inputs) = make_validation_workload(seed);
    let cfg = match opts.mode {
        Mode::Light => RandomXConfig::new(),
        Mode::Fast => fast_config()?,
    };

    let mut vm_interp = build_vm_for_validate(
        opts.mode,
        &cfg,
        build_flags(false, false, opts.large_pages),
        &key,
        opts.threads,
    )?;

    let want_jit = matches!(opts.jit, JitMode::On | JitMode::Both);
    let want_fast = want_jit && opts.jit_fast_regs;

    let mut vm_jit = if want_jit {
        let vm = build_vm_for_validate(
            opts.mode,
            &cfg,
            build_flags(true, false, opts.large_pages),
            &key,
            opts.threads,
        )?;
        if !vm.is_jit_active() {
            return Err("jit requested but not active".to_string());
        }
        Some(vm)
    } else {
        None
    };

    let mut vm_fast = if want_fast {
        let vm = build_vm_for_validate(
            opts.mode,
            &cfg,
            build_flags(true, true, opts.large_pages),
            &key,
            opts.threads,
        )?;
        if !vm.is_jit_active() {
            return Err("jit-fast-regs requested but not active".to_string());
        }
        Some(vm)
    } else {
        None
    };

    for iter in 0..opts.validate_iters {
        for (idx, input) in inputs.iter().enumerate() {
            let expected = vm_interp.hash(input);
            if let Some(vm) = vm_jit.as_mut() {
                let actual = vm.hash(input);
                if expected != actual {
                    return Err(format!(
                        "jit mismatch iter={iter} input={idx} len={} expected={} actual={}",
                        input.len(),
                        bytes_to_hex(&expected),
                        bytes_to_hex(&actual)
                    ));
                }
                if !vm.is_jit_active() {
                    return Err("jit requested but interpreter fallback occurred".to_string());
                }
            }
            if let Some(vm) = vm_fast.as_mut() {
                let actual = vm.hash(input);
                if expected != actual {
                    return Err(format!(
                        "jit-fast-regs mismatch iter={iter} input={idx} len={} expected={} actual={}",
                        input.len(),
                        bytes_to_hex(&expected),
                        bytes_to_hex(&actual)
                    ));
                }
                if !vm.is_jit_active() {
                    return Err(
                        "jit-fast-regs requested but interpreter fallback occurred".to_string()
                    );
                }
            }
        }
    }

    Ok(())
}

fn build_vm_for_validate(
    mode: Mode,
    cfg: &RandomXConfig,
    flags: RandomXFlags,
    key: &[u8],
    threads: usize,
) -> Result<RandomXVm, String> {
    let cache = RandomXCache::new(key, cfg).map_err(|e| format!("{e:?}"))?;
    match mode {
        Mode::Light => {
            RandomXVm::new_light(cache, cfg.clone(), flags).map_err(|e| format!("{e:?}"))
        }
        Mode::Fast => {
            let dataset =
                RandomXDataset::new(&cache, cfg, threads).map_err(|e| format!("{e:?}"))?;
            RandomXVm::new_fast(cache, dataset, cfg.clone(), flags).map_err(|e| format!("{e:?}"))
        }
    }
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn make_workload() -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut key = vec![0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let sizes = [0usize, 1, 16, 64, 256, 1024];
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
    (key, inputs)
}

fn make_validation_workload(seed: u64) -> (Vec<u8>, Vec<Vec<u8>>) {
    const SIZES: &[usize] = &[0, 1, 32, 64];
    let mut key = vec![0u8; 32];
    let mut state = seed;
    for byte in key.iter_mut() {
        state = lcg_next(&mut state);
        *byte = (state >> 56) as u8;
    }
    let mut inputs = Vec::with_capacity(SIZES.len());
    for size in SIZES.iter().copied() {
        let mut input = Vec::with_capacity(size);
        for _ in 0..size {
            state = lcg_next(&mut state);
            input.push((state >> 56) as u8);
        }
        inputs.push(input);
    }
    (key, inputs)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn build_flags(jit_on: bool, jit_fast_regs: bool, large_pages: bool) -> RandomXFlags {
    let mut flags = RandomXFlags::default();
    apply_prefetch_env_overrides(&mut flags);
    #[cfg(feature = "jit")]
    {
        flags.jit = jit_on;
        flags.jit_fast_regs = jit_fast_regs;
    }
    #[cfg(not(feature = "jit"))]
    {
        let _ = (jit_on, jit_fast_regs);
    }
    flags.large_pages_plumbing = large_pages;
    flags
}

fn apply_prefetch_env_overrides(flags: &mut RandomXFlags) {
    let env_flags = RandomXFlags::from_env();
    flags.prefetch = env_flags.prefetch;
    flags.prefetch_distance = env_flags.prefetch_distance;
    flags.prefetch_auto_tune = env_flags.prefetch_auto_tune;
    flags.scratchpad_prefetch_distance = env_flags.scratchpad_prefetch_distance;
}

fn fast_config() -> Result<RandomXConfig, String> {
    if env::var("OXIDE_RANDOMX_FAST_BENCH").ok().as_deref() != Some("1") {
        return Err("fast mode requires OXIDE_RANDOMX_FAST_BENCH=1".to_string());
    }

    if cfg!(feature = "unsafe-config")
        && env::var("OXIDE_RANDOMX_FAST_BENCH_SMALL").ok().as_deref() == Some("1")
    {
        return small_fast_config();
    }

    Ok(RandomXConfig::new())
}

fn small_fast_config() -> Result<RandomXConfig, String> {
    #[cfg(feature = "unsafe-config")]
    {
        use oxide_randomx::RandomXConfigBuilder;
        RandomXConfigBuilder::new()
            .argon_memory(1024)
            .argon_iterations(1)
            .dataset_base_size(1 << 24)
            .dataset_extra_size(0)
            .build()
            .map_err(|e| format!("{e:?}"))
    }
    #[cfg(not(feature = "unsafe-config"))]
    {
        let _ = ();
        Err("small fast config requires --features unsafe-config".to_string())
    }
}

fn perf_delta(after: PerfStats, before: PerfStats) -> PerfStats {
    PerfStats {
        hashes: after.hashes.saturating_sub(before.hashes),
        program_execs: after.program_execs.saturating_sub(before.program_execs),
        program_gen_ns: after.program_gen_ns.saturating_sub(before.program_gen_ns),
        prepare_iteration_ns: after
            .prepare_iteration_ns
            .saturating_sub(before.prepare_iteration_ns),
        finish_iteration_ns: after
            .finish_iteration_ns
            .saturating_sub(before.finish_iteration_ns),
        finish_addr_select_ns: after
            .finish_addr_select_ns
            .saturating_sub(before.finish_addr_select_ns),
        finish_prefetch_ns: after
            .finish_prefetch_ns
            .saturating_sub(before.finish_prefetch_ns),
        finish_dataset_item_load_ns: after
            .finish_dataset_item_load_ns
            .saturating_sub(before.finish_dataset_item_load_ns),
        finish_light_cache_item_ns: after
            .finish_light_cache_item_ns
            .saturating_sub(before.finish_light_cache_item_ns),
        finish_r_xor_ns: after.finish_r_xor_ns.saturating_sub(before.finish_r_xor_ns),
        finish_store_int_ns: after
            .finish_store_int_ns
            .saturating_sub(before.finish_store_int_ns),
        finish_f_xor_e_ns: after
            .finish_f_xor_e_ns
            .saturating_sub(before.finish_f_xor_e_ns),
        finish_store_fp_ns: after
            .finish_store_fp_ns
            .saturating_sub(before.finish_store_fp_ns),
        jit_fastregs_prepare_ns: after
            .jit_fastregs_prepare_ns
            .saturating_sub(before.jit_fastregs_prepare_ns),
        jit_fastregs_finish_ns: after
            .jit_fastregs_finish_ns
            .saturating_sub(before.jit_fastregs_finish_ns),
        scratchpad_read_bytes: after
            .scratchpad_read_bytes
            .saturating_sub(before.scratchpad_read_bytes),
        scratchpad_write_bytes: after
            .scratchpad_write_bytes
            .saturating_sub(before.scratchpad_write_bytes),
        dataset_item_loads: after
            .dataset_item_loads
            .saturating_sub(before.dataset_item_loads),
        mem_read_l1: after.mem_read_l1.saturating_sub(before.mem_read_l1),
        mem_read_l2: after.mem_read_l2.saturating_sub(before.mem_read_l2),
        mem_read_l3: after.mem_read_l3.saturating_sub(before.mem_read_l3),
        mem_write_l1: after.mem_write_l1.saturating_sub(before.mem_write_l1),
        mem_write_l2: after.mem_write_l2.saturating_sub(before.mem_write_l2),
        mem_write_l3: after.mem_write_l3.saturating_sub(before.mem_write_l3),
        vm_exec_ns_interpreter: after
            .vm_exec_ns_interpreter
            .saturating_sub(before.vm_exec_ns_interpreter),
        vm_exec_ns_jit: after.vm_exec_ns_jit.saturating_sub(before.vm_exec_ns_jit),
        jit_compile_ns: after.jit_compile_ns.saturating_sub(before.jit_compile_ns),
        jit_get_or_compile_calls: after
            .jit_get_or_compile_calls
            .saturating_sub(before.jit_get_or_compile_calls),
        jit_exec_calls: after.jit_exec_calls.saturating_sub(before.jit_exec_calls),
        jit_program_execs: after
            .jit_program_execs
            .saturating_sub(before.jit_program_execs),
        jit_helper_calls_float: after
            .jit_helper_calls_float
            .saturating_sub(before.jit_helper_calls_float),
        jit_helper_calls_cbranch: after
            .jit_helper_calls_cbranch
            .saturating_sub(before.jit_helper_calls_cbranch),
        jit_fastregs_spill_count: after
            .jit_fastregs_spill_count
            .saturating_sub(before.jit_fastregs_spill_count),
        jit_fastregs_reload_count: after
            .jit_fastregs_reload_count
            .saturating_sub(before.jit_fastregs_reload_count),
        jit_fastregs_sync_to_ctx_count: after
            .jit_fastregs_sync_to_ctx_count
            .saturating_sub(before.jit_fastregs_sync_to_ctx_count),
        jit_fastregs_sync_from_ctx_count: after
            .jit_fastregs_sync_from_ctx_count
            .saturating_sub(before.jit_fastregs_sync_from_ctx_count),
        jit_fastregs_call_boundary_count: after
            .jit_fastregs_call_boundary_count
            .saturating_sub(before.jit_fastregs_call_boundary_count),
        jit_fastregs_call_boundary_float_nomem: after
            .jit_fastregs_call_boundary_float_nomem
            .saturating_sub(before.jit_fastregs_call_boundary_float_nomem),
        jit_fastregs_call_boundary_float_mem: after
            .jit_fastregs_call_boundary_float_mem
            .saturating_sub(before.jit_fastregs_call_boundary_float_mem),
        jit_fastregs_call_boundary_prepare_finish: after
            .jit_fastregs_call_boundary_prepare_finish
            .saturating_sub(before.jit_fastregs_call_boundary_prepare_finish),
        jit_fastregs_preserve_spill_count: after
            .jit_fastregs_preserve_spill_count
            .saturating_sub(before.jit_fastregs_preserve_spill_count),
        jit_fastregs_preserve_reload_count: after
            .jit_fastregs_preserve_reload_count
            .saturating_sub(before.jit_fastregs_preserve_reload_count),
        jit_fastregs_light_cache_item_helper_calls: after
            .jit_fastregs_light_cache_item_helper_calls
            .saturating_sub(before.jit_fastregs_light_cache_item_helper_calls),
        jit_fastregs_light_cache_item_helper_ns: after
            .jit_fastregs_light_cache_item_helper_ns
            .saturating_sub(before.jit_fastregs_light_cache_item_helper_ns),
        instr_int: after.instr_int.saturating_sub(before.instr_int),
        instr_float: after.instr_float.saturating_sub(before.instr_float),
        instr_mem: after.instr_mem.saturating_sub(before.instr_mem),
        instr_ctrl: after.instr_ctrl.saturating_sub(before.instr_ctrl),
        instr_store: after.instr_store.saturating_sub(before.instr_store),
    }
}

fn emit_results(results: &[BenchResult], format: OutputFormat, report: bool) {
    match format {
        OutputFormat::Human => emit_human(results, report),
        OutputFormat::Csv => emit_csv(results),
        OutputFormat::Json => emit_json(results),
    }
}

fn emit_human(results: &[BenchResult], report: bool) {
    for result in results {
        println!(
            "mode={:?} jit={} fast_regs={} hashes={} ns/hash={} prefetch={} prefetch_distance={} \
prefetch_auto_tune={} scratchpad_prefetch_distance={}",
            result.mode,
            result.jit,
            result.jit_fast_regs,
            result.hashes,
            result.ns_per_hash,
            result.prefetch,
            result.prefetch_distance,
            result.prefetch_auto_tune,
            result.scratchpad_prefetch_distance
        );
        if report {
            emit_report(result);
        }
    }
}

fn emit_provenance(result: &BenchResult) {
    let git_sha = option_env!("OXIDE_RANDOMX_GIT_SHA").unwrap_or("unknown");
    let git_sha_short = option_env!("OXIDE_RANDOMX_GIT_SHA_SHORT").unwrap_or_else(|| {
        if git_sha != "unknown" && git_sha.len() >= 7 {
            &git_sha[..7]
        } else {
            git_sha
        }
    });
    let git_dirty = option_env!("OXIDE_RANDOMX_GIT_DIRTY").unwrap_or("unknown");
    let rustc = option_env!("OXIDE_RANDOMX_RUSTC_VERSION").unwrap_or("unknown");
    let features = enabled_features();
    let cpu = cpu_model_string();
    let mode = format!("{:?}", result.mode);
    println!(
        "provenance git_sha={} git_sha_short={} git_dirty={} features={} cpu={} cores={} \
rustc={} mode={} jit={} jit_fast_regs={} iters={} warmup={} threads={} hashes={}",
        git_sha,
        git_sha_short,
        git_dirty,
        features,
        quote_value(&cpu),
        logical_cores(),
        quote_value(rustc),
        mode,
        result.jit,
        result.jit_fast_regs,
        result.iters,
        result.warmup,
        result.threads,
        result.hashes
    );
}

fn emit_report(result: &BenchResult) {
    emit_provenance(result);
    let dataset_pages = match result.large_pages_dataset {
        Some(value) => value.to_string(),
        None => "n/a".to_string(),
    };
    let dataset_pages_1gb = match result.large_pages_1gb_dataset {
        Some(value) => value.to_string(),
        None => "n/a".to_string(),
    };
    let affinity = result.affinity.as_deref().unwrap_or("off");
    println!(
        "large_pages_requested={} large_pages_1gb_requested={} large_pages_dataset={} \
large_pages_1gb_dataset={} large_pages_scratchpad={} large_pages_1gb_scratchpad={} \
thread_names={} affinity={}",
        result.large_pages_requested,
        result.large_pages_1gb_requested,
        dataset_pages,
        dataset_pages_1gb,
        result.large_pages_scratchpad,
        result.large_pages_1gb_scratchpad,
        result.thread_names,
        affinity
    );
    println!(
        "prefetch={} prefetch_distance={} prefetch_auto_tune={} scratchpad_prefetch_distance={}",
        result.prefetch,
        result.prefetch_distance,
        result.prefetch_auto_tune,
        result.scratchpad_prefetch_distance
    );
    if !cfg!(feature = "bench-instrument") {
        println!("report=disabled (compile with --features bench-instrument)");
        return;
    }
    println!(
        "jit_active={} jit_compiles={} jit_cache_hits={} jit_cache_misses={} jit_cache_evictions={}",
        result.jit_active,
        result.jit_compiles,
        result.jit_cache_hits,
        result.jit_cache_misses,
        result.jit_cache_evictions
    );
    println!(
        "jit_compiles_measured={} jit_cache_hits_measured={} jit_cache_misses_measured={} \
jit_cache_evictions_measured={}",
        result.jit_compiles_measured,
        result.jit_cache_hits_measured,
        result.jit_cache_misses_measured,
        result.jit_cache_evictions_measured
    );
    println!("jit_compile_ns={}", result.jit_compile_ns);
    println!("jit_compile_ns_measured={}", result.jit_compile_ns_measured);
    println!(
        "jit_get_or_compile_calls={} jit_exec_calls={} jit_program_execs={}",
        result.perf.jit_get_or_compile_calls,
        result.perf.jit_exec_calls,
        result.perf.jit_program_execs
    );
    println!(
        "jit_get_or_compile_calls_measured={} jit_exec_calls_measured={} \
jit_program_execs_measured={}",
        result.perf_measured.jit_get_or_compile_calls,
        result.perf_measured.jit_exec_calls,
        result.perf_measured.jit_program_execs
    );
    println!(
        "jit_helper_calls_float={} jit_helper_calls_cbranch={}",
        result.perf.jit_helper_calls_float, result.perf.jit_helper_calls_cbranch
    );
    println!(
        "jit_helper_calls_float_measured={} jit_helper_calls_cbranch_measured={}",
        result.perf_measured.jit_helper_calls_float, result.perf_measured.jit_helper_calls_cbranch
    );
    println!(
        "jit_fastregs_spill_count={} jit_fastregs_reload_count={} jit_fastregs_sync_to_ctx_count={} \
jit_fastregs_sync_from_ctx_count={} jit_fastregs_call_boundary_count={}",
        result.perf.jit_fastregs_spill_count,
        result.perf.jit_fastregs_reload_count,
        result.perf.jit_fastregs_sync_to_ctx_count,
        result.perf.jit_fastregs_sync_from_ctx_count,
        result.perf.jit_fastregs_call_boundary_count
    );
    println!(
        "jit_fastregs_call_boundary_float_nomem={} jit_fastregs_call_boundary_float_mem={} \
jit_fastregs_call_boundary_prepare_finish={}",
        result.perf.jit_fastregs_call_boundary_float_nomem,
        result.perf.jit_fastregs_call_boundary_float_mem,
        result.perf.jit_fastregs_call_boundary_prepare_finish
    );
    println!(
        "jit_fastregs_preserve_spill_count={} jit_fastregs_preserve_reload_count={}",
        result.perf.jit_fastregs_preserve_spill_count,
        result.perf.jit_fastregs_preserve_reload_count
    );
    println!(
        "jit_fastregs_light_cache_item_helper_calls={} jit_fastregs_light_cache_item_helper_ns={}",
        result.perf.jit_fastregs_light_cache_item_helper_calls,
        result.perf.jit_fastregs_light_cache_item_helper_ns
    );
    println!(
        "jit_fastregs_spill_count_measured={} jit_fastregs_reload_count_measured={} \
jit_fastregs_sync_to_ctx_count_measured={} jit_fastregs_sync_from_ctx_count_measured={} \
jit_fastregs_call_boundary_count_measured={}",
        result.perf_measured.jit_fastregs_spill_count,
        result.perf_measured.jit_fastregs_reload_count,
        result.perf_measured.jit_fastregs_sync_to_ctx_count,
        result.perf_measured.jit_fastregs_sync_from_ctx_count,
        result.perf_measured.jit_fastregs_call_boundary_count
    );
    println!(
        "jit_fastregs_call_boundary_float_nomem_measured={} \
jit_fastregs_call_boundary_float_mem_measured={} \
jit_fastregs_call_boundary_prepare_finish_measured={}",
        result.perf_measured.jit_fastregs_call_boundary_float_nomem,
        result.perf_measured.jit_fastregs_call_boundary_float_mem,
        result
            .perf_measured
            .jit_fastregs_call_boundary_prepare_finish
    );
    println!(
        "jit_fastregs_preserve_spill_count_measured={} \
jit_fastregs_preserve_reload_count_measured={}",
        result.perf_measured.jit_fastregs_preserve_spill_count,
        result.perf_measured.jit_fastregs_preserve_reload_count
    );
    println!(
        "jit_fastregs_light_cache_item_helper_calls_measured={} \
jit_fastregs_light_cache_item_helper_ns_measured={}",
        result
            .perf_measured
            .jit_fastregs_light_cache_item_helper_calls,
        result.perf_measured.jit_fastregs_light_cache_item_helper_ns
    );
    println!(
        "vm_exec_ns_interpreter={} vm_exec_ns_jit={}",
        result.perf.vm_exec_ns_interpreter, result.perf.vm_exec_ns_jit
    );
    println!(
        "vm_exec_ns_interpreter_measured={} vm_exec_ns_jit_measured={}",
        result.perf_measured.vm_exec_ns_interpreter, result.perf_measured.vm_exec_ns_jit
    );
    println!(
        "program_gen_ns={} prepare_iteration_ns={} finish_iteration_ns={} \
jit_fastregs_prepare_ns={} jit_fastregs_finish_ns={} finish_addr_select_ns={} \
finish_prefetch_ns={} finish_dataset_item_load_ns={} finish_light_cache_item_ns={} \
finish_r_xor_ns={} finish_store_int_ns={} finish_f_xor_e_ns={} finish_store_fp_ns={} \
program_execs={}",
        result.perf.program_gen_ns,
        result.perf.prepare_iteration_ns,
        result.perf.finish_iteration_ns,
        result.perf.jit_fastregs_prepare_ns,
        result.perf.jit_fastregs_finish_ns,
        result.perf.finish_addr_select_ns,
        result.perf.finish_prefetch_ns,
        result.perf.finish_dataset_item_load_ns,
        result.perf.finish_light_cache_item_ns,
        result.perf.finish_r_xor_ns,
        result.perf.finish_store_int_ns,
        result.perf.finish_f_xor_e_ns,
        result.perf.finish_store_fp_ns,
        result.perf.program_execs
    );
    println!(
        "program_gen_ns_measured={} prepare_iteration_ns_measured={} \
finish_iteration_ns_measured={} jit_fastregs_prepare_ns_measured={} \
jit_fastregs_finish_ns_measured={} finish_addr_select_ns_measured={} \
finish_prefetch_ns_measured={} finish_dataset_item_load_ns_measured={} \
finish_light_cache_item_ns_measured={} finish_r_xor_ns_measured={} \
finish_store_int_ns_measured={} finish_f_xor_e_ns_measured={} \
finish_store_fp_ns_measured={} program_execs_measured={}",
        result.perf_measured.program_gen_ns,
        result.perf_measured.prepare_iteration_ns,
        result.perf_measured.finish_iteration_ns,
        result.perf_measured.jit_fastregs_prepare_ns,
        result.perf_measured.jit_fastregs_finish_ns,
        result.perf_measured.finish_addr_select_ns,
        result.perf_measured.finish_prefetch_ns,
        result.perf_measured.finish_dataset_item_load_ns,
        result.perf_measured.finish_light_cache_item_ns,
        result.perf_measured.finish_r_xor_ns,
        result.perf_measured.finish_store_int_ns,
        result.perf_measured.finish_f_xor_e_ns,
        result.perf_measured.finish_store_fp_ns,
        result.perf_measured.program_execs
    );
    println!(
        "scratchpad_read_bytes={} scratchpad_write_bytes={} dataset_item_loads={}",
        result.perf.scratchpad_read_bytes,
        result.perf.scratchpad_write_bytes,
        result.perf.dataset_item_loads
    );
    println!(
        "scratchpad_read_bytes_measured={} scratchpad_write_bytes_measured={} \
dataset_item_loads_measured={}",
        result.perf_measured.scratchpad_read_bytes,
        result.perf_measured.scratchpad_write_bytes,
        result.perf_measured.dataset_item_loads
    );
    println!(
        "mem_read_l1={} mem_read_l2={} mem_read_l3={} mem_write_l1={} mem_write_l2={} mem_write_l3={}",
        result.perf.mem_read_l1,
        result.perf.mem_read_l2,
        result.perf.mem_read_l3,
        result.perf.mem_write_l1,
        result.perf.mem_write_l2,
        result.perf.mem_write_l3
    );
    println!(
        "mem_read_l1_measured={} mem_read_l2_measured={} mem_read_l3_measured={} \
mem_write_l1_measured={} mem_write_l2_measured={} mem_write_l3_measured={}",
        result.perf_measured.mem_read_l1,
        result.perf_measured.mem_read_l2,
        result.perf_measured.mem_read_l3,
        result.perf_measured.mem_write_l1,
        result.perf_measured.mem_write_l2,
        result.perf_measured.mem_write_l3
    );
    println!(
        "instr_counts_source={}",
        if result.jit {
            "jit_derived_static_mix"
        } else {
            "interp_exact"
        }
    );
    println!(
        "instr_int={} instr_float={} instr_mem={} instr_ctrl={} instr_store={}",
        result.perf.instr_int,
        result.perf.instr_float,
        result.perf.instr_mem,
        result.perf.instr_ctrl,
        result.perf.instr_store
    );
    println!(
        "instr_int_measured={} instr_float_measured={} instr_mem_measured={} \
instr_ctrl_measured={} instr_store_measured={}",
        result.perf_measured.instr_int,
        result.perf_measured.instr_float,
        result.perf_measured.instr_mem,
        result.perf_measured.instr_ctrl,
        result.perf_measured.instr_store
    );
}

fn emit_csv(results: &[BenchResult]) {
    println!("{}", csv_header());
    for result in results {
        println!("{}", csv_row(result));
    }
}

fn emit_json(results: &[BenchResult]) {
    println!("[");
    for (idx, result) in results.iter().enumerate() {
        println!("{}", json_row(result, idx + 1 != results.len()));
    }
    println!("]");
}

fn csv_header() -> &'static str {
    "mode,jit,jit_fast_regs,jit_active,iters,inputs,hashes,elapsed_ns,ns_per_hash,\
jit_compiles,jit_cache_hits,jit_cache_misses,jit_cache_evictions,jit_compile_ns,\
large_pages_requested,large_pages_1gb_requested,large_pages_dataset,large_pages_1gb_dataset,\
large_pages_scratchpad,large_pages_1gb_scratchpad,\
vm_exec_ns_interpreter,vm_exec_ns_jit,instr_int,instr_float,instr_mem,instr_ctrl,instr_store,\
jit_fastregs_spill_count,jit_fastregs_reload_count,jit_fastregs_sync_to_ctx_count,\
jit_fastregs_sync_from_ctx_count,jit_fastregs_call_boundary_count,\
jit_fastregs_call_boundary_float_nomem,jit_fastregs_call_boundary_float_mem,\
jit_fastregs_call_boundary_prepare_finish,jit_fastregs_preserve_spill_count,\
jit_fastregs_preserve_reload_count,prefetch,prefetch_distance,prefetch_auto_tune,\
scratchpad_prefetch_distance,jit_fastregs_prepare_ns,jit_fastregs_finish_ns,\
jit_fastregs_light_cache_item_helper_calls,jit_fastregs_light_cache_item_helper_ns,\
finish_addr_select_ns,finish_prefetch_ns,finish_dataset_item_load_ns,finish_light_cache_item_ns,\
finish_r_xor_ns,finish_store_int_ns,finish_f_xor_e_ns,finish_store_fp_ns"
}

fn csv_row(result: &BenchResult) -> String {
    let dataset_pages = result
        .large_pages_dataset
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let dataset_pages_1gb = result
        .large_pages_1gb_dataset
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());

    [
        format!("{:?}", result.mode),
        result.jit.to_string(),
        result.jit_fast_regs.to_string(),
        result.jit_active.to_string(),
        result.iters.to_string(),
        result.inputs.to_string(),
        result.hashes.to_string(),
        result.elapsed.as_nanos().to_string(),
        result.ns_per_hash.to_string(),
        result.jit_compiles.to_string(),
        result.jit_cache_hits.to_string(),
        result.jit_cache_misses.to_string(),
        result.jit_cache_evictions.to_string(),
        result.jit_compile_ns.to_string(),
        result.large_pages_requested.to_string(),
        result.large_pages_1gb_requested.to_string(),
        dataset_pages,
        dataset_pages_1gb,
        result.large_pages_scratchpad.to_string(),
        result.large_pages_1gb_scratchpad.to_string(),
        result.perf.vm_exec_ns_interpreter.to_string(),
        result.perf.vm_exec_ns_jit.to_string(),
        result.perf.instr_int.to_string(),
        result.perf.instr_float.to_string(),
        result.perf.instr_mem.to_string(),
        result.perf.instr_ctrl.to_string(),
        result.perf.instr_store.to_string(),
        result.perf.jit_fastregs_spill_count.to_string(),
        result.perf.jit_fastregs_reload_count.to_string(),
        result.perf.jit_fastregs_sync_to_ctx_count.to_string(),
        result.perf.jit_fastregs_sync_from_ctx_count.to_string(),
        result.perf.jit_fastregs_call_boundary_count.to_string(),
        result
            .perf
            .jit_fastregs_call_boundary_float_nomem
            .to_string(),
        result.perf.jit_fastregs_call_boundary_float_mem.to_string(),
        result
            .perf
            .jit_fastregs_call_boundary_prepare_finish
            .to_string(),
        result.perf.jit_fastregs_preserve_spill_count.to_string(),
        result.perf.jit_fastregs_preserve_reload_count.to_string(),
        result.prefetch.to_string(),
        result.prefetch_distance.to_string(),
        result.prefetch_auto_tune.to_string(),
        result.scratchpad_prefetch_distance.to_string(),
        result.perf.jit_fastregs_prepare_ns.to_string(),
        result.perf.jit_fastregs_finish_ns.to_string(),
        result
            .perf
            .jit_fastregs_light_cache_item_helper_calls
            .to_string(),
        result
            .perf
            .jit_fastregs_light_cache_item_helper_ns
            .to_string(),
        result.perf.finish_addr_select_ns.to_string(),
        result.perf.finish_prefetch_ns.to_string(),
        result.perf.finish_dataset_item_load_ns.to_string(),
        result.perf.finish_light_cache_item_ns.to_string(),
        result.perf.finish_r_xor_ns.to_string(),
        result.perf.finish_store_int_ns.to_string(),
        result.perf.finish_f_xor_e_ns.to_string(),
        result.perf.finish_store_fp_ns.to_string(),
    ]
    .join(",")
}

fn json_row(result: &BenchResult, trailing_comma: bool) -> String {
    let dataset_pages = result
        .large_pages_dataset
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string());
    let dataset_pages_1gb = result
        .large_pages_1gb_dataset
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string());
    let suffix = if trailing_comma { "," } else { "" };
    format!(
        "  {{\"mode\":\"{:?}\",\"jit\":{},\"jit_fast_regs\":{},\"jit_active\":{},\
\"iters\":{},\"inputs\":{},\"hashes\":{},\"elapsed_ns\":{},\"ns_per_hash\":{},\
\"jit_compiles\":{},\"jit_cache_hits\":{},\"jit_cache_misses\":{},\
\"jit_cache_evictions\":{},\"jit_compile_ns\":{},\"vm_exec_ns_interpreter\":{},\
\"vm_exec_ns_jit\":{},\"large_pages_requested\":{},\"large_pages_1gb_requested\":{},\
\"large_pages_dataset\":{},\"large_pages_1gb_dataset\":{},\"large_pages_scratchpad\":{},\
\"large_pages_1gb_scratchpad\":{},\"instr_int\":{},\"instr_float\":{},\"instr_mem\":{},\
\"instr_ctrl\":{},\"instr_store\":{},\"jit_fastregs_spill_count\":{},\
\"jit_fastregs_reload_count\":{},\"jit_fastregs_sync_to_ctx_count\":{},\
\"jit_fastregs_sync_from_ctx_count\":{},\"jit_fastregs_call_boundary_count\":{},\
\"jit_fastregs_call_boundary_float_nomem\":{},\"jit_fastregs_call_boundary_float_mem\":{},\
\"jit_fastregs_call_boundary_prepare_finish\":{},\
\"jit_fastregs_preserve_spill_count\":{},\"jit_fastregs_preserve_reload_count\":{},\
\"prefetch\":{},\"prefetch_distance\":{},\"prefetch_auto_tune\":{},\
\"scratchpad_prefetch_distance\":{},\"jit_fastregs_prepare_ns\":{},\
\"jit_fastregs_finish_ns\":{},\"jit_fastregs_light_cache_item_helper_calls\":{},\
\"jit_fastregs_light_cache_item_helper_ns\":{},\"finish_addr_select_ns\":{},\
\"finish_prefetch_ns\":{},\"finish_dataset_item_load_ns\":{},\
\"finish_light_cache_item_ns\":{},\"finish_r_xor_ns\":{},\"finish_store_int_ns\":{},\
\"finish_f_xor_e_ns\":{},\"finish_store_fp_ns\":{}}}{suffix}",
        result.mode,
        result.jit,
        result.jit_fast_regs,
        result.jit_active,
        result.iters,
        result.inputs,
        result.hashes,
        result.elapsed.as_nanos(),
        result.ns_per_hash,
        result.jit_compiles,
        result.jit_cache_hits,
        result.jit_cache_misses,
        result.jit_cache_evictions,
        result.jit_compile_ns,
        result.perf.vm_exec_ns_interpreter,
        result.perf.vm_exec_ns_jit,
        result.large_pages_requested,
        result.large_pages_1gb_requested,
        dataset_pages,
        dataset_pages_1gb,
        result.large_pages_scratchpad,
        result.large_pages_1gb_scratchpad,
        result.perf.instr_int,
        result.perf.instr_float,
        result.perf.instr_mem,
        result.perf.instr_ctrl,
        result.perf.instr_store,
        result.perf.jit_fastregs_spill_count,
        result.perf.jit_fastregs_reload_count,
        result.perf.jit_fastregs_sync_to_ctx_count,
        result.perf.jit_fastregs_sync_from_ctx_count,
        result.perf.jit_fastregs_call_boundary_count,
        result.perf.jit_fastregs_call_boundary_float_nomem,
        result.perf.jit_fastregs_call_boundary_float_mem,
        result.perf.jit_fastregs_call_boundary_prepare_finish,
        result.perf.jit_fastregs_preserve_spill_count,
        result.perf.jit_fastregs_preserve_reload_count,
        result.prefetch,
        result.prefetch_distance,
        result.prefetch_auto_tune,
        result.scratchpad_prefetch_distance,
        result.perf.jit_fastregs_prepare_ns,
        result.perf.jit_fastregs_finish_ns,
        result.perf.jit_fastregs_light_cache_item_helper_calls,
        result.perf.jit_fastregs_light_cache_item_helper_ns,
        result.perf.finish_addr_select_ns,
        result.perf.finish_prefetch_ns,
        result.perf.finish_dataset_item_load_ns,
        result.perf.finish_light_cache_item_ns,
        result.perf.finish_r_xor_ns,
        result.perf.finish_store_int_ns,
        result.perf.finish_f_xor_e_ns,
        result.perf.finish_store_fp_ns,
    )
}

fn env_flag(name: &str) -> bool {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(_) => return false,
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => false,
    }
}

fn env_usize(name: &str) -> Option<usize> {
    let value = env::var(name).ok()?;
    value.trim().parse::<usize>().ok()
}

fn parse_affinity_env() -> Option<AffinitySpec> {
    let value = env::var("OXIDE_RANDOMX_AFFINITY").ok()?;
    match AffinitySpec::parse(&value) {
        Ok(spec) => Some(spec),
        Err(err) => {
            eprintln!("warning: invalid OXIDE_RANDOMX_AFFINITY value ({err})");
            None
        }
    }
}

fn enabled_features() -> String {
    let mut features = Vec::new();
    if cfg!(feature = "jit") {
        features.push("jit");
    }
    if cfg!(feature = "jit-fastregs") {
        features.push("jit-fastregs");
    }
    if cfg!(feature = "bench-instrument") {
        features.push("bench-instrument");
    }
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

fn logical_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn quote_value(value: &str) -> String {
    let trimmed = value.trim();
    let mut out = String::with_capacity(trimmed.len() + 2);
    out.push('"');
    for ch in trimmed.chars() {
        match ch {
            '"' => out.push('\''),
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(target_os = "windows")]
fn cpu_model_string() -> String {
    env::var("PROCESSOR_IDENTIFIER")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(target_os = "linux")]
fn cpu_model_string() -> String {
    if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("model name") {
                if let Some(value) = rest.split_once(':').map(|x| x.1) {
                    let value = value.trim();
                    if !value.is_empty() {
                        return value.to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

#[cfg(target_os = "macos")]
fn cpu_model_string() -> String {
    if let Ok(output) = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
    {
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return value;
            }
        }
    }
    "unknown".to_string()
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn cpu_model_string() -> String {
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_result() -> BenchResult {
        BenchResult {
            mode: Mode::Light,
            jit: false,
            jit_fast_regs: false,
            jit_active: false,
            iters: 1,
            warmup: 0,
            threads: 1,
            large_pages_requested: false,
            large_pages_1gb_requested: false,
            large_pages_dataset: None,
            large_pages_1gb_dataset: None,
            large_pages_scratchpad: false,
            large_pages_1gb_scratchpad: false,
            prefetch: true,
            prefetch_distance: 2,
            prefetch_auto_tune: false,
            scratchpad_prefetch_distance: 1,
            thread_names: false,
            affinity: Some("off".to_string()),
            inputs: 1,
            hashes: 1,
            elapsed: Duration::from_nanos(100),
            ns_per_hash: 100,
            perf: PerfStats::default(),
            perf_measured: PerfStats::default(),
            jit_compiles: 0,
            jit_compiles_measured: 0,
            jit_cache_hits: 0,
            jit_cache_hits_measured: 0,
            jit_cache_misses: 0,
            jit_cache_misses_measured: 0,
            jit_cache_evictions: 0,
            jit_cache_evictions_measured: 0,
            jit_compile_ns: 0,
            jit_compile_ns_measured: 0,
        }
    }

    #[test]
    fn csv_header_appends_prefetch_columns() {
        let header = csv_header();
        let columns = header.split(',').collect::<Vec<_>>();
        let tail = &columns[columns.len() - 16..];
        assert_eq!(
            tail,
            [
                "prefetch",
                "prefetch_distance",
                "prefetch_auto_tune",
                "scratchpad_prefetch_distance",
                "jit_fastregs_prepare_ns",
                "jit_fastregs_finish_ns",
                "jit_fastregs_light_cache_item_helper_calls",
                "jit_fastregs_light_cache_item_helper_ns",
                "finish_addr_select_ns",
                "finish_prefetch_ns",
                "finish_dataset_item_load_ns",
                "finish_light_cache_item_ns",
                "finish_r_xor_ns",
                "finish_store_int_ns",
                "finish_f_xor_e_ns",
                "finish_store_fp_ns",
            ]
        );
    }

    #[test]
    fn csv_row_matches_header_and_emits_prefetch_values() {
        let result = sample_result();
        let header = csv_header();
        let row = csv_row(&result);
        let header_cols = header.split(',').collect::<Vec<_>>();
        let row_cols = row.split(',').collect::<Vec<_>>();
        assert_eq!(row_cols.len(), header_cols.len());
        assert_eq!(
            &row_cols[row_cols.len() - 16..],
            [
                "true", "2", "false", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0"
            ]
        );
    }

    #[test]
    fn json_row_emits_prefetch_fields() {
        let result = sample_result();
        let row = json_row(&result, false);
        let parsed: serde_json::Value = serde_json::from_str(&row).expect("json row should parse");
        assert_eq!(parsed["prefetch"], true);
        assert_eq!(parsed["prefetch_distance"], 2);
        assert_eq!(parsed["prefetch_auto_tune"], false);
        assert_eq!(parsed["scratchpad_prefetch_distance"], 1);
        assert_eq!(parsed["jit_fastregs_prepare_ns"], 0);
        assert_eq!(parsed["jit_fastregs_finish_ns"], 0);
        assert_eq!(parsed["jit_fastregs_light_cache_item_helper_calls"], 0);
        assert_eq!(parsed["jit_fastregs_light_cache_item_helper_ns"], 0);
        assert_eq!(parsed["finish_addr_select_ns"], 0);
        assert_eq!(parsed["finish_prefetch_ns"], 0);
        assert_eq!(parsed["finish_dataset_item_load_ns"], 0);
        assert_eq!(parsed["finish_light_cache_item_ns"], 0);
        assert_eq!(parsed["finish_r_xor_ns"], 0);
        assert_eq!(parsed["finish_store_int_ns"], 0);
        assert_eq!(parsed["finish_f_xor_e_ns"], 0);
        assert_eq!(parsed["finish_store_fp_ns"], 0);
    }
}
