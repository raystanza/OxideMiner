use oxide_randomx::{
    AffinitySpec, DatasetInitOptions, PerfStats, RandomXCache, RandomXConfig, RandomXDataset,
    RandomXFlags, RandomXVm,
};
use serde::Serialize;
use std::env;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Light,
    Fast,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Light => "light",
            Mode::Fast => "fast",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum OutputFormat {
    Human,
    Json,
    Csv,
}

struct Options {
    mode: Mode,
    iters: u64,
    warmup: u64,
    threads: usize,
    jit: bool,
    jit_fast_regs: bool,
    large_pages: bool,
    use_1gb_pages: bool,
    thread_names: bool,
    affinity: Option<AffinitySpec>,
    format: OutputFormat,
    out: Option<String>,
}

#[derive(Serialize)]
struct PerfReport {
    provenance: Provenance,
    params: Params,
    results: Results,
    stages: Stages,
    counters: Counters,
    jit: Option<JitReport>,
    instrumented: bool,
}

#[derive(Serialize)]
struct Provenance {
    git_sha: String,
    git_sha_short: String,
    git_dirty: String,
    features: String,
    cpu: String,
    cores: usize,
    rustc: String,
}

#[derive(Serialize)]
struct Params {
    mode: String,
    iters: u64,
    warmup: u64,
    threads: usize,
    inputs: usize,
    jit_requested: bool,
    jit_fast_regs: bool,
    large_pages_requested: bool,
    large_pages_1gb_requested: bool,
    thread_names: bool,
    affinity: Option<String>,
    prefetch: bool,
    prefetch_distance: u8,
    prefetch_auto_tune: bool,
    scratchpad_prefetch_distance: u8,
}

#[derive(Serialize)]
struct Results {
    hashes: u64,
    elapsed_ns: u64,
    ns_per_hash: u64,
    hashes_per_sec: f64,
    jit_active: bool,
    large_pages_dataset: Option<bool>,
    large_pages_1gb_dataset: Option<bool>,
    large_pages_scratchpad: bool,
    large_pages_1gb_scratchpad: bool,
}

#[derive(Serialize)]
struct Stages {
    cache_init_ns: u64,
    dataset_init_ns: Option<u64>,
    program_gen_ns: u64,
    prepare_iteration_ns: u64,
    jit_fastregs_prepare_ns: u64,
    execute_program_ns_interpreter: u64,
    execute_program_ns_jit: u64,
    finish_iteration_ns: u64,
    jit_fastregs_finish_ns: u64,
    finish_addr_select_ns: u64,
    finish_prefetch_ns: u64,
    finish_dataset_item_load_ns: u64,
    finish_light_cache_item_ns: u64,
    finish_r_xor_ns: u64,
    finish_store_int_ns: u64,
    finish_f_xor_e_ns: u64,
    finish_store_fp_ns: u64,
}

#[derive(Serialize)]
struct Counters {
    hashes: u64,
    program_execs: u64,
    scratchpad_read_bytes: u64,
    scratchpad_write_bytes: u64,
    dataset_item_loads: u64,
    mem_read_l1: u64,
    mem_read_l2: u64,
    mem_read_l3: u64,
    mem_write_l1: u64,
    mem_write_l2: u64,
    mem_write_l3: u64,
    instr_int: u64,
    instr_float: u64,
    instr_mem: u64,
    instr_ctrl: u64,
    instr_store: u64,
    jit_get_or_compile_calls: u64,
    jit_exec_calls: u64,
    jit_program_execs: u64,
    jit_helper_calls_float: u64,
    jit_helper_calls_cbranch: u64,
    jit_fastregs_spill_count: u64,
    jit_fastregs_reload_count: u64,
    jit_fastregs_sync_to_ctx_count: u64,
    jit_fastregs_sync_from_ctx_count: u64,
    jit_fastregs_call_boundary_count: u64,
    jit_fastregs_call_boundary_float_nomem: u64,
    jit_fastregs_call_boundary_float_mem: u64,
    jit_fastregs_call_boundary_prepare_finish: u64,
    jit_fastregs_preserve_spill_count: u64,
    jit_fastregs_preserve_reload_count: u64,
    jit_fastregs_light_cache_item_helper_calls: u64,
    jit_fastregs_light_cache_item_helper_ns: u64,
}

#[derive(Serialize)]
struct JitReport {
    total: JitStatsReport,
    measured: JitStatsReport,
}

#[derive(Serialize, Clone, Copy)]
struct JitStatsReport {
    compiles: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_evictions: u64,
    compile_ns: u64,
}

fn main() {
    let opts = parse_args();
    if opts.jit && !cfg!(feature = "jit") {
        eprintln!("jit requested but not compiled; rebuild with --features jit");
        std::process::exit(1);
    }
    if opts.jit_fast_regs && !cfg!(feature = "jit-fastregs") {
        eprintln!("jit-fast-regs requested but not compiled; rebuild with --features jit-fastregs");
        std::process::exit(1);
    }
    if opts.jit_fast_regs && !opts.jit {
        eprintln!("jit-fast-regs requires --jit on");
        std::process::exit(1);
    }

    let report = match run_harness(&opts) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("perf_harness failed: {err}");
            std::process::exit(1);
        }
    };

    emit_report(&opts, &report);
}

fn parse_args() -> Options {
    let mut mode = Mode::Light;
    let mut iters = 50u64;
    let mut warmup = 5u64;
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut jit = false;
    let mut jit_fast_regs = false;
    let mut large_pages = env_flag("OXIDE_RANDOMX_LARGE_PAGES");
    let use_1gb_pages = env_flag("OXIDE_RANDOMX_HUGE_1G");
    let mut thread_names = env_flag("OXIDE_RANDOMX_THREAD_NAMES");
    let mut affinity = parse_affinity_env();
    let mut format = OutputFormat::Human;
    let mut out = None;

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
            "--iters" => {
                iters = parse_u64(args.next().as_deref());
            }
            "--warmup" => {
                warmup = parse_u64(args.next().as_deref());
            }
            "--threads" => {
                threads = parse_usize(args.next().as_deref());
            }
            "--jit" => {
                jit = match args.next().as_deref() {
                    Some("on") => true,
                    Some("off") => false,
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
            "--large-pages" => {
                large_pages = parse_on_off(args.next().as_deref());
            }
            "--thread-names" => {
                thread_names = parse_on_off(args.next().as_deref());
            }
            "--affinity" => {
                let value = args.next().unwrap_or_else(|| usage_and_exit());
                affinity = parse_affinity_arg(&value);
            }
            "--format" => {
                format = match args.next().as_deref() {
                    Some("human") => OutputFormat::Human,
                    Some("json") => OutputFormat::Json,
                    Some("csv") => OutputFormat::Csv,
                    _ => usage_and_exit(),
                };
            }
            "--out" => {
                out = args.next().map(|value| value.to_string());
                if out.is_none() {
                    usage_and_exit();
                }
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
        iters,
        warmup,
        threads,
        jit,
        jit_fast_regs,
        large_pages,
        use_1gb_pages,
        thread_names,
        affinity,
        format,
        out,
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage: perf_harness [--mode light|fast] [--jit on|off] [--jit-fast-regs on|off]\n\
            [--iters N] [--warmup N] [--threads N] [--large-pages on|off] [--thread-names on|off]\n\
            [--affinity off|compact|spread|LIST] [--format human|json|csv] [--out PATH]"
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

fn parse_on_off(input: Option<&str>) -> bool {
    match input {
        Some("on") => true,
        Some("off") => false,
        _ => usage_and_exit(),
    }
}

fn parse_affinity_arg(input: &str) -> Option<AffinitySpec> {
    if input.eq_ignore_ascii_case("off") {
        return None;
    }
    match AffinitySpec::parse(input) {
        Ok(spec) => Some(spec),
        Err(err) => {
            eprintln!("invalid affinity value: {err}");
            std::process::exit(1);
        }
    }
}
fn run_harness(opts: &Options) -> Result<PerfReport, String> {
    let (key, inputs) = make_workload();
    let cfg = match opts.mode {
        Mode::Light => RandomXConfig::new(),
        Mode::Fast => fast_config()?,
    };

    let flags = build_flags(opts.jit, opts.jit_fast_regs, opts.large_pages);
    let prefetch = flags.prefetch;
    let prefetch_distance = flags.prefetch_distance;
    let prefetch_auto_tune = flags.prefetch_auto_tune;
    let scratchpad_prefetch_distance = flags.scratchpad_prefetch_distance;
    let cache_start = Instant::now();
    let cache = RandomXCache::new(&key, &cfg).map_err(|e| format!("{e:?}"))?;
    let cache_init_ns = cache_start.elapsed().as_nanos() as u64;

    let mut dataset_init_ns = None;
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
            let start = Instant::now();
            let dataset = RandomXDataset::new_with_options(&cache, &cfg, ds_opts)
                .map_err(|e| format!("{e:?}"))?;
            dataset_init_ns = Some(start.elapsed().as_nanos() as u64);
            dataset_large_pages = Some(dataset.uses_large_pages());
            dataset_large_pages_1gb = dataset
                .huge_page_size()
                .map(|size| size >= 1024 * 1024 * 1024);
            RandomXVm::new_fast(cache, dataset, cfg, flags).map_err(|e| format!("{e:?}"))?
        }
    };

    let scratchpad_large_pages = vm.scratchpad_uses_large_pages();
    let scratchpad_large_pages_1gb = vm
        .scratchpad_huge_page_size()
        .map(|size| size >= 1024 * 1024 * 1024)
        .unwrap_or(false);

    if opts.jit && !vm.is_jit_active() {
        eprintln!("warning: jit requested but not active; using interpreter");
    }

    for _ in 0..opts.warmup {
        for input in inputs.iter() {
            let out = vm.hash(std::hint::black_box(input));
            std::hint::black_box(out);
        }
    }

    vm.reset_perf_stats();
    #[cfg(feature = "jit")]
    let jit_stats_before = vm.jit_stats();

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
        (elapsed.as_nanos() / hashes as u128) as u64
    } else {
        0
    };
    let hashes_per_sec = if ns_per_hash > 0 {
        1_000_000_000f64 / ns_per_hash as f64
    } else {
        0.0
    };

    let perf = vm.perf_stats();
    #[cfg(feature = "jit")]
    let jit_stats_after = vm.jit_stats();
    #[cfg(feature = "jit")]
    let jit = build_jit_report(jit_stats_after, jit_stats_before);
    #[cfg(not(feature = "jit"))]
    let jit = None;

    let provenance = build_provenance();
    let params = Params {
        mode: opts.mode.as_str().to_string(),
        iters: opts.iters,
        warmup: opts.warmup,
        threads: opts.threads,
        inputs: inputs.len(),
        jit_requested: opts.jit,
        jit_fast_regs: opts.jit_fast_regs,
        large_pages_requested: opts.large_pages,
        large_pages_1gb_requested: opts.use_1gb_pages,
        thread_names: opts.thread_names,
        affinity: opts.affinity.as_ref().map(|spec| spec.to_string()),
        prefetch,
        prefetch_distance,
        prefetch_auto_tune,
        scratchpad_prefetch_distance,
    };
    let results = Results {
        hashes,
        elapsed_ns: elapsed.as_nanos() as u64,
        ns_per_hash,
        hashes_per_sec,
        jit_active: vm.is_jit_active(),
        large_pages_dataset: dataset_large_pages,
        large_pages_1gb_dataset: dataset_large_pages_1gb,
        large_pages_scratchpad: scratchpad_large_pages,
        large_pages_1gb_scratchpad: scratchpad_large_pages_1gb,
    };
    let stages = Stages {
        cache_init_ns,
        dataset_init_ns,
        program_gen_ns: perf.program_gen_ns,
        prepare_iteration_ns: perf.prepare_iteration_ns,
        jit_fastregs_prepare_ns: perf.jit_fastregs_prepare_ns,
        execute_program_ns_interpreter: perf.vm_exec_ns_interpreter,
        execute_program_ns_jit: perf.vm_exec_ns_jit,
        finish_iteration_ns: perf.finish_iteration_ns,
        jit_fastregs_finish_ns: perf.jit_fastregs_finish_ns,
        finish_addr_select_ns: perf.finish_addr_select_ns,
        finish_prefetch_ns: perf.finish_prefetch_ns,
        finish_dataset_item_load_ns: perf.finish_dataset_item_load_ns,
        finish_light_cache_item_ns: perf.finish_light_cache_item_ns,
        finish_r_xor_ns: perf.finish_r_xor_ns,
        finish_store_int_ns: perf.finish_store_int_ns,
        finish_f_xor_e_ns: perf.finish_f_xor_e_ns,
        finish_store_fp_ns: perf.finish_store_fp_ns,
    };
    let counters = counters_from_perf(perf);

    Ok(PerfReport {
        provenance,
        params,
        results,
        stages,
        counters,
        jit,
        instrumented: cfg!(feature = "bench-instrument"),
    })
}

#[cfg(feature = "jit")]
fn build_jit_report(
    after: oxide_randomx::jit::JitStats,
    before: oxide_randomx::jit::JitStats,
) -> Option<JitReport> {
    let total = jit_stats_to_report(after);
    let measured = JitStatsReport {
        compiles: total.compiles.saturating_sub(before.compiles),
        cache_hits: total.cache_hits.saturating_sub(before.cache_hits),
        cache_misses: total.cache_misses.saturating_sub(before.cache_misses),
        cache_evictions: total.cache_evictions.saturating_sub(before.cache_evictions),
        compile_ns: total.compile_ns.saturating_sub(before.compile_ns),
    };
    Some(JitReport { total, measured })
}

#[cfg(feature = "jit")]
fn jit_stats_to_report(stats: oxide_randomx::jit::JitStats) -> JitStatsReport {
    JitStatsReport {
        compiles: stats.compiles,
        cache_hits: stats.cache_hits,
        cache_misses: stats.cache_misses,
        cache_evictions: stats.cache_evictions,
        compile_ns: stats.compile_ns,
    }
}

fn counters_from_perf(perf: PerfStats) -> Counters {
    Counters {
        hashes: perf.hashes,
        program_execs: perf.program_execs,
        scratchpad_read_bytes: perf.scratchpad_read_bytes,
        scratchpad_write_bytes: perf.scratchpad_write_bytes,
        dataset_item_loads: perf.dataset_item_loads,
        mem_read_l1: perf.mem_read_l1,
        mem_read_l2: perf.mem_read_l2,
        mem_read_l3: perf.mem_read_l3,
        mem_write_l1: perf.mem_write_l1,
        mem_write_l2: perf.mem_write_l2,
        mem_write_l3: perf.mem_write_l3,
        instr_int: perf.instr_int,
        instr_float: perf.instr_float,
        instr_mem: perf.instr_mem,
        instr_ctrl: perf.instr_ctrl,
        instr_store: perf.instr_store,
        jit_get_or_compile_calls: perf.jit_get_or_compile_calls,
        jit_exec_calls: perf.jit_exec_calls,
        jit_program_execs: perf.jit_program_execs,
        jit_helper_calls_float: perf.jit_helper_calls_float,
        jit_helper_calls_cbranch: perf.jit_helper_calls_cbranch,
        jit_fastregs_spill_count: perf.jit_fastregs_spill_count,
        jit_fastregs_reload_count: perf.jit_fastregs_reload_count,
        jit_fastregs_sync_to_ctx_count: perf.jit_fastregs_sync_to_ctx_count,
        jit_fastregs_sync_from_ctx_count: perf.jit_fastregs_sync_from_ctx_count,
        jit_fastregs_call_boundary_count: perf.jit_fastregs_call_boundary_count,
        jit_fastregs_call_boundary_float_nomem: perf.jit_fastregs_call_boundary_float_nomem,
        jit_fastregs_call_boundary_float_mem: perf.jit_fastregs_call_boundary_float_mem,
        jit_fastregs_call_boundary_prepare_finish: perf.jit_fastregs_call_boundary_prepare_finish,
        jit_fastregs_preserve_spill_count: perf.jit_fastregs_preserve_spill_count,
        jit_fastregs_preserve_reload_count: perf.jit_fastregs_preserve_reload_count,
        jit_fastregs_light_cache_item_helper_calls: perf.jit_fastregs_light_cache_item_helper_calls,
        jit_fastregs_light_cache_item_helper_ns: perf.jit_fastregs_light_cache_item_helper_ns,
    }
}
fn emit_report(opts: &Options, report: &PerfReport) {
    let summary = summary_line(report);
    match opts.format {
        OutputFormat::Human => {
            let output = format_human(report);
            if let Some(path) = opts.out.as_deref() {
                write_output(path, &output);
                println!("{summary}");
            } else {
                print!("{output}");
            }
        }
        OutputFormat::Json => {
            let output = format_json(report);
            eprintln!("{summary}");
            if let Some(path) = opts.out.as_deref() {
                write_output(path, &output);
            } else {
                print!("{output}");
            }
        }
        OutputFormat::Csv => {
            let output = format_csv(report);
            eprintln!("{summary}");
            if let Some(path) = opts.out.as_deref() {
                write_output(path, &output);
            } else {
                print!("{output}");
            }
        }
    }
}

fn summary_line(report: &PerfReport) -> String {
    format!(
        "summary mode={} jit_requested={} jit_active={} hashes={} ns_per_hash={} hashes_per_sec={:.3}",
        report.params.mode,
        report.params.jit_requested,
        report.results.jit_active,
        report.results.hashes,
        report.results.ns_per_hash,
        report.results.hashes_per_sec
    )
}

fn format_human(report: &PerfReport) -> String {
    let mut out = String::new();
    let dataset_pages = match report.results.large_pages_dataset {
        Some(value) => value.to_string(),
        None => "n/a".to_string(),
    };
    let dataset_pages_1gb = match report.results.large_pages_1gb_dataset {
        Some(value) => value.to_string(),
        None => "n/a".to_string(),
    };
    let affinity = report.params.affinity.as_deref().unwrap_or("off");
    let dataset_init = report
        .stages
        .dataset_init_ns
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    out.push_str(&format!("{}\n", summary_line(report)));
    out.push_str(&format!(
        "provenance git_sha={} git_sha_short={} git_dirty={} features={} cpu={} cores={} rustc={}\n",
        report.provenance.git_sha,
        report.provenance.git_sha_short,
        report.provenance.git_dirty,
        report.provenance.features,
        quote_value(&report.provenance.cpu),
        report.provenance.cores,
        quote_value(&report.provenance.rustc)
    ));
    out.push_str(&format!(
        "params mode={} iters={} warmup={} threads={} inputs={} jit_requested={} jit_fast_regs={} \
large_pages_requested={} large_pages_1gb_requested={} thread_names={} affinity={} \
prefetch={} prefetch_distance={} prefetch_auto_tune={} scratchpad_prefetch_distance={}\n",
        report.params.mode,
        report.params.iters,
        report.params.warmup,
        report.params.threads,
        report.params.inputs,
        report.params.jit_requested,
        report.params.jit_fast_regs,
        report.params.large_pages_requested,
        report.params.large_pages_1gb_requested,
        report.params.thread_names,
        affinity,
        report.params.prefetch,
        report.params.prefetch_distance,
        report.params.prefetch_auto_tune,
        report.params.scratchpad_prefetch_distance
    ));
    out.push_str(&format!(
        "results hashes={} elapsed_ns={} ns_per_hash={} hashes_per_sec={:.3} \
jit_active={} large_pages_dataset={} large_pages_1gb_dataset={} \
large_pages_scratchpad={} large_pages_1gb_scratchpad={}\n",
        report.results.hashes,
        report.results.elapsed_ns,
        report.results.ns_per_hash,
        report.results.hashes_per_sec,
        report.results.jit_active,
        dataset_pages,
        dataset_pages_1gb,
        report.results.large_pages_scratchpad,
        report.results.large_pages_1gb_scratchpad
    ));
    out.push_str(&format!(
        "stages cache_init_ns={} dataset_init_ns={} program_gen_ns={} prepare_iteration_ns={} \
jit_fastregs_prepare_ns={} execute_program_ns_interpreter={} execute_program_ns_jit={} \
finish_iteration_ns={} jit_fastregs_finish_ns={} finish_addr_select_ns={} \
finish_prefetch_ns={} finish_dataset_item_load_ns={} finish_light_cache_item_ns={} \
finish_r_xor_ns={} finish_store_int_ns={} finish_f_xor_e_ns={} finish_store_fp_ns={}\n",
        report.stages.cache_init_ns,
        dataset_init,
        report.stages.program_gen_ns,
        report.stages.prepare_iteration_ns,
        report.stages.jit_fastregs_prepare_ns,
        report.stages.execute_program_ns_interpreter,
        report.stages.execute_program_ns_jit,
        report.stages.finish_iteration_ns,
        report.stages.jit_fastregs_finish_ns,
        report.stages.finish_addr_select_ns,
        report.stages.finish_prefetch_ns,
        report.stages.finish_dataset_item_load_ns,
        report.stages.finish_light_cache_item_ns,
        report.stages.finish_r_xor_ns,
        report.stages.finish_store_int_ns,
        report.stages.finish_f_xor_e_ns,
        report.stages.finish_store_fp_ns
    ));
    out.push_str(&format!(
        "counters program_execs={} scratchpad_read_bytes={} scratchpad_write_bytes={} \
dataset_item_loads={} mem_read_l1={} mem_read_l2={} mem_read_l3={} mem_write_l1={} \
mem_write_l2={} mem_write_l3={}\n",
        report.counters.program_execs,
        report.counters.scratchpad_read_bytes,
        report.counters.scratchpad_write_bytes,
        report.counters.dataset_item_loads,
        report.counters.mem_read_l1,
        report.counters.mem_read_l2,
        report.counters.mem_read_l3,
        report.counters.mem_write_l1,
        report.counters.mem_write_l2,
        report.counters.mem_write_l3
    ));
    out.push_str(&format!(
        "instr_mix instr_int={} instr_float={} instr_mem={} instr_ctrl={} instr_store={}\n",
        report.counters.instr_int,
        report.counters.instr_float,
        report.counters.instr_mem,
        report.counters.instr_ctrl,
        report.counters.instr_store
    ));
    out.push_str(&format!(
        "jit_calls jit_get_or_compile_calls={} jit_exec_calls={} jit_program_execs={} \
jit_helper_calls_float={} jit_helper_calls_cbranch={}\n",
        report.counters.jit_get_or_compile_calls,
        report.counters.jit_exec_calls,
        report.counters.jit_program_execs,
        report.counters.jit_helper_calls_float,
        report.counters.jit_helper_calls_cbranch
    ));
    out.push_str(&format!(
        "jit_fastregs spill_count={} reload_count={} sync_to_ctx_count={} sync_from_ctx_count={} \
call_boundary_count={} call_boundary_float_nomem={} call_boundary_float_mem={} \
call_boundary_prepare_finish={} preserve_spill_count={} preserve_reload_count={} \
light_cache_item_helper_calls={} light_cache_item_helper_ns={}\n",
        report.counters.jit_fastregs_spill_count,
        report.counters.jit_fastregs_reload_count,
        report.counters.jit_fastregs_sync_to_ctx_count,
        report.counters.jit_fastregs_sync_from_ctx_count,
        report.counters.jit_fastregs_call_boundary_count,
        report.counters.jit_fastregs_call_boundary_float_nomem,
        report.counters.jit_fastregs_call_boundary_float_mem,
        report.counters.jit_fastregs_call_boundary_prepare_finish,
        report.counters.jit_fastregs_preserve_spill_count,
        report.counters.jit_fastregs_preserve_reload_count,
        report.counters.jit_fastregs_light_cache_item_helper_calls,
        report.counters.jit_fastregs_light_cache_item_helper_ns
    ));
    if let Some(jit) = &report.jit {
        out.push_str(&format!(
            "jit_stats_total compiles={} cache_hits={} cache_misses={} cache_evictions={} compile_ns={}\n",
            jit.total.compiles,
            jit.total.cache_hits,
            jit.total.cache_misses,
            jit.total.cache_evictions,
            jit.total.compile_ns
        ));
        out.push_str(&format!(
            "jit_stats_measured compiles={} cache_hits={} cache_misses={} cache_evictions={} \
compile_ns={}\n",
            jit.measured.compiles,
            jit.measured.cache_hits,
            jit.measured.cache_misses,
            jit.measured.cache_evictions,
            jit.measured.compile_ns
        ));
    }
    out.push_str(&format!("instrumented={}\n", report.instrumented));
    out
}

fn format_json(report: &PerfReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

fn format_csv(report: &PerfReport) -> String {
    let mut out = String::new();
    out.push_str(&csv_header());
    out.push('\n');
    out.push_str(&csv_row(report));
    out.push('\n');
    out
}

fn csv_header() -> String {
    [
        "git_sha",
        "git_sha_short",
        "git_dirty",
        "features",
        "cpu",
        "cores",
        "rustc",
        "mode",
        "iters",
        "warmup",
        "threads",
        "inputs",
        "jit_requested",
        "jit_fast_regs",
        "jit_active",
        "large_pages_requested",
        "large_pages_1gb_requested",
        "large_pages_dataset",
        "large_pages_1gb_dataset",
        "large_pages_scratchpad",
        "large_pages_1gb_scratchpad",
        "thread_names",
        "affinity",
        "hashes",
        "elapsed_ns",
        "ns_per_hash",
        "hashes_per_sec",
        "cache_init_ns",
        "dataset_init_ns",
        "program_gen_ns",
        "prepare_iteration_ns",
        "execute_program_ns_interpreter",
        "execute_program_ns_jit",
        "finish_iteration_ns",
        "program_execs",
        "scratchpad_read_bytes",
        "scratchpad_write_bytes",
        "dataset_item_loads",
        "mem_read_l1",
        "mem_read_l2",
        "mem_read_l3",
        "mem_write_l1",
        "mem_write_l2",
        "mem_write_l3",
        "instr_int",
        "instr_float",
        "instr_mem",
        "instr_ctrl",
        "instr_store",
        "jit_get_or_compile_calls",
        "jit_exec_calls",
        "jit_program_execs",
        "jit_helper_calls_float",
        "jit_helper_calls_cbranch",
        "jit_fastregs_spill_count",
        "jit_fastregs_reload_count",
        "jit_fastregs_sync_to_ctx_count",
        "jit_fastregs_sync_from_ctx_count",
        "jit_fastregs_call_boundary_count",
        "jit_fastregs_call_boundary_float_nomem",
        "jit_fastregs_call_boundary_float_mem",
        "jit_fastregs_call_boundary_prepare_finish",
        "jit_fastregs_preserve_spill_count",
        "jit_fastregs_preserve_reload_count",
        "jit_compiles_total",
        "jit_cache_hits_total",
        "jit_cache_misses_total",
        "jit_cache_evictions_total",
        "jit_compile_ns_total",
        "jit_compiles_measured",
        "jit_cache_hits_measured",
        "jit_cache_misses_measured",
        "jit_cache_evictions_measured",
        "jit_compile_ns_measured",
        "instrumented",
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
    .join(",")
}

fn csv_row(report: &PerfReport) -> String {
    let affinity = report.params.affinity.as_deref().unwrap_or("off");
    let dataset_pages = report
        .results
        .large_pages_dataset
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let dataset_pages_1gb = report
        .results
        .large_pages_1gb_dataset
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let dataset_init = report
        .stages
        .dataset_init_ns
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string());
    let (jit_total, jit_measured) = if let Some(jit) = &report.jit {
        (jit.total, jit.measured)
    } else {
        (
            JitStatsReport {
                compiles: 0,
                cache_hits: 0,
                cache_misses: 0,
                cache_evictions: 0,
                compile_ns: 0,
            },
            JitStatsReport {
                compiles: 0,
                cache_hits: 0,
                cache_misses: 0,
                cache_evictions: 0,
                compile_ns: 0,
            },
        )
    };
    [
        csv_escape(&report.provenance.git_sha),
        csv_escape(&report.provenance.git_sha_short),
        csv_escape(&report.provenance.git_dirty),
        csv_escape(&report.provenance.features),
        csv_escape(&report.provenance.cpu),
        report.provenance.cores.to_string(),
        csv_escape(&report.provenance.rustc),
        report.params.mode.clone(),
        report.params.iters.to_string(),
        report.params.warmup.to_string(),
        report.params.threads.to_string(),
        report.params.inputs.to_string(),
        report.params.jit_requested.to_string(),
        report.params.jit_fast_regs.to_string(),
        report.results.jit_active.to_string(),
        report.params.large_pages_requested.to_string(),
        report.params.large_pages_1gb_requested.to_string(),
        dataset_pages,
        dataset_pages_1gb,
        report.results.large_pages_scratchpad.to_string(),
        report.results.large_pages_1gb_scratchpad.to_string(),
        report.params.thread_names.to_string(),
        csv_escape(affinity),
        report.results.hashes.to_string(),
        report.results.elapsed_ns.to_string(),
        report.results.ns_per_hash.to_string(),
        report.results.hashes_per_sec.to_string(),
        report.stages.cache_init_ns.to_string(),
        dataset_init,
        report.stages.program_gen_ns.to_string(),
        report.stages.prepare_iteration_ns.to_string(),
        report.stages.execute_program_ns_interpreter.to_string(),
        report.stages.execute_program_ns_jit.to_string(),
        report.stages.finish_iteration_ns.to_string(),
        report.counters.program_execs.to_string(),
        report.counters.scratchpad_read_bytes.to_string(),
        report.counters.scratchpad_write_bytes.to_string(),
        report.counters.dataset_item_loads.to_string(),
        report.counters.mem_read_l1.to_string(),
        report.counters.mem_read_l2.to_string(),
        report.counters.mem_read_l3.to_string(),
        report.counters.mem_write_l1.to_string(),
        report.counters.mem_write_l2.to_string(),
        report.counters.mem_write_l3.to_string(),
        report.counters.instr_int.to_string(),
        report.counters.instr_float.to_string(),
        report.counters.instr_mem.to_string(),
        report.counters.instr_ctrl.to_string(),
        report.counters.instr_store.to_string(),
        report.counters.jit_get_or_compile_calls.to_string(),
        report.counters.jit_exec_calls.to_string(),
        report.counters.jit_program_execs.to_string(),
        report.counters.jit_helper_calls_float.to_string(),
        report.counters.jit_helper_calls_cbranch.to_string(),
        report.counters.jit_fastregs_spill_count.to_string(),
        report.counters.jit_fastregs_reload_count.to_string(),
        report.counters.jit_fastregs_sync_to_ctx_count.to_string(),
        report.counters.jit_fastregs_sync_from_ctx_count.to_string(),
        report.counters.jit_fastregs_call_boundary_count.to_string(),
        report
            .counters
            .jit_fastregs_call_boundary_float_nomem
            .to_string(),
        report
            .counters
            .jit_fastregs_call_boundary_float_mem
            .to_string(),
        report
            .counters
            .jit_fastregs_call_boundary_prepare_finish
            .to_string(),
        report
            .counters
            .jit_fastregs_preserve_spill_count
            .to_string(),
        report
            .counters
            .jit_fastregs_preserve_reload_count
            .to_string(),
        jit_total.compiles.to_string(),
        jit_total.cache_hits.to_string(),
        jit_total.cache_misses.to_string(),
        jit_total.cache_evictions.to_string(),
        jit_total.compile_ns.to_string(),
        jit_measured.compiles.to_string(),
        jit_measured.cache_hits.to_string(),
        jit_measured.cache_misses.to_string(),
        jit_measured.cache_evictions.to_string(),
        jit_measured.compile_ns.to_string(),
        report.instrumented.to_string(),
        report.params.prefetch.to_string(),
        report.params.prefetch_distance.to_string(),
        report.params.prefetch_auto_tune.to_string(),
        report.params.scratchpad_prefetch_distance.to_string(),
        report.stages.jit_fastregs_prepare_ns.to_string(),
        report.stages.jit_fastregs_finish_ns.to_string(),
        report
            .counters
            .jit_fastregs_light_cache_item_helper_calls
            .to_string(),
        report
            .counters
            .jit_fastregs_light_cache_item_helper_ns
            .to_string(),
        report.stages.finish_addr_select_ns.to_string(),
        report.stages.finish_prefetch_ns.to_string(),
        report.stages.finish_dataset_item_load_ns.to_string(),
        report.stages.finish_light_cache_item_ns.to_string(),
        report.stages.finish_r_xor_ns.to_string(),
        report.stages.finish_store_int_ns.to_string(),
        report.stages.finish_f_xor_e_ns.to_string(),
        report.stages.finish_store_fp_ns.to_string(),
    ]
    .join(",")
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn write_output(path: &str, output: &str) {
    if let Err(err) = std::fs::write(path, output) {
        eprintln!("failed to write {path}: {err}");
        std::process::exit(1);
    }
}
fn build_provenance() -> Provenance {
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
    Provenance {
        git_sha: git_sha.to_string(),
        git_sha_short: git_sha_short.to_string(),
        git_dirty: git_dirty.to_string(),
        features: enabled_features(),
        cpu: cpu_model_string(),
        cores: logical_cores(),
        rustc: rustc.to_string(),
    }
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

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
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

fn build_flags(jit_on: bool, jit_fast_regs: bool, large_pages: bool) -> RandomXFlags {
    #[cfg(feature = "jit")]
    {
        RandomXFlags {
            large_pages_plumbing: large_pages,
            jit: jit_on,
            jit_fast_regs,
            ..RandomXFlags::from_env()
        }
    }
    #[cfg(not(feature = "jit"))]
    {
        let _ = (jit_on, jit_fast_regs);
        RandomXFlags {
            large_pages_plumbing: large_pages,
            ..RandomXFlags::from_env()
        }
    }
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

    fn sample_report() -> PerfReport {
        PerfReport {
            provenance: Provenance {
                git_sha: "sha".to_string(),
                git_sha_short: "sha1234".to_string(),
                git_dirty: "false".to_string(),
                features: "bench-instrument".to_string(),
                cpu: "cpu".to_string(),
                cores: 1,
                rustc: "rustc".to_string(),
            },
            params: Params {
                mode: "light".to_string(),
                iters: 1,
                warmup: 0,
                threads: 1,
                inputs: 1,
                jit_requested: false,
                jit_fast_regs: false,
                large_pages_requested: false,
                large_pages_1gb_requested: false,
                thread_names: false,
                affinity: Some("off".to_string()),
                prefetch: true,
                prefetch_distance: 2,
                prefetch_auto_tune: false,
                scratchpad_prefetch_distance: 1,
            },
            results: Results {
                hashes: 1,
                elapsed_ns: 1,
                ns_per_hash: 1,
                hashes_per_sec: 1.0,
                jit_active: false,
                large_pages_dataset: None,
                large_pages_1gb_dataset: None,
                large_pages_scratchpad: false,
                large_pages_1gb_scratchpad: false,
            },
            stages: Stages {
                cache_init_ns: 1,
                dataset_init_ns: None,
                program_gen_ns: 1,
                prepare_iteration_ns: 1,
                jit_fastregs_prepare_ns: 0,
                execute_program_ns_interpreter: 1,
                execute_program_ns_jit: 0,
                finish_iteration_ns: 1,
                jit_fastregs_finish_ns: 0,
                finish_addr_select_ns: 0,
                finish_prefetch_ns: 0,
                finish_dataset_item_load_ns: 0,
                finish_light_cache_item_ns: 0,
                finish_r_xor_ns: 0,
                finish_store_int_ns: 0,
                finish_f_xor_e_ns: 0,
                finish_store_fp_ns: 0,
            },
            counters: Counters {
                hashes: 1,
                program_execs: 1,
                scratchpad_read_bytes: 1,
                scratchpad_write_bytes: 1,
                dataset_item_loads: 1,
                mem_read_l1: 1,
                mem_read_l2: 1,
                mem_read_l3: 1,
                mem_write_l1: 1,
                mem_write_l2: 1,
                mem_write_l3: 1,
                instr_int: 1,
                instr_float: 1,
                instr_mem: 1,
                instr_ctrl: 1,
                instr_store: 1,
                jit_get_or_compile_calls: 0,
                jit_exec_calls: 0,
                jit_program_execs: 0,
                jit_helper_calls_float: 0,
                jit_helper_calls_cbranch: 0,
                jit_fastregs_spill_count: 0,
                jit_fastregs_reload_count: 0,
                jit_fastregs_sync_to_ctx_count: 0,
                jit_fastregs_sync_from_ctx_count: 0,
                jit_fastregs_call_boundary_count: 0,
                jit_fastregs_call_boundary_float_nomem: 0,
                jit_fastregs_call_boundary_float_mem: 0,
                jit_fastregs_call_boundary_prepare_finish: 0,
                jit_fastregs_preserve_spill_count: 0,
                jit_fastregs_preserve_reload_count: 0,
                jit_fastregs_light_cache_item_helper_calls: 0,
                jit_fastregs_light_cache_item_helper_ns: 0,
            },
            jit: None,
            instrumented: true,
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
        let report = sample_report();
        let header = csv_header();
        let row = csv_row(&report);
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
    fn human_output_contains_prefetch_fields() {
        let report = sample_report();
        let output = format_human(&report);
        assert!(output.contains("prefetch=true"));
        assert!(output.contains("prefetch_distance=2"));
        assert!(output.contains("prefetch_auto_tune=false"));
        assert!(output.contains("scratchpad_prefetch_distance=1"));
        assert!(output.contains("jit_fastregs_prepare_ns=0"));
        assert!(output.contains("jit_fastregs_finish_ns=0"));
        assert!(output.contains("light_cache_item_helper_calls=0"));
        assert!(output.contains("light_cache_item_helper_ns=0"));
        assert!(output.contains("finish_addr_select_ns=0"));
        assert!(output.contains("finish_prefetch_ns=0"));
        assert!(output.contains("finish_dataset_item_load_ns=0"));
        assert!(output.contains("finish_light_cache_item_ns=0"));
        assert!(output.contains("finish_r_xor_ns=0"));
        assert!(output.contains("finish_store_int_ns=0"));
        assert!(output.contains("finish_f_xor_e_ns=0"));
        assert!(output.contains("finish_store_fp_ns=0"));
    }
}
