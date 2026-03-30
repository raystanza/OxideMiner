//! Host-local prefetch calibration helper.
//!
//! This tool performs a bounded fixed-distance sweep and can persist one
//! host/mode/code-scoped recommendation for later reuse.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oxide_randomx::prefetch_calibration::{
    upsert_calibration_record, PrefetchCalibrationRecord, PrefetchCodeIdentity,
    PrefetchCpuIdentity, PrefetchScenarioKey, PREFETCH_CALIBRATION_WORKLOAD_ID,
};
use oxide_randomx::{
    DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Human,
    Json,
    Csv,
}

#[derive(Debug)]
struct Options {
    mode: Mode,
    jit_requested: bool,
    jit_fast_regs: bool,
    iters: u64,
    warmup: u64,
    rounds: u32,
    distances: Vec<u8>,
    threads: usize,
    scratchpad_prefetch_distance: u8,
    format: OutputFormat,
    out: Option<PathBuf>,
    persist: Option<PathBuf>,
    workload_id: String,
}

#[derive(Debug)]
struct DistanceSummary {
    distance: u8,
    samples: usize,
    mean_ns_per_hash: u64,
    min_ns_per_hash: u64,
    max_ns_per_hash: u64,
}

#[derive(Debug)]
struct DistanceRun {
    round: u32,
    distance: u8,
    ns_per_hash: u64,
}

#[derive(Debug)]
struct CalibrationReport {
    code: PrefetchCodeIdentity,
    cpu: PrefetchCpuIdentity,
    scenario: PrefetchScenarioKey,
    rounds: u32,
    iters: u64,
    warmup: u64,
    best_distance: u8,
    best_mean_ns_per_hash: u64,
    summaries: Vec<DistanceSummary>,
    runs: Vec<DistanceRun>,
    persisted_path: Option<String>,
}

fn main() {
    match run(parse_args()) {
        Ok((format, out_path, output)) => {
            if let Some(path) = out_path {
                if let Some(parent) = path.parent() {
                    if let Err(err) = fs::create_dir_all(parent) {
                        eprintln!("create {}: {err}", parent.display());
                        std::process::exit(1);
                    }
                }
                if let Err(err) = fs::write(&path, output) {
                    eprintln!("write {}: {err}", path.display());
                    std::process::exit(1);
                }
                if format == OutputFormat::Human {
                    eprintln!("wrote calibration report to {}", path.display());
                }
            } else {
                println!("{output}");
            }
        }
        Err(err) => {
            eprintln!("prefetch_calibrate error: {err}");
            std::process::exit(1);
        }
    }
}

fn run(opts: Options) -> Result<(OutputFormat, Option<PathBuf>, String), String> {
    let code = PrefetchCodeIdentity::current();
    let cpu = PrefetchCpuIdentity::current();
    let scenario = PrefetchScenarioKey::new(
        opts.mode.as_str(),
        opts.jit_requested,
        opts.jit_fast_regs,
        opts.scratchpad_prefetch_distance,
        opts.workload_id.clone(),
    );

    let mut runs = Vec::new();
    for round in 0..opts.rounds {
        let ordered = deterministic_round_order(&opts.distances, round);
        for distance in ordered {
            let ns_per_hash = run_single_distance(&opts, distance)?;
            runs.push(DistanceRun {
                round,
                distance,
                ns_per_hash,
            });
        }
    }

    let summaries = summarize_runs(&runs);
    let best = summaries
        .iter()
        .min_by_key(|row| (row.mean_ns_per_hash, row.distance))
        .ok_or_else(|| "no calibration summaries produced".to_string())?;

    let mut persisted_path = None;
    if let Some(path) = opts.persist.as_ref() {
        let record = PrefetchCalibrationRecord {
            code: code.clone(),
            cpu: cpu.clone(),
            scenario: scenario.clone(),
            best_prefetch_distance: best.distance,
            best_ns_per_hash: best.mean_ns_per_hash,
            rounds: opts.rounds,
            iters_per_round: opts.iters,
            warmup_per_round: opts.warmup,
            calibrated_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("clock error: {e}"))?
                .as_secs(),
        };
        upsert_calibration_record(path, record)?;
        persisted_path = Some(path.display().to_string());
    }

    let report = CalibrationReport {
        code,
        cpu,
        scenario,
        rounds: opts.rounds,
        iters: opts.iters,
        warmup: opts.warmup,
        best_distance: best.distance,
        best_mean_ns_per_hash: best.mean_ns_per_hash,
        summaries,
        runs,
        persisted_path,
    };

    let output = match opts.format {
        OutputFormat::Human => format_human(&report),
        OutputFormat::Json => format_json(&report),
        OutputFormat::Csv => format_csv(&report),
    };
    Ok((opts.format, opts.out, output))
}

fn parse_args() -> Options {
    let mut mode = Mode::Light;
    let mut jit_requested = false;
    let mut jit_fast_regs = false;
    let mut iters = 20u64;
    let mut warmup = 2u64;
    let mut rounds = 3u32;
    let mut distances = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let mut scratchpad_prefetch_distance = 0u8;
    let mut format = OutputFormat::Human;
    let mut out = None;
    let mut persist = None;
    let mut workload_id = PREFETCH_CALIBRATION_WORKLOAD_ID.to_string();

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
                jit_requested = parse_on_off(args.next().as_deref());
            }
            "--jit-fast-regs" => {
                jit_fast_regs = parse_on_off(args.next().as_deref());
            }
            "--iters" => {
                iters = parse_u64(args.next().as_deref());
            }
            "--warmup" => {
                warmup = parse_u64(args.next().as_deref());
            }
            "--rounds" => {
                rounds = parse_u32(args.next().as_deref());
            }
            "--distances" => {
                distances = parse_distance_list(args.next().as_deref());
            }
            "--threads" => {
                threads = parse_usize(args.next().as_deref()).max(1);
            }
            "--scratchpad-prefetch-distance" => {
                scratchpad_prefetch_distance = parse_u8(args.next().as_deref());
                if scratchpad_prefetch_distance > 32 {
                    usage_and_exit();
                }
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
                out = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| usage_and_exit()),
                ));
            }
            "--persist" => {
                persist = Some(PathBuf::from(
                    args.next().unwrap_or_else(|| usage_and_exit()),
                ));
            }
            "--workload-id" => {
                workload_id = args.next().unwrap_or_else(|| usage_and_exit());
            }
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }

    if distances.is_empty() || rounds == 0 || iters == 0 {
        usage_and_exit();
    }

    Options {
        mode,
        jit_requested,
        jit_fast_regs,
        iters,
        warmup,
        rounds,
        distances,
        threads,
        scratchpad_prefetch_distance,
        format,
        out,
        persist,
        workload_id,
    }
}

fn parse_u64(input: Option<&str>) -> u64 {
    input
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn parse_u32(input: Option<&str>) -> u32 {
    input
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn parse_u8(input: Option<&str>) -> u8 {
    input
        .and_then(|value| value.parse::<u8>().ok())
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

fn parse_distance_list(input: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    let raw = input.unwrap_or_else(|| usage_and_exit());
    for token in raw.split(',') {
        if token.is_empty() {
            usage_and_exit();
        }
        let dist = token.parse::<u8>().ok().unwrap_or_else(|| usage_and_exit());
        if dist > 8 {
            usage_and_exit();
        }
        if !out.contains(&dist) {
            out.push(dist);
        }
    }
    out
}

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage: prefetch_calibrate [--mode light|fast] [--jit on|off] [--jit-fast-regs on|off]\n\
         [--iters N] [--warmup N] [--rounds N] [--distances 0,1,2,...,8] [--threads N]\n\
         [--scratchpad-prefetch-distance N] [--format human|json|csv] [--out PATH]\n\
         [--persist PATH] [--workload-id ID]"
    );
    std::process::exit(1);
}

fn deterministic_round_order(distances: &[u8], round: u32) -> Vec<u8> {
    let mut out = distances.to_vec();
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ ((round as u64) << 24);
    for idx in (1..out.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let swap_idx = (state as usize) % (idx + 1);
        out.swap(idx, swap_idx);
    }
    out
}

fn summarize_runs(runs: &[DistanceRun]) -> Vec<DistanceSummary> {
    let mut buckets: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
    for run in runs {
        buckets
            .entry(run.distance)
            .or_default()
            .push(run.ns_per_hash);
    }
    let mut out = Vec::with_capacity(buckets.len());
    for (distance, values) in buckets {
        let samples = values.len();
        let sum = values.iter().copied().sum::<u64>();
        let mean = if samples == 0 {
            0
        } else {
            ((sum as f64) / (samples as f64)).round() as u64
        };
        let min = values.iter().copied().min().unwrap_or(0);
        let max = values.iter().copied().max().unwrap_or(0);
        out.push(DistanceSummary {
            distance,
            samples,
            mean_ns_per_hash: mean,
            min_ns_per_hash: min,
            max_ns_per_hash: max,
        });
    }
    out
}

fn run_single_distance(opts: &Options, distance: u8) -> Result<u64, String> {
    let (key, inputs) = workload();
    let cfg = match opts.mode {
        Mode::Light => RandomXConfig::new(),
        Mode::Fast => fast_config()?,
    };
    let flags = build_flags(opts, distance)?;
    let cache = RandomXCache::new(&key, &cfg).map_err(|e| format!("{e:?}"))?;
    let mut vm = match opts.mode {
        Mode::Light => RandomXVm::new_light(cache, cfg, flags).map_err(|e| format!("{e:?}"))?,
        Mode::Fast => {
            if env::var("OXIDE_RANDOMX_FAST_BENCH").ok().as_deref() != Some("1") {
                return Err("fast mode requires OXIDE_RANDOMX_FAST_BENCH=1".to_string());
            }
            let ds_opts = DatasetInitOptions::new(opts.threads);
            let dataset = RandomXDataset::new_with_options(&cache, &cfg, ds_opts)
                .map_err(|e| format!("{e:?}"))?;
            RandomXVm::new_fast(cache, dataset, cfg, flags).map_err(|e| format!("{e:?}"))?
        }
    };

    for _ in 0..opts.warmup {
        for input in &inputs {
            let output = vm.hash(std::hint::black_box(input));
            std::hint::black_box(output);
        }
    }

    let start = Instant::now();
    for _ in 0..opts.iters {
        for input in &inputs {
            let output = vm.hash(std::hint::black_box(input));
            std::hint::black_box(output);
        }
    }
    let elapsed_ns = start.elapsed().as_nanos() as u64;
    let hashes = opts.iters.saturating_mul(inputs.len() as u64);
    if hashes == 0 {
        return Err("hash count is zero".to_string());
    }
    Ok(elapsed_ns / hashes)
}

fn workload() -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut key = vec![0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let sizes = [0usize, 1, 16, 64, 256, 1024];
    let mut inputs = Vec::with_capacity(sizes.len());
    let mut state = 0x243f_6a88_85a3_08d3u64;
    for size in sizes {
        let mut input = Vec::with_capacity(size);
        for _ in 0..size {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            input.push((state >> 56) as u8);
        }
        inputs.push(input);
    }
    (key, inputs)
}

fn build_flags(opts: &Options, distance: u8) -> Result<RandomXFlags, String> {
    #[cfg(feature = "jit")]
    {
        Ok(RandomXFlags {
            prefetch: distance > 0,
            prefetch_distance: distance,
            prefetch_auto_tune: false,
            scratchpad_prefetch_distance: opts.scratchpad_prefetch_distance,
            jit: opts.jit_requested,
            jit_fast_regs: opts.jit_fast_regs,
            ..RandomXFlags::default()
        })
    }
    #[cfg(not(feature = "jit"))]
    {
        if opts.jit_requested || opts.jit_fast_regs {
            return Err("jit options require --features jit".to_string());
        }
        Ok(RandomXFlags {
            prefetch: distance > 0,
            prefetch_distance: distance,
            prefetch_auto_tune: false,
            scratchpad_prefetch_distance: opts.scratchpad_prefetch_distance,
            ..RandomXFlags::default()
        })
    }
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
        Err("small fast config requires --features unsafe-config".to_string())
    }
}

fn format_human(report: &CalibrationReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "calibration cpu={} family={} model={} stepping={} bucket=\"{}\"\n",
        report.cpu.vendor,
        report.cpu.family,
        report.cpu.model,
        report.cpu.stepping,
        report.cpu.family_bucket
    ));
    out.push_str(&format!(
        "code schema={} crate={} git_sha={} git_dirty={} rustc=\"{}\"\n",
        report.code.schema_version,
        report.code.crate_version,
        report.code.git_sha,
        report.code.git_dirty,
        report.code.rustc
    ));
    out.push_str(&format!(
        "scenario mode={} jit_requested={} jit_fast_regs={} scratchpad_prefetch_distance={} workload_id={}\n",
        report.scenario.mode,
        report.scenario.jit_requested,
        report.scenario.jit_fast_regs,
        report.scenario.scratchpad_prefetch_distance,
        report.scenario.workload_id
    ));
    out.push_str(&format!(
        "config rounds={} warmup={} iters={} samples={}\n",
        report.rounds,
        report.warmup,
        report.iters,
        report.runs.len()
    ));
    out.push_str(&format!(
        "best prefetch_distance={} mean_ns_per_hash={}\n",
        report.best_distance, report.best_mean_ns_per_hash
    ));
    if let Some(path) = &report.persisted_path {
        out.push_str(&format!("persisted path={path}\n"));
    }
    out.push_str("distance_summaries:\n");
    for row in &report.summaries {
        out.push_str(&format!(
            "  d{} mean={} min={} max={} samples={}\n",
            row.distance,
            row.mean_ns_per_hash,
            row.min_ns_per_hash,
            row.max_ns_per_hash,
            row.samples
        ));
    }
    out
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn format_json(report: &CalibrationReport) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!(
        "\"cpu\":{{\"vendor\":\"{}\",\"family\":{},\"model\":{},\"stepping\":{},\"family_bucket\":\"{}\"}},",
        json_escape(&report.cpu.vendor),
        report.cpu.family,
        report.cpu.model,
        report.cpu.stepping,
        json_escape(&report.cpu.family_bucket)
    ));
    out.push_str(&format!(
        "\"code\":{{\"schema_version\":{},\"crate_version\":\"{}\",\"git_sha\":\"{}\",\"git_dirty\":\"{}\",\"rustc\":\"{}\"}},",
        report.code.schema_version,
        json_escape(&report.code.crate_version),
        json_escape(&report.code.git_sha),
        json_escape(&report.code.git_dirty),
        json_escape(&report.code.rustc)
    ));
    out.push_str(&format!(
        "\"scenario\":{{\"mode\":\"{}\",\"jit_requested\":{},\"jit_fast_regs\":{},\"scratchpad_prefetch_distance\":{},\"workload_id\":\"{}\"}},",
        json_escape(&report.scenario.mode),
        report.scenario.jit_requested,
        report.scenario.jit_fast_regs,
        report.scenario.scratchpad_prefetch_distance,
        json_escape(&report.scenario.workload_id)
    ));
    out.push_str(&format!(
        "\"rounds\":{},\"warmup\":{},\"iters\":{},\"best_distance\":{},\"best_mean_ns_per_hash\":{},",
        report.rounds, report.warmup, report.iters, report.best_distance, report.best_mean_ns_per_hash
    ));
    if let Some(path) = &report.persisted_path {
        out.push_str(&format!("\"persisted_path\":\"{}\",", json_escape(path)));
    } else {
        out.push_str("\"persisted_path\":null,");
    }
    out.push_str("\"summaries\":[");
    for (idx, row) in report.summaries.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"distance\":{},\"samples\":{},\"mean_ns_per_hash\":{},\"min_ns_per_hash\":{},\"max_ns_per_hash\":{}}}",
            row.distance, row.samples, row.mean_ns_per_hash, row.min_ns_per_hash, row.max_ns_per_hash
        ));
    }
    out.push_str("],\"runs\":[");
    for (idx, row) in report.runs.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"round\":{},\"distance\":{},\"ns_per_hash\":{}}}",
            row.round, row.distance, row.ns_per_hash
        ));
    }
    out.push_str("]}");
    out
}

fn format_csv(report: &CalibrationReport) -> String {
    let mut out = String::new();
    out.push_str(
        "distance,mean_ns_per_hash,min_ns_per_hash,max_ns_per_hash,samples,is_best,mode,jit_requested,jit_fast_regs,workload_id\n",
    );
    for row in &report.summaries {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            row.distance,
            row.mean_ns_per_hash,
            row.min_ns_per_hash,
            row.max_ns_per_hash,
            row.samples,
            row.distance == report.best_distance,
            report.scenario.mode,
            report.scenario.jit_requested,
            report.scenario.jit_fast_regs,
            report.scenario.workload_id
        ));
    }
    out
}
