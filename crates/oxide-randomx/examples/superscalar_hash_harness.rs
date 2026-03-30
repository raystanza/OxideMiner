// Research-only SuperscalarHash/cache-item differential harness.
//
// This harness isolates:
// - `compute_item_words_in_place(...)`
// - scalar superscalar program execution used by that path
//
// It is intended to compare the active implementation against the scalar
// reference and is not a supported parent-path benchmark surface.

use std::env;
use std::process;
use std::time::Instant;

use oxide_randomx::{diagnostics, RandomXCache, RandomXConfig};

#[derive(Clone, Copy)]
enum Format {
    Human,
    Json,
    Csv,
}

#[derive(Clone, Copy)]
enum ConfigPreset {
    TestSmall,
    Default,
}

#[derive(Clone, Copy)]
enum ImplKind {
    Active,
    Scalar,
}

struct Options {
    iters: u64,
    warmup: u64,
    items: usize,
    format: Format,
    config: ConfigPreset,
    impl_kind: ImplKind,
}

struct HarnessReport {
    config: &'static str,
    impl_kind: &'static str,
    cache_items: usize,
    cache_accesses: usize,
    items: usize,
    warmup: u64,
    iters: u64,
    compute_calls: u64,
    compute_total_ns: u64,
    compute_ns_per_call: f64,
    compute_checksum: u64,
    execute_calls: u64,
    execute_total_ns: u64,
    execute_ns_per_call: f64,
    execute_checksum: u64,
    execute_select_checksum: u64,
}

fn main() {
    let opts = parse_args();
    match run_harness(&opts) {
        Ok(report) => match opts.format {
            Format::Human => print_human(&report),
            Format::Json => print_json(&report),
            Format::Csv => print_csv(&report),
        },
        Err(err) => {
            eprintln!("superscalar_hash_harness error: {err}");
            process::exit(1);
        }
    }
}

fn parse_args() -> Options {
    let mut iters = 2_000u64;
    let mut warmup = 200u64;
    let mut items = 128usize;
    let mut format = Format::Human;
    let mut config = ConfigPreset::TestSmall;
    let mut impl_kind = ImplKind::Active;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iters" => iters = parse_u64(args.next().as_deref()),
            "--warmup" => warmup = parse_u64(args.next().as_deref()),
            "--items" => items = parse_usize(args.next().as_deref()),
            "--format" => {
                format = match args.next().as_deref() {
                    Some("human") => Format::Human,
                    Some("json") => Format::Json,
                    Some("csv") => Format::Csv,
                    _ => usage_and_exit(),
                }
            }
            "--config" => {
                config = match args.next().as_deref() {
                    Some("test-small") => ConfigPreset::TestSmall,
                    Some("default") => ConfigPreset::Default,
                    _ => usage_and_exit(),
                }
            }
            "--impl" => {
                impl_kind = match args.next().as_deref() {
                    Some("active") => ImplKind::Active,
                    Some("scalar") => ImplKind::Scalar,
                    _ => usage_and_exit(),
                }
            }
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }

    if items == 0 {
        eprintln!("--items must be > 0");
        process::exit(1);
    }

    Options {
        iters,
        warmup,
        items,
        format,
        config,
        impl_kind,
    }
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

fn usage_and_exit() -> ! {
    eprintln!(
        "Usage: superscalar_hash_harness [--iters N] [--warmup N] [--items N] \
         [--config test-small|default] [--impl active|scalar] [--format human|json|csv]\n\
         Research-only differential harness for superscalar-accel-proto.\n\
         Compare --impl active against --impl scalar; do not treat this as a supported parent-path benchmark."
    );
    process::exit(1);
}

fn run_harness(opts: &Options) -> Result<HarnessReport, String> {
    let cfg = match opts.config {
        ConfigPreset::TestSmall => RandomXConfig::test_small(),
        ConfigPreset::Default => RandomXConfig::new(),
    };
    let key = deterministic_key();
    let cache = RandomXCache::new(&key, &cfg).map_err(|e| format!("{e:?}"))?;
    let cache_items = diagnostics::cache_item_count(&cache);
    if cache_items == 0 || !cache_items.is_power_of_two() {
        return Err("cache item count must be a non-zero power of two".to_string());
    }

    let cache_mask = cache_items as u64 - 1;
    let item_numbers = deterministic_item_numbers(opts.items, cache_mask);
    let register_seeds = deterministic_register_seeds(opts.items);
    let program_count = cfg.cache_accesses() as usize;
    let (compute_fn, execute_fn, impl_label): (ComputeFn, ExecuteFn, &'static str) =
        match opts.impl_kind {
            ImplKind::Active => (
                diagnostics::compute_item_words_in_place,
                diagnostics::execute_superscalar_program,
                "active",
            ),
            ImplKind::Scalar => (
                diagnostics::compute_item_words_in_place_scalar,
                diagnostics::execute_superscalar_program_scalar,
                "scalar",
            ),
        };

    let (compute_calls, compute_total_ns, compute_checksum) = bench_compute_item_words(
        compute_fn,
        &cache,
        &cfg,
        &item_numbers,
        opts.warmup,
        opts.iters,
    );
    let (execute_calls, execute_total_ns, execute_checksum, execute_select_checksum) =
        bench_execute_programs(
            execute_fn,
            &cache,
            program_count,
            &register_seeds,
            opts.warmup,
            opts.iters,
        );

    let compute_ns_per_call = ns_per_call(compute_total_ns, compute_calls);
    let execute_ns_per_call = ns_per_call(execute_total_ns, execute_calls);

    Ok(HarnessReport {
        config: match opts.config {
            ConfigPreset::TestSmall => "test-small",
            ConfigPreset::Default => "default",
        },
        impl_kind: impl_label,
        cache_items,
        cache_accesses: program_count,
        items: item_numbers.len(),
        warmup: opts.warmup,
        iters: opts.iters,
        compute_calls,
        compute_total_ns,
        compute_ns_per_call,
        compute_checksum,
        execute_calls,
        execute_total_ns,
        execute_ns_per_call,
        execute_checksum,
        execute_select_checksum,
    })
}

type ComputeFn = fn(&RandomXCache, &RandomXConfig, u64, &mut [u64; 8]);
type ExecuteFn = fn(&RandomXCache, usize, &mut [u64; 8]) -> usize;

fn bench_compute_item_words(
    compute_fn: ComputeFn,
    cache: &RandomXCache,
    cfg: &RandomXConfig,
    item_numbers: &[u64],
    warmup: u64,
    iters: u64,
) -> (u64, u64, u64) {
    for _ in 0..warmup {
        for &item_number in item_numbers {
            let mut regs = [0u64; 8];
            compute_fn(cache, cfg, item_number, &mut regs);
            std::hint::black_box(regs);
        }
    }

    let mut checksum = 0u64;
    let start = Instant::now();
    for _ in 0..iters {
        for &item_number in item_numbers {
            let mut regs = [0u64; 8];
            compute_fn(cache, cfg, item_number, &mut regs);
            checksum = mix_checksum(checksum, &regs);
        }
    }
    let elapsed = start.elapsed().as_nanos() as u64;
    let calls = iters.saturating_mul(item_numbers.len() as u64);
    (calls, elapsed, checksum)
}

fn bench_execute_programs(
    execute_fn: ExecuteFn,
    cache: &RandomXCache,
    program_count: usize,
    register_seeds: &[[u64; 8]],
    warmup: u64,
    iters: u64,
) -> (u64, u64, u64, u64) {
    for _ in 0..warmup {
        for regs_seed in register_seeds {
            for program_index in 0..program_count {
                let mut regs = *regs_seed;
                let selected = execute_fn(cache, program_index, &mut regs);
                std::hint::black_box((regs, selected));
            }
        }
    }

    let mut checksum = 0u64;
    let mut select_checksum = 0u64;
    let start = Instant::now();
    for _ in 0..iters {
        for regs_seed in register_seeds {
            for program_index in 0..program_count {
                let mut regs = *regs_seed;
                let selected = execute_fn(cache, program_index, &mut regs);
                checksum = mix_checksum(checksum, &regs);
                select_checksum = select_checksum
                    .rotate_left(5)
                    .wrapping_add((selected as u64) ^ (program_index as u64));
            }
        }
    }
    let elapsed = start.elapsed().as_nanos() as u64;
    let calls = iters
        .saturating_mul(register_seeds.len() as u64)
        .saturating_mul(program_count as u64);
    (calls, elapsed, checksum, select_checksum)
}

fn ns_per_call(total_ns: u64, calls: u64) -> f64 {
    if calls == 0 {
        0.0
    } else {
        total_ns as f64 / calls as f64
    }
}

fn deterministic_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    key
}

fn deterministic_item_numbers(count: usize, mask: u64) -> Vec<u64> {
    let mut out = Vec::with_capacity(count);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..count {
        state = lcg_next(state);
        out.push(state & mask);
    }
    out
}

fn deterministic_register_seeds(count: usize) -> Vec<[u64; 8]> {
    let mut out = Vec::with_capacity(count);
    let mut state = 0x243f_6a88_85a3_08d3u64;
    for _ in 0..count {
        let mut regs = [0u64; 8];
        for (idx, reg) in regs.iter_mut().enumerate() {
            state = lcg_next(state);
            *reg = state ^ ((idx as u64) << 28);
        }
        out.push(regs);
    }
    out
}

fn lcg_next(state: u64) -> u64 {
    state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

fn mix_checksum(mut acc: u64, words: &[u64; 8]) -> u64 {
    for (idx, &word) in words.iter().enumerate() {
        let rot = ((idx * 7 + 1) & 63) as u32;
        acc ^= word.rotate_left(rot);
        acc = acc.rotate_left(9).wrapping_mul(0x9E37_79B1_85EB_CA87);
    }
    acc
}

fn print_human(report: &HarnessReport) {
    println!(
        "summary config={} impl={} cache_items={} cache_accesses={} items={} warmup={} iters={}",
        report.config,
        report.impl_kind,
        report.cache_items,
        report.cache_accesses,
        report.items,
        report.warmup,
        report.iters
    );
    println!(
        "compute calls={} total_ns={} ns_per_call={:.3} checksum={:#018x}",
        report.compute_calls,
        report.compute_total_ns,
        report.compute_ns_per_call,
        report.compute_checksum
    );
    println!(
        "execute calls={} total_ns={} ns_per_call={:.3} checksum={:#018x} select_checksum={:#018x}",
        report.execute_calls,
        report.execute_total_ns,
        report.execute_ns_per_call,
        report.execute_checksum,
        report.execute_select_checksum
    );
}

fn print_json(report: &HarnessReport) {
    println!(
        "{{\"config\":\"{}\",\"impl\":\"{}\",\"cache_items\":{},\"cache_accesses\":{},\"items\":{},\
\"warmup\":{},\"iters\":{},\"compute_calls\":{},\"compute_total_ns\":{},\
\"compute_ns_per_call\":{:.3},\"compute_checksum\":{},\"execute_calls\":{},\
\"execute_total_ns\":{},\"execute_ns_per_call\":{:.3},\"execute_checksum\":{},\
\"execute_select_checksum\":{}}}",
        report.config,
        report.impl_kind,
        report.cache_items,
        report.cache_accesses,
        report.items,
        report.warmup,
        report.iters,
        report.compute_calls,
        report.compute_total_ns,
        report.compute_ns_per_call,
        report.compute_checksum,
        report.execute_calls,
        report.execute_total_ns,
        report.execute_ns_per_call,
        report.execute_checksum,
        report.execute_select_checksum
    );
}

fn print_csv(report: &HarnessReport) {
    println!(
        "config,impl,cache_items,cache_accesses,items,warmup,iters,compute_calls,compute_total_ns,\
compute_ns_per_call,compute_checksum,execute_calls,execute_total_ns,execute_ns_per_call,\
execute_checksum,execute_select_checksum"
    );
    println!(
        "{},{},{},{},{},{},{},{},{},{:.3},{},{},{},{:.3},{},{}",
        report.config,
        report.impl_kind,
        report.cache_items,
        report.cache_accesses,
        report.items,
        report.warmup,
        report.iters,
        report.compute_calls,
        report.compute_total_ns,
        report.compute_ns_per_call,
        report.compute_checksum,
        report.execute_calls,
        report.execute_total_ns,
        report.execute_ns_per_call,
        report.execute_checksum,
        report.execute_select_checksum
    );
}
