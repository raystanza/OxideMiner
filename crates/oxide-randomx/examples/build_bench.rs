use oxide_randomx::{RandomXCache, RandomXConfig, RandomXDataset};
use std::env;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
enum ConfigKind {
    Default,
    TestSmall,
}

struct Options {
    config: ConfigKind,
    threads: usize,
}

fn main() {
    let opts = parse_args();
    let cfg = match opts.config {
        ConfigKind::Default => RandomXConfig::new(),
        ConfigKind::TestSmall => RandomXConfig::test_small(),
    };

    let mut key = [0u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = idx as u8;
    }

    let start = Instant::now();
    let cache = RandomXCache::new(&key, &cfg).expect("cache");
    let cache_elapsed = start.elapsed();

    let start = Instant::now();
    let _dataset = RandomXDataset::new(&cache, &cfg, opts.threads).expect("dataset");
    let dataset_elapsed = start.elapsed();

    emit_report(
        &cfg,
        &opts,
        cache_elapsed.as_nanos(),
        dataset_elapsed.as_nanos(),
    );
}

fn parse_args() -> Options {
    let mut config = ConfigKind::Default;
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config = match args.next().as_deref() {
                    Some("default") => ConfigKind::Default,
                    Some("test-small") => ConfigKind::TestSmall,
                    _ => usage_and_exit(),
                };
            }
            "--threads" => {
                threads = parse_usize(args.next().as_deref());
            }
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }

    Options { config, threads }
}

fn usage_and_exit() -> ! {
    eprintln!("Usage: build_bench [--config default|test-small] [--threads N]");
    std::process::exit(1);
}

fn parse_usize(input: Option<&str>) -> usize {
    input
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| usage_and_exit())
}

fn emit_report(cfg: &RandomXConfig, opts: &Options, cache_ns: u128, dataset_ns: u128) {
    emit_provenance(cfg, opts);
    println!("cache_init_ns={} dataset_init_ns={}", cache_ns, dataset_ns);
}

fn emit_provenance(cfg: &RandomXConfig, opts: &Options) {
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
    let config = match opts.config {
        ConfigKind::Default => "default",
        ConfigKind::TestSmall => "test-small",
    };
    println!(
        "provenance git_sha={} git_sha_short={} git_dirty={} features={} cpu={} cores={} \
rustc={} config={} threads={} cache_bytes={} dataset_bytes={}",
        git_sha,
        git_sha_short,
        git_dirty,
        features,
        quote_value(&cpu),
        logical_cores(),
        quote_value(rustc),
        config,
        opts.threads,
        cfg.cache_size_bytes(),
        cfg.dataset_size()
    );
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
