use oxide_randomx::{
    DatasetInitOptions, PerfStats, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags,
    RandomXVm,
};
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SIMD_FORCE_ENV: &str = "OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE";
const SIMD_DISABLE_ENV: &str = "OXIDE_RANDOMX_SIMD_BLOCKIO_DISABLE";

const PROMPT_ID: &str = "PROMPTv7_10";
const DEFAULT_EMAIL: &str = "raystanza@raystanza.uk";
const DUPLICATE_AMD_FAMILY: u32 = 23;
const DUPLICATE_AMD_MODEL: u32 = 8;

const DEFAULT_PERF_ITERS: u64 = 30;
const DEFAULT_PERF_WARMUP: u64 = 5;

const GIT_SHA: &str = env!("OXIDE_RANDOMX_GIT_SHA");
const GIT_SHA_SHORT: &str = env!("OXIDE_RANDOMX_GIT_SHA_SHORT");
const GIT_DIRTY: &str = env!("OXIDE_RANDOMX_GIT_DIRTY");
const RUSTC_VERSION: &str = env!("OXIDE_RANDOMX_RUSTC_VERSION");

#[derive(Clone, Copy, Debug)]
enum Mode {
    Light,
    Fast,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Fast => "fast",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SimdState {
    BaselineScalar,
    ForcedInvestigation,
}

impl SimdState {
    fn config_label(self) -> &'static str {
        match self {
            Self::BaselineScalar => "baseline_scalar",
            Self::ForcedInvestigation => "forced_investigation",
        }
    }

    fn force_enabled(self) -> bool {
        matches!(self, Self::ForcedInvestigation)
    }

    fn disable_enabled(self) -> bool {
        matches!(self, Self::BaselineScalar)
    }
}

#[derive(Debug)]
struct Options {
    out_dir: Option<PathBuf>,
    threads: usize,
    perf_iters: u64,
    perf_warmup: u64,
    large_pages: bool,
    skip_correctness: bool,
    owner_email: String,
}

#[derive(Debug)]
struct HostIdentity {
    vendor: String,
    family: u32,
    model: u32,
    stepping: u32,
    model_name: String,
}

impl HostIdentity {
    fn host_tag(&self) -> String {
        format!("amd_fam{}_mod{}", self.family, self.model)
    }

    fn is_amd(&self) -> bool {
        self.vendor == "AuthenticAMD"
    }

    fn is_duplicate_family(&self) -> bool {
        self.family == DUPLICATE_AMD_FAMILY && self.model == DUPLICATE_AMD_MODEL
    }
}

#[derive(Debug, Clone)]
struct PerfRun {
    mode: Mode,
    config_label: String,
    seq: String,
    force: bool,
    disable: bool,
    iters: u64,
    warmup: u64,
    threads: usize,
    hashes: u64,
    elapsed_ns: u64,
    ns_per_hash: u64,
    hashes_per_sec: f64,
    prefetch: bool,
    prefetch_distance: u8,
    prefetch_auto_tune: bool,
    scratchpad_prefetch_distance: u8,
    large_pages_requested: bool,
    large_pages_dataset: Option<bool>,
    large_pages_scratchpad: bool,
    perf: PerfStats,
    git_sha_short: String,
    git_dirty: String,
    cpu: String,
    csv_file_name: String,
}

#[derive(Debug)]
struct ModeSummary {
    baseline_mean_ns_per_hash: f64,
    forced_mean_ns_per_hash: f64,
    delta_pct_forced_vs_baseline: f64,
    pair_deltas_pct: [f64; 2],
    baseline_drift_pct: f64,
    forced_drift_pct: f64,
    stage_delta_pct_forced_vs_baseline_prepare: f64,
    stage_delta_pct_forced_vs_baseline_execute: f64,
    stage_delta_pct_forced_vs_baseline_finish: f64,
    counter_spans: Vec<(&'static str, u64)>,
    counter_spans_all_zero: bool,
    baseline_combined_file_name: String,
    forced_combined_file_name: String,
    pair_matrix_file_name: String,
}

#[derive(Debug)]
struct CorrectnessSummary {
    status: &'static str,
    checked_cases: usize,
    report_file_name: String,
}

struct ReportContext<'a> {
    host: &'a HostIdentity,
    host_tag: &'a str,
    now: &'a NowStrings,
    options: &'a Options,
}

struct LimitationArtifacts<'a> {
    manifest_name: &'a str,
    provenance_name: &'a str,
    memo_name: &'a str,
}

struct SummaryArtifacts<'a> {
    manifest_name: &'a str,
    provenance_name: &'a str,
    perf_index_name: &'a str,
}

#[derive(Clone, Copy)]
struct OracleVector {
    mode: Mode,
    key_hex: &'static str,
    input_hex: &'static str,
    expected_hash_hex: &'static str,
}

const ORACLE_VECTORS: &[OracleVector] = &[
    OracleVector {
        mode: Mode::Light,
        key_hex: "",
        input_hex: "",
        expected_hash_hex: "c0beb061be7f5fc06127b9ef7be883e37bd12e8b62777e4ec3c062062c4daf75",
    },
    OracleVector {
        mode: Mode::Light,
        key_hex: "3d",
        input_hex: "6f",
        expected_hash_hex: "37725d72ae578648efca1e5052f1dde6a7f9d614b0614ed6832c55a805e86abb",
    },
    OracleVector {
        mode: Mode::Light,
        key_hex: "a86c",
        input_hex: "74c3fe",
        expected_hash_hex: "21e6f4b45a3c3555501eab408eb272b1939bd47315e6a346b94a95a365730176",
    },
    OracleVector {
        mode: Mode::Fast,
        key_hex: "",
        input_hex: "",
        expected_hash_hex: "c0beb061be7f5fc06127b9ef7be883e37bd12e8b62777e4ec3c062062c4daf75",
    },
    OracleVector {
        mode: Mode::Fast,
        key_hex: "3d",
        input_hex: "6f",
        expected_hash_hex: "37725d72ae578648efca1e5052f1dde6a7f9d614b0614ed6832c55a805e86abb",
    },
    OracleVector {
        mode: Mode::Fast,
        key_hex: "a86c",
        input_hex: "74c3fe",
        expected_hash_hex: "21e6f4b45a3c3555501eab408eb272b1939bd47315e6a346b94a95a365730176",
    },
];

fn main() {
    let options = match parse_args() {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("error: {err}");
            print_usage();
            process::exit(2);
        }
    };

    let now = now_strings();
    let host = match detect_host_identity() {
        Ok(host) => host,
        Err(err) => {
            eprintln!("error: failed to detect host identity: {err}");
            process::exit(1);
        }
    };

    let host_tag = host.host_tag();
    let out_dir = options.out_dir.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            "v7_10_capture_{}_{}",
            host_tag, now.timestamp_compact
        ))
    });

    if let Err(err) = fs::create_dir_all(&out_dir) {
        eprintln!(
            "error: failed to create output directory {}: {err}",
            out_dir.display()
        );
        process::exit(1);
    }

    let manifest_name = format!("v7_10_manifest_{}_{}.txt", host_tag, now.timestamp_compact);
    let provenance_name = format!(
        "v7_10_novel_family_host_provenance_{}_{}.txt",
        host_tag, now.timestamp_compact
    );
    let perf_index_name = format!(
        "v7_10_perf_index_{}_{}.csv",
        host_tag, now.timestamp_compact
    );
    let summary_name = format!(
        "v7_10_simd_blockio_summary_{}_{}.json",
        host_tag, now.timestamp_compact
    );
    let share_name = format!(
        "v7_10_share_instructions_{}_{}.txt",
        host_tag, now.timestamp_compact
    );

    if let Err(err) = write_manifest(
        &out_dir.join(&manifest_name),
        &host,
        &now,
        &host_tag,
        &options,
        &out_dir,
    ) {
        eprintln!("error: failed to write manifest: {err}");
        process::exit(1);
    }

    if let Err(err) = write_provenance(
        &out_dir.join(&provenance_name),
        &host,
        &now,
        &host_tag,
        &options,
    ) {
        eprintln!("error: failed to write provenance: {err}");
        process::exit(1);
    }
    let report_ctx = ReportContext {
        host: &host,
        host_tag: &host_tag,
        now: &now,
        options: &options,
    };

    if !host.is_amd() {
        let memo_name = format!(
            "v7_10_simd_blockio_amd_novel_family_gap_blocked_{}.md",
            now.date_hyphen
        );
        let memo_path = out_dir.join(&memo_name);
        if let Err(err) = write_non_amd_memo(&memo_path, &host, &host_tag, &now) {
            eprintln!("error: failed to write non-AMD memo: {err}");
            process::exit(1);
        }
        let limitation_artifacts = LimitationArtifacts {
            manifest_name: &manifest_name,
            provenance_name: &provenance_name,
            memo_name: &memo_name,
        };
        if let Err(err) = write_limitation_summary_json(
            &out_dir.join(&summary_name),
            &report_ctx,
            &limitation_artifacts,
            "not_amd_host",
        ) {
            eprintln!("error: failed to write summary: {err}");
            process::exit(1);
        }
        if let Err(err) = write_share_instructions(
            &out_dir.join(&share_name),
            &options.owner_email,
            &out_dir,
            &[&manifest_name, &provenance_name, &summary_name, &memo_name],
        ) {
            eprintln!("error: failed to write share instructions: {err}");
            process::exit(1);
        }
        println!(
            "Run completed with host gate limitation. Share folder: {}",
            out_dir.display()
        );
        println!("Send artifacts to {}", options.owner_email);
        return;
    }

    if host.is_duplicate_family() {
        let memo_name = format!(
            "v7_10_simd_blockio_amd_novel_family_gap_blocked_{}.md",
            now.date_hyphen
        );
        let memo_path = out_dir.join(&memo_name);
        if let Err(err) = write_duplicate_family_memo(&memo_path, &host, &host_tag, &now) {
            eprintln!("error: failed to write duplicate-family memo: {err}");
            process::exit(1);
        }
        let limitation_artifacts = LimitationArtifacts {
            manifest_name: &manifest_name,
            provenance_name: &provenance_name,
            memo_name: &memo_name,
        };
        if let Err(err) = write_limitation_summary_json(
            &out_dir.join(&summary_name),
            &report_ctx,
            &limitation_artifacts,
            "duplicate_family_blocked",
        ) {
            eprintln!("error: failed to write summary: {err}");
            process::exit(1);
        }
        if let Err(err) = write_share_instructions(
            &out_dir.join(&share_name),
            &options.owner_email,
            &out_dir,
            &[&manifest_name, &provenance_name, &summary_name, &memo_name],
        ) {
            eprintln!("error: failed to write share instructions: {err}");
            process::exit(1);
        }
        println!(
            "Run completed with duplicate-family limitation (AMD 23/8). Share folder: {}",
            out_dir.display()
        );
        println!("Send artifacts to {}", options.owner_email);
        return;
    }

    let correctness = if options.skip_correctness {
        let report_name = format!(
            "v7_10_correctness_{}_{}.txt",
            host_tag, now.timestamp_compact
        );
        let report_path = out_dir.join(&report_name);
        let message = "status=skipped\nreason=--skip-correctness set\n";
        if let Err(err) = fs::write(&report_path, message) {
            eprintln!("error: failed to write correctness report: {err}");
            process::exit(1);
        }
        CorrectnessSummary {
            status: "skipped",
            checked_cases: 0,
            report_file_name: report_name,
        }
    } else {
        let report_name = format!(
            "v7_10_correctness_{}_{}.txt",
            host_tag, now.timestamp_compact
        );
        let report_path = out_dir.join(&report_name);
        match run_correctness_checks(&report_path) {
            Ok(mut summary) => {
                summary.report_file_name = report_name;
                summary
            }
            Err(err) => {
                eprintln!("error: correctness validation failed: {err}");
                process::exit(1);
            }
        }
    };

    let (key, inputs) = make_workload();

    let mut perf_runs: Vec<PerfRun> = Vec::new();
    for mode in [Mode::Light, Mode::Fast] {
        for (seq, state) in [
            ("a1", SimdState::BaselineScalar),
            ("b1", SimdState::ForcedInvestigation),
            ("b2", SimdState::ForcedInvestigation),
            ("a2", SimdState::BaselineScalar),
        ] {
            let csv_name = format!(
                "v7_10_perf_{}_baseline_vs_forced_{}_{}_{}_{}.csv",
                mode.as_str(),
                state.config_label(),
                seq,
                host_tag,
                now.timestamp_compact
            );
            let run = match run_perf_capture(mode, state, seq, &csv_name, &options, &key, &inputs) {
                Ok(run) => run,
                Err(err) => {
                    eprintln!(
                        "error: perf capture failed for mode={} seq={} config={}: {err}",
                        mode.as_str(),
                        seq,
                        state.config_label()
                    );
                    process::exit(1);
                }
            };

            if let Err(err) = write_perf_run_csv(&out_dir.join(&csv_name), &run) {
                eprintln!("error: failed to write perf CSV {}: {err}", csv_name);
                process::exit(1);
            }
            perf_runs.push(run);
        }
    }

    if let Err(err) = write_perf_index_csv(&out_dir.join(&perf_index_name), &perf_runs) {
        eprintln!("error: failed to write perf index: {err}");
        process::exit(1);
    }

    let light_runs = runs_for_mode(&perf_runs, Mode::Light);
    let fast_runs = runs_for_mode(&perf_runs, Mode::Fast);

    let light_summary = match summarize_mode(
        "light",
        &out_dir,
        &host_tag,
        &now.timestamp_compact,
        &light_runs,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            eprintln!("error: failed to summarize light mode: {err}");
            process::exit(1);
        }
    };
    let fast_summary = match summarize_mode(
        "fast",
        &out_dir,
        &host_tag,
        &now.timestamp_compact,
        &fast_runs,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            eprintln!("error: failed to summarize fast mode: {err}");
            process::exit(1);
        }
    };

    let summary_artifacts = SummaryArtifacts {
        manifest_name: &manifest_name,
        provenance_name: &provenance_name,
        perf_index_name: &perf_index_name,
    };
    if let Err(err) = write_summary_json(
        &out_dir.join(&summary_name),
        &report_ctx,
        &correctness,
        &summary_artifacts,
        &light_summary,
        &fast_summary,
    ) {
        eprintln!("error: failed to write summary JSON: {err}");
        process::exit(1);
    }

    let memo_name = format!(
        "v7_10_simd_blockio_amd_novel_family_evidence_{}.md",
        now.date_hyphen
    );
    if let Err(err) = write_evidence_memo(
        &out_dir.join(&memo_name),
        &report_ctx,
        &correctness,
        &light_summary,
        &fast_summary,
        &summary_name,
    ) {
        eprintln!("error: failed to write evidence memo: {err}");
        process::exit(1);
    }

    if let Err(err) = write_share_instructions(
        &out_dir.join(&share_name),
        &options.owner_email,
        &out_dir,
        &[
            &manifest_name,
            &provenance_name,
            &perf_index_name,
            &summary_name,
            &correctness.report_file_name,
            &memo_name,
            &light_summary.baseline_combined_file_name,
            &light_summary.forced_combined_file_name,
            &light_summary.pair_matrix_file_name,
            &fast_summary.baseline_combined_file_name,
            &fast_summary.forced_combined_file_name,
            &fast_summary.pair_matrix_file_name,
        ],
    ) {
        eprintln!("error: failed to write share instructions: {err}");
        process::exit(1);
    }

    println!("Capture complete.");
    println!("Artifact folder: {}", out_dir.display());
    println!("Share this folder with: {}", options.owner_email);
    println!(
        "Host identity: vendor={} family={} model={} stepping={}",
        host.vendor, host.family, host.model, host.stepping
    );
    println!(
        "Light forced-vs-baseline delta: {:+.3}%",
        light_summary.delta_pct_forced_vs_baseline
    );
    println!(
        "Fast forced-vs-baseline delta: {:+.3}%",
        fast_summary.delta_pct_forced_vs_baseline
    );
}

fn parse_args() -> Result<Options, String> {
    let mut out_dir = None::<PathBuf>;
    let mut threads = std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1);
    let mut perf_iters = DEFAULT_PERF_ITERS;
    let mut perf_warmup = DEFAULT_PERF_WARMUP;
    let mut large_pages = false;
    let mut skip_correctness = false;
    let mut owner_email = DEFAULT_EMAIL.to_string();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --out-dir".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--threads" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --threads".to_string())?;
                threads = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --threads value: {value}"))?;
                if threads == 0 {
                    return Err("--threads must be >= 1".to_string());
                }
            }
            "--perf-iters" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --perf-iters".to_string())?;
                perf_iters = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --perf-iters value: {value}"))?;
                if perf_iters == 0 {
                    return Err("--perf-iters must be >= 1".to_string());
                }
            }
            "--perf-warmup" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --perf-warmup".to_string())?;
                perf_warmup = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --perf-warmup value: {value}"))?;
            }
            "--large-pages" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --large-pages".to_string())?;
                large_pages = parse_on_off(&value)?;
            }
            "--skip-correctness" => {
                skip_correctness = true;
            }
            "--owner-email" => {
                owner_email = args
                    .next()
                    .ok_or_else(|| "missing value for --owner-email".to_string())?;
                if owner_email.trim().is_empty() {
                    return Err("--owner-email cannot be empty".to_string());
                }
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => {
                return Err(format!("unknown argument: {arg}"));
            }
        }
    }

    Ok(Options {
        out_dir,
        threads,
        perf_iters,
        perf_warmup,
        large_pages,
        skip_correctness,
        owner_email,
    })
}

fn parse_on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!(
            "invalid value for --large-pages: {value} (expected on|off)"
        )),
    }
}

fn print_usage() {
    let program = env::args()
        .next()
        .and_then(|value| {
            Path::new(&value)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "v7_10_amd_capture".to_string());

    eprintln!(
        "Usage: {program} [options]\n\
         Options:\n\
           --out-dir <path>          Output directory (default: v7_10_capture_<host>_<timestamp>)\n\
           --threads <n>             Thread count for fast-mode dataset init\n\
           --perf-iters <n>          Perf iterations per run (default: 30)\n\
           --perf-warmup <n>         Perf warmup iterations per run (default: 5)\n\
           --large-pages on|off      Request large pages (default: off)\n\
           --skip-correctness        Skip built-in oracle checks\n\
           --owner-email <address>   Contact target for artifact handoff\n\
           -h, --help                Show help"
    );
}

struct NowStrings {
    timestamp_compact: String,
    date_hyphen: String,
    timestamp_iso: String,
}

fn now_strings() -> NowStrings {
    #[cfg(target_os = "windows")]
    let compact = command_timestamp_windows("yyyyMMdd_HHmmss");
    #[cfg(target_os = "windows")]
    let date = command_timestamp_windows("yyyy-MM-dd");
    #[cfg(target_os = "windows")]
    let iso = command_timestamp_windows("yyyy-MM-ddTHH:mm:ssK");

    #[cfg(target_os = "linux")]
    let compact = command_timestamp_linux("+%Y%m%d_%H%M%S");
    #[cfg(target_os = "linux")]
    let date = command_timestamp_linux("+%Y-%m-%d");
    #[cfg(target_os = "linux")]
    let iso = command_timestamp_linux("+%Y-%m-%dT%H:%M:%S%:z");

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let compact: Option<String> = None;
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let date: Option<String> = None;
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let iso: Option<String> = None;

    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    NowStrings {
        timestamp_compact: compact.unwrap_or_else(|| format!("{epoch_secs}")),
        date_hyphen: date.unwrap_or_else(|| format!("unix-{epoch_secs}")),
        timestamp_iso: iso.unwrap_or_else(|| format!("unix:{epoch_secs}")),
    }
}

#[cfg(target_os = "windows")]
fn command_timestamp_windows(format: &str) -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Get-Date -Format {format}"),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(target_os = "linux")]
fn command_timestamp_linux(format: &str) -> Option<String> {
    let output = std::process::Command::new("date")
        .arg(format)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn detect_host_identity() -> Result<HostIdentity, String> {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;

        let cpuid0 = __cpuid(0);
        let mut vendor = [0u8; 12];
        vendor[..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

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

        let stepping = eax & 0xF;

        let vendor = String::from_utf8_lossy(&vendor).to_string();
        let model_name = cpu_model_string();

        Ok(HostIdentity {
            vendor,
            family,
            model,
            stepping,
            model_name,
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err("unsupported architecture (requires x86_64)".to_string())
    }
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
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("model name") {
                if let Some((_, value)) = rest.split_once(':') {
                    let trimmed = value.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn cpu_model_string() -> String {
    "unknown".to_string()
}

fn write_manifest(
    path: &Path,
    host: &HostIdentity,
    now: &NowStrings,
    host_tag: &str,
    options: &Options,
    out_dir: &Path,
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "prompt_id={PROMPT_ID}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "capture_timestamp={}", now.timestamp_compact)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "capture_timestamp_iso={}", now.timestamp_iso)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={host_tag}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "stepping={}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "cpu_model_string={}", host.model_name).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_iters={}", options.perf_iters).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_warmup={}", options.perf_warmup).map_err(|e| e.to_string())?;
    writeln!(&mut body, "threads={}", options.threads).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "large_pages={}",
        if options.large_pages { "on" } else { "off" }
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "skip_correctness={}", options.skip_correctness)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "owner_email={}", options.owner_email).map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha={GIT_SHA}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha_short={GIT_SHA_SHORT}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_dirty={GIT_DIRTY}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "rustc={RUSTC_VERSION}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "artifact_dir={}", out_dir.display()).map_err(|e| e.to_string())?;

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_provenance(
    path: &Path,
    host: &HostIdentity,
    now: &NowStrings,
    host_tag: &str,
    options: &Options,
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "timestamp={}", now.timestamp_iso).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={host_tag}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "os={}", env::consts::OS).map_err(|e| e.to_string())?;
    writeln!(&mut body, "arch={}", env::consts::ARCH).map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "stepping={}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "cpu_model_string={}", host.model_name).map_err(|e| e.to_string())?;
    writeln!(&mut body, "threads={}", options.threads).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_iters={}", options.perf_iters).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_warmup={}", options.perf_warmup).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "large_pages={}",
        if options.large_pages { "on" } else { "off" }
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha={GIT_SHA}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha_short={GIT_SHA_SHORT}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_dirty={GIT_DIRTY}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "rustc={RUSTC_VERSION}").map_err(|e| e.to_string())?;

    if let Some(version_line) = windows_ver_line() {
        writeln!(&mut body, "windows_ver={version_line}").map_err(|e| e.to_string())?;
    }
    if let Some(release_line) = linux_release_line() {
        writeln!(&mut body, "linux_release={release_line}").map_err(|e| e.to_string())?;
    }
    if let Some(uname_line) = linux_uname_line() {
        writeln!(&mut body, "linux_uname={uname_line}").map_err(|e| e.to_string())?;
    }

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn windows_ver_line() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if line.is_empty() {
            None
        } else {
            Some(line)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

fn linux_release_line() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let contents = fs::read_to_string("/etc/os-release").ok()?;
        let mut pretty = None::<String>;
        let mut distro = None::<String>;
        let mut like = None::<String>;
        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                pretty = Some(trim_shell_quote(value).to_string());
            } else if let Some(value) = line.strip_prefix("ID=") {
                distro = Some(trim_shell_quote(value).to_string());
            } else if let Some(value) = line.strip_prefix("ID_LIKE=") {
                like = Some(trim_shell_quote(value).to_string());
            }
        }
        let pretty = pretty.unwrap_or_else(|| "unknown".to_string());
        let distro = distro.unwrap_or_else(|| "unknown".to_string());
        let like = like.unwrap_or_else(|| "unknown".to_string());
        Some(format!("pretty={pretty};id={distro};id_like={like}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn linux_uname_line() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("uname")
            .args(["-srmo"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if line.is_empty() {
            None
        } else {
            Some(line)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn trim_shell_quote(value: &str) -> &str {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        stripped
    } else {
        trimmed
    }
}

fn write_non_amd_memo(
    path: &Path,
    host: &HostIdentity,
    host_tag: &str,
    now: &NowStrings,
) -> Result<(), String> {
    let body = format!(
        "# v7.10 AMD Novel-Family `simd-blockio` Attempt (Blocked: Non-AMD Host, {})\n\n\
         ## Objective\n\
         Capture novel-family AMD `simd-blockio` evidence for prompt `{}`.\n\n\
         ## Host Identity\n\
         - vendor: `{}`\n\
         - family: `{}`\n\
         - model: `{}`\n\
         - stepping: `{}`\n\
         - host tag: `{}`\n\n\
         ## Decision\n\
         This host is not AMD (`AuthenticAMD`). Prompt `v7.10` is blocked on this machine.\n\n\
         ## Next Required Condition\n\
         Run this tool on an AMD host (Windows 11 or Debian-based Linux) whose family/model is\n\
         novel relative to prior AMD\n\
         evidence (`23/8` is already covered).\n",
        now.date_hyphen, PROMPT_ID, host.vendor, host.family, host.model, host.stepping, host_tag
    );

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_duplicate_family_memo(
    path: &Path,
    host: &HostIdentity,
    host_tag: &str,
    now: &NowStrings,
) -> Result<(), String> {
    let body = format!(
        "# v7.10 AMD Novel-Family `simd-blockio` Attempt (Blocked, {})\n\n\
         ## Objective\n\
         Capture AMD `simd-blockio` evidence on a family/model different from prior AMD policy\n\
         coverage (`AuthenticAMD` Family `23` Model `8`).\n\n\
         ## Host Identity\n\
         - vendor: `{}`\n\
         - family: `{}`\n\
         - model: `{}`\n\
         - stepping: `{}`\n\
         - host tag: `{}`\n\n\
         ## Decision\n\
         This host is duplicate-family relative to existing AMD evidence (`23/8`), so prompt\n\
         `v7.10` stops here by design and records a limitation memo instead of another duplicate\n\
         capture.\n\n\
         ## Next Required Condition\n\
         Rerun this tool on an AMD host where family/model is not `23/8`, then capture\n\
         baseline-vs-forced Light/Fast evidence and correctness artifacts.\n",
        now.date_hyphen, host.vendor, host.family, host.model, host.stepping, host_tag
    );

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_limitation_summary_json(
    path: &Path,
    ctx: &ReportContext<'_>,
    artifacts: &LimitationArtifacts<'_>,
    status: &str,
) -> Result<(), String> {
    let mut json = String::new();
    writeln!(&mut json, "{{").map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"prompt\": \"{}\",", PROMPT_ID).map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "  \"timestamp\": \"{}\",",
        escape_json(&ctx.now.timestamp_compact)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"status\": \"{}\",", escape_json(status)).map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"head_sha\": \"{}\",", escape_json(GIT_SHA))
        .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"host\": {{").map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"vendor\": \"{}\",",
        escape_json(&ctx.host.vendor)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"family\": {},", ctx.host.family).map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"model\": {},", ctx.host.model).map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"stepping\": {},", ctx.host.stepping).map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"model_name\": \"{}\",",
        escape_json(&ctx.host.model_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"host_tag\": \"{}\",",
        escape_json(ctx.host_tag)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"novelty\": \"{}\"",
        if ctx.host.is_duplicate_family() {
            "duplicate_family_confirmation"
        } else {
            "not_amd_host"
        }
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }},").map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"params\": {{").map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"threads\": {},", ctx.options.threads).map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"perf_iters\": {},", ctx.options.perf_iters)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"perf_warmup\": {},",
        ctx.options.perf_warmup
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"large_pages\": {}",
        ctx.options.large_pages
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }},").map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"artifacts\": {{").map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"manifest\": \"{}\",",
        escape_json(artifacts.manifest_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"provenance\": \"{}\",",
        escape_json(artifacts.provenance_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"memo\": \"{}\"",
        escape_json(artifacts.memo_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }}").map_err(|e| e.to_string())?;
    writeln!(&mut json, "}}").map_err(|e| e.to_string())?;

    fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

fn run_correctness_checks(report_path: &Path) -> Result<CorrectnessSummary, String> {
    let mut details = Vec::new();
    let mut checked = 0usize;

    for vector in ORACLE_VECTORS {
        let key = hex_decode(vector.key_hex)?;
        let input = hex_decode(vector.input_hex)?;

        let baseline = run_oracle_case(vector.mode, SimdState::BaselineScalar, &key, &input)?;
        let forced = run_oracle_case(vector.mode, SimdState::ForcedInvestigation, &key, &input)?;

        let expected = vector.expected_hash_hex.to_ascii_lowercase();
        let baseline_hex = hex_encode(&baseline);
        let forced_hex = hex_encode(&forced);

        if baseline_hex != expected {
            return Err(format!(
                "oracle mismatch for mode={} baseline: expected={} actual={}",
                vector.mode.as_str(),
                expected,
                baseline_hex
            ));
        }

        if forced_hex != expected {
            return Err(format!(
                "oracle mismatch for mode={} forced: expected={} actual={}",
                vector.mode.as_str(),
                expected,
                forced_hex
            ));
        }

        if baseline_hex != forced_hex {
            return Err(format!(
                "baseline/forced mismatch for mode={} expected same hash, baseline={} forced={}",
                vector.mode.as_str(),
                baseline_hex,
                forced_hex
            ));
        }

        checked += 1;
        details.push(format!(
            "mode={} key_len={} input_len={} hash={}",
            vector.mode.as_str(),
            key.len(),
            input.len(),
            baseline_hex
        ));
    }

    let mut report = String::new();
    writeln!(&mut report, "status=passed").map_err(|e| e.to_string())?;
    writeln!(&mut report, "checked_cases={checked}").map_err(|e| e.to_string())?;
    writeln!(&mut report, "states=baseline_scalar,forced_investigation")
        .map_err(|e| e.to_string())?;
    for line in &details {
        writeln!(&mut report, "{line}").map_err(|e| e.to_string())?;
    }

    fs::write(report_path, report).map_err(|e| format!("{}: {e}", report_path.display()))?;

    Ok(CorrectnessSummary {
        status: "passed",
        checked_cases: checked,
        report_file_name: String::new(),
    })
}

fn run_oracle_case(
    mode: Mode,
    state: SimdState,
    key: &[u8],
    input: &[u8],
) -> Result<[u8; 32], String> {
    let _env_guard = SimdEnvGuard::new(state.force_enabled(), state.disable_enabled());

    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags {
        large_pages_plumbing: false,
        use_1gb_pages: false,
        ..RandomXFlags::default()
    };

    let cache = RandomXCache::new(key, &cfg).map_err(|e| format!("cache init failed: {e:?}"))?;
    let mut vm = match mode {
        Mode::Light => {
            RandomXVm::new_light(cache, cfg, flags).map_err(|e| format!("vm init failed: {e:?}"))?
        }
        Mode::Fast => {
            let ds_opts = DatasetInitOptions::new(1)
                .with_large_pages(false)
                .with_1gb_pages(false)
                .with_thread_names(false);
            let dataset = RandomXDataset::new_with_options(&cache, &cfg, ds_opts)
                .map_err(|e| format!("dataset init failed: {e:?}"))?;
            RandomXVm::new_fast(cache, dataset, cfg, flags)
                .map_err(|e| format!("vm init failed: {e:?}"))?
        }
    };

    Ok(vm.hash(input))
}

fn run_perf_capture(
    mode: Mode,
    state: SimdState,
    seq: &str,
    csv_file_name: &str,
    options: &Options,
    key: &[u8],
    inputs: &[Vec<u8>],
) -> Result<PerfRun, String> {
    let _env_guard = SimdEnvGuard::new(state.force_enabled(), state.disable_enabled());

    let cfg = RandomXConfig::new();
    let flags = build_flags(options.large_pages);

    let prefetch = flags.prefetch;
    let prefetch_distance = flags.prefetch_distance;
    let prefetch_auto_tune = flags.prefetch_auto_tune;
    let scratchpad_prefetch_distance = flags.scratchpad_prefetch_distance;

    let cache = RandomXCache::new(key, &cfg).map_err(|e| format!("cache init failed: {e:?}"))?;

    let mut dataset_large_pages = None;
    let mut vm = match mode {
        Mode::Light => {
            RandomXVm::new_light(cache, cfg, flags).map_err(|e| format!("vm init failed: {e:?}"))?
        }
        Mode::Fast => {
            let mut ds_opts = DatasetInitOptions::new(options.threads)
                .with_large_pages(options.large_pages)
                .with_1gb_pages(false)
                .with_thread_names(false);
            if let Ok(spec) = env::var("OXIDE_RANDOMX_AFFINITY") {
                if let Ok(parsed) = oxide_randomx::AffinitySpec::parse(&spec) {
                    ds_opts = ds_opts.with_affinity(parsed);
                }
            }
            let dataset = RandomXDataset::new_with_options(&cache, &cfg, ds_opts)
                .map_err(|e| format!("dataset init failed: {e:?}"))?;
            dataset_large_pages = Some(dataset.uses_large_pages());
            RandomXVm::new_fast(cache, dataset, cfg, flags)
                .map_err(|e| format!("vm init failed: {e:?}"))?
        }
    };

    let scratchpad_large_pages = vm.scratchpad_uses_large_pages();

    for _ in 0..options.perf_warmup {
        for input in inputs {
            let out = vm.hash(std::hint::black_box(input));
            std::hint::black_box(out);
        }
    }

    vm.reset_perf_stats();
    let started = Instant::now();
    for _ in 0..options.perf_iters {
        for input in inputs {
            let out = vm.hash(std::hint::black_box(input));
            std::hint::black_box(out);
        }
    }
    let elapsed = started.elapsed();

    let hashes = options.perf_iters.saturating_mul(inputs.len() as u64);
    let elapsed_ns = elapsed.as_nanos() as u64;
    let ns_per_hash = if hashes > 0 { elapsed_ns / hashes } else { 0 };
    let hashes_per_sec = if ns_per_hash > 0 {
        1_000_000_000.0 / ns_per_hash as f64
    } else {
        0.0
    };

    let perf = vm.perf_stats();

    Ok(PerfRun {
        mode,
        config_label: state.config_label().to_string(),
        seq: seq.to_string(),
        force: state.force_enabled(),
        disable: state.disable_enabled(),
        iters: options.perf_iters,
        warmup: options.perf_warmup,
        threads: options.threads,
        hashes,
        elapsed_ns,
        ns_per_hash,
        hashes_per_sec,
        prefetch,
        prefetch_distance,
        prefetch_auto_tune,
        scratchpad_prefetch_distance,
        large_pages_requested: options.large_pages,
        large_pages_dataset: dataset_large_pages,
        large_pages_scratchpad: scratchpad_large_pages,
        perf,
        git_sha_short: GIT_SHA_SHORT.to_string(),
        git_dirty: GIT_DIRTY.to_string(),
        cpu: cpu_model_string(),
        csv_file_name: csv_file_name.to_string(),
    })
}

fn build_flags(large_pages: bool) -> RandomXFlags {
    let mut flags = RandomXFlags::default();
    let env_flags = RandomXFlags::from_env();
    flags.prefetch = env_flags.prefetch;
    flags.prefetch_distance = env_flags.prefetch_distance;
    flags.prefetch_auto_tune = env_flags.prefetch_auto_tune;
    flags.scratchpad_prefetch_distance = env_flags.scratchpad_prefetch_distance;
    flags.large_pages_plumbing = large_pages;
    flags.use_1gb_pages = false;
    #[cfg(feature = "jit")]
    {
        flags.jit = false;
        flags.jit_fast_regs = false;
    }
    flags
}

struct SimdEnvGuard {
    prev_force: Option<OsString>,
    prev_disable: Option<OsString>,
}

impl SimdEnvGuard {
    fn new(force: bool, disable: bool) -> Self {
        let prev_force = env::var_os(SIMD_FORCE_ENV);
        let prev_disable = env::var_os(SIMD_DISABLE_ENV);

        if force {
            env::set_var(SIMD_FORCE_ENV, "1");
        } else {
            env::remove_var(SIMD_FORCE_ENV);
        }

        if disable {
            env::set_var(SIMD_DISABLE_ENV, "1");
        } else {
            env::remove_var(SIMD_DISABLE_ENV);
        }

        Self {
            prev_force,
            prev_disable,
        }
    }
}

impl Drop for SimdEnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.prev_force {
            env::set_var(SIMD_FORCE_ENV, value);
        } else {
            env::remove_var(SIMD_FORCE_ENV);
        }

        if let Some(value) = &self.prev_disable {
            env::set_var(SIMD_DISABLE_ENV, value);
        } else {
            env::remove_var(SIMD_DISABLE_ENV);
        }
    }
}

fn write_perf_run_csv(path: &Path, run: &PerfRun) -> Result<(), String> {
    let header = "mode,config_label,seq,force,disable,iters,warmup,threads,hashes,elapsed_ns,ns_per_hash,hashes_per_sec,program_execs,prepare_iteration_ns,execute_program_ns_interpreter,finish_iteration_ns,scratchpad_read_bytes,scratchpad_write_bytes,dataset_item_loads,mem_read_l1,mem_read_l2,mem_read_l3,mem_write_l1,mem_write_l2,mem_write_l3,instr_int,instr_float,instr_mem,instr_ctrl,instr_store,large_pages_requested,large_pages_dataset,large_pages_scratchpad,prefetch,prefetch_distance,prefetch_auto_tune,scratchpad_prefetch_distance,git_sha_short,git_dirty,cpu\n";

    let row = format!(
        "{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
        run.mode.as_str(),
        run.config_label,
        run.seq,
        run.force,
        run.disable,
        run.iters,
        run.warmup,
        run.threads,
        run.hashes,
        run.elapsed_ns,
        run.ns_per_hash,
        run.hashes_per_sec,
        run.perf.program_execs,
        run.perf.prepare_iteration_ns,
        run.perf.vm_exec_ns_interpreter,
        run.perf.finish_iteration_ns,
        run.perf.scratchpad_read_bytes,
        run.perf.scratchpad_write_bytes,
        run.perf.dataset_item_loads,
        run.perf.mem_read_l1,
        run.perf.mem_read_l2,
        run.perf.mem_read_l3,
        run.perf.mem_write_l1,
        run.perf.mem_write_l2,
        run.perf.mem_write_l3,
        run.perf.instr_int,
        run.perf.instr_float,
        run.perf.instr_mem,
        run.perf.instr_ctrl,
        run.perf.instr_store,
        run.large_pages_requested,
        bool_or_na(run.large_pages_dataset),
        run.large_pages_scratchpad,
        run.prefetch,
        run.prefetch_distance,
        run.prefetch_auto_tune,
        run.scratchpad_prefetch_distance,
        csv_escape(&run.git_sha_short),
        csv_escape(&run.git_dirty),
        csv_escape(&run.cpu),
    );

    fs::write(path, format!("{header}{row}")).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_perf_index_csv(path: &Path, runs: &[PerfRun]) -> Result<(), String> {
    let mut out = String::from("mode,pair_label,config_label,seq,force,path\n");
    for run in runs {
        let row = format!(
            "{},baseline_vs_forced,{},{},{},{}\n",
            run.mode.as_str(),
            run.config_label,
            run.seq,
            run.force,
            run.csv_file_name
        );
        out.push_str(&row);
    }
    fs::write(path, out).map_err(|e| format!("{}: {e}", path.display()))
}

fn runs_for_mode(runs: &[PerfRun], mode: Mode) -> Vec<PerfRun> {
    let mut selected: Vec<PerfRun> = runs
        .iter()
        .filter(|r| r.mode.as_str() == mode.as_str())
        .cloned()
        .collect();
    selected.sort_by_key(|r| r.seq.clone());
    selected
}

fn summarize_mode(
    mode_label: &str,
    out_dir: &Path,
    host_tag: &str,
    ts: &str,
    runs: &[PerfRun],
) -> Result<ModeSummary, String> {
    if runs.len() != 4 {
        return Err(format!(
            "expected 4 runs for mode {mode_label}, got {}",
            runs.len()
        ));
    }

    let a1 = find_run(runs, "a1")?;
    let a2 = find_run(runs, "a2")?;
    let b1 = find_run(runs, "b1")?;
    let b2 = find_run(runs, "b2")?;

    let baseline_mean = mean_u64([a1.ns_per_hash, a2.ns_per_hash]);
    let forced_mean = mean_u64([b1.ns_per_hash, b2.ns_per_hash]);

    let pair_delta1 = pct_delta(a1.ns_per_hash as f64, b1.ns_per_hash as f64);
    let pair_delta2 = pct_delta(a2.ns_per_hash as f64, b2.ns_per_hash as f64);

    let baseline_drift = pct_delta(a1.ns_per_hash as f64, a2.ns_per_hash as f64);
    let forced_drift = pct_delta(b1.ns_per_hash as f64, b2.ns_per_hash as f64);

    let baseline_prepare_mean =
        mean_u64([a1.perf.prepare_iteration_ns, a2.perf.prepare_iteration_ns]);
    let forced_prepare_mean =
        mean_u64([b1.perf.prepare_iteration_ns, b2.perf.prepare_iteration_ns]);

    let baseline_execute_mean = mean_u64([
        a1.perf.vm_exec_ns_interpreter,
        a2.perf.vm_exec_ns_interpreter,
    ]);
    let forced_execute_mean = mean_u64([
        b1.perf.vm_exec_ns_interpreter,
        b2.perf.vm_exec_ns_interpreter,
    ]);

    let baseline_finish_mean = mean_u64([a1.perf.finish_iteration_ns, a2.perf.finish_iteration_ns]);
    let forced_finish_mean = mean_u64([b1.perf.finish_iteration_ns, b2.perf.finish_iteration_ns]);

    let stage_delta_prepare = pct_delta(baseline_prepare_mean, forced_prepare_mean);
    let stage_delta_execute = pct_delta(baseline_execute_mean, forced_execute_mean);
    let stage_delta_finish = pct_delta(baseline_finish_mean, forced_finish_mean);

    let counter_spans = counter_spans([a1, b1, b2, a2]);
    let spans_all_zero = counter_spans.iter().all(|(_, span)| *span == 0);

    let baseline_combined_name = format!(
        "v7_10_perf_{}_baseline_vs_forced_baseline_scalar_combined_{}_{}.csv",
        mode_label, host_tag, ts
    );
    let forced_combined_name = format!(
        "v7_10_perf_{}_baseline_vs_forced_forced_investigation_combined_{}_{}.csv",
        mode_label, host_tag, ts
    );
    let pair_matrix_name = format!(
        "v7_10_perf_{}_baseline_vs_forced_pair_matrix_{}_{}.csv",
        mode_label, host_tag, ts
    );

    write_combined_csv(
        &out_dir.join(&baseline_combined_name),
        &[
            &out_dir.join(&a1.csv_file_name),
            &out_dir.join(&a2.csv_file_name),
        ],
    )?;
    write_combined_csv(
        &out_dir.join(&forced_combined_name),
        &[
            &out_dir.join(&b1.csv_file_name),
            &out_dir.join(&b2.csv_file_name),
        ],
    )?;
    write_combined_csv(
        &out_dir.join(&pair_matrix_name),
        &[
            &out_dir.join(&a1.csv_file_name),
            &out_dir.join(&b1.csv_file_name),
            &out_dir.join(&b2.csv_file_name),
            &out_dir.join(&a2.csv_file_name),
        ],
    )?;

    Ok(ModeSummary {
        baseline_mean_ns_per_hash: baseline_mean,
        forced_mean_ns_per_hash: forced_mean,
        delta_pct_forced_vs_baseline: pct_delta(baseline_mean, forced_mean),
        pair_deltas_pct: [pair_delta1, pair_delta2],
        baseline_drift_pct: baseline_drift,
        forced_drift_pct: forced_drift,
        stage_delta_pct_forced_vs_baseline_prepare: stage_delta_prepare,
        stage_delta_pct_forced_vs_baseline_execute: stage_delta_execute,
        stage_delta_pct_forced_vs_baseline_finish: stage_delta_finish,
        counter_spans,
        counter_spans_all_zero: spans_all_zero,
        baseline_combined_file_name: baseline_combined_name,
        forced_combined_file_name: forced_combined_name,
        pair_matrix_file_name: pair_matrix_name,
    })
}

fn find_run<'a>(runs: &'a [PerfRun], seq: &str) -> Result<&'a PerfRun, String> {
    runs.iter()
        .find(|run| run.seq == seq)
        .ok_or_else(|| format!("missing run seq={seq}"))
}

fn write_combined_csv(out_path: &Path, inputs: &[&Path]) -> Result<(), String> {
    if inputs.is_empty() {
        return Err("write_combined_csv requires at least one input".to_string());
    }

    let mut out = String::new();
    for (idx, input) in inputs.iter().enumerate() {
        let content = fs::read_to_string(input).map_err(|e| format!("{}: {e}", input.display()))?;
        let mut lines = content.lines();
        let header = lines
            .next()
            .ok_or_else(|| format!("{} has no header", input.display()))?;
        if idx == 0 {
            out.push_str(header);
            out.push('\n');
            for line in lines {
                if !line.trim().is_empty() {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        } else {
            for line in lines {
                if !line.trim().is_empty() {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
    }

    fs::write(out_path, out).map_err(|e| format!("{}: {e}", out_path.display()))
}

fn write_summary_json(
    path: &Path,
    ctx: &ReportContext<'_>,
    correctness: &CorrectnessSummary,
    artifacts: &SummaryArtifacts<'_>,
    light: &ModeSummary,
    fast: &ModeSummary,
) -> Result<(), String> {
    let mut json = String::new();
    writeln!(&mut json, "{{").map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"prompt\": \"{}\",", PROMPT_ID).map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "  \"timestamp\": \"{}\",",
        escape_json(&ctx.now.timestamp_compact)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"head_sha\": \"{}\",", escape_json(GIT_SHA))
        .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  \"host\": {{").map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"vendor\": \"{}\",",
        escape_json(&ctx.host.vendor)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"family\": {},", ctx.host.family).map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"model\": {},", ctx.host.model).map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"stepping\": {},", ctx.host.stepping).map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"model_name\": \"{}\",",
        escape_json(&ctx.host.model_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"host_tag\": \"{}\",",
        escape_json(ctx.host_tag)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"novelty\": \"novel_family_evidence\",")
        .map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"supports_classifier_broadening\": false")
        .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }},").map_err(|e| e.to_string())?;

    writeln!(&mut json, "  \"params\": {{").map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"threads\": {},", ctx.options.threads).map_err(|e| e.to_string())?;
    writeln!(&mut json, "    \"perf_iters\": {},", ctx.options.perf_iters)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"perf_warmup\": {},",
        ctx.options.perf_warmup
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"large_pages\": {}",
        ctx.options.large_pages
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }},").map_err(|e| e.to_string())?;

    writeln!(&mut json, "  \"correctness\": {{").map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"status\": \"{}\",",
        escape_json(correctness.status)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"checked_cases\": {},",
        correctness.checked_cases
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"report\": \"{}\"",
        escape_json(&correctness.report_file_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }},").map_err(|e| e.to_string())?;

    writeln!(&mut json, "  \"perf\": {{").map_err(|e| e.to_string())?;
    write_mode_summary_json(&mut json, "light", light, true)?;
    write_mode_summary_json(&mut json, "fast", fast, false)?;
    writeln!(&mut json, "  }},").map_err(|e| e.to_string())?;

    writeln!(&mut json, "  \"artifacts\": {{").map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"manifest\": \"{}\",",
        escape_json(artifacts.manifest_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"provenance\": \"{}\",",
        escape_json(artifacts.provenance_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"perf_index\": \"{}\",",
        escape_json(artifacts.perf_index_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut json,
        "    \"summary\": \"{}\"",
        escape_json(&path.file_name().unwrap_or_default().to_string_lossy())
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut json, "  }}").map_err(|e| e.to_string())?;

    writeln!(&mut json, "}}").map_err(|e| e.to_string())?;

    fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_mode_summary_json(
    out: &mut String,
    label: &str,
    summary: &ModeSummary,
    trailing_comma: bool,
) -> Result<(), String> {
    writeln!(out, "    \"{}\": {{", label).map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"baseline_mean_ns_per_hash\": {:.3},",
        summary.baseline_mean_ns_per_hash
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"forced_mean_ns_per_hash\": {:.3},",
        summary.forced_mean_ns_per_hash
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"delta_pct_forced_vs_baseline\": {:.6},",
        summary.delta_pct_forced_vs_baseline
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"pair_deltas_pct\": [{:.6}, {:.6}],",
        summary.pair_deltas_pct[0], summary.pair_deltas_pct[1]
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"baseline_drift_pct\": {:.6},",
        summary.baseline_drift_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"forced_drift_pct\": {:.6},",
        summary.forced_drift_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"stage_delta_pct_forced_vs_baseline_prepare\": {:.6},",
        summary.stage_delta_pct_forced_vs_baseline_prepare
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"stage_delta_pct_forced_vs_baseline_execute\": {:.6},",
        summary.stage_delta_pct_forced_vs_baseline_execute
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"stage_delta_pct_forced_vs_baseline_finish\": {:.6},",
        summary.stage_delta_pct_forced_vs_baseline_finish
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "      \"counter_spans_all_zero\": {},",
        summary.counter_spans_all_zero
    )
    .map_err(|e| e.to_string())?;

    writeln!(out, "      \"counter_spans\": {{").map_err(|e| e.to_string())?;
    for (idx, (name, span)) in summary.counter_spans.iter().enumerate() {
        let comma = if idx + 1 == summary.counter_spans.len() {
            ""
        } else {
            ","
        };
        writeln!(out, "        \"{}\": {}{}", name, span, comma).map_err(|e| e.to_string())?;
    }
    writeln!(out, "      }},").map_err(|e| e.to_string())?;

    writeln!(out, "      \"artifacts\": {{").map_err(|e| e.to_string())?;
    writeln!(
        out,
        "        \"baseline_combined\": \"{}\",",
        escape_json(&summary.baseline_combined_file_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "        \"forced_combined\": \"{}\",",
        escape_json(&summary.forced_combined_file_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "        \"pair_matrix\": \"{}\"",
        escape_json(&summary.pair_matrix_file_name)
    )
    .map_err(|e| e.to_string())?;
    writeln!(out, "      }}").map_err(|e| e.to_string())?;

    if trailing_comma {
        writeln!(out, "    }},").map_err(|e| e.to_string())?;
    } else {
        writeln!(out, "    }}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn write_evidence_memo(
    path: &Path,
    ctx: &ReportContext<'_>,
    correctness: &CorrectnessSummary,
    light: &ModeSummary,
    fast: &ModeSummary,
    summary_name: &str,
) -> Result<(), String> {
    let body = format!(
        "# v7.10 AMD Novel-Family `simd-blockio` Evidence ({})\n\n\
         ## Scope\n\
         Prompt: `{}`.\n\n\
         This capture was run from the single executable harness on a Windows host and records\n\
         scalar-baseline (`{}`) vs forced-`simd-blockio` (`{}`) evidence for Light and Fast modes.\n\n\
         ## Host Identity\n\
         - vendor: `{}`\n\
         - family: `{}`\n\
         - model: `{}`\n\
         - stepping: `{}`\n\
         - model string: `{}`\n\
         - host tag: `{}`\n\n\
         ## Method\n\
         - threads: `{}`\n\
         - perf iters: `{}`\n\
         - perf warmup: `{}`\n\
         - large pages requested: `{}`\n\
         - ABBA sequence per mode: `baseline a1`, `forced b1`, `forced b2`, `baseline a2`\n\n\
         ## Correctness Validation\n\
         - status: `{}`\n\
         - checked cases: `{}`\n\
         - states checked: baseline scalar and forced investigation\n\n\
         ## Results (`ns_per_hash`, lower is better)\n\
         | Mode | Baseline mean | Forced mean | Delta (forced vs baseline) | Pair deltas | Counter spans all zero |
\n\
         | --- | ---: | ---: | ---: | --- | --- |
\n\
         | Light | `{:.3}` | `{:.3}` | `{:+.3}%` | `{:+.3}%`, `{:+.3}%` | `{}` |
\n\
         | Fast | `{:.3}` | `{:.3}` | `{:+.3}%` | `{:+.3}%`, `{:+.3}%` | `{}` |
\n\
         ## Stage Delta Snapshot (forced vs baseline mean)
\n\
         - Light prepare / execute / finish: `{:+.3}%` / `{:+.3}%` / `{:+.3}%`
\n\
         - Fast prepare / execute / finish: `{:+.3}%` / `{:+.3}%` / `{:+.3}%`
\n\
         ## Interpretation Constraint
\n\
         This capture expands AMD host diversity by family/model compared with prior AMD `23/8`
\
         evidence, but this memo does not claim AMD-wide safety or policy broadening by itself.
\
         Prompt `v7.11` must synthesize this with Intel novel-family evidence and keep Fast-mode
\
         interpretation conservative if direction is mixed.
\n\
         ## Primary Analysis Artifact
\
         - `{}`
",
        ctx.now.date_hyphen,
        PROMPT_ID,
        SimdState::BaselineScalar.config_label(),
        SimdState::ForcedInvestigation.config_label(),
        ctx.host.vendor,
        ctx.host.family,
        ctx.host.model,
        ctx.host.stepping,
        ctx.host.model_name,
        ctx.host_tag,
        ctx.options.threads,
        ctx.options.perf_iters,
        ctx.options.perf_warmup,
        if ctx.options.large_pages { "on" } else { "off" },
        correctness.status,
        correctness.checked_cases,
        light.baseline_mean_ns_per_hash,
        light.forced_mean_ns_per_hash,
        light.delta_pct_forced_vs_baseline,
        light.pair_deltas_pct[0],
        light.pair_deltas_pct[1],
        light.counter_spans_all_zero,
        fast.baseline_mean_ns_per_hash,
        fast.forced_mean_ns_per_hash,
        fast.delta_pct_forced_vs_baseline,
        fast.pair_deltas_pct[0],
        fast.pair_deltas_pct[1],
        fast.counter_spans_all_zero,
        light.stage_delta_pct_forced_vs_baseline_prepare,
        light.stage_delta_pct_forced_vs_baseline_execute,
        light.stage_delta_pct_forced_vs_baseline_finish,
        fast.stage_delta_pct_forced_vs_baseline_prepare,
        fast.stage_delta_pct_forced_vs_baseline_execute,
        fast.stage_delta_pct_forced_vs_baseline_finish,
        summary_name
    );

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_share_instructions(
    path: &Path,
    email: &str,
    out_dir: &Path,
    primary_files: &[&str],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(
        &mut body,
        "v7.10 AMD Novel-Family Capture: Share Instructions"
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "1) Open this folder:").map_err(|e| e.to_string())?;
    writeln!(&mut body, "   {}", out_dir.display()).map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "2) Keep all files in this folder together.").map_err(|e| e.to_string())?;
    writeln!(&mut body, "3) Zip the folder.").map_err(|e| e.to_string())?;
    writeln!(&mut body, "4) Email the zip to: {email}").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "Primary files in this run:").map_err(|e| e.to_string())?;
    for file in primary_files {
        writeln!(&mut body, "- {file}").map_err(|e| e.to_string())?;
    }

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn make_workload() -> (Vec<u8>, Vec<Vec<u8>>) {
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

fn pct_delta(baseline: f64, candidate: f64) -> f64 {
    if baseline == 0.0 {
        0.0
    } else {
        ((candidate - baseline) / baseline) * 100.0
    }
}

fn mean_u64<const N: usize>(values: [u64; N]) -> f64 {
    let sum: u128 = values.iter().map(|value| *value as u128).sum();
    (sum as f64) / (N as f64)
}

fn counter_spans(runs: [&PerfRun; 4]) -> Vec<(&'static str, u64)> {
    let mut spans = Vec::new();

    let counters: [(&'static str, [u64; 4]); 15] = [
        (
            "program_execs",
            [
                runs[0].perf.program_execs,
                runs[1].perf.program_execs,
                runs[2].perf.program_execs,
                runs[3].perf.program_execs,
            ],
        ),
        (
            "scratchpad_read_bytes",
            [
                runs[0].perf.scratchpad_read_bytes,
                runs[1].perf.scratchpad_read_bytes,
                runs[2].perf.scratchpad_read_bytes,
                runs[3].perf.scratchpad_read_bytes,
            ],
        ),
        (
            "scratchpad_write_bytes",
            [
                runs[0].perf.scratchpad_write_bytes,
                runs[1].perf.scratchpad_write_bytes,
                runs[2].perf.scratchpad_write_bytes,
                runs[3].perf.scratchpad_write_bytes,
            ],
        ),
        (
            "dataset_item_loads",
            [
                runs[0].perf.dataset_item_loads,
                runs[1].perf.dataset_item_loads,
                runs[2].perf.dataset_item_loads,
                runs[3].perf.dataset_item_loads,
            ],
        ),
        (
            "mem_read_l1",
            [
                runs[0].perf.mem_read_l1,
                runs[1].perf.mem_read_l1,
                runs[2].perf.mem_read_l1,
                runs[3].perf.mem_read_l1,
            ],
        ),
        (
            "mem_read_l2",
            [
                runs[0].perf.mem_read_l2,
                runs[1].perf.mem_read_l2,
                runs[2].perf.mem_read_l2,
                runs[3].perf.mem_read_l2,
            ],
        ),
        (
            "mem_read_l3",
            [
                runs[0].perf.mem_read_l3,
                runs[1].perf.mem_read_l3,
                runs[2].perf.mem_read_l3,
                runs[3].perf.mem_read_l3,
            ],
        ),
        (
            "mem_write_l1",
            [
                runs[0].perf.mem_write_l1,
                runs[1].perf.mem_write_l1,
                runs[2].perf.mem_write_l1,
                runs[3].perf.mem_write_l1,
            ],
        ),
        (
            "mem_write_l2",
            [
                runs[0].perf.mem_write_l2,
                runs[1].perf.mem_write_l2,
                runs[2].perf.mem_write_l2,
                runs[3].perf.mem_write_l2,
            ],
        ),
        (
            "mem_write_l3",
            [
                runs[0].perf.mem_write_l3,
                runs[1].perf.mem_write_l3,
                runs[2].perf.mem_write_l3,
                runs[3].perf.mem_write_l3,
            ],
        ),
        (
            "instr_int",
            [
                runs[0].perf.instr_int,
                runs[1].perf.instr_int,
                runs[2].perf.instr_int,
                runs[3].perf.instr_int,
            ],
        ),
        (
            "instr_float",
            [
                runs[0].perf.instr_float,
                runs[1].perf.instr_float,
                runs[2].perf.instr_float,
                runs[3].perf.instr_float,
            ],
        ),
        (
            "instr_mem",
            [
                runs[0].perf.instr_mem,
                runs[1].perf.instr_mem,
                runs[2].perf.instr_mem,
                runs[3].perf.instr_mem,
            ],
        ),
        (
            "instr_ctrl",
            [
                runs[0].perf.instr_ctrl,
                runs[1].perf.instr_ctrl,
                runs[2].perf.instr_ctrl,
                runs[3].perf.instr_ctrl,
            ],
        ),
        (
            "instr_store",
            [
                runs[0].perf.instr_store,
                runs[1].perf.instr_store,
                runs[2].perf.instr_store,
                runs[3].perf.instr_store,
            ],
        ),
    ];

    for (name, values) in counters {
        let min = values.iter().copied().min().unwrap_or(0);
        let max = values.iter().copied().max().unwrap_or(0);
        spans.push((name, max.saturating_sub(min)));
    }

    spans
}

fn bool_or_na(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "n/a",
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let replaced = value.replace('"', "''");
        format!("\"{}\"", replaced)
    } else {
        value.to_string()
    }
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {trimmed}"));
    }

    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = decode_nibble(bytes[i]).ok_or_else(|| {
            format!(
                "invalid hex character '{}' at index {}",
                bytes[i] as char, i
            )
        })?;
        let lo = decode_nibble(bytes[i + 1]).ok_or_else(|| {
            format!(
                "invalid hex character '{}' at index {}",
                bytes[i + 1] as char,
                i + 1
            )
        })?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
