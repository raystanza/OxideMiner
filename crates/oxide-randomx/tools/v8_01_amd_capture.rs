use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

const PROMPT_ID: &str = "PROMPTv8_01";
const DEFAULT_EMAIL: &str = "raystanza@raystanza.uk";
const DEFAULT_PERF_ITERS: u64 = 50;
const DEFAULT_PERF_WARMUP: u64 = 5;
const EXPECTED_HOSTS: &[(u32, u32)] = &[(23, 8), (23, 113)];

const GIT_SHA: &str = env!("OXIDE_RANDOMX_GIT_SHA");
const GIT_SHA_SHORT: &str = env!("OXIDE_RANDOMX_GIT_SHA_SHORT");
const GIT_DIRTY: &str = env!("OXIDE_RANDOMX_GIT_DIRTY");
const RUSTC_VERSION: &str = env!("OXIDE_RANDOMX_RUSTC_VERSION");

mod perf_harness_support {
    #![allow(dead_code)]

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/perf_harness.rs"
    ));

    pub struct CaptureSpec<'a> {
        pub mode: &'a str,
        pub iters: u64,
        pub warmup: u64,
        pub threads: usize,
        pub jit: bool,
        pub jit_fast_regs: bool,
        pub large_pages: bool,
    }

    pub struct CaptureArtifacts {
        pub csv: String,
        pub json: String,
        pub summary: String,
    }

    pub fn ensure_compiled_features() -> Result<(), String> {
        if !cfg!(feature = "jit") {
            return Err("v8_01_amd_capture must be built with --features jit".to_string());
        }
        if !cfg!(feature = "jit-fastregs") {
            return Err("v8_01_amd_capture must be built with --features jit-fastregs".to_string());
        }
        if !cfg!(feature = "bench-instrument") {
            return Err(
                "v8_01_amd_capture must be built with --features bench-instrument".to_string(),
            );
        }
        Ok(())
    }

    pub fn capture(spec: &CaptureSpec<'_>) -> Result<CaptureArtifacts, String> {
        let mode = match spec.mode {
            "light" => Mode::Light,
            "fast" => Mode::Fast,
            other => return Err(format!("unsupported capture mode: {other}")),
        };

        let opts = Options {
            mode,
            iters: spec.iters,
            warmup: spec.warmup,
            threads: spec.threads,
            jit: spec.jit,
            jit_fast_regs: spec.jit_fast_regs,
            large_pages: spec.large_pages,
            use_1gb_pages: false,
            thread_names: false,
            affinity: None,
            format: OutputFormat::Human,
            out: None,
        };

        let report = run_harness(&opts)?;
        Ok(CaptureArtifacts {
            csv: format_csv(&report),
            json: format_json(&report),
            summary: summary_line(&report),
        })
    }
}

#[derive(Debug)]
struct Options {
    out_dir: Option<PathBuf>,
    threads: usize,
    perf_iters: u64,
    perf_warmup: u64,
    large_pages: bool,
    owner_email: String,
    validate_only: bool,
}

#[derive(Debug)]
struct HostIdentity {
    vendor: String,
    family: u32,
    model: u32,
    stepping: u32,
    cpu_model_string: String,
    os_name: String,
    os_version: String,
    os_build_or_kernel: String,
    logical_threads: usize,
}

impl HostIdentity {
    fn host_tag(&self) -> String {
        format!("amd_fam{}_mod{}", self.family, self.model)
    }

    fn is_expected(&self) -> bool {
        self.vendor == "AuthenticAMD"
            && EXPECTED_HOSTS
                .iter()
                .any(|(family, model)| *family == self.family && *model == self.model)
    }
}

#[derive(Debug)]
struct NowStrings {
    compact: String,
    date: String,
    iso: String,
}

#[derive(Clone, Copy)]
struct MatrixRowDef {
    label: &'static str,
    display_mode: &'static str,
    capture_mode: &'static str,
    config: &'static str,
    jit: bool,
    jit_fast_regs: bool,
    fast_mode: bool,
}

const MATRIX_ROWS: [MatrixRowDef; 6] = [
    MatrixRowDef {
        label: "light_interp",
        display_mode: "Light",
        capture_mode: "light",
        config: "Interpreter",
        jit: false,
        jit_fast_regs: false,
        fast_mode: false,
    },
    MatrixRowDef {
        label: "light_jit_conservative",
        display_mode: "Light",
        capture_mode: "light",
        config: "JIT conservative",
        jit: true,
        jit_fast_regs: false,
        fast_mode: false,
    },
    MatrixRowDef {
        label: "light_jit_fastregs",
        display_mode: "Light",
        capture_mode: "light",
        config: "JIT fast-regs",
        jit: true,
        jit_fast_regs: true,
        fast_mode: false,
    },
    MatrixRowDef {
        label: "fast_interp",
        display_mode: "Fast",
        capture_mode: "fast",
        config: "Interpreter",
        jit: false,
        jit_fast_regs: false,
        fast_mode: true,
    },
    MatrixRowDef {
        label: "fast_jit_conservative",
        display_mode: "Fast",
        capture_mode: "fast",
        config: "JIT conservative",
        jit: true,
        jit_fast_regs: false,
        fast_mode: true,
    },
    MatrixRowDef {
        label: "fast_jit_fastregs",
        display_mode: "Fast",
        capture_mode: "fast",
        config: "JIT fast-regs",
        jit: true,
        jit_fast_regs: true,
        fast_mode: true,
    },
];

struct RowArtifact {
    def: MatrixRowDef,
    csv_name: String,
    json_name: String,
    summary_line: String,
    csv_header: Vec<String>,
    csv_fields: BTreeMap<String, String>,
}

struct ArtifactNameSet<'a> {
    provenance_name: &'a str,
    commands_name: &'a str,
    manifest_name: &'a str,
    perf_index_name: &'a str,
    summary_name: &'a str,
    memo_name: &'a str,
    share_name: &'a str,
}

fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(err) => {
            eprintln!("error: {err}");
            print_usage();
            process::exit(2);
        }
    };

    if let Err(err) = perf_harness_support::ensure_compiled_features() {
        eprintln!("error: {err}");
        process::exit(1);
    }

    let now = now_strings();
    let host = match detect_host_identity() {
        Ok(host) => host,
        Err(err) => {
            eprintln!("error: failed to detect host identity: {err}");
            process::exit(1);
        }
    };

    if options.validate_only {
        if !host.is_expected() {
            eprintln!(
                "error: unexpected host tag for {} single-binary capture: {}",
                PROMPT_ID,
                host.host_tag()
            );
            process::exit(1);
        }
        println!(
            "validate-only: binary OK for {} ({})",
            host.host_tag(),
            host.os_name
        );
        println!(
            "current_exe={}",
            env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("unknown"))
                .display()
        );
        return;
    }

    let host_tag = host.host_tag();
    let out_dir = options
        .out_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("v8_01_capture_{}_{}", host_tag, now.compact)));

    if let Err(err) = fs::create_dir_all(&out_dir) {
        eprintln!(
            "error: failed to create output directory {}: {err}",
            out_dir.display()
        );
        process::exit(1);
    }

    if !host.is_expected() {
        if let Err(err) =
            write_unexpected_host_artifacts(&out_dir, &host, &now, &options.owner_email)
        {
            eprintln!("error: failed to write unexpected-host artifacts: {err}");
            process::exit(1);
        }
        println!(
            "Run completed with host limitation. Output folder: {}",
            out_dir.display()
        );
        return;
    }

    let provenance_name = format!("v8_01_host_provenance_{}_{}.txt", host_tag, now.compact);
    let commands_name = format!("v8_01_commands_{}_{}.log", host_tag, now.compact);
    let manifest_name = format!("v8_01_manifest_{}_{}.txt", host_tag, now.compact);
    let perf_index_name = format!("v8_01_perf_index_{}_{}.csv", host_tag, now.compact);
    let summary_name = format!("v8_01_summary_{}_{}.json", host_tag, now.compact);
    let memo_name = format!("v8_01_current_head_baseline_{}_{}.md", host_tag, now.date);
    let share_name = format!("v8_01_share_instructions_{}_{}.txt", host_tag, now.compact);

    let provenance_path = out_dir.join(&provenance_name);
    let commands_path = out_dir.join(&commands_name);
    let manifest_path = out_dir.join(&manifest_name);
    let perf_index_path = out_dir.join(&perf_index_name);
    let summary_path = out_dir.join(&summary_name);
    let memo_path = out_dir.join(&memo_name);
    let share_path = out_dir.join(&share_name);

    if let Err(err) = write_commands_header(&commands_path, &host_tag) {
        eprintln!("error: failed to write command log header: {err}");
        process::exit(1);
    }

    if let Err(err) = write_provenance(&provenance_path, &host, &options, &now) {
        eprintln!("error: failed to write provenance: {err}");
        process::exit(1);
    }

    let mut row_artifacts = Vec::new();
    let mut perf_index_header = None::<Vec<String>>;
    for def in MATRIX_ROWS {
        match capture_row(
            def,
            &out_dir,
            &host_tag,
            &now.compact,
            &options,
            &commands_path,
        ) {
            Ok(artifact) => {
                if perf_index_header.is_none() {
                    perf_index_header = Some(artifact.csv_header.clone());
                }
                row_artifacts.push(artifact);
            }
            Err(err) => {
                eprintln!("error: perf capture failed for {}: {err}", def.label);
                process::exit(1);
            }
        }
    }

    let perf_index_header = perf_index_header.unwrap_or_default();
    if let Err(err) = write_perf_index(&perf_index_path, &perf_index_header, &row_artifacts) {
        eprintln!("error: failed to write perf index: {err}");
        process::exit(1);
    }

    let artifact_names = collect_artifact_names(
        &ArtifactNameSet {
            provenance_name: &provenance_name,
            commands_name: &commands_name,
            manifest_name: &manifest_name,
            perf_index_name: &perf_index_name,
            summary_name: &summary_name,
            memo_name: &memo_name,
            share_name: &share_name,
        },
        &row_artifacts,
    );

    if let Err(err) = write_manifest(
        &manifest_path,
        &host,
        &now,
        &options,
        &out_dir,
        &artifact_names,
    ) {
        eprintln!("error: failed to write manifest: {err}");
        process::exit(1);
    }

    if let Err(err) = write_summary_json(
        &summary_path,
        &host,
        &now,
        &options,
        &row_artifacts,
        &artifact_names,
    ) {
        eprintln!("error: failed to write summary JSON: {err}");
        process::exit(1);
    }

    if let Err(err) = write_memo(
        &memo_path,
        &host,
        &now,
        &options,
        &row_artifacts,
        &artifact_names,
    ) {
        eprintln!("error: failed to write memo: {err}");
        process::exit(1);
    }

    if let Err(err) =
        write_share_instructions(&share_path, &options.owner_email, &out_dir, &artifact_names)
    {
        eprintln!("error: failed to write share instructions: {err}");
        process::exit(1);
    }

    println!("v8.01 AMD packaged capture complete.");
    println!("Artifact folder: {}", out_dir.display());
    println!("Host tag: {}", host_tag);
    println!("Send artifacts to: {}", options.owner_email);
}

fn parse_args() -> Result<Options, String> {
    let mut out_dir = None::<PathBuf>;
    let mut threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let mut perf_iters = DEFAULT_PERF_ITERS;
    let mut perf_warmup = DEFAULT_PERF_WARMUP;
    let mut large_pages = false;
    let mut owner_email = DEFAULT_EMAIL.to_string();
    let mut validate_only = false;

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
            "--owner-email" => {
                owner_email = args
                    .next()
                    .ok_or_else(|| "missing value for --owner-email".to_string())?;
                if owner_email.trim().is_empty() {
                    return Err("--owner-email cannot be empty".to_string());
                }
            }
            "--validate-only" => {
                validate_only = true;
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Options {
        out_dir,
        threads,
        perf_iters,
        perf_warmup,
        large_pages,
        owner_email,
        validate_only,
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
        .unwrap_or_else(|| "v8_01_amd_capture".to_string());

    eprintln!(
        "Usage: {program} [--out-dir PATH] [--threads N] [--perf-iters N] [--perf-warmup N]\n\
         \x20\x20\x20\x20\x20\x20\x20\x20[--large-pages on|off] [--owner-email EMAIL] [--validate-only]"
    );
}

fn now_strings() -> NowStrings {
    #[cfg(target_os = "windows")]
    let compact = command_output(
        "powershell",
        &["-NoProfile", "-Command", "Get-Date -Format yyyyMMdd_HHmmss"],
    );
    #[cfg(target_os = "windows")]
    let date = command_output(
        "powershell",
        &["-NoProfile", "-Command", "Get-Date -Format yyyy-MM-dd"],
    );
    #[cfg(target_os = "windows")]
    let iso = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "Get-Date -Format yyyy-MM-ddTHH:mm:ssK",
        ],
    );

    #[cfg(target_os = "linux")]
    let compact = command_output("date", &["+%Y%m%d_%H%M%S"]);
    #[cfg(target_os = "linux")]
    let date = command_output("date", &["+%Y-%m-%d"]);
    #[cfg(target_os = "linux")]
    let iso = command_output("date", &["+%Y-%m-%dT%H:%M:%S%:z"]);

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let compact: Option<String> = None;
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let date: Option<String> = None;
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let iso: Option<String> = None;

    let epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);

    NowStrings {
        compact: compact.unwrap_or_else(|| format!("{epoch_secs}")),
        date: date.unwrap_or_else(|| format!("unix-{epoch_secs}")),
        iso: iso.unwrap_or_else(|| format!("unix:{epoch_secs}")),
    }
}

fn detect_host_identity() -> Result<HostIdentity, String> {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;

        let cpuid0 = unsafe { __cpuid(0) };
        let mut vendor = [0u8; 12];
        vendor[..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

        let cpuid1 = unsafe { __cpuid(1) };
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
        let cpu_model_string = cpu_model_string();
        let (os_name, os_version, os_build_or_kernel) = os_details();

        Ok(HostIdentity {
            vendor,
            family,
            model,
            stepping,
            cpu_model_string,
            os_name,
            os_version,
            os_build_or_kernel,
            logical_threads: std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1),
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err("unsupported architecture (requires x86_64)".to_string())
    }
}

#[cfg(target_os = "windows")]
fn os_details() -> (String, String, String) {
    if let Some(line) = command_output(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "$os = Get-ComputerInfo | Select-Object OsName,WindowsVersion,OsBuildNumber; \"$($os.OsName)|$($os.WindowsVersion)|$($os.OsBuildNumber)\"",
        ],
    ) {
        let parts = line.split('|').collect::<Vec<_>>();
        if parts.len() == 3 {
            return (
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
                parts[2].trim().to_string(),
            );
        }
    }

    let version = command_output("cmd", &["/C", "ver"]).unwrap_or_else(|| "unknown".to_string());
    (
        "Microsoft Windows".to_string(),
        version,
        "unknown".to_string(),
    )
}

#[cfg(target_os = "linux")]
fn os_details() -> (String, String, String) {
    let pretty_name = linux_os_release_value("PRETTY_NAME").unwrap_or_else(|| "Linux".to_string());
    let version_id = linux_os_release_value("VERSION_ID").unwrap_or_else(|| "unknown".to_string());
    let kernel = command_output("uname", &["-sr"]).unwrap_or_else(|| "unknown".to_string());
    (pretty_name, version_id, kernel)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn os_details() -> (String, String, String) {
    (
        env::consts::OS.to_string(),
        "unknown".to_string(),
        "unknown".to_string(),
    )
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

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
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
fn linux_os_release_value(key: &str) -> Option<String> {
    let contents = fs::read_to_string("/etc/os-release").ok()?;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix(&format!("{key}=")) {
            return Some(trim_shell_quote(value).to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn trim_shell_quote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn capture_row(
    def: MatrixRowDef,
    out_dir: &Path,
    host_tag: &str,
    timestamp: &str,
    options: &Options,
    commands_path: &Path,
) -> Result<RowArtifact, String> {
    let csv_name = format!(
        "v8_01_current_head_{}_{}_{}.csv",
        def.label, host_tag, timestamp
    );
    let json_name = format!(
        "v8_01_current_head_{}_{}_{}.json",
        def.label, host_tag, timestamp
    );

    append_command_log(
        commands_path,
        &equivalent_perf_harness_command(def, &csv_name, options),
    )?;
    let capture = with_capture_env(def.fast_mode, || {
        perf_harness_support::capture(&perf_harness_support::CaptureSpec {
            mode: def.capture_mode,
            iters: options.perf_iters,
            warmup: options.perf_warmup,
            threads: options.threads,
            jit: def.jit,
            jit_fast_regs: def.jit_fast_regs,
            large_pages: options.large_pages,
        })
    })?;

    fs::write(out_dir.join(&csv_name), &capture.csv)
        .map_err(|e| format!("{}: {e}", out_dir.join(&csv_name).display()))?;
    append_command_log(
        commands_path,
        &equivalent_perf_harness_command(def, &json_name, options),
    )?;
    fs::write(out_dir.join(&json_name), &capture.json)
        .map_err(|e| format!("{}: {e}", out_dir.join(&json_name).display()))?;

    let (csv_header, csv_fields) = parse_single_row_csv(&capture.csv)?;

    Ok(RowArtifact {
        def,
        csv_name,
        json_name,
        summary_line: capture.summary,
        csv_header,
        csv_fields,
    })
}

fn equivalent_perf_harness_command(def: MatrixRowDef, out_name: &str, options: &Options) -> String {
    let env_prefix = if def.fast_mode {
        "OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_HUGE_1G=0"
    } else {
        "OXIDE_RANDOMX_HUGE_1G=0"
    };
    format!(
        "{env_prefix} perf_harness --mode {} --jit {} --jit-fast-regs {} --iters {} --warmup {} --threads {} --large-pages {} --thread-names off --affinity off --format {} --out {}",
        def.capture_mode,
        if def.jit { "on" } else { "off" },
        if def.jit_fast_regs { "on" } else { "off" },
        options.perf_iters,
        options.perf_warmup,
        options.threads,
        if options.large_pages { "on" } else { "off" },
        if out_name.ends_with(".json") { "json" } else { "csv" },
        out_name
    )
}

fn with_capture_env<T, F>(fast_mode: bool, op: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let prev_fast = env::var_os("OXIDE_RANDOMX_FAST_BENCH");
    let prev_huge = env::var_os("OXIDE_RANDOMX_HUGE_1G");
    let prev_small = env::var_os("OXIDE_RANDOMX_FAST_BENCH_SMALL");

    if fast_mode {
        env::set_var("OXIDE_RANDOMX_FAST_BENCH", "1");
    } else {
        env::remove_var("OXIDE_RANDOMX_FAST_BENCH");
    }
    env::set_var("OXIDE_RANDOMX_HUGE_1G", "0");
    env::remove_var("OXIDE_RANDOMX_FAST_BENCH_SMALL");

    let result = op();

    restore_env_var("OXIDE_RANDOMX_FAST_BENCH", prev_fast);
    restore_env_var("OXIDE_RANDOMX_HUGE_1G", prev_huge);
    restore_env_var("OXIDE_RANDOMX_FAST_BENCH_SMALL", prev_small);
    result
}

fn restore_env_var(name: &str, value: Option<OsString>) {
    match value {
        Some(value) => env::set_var(name, value),
        None => env::remove_var(name),
    }
}

fn write_commands_header(path: &Path, host_tag: &str) -> Result<(), String> {
    let current_exe = env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("unknown"))
        .display()
        .to_string();
    let body = format!(
        "# {PROMPT_ID} AMD single-binary baseline capture\nhost_tag={host_tag}\nrunner_binary={current_exe}\nvalidation_split=validation must still be run on the clean build host that produced this binary; the packaged binary captures perf rows only\n"
    );
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn append_command_log(path: &Path, line: &str) -> Result<(), String> {
    let mut body = fs::read_to_string(path).unwrap_or_default();
    writeln!(&mut body, "{line}").map_err(|e| e.to_string())?;
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_provenance(
    path: &Path,
    host: &HostIdentity,
    options: &Options,
    now: &NowStrings,
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "timestamp={}", now.iso).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={}", host.host_tag()).map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "stepping={}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "cpu_model_string={}", host.cpu_model_string).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_name={}", host.os_name).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_version={}", host.os_version).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_build_or_kernel={}", host.os_build_or_kernel)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "logical_threads={}", host.logical_threads).map_err(|e| e.to_string())?;
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
    writeln!(
        &mut body,
        "validation_split=validation must still be run on the clean build host that produced this binary; the packaged binary captures perf rows only"
    )
    .map_err(|e| e.to_string())?;
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_manifest(
    path: &Path,
    host: &HostIdentity,
    now: &NowStrings,
    options: &Options,
    out_dir: &Path,
    artifacts: &[String],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "prompt_id={PROMPT_ID}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "capture_timestamp={}", now.compact).map_err(|e| e.to_string())?;
    writeln!(&mut body, "capture_timestamp_iso={}", now.iso).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={}", host.host_tag()).map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "stepping={}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "cpu_model_string={}", host.cpu_model_string).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_name={}", host.os_name).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_version={}", host.os_version).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_build_or_kernel={}", host.os_build_or_kernel)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_iters={}", options.perf_iters).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_warmup={}", options.perf_warmup).map_err(|e| e.to_string())?;
    writeln!(&mut body, "threads={}", options.threads).map_err(|e| e.to_string())?;
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
    writeln!(&mut body, "artifact_dir={}", out_dir.display()).map_err(|e| e.to_string())?;
    writeln!(&mut body, "artifacts:").map_err(|e| e.to_string())?;
    for artifact in artifacts {
        writeln!(&mut body, "- {artifact}").map_err(|e| e.to_string())?;
    }
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_perf_index(
    path: &Path,
    csv_header: &[String],
    rows: &[RowArtifact],
) -> Result<(), String> {
    let mut body = String::new();
    let mut header = vec![
        "label".to_string(),
        "matrix_mode".to_string(),
        "config".to_string(),
        "runtime_jit_flags".to_string(),
        "csv_artifact".to_string(),
        "json_artifact".to_string(),
    ];
    header.extend_from_slice(csv_header);
    writeln!(&mut body, "{}", header.join(",")).map_err(|e| e.to_string())?;

    for row in rows {
        let mut values = vec![
            csv_escape(row.def.label),
            csv_escape(row.def.display_mode),
            csv_escape(row.def.config),
            csv_escape(runtime_jit_flags(row.def)),
            csv_escape(&row.csv_name),
            csv_escape(&row.json_name),
        ];
        for column in csv_header {
            values.push(csv_escape(
                row.csv_fields.get(column).map(String::as_str).unwrap_or(""),
            ));
        }
        writeln!(&mut body, "{}", values.join(",")).map_err(|e| e.to_string())?;
    }

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_summary_json(
    path: &Path,
    host: &HostIdentity,
    now: &NowStrings,
    options: &Options,
    rows: &[RowArtifact],
    artifacts: &[String],
) -> Result<(), String> {
    let git_dirty_all_false = rows.iter().all(|row| {
        row.csv_fields
            .get("git_dirty")
            .map(|value| value == "false")
            .unwrap_or(false)
    });

    let summary = json!({
        "prompt": PROMPT_ID,
        "timestamp": now.compact,
        "date": now.date,
        "host_tag": host.host_tag(),
        "host": {
            "vendor": host.vendor,
            "family": host.family,
            "model": host.model,
            "stepping": host.stepping,
            "cpu_model_string": host.cpu_model_string,
            "os_name": host.os_name,
            "os_version": host.os_version,
            "os_build_or_kernel": host.os_build_or_kernel,
            "logical_threads": host.logical_threads,
        },
        "provenance": {
            "git_sha": GIT_SHA,
            "git_sha_short": GIT_SHA_SHORT,
            "git_dirty": GIT_DIRTY,
            "rustc": RUSTC_VERSION,
            "git_dirty_all_csv_false": git_dirty_all_false,
            "validation_split": "validation must still be run on the clean build host that produced this binary; the packaged binary captures perf rows only",
        },
        "params": {
            "iters": options.perf_iters,
            "warmup": options.perf_warmup,
            "threads": options.threads,
            "inputs": parse_u64_field(find_row(rows, "light_interp"), "inputs").unwrap_or(6),
            "large_pages": if options.large_pages { "on" } else { "off" },
            "large_pages_1gb": "off",
            "thread_names": "off",
            "affinity": "off",
            "fast_mode_env": "OXIDE_RANDOMX_FAST_BENCH=1",
        },
        "artifacts": artifacts,
        "rows": rows.iter().map(row_json_value).collect::<Vec<_>>(),
        "derived": build_derived_metrics(rows),
    });

    let body = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_memo(
    path: &Path,
    host: &HostIdentity,
    now: &NowStrings,
    options: &Options,
    rows: &[RowArtifact],
    artifacts: &[String],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(
        &mut body,
        "# v8.01 AMD Current-HEAD Baseline Capture ({}, {})",
        host.host_tag(),
        host.os_name
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Scope").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "Captured the current-HEAD six-row `perf_harness` matrix from a single packaged binary on an expected AMD host class. This binary captures benchmark artifacts only; validation belongs on the clean build host that produced it."
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Host Provenance").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- vendor: {}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- family: {}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- model: {}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- stepping: {}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- CPU: {}", host.cpu_model_string).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- OS: {} (version {}, build/kernel {})",
        host.os_name, host.os_version, host.os_build_or_kernel
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- logical threads used: {}", options.threads)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- git SHA: {}", GIT_SHA).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- rustc: {}", RUSTC_VERSION).map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Locked Runtime Parameters").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- capture date: {}", now.date).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- iters={}", options.perf_iters).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- warmup={}", options.perf_warmup).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- threads={}", options.threads).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- inputs=6").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- large-pages {}",
        if options.large_pages { "on" } else { "off" }
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- thread-names off").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- affinity off").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- OXIDE_RANDOMX_HUGE_1G=0 for all rows").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- OXIDE_RANDOMX_FAST_BENCH=1 for Fast rows only")
        .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Current-HEAD Matrix (CSV authority)").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "| Mode | Configuration | Runtime JIT flags | features | ns/hash | hashes/sec | CSV artifact | JSON artifact |"
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "| --- | --- | --- | --- | ---: | ---: | --- | --- |"
    )
    .map_err(|e| e.to_string())?;
    for row in rows {
        writeln!(
            &mut body,
            "| {} | {} | {} | {} | {} | {:.3} | {} | {} |",
            row.def.display_mode,
            row.def.config,
            runtime_jit_flags(row.def),
            row.csv_fields
                .get("features")
                .map(String::as_str)
                .unwrap_or(""),
            format_int_with_commas(parse_u64_field(Some(row), "ns_per_hash").unwrap_or_default()),
            parse_f64_field(Some(row), "hashes_per_sec").unwrap_or_default(),
            row.csv_name,
            row.json_name,
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Emitted-State Verification").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- All six CSV authority rows share one git SHA and report `git_dirty=false`."
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- All rows report `large_pages_requested=false`, `large_pages_1gb_requested=false`, `prefetch_distance=2`, and `prefetch_auto_tune=false` unless the binary was rebuilt intentionally with different defaults.").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- Interpreter rows report `jit_active=false`; conservative JIT rows report `jit_active=true` and `jit_fast_regs=false`; fast-regs rows report `jit_active=true` and `jit_fast_regs=true`.").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- Fast rows report dataset page outcomes directly; light rows report dataset page fields as `n/a`.").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- Fast-regs rows carry the aggregate fast-regs prepare/finish fields and helper counters required for v8 authority capture.").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Commands").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    for row in rows {
        writeln!(
            &mut body,
            "- `{}`",
            equivalent_perf_harness_command(row.def, &row.csv_name, options)
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Artifacts").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    for artifact in artifacts {
        writeln!(&mut body, "- {artifact}").map_err(|e| e.to_string())?;
    }

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_share_instructions(
    path: &Path,
    email: &str,
    out_dir: &Path,
    artifacts: &[String],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(
        &mut body,
        "v8.01 AMD current-head baseline capture: share instructions"
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
    for artifact in artifacts {
        writeln!(&mut body, "- {artifact}").map_err(|e| e.to_string())?;
    }

    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_unexpected_host_artifacts(
    out_dir: &Path,
    host: &HostIdentity,
    now: &NowStrings,
    owner_email: &str,
) -> Result<(), String> {
    let summary_name = format!("v8_01_summary_{}_{}.json", host.host_tag(), now.compact);
    let memo_name = format!("v8_01_unexpected_host_{}_{}.md", host.host_tag(), now.date);
    let share_name = format!(
        "v8_01_share_instructions_{}_{}.txt",
        host.host_tag(),
        now.compact
    );

    let memo_path = out_dir.join(&memo_name);
    let summary_path = out_dir.join(&summary_name);
    let share_path = out_dir.join(&share_name);

    let mut memo = String::new();
    writeln!(
        &mut memo,
        "# v8.01 AMD Baseline Capture Blocked ({})",
        host.host_tag()
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut memo).map_err(|e| e.to_string())?;
    writeln!(
        &mut memo,
        "This single-binary capture only treats the following host classes as authority targets:"
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut memo).map_err(|e| e.to_string())?;
    for (family, model) in EXPECTED_HOSTS {
        writeln!(&mut memo, "- AuthenticAMD/{family}/{model}").map_err(|e| e.to_string())?;
    }
    writeln!(&mut memo).map_err(|e| e.to_string())?;
    writeln!(&mut memo, "Observed host:").map_err(|e| e.to_string())?;
    writeln!(&mut memo).map_err(|e| e.to_string())?;
    writeln!(&mut memo, "- vendor: {}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut memo, "- family: {}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut memo, "- model: {}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut memo, "- stepping: {}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut memo, "- CPU: {}", host.cpu_model_string).map_err(|e| e.to_string())?;
    writeln!(
        &mut memo,
        "- OS: {} (version {}, build/kernel {})",
        host.os_name, host.os_version, host.os_build_or_kernel
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut memo).map_err(|e| e.to_string())?;
    writeln!(
        &mut memo,
        "This machine is not baseline authority for the current AMD host inventory, so the binary stopped without producing benchmark rows."
    )
    .map_err(|e| e.to_string())?;
    fs::write(&memo_path, memo).map_err(|e| format!("{}: {e}", memo_path.display()))?;

    let summary = json!({
        "prompt": PROMPT_ID,
        "timestamp": now.compact,
        "host_tag": host.host_tag(),
        "status": "blocked_unexpected_host",
        "expected_host_tags": EXPECTED_HOSTS
            .iter()
            .map(|(family, model)| format!("amd_fam{}_mod{}", family, model))
            .collect::<Vec<_>>(),
        "observed": {
            "vendor": host.vendor,
            "family": host.family,
            "model": host.model,
            "stepping": host.stepping,
            "cpu_model_string": host.cpu_model_string,
            "os_name": host.os_name,
            "os_version": host.os_version,
            "os_build_or_kernel": host.os_build_or_kernel,
        },
        "artifacts": {
            "memo": memo_name,
            "summary": summary_name,
        }
    });
    let body = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    fs::write(&summary_path, body).map_err(|e| format!("{}: {e}", summary_path.display()))?;

    write_share_instructions(
        &share_path,
        owner_email,
        out_dir,
        &[memo_name, summary_name, share_name],
    )
}

fn collect_artifact_names(
    artifact_names: &ArtifactNameSet<'_>,
    rows: &[RowArtifact],
) -> Vec<String> {
    let mut artifacts = vec![
        artifact_names.provenance_name.to_string(),
        artifact_names.commands_name.to_string(),
        artifact_names.manifest_name.to_string(),
        artifact_names.perf_index_name.to_string(),
        artifact_names.summary_name.to_string(),
        artifact_names.memo_name.to_string(),
        artifact_names.share_name.to_string(),
    ];
    for row in rows {
        artifacts.push(row.csv_name.clone());
        artifacts.push(row.json_name.clone());
    }
    artifacts.sort();
    artifacts
}

fn runtime_jit_flags(def: MatrixRowDef) -> &'static str {
    match (def.jit, def.jit_fast_regs) {
        (false, false) => "--jit off",
        (true, false) => "--jit on --jit-fast-regs off",
        (true, true) => "--jit on --jit-fast-regs on",
        (false, true) => "--jit off",
    }
}

fn row_json_value(row: &RowArtifact) -> Value {
    let mut value = Map::new();
    value.insert(
        "label".to_string(),
        Value::String(row.def.label.to_string()),
    );
    value.insert(
        "matrix_mode".to_string(),
        Value::String(row.def.display_mode.to_string()),
    );
    value.insert(
        "config".to_string(),
        Value::String(row.def.config.to_string()),
    );
    value.insert(
        "runtime_jit_flags".to_string(),
        Value::String(runtime_jit_flags(row.def).to_string()),
    );
    value.insert(
        "csv_artifact".to_string(),
        Value::String(row.csv_name.clone()),
    );
    value.insert(
        "json_artifact".to_string(),
        Value::String(row.json_name.clone()),
    );
    value.insert(
        "summary_line".to_string(),
        Value::String(row.summary_line.clone()),
    );
    for column in &row.csv_header {
        value.insert(
            column.clone(),
            coerce_json_value(row.csv_fields.get(column).map(String::as_str).unwrap_or("")),
        );
    }
    Value::Object(value)
}

fn build_derived_metrics(rows: &[RowArtifact]) -> Value {
    let metric =
        |label: &str, field: &str| parse_u64_field(find_row(rows, label), field).unwrap_or(0);
    let light_interp = metric("light_interp", "ns_per_hash");
    let light_jit = metric("light_jit_conservative", "ns_per_hash");
    let light_fastregs = metric("light_jit_fastregs", "ns_per_hash");
    let fast_interp = metric("fast_interp", "ns_per_hash");
    let fast_jit = metric("fast_jit_conservative", "ns_per_hash");
    let fast_fastregs = metric("fast_jit_fastregs", "ns_per_hash");

    json!({
        "light_jit_conservative_vs_interp_pct": pct_delta(light_interp, light_jit),
        "light_jit_fastregs_vs_conservative_pct": pct_delta(light_jit, light_fastregs),
        "fast_jit_conservative_vs_interp_pct": pct_delta(fast_interp, fast_jit),
        "fast_jit_fastregs_vs_conservative_pct": pct_delta(fast_jit, fast_fastregs),
        "fast_jit_fastregs_vs_interp_pct": pct_delta(fast_interp, fast_fastregs),
    })
}

fn parse_single_row_csv(input: &str) -> Result<(Vec<String>, BTreeMap<String, String>), String> {
    let mut lines = input
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty());
    let header_line = lines
        .next()
        .ok_or_else(|| "missing CSV header row".to_string())?;
    let value_line = lines
        .next()
        .ok_or_else(|| "missing CSV value row".to_string())?;

    let header = parse_csv_line(header_line)?;
    let values = parse_csv_line(value_line)?;
    if header.len() != values.len() {
        return Err(format!(
            "CSV header/value length mismatch: {} vs {}",
            header.len(),
            values.len()
        ));
    }

    let mut map = BTreeMap::new();
    for (column, value) in header.iter().zip(values.into_iter()) {
        map.insert(column.clone(), value);
    }

    Ok((header, map))
}

fn parse_csv_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if matches!(chars.peek(), Some('"')) {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else if current.is_empty() {
                    in_quotes = true;
                } else {
                    current.push(ch);
                }
            }
            ',' if !in_quotes => {
                fields.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if in_quotes {
        return Err("unterminated quoted CSV field".to_string());
    }
    fields.push(current);
    Ok(fields)
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn coerce_json_value(value: &str) -> Value {
    match value {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "n/a" => Value::String("n/a".to_string()),
        _ => {
            if let Ok(parsed) = value.parse::<i64>() {
                return Value::from(parsed);
            }
            if let Ok(parsed) = value.parse::<u64>() {
                return Value::from(parsed);
            }
            if let Ok(parsed) = value.parse::<f64>() {
                return Value::from(parsed);
            }
            Value::String(value.to_string())
        }
    }
}

fn find_row<'a>(rows: &'a [RowArtifact], label: &str) -> Option<&'a RowArtifact> {
    rows.iter().find(|row| row.def.label == label)
}

fn parse_u64_field(row: Option<&RowArtifact>, field: &str) -> Option<u64> {
    row?.csv_fields.get(field)?.parse::<u64>().ok()
}

fn parse_f64_field(row: Option<&RowArtifact>, field: &str) -> Option<f64> {
    row?.csv_fields.get(field)?.parse::<f64>().ok()
}

fn pct_delta(baseline: u64, candidate: u64) -> f64 {
    if baseline == 0 {
        0.0
    } else {
        ((candidate as f64 - baseline as f64) / baseline as f64) * 100.0
    }
}

fn format_int_with_commas(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (idx, ch) in digits.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_line_handles_quotes() {
        let fields = parse_csv_line("a,\"b,c\",\"d\"\"e\"").unwrap();
        assert_eq!(fields, vec!["a", "b,c", "d\"e"]);
    }

    #[test]
    fn runtime_flags_match_matrix_shape() {
        assert_eq!(runtime_jit_flags(MATRIX_ROWS[0]), "--jit off");
        assert_eq!(
            runtime_jit_flags(MATRIX_ROWS[1]),
            "--jit on --jit-fast-regs off"
        );
        assert_eq!(
            runtime_jit_flags(MATRIX_ROWS[2]),
            "--jit on --jit-fast-regs on"
        );
    }

    #[test]
    fn coerce_json_value_preserves_na() {
        assert_eq!(coerce_json_value("n/a"), Value::String("n/a".to_string()));
        assert_eq!(coerce_json_value("42"), Value::from(42u64));
        assert_eq!(coerce_json_value("false"), Value::Bool(false));
    }
}
