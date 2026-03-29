use oxide_randomx::full_features_capture::{
    collect_artifacts, detect_host_identity, ensure_compiled_features, execute_capture_plan,
    now_strings, page_backing_summary_json, page_profile_json, public_beta_plan, run_json_value,
    short_hash32, superscalar_json_value, write_artifact, write_matrix_index, write_pair_index,
    write_pair_summary_csv, CaptureContext, CaptureOptions, CaptureSurface, HostIdentity,
    HostOsClass, PageBackingSummary, PairSummary, PublicBetaProfile, COMMANDS_ARTIFACT,
    DEFAULT_PERF_ITERS, DEFAULT_PERF_WARMUP, MANIFEST_ARTIFACT, MATRIX_INDEX_ARTIFACT,
    PAIR_INDEX_ARTIFACT, PAIR_SUMMARY_ARTIFACT,
};
use serde_json::json;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

const TOOL_ID: &str = "oxide-randomx-beta-capture";
const PUBLIC_SCHEMA_VERSION: &str = "oxide_randomx_public_beta_v1";
const README_FIRST_FILE: &str = "README_FIRST.txt";
const SUMMARY_FILE: &str = "SUMMARY.txt";
const SUMMARY_JSON_FILE: &str = "summary.json";
const SHARE_FILE: &str = "SHARE_THIS_FILE.txt";
const BETA_RELEASE_ID: &str = env!("OXIDE_RANDOMX_BETA_RELEASE_ID");
const RUSTC_VERSION: &str = env!("OXIDE_RANDOMX_RUSTC_VERSION");

const COLLECT_DATA: &[&str] = &[
    "CPU vendor, family, model, stepping, and model string",
    "logical thread count",
    "OS name, version, and build/kernel",
    "benchmark timings for baseline and selected experimental states",
    "realized page-backing results",
    "public beta release ID and bundle ID",
];

const DO_NOT_COLLECT_DATA: &[&str] = &[
    "wallet data",
    "mining activity",
    "files outside the output directory",
    "browser history or installed-application inventories",
    "automatic telemetry upload",
    "usernames or absolute local file paths in the intended public artifact surface",
];

#[derive(Debug)]
struct Options {
    profile: PublicBetaProfile,
    out_dir: Option<PathBuf>,
    accept_data_contract: bool,
    validate_only: bool,
}

#[derive(Debug)]
struct BundleMeta {
    beta_release_id: String,
    bundle_id: String,
    result_dir_name: String,
    archive_name: String,
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

    if let Err(err) = ensure_compiled_features(TOOL_ID) {
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
    ensure_public_host_scope(&host);

    let mut bundle_meta = build_bundle_meta(&host, &now, options.profile);
    let out_dir = options
        .out_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(&bundle_meta.result_dir_name));
    bundle_meta.result_dir_name = out_dir
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| bundle_meta.result_dir_name.clone());

    if options.validate_only {
        println!(
            "validate-only: binary OK for {} ({})",
            host.host_tag(),
            host.os_name
        );
        println!("profile={}", options.profile.as_str());
        println!("beta_release_id={}", bundle_meta.beta_release_id);
        println!(
            "required_features={}",
            oxide_randomx::full_features_capture::REQUIRED_FEATURES
        );
        return;
    }

    if let Err(err) = fs::create_dir_all(&out_dir) {
        eprintln!(
            "error: failed to create output directory {}: {err}",
            out_dir.display()
        );
        process::exit(1);
    }

    let plan = public_beta_plan(options.profile, host.os_class());
    print_startup_contract(&bundle_meta, options.profile, &plan, &host, &out_dir);
    if !options.accept_data_contract {
        if let Err(err) = prompt_for_contract_acceptance() {
            eprintln!("error: {err}");
            process::exit(1);
        }
    }

    let commands_path = out_dir.join(COMMANDS_ARTIFACT);
    if let Err(err) = write_public_commands_header(&commands_path, &bundle_meta, options.profile) {
        eprintln!("error: failed to initialize command log: {err}");
        process::exit(1);
    }

    let shared_ctx = CaptureContext {
        options: CaptureOptions {
            threads: host.logical_threads,
            perf_iters: DEFAULT_PERF_ITERS,
            perf_warmup: DEFAULT_PERF_WARMUP,
        },
        now: now.clone(),
        host: host.clone(),
        host_tag: host.host_tag(),
        out_dir: out_dir.clone(),
        commands_path,
        surface: CaptureSurface::Public {
            beta_release_id: &bundle_meta.beta_release_id,
        },
    };

    let output = match execute_capture_plan(&shared_ctx, &plan) {
        Ok(output) => output,
        Err(err) => {
            eprintln!("error: capture failed: {err}");
            process::exit(1);
        }
    };

    if let Err(err) = write_matrix_index(&out_dir.join(MATRIX_INDEX_ARTIFACT), &output.matrix_runs)
    {
        eprintln!("error: failed to write matrix index: {err}");
        process::exit(1);
    }
    if let Err(err) = write_pair_index(&out_dir.join(PAIR_INDEX_ARTIFACT), &output.pair_runs) {
        eprintln!("error: failed to write pair index: {err}");
        process::exit(1);
    }
    if let Err(err) =
        write_pair_summary_csv(&out_dir.join(PAIR_SUMMARY_ARTIFACT), &output.pair_summaries)
    {
        eprintln!("error: failed to write pair summary: {err}");
        process::exit(1);
    }

    let artifact_names = collect_artifacts(
        &[
            README_FIRST_FILE.to_string(),
            SUMMARY_FILE.to_string(),
            SUMMARY_JSON_FILE.to_string(),
            SHARE_FILE.to_string(),
            COMMANDS_ARTIFACT.to_string(),
            MANIFEST_ARTIFACT.to_string(),
            MATRIX_INDEX_ARTIFACT.to_string(),
            PAIR_INDEX_ARTIFACT.to_string(),
            PAIR_SUMMARY_ARTIFACT.to_string(),
        ],
        &output.matrix_runs,
        &output.pair_runs,
        &output.pair_summaries,
        &output.superscalar_runs,
    );

    if let Err(err) = write_public_manifest(
        &out_dir.join(MANIFEST_ARTIFACT),
        &bundle_meta,
        &host,
        options.profile,
        &plan,
        &artifact_names,
    ) {
        eprintln!("error: failed to write manifest: {err}");
        process::exit(1);
    }
    if let Err(err) = write_public_summary_json(
        &out_dir.join(SUMMARY_JSON_FILE),
        &bundle_meta,
        &host,
        &now,
        options.profile,
        &plan,
        &artifact_names,
        &output,
    ) {
        eprintln!("error: failed to write summary.json: {err}");
        process::exit(1);
    }
    if let Err(err) = write_summary_txt(
        &out_dir.join(SUMMARY_FILE),
        &bundle_meta,
        &host,
        options.profile,
        &output.pair_summaries,
        &output.page_backing_summaries,
    ) {
        eprintln!("error: failed to write SUMMARY.txt: {err}");
        process::exit(1);
    }
    if let Err(err) = write_readme_first(
        &out_dir.join(README_FIRST_FILE),
        &bundle_meta,
        options.profile,
        &host,
    ) {
        eprintln!("error: failed to write README_FIRST.txt: {err}");
        process::exit(1);
    }
    if let Err(err) = write_share_file(&out_dir.join(SHARE_FILE), &bundle_meta) {
        eprintln!("error: failed to write SHARE_THIS_FILE.txt: {err}");
        process::exit(1);
    }

    let archive_path = out_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&bundle_meta.archive_name);
    if let Err(err) = create_share_archive(&out_dir, &bundle_meta, &archive_path) {
        eprintln!("error: failed to create share archive: {err}");
        process::exit(1);
    }

    println!("public beta capture complete");
    println!("bundle_id={}", bundle_meta.bundle_id);
    println!("result_dir={}", out_dir.display());
    println!("share_archive={}", archive_path.display());
    println!("matrix_rows={}", output.matrix_runs.len());
    println!("abba_pairs={}", output.pair_summaries.len());
    println!(
        "superscalar_isolated_runs={}",
        output.superscalar_runs.len()
    );
}

fn parse_args() -> Result<Options, String> {
    let mut profile = PublicBetaProfile::Standard;
    let mut out_dir = None::<PathBuf>;
    let mut accept_data_contract = false;
    let mut validate_only = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --profile".to_string())?;
                profile = PublicBetaProfile::parse(&value)?;
            }
            "--out-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --out-dir".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--accept-data-contract" => accept_data_contract = true,
            "--validate-only" => validate_only = true,
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Options {
        profile,
        out_dir,
        accept_data_contract,
        validate_only,
    })
}

fn print_usage() {
    let program = env::args()
        .next()
        .and_then(|value| {
            Path::new(&value)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| TOOL_ID.to_string());
    eprintln!(
        "Usage: {program} [--profile standard|full] [--out-dir PATH] [--accept-data-contract] [--validate-only]"
    );
}

fn ensure_public_host_scope(host: &HostIdentity) {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("error: {TOOL_ID} supports x86_64 only");
        process::exit(1);
    }
    if !matches!(host.os_class(), HostOsClass::Windows | HostOsClass::Linux) {
        eprintln!("error: {TOOL_ID} supports Windows x86_64 and Linux x86_64 only");
        process::exit(1);
    }
}

fn build_bundle_meta(
    host: &HostIdentity,
    now: &oxide_randomx::full_features_capture::NowStrings,
    profile: PublicBetaProfile,
) -> BundleMeta {
    let seed = format!(
        "{}:{}:{}:{}",
        BETA_RELEASE_ID,
        host.host_tag(),
        profile.as_str(),
        now.compact
    );
    let bundle_id = format!(
        "{}-{}-{:08x}",
        host.host_tag(),
        profile.as_str(),
        short_hash32(&seed)
    );
    BundleMeta {
        beta_release_id: BETA_RELEASE_ID.to_string(),
        archive_name: format!("oxide-randomx-beta-results-{bundle_id}.zip"),
        result_dir_name: format!("oxide-randomx-beta-results-{bundle_id}"),
        bundle_id,
    }
}

fn runtime_class_text(profile: PublicBetaProfile) -> &'static str {
    match profile {
        PublicBetaProfile::Standard => "moderate: roughly 45 to 75 minutes on many desktop hosts",
        PublicBetaProfile::Full => "long: often around 2 hours or more on the same host",
    }
}

fn print_startup_contract(
    bundle_meta: &BundleMeta,
    profile: PublicBetaProfile,
    plan: &oxide_randomx::full_features_capture::CapturePlan,
    host: &HostIdentity,
    out_dir: &Path,
) {
    println!("{TOOL_ID} starting");
    println!("beta_release_id={}", bundle_meta.beta_release_id);
    println!("bundle_id={}", bundle_meta.bundle_id);
    println!(
        "profile={} ({})",
        profile.as_str(),
        runtime_class_text(profile)
    );
    println!("host_tag={} os={}", host.host_tag(), host.os_name);
    println!("output_path={}", out_dir.display());
    println!("network=no automatic upload; no background network traffic; local capture only");
    println!("collect={}", COLLECT_DATA.join("; "));
    println!("do_not_collect={}", DO_NOT_COLLECT_DATA.join("; "));
    println!(
        "plan=page_profiles:{} matrix_rows:{} abba_pairs:{} superscalar_isolated:{}",
        plan.page_profiles.len(),
        plan.matrix_specs.len(),
        plan.pair_specs.len(),
        plan.superscalar_specs.len()
    );
}

fn prompt_for_contract_acceptance() -> Result<(), String> {
    println!("Type ACCEPT to continue with the public beta data contract.");
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read confirmation: {e}"))?;
    if line.trim() == "ACCEPT" {
        Ok(())
    } else {
        Err("data contract was not accepted".to_string())
    }
}

fn write_public_commands_header(
    path: &Path,
    bundle_meta: &BundleMeta,
    profile: PublicBetaProfile,
) -> Result<(), String> {
    let body = format!(
        "# {TOOL_ID}\nschema_version={PUBLIC_SCHEMA_VERSION}\nbeta_release_id={}\nbundle_id={}\nprofile={}\nrunner_binary={TOOL_ID}\nnetwork=no automatic upload; no background network traffic; local capture only\nrustc={RUSTC_VERSION}\n",
        bundle_meta.beta_release_id,
        bundle_meta.bundle_id,
        profile.as_str(),
    );
    write_artifact(path, body)
}

fn write_public_manifest(
    path: &Path,
    bundle_meta: &BundleMeta,
    host: &HostIdentity,
    profile: PublicBetaProfile,
    plan: &oxide_randomx::full_features_capture::CapturePlan,
    artifacts: &[String],
) -> Result<(), String> {
    let abba_page = plan
        .page_profiles
        .iter()
        .find(|profile| profile.abba_primary)
        .map(|profile| profile.key)
        .unwrap_or("n/a");
    let mut body = String::new();
    writeln!(&mut body, "schema_version={PUBLIC_SCHEMA_VERSION}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "beta_release_id={}", bundle_meta.beta_release_id)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "bundle_id={}", bundle_meta.bundle_id).map_err(|e| e.to_string())?;
    writeln!(&mut body, "profile={}", profile.as_str()).map_err(|e| e.to_string())?;
    writeln!(&mut body, "runtime_class={}", runtime_class_text(profile))
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "result_dir_name={}", bundle_meta.result_dir_name)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "share_archive_file={}", bundle_meta.archive_name)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={}", host.host_tag()).map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "stepping={}", host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_name={}", host.os_name).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_version={}", host.os_version).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_build_or_kernel={}", host.os_build_or_kernel)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "logical_threads={}", host.logical_threads).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "page_profiles={}",
        plan.page_profiles
            .iter()
            .map(|profile| profile.key)
            .collect::<Vec<_>>()
            .join(",")
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "abba_page_profile={abba_page}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "artifacts:").map_err(|e| e.to_string())?;
    for artifact in artifacts {
        writeln!(&mut body, "- {artifact}").map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn write_public_summary_json(
    path: &Path,
    bundle_meta: &BundleMeta,
    host: &HostIdentity,
    now: &oxide_randomx::full_features_capture::NowStrings,
    profile: PublicBetaProfile,
    plan: &oxide_randomx::full_features_capture::CapturePlan,
    artifacts: &[String],
    output: &oxide_randomx::full_features_capture::CaptureOutput,
) -> Result<(), String> {
    let summary = json!({
        "schema_version": PUBLIC_SCHEMA_VERSION,
        "tool": TOOL_ID,
        "beta_release_id": bundle_meta.beta_release_id,
        "bundle_id": bundle_meta.bundle_id,
        "created_at": {
            "timestamp": now.compact,
            "date": now.date,
            "iso": now.iso,
        },
        "profile": {
            "key": profile.as_str(),
            "display": profile.display(),
            "runtime_class": runtime_class_text(profile),
        },
        "network_behavior": {
            "automatic_upload": false,
            "background_network_traffic": false,
            "local_capture_only": true,
        },
        "data_contract": {
            "collect": COLLECT_DATA,
            "do_not_collect": DO_NOT_COLLECT_DATA,
        },
        "supported_scope": {
            "arch": "x86_64",
            "oses": ["windows", "linux"],
        },
        "host": {
            "host_tag": host.host_tag(),
            "vendor": host.vendor,
            "family": host.family,
            "model": host.model,
            "stepping": host.stepping,
            "cpu_model_string": host.cpu_model_string,
            "logical_threads": host.logical_threads,
            "os_name": host.os_name,
            "os_version": host.os_version,
            "os_build_or_kernel": host.os_build_or_kernel,
        },
        "plan": {
            "page_profiles": plan.page_profiles.iter().map(page_profile_json).collect::<Vec<_>>(),
            "matrix_rows": plan.matrix_specs.len(),
            "abba_pairs": plan.pair_specs.len(),
            "superscalar_isolated": plan.superscalar_specs.len(),
        },
        "artifacts": {
            "result_dir_name": bundle_meta.result_dir_name,
            "share_archive_file": bundle_meta.archive_name,
            "files": artifacts,
        },
        "page_backing_summary": output.page_backing_summaries.iter().map(page_backing_summary_json).collect::<Vec<_>>(),
        "matrix_rows": output.matrix_runs.iter().map(run_json_value).collect::<Vec<_>>(),
        "pair_runs": output.pair_runs.iter().map(run_json_value).collect::<Vec<_>>(),
        "pair_summaries": output.pair_summaries.iter().map(oxide_randomx::full_features_capture::pair_summary_json).collect::<Vec<_>>(),
        "superscalar_isolated": output.superscalar_runs.iter().map(superscalar_json_value).collect::<Vec<_>>(),
    });
    let body = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    write_artifact(path, body)
}

fn write_summary_txt(
    path: &Path,
    bundle_meta: &BundleMeta,
    host: &HostIdentity,
    profile: PublicBetaProfile,
    pair_summaries: &[PairSummary],
    page_backing_summaries: &[PageBackingSummary],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "{TOOL_ID} summary").map_err(|e| e.to_string())?;
    writeln!(&mut body, "beta_release_id={}", bundle_meta.beta_release_id)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "bundle_id={}", bundle_meta.bundle_id).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "profile={} ({})",
        profile.as_str(),
        runtime_class_text(profile)
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={}", host.host_tag()).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "cpu={} family/model={}/{} threads={}",
        host.cpu_model_string, host.family, host.model, host.logical_threads
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "os={} {} {}",
        host.os_name, host.os_version, host.os_build_or_kernel
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "Page backing summary:").map_err(|e| e.to_string())?;
    for summary in page_backing_summaries {
        writeln!(
            &mut body,
            "- {}: dataset_lp={} dataset_1g={} scratchpad_lp={} scratchpad_1g={}",
            summary.page_profile,
            summary.dataset_large_pages.status.as_str(),
            summary.dataset_1gb_pages.status.as_str(),
            summary.scratchpad_large_pages.status.as_str(),
            summary.scratchpad_1gb_pages.status.as_str()
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "Largest pair deltas:").map_err(|e| e.to_string())?;
    let mut top_pairs = pair_summaries.to_vec();
    top_pairs.sort_by(|lhs, rhs| {
        rhs.delta_pct_candidate_vs_baseline
            .abs()
            .partial_cmp(&lhs.delta_pct_candidate_vs_baseline.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for summary in top_pairs.iter().take(6) {
        writeln!(
            &mut body,
            "- {} / {} / {}: {:+.3}% ({})",
            summary.family,
            summary.mode,
            summary.config,
            summary.delta_pct_candidate_vs_baseline,
            summary.signal_classification
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "Share archive: {}", bundle_meta.archive_name)
        .map_err(|e| e.to_string())?;
    write_artifact(path, body)
}

fn write_readme_first(
    path: &Path,
    bundle_meta: &BundleMeta,
    profile: PublicBetaProfile,
    host: &HostIdentity,
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "{TOOL_ID} public beta results").map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "This folder was created by the public beta capture runner."
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "No automatic upload happened. No background network traffic was used. Everything here was captured locally."
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "Profile: {} ({})",
        profile.as_str(),
        runtime_class_text(profile)
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "Host: {} / {} family-model {}/{}",
        host.cpu_model_string, host.vendor, host.family, host.model
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "Beta release ID: {}",
        bundle_meta.beta_release_id
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "Bundle ID: {}", bundle_meta.bundle_id).map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "Send the file named `{}` back to the project contact or issue thread.",
        bundle_meta.archive_name
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "Top-level files:").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- `{SUMMARY_FILE}`: human-readable result summary"
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- `{SUMMARY_JSON_FILE}`: machine-readable result summary"
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- `meta/`: sanitized raw indexes and command log"
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- `matrix/`, `abba/`, `superscalar/`: raw capture tree"
    )
    .map_err(|e| e.to_string())?;
    write_artifact(path, body)
}

fn write_share_file(path: &Path, bundle_meta: &BundleMeta) -> Result<(), String> {
    let body = format!(
        "Send this file back: {}\nNo manual zipping is required.\n",
        bundle_meta.archive_name
    );
    write_artifact(path, body)
}

fn create_share_archive(
    out_dir: &Path,
    bundle_meta: &BundleMeta,
    archive_path: &Path,
) -> Result<(), String> {
    let file =
        fs::File::create(archive_path).map_err(|e| format!("{}: {e}", archive_path.display()))?;
    let mut zip = ZipWriter::new(file);
    let file_options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    let root_name = Path::new(&bundle_meta.result_dir_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("oxide-randomx-beta-results");

    let files = collect_files_sorted(out_dir)?;
    for file_path in files {
        let rel = file_path
            .strip_prefix(out_dir)
            .map_err(|e| format!("{}: {e}", file_path.display()))?;
        let zip_name = format!("{}/{}", root_name, rel.to_string_lossy().replace('\\', "/"));
        zip.start_file(zip_name, file_options)
            .map_err(|e| e.to_string())?;
        let mut input =
            fs::File::open(&file_path).map_err(|e| format!("{}: {e}", file_path.display()))?;
        let mut buffer = Vec::new();
        input
            .read_to_end(&mut buffer)
            .map_err(|e| format!("{}: {e}", file_path.display()))?;
        zip.write_all(&buffer).map_err(|e| e.to_string())?;
    }
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

fn collect_files_sorted(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    collect_files_recursive(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_recursive(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(root)
        .map_err(|e| format!("{}: {e}", root.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", root.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_host() -> HostIdentity {
        HostIdentity {
            bucket: oxide_randomx::full_features_capture::HostBucket::Intel,
            vendor: "GenuineIntel".to_string(),
            family: 6,
            model: 45,
            stepping: 0,
            cpu_model_string: "Intel test cpu".to_string(),
            os_name: "Ubuntu 24.04".to_string(),
            os_version: "24.04".to_string(),
            os_build_or_kernel: "Linux 6.8".to_string(),
            logical_threads: 32,
        }
    }

    #[test]
    fn bundle_id_is_deterministic() {
        let host = test_host();
        let now = oxide_randomx::full_features_capture::NowStrings {
            compact: "20260321_150000".to_string(),
            date: "2026-03-21".to_string(),
            iso: "2026-03-21T15:00:00-04:00".to_string(),
        };

        let a = build_bundle_meta(&host, &now, PublicBetaProfile::Standard);
        let b = build_bundle_meta(&host, &now, PublicBetaProfile::Standard);

        assert_eq!(a.bundle_id, b.bundle_id);
        assert!(a.archive_name.ends_with(".zip"));
    }

    #[test]
    fn summary_text_uses_archive_name_not_path() {
        let bundle = BundleMeta {
            beta_release_id: "beta-2026-03".to_string(),
            bundle_id: "intel-test".to_string(),
            result_dir_name: "oxide-randomx-beta-results-intel-test".to_string(),
            archive_name: "oxide-randomx-beta-results-intel-test.zip".to_string(),
        };
        let temp_dir = std::env::temp_dir().join("oxide_randomx_beta_summary_text");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        write_share_file(&temp_dir.join(SHARE_FILE), &bundle).unwrap();
        let body = fs::read_to_string(temp_dir.join(SHARE_FILE)).unwrap();
        assert!(body.contains(&bundle.archive_name));
        assert!(!body.contains(temp_dir.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn summary_json_uses_public_release_metadata() {
        let host = test_host();
        let bundle = BundleMeta {
            beta_release_id: "beta-2026-03".to_string(),
            bundle_id: "intel-test".to_string(),
            result_dir_name: "oxide-randomx-beta-results-intel-test".to_string(),
            archive_name: "oxide-randomx-beta-results-intel-test.zip".to_string(),
        };
        let now = oxide_randomx::full_features_capture::NowStrings {
            compact: "20260321_150000".to_string(),
            date: "2026-03-21".to_string(),
            iso: "2026-03-21T15:00:00-04:00".to_string(),
        };
        let temp_dir = std::env::temp_dir().join("oxide_randomx_beta_summary_json");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        write_public_summary_json(
            &temp_dir.join(SUMMARY_JSON_FILE),
            &bundle,
            &host,
            &now,
            PublicBetaProfile::Standard,
            &public_beta_plan(PublicBetaProfile::Standard, HostOsClass::Linux),
            &[SUMMARY_JSON_FILE.to_string()],
            &oxide_randomx::full_features_capture::CaptureOutput {
                matrix_runs: Vec::new(),
                pair_runs: Vec::new(),
                pair_summaries: Vec::new(),
                superscalar_runs: Vec::new(),
                page_backing_summaries: Vec::new(),
            },
        )
        .unwrap();
        let body = fs::read_to_string(temp_dir.join(SUMMARY_JSON_FILE)).unwrap();
        assert!(body.contains("\"beta_release_id\": \"beta-2026-03\""));
        assert!(!body.contains("\"git_sha\""));
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
