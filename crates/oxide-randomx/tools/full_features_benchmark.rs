use oxide_randomx::full_features_capture::{
    canonical_page_profiles, collect_artifacts, detect_host_identity, ensure_compiled_features,
    execute_capture_plan, internal_full_plan, now_strings, short_hash32, write_artifact,
    CaptureContext, CaptureOptions, CaptureSurface, CapturedRun, HostIdentity, HostOsClass,
    PageBackingSummary, PageProfile, PageProfileRole, PairSummary, COMMANDS_ARTIFACT,
    DEFAULT_PERF_ITERS, DEFAULT_PERF_WARMUP, MANIFEST_ARTIFACT, MATRIX_INDEX_ARTIFACT,
    PAIR_INDEX_ARTIFACT, PAIR_SUMMARY_ARTIFACT,
};
use serde_json::{json, Map, Value};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const TOOL_ID: &str = "full_features_benchmark";
const CAPTURE_DIR_PREFIX: &str = "ff";
const PROVENANCE_ARTIFACT: &str = "meta/provenance.txt";
const SUMMARY_ARTIFACT: &str = "meta/summary.json";
const OVERVIEW_ARTIFACT: &str = "meta/overview.md";
const AUTHORITY_WORKFLOW_VERSION: &str = "v10";

const GIT_SHA: &str = env!("OXIDE_RANDOMX_GIT_SHA");
const GIT_SHA_SHORT: &str = env!("OXIDE_RANDOMX_GIT_SHA_SHORT");
const GIT_DIRTY: &str = env!("OXIDE_RANDOMX_GIT_DIRTY");
const RUSTC_VERSION: &str = env!("OXIDE_RANDOMX_RUSTC_VERSION");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceTier {
    Authority,
    Supporting,
    Exploratory,
}

impl EvidenceTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Supporting => "supporting",
            Self::Exploratory => "exploratory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RerunExpectation {
    SingleCaptureSufficient,
    RepeatedSameShaRequired,
}

impl RerunExpectation {
    fn as_str(self) -> &'static str {
        match self {
            Self::SingleCaptureSufficient => "single_capture_sufficient",
            Self::RepeatedSameShaRequired => "repeated_same_sha_required",
        }
    }
}

#[derive(Debug)]
struct Options {
    out_dir: Option<PathBuf>,
    threads: usize,
    perf_iters: u64,
    perf_warmup: u64,
    validate_only: bool,
}

#[derive(Debug)]
struct AuthorityWorkflow {
    host_class_id: String,
    host_inventory_label: String,
    canonical_host_class: bool,
    host_inventory_tier: EvidenceTier,
    host_inventory_reason: String,
    capture_evidence_tier: EvidenceTier,
    capture_evidence_reason: String,
    clean_provenance: bool,
    clean_provenance_notes: Vec<String>,
    rerun_expectation: RerunExpectation,
    rerun_reason: String,
    rerun_group_id: String,
}

#[derive(Debug)]
struct Context {
    options: Options,
    now: oxide_randomx::full_features_capture::NowStrings,
    host: HostIdentity,
    host_tag: String,
    out_dir: PathBuf,
    commands_path: PathBuf,
    page_profiles: Vec<PageProfile>,
    authority: AuthorityWorkflow,
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
    let host_tag = host.host_tag();

    if options.validate_only {
        println!(
            "validate-only: binary OK for {} ({})",
            host_tag, host.os_name
        );
        println!(
            "current_exe={}",
            env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("unknown"))
                .display()
        );
        println!(
            "required_features={}",
            oxide_randomx::full_features_capture::REQUIRED_FEATURES
        );
        return;
    }

    let out_dir = options.out_dir.clone().unwrap_or_else(|| {
        PathBuf::from("perf_results")
            .join(host.bucket.dir_name())
            .join(format!("{CAPTURE_DIR_PREFIX}_{}_{}", host_tag, now.compact))
    });
    if let Err(err) = fs::create_dir_all(&out_dir) {
        eprintln!(
            "error: failed to create output directory {}: {err}",
            out_dir.display()
        );
        process::exit(1);
    }

    let page_profiles = canonical_page_profiles(host.os_class());
    let authority = build_authority_workflow(&host, &options, &page_profiles);
    let ctx = Context {
        options,
        now,
        host,
        host_tag,
        commands_path: out_dir.join(COMMANDS_ARTIFACT),
        out_dir,
        page_profiles,
        authority,
    };

    if let Err(err) = write_commands_header(&ctx) {
        eprintln!("error: failed to initialize command log: {err}");
        process::exit(1);
    }

    let plan = internal_full_plan(ctx.host.os_class());
    print_capture_header(&ctx, &plan);

    let shared_ctx = CaptureContext {
        options: CaptureOptions {
            threads: ctx.options.threads,
            perf_iters: ctx.options.perf_iters,
            perf_warmup: ctx.options.perf_warmup,
        },
        now: ctx.now.clone(),
        host: ctx.host.clone(),
        host_tag: ctx.host_tag.clone(),
        out_dir: ctx.out_dir.clone(),
        commands_path: ctx.commands_path.clone(),
        surface: CaptureSurface::Internal,
    };

    let output = match execute_capture_plan(&shared_ctx, &plan) {
        Ok(output) => output,
        Err(err) => {
            eprintln!("error: capture failed: {err}");
            process::exit(1);
        }
    };

    if let Err(err) =
        rewrite_compare_txt_with_authority(&ctx, &output.pair_runs, &output.pair_summaries)
    {
        eprintln!("error: failed to write authority compare artifacts: {err}");
        process::exit(1);
    }

    let abba_page = plan
        .page_profiles
        .iter()
        .copied()
        .find(|profile| profile.abba_primary)
        .unwrap_or_else(|| plan.page_profiles[0]);

    if let Err(err) = write_provenance(
        &ctx.out_dir.join(PROVENANCE_ARTIFACT),
        &ctx,
        abba_page,
        &output.page_backing_summaries,
    ) {
        eprintln!("error: failed to write provenance: {err}");
        process::exit(1);
    }
    if let Err(err) = write_matrix_index_internal(
        &ctx.out_dir.join(MATRIX_INDEX_ARTIFACT),
        &ctx,
        &output.matrix_runs,
    ) {
        eprintln!("error: failed to write matrix index: {err}");
        process::exit(1);
    }
    if let Err(err) = write_matrix_index_internal(
        &ctx.out_dir.join(PAIR_INDEX_ARTIFACT),
        &ctx,
        &output.pair_runs,
    ) {
        eprintln!("error: failed to write pair index: {err}");
        process::exit(1);
    }
    if let Err(err) = write_pair_summary_csv_internal(
        &ctx.out_dir.join(PAIR_SUMMARY_ARTIFACT),
        &ctx,
        &output.pair_summaries,
    ) {
        eprintln!("error: failed to write pair summary: {err}");
        process::exit(1);
    }

    let artifact_names = collect_artifacts(
        &[
            COMMANDS_ARTIFACT.to_string(),
            PROVENANCE_ARTIFACT.to_string(),
            MANIFEST_ARTIFACT.to_string(),
            MATRIX_INDEX_ARTIFACT.to_string(),
            PAIR_INDEX_ARTIFACT.to_string(),
            PAIR_SUMMARY_ARTIFACT.to_string(),
            SUMMARY_ARTIFACT.to_string(),
            OVERVIEW_ARTIFACT.to_string(),
        ],
        &output.matrix_runs,
        &output.pair_runs,
        &output.pair_summaries,
        &output.superscalar_runs,
    );

    if let Err(err) = write_manifest(
        &ctx.out_dir.join(MANIFEST_ARTIFACT),
        &ctx,
        abba_page,
        &artifact_names,
    ) {
        eprintln!("error: failed to write manifest: {err}");
        process::exit(1);
    }
    if let Err(err) = write_summary_json(
        &ctx.out_dir.join(SUMMARY_ARTIFACT),
        &ctx,
        abba_page,
        &artifact_names,
        &output,
    ) {
        eprintln!("error: failed to write summary JSON: {err}");
        process::exit(1);
    }
    if let Err(err) = write_overview_markdown(
        &ctx.out_dir.join(OVERVIEW_ARTIFACT),
        &ctx,
        abba_page,
        &artifact_names,
        &output,
    ) {
        eprintln!("error: failed to write overview markdown: {err}");
        process::exit(1);
    }

    println!("full features benchmark complete");
    println!("artifact_dir={}", ctx.out_dir.display());
    println!("host_tag={}", ctx.host_tag);
    println!("matrix_rows={}", output.matrix_runs.len());
    println!("abba_pairs={}", output.pair_summaries.len());
    println!(
        "superscalar_isolated_runs={}",
        output.superscalar_runs.len()
    );
}

fn parse_args() -> Result<Options, String> {
    let mut out_dir = None::<PathBuf>;
    let mut threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let mut perf_iters = DEFAULT_PERF_ITERS;
    let mut perf_warmup = DEFAULT_PERF_WARMUP;
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
        "Usage: {program} [--out-dir PATH] [--threads N] [--perf-iters N] [--perf-warmup N] [--validate-only]"
    );
}

fn print_capture_header(ctx: &Context, plan: &oxide_randomx::full_features_capture::CapturePlan) {
    println!("full features benchmark starting");
    println!("host_tag={}", ctx.host_tag);
    println!("host_class_id={}", ctx.authority.host_class_id);
    println!(
        "host={} vendor={} family={} model={} stepping={}",
        ctx.host.cpu_model_string,
        ctx.host.vendor,
        ctx.host.family,
        ctx.host.model,
        ctx.host.stepping
    );
    println!(
        "os={} version={} build_or_kernel={}",
        ctx.host.os_name, ctx.host.os_version, ctx.host.os_build_or_kernel
    );
    println!(
        "perf_options iters={} warmup={} threads={}",
        ctx.options.perf_iters, ctx.options.perf_warmup, ctx.options.threads
    );
    println!(
        "authority_workflow={} tier={} clean_provenance={} rerun_expectation={}",
        AUTHORITY_WORKFLOW_VERSION,
        ctx.authority.capture_evidence_tier.as_str(),
        ctx.authority.clean_provenance,
        ctx.authority.rerun_expectation.as_str()
    );
    println!("rerun_group_id={}", ctx.authority.rerun_group_id);
    let page_desc = plan
        .page_profiles
        .iter()
        .map(|profile| profile.display)
        .collect::<Vec<_>>()
        .join(", ");
    println!("page_profiles={page_desc}");
    println!(
        "abba_page_profile={}",
        plan.page_profiles
            .iter()
            .find(|profile| profile.abba_primary)
            .map(|profile| profile.display)
            .unwrap_or("n/a")
    );
    println!("artifact_dir={}", ctx.out_dir.display());
}

fn build_authority_workflow(
    host: &HostIdentity,
    options: &Options,
    page_profiles: &[PageProfile],
) -> AuthorityWorkflow {
    let host_tag = host.host_tag();
    let host_class_id = format!("{}_{}", host_tag, host.os_class().as_str());
    let (canonical_host_class, host_inventory_label, host_inventory_tier, host_inventory_reason, rerun_expectation, rerun_reason) =
        match (host.vendor.as_str(), host.family, host.model, host.os_class()) {
            ("AuthenticAMD", 23, 113, HostOsClass::Windows) => (
                true,
                "AMD R5 3600 / Win11".to_string(),
                EvidenceTier::Supporting,
                "canonical v10 host class, but known rerun instability keeps captures in the supporting tier until repeated same-SHA behavior is reviewed".to_string(),
                RerunExpectation::RepeatedSameShaRequired,
                "same-SHA repeated runs are required because the 2026-03-18 and 2026-03-20 captures changed realized large-page backing and integrated superscalar behavior".to_string(),
            ),
            ("AuthenticAMD", 23, 8, HostOsClass::Windows) => (
                true,
                "AMD R5 2600 / Win11".to_string(),
                EvidenceTier::Authority,
                "canonical v10 host class for Windows AMD Zen+ evidence".to_string(),
                RerunExpectation::SingleCaptureSufficient,
                "single clean capture is normally sufficient for this host class".to_string(),
            ),
            ("AuthenticAMD", 23, 8, HostOsClass::Linux) => (
                true,
                "AMD R5 2600 / Ubuntu".to_string(),
                EvidenceTier::Authority,
                "canonical v10 host class for Linux AMD Zen+ evidence".to_string(),
                RerunExpectation::SingleCaptureSufficient,
                "single clean capture is normally sufficient for this host class".to_string(),
            ),
            ("GenuineIntel", 6, 45, HostOsClass::Linux) => (
                true,
                "Intel Dual-Xeon / Ubuntu".to_string(),
                EvidenceTier::Authority,
                "canonical v10 host class for dual-socket Intel Linux evidence".to_string(),
                RerunExpectation::SingleCaptureSufficient,
                "single clean capture is normally sufficient for this host class".to_string(),
            ),
            ("GenuineIntel", 6, 58, HostOsClass::Linux) => (
                true,
                "Intel i5 / Ubuntu".to_string(),
                EvidenceTier::Authority,
                "canonical v10 host class for small Intel Linux evidence".to_string(),
                RerunExpectation::SingleCaptureSufficient,
                "single clean capture is normally sufficient for this host class".to_string(),
            ),
            _ => (
                false,
                format!(
                    "{} family/model {}/{} ({})",
                    host.vendor, host.family, host.model, host.os_name
                ),
                EvidenceTier::Exploratory,
                "outside the documented v10 canonical host inventory; use for exploratory evidence only".to_string(),
                RerunExpectation::SingleCaptureSufficient,
                "non-canonical hosts are exploratory until the host inventory is intentionally extended".to_string(),
            ),
        };

    let mut clean_provenance_notes = Vec::new();
    if GIT_DIRTY != "false" {
        clean_provenance_notes.push("git tree is dirty".to_string());
    }
    if options.perf_iters != DEFAULT_PERF_ITERS {
        clean_provenance_notes.push(format!(
            "perf_iters={} differs from canonical {}",
            options.perf_iters, DEFAULT_PERF_ITERS
        ));
    }
    if options.perf_warmup != DEFAULT_PERF_WARMUP {
        clean_provenance_notes.push(format!(
            "perf_warmup={} differs from canonical {}",
            options.perf_warmup, DEFAULT_PERF_WARMUP
        ));
    }
    if options.threads != host.logical_threads {
        clean_provenance_notes.push(format!(
            "threads={} differs from detected logical_threads={}",
            options.threads, host.logical_threads
        ));
    }
    let clean_provenance = clean_provenance_notes.is_empty();
    let capture_evidence_tier = if clean_provenance {
        host_inventory_tier
    } else {
        EvidenceTier::Exploratory
    };
    let capture_evidence_reason = if clean_provenance {
        host_inventory_reason.clone()
    } else {
        format!(
            "exploratory because clean provenance failed: {}",
            clean_provenance_notes.join("; ")
        )
    };

    let page_profile_key_suffix = page_profiles
        .iter()
        .map(|profile| profile.key)
        .collect::<Vec<_>>()
        .join("-");
    let rerun_group_id = format!(
        "{}__{}__r{:08x}__t{}__i{}w{}__{}",
        host_class_id,
        GIT_SHA_SHORT,
        short_hash32(RUSTC_VERSION),
        options.threads,
        options.perf_iters,
        options.perf_warmup,
        page_profile_key_suffix
    );

    AuthorityWorkflow {
        host_class_id,
        host_inventory_label,
        canonical_host_class,
        host_inventory_tier,
        host_inventory_reason,
        capture_evidence_tier,
        capture_evidence_reason,
        clean_provenance,
        clean_provenance_notes,
        rerun_expectation,
        rerun_reason,
        rerun_group_id,
    }
}

fn page_profile_evidence_tier(capture_tier: EvidenceTier, role: PageProfileRole) -> EvidenceTier {
    match capture_tier {
        EvidenceTier::Exploratory => EvidenceTier::Exploratory,
        EvidenceTier::Supporting => EvidenceTier::Supporting,
        EvidenceTier::Authority => match role {
            PageProfileRole::AuthorityPrimary => EvidenceTier::Authority,
            PageProfileRole::SupportingControl | PageProfileRole::SupportingSemantics => {
                EvidenceTier::Supporting
            }
        },
    }
}

fn page_profile_for_key<'a>(ctx: &'a Context, key: &str) -> &'a PageProfile {
    ctx.page_profiles
        .iter()
        .find(|profile| profile.key == key)
        .unwrap_or_else(|| panic!("missing page profile for key {key}"))
}

fn write_commands_header(ctx: &Context) -> Result<(), String> {
    let current_exe = env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("unknown"))
        .display()
        .to_string();
    let body = format!(
        "# {TOOL_ID}\nauthority_workflow={AUTHORITY_WORKFLOW_VERSION}\nhost_tag={}\nhost_class_id={}\nrunner_binary={current_exe}\ncapture_evidence_tier={}\nrerun_group_id={}\ngit_sha={GIT_SHA}\ngit_sha_short={GIT_SHA_SHORT}\nrustc={RUSTC_VERSION}\n",
        ctx.host_tag,
        ctx.authority.host_class_id,
        ctx.authority.capture_evidence_tier.as_str(),
        ctx.authority.rerun_group_id
    );
    write_artifact(&ctx.commands_path, body)
}

fn rewrite_compare_txt_with_authority(
    ctx: &Context,
    pair_runs: &[CapturedRun],
    pair_summaries: &[PairSummary],
) -> Result<(), String> {
    for (summary, runs) in pair_summaries.iter().zip(pair_runs.chunks_exact(4)) {
        let run_refs = [&runs[0], &runs[1], &runs[2], &runs[3]];
        write_compare_txt_internal(
            &ctx.out_dir.join(&summary.artifacts.compare_name),
            ctx,
            summary,
            run_refs,
        )?;
    }
    Ok(())
}

fn write_provenance(
    path: &Path,
    ctx: &Context,
    abba_page: PageProfile,
    page_backing_summaries: &[PageBackingSummary],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "timestamp={}", ctx.now.iso).map_err(|e| e.to_string())?;
    writeln!(&mut body, "authority_workflow={AUTHORITY_WORKFLOW_VERSION}")
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={}", ctx.host_tag).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_class_id={}", ctx.authority.host_class_id)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "host_inventory_label={}",
        ctx.authority.host_inventory_label
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "canonical_host_class={}",
        ctx.authority.canonical_host_class
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "host_inventory_tier={}",
        ctx.authority.host_inventory_tier.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "host_inventory_reason={}",
        ctx.authority.host_inventory_reason
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "capture_evidence_tier={}",
        ctx.authority.capture_evidence_tier.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "capture_evidence_reason={}",
        ctx.authority.capture_evidence_reason
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "clean_provenance={}",
        ctx.authority.clean_provenance
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "clean_provenance_notes={}",
        if ctx.authority.clean_provenance_notes.is_empty() {
            "none".to_string()
        } else {
            ctx.authority.clean_provenance_notes.join("; ")
        }
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "rerun_expectation={}",
        ctx.authority.rerun_expectation.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "rerun_reason={}", ctx.authority.rerun_reason)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "rerun_group_id={}", ctx.authority.rerun_group_id)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", ctx.host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", ctx.host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", ctx.host.model).map_err(|e| e.to_string())?;
    writeln!(&mut body, "stepping={}", ctx.host.stepping).map_err(|e| e.to_string())?;
    writeln!(&mut body, "cpu_model_string={}", ctx.host.cpu_model_string)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_name={}", ctx.host.os_name).map_err(|e| e.to_string())?;
    writeln!(&mut body, "os_version={}", ctx.host.os_version).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "os_build_or_kernel={}",
        ctx.host.os_build_or_kernel
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "logical_threads={}", ctx.host.logical_threads)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "threads={}", ctx.options.threads).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_iters={}", ctx.options.perf_iters).map_err(|e| e.to_string())?;
    writeln!(&mut body, "perf_warmup={}", ctx.options.perf_warmup).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "page_profiles={}",
        ctx.page_profiles
            .iter()
            .map(|profile| profile.key)
            .collect::<Vec<_>>()
            .join(",")
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "abba_page_profile={}", abba_page.key).map_err(|e| e.to_string())?;
    for profile in &ctx.page_profiles {
        let evidence_tier =
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, profile.role);
        writeln!(
            &mut body,
            "page_profile_role.{}={}",
            profile.key,
            profile.role.as_str()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            &mut body,
            "page_profile_evidence_tier.{}={}",
            profile.key,
            evidence_tier.as_str()
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body, "git_sha={GIT_SHA}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha_short={GIT_SHA_SHORT}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_dirty={GIT_DIRTY}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "rustc={RUSTC_VERSION}").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "compiled_features={}",
        oxide_randomx::full_features_capture::REQUIRED_FEATURES
    )
    .map_err(|e| e.to_string())?;
    for summary in page_backing_summaries {
        writeln!(
            &mut body,
            "page_backing.{}.dataset_large_pages_status={}",
            summary.page_profile,
            summary.dataset_large_pages.status.as_str()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            &mut body,
            "page_backing.{}.dataset_1gb_pages_status={}",
            summary.page_profile,
            summary.dataset_1gb_pages.status.as_str()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            &mut body,
            "page_backing.{}.scratchpad_large_pages_status={}",
            summary.page_profile,
            summary.scratchpad_large_pages.status.as_str()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            &mut body,
            "page_backing.{}.scratchpad_1gb_pages_status={}",
            summary.page_profile,
            summary.scratchpad_1gb_pages.status.as_str()
        )
        .map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn write_manifest(
    path: &Path,
    ctx: &Context,
    abba_page: PageProfile,
    artifacts: &[String],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "authority_workflow={AUTHORITY_WORKFLOW_VERSION}")
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "capture_timestamp={}", ctx.now.compact).map_err(|e| e.to_string())?;
    writeln!(&mut body, "capture_timestamp_iso={}", ctx.now.iso).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_tag={}", ctx.host_tag).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_class_id={}", ctx.authority.host_class_id)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "host_inventory_label={}",
        ctx.authority.host_inventory_label
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "capture_evidence_tier={}",
        ctx.authority.capture_evidence_tier.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "clean_provenance={}",
        ctx.authority.clean_provenance
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "rerun_group_id={}", ctx.authority.rerun_group_id)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "vendor={}", ctx.host.vendor).map_err(|e| e.to_string())?;
    writeln!(&mut body, "family={}", ctx.host.family).map_err(|e| e.to_string())?;
    writeln!(&mut body, "model={}", ctx.host.model).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "page_profiles={}",
        ctx.page_profiles
            .iter()
            .map(|profile| profile.key)
            .collect::<Vec<_>>()
            .join(",")
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "abba_page_profile={}", abba_page.key).map_err(|e| e.to_string())?;
    writeln!(&mut body, "artifact_dir={}", ctx.out_dir.display()).map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha={GIT_SHA}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_sha_short={GIT_SHA_SHORT}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "git_dirty={GIT_DIRTY}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "rustc={RUSTC_VERSION}").map_err(|e| e.to_string())?;
    writeln!(&mut body, "artifacts:").map_err(|e| e.to_string())?;
    for artifact in artifacts {
        writeln!(&mut body, "- {artifact}").map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn internal_matrix_index_fields() -> &'static [&'static str] {
    &[
        "git_sha",
        "git_sha_short",
        "git_dirty",
        "features",
        "cpu",
        "cores",
        "rustc",
        "ns_per_hash",
        "hashes_per_sec",
        "dataset_init_ns",
        "jit_requested",
        "jit_active",
        "jit_fast_regs",
        "large_pages_requested",
        "large_pages_1gb_requested",
        "large_pages_dataset",
        "large_pages_1gb_dataset",
        "large_pages_scratchpad",
        "large_pages_1gb_scratchpad",
        "prepare_iteration_ns",
        "execute_program_ns_interpreter",
        "finish_iteration_ns",
        "prefetch_distance",
        "prefetch_auto_tune",
    ]
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn write_matrix_index_internal(
    path: &Path,
    ctx: &Context,
    runs: &[CapturedRun],
) -> Result<(), String> {
    let selected = internal_matrix_index_fields();
    let header = vec![
        "capture_kind".to_string(),
        "feature_family".to_string(),
        "label".to_string(),
        "mode".to_string(),
        "config".to_string(),
        "page_profile".to_string(),
        "host_class_id".to_string(),
        "capture_evidence_tier".to_string(),
        "page_profile_role".to_string(),
        "page_profile_evidence_tier".to_string(),
        "rerun_group_id".to_string(),
        "runtime_profile".to_string(),
        "runtime_jit_flags".to_string(),
        "csv_artifact".to_string(),
        "json_artifact".to_string(),
        "summary_line".to_string(),
        "elapsed_ms".to_string(),
    ]
    .into_iter()
    .chain(selected.iter().map(|field| field.to_string()))
    .collect::<Vec<_>>();
    let mut body = String::new();
    writeln!(&mut body, "{}", header.join(",")).map_err(|e| e.to_string())?;
    for run in runs {
        let role = page_profile_for_key(ctx, &run.page_profile).role;
        let mut values = vec![
            csv_escape(run.capture_kind),
            csv_escape(run.feature_family),
            csv_escape(&run.label),
            csv_escape(&run.mode),
            csv_escape(&run.config),
            csv_escape(&run.page_profile),
            csv_escape(&ctx.authority.host_class_id),
            csv_escape(ctx.authority.capture_evidence_tier.as_str()),
            csv_escape(&run.page_profile_role),
            csv_escape(
                page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role).as_str(),
            ),
            csv_escape(&ctx.authority.rerun_group_id),
            csv_escape(&run.runtime_profile),
            csv_escape(&run.runtime_jit_flags),
            csv_escape(&run.csv_name),
            csv_escape(&run.json_name),
            csv_escape(&run.summary_line),
            format!("{:.3}", run.elapsed.as_secs_f64() * 1000.0),
        ];
        for column in selected {
            values.push(csv_escape(
                run.csv_fields
                    .get(*column)
                    .map(String::as_str)
                    .unwrap_or(""),
            ));
        }
        writeln!(&mut body, "{}", values.join(",")).map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn write_pair_summary_csv_internal(
    path: &Path,
    ctx: &Context,
    summaries: &[PairSummary],
) -> Result<(), String> {
    let mut body = String::from(
        "pair_label,family,config,mode,page_profile,host_class_id,evidence_tier,capture_clean_provenance,rerun_group_id,page_profile_role,baseline_label,candidate_label,baseline_dataset_large_pages_status,baseline_dataset_1gb_pages_status,baseline_scratchpad_large_pages_status,baseline_scratchpad_1gb_pages_status,candidate_dataset_large_pages_status,candidate_dataset_1gb_pages_status,candidate_scratchpad_large_pages_status,candidate_scratchpad_1gb_pages_status,baseline_mean_ns_per_hash,candidate_mean_ns_per_hash,delta_pct_candidate_vs_baseline,pair_delta_a1_b1_pct,pair_delta_a2_b2_pct,baseline_drift_pct,candidate_drift_pct,stage_delta_prepare_pct,stage_delta_execute_pct,stage_delta_finish_pct,signal_classification,signal_threshold_pct,signal_noise_floor_pct,signal_pair_spread_pct,signal_direction_consistent,baseline_combined,candidate_combined,pair_matrix,compare_txt\n",
    );
    for summary in summaries {
        let role = page_profile_for_key(ctx, &summary.page_profile).role;
        let evidence_tier =
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role).as_str();
        writeln!(
            &mut body,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{},{:.6},{:.6},{:.6},{},{},{},{},{}",
            summary.pair_label,
            summary.family,
            summary.config,
            summary.mode,
            summary.page_profile,
            ctx.authority.host_class_id,
            evidence_tier,
            ctx.authority.clean_provenance,
            ctx.authority.rerun_group_id,
            summary.page_profile_role,
            summary.baseline_label,
            summary.candidate_label,
            summary.baseline_dataset_large_pages_status,
            summary.baseline_dataset_1gb_pages_status,
            summary.baseline_scratchpad_large_pages_status,
            summary.baseline_scratchpad_1gb_pages_status,
            summary.candidate_dataset_large_pages_status,
            summary.candidate_dataset_1gb_pages_status,
            summary.candidate_scratchpad_large_pages_status,
            summary.candidate_scratchpad_1gb_pages_status,
            summary.baseline_mean_ns_per_hash,
            summary.candidate_mean_ns_per_hash,
            summary.delta_pct_candidate_vs_baseline,
            summary.pair_delta_a1_b1_pct,
            summary.pair_delta_a2_b2_pct,
            summary.baseline_drift_pct,
            summary.candidate_drift_pct,
            summary.stage_delta_prepare_pct,
            summary.stage_delta_execute_pct,
            summary.stage_delta_finish_pct,
            summary.signal_classification,
            summary.signal_threshold_pct,
            summary.signal_noise_floor_pct,
            summary.signal_pair_spread_pct,
            summary.signal_direction_consistent,
            summary.artifacts.baseline_combined_name,
            summary.artifacts.candidate_combined_name,
            summary.artifacts.pair_matrix_name,
            summary.artifacts.compare_name,
        )
        .map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn write_summary_json(
    path: &Path,
    ctx: &Context,
    abba_page: PageProfile,
    artifacts: &[String],
    output: &oxide_randomx::full_features_capture::CaptureOutput,
) -> Result<(), String> {
    let summary = json!({
        "timestamp": ctx.now.compact,
        "date": ctx.now.date,
        "host_tag": ctx.host_tag,
        "host": {
            "vendor": ctx.host.vendor,
            "family": ctx.host.family,
            "model": ctx.host.model,
            "stepping": ctx.host.stepping,
            "cpu_model_string": ctx.host.cpu_model_string,
            "os_name": ctx.host.os_name,
            "os_version": ctx.host.os_version,
            "os_build_or_kernel": ctx.host.os_build_or_kernel,
            "logical_threads": ctx.host.logical_threads,
        },
        "authority_workflow": {
            "version": AUTHORITY_WORKFLOW_VERSION,
            "host_class_id": ctx.authority.host_class_id,
            "host_inventory_label": ctx.authority.host_inventory_label,
            "canonical_host_class": ctx.authority.canonical_host_class,
            "host_inventory_tier": ctx.authority.host_inventory_tier.as_str(),
            "host_inventory_reason": ctx.authority.host_inventory_reason,
            "capture_evidence_tier": ctx.authority.capture_evidence_tier.as_str(),
            "capture_evidence_reason": ctx.authority.capture_evidence_reason,
            "clean_provenance": ctx.authority.clean_provenance,
            "clean_provenance_notes": ctx.authority.clean_provenance_notes,
            "rerun_expectation": ctx.authority.rerun_expectation.as_str(),
            "rerun_reason": ctx.authority.rerun_reason,
            "rerun_group_id": ctx.authority.rerun_group_id,
        },
        "provenance": {
            "git_sha": GIT_SHA,
            "git_sha_short": GIT_SHA_SHORT,
            "git_dirty": GIT_DIRTY,
            "rustc": RUSTC_VERSION,
            "compiled_features": oxide_randomx::full_features_capture::REQUIRED_FEATURES,
        },
        "runtime": {
            "perf_iters": ctx.options.perf_iters,
            "perf_warmup": ctx.options.perf_warmup,
            "threads": ctx.options.threads,
            "page_profiles": ctx.page_profiles.iter().map(|profile| internal_page_profile_json(ctx, profile)).collect::<Vec<_>>(),
            "abba_page_profile": abba_page.key,
            "superscalar_iters": oxide_randomx::full_features_capture::DEFAULT_SUPERSCALAR_ITERS,
            "superscalar_warmup": oxide_randomx::full_features_capture::DEFAULT_SUPERSCALAR_WARMUP,
            "superscalar_items": oxide_randomx::full_features_capture::DEFAULT_SUPERSCALAR_ITEMS,
        },
        "page_backing_summary": output.page_backing_summaries.iter().map(|summary| internal_page_backing_summary_json(ctx, summary)).collect::<Vec<_>>(),
        "artifacts": artifacts,
        "matrix_rows": output.matrix_runs.iter().map(|run| internal_run_json_value(ctx, run)).collect::<Vec<_>>(),
        "pair_runs": output.pair_runs.iter().map(|run| internal_run_json_value(ctx, run)).collect::<Vec<_>>(),
        "pair_summaries": output.pair_summaries.iter().map(|summary| internal_pair_summary_json(ctx, summary)).collect::<Vec<_>>(),
        "superscalar_isolated": output.superscalar_runs.iter().map(oxide_randomx::full_features_capture::superscalar_json_value).collect::<Vec<_>>(),
    });
    let body = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    write_artifact(path, body)
}

fn write_overview_markdown(
    path: &Path,
    ctx: &Context,
    abba_page: PageProfile,
    artifacts: &[String],
    output: &oxide_randomx::full_features_capture::CaptureOutput,
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(
        &mut body,
        "# Full Features Benchmark ({}, {})",
        ctx.host_tag, ctx.host.os_name
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Authority Workflow").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- workflow version: {}",
        AUTHORITY_WORKFLOW_VERSION
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- host class id: {}",
        ctx.authority.host_class_id
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- host inventory label: {}",
        ctx.authority.host_inventory_label
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- canonical host class: {}",
        ctx.authority.canonical_host_class
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- host inventory tier: {}",
        ctx.authority.host_inventory_tier.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- capture evidence tier: {}",
        ctx.authority.capture_evidence_tier.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- clean provenance: {}",
        ctx.authority.clean_provenance
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- rerun expectation: {}",
        ctx.authority.rerun_expectation.as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- rerun group id: {}",
        ctx.authority.rerun_group_id
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- capture tier note: {}",
        ctx.authority.capture_evidence_reason
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- rerun note: {}", ctx.authority.rerun_reason)
        .map_err(|e| e.to_string())?;
    if !ctx.authority.clean_provenance_notes.is_empty() {
        writeln!(
            &mut body,
            "- clean provenance issues: {}",
            ctx.authority.clean_provenance_notes.join("; ")
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "Captured a host-tagged full-features refresh from one all-features binary. The standalone matrix spans every requested page profile; ABBA reevaluation uses the primary evidence profile `{}`.",
        abba_page.display
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Host").map_err(|e| e.to_string())?;
    writeln!(&mut body, "- vendor: {}", ctx.host.vendor).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- family/model: {}/{}",
        ctx.host.family, ctx.host.model
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- CPU: {}", ctx.host.cpu_model_string).map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- OS: {} (version {}, build/kernel {})",
        ctx.host.os_name, ctx.host.os_version, ctx.host.os_build_or_kernel
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "- git SHA: {}", GIT_SHA).map_err(|e| e.to_string())?;
    writeln!(&mut body, "- rustc: {}", RUSTC_VERSION).map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Run Plan").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- perf_harness iters={} warmup={} threads={}",
        ctx.options.perf_iters, ctx.options.perf_warmup, ctx.options.threads
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- page profiles: {}",
        ctx.page_profiles
            .iter()
            .map(|profile| format!(
                "{} [{} -> {}]",
                profile.display,
                profile.role.as_str(),
                page_profile_evidence_tier(ctx.authority.capture_evidence_tier, profile.role)
                    .as_str()
            ))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- matrix row count: {}",
        output.matrix_runs.len()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- ABBA pair count: {}",
        output.pair_summaries.len()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "- superscalar isolated runs: {}",
        output.superscalar_runs.len()
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Realized Page Backing").map_err(|e| e.to_string())?;
    writeln!(&mut body, "| Page profile | Role | Evidence tier | Observed runs | Dataset LP | Dataset 1G | Scratchpad LP | Scratchpad 1G |").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "| --- | --- | --- | ---: | --- | --- | --- | --- |"
    )
    .map_err(|e| e.to_string())?;
    for summary in &output.page_backing_summaries {
        let role = page_profile_for_key(ctx, &summary.page_profile).role;
        writeln!(
            &mut body,
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            summary.page_profile,
            summary.page_profile_role,
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role).as_str(),
            summary.observed_run_count,
            summary.dataset_large_pages.status.as_str(),
            summary.dataset_1gb_pages.status.as_str(),
            summary.scratchpad_large_pages.status.as_str(),
            summary.scratchpad_1gb_pages.status.as_str()
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Pair Summary").map_err(|e| e.to_string())?;
    writeln!(&mut body, "| Pair | Mode | Config | Page | Evidence tier | Delta (candidate vs baseline) | Classification | Baseline mean ns/hash | Candidate mean ns/hash |").map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "| --- | --- | --- | --- | --- | ---: | --- | ---: | ---: |"
    )
    .map_err(|e| e.to_string())?;
    for summary in &output.pair_summaries {
        let role = page_profile_for_key(ctx, &summary.page_profile).role;
        writeln!(
            &mut body,
            "| {} | {} | {} | {} | {} | {:+.3}% | {} | {:.3} | {:.3} |",
            summary.pair_label,
            summary.mode,
            summary.config,
            summary.page_profile,
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role).as_str(),
            summary.delta_pct_candidate_vs_baseline,
            summary.signal_classification,
            summary.baseline_mean_ns_per_hash,
            summary.candidate_mean_ns_per_hash
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(&mut body).map_err(|e| e.to_string())?;
    writeln!(&mut body, "## Artifacts").map_err(|e| e.to_string())?;
    for artifact in artifacts {
        writeln!(&mut body, "- {artifact}").map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn internal_run_json_value(ctx: &Context, run: &CapturedRun) -> Value {
    let mut value = match oxide_randomx::full_features_capture::run_json_value(run) {
        Value::Object(value) => value,
        _ => Map::new(),
    };
    let role = page_profile_for_key(ctx, &run.page_profile).role;
    value.insert(
        "host_class_id".to_string(),
        Value::String(ctx.authority.host_class_id.clone()),
    );
    value.insert(
        "capture_evidence_tier".to_string(),
        Value::String(ctx.authority.capture_evidence_tier.as_str().to_string()),
    );
    value.insert(
        "rerun_group_id".to_string(),
        Value::String(ctx.authority.rerun_group_id.clone()),
    );
    value.insert(
        "page_profile_evidence_tier".to_string(),
        Value::String(
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role)
                .as_str()
                .to_string(),
        ),
    );
    Value::Object(value)
}

fn internal_pair_summary_json(ctx: &Context, summary: &PairSummary) -> Value {
    let mut value = match oxide_randomx::full_features_capture::pair_summary_json(summary) {
        Value::Object(value) => value,
        _ => Map::new(),
    };
    let role = page_profile_for_key(ctx, &summary.page_profile).role;
    value.insert(
        "host_class_id".to_string(),
        Value::String(ctx.authority.host_class_id.clone()),
    );
    value.insert(
        "evidence_tier".to_string(),
        Value::String(
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role)
                .as_str()
                .to_string(),
        ),
    );
    value.insert(
        "capture_clean_provenance".to_string(),
        Value::Bool(ctx.authority.clean_provenance),
    );
    value.insert(
        "rerun_group_id".to_string(),
        Value::String(ctx.authority.rerun_group_id.clone()),
    );
    Value::Object(value)
}

fn internal_page_backing_summary_json(ctx: &Context, summary: &PageBackingSummary) -> Value {
    let mut value = match oxide_randomx::full_features_capture::page_backing_summary_json(summary) {
        Value::Object(value) => value,
        _ => Map::new(),
    };
    let role = page_profile_for_key(ctx, &summary.page_profile).role;
    value.insert(
        "evidence_tier".to_string(),
        Value::String(
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role)
                .as_str()
                .to_string(),
        ),
    );
    Value::Object(value)
}

fn internal_page_profile_json(ctx: &Context, profile: &PageProfile) -> Value {
    let mut value = match oxide_randomx::full_features_capture::page_profile_json(profile) {
        Value::Object(value) => value,
        _ => Map::new(),
    };
    value.insert(
        "evidence_tier".to_string(),
        Value::String(
            page_profile_evidence_tier(ctx.authority.capture_evidence_tier, profile.role)
                .as_str()
                .to_string(),
        ),
    );
    Value::Object(value)
}

fn write_compare_txt_internal(
    path: &Path,
    ctx: &Context,
    summary: &PairSummary,
    runs: [&CapturedRun; 4],
) -> Result<(), String> {
    let role = page_profile_for_key(ctx, &summary.page_profile).role;
    let mut body = String::new();
    writeln!(&mut body, "pair_label={}", summary.pair_label).map_err(|e| e.to_string())?;
    writeln!(&mut body, "mode={}", summary.mode).map_err(|e| e.to_string())?;
    writeln!(&mut body, "config={}", summary.config).map_err(|e| e.to_string())?;
    writeln!(&mut body, "page_profile={}", summary.page_profile).map_err(|e| e.to_string())?;
    writeln!(&mut body, "host_class_id={}", ctx.authority.host_class_id)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "evidence_tier={}",
        page_profile_evidence_tier(ctx.authority.capture_evidence_tier, role).as_str()
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "capture_clean_provenance={}",
        ctx.authority.clean_provenance
    )
    .map_err(|e| e.to_string())?;
    writeln!(&mut body, "rerun_group_id={}", ctx.authority.rerun_group_id)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "page_profile_role={}", summary.page_profile_role)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "baseline_label={}", summary.baseline_label).map_err(|e| e.to_string())?;
    writeln!(&mut body, "candidate_label={}", summary.candidate_label)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "baseline_mean_ns_per_hash={:.3}",
        summary.baseline_mean_ns_per_hash
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "candidate_mean_ns_per_hash={:.3}",
        summary.candidate_mean_ns_per_hash
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "delta_pct_candidate_vs_baseline={:+.3}",
        summary.delta_pct_candidate_vs_baseline
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_classification={}",
        summary.signal_classification
    )
    .map_err(|e| e.to_string())?;
    for (seq, run) in [
        ("a1", runs[0]),
        ("b1", runs[1]),
        ("b2", runs[2]),
        ("a2", runs[3]),
    ] {
        writeln!(
            &mut body,
            "{} ns_per_hash={} hashes_per_sec={} csv={} json={}",
            seq,
            run.csv_fields
                .get("ns_per_hash")
                .map(String::as_str)
                .unwrap_or(""),
            run.csv_fields
                .get("hashes_per_sec")
                .map(String::as_str)
                .unwrap_or(""),
            run.csv_name,
            run.json_name
        )
        .map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_host(
        vendor: &str,
        family: u32,
        model: u32,
        os_name: &str,
        logical_threads: usize,
    ) -> HostIdentity {
        HostIdentity {
            bucket: if vendor == "AuthenticAMD" {
                oxide_randomx::full_features_capture::HostBucket::Amd
            } else if vendor == "GenuineIntel" {
                oxide_randomx::full_features_capture::HostBucket::Intel
            } else {
                oxide_randomx::full_features_capture::HostBucket::Unlabeled
            },
            vendor: vendor.to_string(),
            family,
            model,
            stepping: 0,
            cpu_model_string: format!("{vendor} {family}/{model}"),
            os_name: os_name.to_string(),
            os_version: "test".to_string(),
            os_build_or_kernel: "test".to_string(),
            logical_threads,
        }
    }

    fn test_options(threads: usize) -> Options {
        Options {
            out_dir: None,
            threads,
            perf_iters: DEFAULT_PERF_ITERS,
            perf_warmup: DEFAULT_PERF_WARMUP,
            validate_only: false,
        }
    }

    #[test]
    fn authority_workflow_marks_amd_23_113_windows_as_supporting() {
        let host = test_host("AuthenticAMD", 23, 113, "Microsoft Windows 11 Pro", 12);
        let workflow = build_authority_workflow(
            &host,
            &test_options(12),
            &canonical_page_profiles(HostOsClass::Windows),
        );

        assert_eq!(workflow.host_class_id, "amd_fam23_mod113_windows");
        assert!(workflow.canonical_host_class);
        assert_eq!(workflow.host_inventory_tier, EvidenceTier::Supporting);
        assert_eq!(
            workflow.capture_evidence_tier,
            if GIT_DIRTY == "false" {
                EvidenceTier::Supporting
            } else {
                EvidenceTier::Exploratory
            }
        );
    }

    #[test]
    fn authority_workflow_downgrades_noncanonical_settings_to_exploratory() {
        let host = test_host("GenuineIntel", 6, 45, "Ubuntu 24.04.4 LTS", 32);
        let workflow = build_authority_workflow(
            &host,
            &test_options(16),
            &canonical_page_profiles(HostOsClass::Linux),
        );

        assert_eq!(workflow.capture_evidence_tier, EvidenceTier::Exploratory);
        assert!(!workflow.clean_provenance);
    }
}
