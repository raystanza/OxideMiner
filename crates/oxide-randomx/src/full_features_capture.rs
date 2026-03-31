use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MATRIX_DIR: &str = "matrix";
pub const ABBA_RUNS_DIR: &str = "abba/runs";
pub const ABBA_PAIRS_DIR: &str = "abba/pairs";
pub const SUPERSCALAR_DIR: &str = "superscalar";
pub const COMMANDS_ARTIFACT: &str = "meta/commands.log";
pub const MANIFEST_ARTIFACT: &str = "meta/manifest.txt";
pub const MATRIX_INDEX_ARTIFACT: &str = "meta/matrix_index.csv";
pub const PAIR_INDEX_ARTIFACT: &str = "meta/pair_index.csv";
pub const PAIR_SUMMARY_ARTIFACT: &str = "meta/pair_summary.csv";

pub const DEFAULT_PERF_ITERS: u64 = 50;
pub const DEFAULT_PERF_WARMUP: u64 = 5;
pub const DEFAULT_SUPERSCALAR_ITERS: u64 = 2_000;
pub const DEFAULT_SUPERSCALAR_WARMUP: u64 = 200;
pub const DEFAULT_SUPERSCALAR_ITEMS: usize = 256;
pub const REQUIRED_FEATURES: &str =
    "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto";
pub const SIGNAL_CLASS_LIKELY_SIGNAL: &str = "likely_signal";
pub const SIGNAL_CLASS_LIKELY_NOISE: &str = "likely_noise";

const FAST_BENCH_ENV: &str = "OXIDE_RANDOMX_FAST_BENCH";
const HUGE_1G_ENV: &str = "OXIDE_RANDOMX_HUGE_1G";
const THREADED_INTERP_ENV: &str = "OXIDE_RANDOMX_THREADED_INTERP";
const SIMD_BLOCKIO_FORCE_ENV: &str = "OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE";
const SIMD_BLOCKIO_DISABLE_ENV: &str = "OXIDE_RANDOMX_SIMD_BLOCKIO_DISABLE";
const SIMD_XOR_FORCE_ENV: &str = "OXIDE_RANDOMX_SIMD_XOR_PATHS_FORCE";
const SIMD_XOR_DISABLE_ENV: &str = "OXIDE_RANDOMX_SIMD_XOR_PATHS_DISABLE";
const SUPERSCALAR_FORCE_ENV: &str = "OXIDE_RANDOMX_SUPERSCALAR_ACCEL_PROTO_FORCE";
const SUPERSCALAR_DISABLE_ENV: &str = "OXIDE_RANDOMX_SUPERSCALAR_ACCEL_PROTO_DISABLE";
const FAST_BENCH_SMALL_ENV: &str = "OXIDE_RANDOMX_FAST_BENCH_SMALL";

#[allow(dead_code)]
mod perf_harness_support {
    pub struct CaptureSpec {
        pub mode: &'static str,
        pub iters: u64,
        pub warmup: u64,
        pub threads: usize,
        pub jit: bool,
        pub jit_fast_regs: bool,
        pub large_pages: bool,
        pub use_1gb_pages: bool,
    }

    pub struct CaptureArtifacts {
        pub csv: String,
        pub json: String,
        pub summary: String,
    }

    pub fn ensure_compiled_features(tool_id: &str) -> Result<(), String> {
        for (enabled, feature) in [
            (cfg!(feature = "jit"), "jit"),
            (cfg!(feature = "jit-fastregs"), "jit-fastregs"),
            (cfg!(feature = "bench-instrument"), "bench-instrument"),
            (cfg!(feature = "threaded-interp"), "threaded-interp"),
            (cfg!(feature = "simd-blockio"), "simd-blockio"),
            (cfg!(feature = "simd-xor-paths"), "simd-xor-paths"),
            (
                cfg!(feature = "superscalar-accel-proto"),
                "superscalar-accel-proto",
            ),
        ] {
            if !enabled {
                return Err(format!(
                    "{tool_id} must be built with --features \"{}\" (missing {feature})",
                    super::REQUIRED_FEATURES
                ));
            }
        }
        Ok(())
    }

    pub fn capture(spec: &CaptureSpec) -> Result<CaptureArtifacts, String> {
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
            use_1gb_pages: spec.use_1gb_pages,
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

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/perf_harness.rs"
    ));
}

#[allow(dead_code)]
mod superscalar_support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/superscalar_hash_harness.rs"
    ));

    pub struct CaptureSpec {
        pub config: &'static str,
        pub impl_kind: &'static str,
        pub iters: u64,
        pub warmup: u64,
        pub items: usize,
    }

    pub struct CaptureArtifacts {
        pub csv: String,
        pub json: String,
        pub summary: String,
    }

    pub fn capture(spec: &CaptureSpec) -> Result<CaptureArtifacts, String> {
        let config = match spec.config {
            "test-small" => ConfigPreset::TestSmall,
            "default" => ConfigPreset::Default,
            other => return Err(format!("unsupported superscalar config: {other}")),
        };
        let impl_kind = match spec.impl_kind {
            "active" => ImplKind::Active,
            "scalar" => ImplKind::Scalar,
            other => return Err(format!("unsupported superscalar impl: {other}")),
        };
        let opts = Options {
            iters: spec.iters,
            warmup: spec.warmup,
            items: spec.items,
            format: Format::Human,
            config,
            impl_kind,
        };
        let report = run_harness(&opts)?;
        Ok(CaptureArtifacts {
            csv: format_csv(&report),
            json: format_json(&report),
            summary: format!(
                "summary config={} impl={} compute_ns_per_call={:.3} execute_ns_per_call={:.3}",
                report.config,
                report.impl_kind,
                report.compute_ns_per_call,
                report.execute_ns_per_call
            ),
        })
    }

    fn format_json(report: &HarnessReport) -> String {
        format!(
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
        )
    }

    fn format_csv(report: &HarnessReport) -> String {
        format!(
            "config,impl,cache_items,cache_accesses,items,warmup,iters,compute_calls,compute_total_ns,\
compute_ns_per_call,compute_checksum,execute_calls,execute_total_ns,execute_ns_per_call,\
execute_checksum,execute_select_checksum\n\
{},{},{},{},{},{},{},{},{},{:.3},{},{},{},{:.3},{},{}\n",
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
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureSurface<'a> {
    Internal,
    Public { release_id: &'a str },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostBucket {
    Amd,
    Intel,
    Unlabeled,
}

impl HostBucket {
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Amd => "AMD",
            Self::Intel => "Intel",
            Self::Unlabeled => "unlabeled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOsClass {
    Windows,
    Linux,
    Other,
}

impl HostOsClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageProfileRole {
    AuthorityPrimary,
    SupportingControl,
    SupportingSemantics,
}

impl PageProfileRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityPrimary => "authority_primary",
            Self::SupportingControl => "supporting_control",
            Self::SupportingSemantics => "supporting_semantics",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedFlagStatus {
    AllTrue,
    AllFalse,
    Mixed,
    Unknown,
}

impl ObservedFlagStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllTrue => "all_true",
            Self::AllFalse => "all_false",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeKey {
    Light,
    Fast,
}

impl ModeKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Fast => "fast",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Fast => "Fast",
        }
    }

    fn uses_fast_env(self) -> bool {
        matches!(self, Self::Fast)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdBlockioState {
    Disabled,
    Guarded,
    Forced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureState {
    pub threaded_interp: bool,
    pub simd_blockio: SimdBlockioState,
    pub simd_xor: bool,
    pub superscalar_proto: bool,
}

impl FeatureState {
    pub const fn baseline() -> Self {
        Self {
            threaded_interp: false,
            simd_blockio: SimdBlockioState::Disabled,
            simd_xor: false,
            superscalar_proto: false,
        }
    }

    pub fn display(self) -> String {
        let mut parts = Vec::new();
        if self.threaded_interp {
            parts.push("threaded-interp");
        }
        match self.simd_blockio {
            SimdBlockioState::Disabled => {}
            SimdBlockioState::Guarded => parts.push("simd-blockio guarded"),
            SimdBlockioState::Forced => parts.push("simd-blockio forced"),
        }
        if self.simd_xor {
            parts.push("simd-xor-paths");
        }
        if self.superscalar_proto {
            parts.push("superscalar-accel-proto");
        }
        if parts.is_empty() {
            "baseline".to_string()
        } else {
            parts.join(" + ")
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PageProfile {
    pub key: &'static str,
    pub display: &'static str,
    pub large_pages: bool,
    pub use_1gb_pages: bool,
    pub abba_primary: bool,
    pub role: PageProfileRole,
}

#[derive(Clone, Copy, Debug)]
pub struct RunConfig {
    pub key: &'static str,
    pub config: &'static str,
    pub mode: ModeKey,
    pub jit: bool,
    pub jit_fast_regs: bool,
    pub state: FeatureState,
}

#[derive(Clone, Copy, Debug)]
pub struct MatrixSpec {
    pub label: &'static str,
    pub category: &'static str,
    pub run: RunConfig,
}

#[derive(Clone, Copy, Debug)]
pub struct PairSpec {
    pub pair_label: &'static str,
    pub family: &'static str,
    pub baseline_label: &'static str,
    pub candidate_label: &'static str,
    pub run: RunConfig,
    pub baseline: FeatureState,
    pub candidate: FeatureState,
}

#[derive(Clone, Copy, Debug)]
pub struct SuperscalarSpec {
    pub label: &'static str,
    pub config: &'static str,
    pub impl_kind: &'static str,
    pub force_proto: bool,
    pub disable_proto: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicCaptureProfile {
    Standard,
    Full,
}

impl PublicCaptureProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Full => "Full",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            other => Err(format!("unsupported --profile value: {other}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CapturePlan {
    pub id: &'static str,
    pub display_name: &'static str,
    pub runtime_class: &'static str,
    pub page_profiles: Vec<PageProfile>,
    pub matrix_specs: Vec<MatrixSpec>,
    pub pair_specs: Vec<PairSpec>,
    pub superscalar_specs: Vec<SuperscalarSpec>,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureOptions {
    pub threads: usize,
    pub perf_iters: u64,
    pub perf_warmup: u64,
}

#[derive(Clone, Debug)]
pub struct HostIdentity {
    pub bucket: HostBucket,
    pub vendor: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub cpu_model_string: String,
    pub os_name: String,
    pub os_version: String,
    pub os_build_or_kernel: String,
    pub logical_threads: usize,
}

impl HostIdentity {
    pub fn host_tag(&self) -> String {
        let vendor = match self.bucket {
            HostBucket::Amd => "amd",
            HostBucket::Intel => "intel",
            HostBucket::Unlabeled => "host",
        };
        let fingerprint = short_hash32(&format!(
            "{}:{}:{}:{}",
            self.vendor, self.family, self.model, self.cpu_model_string
        ));
        format!(
            "{vendor}_{}_{}t_{fingerprint:08x}",
            self.os_class().as_str(),
            self.logical_threads
        )
    }

    pub fn os_class(&self) -> HostOsClass {
        let os = self.os_name.to_ascii_lowercase();
        if os.contains("windows") {
            HostOsClass::Windows
        } else if os.contains("linux") || os.contains("ubuntu") {
            HostOsClass::Linux
        } else {
            HostOsClass::Other
        }
    }
}

#[derive(Clone, Debug)]
pub struct NowStrings {
    pub compact: String,
    pub date: String,
    pub iso: String,
}

#[derive(Clone, Debug)]
pub struct CaptureContext<'a> {
    pub options: CaptureOptions,
    pub now: NowStrings,
    pub host: HostIdentity,
    pub host_tag: String,
    pub out_dir: PathBuf,
    pub commands_path: PathBuf,
    pub surface: CaptureSurface<'a>,
}

#[derive(Clone, Debug)]
pub struct CapturedRun {
    pub capture_kind: &'static str,
    pub feature_family: &'static str,
    pub label: String,
    pub config: String,
    pub mode: String,
    pub page_profile: String,
    pub page_profile_role: String,
    pub runtime_profile: String,
    pub runtime_jit_flags: String,
    pub csv_name: String,
    pub json_name: String,
    pub summary_line: String,
    pub csv_header: Vec<String>,
    pub csv_fields: BTreeMap<String, String>,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct PairArtifacts {
    pub baseline_combined_name: String,
    pub candidate_combined_name: String,
    pub pair_matrix_name: String,
    pub compare_name: String,
}

#[derive(Clone, Debug)]
pub struct PageBackingObservation {
    pub status: ObservedFlagStatus,
    pub true_count: usize,
    pub false_count: usize,
    pub unknown_count: usize,
}

#[derive(Clone, Debug)]
pub struct PageBackingSummary {
    pub page_profile: String,
    pub page_profile_display: String,
    pub page_profile_role: String,
    pub requested_large_pages: bool,
    pub requested_1gb_pages: bool,
    pub observed_run_count: usize,
    pub dataset_large_pages: PageBackingObservation,
    pub dataset_1gb_pages: PageBackingObservation,
    pub scratchpad_large_pages: PageBackingObservation,
    pub scratchpad_1gb_pages: PageBackingObservation,
}

#[derive(Clone, Debug)]
pub struct PairSummary {
    pub pair_label: String,
    pub family: String,
    pub config: String,
    pub mode: String,
    pub page_profile: String,
    pub page_profile_role: String,
    pub baseline_label: String,
    pub candidate_label: String,
    pub baseline_dataset_large_pages_status: String,
    pub baseline_dataset_1gb_pages_status: String,
    pub baseline_scratchpad_large_pages_status: String,
    pub baseline_scratchpad_1gb_pages_status: String,
    pub candidate_dataset_large_pages_status: String,
    pub candidate_dataset_1gb_pages_status: String,
    pub candidate_scratchpad_large_pages_status: String,
    pub candidate_scratchpad_1gb_pages_status: String,
    pub baseline_mean_ns_per_hash: f64,
    pub candidate_mean_ns_per_hash: f64,
    pub delta_pct_candidate_vs_baseline: f64,
    pub pair_delta_a1_b1_pct: f64,
    pub pair_delta_a2_b2_pct: f64,
    pub baseline_drift_pct: f64,
    pub candidate_drift_pct: f64,
    pub stage_delta_prepare_pct: f64,
    pub stage_delta_execute_pct: f64,
    pub stage_delta_finish_pct: f64,
    pub signal_classification: String,
    pub signal_threshold_pct: f64,
    pub signal_noise_floor_pct: f64,
    pub signal_pair_spread_pct: f64,
    pub signal_direction_consistent: bool,
    pub artifacts: PairArtifacts,
}

#[derive(Clone, Debug)]
struct PairSignalAssessment {
    classification: &'static str,
    threshold_pct: f64,
    noise_floor_pct: f64,
    pair_spread_pct: f64,
    direction_consistent: bool,
}

#[derive(Clone, Debug)]
pub struct SuperscalarCapture {
    pub label: String,
    pub csv_name: String,
    pub json_name: String,
    pub summary_line: String,
    pub json_value: Value,
}

#[derive(Clone, Debug)]
pub struct CaptureOutput {
    pub matrix_runs: Vec<CapturedRun>,
    pub pair_runs: Vec<CapturedRun>,
    pub pair_summaries: Vec<PairSummary>,
    pub superscalar_runs: Vec<SuperscalarCapture>,
    pub page_backing_summaries: Vec<PageBackingSummary>,
}

pub fn ensure_compiled_features(tool_id: &str) -> Result<(), String> {
    perf_harness_support::ensure_compiled_features(tool_id)
}

pub fn execute_capture_plan(
    ctx: &CaptureContext<'_>,
    plan: &CapturePlan,
) -> Result<CaptureOutput, String> {
    let abba_page = plan
        .page_profiles
        .iter()
        .copied()
        .find(|profile| profile.abba_primary)
        .unwrap_or_else(|| plan.page_profiles[0]);

    let matrix_runs = run_matrix_suite(ctx, plan)?;
    let (pair_runs, pair_summaries) = run_abba_suite(ctx, plan, abba_page)?;
    let superscalar_runs = run_superscalar_suite(ctx, plan)?;
    let page_backing_summaries =
        summarize_page_backing(&plan.page_profiles, &matrix_runs, &pair_runs);

    Ok(CaptureOutput {
        matrix_runs,
        pair_runs,
        pair_summaries,
        superscalar_runs,
        page_backing_summaries,
    })
}

pub fn write_artifact(path: &Path, body: impl AsRef<[u8]>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn append_command_log(path: &Path, line: &str) -> Result<(), String> {
    let mut body = fs::read_to_string(path).unwrap_or_default();
    writeln!(&mut body, "{line}").map_err(|e| e.to_string())?;
    write_artifact(path, body)
}

pub fn collect_artifacts(
    extra_artifacts: &[String],
    matrix_runs: &[CapturedRun],
    pair_runs: &[CapturedRun],
    pair_summaries: &[PairSummary],
    superscalar_runs: &[SuperscalarCapture],
) -> Vec<String> {
    let mut artifacts = extra_artifacts.to_vec();
    for run in matrix_runs.iter().chain(pair_runs.iter()) {
        artifacts.push(run.csv_name.clone());
        artifacts.push(run.json_name.clone());
    }
    for summary in pair_summaries {
        artifacts.push(summary.artifacts.baseline_combined_name.clone());
        artifacts.push(summary.artifacts.candidate_combined_name.clone());
        artifacts.push(summary.artifacts.pair_matrix_name.clone());
        artifacts.push(summary.artifacts.compare_name.clone());
    }
    for run in superscalar_runs {
        artifacts.push(run.csv_name.clone());
        artifacts.push(run.json_name.clone());
    }
    artifacts.sort();
    artifacts.dedup();
    artifacts
}

pub fn compact_key(value: &str) -> String {
    let mut initials = String::new();
    for segment in value.split(['_', '-', ' ']) {
        if segment.is_empty() {
            continue;
        }
        if let Some(ch) = segment.chars().find(|ch| ch.is_ascii_alphanumeric()) {
            initials.push(ch.to_ascii_lowercase());
            if initials.len() >= 6 {
                break;
            }
        }
    }
    if initials.is_empty() {
        initials.push('k');
    }
    format!("{initials}-{:08x}", short_hash32(value))
}

pub fn short_hash32(value: &str) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for byte in value.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

pub fn write_matrix_index(path: &Path, runs: &[CapturedRun]) -> Result<(), String> {
    if runs.is_empty() {
        return Err("matrix index requires at least one run".to_string());
    }
    let selected = matrix_index_fields();
    let header = vec![
        "capture_kind".to_string(),
        "feature_family".to_string(),
        "label".to_string(),
        "mode".to_string(),
        "config".to_string(),
        "page_profile".to_string(),
        "page_profile_role".to_string(),
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
        let mut values = vec![
            csv_escape(run.capture_kind),
            csv_escape(run.feature_family),
            csv_escape(&run.label),
            csv_escape(&run.mode),
            csv_escape(&run.config),
            csv_escape(&run.page_profile),
            csv_escape(&run.page_profile_role),
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

pub fn write_pair_index(path: &Path, runs: &[CapturedRun]) -> Result<(), String> {
    write_matrix_index(path, runs)
}

pub fn write_pair_summary_csv(path: &Path, summaries: &[PairSummary]) -> Result<(), String> {
    let mut body = String::from(
        "pair_label,family,config,mode,page_profile,page_profile_role,baseline_label,candidate_label,baseline_dataset_large_pages_status,baseline_dataset_1gb_pages_status,baseline_scratchpad_large_pages_status,baseline_scratchpad_1gb_pages_status,candidate_dataset_large_pages_status,candidate_dataset_1gb_pages_status,candidate_scratchpad_large_pages_status,candidate_scratchpad_1gb_pages_status,baseline_mean_ns_per_hash,candidate_mean_ns_per_hash,delta_pct_candidate_vs_baseline,pair_delta_a1_b1_pct,pair_delta_a2_b2_pct,baseline_drift_pct,candidate_drift_pct,stage_delta_prepare_pct,stage_delta_execute_pct,stage_delta_finish_pct,signal_classification,signal_threshold_pct,signal_noise_floor_pct,signal_pair_spread_pct,signal_direction_consistent,baseline_combined,candidate_combined,pair_matrix,compare_txt\n",
    );
    for summary in summaries {
        writeln!(
            &mut body,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{:+.6},{},{:.6},{:.6},{:.6},{},{},{},{},{}",
            summary.pair_label,
            summary.family,
            summary.config,
            summary.mode,
            summary.page_profile,
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

pub fn run_json_value(run: &CapturedRun) -> Value {
    let mut value = Map::new();
    value.insert(
        "capture_kind".to_string(),
        Value::String(run.capture_kind.to_string()),
    );
    value.insert(
        "feature_family".to_string(),
        Value::String(run.feature_family.to_string()),
    );
    value.insert("label".to_string(), Value::String(run.label.clone()));
    value.insert("config".to_string(), Value::String(run.config.clone()));
    value.insert("mode".to_string(), Value::String(run.mode.clone()));
    value.insert(
        "page_profile".to_string(),
        Value::String(run.page_profile.clone()),
    );
    value.insert(
        "page_profile_role".to_string(),
        Value::String(run.page_profile_role.clone()),
    );
    value.insert(
        "runtime_profile".to_string(),
        Value::String(run.runtime_profile.clone()),
    );
    value.insert(
        "runtime_jit_flags".to_string(),
        Value::String(run.runtime_jit_flags.clone()),
    );
    value.insert(
        "csv_artifact".to_string(),
        Value::String(run.csv_name.clone()),
    );
    value.insert(
        "json_artifact".to_string(),
        Value::String(run.json_name.clone()),
    );
    value.insert(
        "summary_line".to_string(),
        Value::String(run.summary_line.clone()),
    );
    value.insert(
        "elapsed_ms".to_string(),
        Value::from(run.elapsed.as_secs_f64() * 1000.0),
    );
    for column in &run.csv_header {
        value.insert(
            column.clone(),
            coerce_json_value(run.csv_fields.get(column).map(String::as_str).unwrap_or("")),
        );
    }
    Value::Object(value)
}

pub fn pair_summary_json(summary: &PairSummary) -> Value {
    json!({
        "pair_label": summary.pair_label,
        "family": summary.family,
        "config": summary.config,
        "mode": summary.mode,
        "page_profile": summary.page_profile,
        "page_profile_role": summary.page_profile_role,
        "baseline_label": summary.baseline_label,
        "candidate_label": summary.candidate_label,
        "baseline_realized_page_backing": {
            "dataset_large_pages_status": summary.baseline_dataset_large_pages_status,
            "dataset_1gb_pages_status": summary.baseline_dataset_1gb_pages_status,
            "scratchpad_large_pages_status": summary.baseline_scratchpad_large_pages_status,
            "scratchpad_1gb_pages_status": summary.baseline_scratchpad_1gb_pages_status,
        },
        "candidate_realized_page_backing": {
            "dataset_large_pages_status": summary.candidate_dataset_large_pages_status,
            "dataset_1gb_pages_status": summary.candidate_dataset_1gb_pages_status,
            "scratchpad_large_pages_status": summary.candidate_scratchpad_large_pages_status,
            "scratchpad_1gb_pages_status": summary.candidate_scratchpad_1gb_pages_status,
        },
        "baseline_mean_ns_per_hash": summary.baseline_mean_ns_per_hash,
        "candidate_mean_ns_per_hash": summary.candidate_mean_ns_per_hash,
        "delta_pct_candidate_vs_baseline": summary.delta_pct_candidate_vs_baseline,
        "pair_delta_a1_b1_pct": summary.pair_delta_a1_b1_pct,
        "pair_delta_a2_b2_pct": summary.pair_delta_a2_b2_pct,
        "baseline_drift_pct": summary.baseline_drift_pct,
        "candidate_drift_pct": summary.candidate_drift_pct,
        "stage_delta_prepare_pct": summary.stage_delta_prepare_pct,
        "stage_delta_execute_pct": summary.stage_delta_execute_pct,
        "stage_delta_finish_pct": summary.stage_delta_finish_pct,
        "signal_classification": summary.signal_classification,
        "signal_threshold_pct": summary.signal_threshold_pct,
        "signal_noise_floor_pct": summary.signal_noise_floor_pct,
        "signal_pair_spread_pct": summary.signal_pair_spread_pct,
        "signal_direction_consistent": summary.signal_direction_consistent,
        "artifacts": {
            "baseline_combined": summary.artifacts.baseline_combined_name,
            "candidate_combined": summary.artifacts.candidate_combined_name,
            "pair_matrix": summary.artifacts.pair_matrix_name,
            "compare_txt": summary.artifacts.compare_name,
        }
    })
}

pub fn superscalar_json_value(run: &SuperscalarCapture) -> Value {
    json!({
        "label": run.label,
        "csv_artifact": run.csv_name,
        "json_artifact": run.json_name,
        "summary_line": run.summary_line,
        "metrics": run.json_value,
    })
}

pub fn page_profile_json(profile: &PageProfile) -> Value {
    json!({
        "key": profile.key,
        "display": profile.display,
        "large_pages": profile.large_pages,
        "use_1gb_pages": profile.use_1gb_pages,
        "abba_primary": profile.abba_primary,
        "role": profile.role.as_str(),
    })
}

pub fn page_backing_summary_json(summary: &PageBackingSummary) -> Value {
    json!({
        "page_profile": summary.page_profile,
        "page_profile_display": summary.page_profile_display,
        "page_profile_role": summary.page_profile_role,
        "requested_large_pages": summary.requested_large_pages,
        "requested_1gb_pages": summary.requested_1gb_pages,
        "observed_run_count": summary.observed_run_count,
        "dataset_large_pages": page_backing_observation_json(&summary.dataset_large_pages),
        "dataset_1gb_pages": page_backing_observation_json(&summary.dataset_1gb_pages),
        "scratchpad_large_pages": page_backing_observation_json(&summary.scratchpad_large_pages),
        "scratchpad_1gb_pages": page_backing_observation_json(&summary.scratchpad_1gb_pages),
    })
}

pub fn now_strings() -> NowStrings {
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

pub fn detect_host_identity() -> Result<HostIdentity, String> {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;

        // SAFETY: This probe is gated to x86_64, where CPUID is a stable
        // userspace instruction. Leaves 0 and 1 only expose CPU identity data.
        let (cpuid0, cpuid1) = unsafe { (__cpuid(0), __cpuid(1)) };
        let mut vendor = [0u8; 12];
        vendor[..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

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
        let bucket = match vendor.as_str() {
            "AuthenticAMD" => HostBucket::Amd,
            "GenuineIntel" => HostBucket::Intel,
            _ => HostBucket::Unlabeled,
        };
        let (os_name, os_version, os_build_or_kernel) = os_details();

        Ok(HostIdentity {
            bucket,
            vendor,
            family,
            model,
            stepping,
            cpu_model_string: cpu_model_string(),
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

pub fn canonical_page_profiles(os_class: HostOsClass) -> Vec<PageProfile> {
    match os_class {
        HostOsClass::Linux => vec![
            PageProfile {
                key: "pages_off",
                display: "4KB pages / large pages off",
                large_pages: false,
                use_1gb_pages: false,
                abba_primary: false,
                role: PageProfileRole::SupportingControl,
            },
            PageProfile {
                key: "large_pages_on",
                display: "large pages on",
                large_pages: true,
                use_1gb_pages: false,
                abba_primary: true,
                role: PageProfileRole::AuthorityPrimary,
            },
            PageProfile {
                key: "huge_1g_requested",
                display: "large pages on + 1GB huge page requested",
                large_pages: true,
                use_1gb_pages: true,
                abba_primary: false,
                role: PageProfileRole::SupportingSemantics,
            },
        ],
        HostOsClass::Windows => vec![
            PageProfile {
                key: "pages_off",
                display: "4KB pages / large pages off",
                large_pages: false,
                use_1gb_pages: false,
                abba_primary: false,
                role: PageProfileRole::SupportingControl,
            },
            PageProfile {
                key: "large_pages_on",
                display: "large pages on",
                large_pages: true,
                use_1gb_pages: false,
                abba_primary: true,
                role: PageProfileRole::AuthorityPrimary,
            },
        ],
        HostOsClass::Other => vec![PageProfile {
            key: "pages_off",
            display: "default pages",
            large_pages: false,
            use_1gb_pages: false,
            abba_primary: true,
            role: PageProfileRole::AuthorityPrimary,
        }],
    }
}

pub fn internal_full_plan(os_class: HostOsClass) -> CapturePlan {
    CapturePlan {
        id: "internal_full",
        display_name: "Internal Full Features Benchmark",
        runtime_class: "deep",
        page_profiles: canonical_page_profiles(os_class),
        matrix_specs: full_matrix_specs(),
        pair_specs: full_pair_specs(),
        superscalar_specs: superscalar_specs(),
    }
}

pub fn public_capture_plan(profile: PublicCaptureProfile, os_class: HostOsClass) -> CapturePlan {
    match profile {
        PublicCaptureProfile::Standard => CapturePlan {
            id: "standard",
            display_name: "Public Capture Standard",
            runtime_class: "moderate",
            page_profiles: canonical_page_profiles(os_class),
            matrix_specs: full_matrix_specs()
                .into_iter()
                .filter(|spec| spec.category == "baseline_matrix")
                .collect(),
            pair_specs: full_pair_specs()
                .into_iter()
                .filter(|spec| {
                    matches!(
                        (spec.family, spec.pair_label, spec.run.key),
                        ("threaded_interp", "baseline_vs_threaded", "light_interp")
                            | ("simd_blockio", "baseline_vs_guarded", "light_interp")
                            | ("simd_blockio", "baseline_vs_guarded", "fast_interp")
                            | ("superscalar_proto", "baseline_vs_superscalar_proto", _)
                    )
                })
                .collect(),
            superscalar_specs: superscalar_specs(),
        },
        PublicCaptureProfile::Full => CapturePlan {
            id: "full",
            display_name: "Public Capture Full",
            runtime_class: "long",
            page_profiles: canonical_page_profiles(os_class),
            matrix_specs: full_matrix_specs(),
            pair_specs: full_pair_specs(),
            superscalar_specs: superscalar_specs(),
        },
    }
}

pub fn summarize_page_backing(
    page_profiles: &[PageProfile],
    matrix_runs: &[CapturedRun],
    pair_runs: &[CapturedRun],
) -> Vec<PageBackingSummary> {
    page_profiles
        .iter()
        .map(|profile| {
            let runs = matrix_runs
                .iter()
                .chain(pair_runs.iter())
                .filter(|run| run.page_profile == profile.key)
                .collect::<Vec<_>>();
            PageBackingSummary {
                page_profile: profile.key.to_string(),
                page_profile_display: profile.display.to_string(),
                page_profile_role: profile.role.as_str().to_string(),
                requested_large_pages: profile.large_pages,
                requested_1gb_pages: profile.use_1gb_pages,
                observed_run_count: runs.len(),
                dataset_large_pages: observe_flag(&runs, "large_pages_dataset"),
                dataset_1gb_pages: observe_flag(&runs, "large_pages_1gb_dataset"),
                scratchpad_large_pages: observe_flag(&runs, "large_pages_scratchpad"),
                scratchpad_1gb_pages: observe_flag(&runs, "large_pages_1gb_scratchpad"),
            }
        })
        .collect()
}

fn run_matrix_suite(
    ctx: &CaptureContext<'_>,
    plan: &CapturePlan,
) -> Result<Vec<CapturedRun>, String> {
    let mut runs = Vec::new();
    println!(
        "stage=matrix total_pages={} rows_per_page={}",
        plan.page_profiles.len(),
        plan.matrix_specs.len()
    );
    for profile in &plan.page_profiles {
        println!(
            "stage=matrix page_profile={} role={} large_pages_requested={} huge_1g_requested={}",
            profile.display,
            profile.role.as_str(),
            profile.large_pages,
            profile.use_1gb_pages
        );
        for spec in &plan.matrix_specs {
            let label_key = compact_key(spec.label);
            let stem = format!(
                "{MATRIX_DIR}/{}/{}/{}",
                profile.key, spec.category, label_key
            );
            let run = capture_perf_run(ctx, "matrix", spec.category, spec.run, *profile, &stem)?;
            print_run_status("matrix", &run);
            runs.push(run);
        }
    }
    Ok(runs)
}

fn run_abba_suite(
    ctx: &CaptureContext<'_>,
    plan: &CapturePlan,
    page_profile: PageProfile,
) -> Result<(Vec<CapturedRun>, Vec<PairSummary>), String> {
    let mut runs = Vec::new();
    let mut summaries = Vec::new();
    println!(
        "stage=abba page_profile={} pair_count={}",
        page_profile.display,
        plan.pair_specs.len()
    );
    for spec in &plan.pair_specs {
        println!(
            "stage=abba pair={} config={} baseline={} candidate={}",
            spec.pair_label, spec.run.config, spec.baseline_label, spec.candidate_label
        );
        let a1 = capture_pair_run(ctx, *spec, page_profile, "a1", spec.baseline)?;
        print_run_status("abba", &a1);
        let b1 = capture_pair_run(ctx, *spec, page_profile, "b1", spec.candidate)?;
        print_run_status("abba", &b1);
        let b2 = capture_pair_run(ctx, *spec, page_profile, "b2", spec.candidate)?;
        print_run_status("abba", &b2);
        let a2 = capture_pair_run(ctx, *spec, page_profile, "a2", spec.baseline)?;
        print_run_status("abba", &a2);

        let summary = write_pair_artifacts(ctx, *spec, page_profile, [&a1, &b1, &b2, &a2])?;
        println!(
            "stage=abba-summary pair={} delta_pct={:+.3} baseline_mean_ns_per_hash={:.3} candidate_mean_ns_per_hash={:.3}",
            summary.pair_label,
            summary.delta_pct_candidate_vs_baseline,
            summary.baseline_mean_ns_per_hash,
            summary.candidate_mean_ns_per_hash
        );
        runs.extend([a1, b1, b2, a2]);
        summaries.push(summary);
    }
    Ok((runs, summaries))
}

fn run_superscalar_suite(
    ctx: &CaptureContext<'_>,
    plan: &CapturePlan,
) -> Result<Vec<SuperscalarCapture>, String> {
    println!(
        "stage=superscalar iters={} warmup={} items={}",
        DEFAULT_SUPERSCALAR_ITERS, DEFAULT_SUPERSCALAR_WARMUP, DEFAULT_SUPERSCALAR_ITEMS
    );
    let mut runs = Vec::new();
    for spec in &plan.superscalar_specs {
        let stem = format!("{SUPERSCALAR_DIR}/{}", spec.label);
        let run = with_superscalar_env(spec.force_proto, spec.disable_proto, || {
            let started = Instant::now();
            let capture = superscalar_support::capture(&superscalar_support::CaptureSpec {
                config: spec.config,
                impl_kind: spec.impl_kind,
                iters: DEFAULT_SUPERSCALAR_ITERS,
                warmup: DEFAULT_SUPERSCALAR_WARMUP,
                items: DEFAULT_SUPERSCALAR_ITEMS,
            })?;
            let csv_name = format!("{stem}.csv");
            let json_name = format!("{stem}.json");
            write_artifact(&ctx.out_dir.join(&csv_name), &capture.csv)?;
            write_artifact(&ctx.out_dir.join(&json_name), &capture.json)?;
            append_command_log(
                &ctx.commands_path,
                &format!(
                    "{} superscalar_hash_harness --config {} --impl {} --iters {} --warmup {} --items {} --format json --out {}",
                    superscalar_env_prefix(spec.force_proto, spec.disable_proto),
                    spec.config,
                    spec.impl_kind,
                    DEFAULT_SUPERSCALAR_ITERS,
                    DEFAULT_SUPERSCALAR_WARMUP,
                    DEFAULT_SUPERSCALAR_ITEMS,
                    json_name
                ),
            )?;
            let json_value = serde_json::from_str::<Value>(&capture.json)
                .map_err(|e| format!("invalid superscalar JSON: {e}"))?;
            Ok(SuperscalarCapture {
                label: spec.label.to_string(),
                csv_name,
                json_name,
                summary_line: format!(
                    "{} elapsed_ms={:.1}",
                    capture.summary,
                    started.elapsed().as_secs_f64() * 1000.0
                ),
                json_value,
            })
        })?;
        println!("stage=superscalar-run {} {}", run.label, run.summary_line);
        runs.push(run);
    }
    Ok(runs)
}

fn capture_perf_run(
    ctx: &CaptureContext<'_>,
    capture_kind: &'static str,
    feature_family: &'static str,
    run: RunConfig,
    page_profile: PageProfile,
    artifact_stem: &str,
) -> Result<CapturedRun, String> {
    append_command_log(
        &ctx.commands_path,
        &equivalent_perf_harness_command(ctx, run, page_profile, artifact_stem),
    )?;

    let started = Instant::now();
    let capture = with_capture_env(run, page_profile, || {
        perf_harness_support::capture(&perf_harness_support::CaptureSpec {
            mode: run.mode.as_str(),
            iters: ctx.options.perf_iters,
            warmup: ctx.options.perf_warmup,
            threads: ctx.options.threads,
            jit: run.jit,
            jit_fast_regs: run.jit_fast_regs,
            large_pages: page_profile.large_pages,
            use_1gb_pages: page_profile.use_1gb_pages,
        })
    })?;
    let elapsed = started.elapsed();

    let (csv_header, csv_fields) = parse_single_row_csv(&capture.csv)?;
    let json_value =
        serde_json::from_str::<Value>(&capture.json).map_err(|e| format!("invalid JSON: {e}"))?;
    let (csv_header, csv_fields, json_value) =
        sanitize_perf_artifacts(ctx.surface, &csv_header, &csv_fields, json_value);

    let csv_name = format!("{artifact_stem}.csv");
    let json_name = format!("{artifact_stem}.json");
    write_artifact(
        &ctx.out_dir.join(&csv_name),
        csv_from_fields(&csv_header, &csv_fields),
    )?;
    let json_body = serde_json::to_string_pretty(&json_value).map_err(|e| e.to_string())?;
    write_artifact(&ctx.out_dir.join(&json_name), json_body)?;

    Ok(CapturedRun {
        capture_kind,
        feature_family,
        label: run.key.to_string(),
        config: run.config.to_string(),
        mode: run.mode.display().to_string(),
        page_profile: page_profile.key.to_string(),
        page_profile_role: page_profile.role.as_str().to_string(),
        runtime_profile: run.state.display(),
        runtime_jit_flags: runtime_jit_flags(run).to_string(),
        csv_name,
        json_name,
        summary_line: capture.summary,
        csv_header,
        csv_fields,
        elapsed,
    })
}

fn capture_pair_run(
    ctx: &CaptureContext<'_>,
    spec: PairSpec,
    page_profile: PageProfile,
    seq: &str,
    state: FeatureState,
) -> Result<CapturedRun, String> {
    let run = RunConfig {
        key: spec.run.key,
        config: spec.run.config,
        mode: spec.run.mode,
        jit: spec.run.jit,
        jit_fast_regs: spec.run.jit_fast_regs,
        state,
    };
    let pair_key = compact_key(spec.pair_label);
    let run_key = compact_key(spec.run.key);
    let stem = format!(
        "{ABBA_RUNS_DIR}/{}/{}/{}/{}/{}",
        spec.family, pair_key, run_key, page_profile.key, seq
    );
    capture_perf_run(ctx, "abba", spec.family, run, page_profile, &stem)
}

fn with_capture_env<T>(
    run: RunConfig,
    page_profile: PageProfile,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let guard = CaptureEnvGuard::set(&[
        (FAST_BENCH_ENV, run.mode.uses_fast_env().then_some("1")),
        (HUGE_1G_ENV, page_profile.use_1gb_pages.then_some("1")),
        (
            THREADED_INTERP_ENV,
            run.state.threaded_interp.then_some("1"),
        ),
        (
            SIMD_BLOCKIO_FORCE_ENV,
            matches!(run.state.simd_blockio, SimdBlockioState::Forced).then_some("1"),
        ),
        (
            SIMD_BLOCKIO_DISABLE_ENV,
            matches!(run.state.simd_blockio, SimdBlockioState::Disabled).then_some("1"),
        ),
        (SIMD_XOR_FORCE_ENV, run.state.simd_xor.then_some("1")),
        (SIMD_XOR_DISABLE_ENV, (!run.state.simd_xor).then_some("1")),
        (
            SUPERSCALAR_FORCE_ENV,
            run.state.superscalar_proto.then_some("1"),
        ),
        (
            SUPERSCALAR_DISABLE_ENV,
            (!run.state.superscalar_proto).then_some("1"),
        ),
        (FAST_BENCH_SMALL_ENV, None),
    ]);
    let result = op();
    drop(guard);
    result
}

fn with_superscalar_env<T>(
    force_proto: bool,
    disable_proto: bool,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let guard = CaptureEnvGuard::set(&[
        (SUPERSCALAR_FORCE_ENV, force_proto.then_some("1")),
        (SUPERSCALAR_DISABLE_ENV, disable_proto.then_some("1")),
    ]);
    let result = op();
    drop(guard);
    result
}

struct CaptureEnvGuard {
    prev: Vec<(&'static str, Option<OsString>)>,
}

impl CaptureEnvGuard {
    fn set(values: &[(&'static str, Option<&'static str>)]) -> Self {
        let prev = values
            .iter()
            .map(|(name, _)| (*name, env::var_os(name)))
            .collect::<Vec<_>>();
        for (name, value) in values {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
        Self { prev }
    }
}

impl Drop for CaptureEnvGuard {
    fn drop(&mut self) {
        for (name, value) in self.prev.drain(..) {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
    }
}

fn equivalent_perf_harness_command(
    ctx: &CaptureContext<'_>,
    run: RunConfig,
    page_profile: PageProfile,
    artifact_stem: &str,
) -> String {
    let mut env_parts = Vec::new();
    if run.mode.uses_fast_env() {
        env_parts.push(format!("{FAST_BENCH_ENV}=1"));
    }
    if page_profile.use_1gb_pages {
        env_parts.push(format!("{HUGE_1G_ENV}=1"));
    } else {
        env_parts.push(format!("{HUGE_1G_ENV}=0"));
    }
    if run.state.threaded_interp {
        env_parts.push(format!("{THREADED_INTERP_ENV}=1"));
    }
    match run.state.simd_blockio {
        SimdBlockioState::Disabled => env_parts.push(format!("{SIMD_BLOCKIO_DISABLE_ENV}=1")),
        SimdBlockioState::Guarded => {}
        SimdBlockioState::Forced => env_parts.push(format!("{SIMD_BLOCKIO_FORCE_ENV}=1")),
    }
    if run.state.simd_xor {
        env_parts.push(format!("{SIMD_XOR_FORCE_ENV}=1"));
    } else {
        env_parts.push(format!("{SIMD_XOR_DISABLE_ENV}=1"));
    }
    if run.state.superscalar_proto {
        env_parts.push(format!("{SUPERSCALAR_FORCE_ENV}=1"));
    } else {
        env_parts.push(format!("{SUPERSCALAR_DISABLE_ENV}=1"));
    }
    format!(
        "{} perf_harness --mode {} --jit {} --jit-fast-regs {} --iters {} --warmup {} --threads {} --large-pages {} --thread-names off --affinity off --format json --out {}.json",
        env_parts.join(" "),
        run.mode.as_str(),
        if run.jit { "on" } else { "off" },
        if run.jit_fast_regs { "on" } else { "off" },
        ctx.options.perf_iters,
        ctx.options.perf_warmup,
        ctx.options.threads,
        if page_profile.large_pages { "on" } else { "off" },
        artifact_stem
    )
}

fn superscalar_env_prefix(force_proto: bool, disable_proto: bool) -> String {
    let mut parts = Vec::new();
    if force_proto {
        parts.push(format!("{SUPERSCALAR_FORCE_ENV}=1"));
    }
    if disable_proto {
        parts.push(format!("{SUPERSCALAR_DISABLE_ENV}=1"));
    }
    parts.join(" ")
}

fn write_pair_artifacts(
    ctx: &CaptureContext<'_>,
    spec: PairSpec,
    page_profile: PageProfile,
    runs: [&CapturedRun; 4],
) -> Result<PairSummary, String> {
    let [a1, b1, b2, a2] = runs;
    let a1_ns = required_f64(a1, "ns_per_hash")?;
    let b1_ns = required_f64(b1, "ns_per_hash")?;
    let b2_ns = required_f64(b2, "ns_per_hash")?;
    let a2_ns = required_f64(a2, "ns_per_hash")?;
    let baseline_mean = mean([a1_ns, a2_ns]);
    let candidate_mean = mean([b1_ns, b2_ns]);
    let baseline_prepare_mean = mean([
        required_f64(a1, "prepare_iteration_ns")?,
        required_f64(a2, "prepare_iteration_ns")?,
    ]);
    let candidate_prepare_mean = mean([
        required_f64(b1, "prepare_iteration_ns")?,
        required_f64(b2, "prepare_iteration_ns")?,
    ]);
    let baseline_execute_mean = mean([
        required_f64(a1, "execute_program_ns_interpreter")?,
        required_f64(a2, "execute_program_ns_interpreter")?,
    ]);
    let candidate_execute_mean = mean([
        required_f64(b1, "execute_program_ns_interpreter")?,
        required_f64(b2, "execute_program_ns_interpreter")?,
    ]);
    let baseline_finish_mean = mean([
        required_f64(a1, "finish_iteration_ns")?,
        required_f64(a2, "finish_iteration_ns")?,
    ]);
    let candidate_finish_mean = mean([
        required_f64(b1, "finish_iteration_ns")?,
        required_f64(b2, "finish_iteration_ns")?,
    ]);

    let pair_key = compact_key(spec.pair_label);
    let run_key = compact_key(spec.run.key);
    let pair_dir = format!(
        "{ABBA_PAIRS_DIR}/{}/{}/{}/{}",
        spec.family, pair_key, run_key, page_profile.key
    );
    let artifacts = PairArtifacts {
        baseline_combined_name: format!("{pair_dir}/baseline_combined.csv"),
        candidate_combined_name: format!("{pair_dir}/candidate_combined.csv"),
        pair_matrix_name: format!("{pair_dir}/pair_matrix.csv"),
        compare_name: format!("{pair_dir}/compare.txt"),
    };

    write_combined_csv(
        &ctx.out_dir.join(&artifacts.baseline_combined_name),
        &[a1, a2],
    )?;
    write_combined_csv(
        &ctx.out_dir.join(&artifacts.candidate_combined_name),
        &[b1, b2],
    )?;
    write_pair_matrix_csv(
        &ctx.out_dir.join(&artifacts.pair_matrix_name),
        spec,
        page_profile,
        runs,
    )?;
    let delta_pct_candidate_vs_baseline = pct_delta_f64(baseline_mean, candidate_mean);
    let pair_delta_a1_b1_pct = pct_delta_f64(a1_ns, b1_ns);
    let pair_delta_a2_b2_pct = pct_delta_f64(a2_ns, b2_ns);
    let baseline_drift_pct = pct_delta_f64(a1_ns, a2_ns);
    let candidate_drift_pct = pct_delta_f64(b1_ns, b2_ns);
    let signal_assessment = assess_pair_signal(
        delta_pct_candidate_vs_baseline,
        pair_delta_a1_b1_pct,
        pair_delta_a2_b2_pct,
        baseline_drift_pct,
        candidate_drift_pct,
    );
    let baseline_dataset_large_pages = observe_flag(&[a1, a2], "large_pages_dataset");
    let baseline_dataset_1gb_pages = observe_flag(&[a1, a2], "large_pages_1gb_dataset");
    let baseline_scratchpad_large_pages = observe_flag(&[a1, a2], "large_pages_scratchpad");
    let baseline_scratchpad_1gb_pages = observe_flag(&[a1, a2], "large_pages_1gb_scratchpad");
    let candidate_dataset_large_pages = observe_flag(&[b1, b2], "large_pages_dataset");
    let candidate_dataset_1gb_pages = observe_flag(&[b1, b2], "large_pages_1gb_dataset");
    let candidate_scratchpad_large_pages = observe_flag(&[b1, b2], "large_pages_scratchpad");
    let candidate_scratchpad_1gb_pages = observe_flag(&[b1, b2], "large_pages_1gb_scratchpad");

    let summary = PairSummary {
        pair_label: spec.pair_label.to_string(),
        family: spec.family.to_string(),
        config: spec.run.config.to_string(),
        mode: spec.run.mode.display().to_string(),
        page_profile: page_profile.key.to_string(),
        page_profile_role: page_profile.role.as_str().to_string(),
        baseline_label: spec.baseline_label.to_string(),
        candidate_label: spec.candidate_label.to_string(),
        baseline_dataset_large_pages_status: baseline_dataset_large_pages
            .status
            .as_str()
            .to_string(),
        baseline_dataset_1gb_pages_status: baseline_dataset_1gb_pages.status.as_str().to_string(),
        baseline_scratchpad_large_pages_status: baseline_scratchpad_large_pages
            .status
            .as_str()
            .to_string(),
        baseline_scratchpad_1gb_pages_status: baseline_scratchpad_1gb_pages
            .status
            .as_str()
            .to_string(),
        candidate_dataset_large_pages_status: candidate_dataset_large_pages
            .status
            .as_str()
            .to_string(),
        candidate_dataset_1gb_pages_status: candidate_dataset_1gb_pages.status.as_str().to_string(),
        candidate_scratchpad_large_pages_status: candidate_scratchpad_large_pages
            .status
            .as_str()
            .to_string(),
        candidate_scratchpad_1gb_pages_status: candidate_scratchpad_1gb_pages
            .status
            .as_str()
            .to_string(),
        baseline_mean_ns_per_hash: baseline_mean,
        candidate_mean_ns_per_hash: candidate_mean,
        delta_pct_candidate_vs_baseline,
        pair_delta_a1_b1_pct,
        pair_delta_a2_b2_pct,
        baseline_drift_pct,
        candidate_drift_pct,
        stage_delta_prepare_pct: pct_delta_f64(baseline_prepare_mean, candidate_prepare_mean),
        stage_delta_execute_pct: pct_delta_f64(baseline_execute_mean, candidate_execute_mean),
        stage_delta_finish_pct: pct_delta_f64(baseline_finish_mean, candidate_finish_mean),
        signal_classification: signal_assessment.classification.to_string(),
        signal_threshold_pct: signal_assessment.threshold_pct,
        signal_noise_floor_pct: signal_assessment.noise_floor_pct,
        signal_pair_spread_pct: signal_assessment.pair_spread_pct,
        signal_direction_consistent: signal_assessment.direction_consistent,
        artifacts,
    };

    write_compare_txt(
        &ctx.out_dir.join(&summary.artifacts.compare_name),
        &summary,
        runs,
    )?;

    Ok(summary)
}

fn write_combined_csv(path: &Path, runs: &[&CapturedRun]) -> Result<(), String> {
    let header = runs
        .first()
        .ok_or_else(|| "combined CSV requires at least one run".to_string())?
        .csv_header
        .join(",");
    let mut body = String::new();
    body.push_str(&header);
    body.push('\n');
    for run in runs {
        body.push_str(&csv_row_from_fields(&run.csv_header, &run.csv_fields));
        body.push('\n');
    }
    write_artifact(path, body)
}

fn write_pair_matrix_csv(
    path: &Path,
    spec: PairSpec,
    page_profile: PageProfile,
    runs: [&CapturedRun; 4],
) -> Result<(), String> {
    let mut body = String::from(
        "pair_label,mode,config,page_profile,seq,state_label,csv_artifact,json_artifact,ns_per_hash,hashes_per_sec,prepare_iteration_ns,execute_program_ns_interpreter,finish_iteration_ns\n",
    );
    for (seq, state_label, run) in [
        ("a1", spec.baseline_label, runs[0]),
        ("b1", spec.candidate_label, runs[1]),
        ("b2", spec.candidate_label, runs[2]),
        ("a2", spec.baseline_label, runs[3]),
    ] {
        writeln!(
            &mut body,
            "{},{},{},{},{},{},{},{},{:.3},{:.6},{:.3},{:.3},{:.3}",
            spec.pair_label,
            spec.run.mode.display(),
            spec.run.config,
            page_profile.key,
            seq,
            state_label,
            run.csv_name,
            run.json_name,
            required_f64(run, "ns_per_hash")?,
            required_f64(run, "hashes_per_sec")?,
            required_f64(run, "prepare_iteration_ns")?,
            required_f64(run, "execute_program_ns_interpreter")?,
            required_f64(run, "finish_iteration_ns")?,
        )
        .map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn write_compare_txt(
    path: &Path,
    summary: &PairSummary,
    runs: [&CapturedRun; 4],
) -> Result<(), String> {
    let mut body = String::new();
    writeln!(&mut body, "pair_label={}", summary.pair_label).map_err(|e| e.to_string())?;
    writeln!(&mut body, "mode={}", summary.mode).map_err(|e| e.to_string())?;
    writeln!(&mut body, "config={}", summary.config).map_err(|e| e.to_string())?;
    writeln!(&mut body, "page_profile={}", summary.page_profile).map_err(|e| e.to_string())?;
    writeln!(&mut body, "page_profile_role={}", summary.page_profile_role)
        .map_err(|e| e.to_string())?;
    writeln!(&mut body, "baseline_label={}", summary.baseline_label).map_err(|e| e.to_string())?;
    writeln!(&mut body, "candidate_label={}", summary.candidate_label)
        .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "baseline_dataset_large_pages_status={}",
        summary.baseline_dataset_large_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "baseline_dataset_1gb_pages_status={}",
        summary.baseline_dataset_1gb_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "baseline_scratchpad_large_pages_status={}",
        summary.baseline_scratchpad_large_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "baseline_scratchpad_1gb_pages_status={}",
        summary.baseline_scratchpad_1gb_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "candidate_dataset_large_pages_status={}",
        summary.candidate_dataset_large_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "candidate_dataset_1gb_pages_status={}",
        summary.candidate_dataset_1gb_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "candidate_scratchpad_large_pages_status={}",
        summary.candidate_scratchpad_large_pages_status
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "candidate_scratchpad_1gb_pages_status={}",
        summary.candidate_scratchpad_1gb_pages_status
    )
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
        "pair_delta_a1_b1_pct={:+.3}",
        summary.pair_delta_a1_b1_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "pair_delta_a2_b2_pct={:+.3}",
        summary.pair_delta_a2_b2_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "baseline_drift_pct={:+.3}",
        summary.baseline_drift_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "candidate_drift_pct={:+.3}",
        summary.candidate_drift_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "stage_delta_prepare_pct={:+.3}",
        summary.stage_delta_prepare_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "stage_delta_execute_pct={:+.3}",
        summary.stage_delta_execute_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "stage_delta_finish_pct={:+.3}",
        summary.stage_delta_finish_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_classification={}",
        summary.signal_classification
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_threshold_pct={:.3}",
        summary.signal_threshold_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_noise_floor_pct={:.3}",
        summary.signal_noise_floor_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_pair_spread_pct={:.3}",
        summary.signal_pair_spread_pct
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_direction_consistent={}",
        summary.signal_direction_consistent
    )
    .map_err(|e| e.to_string())?;
    writeln!(
        &mut body,
        "signal_rule=likely_signal requires direction_consistent=true and abs(delta_pct_candidate_vs_baseline) >= signal_threshold_pct, where signal_threshold_pct=max(1.0, 2.0*signal_noise_floor_pct)"
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
            "{} ns_per_hash={:.3} hashes_per_sec={:.6} csv={} json={}",
            seq,
            required_f64(run, "ns_per_hash")?,
            required_f64(run, "hashes_per_sec")?,
            run.csv_name,
            run.json_name
        )
        .map_err(|e| e.to_string())?;
    }
    write_artifact(path, body)
}

fn matrix_index_fields() -> &'static [&'static str] {
    &[
        "release_id",
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

fn runtime_jit_flags(run: RunConfig) -> &'static str {
    match (run.jit, run.jit_fast_regs) {
        (false, false) => "--jit off",
        (true, false) => "--jit on --jit-fast-regs off",
        (true, true) => "--jit on --jit-fast-regs on",
        (false, true) => "--jit off",
    }
}

fn page_backing_observation_json(observation: &PageBackingObservation) -> Value {
    json!({
        "status": observation.status.as_str(),
        "true_count": observation.true_count,
        "false_count": observation.false_count,
        "unknown_count": observation.unknown_count,
    })
}

fn print_run_status(stage: &str, run: &CapturedRun) {
    let prepare = run
        .csv_fields
        .get("prepare_iteration_ns")
        .map(String::as_str)
        .unwrap_or("n/a");
    let execute = run
        .csv_fields
        .get("execute_program_ns_interpreter")
        .map(String::as_str)
        .unwrap_or("n/a");
    let finish = run
        .csv_fields
        .get("finish_iteration_ns")
        .map(String::as_str)
        .unwrap_or("n/a");
    let dataset_pages = run
        .csv_fields
        .get("large_pages_dataset")
        .map(String::as_str)
        .unwrap_or("n/a");
    let scratchpad_pages = run
        .csv_fields
        .get("large_pages_scratchpad")
        .map(String::as_str)
        .unwrap_or("n/a");
    let dataset_1g = run
        .csv_fields
        .get("large_pages_1gb_dataset")
        .map(String::as_str)
        .unwrap_or("n/a");
    let scratchpad_1g = run
        .csv_fields
        .get("large_pages_1gb_scratchpad")
        .map(String::as_str)
        .unwrap_or("n/a");
    println!(
        "stage={} label={} page={} page_role={} profile={} elapsed_ms={:.1} {} prepare_ns={} execute_ns={} finish_ns={} dataset_large_pages={} dataset_1gb_pages={} scratchpad_large_pages={} scratchpad_1gb_pages={}",
        stage,
        run.label,
        run.page_profile,
        run.page_profile_role,
        run.runtime_profile,
        run.elapsed.as_secs_f64() * 1000.0,
        run.summary_line,
        prepare,
        execute,
        finish,
        dataset_pages,
        dataset_1g,
        scratchpad_pages,
        scratchpad_1g
    );
}

fn observe_flag(runs: &[&CapturedRun], field: &str) -> PageBackingObservation {
    let mut true_count = 0usize;
    let mut false_count = 0usize;
    let mut unknown_count = 0usize;

    for run in runs {
        match run
            .csv_fields
            .get(field)
            .and_then(|value| parse_observed_bool(value))
        {
            Some(true) => true_count += 1,
            Some(false) => false_count += 1,
            None => unknown_count += 1,
        }
    }

    let status = match (true_count, false_count) {
        (0, 0) => ObservedFlagStatus::Unknown,
        (_, 0) => ObservedFlagStatus::AllTrue,
        (0, _) => ObservedFlagStatus::AllFalse,
        _ => ObservedFlagStatus::Mixed,
    };

    PageBackingObservation {
        status,
        true_count,
        false_count,
        unknown_count,
    }
}

fn parse_observed_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
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

fn csv_row_from_fields(header: &[String], fields: &BTreeMap<String, String>) -> String {
    header
        .iter()
        .map(|column| csv_escape(fields.get(column).map(String::as_str).unwrap_or("")))
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_from_fields(header: &[String], fields: &BTreeMap<String, String>) -> String {
    format!(
        "{}\n{}\n",
        header.join(","),
        csv_row_from_fields(header, fields)
    )
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

fn required_f64(run: &CapturedRun, field: &str) -> Result<f64, String> {
    run.csv_fields
        .get(field)
        .ok_or_else(|| format!("missing field '{field}' for {}", run.label))?
        .parse::<f64>()
        .map_err(|_| format!("invalid field '{field}' for {}", run.label))
}

fn mean<const N: usize>(values: [f64; N]) -> f64 {
    values.iter().copied().sum::<f64>() / values.len() as f64
}

fn pct_delta_f64(baseline: f64, candidate: f64) -> f64 {
    if baseline == 0.0 {
        0.0
    } else {
        ((candidate - baseline) / baseline) * 100.0
    }
}

fn assess_pair_signal(
    delta_pct_candidate_vs_baseline: f64,
    pair_delta_a1_b1_pct: f64,
    pair_delta_a2_b2_pct: f64,
    baseline_drift_pct: f64,
    candidate_drift_pct: f64,
) -> PairSignalAssessment {
    let pair_spread_pct = (pair_delta_a1_b1_pct - pair_delta_a2_b2_pct).abs();
    let noise_floor_pct = pair_spread_pct
        .max(baseline_drift_pct.abs())
        .max(candidate_drift_pct.abs());
    let threshold_pct = (noise_floor_pct * 2.0).max(1.0);
    let direction_consistent = same_nonzero_sign([
        delta_pct_candidate_vs_baseline,
        pair_delta_a1_b1_pct,
        pair_delta_a2_b2_pct,
    ]);
    let classification =
        if direction_consistent && delta_pct_candidate_vs_baseline.abs() >= threshold_pct {
            SIGNAL_CLASS_LIKELY_SIGNAL
        } else {
            SIGNAL_CLASS_LIKELY_NOISE
        };

    PairSignalAssessment {
        classification,
        threshold_pct,
        noise_floor_pct,
        pair_spread_pct,
        direction_consistent,
    }
}

fn same_nonzero_sign<const N: usize>(values: [f64; N]) -> bool {
    values.iter().all(|value| *value > 0.0) || values.iter().all(|value| *value < 0.0)
}

fn sanitize_perf_artifacts(
    surface: CaptureSurface<'_>,
    csv_header: &[String],
    csv_fields: &BTreeMap<String, String>,
    mut json_value: Value,
) -> (Vec<String>, BTreeMap<String, String>, Value) {
    match surface {
        CaptureSurface::Internal => (csv_header.to_vec(), csv_fields.clone(), json_value),
        CaptureSurface::Public { release_id } => {
            let mut header = Vec::new();
            let mut fields = BTreeMap::new();
            for column in csv_header {
                if matches!(column.as_str(), "git_sha" | "git_sha_short" | "git_dirty") {
                    continue;
                }
                header.push(column.clone());
                if let Some(value) = csv_fields.get(column) {
                    fields.insert(column.clone(), value.clone());
                }
            }
            header.push("release_id".to_string());
            fields.insert("release_id".to_string(), release_id.to_string());

            if let Some(root) = json_value.as_object_mut() {
                if let Some(provenance) = root.get_mut("provenance").and_then(Value::as_object_mut)
                {
                    provenance.remove("git_sha");
                    provenance.remove("git_sha_short");
                    provenance.remove("git_dirty");
                    provenance.insert(
                        "release_id".to_string(),
                        Value::String(release_id.to_string()),
                    );
                }
                root.insert(
                    "release_id".to_string(),
                    Value::String(release_id.to_string()),
                );
            }

            (header, fields, json_value)
        }
    }
}

fn full_matrix_specs() -> Vec<MatrixSpec> {
    let baseline = FeatureState::baseline();
    let threaded = FeatureState {
        threaded_interp: true,
        ..baseline
    };
    let simd_guarded = FeatureState {
        simd_blockio: SimdBlockioState::Guarded,
        ..baseline
    };
    let simd_forced = FeatureState {
        simd_blockio: SimdBlockioState::Forced,
        ..baseline
    };
    let simd_xor = FeatureState {
        simd_blockio: SimdBlockioState::Forced,
        simd_xor: true,
        ..baseline
    };
    let superscalar = FeatureState {
        superscalar_proto: true,
        ..baseline
    };

    vec![
        MatrixSpec {
            label: "light_interp_baseline",
            category: "baseline_matrix",
            run: RunConfig {
                key: "light_interp_baseline",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
        },
        MatrixSpec {
            label: "light_jit_conservative_baseline",
            category: "baseline_matrix",
            run: RunConfig {
                key: "light_jit_conservative_baseline",
                config: "JIT conservative",
                mode: ModeKey::Light,
                jit: true,
                jit_fast_regs: false,
                state: baseline,
            },
        },
        MatrixSpec {
            label: "light_jit_fastregs_baseline",
            category: "baseline_matrix",
            run: RunConfig {
                key: "light_jit_fastregs_baseline",
                config: "JIT fast-regs",
                mode: ModeKey::Light,
                jit: true,
                jit_fast_regs: true,
                state: baseline,
            },
        },
        MatrixSpec {
            label: "fast_interp_baseline",
            category: "baseline_matrix",
            run: RunConfig {
                key: "fast_interp_baseline",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
        },
        MatrixSpec {
            label: "fast_jit_conservative_baseline",
            category: "baseline_matrix",
            run: RunConfig {
                key: "fast_jit_conservative_baseline",
                config: "JIT conservative",
                mode: ModeKey::Fast,
                jit: true,
                jit_fast_regs: false,
                state: baseline,
            },
        },
        MatrixSpec {
            label: "fast_jit_fastregs_baseline",
            category: "baseline_matrix",
            run: RunConfig {
                key: "fast_jit_fastregs_baseline",
                config: "JIT fast-regs",
                mode: ModeKey::Fast,
                jit: true,
                jit_fast_regs: true,
                state: baseline,
            },
        },
        MatrixSpec {
            label: "light_interp_threaded_candidate",
            category: "threaded_interp",
            run: RunConfig {
                key: "light_interp_threaded_candidate",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: threaded,
            },
        },
        MatrixSpec {
            label: "light_interp_simd_guarded",
            category: "simd_blockio",
            run: RunConfig {
                key: "light_interp_simd_guarded",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: simd_guarded,
            },
        },
        MatrixSpec {
            label: "fast_interp_simd_guarded",
            category: "simd_blockio",
            run: RunConfig {
                key: "fast_interp_simd_guarded",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: simd_guarded,
            },
        },
        MatrixSpec {
            label: "light_interp_simd_forced",
            category: "simd_blockio",
            run: RunConfig {
                key: "light_interp_simd_forced",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: simd_forced,
            },
        },
        MatrixSpec {
            label: "fast_interp_simd_forced",
            category: "simd_blockio",
            run: RunConfig {
                key: "fast_interp_simd_forced",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: simd_forced,
            },
        },
        MatrixSpec {
            label: "light_interp_simd_xor",
            category: "simd_xor_paths",
            run: RunConfig {
                key: "light_interp_simd_xor",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: simd_xor,
            },
        },
        MatrixSpec {
            label: "fast_interp_simd_xor",
            category: "simd_xor_paths",
            run: RunConfig {
                key: "fast_interp_simd_xor",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: simd_xor,
            },
        },
        MatrixSpec {
            label: "light_interp_superscalar_proto",
            category: "superscalar_proto",
            run: RunConfig {
                key: "light_interp_superscalar_proto",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: superscalar,
            },
        },
        MatrixSpec {
            label: "light_jit_conservative_superscalar_proto",
            category: "superscalar_proto",
            run: RunConfig {
                key: "light_jit_conservative_superscalar_proto",
                config: "JIT conservative",
                mode: ModeKey::Light,
                jit: true,
                jit_fast_regs: false,
                state: superscalar,
            },
        },
        MatrixSpec {
            label: "light_jit_fastregs_superscalar_proto",
            category: "superscalar_proto",
            run: RunConfig {
                key: "light_jit_fastregs_superscalar_proto",
                config: "JIT fast-regs",
                mode: ModeKey::Light,
                jit: true,
                jit_fast_regs: true,
                state: superscalar,
            },
        },
        MatrixSpec {
            label: "fast_jit_conservative_superscalar_proto",
            category: "superscalar_proto",
            run: RunConfig {
                key: "fast_jit_conservative_superscalar_proto",
                config: "JIT conservative",
                mode: ModeKey::Fast,
                jit: true,
                jit_fast_regs: false,
                state: superscalar,
            },
        },
        MatrixSpec {
            label: "fast_jit_fastregs_superscalar_proto",
            category: "superscalar_proto",
            run: RunConfig {
                key: "fast_jit_fastregs_superscalar_proto",
                config: "JIT fast-regs",
                mode: ModeKey::Fast,
                jit: true,
                jit_fast_regs: true,
                state: superscalar,
            },
        },
    ]
}

fn full_pair_specs() -> Vec<PairSpec> {
    let baseline = FeatureState::baseline();
    let threaded = FeatureState {
        threaded_interp: true,
        ..baseline
    };
    let simd_guarded = FeatureState {
        simd_blockio: SimdBlockioState::Guarded,
        ..baseline
    };
    let simd_forced = FeatureState {
        simd_blockio: SimdBlockioState::Forced,
        ..baseline
    };
    let simd_xor = FeatureState {
        simd_blockio: SimdBlockioState::Forced,
        simd_xor: true,
        ..baseline
    };
    let superscalar = FeatureState {
        superscalar_proto: true,
        ..baseline
    };

    vec![
        PairSpec {
            pair_label: "baseline_vs_threaded",
            family: "threaded_interp",
            baseline_label: "baseline_scalar",
            candidate_label: "threaded_enabled",
            run: RunConfig {
                key: "light_interp",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: threaded,
        },
        PairSpec {
            pair_label: "baseline_vs_guarded",
            family: "simd_blockio",
            baseline_label: "baseline_scalar",
            candidate_label: "guarded_default",
            run: RunConfig {
                key: "light_interp",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: simd_guarded,
        },
        PairSpec {
            pair_label: "baseline_vs_guarded",
            family: "simd_blockio",
            baseline_label: "baseline_scalar",
            candidate_label: "guarded_default",
            run: RunConfig {
                key: "fast_interp",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: simd_guarded,
        },
        PairSpec {
            pair_label: "guarded_vs_forced",
            family: "simd_blockio",
            baseline_label: "guarded_default",
            candidate_label: "forced_investigation",
            run: RunConfig {
                key: "light_interp",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: simd_guarded,
            },
            baseline: simd_guarded,
            candidate: simd_forced,
        },
        PairSpec {
            pair_label: "guarded_vs_forced",
            family: "simd_blockio",
            baseline_label: "guarded_default",
            candidate_label: "forced_investigation",
            run: RunConfig {
                key: "fast_interp",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: simd_guarded,
            },
            baseline: simd_guarded,
            candidate: simd_forced,
        },
        PairSpec {
            pair_label: "baseline_vs_forced",
            family: "simd_blockio",
            baseline_label: "baseline_scalar",
            candidate_label: "forced_investigation",
            run: RunConfig {
                key: "light_interp",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: simd_forced,
        },
        PairSpec {
            pair_label: "baseline_vs_forced",
            family: "simd_blockio",
            baseline_label: "baseline_scalar",
            candidate_label: "forced_investigation",
            run: RunConfig {
                key: "fast_interp",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: simd_forced,
        },
        PairSpec {
            pair_label: "simd_forced_vs_simd_xor",
            family: "simd_xor_paths",
            baseline_label: "simd_forced",
            candidate_label: "simd_xor_enabled",
            run: RunConfig {
                key: "light_interp",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: simd_forced,
            },
            baseline: simd_forced,
            candidate: simd_xor,
        },
        PairSpec {
            pair_label: "simd_forced_vs_simd_xor",
            family: "simd_xor_paths",
            baseline_label: "simd_forced",
            candidate_label: "simd_xor_enabled",
            run: RunConfig {
                key: "fast_interp",
                config: "Interpreter",
                mode: ModeKey::Fast,
                jit: false,
                jit_fast_regs: false,
                state: simd_forced,
            },
            baseline: simd_forced,
            candidate: simd_xor,
        },
        PairSpec {
            pair_label: "baseline_vs_superscalar_proto",
            family: "superscalar_proto",
            baseline_label: "baseline",
            candidate_label: "superscalar_proto",
            run: RunConfig {
                key: "light_interp",
                config: "Interpreter",
                mode: ModeKey::Light,
                jit: false,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: superscalar,
        },
        PairSpec {
            pair_label: "baseline_vs_superscalar_proto",
            family: "superscalar_proto",
            baseline_label: "baseline",
            candidate_label: "superscalar_proto",
            run: RunConfig {
                key: "light_jit_conservative",
                config: "JIT conservative",
                mode: ModeKey::Light,
                jit: true,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: superscalar,
        },
        PairSpec {
            pair_label: "baseline_vs_superscalar_proto",
            family: "superscalar_proto",
            baseline_label: "baseline",
            candidate_label: "superscalar_proto",
            run: RunConfig {
                key: "light_jit_fastregs",
                config: "JIT fast-regs",
                mode: ModeKey::Light,
                jit: true,
                jit_fast_regs: true,
                state: baseline,
            },
            baseline,
            candidate: superscalar,
        },
        PairSpec {
            pair_label: "baseline_vs_superscalar_proto",
            family: "superscalar_proto",
            baseline_label: "baseline",
            candidate_label: "superscalar_proto",
            run: RunConfig {
                key: "fast_jit_conservative",
                config: "JIT conservative",
                mode: ModeKey::Fast,
                jit: true,
                jit_fast_regs: false,
                state: baseline,
            },
            baseline,
            candidate: superscalar,
        },
        PairSpec {
            pair_label: "baseline_vs_superscalar_proto",
            family: "superscalar_proto",
            baseline_label: "baseline",
            candidate_label: "superscalar_proto",
            run: RunConfig {
                key: "fast_jit_fastregs",
                config: "JIT fast-regs",
                mode: ModeKey::Fast,
                jit: true,
                jit_fast_regs: true,
                state: baseline,
            },
            baseline,
            candidate: superscalar,
        },
    ]
}

fn superscalar_specs() -> Vec<SuperscalarSpec> {
    vec![
        SuperscalarSpec {
            label: "baseline_active",
            config: "default",
            impl_kind: "active",
            force_proto: false,
            disable_proto: true,
        },
        SuperscalarSpec {
            label: "proto_active",
            config: "default",
            impl_kind: "active",
            force_proto: true,
            disable_proto: false,
        },
        SuperscalarSpec {
            label: "proto_scalar",
            config: "default",
            impl_kind: "scalar",
            force_proto: true,
            disable_proto: false,
        },
    ]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_run(
        page_profile: &str,
        page_profile_role: &str,
        extra_fields: &[(&str, &str)],
    ) -> CapturedRun {
        let mut csv_header = vec![
            "ns_per_hash".to_string(),
            "hashes_per_sec".to_string(),
            "prepare_iteration_ns".to_string(),
            "execute_program_ns_interpreter".to_string(),
            "finish_iteration_ns".to_string(),
            "large_pages_dataset".to_string(),
            "large_pages_1gb_dataset".to_string(),
            "large_pages_scratchpad".to_string(),
            "large_pages_1gb_scratchpad".to_string(),
        ];
        let mut csv_fields = BTreeMap::from([
            ("ns_per_hash".to_string(), "100.0".to_string()),
            ("hashes_per_sec".to_string(), "10.0".to_string()),
            ("prepare_iteration_ns".to_string(), "10.0".to_string()),
            (
                "execute_program_ns_interpreter".to_string(),
                "20.0".to_string(),
            ),
            ("finish_iteration_ns".to_string(), "30.0".to_string()),
            ("large_pages_dataset".to_string(), "true".to_string()),
            ("large_pages_1gb_dataset".to_string(), "false".to_string()),
            ("large_pages_scratchpad".to_string(), "true".to_string()),
            (
                "large_pages_1gb_scratchpad".to_string(),
                "false".to_string(),
            ),
        ]);
        for (column, value) in extra_fields {
            if !csv_header.iter().any(|existing| existing == column) {
                csv_header.push((*column).to_string());
            }
            csv_fields.insert((*column).to_string(), (*value).to_string());
        }

        CapturedRun {
            capture_kind: "matrix",
            feature_family: "baseline_matrix",
            label: "test".to_string(),
            config: "Interpreter".to_string(),
            mode: "Light".to_string(),
            page_profile: page_profile.to_string(),
            page_profile_role: page_profile_role.to_string(),
            runtime_profile: "baseline".to_string(),
            runtime_jit_flags: "--jit off".to_string(),
            csv_name: "matrix/test.csv".to_string(),
            json_name: "matrix/test.json".to_string(),
            summary_line: "summary".to_string(),
            csv_header,
            csv_fields,
            elapsed: Duration::from_millis(123),
        }
    }

    #[test]
    fn public_standard_plan_has_expected_scope() {
        let windows = public_capture_plan(PublicCaptureProfile::Standard, HostOsClass::Windows);
        let linux = public_capture_plan(PublicCaptureProfile::Standard, HostOsClass::Linux);

        assert_eq!(windows.matrix_specs.len(), 6);
        assert_eq!(linux.matrix_specs.len(), 6);
        assert_eq!(windows.pair_specs.len(), 8);
        assert_eq!(linux.pair_specs.len(), 8);
        assert!(windows.pair_specs.iter().all(|spec| matches!(
            spec.family,
            "threaded_interp" | "simd_blockio" | "superscalar_proto"
        )));
        assert!(linux
            .page_profiles
            .iter()
            .any(|profile| profile.key == "huge_1g_requested"));
    }

    #[test]
    fn summarize_page_backing_reports_mixed_realization() {
        let profile = PageProfile {
            key: "large_pages_on",
            display: "large pages on",
            large_pages: true,
            use_1gb_pages: false,
            abba_primary: true,
            role: PageProfileRole::AuthorityPrimary,
        };
        let matrix_runs = vec![
            test_run(
                "large_pages_on",
                "authority_primary",
                &[("large_pages_dataset", "true")],
            ),
            test_run(
                "large_pages_on",
                "authority_primary",
                &[("large_pages_dataset", "false")],
            ),
        ];

        let summaries = summarize_page_backing(&[profile], &matrix_runs, &[]);
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].dataset_large_pages.status,
            ObservedFlagStatus::Mixed
        );
        assert_eq!(
            summaries[0].scratchpad_large_pages.status,
            ObservedFlagStatus::AllTrue
        );
        assert_eq!(summaries[0].observed_run_count, 2);
    }

    #[test]
    fn public_surface_sanitizes_git_provenance() {
        let header = vec![
            "git_sha".to_string(),
            "git_sha_short".to_string(),
            "git_dirty".to_string(),
            "ns_per_hash".to_string(),
        ];
        let fields = BTreeMap::from([
            ("git_sha".to_string(), "abcdef".to_string()),
            ("git_sha_short".to_string(), "abc1234".to_string()),
            ("git_dirty".to_string(), "false".to_string()),
            ("ns_per_hash".to_string(), "100".to_string()),
        ]);
        let json_value = json!({
            "provenance": {
                "git_sha": "abcdef",
                "git_sha_short": "abc1234",
                "git_dirty": "false",
                "rustc": "rustc test",
            }
        });

        let (header, fields, json_value) = sanitize_perf_artifacts(
            CaptureSurface::Public {
                release_id: "capture-2026-03",
            },
            &header,
            &fields,
            json_value,
        );

        assert!(!header.iter().any(|value| value == "git_sha"));
        assert_eq!(
            fields.get("release_id").map(String::as_str),
            Some("capture-2026-03")
        );
        assert!(json_value
            .get("provenance")
            .and_then(Value::as_object)
            .is_some_and(|provenance| provenance.get("git_sha").is_none()));
    }
}
