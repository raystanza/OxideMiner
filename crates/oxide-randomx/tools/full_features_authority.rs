use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const DEFAULT_INDEX_PATH: &str = "perf_results/full_features_authority_index_v9.json";
const PROVENANCE_ARTIFACT: &str = "meta/provenance.txt";
const PAIR_SUMMARY_ARTIFACT: &str = "meta/pair_summary.csv";
const MATRIX_INDEX_ARTIFACT: &str = "meta/matrix_index.csv";
const PRIMARY_ABBA_PAGE_PROFILE: &str = "large_pages_on";

fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(msg) => {
            eprintln!("error: {msg}");
            print_usage();
            process::exit(2);
        }
    };

    let repo_root = match find_repo_root() {
        Ok(root) => root,
        Err(msg) => {
            eprintln!("error: {msg}");
            process::exit(2);
        }
    };

    let result = match options.command {
        Command::ValidateIndex { index_path } => {
            let index_path = resolve_repo_path(&repo_root, &index_path);
            match load_authority_index(&index_path) {
                Ok(index) => match validate_index(&repo_root, &index_path, &index) {
                    Ok(report) => {
                        print_validation_report(&report);
                        Ok(())
                    }
                    Err(msg) => Err(msg),
                },
                Err(msg) => Err(msg),
            }
        }
        Command::Compare {
            index_path,
            capture_path,
        } => {
            let index_path = resolve_repo_path(&repo_root, &index_path);
            let capture_path = resolve_repo_path(&repo_root, &capture_path);
            match load_authority_index(&index_path) {
                Ok(index) => {
                    match compare_capture_to_index(&repo_root, &index_path, &index, &capture_path) {
                        Ok(report) => {
                            print_compare_report(&report);
                            Ok(())
                        }
                        Err(msg) => Err(msg),
                    }
                }
                Err(msg) => Err(msg),
            }
        }
    };

    if let Err(msg) = result {
        eprintln!("error: {msg}");
        process::exit(2);
    }
}

#[derive(Debug)]
struct Options {
    command: Command,
}

#[derive(Debug)]
enum Command {
    ValidateIndex {
        index_path: PathBuf,
    },
    Compare {
        index_path: PathBuf,
        capture_path: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct AuthorityIndex {
    schema_version: u32,
    workflow_version: String,
    artifact_kind: String,
    analysis_memo: String,
    entries: Vec<AuthorityEntry>,
}

#[derive(Debug, Deserialize)]
struct AuthorityEntry {
    host_class_id: String,
    label: String,
    authority_classification: EvidenceClass,
    authority_capture_path: String,
    #[serde(default)]
    related_captures: Vec<RelatedCapture>,
    provenance: IndexedProvenance,
    rerun_stability: RerunStability,
    #[serde(rename = "notes", default)]
    _notes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RelatedCapture {
    path: String,
    role: String,
    #[serde(rename = "note")]
    _note: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceClass {
    Authority,
    Supporting,
    Exploratory,
}

impl EvidenceClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Supporting => "supporting",
            Self::Exploratory => "exploratory",
        }
    }
}

#[derive(Debug, Deserialize)]
struct IndexedProvenance {
    vendor: String,
    family: u32,
    model: u32,
    stepping: u32,
    cpu_model_string: String,
    os_name: String,
    os_version: String,
    os_build_or_kernel: String,
    logical_threads: u32,
    threads: u32,
    page_profiles: Vec<String>,
    abba_page_profile: String,
    git_sha: String,
    git_sha_short: String,
    git_dirty: bool,
    rustc: String,
}

#[derive(Debug, Deserialize)]
struct RerunStability {
    status: String,
    expectation: RerunExpectation,
    note: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RerunExpectation {
    RepeatedSameShaRequired,
    SingleCaptureSufficient,
}

impl RerunExpectation {
    fn as_str(&self) -> &'static str {
        match self {
            Self::RepeatedSameShaRequired => "repeated_same_sha_required",
            Self::SingleCaptureSufficient => "single_capture_sufficient",
        }
    }
}

#[derive(Debug, Clone)]
struct CaptureArtifacts {
    root: PathBuf,
    provenance: CaptureProvenance,
    pair_summaries: BTreeMap<PairKey, PairSummaryRecord>,
    page_backing: BTreeMap<String, PageBackingSummary>,
}

#[derive(Debug, Clone)]
struct CaptureProvenance {
    host_class_id: Option<String>,
    vendor: String,
    family: u32,
    model: u32,
    stepping: Option<u32>,
    cpu_model_string: String,
    os_name: String,
    os_version: Option<String>,
    os_build_or_kernel: Option<String>,
    logical_threads: Option<u32>,
    threads: Option<u32>,
    perf_iters: Option<u32>,
    perf_warmup: Option<u32>,
    page_profiles: Vec<String>,
    abba_page_profile: Option<String>,
    git_sha: String,
    git_sha_short: Option<String>,
    git_dirty: Option<bool>,
    rustc: String,
    capture_evidence_tier: Option<String>,
    rerun_group_id: Option<String>,
}

impl CaptureProvenance {
    fn inferred_host_class_id(&self) -> Result<String, String> {
        if let Some(value) = self.host_class_id.as_ref() {
            if !value.trim().is_empty() {
                return Ok(value.clone());
            }
        }

        let vendor_prefix = match self.vendor.as_str() {
            "AuthenticAMD" => "amd".to_string(),
            "GenuineIntel" => "intel".to_string(),
            other => sanitize_id_component(other),
        };
        let os_class = infer_os_class(&self.os_name, self.os_build_or_kernel.as_deref())?;
        Ok(format!(
            "{vendor_prefix}_fam{}_mod{}_{}",
            self.family, self.model, os_class
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PairKey {
    pair_label: String,
    family: String,
    config: String,
    mode: String,
    page_profile: String,
}

impl PairKey {
    fn display_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.pair_label, self.family, self.config, self.mode, self.page_profile
        )
    }
}

#[derive(Debug, Clone)]
struct PairSummaryRecord {
    delta_pct_candidate_vs_baseline: f64,
    signal_classification: String,
    baseline_dataset_large_pages_status: Option<ObservedFlagStatus>,
    baseline_dataset_1gb_pages_status: Option<ObservedFlagStatus>,
    baseline_scratchpad_large_pages_status: Option<ObservedFlagStatus>,
    baseline_scratchpad_1gb_pages_status: Option<ObservedFlagStatus>,
    candidate_dataset_large_pages_status: Option<ObservedFlagStatus>,
    candidate_dataset_1gb_pages_status: Option<ObservedFlagStatus>,
    candidate_scratchpad_large_pages_status: Option<ObservedFlagStatus>,
    candidate_scratchpad_1gb_pages_status: Option<ObservedFlagStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedFlagStatus {
    AllTrue,
    AllFalse,
    Mixed,
    Unknown,
}

impl ObservedFlagStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::AllTrue => "all_true",
            Self::AllFalse => "all_false",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
        }
    }

    fn parse(raw: &str) -> Result<Option<Self>, String> {
        let value = raw.trim();
        if value.is_empty() {
            return Ok(None);
        }
        match value {
            "all_true" => Ok(Some(Self::AllTrue)),
            "all_false" => Ok(Some(Self::AllFalse)),
            "mixed" => Ok(Some(Self::Mixed)),
            "unknown" => Ok(Some(Self::Unknown)),
            _ => Err(format!("unknown page-backing status '{value}'")),
        }
    }
}

#[derive(Debug, Clone)]
struct PageBackingSummary {
    observed_rows: usize,
    dataset_large_pages: ObservedFlagStatus,
    dataset_1gb_pages: ObservedFlagStatus,
    scratchpad_large_pages: ObservedFlagStatus,
    scratchpad_1gb_pages: ObservedFlagStatus,
}

#[derive(Debug)]
struct ValidationReport {
    index_path: PathBuf,
    schema_version: u32,
    workflow_version: String,
    entry_reports: Vec<ValidationEntryReport>,
}

#[derive(Debug)]
struct ValidationEntryReport {
    host_class_id: String,
    authority_capture_path: String,
    related_capture_count: usize,
}

#[derive(Debug)]
struct CompareReport {
    index_path: PathBuf,
    analysis_memo: String,
    host_class_id: String,
    authority_label: String,
    authority_classification: EvidenceClass,
    authority_capture_path: String,
    candidate_capture_path: PathBuf,
    candidate_index_status: CandidateIndexStatus,
    rerun_expectation: RerunExpectation,
    rerun_status: String,
    rerun_note: String,
    rerun_relationship: RerunRelationship,
    candidate_capture_evidence_tier: Option<String>,
    candidate_rerun_group_id: Option<String>,
    provenance_comparisons: Vec<ProvenanceComparison>,
    page_backing_comparisons: Vec<PageBackingComparison>,
    pair_comparisons: Vec<PairComparison>,
    missing_in_candidate: Vec<PairKey>,
    missing_in_authority: Vec<PairKey>,
}

#[derive(Debug)]
enum CandidateIndexStatus {
    AuthorityCapture,
    RelatedCapture { role: String },
    NotIndexed,
}

impl CandidateIndexStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::AuthorityCapture => "authority_capture",
            Self::RelatedCapture { .. } => "related_capture",
            Self::NotIndexed => "not_indexed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RerunRelationship {
    SameCapture,
    SameShaSameSettings,
    SameShaSettingsDrift,
    DifferentShaSameHostClass,
}

impl RerunRelationship {
    fn as_str(&self) -> &'static str {
        match self {
            Self::SameCapture => "same_capture",
            Self::SameShaSameSettings => "same_sha_same_settings",
            Self::SameShaSettingsDrift => "same_sha_settings_drift",
            Self::DifferentShaSameHostClass => "different_sha_same_host_class",
        }
    }
}

#[derive(Debug)]
struct ProvenanceComparison {
    field: &'static str,
    authority: String,
    candidate: String,
    matches: bool,
}

#[derive(Debug)]
struct PageBackingComparison {
    page_profile: String,
    authority: PageBackingSummary,
    candidate: PageBackingSummary,
    changed_fields: Vec<&'static str>,
}

#[derive(Debug)]
struct PairComparison {
    key: PairKey,
    authority_delta_pct: f64,
    candidate_delta_pct: f64,
    delta_shift_pct: f64,
    authority_signal_classification: String,
    candidate_signal_classification: String,
    authority_realized_backing: PairRealizedBacking,
    candidate_realized_backing: PairRealizedBacking,
}

#[derive(Debug)]
struct PairRealizedBacking {
    baseline_dataset_large_pages_status: Option<ObservedFlagStatus>,
    baseline_dataset_1gb_pages_status: Option<ObservedFlagStatus>,
    baseline_scratchpad_large_pages_status: Option<ObservedFlagStatus>,
    baseline_scratchpad_1gb_pages_status: Option<ObservedFlagStatus>,
    candidate_dataset_large_pages_status: Option<ObservedFlagStatus>,
    candidate_dataset_1gb_pages_status: Option<ObservedFlagStatus>,
    candidate_scratchpad_large_pages_status: Option<ObservedFlagStatus>,
    candidate_scratchpad_1gb_pages_status: Option<ObservedFlagStatus>,
}

#[derive(Debug, Default)]
struct PageBackingAccumulator {
    observed_rows: usize,
    dataset_large_pages: FlagCounter,
    dataset_1gb_pages: FlagCounter,
    scratchpad_large_pages: FlagCounter,
    scratchpad_1gb_pages: FlagCounter,
}

#[derive(Debug, Default)]
struct FlagCounter {
    true_count: usize,
    false_count: usize,
}

impl FlagCounter {
    fn observe(&mut self, value: Option<bool>) {
        match value {
            Some(true) => self.true_count += 1,
            Some(false) => self.false_count += 1,
            None => {}
        }
    }

    fn summarize(&self) -> ObservedFlagStatus {
        match (self.true_count > 0, self.false_count > 0) {
            (true, true) => ObservedFlagStatus::Mixed,
            (true, false) => ObservedFlagStatus::AllTrue,
            (false, true) => ObservedFlagStatus::AllFalse,
            (false, false) => ObservedFlagStatus::Unknown,
        }
    }
}

fn parse_args() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| "missing subcommand (expected validate-index or compare)".to_string())?;

    match command.as_str() {
        "validate-index" => {
            let mut index_path = PathBuf::from(DEFAULT_INDEX_PATH);
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--index" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "missing value for --index".to_string())?;
                        index_path = PathBuf::from(value);
                    }
                    "--help" | "-h" => {
                        print_usage();
                        process::exit(0);
                    }
                    _ => return Err(format!("unknown argument for validate-index: {arg}")),
                }
            }
            Ok(Options {
                command: Command::ValidateIndex { index_path },
            })
        }
        "compare" => {
            let mut index_path = PathBuf::from(DEFAULT_INDEX_PATH);
            let mut capture_path = None::<PathBuf>;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--index" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "missing value for --index".to_string())?;
                        index_path = PathBuf::from(value);
                    }
                    "--capture" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "missing value for --capture".to_string())?;
                        capture_path = Some(PathBuf::from(value));
                    }
                    "--help" | "-h" => {
                        print_usage();
                        process::exit(0);
                    }
                    _ => return Err(format!("unknown argument for compare: {arg}")),
                }
            }
            let capture_path =
                capture_path.ok_or_else(|| "missing required --capture <path>".to_string())?;
            Ok(Options {
                command: Command::Compare {
                    index_path,
                    capture_path,
                },
            })
        }
        "--help" | "-h" => {
            print_usage();
            process::exit(0);
        }
        _ => Err(format!("unknown subcommand: {command}")),
    }
}

fn print_usage() {
    eprintln!(
        "Usage:\n\
         \n\
         full_features_authority validate-index [--index <path>]\n\
         full_features_authority compare --capture <ff_dir> [--index <path>]\n\
         \n\
         Examples:\n\
           cargo run --release --bin full_features_authority -- validate-index\n\
           cargo run --release --bin full_features_authority -- compare \\\n\
             --capture perf_results/AMD/ff_amd_fam23_mod113_20260318_210634"
    );
}

fn find_repo_root() -> Result<PathBuf, String> {
    let mut dir = env::current_dir().map_err(|err| format!("failed to read cwd: {err}"))?;
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("perf_results").is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    Err("failed to locate repo root from current working directory".to_string())
}

fn resolve_repo_path(repo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    }
}

fn load_authority_index(path: &Path) -> Result<AuthorityIndex, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let index: AuthorityIndex = serde_json::from_str(&content)
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;

    if index.artifact_kind != "full_features_authority_index" {
        return Err(format!(
            "{} has unexpected artifact_kind '{}'",
            path.display(),
            index.artifact_kind
        ));
    }
    if index.entries.is_empty() {
        return Err(format!("{} has no authority entries", path.display()));
    }

    let mut seen_host_ids = BTreeSet::new();
    let mut seen_authority_paths = BTreeSet::new();
    for entry in &index.entries {
        if entry.host_class_id.trim().is_empty() {
            return Err(format!(
                "{} contains an entry with empty host_class_id",
                path.display()
            ));
        }
        if !seen_host_ids.insert(entry.host_class_id.clone()) {
            return Err(format!(
                "{} contains duplicate host_class_id '{}'",
                path.display(),
                entry.host_class_id
            ));
        }
        if entry.authority_capture_path.trim().is_empty() {
            return Err(format!(
                "{} entry '{}' has empty authority_capture_path",
                path.display(),
                entry.host_class_id
            ));
        }
        if !seen_authority_paths.insert(entry.authority_capture_path.clone()) {
            return Err(format!(
                "{} contains duplicate authority_capture_path '{}'",
                path.display(),
                entry.authority_capture_path
            ));
        }
        let mut related_paths = BTreeSet::new();
        for related in &entry.related_captures {
            if !related_paths.insert(related.path.clone()) {
                return Err(format!(
                    "{} entry '{}' lists duplicate related capture '{}'",
                    path.display(),
                    entry.host_class_id,
                    related.path
                ));
            }
        }
    }

    Ok(index)
}

fn validate_index(
    repo_root: &Path,
    index_path: &Path,
    index: &AuthorityIndex,
) -> Result<ValidationReport, String> {
    let mut entry_reports = Vec::new();

    for entry in &index.entries {
        let authority_capture_path =
            resolve_repo_path(repo_root, Path::new(&entry.authority_capture_path));
        let authority_capture = load_capture(&authority_capture_path)?;
        validate_entry_against_capture(entry, &authority_capture, true)?;

        for related in &entry.related_captures {
            let related_path = resolve_repo_path(repo_root, Path::new(&related.path));
            let related_capture = load_capture(&related_path)?;
            validate_entry_against_capture(entry, &related_capture, false)?;
        }

        entry_reports.push(ValidationEntryReport {
            host_class_id: entry.host_class_id.clone(),
            authority_capture_path: entry.authority_capture_path.clone(),
            related_capture_count: entry.related_captures.len(),
        });
    }

    Ok(ValidationReport {
        index_path: index_path.to_path_buf(),
        schema_version: index.schema_version,
        workflow_version: index.workflow_version.clone(),
        entry_reports,
    })
}

fn validate_entry_against_capture(
    entry: &AuthorityEntry,
    capture: &CaptureArtifacts,
    require_provenance_match: bool,
) -> Result<(), String> {
    let inferred_host_class = capture.provenance.inferred_host_class_id()?;
    if inferred_host_class != entry.host_class_id {
        return Err(format!(
            "capture {} infers host_class_id '{}' but index entry expects '{}'",
            capture.root.display(),
            inferred_host_class,
            entry.host_class_id
        ));
    }

    if require_provenance_match {
        validate_indexed_provenance(&entry.provenance, &capture.provenance, &capture.root)?;
    } else {
        validate_related_capture_shape(entry, &capture.provenance, &capture.root)?;
    }

    Ok(())
}

fn validate_indexed_provenance(
    indexed: &IndexedProvenance,
    capture: &CaptureProvenance,
    root: &Path,
) -> Result<(), String> {
    compare_exact("vendor", &indexed.vendor, &capture.vendor, root)?;
    compare_exact("family", indexed.family, capture.family, root)?;
    compare_exact("model", indexed.model, capture.model, root)?;
    compare_exact(
        "stepping",
        indexed.stepping,
        capture
            .stepping
            .ok_or_else(|| format!("{} missing stepping", root.display()))?,
        root,
    )?;
    compare_exact(
        "cpu_model_string",
        &indexed.cpu_model_string,
        &capture.cpu_model_string,
        root,
    )?;
    compare_exact("os_name", &indexed.os_name, &capture.os_name, root)?;
    compare_exact(
        "os_version",
        indexed.os_version.as_str(),
        capture
            .os_version
            .as_deref()
            .ok_or_else(|| format!("{} missing os_version", root.display()))?,
        root,
    )?;
    compare_exact(
        "os_build_or_kernel",
        indexed.os_build_or_kernel.as_str(),
        capture
            .os_build_or_kernel
            .as_deref()
            .ok_or_else(|| format!("{} missing os_build_or_kernel", root.display()))?,
        root,
    )?;
    compare_exact(
        "logical_threads",
        indexed.logical_threads,
        capture
            .logical_threads
            .ok_or_else(|| format!("{} missing logical_threads", root.display()))?,
        root,
    )?;
    compare_exact(
        "threads",
        indexed.threads,
        capture
            .threads
            .ok_or_else(|| format!("{} missing threads", root.display()))?,
        root,
    )?;
    compare_exact(
        "page_profiles",
        indexed.page_profiles.join(","),
        capture.page_profiles.join(","),
        root,
    )?;
    compare_exact(
        "abba_page_profile",
        indexed.abba_page_profile.as_str(),
        capture
            .abba_page_profile
            .as_deref()
            .ok_or_else(|| format!("{} missing abba_page_profile", root.display()))?,
        root,
    )?;
    compare_exact("git_sha", &indexed.git_sha, &capture.git_sha, root)?;
    compare_exact(
        "git_sha_short",
        indexed.git_sha_short.as_str(),
        capture
            .git_sha_short
            .as_deref()
            .ok_or_else(|| format!("{} missing git_sha_short", root.display()))?,
        root,
    )?;
    compare_exact(
        "git_dirty",
        indexed.git_dirty,
        capture
            .git_dirty
            .ok_or_else(|| format!("{} missing git_dirty", root.display()))?,
        root,
    )?;
    compare_exact("rustc", &indexed.rustc, &capture.rustc, root)?;
    Ok(())
}

fn validate_related_capture_shape(
    entry: &AuthorityEntry,
    capture: &CaptureProvenance,
    root: &Path,
) -> Result<(), String> {
    compare_exact("vendor", &entry.provenance.vendor, &capture.vendor, root)?;
    compare_exact("family", entry.provenance.family, capture.family, root)?;
    compare_exact("model", entry.provenance.model, capture.model, root)?;
    compare_exact(
        "os_class",
        infer_os_class(
            &entry.provenance.os_name,
            Some(&entry.provenance.os_build_or_kernel),
        )?,
        infer_os_class(&capture.os_name, capture.os_build_or_kernel.as_deref())?,
        root,
    )?;
    Ok(())
}

fn compare_exact<T>(field: &str, expected: T, actual: T, root: &Path) -> Result<(), String>
where
    T: std::fmt::Display + PartialEq,
{
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "{} {field} mismatch: expected '{}' but found '{}'",
            root.display(),
            expected,
            actual
        ))
    }
}

fn load_capture(root: &Path) -> Result<CaptureArtifacts, String> {
    if !root.is_dir() {
        return Err(format!(
            "capture directory does not exist: {}",
            root.display()
        ));
    }

    let provenance_path = root.join(PROVENANCE_ARTIFACT);
    let pair_summary_path = root.join(PAIR_SUMMARY_ARTIFACT);
    let matrix_index_path = root.join(MATRIX_INDEX_ARTIFACT);

    let provenance = parse_provenance(&provenance_path)?;
    let pair_summaries = parse_pair_summary(&pair_summary_path)?;
    let page_backing = parse_matrix_page_backing(&matrix_index_path)?;

    Ok(CaptureArtifacts {
        root: root.to_path_buf(),
        provenance,
        pair_summaries,
        page_backing,
    })
}

fn parse_provenance(path: &Path) -> Result<CaptureProvenance, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    let mut fields = BTreeMap::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            format!(
                "invalid provenance line at {}:{}: expected key=value",
                path.display(),
                idx + 1
            )
        })?;
        fields.insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok(CaptureProvenance {
        host_class_id: fields.remove("host_class_id"),
        vendor: require_string(&mut fields, "vendor", path)?,
        family: require_u32(&mut fields, "family", path)?,
        model: require_u32(&mut fields, "model", path)?,
        stepping: optional_u32(&mut fields, "stepping", path)?,
        cpu_model_string: require_string(&mut fields, "cpu_model_string", path)?,
        os_name: require_string(&mut fields, "os_name", path)?,
        os_version: optional_string(&mut fields, "os_version"),
        os_build_or_kernel: optional_string(&mut fields, "os_build_or_kernel"),
        logical_threads: optional_u32(&mut fields, "logical_threads", path)?,
        threads: optional_u32(&mut fields, "threads", path)?,
        perf_iters: optional_u32(&mut fields, "perf_iters", path)?,
        perf_warmup: optional_u32(&mut fields, "perf_warmup", path)?,
        page_profiles: optional_csv_list(&mut fields, "page_profiles"),
        abba_page_profile: optional_string(&mut fields, "abba_page_profile"),
        git_sha: require_string(&mut fields, "git_sha", path)?,
        git_sha_short: optional_string(&mut fields, "git_sha_short"),
        git_dirty: optional_bool(&mut fields, "git_dirty", path)?,
        rustc: require_string(&mut fields, "rustc", path)?,
        capture_evidence_tier: optional_string(&mut fields, "capture_evidence_tier"),
        rerun_group_id: optional_string(&mut fields, "rerun_group_id"),
    })
}

fn require_string(
    fields: &mut BTreeMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<String, String> {
    fields
        .remove(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{} missing required field '{}'", path.display(), key))
}

fn require_u32(
    fields: &mut BTreeMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<u32, String> {
    let value = require_string(fields, key, path)?;
    value.parse::<u32>().map_err(|_| {
        format!(
            "{} field '{}' has invalid u32 value '{}'",
            path.display(),
            key,
            value
        )
    })
}

fn optional_u32(
    fields: &mut BTreeMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<Option<u32>, String> {
    match fields.remove(key) {
        Some(value) if !value.trim().is_empty() => value.parse::<u32>().map(Some).map_err(|_| {
            format!(
                "{} field '{}' has invalid u32 value '{}'",
                path.display(),
                key,
                value
            )
        }),
        _ => Ok(None),
    }
}

fn optional_bool(
    fields: &mut BTreeMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<Option<bool>, String> {
    match fields.remove(key) {
        Some(value) if !value.trim().is_empty() => parse_bool_value(&value)
            .map(Some)
            .map_err(|msg| format!("{} field '{}' {}", path.display(), key, msg)),
        _ => Ok(None),
    }
}

fn optional_string(fields: &mut BTreeMap<String, String>, key: &str) -> Option<String> {
    fields.remove(key).filter(|value| !value.trim().is_empty())
}

fn optional_csv_list(fields: &mut BTreeMap<String, String>, key: &str) -> Vec<String> {
    match fields.remove(key) {
        Some(value) => value
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect(),
        None => Vec::new(),
    }
}

fn parse_pair_summary(path: &Path) -> Result<BTreeMap<PairKey, PairSummaryRecord>, String> {
    let table = parse_csv_table(path)?;
    let mut pairs = BTreeMap::new();

    for row in table.rows {
        let key = PairKey {
            pair_label: require_row_value(&row, "pair_label", path)?,
            family: require_row_value(&row, "family", path)?,
            config: require_row_value(&row, "config", path)?,
            mode: require_row_value(&row, "mode", path)?,
            page_profile: require_row_value(&row, "page_profile", path)?,
        };
        let delta_pct_candidate_vs_baseline =
            require_row_f64(&row, "delta_pct_candidate_vs_baseline", path)?;
        let signal_classification = require_row_value(&row, "signal_classification", path)?;

        let record = PairSummaryRecord {
            delta_pct_candidate_vs_baseline,
            signal_classification,
            baseline_dataset_large_pages_status: optional_row_status(
                &row,
                "baseline_dataset_large_pages_status",
                path,
            )?,
            baseline_dataset_1gb_pages_status: optional_row_status(
                &row,
                "baseline_dataset_1gb_pages_status",
                path,
            )?,
            baseline_scratchpad_large_pages_status: optional_row_status(
                &row,
                "baseline_scratchpad_large_pages_status",
                path,
            )?,
            baseline_scratchpad_1gb_pages_status: optional_row_status(
                &row,
                "baseline_scratchpad_1gb_pages_status",
                path,
            )?,
            candidate_dataset_large_pages_status: optional_row_status(
                &row,
                "candidate_dataset_large_pages_status",
                path,
            )?,
            candidate_dataset_1gb_pages_status: optional_row_status(
                &row,
                "candidate_dataset_1gb_pages_status",
                path,
            )?,
            candidate_scratchpad_large_pages_status: optional_row_status(
                &row,
                "candidate_scratchpad_large_pages_status",
                path,
            )?,
            candidate_scratchpad_1gb_pages_status: optional_row_status(
                &row,
                "candidate_scratchpad_1gb_pages_status",
                path,
            )?,
        };

        if pairs.insert(key.clone(), record).is_some() {
            return Err(format!(
                "{} contains duplicate pair summary row '{}'",
                path.display(),
                key.display_key()
            ));
        }
    }

    Ok(pairs)
}

fn parse_matrix_page_backing(path: &Path) -> Result<BTreeMap<String, PageBackingSummary>, String> {
    let table = parse_csv_table(path)?;
    let mut accumulators: BTreeMap<String, PageBackingAccumulator> = BTreeMap::new();

    for row in table.rows {
        let page_profile = require_row_value(&row, "page_profile", path)?;
        let accumulator = accumulators.entry(page_profile).or_default();
        accumulator.observed_rows += 1;
        accumulator.dataset_large_pages.observe(optional_row_bool(
            &row,
            "large_pages_dataset",
            path,
        )?);
        accumulator.dataset_1gb_pages.observe(optional_row_bool(
            &row,
            "large_pages_1gb_dataset",
            path,
        )?);
        accumulator
            .scratchpad_large_pages
            .observe(optional_row_bool(&row, "large_pages_scratchpad", path)?);
        accumulator.scratchpad_1gb_pages.observe(optional_row_bool(
            &row,
            "large_pages_1gb_scratchpad",
            path,
        )?);
    }

    let mut summaries = BTreeMap::new();
    for (page_profile, accumulator) in accumulators {
        summaries.insert(
            page_profile.clone(),
            PageBackingSummary {
                observed_rows: accumulator.observed_rows,
                dataset_large_pages: accumulator.dataset_large_pages.summarize(),
                dataset_1gb_pages: accumulator.dataset_1gb_pages.summarize(),
                scratchpad_large_pages: accumulator.scratchpad_large_pages.summarize(),
                scratchpad_1gb_pages: accumulator.scratchpad_1gb_pages.summarize(),
            },
        );
    }

    Ok(summaries)
}

#[derive(Debug)]
struct CsvTable {
    rows: Vec<CsvRow>,
}

type CsvRow = BTreeMap<String, String>;

fn parse_csv_table(path: &Path) -> Result<CsvTable, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;

    let mut lines = content.lines().enumerate().filter_map(|(idx, line)| {
        if line.trim().is_empty() {
            None
        } else {
            Some((idx + 1, line))
        }
    });

    let (header_line_no, header_line) = lines
        .next()
        .ok_or_else(|| format!("CSV has no header: {}", path.display()))?;
    let headers = parse_csv_record(header_line).map_err(|err| {
        format!(
            "failed to parse header at {}:{}: {err}",
            path.display(),
            header_line_no
        )
    })?;

    if headers.is_empty() {
        return Err(format!("CSV has empty header row: {}", path.display()));
    }

    let mut rows = Vec::new();
    for (line_no, line) in lines {
        let fields = parse_csv_record(line).map_err(|err| {
            format!(
                "failed to parse row at {}:{}: {err}",
                path.display(),
                line_no
            )
        })?;
        if fields.len() != headers.len() {
            return Err(format!(
                "{}:{} field count mismatch: expected {} fields from header, found {}",
                path.display(),
                line_no,
                headers.len(),
                fields.len()
            ));
        }
        let row = headers
            .iter()
            .cloned()
            .zip(fields.into_iter())
            .collect::<BTreeMap<_, _>>();
        rows.push(row);
    }

    Ok(CsvTable { rows })
}

fn parse_csv_record(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if matches!(chars.peek(), Some('"')) {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else if field.is_empty() {
                    in_quotes = true;
                } else {
                    return Err("unexpected quote character".to_string());
                }
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut field)),
            _ => field.push(ch),
        }
    }

    if in_quotes {
        return Err("unterminated quoted field".to_string());
    }

    out.push(field);
    Ok(out)
}

fn require_row_value(row: &CsvRow, key: &str, path: &Path) -> Result<String, String> {
    row.get(key)
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{} missing required CSV column '{}'", path.display(), key))
}

fn require_row_f64(row: &CsvRow, key: &str, path: &Path) -> Result<f64, String> {
    let value = require_row_value(row, key, path)?;
    value.parse::<f64>().map_err(|_| {
        format!(
            "{} field '{}' has invalid f64 value '{}'",
            path.display(),
            key,
            value
        )
    })
}

fn optional_row_status(
    row: &CsvRow,
    key: &str,
    path: &Path,
) -> Result<Option<ObservedFlagStatus>, String> {
    match row.get(key) {
        Some(value) => ObservedFlagStatus::parse(value).map_err(|msg| {
            format!(
                "{} field '{}' has invalid value: {}",
                path.display(),
                key,
                msg
            )
        }),
        None => Ok(None),
    }
}

fn optional_row_bool(row: &CsvRow, key: &str, path: &Path) -> Result<Option<bool>, String> {
    match row.get(key) {
        Some(value) => parse_optional_bool(value).map_err(|msg| {
            format!(
                "{} field '{}' has invalid value '{}': {}",
                path.display(),
                key,
                value,
                msg
            )
        }),
        None => Ok(None),
    }
}

fn parse_optional_bool(raw: &str) -> Result<Option<bool>, String> {
    let value = raw.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("n/a") {
        return Ok(None);
    }
    parse_bool_value(value).map(Some)
}

fn parse_bool_value(raw: &str) -> Result<bool, String> {
    match raw.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(format!("expected true/false, found '{value}'")),
    }
}

fn compare_capture_to_index(
    repo_root: &Path,
    index_path: &Path,
    index: &AuthorityIndex,
    candidate_capture_path: &Path,
) -> Result<CompareReport, String> {
    let candidate_capture = load_capture(candidate_capture_path)?;
    let host_class_id = candidate_capture.provenance.inferred_host_class_id()?;
    let entry = index
        .entries
        .iter()
        .find(|entry| entry.host_class_id == host_class_id)
        .ok_or_else(|| {
            format!(
                "capture {} resolved to host_class_id '{}' which is not present in the authority index",
                candidate_capture_path.display(),
                host_class_id
            )
        })?;

    let authority_capture_path =
        resolve_repo_path(repo_root, Path::new(&entry.authority_capture_path));
    let authority_capture = load_capture(&authority_capture_path)?;
    validate_entry_against_capture(entry, &authority_capture, true)?;

    let candidate_index_status = detect_candidate_index_status(
        repo_root,
        candidate_capture_path,
        &entry.authority_capture_path,
        &entry.related_captures,
    )?;
    let rerun_relationship = classify_rerun_relationship(&authority_capture, &candidate_capture)?;
    let provenance_comparisons =
        build_provenance_comparisons(&authority_capture.provenance, &candidate_capture.provenance);
    let page_backing_comparisons =
        build_page_backing_comparisons(&authority_capture, &candidate_capture);
    let (pair_comparisons, missing_in_candidate, missing_in_authority) =
        build_pair_comparisons(&authority_capture, &candidate_capture);

    Ok(CompareReport {
        index_path: index_path.to_path_buf(),
        analysis_memo: index.analysis_memo.clone(),
        host_class_id,
        authority_label: entry.label.clone(),
        authority_classification: entry.authority_classification.clone(),
        authority_capture_path: entry.authority_capture_path.clone(),
        candidate_capture_path: candidate_capture.root.clone(),
        candidate_index_status,
        rerun_expectation: entry.rerun_stability.expectation.clone(),
        rerun_status: entry.rerun_stability.status.clone(),
        rerun_note: entry.rerun_stability.note.clone(),
        rerun_relationship,
        candidate_capture_evidence_tier: candidate_capture.provenance.capture_evidence_tier.clone(),
        candidate_rerun_group_id: candidate_capture.provenance.rerun_group_id.clone(),
        provenance_comparisons,
        page_backing_comparisons,
        pair_comparisons,
        missing_in_candidate,
        missing_in_authority,
    })
}

fn detect_candidate_index_status(
    repo_root: &Path,
    candidate_capture_path: &Path,
    authority_capture_path: &str,
    related_captures: &[RelatedCapture],
) -> Result<CandidateIndexStatus, String> {
    let candidate_canonical = fs::canonicalize(candidate_capture_path).map_err(|err| {
        format!(
            "failed to canonicalize candidate capture {}: {err}",
            candidate_capture_path.display()
        )
    })?;
    let authority_canonical = fs::canonicalize(resolve_repo_path(
        repo_root,
        Path::new(authority_capture_path),
    ))
    .map_err(|err| {
        format!(
            "failed to canonicalize authority capture {}: {err}",
            authority_capture_path
        )
    })?;

    if candidate_canonical == authority_canonical {
        return Ok(CandidateIndexStatus::AuthorityCapture);
    }

    for related in related_captures {
        let related_canonical =
            fs::canonicalize(resolve_repo_path(repo_root, Path::new(&related.path))).map_err(
                |err| {
                    format!(
                        "failed to canonicalize related capture {}: {err}",
                        related.path
                    )
                },
            )?;
        if candidate_canonical == related_canonical {
            return Ok(CandidateIndexStatus::RelatedCapture {
                role: related.role.clone(),
            });
        }
    }

    Ok(CandidateIndexStatus::NotIndexed)
}

fn classify_rerun_relationship(
    authority: &CaptureArtifacts,
    candidate: &CaptureArtifacts,
) -> Result<RerunRelationship, String> {
    let authority_canonical = fs::canonicalize(&authority.root).map_err(|err| {
        format!(
            "failed to canonicalize authority capture {}: {err}",
            authority.root.display()
        )
    })?;
    let candidate_canonical = fs::canonicalize(&candidate.root).map_err(|err| {
        format!(
            "failed to canonicalize candidate capture {}: {err}",
            candidate.root.display()
        )
    })?;

    if authority_canonical == candidate_canonical {
        return Ok(RerunRelationship::SameCapture);
    }

    if authority.provenance.git_sha == candidate.provenance.git_sha {
        if same_rerun_settings(&authority.provenance, &candidate.provenance) {
            Ok(RerunRelationship::SameShaSameSettings)
        } else {
            Ok(RerunRelationship::SameShaSettingsDrift)
        }
    } else {
        Ok(RerunRelationship::DifferentShaSameHostClass)
    }
}

fn same_rerun_settings(authority: &CaptureProvenance, candidate: &CaptureProvenance) -> bool {
    authority.rustc == candidate.rustc
        && authority.threads == candidate.threads
        && authority.perf_iters == candidate.perf_iters
        && authority.perf_warmup == candidate.perf_warmup
        && authority.page_profiles == candidate.page_profiles
}

fn build_provenance_comparisons(
    authority: &CaptureProvenance,
    candidate: &CaptureProvenance,
) -> Vec<ProvenanceComparison> {
    vec![
        compare_provenance_field("vendor", &authority.vendor, &candidate.vendor),
        compare_provenance_field(
            "family",
            &authority.family.to_string(),
            &candidate.family.to_string(),
        ),
        compare_provenance_field(
            "model",
            &authority.model.to_string(),
            &candidate.model.to_string(),
        ),
        compare_provenance_field("os_name", &authority.os_name, &candidate.os_name),
        compare_provenance_field(
            "os_version",
            authority.os_version.as_deref().unwrap_or(""),
            candidate.os_version.as_deref().unwrap_or(""),
        ),
        compare_provenance_field(
            "os_build_or_kernel",
            authority.os_build_or_kernel.as_deref().unwrap_or(""),
            candidate.os_build_or_kernel.as_deref().unwrap_or(""),
        ),
        compare_provenance_field(
            "logical_threads",
            &authority
                .logical_threads
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &candidate
                .logical_threads
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        compare_provenance_field(
            "threads",
            &authority
                .threads
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &candidate
                .threads
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        compare_provenance_field(
            "perf_iters",
            &authority
                .perf_iters
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &candidate
                .perf_iters
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        compare_provenance_field(
            "perf_warmup",
            &authority
                .perf_warmup
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &candidate
                .perf_warmup
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        compare_provenance_field(
            "page_profiles",
            &authority.page_profiles.join(","),
            &candidate.page_profiles.join(","),
        ),
        compare_provenance_field(
            "abba_page_profile",
            authority.abba_page_profile.as_deref().unwrap_or(""),
            candidate.abba_page_profile.as_deref().unwrap_or(""),
        ),
        compare_provenance_field("git_sha", &authority.git_sha, &candidate.git_sha),
        compare_provenance_field("rustc", &authority.rustc, &candidate.rustc),
    ]
}

fn compare_provenance_field(
    field: &'static str,
    authority: &str,
    candidate: &str,
) -> ProvenanceComparison {
    ProvenanceComparison {
        field,
        authority: authority.to_string(),
        candidate: candidate.to_string(),
        matches: authority == candidate,
    }
}

fn build_page_backing_comparisons(
    authority: &CaptureArtifacts,
    candidate: &CaptureArtifacts,
) -> Vec<PageBackingComparison> {
    let mut page_profiles = BTreeSet::new();
    page_profiles.extend(authority.page_backing.keys().cloned());
    page_profiles.extend(candidate.page_backing.keys().cloned());

    let mut comparisons = Vec::new();
    for page_profile in sort_page_profiles(page_profiles.into_iter().collect()) {
        let authority_summary = authority
            .page_backing
            .get(&page_profile)
            .cloned()
            .unwrap_or_else(|| empty_page_backing_summary(&page_profile));
        let candidate_summary = candidate
            .page_backing
            .get(&page_profile)
            .cloned()
            .unwrap_or_else(|| empty_page_backing_summary(&page_profile));

        let mut changed_fields = Vec::new();
        if authority_summary.dataset_large_pages != candidate_summary.dataset_large_pages {
            changed_fields.push("dataset_large_pages");
        }
        if authority_summary.dataset_1gb_pages != candidate_summary.dataset_1gb_pages {
            changed_fields.push("dataset_1gb_pages");
        }
        if authority_summary.scratchpad_large_pages != candidate_summary.scratchpad_large_pages {
            changed_fields.push("scratchpad_large_pages");
        }
        if authority_summary.scratchpad_1gb_pages != candidate_summary.scratchpad_1gb_pages {
            changed_fields.push("scratchpad_1gb_pages");
        }

        comparisons.push(PageBackingComparison {
            page_profile,
            authority: authority_summary,
            candidate: candidate_summary,
            changed_fields,
        });
    }
    comparisons
}

fn empty_page_backing_summary(_page_profile: &str) -> PageBackingSummary {
    PageBackingSummary {
        observed_rows: 0,
        dataset_large_pages: ObservedFlagStatus::Unknown,
        dataset_1gb_pages: ObservedFlagStatus::Unknown,
        scratchpad_large_pages: ObservedFlagStatus::Unknown,
        scratchpad_1gb_pages: ObservedFlagStatus::Unknown,
    }
}

fn sort_page_profiles(mut profiles: Vec<String>) -> Vec<String> {
    profiles.sort_by(|left, right| {
        page_profile_rank(left)
            .cmp(&page_profile_rank(right))
            .then_with(|| left.cmp(right))
    });
    profiles
}

fn page_profile_rank(page_profile: &str) -> usize {
    match page_profile {
        "pages_off" => 0,
        "large_pages_on" => 1,
        "huge_1g_requested" => 2,
        _ => 3,
    }
}

fn build_pair_comparisons(
    authority: &CaptureArtifacts,
    candidate: &CaptureArtifacts,
) -> (Vec<PairComparison>, Vec<PairKey>, Vec<PairKey>) {
    let authority_keys = authority
        .pair_summaries
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let candidate_keys = candidate
        .pair_summaries
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    let shared_keys = authority_keys
        .intersection(&candidate_keys)
        .cloned()
        .collect::<Vec<_>>();
    let missing_in_candidate = authority_keys
        .difference(&candidate_keys)
        .cloned()
        .collect::<Vec<_>>();
    let missing_in_authority = candidate_keys
        .difference(&authority_keys)
        .cloned()
        .collect::<Vec<_>>();

    let mut pair_comparisons = Vec::new();
    for key in shared_keys {
        let authority_row = authority.pair_summaries.get(&key).expect("shared key");
        let candidate_row = candidate.pair_summaries.get(&key).expect("shared key");
        pair_comparisons.push(PairComparison {
            key: key.clone(),
            authority_delta_pct: authority_row.delta_pct_candidate_vs_baseline,
            candidate_delta_pct: candidate_row.delta_pct_candidate_vs_baseline,
            delta_shift_pct: candidate_row.delta_pct_candidate_vs_baseline
                - authority_row.delta_pct_candidate_vs_baseline,
            authority_signal_classification: authority_row.signal_classification.clone(),
            candidate_signal_classification: candidate_row.signal_classification.clone(),
            authority_realized_backing: PairRealizedBacking::from(authority_row),
            candidate_realized_backing: PairRealizedBacking::from(candidate_row),
        });
    }

    pair_comparisons.sort_by(|left, right| {
        page_profile_rank(&left.key.page_profile)
            .cmp(&page_profile_rank(&right.key.page_profile))
            .then_with(|| left.key.cmp(&right.key))
    });

    (pair_comparisons, missing_in_candidate, missing_in_authority)
}

impl PairRealizedBacking {
    fn from(record: &PairSummaryRecord) -> Self {
        Self {
            baseline_dataset_large_pages_status: record.baseline_dataset_large_pages_status,
            baseline_dataset_1gb_pages_status: record.baseline_dataset_1gb_pages_status,
            baseline_scratchpad_large_pages_status: record.baseline_scratchpad_large_pages_status,
            baseline_scratchpad_1gb_pages_status: record.baseline_scratchpad_1gb_pages_status,
            candidate_dataset_large_pages_status: record.candidate_dataset_large_pages_status,
            candidate_dataset_1gb_pages_status: record.candidate_dataset_1gb_pages_status,
            candidate_scratchpad_large_pages_status: record.candidate_scratchpad_large_pages_status,
            candidate_scratchpad_1gb_pages_status: record.candidate_scratchpad_1gb_pages_status,
        }
    }

    fn as_compact_string(&self) -> String {
        let mut fields = Vec::new();
        if let Some(value) = self.baseline_dataset_large_pages_status {
            fields.push(format!("baseline_dataset_large_pages={}", value.as_str()));
        }
        if let Some(value) = self.baseline_dataset_1gb_pages_status {
            fields.push(format!("baseline_dataset_1gb_pages={}", value.as_str()));
        }
        if let Some(value) = self.baseline_scratchpad_large_pages_status {
            fields.push(format!(
                "baseline_scratchpad_large_pages={}",
                value.as_str()
            ));
        }
        if let Some(value) = self.baseline_scratchpad_1gb_pages_status {
            fields.push(format!("baseline_scratchpad_1gb_pages={}", value.as_str()));
        }
        if let Some(value) = self.candidate_dataset_large_pages_status {
            fields.push(format!("candidate_dataset_large_pages={}", value.as_str()));
        }
        if let Some(value) = self.candidate_dataset_1gb_pages_status {
            fields.push(format!("candidate_dataset_1gb_pages={}", value.as_str()));
        }
        if let Some(value) = self.candidate_scratchpad_large_pages_status {
            fields.push(format!(
                "candidate_scratchpad_large_pages={}",
                value.as_str()
            ));
        }
        if let Some(value) = self.candidate_scratchpad_1gb_pages_status {
            fields.push(format!("candidate_scratchpad_1gb_pages={}", value.as_str()));
        }
        if fields.is_empty() {
            "unavailable".to_string()
        } else {
            fields.join(" ")
        }
    }
}

fn print_validation_report(report: &ValidationReport) {
    println!("full_features_authority validate-index");
    println!("index={}", report.index_path.display());
    println!("schema_version={}", report.schema_version);
    println!("workflow_version={}", report.workflow_version);
    println!("validated_entries={}", report.entry_reports.len());
    for entry in &report.entry_reports {
        println!(
            "entry host_class_id={} authority_capture_path={} related_captures={}",
            entry.host_class_id, entry.authority_capture_path, entry.related_capture_count
        );
    }
    println!("result=ok");
}

fn print_compare_report(report: &CompareReport) {
    println!("full_features_authority compare");
    println!("index={}", report.index_path.display());
    println!("analysis_memo={}", report.analysis_memo);
    println!("host_class_id={}", report.host_class_id);
    println!("authority_label={}", report.authority_label);
    println!(
        "authority_classification={}",
        report.authority_classification.as_str()
    );
    println!("authority_capture={}", report.authority_capture_path);
    println!(
        "candidate_capture={}",
        report.candidate_capture_path.display()
    );
    println!(
        "candidate_index_status={}",
        report.candidate_index_status.as_str()
    );
    if let CandidateIndexStatus::RelatedCapture { role } = &report.candidate_index_status {
        println!("candidate_related_role={role}");
    }
    println!(
        "candidate_capture_evidence_tier={}",
        report
            .candidate_capture_evidence_tier
            .as_deref()
            .unwrap_or("unavailable")
    );
    println!(
        "candidate_rerun_group_id={}",
        report
            .candidate_rerun_group_id
            .as_deref()
            .unwrap_or("unavailable")
    );
    println!("rerun_expectation={}", report.rerun_expectation.as_str());
    println!("rerun_status={}", report.rerun_status);
    println!("rerun_relationship={}", report.rerun_relationship.as_str());
    println!("rerun_note={}", report.rerun_note);

    println!();
    println!("[provenance_identity]");
    for comparison in &report.provenance_comparisons {
        println!(
            "{} status={} authority={} candidate={}",
            comparison.field,
            if comparison.matches { "match" } else { "diff" },
            comparison.authority,
            comparison.candidate
        );
    }

    println!();
    println!("[realized_page_backing]");
    for comparison in &report.page_backing_comparisons {
        println!(
            "page_profile={} authority_rows={} candidate_rows={} authority=dataset_large_pages:{} dataset_1gb_pages:{} scratchpad_large_pages:{} scratchpad_1gb_pages:{} candidate=dataset_large_pages:{} dataset_1gb_pages:{} scratchpad_large_pages:{} scratchpad_1gb_pages:{} changed_fields={}",
            comparison.page_profile,
            comparison.authority.observed_rows,
            comparison.candidate.observed_rows,
            comparison.authority.dataset_large_pages.as_str(),
            comparison.authority.dataset_1gb_pages.as_str(),
            comparison.authority.scratchpad_large_pages.as_str(),
            comparison.authority.scratchpad_1gb_pages.as_str(),
            comparison.candidate.dataset_large_pages.as_str(),
            comparison.candidate.dataset_1gb_pages.as_str(),
            comparison.candidate.scratchpad_large_pages.as_str(),
            comparison.candidate.scratchpad_1gb_pages.as_str(),
            if comparison.changed_fields.is_empty() {
                "none".to_string()
            } else {
                comparison.changed_fields.join(",")
            }
        );
    }

    println!();
    println!("[abba_pair_deltas]");
    println!(
        "primary_page_profile={} shared_pairs={} missing_in_candidate={} missing_in_authority={}",
        PRIMARY_ABBA_PAGE_PROFILE,
        report.pair_comparisons.len(),
        report.missing_in_candidate.len(),
        report.missing_in_authority.len()
    );
    for comparison in &report.pair_comparisons {
        println!(
            "pair={} authority_delta_pct={:+.6} candidate_delta_pct={:+.6} delta_shift_pct={:+.6} authority_signal={} candidate_signal={} authority_realized_backing={} candidate_realized_backing={}",
            comparison.key.display_key(),
            comparison.authority_delta_pct,
            comparison.candidate_delta_pct,
            comparison.delta_shift_pct,
            comparison.authority_signal_classification,
            comparison.candidate_signal_classification,
            comparison.authority_realized_backing.as_compact_string(),
            comparison.candidate_realized_backing.as_compact_string()
        );
    }
    for key in &report.missing_in_candidate {
        println!("missing_in_candidate={}", key.display_key());
    }
    for key in &report.missing_in_authority {
        println!("missing_in_authority={}", key.display_key());
    }
}

fn sanitize_id_component(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        if mapped == '_' {
            if !last_was_sep && !out.is_empty() {
                out.push(mapped);
            }
            last_was_sep = true;
        } else {
            out.push(mapped);
            last_was_sep = false;
        }
    }
    out.trim_matches('_').to_string()
}

fn infer_os_class(os_name: &str, os_build_or_kernel: Option<&str>) -> Result<&'static str, String> {
    let os_name_lower = os_name.to_ascii_lowercase();
    if os_name_lower.contains("windows") {
        return Ok("windows");
    }
    if os_name_lower.contains("ubuntu") || os_name_lower.contains("linux") {
        return Ok("linux");
    }
    if let Some(kernel) = os_build_or_kernel {
        if kernel.to_ascii_lowercase().contains("linux") {
            return Ok("linux");
        }
    }
    Err(format!(
        "unable to infer OS class from os_name='{}' os_build_or_kernel='{}'",
        os_name,
        os_build_or_kernel.unwrap_or("")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!("full_features_authority_{name}_{nanos}"));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn write_capture(root: &Path, provenance: &str, pair_summary: &str, matrix_index: &str) {
        let meta_dir = root.join("meta");
        fs::create_dir_all(&meta_dir).expect("create meta dir");
        fs::write(meta_dir.join("provenance.txt"), provenance).expect("write provenance");
        fs::write(meta_dir.join("pair_summary.csv"), pair_summary).expect("write pair summary");
        fs::write(meta_dir.join("matrix_index.csv"), matrix_index).expect("write matrix index");
    }

    fn test_pair_summary_csv(include_v9_statuses: bool, delta_pct: f64, signal: &str) -> String {
        let mut header = "pair_label,family,config,mode,page_profile,delta_pct_candidate_vs_baseline,signal_classification".to_string();
        let mut row = format!(
            "baseline_vs_superscalar_proto,superscalar_proto,Interpreter,Light,large_pages_on,{delta_pct:.6},{signal}"
        );
        if include_v9_statuses {
            header.push_str(",baseline_dataset_large_pages_status,baseline_dataset_1gb_pages_status,baseline_scratchpad_large_pages_status,baseline_scratchpad_1gb_pages_status,candidate_dataset_large_pages_status,candidate_dataset_1gb_pages_status,candidate_scratchpad_large_pages_status,candidate_scratchpad_1gb_pages_status");
            row.push_str(
                ",all_true,all_false,all_true,all_false,all_true,all_false,all_true,all_false",
            );
        }
        format!("{header}\n{row}\n")
    }

    fn test_matrix_index_csv(dataset_large_pages: &[&str]) -> String {
        let mut body = String::from(
            "capture_kind,page_profile,large_pages_dataset,large_pages_1gb_dataset,large_pages_scratchpad,large_pages_1gb_scratchpad\n",
        );
        for value in dataset_large_pages {
            body.push_str(&format!("matrix,large_pages_on,{value},false,true,false\n"));
        }
        body
    }

    fn test_provenance(
        os_name: &str,
        os_build_or_kernel: &str,
        git_sha: &str,
        rustc: &str,
        include_v9: bool,
    ) -> String {
        let mut body = format!(
            "timestamp=2026-03-20T12:00:00-04:00\nhost_tag=amd_fam23_mod113\nvendor=AuthenticAMD\nfamily=23\nmodel=113\nstepping=0\ncpu_model_string=AMD test CPU\nos_name={os_name}\nos_version=2009\nos_build_or_kernel={os_build_or_kernel}\nlogical_threads=12\nthreads=12\nperf_iters=50\nperf_warmup=5\npage_profiles=pages_off,large_pages_on\nabba_page_profile=large_pages_on\ngit_sha={git_sha}\ngit_sha_short={}\ngit_dirty=false\nrustc={rustc}\ncompiled_features=jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto\n",
            &git_sha[..7]
        );
        if include_v9 {
            body.push_str("host_class_id=amd_fam23_mod113_windows\ncapture_evidence_tier=supporting\nrerun_group_id=amd_fam23_mod113_windows_17ef718_rustc193\nrerun_expectation=repeated_same_sha_required\n");
        }
        body
    }

    fn test_index_json(authority_capture: &str, related_capture: &str) -> String {
        format!(
            r#"{{
  "schema_version": 1,
  "workflow_version": "v9",
  "artifact_kind": "full_features_authority_index",
  "analysis_memo": "dev/full_features_benchmark_ff_analysis_2026-03-19.md",
  "entries": [
    {{
      "host_class_id": "amd_fam23_mod113_windows",
      "label": "AMD test",
      "authority_classification": "supporting",
      "authority_capture_path": "{authority_capture}",
      "related_captures": [
        {{
          "path": "{related_capture}",
          "role": "rerun_reference",
          "note": "same-sha rerun"
        }}
      ],
      "provenance": {{
        "vendor": "AuthenticAMD",
        "family": 23,
        "model": 113,
        "stepping": 0,
        "cpu_model_string": "AMD test CPU",
        "os_name": "Microsoft Windows 11 Pro",
        "os_version": "2009",
        "os_build_or_kernel": "26200",
        "logical_threads": 12,
        "threads": 12,
        "page_profiles": ["pages_off", "large_pages_on"],
        "abba_page_profile": "large_pages_on",
        "git_sha": "17ef71850b9cfada075e52f4791f362f6f4e3e99",
        "git_sha_short": "17ef718",
        "git_dirty": false,
        "rustc": "rustc 1.93.0"
      }},
      "rerun_stability": {{
        "status": "unstable",
        "expectation": "repeated_same_sha_required",
        "note": "Same-SHA reruns changed realized page backing."
      }},
      "notes": ["supporting only"]
    }}
  ]
}}"#
        )
    }

    #[test]
    fn parse_csv_record_handles_quotes() {
        let row = parse_csv_record("a,\"b,c\",d").expect("parse");
        assert_eq!(row, vec!["a", "b,c", "d"]);
    }

    #[test]
    fn load_authority_index_rejects_duplicate_host_class_ids() {
        let temp_dir = temp_root("duplicate_index");
        let index_path = temp_dir.join("index.json");
        fs::write(
            &index_path,
            r#"{
  "schema_version": 1,
  "workflow_version": "v9",
  "artifact_kind": "full_features_authority_index",
  "analysis_memo": "memo",
  "entries": [
    {
      "host_class_id": "dup",
      "label": "A",
      "authority_classification": "authority",
      "authority_capture_path": "perf_results/A",
      "related_captures": [],
      "provenance": {
        "vendor": "AuthenticAMD",
        "family": 23,
        "model": 113,
        "stepping": 0,
        "cpu_model_string": "cpu",
        "os_name": "Windows",
        "os_version": "1",
        "os_build_or_kernel": "1",
        "logical_threads": 1,
        "threads": 1,
        "page_profiles": ["pages_off"],
        "abba_page_profile": "large_pages_on",
        "git_sha": "a",
        "git_sha_short": "a",
        "git_dirty": false,
        "rustc": "rustc"
      },
      "rerun_stability": {
        "status": "single_capture_currently_accepted",
        "expectation": "single_capture_sufficient",
        "note": "note"
      },
      "notes": []
    },
    {
      "host_class_id": "dup",
      "label": "B",
      "authority_classification": "supporting",
      "authority_capture_path": "perf_results/B",
      "related_captures": [],
      "provenance": {
        "vendor": "AuthenticAMD",
        "family": 23,
        "model": 8,
        "stepping": 0,
        "cpu_model_string": "cpu",
        "os_name": "Windows",
        "os_version": "1",
        "os_build_or_kernel": "1",
        "logical_threads": 1,
        "threads": 1,
        "page_profiles": ["pages_off"],
        "abba_page_profile": "large_pages_on",
        "git_sha": "b",
        "git_sha_short": "b",
        "git_dirty": false,
        "rustc": "rustc"
      },
      "rerun_stability": {
        "status": "single_capture_currently_accepted",
        "expectation": "single_capture_sufficient",
        "note": "note"
      },
      "notes": []
    }
  ]
}"#,
        )
        .expect("write index");

        let err = load_authority_index(&index_path).expect_err("duplicate ids should fail");
        assert!(err.contains("duplicate host_class_id"));

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn parse_provenance_infers_host_class_from_pre_v9_capture() {
        let temp_dir = temp_root("pre_v9_provenance");
        let provenance_path = temp_dir.join("provenance.txt");
        fs::write(
            &provenance_path,
            test_provenance(
                "Microsoft Windows 11 Pro",
                "26200",
                "17ef71850b9cfada075e52f4791f362f6f4e3e99",
                "rustc 1.93.0",
                false,
            ),
        )
        .expect("write provenance");

        let provenance = parse_provenance(&provenance_path).expect("parse provenance");
        assert_eq!(
            provenance.inferred_host_class_id().expect("host class"),
            "amd_fam23_mod113_windows"
        );
        assert!(provenance.host_class_id.is_none());

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn parse_matrix_page_backing_reports_mixed_status() {
        let temp_dir = temp_root("mixed_page_backing");
        let matrix_path = temp_dir.join("matrix_index.csv");
        fs::write(&matrix_path, test_matrix_index_csv(&["true", "false"])).expect("write matrix");

        let summaries = parse_matrix_page_backing(&matrix_path).expect("parse matrix");
        let summary = summaries
            .get("large_pages_on")
            .expect("large pages summary exists");
        assert_eq!(summary.dataset_large_pages, ObservedFlagStatus::Mixed);
        assert_eq!(summary.dataset_1gb_pages, ObservedFlagStatus::AllFalse);
        assert_eq!(summary.scratchpad_large_pages, ObservedFlagStatus::AllTrue);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn compare_capture_to_index_reports_rerun_relationship_and_pair_shift() {
        let repo_root = temp_root("compare_repo");
        fs::write(
            repo_root.join("Cargo.toml"),
            "[package]\nname=\"test\"\nversion=\"0.0.0\"\n",
        )
        .expect("write cargo");
        fs::create_dir_all(repo_root.join("perf_results")).expect("create perf_results");

        let authority_rel = "perf_results/AMD/ff_authority";
        let related_rel = "perf_results/AMD/ff_related";
        let candidate_rel = "perf_results/AMD/ff_candidate";
        let authority_dir = repo_root.join(authority_rel);
        let related_dir = repo_root.join(related_rel);
        let candidate_dir = repo_root.join(candidate_rel);

        write_capture(
            &authority_dir,
            &test_provenance(
                "Microsoft Windows 11 Pro",
                "26200",
                "17ef71850b9cfada075e52f4791f362f6f4e3e99",
                "rustc 1.93.0",
                true,
            ),
            &test_pair_summary_csv(true, -2.0, "likely_noise"),
            &test_matrix_index_csv(&["false", "false"]),
        );
        write_capture(
            &related_dir,
            &test_provenance(
                "Microsoft Windows 11 Pro",
                "26200",
                "17ef71850b9cfada075e52f4791f362f6f4e3e99",
                "rustc 1.93.0",
                false,
            ),
            &test_pair_summary_csv(false, -3.0, "likely_signal"),
            &test_matrix_index_csv(&["true", "true"]),
        );
        write_capture(
            &candidate_dir,
            &test_provenance(
                "Microsoft Windows 11 Pro",
                "26200",
                "17ef71850b9cfada075e52f4791f362f6f4e3e99",
                "rustc 1.93.0",
                false,
            ),
            &test_pair_summary_csv(false, -5.0, "likely_signal"),
            &test_matrix_index_csv(&["true", "true"]),
        );

        let index_rel = "perf_results/full_features_authority_index_v9.json";
        let index_path = repo_root.join(index_rel);
        fs::write(&index_path, test_index_json(authority_rel, related_rel)).expect("write index");

        let index = load_authority_index(&index_path).expect("load index");
        let validation = validate_index(&repo_root, &index_path, &index).expect("validate index");
        assert_eq!(validation.entry_reports.len(), 1);

        let report = compare_capture_to_index(&repo_root, &index_path, &index, &candidate_dir)
            .expect("compare capture");
        assert_eq!(report.host_class_id, "amd_fam23_mod113_windows");
        assert_eq!(
            report.rerun_relationship,
            RerunRelationship::SameShaSameSettings
        );
        assert!(matches!(
            report.candidate_index_status,
            CandidateIndexStatus::NotIndexed
        ));
        assert_eq!(report.pair_comparisons.len(), 1);
        assert!((report.pair_comparisons[0].delta_shift_pct - (-3.0)).abs() < f64::EPSILON);
        assert_eq!(
            report.page_backing_comparisons[0]
                .authority
                .dataset_large_pages,
            ObservedFlagStatus::AllFalse
        );
        assert_eq!(
            report.page_backing_comparisons[0]
                .candidate
                .dataset_large_pages,
            ObservedFlagStatus::AllTrue
        );

        let _ = fs::remove_dir_all(repo_root);
    }
}
