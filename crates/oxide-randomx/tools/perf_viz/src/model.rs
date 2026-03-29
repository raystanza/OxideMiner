#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostBucket {
    Amd,
    Intel,
    Local,
    Unlabeled,
    TopLevel,
    Unknown,
}

impl HostBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amd => "AMD",
            Self::Intel => "Intel",
            Self::Local => "local",
            Self::Unlabeled => "unlabeled",
            Self::TopLevel => "top-level",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub abs_path: PathBuf,
    pub rel_path: PathBuf,
    pub extension: String,
    pub size_bytes: u64,
    pub host_bucket: HostBucket,
    pub encoding_hint: String,
    pub schema_hint: String,
}

#[derive(Debug, Clone)]
pub struct PerfRunRecord {
    pub source_path: PathBuf,
    pub schema_name: String,
    pub mode: Option<String>,
    pub jit_requested: Option<bool>,
    pub jit_fast_regs: Option<bool>,
    pub jit_active: Option<bool>,
    pub iters: Option<u64>,
    pub warmup: Option<u64>,
    pub threads: Option<u64>,
    pub inputs: Option<u64>,
    pub hashes: Option<u64>,
    pub elapsed_ns: Option<u64>,
    pub ns_per_hash: Option<f64>,
    pub hashes_per_sec: Option<f64>,
    pub prefetch: Option<bool>,
    pub prefetch_distance: Option<i64>,
    pub prefetch_auto_tune: Option<bool>,
    pub scratchpad_prefetch_distance: Option<i64>,
    pub git_sha_short: Option<String>,
    pub cpu: Option<String>,
    pub features: Option<String>,
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PrefetchManifestRow {
    pub source_path: PathBuf,
    pub host_tag: Option<String>,
    pub timestamp: Option<String>,
    pub scenario_id: Option<String>,
    pub mode: Option<String>,
    pub jit: Option<String>,
    pub features: Option<String>,
    pub iters: Option<u64>,
    pub warmup: Option<u64>,
    pub threads: Option<u64>,
    pub repeat_index: Option<u64>,
    pub order_position: Option<u64>,
    pub order_label: Option<String>,
    pub run_index: Option<u64>,
    pub setting_kind: Option<String>,
    pub setting_label: Option<String>,
    pub requested_distance: Option<i64>,
    pub requested_auto: Option<bool>,
    pub effective_prefetch_distance: Option<i64>,
    pub ns_per_hash: Option<f64>,
    pub hashes_per_sec: Option<f64>,
    pub artifact_csv: Option<String>,
    pub artifact_stdout: Option<String>,
    pub artifact_stderr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PrefetchSettingSummaryRow {
    pub source_path: PathBuf,
    pub host_tag: Option<String>,
    pub timestamp: Option<String>,
    pub scenario_id: Option<String>,
    pub scenario_label: Option<String>,
    pub mode: Option<String>,
    pub jit: Option<String>,
    pub setting_label: Option<String>,
    pub setting_kind: Option<String>,
    pub effective_prefetch_distance: Option<i64>,
    pub repeats: Option<u64>,
    pub mean_ns_per_hash: Option<f64>,
    pub median_ns_per_hash: Option<f64>,
    pub stddev_ns_per_hash: Option<f64>,
    pub cv_pct: Option<f64>,
    pub min_ns_per_hash: Option<f64>,
    pub max_ns_per_hash: Option<f64>,
    pub run_order_drift_pct: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct PrefetchScenarioSummaryRow {
    pub source_path: PathBuf,
    pub host_tag: Option<String>,
    pub timestamp: Option<String>,
    pub scenario_id: Option<String>,
    pub scenario_label: Option<String>,
    pub mode: Option<String>,
    pub jit: Option<String>,
    pub best_fixed_setting: Option<String>,
    pub best_fixed_distance: Option<i64>,
    pub best_fixed_mean_ns_per_hash: Option<f64>,
    pub best_fixed_median_ns_per_hash: Option<f64>,
    pub auto_setting: Option<String>,
    pub auto_effective_distance: Option<i64>,
    pub auto_mean_ns_per_hash: Option<f64>,
    pub auto_median_ns_per_hash: Option<f64>,
    pub auto_cv_pct: Option<f64>,
    pub delta_auto_vs_best_fixed_pct: Option<f64>,
    pub delta_auto_vs_best_fixed_mean_pct: Option<f64>,
    pub delta_auto_vs_best_fixed_median_pct: Option<f64>,
    pub scenario_mean_abs_run_order_drift_pct: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct PrefetchSummaryDoc {
    pub source_path: PathBuf,
    pub host_tag: Option<String>,
    pub timestamp: Option<String>,
    pub manifest: Option<String>,
    pub settings_summary_csv: Option<String>,
    pub scenario_summary_csv: Option<String>,
    pub practical_tolerance_pct: Option<f64>,
    pub scenarios_len: usize,
}

#[derive(Debug, Default)]
pub struct Dataset {
    pub root: PathBuf,
    pub catalog: Vec<CatalogEntry>,
    pub schema_counts: BTreeMap<String, usize>,
    pub host_counts: BTreeMap<String, usize>,
    pub parse_errors: Vec<String>,
    pub perf_runs: Vec<PerfRunRecord>,
    pub prefetch_manifest_rows: Vec<PrefetchManifestRow>,
    pub prefetch_settings_rows: Vec<PrefetchSettingSummaryRow>,
    pub prefetch_scenario_rows: Vec<PrefetchScenarioSummaryRow>,
    pub prefetch_summary_docs: Vec<PrefetchSummaryDoc>,
}

#[derive(Debug, Clone)]
pub struct IngestConfig {
    pub root: PathBuf,
    pub raw_preview_max_bytes: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("perf_results"),
            raw_preview_max_bytes: 512 * 1024,
        }
    }
}
