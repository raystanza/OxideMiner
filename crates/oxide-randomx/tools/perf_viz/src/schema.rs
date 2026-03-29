use sha1::{Digest, Sha1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvSchema {
    CorePerf75,
    CorePerf79,
    CorePerf83,
    CorePerf91,
    PrefetchManifest47,
    PrefetchManifest30,
    PrefetchManifest10,
    PrefetchSettingsSummary24,
    PrefetchSettingsSummary26,
    PrefetchScenarioSummary19,
    PrefetchScenarioSummary29,
    PairIndex8,
    PairIndex7,
    BenchIndex4,
    PairBench16,
    BenchApples15,
    BenchApples18,
    MeasurementMatrix17,
    MeasurementMatrix18,
    Calibration21,
    VendorClassification6,
    Unknown {
        col_count: usize,
        header_hash: String,
    },
}

impl CsvSchema {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CorePerf75 => "csv_core_perf_75",
            Self::CorePerf79 => "csv_core_perf_79",
            Self::CorePerf83 => "csv_core_perf_83",
            Self::CorePerf91 => "csv_core_perf_91",
            Self::PrefetchManifest47 => "csv_prefetch_manifest_47",
            Self::PrefetchManifest30 => "csv_prefetch_manifest_30",
            Self::PrefetchManifest10 => "csv_prefetch_manifest_10",
            Self::PrefetchSettingsSummary24 => "csv_prefetch_settings_summary_24",
            Self::PrefetchSettingsSummary26 => "csv_prefetch_settings_summary_26",
            Self::PrefetchScenarioSummary19 => "csv_prefetch_scenario_summary_19",
            Self::PrefetchScenarioSummary29 => "csv_prefetch_scenario_summary_29",
            Self::PairIndex8 => "csv_pair_index_8",
            Self::PairIndex7 => "csv_pair_index_7",
            Self::BenchIndex4 => "csv_bench_index_4",
            Self::PairBench16 => "csv_pair_bench_16",
            Self::BenchApples15 => "csv_bench_apples_15",
            Self::BenchApples18 => "csv_bench_apples_18",
            Self::MeasurementMatrix17 => "csv_measurement_matrix_17",
            Self::MeasurementMatrix18 => "csv_measurement_matrix_18",
            Self::Calibration21 => "csv_calibration_21",
            Self::VendorClassification6 => "csv_vendor_classification_6",
            Self::Unknown { .. } => "csv_unknown",
        }
    }

    pub fn header_hash(&self) -> Option<&str> {
        match self {
            Self::Unknown { header_hash, .. } => Some(header_hash),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonSchema {
    PrefetchSummary,
    CorePerfRun,
    Unknown,
}

impl JsonSchema {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrefetchSummary => "json_prefetch_summary",
            Self::CorePerfRun => "json_core_perf_run",
            Self::Unknown => "json_unknown",
        }
    }
}

pub fn sha1_header(line: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(line.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn parse_header_fields(header_line: &str) -> Vec<String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(header_line.as_bytes());

    if let Some(Ok(record)) = reader.records().next() {
        return record
            .iter()
            .map(|v| v.trim().trim_matches('"').to_string())
            .collect();
    }

    header_line
        .split(',')
        .map(|v| v.trim().trim_matches('"').to_string())
        .collect()
}

fn has_all(cols: &[String], needed: &[&str]) -> bool {
    needed.iter().all(|k| cols.iter().any(|c| c == k))
}

pub fn classify_csv_header(header_line: &str) -> CsvSchema {
    let header = header_line.trim_end_matches(['\r', '\n']);
    let cols = parse_header_fields(header);
    let col_count = cols.len();

    if col_count == 91 && has_all(&cols, &["finish_addr_select_ns", "finish_store_fp_ns"]) {
        return CsvSchema::CorePerf91;
    }
    if col_count == 83 && has_all(&cols, &["jit_fastregs_prepare_ns", "prefetch"]) {
        return CsvSchema::CorePerf83;
    }
    if col_count == 79 && has_all(&cols, &["prefetch", "prefetch_distance", "instrumented"]) {
        return CsvSchema::CorePerf79;
    }
    if col_count == 75 && has_all(&cols, &["instrumented", "jit_compile_ns_measured"]) {
        return CsvSchema::CorePerf75;
    }

    if col_count == 47 && has_all(&cols, &["scenario_id", "command_preview", "artifact_csv"]) {
        return CsvSchema::PrefetchManifest47;
    }
    if col_count == 30 && has_all(&cols, &["scenario_id", "artifact_csv", "order_position"]) {
        return CsvSchema::PrefetchManifest30;
    }
    if col_count == 10 && has_all(&cols, &["run_idx", "mode_key", "out_csv"]) {
        return CsvSchema::PrefetchManifest10;
    }

    if col_count == 24
        && has_all(
            &cols,
            &["setting_label", "run_order_drift_pct", "stddev_ns_per_hash"],
        )
    {
        return CsvSchema::PrefetchSettingsSummary24;
    }
    if col_count == 26
        && has_all(
            &cols,
            &["setting_label", "median_ns_per_hash", "run_order_drift_pct"],
        )
    {
        return CsvSchema::PrefetchSettingsSummary26;
    }

    if col_count == 19
        && has_all(
            &cols,
            &["best_fixed_setting", "delta_auto_vs_best_fixed_pct"],
        )
    {
        return CsvSchema::PrefetchScenarioSummary19;
    }
    if col_count == 29
        && has_all(
            &cols,
            &[
                "best_fixed_setting_mean",
                "delta_auto_vs_best_fixed_mean_pct",
            ],
        )
    {
        return CsvSchema::PrefetchScenarioSummary29;
    }

    if col_count == 8 && has_all(&cols, &["pair_label", "stdout_path", "stderr_path"]) {
        return CsvSchema::PairIndex8;
    }
    if col_count == 7 && has_all(&cols, &["pair_label", "csv", "stdout", "stderr"]) {
        return CsvSchema::PairIndex7;
    }
    if col_count == 4 && has_all(&cols, &["pair_label", "path", "raw_log_path"]) {
        return CsvSchema::BenchIndex4;
    }

    if col_count == 16 && has_all(&cols, &["pair_label", "force", "large_pages_triplet"]) {
        return CsvSchema::PairBench16;
    }

    if col_count == 15 && has_all(&cols, &["configuration", "active_nsph", "jit_nsph"]) {
        return CsvSchema::BenchApples15;
    }
    if col_count == 18 && has_all(&cols, &["configuration", "repeat_index", "run_order"]) {
        return CsvSchema::BenchApples18;
    }

    if col_count == 17 && has_all(&cols, &["tag", "state", "hotpath_on", "csv", "log"]) {
        return CsvSchema::MeasurementMatrix17;
    }
    if col_count == 18
        && has_all(
            &cols,
            &["run_index", "tag", "state", "hotpath_on", "csv", "log"],
        )
    {
        return CsvSchema::MeasurementMatrix18;
    }

    if col_count == 21
        && has_all(
            &cols,
            &["schema_version", "workload_id", "best_prefetch_distance"],
        )
    {
        return CsvSchema::Calibration21;
    }

    if col_count == 6 && has_all(&cols, &["Name", "Class", "Reason"]) {
        return CsvSchema::VendorClassification6;
    }

    CsvSchema::Unknown {
        col_count,
        header_hash: sha1_header(header),
    }
}

pub fn classify_json_by_keys(value: &serde_json::Value) -> JsonSchema {
    let Some(obj) = value.as_object() else {
        return JsonSchema::Unknown;
    };

    if obj.contains_key("scenarios")
        && obj.contains_key("settings_summary_csv")
        && obj.contains_key("scenario_summary_csv")
    {
        return JsonSchema::PrefetchSummary;
    }

    if obj.contains_key("provenance")
        && obj.contains_key("params")
        && obj.contains_key("results")
        && obj.contains_key("stages")
        && obj.contains_key("counters")
    {
        return JsonSchema::CorePerfRun;
    }

    JsonSchema::Unknown
}
