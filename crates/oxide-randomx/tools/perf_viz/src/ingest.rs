use crate::model::{
    CatalogEntry, Dataset, HostBucket, IngestConfig, PerfRunRecord, PrefetchManifestRow,
    PrefetchScenarioSummaryRow, PrefetchSettingSummaryRow, PrefetchSummaryDoc,
};
use crate::schema::{classify_csv_header, classify_json_by_keys, CsvSchema, JsonSchema};
use anyhow::{Context, Result};
use encoding_rs::{UTF_16BE, UTF_16LE};
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

#[derive(Debug, Default)]
struct FileOutcome {
    catalog_entry: Option<CatalogEntry>,
    perf_runs: Vec<PerfRunRecord>,
    prefetch_manifest_rows: Vec<PrefetchManifestRow>,
    prefetch_settings_rows: Vec<PrefetchSettingSummaryRow>,
    prefetch_scenario_rows: Vec<PrefetchScenarioSummaryRow>,
    prefetch_summary_docs: Vec<PrefetchSummaryDoc>,
    parse_errors: Vec<String>,
}

pub fn load_dataset(config: &IngestConfig) -> Result<Dataset> {
    let root = config
        .root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize root: {}", config.root.display()))?;

    let mut files: Vec<PathBuf> = WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();
    files.sort();

    let outcomes: Vec<FileOutcome> = files
        .par_iter()
        .map(|path| parse_file(&root, path))
        .collect();

    let mut dataset = Dataset {
        root,
        ..Dataset::default()
    };

    for mut outcome in outcomes {
        if let Some(entry) = outcome.catalog_entry.take() {
            *dataset
                .schema_counts
                .entry(entry.schema_hint.clone())
                .or_insert(0) += 1;
            *dataset
                .host_counts
                .entry(entry.host_bucket.as_str().to_string())
                .or_insert(0) += 1;
            dataset.catalog.push(entry);
        }

        dataset.perf_runs.append(&mut outcome.perf_runs);
        dataset
            .prefetch_manifest_rows
            .append(&mut outcome.prefetch_manifest_rows);
        dataset
            .prefetch_settings_rows
            .append(&mut outcome.prefetch_settings_rows);
        dataset
            .prefetch_scenario_rows
            .append(&mut outcome.prefetch_scenario_rows);
        dataset
            .prefetch_summary_docs
            .append(&mut outcome.prefetch_summary_docs);
        dataset.parse_errors.append(&mut outcome.parse_errors);
    }

    dataset
        .catalog
        .sort_by(|a, b| a.rel_path.as_os_str().cmp(b.rel_path.as_os_str()));
    dataset
        .perf_runs
        .sort_by(|a, b| a.source_path.as_os_str().cmp(b.source_path.as_os_str()));
    dataset
        .prefetch_manifest_rows
        .sort_by(|a, b| a.source_path.as_os_str().cmp(b.source_path.as_os_str()));
    dataset
        .prefetch_settings_rows
        .sort_by(|a, b| a.source_path.as_os_str().cmp(b.source_path.as_os_str()));
    dataset
        .prefetch_scenario_rows
        .sort_by(|a, b| a.source_path.as_os_str().cmp(b.source_path.as_os_str()));

    Ok(dataset)
}

fn parse_file(root: &Path, path: &Path) -> FileOutcome {
    let mut out = FileOutcome::default();

    let rel_path = match path.strip_prefix(root) {
        Ok(p) => p.to_path_buf(),
        Err(_) => path.to_path_buf(),
    };
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(err) => {
            out.parse_errors
                .push(format!("{}: metadata error: {err}", rel_path.display()));
            return out;
        }
    };

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("<noext>")
        .to_ascii_lowercase();

    let host_bucket = detect_host_bucket(&rel_path);
    let file_bytes = fs::read(path).ok();
    let encoding_hint = file_bytes
        .as_deref()
        .map(detect_encoding_hint_from_bytes)
        .unwrap_or_else(|| "unreadable".to_string());

    let mut schema_hint = format!("ext:{ext}");

    match ext.as_str() {
        "csv" => match file_bytes.as_deref() {
            Some(bytes) => {
                let text = decode_bytes_to_text(bytes)
                    .unwrap_or_else(|| String::from_utf8_lossy(bytes).to_string());
                let header_line = text
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("");
                let schema = classify_csv_header(header_line);
                schema_hint = schema_name_with_hash(&schema);
                parse_csv_typed(root, path, &text, &schema, &mut out);
            }
            None => {
                out.parse_errors.push(format!(
                    "{}: csv read error: file unreadable",
                    rel_path.display()
                ));
            }
        },
        "json" => match file_bytes.as_deref() {
            Some(bytes) => {
                let text = decode_bytes_to_text(bytes)
                    .unwrap_or_else(|| String::from_utf8_lossy(bytes).to_string());
                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(value) => {
                        let schema = classify_json_by_keys(&value);
                        schema_hint = schema.as_str().to_string();
                        parse_json_typed(path, &value, &schema, &mut out);
                    }
                    Err(err) => out
                        .parse_errors
                        .push(format!("{}: json parse error: {err}", rel_path.display())),
                }
            }
            None => out.parse_errors.push(format!(
                "{}: json read error: file unreadable",
                rel_path.display()
            )),
        },
        _ => {}
    }

    out.catalog_entry = Some(CatalogEntry {
        abs_path: path.to_path_buf(),
        rel_path,
        extension: ext,
        size_bytes: metadata.len(),
        host_bucket,
        encoding_hint,
        schema_hint,
    });

    out
}

fn parse_csv_typed(
    root: &Path,
    source_path: &Path,
    text: &str,
    schema: &CsvSchema,
    out: &mut FileOutcome,
) {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(err) => {
            out.parse_errors.push(format!(
                "{}: csv header error: {err}",
                source_path.display()
            ));
            return;
        }
    };

    for record_result in reader.records() {
        let record = match record_result {
            Ok(r) => r,
            Err(err) => {
                out.parse_errors
                    .push(format!("{}: csv row error: {err}", source_path.display()));
                continue;
            }
        };

        let row = record_to_map(&headers, &record);
        match schema {
            CsvSchema::CorePerf75
            | CsvSchema::CorePerf79
            | CsvSchema::CorePerf83
            | CsvSchema::CorePerf91 => {
                out.perf_runs
                    .push(parse_perf_run_record(source_path, schema, &row));
            }
            CsvSchema::PrefetchManifest47
            | CsvSchema::PrefetchManifest30
            | CsvSchema::PrefetchManifest10 => {
                out.prefetch_manifest_rows.push(parse_prefetch_manifest_row(
                    root,
                    source_path,
                    &row,
                ));
            }
            CsvSchema::PrefetchSettingsSummary24 | CsvSchema::PrefetchSettingsSummary26 => {
                out.prefetch_settings_rows
                    .push(parse_prefetch_settings_summary_row(source_path, &row));
            }
            CsvSchema::PrefetchScenarioSummary19 | CsvSchema::PrefetchScenarioSummary29 => {
                out.prefetch_scenario_rows
                    .push(parse_prefetch_scenario_summary_row(source_path, &row));
            }
            _ => {}
        }
    }
}

fn parse_json_typed(
    source_path: &Path,
    value: &serde_json::Value,
    schema: &JsonSchema,
    out: &mut FileOutcome,
) {
    if *schema != JsonSchema::PrefetchSummary {
        return;
    }

    let obj = match value.as_object() {
        Some(obj) => obj,
        None => return,
    };

    let scenarios_len = obj
        .get("scenarios")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);

    out.prefetch_summary_docs.push(PrefetchSummaryDoc {
        source_path: source_path.to_path_buf(),
        host_tag: obj
            .get("host_tag")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        timestamp: obj
            .get("timestamp")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        manifest: obj
            .get("manifest")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        settings_summary_csv: obj
            .get("settings_summary_csv")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        scenario_summary_csv: obj
            .get("scenario_summary_csv")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned),
        practical_tolerance_pct: obj.get("practical_tolerance_pct").and_then(value_to_f64),
        scenarios_len,
    });
}

fn parse_perf_run_record(
    source_path: &Path,
    schema: &CsvSchema,
    row: &BTreeMap<String, String>,
) -> PerfRunRecord {
    let mut extra = BTreeMap::new();
    for (k, v) in row {
        if is_perf_core_key(k) || v.trim().is_empty() {
            continue;
        }
        extra.insert(k.clone(), v.clone());
    }

    PerfRunRecord {
        source_path: source_path.to_path_buf(),
        schema_name: schema.as_str().to_string(),
        mode: get_string(row, "mode"),
        jit_requested: get_bool(row, "jit_requested").or_else(|| get_bool(row, "jit")),
        jit_fast_regs: get_bool(row, "jit_fast_regs"),
        jit_active: get_bool(row, "jit_active"),
        iters: get_u64(row, "iters"),
        warmup: get_u64(row, "warmup"),
        threads: get_u64(row, "threads"),
        inputs: get_u64(row, "inputs"),
        hashes: get_u64(row, "hashes"),
        elapsed_ns: get_u64(row, "elapsed_ns"),
        ns_per_hash: get_f64(row, "ns_per_hash"),
        hashes_per_sec: get_f64(row, "hashes_per_sec"),
        prefetch: get_bool(row, "prefetch"),
        prefetch_distance: get_i64(row, "prefetch_distance"),
        prefetch_auto_tune: get_bool(row, "prefetch_auto_tune"),
        scratchpad_prefetch_distance: get_i64(row, "scratchpad_prefetch_distance"),
        git_sha_short: get_string(row, "git_sha_short"),
        cpu: get_string(row, "cpu"),
        features: get_string(row, "features"),
        extra,
    }
}

fn parse_prefetch_manifest_row(
    root: &Path,
    source_path: &Path,
    row: &BTreeMap<String, String>,
) -> PrefetchManifestRow {
    let (inferred_host, inferred_ts) = infer_host_and_timestamp(source_path);

    let artifact_csv = get_string(row, "artifact_csv")
        .or_else(|| get_string(row, "out_csv"))
        .or_else(|| get_string(row, "path"));
    let artifact_stdout = get_string(row, "artifact_stdout")
        .or_else(|| get_string(row, "out_stdout"))
        .or_else(|| get_string(row, "stdout_path"));
    let artifact_stderr = get_string(row, "artifact_stderr")
        .or_else(|| get_string(row, "out_stderr"))
        .or_else(|| get_string(row, "stderr_path"));

    let mut effective_prefetch_distance = get_i64(row, "effective_prefetch_distance");
    let mut ns_per_hash = get_f64(row, "ns_per_hash");
    let mut hashes_per_sec = get_f64(row, "hashes_per_sec");

    if ns_per_hash.is_none() {
        if let Some(artifact_csv_path) = artifact_csv
            .as_deref()
            .and_then(|s| resolve_artifact_path(root, source_path, s))
        {
            if let Some(csv_row) = load_single_csv_row(&artifact_csv_path) {
                ns_per_hash = csv_row
                    .get("ns_per_hash")
                    .and_then(|v| parse_f64_opt(Some(v.as_str())));
                hashes_per_sec = csv_row
                    .get("hashes_per_sec")
                    .and_then(|v| parse_f64_opt(Some(v.as_str())));
                if effective_prefetch_distance.is_none() {
                    effective_prefetch_distance = csv_row
                        .get("prefetch_distance")
                        .and_then(|v| parse_i64_opt(Some(v.as_str())));
                }
            }
        }
    }

    let setting_label = get_string(row, "setting_label").or_else(|| get_string(row, "variant"));
    let requested_distance = get_i64(row, "requested_distance")
        .or_else(|| get_i64(row, "env_prefetch_distance"))
        .or_else(|| {
            setting_label
                .as_deref()
                .and_then(extract_fixed_distance_from_label)
        });

    let requested_auto = get_bool(row, "requested_auto")
        .or_else(|| get_bool(row, "env_prefetch_auto"))
        .or_else(|| {
            setting_label
                .as_deref()
                .map(|v| v.eq_ignore_ascii_case("auto"))
        });

    let setting_kind = get_string(row, "setting_kind").or_else(|| {
        setting_label.as_deref().map(|v| {
            if v.eq_ignore_ascii_case("auto") {
                "auto"
            } else {
                "fixed"
            }
            .to_string()
        })
    });

    PrefetchManifestRow {
        source_path: source_path.to_path_buf(),
        host_tag: get_string(row, "host_tag").or(inferred_host),
        timestamp: get_string(row, "timestamp").or(inferred_ts),
        scenario_id: get_string(row, "scenario_id")
            .or_else(|| get_string(row, "mode_key"))
            .or_else(|| get_string(row, "pair_label")),
        mode: get_string(row, "mode"),
        jit: get_string(row, "jit"),
        features: get_string(row, "features"),
        iters: get_u64(row, "iters"),
        warmup: get_u64(row, "warmup"),
        threads: get_u64(row, "threads"),
        repeat_index: get_u64(row, "repeat_index").or_else(|| get_u64(row, "repeat")),
        order_position: get_u64(row, "order_position").or_else(|| get_u64(row, "order_pos")),
        order_label: get_string(row, "order_label"),
        run_index: get_u64(row, "run_index").or_else(|| get_u64(row, "run_idx")),
        setting_kind,
        setting_label,
        requested_distance,
        requested_auto,
        effective_prefetch_distance,
        ns_per_hash,
        hashes_per_sec,
        artifact_csv,
        artifact_stdout,
        artifact_stderr,
    }
}

fn parse_prefetch_settings_summary_row(
    source_path: &Path,
    row: &BTreeMap<String, String>,
) -> PrefetchSettingSummaryRow {
    PrefetchSettingSummaryRow {
        source_path: source_path.to_path_buf(),
        host_tag: get_string(row, "host_tag"),
        timestamp: get_string(row, "timestamp"),
        scenario_id: get_string(row, "scenario_id"),
        scenario_label: get_string(row, "scenario_label"),
        mode: get_string(row, "mode"),
        jit: get_string(row, "jit"),
        setting_label: get_string(row, "setting_label"),
        setting_kind: get_string(row, "setting_kind"),
        effective_prefetch_distance: get_i64(row, "effective_prefetch_distance").or_else(|| {
            row.get("effective_prefetch_distance")
                .and_then(|v| first_i64_segment(v))
        }),
        repeats: get_u64(row, "repeats"),
        mean_ns_per_hash: get_f64(row, "mean_ns_per_hash"),
        median_ns_per_hash: get_f64(row, "median_ns_per_hash"),
        stddev_ns_per_hash: get_f64(row, "stddev_ns_per_hash"),
        cv_pct: get_f64(row, "cv_pct"),
        min_ns_per_hash: get_f64(row, "min_ns_per_hash"),
        max_ns_per_hash: get_f64(row, "max_ns_per_hash"),
        run_order_drift_pct: get_f64(row, "run_order_drift_pct"),
    }
}

fn parse_prefetch_scenario_summary_row(
    source_path: &Path,
    row: &BTreeMap<String, String>,
) -> PrefetchScenarioSummaryRow {
    PrefetchScenarioSummaryRow {
        source_path: source_path.to_path_buf(),
        host_tag: get_string(row, "host_tag"),
        timestamp: get_string(row, "timestamp"),
        scenario_id: get_string(row, "scenario_id"),
        scenario_label: get_string(row, "scenario_label"),
        mode: get_string(row, "mode"),
        jit: get_string(row, "jit"),
        best_fixed_setting: get_string(row, "best_fixed_setting")
            .or_else(|| get_string(row, "best_fixed_setting_mean")),
        best_fixed_distance: get_i64(row, "best_fixed_distance")
            .or_else(|| get_i64(row, "best_fixed_distance_mean")),
        best_fixed_mean_ns_per_hash: get_f64(row, "best_fixed_mean_ns_per_hash"),
        best_fixed_median_ns_per_hash: get_f64(row, "best_fixed_median_ns_per_hash")
            .or_else(|| get_f64(row, "best_fixed_median_ns_per_hash_for_mean_winner")),
        auto_setting: get_string(row, "auto_setting"),
        auto_effective_distance: get_i64(row, "auto_effective_distance"),
        auto_mean_ns_per_hash: get_f64(row, "auto_mean_ns_per_hash"),
        auto_median_ns_per_hash: get_f64(row, "auto_median_ns_per_hash"),
        auto_cv_pct: get_f64(row, "auto_cv_pct"),
        delta_auto_vs_best_fixed_pct: get_f64(row, "delta_auto_vs_best_fixed_pct"),
        delta_auto_vs_best_fixed_mean_pct: get_f64(row, "delta_auto_vs_best_fixed_mean_pct"),
        delta_auto_vs_best_fixed_median_pct: get_f64(row, "delta_auto_vs_best_fixed_median_pct"),
        scenario_mean_abs_run_order_drift_pct: get_f64(
            row,
            "scenario_mean_abs_run_order_drift_pct",
        ),
    }
}

fn schema_name_with_hash(schema: &CsvSchema) -> String {
    if let Some(hash) = schema.header_hash() {
        if let CsvSchema::Unknown { col_count, .. } = schema {
            return format!("{}:cols={}:sha1={hash}", schema.as_str(), col_count);
        }
    }
    schema.as_str().to_string()
}

fn detect_host_bucket(rel_path: &Path) -> HostBucket {
    let first = rel_path
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .unwrap_or_default();

    match first.as_str() {
        "AMD" => HostBucket::Amd,
        "Intel" => HostBucket::Intel,
        "local" => HostBucket::Local,
        "unlabeled" => HostBucket::Unlabeled,
        "" => HostBucket::Unknown,
        _ => {
            if rel_path.components().count() == 1 {
                HostBucket::TopLevel
            } else {
                HostBucket::Unknown
            }
        }
    }
}

fn record_to_map(
    headers: &csv::StringRecord,
    record: &csv::StringRecord,
) -> BTreeMap<String, String> {
    headers
        .iter()
        .zip(record.iter())
        .map(|(k, v)| (clean_key(k), v.trim().to_string()))
        .collect()
}

fn clean_key(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn get_string(row: &BTreeMap<String, String>, key: &str) -> Option<String> {
    row.get(key)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
}

fn get_bool(row: &BTreeMap<String, String>, key: &str) -> Option<bool> {
    row.get(key).and_then(|v| parse_bool_opt(Some(v.as_str())))
}

fn get_u64(row: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    row.get(key).and_then(|v| parse_u64_opt(Some(v.as_str())))
}

fn get_i64(row: &BTreeMap<String, String>, key: &str) -> Option<i64> {
    row.get(key).and_then(|v| parse_i64_opt(Some(v.as_str())))
}

fn get_f64(row: &BTreeMap<String, String>, key: &str) -> Option<f64> {
    row.get(key).and_then(|v| parse_f64_opt(Some(v.as_str())))
}

fn parse_bool_opt(input: Option<&str>) -> Option<bool> {
    let raw = input?.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("n/a") {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_u64_opt(input: Option<&str>) -> Option<u64> {
    let raw = normalize_numeric(input?)?;
    if let Ok(v) = raw.parse::<u64>() {
        return Some(v);
    }
    raw.parse::<f64>().ok().map(|v| v as u64)
}

fn parse_i64_opt(input: Option<&str>) -> Option<i64> {
    let raw = normalize_numeric(input?)?;
    if let Ok(v) = raw.parse::<i64>() {
        return Some(v);
    }
    raw.parse::<f64>().ok().map(|v| v as i64)
}

fn parse_f64_opt(input: Option<&str>) -> Option<f64> {
    let raw = normalize_numeric(input?)?;
    raw.parse::<f64>().ok()
}

fn normalize_numeric(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("n/a")
        || trimmed.eq_ignore_ascii_case("na")
        || trimmed.eq_ignore_ascii_case("nan")
    {
        return None;
    }
    Some(trimmed)
}

fn value_to_f64(v: &serde_json::Value) -> Option<f64> {
    if let Some(n) = v.as_f64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        return parse_f64_opt(Some(s));
    }
    None
}

fn infer_host_and_timestamp(source_path: &Path) -> (Option<String>, Option<String>) {
    let parts: Vec<String> = source_path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    let host_tag = if let Some(pos) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("perf_results"))
    {
        parts.get(pos + 1).cloned()
    } else {
        parts.first().cloned().and_then(|first| {
            if matches!(first.as_str(), "AMD" | "Intel" | "local" | "unlabeled") {
                Some(first)
            } else {
                None
            }
        })
    };

    let timestamp = source_path
        .file_name()
        .and_then(|f| f.to_str())
        .and_then(|name| timestamp_regex().captures(name))
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()));

    (host_tag, timestamp)
}

fn timestamp_regex() -> &'static Regex {
    static TIMESTAMP_RE: OnceLock<Regex> = OnceLock::new();
    TIMESTAMP_RE
        .get_or_init(|| Regex::new(r"(\d{8}_[A-Za-z0-9]+)").expect("timestamp regex must compile"))
}

fn extract_fixed_distance_from_label(label: &str) -> Option<i64> {
    let trimmed = label.trim();
    if let Some(v) = trimmed.strip_prefix("fixed_d") {
        return parse_i64_opt(Some(v));
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return parse_i64_opt(Some(trimmed));
    }
    None
}

fn first_i64_segment(raw: &str) -> Option<i64> {
    raw.split(';')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .and_then(|s| parse_i64_opt(Some(s)))
}

fn load_single_csv_row(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = read_text(path).ok()?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = reader.headers().ok()?.clone();
    let record = reader.records().next()?.ok()?;
    Some(record_to_map(&headers, &record))
}

fn resolve_artifact_path(root: &Path, source_path: &Path, raw: &str) -> Option<PathBuf> {
    let normalized = normalize_path(raw);
    if normalized.is_empty() {
        return None;
    }

    let direct = PathBuf::from(&normalized);
    if direct.exists() {
        return Some(direct);
    }

    if let Some(p) = source_path.parent().map(|parent| parent.join(&normalized)) {
        if p.exists() {
            return Some(p);
        }
    }

    let join_root = root.join(&normalized);
    if join_root.exists() {
        return Some(join_root);
    }

    if let Some(idx) = normalized.find("perf_results/") {
        let tail = &normalized[idx..];
        if let Some(repo_root) = root.parent() {
            let p = repo_root.join(tail);
            if p.exists() {
                return Some(p);
            }
        }
    }

    None
}

fn normalize_path(raw: &str) -> String {
    raw.trim().replace('\\', "/")
}

fn is_perf_core_key(k: &str) -> bool {
    matches!(
        k,
        "mode"
            | "jit_requested"
            | "jit_fast_regs"
            | "jit_active"
            | "iters"
            | "warmup"
            | "threads"
            | "inputs"
            | "hashes"
            | "elapsed_ns"
            | "ns_per_hash"
            | "hashes_per_sec"
            | "prefetch"
            | "prefetch_distance"
            | "prefetch_auto_tune"
            | "scratchpad_prefetch_distance"
            | "git_sha_short"
            | "cpu"
            | "features"
    )
}

fn read_text(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(decode_bytes_to_text(&bytes).unwrap_or_else(|| String::from_utf8_lossy(&bytes).to_string()))
}

fn decode_bytes_to_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }

    if bytes.starts_with(&[0xFF, 0xFE]) {
        let (cow, _, _) = UTF_16LE.decode(&bytes[2..]);
        return Some(cow.into_owned());
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let (cow, _, _) = UTF_16BE.decode(&bytes[2..]);
        return Some(cow.into_owned());
    }

    if let Ok(s) = std::str::from_utf8(bytes) {
        return Some(s.to_string());
    }

    if looks_like_utf16le_without_bom(bytes) {
        let (cow, _, _) = UTF_16LE.decode(bytes);
        return Some(cow.into_owned());
    }

    None
}

fn looks_like_utf16le_without_bom(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let sample_len = bytes.len().min(512);
    let sample = &bytes[..sample_len];
    let mut zero_odd = 0usize;
    let mut odd_total = 0usize;

    for (idx, b) in sample.iter().enumerate() {
        if idx % 2 == 1 {
            odd_total += 1;
            if *b == 0 {
                zero_odd += 1;
            }
        }
    }

    odd_total > 0 && (zero_odd as f64 / odd_total as f64) > 0.3
}

fn detect_encoding_hint_from_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "empty".to_string();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return "utf-16le".to_string();
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return "utf-16be".to_string();
    }
    if std::str::from_utf8(bytes).is_ok() {
        return "utf-8/ascii".to_string();
    }
    if looks_like_utf16le_without_bom(bytes) {
        return "utf-16le(no-bom)".to_string();
    }
    "binary".to_string()
}

#[allow(dead_code)]
pub fn read_text_preview(path: &Path, max_bytes: usize) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.is_empty() {
        return Ok("<empty file>".to_string());
    }

    let truncated = bytes.len() > max_bytes;
    let slice = &bytes[..bytes.len().min(max_bytes)];

    let content = if let Some(text) = decode_bytes_to_text(slice) {
        text
    } else {
        return Ok(format!(
            "<binary file: {} bytes, showing disabled>",
            bytes.len()
        ));
    };

    if truncated {
        Ok(format!(
            "{content}\n\n[truncated: showing first {} of {} bytes]",
            slice.len(),
            bytes.len()
        ))
    } else {
        Ok(content)
    }
}
