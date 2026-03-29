use crate::model::{Dataset, PerfRunRecord, PrefetchManifestRow};
use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone)]
struct MetricCatalog {
    perf_metrics: Vec<String>,
    manifest_metrics: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UiOptions {
    perf_metrics: Vec<String>,
    manifest_metrics: Vec<String>,
    hosts_perf: Vec<String>,
    modes_perf: Vec<String>,
    jits_perf: Vec<String>,
    hosts_manifest: Vec<String>,
    modes_manifest: Vec<String>,
    jits_manifest: Vec<String>,
    scenarios_manifest: Vec<String>,
    color_options_perf: Vec<String>,
    color_options_manifest: Vec<String>,
}

#[derive(Clone)]
struct WebState {
    dataset: Arc<Dataset>,
    metrics: Arc<MetricCatalog>,
    options: Arc<UiOptions>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataKind {
    Perf,
    Manifest,
}

impl DataKind {
    fn parse(input: Option<&str>) -> Self {
        match input.unwrap_or("perf").to_ascii_lowercase().as_str() {
            "manifest" | "prefetch_manifest" => Self::Manifest,
            _ => Self::Perf,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Perf => "perf",
            Self::Manifest => "manifest",
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct CorrelationQuery {
    dataset: Option<String>,
    x_metric: Option<String>,
    y_metric: Option<String>,
    color_by: Option<String>,
    host: Option<String>,
    mode: Option<String>,
    jit: Option<String>,
    scenario: Option<String>,
    max_points: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct MatrixQuery {
    dataset: Option<String>,
    host: Option<String>,
    mode: Option<String>,
    jit: Option<String>,
    scenario: Option<String>,
    max_metrics: Option<usize>,
    coverage_sort: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct PrefetchQuery {
    host: Option<String>,
    scenario: Option<String>,
    mode: Option<String>,
    jit: Option<String>,
    only_with_ns_per_hash: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct ExplanationsQuery {
    host: Option<String>,
    scenario: Option<String>,
    mode: Option<String>,
    jit: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AnalyticsQuery {
    host: Option<String>,
    scenario: Option<String>,
    mode: Option<String>,
    jit: Option<String>,
    max_anomalies: Option<usize>,
    max_timeline_points: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
struct ChartPoint {
    x: f64,
    y: f64,
    color: String,
}

#[derive(Debug, Clone, Serialize)]
struct GroupStats {
    group: String,
    mean: f64,
    stddev: f64,
    count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct TopCorrelation {
    metric: String,
    pearson_r: f64,
    pairs: usize,
}

#[derive(Debug, Clone, Serialize)]
struct RegressionLine {
    slope: f64,
    intercept: f64,
}

#[derive(Debug, Clone, Serialize)]
struct SummaryStats {
    count: usize,
    min: Option<f64>,
    median: Option<f64>,
    mean: Option<f64>,
    max: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct CorrelationResponse {
    dataset: String,
    x_metric: String,
    y_metric: String,
    pearson_r: Option<f64>,
    r_squared: Option<f64>,
    regression: Option<RegressionLine>,
    points: Vec<ChartPoint>,
    group_stats: Vec<GroupStats>,
    top_correlations: Vec<TopCorrelation>,
    x_summary: SummaryStats,
    y_summary: SummaryStats,
}

#[derive(Debug, Clone, Serialize)]
struct MatrixResponse {
    dataset: String,
    metrics: Vec<String>,
    r_values: Vec<Vec<Option<f64>>>,
    pair_counts: Vec<Vec<usize>>,
}

#[derive(Debug, Clone, Serialize)]
struct DriftPoint {
    label: String,
    drift_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
struct PrefetchHeatmap {
    x_distances: Vec<i64>,
    y_scenarios: Vec<String>,
    z_values: Vec<Vec<Option<f64>>>,
}

#[derive(Debug, Clone, Serialize)]
struct PrefetchResponse {
    stats: SummaryStats,
    fixed_points: Vec<[f64; 2]>,
    auto_points: Vec<[f64; 2]>,
    drift: Vec<DriftPoint>,
    heatmap: PrefetchHeatmap,
}

#[derive(Debug, Clone, Serialize)]
struct NamedCount {
    name: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ExplanationCard {
    title: String,
    value: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct ExplanationFinding {
    title: String,
    explanation: String,
}

#[derive(Debug, Clone, Serialize)]
struct ScenarioScore {
    scenario: String,
    mean_ns_per_hash: f64,
    rows: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DriftHotspot {
    key: String,
    drift_pct: f64,
    rows: usize,
}

#[derive(Debug, Clone, Serialize)]
struct AutoFixedSummary {
    auto_rows: usize,
    fixed_rows: usize,
    auto_mean_ns_per_hash: Option<f64>,
    fixed_mean_ns_per_hash: Option<f64>,
    delta_pct_auto_vs_fixed: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct ExplanationsResponse {
    cards: Vec<ExplanationCard>,
    findings: Vec<ExplanationFinding>,
    host_counts: Vec<NamedCount>,
    scenario_scores: Vec<ScenarioScore>,
    drift_hotspots: Vec<DriftHotspot>,
    perf_top_correlations: Vec<TopCorrelation>,
    manifest_top_correlations: Vec<TopCorrelation>,
    auto_vs_fixed: AutoFixedSummary,
}

#[derive(Debug, Clone, Serialize)]
struct DatasetOverview {
    scope: String,
    total_files: usize,
    total_perf_rows: usize,
    total_manifest_rows: usize,
    total_hosts: usize,
    total_modes: usize,
    total_jits: usize,
    total_scenarios: usize,
    parse_errors: usize,
    parse_error_rate_pct: f64,
    scope_perf_rows: usize,
    scope_manifest_rows: usize,
    latest_delta_label: String,
    latest_delta_pct: Option<f64>,
    ingest_health: Vec<ExplanationCard>,
    snapshots: Vec<SnapshotPoint>,
    schema_totals: Vec<NamedCount>,
}

#[derive(Debug, Clone, Serialize)]
struct SnapshotPoint {
    bucket: String,
    perf_rows: usize,
    manifest_rows: usize,
    files: usize,
}

#[derive(Debug, Clone, Serialize)]
struct HeatmapCell {
    value: f64,
    missing_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct HeatmapPayload {
    x_labels: Vec<String>,
    y_labels: Vec<String>,
    cells: Vec<Vec<HeatmapCell>>,
}

#[derive(Debug, Clone, Serialize)]
struct CoverageMaps {
    host_mode: HeatmapPayload,
    host_jit: HeatmapPayload,
    scenario_distance: HeatmapPayload,
}

#[derive(Debug, Clone, Serialize)]
struct NullRateRow {
    column: String,
    missing: usize,
    total: usize,
    missing_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
struct SchemaTimeRow {
    bucket: String,
    schema: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DataQualityReport {
    parse_errors_by_extension: Vec<NamedCount>,
    null_rates_perf: Vec<NullRateRow>,
    null_rates_manifest: Vec<NullRateRow>,
    schema_time_series: Vec<SchemaTimeRow>,
}

#[derive(Debug, Clone, Serialize)]
struct DriftControlPoint {
    key: String,
    timestamp: String,
    drift_pct: f64,
    center_line: f64,
    upper_control: f64,
    lower_control: f64,
}

#[derive(Debug, Clone, Serialize)]
struct RepeatabilityScore {
    key: String,
    scenario: String,
    setting: String,
    rows: usize,
    mean_ns_per_hash: f64,
    stddev_ns_per_hash: f64,
    cv_pct: f64,
    repeatability_score: f64,
}

#[derive(Debug, Clone, Serialize)]
struct StabilityLab {
    cv_distribution: Vec<f64>,
    drift_control: Vec<DriftControlPoint>,
    stable_top: Vec<RepeatabilityScore>,
    unstable_top: Vec<RepeatabilityScore>,
}

#[derive(Debug, Clone, Serialize)]
struct HostBenchmarkGroup {
    host: String,
    mode: String,
    jit: String,
    rows: usize,
    mean_ns_per_hash: Option<f64>,
    ns_ci95: Option<f64>,
    mean_hashes_per_sec: Option<f64>,
    hps_ci95: Option<f64>,
    ns_normalized: Option<f64>,
    hps_normalized: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct PairwiseDeltaRow {
    mode: String,
    jit: String,
    host: String,
    baseline_host: String,
    delta_ns_pct: f64,
    delta_ci95_pct: Option<f64>,
    rows: usize,
}

#[derive(Debug, Clone, Serialize)]
struct HostBenchmarkArena {
    groups: Vec<HostBenchmarkGroup>,
    pairwise_deltas: Vec<PairwiseDeltaRow>,
}

#[derive(Debug, Clone, Serialize)]
struct ParetoPoint {
    id: String,
    scenario: String,
    setting: String,
    distance: Option<i64>,
    host: String,
    mode: String,
    jit: String,
    rows: usize,
    mean_ns_per_hash: f64,
    stddev_ns_per_hash: f64,
    cv_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ParetoFrontier {
    points: Vec<ParetoPoint>,
    frontier_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AnomalyEntry {
    id: String,
    source_path: String,
    host: String,
    mode: String,
    jit: String,
    scenario: String,
    setting: String,
    run_index: Option<u64>,
    ns_per_hash: f64,
    hashes_per_sec: Option<f64>,
    robust_z: f64,
    iqr_low: Option<f64>,
    iqr_high: Option<f64>,
    deviation_pct_from_group_median: Option<f64>,
    reason: String,
    artifact_csv: Option<String>,
    artifact_stdout: Option<String>,
    artifact_stderr: Option<String>,
    group_series: Vec<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct AnomalyForensics {
    global_median_ns: Option<f64>,
    global_mad_ns: Option<f64>,
    anomalies: Vec<AnomalyEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct TimelinePoint {
    bucket: String,
    perf_rows: usize,
    manifest_rows: usize,
    perf_mean_ns_per_hash: Option<f64>,
    manifest_mean_ns_per_hash: Option<f64>,
    perf_mean_hashes_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct ChangePoint {
    bucket: String,
    metric: String,
    pct_change: f64,
    from_value: f64,
    to_value: f64,
}

#[derive(Debug, Clone, Serialize)]
struct TimelineWatch {
    points: Vec<TimelinePoint>,
    change_points: Vec<ChangePoint>,
}

#[derive(Debug, Clone, Serialize)]
struct AnalyticsResponse {
    scope: String,
    overview: DatasetOverview,
    coverage: CoverageMaps,
    quality: DataQualityReport,
    stability: StabilityLab,
    host_benchmark: HostBenchmarkArena,
    pareto: ParetoFrontier,
    anomalies: AnomalyForensics,
    timeline: TimelineWatch,
}

pub async fn serve_web_app(
    dataset: Dataset,
    host: &str,
    port: u16,
    open_browser: bool,
) -> Result<()> {
    let dataset = Arc::new(dataset);
    let metrics = Arc::new(build_metric_catalog(&dataset));
    let options = Arc::new(build_ui_options(&dataset, &metrics));
    let state = WebState {
        dataset,
        metrics,
        options,
    };

    let app = Router::new()
        .route("/", get(index_html))
        .route("/explanations", get(explanations_html))
        .route("/static/styles.css", get(styles_css))
        .route("/static/app.js", get(app_js))
        .route("/static/explanations.js", get(explanations_js))
        .route("/api/options", get(api_options))
        .route("/api/correlation", get(api_correlation))
        .route("/api/matrix", get(api_matrix))
        .route("/api/prefetch", get(api_prefetch))
        .route("/api/analytics", get(api_analytics))
        .route("/api/explanations", get(api_explanations))
        .with_state(state);

    let addr_str = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr_str)
        .await
        .with_context(|| format!("failed to bind {addr_str}"))?;

    let url = format!("http://{addr_str}/");
    println!("perf_viz web dashboard: {url}");
    if open_browser {
        let _ = webbrowser::open(&url);
    }

    axum::serve(listener, app)
        .await
        .context("web server failed")?;
    Ok(())
}

async fn index_html() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn explanations_html() -> Html<&'static str> {
    Html(EXPLANATIONS_HTML)
}

async fn styles_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLES_CSS,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
}

async fn explanations_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        EXPLANATIONS_JS,
    )
}

async fn api_options(State(state): State<WebState>) -> Json<UiOptions> {
    Json((*state.options).clone())
}

async fn api_correlation(
    State(state): State<WebState>,
    Query(query): Query<CorrelationQuery>,
) -> Json<CorrelationResponse> {
    let kind = DataKind::parse(query.dataset.as_deref());
    let max_points = query.max_points.unwrap_or(18_000).max(500);

    let x_metric = match kind {
        DataKind::Perf => pick_metric(
            &state.metrics.perf_metrics,
            query.x_metric.as_deref(),
            "prefetch_distance",
        ),
        DataKind::Manifest => pick_metric(
            &state.metrics.manifest_metrics,
            query.x_metric.as_deref(),
            "effective_prefetch_distance",
        ),
    };
    let y_metric = match kind {
        DataKind::Perf => pick_metric(
            &state.metrics.perf_metrics,
            query.y_metric.as_deref(),
            "ns_per_hash",
        ),
        DataKind::Manifest => pick_metric(
            &state.metrics.manifest_metrics,
            query.y_metric.as_deref(),
            "ns_per_hash",
        ),
    };

    let filters = FilterSet::from_query(&query.host, &query.mode, &query.jit, &query.scenario);
    let color_by =
        normalize_filter(query.color_by.as_deref()).unwrap_or_else(|| "mode".to_string());

    let (mut points, top_correlations) = match kind {
        DataKind::Perf => {
            let rows = filtered_perf_rows(&state.dataset, &filters);
            let points = rows
                .iter()
                .filter_map(|row| {
                    let x = perf_metric_value(row, &x_metric)?;
                    let y = perf_metric_value(row, &y_metric)?;
                    if !x.is_finite() || !y.is_finite() {
                        return None;
                    }
                    Some(ChartPoint {
                        x,
                        y,
                        color: perf_color_key(row, &color_by),
                    })
                })
                .collect::<Vec<_>>();
            let top = ranked_correlations_perf(&rows, &state.metrics.perf_metrics, &y_metric)
                .into_iter()
                .take(40)
                .collect::<Vec<_>>();
            (points, top)
        }
        DataKind::Manifest => {
            let rows = filtered_manifest_rows(&state.dataset, &filters);
            let points = rows
                .iter()
                .filter_map(|row| {
                    let x = manifest_metric_value(row, &x_metric)?;
                    let y = manifest_metric_value(row, &y_metric)?;
                    if !x.is_finite() || !y.is_finite() {
                        return None;
                    }
                    Some(ChartPoint {
                        x,
                        y,
                        color: manifest_color_key(row, &color_by),
                    })
                })
                .collect::<Vec<_>>();
            let top =
                ranked_correlations_manifest(&rows, &state.metrics.manifest_metrics, &y_metric)
                    .into_iter()
                    .take(40)
                    .collect::<Vec<_>>();
            (points, top)
        }
    };

    if points.len() > max_points {
        points = deterministic_sample(points, max_points);
    }

    let pairs: Vec<(f64, f64)> = points.iter().map(|p| (p.x, p.y)).collect();
    let pearson_r = pearson_from_pairs(&pairs);
    let r_squared = pearson_r.map(|r| r * r);
    let regression = linear_regression_from_pairs(&pairs)
        .map(|(slope, intercept)| RegressionLine { slope, intercept });

    let mut grouped: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for p in &points {
        grouped.entry(p.color.clone()).or_default().push(p.y);
    }
    let mut group_stats = grouped
        .into_iter()
        .filter_map(|(group, values)| {
            if values.is_empty() {
                return None;
            }
            let mean = values.iter().sum::<f64>() / values.len() as f64;
            let variance = values
                .iter()
                .map(|v| {
                    let d = *v - mean;
                    d * d
                })
                .sum::<f64>()
                / values.len() as f64;
            Some(GroupStats {
                group,
                mean,
                stddev: variance.sqrt(),
                count: values.len(),
            })
        })
        .collect::<Vec<_>>();
    group_stats.sort_by(|a, b| a.mean.partial_cmp(&b.mean).unwrap_or(Ordering::Equal));

    let x_summary = summary_stats(points.iter().map(|p| p.x));
    let y_summary = summary_stats(points.iter().map(|p| p.y));

    Json(CorrelationResponse {
        dataset: kind.as_str().to_string(),
        x_metric,
        y_metric,
        pearson_r,
        r_squared,
        regression,
        points,
        group_stats,
        top_correlations: top_correlations
            .into_iter()
            .map(|(metric, pearson_r, pairs)| TopCorrelation {
                metric,
                pearson_r,
                pairs,
            })
            .collect(),
        x_summary,
        y_summary,
    })
}

async fn api_matrix(
    State(state): State<WebState>,
    Query(query): Query<MatrixQuery>,
) -> Json<MatrixResponse> {
    let kind = DataKind::parse(query.dataset.as_deref());
    let max_metrics = query.max_metrics.unwrap_or(18).clamp(4, 40);
    let coverage_sort = query.coverage_sort.unwrap_or(true);
    let filters = FilterSet::from_query(&query.host, &query.mode, &query.jit, &query.scenario);

    let (metrics, columns): (Vec<String>, Vec<Vec<Option<f64>>>) = match kind {
        DataKind::Perf => {
            let rows = filtered_perf_rows(&state.dataset, &filters);
            let mut scored = state
                .metrics
                .perf_metrics
                .iter()
                .map(|metric| {
                    let coverage = rows
                        .iter()
                        .filter(|r| {
                            perf_metric_value(r, metric)
                                .map(|v| v.is_finite())
                                .unwrap_or(false)
                        })
                        .count();
                    (metric.clone(), coverage)
                })
                .filter(|(_, c)| *c >= 3)
                .collect::<Vec<_>>();
            if coverage_sort {
                scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            } else {
                scored.sort_by(|a, b| a.0.cmp(&b.0));
            }
            let metrics = scored
                .into_iter()
                .take(max_metrics)
                .map(|(metric, _)| metric)
                .collect::<Vec<_>>();
            let columns = metrics
                .iter()
                .map(|m| {
                    rows.iter()
                        .map(|r| perf_metric_value(r, m))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            (metrics, columns)
        }
        DataKind::Manifest => {
            let rows = filtered_manifest_rows(&state.dataset, &filters);
            let mut scored = state
                .metrics
                .manifest_metrics
                .iter()
                .map(|metric| {
                    let coverage = rows
                        .iter()
                        .filter(|r| {
                            manifest_metric_value(r, metric)
                                .map(|v| v.is_finite())
                                .unwrap_or(false)
                        })
                        .count();
                    (metric.clone(), coverage)
                })
                .filter(|(_, c)| *c >= 3)
                .collect::<Vec<_>>();
            if coverage_sort {
                scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            } else {
                scored.sort_by(|a, b| a.0.cmp(&b.0));
            }
            let metrics = scored
                .into_iter()
                .take(max_metrics)
                .map(|(metric, _)| metric)
                .collect::<Vec<_>>();
            let columns = metrics
                .iter()
                .map(|m| {
                    rows.iter()
                        .map(|r| manifest_metric_value(r, m))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            (metrics, columns)
        }
    };

    let n = metrics.len();
    let mut r_values = vec![vec![None; n]; n];
    let mut pair_counts = vec![vec![0usize; n]; n];
    for y in 0..n {
        for x in 0..n {
            let mut pairs = Vec::new();
            for (xv, yv) in columns[x].iter().zip(columns[y].iter()) {
                if let (Some(xv), Some(yv)) = (xv, yv) {
                    if xv.is_finite() && yv.is_finite() {
                        pairs.push((*xv, *yv));
                    }
                }
            }
            pair_counts[y][x] = pairs.len();
            r_values[y][x] = if x == y {
                if pairs.len() >= 2 {
                    Some(1.0)
                } else {
                    None
                }
            } else {
                pearson_from_pairs(&pairs)
            };
        }
    }

    Json(MatrixResponse {
        dataset: kind.as_str().to_string(),
        metrics,
        r_values,
        pair_counts,
    })
}

async fn api_prefetch(
    State(state): State<WebState>,
    Query(query): Query<PrefetchQuery>,
) -> Json<PrefetchResponse> {
    let filters = FilterSet::from_query(&query.host, &query.mode, &query.jit, &query.scenario);
    let only_with_ns = query.only_with_ns_per_hash.unwrap_or(false);

    let rows = state
        .dataset
        .prefetch_manifest_rows
        .iter()
        .filter(|row| {
            let host = row
                .host_tag
                .as_deref()
                .map(canonical_label)
                .or_else(|| infer_host_from_any_path(&row.source_path));
            match_filter(&filters.host, host.as_deref())
        })
        .filter(|row| {
            let mode = canonical_option_label(row.mode.as_deref());
            match_filter(&filters.mode, mode.as_deref())
        })
        .filter(|row| match_jit_filter(&filters.jit, row.jit.as_deref()))
        .filter(|row| {
            let scenario = canonical_option_label(row.scenario_id.as_deref());
            match_filter(&filters.scenario, scenario.as_deref())
        })
        .filter(|row| !only_with_ns || row.ns_per_hash.is_some())
        .collect::<Vec<_>>();

    let mut fixed_points = Vec::new();
    let mut auto_points = Vec::new();
    let mut ns_values = Vec::new();

    for row in &rows {
        let Some(ns) = row.ns_per_hash else {
            continue;
        };
        let Some(distance) = row.effective_prefetch_distance.or(row.requested_distance) else {
            continue;
        };
        ns_values.push(ns);
        let is_auto = row.requested_auto.unwrap_or_else(|| {
            row.setting_kind
                .as_deref()
                .map(|k| k.eq_ignore_ascii_case("auto"))
                .unwrap_or(false)
        });
        if is_auto {
            auto_points.push([distance as f64, ns]);
        } else {
            fixed_points.push([distance as f64, ns]);
        }
    }

    let mut drift_groups: BTreeMap<String, Vec<&PrefetchManifestRow>> = BTreeMap::new();
    for row in &rows {
        let key = format!(
            "{} | {} | {}",
            canonical_or_unknown(row.scenario_id.as_deref()),
            canonical_or_unknown(row.setting_label.as_deref()),
            canonical_or_unknown(row.setting_kind.as_deref())
        );
        drift_groups.entry(key).or_default().push(row);
    }
    let mut drift = Vec::new();
    for (label, grouped) in drift_groups {
        let mut grouped = grouped;
        grouped.sort_by_key(|r| r.run_index.unwrap_or(0));
        let first = grouped.first().and_then(|r| r.ns_per_hash);
        let last = grouped.last().and_then(|r| r.ns_per_hash);
        if let (Some(first), Some(last)) = (first, last) {
            if first.abs() > f64::EPSILON {
                drift.push(DriftPoint {
                    label,
                    drift_pct: ((last / first) - 1.0) * 100.0,
                });
            }
        }
    }
    drift.sort_by(|a, b| a.label.cmp(&b.label));

    let mut heatmap_bucket: BTreeMap<(String, i64), (f64, usize)> = BTreeMap::new();
    let mut scenario_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut distances_set = BTreeSet::new();
    for row in &rows {
        let Some(ns) = row.ns_per_hash else {
            continue;
        };
        let Some(distance) = row.effective_prefetch_distance.or(row.requested_distance) else {
            continue;
        };
        let scenario = row
            .scenario_id
            .as_deref()
            .map(canonical_label)
            .unwrap_or_else(|| "unknown".to_string());
        *scenario_counts.entry(scenario.clone()).or_insert(0) += 1;
        distances_set.insert(distance);
        let entry = heatmap_bucket
            .entry((scenario, distance))
            .or_insert((0.0, 0));
        entry.0 += ns;
        entry.1 += 1;
    }

    let mut scenarios = scenario_counts.into_iter().collect::<Vec<_>>();
    scenarios.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut y_scenarios = scenarios
        .into_iter()
        .map(|(scenario, _)| scenario)
        .take(28)
        .collect::<Vec<_>>();
    y_scenarios.sort();
    let x_distances = distances_set.into_iter().take(32).collect::<Vec<_>>();
    let z_values = y_scenarios
        .iter()
        .map(|scenario| {
            x_distances
                .iter()
                .map(|distance| {
                    heatmap_bucket
                        .get(&(scenario.clone(), *distance))
                        .map(|(sum, count)| sum / *count as f64)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    Json(PrefetchResponse {
        stats: summary_stats(ns_values.into_iter()),
        fixed_points,
        auto_points,
        drift,
        heatmap: PrefetchHeatmap {
            x_distances,
            y_scenarios,
            z_values,
        },
    })
}

async fn api_explanations(
    State(state): State<WebState>,
    Query(query): Query<ExplanationsQuery>,
) -> Json<ExplanationsResponse> {
    let filters = FilterSet::from_query(&query.host, &query.mode, &query.jit, &query.scenario);

    let perf_rows = filtered_perf_rows(&state.dataset, &filters);
    let manifest_rows = filtered_manifest_rows(&state.dataset, &filters);

    let perf_ns_stats = summary_stats(perf_rows.iter().filter_map(|r| r.ns_per_hash));
    let manifest_ns_stats = summary_stats(manifest_rows.iter().filter_map(|r| r.ns_per_hash));

    let mut host_scope_counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in &perf_rows {
        let host = infer_host_from_any_path(&row.source_path).unwrap_or_else(|| "unknown".into());
        *host_scope_counts.entry(host).or_insert(0) += 1;
    }
    for row in &manifest_rows {
        let host = row
            .host_tag
            .as_deref()
            .map(canonical_label)
            .or_else(|| infer_host_from_any_path(&row.source_path))
            .unwrap_or_else(|| "unknown".into());
        *host_scope_counts.entry(host).or_insert(0) += 1;
    }

    let mut host_counts = host_scope_counts
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect::<Vec<_>>();
    host_counts.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));

    let mut scenario_accum: BTreeMap<String, (f64, usize)> = BTreeMap::new();
    let mut auto_ns = Vec::new();
    let mut fixed_ns = Vec::new();
    for row in &manifest_rows {
        if let Some(ns) = row.ns_per_hash {
            let scenario = row
                .scenario_id
                .as_deref()
                .map(canonical_label)
                .unwrap_or_else(|| "unknown".to_string());
            let entry = scenario_accum.entry(scenario).or_insert((0.0, 0));
            entry.0 += ns;
            entry.1 += 1;

            let is_auto = row.requested_auto.unwrap_or_else(|| {
                row.setting_kind
                    .as_deref()
                    .map(|k| k.eq_ignore_ascii_case("auto"))
                    .unwrap_or(false)
            });
            if is_auto {
                auto_ns.push(ns);
            } else {
                fixed_ns.push(ns);
            }
        }
    }

    let mut scenario_scores = scenario_accum
        .into_iter()
        .filter_map(|(scenario, (sum, rows))| {
            if rows == 0 {
                return None;
            }
            Some(ScenarioScore {
                scenario,
                mean_ns_per_hash: sum / rows as f64,
                rows,
            })
        })
        .collect::<Vec<_>>();
    scenario_scores.sort_by(|a, b| {
        a.mean_ns_per_hash
            .partial_cmp(&b.mean_ns_per_hash)
            .unwrap_or(Ordering::Equal)
            .then(a.scenario.cmp(&b.scenario))
    });

    let mut drift_groups: BTreeMap<String, Vec<&PrefetchManifestRow>> = BTreeMap::new();
    for row in &manifest_rows {
        let key = format!(
            "{} | {} | {}",
            canonical_or_unknown(row.scenario_id.as_deref()),
            canonical_or_unknown(row.setting_label.as_deref()),
            canonical_or_unknown(row.setting_kind.as_deref())
        );
        drift_groups.entry(key).or_default().push(row);
    }
    let mut drift_hotspots = Vec::new();
    for (key, grouped) in drift_groups {
        let mut grouped = grouped;
        grouped.sort_by_key(|r| r.run_index.unwrap_or(0));
        let first = grouped.first().and_then(|r| r.ns_per_hash);
        let last = grouped.last().and_then(|r| r.ns_per_hash);
        if let (Some(first), Some(last)) = (first, last) {
            if first.abs() > f64::EPSILON {
                drift_hotspots.push(DriftHotspot {
                    key,
                    drift_pct: ((last / first) - 1.0) * 100.0,
                    rows: grouped.len(),
                });
            }
        }
    }
    drift_hotspots.sort_by(|a, b| {
        b.drift_pct
            .abs()
            .partial_cmp(&a.drift_pct.abs())
            .unwrap_or(Ordering::Equal)
    });

    let perf_top_correlations =
        ranked_correlations_perf(&perf_rows, &state.metrics.perf_metrics, "ns_per_hash")
            .into_iter()
            .take(10)
            .map(|(metric, pearson_r, pairs)| TopCorrelation {
                metric,
                pearson_r,
                pairs,
            })
            .collect::<Vec<_>>();
    let manifest_top_correlations = ranked_correlations_manifest(
        &manifest_rows,
        &state.metrics.manifest_metrics,
        "ns_per_hash",
    )
    .into_iter()
    .take(10)
    .map(|(metric, pearson_r, pairs)| TopCorrelation {
        metric,
        pearson_r,
        pairs,
    })
    .collect::<Vec<_>>();

    let auto_mean = mean_values(&auto_ns);
    let fixed_mean = mean_values(&fixed_ns);
    let auto_vs_fixed = AutoFixedSummary {
        auto_rows: auto_ns.len(),
        fixed_rows: fixed_ns.len(),
        auto_mean_ns_per_hash: auto_mean,
        fixed_mean_ns_per_hash: fixed_mean,
        delta_pct_auto_vs_fixed: match (auto_mean, fixed_mean) {
            (Some(auto), Some(fixed)) if fixed.abs() > f64::EPSILON => {
                Some(((auto / fixed) - 1.0) * 100.0)
            }
            _ => None,
        },
    };

    let scope = format_filter_scope(&filters);
    let cards = vec![
        ExplanationCard {
            title: "Scope".to_string(),
            value: scope,
            detail: "Scenario filter applies to prefetch manifest dimensions.".to_string(),
        },
        ExplanationCard {
            title: "Rows In Scope".to_string(),
            value: format!(
                "perf={} | manifest={}",
                perf_rows.len(),
                manifest_rows.len()
            ),
            detail: format!(
                "dataset totals: perf={} | manifest={} | files={}",
                state.dataset.perf_runs.len(),
                state.dataset.prefetch_manifest_rows.len(),
                state.dataset.catalog.len()
            ),
        },
        ExplanationCard {
            title: "Perf ns/hash (median)".to_string(),
            value: fmt_opt_num(perf_ns_stats.median, 4),
            detail: format!(
                "mean={} | count={}",
                fmt_opt_num(perf_ns_stats.mean, 4),
                perf_ns_stats.count
            ),
        },
        ExplanationCard {
            title: "Manifest ns/hash (median)".to_string(),
            value: fmt_opt_num(manifest_ns_stats.median, 4),
            detail: format!(
                "mean={} | count={}",
                fmt_opt_num(manifest_ns_stats.mean, 4),
                manifest_ns_stats.count
            ),
        },
        ExplanationCard {
            title: "Auto vs Fixed".to_string(),
            value: auto_vs_fixed
                .delta_pct_auto_vs_fixed
                .map(|v| format!("{v:.2}%"))
                .unwrap_or_else(|| "n/a".to_string()),
            detail: format!(
                "auto_mean={} vs fixed_mean={}",
                fmt_opt_num(auto_vs_fixed.auto_mean_ns_per_hash, 4),
                fmt_opt_num(auto_vs_fixed.fixed_mean_ns_per_hash, 4)
            ),
        },
    ];

    let mut findings = Vec::new();
    if let (Some(best), Some(worst)) = (scenario_scores.first(), scenario_scores.last()) {
        findings.push(ExplanationFinding {
            title: "Scenario Spread".to_string(),
            explanation: format!(
                "Best observed scenario mean is '{}' at {:.4} ns/hash, while worst is '{}' at {:.4} ns/hash ({} scenarios analyzed).",
                best.scenario,
                best.mean_ns_per_hash,
                worst.scenario,
                worst.mean_ns_per_hash,
                scenario_scores.len()
            ),
        });
    }
    if let Some(top) = perf_top_correlations.first() {
        findings.push(ExplanationFinding {
            title: "Strongest Perf Correlate".to_string(),
            explanation: format!(
                "'{}' has {} correlation with ns_per_hash (r={:.4}, pairs={}).",
                top.metric,
                corr_direction(top.pearson_r),
                top.pearson_r,
                top.pairs
            ),
        });
    }
    if let Some(top) = manifest_top_correlations.first() {
        findings.push(ExplanationFinding {
            title: "Strongest Manifest Correlate".to_string(),
            explanation: format!(
                "'{}' has {} correlation with ns_per_hash (r={:.4}, pairs={}).",
                top.metric,
                corr_direction(top.pearson_r),
                top.pearson_r,
                top.pairs
            ),
        });
    }
    if let Some(hotspot) = drift_hotspots.first() {
        findings.push(ExplanationFinding {
            title: "Largest Drift Hotspot".to_string(),
            explanation: format!(
                "'{}' shows {:.4}% run-order drift across {} rows; this setting should be validated for stability.",
                hotspot.key, hotspot.drift_pct, hotspot.rows
            ),
        });
    }
    if state.dataset.parse_errors.is_empty() {
        findings.push(ExplanationFinding {
            title: "Ingest Health".to_string(),
            explanation: "No ingest parse errors were recorded in this dataset snapshot."
                .to_string(),
        });
    } else {
        findings.push(ExplanationFinding {
            title: "Ingest Health".to_string(),
            explanation: format!(
                "{} ingest parse errors were recorded. Validate affected files before making high-confidence conclusions.",
                state.dataset.parse_errors.len()
            ),
        });
    }

    Json(ExplanationsResponse {
        cards,
        findings,
        host_counts,
        scenario_scores,
        drift_hotspots,
        perf_top_correlations,
        manifest_top_correlations,
        auto_vs_fixed,
    })
}

async fn api_analytics(
    State(state): State<WebState>,
    Query(query): Query<AnalyticsQuery>,
) -> Json<AnalyticsResponse> {
    let filters = FilterSet::from_query(&query.host, &query.mode, &query.jit, &query.scenario);
    let scope = format_filter_scope(&filters);
    let max_anomalies = query.max_anomalies.unwrap_or(120).clamp(20, 400);
    let max_timeline_points = query.max_timeline_points.unwrap_or(180).clamp(24, 720);

    let perf_rows = filtered_perf_rows(&state.dataset, &filters);
    let manifest_rows = filtered_manifest_rows(&state.dataset, &filters);
    let settings_rows = filtered_settings_rows(&state.dataset, &filters);

    let timeline = build_timeline_watch(
        &state.dataset,
        &perf_rows,
        &manifest_rows,
        max_timeline_points,
    );
    let overview = build_dataset_overview(
        &state.dataset,
        &filters,
        &scope,
        &perf_rows,
        &manifest_rows,
        &timeline.points,
    );
    let coverage = build_coverage_maps(&perf_rows, &manifest_rows);
    let quality = build_quality_report(
        &state.dataset,
        &state.metrics,
        &filters,
        &perf_rows,
        &manifest_rows,
    );
    let stability = build_stability_lab(&settings_rows, &manifest_rows);
    let host_benchmark = build_host_benchmark_arena(&perf_rows);
    let pareto = build_pareto_frontier(&manifest_rows);
    let anomalies = build_anomaly_forensics(&manifest_rows, max_anomalies);

    Json(AnalyticsResponse {
        scope,
        overview,
        coverage,
        quality,
        stability,
        host_benchmark,
        pareto,
        anomalies,
        timeline,
    })
}

#[derive(Debug, Clone, Default)]
struct FilterSet {
    host: Option<String>,
    mode: Option<String>,
    jit: Option<String>,
    scenario: Option<String>,
}

impl FilterSet {
    fn from_query(
        host: &Option<String>,
        mode: &Option<String>,
        jit: &Option<String>,
        scenario: &Option<String>,
    ) -> Self {
        Self {
            host: normalize_filter(host.as_deref()),
            mode: normalize_filter(mode.as_deref()),
            jit: normalize_filter(jit.as_deref()),
            scenario: normalize_filter(scenario.as_deref()),
        }
    }
}

fn build_metric_catalog(dataset: &Dataset) -> MetricCatalog {
    let mut perf_metrics = vec![
        "iters".to_string(),
        "warmup".to_string(),
        "threads".to_string(),
        "inputs".to_string(),
        "hashes".to_string(),
        "elapsed_ns".to_string(),
        "ns_per_hash".to_string(),
        "hashes_per_sec".to_string(),
        "prefetch_distance".to_string(),
        "scratchpad_prefetch_distance".to_string(),
    ];
    let mut extra_numeric_counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in &dataset.perf_runs {
        for (k, v) in &row.extra {
            if parse_f64_opt(Some(v.as_str())).is_some() {
                *extra_numeric_counts.entry(k.clone()).or_insert(0) += 1;
            }
        }
    }
    for (k, c) in extra_numeric_counts {
        if c >= 8 {
            perf_metrics.push(k);
        }
    }
    perf_metrics.sort();
    perf_metrics.dedup();

    let mut manifest_metrics = vec![
        "requested_distance".to_string(),
        "effective_prefetch_distance".to_string(),
        "repeat_index".to_string(),
        "order_position".to_string(),
        "run_index".to_string(),
        "ns_per_hash".to_string(),
        "hashes_per_sec".to_string(),
        "iters".to_string(),
        "warmup".to_string(),
        "threads".to_string(),
    ];
    manifest_metrics.sort();
    manifest_metrics.dedup();

    MetricCatalog {
        perf_metrics,
        manifest_metrics,
    }
}

fn build_ui_options(dataset: &Dataset, metrics: &MetricCatalog) -> UiOptions {
    UiOptions {
        perf_metrics: metrics.perf_metrics.clone(),
        manifest_metrics: metrics.manifest_metrics.clone(),
        hosts_perf: values_with_all(
            dataset
                .perf_runs
                .iter()
                .filter_map(|r| infer_host_from_any_path(&r.source_path)),
        ),
        modes_perf: values_with_all(
            dataset
                .perf_runs
                .iter()
                .filter_map(|r| r.mode.as_deref().map(ToOwned::to_owned)),
        ),
        jits_perf: values_with_all(dataset.perf_runs.iter().map(|r| match r.jit_requested {
            Some(true) => "true".to_string(),
            Some(false) => "false".to_string(),
            None => "unknown".to_string(),
        })),
        hosts_manifest: values_with_all(
            dataset
                .prefetch_manifest_rows
                .iter()
                .filter_map(|r| r.host_tag.as_deref().map(ToOwned::to_owned)),
        ),
        modes_manifest: values_with_all(
            dataset
                .prefetch_manifest_rows
                .iter()
                .filter_map(|r| r.mode.as_deref().map(ToOwned::to_owned)),
        ),
        jits_manifest: values_with_all(
            dataset
                .prefetch_manifest_rows
                .iter()
                .filter_map(|r| r.jit.as_deref().map(normalize_jit_value)),
        ),
        scenarios_manifest: values_with_all(
            dataset
                .prefetch_manifest_rows
                .iter()
                .filter_map(|r| r.scenario_id.as_deref().map(ToOwned::to_owned)),
        ),
        color_options_perf: vec![
            "host".to_string(),
            "mode".to_string(),
            "jit".to_string(),
            "schema".to_string(),
            "prefetch_auto".to_string(),
        ],
        color_options_manifest: vec![
            "host".to_string(),
            "mode".to_string(),
            "jit".to_string(),
            "scenario".to_string(),
            "setting_kind".to_string(),
            "prefetch_auto".to_string(),
        ],
    }
}

fn pick_metric(metrics: &[String], requested: Option<&str>, preferred: &str) -> String {
    if let Some(req) = requested {
        if metrics.iter().any(|m| m == req) {
            return req.to_string();
        }
    }
    if metrics.iter().any(|m| m == preferred) {
        return preferred.to_string();
    }
    metrics
        .first()
        .cloned()
        .unwrap_or_else(|| preferred.to_string())
}

fn filtered_perf_rows<'a>(dataset: &'a Dataset, filters: &FilterSet) -> Vec<&'a PerfRunRecord> {
    dataset
        .perf_runs
        .iter()
        .filter(|row| {
            let host = infer_host_from_any_path(&row.source_path);
            match_filter(&filters.host, host.as_deref())
        })
        .filter(|row| match_filter(&filters.mode, row.mode.as_deref()))
        .filter(|row| {
            let jit = match row.jit_requested {
                Some(true) => "true",
                Some(false) => "false",
                None => "unknown",
            };
            match_jit_filter(&filters.jit, Some(jit))
        })
        .collect()
}

fn filtered_manifest_rows<'a>(
    dataset: &'a Dataset,
    filters: &FilterSet,
) -> Vec<&'a PrefetchManifestRow> {
    dataset
        .prefetch_manifest_rows
        .iter()
        .filter(|row| {
            let host = row
                .host_tag
                .as_deref()
                .map(canonical_label)
                .or_else(|| infer_host_from_any_path(&row.source_path));
            match_filter(&filters.host, host.as_deref())
        })
        .filter(|row| {
            let mode = canonical_option_label(row.mode.as_deref());
            match_filter(&filters.mode, mode.as_deref())
        })
        .filter(|row| match_jit_filter(&filters.jit, row.jit.as_deref()))
        .filter(|row| {
            let scenario = canonical_option_label(row.scenario_id.as_deref());
            match_filter(&filters.scenario, scenario.as_deref())
        })
        .collect()
}

fn filtered_settings_rows<'a>(
    dataset: &'a Dataset,
    filters: &FilterSet,
) -> Vec<&'a crate::model::PrefetchSettingSummaryRow> {
    dataset
        .prefetch_settings_rows
        .iter()
        .filter(|row| {
            let host = row
                .host_tag
                .as_deref()
                .map(canonical_label)
                .or_else(|| infer_host_from_any_path(&row.source_path));
            match_filter(&filters.host, host.as_deref())
        })
        .filter(|row| {
            let mode = canonical_option_label(row.mode.as_deref());
            match_filter(&filters.mode, mode.as_deref())
        })
        .filter(|row| match_jit_filter(&filters.jit, row.jit.as_deref()))
        .filter(|row| {
            let scenario = canonical_option_label(row.scenario_id.as_deref());
            match_filter(&filters.scenario, scenario.as_deref())
        })
        .collect()
}

fn perf_metric_value(row: &PerfRunRecord, metric: &str) -> Option<f64> {
    match metric {
        "iters" => row.iters.map(|v| v as f64),
        "warmup" => row.warmup.map(|v| v as f64),
        "threads" => row.threads.map(|v| v as f64),
        "inputs" => row.inputs.map(|v| v as f64),
        "hashes" => row.hashes.map(|v| v as f64),
        "elapsed_ns" => row.elapsed_ns.map(|v| v as f64),
        "ns_per_hash" => row.ns_per_hash,
        "hashes_per_sec" => row.hashes_per_sec,
        "prefetch_distance" => row.prefetch_distance.map(|v| v as f64),
        "scratchpad_prefetch_distance" => row.scratchpad_prefetch_distance.map(|v| v as f64),
        _ => row
            .extra
            .get(metric)
            .and_then(|v| parse_f64_opt(Some(v.as_str()))),
    }
}

fn manifest_metric_value(row: &PrefetchManifestRow, metric: &str) -> Option<f64> {
    match metric {
        "requested_distance" => row.requested_distance.map(|v| v as f64),
        "effective_prefetch_distance" => row.effective_prefetch_distance.map(|v| v as f64),
        "repeat_index" => row.repeat_index.map(|v| v as f64),
        "order_position" => row.order_position.map(|v| v as f64),
        "run_index" => row.run_index.map(|v| v as f64),
        "ns_per_hash" => row.ns_per_hash,
        "hashes_per_sec" => row.hashes_per_sec,
        "iters" => row.iters.map(|v| v as f64),
        "warmup" => row.warmup.map(|v| v as f64),
        "threads" => row.threads.map(|v| v as f64),
        _ => None,
    }
}

fn perf_color_key(row: &PerfRunRecord, color_by: &str) -> String {
    match color_by {
        "host" => {
            infer_host_from_any_path(&row.source_path).unwrap_or_else(|| "unknown".to_string())
        }
        "mode" => canonical_or_unknown(row.mode.as_deref()),
        "jit" => match row.jit_requested {
            Some(true) => "jit:true".to_string(),
            Some(false) => "jit:false".to_string(),
            None => "jit:unknown".to_string(),
        },
        "schema" => row.schema_name.clone(),
        "prefetch_auto" => match row.prefetch_auto_tune {
            Some(true) => "auto:true".to_string(),
            Some(false) => "auto:false".to_string(),
            None => "auto:unknown".to_string(),
        },
        _ => "all".to_string(),
    }
}

fn manifest_color_key(row: &PrefetchManifestRow, color_by: &str) -> String {
    match color_by {
        "host" => row
            .host_tag
            .as_deref()
            .map(canonical_label)
            .or_else(|| infer_host_from_any_path(&row.source_path))
            .unwrap_or_else(|| "unknown".to_string()),
        "mode" => canonical_or_unknown(row.mode.as_deref()),
        "jit" => row
            .jit
            .as_deref()
            .map(normalize_jit_value)
            .unwrap_or_else(|| "unknown".to_string()),
        "scenario" => canonical_or_unknown(row.scenario_id.as_deref()),
        "setting_kind" => row
            .setting_kind
            .as_deref()
            .map(canonical_label)
            .unwrap_or_else(|| "unknown".to_string()),
        "prefetch_auto" => match row.requested_auto {
            Some(true) => "auto:true".to_string(),
            Some(false) => "auto:false".to_string(),
            None => "auto:unknown".to_string(),
        },
        _ => "all".to_string(),
    }
}

fn ranked_correlations_perf(
    rows: &[&PerfRunRecord],
    metrics: &[String],
    target_metric: &str,
) -> Vec<(String, f64, usize)> {
    let mut out = Vec::new();
    for metric in metrics {
        if metric == target_metric {
            continue;
        }
        let mut pairs = Vec::new();
        for row in rows {
            let x = perf_metric_value(row, metric);
            let y = perf_metric_value(row, target_metric);
            if let (Some(x), Some(y)) = (x, y) {
                if x.is_finite() && y.is_finite() {
                    pairs.push((x, y));
                }
            }
        }
        if pairs.len() < 3 {
            continue;
        }
        if let Some(r) = pearson_from_pairs(&pairs) {
            out.push((metric.clone(), r, pairs.len()));
        }
    }
    out.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap_or(Ordering::Equal));
    out
}

fn ranked_correlations_manifest(
    rows: &[&PrefetchManifestRow],
    metrics: &[String],
    target_metric: &str,
) -> Vec<(String, f64, usize)> {
    let mut out = Vec::new();
    for metric in metrics {
        if metric == target_metric {
            continue;
        }
        let mut pairs = Vec::new();
        for row in rows {
            let x = manifest_metric_value(row, metric);
            let y = manifest_metric_value(row, target_metric);
            if let (Some(x), Some(y)) = (x, y) {
                if x.is_finite() && y.is_finite() {
                    pairs.push((x, y));
                }
            }
        }
        if pairs.len() < 3 {
            continue;
        }
        if let Some(r) = pearson_from_pairs(&pairs) {
            out.push((metric.clone(), r, pairs.len()));
        }
    }
    out.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap_or(Ordering::Equal));
    out
}

fn pearson_from_pairs(pairs: &[(f64, f64)]) -> Option<f64> {
    if pairs.len() < 2 {
        return None;
    }
    let n = pairs.len() as f64;
    let sx = pairs.iter().map(|(x, _)| *x).sum::<f64>();
    let sy = pairs.iter().map(|(_, y)| *y).sum::<f64>();
    let sxx = pairs.iter().map(|(x, _)| x * x).sum::<f64>();
    let syy = pairs.iter().map(|(_, y)| y * y).sum::<f64>();
    let sxy = pairs.iter().map(|(x, y)| x * y).sum::<f64>();

    let cov_num = sxy - (sx * sy / n);
    let var_x = sxx - (sx * sx / n);
    let var_y = syy - (sy * sy / n);
    if var_x <= f64::EPSILON || var_y <= f64::EPSILON {
        return None;
    }
    Some(cov_num / (var_x.sqrt() * var_y.sqrt()))
}

fn linear_regression_from_pairs(pairs: &[(f64, f64)]) -> Option<(f64, f64)> {
    if pairs.len() < 2 {
        return None;
    }
    let n = pairs.len() as f64;
    let sx = pairs.iter().map(|(x, _)| *x).sum::<f64>();
    let sy = pairs.iter().map(|(_, y)| *y).sum::<f64>();
    let sxx = pairs.iter().map(|(x, _)| x * x).sum::<f64>();
    let sxy = pairs.iter().map(|(x, y)| x * y).sum::<f64>();
    let denom = sxx - (sx * sx / n);
    if denom.abs() <= f64::EPSILON {
        return None;
    }
    let slope = (sxy - (sx * sy / n)) / denom;
    let intercept = (sy - slope * sx) / n;
    Some((slope, intercept))
}

fn deterministic_sample<T: Clone>(items: Vec<T>, max: usize) -> Vec<T> {
    if items.len() <= max {
        return items;
    }
    let step = items.len() as f64 / max as f64;
    let mut out = Vec::with_capacity(max);
    let mut idx = 0.0_f64;
    while out.len() < max {
        let src = idx.floor() as usize;
        let src = src.min(items.len() - 1);
        out.push(items[src].clone());
        idx += step;
    }
    out
}

fn summary_stats(values: impl Iterator<Item = f64>) -> SummaryStats {
    let mut values = values.filter(|v| v.is_finite()).collect::<Vec<_>>();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let count = values.len();
    let min = values.first().copied();
    let max = values.last().copied();
    let mean = if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    };
    let median = if values.is_empty() {
        None
    } else {
        let mid = values.len() / 2;
        if values.len().is_multiple_of(2) {
            Some((values[mid - 1] + values[mid]) / 2.0)
        } else {
            values.get(mid).copied()
        }
    };
    SummaryStats {
        count,
        min,
        median,
        mean,
        max,
    }
}

fn mean_values(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

fn fmt_opt_num(value: Option<f64>, precision: usize) -> String {
    match value {
        Some(v) => format!("{:.*}", precision, v),
        None => "n/a".to_string(),
    }
}

fn format_filter_scope(filters: &FilterSet) -> String {
    let host = filters.host.as_deref().unwrap_or("All");
    let mode = filters.mode.as_deref().unwrap_or("All");
    let jit = filters.jit.as_deref().unwrap_or("All");
    let scenario = filters.scenario.as_deref().unwrap_or("All");
    format!("host={host} | mode={mode} | jit={jit} | scenario={scenario}")
}

fn corr_direction(r: f64) -> &'static str {
    if r >= 0.0 {
        "positive"
    } else {
        "negative"
    }
}

fn canonical_label(raw: &str) -> String {
    let key = raw.trim().to_ascii_lowercase();
    match key.as_str() {
        "intel" => "Intel".to_string(),
        "amd" => "AMD".to_string(),
        _ => key,
    }
}

fn canonical_option_label(raw: Option<&str>) -> Option<String> {
    let value = raw?.trim();
    if value.is_empty() {
        return None;
    }
    Some(canonical_label(value))
}

fn canonical_or_unknown(raw: Option<&str>) -> String {
    canonical_option_label(raw).unwrap_or_else(|| "unknown".to_string())
}

fn normalize_filter(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return None;
    }
    Some(canonical_label(trimmed))
}

fn match_filter(filter: &Option<String>, candidate: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(expected) => candidate
            .map(|c| c.eq_ignore_ascii_case(expected))
            .unwrap_or(false),
    }
}

fn normalize_jit_value(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => "true".to_string(),
        "0" | "false" | "no" | "off" => "false".to_string(),
        "" | "unknown" | "n/a" | "na" => "unknown".to_string(),
        other => other.to_string(),
    }
}

fn match_jit_filter(filter: &Option<String>, candidate: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(expected) => {
            let expected_norm = normalize_jit_value(expected);
            candidate
                .map(normalize_jit_value)
                .map(|candidate_norm| candidate_norm == expected_norm)
                .unwrap_or(false)
        }
    }
}

fn parse_f64_opt(input: Option<&str>) -> Option<f64> {
    let raw = input?.trim();
    if raw.is_empty()
        || raw.eq_ignore_ascii_case("n/a")
        || raw.eq_ignore_ascii_case("na")
        || raw.eq_ignore_ascii_case("nan")
    {
        return None;
    }
    raw.parse::<f64>().ok()
}

fn infer_host_from_any_path(path: &std::path::Path) -> Option<String> {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    if let Some(pos) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("perf_results"))
    {
        return parts.get(pos + 1).map(|s| canonical_label(s));
    }
    parts.first().map(|s| canonical_label(s))
}

fn values_with_all(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for value in values {
        let canonical = canonical_label(&value);
        if !canonical.trim().is_empty() {
            set.insert(canonical);
        }
    }
    let mut out = Vec::with_capacity(set.len() + 1);
    out.push("All".to_string());
    out.extend(set);
    out
}

fn build_dataset_overview(
    dataset: &Dataset,
    filters: &FilterSet,
    scope: &str,
    perf_rows: &[&PerfRunRecord],
    manifest_rows: &[&PrefetchManifestRow],
    timeline_points: &[TimelinePoint],
) -> DatasetOverview {
    let total_hosts = dataset
        .catalog
        .iter()
        .filter_map(|e| infer_host_from_any_path(&e.rel_path))
        .collect::<BTreeSet<_>>()
        .len();
    let total_modes = dataset
        .perf_runs
        .iter()
        .filter_map(|r| canonical_option_label(r.mode.as_deref()))
        .chain(
            dataset
                .prefetch_manifest_rows
                .iter()
                .filter_map(|r| canonical_option_label(r.mode.as_deref())),
        )
        .collect::<BTreeSet<_>>()
        .len();
    let total_jits = dataset
        .perf_runs
        .iter()
        .map(|r| match r.jit_requested {
            Some(true) => "true".to_string(),
            Some(false) => "false".to_string(),
            None => "unknown".to_string(),
        })
        .chain(
            dataset
                .prefetch_manifest_rows
                .iter()
                .filter_map(|r| r.jit.as_ref().map(|v| normalize_jit_value(v))),
        )
        .collect::<BTreeSet<_>>()
        .len();
    let total_scenarios = dataset
        .prefetch_manifest_rows
        .iter()
        .filter_map(|r| canonical_option_label(r.scenario_id.as_deref()))
        .collect::<BTreeSet<_>>()
        .len();

    let mut latest_delta_label = "n/a".to_string();
    let mut latest_delta_pct = None;
    if timeline_points.len() >= 2 {
        let prev = &timeline_points[timeline_points.len() - 2];
        let last = &timeline_points[timeline_points.len() - 1];
        latest_delta_label = format!("{} -> {}", prev.bucket, last.bucket);
        let prev_total = prev.perf_rows + prev.manifest_rows;
        let last_total = last.perf_rows + last.manifest_rows;
        if prev_total > 0 {
            latest_delta_pct = Some(((last_total as f64 / prev_total as f64) - 1.0) * 100.0);
        }
    }

    let rows_missing_ns = perf_rows.iter().filter(|r| r.ns_per_hash.is_none()).count()
        + manifest_rows
            .iter()
            .filter(|r| r.ns_per_hash.is_none())
            .count();
    let rows_missing_hps = perf_rows
        .iter()
        .filter(|r| r.hashes_per_sec.is_none())
        .count()
        + manifest_rows
            .iter()
            .filter(|r| r.hashes_per_sec.is_none())
            .count();
    let unreadable_files = dataset
        .catalog
        .iter()
        .filter(|e| {
            e.encoding_hint.eq_ignore_ascii_case("unreadable")
                || e.encoding_hint.eq_ignore_ascii_case("unknown")
        })
        .count();

    let ingest_health = vec![
        ExplanationCard {
            title: "Parse Errors".to_string(),
            value: dataset.parse_errors.len().to_string(),
            detail: "Total ingest parse/row failures across scanned files.".to_string(),
        },
        ExplanationCard {
            title: "Rows Missing ns_per_hash".to_string(),
            value: rows_missing_ns.to_string(),
            detail: "Across current filter scope (perf + manifest rows).".to_string(),
        },
        ExplanationCard {
            title: "Rows Missing hashes_per_sec".to_string(),
            value: rows_missing_hps.to_string(),
            detail: "Across current filter scope (perf + manifest rows).".to_string(),
        },
        ExplanationCard {
            title: "Unreadable/Unknown Encodings".to_string(),
            value: unreadable_files.to_string(),
            detail: "Catalog files with unreadable or unknown encoding hint.".to_string(),
        },
    ];

    let mut schema_totals = dataset
        .schema_counts
        .iter()
        .map(|(name, count)| NamedCount {
            name: name.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    schema_totals.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    schema_totals.truncate(24);

    let snapshots = build_snapshot_points(dataset, filters);

    DatasetOverview {
        scope: scope.to_string(),
        total_files: dataset.catalog.len(),
        total_perf_rows: dataset.perf_runs.len(),
        total_manifest_rows: dataset.prefetch_manifest_rows.len(),
        total_hosts,
        total_modes,
        total_jits,
        total_scenarios,
        parse_errors: dataset.parse_errors.len(),
        parse_error_rate_pct: pct(dataset.parse_errors.len(), dataset.catalog.len()),
        scope_perf_rows: perf_rows.len(),
        scope_manifest_rows: manifest_rows.len(),
        latest_delta_label,
        latest_delta_pct,
        ingest_health,
        snapshots,
        schema_totals,
    }
}

fn build_coverage_maps(
    perf_rows: &[&PerfRunRecord],
    manifest_rows: &[&PrefetchManifestRow],
) -> CoverageMaps {
    let host_mode_entries = perf_rows
        .iter()
        .map(|row| {
            (
                canonical_or_unknown(row.mode.as_deref()),
                infer_host_from_any_path(&row.source_path).unwrap_or_else(|| "unknown".to_string()),
                row.ns_per_hash.is_some(),
            )
        })
        .collect::<Vec<_>>();

    let host_jit_entries = perf_rows
        .iter()
        .map(|row| {
            let jit = match row.jit_requested {
                Some(true) => "true",
                Some(false) => "false",
                None => "unknown",
            };
            (
                jit.to_string(),
                infer_host_from_any_path(&row.source_path).unwrap_or_else(|| "unknown".to_string()),
                row.ns_per_hash.is_some(),
            )
        })
        .collect::<Vec<_>>();

    let scenario_distance_entries = manifest_rows
        .iter()
        .filter_map(|row| {
            let distance = row.effective_prefetch_distance.or(row.requested_distance)?;
            Some((
                distance.to_string(),
                canonical_or_unknown(row.scenario_id.as_deref()),
                row.ns_per_hash.is_some(),
            ))
        })
        .collect::<Vec<_>>();

    CoverageMaps {
        host_mode: build_heatmap_payload(host_mode_entries, 18, 18, false),
        host_jit: build_heatmap_payload(host_jit_entries, 8, 18, false),
        scenario_distance: build_heatmap_payload(scenario_distance_entries, 36, 28, true),
    }
}

fn build_quality_report(
    dataset: &Dataset,
    metrics: &MetricCatalog,
    filters: &FilterSet,
    perf_rows: &[&PerfRunRecord],
    manifest_rows: &[&PrefetchManifestRow],
) -> DataQualityReport {
    let mut parse_errors_by_extension = BTreeMap::<String, usize>::new();
    for err in &dataset.parse_errors {
        let ext = parse_error_extension(err);
        *parse_errors_by_extension.entry(ext).or_insert(0) += 1;
    }
    let mut parse_errors_by_extension = parse_errors_by_extension
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect::<Vec<_>>();
    parse_errors_by_extension.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));

    let null_rates_perf = build_null_rates_perf(perf_rows, &metrics.perf_metrics);
    let null_rates_manifest = build_null_rates_manifest(manifest_rows, &metrics.manifest_metrics);

    let mut schema_totals = dataset
        .schema_counts
        .iter()
        .map(|(schema, count)| (schema.clone(), *count))
        .collect::<Vec<_>>();
    schema_totals.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let top_schemas = schema_totals
        .into_iter()
        .take(10)
        .map(|(schema, _)| schema)
        .collect::<BTreeSet<_>>();

    let mut schema_map = BTreeMap::<(String, String), usize>::new();
    for entry in &dataset.catalog {
        if !top_schemas.contains(&entry.schema_hint) {
            continue;
        }
        let host = infer_host_from_any_path(&entry.rel_path);
        if !match_filter(&filters.host, host.as_deref()) {
            continue;
        }
        let bucket =
            extract_date_bucket_from_path(&entry.rel_path).unwrap_or_else(|| "unknown".to_string());
        *schema_map
            .entry((bucket, entry.schema_hint.clone()))
            .or_insert(0) += 1;
    }
    let schema_time_series = schema_map
        .into_iter()
        .map(|((bucket, schema), count)| SchemaTimeRow {
            bucket,
            schema,
            count,
        })
        .collect::<Vec<_>>();

    DataQualityReport {
        parse_errors_by_extension,
        null_rates_perf,
        null_rates_manifest,
        schema_time_series,
    }
}

fn build_snapshot_points(dataset: &Dataset, filters: &FilterSet) -> Vec<SnapshotPoint> {
    let mut map = BTreeMap::<String, (usize, usize, usize)>::new();
    for row in &dataset.perf_runs {
        let host = infer_host_from_any_path(&row.source_path);
        if !match_filter(&filters.host, host.as_deref()) {
            continue;
        }
        let bucket = extract_date_bucket_from_path(&row.source_path)
            .unwrap_or_else(|| "unknown".to_string());
        map.entry(bucket).or_insert((0, 0, 0)).0 += 1;
    }
    for row in &dataset.prefetch_manifest_rows {
        let host = row
            .host_tag
            .as_deref()
            .map(canonical_label)
            .or_else(|| infer_host_from_any_path(&row.source_path));
        if !match_filter(&filters.host, host.as_deref()) {
            continue;
        }
        let mode = canonical_option_label(row.mode.as_deref());
        if !match_filter(&filters.mode, mode.as_deref()) {
            continue;
        }
        if !match_jit_filter(&filters.jit, row.jit.as_deref()) {
            continue;
        }
        let scenario = canonical_option_label(row.scenario_id.as_deref());
        if !match_filter(&filters.scenario, scenario.as_deref()) {
            continue;
        }
        let bucket = row
            .timestamp
            .as_deref()
            .and_then(normalize_date_bucket)
            .or_else(|| extract_date_bucket_from_path(&row.source_path))
            .unwrap_or_else(|| "unknown".to_string());
        map.entry(bucket).or_insert((0, 0, 0)).1 += 1;
    }
    for entry in &dataset.catalog {
        let host = infer_host_from_any_path(&entry.rel_path);
        if !match_filter(&filters.host, host.as_deref()) {
            continue;
        }
        let bucket =
            extract_date_bucket_from_path(&entry.rel_path).unwrap_or_else(|| "unknown".to_string());
        map.entry(bucket).or_insert((0, 0, 0)).2 += 1;
    }

    let mut snapshots = map
        .into_iter()
        .map(
            |(bucket, (perf_rows, manifest_rows, files))| SnapshotPoint {
                bucket,
                perf_rows,
                manifest_rows,
                files,
            },
        )
        .collect::<Vec<_>>();
    snapshots.sort_by(|a, b| a.bucket.cmp(&b.bucket));
    snapshots
}

fn build_heatmap_payload(
    entries: Vec<(String, String, bool)>,
    max_x: usize,
    max_y: usize,
    numeric_x_sort: bool,
) -> HeatmapPayload {
    if entries.is_empty() {
        return HeatmapPayload {
            x_labels: Vec::new(),
            y_labels: Vec::new(),
            cells: Vec::new(),
        };
    }

    let mut x_counts = BTreeMap::<String, usize>::new();
    let mut y_counts = BTreeMap::<String, usize>::new();
    let mut pair_counts = BTreeMap::<(String, String), (usize, usize)>::new();
    for (x, y, has_metric) in &entries {
        *x_counts.entry(x.clone()).or_insert(0) += 1;
        *y_counts.entry(y.clone()).or_insert(0) += 1;
        let entry = pair_counts.entry((y.clone(), x.clone())).or_insert((0, 0));
        entry.0 += 1;
        if !*has_metric {
            entry.1 += 1;
        }
    }

    let mut x_labels = x_counts.into_iter().collect::<Vec<_>>();
    x_labels.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut x_labels = x_labels
        .into_iter()
        .take(max_x.max(1))
        .map(|(label, _)| label)
        .collect::<Vec<_>>();
    if numeric_x_sort {
        x_labels.sort_by(|a, b| {
            parse_f64_opt(Some(a.as_str()))
                .partial_cmp(&parse_f64_opt(Some(b.as_str())))
                .unwrap_or(Ordering::Equal)
                .then(a.cmp(b))
        });
    } else {
        x_labels.sort();
    }

    let mut y_labels = y_counts.into_iter().collect::<Vec<_>>();
    y_labels.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut y_labels = y_labels
        .into_iter()
        .take(max_y.max(1))
        .map(|(label, _)| label)
        .collect::<Vec<_>>();
    y_labels.sort();

    let x_index = x_labels
        .iter()
        .enumerate()
        .map(|(idx, label)| (label.clone(), idx))
        .collect::<BTreeMap<_, _>>();
    let y_index = y_labels
        .iter()
        .enumerate()
        .map(|(idx, label)| (label.clone(), idx))
        .collect::<BTreeMap<_, _>>();

    let mut counts = vec![vec![0usize; x_labels.len()]; y_labels.len()];
    let mut missing = vec![vec![0usize; x_labels.len()]; y_labels.len()];
    for ((y, x), (count, miss)) in pair_counts {
        let Some(yi) = y_index.get(&y).copied() else {
            continue;
        };
        let Some(xi) = x_index.get(&x).copied() else {
            continue;
        };
        counts[yi][xi] += count;
        missing[yi][xi] += miss;
    }

    let cells = counts
        .iter()
        .enumerate()
        .map(|(yi, row)| {
            row.iter()
                .enumerate()
                .map(|(xi, count)| {
                    let missing_pct = if *count > 0 {
                        Some(missing[yi][xi] as f64 * 100.0 / *count as f64)
                    } else {
                        None
                    };
                    HeatmapCell {
                        value: *count as f64,
                        missing_pct,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    HeatmapPayload {
        x_labels,
        y_labels,
        cells,
    }
}

fn build_null_rates_perf(rows: &[&PerfRunRecord], metrics: &[String]) -> Vec<NullRateRow> {
    let total = rows.len();
    if total == 0 {
        return Vec::new();
    }
    let mut out = metrics
        .iter()
        .map(|metric| {
            let missing = rows
                .iter()
                .filter(|row| {
                    perf_metric_value(row, metric)
                        .filter(|v| v.is_finite())
                        .is_none()
                })
                .count();
            NullRateRow {
                column: metric.clone(),
                missing,
                total,
                missing_pct: missing as f64 * 100.0 / total as f64,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.missing_pct
            .partial_cmp(&a.missing_pct)
            .unwrap_or(Ordering::Equal)
            .then(a.column.cmp(&b.column))
    });
    out.truncate(40);
    out
}

fn build_null_rates_manifest(
    rows: &[&PrefetchManifestRow],
    metrics: &[String],
) -> Vec<NullRateRow> {
    let total = rows.len();
    if total == 0 {
        return Vec::new();
    }
    let mut out = metrics
        .iter()
        .map(|metric| {
            let missing = rows
                .iter()
                .filter(|row| {
                    manifest_metric_value(row, metric)
                        .filter(|v| v.is_finite())
                        .is_none()
                })
                .count();
            NullRateRow {
                column: metric.clone(),
                missing,
                total,
                missing_pct: missing as f64 * 100.0 / total as f64,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.missing_pct
            .partial_cmp(&a.missing_pct)
            .unwrap_or(Ordering::Equal)
            .then(a.column.cmp(&b.column))
    });
    out.truncate(40);
    out
}

fn parse_error_extension(err: &str) -> String {
    let path_like = err.split(':').next().unwrap_or(err).trim();
    std::path::Path::new(path_like)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

fn pct(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}

fn build_stability_lab(
    settings_rows: &[&crate::model::PrefetchSettingSummaryRow],
    manifest_rows: &[&PrefetchManifestRow],
) -> StabilityLab {
    let mut cv_distribution = settings_rows
        .iter()
        .filter_map(|row| row.cv_pct)
        .filter(|v| v.is_finite())
        .collect::<Vec<_>>();
    cv_distribution.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    if cv_distribution.len() > 800 {
        cv_distribution = deterministic_sample(cv_distribution, 800);
    }

    let mut drift_values = Vec::new();
    let mut drift_control = settings_rows
        .iter()
        .filter_map(|row| {
            let drift = row.run_order_drift_pct?;
            if !drift.is_finite() {
                return None;
            }
            let timestamp = row
                .timestamp
                .as_deref()
                .and_then(normalize_date_bucket)
                .or_else(|| extract_date_bucket_from_path(&row.source_path))
                .unwrap_or_else(|| "unknown".to_string());
            let key = format!(
                "{} | {}",
                canonical_or_unknown(row.scenario_id.as_deref()),
                canonical_or_unknown(row.setting_label.as_deref())
            );
            drift_values.push(drift);
            Some((
                timestamp,
                DriftControlPoint {
                    key,
                    timestamp: String::new(),
                    drift_pct: drift,
                    center_line: 0.0,
                    upper_control: 0.0,
                    lower_control: 0.0,
                },
            ))
        })
        .collect::<Vec<_>>();

    let center = mean_values(&drift_values).unwrap_or(0.0);
    let sigma = stddev(&drift_values).unwrap_or(0.0);
    let upper = center + (3.0 * sigma);
    let lower = center - (3.0 * sigma);
    drift_control.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.key.cmp(&b.1.key)));
    let mut drift_control = drift_control
        .into_iter()
        .map(|(timestamp, mut point)| {
            point.timestamp = timestamp;
            point.center_line = center;
            point.upper_control = upper;
            point.lower_control = lower;
            point
        })
        .collect::<Vec<_>>();
    if drift_control.len() > 420 {
        drift_control = deterministic_sample(drift_control, 420);
    }

    let mut repeat_groups = BTreeMap::<String, (String, String, Vec<f64>)>::new();
    for row in manifest_rows {
        let Some(ns) = row.ns_per_hash else {
            continue;
        };
        if !ns.is_finite() {
            continue;
        }
        let scenario = canonical_or_unknown(row.scenario_id.as_deref());
        let setting = row
            .setting_label
            .as_deref()
            .or(row.setting_kind.as_deref())
            .map(canonical_label)
            .unwrap_or_else(|| "unknown".to_string());
        let key = format!("{scenario} | {setting}");
        repeat_groups
            .entry(key)
            .or_insert_with(|| (scenario, setting, Vec::new()))
            .2
            .push(ns);
    }

    let mut repeatability = repeat_groups
        .into_iter()
        .filter_map(|(key, (scenario, setting, values))| {
            if values.len() < 3 {
                return None;
            }
            let mean = mean_values(&values)?;
            let sd = stddev(&values)?;
            let cv = if mean.abs() > f64::EPSILON {
                (sd / mean.abs()) * 100.0
            } else {
                0.0
            };
            let score = 100.0 / (1.0 + cv.max(0.0));
            Some(RepeatabilityScore {
                key,
                scenario,
                setting,
                rows: values.len(),
                mean_ns_per_hash: mean,
                stddev_ns_per_hash: sd,
                cv_pct: cv,
                repeatability_score: score,
            })
        })
        .collect::<Vec<_>>();
    repeatability.sort_by(|a, b| {
        b.repeatability_score
            .partial_cmp(&a.repeatability_score)
            .unwrap_or(Ordering::Equal)
            .then(b.rows.cmp(&a.rows))
    });

    let stable_top = repeatability.iter().take(12).cloned().collect::<Vec<_>>();
    let mut unstable_top = repeatability
        .iter()
        .rev()
        .take(12)
        .cloned()
        .collect::<Vec<_>>();
    unstable_top.sort_by(|a, b| {
        a.repeatability_score
            .partial_cmp(&b.repeatability_score)
            .unwrap_or(Ordering::Equal)
    });

    StabilityLab {
        cv_distribution,
        drift_control,
        stable_top,
        unstable_top,
    }
}

fn build_host_benchmark_arena(perf_rows: &[&PerfRunRecord]) -> HostBenchmarkArena {
    #[derive(Default)]
    struct GroupAccum {
        host: String,
        mode: String,
        jit: String,
        rows: usize,
        ns: Vec<f64>,
        hps: Vec<f64>,
    }

    let mut groups = BTreeMap::<String, GroupAccum>::new();
    let mut global_ns = Vec::new();
    let mut global_hps = Vec::new();

    for row in perf_rows {
        let host =
            infer_host_from_any_path(&row.source_path).unwrap_or_else(|| "unknown".to_string());
        let mode = canonical_or_unknown(row.mode.as_deref());
        let jit = match row.jit_requested {
            Some(true) => "true",
            Some(false) => "false",
            None => "unknown",
        }
        .to_string();
        let key = format!("{host}|{mode}|{jit}");
        let entry = groups.entry(key).or_insert_with(|| GroupAccum {
            host,
            mode,
            jit,
            ..GroupAccum::default()
        });
        entry.rows += 1;
        if let Some(ns) = row.ns_per_hash.filter(|v| v.is_finite()) {
            entry.ns.push(ns);
            global_ns.push(ns);
        }
        if let Some(hps) = row.hashes_per_sec.filter(|v| v.is_finite()) {
            entry.hps.push(hps);
            global_hps.push(hps);
        }
    }

    let global_ns_mean = mean_values(&global_ns);
    let global_hps_mean = mean_values(&global_hps);

    let mut groups = groups
        .into_iter()
        .filter_map(|(_, group)| {
            if group.rows == 0 {
                return None;
            }
            let ns_mean = mean_values(&group.ns);
            let hps_mean = mean_values(&group.hps);
            let ns_sd = stddev(&group.ns);
            let hps_sd = stddev(&group.hps);
            let ns_ci95 = match (ns_sd, group.ns.len()) {
                (Some(sd), n) if n > 1 => Some(1.96 * sd / (n as f64).sqrt()),
                _ => None,
            };
            let hps_ci95 = match (hps_sd, group.hps.len()) {
                (Some(sd), n) if n > 1 => Some(1.96 * sd / (n as f64).sqrt()),
                _ => None,
            };
            let ns_normalized = match (global_ns_mean, ns_mean) {
                (Some(global), Some(mean)) if mean.abs() > f64::EPSILON => Some(global / mean),
                _ => None,
            };
            let hps_normalized = match (global_hps_mean, hps_mean) {
                (Some(global), Some(mean)) if global.abs() > f64::EPSILON => Some(mean / global),
                _ => None,
            };
            Some(HostBenchmarkGroup {
                host: group.host,
                mode: group.mode,
                jit: group.jit,
                rows: group.rows,
                mean_ns_per_hash: ns_mean,
                ns_ci95,
                mean_hashes_per_sec: hps_mean,
                hps_ci95,
                ns_normalized,
                hps_normalized,
            })
        })
        .collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        a.mean_ns_per_hash
            .partial_cmp(&b.mean_ns_per_hash)
            .unwrap_or(Ordering::Equal)
            .then(b.rows.cmp(&a.rows))
    });

    let mut bucketed = BTreeMap::<(String, String), Vec<&HostBenchmarkGroup>>::new();
    for group in &groups {
        if group.mean_ns_per_hash.is_none() {
            continue;
        }
        bucketed
            .entry((group.mode.clone(), group.jit.clone()))
            .or_default()
            .push(group);
    }

    let mut pairwise_deltas = Vec::new();
    for ((mode, jit), mut rows) in bucketed {
        if rows.len() < 2 {
            continue;
        }
        rows.sort_by(|a, b| {
            a.mean_ns_per_hash
                .partial_cmp(&b.mean_ns_per_hash)
                .unwrap_or(Ordering::Equal)
        });
        let baseline = rows[0];
        let baseline_mean = baseline.mean_ns_per_hash.unwrap_or(0.0);
        let baseline_ci = baseline.ns_ci95.unwrap_or(0.0);

        for row in rows {
            let Some(mean_ns) = row.mean_ns_per_hash else {
                continue;
            };
            if baseline_mean.abs() <= f64::EPSILON {
                continue;
            }
            let delta_ns_pct = ((mean_ns / baseline_mean) - 1.0) * 100.0;
            let delta_ci95_pct =
                Some((((row.ns_ci95.unwrap_or(0.0) + baseline_ci) / baseline_mean) * 100.0).abs());
            pairwise_deltas.push(PairwiseDeltaRow {
                mode: mode.clone(),
                jit: jit.clone(),
                host: row.host.clone(),
                baseline_host: baseline.host.clone(),
                delta_ns_pct,
                delta_ci95_pct,
                rows: row.rows,
            });
        }
    }
    pairwise_deltas.sort_by(|a, b| {
        b.delta_ns_pct
            .abs()
            .partial_cmp(&a.delta_ns_pct.abs())
            .unwrap_or(Ordering::Equal)
            .then(a.mode.cmp(&b.mode))
    });
    pairwise_deltas.truncate(140);

    HostBenchmarkArena {
        groups,
        pairwise_deltas,
    }
}

fn build_pareto_frontier(manifest_rows: &[&PrefetchManifestRow]) -> ParetoFrontier {
    let mut grouped = BTreeMap::<
        String,
        (
            String,
            String,
            Option<i64>,
            String,
            String,
            String,
            Vec<f64>,
        ),
    >::new();
    for row in manifest_rows {
        let Some(ns) = row.ns_per_hash else {
            continue;
        };
        if !ns.is_finite() {
            continue;
        }
        let scenario = canonical_or_unknown(row.scenario_id.as_deref());
        let setting = row
            .setting_label
            .as_deref()
            .or(row.setting_kind.as_deref())
            .map(canonical_label)
            .unwrap_or_else(|| "unknown".to_string());
        let distance = row.effective_prefetch_distance.or(row.requested_distance);
        let host = row
            .host_tag
            .as_deref()
            .map(canonical_label)
            .or_else(|| infer_host_from_any_path(&row.source_path))
            .unwrap_or_else(|| "unknown".to_string());
        let mode = canonical_or_unknown(row.mode.as_deref());
        let jit = row
            .jit
            .as_deref()
            .map(normalize_jit_value)
            .unwrap_or_else(|| "unknown".to_string());
        let key = format!(
            "{scenario}|{setting}|{}|{host}|{mode}|{jit}",
            distance.unwrap_or(i64::MIN)
        );
        grouped
            .entry(key)
            .or_insert_with(|| {
                (
                    scenario.clone(),
                    setting.clone(),
                    distance,
                    host.clone(),
                    mode.clone(),
                    jit.clone(),
                    Vec::new(),
                )
            })
            .6
            .push(ns);
    }

    let mut points = grouped
        .into_iter()
        .filter_map(
            |(id, (scenario, setting, distance, host, mode, jit, values))| {
                if values.len() < 3 {
                    return None;
                }
                let mean = mean_values(&values)?;
                let sd = stddev(&values)?;
                let cv = if mean.abs() > f64::EPSILON {
                    (sd / mean.abs()) * 100.0
                } else {
                    0.0
                };
                Some(ParetoPoint {
                    id,
                    scenario,
                    setting,
                    distance,
                    host,
                    mode,
                    jit,
                    rows: values.len(),
                    mean_ns_per_hash: mean,
                    stddev_ns_per_hash: sd,
                    cv_pct: cv,
                })
            },
        )
        .collect::<Vec<_>>();
    points.sort_by(|a, b| {
        a.mean_ns_per_hash
            .partial_cmp(&b.mean_ns_per_hash)
            .unwrap_or(Ordering::Equal)
            .then(a.cv_pct.partial_cmp(&b.cv_pct).unwrap_or(Ordering::Equal))
    });
    if points.len() > 900 {
        points = deterministic_sample(points, 900);
    }

    let mut frontier_ids = Vec::new();
    for (idx, point) in points.iter().enumerate() {
        let dominated = points.iter().enumerate().any(|(j, other)| {
            if idx == j {
                return false;
            }
            let better_or_equal =
                other.mean_ns_per_hash <= point.mean_ns_per_hash && other.cv_pct <= point.cv_pct;
            let strictly_better =
                other.mean_ns_per_hash < point.mean_ns_per_hash || other.cv_pct < point.cv_pct;
            better_or_equal && strictly_better
        });
        if !dominated {
            frontier_ids.push(point.id.clone());
        }
    }

    ParetoFrontier {
        points,
        frontier_ids,
    }
}

fn build_anomaly_forensics(
    manifest_rows: &[&PrefetchManifestRow],
    max_anomalies: usize,
) -> AnomalyForensics {
    let all_ns = manifest_rows
        .iter()
        .filter_map(|row| row.ns_per_hash)
        .filter(|v| v.is_finite())
        .collect::<Vec<_>>();
    let global_median = median(all_ns.clone());
    let global_mad = global_median.and_then(|m| {
        let deviations = all_ns.iter().map(|v| (v - m).abs()).collect::<Vec<_>>();
        median(deviations)
    });

    #[derive(Clone)]
    struct GroupStats {
        values: Vec<f64>,
        median: f64,
        q1: f64,
        q3: f64,
    }

    let mut grouped = BTreeMap::<String, Vec<f64>>::new();
    for row in manifest_rows {
        let Some(ns) = row.ns_per_hash else {
            continue;
        };
        if !ns.is_finite() {
            continue;
        }
        let key = format!(
            "{}|{}",
            canonical_or_unknown(row.scenario_id.as_deref()),
            row.setting_label
                .as_deref()
                .or(row.setting_kind.as_deref())
                .map(canonical_label)
                .unwrap_or_else(|| "unknown".to_string())
        );
        grouped.entry(key).or_default().push(ns);
    }

    let mut group_stats = BTreeMap::<String, GroupStats>::new();
    for (key, mut values) in grouped {
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
        if values.len() < 4 {
            continue;
        }
        let med = quantile_sorted(&values, 0.5);
        let q1 = quantile_sorted(&values, 0.25);
        let q3 = quantile_sorted(&values, 0.75);
        group_stats.insert(
            key,
            GroupStats {
                values,
                median: med,
                q1,
                q3,
            },
        );
    }

    let mut anomalies = Vec::new();
    for row in manifest_rows {
        let Some(ns) = row.ns_per_hash else {
            continue;
        };
        if !ns.is_finite() {
            continue;
        }
        let scenario = canonical_or_unknown(row.scenario_id.as_deref());
        let setting = row
            .setting_label
            .as_deref()
            .or(row.setting_kind.as_deref())
            .map(canonical_label)
            .unwrap_or_else(|| "unknown".to_string());
        let key = format!("{scenario}|{setting}");
        let stats = group_stats.get(&key);

        let robust_z = match (global_median, global_mad) {
            (Some(med), Some(mad)) if mad > f64::EPSILON => 0.6745 * (ns - med) / mad,
            _ => 0.0,
        };
        let z_flag = robust_z.abs() >= 3.5;

        let (iqr_low, iqr_high, iqr_flag, deviation_pct, group_series) = if let Some(stats) = stats
        {
            let iqr = stats.q3 - stats.q1;
            let low = stats.q1 - (1.5 * iqr);
            let high = stats.q3 + (1.5 * iqr);
            let iqr_flag = ns < low || ns > high;
            let deviation_pct = if stats.median.abs() > f64::EPSILON {
                Some(((ns / stats.median) - 1.0) * 100.0)
            } else {
                None
            };
            let mut series = stats.values.clone();
            if series.len() > 64 {
                series = deterministic_sample(series, 64);
            }
            (Some(low), Some(high), iqr_flag, deviation_pct, series)
        } else {
            (None, None, false, None, Vec::new())
        };

        if !(z_flag || iqr_flag) {
            continue;
        }
        let reason = match (z_flag, iqr_flag) {
            (true, true) => "robust-z + iqr-outlier".to_string(),
            (true, false) => "robust-z".to_string(),
            (false, true) => "iqr-outlier".to_string(),
            (false, false) => "flagged".to_string(),
        };
        let host = row
            .host_tag
            .as_deref()
            .map(canonical_label)
            .or_else(|| infer_host_from_any_path(&row.source_path))
            .unwrap_or_else(|| "unknown".to_string());
        anomalies.push(AnomalyEntry {
            id: format!("anom-{:05}", anomalies.len() + 1),
            source_path: row.source_path.display().to_string(),
            host,
            mode: canonical_or_unknown(row.mode.as_deref()),
            jit: row
                .jit
                .as_deref()
                .map(normalize_jit_value)
                .unwrap_or_else(|| "unknown".to_string()),
            scenario,
            setting,
            run_index: row.run_index,
            ns_per_hash: ns,
            hashes_per_sec: row.hashes_per_sec,
            robust_z,
            iqr_low,
            iqr_high,
            deviation_pct_from_group_median: deviation_pct,
            reason,
            artifact_csv: row.artifact_csv.clone(),
            artifact_stdout: row.artifact_stdout.clone(),
            artifact_stderr: row.artifact_stderr.clone(),
            group_series,
        });
    }

    anomalies.sort_by(|a, b| {
        b.robust_z
            .abs()
            .partial_cmp(&a.robust_z.abs())
            .unwrap_or(Ordering::Equal)
            .then(
                b.deviation_pct_from_group_median
                    .unwrap_or(0.0)
                    .abs()
                    .partial_cmp(&a.deviation_pct_from_group_median.unwrap_or(0.0).abs())
                    .unwrap_or(Ordering::Equal),
            )
    });
    anomalies.truncate(max_anomalies);

    AnomalyForensics {
        global_median_ns: global_median,
        global_mad_ns: global_mad,
        anomalies,
    }
}

fn build_timeline_watch(
    dataset: &Dataset,
    perf_rows: &[&PerfRunRecord],
    manifest_rows: &[&PrefetchManifestRow],
    max_timeline_points: usize,
) -> TimelineWatch {
    #[derive(Default)]
    struct BucketAccum {
        perf_rows: usize,
        manifest_rows: usize,
        perf_ns_sum: f64,
        perf_ns_count: usize,
        manifest_ns_sum: f64,
        manifest_ns_count: usize,
        perf_hps_sum: f64,
        perf_hps_count: usize,
    }

    let mut map = BTreeMap::<String, BucketAccum>::new();
    for row in perf_rows {
        let bucket = extract_date_bucket_from_path(&row.source_path)
            .unwrap_or_else(|| "unknown".to_string());
        let entry = map.entry(bucket).or_default();
        entry.perf_rows += 1;
        if let Some(ns) = row.ns_per_hash.filter(|v| v.is_finite()) {
            entry.perf_ns_sum += ns;
            entry.perf_ns_count += 1;
        }
        if let Some(hps) = row.hashes_per_sec.filter(|v| v.is_finite()) {
            entry.perf_hps_sum += hps;
            entry.perf_hps_count += 1;
        }
    }
    for row in manifest_rows {
        let bucket = row
            .timestamp
            .as_deref()
            .and_then(normalize_date_bucket)
            .or_else(|| extract_date_bucket_from_path(&row.source_path))
            .unwrap_or_else(|| "unknown".to_string());
        let entry = map.entry(bucket).or_default();
        entry.manifest_rows += 1;
        if let Some(ns) = row.ns_per_hash.filter(|v| v.is_finite()) {
            entry.manifest_ns_sum += ns;
            entry.manifest_ns_count += 1;
        }
    }

    for entry in &dataset.catalog {
        let bucket =
            extract_date_bucket_from_path(&entry.rel_path).unwrap_or_else(|| "unknown".to_string());
        map.entry(bucket).or_default();
    }

    let mut points = map
        .into_iter()
        .map(|(bucket, a)| TimelinePoint {
            bucket,
            perf_rows: a.perf_rows,
            manifest_rows: a.manifest_rows,
            perf_mean_ns_per_hash: if a.perf_ns_count > 0 {
                Some(a.perf_ns_sum / a.perf_ns_count as f64)
            } else {
                None
            },
            manifest_mean_ns_per_hash: if a.manifest_ns_count > 0 {
                Some(a.manifest_ns_sum / a.manifest_ns_count as f64)
            } else {
                None
            },
            perf_mean_hashes_per_sec: if a.perf_hps_count > 0 {
                Some(a.perf_hps_sum / a.perf_hps_count as f64)
            } else {
                None
            },
        })
        .collect::<Vec<_>>();
    points.sort_by(|a, b| a.bucket.cmp(&b.bucket));
    if points.len() > max_timeline_points {
        points = deterministic_sample(points, max_timeline_points);
    }

    let mut change_points = Vec::new();
    collect_change_points(
        &points,
        "perf_mean_ns_per_hash",
        |p| p.perf_mean_ns_per_hash,
        &mut change_points,
    );
    collect_change_points(
        &points,
        "manifest_mean_ns_per_hash",
        |p| p.manifest_mean_ns_per_hash,
        &mut change_points,
    );
    collect_change_points(
        &points,
        "perf_mean_hashes_per_sec",
        |p| p.perf_mean_hashes_per_sec,
        &mut change_points,
    );
    change_points.sort_by(|a, b| {
        b.pct_change
            .abs()
            .partial_cmp(&a.pct_change.abs())
            .unwrap_or(Ordering::Equal)
    });
    change_points.truncate(48);

    TimelineWatch {
        points,
        change_points,
    }
}

fn collect_change_points(
    points: &[TimelinePoint],
    metric: &str,
    value: impl Fn(&TimelinePoint) -> Option<f64>,
    out: &mut Vec<ChangePoint>,
) {
    let mut prev: Option<(&str, f64)> = None;
    for point in points {
        let Some(curr) = value(point).filter(|v| v.is_finite()) else {
            continue;
        };
        if let Some((_prev_bucket, prev_value)) = prev {
            if prev_value.abs() > f64::EPSILON {
                let pct_change = ((curr / prev_value) - 1.0) * 100.0;
                if pct_change.abs() >= 5.0 {
                    out.push(ChangePoint {
                        bucket: point.bucket.clone(),
                        metric: metric.to_string(),
                        pct_change,
                        from_value: prev_value,
                        to_value: curr,
                    });
                }
            }
        }
        prev = Some((point.bucket.as_str(), curr));
    }
}

fn normalize_date_bucket(input: &str) -> Option<String> {
    let digits = input
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();
    if digits.len() < 8 {
        return None;
    }
    let y = digits.get(0..4)?;
    let m = digits.get(4..6)?;
    let d = digits.get(6..8)?;
    let year: i32 = y.parse().ok()?;
    let month: i32 = m.parse().ok()?;
    let day: i32 = d.parse().ok()?;
    if !(1900..=2200).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn extract_date_bucket_from_path(path: &std::path::Path) -> Option<String> {
    static TS_RE: OnceLock<Regex> = OnceLock::new();
    let re =
        TS_RE.get_or_init(|| Regex::new(r"(?P<date>\d{8})(?:[_-]?\d{6})?").expect("valid regex"));
    let text = path.to_string_lossy();
    let caps = re.captures(&text)?;
    let date = caps.name("date")?.as_str();
    normalize_date_bucket(date)
}

fn stddev(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = mean_values(values)?;
    let var = values
        .iter()
        .map(|v| {
            let d = *v - mean;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    Some(var.sqrt())
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some((values[mid - 1] + values[mid]) / 2.0)
    } else {
        values.get(mid).copied()
    }
}

fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let q = q.clamp(0.0, 1.0);
    let pos = q * (sorted.len() as f64 - 1.0);
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let w = pos - lo as f64;
        sorted[lo] * (1.0 - w) + sorted[hi] * w
    }
}

const INDEX_HTML: &str = include_str!("../web/index.html");
const STYLES_CSS: &str = include_str!("../web/styles.css");
const APP_JS: &str = include_str!("../web/app.js");
const EXPLANATIONS_HTML: &str = include_str!("../web/explanations.html");
const EXPLANATIONS_JS: &str = include_str!("../web/explanations.js");
