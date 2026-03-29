use crate::ingest::read_text_preview;
use crate::model::{Dataset, PerfRunRecord, PrefetchManifestRow};
use eframe::egui;
use egui_plot::{Bar, BarChart, Line, Plot, PlotPoints, Points};
use plotters::prelude::*;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    PrefetchExplorer,
    CorrelationLab,
    RunInspector,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::PrefetchExplorer => "Prefetch Explorer",
            Self::CorrelationLab => "Correlation Lab",
            Self::RunInspector => "Run Inspector",
        }
    }
}

#[derive(Debug, Clone)]
struct PrefetchFilter {
    host_tag: String,
    scenario_id: String,
    mode: String,
    jit: String,
    only_rows_with_ns_per_hash: bool,
}

impl Default for PrefetchFilter {
    fn default() -> Self {
        Self {
            host_tag: "All".to_string(),
            scenario_id: "All".to_string(),
            mode: "All".to_string(),
            jit: "All".to_string(),
            only_rows_with_ns_per_hash: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestSortKey {
    Scenario,
    Setting,
    Distance,
    RunIndex,
    NsPerHash,
}

#[derive(Debug, Clone, Copy)]
struct ManifestSortState {
    key: ManifestSortKey,
    descending: bool,
}

impl Default for ManifestSortState {
    fn default() -> Self {
        Self {
            key: ManifestSortKey::Scenario,
            descending: false,
        }
    }
}

#[derive(Debug, Clone)]
struct FilterOptions {
    hosts: Vec<String>,
    scenarios: Vec<String>,
    modes: Vec<String>,
    jits: Vec<String>,
}

#[derive(Debug, Clone)]
struct DriftPoint {
    x: f64,
    drift_pct: f64,
    label: String,
}

#[derive(Debug, Clone)]
struct MetricCatalog {
    perf_metrics: Vec<String>,
    manifest_metrics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorrDataset {
    PerfRuns,
    PrefetchManifest,
}

impl CorrDataset {
    fn label(self) -> &'static str {
        match self {
            Self::PerfRuns => "Perf Runs",
            Self::PrefetchManifest => "Prefetch Manifest",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorrColorBy {
    None,
    Host,
    Mode,
    Jit,
    Scenario,
    SettingKind,
    Schema,
    PrefetchAuto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorrViewMode {
    Scatter,
    DensityHeatmap,
    Distribution,
    GroupBars,
    MatrixHeatmap,
}

impl CorrViewMode {
    fn label(self) -> &'static str {
        match self {
            Self::Scatter => "Scatter",
            Self::DensityHeatmap => "Density Heatmap",
            Self::Distribution => "Distributions",
            Self::GroupBars => "Group Bars",
            Self::MatrixHeatmap => "Correlation Matrix",
        }
    }
}

impl CorrColorBy {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Host => "host",
            Self::Mode => "mode",
            Self::Jit => "jit",
            Self::Scenario => "scenario",
            Self::SettingKind => "setting_kind",
            Self::Schema => "schema",
            Self::PrefetchAuto => "prefetch_auto",
        }
    }
}

#[derive(Debug, Clone)]
struct CorrelationState {
    dataset: CorrDataset,
    x_metric: String,
    y_metric: String,
    color_by: CorrColorBy,
    host_filter: String,
    mode_filter: String,
    jit_filter: String,
    scenario_filter: String,
    show_regression: bool,
    only_complete_pairs: bool,
    view_mode: CorrViewMode,
    density_bins: usize,
    hist_bins: usize,
    matrix_max_metrics: usize,
    matrix_abs_sort: bool,
    export_feedback: Option<String>,
}

#[derive(Debug, Clone)]
struct CorrelationPoint {
    x: f64,
    y: f64,
    color_key: String,
}

#[derive(Debug, Clone)]
struct CorrelationMatrixCell {
    metric_x: String,
    metric_y: String,
    pearson_r: Option<f64>,
    n_pairs: usize,
}

#[derive(Debug, Clone)]
struct CorrelationMatrix {
    metrics: Vec<String>,
    cells: Vec<Vec<CorrelationMatrixCell>>,
}

type GroupedScatterPoints = BTreeMap<String, Vec<[f64; 2]>>;
type PairValues = Vec<(f64, f64)>;
type XMinMax = Option<(f64, f64)>;

#[derive(Debug, Clone)]
struct CorrelationView {
    points: Vec<CorrelationPoint>,
    points_by_color: GroupedScatterPoints,
    n_pairs: usize,
    pearson_r: Option<f64>,
    regression: Option<(f64, f64)>,
    x_min_max: Option<(f64, f64)>,
    y_min_max: Option<(f64, f64)>,
    top_correlations: Vec<(String, f64, usize)>,
}

pub struct PerfVizApp {
    dataset: Arc<Dataset>,
    raw_preview_max_bytes: usize,
    filter_options: FilterOptions,
    metric_catalog: MetricCatalog,
    tab: Tab,
    prefetch_filter: PrefetchFilter,
    manifest_sort: ManifestSortState,
    corr: CorrelationState,
    file_search: String,
    catalog_lowercase_paths: Vec<String>,
    selected_file_idx: Option<usize>,
    raw_cache: HashMap<PathBuf, String>,
    corr_matrix_cache_key: Option<String>,
    corr_matrix_cache: Option<CorrelationMatrix>,
    action_feedback: Option<String>,
}

impl PerfVizApp {
    pub fn new(dataset: Arc<Dataset>, raw_preview_max_bytes: usize) -> Self {
        let filter_options = FilterOptions {
            hosts: values_with_all(
                dataset
                    .prefetch_manifest_rows
                    .iter()
                    .filter_map(|r| r.host_tag.as_deref().map(ToOwned::to_owned)),
            ),
            scenarios: values_with_all(
                dataset
                    .prefetch_manifest_rows
                    .iter()
                    .filter_map(|r| r.scenario_id.as_deref().map(ToOwned::to_owned)),
            ),
            modes: values_with_all(
                dataset
                    .prefetch_manifest_rows
                    .iter()
                    .filter_map(|r| r.mode.as_deref().map(ToOwned::to_owned)),
            ),
            jits: values_with_all(
                dataset
                    .prefetch_manifest_rows
                    .iter()
                    .filter_map(|r| r.jit.as_deref().map(ToOwned::to_owned)),
            ),
        };

        let metric_catalog = build_metric_catalog(&dataset);
        let default_x = pick_default_metric(&metric_catalog.perf_metrics, "prefetch_distance");
        let default_y = pick_default_metric(&metric_catalog.perf_metrics, "ns_per_hash");

        let catalog_lowercase_paths = dataset
            .catalog
            .iter()
            .map(|entry| entry.rel_path.to_string_lossy().to_ascii_lowercase())
            .collect();

        Self {
            dataset,
            raw_preview_max_bytes,
            filter_options,
            metric_catalog,
            tab: Tab::Overview,
            prefetch_filter: PrefetchFilter::default(),
            manifest_sort: ManifestSortState::default(),
            corr: CorrelationState {
                dataset: CorrDataset::PerfRuns,
                x_metric: default_x,
                y_metric: default_y,
                color_by: CorrColorBy::Mode,
                host_filter: "All".to_string(),
                mode_filter: "All".to_string(),
                jit_filter: "All".to_string(),
                scenario_filter: "All".to_string(),
                show_regression: true,
                only_complete_pairs: true,
                view_mode: CorrViewMode::Scatter,
                density_bins: 24,
                hist_bins: 32,
                matrix_max_metrics: 20,
                matrix_abs_sort: true,
                export_feedback: None,
            },
            file_search: String::new(),
            catalog_lowercase_paths,
            selected_file_idx: None,
            raw_cache: HashMap::new(),
            corr_matrix_cache_key: None,
            corr_matrix_cache: None,
            action_feedback: None,
        }
    }

    fn ui_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for tab in [
                Tab::Overview,
                Tab::PrefetchExplorer,
                Tab::CorrelationLab,
                Tab::RunInspector,
            ] {
                ui.selectable_value(&mut self.tab, tab, tab.label());
            }
            ui.separator();
            ui.label(format!("root: {}", self.dataset.root.display()));
            ui.separator();
            ui.label(format!("files: {}", self.dataset.catalog.len()));
            ui.label(format!("perf rows: {}", self.dataset.perf_runs.len()));
            ui.label(format!(
                "prefetch rows: {}",
                self.dataset.prefetch_manifest_rows.len()
            ));
            ui.label(format!("errors: {}", self.dataset.parse_errors.len()));
        });
    }

    fn ui_navigation_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Navigator");
        ui.separator();

        for tab in [
            Tab::Overview,
            Tab::PrefetchExplorer,
            Tab::CorrelationLab,
            Tab::RunInspector,
        ] {
            ui.selectable_value(&mut self.tab, tab, tab.label());
        }

        ui.separator();
        ui.label("Current Focus");
        match self.tab {
            Tab::Overview => {
                chip(ui, "Dataset inventory");
            }
            Tab::PrefetchExplorer => {
                chip(
                    ui,
                    format!("Scenario: {}", self.prefetch_filter.scenario_id),
                );
                chip(ui, format!("Mode: {}", self.prefetch_filter.mode));
                chip(ui, format!("JIT: {}", self.prefetch_filter.jit));
            }
            Tab::CorrelationLab => {
                chip(ui, format!("Dataset: {}", self.corr.dataset.label()));
                chip(ui, format!("X: {}", self.corr.x_metric));
                chip(ui, format!("Y: {}", self.corr.y_metric));
                chip(ui, format!("View: {}", self.corr.view_mode.label()));
            }
            Tab::RunInspector => {
                chip(ui, format!("Search: {}", self.file_search));
                chip(ui, format!("Cached previews: {}", self.raw_cache.len()));
            }
        }

        ui.separator();
        ui.label("Data Scale");
        ui.monospace(format!("files: {}", self.dataset.catalog.len()));
        ui.monospace(format!("perf rows: {}", self.dataset.perf_runs.len()));
        ui.monospace(format!(
            "manifest rows: {}",
            self.dataset.prefetch_manifest_rows.len()
        ));
        ui.monospace(format!(
            "setting rows: {}",
            self.dataset.prefetch_settings_rows.len()
        ));
        ui.monospace(format!(
            "scenario rows: {}",
            self.dataset.prefetch_scenario_rows.len()
        ));
    }

    fn ui_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Dataset Overview");
        ui.separator();

        ui.columns(2, |cols| {
            cols[0].label("Host Buckets");
            egui::Grid::new("host_counts_grid")
                .striped(true)
                .show(&mut cols[0], |ui| {
                    ui.label("Host");
                    ui.label("Files");
                    ui.end_row();
                    for (host, count) in &self.dataset.host_counts {
                        ui.label(host);
                        ui.label(count.to_string());
                        ui.end_row();
                    }
                });

            cols[1].label("Schema Counts");
            egui::ScrollArea::vertical()
                .max_height(320.0)
                .show(&mut cols[1], |ui| {
                    let mut entries: Vec<_> = self.dataset.schema_counts.iter().collect();
                    entries.sort_by_key(|(_, count)| usize::MAX - **count);
                    egui::Grid::new("schema_counts_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Schema");
                            ui.label("Files");
                            ui.end_row();
                            for (schema, count) in entries {
                                ui.label(schema);
                                ui.label(count.to_string());
                                ui.end_row();
                            }
                        });
                });
        });

        ui.separator();
        ui.collapsing("Ingest Errors", |ui| {
            if self.dataset.parse_errors.is_empty() {
                ui.label("No parser errors recorded.");
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for err in self.dataset.parse_errors.iter().take(400) {
                    ui.label(err);
                }
                if self.dataset.parse_errors.len() > 400 {
                    ui.label(format!(
                        "... {} additional errors hidden",
                        self.dataset.parse_errors.len() - 400
                    ));
                }
            });
        });
    }

    fn ui_prefetch_explorer(&mut self, ui: &mut egui::Ui) {
        ui.heading("Prefetch Explorer");
        ui.separator();

        self.ui_prefetch_filters(ui);

        let filtered_rows = self.filtered_prefetch_rows();
        ui.label(format!("filtered manifest rows: {}", filtered_rows.len()));
        self.ui_prefetch_stats_cards(ui, &filtered_rows);

        ui.separator();
        ui.label("Distance vs ns_per_hash");
        let mut fixed_points: Vec<[f64; 2]> = Vec::new();
        let mut auto_points: Vec<[f64; 2]> = Vec::new();

        for row in &filtered_rows {
            let Some(ns_per_hash) = row.ns_per_hash else {
                continue;
            };
            let dist = row
                .effective_prefetch_distance
                .or(row.requested_distance)
                .map(|v| v as f64);
            let Some(distance) = dist else {
                continue;
            };

            let is_auto = row.requested_auto.unwrap_or_else(|| {
                row.setting_kind
                    .as_deref()
                    .map(|k| k.eq_ignore_ascii_case("auto"))
                    .unwrap_or(false)
            });

            if is_auto {
                auto_points.push([distance, ns_per_hash]);
            } else {
                fixed_points.push([distance, ns_per_hash]);
            }
        }

        Plot::new("prefetch_distance_plot")
            .height(240.0)
            .show(ui, |plot_ui| {
                if !fixed_points.is_empty() {
                    plot_ui.points(
                        Points::new(PlotPoints::from(fixed_points))
                            .name("fixed")
                            .radius(3.0)
                            .color(egui::Color32::from_rgb(60, 140, 240)),
                    );
                }
                if !auto_points.is_empty() {
                    plot_ui.points(
                        Points::new(PlotPoints::from(auto_points))
                            .name("auto")
                            .radius(4.0)
                            .color(egui::Color32::from_rgb(240, 120, 40)),
                    );
                }
            });

        ui.separator();
        ui.label("Run-order drift by setting (last vs first, %) ");
        let drift_points = self.compute_drift_points(&filtered_rows);
        let drift_plot_points: Vec<[f64; 2]> =
            drift_points.iter().map(|p| [p.x, p.drift_pct]).collect();
        let drift_labels: Vec<String> = drift_points.iter().map(|p| p.label.clone()).collect();
        let x_axis_labels = drift_labels.clone();
        let hover_labels = drift_labels.clone();

        Plot::new("prefetch_drift_plot")
            .height(220.0)
            .x_axis_formatter(move |mark, _range| {
                let idx = mark.value.round();
                if (mark.value - idx).abs() > 0.2 {
                    return String::new();
                }
                let idx = idx as isize;
                if idx < 0 {
                    return String::new();
                }
                let idx = idx as usize;
                let Some(label) = x_axis_labels.get(idx) else {
                    return String::new();
                };
                if label.len() > 24 {
                    format!("{}...", &label[..24])
                } else {
                    label.clone()
                }
            })
            .label_formatter(move |_series_name, point| {
                let idx = point.x.round();
                let label = if idx >= 0.0 {
                    hover_labels
                        .get(idx as usize)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown")
                } else {
                    "unknown"
                };
                format!("{label}\ndrift: {:.4}%", point.y)
            })
            .show(ui, |plot_ui| {
                if !drift_plot_points.is_empty() {
                    plot_ui.points(
                        Points::new(PlotPoints::from(drift_plot_points))
                            .name("run_order_drift")
                            .radius(3.5)
                            .color(egui::Color32::from_rgb(90, 200, 120)),
                    );
                }
            });

        ui.separator();
        ui.label("Scenario x Distance Heatmap (mean ns_per_hash)");
        self.ui_prefetch_scenario_distance_heatmap(ui, &filtered_rows);

        ui.separator();
        ui.label("Scenario Summary (Auto vs Best Fixed)");
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                egui::Grid::new("scenario_summary_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Host");
                        ui.label("Scenario");
                        ui.label("Mode");
                        ui.label("JIT");
                        ui.label("Delta % (19-col)");
                        ui.label("Delta Mean % (29-col)");
                        ui.label("Delta Median % (29-col)");
                        ui.end_row();

                        for row in self.filtered_scenario_rows() {
                            ui.label(row.host_tag.as_deref().unwrap_or("?"));
                            ui.label(row.scenario_id.as_deref().unwrap_or("?"));
                            ui.label(row.mode.as_deref().unwrap_or("?"));
                            ui.label(row.jit.as_deref().unwrap_or("?"));
                            ui.label(fmt_opt_f64(row.delta_auto_vs_best_fixed_pct));
                            ui.label(fmt_opt_f64(row.delta_auto_vs_best_fixed_mean_pct));
                            ui.label(fmt_opt_f64(row.delta_auto_vs_best_fixed_median_pct));
                            ui.end_row();
                        }
                    });
            });

        ui.separator();
        let mut sort_state = self.manifest_sort;
        Self::ui_manifest_table(ui, &filtered_rows, &mut sort_state);
        self.manifest_sort = sort_state;
    }

    fn ui_prefetch_filters(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            combo_str(
                ui,
                "host",
                &self.filter_options.hosts,
                &mut self.prefetch_filter.host_tag,
            );
            combo_str(
                ui,
                "scenario",
                &self.filter_options.scenarios,
                &mut self.prefetch_filter.scenario_id,
            );
            combo_str(
                ui,
                "mode",
                &self.filter_options.modes,
                &mut self.prefetch_filter.mode,
            );
            combo_str(
                ui,
                "jit",
                &self.filter_options.jits,
                &mut self.prefetch_filter.jit,
            );
            ui.checkbox(
                &mut self.prefetch_filter.only_rows_with_ns_per_hash,
                "Only rows with ns_per_hash",
            );
            if ui.button("Reset Filters").clicked() {
                self.prefetch_filter = PrefetchFilter::default();
            }
        });
    }

    fn filtered_prefetch_rows(&self) -> Vec<&PrefetchManifestRow> {
        self.dataset
            .prefetch_manifest_rows
            .iter()
            .filter(|row| match_str_filter(&self.prefetch_filter.host_tag, row.host_tag.as_deref()))
            .filter(|row| {
                match_str_filter(
                    &self.prefetch_filter.scenario_id,
                    row.scenario_id.as_deref(),
                )
            })
            .filter(|row| match_str_filter(&self.prefetch_filter.mode, row.mode.as_deref()))
            .filter(|row| match_str_filter(&self.prefetch_filter.jit, row.jit.as_deref()))
            .filter(|row| {
                !self.prefetch_filter.only_rows_with_ns_per_hash || row.ns_per_hash.is_some()
            })
            .collect()
    }

    fn filtered_scenario_rows(&self) -> Vec<&crate::model::PrefetchScenarioSummaryRow> {
        self.dataset
            .prefetch_scenario_rows
            .iter()
            .filter(|row| match_str_filter(&self.prefetch_filter.host_tag, row.host_tag.as_deref()))
            .filter(|row| {
                match_str_filter(
                    &self.prefetch_filter.scenario_id,
                    row.scenario_id.as_deref(),
                )
            })
            .filter(|row| match_str_filter(&self.prefetch_filter.mode, row.mode.as_deref()))
            .filter(|row| match_str_filter(&self.prefetch_filter.jit, row.jit.as_deref()))
            .collect()
    }

    fn compute_drift_points(&self, rows: &[&PrefetchManifestRow]) -> Vec<DriftPoint> {
        let mut groups: BTreeMap<String, Vec<&PrefetchManifestRow>> = BTreeMap::new();

        for row in rows {
            let key = format!(
                "{}|{}|{}",
                row.scenario_id.as_deref().unwrap_or("?"),
                row.setting_label.as_deref().unwrap_or("?"),
                row.setting_kind.as_deref().unwrap_or("?"),
            );
            groups.entry(key).or_default().push(row);
        }

        let mut points = Vec::new();
        let mut idx = 0.0;

        for (key, grouped) in &mut groups {
            grouped.sort_by_key(|r| r.run_index.unwrap_or(0));
            let first = grouped.first().and_then(|r| r.ns_per_hash);
            let last = grouped.last().and_then(|r| r.ns_per_hash);
            if let (Some(first), Some(last)) = (first, last) {
                if first.abs() > f64::EPSILON {
                    let drift_pct = ((last / first) - 1.0) * 100.0;
                    points.push(DriftPoint {
                        x: idx,
                        drift_pct,
                        label: key.clone(),
                    });
                    idx += 1.0;
                }
            }
        }

        points
    }

    fn ui_prefetch_stats_cards(&self, ui: &mut egui::Ui, filtered_rows: &[&PrefetchManifestRow]) {
        let mut values: Vec<f64> = filtered_rows.iter().filter_map(|r| r.ns_per_hash).collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

        let count = values.len();
        let min = values.first().copied();
        let median = median(&values);
        let mean = if values.is_empty() {
            None
        } else {
            Some(values.iter().sum::<f64>() / values.len() as f64)
        };
        let max = values.last().copied();

        ui.horizontal_wrapped(|ui| {
            stat_chip(ui, "Rows", count.to_string());
            stat_chip(ui, "Min ns/hash", fmt_opt_f64(min));
            stat_chip(ui, "Median ns/hash", fmt_opt_f64(median));
            stat_chip(ui, "Mean ns/hash", fmt_opt_f64(mean));
            stat_chip(ui, "Max ns/hash", fmt_opt_f64(max));
        });
    }

    fn ui_manifest_table(
        ui: &mut egui::Ui,
        filtered_rows: &[&PrefetchManifestRow],
        sort_state: &mut ManifestSortState,
    ) {
        ui.label("Filtered Manifest Rows");
        ui.horizontal_wrapped(|ui| {
            sort_header_button(ui, "Scenario", ManifestSortKey::Scenario, sort_state);
            sort_header_button(ui, "Setting", ManifestSortKey::Setting, sort_state);
            sort_header_button(ui, "Distance", ManifestSortKey::Distance, sort_state);
            sort_header_button(ui, "Run Index", ManifestSortKey::RunIndex, sort_state);
            sort_header_button(ui, "ns_per_hash", ManifestSortKey::NsPerHash, sort_state);
        });

        let mut rows: Vec<&PrefetchManifestRow> = filtered_rows.to_vec();
        rows.sort_by(|a, b| compare_manifest_rows(a, b, *sort_state));

        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                egui::Grid::new("manifest_rows_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Scenario");
                        ui.label("Setting");
                        ui.label("Distance");
                        ui.label("Run");
                        ui.label("ns/hash");
                        ui.end_row();

                        for row in rows {
                            ui.label(row.scenario_id.as_deref().unwrap_or("?"));
                            ui.label(row.setting_label.as_deref().unwrap_or("?"));
                            ui.label(
                                row.effective_prefetch_distance
                                    .or(row.requested_distance)
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.label(
                                row.run_index
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.label(fmt_opt_f64(row.ns_per_hash));
                            ui.end_row();
                        }
                    });
            });
    }

    fn ui_prefetch_scenario_distance_heatmap(
        &self,
        ui: &mut egui::Ui,
        filtered_rows: &[&PrefetchManifestRow],
    ) {
        let mut bucket: BTreeMap<(String, i64), (f64, usize)> = BTreeMap::new();
        let mut scenario_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut distance_set: BTreeSet<i64> = BTreeSet::new();

        for row in filtered_rows {
            let Some(ns) = row.ns_per_hash else {
                continue;
            };
            let Some(distance) = row.effective_prefetch_distance.or(row.requested_distance) else {
                continue;
            };
            let scenario = row.scenario_id.as_deref().unwrap_or("unknown").to_string();

            let entry = bucket
                .entry((scenario.clone(), distance))
                .or_insert((0.0, 0));
            entry.0 += ns;
            entry.1 += 1;
            *scenario_counts.entry(scenario).or_insert(0) += 1;
            distance_set.insert(distance);
        }

        if bucket.is_empty() {
            ui.label("No rows with both scenario, distance, and ns_per_hash in current filter.");
            return;
        }

        let mut scenarios: Vec<(String, usize)> = scenario_counts.into_iter().collect();
        scenarios.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut scenario_labels: Vec<String> = scenarios
            .into_iter()
            .map(|(scenario, _)| scenario)
            .collect();

        const MAX_SCENARIOS: usize = 20;
        if scenario_labels.len() > MAX_SCENARIOS {
            scenario_labels.truncate(MAX_SCENARIOS);
            ui.small(format!(
                "Showing top {MAX_SCENARIOS} scenarios by row count (use scenario filter to focus)."
            ));
        }

        let mut distances: Vec<i64> = distance_set.into_iter().collect();
        const MAX_DISTANCES: usize = 24;
        if distances.len() > MAX_DISTANCES {
            distances.truncate(MAX_DISTANCES);
            ui.small(format!(
                "Showing first {MAX_DISTANCES} distances (ascending) for readability."
            ));
        }

        let mut min_v = f64::INFINITY;
        let mut max_v = f64::NEG_INFINITY;
        for scenario in &scenario_labels {
            for distance in &distances {
                if let Some((sum, count)) = bucket.get(&(scenario.clone(), *distance)) {
                    let mean = sum / *count as f64;
                    min_v = min_v.min(mean);
                    max_v = max_v.max(mean);
                }
            }
        }

        let spread = (max_v - min_v).max(f64::EPSILON);

        egui::ScrollArea::both().max_height(320.0).show(ui, |ui| {
            egui::Grid::new("prefetch_scenario_distance_heatmap")
                .striped(true)
                .spacing(egui::vec2(3.0, 3.0))
                .show(ui, |ui| {
                    ui.strong("Scenario \\ Distance");
                    for distance in &distances {
                        ui.monospace(distance.to_string());
                    }
                    ui.end_row();

                    for scenario in &scenario_labels {
                        ui.selectable_label(
                            self.prefetch_filter.scenario_id == *scenario,
                            truncate_label(scenario, 24),
                        )
                        .on_hover_text("Use scenario filter above to focus this scenario");

                        for distance in &distances {
                            let Some((sum, count)) = bucket.get(&(scenario.clone(), *distance)) else {
                                ui.label("-");
                                continue;
                            };
                            let mean = sum / *count as f64;
                            let t = ((mean - min_v) / spread).clamp(0.0, 1.0);
                            let fill = heat_color(t);
                            let text = format!("{mean:.2}");
                            let response = ui
                                .add(
                                    egui::Button::new(text)
                                        .fill(fill)
                                        .min_size(egui::vec2(52.0, 20.0)),
                                )
                                .on_hover_text(format!(
                                    "scenario: {scenario}\ndistance: {distance}\nmean ns/hash: {mean:.6}\nrows: {count}"
                                ));
                            let _ = response;
                        }
                        ui.end_row();
                    }
                });
        });
    }

    fn ui_correlation_lab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Correlation Lab");
        ui.separator();

        self.ui_correlation_controls(ui);

        let view = self.build_correlation_view();
        let matrix_opt = if self.corr.view_mode == CorrViewMode::MatrixHeatmap {
            Some(self.correlation_matrix_cached())
        } else {
            None
        };

        ui.horizontal_wrapped(|ui| {
            stat_chip(ui, "Pairs", view.n_pairs.to_string());
            stat_chip(ui, "Pearson r", fmt_opt_f64(view.pearson_r));
            stat_chip(
                ui,
                "R²",
                view.pearson_r
                    .map(|r| format!("{:.4}", r * r))
                    .unwrap_or_else(|| "-".to_string()),
            );
            let slope = view.regression.map(|(m, _)| m);
            let intercept = view.regression.map(|(_, b)| b);
            stat_chip(ui, "Slope", fmt_opt_f64(slope));
            stat_chip(ui, "Intercept", fmt_opt_f64(intercept));
        });

        ui.separator();
        self.ui_correlation_export_actions(ui, &view, matrix_opt.as_ref());
        if let Some(feedback) = &self.corr.export_feedback {
            ui.small(feedback);
        }

        ui.separator();
        match self.corr.view_mode {
            CorrViewMode::Scatter => self.ui_correlation_scatter(ui, &view),
            CorrViewMode::DensityHeatmap => self.ui_correlation_density(ui, &view),
            CorrViewMode::Distribution => self.ui_correlation_distributions(ui, &view),
            CorrViewMode::GroupBars => self.ui_correlation_group_bars(ui, &view),
            CorrViewMode::MatrixHeatmap => {
                if let Some(matrix) = matrix_opt.as_ref() {
                    self.ui_correlation_matrix(ui, matrix);
                } else {
                    ui.label("Matrix unavailable.");
                }
            }
        }

        ui.separator();
        self.ui_correlation_top_corr_table(ui, &view);
    }

    fn ui_correlation_controls(&mut self, ui: &mut egui::Ui) {
        let mut dataset_changed = false;

        ui.horizontal_wrapped(|ui| {
            let before = self.corr.dataset;
            egui::ComboBox::from_label("dataset")
                .selected_text(self.corr.dataset.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.corr.dataset,
                        CorrDataset::PerfRuns,
                        CorrDataset::PerfRuns.label(),
                    );
                    ui.selectable_value(
                        &mut self.corr.dataset,
                        CorrDataset::PrefetchManifest,
                        CorrDataset::PrefetchManifest.label(),
                    );
                });
            dataset_changed = before != self.corr.dataset;

            let metrics = self.active_metric_list().to_vec();
            ensure_metric_selected(&mut self.corr.x_metric, &metrics, "prefetch_distance");
            ensure_metric_selected(&mut self.corr.y_metric, &metrics, "ns_per_hash");

            combo_str(ui, "x metric", &metrics, &mut self.corr.x_metric);
            combo_str(ui, "y metric", &metrics, &mut self.corr.y_metric);

            if ui.button("Swap Axes").clicked() {
                std::mem::swap(&mut self.corr.x_metric, &mut self.corr.y_metric);
            }
        });

        let (hosts, modes, jits, scenarios) = self.correlation_filter_values();

        ui.horizontal_wrapped(|ui| {
            self.correlation_color_combo(ui);
            combo_str(ui, "host", &hosts, &mut self.corr.host_filter);
            combo_str(ui, "mode", &modes, &mut self.corr.mode_filter);
            combo_str(ui, "jit", &jits, &mut self.corr.jit_filter);
            if self.corr.dataset == CorrDataset::PrefetchManifest {
                combo_str(ui, "scenario", &scenarios, &mut self.corr.scenario_filter);
            }
            ui.checkbox(&mut self.corr.only_complete_pairs, "Only complete pairs");
            ui.checkbox(&mut self.corr.show_regression, "Show regression");
        });

        ui.horizontal_wrapped(|ui| {
            ui.label("view:");
            for mode in [
                CorrViewMode::Scatter,
                CorrViewMode::DensityHeatmap,
                CorrViewMode::Distribution,
                CorrViewMode::GroupBars,
                CorrViewMode::MatrixHeatmap,
            ] {
                ui.selectable_value(&mut self.corr.view_mode, mode, mode.label());
            }

            ui.add(
                egui::Slider::new(&mut self.corr.density_bins, 8..=64)
                    .text("density bins")
                    .clamping(egui::SliderClamping::Always),
            );
            ui.add(
                egui::Slider::new(&mut self.corr.hist_bins, 8..=96)
                    .text("hist bins")
                    .clamping(egui::SliderClamping::Always),
            );
            ui.add(
                egui::Slider::new(&mut self.corr.matrix_max_metrics, 6..=40)
                    .text("matrix metrics")
                    .clamping(egui::SliderClamping::Always),
            );
            ui.checkbox(&mut self.corr.matrix_abs_sort, "Coverage sort");
        });

        if dataset_changed {
            self.corr.color_by = default_color_for_dataset(self.corr.dataset);
            self.corr.scenario_filter = "All".to_string();
            self.corr.export_feedback = None;
        }
    }

    fn ui_correlation_export_actions(
        &mut self,
        ui: &mut egui::Ui,
        view: &CorrelationView,
        matrix_opt: Option<&CorrelationMatrix>,
    ) {
        let matrix_cached = matrix_opt.cloned();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Export Scatter CSV").clicked() {
                self.corr.export_feedback = match self.export_corr_points_csv(view) {
                    Ok(path) => Some(format!("wrote {}", path.display())),
                    Err(err) => Some(format!("scatter csv export failed: {err}")),
                };
            }
            if ui.button("Export Correlation CSV").clicked() {
                self.corr.export_feedback = match self.export_corr_rankings_csv(view) {
                    Ok(path) => Some(format!("wrote {}", path.display())),
                    Err(err) => Some(format!("correlation csv export failed: {err}")),
                };
            }
            if ui.button("Export Scatter PNG").clicked() {
                self.corr.export_feedback = match self.export_corr_scatter_png(view) {
                    Ok(path) => Some(format!("wrote {}", path.display())),
                    Err(err) => Some(format!("scatter png export failed: {err}")),
                };
            }
            if ui.button("Export Matrix PNG").clicked() {
                let matrix = matrix_cached
                    .clone()
                    .unwrap_or_else(|| self.correlation_matrix_cached());
                self.corr.export_feedback = match self.export_corr_matrix_png(&matrix) {
                    Ok(path) => Some(format!("wrote {}", path.display())),
                    Err(err) => Some(format!("matrix png export failed: {err}")),
                };
            }
        });
    }

    fn ui_correlation_scatter(&mut self, ui: &mut egui::Ui, view: &CorrelationView) {
        ui.label(format!(
            "Scatter: {} vs {}",
            self.corr.y_metric, self.corr.x_metric
        ));

        let color_keys: Vec<String> = view.points_by_color.keys().cloned().collect();
        let x_metric_label = self.corr.x_metric.clone();
        let y_metric_label = self.corr.y_metric.clone();

        Plot::new("correlation_scatter_plot")
            .height(360.0)
            .label_formatter(move |series, point| {
                format!(
                    "group: {series}\n{}: {:.4}\n{}: {:.4}",
                    x_metric_label, point.x, y_metric_label, point.y
                )
            })
            .show(ui, |plot_ui| {
                for key in &color_keys {
                    if let Some(points) = view.points_by_color.get(key) {
                        plot_ui.points(
                            Points::new(PlotPoints::from(points.clone()))
                                .name(key)
                                .radius(3.0)
                                .color(color_for_key(key)),
                        );
                    }
                }

                if self.corr.show_regression {
                    if let (Some((slope, intercept)), Some((xmin, xmax))) =
                        (view.regression, view.x_min_max)
                    {
                        let line_points = vec![
                            [xmin, slope * xmin + intercept],
                            [xmax, slope * xmax + intercept],
                        ];
                        plot_ui.line(
                            Line::new(PlotPoints::from(line_points))
                                .name("regression")
                                .color(egui::Color32::from_rgb(240, 80, 80)),
                        );
                    }
                }
            });
    }

    fn ui_correlation_density(&self, ui: &mut egui::Ui, view: &CorrelationView) {
        ui.label(format!(
            "Density Heatmap: {} vs {}",
            self.corr.y_metric, self.corr.x_metric
        ));

        let Some((x_min, x_max)) = view.x_min_max else {
            ui.label("No finite x values.");
            return;
        };
        let Some((y_min, y_max)) = view.y_min_max else {
            ui.label("No finite y values.");
            return;
        };
        if view.points.is_empty() {
            ui.label("No finite points.");
            return;
        }

        let bins = self.corr.density_bins.max(2);
        let mut counts = vec![0usize; bins * bins];
        let x_span = (x_max - x_min).max(f64::EPSILON);
        let y_span = (y_max - y_min).max(f64::EPSILON);
        for p in &view.points {
            let tx = ((p.x - x_min) / x_span).clamp(0.0, 1.0);
            let ty = ((p.y - y_min) / y_span).clamp(0.0, 1.0);
            let ix = ((tx * (bins as f64 - 1.0)).round() as usize).min(bins - 1);
            let iy = ((ty * (bins as f64 - 1.0)).round() as usize).min(bins - 1);
            counts[iy * bins + ix] += 1;
        }
        let max_count = counts.iter().copied().max().unwrap_or(1).max(1);

        let available = ui.available_size();
        let size = egui::vec2(available.x.min(920.0), available.y.clamp(320.0, 480.0));
        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, egui::Color32::from_rgb(16, 22, 30));

        let cell_w = rect.width() / bins as f32;
        let cell_h = rect.height() / bins as f32;

        for iy in 0..bins {
            for ix in 0..bins {
                let idx = iy * bins + ix;
                let count = counts[idx];
                let t = count as f64 / max_count as f64;
                let y_inv = bins - 1 - iy;
                let x0 = rect.left() + ix as f32 * cell_w;
                let y0 = rect.top() + y_inv as f32 * cell_h;
                let cell_rect =
                    egui::Rect::from_min_size(egui::pos2(x0, y0), egui::vec2(cell_w, cell_h));
                painter.rect_filled(cell_rect.shrink(1.0), 2.0, density_color(t));
            }
        }

        painter.text(
            rect.left_top() + egui::vec2(6.0, 6.0),
            egui::Align2::LEFT_TOP,
            format!("x: {} [{x_min:.3}..{x_max:.3}]", self.corr.x_metric),
            egui::TextStyle::Monospace.resolve(ui.style()),
            egui::Color32::WHITE,
        );
        painter.text(
            rect.left_top() + egui::vec2(6.0, 24.0),
            egui::Align2::LEFT_TOP,
            format!("y: {} [{y_min:.3}..{y_max:.3}]", self.corr.y_metric),
            egui::TextStyle::Monospace.resolve(ui.style()),
            egui::Color32::WHITE,
        );
        painter.text(
            rect.left_top() + egui::vec2(6.0, 42.0),
            egui::Align2::LEFT_TOP,
            format!("bins: {bins}x{bins}   max bin count: {max_count}"),
            egui::TextStyle::Monospace.resolve(ui.style()),
            egui::Color32::from_rgb(220, 225, 230),
        );

        if let Some(pos) = response.hover_pos() {
            let ix = (((pos.x - rect.left()) / cell_w).floor() as isize).clamp(0, bins as isize - 1)
                as usize;
            let y_inv = (((pos.y - rect.top()) / cell_h).floor() as isize)
                .clamp(0, bins as isize - 1) as usize;
            let iy = bins - 1 - y_inv;
            let idx = iy * bins + ix;
            let count = counts[idx];
            response.on_hover_text(format!("bin ({ix},{iy})\ncount: {count}"));
        }
    }

    fn ui_correlation_distributions(&self, ui: &mut egui::Ui, view: &CorrelationView) {
        let x_values: Vec<f64> = view.points.iter().map(|p| p.x).collect();
        let y_values: Vec<f64> = view.points.iter().map(|p| p.y).collect();
        if x_values.is_empty() || y_values.is_empty() {
            ui.label("Not enough points for distribution charts.");
            return;
        }

        ui.columns(2, |cols| {
            cols[0].label(format!("Histogram: {}", self.corr.x_metric));
            histogram_plot(
                &mut cols[0],
                "corr_hist_x",
                &x_values,
                self.corr.hist_bins,
                &self.corr.x_metric,
            );
            cols[0].separator();
            cols[0].label(format!("ECDF: {}", self.corr.x_metric));
            ecdf_plot(&mut cols[0], "corr_ecdf_x", &x_values, &self.corr.x_metric);

            cols[1].label(format!("Histogram: {}", self.corr.y_metric));
            histogram_plot(
                &mut cols[1],
                "corr_hist_y",
                &y_values,
                self.corr.hist_bins,
                &self.corr.y_metric,
            );
            cols[1].separator();
            cols[1].label(format!("ECDF: {}", self.corr.y_metric));
            ecdf_plot(&mut cols[1], "corr_ecdf_y", &y_values, &self.corr.y_metric);
        });
    }

    fn ui_correlation_group_bars(&self, ui: &mut egui::Ui, view: &CorrelationView) {
        if view.points.is_empty() {
            ui.label("No grouped points to plot.");
            return;
        }

        let mut grouped: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for point in &view.points {
            grouped
                .entry(point.color_key.clone())
                .or_default()
                .push(point.y);
        }
        if grouped.is_empty() {
            ui.label("No grouped points to plot.");
            return;
        }

        let mut rows: Vec<(String, f64, f64, usize)> = grouped
            .into_iter()
            .filter_map(|(key, values)| {
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
                Some((key, mean, variance.sqrt(), values.len()))
            })
            .collect();
        rows.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal));

        if rows.len() > 24 {
            rows.truncate(24);
            ui.small("Showing 24 groups max in chart for readability.");
        }

        let labels: Vec<String> = rows.iter().map(|(k, _, _, _)| k.clone()).collect();
        let bars: Vec<Bar> = rows
            .iter()
            .enumerate()
            .map(|(idx, (_, mean, _, _))| Bar::new(idx as f64, *mean).width(0.75))
            .collect();
        let y_metric_label = self.corr.y_metric.clone();
        let labels_for_ticks = labels.clone();

        Plot::new("corr_group_means_plot")
            .height(320.0)
            .x_axis_formatter(move |mark, _| {
                let idx = mark.value.round() as isize;
                if idx < 0 {
                    return String::new();
                }
                labels_for_ticks
                    .get(idx as usize)
                    .map(|s| truncate_label(s, 12))
                    .unwrap_or_default()
            })
            .label_formatter(move |series, point| {
                format!("group: {series}\n{}: {:.5}", y_metric_label, point.y)
            })
            .show(ui, |plot_ui| {
                plot_ui.bar_chart(
                    BarChart::new(bars)
                        .name("group mean")
                        .color(egui::Color32::from_rgb(92, 172, 255)),
                );
            });

        ui.separator();
        ui.label("Group Stats");
        egui::Grid::new("corr_group_stats_grid")
            .striped(true)
            .show(ui, |ui| {
                ui.label("Group");
                ui.label("Mean");
                ui.label("StdDev");
                ui.label("Rows");
                ui.end_row();
                for (group, mean, stddev, n) in rows {
                    ui.monospace(group);
                    ui.monospace(format!("{mean:.6}"));
                    ui.monospace(format!("{stddev:.6}"));
                    ui.monospace(n.to_string());
                    ui.end_row();
                }
            });
    }

    fn ui_correlation_matrix(&mut self, ui: &mut egui::Ui, matrix: &CorrelationMatrix) {
        if matrix.metrics.is_empty() {
            ui.label("Not enough numeric metrics for matrix view.");
            return;
        }

        ui.label("Click a cell to drill down into scatter view.");
        egui::ScrollArea::both().max_height(520.0).show(ui, |ui| {
            egui::Grid::new("corr_matrix_grid")
                .striped(false)
                .spacing(egui::vec2(3.0, 3.0))
                .show(ui, |ui| {
                    ui.strong("metric");
                    for metric in &matrix.metrics {
                        ui.small(truncate_label(metric, 10));
                    }
                    ui.end_row();

                    for (ry, row_metric) in matrix.metrics.iter().enumerate() {
                        ui.monospace(truncate_label(row_metric, 22));
                        for (rx, _col_metric) in matrix.metrics.iter().enumerate() {
                            let cell = &matrix.cells[ry][rx];
                            let fill = match cell.pearson_r {
                                Some(r) => diverging_color(r),
                                None => egui::Color32::from_rgb(44, 48, 56),
                            };
                            let text = cell
                                .pearson_r
                                .map(|r| format!("{r:.2}"))
                                .unwrap_or_else(|| "-".to_string());
                            let clicked = ui
                                .add(
                                    egui::Button::new(text)
                                        .fill(fill)
                                        .min_size(egui::vec2(40.0, 22.0)),
                                )
                                .on_hover_text(format!(
                                    "x: {}\ny: {}\npearson r: {}\npairs: {}",
                                    cell.metric_x,
                                    cell.metric_y,
                                    cell.pearson_r
                                        .map(|v| format!("{v:.6}"))
                                        .unwrap_or_else(|| "n/a".to_string()),
                                    cell.n_pairs
                                ))
                                .clicked();

                            if clicked && cell.metric_x != cell.metric_y {
                                self.corr.x_metric = cell.metric_x.clone();
                                self.corr.y_metric = cell.metric_y.clone();
                                self.corr.view_mode = CorrViewMode::Scatter;
                            }
                        }
                        ui.end_row();
                    }
                });
        });
    }

    fn ui_correlation_top_corr_table(&self, ui: &mut egui::Ui, view: &CorrelationView) {
        ui.label(format!(
            "Top correlations against target metric '{}'",
            self.corr.y_metric
        ));
        egui::ScrollArea::vertical()
            .max_height(240.0)
            .show(ui, |ui| {
                egui::Grid::new("top_corr_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Metric");
                        ui.label("Pearson r");
                        ui.label("Pairs");
                        ui.end_row();

                        for (metric, r, pairs) in view.top_correlations.iter().take(25) {
                            ui.monospace(metric);
                            ui.monospace(format!("{r:.5}"));
                            ui.monospace(pairs.to_string());
                            ui.end_row();
                        }
                    });
            });
    }

    fn correlation_matrix_cache_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.corr.dataset.label(),
            self.corr.host_filter,
            self.corr.mode_filter,
            self.corr.jit_filter,
            self.corr.scenario_filter,
            self.corr.matrix_max_metrics,
            self.corr.matrix_abs_sort,
            self.corr.only_complete_pairs,
            self.active_metric_list().join(",")
        )
    }

    fn correlation_matrix_cached(&mut self) -> CorrelationMatrix {
        let key = self.correlation_matrix_cache_key();
        if self.corr_matrix_cache_key.as_deref() != Some(key.as_str()) {
            let matrix = self.build_correlation_matrix();
            self.corr_matrix_cache = Some(matrix.clone());
            self.corr_matrix_cache_key = Some(key);
            return matrix;
        }
        self.corr_matrix_cache
            .clone()
            .unwrap_or_else(|| self.build_correlation_matrix())
    }

    fn build_correlation_matrix(&self) -> CorrelationMatrix {
        let metrics = self.matrix_metrics_ranked();
        if metrics.is_empty() {
            return CorrelationMatrix {
                metrics,
                cells: Vec::new(),
            };
        }

        match self.corr.dataset {
            CorrDataset::PerfRuns => {
                let rows = self.filtered_perf_corr_rows();
                let columns: Vec<Vec<Option<f64>>> = metrics
                    .iter()
                    .map(|metric| rows.iter().map(|r| perf_metric_value(r, metric)).collect())
                    .collect();
                let cells = build_matrix_cells(&metrics, &columns);
                CorrelationMatrix { metrics, cells }
            }
            CorrDataset::PrefetchManifest => {
                let rows = self.filtered_manifest_corr_rows();
                let columns: Vec<Vec<Option<f64>>> = metrics
                    .iter()
                    .map(|metric| {
                        rows.iter()
                            .map(|r| manifest_metric_value(r, metric))
                            .collect()
                    })
                    .collect();
                let cells = build_matrix_cells(&metrics, &columns);
                CorrelationMatrix { metrics, cells }
            }
        }
    }

    fn matrix_metrics_ranked(&self) -> Vec<String> {
        let base = self.active_metric_list();
        let mut scored: Vec<(String, usize)> = match self.corr.dataset {
            CorrDataset::PerfRuns => {
                let rows = self.filtered_perf_corr_rows();
                base.iter()
                    .map(|metric| {
                        let coverage = rows
                            .iter()
                            .filter(|row| {
                                perf_metric_value(row, metric)
                                    .map(|v| v.is_finite())
                                    .unwrap_or(false)
                            })
                            .count();
                        (metric.clone(), coverage)
                    })
                    .collect()
            }
            CorrDataset::PrefetchManifest => {
                let rows = self.filtered_manifest_corr_rows();
                base.iter()
                    .map(|metric| {
                        let coverage = rows
                            .iter()
                            .filter(|row| {
                                manifest_metric_value(row, metric)
                                    .map(|v| v.is_finite())
                                    .unwrap_or(false)
                            })
                            .count();
                        (metric.clone(), coverage)
                    })
                    .collect()
            }
        };
        scored.retain(|(_, coverage)| *coverage >= 3);

        if self.corr.matrix_abs_sort {
            scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        } else {
            scored.sort_by(|a, b| a.0.cmp(&b.0));
        }

        scored
            .into_iter()
            .take(self.corr.matrix_max_metrics)
            .map(|(metric, _)| metric)
            .collect()
    }

    fn export_corr_points_csv(&self, view: &CorrelationView) -> Result<PathBuf, String> {
        let path = self.next_export_path("scatter", "csv");
        write_correlation_points_csv(&path, view, &self.corr.x_metric, &self.corr.y_metric)?;
        Ok(path)
    }

    fn export_corr_rankings_csv(&self, view: &CorrelationView) -> Result<PathBuf, String> {
        let path = self.next_export_path("correlations", "csv");
        write_correlation_rankings_csv(&path, &self.corr.y_metric, &view.top_correlations)?;
        Ok(path)
    }

    fn export_corr_scatter_png(&self, view: &CorrelationView) -> Result<PathBuf, String> {
        let path = self.next_export_path("scatter", "png");
        write_scatter_png(&path, view, &self.corr.x_metric, &self.corr.y_metric)?;
        Ok(path)
    }

    fn export_corr_matrix_png(&self, matrix: &CorrelationMatrix) -> Result<PathBuf, String> {
        let path = self.next_export_path("corr_matrix", "png");
        write_matrix_png(&path, matrix)?;
        Ok(path)
    }

    fn next_export_path(&self, stem: &str, ext: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dataset = self
            .corr
            .dataset
            .label()
            .to_ascii_lowercase()
            .replace(' ', "_");
        self.export_root_dir()
            .join(format!("{}_{}_{}.{}", dataset, stem, ts, ext))
    }

    fn export_root_dir(&self) -> PathBuf {
        self.dataset
            .root
            .parent()
            .map(|p| p.join("tools/perf_viz/exports"))
            .unwrap_or_else(|| PathBuf::from("perf_viz_exports"))
    }

    fn correlation_color_combo(&mut self, ui: &mut egui::Ui) {
        let allowed = allowed_color_options(self.corr.dataset);
        if !allowed.contains(&self.corr.color_by) {
            self.corr.color_by = default_color_for_dataset(self.corr.dataset);
        }

        egui::ComboBox::from_label("color by")
            .selected_text(self.corr.color_by.label())
            .show_ui(ui, |ui| {
                for option in allowed {
                    ui.selectable_value(&mut self.corr.color_by, option, option.label());
                }
            });
    }

    fn active_metric_list(&self) -> &[String] {
        match self.corr.dataset {
            CorrDataset::PerfRuns => &self.metric_catalog.perf_metrics,
            CorrDataset::PrefetchManifest => &self.metric_catalog.manifest_metrics,
        }
    }

    fn correlation_filter_values(&self) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
        match self.corr.dataset {
            CorrDataset::PerfRuns => {
                let hosts = values_with_all(
                    self.dataset
                        .perf_runs
                        .iter()
                        .filter_map(|r| infer_host_from_any_path(&r.source_path)),
                );
                let modes = values_with_all(
                    self.dataset
                        .perf_runs
                        .iter()
                        .filter_map(|r| r.mode.as_deref().map(ToOwned::to_owned)),
                );
                let jits =
                    values_with_all(
                        self.dataset
                            .perf_runs
                            .iter()
                            .map(|r| match r.jit_requested {
                                Some(true) => "true".to_string(),
                                Some(false) => "false".to_string(),
                                None => "unknown".to_string(),
                            }),
                    );
                let scenarios = vec!["All".to_string()];
                (hosts, modes, jits, scenarios)
            }
            CorrDataset::PrefetchManifest => {
                let hosts = values_with_all(
                    self.dataset
                        .prefetch_manifest_rows
                        .iter()
                        .filter_map(|r| r.host_tag.as_deref().map(ToOwned::to_owned)),
                );
                let modes = values_with_all(
                    self.dataset
                        .prefetch_manifest_rows
                        .iter()
                        .filter_map(|r| r.mode.as_deref().map(ToOwned::to_owned)),
                );
                let jits = values_with_all(
                    self.dataset
                        .prefetch_manifest_rows
                        .iter()
                        .filter_map(|r| r.jit.as_deref().map(ToOwned::to_owned)),
                );
                let scenarios = values_with_all(
                    self.dataset
                        .prefetch_manifest_rows
                        .iter()
                        .filter_map(|r| r.scenario_id.as_deref().map(ToOwned::to_owned)),
                );
                (hosts, modes, jits, scenarios)
            }
        }
    }

    fn filtered_perf_corr_rows(&self) -> Vec<&PerfRunRecord> {
        self.dataset
            .perf_runs
            .iter()
            .filter(|row| {
                let host = infer_host_from_any_path(&row.source_path)
                    .unwrap_or_else(|| "unknown".to_string());
                match_str_filter(&self.corr.host_filter, Some(&host))
            })
            .filter(|row| match_str_filter(&self.corr.mode_filter, row.mode.as_deref()))
            .filter(|row| {
                let jit = match row.jit_requested {
                    Some(true) => "true",
                    Some(false) => "false",
                    None => "unknown",
                };
                match_str_filter(&self.corr.jit_filter, Some(jit))
            })
            .collect()
    }

    fn filtered_manifest_corr_rows(&self) -> Vec<&PrefetchManifestRow> {
        self.dataset
            .prefetch_manifest_rows
            .iter()
            .filter(|row| match_str_filter(&self.corr.host_filter, row.host_tag.as_deref()))
            .filter(|row| match_str_filter(&self.corr.mode_filter, row.mode.as_deref()))
            .filter(|row| match_str_filter(&self.corr.jit_filter, row.jit.as_deref()))
            .filter(|row| match_str_filter(&self.corr.scenario_filter, row.scenario_id.as_deref()))
            .collect()
    }

    fn build_correlation_view(&self) -> CorrelationView {
        match self.corr.dataset {
            CorrDataset::PerfRuns => self.build_perf_correlation_view(),
            CorrDataset::PrefetchManifest => self.build_manifest_correlation_view(),
        }
    }

    fn build_perf_correlation_view(&self) -> CorrelationView {
        let mut points: Vec<CorrelationPoint> = Vec::new();

        let filtered_rows = self.filtered_perf_corr_rows();

        for row in &filtered_rows {
            let x = perf_metric_value(row, &self.corr.x_metric);
            let y = perf_metric_value(row, &self.corr.y_metric);

            if self.corr.only_complete_pairs {
                let (Some(x), Some(y)) = (x, y) else {
                    continue;
                };
                if !x.is_finite() || !y.is_finite() {
                    continue;
                }
                points.push(CorrelationPoint {
                    x,
                    y,
                    color_key: perf_color_key(row, self.corr.color_by),
                });
            } else if let (Some(x), Some(y)) = (x, y) {
                if x.is_finite() && y.is_finite() {
                    points.push(CorrelationPoint {
                        x,
                        y,
                        color_key: perf_color_key(row, self.corr.color_by),
                    });
                }
            }
        }

        let points_snapshot = points.clone();
        let (points_by_color, flat_points, x_min_max, y_min_max) = group_points(points);
        let pearson_r = pearson_from_pairs(&flat_points);
        let regression = linear_regression_from_pairs(&flat_points);

        let top_correlations = ranked_correlations_perf(
            &filtered_rows,
            &self.metric_catalog.perf_metrics,
            &self.corr.y_metric,
        );

        CorrelationView {
            points: points_snapshot,
            n_pairs: flat_points.len(),
            points_by_color,
            pearson_r,
            regression,
            x_min_max,
            y_min_max,
            top_correlations,
        }
    }

    fn build_manifest_correlation_view(&self) -> CorrelationView {
        let mut points: Vec<CorrelationPoint> = Vec::new();

        let filtered_rows = self.filtered_manifest_corr_rows();

        for row in &filtered_rows {
            let x = manifest_metric_value(row, &self.corr.x_metric);
            let y = manifest_metric_value(row, &self.corr.y_metric);

            if self.corr.only_complete_pairs {
                let (Some(x), Some(y)) = (x, y) else {
                    continue;
                };
                if !x.is_finite() || !y.is_finite() {
                    continue;
                }
                points.push(CorrelationPoint {
                    x,
                    y,
                    color_key: manifest_color_key(row, self.corr.color_by),
                });
            } else if let (Some(x), Some(y)) = (x, y) {
                if x.is_finite() && y.is_finite() {
                    points.push(CorrelationPoint {
                        x,
                        y,
                        color_key: manifest_color_key(row, self.corr.color_by),
                    });
                }
            }
        }

        let points_snapshot = points.clone();
        let (points_by_color, flat_points, x_min_max, y_min_max) = group_points(points);
        let pearson_r = pearson_from_pairs(&flat_points);
        let regression = linear_regression_from_pairs(&flat_points);

        let top_correlations = ranked_correlations_manifest(
            &filtered_rows,
            &self.metric_catalog.manifest_metrics,
            &self.corr.y_metric,
        );

        CorrelationView {
            points: points_snapshot,
            n_pairs: flat_points.len(),
            points_by_color,
            pearson_r,
            regression,
            x_min_max,
            y_min_max,
            top_correlations,
        }
    }

    fn ui_run_inspector(&mut self, ui: &mut egui::Ui) {
        ui.heading("Run Inspector");
        ui.separator();

        let needle = self.file_search.trim().to_ascii_lowercase();
        let matching_indices: Vec<usize> = self
            .catalog_lowercase_paths
            .iter()
            .enumerate()
            .filter_map(|(idx, lower)| {
                if needle.is_empty() || lower.contains(&needle) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        ui.columns(2, |cols| {
            cols[0].horizontal(|ui| {
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.file_search);
                ui.label(format!("Matches: {}", matching_indices.len()));
            });

            cols[0].separator();
            let row_height = cols[0].text_style_height(&egui::TextStyle::Body);
            egui::ScrollArea::vertical().show_rows(
                &mut cols[0],
                row_height,
                matching_indices.len(),
                |ui, row_range| {
                    for row in row_range {
                        let idx = matching_indices[row];
                        let entry = &self.dataset.catalog[idx];
                        let selected = self.selected_file_idx == Some(idx);
                        if ui
                            .selectable_label(selected, entry.rel_path.to_string_lossy())
                            .clicked()
                        {
                            self.selected_file_idx = Some(idx);
                        }
                    }
                },
            );

            cols[1].separator();
            self.ui_selected_file_preview(&mut cols[1]);
        });
    }

    fn ui_selected_file_preview(&mut self, ui: &mut egui::Ui) {
        let Some(selected_idx) = self.selected_file_idx else {
            ui.label("Select a file from the list.");
            return;
        };

        let Some(entry) = self.dataset.catalog.get(selected_idx) else {
            ui.label("Selection out of range.");
            return;
        };

        ui.label(format!("path: {}", entry.rel_path.display()));
        ui.horizontal_wrapped(|ui| {
            chip(ui, format!("ext: {}", entry.extension));
            chip(ui, format!("schema: {}", entry.schema_hint));
            chip(ui, format!("encoding: {}", entry.encoding_hint));
            chip(ui, format!("size: {}", human_bytes(entry.size_bytes)));
        });
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open in Editor").clicked() {
                self.action_feedback = match open_in_editor(&entry.abs_path) {
                    Ok(()) => Some("Opened file in editor/system viewer.".to_string()),
                    Err(err) => Some(format!("Open in editor failed: {err}")),
                };
            }
            if ui.button("Open Folder").clicked() {
                self.action_feedback = match open_folder(&entry.abs_path) {
                    Ok(()) => Some("Opened containing folder.".to_string()),
                    Err(err) => Some(format!("Open folder failed: {err}")),
                };
            }
            if let Some(feedback) = &self.action_feedback {
                ui.label(feedback);
            }
        });
        ui.separator();

        self.raw_cache
            .entry(entry.abs_path.clone())
            .or_insert_with(|| {
                read_text_preview(&entry.abs_path, self.raw_preview_max_bytes)
                    .unwrap_or_else(|e| format!("failed to read preview: {e}"))
            });

        egui::ScrollArea::both().show(ui, |ui| {
            if let Some(content) = self.raw_cache.get(&entry.abs_path) {
                ui.monospace(content);
            }
        });
    }
}

impl eframe::App for PerfVizApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            self.ui_top_bar(ui);
        });

        egui::SidePanel::left("nav_panel")
            .resizable(true)
            .default_width(210.0)
            .min_width(180.0)
            .show(ctx, |ui| {
                self.ui_navigation_panel(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Overview => self.ui_overview(ui),
            Tab::PrefetchExplorer => self.ui_prefetch_explorer(ui),
            Tab::CorrelationLab => self.ui_correlation_lab(ui),
            Tab::RunInspector => self.ui_run_inspector(ui),
        });
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

    for (key, count) in extra_numeric_counts {
        if count >= 8 {
            perf_metrics.push(key);
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

fn pick_default_metric(metrics: &[String], preferred: &str) -> String {
    if metrics.iter().any(|m| m == preferred) {
        return preferred.to_string();
    }
    metrics
        .first()
        .cloned()
        .unwrap_or_else(|| preferred.to_string())
}

fn ensure_metric_selected(selected: &mut String, metrics: &[String], preferred: &str) {
    if metrics.is_empty() {
        selected.clear();
        return;
    }
    if metrics.iter().any(|m| m == selected) {
        return;
    }
    *selected = pick_default_metric(metrics, preferred);
}

fn allowed_color_options(dataset: CorrDataset) -> Vec<CorrColorBy> {
    match dataset {
        CorrDataset::PerfRuns => vec![
            CorrColorBy::None,
            CorrColorBy::Host,
            CorrColorBy::Mode,
            CorrColorBy::Jit,
            CorrColorBy::Schema,
            CorrColorBy::PrefetchAuto,
        ],
        CorrDataset::PrefetchManifest => vec![
            CorrColorBy::None,
            CorrColorBy::Host,
            CorrColorBy::Mode,
            CorrColorBy::Jit,
            CorrColorBy::Scenario,
            CorrColorBy::SettingKind,
            CorrColorBy::PrefetchAuto,
        ],
    }
}

fn default_color_for_dataset(dataset: CorrDataset) -> CorrColorBy {
    match dataset {
        CorrDataset::PerfRuns => CorrColorBy::Mode,
        CorrDataset::PrefetchManifest => CorrColorBy::Scenario,
    }
}

type YMinMax = Option<(f64, f64)>;

fn group_points(
    points: Vec<CorrelationPoint>,
) -> (GroupedScatterPoints, PairValues, XMinMax, YMinMax) {
    let mut points_by_color: GroupedScatterPoints = BTreeMap::new();
    let mut flat_points = Vec::new();

    let mut x_min = f64::INFINITY;
    let mut x_max = f64::NEG_INFINITY;
    let mut y_min = f64::INFINITY;
    let mut y_max = f64::NEG_INFINITY;

    for p in points {
        points_by_color
            .entry(p.color_key)
            .or_default()
            .push([p.x, p.y]);
        flat_points.push((p.x, p.y));

        if p.x < x_min {
            x_min = p.x;
        }
        if p.x > x_max {
            x_max = p.x;
        }
        if p.y < y_min {
            y_min = p.y;
        }
        if p.y > y_max {
            y_max = p.y;
        }
    }

    let x_min_max = if x_min.is_finite() && x_max.is_finite() {
        Some((x_min, x_max))
    } else {
        None
    };
    let y_min_max = if y_min.is_finite() && y_max.is_finite() {
        Some((y_min, y_max))
    } else {
        None
    };

    (points_by_color, flat_points, x_min_max, y_min_max)
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

fn build_matrix_cells(
    metrics: &[String],
    columns: &[Vec<Option<f64>>],
) -> Vec<Vec<CorrelationMatrixCell>> {
    let mut out = Vec::with_capacity(metrics.len());

    for (iy, metric_y) in metrics.iter().enumerate() {
        let mut row_cells = Vec::with_capacity(metrics.len());
        for (ix, metric_x) in metrics.iter().enumerate() {
            if ix == iy {
                let count = columns[ix]
                    .iter()
                    .filter(|v| v.map(|x| x.is_finite()).unwrap_or(false))
                    .count();
                row_cells.push(CorrelationMatrixCell {
                    metric_x: metric_x.clone(),
                    metric_y: metric_y.clone(),
                    pearson_r: if count >= 2 { Some(1.0) } else { None },
                    n_pairs: count,
                });
                continue;
            }

            let mut pairs = Vec::new();
            for (xv, yv) in columns[ix].iter().zip(columns[iy].iter()) {
                if let (Some(x), Some(y)) = (xv, yv) {
                    if x.is_finite() && y.is_finite() {
                        pairs.push((*x, *y));
                    }
                }
            }
            let r = pearson_from_pairs(&pairs);
            row_cells.push(CorrelationMatrixCell {
                metric_x: metric_x.clone(),
                metric_y: metric_y.clone(),
                pearson_r: r,
                n_pairs: pairs.len(),
            });
        }
        out.push(row_cells);
    }

    out
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

fn perf_color_key(row: &PerfRunRecord, color_by: CorrColorBy) -> String {
    match color_by {
        CorrColorBy::None => "all".to_string(),
        CorrColorBy::Host => {
            infer_host_from_any_path(&row.source_path).unwrap_or_else(|| "unknown".to_string())
        }
        CorrColorBy::Mode => row.mode.clone().unwrap_or_else(|| "unknown".to_string()),
        CorrColorBy::Jit => match row.jit_requested {
            Some(true) => "jit:true".to_string(),
            Some(false) => "jit:false".to_string(),
            None => "jit:unknown".to_string(),
        },
        CorrColorBy::Schema => row.schema_name.clone(),
        CorrColorBy::PrefetchAuto => match row.prefetch_auto_tune {
            Some(true) => "auto:true".to_string(),
            Some(false) => "auto:false".to_string(),
            None => "auto:unknown".to_string(),
        },
        CorrColorBy::Scenario | CorrColorBy::SettingKind => "n/a".to_string(),
    }
}

fn manifest_color_key(row: &PrefetchManifestRow, color_by: CorrColorBy) -> String {
    match color_by {
        CorrColorBy::None => "all".to_string(),
        CorrColorBy::Host => row
            .host_tag
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        CorrColorBy::Mode => row.mode.clone().unwrap_or_else(|| "unknown".to_string()),
        CorrColorBy::Jit => row.jit.clone().unwrap_or_else(|| "unknown".to_string()),
        CorrColorBy::Scenario => row
            .scenario_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        CorrColorBy::SettingKind => row
            .setting_kind
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        CorrColorBy::PrefetchAuto => match row.requested_auto {
            Some(true) => "auto:true".to_string(),
            Some(false) => "auto:false".to_string(),
            None => "auto:unknown".to_string(),
        },
        CorrColorBy::Schema => "manifest".to_string(),
    }
}

fn infer_host_from_any_path(path: &Path) -> Option<String> {
    let parts: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    if let Some(pos) = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("perf_results"))
    {
        return parts.get(pos + 1).cloned();
    }
    parts.first().cloned()
}

fn values_with_all(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for value in values {
        if !value.trim().is_empty() {
            set.insert(value);
        }
    }
    let mut out = Vec::with_capacity(set.len() + 1);
    out.push("All".to_string());
    out.extend(set);
    out
}

fn combo_str(ui: &mut egui::Ui, label: &str, values: &[String], selected: &mut String) {
    egui::ComboBox::from_label(label)
        .selected_text(selected.clone())
        .show_ui(ui, |ui| {
            for value in values {
                ui.selectable_value(selected, value.clone(), value);
            }
        });
}

fn match_str_filter(filter_value: &str, candidate: Option<&str>) -> bool {
    if filter_value == "All" {
        return true;
    }
    candidate
        .map(|v| v.eq_ignore_ascii_case(filter_value))
        .unwrap_or(false)
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

fn fmt_opt_f64(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{v:.4}"),
        None => "-".to_string(),
    }
}

fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some((values[mid - 1] + values[mid]) / 2.0)
    } else {
        values.get(mid).copied()
    }
}

fn sort_header_button(
    ui: &mut egui::Ui,
    label: &str,
    key: ManifestSortKey,
    state: &mut ManifestSortState,
) {
    let indicator = if state.key == key {
        if state.descending {
            " ▼"
        } else {
            " ▲"
        }
    } else {
        ""
    };
    let text = format!("{label}{indicator}");
    if ui.button(text).clicked() {
        if state.key == key {
            state.descending = !state.descending;
        } else {
            state.key = key;
            state.descending = false;
        }
    }
}

fn compare_manifest_rows(
    a: &PrefetchManifestRow,
    b: &PrefetchManifestRow,
    sort: ManifestSortState,
) -> Ordering {
    let ord = match sort.key {
        ManifestSortKey::Scenario => {
            cmp_opt_str(a.scenario_id.as_deref(), b.scenario_id.as_deref()).then(cmp_opt_str(
                a.setting_label.as_deref(),
                b.setting_label.as_deref(),
            ))
        }
        ManifestSortKey::Setting => {
            cmp_opt_str(a.setting_label.as_deref(), b.setting_label.as_deref())
                .then(cmp_opt_u64(a.run_index, b.run_index))
        }
        ManifestSortKey::Distance => cmp_opt_i64(
            a.effective_prefetch_distance.or(a.requested_distance),
            b.effective_prefetch_distance.or(b.requested_distance),
        )
        .then(cmp_opt_u64(a.run_index, b.run_index)),
        ManifestSortKey::RunIndex => cmp_opt_u64(a.run_index, b.run_index),
        ManifestSortKey::NsPerHash => cmp_opt_f64(a.ns_per_hash, b.ns_per_hash),
    };

    if sort.descending {
        ord.reverse()
    } else {
        ord
    }
}

fn cmp_opt_str(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn cmp_opt_u64(a: Option<u64>, b: Option<u64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn cmp_opt_i64(a: Option<i64>, b: Option<i64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn cmp_opt_f64(a: Option<f64>, b: Option<f64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn chip(ui: &mut egui::Ui, text: impl Into<String>) {
    let text = text.into();
    let chip_text = egui::RichText::new(text)
        .monospace()
        .background_color(egui::Color32::from_rgb(38, 45, 54))
        .color(egui::Color32::from_rgb(230, 236, 244));
    ui.label(chip_text);
}

fn stat_chip(ui: &mut egui::Ui, label: &str, value: String) {
    ui.group(|ui| {
        ui.label(egui::RichText::new(label).strong());
        ui.monospace(value);
    });
}

fn human_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.2} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

fn color_for_key(key: &str) -> egui::Color32 {
    let palette = [
        egui::Color32::from_rgb(231, 76, 60),
        egui::Color32::from_rgb(52, 152, 219),
        egui::Color32::from_rgb(46, 204, 113),
        egui::Color32::from_rgb(241, 196, 15),
        egui::Color32::from_rgb(155, 89, 182),
        egui::Color32::from_rgb(230, 126, 34),
        egui::Color32::from_rgb(26, 188, 156),
        egui::Color32::from_rgb(149, 165, 166),
        egui::Color32::from_rgb(127, 140, 141),
        egui::Color32::from_rgb(52, 73, 94),
    ];
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % palette.len();
    palette[idx]
}

fn truncate_label(label: &str, max_chars: usize) -> String {
    if label.chars().count() <= max_chars {
        return label.to_string();
    }
    let mut out = String::new();
    for (idx, ch) in label.chars().enumerate() {
        if idx >= max_chars {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn density_color(t: f64) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let r = (28.0 + 220.0 * t) as u8;
    let g = (44.0 + 170.0 * (1.0 - (t - 0.45).abs() * 1.4).clamp(0.0, 1.0)) as u8;
    let b = (60.0 + 175.0 * (1.0 - t)) as u8;
    egui::Color32::from_rgb(r, g, b)
}

fn heat_color(t: f64) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let r = (30.0 + 225.0 * t) as u8;
    let g = (88.0 + 130.0 * (1.0 - (t - 0.3).abs() * 1.5).clamp(0.0, 1.0)) as u8;
    let b = (180.0 + 60.0 * (1.0 - t)) as u8;
    egui::Color32::from_rgb(r, g, b)
}

fn diverging_color(r: f64) -> egui::Color32 {
    let v = r.clamp(-1.0, 1.0);
    if v >= 0.0 {
        let t = v;
        let rr = (70.0 + 180.0 * t) as u8;
        let gg = (44.0 + 130.0 * (1.0 - t)) as u8;
        let bb = (64.0 + 90.0 * (1.0 - t)) as u8;
        egui::Color32::from_rgb(rr, gg, bb)
    } else {
        let t = -v;
        let rr = (52.0 + 100.0 * (1.0 - t)) as u8;
        let gg = (86.0 + 100.0 * (1.0 - t)) as u8;
        let bb = (110.0 + 145.0 * t) as u8;
        egui::Color32::from_rgb(rr, gg, bb)
    }
}

fn histogram_plot(ui: &mut egui::Ui, id: &str, values: &[f64], bins: usize, metric_label: &str) {
    let finite: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if finite.is_empty() {
        ui.label("No finite values.");
        return;
    }

    let mut min_v = f64::INFINITY;
    let mut max_v = f64::NEG_INFINITY;
    for v in &finite {
        min_v = min_v.min(*v);
        max_v = max_v.max(*v);
    }

    let bins = bins.max(4);
    let span = (max_v - min_v).max(f64::EPSILON);
    let bin_w = span / bins as f64;
    let mut counts = vec![0usize; bins];
    for v in &finite {
        let t = ((*v - min_v) / span).clamp(0.0, 1.0);
        let idx = ((t * (bins as f64 - 1.0)).round() as usize).min(bins - 1);
        counts[idx] += 1;
    }
    let bars: Vec<Bar> = counts
        .iter()
        .enumerate()
        .map(|(i, count)| {
            let center = min_v + (i as f64 + 0.5) * bin_w;
            Bar::new(center, *count as f64)
                .width(bin_w * 0.9)
                .fill(egui::Color32::from_rgb(88, 160, 245))
        })
        .collect();

    let metric = metric_label.to_string();
    Plot::new(id)
        .height(210.0)
        .label_formatter(move |_series, point| {
            format!("{}: {:.6}\ncount: {:.0}", metric, point.x, point.y)
        })
        .show(ui, |plot_ui| {
            plot_ui.bar_chart(BarChart::new(bars));
        });
}

fn ecdf_plot(ui: &mut egui::Ui, id: &str, values: &[f64], metric_label: &str) {
    let mut finite: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if finite.is_empty() {
        ui.label("No finite values.");
        return;
    }
    finite.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let n = finite.len() as f64;
    let points: Vec<[f64; 2]> = finite
        .iter()
        .enumerate()
        .map(|(idx, v)| [*v, (idx as f64 + 1.0) / n])
        .collect();
    let metric = metric_label.to_string();
    Plot::new(id)
        .height(170.0)
        .label_formatter(move |_series, point| {
            format!("{}: {:.6}\nF(x): {:.4}", metric, point.x, point.y)
        })
        .show(ui, |plot_ui| {
            plot_ui.line(
                Line::new(PlotPoints::from(points))
                    .color(egui::Color32::from_rgb(237, 180, 72))
                    .name("ecdf"),
            );
        });
}

fn write_correlation_points_csv(
    path: &Path,
    view: &CorrelationView,
    x_label: &str,
    y_label: &str,
) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let mut writer = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    writer
        .write_record(["group", x_label, y_label])
        .map_err(|e| e.to_string())?;
    for point in &view.points {
        writer
            .write_record([
                point.color_key.as_str(),
                &format!("{:.12}", point.x),
                &format!("{:.12}", point.y),
            ])
            .map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

fn write_correlation_rankings_csv(
    path: &Path,
    target_metric: &str,
    rows: &[(String, f64, usize)],
) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let mut writer = csv::Writer::from_path(path).map_err(|e| e.to_string())?;
    writer
        .write_record(["target_metric", "metric", "pearson_r", "pairs"])
        .map_err(|e| e.to_string())?;
    for (metric, r, pairs) in rows {
        writer
            .write_record([
                target_metric,
                metric.as_str(),
                &format!("{:.12}", r),
                &pairs.to_string(),
            ])
            .map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

fn write_scatter_png(
    path: &Path,
    view: &CorrelationView,
    x_metric: &str,
    y_metric: &str,
) -> Result<(), String> {
    ensure_parent_dir(path)?;
    if view.points.is_empty() {
        return Err("no points to export".to_string());
    }
    let Some((x_min, x_max)) = view.x_min_max else {
        return Err("x-range unavailable".to_string());
    };
    let Some((y_min, y_max)) = view.y_min_max else {
        return Err("y-range unavailable".to_string());
    };
    let x_pad = ((x_max - x_min).abs() * 0.05).max(1e-9);
    let y_pad = ((y_max - y_min).abs() * 0.05).max(1e-9);

    let root = BitMapBackend::new(path, (1400, 900)).into_drawing_area();
    root.fill(&RGBColor(16, 20, 27))
        .map_err(|e| e.to_string())?;

    let mut chart = ChartBuilder::on(&root)
        .margin(24)
        .caption(
            format!("Correlation Scatter: {y_metric} vs {x_metric}"),
            ("sans-serif", 28).into_font().color(&WHITE),
        )
        .x_label_area_size(48)
        .y_label_area_size(64)
        .build_cartesian_2d(
            (x_min - x_pad)..(x_max + x_pad),
            (y_min - y_pad)..(y_max + y_pad),
        )
        .map_err(|e| e.to_string())?;

    chart
        .configure_mesh()
        .x_desc(x_metric)
        .y_desc(y_metric)
        .axis_style(WHITE.mix(0.7))
        .label_style(("sans-serif", 16).into_font().color(&WHITE))
        .light_line_style(RGBColor(42, 50, 60))
        .draw()
        .map_err(|e| e.to_string())?;

    for (group, points) in &view.points_by_color {
        let color = color_for_key(group);
        let plot_color = RGBColor(color.r(), color.g(), color.b());
        chart
            .draw_series(
                points
                    .iter()
                    .map(|xy| Circle::new((xy[0], xy[1]), 3, plot_color.filled())),
            )
            .map_err(|e| e.to_string())?;
    }

    if let (Some((slope, intercept)), Some((xmin, xmax))) = (view.regression, view.x_min_max) {
        chart
            .draw_series(LineSeries::new(
                vec![
                    (xmin, slope * xmin + intercept),
                    (xmax, slope * xmax + intercept),
                ],
                &RGBColor(245, 90, 90),
            ))
            .map_err(|e| e.to_string())?;
    }

    root.present().map_err(|e| e.to_string())
}

fn write_matrix_png(path: &Path, matrix: &CorrelationMatrix) -> Result<(), String> {
    ensure_parent_dir(path)?;
    if matrix.metrics.is_empty() {
        return Err("no matrix data".to_string());
    }

    let n = matrix.metrics.len();
    let cell = 34i32;
    let left = 260i32;
    let top = 120i32;
    let w = (left + cell * n as i32 + 60).max(1000) as u32;
    let h = (top + cell * n as i32 + 60).max(800) as u32;

    let root = BitMapBackend::new(path, (w, h)).into_drawing_area();
    root.fill(&RGBColor(16, 20, 27))
        .map_err(|e| e.to_string())?;

    root.draw(&Text::new(
        "Correlation Matrix",
        (24, 40),
        ("sans-serif", 34).into_font().color(&WHITE),
    ))
    .map_err(|e| e.to_string())?;

    for (idx, metric) in matrix.metrics.iter().enumerate() {
        let y = top + idx as i32 * cell + (cell / 2);
        root.draw(&Text::new(
            truncate_label(metric, 28),
            (8, y + 4),
            ("sans-serif", 14).into_font().color(&WHITE),
        ))
        .map_err(|e| e.to_string())?;

        let x = left + idx as i32 * cell + (cell / 2);
        root.draw(&Text::new(
            truncate_label(metric, 12),
            (x - 20, 94),
            ("sans-serif", 12).into_font().color(&WHITE),
        ))
        .map_err(|e| e.to_string())?;
    }

    for iy in 0..n {
        for ix in 0..n {
            let cell_data = &matrix.cells[iy][ix];
            let egui_color = match cell_data.pearson_r {
                Some(r) => diverging_color(r),
                None => egui::Color32::from_rgb(44, 48, 56),
            };
            let fill = RGBColor(egui_color.r(), egui_color.g(), egui_color.b());
            let x0 = left + ix as i32 * cell;
            let y0 = top + iy as i32 * cell;
            let rect = Rectangle::new([(x0, y0), (x0 + cell - 1, y0 + cell - 1)], fill.filled());
            root.draw(&rect).map_err(|e| e.to_string())?;
        }
    }

    root.present().map_err(|e| e.to_string())
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn open_in_editor(path: &Path) -> Result<(), String> {
    if let Ok(editor) = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")) {
        Command::new(editor)
            .arg(path)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    open_with_system_default(path)
}

fn open_folder(path: &Path) -> Result<(), String> {
    let folder = path.parent().unwrap_or(path);
    open_with_system_default(folder)
}

fn open_with_system_default(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("explorer");
        c.arg(path);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(path);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(path);
        c
    };

    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}
