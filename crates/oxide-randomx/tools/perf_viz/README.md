# perf_viz

Developer-only web dashboard for `perf_results/` with high-quality Plotly charts.

## Run

From repo root:

```bash
cargo run --manifest-path tools/perf_viz/Cargo.toml --release
```

The server starts on `http://127.0.0.1:8765/` and opens your browser automatically.

Pages:

- Dashboard: `http://127.0.0.1:8765/`
- Explanations: `http://127.0.0.1:8765/explanations`

## Useful Flags

```bash
# Custom dataset root
cargo run --manifest-path tools/perf_viz/Cargo.toml --release -- --root perf_results

# Custom bind address/port
cargo run --manifest-path tools/perf_viz/Cargo.toml --release -- --host 127.0.0.1 --port 9000

# Do not auto-open browser
cargo run --manifest-path tools/perf_viz/Cargo.toml --release -- --no-open
```

## Why The UI Changed

The previous desktop `egui` plotting surface was replaced with a web-first charting UI so we can use:

- denser, clearer, publication-quality chart rendering
- better interaction for large datasets (zoom, pan, hover, click drill-down)
- richer chart types than the original scatter-first layout

## What It Implements (Web Dashboard)

- File catalog with host buckets + schema/encoding hints.
- CSV schema detection and typed parsing for:
  - core perf rows (75/79/83/91 column variants)
  - prefetch manifests (47/30/10)
  - prefetch settings summaries (24/26)
  - prefetch scenario summaries (19/29)
- JSON schema detection and typed parsing for prefetch summary JSON.
- Split frontend assets:
  - `web/index.html` for structure
  - `web/explanations.html` for explanation page structure
  - `web/styles.css` for visual system
  - `web/app.js` for charts, interactions, and state handling
  - `web/explanations.js` for narrative insight rendering
- Web tabs:
  - `Prefetch Explorer`
    - filterable prefetch scatter (`auto` vs `fixed`)
    - run-order drift bars
    - scenario x distance heatmap (`mean ns_per_hash`)
    - summary stat cards
  - `Correlation Studio`
    - high-density scatter + regression
    - 2D density heatmap
    - marginal distributions for X and Y
    - grouped mean/stddev bars
    - full correlation matrix heatmap
    - click matrix cell to drill down to selected X/Y scatter
    - CSV and PNG exports in-browser
  - `Analytics Atlas`
    - `Dataset Overview`: KPI tiles, ingest health, snapshot delta timeline, schema totals
    - `Coverage Map`: host x mode, host x jit, scenario x distance heatmaps + missingness
    - `Data Quality / Schema Drift`: parse errors by extension, null-rates, schema-over-time stacks
    - `Stability Lab`: CV distribution, drift control chart, repeatability stable/unstable rankings
    - `Host Benchmark Arena`: normalized ns/hash + hashes/sec group comparisons and pairwise deltas
    - `Pareto Frontier`: performance vs stability frontier candidates (`mean ns/hash` vs `cv%`)
    - `Outlier & Anomaly Forensics`: robust z-score / IQR anomalies with row drill-down details
    - `Timeline / Regression Watch`: trend lines and detected change-point markers
- Dedicated explanations page:
  - dataset-level explanation cards and key findings
  - filter controls for `host` / `mode` / `jit` / `scenario`
  - host distribution, scenario performance extremes, and drift hotspot charts
  - top perf/manifest correlations explained in table form
  - auto-vs-fixed interpretation summary for prefetch behavior
- Rendering policy:
  - WebGL-independent traces only (`scatter`, `heatmap`, `histogram`, `bar`)
  - no `scattergl` dependency
  - label handling is case-insensitive for grouping/filtering (e.g. `Intel`/`intel`, `AMD`/`amd`)
- Workspace features:
  - theme presets (`Nebula`, `Slate`, `Ember`, `Aurora`)
  - built-in example layouts shipped by default:
    - `Prefetch Explorer - Stability Sweep`
    - `Prefetch Explorer - Intel Focus`
    - `Prefetch Explorer - AMD JIT Off`
    - `Prefetch Explorer - Light Scenario`
    - `Prefetch Explorer - Portable Sweep`
    - `Correlation Studio - Perf Drivers`
    - `Correlation Studio - Manifest Distance`
    - `Correlation Studio - JIT Contrast`
    - `Correlation Studio - Host Buckets`
    - `Correlation Studio - Manifest Drift Lens`
    - `Analytics Atlas - Quality Audit`
    - `Analytics Atlas - Drift Sentinel`
    - `Analytics Atlas - Intel Portable`
    - `Analytics Atlas - AMD JIT Off Audit`
    - `Analytics Atlas - Light Scenario Focus`
    - `Analytics Atlas - Fast Scenario Focus`
  - named custom dashboard layouts (save/load/delete)
  - session persistence across restarts via local storage

## Notes

- This is a local developer dashboard, not a public service.
- Correlation is associative, not causal. Use it to prioritize follow-up experiments.
