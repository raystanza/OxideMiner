# Perf Results Visualizer Guide

`tools/perf_viz/` is a local developer dashboard for browsing untracked
`perf_results/` data.

## Expectations

- point it at local `crates/oxide-randomx/perf_results/`
- treat the data as developer-local scratch or evidence, not committed source
- use it to inspect CSV/JSON outputs from `perf_harness`,
  `full_features_benchmark`, and related tools

## Typical Layout

Common local paths look like:

- `perf_results/local/*.csv`
- `perf_results/local/*.json`
- `perf_results/local/ff_*`
- `perf_results/local/prefetch_calibration.csv`

## Run It

From `crates/oxide-randomx/tools/perf_viz/`:

```bash
cargo run --release -- --root ../../perf_results
```

The visualizer recursively scans the chosen root and groups compatible CSV/JSON
artifacts by filename conventions and embedded metadata such as `host_tag`,
`page_profile`, and timestamps.

## When To Use It

- comparing repeated local runs
- checking page-backing realization changes
- reviewing ABBA pair deltas
- browsing local prefetch or superscalar experiments
