# Perf Results Visualizer Guide (Rust)

This guide is based on the current `perf_results/` data layout in this repo.

## 1. What Is In `perf_results/`

### High-level inventory

- Total files: `2205`
- Total size: about `17 MB`
- Top-level areas:
  - `AMD/` (`1020` files)
  - `Intel/` (`1171` files)
  - `local/` (`1` file)
  - `unlabeled/` (`11` files)
  - 2 top-level cross-host decision markdown files

### File types (count)

- `csv`: `760`
- `stderr`: `567`
- `stdout`: `551`
- `log`: `128`
- `txt`: `68`
- `json`: `66`
- `md`: `37`
- `exe`: `14`
- `py`: `3`
- `ps1`: `5`
- `sh`: `2`
- `patch`: `2`
- no extension: `2` (Linux executables)

### Important encoding/format caveats

- CSV/JSON are ASCII-compatible and parse cleanly.
- `stderr` files are mixed:
  - `379` ASCII
  - `184` UTF-16LE (mostly Windows captures)
  - `4` binary-ish
- `stdout` files are mostly empty.
- Some CSVs use quoted headers; others do not.
- Some fields use sentinels: `n/a`, `NaN`, empty string.
- Paths are mixed Windows and Unix styles in the same dataset.

## 2. Data Families You Need To Parse

You do not need one parser per file. You need one parser per schema family.

### A) Core perf-harness run CSVs (main payload)

- Family sizes:
  - 79 columns, `463` files
  - 75 columns, `188` files
  - 91 columns, `48` files
  - 83 columns, `4` files
- Typical rows per file: usually `1` row (sometimes up to `4`).
- Main fields:
  - provenance: `git_sha`, `features`, `cpu`, `rustc`
  - run params: `mode`, `iters`, `warmup`, `threads`, JIT flags, large-page flags
  - KPIs: `ns_per_hash`, `hashes_per_sec`, `elapsed_ns`
  - counters: instruction/memory/JIT counters
  - prefetch fields (present in 79/83/91): `prefetch`, `prefetch_distance`, `prefetch_auto_tune`, `scratchpad_prefetch_distance`
  - fine-grained stage timings (91/83 variants): `finish_*`, `jit_fastregs_*_ns`

### B) Prefetch sweep manifests and summaries

- Manifest CSVs:
  - 47 columns (v6_01/v6_02 style)
  - 30 columns (v5_07 style)
  - 10 columns (older Intel style)
- Settings summary CSV:
  - 24 columns (AMD)
  - 26 columns (Intel; includes median columns)
- Scenario summary CSV:
  - 19 columns (AMD)
  - 29 columns (Intel; mean+median winner fields and tolerance flags)
- Summary JSON:
  - top-level metadata + `scenarios[]` with per-setting arrays and computed deltas
- Typical rows:
  - manifests: ~`78` to `90` rows
  - settings summaries: ~`26` to `30` rows
  - scenario summaries: `3` rows

### C) Pair/perf index + pair benchmark CSVs

- Index schemas:
  - 8 columns: `mode,pair_label,config_label,seq,force,path,stdout_path,stderr_path`
  - 7 columns: same idea with quoted header and `csv/stdout/stderr`
  - 4 columns: `mode,pair_label,path,raw_log_path`
- Pair benchmark rows (16 columns):
  - `pair_label`, `config_label`, `force`, `repeat_index`, `run_order`, `ns_per_hash`, etc.

### D) Legacy/auxiliary CSVs

- Bench apples:
  - 15-column and 18-column variants
- Measurement matrix:
  - 17-column and 18-column variants
- One-off tables:
  - `local/prefetch_calibration.csv` (21 columns, 1 row)
  - `unlabeled/vendor_classification_final.csv` (6 columns, 211 rows)

### E) JSON families

- JSON schema families observed: `23`
- Largest family (`36` files) shares keys:
  - `provenance`, `params`, `results`, `stages`, `counters`, `jit`, `instrumented`
- Other families are analysis summaries (`simd_blockio`, `dispatch`, `jit_fastregs`, superscalar prototype, prefetch summary).

### F) Text/log artifacts

- `*.txt`:
  - many `key=value` provenance/manifest files
  - `perf_compare summary` files
  - hugepage status/provenance notes
- `*.raw.log`:
  - repeated blocks starting with `---- ... ----`
  - contains many `key=value` lines per run
- `*.stderr`:
  - build/test output or one-line summary output
  - mixed encoding (important)

## 3. Recommended App Shape

Build a dev-only desktop app with `egui` so you can quickly drill down and iterate.

### Suggested crate and dependencies

- Create new binary crate (outside core library path if preferred), for example:
  - `tools/perf_viz/`
- Suggested deps:
  - `anyhow`, `thiserror`
  - `clap`
  - `walkdir`, `globset`, `regex`
  - `csv`, `serde`, `serde_json`
  - `chrono`
  - `encoding_rs`
  - `rayon`
  - `rusqlite` (or in-memory first, then SQLite)
  - `eframe`, `egui`, `egui_plot`

## 4. Implementation Plan

### Step 1: Build a file catalog

- Recursively scan `perf_results/`.
- For each file store:
  - absolute path, repo-relative path, extension, size
  - host bucket (`AMD`, `Intel`, `local`, `unlabeled`, top-level)
  - detected encoding (at least for text/stderr/log)
  - capture timestamp parsed from filename when possible
- Keep this in memory and write to cache JSON/SQLite for fast reload.

### Step 2: Add schema detection by signature

- For CSV:
  - read first non-empty line as header
  - hash it (sha1) and map to parser enum
  - unknown hash -> generic CSV table viewer (do not crash)
- For JSON:
  - parse top-level keys and route by key-set fingerprint
- For TXT/LOG:
  - parse `key=value` lines where possible
  - store unparsed lines for raw viewer

### Step 3: Normalize records into typed models

Use typed structs with optional fields for cross-version compatibility.

- `PerfRunRecord` (for 75/79/83/91-column families)
- `PrefetchManifestRow`
- `PrefetchSettingSummaryRow`
- `PrefetchScenarioSummaryRow`
- `PairPerfIndexRow`
- `PairBenchRow`
- `BenchApplesRow`
- `CalibrationRow`

Model rules:

- parse bool case-insensitive (`true/false`, `on/off`, `1/0`)
- parse numeric with tolerant converters
- map `n/a`, `NaN`, empty -> `None` where appropriate
- retain unknown columns in `extra: BTreeMap<String, String>`

### Step 4: Build joins and relations

- Join manifests to run CSVs by `artifact_csv` / `out_csv` path.
- Join settings/scenario summaries by `host_tag + timestamp + scenario_id`.
- Join pair index rows to detail CSV files by path.
- Normalize path separators:
  - convert backslashes to `/` for matching
  - preserve original path for display

### Step 5: Build UI tabs

- `Overview`
  - counts by host, schema, timestamp
  - ingest errors
- `Prefetch Explorer`
  - filter by host/scenario/mode/jit
  - chart: `prefetch_distance` vs `ns_per_hash`
  - chart: run-order drift per setting
  - table: auto vs best-fixed deltas
- `Pair Compare`
  - show baseline/candidate distributions by pair label
  - show pass/fail from `perf_compare` txt when present
- `Run Inspector`
  - select a row and view all metrics + linked raw files
  - raw panes for CSV/JSON/stdout/stderr/log

### Step 6: Caching and speed

- First pass: parse everything into memory.
- Next pass: add SQLite cache keyed by `(path, size, mtime)`.
- Parallelize parsing with `rayon`.
- Lazy-load large text panes only on selection.

### Step 7: Validation checks

- Validate expected row counts in manifests and summary files.
- Surface path references that do not exist.
- Surface schema hashes not in known registry.
- Surface encoding decode failures (especially UTF-16LE stderr).

## 5. MVP Scope (Recommended)

Implement these first:

1. File scanner + schema classifier.
2. Parsers for:
   - core perf-run CSV (75/79/83/91)
   - prefetch manifest/settings/scenario CSV
   - prefetch summary JSON
3. Egui tab for Prefetch Explorer with filters and 2 plots.
4. Raw-file side panel (CSV/JSON/TXT/LOG/STDERR).

This gets you immediate visual value with minimal complexity.

## 6. Sample Files To Use As Fixtures

- Core perf row (79 cols): `perf_results/AMD/v6_01_prefetch_amd_light_jit_conservative_fixed_d5_r2_o5_20260228_131113.csv`
- Core perf row (75 cols): `perf_results/AMD/v6_08_candidate_light_jit_conservative_a2_amd_20260301_143149.csv`
- Core perf row (91 cols): `perf_results/AMD/v7_12_fast_interp_lp1g_success_amd_linux_20260307_125524.csv`
- Prefetch manifest (47 cols): `perf_results/Intel/v6_02_prefetch_sweep_manifest_intel_20260228_205621.csv`
- Prefetch settings summary: `perf_results/Intel/v6_02_prefetch_settings_summary_intel_20260228_205621.csv`
- Prefetch scenario summary: `perf_results/Intel/v6_02_prefetch_scenario_summary_intel_20260228_205621.csv`
- Prefetch summary JSON: `perf_results/Intel/v6_02_prefetch_summary_intel_20260228_205621.json`
- Pair perf index: `perf_results/Intel/v7_09_perf_index_intel_fam6_mod58_20260306_191318.csv`
- Pair bench rows: `perf_results/Intel/v7_09_bench_light_baseline_vs_forced_intel_fam6_mod58_20260306_191318.csv`
- UTF-16 stderr example: `perf_results/AMD/v5_07_prefetch_amd_light_jit_off_fixed_d0_r1_o1_20260221_130014.stderr`
