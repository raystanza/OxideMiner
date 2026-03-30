# Performance Guide

This repository ships a **deterministic benchmark harness** (an example binary) and **optional instrumentation** for profiling the RandomX **interpreter** and **JIT** execution paths.

The intent of this guide is twofold:

1. Provide a **repeatable way** to benchmark the crate across machines/OSes.
2. Explain **every supported invocation** of the bench tool and how to turn its output into useful performance metrics (throughput, speedup, cache behavior, compile overhead, instruction mix, etc.).

Document boundaries:

- This file (`docs/perf.md`) is the measurement/how-to reference.
- `docs/oxideminer-integration-profile.md` is the narrow parent-facing
  supported-profile reference.
- `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md` is the current
  integrated feature-interaction memo; use it when matrix sweeps and ABBA
  results need interpretation.
- Current host baselines + disposition snapshots are tracked in:
  - `docs/perf-results-amd.md`
  - `docs/perf-results-intel.md`
- Canonical status/priority plan is tracked in `dev/ROADMAPv9.md`.

---

## Upstream-safe integration profile

For current `HEAD`, the parent-safe integration profile is:

- default throughput path: build with `jit jit-fastregs bench-instrument`,
  run with `--jit on --jit-fast-regs on`
- conservative fallback: build with `jit bench-instrument`, run with
  `--jit on --jit-fast-regs off`
- lowest-risk fallback: build with `bench-instrument`, run with `--jit off`
- large pages and Linux 1GB huge pages are explicit request knobs; verify
  emitted outcome fields instead of assuming success
- host-local prefetch calibration is optional; the default mapping remains
  unchanged
- keep `simd-blockio`, `simd-xor-paths`, `threaded-interp`, and
  `superscalar-accel-proto` out of default parent measurements
- do not treat matrix-only "best config" tables as policy authority

Recommended supported-path measurement:

```bash
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --format human
```

Authority:

- `docs/oxideminer-integration-profile.md`
- `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
- `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`
- `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`
- `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`

---

## Quick start

For parent-facing defaults, the `perf_harness` recipe above is the policy
surface. The `bench` commands below often run multiple paths back-to-back for
comparison; that is a measurement convenience, not an implied production
default.

### 1) Light-mode baseline (cache-only)

Run both interpreter and JIT (if compiled), print human output:

```bash
cargo run --release --example bench --features "jit" -- --mode light --jit both
```

Add instrumentation report (requires `bench-instrument`):

```bash
cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit both --report
```

### 2) Enable JIT fast-register mapping (if compiled)

Fast-regs requires the compile-time feature **and** the runtime flag:

```bash
cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --report
```

### 3) Fast-mode (dataset) benchmark (opt-in)

Fast mode is gated to avoid accidental multi-GB allocations:

* You must set `OXIDE_RANDOMX_FAST_BENCH=1`
* You should expect dataset initialization to take time and memory

Example (Linux/macOS bash):

```bash
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --report
```

Example (Windows PowerShell):

```powershell
$env:OXIDE_RANDOMX_FAST_BENCH = "1"
cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --report
```

### Perf harness

The `perf_harness` example is the structured measurement entrypoint. It always emits
provenance, supports JSON/CSV output, and adds stage timers + counters when compiled
with `bench-instrument`.

Example (human output):

```bash
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --format human
```

Example (JSON to file, summary to stderr):

```bash
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --format json --out out.json
```

Examples (CSV recipes with large pages + affinity):

```bash
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 20 --warmup 2 --threads 4 --large-pages on --thread-names on \
  --affinity compact --format csv --out out_light.csv

OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_FAST_BENCH_SMALL=1 cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument unsafe-config" -- \
  --mode fast --jit on --jit-fast-regs on --iters 5 --warmup 1 --threads 4 --large-pages on --thread-names on \
  --affinity compact --format csv --out out_fast.csv
```

### SuperscalarHash microbench harness

`superscalar_hash_harness` is a focused local harness for cache-item synthesis work.
It is intentionally narrower than `bench`/`perf_harness` and targets:

* `compute_item_words_in_place(...)`
* scalar superscalar program execution used by that path

Default workload is deterministic (`RandomXConfig::test_small()`, fixed key, fixed
item/register seed generation) so repeated runs are directly comparable.

Implementation selection:

* `--impl active` (default): uses the crate's currently active superscalar path.
* `--impl scalar`: forces scalar superscalar execution as a baseline/reference.

Run examples:

```bash
# Human summary (default deterministic test-small config)
cargo run --release --example superscalar_hash_harness -- --iters 2000 --warmup 200 --items 128

# Structured output for artifact capture
cargo run --release --example superscalar_hash_harness -- --format json --iters 2000 --warmup 200 --items 128
cargo run --release --example superscalar_hash_harness -- --format csv --iters 2000 --warmup 200 --items 128

# Compare active path vs explicit scalar baseline
cargo run --release --example superscalar_hash_harness -- --impl active --format json --iters 2000 --warmup 200 --items 128
cargo run --release --example superscalar_hash_harness -- --impl scalar --format json --iters 2000 --warmup 200 --items 128

# Experimental proto path (currently parked behind the feature gate)
cargo run --release --example superscalar_hash_harness --features superscalar-accel-proto -- --impl active --format json --iters 2000 --warmup 200 --items 128
```

Notes:

* This harness is for local optimization and differential validation of the
  SuperscalarHash/cache-item path.
* It is **not** a replacement for split host-baseline authority docs:
  `docs/perf-results-amd.md` and `docs/perf-results-intel.md`.
* Current superscalar authority memo:
  `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`.
* Historical v7 prototype memo: `docs/superscalar-prototype-v7-07.md`.

---

## What the bench tool actually measures (very important)

The bench tool runs three distinct phases:

1. **Initialization (not timed)**

   * Creates `RandomXCache` (always).
   * If `--mode fast`, creates `RandomXDataset` using `--threads N`.
   * Creates `RandomXVm` with requested flags.

2. **Warmup loop (not included in timing)**

   * Repeats `--warmup` iterations over a fixed input set.
   * Purpose:

     * heat CPU caches,
     * populate JIT program cache / trigger compiles,
     * reduce first-iteration artifacts.

3. **Measured loop (timed)**

   * Calls `vm.reset_perf_stats()` (instrumented counters reset here).
   * Executes `--iters` iterations over the same fixed input set.
   * Measures total wall time, then reports **ns/hash**.

Key implication:

* **Dataset/cache initialization time is not part of `elapsed_ns` / `ns_per_hash`.**
* With warmup > 0, most JIT compilation happens during warmup, but **JIT compile totals are still reported** (via JIT stats), so we can quantify compile overhead separately.

---

## Workload definition

The bench tool uses a deterministic workload so results are comparable:

* **Key**: 32 bytes, value `0x00..0x1f` (byte index).
* **Inputs**: 6 messages of sizes:

  * `0, 1, 16, 64, 256, 1024` bytes
* Input bytes are generated by a fixed LCG sequence.

This means:

* Results are stable across runs.
* Output fields like `inputs` and `hashes` are predictable.

If you want a different workload (e.g., more inputs, larger messages), modify `make_workload()` in `examples/bench.rs` and keep it deterministic.

---

## Build features and what they unlock

The bench tool’s behavior depends on compile-time Cargo features:

### `jit`

Enables the JIT backend in the library and makes `--jit on|both` meaningful.

Without this feature:

* The bench tool can still run, but JIT cannot be enabled.
* If you request JIT, the bench tool will warn you.

### `jit-fastregs`

Builds the optional “fast register mapping” JIT codegen path.

* You still must opt in at runtime using `--jit-fast-regs on`.
* Status policy: the baseline `jit-fastregs` path is the best-supported
  current-throughput path on the captured host set.
* The later P2.2 dataset-base mask follow-up candidate was dropped after clean cross-host reruns.
* The integrated `ff_*` memo did not displace baseline `jit-fastregs`; it
  reinforces that experimental mixes do not change the supported default path.
* Current decision memo: `perf_results/P2_2_jit_fastregs_cross_host_decision_2026-03-01.md`

### `bench-instrument`

Enables performance counters/timers in the library.

* Required for `--report` to print meaningful details.
* Without it, `--report` prints a “disabled” line.

### `unsafe-config`

Allows reduced-size “small fast bench” config (not representative of real RandomX).

* Only used when you set `OXIDE_RANDOMX_FAST_BENCH_SMALL=1`.

### `superscalar-accel-proto` (parked experimental)

`superscalar-accel-proto` is compiled only when you build with `--features superscalar-accel-proto`.

Status policy:

* Experimental and currently parked for the supported parent path.
* Keep feature-gated; do not treat it as a default-on or production integration surface.
* The March 26, 2026 v9 disposition memo is the current policy authority.
  Light-mode upside remains real on clean Intel Linux and AMD Linux hosts, but
  AMD Windows remains mixed or rerun-sensitive, and Fast mode is still not
  promotive overall.
* Keep the scalar reference path and use `superscalar_hash_harness --impl scalar` for differential capture.
* Do not treat matrix-only "best config" rankings as policy authority for this
  branch.
* Any future promotion needs exact correctness, repeated-run stability on the
  measured hosts, material Light improvement on clean AMD and Intel authority
  hosts, no practical Fast regressions, and bounded disagreement between
  isolated and integrated behavior.

Current disposition/evidence artifacts:

* Primary decision memo: `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`
* Integrated feature-interaction memo: `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`
* AMD `23/113` host-unavailability memo: `perf_results/AMD/P2_amd_fam23_mod113_host_unavailability_2026-03-30.md`
* Clean AMD duplicate-family capture: `perf_results/AMD/v8_05_superscalar_prototype_amd_fam23_mod8_2026-03-11.md`
* Packaged AMD novel-family support capture: `perf_results/AMD/v8_05_capture_amd_fam23_mod113_20260312_170748/v8_05_summary_amd_fam23_mod113_20260312_170748.json`
* Clean Intel duplicate-family capture: `perf_results/Intel/v8_06_superscalar_prototype_intel_fam6_mod45_2026-03-11.md`
* Clean Intel novel-family capture: `perf_results/Intel/v8_06_superscalar_prototype_intel_fam6_mod58_2026-03-11.md`
* Historical AMD rerun: `perf_results/AMD/v7_07_superscalar_prototype_amd_fam23_mod8_2026-03-06.md`

### `threaded-interp` (parked experimental)

`threaded-interp` is compiled only when you build with `--features threaded-interp`, but is still
runtime-disabled by default.

Status policy:

* Experimental, currently parked (not production-recommended).
* Default runtime behavior is off.
* Runtime gate for investigation only: `OXIDE_RANDOMX_THREADED_INTERP=1`.
* The integrated `ff_*` sweep makes this a closed negative result on the current
  host set rather than an optional default candidate.

Current rationale/evidence artifacts:

* `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`
* Historical regression base: `perf_results/AMD/P0_2_regression_memo_2026-02-07.md`
* `perf_results/bench_apples_light_threaded_on_p0_2.csv`

### `simd-blockio` (experimental, CPU-conditional)

`simd-blockio` is compiled only when you build with `--features simd-blockio`.

Status policy:

* Experimental and opt-in (default runtime behavior remains off unless compiled with the feature).
* Treat enablement as host/workload-conditional, not universal.
* Validate with local A/B before enabling in production.
* The March 8, 2026 cross-host policy memo remains the current authority, and
  the March 11, 2026 current-`HEAD` baseline refresh did not promote
  `simd-blockio` into the supported parent path.
* The current integrated authority adds no Tier 1 evidence that promotes
  `simd-blockio` into the supported parent path, so matrix sweeps do not
  justify default-on policy.
* Intel Family 6 Model 45 is runtime-disabled by default when `simd-blockio` is compiled in.
* Clean duplicate-family confirmation on Intel Family 6 Model 45 does not justify classifier broadening beyond that current block.
* Clean duplicate-family confirmation on AMD Family 23 Model 8 does not justify AMD-wide enablement or classifier broadening.
* Local override for investigation only: `OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE=1`.
* Local scalar-baseline override for single-binary evidence capture: `OXIDE_RANDOMX_SIMD_BLOCKIO_DISABLE=1` (takes precedence over force).
* Remote novel-family capture packaging helpers:
  - Windows: `scripts/build/package_v7_10_amd_windows_capture.sh`
  - Debian/Linux: `scripts/build/package_v7_10_amd_linux_capture.sh`
* Windows cross-package prerequisite (when building from Linux):
  - add target: `rustup target add x86_64-pc-windows-gnu`
  - install MinGW linker (`x86_64-w64-mingw32-gcc`): `sudo apt-get install -y mingw-w64`
  - the package script fails fast with install guidance if the linker is missing
* Cross-family evidence now includes AMD `23/8`, AMD `23/113`, Intel `6/45`, and Intel `6/58`; outcomes differ by CPU family, workload, and mode.

Current disposition/evidence artifacts:

* Primary policy memo: `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`
* Current-`HEAD` baseline authority refresh: `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
* Integrated feature-interaction memo: `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`
* Clean Intel duplicate-family confirmation: `perf_results/Intel/v6_10_simd_blockio_intel_family_evidence_2026-03-01.md`
* Clean Intel machine summary: `perf_results/Intel/v6_10_simd_blockio_summary_intel_fam6_mod45_20260301_185552.json`
* Intel novel-family evidence: `perf_results/Intel/v7_09_simd_blockio_intel_novel_family_evidence_2026-03-06.md`
* Intel novel-family summary: `perf_results/Intel/v7_09_simd_blockio_summary_intel_fam6_mod58_20260306_191318.json`
* Clean AMD duplicate-family confirmation: `perf_results/AMD/v6_11_simd_blockio_amd_family_evidence_2026-03-01.md`
* Clean AMD machine summary: `perf_results/AMD/v6_11_simd_blockio_summary_amd_fam23_mod8_20260301_225916.json`
* AMD novel-family evidence: `perf_results/AMD/v7_10_capture_amd_fam23_results/v7_10_simd_blockio_amd_novel_family_evidence_2026-03-08.md`
* AMD novel-family summary: `perf_results/AMD/v7_10_capture_amd_fam23_results/v7_10_simd_blockio_summary_amd_fam23_mod113_20260308_144058.json`
* Historical Intel triage memo: `perf_results/Intel/P0_3_simd_blockio_intel_fast_triage_2026-02-17.md`
* Intel triage analysis artifact: `perf_results/Intel/v5_03_intel_simd_blockio_triage_analysis_20260217_201006.json`
* Cross-CPU disposition memo (historical policy base): `perf_results/Intel/P1_2_simd_blockio_cross_cpu_disposition_2026-02-16.md`
* Historical Ryzen-only supporting memo: `perf_results/unlabeled/P1_2_simd_blockio_disposition_2026-02-14.md`
* Historical Ryzen analysis artifact: `perf_results/AMD/v4_05_simd_blockio_analysis_20260214_181150.json`

### `simd-xor-paths` (experimental follow-up)

`simd-xor-paths` is compiled only when you build with `--features simd-xor-paths` (typically alongside
`simd-blockio`).

Status policy:

* Experimental and opt-in.
* Keep feature-gated; no default-on recommendation in this pass.
* Validate locally with A/B (`simd-blockio` baseline vs `simd-blockio + simd-xor-paths`) before using.
* The current integrated authority adds no Tier 1 promotion case for this
  branch, so there is still no supported default case.
* Direct `simd-xor-paths` A/B remains historical exploratory supporting
  evidence, not a current promotion memo.

Current disposition/evidence artifacts:

* `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`
* Historical exploratory base: `perf_results/AMD/P3_3_simd_xor_paths_disposition_2026-02-15.md`
* `perf_results/v4_11_bench_apples_light_20260215_105304.csv`
* `perf_results/v4_11_bench_apples_fast_20260215_111343.csv`
* `perf_results/v4_11_perf_light_simd_xor_a_20260215_112308.csv`
* `perf_results/v4_11_perf_fast_simd_xor_a_20260215_113639.csv`
* `perf_results/v4_11_simd_xor_analysis_20260215_114322.json`

### Supported-path disposition matrix (current policy authority)

| Feature family | Current status | Parent default state | Current authority |
| --- | --- | --- | --- |
| Interpreter | Supported reference / lowest-risk fallback | Fallback only | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` |
| Conservative JIT | Supported performance fallback | Fallback when fast-regs is unavailable or intentionally disabled | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` |
| Baseline `jit-fastregs` | Supported recommended throughput path | Recommended default on JIT-capable x86_64 parents | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` |
| Large pages / Linux 1GB request semantics | Supported control-plane behavior; verify realized backing | Explicit request, best-effort outcome | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`, `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`, `docs/perf.md` |
| Host-local prefetch calibration | Supported optional host-local override | Off by default; opt-in per host | `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`, `docs/oxideminer-integration-profile.md` |
| `threaded-interp` | Closed negative result; parked experimental | Off by default; runtime-gated for investigation only | `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`, `perf_results/AMD/P0_2_regression_memo_2026-02-07.md` (historical regression base) |
| `superscalar-accel-proto` | Parked experimental research lane | Off by default; feature-gated only | `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`, `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md` |
| `simd-blockio` | Experimental, CPU-conditional | Off by default | `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`, `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md` |
| `simd-xor-paths` | Experimental follow-up; exploratory direct A/B only | Off by default | `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`, `perf_results/AMD/P3_3_simd_xor_paths_disposition_2026-02-15.md` (historical exploratory base) |

Notes:

* `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
  remains the supported default-path authority.
* `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md` changes the current
  interpretation of experimental branches: none of them displaces baseline
  `jit-fastregs`, and matrix-only "best config" tables are supporting context,
  not policy authority.
* AMD `23/113` Windows remains supporting integrated evidence with rerun-stability
  caveats, not clean-equivalent authority.
* As of `2026-03-30`, the historical AMD `23/113` Windows host is unavailable,
  so this evidence remains bounded by an unresolved rerun gap rather than an
  active follow-up lane.
* Older, narrower memos are preserved as supporting context; policy authority is
  the primary memo listed above.
* Clean six-row baseline authority is tracked in `docs/perf-results-amd.md` and `docs/perf-results-intel.md`, not in experimental decision captures.

---

## Command reference (all supported flags)

The bench binary accepts:

```bash
Usage: bench [--mode light|fast] [--jit on|off|both] [--jit-fast-regs on|off]
            [--iters N] [--warmup N] [--threads N] [--report] [--format human|csv|json]
            [--validate] [--validate-iters N] [--validate-seed N]
```

### `--mode light|fast`

* `light` (default): cache-only mode (no full dataset allocation).
* `fast`: dataset-backed mode (requires `OXIDE_RANDOMX_FAST_BENCH=1`).

### `--jit on|off|both`

* `off`: interpreter only.
* `on`: request JIT only.
* `both` (default): run interpreter and JIT back-to-back and print two result lines/records.

Notes:

* If the library was not built with `--features jit`, requesting `on|both` will warn and may exit (depending on selection).
* Even with `--features jit`, JIT may not activate on unsupported platforms/arches. The bench tool will print:

  * “JIT requested but not active on this platform; using interpreter”

### `--jit-fast-regs on|off`

* `off` (default): do not request fast-reg mapping.
* `on`: request fast-reg mapping **only when JIT is active**.

Important:

* If you set `--jit-fast-regs on` but did not compile with `--features jit-fastregs`, the bench tool warns:

  * “jit-fast-regs requested but not compiled; rebuild with --features jit-fastregs”
* Fast-regs only applies when `--jit on|both` includes an actual JIT run.

### `--iters N`

Number of measured outer-loop iterations (default: `50`).
Total hashes = `iters * inputs`.

Use cases:

* Small smoke runs: `--iters 5`
* Stable measurements: `--iters 200` or more

### `--warmup N`

Number of warmup outer-loop iterations (default: `5`).

Use cases:

* **Cold JIT** measurement (include compilation effects in end-to-end run): `--warmup 0`
* **Steady-state throughput**: keep warmup ≥ 5 so compiles/cache warm before measurement

### `--threads N`

Only relevant for `--mode fast` dataset initialization.
Default: `available_parallelism()`.

### `--report`

Prints instrumentation details (requires `--features bench-instrument`).

### `--format human|csv|json`

Controls output format (default: `human`).

* `human`: one-line summary per run, plus optional report lines
* `csv`: header + records (machine-friendly)
* `json`: JSON array of objects (machine-friendly)

### Validation (`--validate`, `--validate-iters N`, `--validate-seed N`)

When `--validate` is set, the bench tool runs a deterministic workload and checks interpreter
results against any requested JIT runs, then exits without emitting benchmark timing output.

* `--validate-iters N`: repeat the validation loop (default: `3`).
* `--validate-seed N`: override the deterministic seed (default: `0x243f_6a88_85a3_08d3`).

Example:

```bash
cargo run --release --example bench --features "jit" -- --mode light --jit both --validate
```

---

## Environment variables

### `OXIDE_RANDOMX_FAST_BENCH=1` (required for `--mode fast`)

This is a safety gate. Without it, fast mode fails.

#### Windows (PowerShell)

```powershell
$env:OXIDE_RANDOMX_FAST_BENCH = "1"
cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --report
```

One-liner:

```powershell
$env:OXIDE_RANDOMX_FAST_BENCH = "1"; cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --report
```

Notes:

* `set OXIDE_RANDOMX_FAST_BENCH=1` is **cmd.exe** syntax and will not set a PowerShell env var.
* Clear it with: `Remove-Item Env:OXIDE_RANDOMX_FAST_BENCH`

#### Linux/macOS (bash)

```bash
export OXIDE_RANDOMX_FAST_BENCH=1
cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --report
```

One-liner:

```bash
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --report
```

### Prefetch tuning env controls (`RandomXFlags::from_env()`)

The following environment variables are parsed by `RandomXFlags::from_env()`:

* `OXIDE_RANDOMX_PREFETCH_DISTANCE` (`0..=8` cachelines)
* `OXIDE_RANDOMX_PREFETCH_AUTO` (enable CPU-family auto-tuned distance)
* `OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE` (`0..=32` cachelines)
* `OXIDE_RANDOMX_HUGE_1G` (sets `use_1gb_pages`)

Important scope note:

* The stock `bench` and `perf_harness` examples now apply these prefetch env variables to their effective runtime flags.
* Effective values are emitted in all output formats as:
  * `prefetch`
  * `prefetch_distance`
  * `prefetch_auto_tune`
  * `scratchpad_prefetch_distance`

Current policy snapshot (`2026-03-11`):

* Current cross-host authority is:
  * `perf_results/AMD/P0_4_clean_prefetch_refresh_amd_2026-02-28.md`
  * `perf_results/Intel/P0_4_clean_prefetch_refresh_intel_2026-02-28.md`
  * `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`
  * `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` (current-`HEAD`
    baseline refresh; no prefetch-policy change)
* The auto-tune mapping in `src/flags.rs` stays unchanged in this pass.
* That no-change decision is a stability default, not evidence that `auto` was locally optimal on the captured AMD or Intel hosts.
* If you care about one host, run a fixed-distance `0..8` sweep before overriding the default mapping.

Typical wiring for a custom harness:

```rust,no_run
use oxide_randomx::RandomXFlags;

fn build_flags(jit_on: bool, jit_fast_regs: bool, large_pages: bool) -> RandomXFlags {
    let mut flags = RandomXFlags::from_env();
    flags.large_pages_plumbing = large_pages;
    #[cfg(feature = "jit")]
    {
        flags.jit = jit_on;
        flags.jit_fast_regs = jit_fast_regs;
    }
    flags
}
```

Fixed-distance sweep recipe (for a binary that uses `from_env()`):

Replace `my_bench` below with your benchmark binary/example target.

Linux/macOS (bash):

```bash
for d in 0 1 2 3 4 5 6 7 8; do
  OXIDE_RANDOMX_PREFETCH_DISTANCE=$d cargo run --release --example my_bench -- --mode light --jit off
done
```

Windows (PowerShell):

```powershell
0..8 | ForEach-Object {
  $env:OXIDE_RANDOMX_PREFETCH_DISTANCE = "$_"
  cargo run --release --example my_bench -- --mode light --jit off
}
```

Auto-tune enablement recipe:

Linux/macOS (bash):

```bash
OXIDE_RANDOMX_PREFETCH_AUTO=1 cargo run --release --example my_bench -- --mode light --jit off
```

Windows (PowerShell):

```powershell
$env:OXIDE_RANDOMX_PREFETCH_AUTO = "1"
cargo run --release --example my_bench -- --mode light --jit off
```

### Host-local prefetch calibration helper (opt-in)

To avoid overfitting global defaults from sparse host evidence, this repo includes
an explicit host-local calibration helper:

```bash
cargo run --release --example prefetch_calibrate -- \
  --mode light --jit off --rounds 3 --warmup 2 --iters 20 \
  --distances 0,1,2,3,4,5,6,7,8 \
  --persist perf_results/local/prefetch_calibration.csv \
  --format human
```

Structured output examples:

```bash
cargo run --release --example prefetch_calibrate -- --mode light --jit off --format json
cargo run --release --example prefetch_calibrate -- --mode light --jit off --format csv --out out.csv
```

Apply a persisted calibration through the library-facing runtime workflow:

```bash
cargo run --release --example prefetch_apply -- \
  --calibration perf_results/local/prefetch_calibration.csv \
  --mode light --jit off
```

Design notes:

* Default runtime behavior is unchanged; this tool is opt-in and does not modify
  `CpuFamily::optimal_prefetch_distance()`.
* Calibration is mode-aware (`--mode light|fast`) and scenario-aware (`jit`, `jit-fast-regs`,
  scratchpad prefetch distance, workload id).
* Persisted rows are traceable and invalidation-friendly via:
  * schema version
  * crate version
  * git SHA / dirty marker
  * rustc version
  * CPU identity bucket (vendor/family/model/stepping + family bucket)
* Startup cost tradeoff: calibration executes repeated runs over multiple distances,
  so it is intentionally bounded (`rounds * distance_count`) and should be run
  deliberately, not on every startup.
* Reproducibility tradeoff: this helper uses deterministic workload and deterministic
  per-round distance ordering, but still measures live host noise; use multiple rounds
  and retain full output artifacts.
* Prototype memo: `docs/prefetch-calibration-prototype-v7-08.md`.

Parent-consumable apply path:

* Persistence format remains a CSV with one row per strict `(code, cpu, scenario)` key.
  Multiple host/config rows can coexist in one file.
* Current host/build matching is explicit via
  `prefetch_calibration::PrefetchCalibrationQuery::for_current_host(...)`.
* Runtime application is explicit via
  `prefetch_calibration::apply_prefetch_calibration_for_current_host(...)`.
* A matched row updates only the dataset prefetch settings:
  * `flags.prefetch`
  * `flags.prefetch_distance`
  * `flags.prefetch_auto_tune = false`
* Missing file fallback is safe: the helper returns `NoCalibrationFile` and leaves
  the caller's flags unchanged.
* Mismatched or stale calibration fallback is safe: the helper returns
  `NoMatchingCalibration` and leaves the caller's flags unchanged.
* Malformed calibration files are surfaced as `Err(...)` so the parent can log and
  continue with its normal default or env-selected flags.

Minimal parent-side usage:

```rust
use std::path::Path;

use oxide_randomx::prefetch_calibration::{
    apply_prefetch_calibration_for_current_host, PrefetchCalibrationApplyStatus,
    PrefetchCalibrationMode, PREFETCH_CALIBRATION_WORKLOAD_ID,
};
use oxide_randomx::RandomXFlags;

let mut flags = RandomXFlags::from_env();
let outcome = apply_prefetch_calibration_for_current_host(
    Path::new("perf_results/local/prefetch_calibration.csv"),
    PrefetchCalibrationMode::Light,
    &mut flags,
    PREFETCH_CALIBRATION_WORKLOAD_ID,
)?;

match outcome.status {
    PrefetchCalibrationApplyStatus::Applied => {
        // flags now carry the persisted host-local prefetch distance
    }
    PrefetchCalibrationApplyStatus::NoCalibrationFile
    | PrefetchCalibrationApplyStatus::NoMatchingCalibration => {
        // flags remain unchanged
    }
}
```

Interpreter/JIT parity notes for fair A/B:

* Keep prefetch env settings identical between interpreter and JIT runs.
* Change only `--jit off` vs `--jit on` when comparing execution engines.
* Do not compare an auto-tuned run against a fixed-distance run unless that is the explicit experiment.
* Record prefetch env values alongside `ns_per_hash` in your benchmark notes.

### `OXIDE_RANDOMX_FAST_BENCH_SMALL=1` (optional, requires `unsafe-config`)

Enables a reduced dataset/cache configuration for fast-mode smoke testing:

* Requires:

  * `OXIDE_RANDOMX_FAST_BENCH=1`
  * `OXIDE_RANDOMX_FAST_BENCH_SMALL=1`
  * `--features unsafe-config`

Example (Linux/macOS):

```bash
OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_FAST_BENCH_SMALL=1 \
cargo run --release --example bench --features "jit bench-instrument unsafe-config" -- \
  --mode fast --jit both --report
```

Example (PowerShell):

```powershell
$env:OXIDE_RANDOMX_FAST_BENCH = "1"
$env:OXIDE_RANDOMX_FAST_BENCH_SMALL = "1"
cargo run --release --example bench --features "jit bench-instrument unsafe-config" -- --mode fast --jit both --report
```

Warning:

* “Small fast bench” is **not representative** of real RandomX performance. It is included for reasons known only to @raystanza

---

## 1GB Huge-Page Request (Linux only, opt-in)

The library supports a 1GB huge-page request path for dataset and scratchpad
allocations on Linux.
It is an explicit opt-in request semantic, and allocation outcome remains
best-effort with fallback to non-1GB pages.

### Platform support

| Platform | 2MB Large Pages                    | 1GB Huge Pages                               |
| --- | --- | --- |
| Linux | ✓ (`MAP_HUGETLB`) | ✓ (opt-in request, kernel + privilege dependent) |
| Windows | ✓ (`VirtualAlloc` + `MEM_LARGE_PAGES`) | ✗ (not exposed to user mode) |

### Enablement (`perf_harness`)

Use both the environment request and large-pages runtime flag:

```bash
OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_HUGE_1G=1 cargo run --release --example perf_harness --features "bench-instrument" -- \
  --mode fast --jit off --iters 50 --warmup 5 --large-pages on --format csv --out perf_results/v5_fast_1gb_<host>_<ts>.csv
```

### Verification (use emitted outcome fields, not request flags)

Read these emitted fields from CSV/JSON/human output:

- `large_pages_1gb_requested`
- `large_pages_1gb_dataset`
- `large_pages_1gb_scratchpad`
- `large_pages_dataset`
- `large_pages_scratchpad`

Interpretation:

- `large_pages_1gb_requested=true` and `large_pages_1gb_dataset=true`: dataset 1GB success.
- `large_pages_1gb_requested=true` and `large_pages_1gb_dataset=false` on a Linux host with 1GB huge-page support: dataset fallback (often to 2MB).
- `large_pages_1gb_requested=true` and `large_pages_1gb_dataset=false` on a non-Linux host: unsupported-platform non-1GB outcome; if `large_pages_dataset=true`, the dataset still used ordinary large pages (for example Windows `VirtualAlloc` large pages).
- `large_pages_dataset=false`: dataset did not get huge pages.
- `large_pages_1gb_scratchpad` is independent from dataset and must be checked separately.

### Linux prerequisites

1. Kernel boot params include 1GB hugepage support (for example `hugepagesz=1G`).
2. Sufficient reserved/free 1GB pages (RandomX fast dataset needs at least 3 pages).
3. Privileges to modify `/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages` for runtime allocation.
4. Low enough memory fragmentation for runtime allocation path.

Quick checks:

```bash
cat /proc/cmdline
cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages
```

### Fallback behavior

If 1GB is requested but unavailable, allocator behavior is:

1. Emit a warning/info message on stderr.
2. Fall back to default huge pages (typically 2MB).
3. If large-page allocation fails, fall back to normal pages (`madvise(MADV_HUGEPAGE)` best-effort).

### Current reproducible evidence snapshot

Latest host-tagged evidence bundle:

- `perf_results/Intel/P3_5_1gb_hugepage_success_fallback_intel_2026-02-23.md`
- `perf_results/Intel/v5_08_1gb_provenance_intel_20260223_010837.txt`
- `perf_results/Intel/v5_08_1gb_pressure_status_intel_20260223_010837.txt`

Observed on that host:

- Success captured with `large_pages_1gb_requested=true` and `large_pages_1gb_dataset=true`.
- Fallback captured with `large_pages_1gb_requested=true` and `large_pages_1gb_dataset=false` under reproducible 1GB-page pressure.

Additional host-tagged limitation evidence:

- `perf_results/AMD/v6_04_P3_5_1gb_hugepage_host_limitation_amd_2026-03-01.md`
- `perf_results/AMD/v6_04_1gb_host_provenance_amd_windows_20260301_005544.txt`

Observed on that AMD Windows host:

- `large_pages_1gb_requested=true` was captured, but both `large_pages_1gb_dataset=false` and `large_pages_1gb_scratchpad=false`.
- `large_pages_dataset=true` and `large_pages_scratchpad=true` showed ordinary large pages still succeeded.
- Because that host is Windows, this is unsupported-platform evidence, not Linux pressure-fallback evidence.

### API usage (library consumers)

The `HugePageSize` enum and `LargePageRequest::enabled_with_size()` let consumers request 1GB pages:

```rust
use oxide_randomx::util::{HugePageSize, LargePageRequest};

let request = LargePageRequest::enabled_with_size("dataset", HugePageSize::OneGigabyte);
if let Some(size) = buf.huge_page_size() {
    println!("Using {} byte huge pages", size);
}
```

Treat `buf.huge_page_size()` (and harness-emitted fields) as allocation truth, not the request knob.

---

## Output formats and fields

### Human output (default)

Per run:

```bash
mode=Light jit=true fast_regs=false hashes=300 ns/hash=123456 prefetch=true prefetch_distance=2 prefetch_auto_tune=false scratchpad_prefetch_distance=0
```

Prefetch runtime fields (effective values):

* `prefetch`: dataset prefetch enable flag actually used by the VM.
* `prefetch_distance`: dataset prefetch distance in cachelines (`0..=8`).
* `prefetch_auto_tune`: whether CPU-family auto-tune was enabled.
* `scratchpad_prefetch_distance`: scratchpad prefetch distance in cachelines (`0..=32`).

Large-page runtime fields (effective outcomes):

* `large_pages_requested`: runtime large-page request for this run.
* `large_pages_1gb_requested`: 1GB request knob from env/runtime options.
* `large_pages_dataset`: whether dataset allocation used any huge pages.
* `large_pages_1gb_dataset`: whether dataset actually used 1GB pages.
* `large_pages_scratchpad`: whether scratchpad allocation used any huge pages.
* `large_pages_1gb_scratchpad`: whether scratchpad actually used 1GB pages.

If `--report` is enabled (and compiled with `bench-instrument`), additional lines print:

* Provenance (single key=value line):

  * `provenance` includes git SHA + dirty flag, enabled features, CPU model + cores, rustc version, and runtime flags.

* JIT status + cache statistics:

  * `jit_active`
  * `jit_compiles`
  * `jit_cache_hits`
  * `jit_cache_misses`
  * `jit_cache_evictions`

* Timings:

  * `jit_compile_ns` (total compilation time across program compiles; includes warmup compiles)
  * `vm_exec_ns_interpreter` and `vm_exec_ns_jit` (instrumented VM execution time)

* Instruction mix counters:

  * `instr_int`, `instr_float`, `instr_mem`, `instr_ctrl`, `instr_store`
  * `instr_counts_source` (either `interp_exact` or `jit_derived_static_mix`)

Additional bench-instrument counters now include:

* Stage timers: `program_gen_ns`, `prepare_iteration_ns`, `finish_iteration_ns`
* Finish-path substage timers:
  * `finish_addr_select_ns`
  * `finish_prefetch_ns`
  * `finish_dataset_item_load_ns`
  * `finish_light_cache_item_ns`
  * `finish_r_xor_ns`
  * `finish_store_int_ns`
  * `finish_f_xor_e_ns`
  * `finish_store_fp_ns`
* Fast-regs stage timers: `jit_fastregs_prepare_ns`, `jit_fastregs_finish_ns`
* Scratchpad totals: `scratchpad_read_bytes`, `scratchpad_write_bytes`
* Dataset accesses: `dataset_item_loads`
* Mem levels: `mem_read_l1/l2/l3`, `mem_write_l1/l2/l3`
* Program execution count: `program_execs`
* Fast-regs light-mode cache helper observability:
  * `jit_fastregs_light_cache_item_helper_calls`
  * `jit_fastregs_light_cache_item_helper_ns`

Interpretation notes for JIT mode:

* Conservative JIT and interpreter runs keep fast-regs-specific fields at `0`.
* Fast-regs runs now populate `prepare_iteration_ns` and `finish_iteration_ns` (no longer hard-zero blind spots).
* `jit_fastregs_prepare_ns` and `jit_fastregs_finish_ns` isolate the inlined fast-regs stage portions specifically.
* In light mode, `jit_fastregs_light_cache_item_helper_*` attributes the helper-boundary cache-item fallback path.
* `finish_iteration_ns` remains the aggregate finish timer; `finish_*` substage fields decompose the non-fastregs `finish_iteration(...)` path (interpreter + conservative JIT helper path).

The `perf_harness` example prints these unconditionally in human/JSON/CSV output.

If you compile without `bench-instrument`, `--report` prints:

```bash
report=disabled (compile with --features bench-instrument)
```

### CSV output

Header (includes large page + affinity fields like `large_pages_requested`, `large_pages_dataset`,
`large_pages_scratchpad`, `thread_names`, and `affinity`):

```csv
git_sha,git_sha_short,git_dirty,features,cpu,cores,rustc,mode,iters,warmup,threads,inputs,jit_requested,jit_fast_regs,jit_active,large_pages_requested,large_pages_1gb_requested,large_pages_dataset,large_pages_1gb_dataset,large_pages_scratchpad,large_pages_1gb_scratchpad,thread_names,affinity,hashes,elapsed_ns,ns_per_hash,hashes_per_sec,cache_init_ns,dataset_init_ns,program_gen_ns,prepare_iteration_ns,execute_program_ns_interpreter,execute_program_ns_jit,finish_iteration_ns,program_execs,scratchpad_read_bytes,scratchpad_write_bytes,dataset_item_loads,mem_read_l1,mem_read_l2,mem_read_l3,mem_write_l1,mem_write_l2,mem_write_l3,instr_int,instr_float,instr_mem,instr_ctrl,instr_store,jit_get_or_compile_calls,jit_exec_calls,jit_program_execs,jit_helper_calls_float,jit_helper_calls_cbranch,jit_fastregs_spill_count,jit_fastregs_reload_count,jit_fastregs_sync_to_ctx_count,jit_fastregs_sync_from_ctx_count,jit_fastregs_call_boundary_count,jit_fastregs_call_boundary_float_nomem,jit_fastregs_call_boundary_float_mem,jit_fastregs_call_boundary_prepare_finish,jit_fastregs_preserve_spill_count,jit_fastregs_preserve_reload_count,jit_compiles_total,jit_cache_hits_total,jit_cache_misses_total,jit_cache_evictions_total,jit_compile_ns_total,jit_compiles_measured,jit_cache_hits_measured,jit_cache_misses_measured,jit_cache_evictions_measured,jit_compile_ns_measured,instrumented,prefetch,prefetch_distance,prefetch_auto_tune,scratchpad_prefetch_distance,jit_fastregs_prepare_ns,jit_fastregs_finish_ns,jit_fastregs_light_cache_item_helper_calls,jit_fastregs_light_cache_item_helper_ns,finish_addr_select_ns,finish_prefetch_ns,finish_dataset_item_load_ns,finish_light_cache_item_ns,finish_r_xor_ns,finish_store_int_ns,finish_f_xor_e_ns,finish_store_fp_ns
```

`bench` CSV appends the same finish-decomposition columns at the end of each row.

### JSON output

A JSON array of objects with the same fields as CSV:

```json
[
  {"mode":"Light","jit":false,"jit_fast_regs":false,"jit_active":false,
   "iters":50,"inputs":6,"hashes":300,"elapsed_ns":123456789,"ns_per_hash":411522,
   "jit_compiles":0,"jit_cache_hits":0,"jit_cache_misses":0,"jit_cache_evictions":0,
   "jit_compile_ns":0,"vm_exec_ns_interpreter":0,"vm_exec_ns_jit":0,
   "instr_int":0,"instr_float":0,"instr_mem":0,"instr_ctrl":0,"instr_store":0,
   "prefetch":true,"prefetch_distance":2,"prefetch_auto_tune":false,"scratchpad_prefetch_distance":0}
]
```

For `perf_harness` JSON, these fields are emitted under `.params`.

---

## Turning output into metrics (how to derive what we care about)

### 1) Throughput (hashes/second)

The tool reports `ns_per_hash`.

Compute:

* `hashes_per_sec = 1e9 / ns_per_hash`

Examples:

* If `ns_per_hash = 250_000`, throughput ≈ `4,000 hashes/sec`.
* If `ns_per_hash = 100_000`, throughput ≈ `10,000 hashes/sec`.

### 2) Speedup (JIT vs interpreter)

Run `--jit both` and compute:

* `speedup = ns_per_hash(interpreter) / ns_per_hash(jit)`

Example:

* interpreter `400_000 ns/hash`, JIT `200_000 ns/hash` → speedup = `2.0x`.

### 3) Cold vs warm JIT behavior

To measure “cold” behavior (JIT compilation impacts the end-to-end run):

* Use `--warmup 0`
* Use `--report` to capture `jit_compile_ns` and compile counts

To measure steady-state throughput:

* Use `--warmup 5` or higher
* Increase `--iters` so measurement dominates noise

### 4) JIT cache efficiency

From `--report` (or CSV/JSON):

* `jit_compiles`: number of program compiles performed
* `jit_cache_hits/misses`: effectiveness of program cache reuse
* `jit_cache_evictions`: whether cache capacity is being exceeded

Derived indicators:

* **Hit rate**: `hits / (hits + misses)` (when denominator > 0)
* If evictions are non-zero during a steady workload, we are likely thrashing the cache.

### 5) Compile overhead contribution

Use:

* `jit_compile_ns` and compare against measured `elapsed_ns`.

Derived:

* `compile_overhead_ratio = jit_compile_ns / elapsed_ns`

Interpretation:

* If warmup > 0, compile time may mostly occur during warmup but is still reported (good for understanding “first run” cost).
* If you want compile time to occur within the measured loop, set `--warmup 0`.

### 6) VM execution time counters (instrumented)

When `bench-instrument` is enabled, we also get:

* `vm_exec_ns_interpreter`
* `vm_exec_ns_jit`

These can be used to validate whether overhead is in VM execution vs surrounding harness, and to compare internal timing with wall-clock timing.

### 7) Instruction mix and hotspots

Counters:

* `instr_int`, `instr_float`, `instr_mem`, `instr_ctrl`, `instr_store`

Use cases:

* Validate that a workload triggers expected instruction distributions.
* Correlate instruction-heavy categories with performance regressions.
* Guide micro-optimizations (i.e. if `instr_mem` dominates, address calculation and masking may be the bottleneck).

---

## Benchmark recipes (copy/paste)

### Minimal smoke test (fast feedback)

```bash
cargo run --release --example bench --features "jit" -- --mode light --jit both --iters 5 --warmup 1
```

### Stable measurement (light mode, steady state)

```bash
cargo run --release --example bench --features "jit bench-instrument" -- \
  --mode light --jit both --iters 200 --warmup 10 --report --format human
```

### Machine-readable output for scripts/CI parsing

CSV:

```bash
cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit both --report --format csv
```

JSON:

```bash
cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit both --report --format json
```

### JIT fast-reg mapping comparison (conservative vs fast-regs)

Conservative JIT:

```bash
cargo run --release --example bench --features "jit bench-instrument" -- \
  --mode light --jit on --jit-fast-regs off --iters 200 --warmup 10 --report
```

Fast-reg JIT:

```bash
cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 200 --warmup 10 --report
```

### Fast mode (dataset), interpreter vs JIT

Linux/macOS:

```bash
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example bench --features "jit bench-instrument" -- \
  --mode fast --jit both --iters 50 --warmup 5 --threads 8 --report
```

PowerShell:

```powershell
$env:OXIDE_RANDOMX_FAST_BENCH = "1"
cargo run --release --example bench --features "jit bench-instrument" -- --mode fast --jit both --threads 8 --report
```

### Small fast bench smoke run (unsafe, non-representative)

Linux/macOS:

```bash
OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_FAST_BENCH_SMALL=1 \
cargo run --release --example bench --features "jit bench-instrument unsafe-config" -- --mode fast --jit both --iters 50 --warmup 5 --report
```

---

## Profiling workflow (how to find where time goes)

Benchmarks tell us *“what”*; profiling tells us *“why”*.

### Build a release bench binary with symbols

```bash
cargo build --release --example bench --features "jit bench-instrument"
```

On Windows, the output binary is:

```powershell
target\release\examples\bench.exe
```

### Windows: WPR/WPA (recommended for system-level CPU sampling)

1. Start a CPU trace:

    ```powershell
    wpr -start CPU
    ```

2. Run the bench (keep it simple and repeatable):

    ```powershell
    target\release\examples\bench.exe --mode light --jit on --iters 200 --warmup 10 --report
    ```

3. Stop the trace:

    ```powershell
    wpr -stop randomx.etl
    ```

4. Open `randomx.etl` in Windows Performance Analyzer (WPA) and:

    * Focus on CPU Usage (Sampled).
    * Filter to functions in `oxide_randomx`.
    * Compare interpreter vs JIT runs if needed.

### Windows: Visual Studio Profiler (good for function-level hotspots)

* Open the repo in Visual Studio, or attach the profiler to `bench.exe`.
* Use CPU Usage profiling.
* Run with the same stable command line as above.

### Linux: `perf`

```bash
perf record -g target/release/examples/bench --mode light --jit on --iters 200 --warmup 10
perf report
```

### Linux/macOS: `cargo flamegraph` (optional convenience)

If it's installed:

```bash
cargo flamegraph --example bench --features "jit bench-instrument" -- --mode light --jit on --iters 200 --warmup 10
```

---

## Reproducibility tips (optional but helpful)

If you need more stable numbers:

* Prefer `--release`.
* Increase `--iters` until results stabilize.
* Close background CPU-heavy apps.
* Ensure consistent power mode (e.g., “Best performance” on laptops).
* Run multiple times and compare medians, not single samples.
* Use a spreadsheet, they don't bite.

---

## Common pitfalls

* **PowerShell env vars:** use `$env:NAME="1"`, not `set NAME=1`.
* **JIT requested but not active:** means arch/platform unsupported or JIT feature not compiled.
* **Fast mode fails:** you forgot `OXIDE_RANDOMX_FAST_BENCH=1`.
* **`--report` shows disabled:** you forgot `--features bench-instrument`.

---

## Perf smoke test (CI-friendly)

The perf smoke test is opt-in and intentionally loose. It validates that key
counters are non-zero and that throughput is not catastrophically slow.

Linux/macOS:

```bash
OXIDE_RANDOMX_PERF_SMOKE=1 cargo test --features bench-instrument --test perf_smoke
```

PowerShell:

```powershell
$env:OXIDE_RANDOMX_PERF_SMOKE = "1"
cargo test --features bench-instrument --test perf_smoke
```

Notes:

* This test runs only when `OXIDE_RANDOMX_PERF_SMOKE=1` is set.
* It uses light mode and should complete in a few seconds.

---

## Perf regression guard tool

Use `perf_compare` to compare baseline vs candidate CSV results and fail on regressions above a threshold.

Default threshold is `2.0%` and the primary metric is `ns_per_hash` (lower is better).

Build/run:

```bash
cargo run --release --bin perf_compare -- \
  --baseline perf_results/baseline.csv \
  --candidate perf_results/candidate.csv \
  --threshold-pct 2.0
```

PowerShell:

```powershell
cargo run --release --bin perf_compare -- --baseline perf_results\baseline.csv --candidate perf_results\candidate.csv --threshold-pct 2.0
```

Behavior:

* Exit code `0`: candidate improved or regression is within threshold.
* Exit code `1`: regression exceeds threshold.
* Exit code `2`: input/parse/tooling error (missing file, unreadable/empty CSV, missing column, invalid numeric data).

Example with current baseline artifacts:

```bash
cargo run --release --bin perf_compare -- \
  --baseline perf_results/v4_baseline_light_jit_conservative_20260210_152108.csv \
  --candidate perf_results/v4_baseline_light_jit_fastregs_20260210_152108.csv \
  --threshold-pct 2.0
```

`perf_compare` now underpins the required Ubuntu perf gate, and it is still useful for local pre-PR comparisons.

### Required CI perf gate

The `oxide-randomx CI` workflow runs
`bash crates/oxide-randomx/scripts/ci/run_ci_perf_gate.sh` on `ubuntu-latest`
for a small, explicit supported-path manifest at
`crates/oxide-randomx/perf_baselines/ci/manifest.txt`.
Workflow enforcement host and fixture provenance are tracked separately; see `perf_baselines/ci/README.md` for the currently blessed capture source.

Current gated scenarios:

* `light_interp`: `--mode light --jit off --iters 10 --warmup 2`
* `light_jit_conservative`: `--mode light --jit on --jit-fast-regs off --iters 10 --warmup 2`
* `fast_jit_fastregs`: `OXIDE_RANDOMX_FAST_BENCH=1 --mode fast --jit on --jit-fast-regs on --iters 10 --warmup 2`

Why this scope:

* The manifest follows the current parent-facing supported path, not every experimental branch.
* The Light rows protect the supported fallback ladder.
* The Fast `jit-fastregs` row protects the default throughput path OxideMiner is expected to use.
* Light `jit-fastregs` is protected by the separate validation-build
  `oxideminer_integration` smoke and by `cargo test -p oxide-randomx --features "jit jit-fastregs"`, which keeps the perf gate small enough that thresholds remain meaningful.
* `scripts/ci/run_ci_perf_gate.sh` enables `OXIDE_RANDOMX_FAST_BENCH=1` automatically for manifest rows whose mode is `fast`, so local reproduction stays one-command.
* The v10 CI refresh did not require a fixture-content replacement because the
  mandatory scenario set is unchanged apart from relabeling the conservative
  JIT row to `light_jit_conservative`.

Gate policy:

* Build features are fixed to `jit jit-fastregs bench-instrument`.
* `ns_per_hash` is the only enforced regression metric.
* Each candidate scenario is captured twice in CI and compared against a checked-in three-row baseline fixture.
* Thresholds are versioned in `perf_baselines/ci/manifest.txt`.
  * `light_interp`: `15.0%`
  * `light_jit_conservative`: `15.0%`
  * `fast_jit_fastregs`: `20.0%`
  * The March 14, 2026 supported-path refresh kept the Light rows at `15.0%`, but widened the Fast row to `20.0%` after the same-`HEAD` local gate rerun on Intel `6/58` drifted by `+17.164%`.
* The job uploads `baseline/*.csv`, `candidate/*.csv`, `compare/*.txt`, and the manifest on both success and failure.
* Fast-mode CI coverage uses the full Fast configuration, not `unsafe-config` or `OXIDE_RANDOMX_FAST_BENCH_SMALL=1`.
* Workflow failure semantics stay explicit:
  * exit `1`: real regression above threshold
  * exit `2`: tool/input failure (missing fixture, unreadable CSV, parse error, invalid data)

Important scope note:

* These CI-host fixtures are narrow guardrails only.
* They do **not** replace `docs/perf-results-amd.md` or `docs/perf-results-intel.md` as host-authority documents.

Adjacent non-perf validation:

* The same GitHub-hosted workflow also runs a lightweight validation-build
  `examples/oxideminer_integration.rs` Light-mode smoke on `ubuntu-latest`.
* That step validates the supported `jit-fastregs` validation build,
  parent-facing lifecycle, and report shape.
* It is not part of the perf-threshold decision, and it does not turn
  GitHub-hosted runners into host-authority evidence or replace broader
  OxideMiner parent validation.

Local reproduction of the mandatory gate:

```bash
bash crates/oxide-randomx/scripts/ci/run_ci_perf_gate.sh
```

This writes combined candidate CSVs, copied baseline fixtures, and compare logs under `artifacts/perf-gate/`.
When the script is invoked from `bash` on Windows, it resolves the built `.exe`
tool paths automatically before running the gate.

Fixture refresh flow:

1. Prefer running the `oxide-randomx CI` workflow with `workflow_dispatch` on the commit you want to bless.
2. Download `oxide-randomx-perf-gate-artifacts` and inspect the relevant `compare/*.txt` plus `candidate/*.csv` files.
3. If the change is intentional and the candidate output is stable, replace the matching baseline CSV under `perf_baselines/ci/` and update `perf_baselines/ci/README.md` with the new provenance in the same PR.
4. If you intentionally bless a local refresh instead, record the host/toolchain provenance explicitly and explain why that local capture is acceptable for the CI guardrail.

---

## Appendix: Recommended "standard run" for PRs

If we want a consistent performance check before/after changes:

```bash
cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 200 --warmup 10 --report --format csv
```

Save the CSV output (before/after) and compare:

* `ns_per_hash` (primary)
* `jit_cache_hits/misses` and `jit_compiles` (cache behavior)
* `jit_compile_ns` (compile overhead)
* `vm_exec_ns_*` (internal timing)
* instruction counters (mix changes)
