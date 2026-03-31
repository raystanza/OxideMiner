# Performance Guide

This guide covers the public, repo-local performance workflow for
`oxide-randomx`.

## Local Artifact Policy

- write local measurements under `crates/oxide-randomx/perf_results/`
- that directory is intentionally ignored by git
- when a measurement changes project policy, update the relevant docs in the
  same patch instead of committing raw capture trees

## Supported-Path Quick Start

Structured supported-path measurement:

```bash
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --format human
```

Reference integration smoke:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- \
  --mode both --runtime-profile jit-fastregs --format json
```

## Local Bench Tools

Bench comparison:

```bash
cargo run --release --example bench --features "jit bench-instrument" -- --mode light --jit both
```

Structured JSON or CSV output:

```bash
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --format json --out perf_results/local/light.json
```

Fast mode is opt-in because it allocates the full dataset:

```bash
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
  --mode fast --jit on --jit-fast-regs on --iters 10 --warmup 2 --format human
```

## Full-Features Workflow

Use the generic full-features tools for local exploratory work:

```bash
cargo run --release --bin full_features_benchmark --features "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto"
cargo run --release --bin full_features_authority -- validate-index --index crates/oxide-randomx/perf_results/full_features_authority_index.json
```

The public repo does not hardcode a committed host inventory. If you promote a
local finding into project policy, document the reasoning in `docs/` and keep
the raw capture trees local.

## Public Capture Runner

For outside-host data collection, use the generic public capture runner:

```bash
cargo run --release --bin oxide-randomx-public-capture -- --accept-data-contract
```

Packaging helpers:

- `scripts/build/package_oxide_randomx_public_capture.sh`
- `scripts/build/package_oxide_randomx_public_capture.ps1`

## Prefetch Calibration

Persist a host-local calibration:

```bash
cargo run --release --example prefetch_calibrate --features "jit jit-fastregs bench-instrument" -- \
  --persist perf_results/local/prefetch_calibration.csv
```

Apply it through the parent-shaped harness:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- \
  --mode both --runtime-profile jit-fastregs --calibration perf_results/local/prefetch_calibration.csv
```

## Compare Two CSV Runs

```bash
cargo run --release --bin perf_compare -- \
  --baseline perf_results/baseline.csv \
  --candidate perf_results/candidate.csv \
  --threshold-pct 2.0
```
