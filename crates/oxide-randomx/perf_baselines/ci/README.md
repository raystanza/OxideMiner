# CI Perf Gate Fixtures

This directory is the checked-in fixture set for the mandatory CI perf gate. It is intentionally narrow:

- Enforcement host: `ubuntu-latest`
- Fixture provenance: GitHub-hosted or explicitly documented local capture
- Scope policy: the parent-facing supported path only
- Scenario scope:
  - `light_interp`
  - `light_jit_conservative`
  - `fast_jit_fastregs`
- Primary metric: `ns_per_hash`
- Threshold source: `crates/oxide-randomx/perf_baselines/ci/manifest.txt`
- Manifest fixture paths are workspace-root relative because the mandatory gate
  runs from the `OxideMiner` repo root.

These fixtures are CI guardrails, not host-performance authority. Canonical host baselines still live in:

- `docs/perf-results-amd.md`
- `docs/perf-results-intel.md`

Adjacent supported-path validation:

- The same GitHub-hosted workflow also runs a lightweight
  `examples/oxideminer_integration.rs` Light-mode smoke with the validation
  build on `ubuntu-latest`.
- That step validates the supported `jit-fastregs` validation build, parent-facing
  lifecycle wiring, and emitted report shape.
- It is not part of the perf-threshold decision, and it does not replace
  host-authority benchmarking or broader OxideMiner parent validation.
- `light_jit_fastregs` stays mandatory in CI through that smoke plus
  `cargo test -p oxide-randomx --features "jit jit-fastregs"`, rather than by
  enlarging the perf-threshold manifest.

Why these three rows:

- `light_interp` keeps the lowest-risk supported fallback under regression watch.
- `light_jit_conservative` keeps the conservative JIT fallback under regression watch.
- `fast_jit_fastregs` covers the default throughput path the parent project is expected to use.
- Experimental branches stay out of this manifest so CI noise does not destabilize the supported path.

The exact runtime flags for each gated scenario are encoded in `crates/oxide-randomx/perf_baselines/ci/manifest.txt`.

Fast-mode note:

- The gate uses the full Fast configuration, not `unsafe-config` or `OXIDE_RANDOMX_FAST_BENCH_SMALL=1`.
- `scripts/ci/run_ci_perf_gate.sh` enables `OXIDE_RANDOMX_FAST_BENCH=1` automatically for manifest rows whose mode is `fast`.

## Current fixture provenance

These fixtures were refreshed on current `HEAD`; capture details are recorded here and must be updated in the same PR as any baseline replacement:

- capture date: `2026-03-14`
- commit: `e40d822dc47aba337cf91cc64ab98530c48ac4df` (`e40d822`)
- host: `Intel(R) Core(TM) i5-3360M CPU @ 2.80GHz` (`4` logical cores, Intel family `6` model `58`)
- Rust: `rustc 1.93.0 (254b59607 2026-01-19)`
- git state: `git_dirty=true` because the current PR's CI/docs refresh files were already modified locally when the perf rows were captured; the perf harness code path itself still matched `HEAD` commit `e40d822`
- features: `jit jit-fastregs bench-instrument`
- repeats per baseline fixture: `3`
- capture method: each scenario was rerun sequentially in isolation before the fixture CSVs were assembled, so the checked-in rows are not distorted by cross-scenario CPU contention
- thresholds after the refresh:
  - `light_interp`: `15.0%`
  - `light_jit_conservative`: `15.0%`
  - `fast_jit_fastregs`: `20.0%`
  - rationale: the same-`HEAD` local gate rerun on this Intel `6/58` host landed at `+2.057%` for `light_interp`, `+4.588%` for `light_jit_conservative`, and `+17.164%` for `fast_jit_fastregs`, so only the Fast supported-path row needed extra headroom
- command shape:
  - Light rows: `<workspace-target>/release/examples/perf_harness --mode light --iters 10 --warmup 2 --format csv`
  - Fast row: `OXIDE_RANDOMX_FAST_BENCH=1 <workspace-target>/release/examples/perf_harness --mode fast --jit on --jit-fast-regs on --iters 10 --warmup 2 --format csv`
- v10 alignment note:
  - no fixture-content replacement was required for this CI refresh
  - the conservative JIT row was relabeled from `light_jit` to
    `light_jit_conservative` so the manifest matches the supported runtime-profile
    language
  - the mandatory perf contract remains `light_interp`,
    `light_jit_conservative`, and `fast_jit_fastregs`

## Refresh flow

1. Prefer running the `oxide-randomx CI` workflow with `workflow_dispatch` on the commit you want to bless.
2. Download the `oxide-randomx-perf-gate-artifacts` artifact, then inspect `compare/*.txt` and the matching `candidate/*.csv` files.
3. If the shift is intentional and the candidate output is stable, replace the corresponding baseline CSV in this directory and update this provenance note in the same PR.
4. If you intentionally bless a non-GitHub-hosted refresh instead, record the host CPU, toolchain, commit, and why that local capture is acceptable for the CI guardrail.

Do not treat these fixtures as AMD/Intel policy authority, and do not refresh them from ad hoc local captures without noting the provenance explicitly.
When `bash crates/oxide-randomx/scripts/ci/run_ci_perf_gate.sh` is invoked from
the `OxideMiner` repo root, it resolves the workspace target dir and Windows
`.exe` tool names automatically before comparing fixtures.
