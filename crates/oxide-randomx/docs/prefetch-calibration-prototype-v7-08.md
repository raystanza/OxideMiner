# Host-Local Prefetch Calibration Prototype (v7_08)

Date: 2026-03-05

## Context

Current authority snapshots:

* `docs/perf-results-amd.md`
* `docs/perf-results-intel.md`
* `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`

Those documents keep the static `CpuFamily::optimal_prefetch_distance()` mapping
unchanged and explicitly recommend host-local sweeps for local tuning.

## Prototype Design

Implementation is an opt-in helper (`examples/prefetch_calibrate.rs`) with bounded
fixed-distance sweeps.

Model:

1. Sweep a configured list of prefetch distances (default `0..8`).
2. Repeat for bounded rounds (`--rounds`, default `3`) using deterministic shuffled
   order per round.
3. Measure `ns_per_hash` on deterministic workload.
4. Pick the best distance by mean `ns_per_hash`.
5. Optionally persist one record keyed by code + CPU + scenario.

Scenario key dimensions:

* mode (`light`/`fast`)
* `jit_requested`
* `jit_fast_regs`
* `scratchpad_prefetch_distance`
* workload id

Persistence key dimensions:

* schema version
* crate version
* git SHA and dirty marker
* rustc version
* CPU vendor/family/model/stepping/family bucket
* scenario key

This makes stale rows easy to invalidate after code/compiler changes.

## Default Behavior

No default runtime behavior changed. `RandomXFlags::from_env()` and
`CpuFamily::optimal_prefetch_distance()` are unchanged by this prototype.

## Local Usage

```bash
cargo run --release --example prefetch_calibrate -- \
  --mode light --jit off --rounds 3 --warmup 2 --iters 20 \
  --distances 0,1,2,3,4,5,6,7,8 \
  --persist perf_results/local/prefetch_calibration.csv \
  --format human
```

## Tradeoffs

* Startup/runtime cost: non-trivial; bounded but intentionally explicit and opt-in.
* Reproducibility: deterministic workload/order improves repeatability, but host noise
  still exists; multiple rounds and artifact retention are recommended.
