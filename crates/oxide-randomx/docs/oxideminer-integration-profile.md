# OxideMiner Integration Profile

This document defines the conservative integration profile that the parent
OxideMiner project should consume on current `HEAD`.
If the parent repo needs one reviewable handoff package instead of reading the
full tree, use `docs/oxideminer-supported-build-contract.md` and the matching
`docs/oxideminer-supported-build-contract.json`.

Current authority chain:

- `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
- `docs/full-features-benchmark-v9-workflow.md`
- `perf_results/full_features_authority_index_v10.json`
- `perf_results/P2_4_integrated_full_features_authority_2026-03-30.md`
- `perf_results/AMD/P2_amd_fam23_mod113_host_unavailability_2026-03-30.md`

Related policy memos:

- `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`
- `perf_results/P2_2_jit_fastregs_cross_host_decision_2026-03-01.md`
- `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`

## v10 Supported Build Contract

Parent integrators should treat these names as the frozen build vocabulary on
current `HEAD`.

| Contract surface | Cargo features | Runtime intent |
| --- | --- | --- |
| `production` | `jit jit-fastregs` | supported shipping profile |
| `validation` | `jit jit-fastregs bench-instrument` | same runtime path plus instrumentation for CI, telemetry, perf gates, and bring-up |
| supported runtime fallbacks | `jit` without `jit-fastregs`, then no JIT features | conservative JIT, then interpreter |
| non-default experimental | `simd-blockio`, `simd-xor-paths`, `threaded-interp`, `superscalar-accel-proto` | outside the shipped default path |

This project does not support `Intel` / `AMD` release splits on current
`HEAD`.
The March 11, 2026 baseline authority keeps baseline `jit-fastregs` as the
best supported throughput path on AMD `23/8`,
AMD `23/113`, Intel `6/45`, and Intel `6/58`.
If future specialization is justified, it should come from a narrow runtime
host classifier or deployment-local calibration / rollout policy, not
vendor-specific release artifacts.

## Scope

The March 11, 2026 supported-path baseline memo spans these measured host
classes:

- AMD `23/8` (baseline authority host)
- AMD `23/113` (historical supporting host evidence; rerun follow-up blocked as
  of `2026-03-30`)
- Intel `6/45` (baseline authority host)
- Intel `6/58` (baseline authority host)

The measured supported-path ordering remains stable on that host set:

1. baseline `jit-fastregs`
2. conservative JIT
3. interpreter

Important caveat:

- `perf_results/full_features_authority_index_v10.json` now separates the clean
  integrated authority hosts from supporting-only AMD `23/113`.
- AMD `23/113` is supporting-only because same-host reruns changed realized
  `large_pages_on` backing and superscalar rows, not because of a dirty-tree
  provenance caveat.
- As of `2026-03-30`, the original AMD `23/113` Windows host is unavailable for
  rerun follow-up, so the current classification is bounded to historical
  supporting evidence.
- The integrated `ff_*` memo adds the current feature-interaction read: none of
  the experimental mixes displaces baseline `jit-fastregs`, and matrix-only
  "best config" tables are supporting context rather than parent policy.

## Production Profile

Use the `production` build for shipping:

- build with `--features "jit jit-fastregs"`
- request JIT at runtime
- request fast-register mapping at runtime
- in the reference harness, model that request as
  `--runtime-profile jit-fastregs`
- keep prefetch defaults unchanged unless the parent intentionally runs
  host-local calibration
- treat large pages and 1GB huge pages as explicit request knobs, not implied
  defaults
- rely on emitted telemetry to confirm actual JIT and page-size outcomes

Supported Rust wiring:

```rust,no_run
use std::sync::Arc;

use oxide_randomx::{
    DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm,
};

# fn main() -> oxide_randomx::Result<()> {
let cfg = RandomXConfig::new();
let mut flags = RandomXFlags::from_env();

#[cfg(feature = "jit")]
{
    flags.jit = true;
    flags.jit_fast_regs = true;
}

let cache = Arc::new(RandomXCache::new(b"my-key", &cfg)?);
let opts = DatasetInitOptions::new(1).with_large_pages(true);
let dataset = Arc::new(RandomXDataset::new_with_options(&cache, &cfg, opts)?);
let mut vm = RandomXVm::new_fast_shared(cache, dataset, cfg, flags)?;
let _hash = vm.hash(b"input data");
# Ok(())
# }
```

Interpretation:

- This is the best-supported throughput path on the captured host set.
- Fast mode is preferred when the parent can afford the dataset memory cost.
- Parent Fast-mode integrations should build the cache and dataset once per
  active key and fan out worker VMs with `RandomXVm::new_fast_shared(...)`.
- Light mode remains supported with the same runtime flag policy when the parent
  is intentionally cache-only.
- The integrated `ff_*` sweep did not change that recommendation; it only made
  the experimental branches easier to classify conservatively.

## Validation Profile

Use the `validation` build when the parent wants instrumentation without
changing the shipped runtime path:

- build with `--features "jit jit-fastregs bench-instrument"`
- use it for integration smoke runs, perf gates, telemetry/schema validation,
  and large-page realization checks
- keep the same supported runtime profiles as `production`
- do not treat `bench-instrument` as part of the default shipped path

## Fallback Profiles

When JIT is unavailable:

- use interpreter mode
- in the reference harness, use `--runtime-profile interpreter`
- keep the same prefetch and large-page request policy
- treat it as the lowest-risk supported fallback

When JIT is available but fast-regs must be disabled:

- use conservative JIT with `jit=true` and `jit_fast_regs=false`
- in the reference harness, use `--runtime-profile jit-conservative`
- keep this as the supported middle path for staged rollouts or isolation work

## Runtime Knobs That Matter

### JIT enablement

- Compile-time gate: `jit`
- Runtime gate: `RandomXFlags::jit = true`
- Verify actual activation from VM state or emitted perf telemetry

### Fast-register mapping

- Compile-time gate: `jit-fastregs`
- Runtime gate: `RandomXFlags::jit_fast_regs = true`
- Keep this on for the parent default profile when JIT is enabled

### Large pages and 1GB huge pages

- Scratchpad request: `RandomXFlags::large_pages_plumbing = true`
- Dataset request: `DatasetInitOptions::with_large_pages(true)`
- 1GB request knob: `RandomXFlags::use_1gb_pages = true` or
  `OXIDE_RANDOMX_HUGE_1G=1`, then plumb that request into
  `DatasetInitOptions::with_1gb_pages(true)` for Fast mode
- Request flags are not proof of allocation success; check emitted fields such
  as `large_pages_dataset`, `large_pages_1gb_dataset`, and
  `large_pages_1gb_scratchpad`

### Prefetch calibration

- Default parent profile: keep the current fixed mapping
  (`prefetch_distance=2`, `prefetch_auto_tune=false`)
- Optional opt-in path: run `prefetch_calibrate` locally on the deployment host
- Do not promote a local calibration result into a repo-wide default without
  new cross-host evidence

## Experimental Features That Stay Off By Default

These remain outside the upstream-safe integration profile:

- `simd-blockio`
- `simd-xor-paths`
- `threaded-interp`
- `superscalar-accel-proto`
- the dropped P2.2 `jit-fastregs` follow-up behavior

Reason:

- the current cross-host authority keeps baseline `jit-fastregs` as the
  supported path
- the integrated v10 authority adds no Tier 1 evidence that reopens
  `threaded-interp` or promotes `simd-blockio` / `simd-xor-paths`
- `superscalar-accel-proto` remains a parked experimental research lane, not a
  supported default, because the integrated cross-host story is still mixed on
  AMD Windows, rerun-sensitive on AMD `23/113`, and not promotive in Fast mode
  overall
- any reopen now requires repeated-run stability plus bounded agreement between
  isolated and integrated behavior, not host-specific Light wins alone
- matrix-only "best config" tables are not policy authority for parent defaults

## Vendor-Split Builds Are Not Supported

Do not publish separate `Intel` and `AMD` release artifacts for current
`HEAD`.

Reason:

- the supported-path winner is the same on every measured host class: baseline
  `jit-fastregs`
- the current experimental-feature evidence does not split cleanly by vendor
- the only hard runtime classifier in this area is model-specific
  (`GenuineIntel` family `6`, model `45` for `simd-blockio`), not vendor-wide
- within-vendor variation is larger than any current vendor-wide packaging rule
  the evidence supports

Legitimate future specialization would be:

- a narrow runtime host classifier, or
- deployment-local calibration / staged rollout policy

It would not be a broad vendor-named release split.

## What OxideMiner Should Treat As Stable

Stable for parent integration:

- interpreter
- conservative JIT
- baseline `jit-fastregs`
- large-page request semantics
- Linux 1GB huge-page request semantics
- emitted perf, stage, allocation, and prefetch telemetry
- host-local prefetch calibration apply path as an opt-in host-local control

Not stable as defaults:

- host-specific prefetch overrides
- `simd-blockio`
- `simd-xor-paths`
- `threaded-interp`
- `superscalar-accel-proto`

## Reference Harness

Use `examples/oxideminer_integration.rs` when you want a parent-shaped smoke
flow instead of a performance lab harness.

- It stays on the public constructors plus `RandomXVm::rekey(...)`.
- It accepts only the supported runtime profiles:
  `interpreter`, `jit-conservative`, and `jit-fastregs`.
- It exercises Light and Fast mode lifecycle, steady-state hashing, telemetry,
  and rekey versus rebuild parity.
- It can optionally apply persisted host-local prefetch calibration through the
  public `prefetch_apply` helper path.
- It now emits a stable `report_version`, a top-level `build_contract`, per-session
  requested versus effective flags, explicit `lifecycle.jit` state, and
  explicit `page_backing.*.request` versus `page_backing.*.realized` summaries
  so parent consumers do not need to infer allocation fallback from raw
  booleans alone.
- It reports rekey validation through `sessions[].rekey.parity.matches` and
  mirrors that result into `sessions[].lifecycle.rekey_matches_rebuild` for a
  one-field lifecycle check.
- It intentionally leaves `simd-blockio`, `simd-xor-paths`,
  `threaded-interp`, and `superscalar-accel-proto` out of the default flow.

See `docs/oxideminer-integration-harness.md` for commands and output mapping.
