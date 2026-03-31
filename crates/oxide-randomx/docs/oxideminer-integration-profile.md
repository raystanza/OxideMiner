# OxideMiner Integration Profile

This document describes the conservative `oxide-randomx` profile that
`oxide-core` and `oxide-miner` should consume on current `HEAD`.

## Contract

| Surface | Cargo features | Runtime intent |
| --- | --- | --- |
| `production` | `jit jit-fastregs` | supported shipping profile |
| `validation` | `jit jit-fastregs bench-instrument` | same runtime path plus telemetry and validation instrumentation |
| supported fallbacks | `jit` without `jit-fastregs`, then no JIT features | conservative JIT, then interpreter |
| non-default experimental | `simd-blockio`, `simd-xor-paths`, `threaded-interp`, `superscalar-accel-proto` | outside the shipped default path |

The supported default remains baseline `jit-fastregs`. Do not publish or
reason about vendor-split product builds.

## Production Profile

Use the production profile for shipping:

- build with `--features "jit jit-fastregs"`
- request JIT and fast-register mapping at runtime
- keep the default prefetch mapping unless the parent intentionally applies a
  host-local calibration file
- treat large pages and 1 GiB huge pages as explicit request knobs
- verify realized page backing from emitted telemetry instead of assuming success

## Validation Profile

Use the validation profile when the parent needs extra observability:

- build with `--features "jit jit-fastregs bench-instrument"`
- use it for integration smokes, telemetry/schema checks, perf gates, and page
  realization checks
- keep the same supported runtime profiles as production

## Fallbacks

When fast-register JIT cannot be used:

- `jit-conservative`: `jit=true`, `jit_fast_regs=false`
- `interpreter`: `jit=false`

These are supported fallbacks, not alternative default recommendations.

## Stable Knobs

Stable for parent integration:

- interpreter
- conservative JIT
- baseline `jit-fastregs`
- large-page request semantics
- Linux 1 GiB huge-page request semantics
- emitted perf, stage, allocation, and prefetch telemetry
- host-local prefetch calibration as an opt-in deployment-local control

Not stable as defaults:

- `simd-blockio`
- `simd-xor-paths`
- `threaded-interp`
- `superscalar-accel-proto`
- repo-wide prefetch-default changes based on a single local capture

## Validation Sources

Use these materials when validating or updating the profile:

- `docs/oxideminer-supported-build-contract.md`
- `docs/oxideminer-integration-harness.md`
- `docs/perf.md`
- `docs/full-features-benchmark-workflow.md`

Raw perf captures and any authority index belong in local, untracked
`perf_results/` data rather than committed git history.
