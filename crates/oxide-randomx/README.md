# oxide-randomx

`oxide-randomx` is OxideMiner's in-tree RandomX engine. It is developed,
tested, and released as part of this workspace under `crates/oxide-randomx`;
it is not maintained as a separate repository or standalone published crate.

This crate contains:

- the RandomX VM, cache, dataset, and JIT paths
- the parent-facing integration harness used by `oxide-core`
- local benchmarking, validation, and capture utilities

## Supported Contract

Treat the OxideMiner-facing contract as the stable surface:

| Surface | Build | Runtime intent |
| --- | --- | --- |
| `production` | `--features "jit jit-fastregs"` | supported throughput path |
| `validation` | `--features "jit jit-fastregs bench-instrument"` | same path plus telemetry and validation instrumentation |
| supported fallbacks | `jit-conservative`, then `interpreter` | keep page-request and prefetch behavior unchanged |
| supported opt-in control | host-local prefetch calibration | local override only |
| experimental and off by default | `simd-blockio`, `simd-xor-paths`, `superscalar-accel-proto`, `threaded-interp` | not part of the shipped default path |

Separate vendor-named release artifacts are not part of the supported contract.

## Quick Start

```rust,no_run
use oxide_randomx::{RandomXCache, RandomXConfig, RandomXFlags, RandomXVm};

# fn main() -> oxide_randomx::Result<()> {
let cfg = RandomXConfig::new();
let flags = RandomXFlags::default();
let cache = RandomXCache::new(b"my-key", &cfg)?;
let mut vm = RandomXVm::new_light(cache, cfg, flags)?;
let _hash = vm.hash(b"input data");
# Ok(())
# }
```

## Local Tooling

The public tree keeps only generic local tooling names:

- `cargo run --release --bin oxide-randomx-public-capture -- --accept-data-contract`
- `cargo run --release --bin full_features_benchmark`
- `cargo run --release --bin full_features_authority -- validate-index`
- `cargo run --release --bin perf_compare -- --baseline perf_results/baseline.csv --candidate perf_results/candidate.csv`

Local benchmark and capture outputs belong under `crates/oxide-randomx/perf_results/`.
That directory is intentionally untracked so maintainers can collect and compare
host-local evidence without publishing raw artifacts in git.

## Docs

- `docs/oxideminer-supported-build-contract.md`: stable parent-facing contract
- `docs/oxideminer-integration-profile.md`: integration defaults and fallbacks
- `docs/oxideminer-integration-harness.md`: lifecycle harness behavior
- `docs/perf.md`: local benchmarking and validation guide
- `docs/public-capture.md`: outside-host capture runner
- `docs/full-features-benchmark-workflow.md`: local full-features workflow
- `docs/perf_results_visualizer_guide.md`: visualizing local `perf_results/`

## Validation

Typical validation commands:

```bash
cargo test -p oxide-randomx
cargo test -p oxide-randomx --features bench-instrument
cargo test -p oxide-randomx --features "jit jit-fastregs"
cargo run -p oxide-randomx --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode both --runtime-profile jit-fastregs --format json
```
