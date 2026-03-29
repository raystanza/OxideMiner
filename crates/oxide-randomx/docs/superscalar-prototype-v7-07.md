# SuperscalarHash Acceleration Prototype (v7_07)

Date: 2026-03-05  
Host: Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz

AMD rerun evidence (same prompt, 2026-03-06 on Windows Ryzen host):

- `perf_results/AMD/v7_07_superscalar_prototype_amd_fam23_mod8_2026-03-06.md`
- `perf_results/AMD/v7_07_superscalar_prototype_summary_amd_fam23_mod8_20260306_172252.json`

## Strategy

Prototype: `superscalar-accel-proto` feature in `src/superscalar/mod.rs`.

Approach:

1. Keep scalar instruction path (`execute_scalar`) intact for baseline/fallback.
2. Build a compact compiled op stream per generated superscalar program.
3. Precompute `IMulRcp` reciprocals once at compile time and execute as multiply-only ops.
4. Dispatch `SuperscalarProgram::execute(...)` to compiled ops only when
   `superscalar-accel-proto` is enabled.

Scalar/reference comparison remains available via:

* feature-off builds (`execute` is scalar), and
* `superscalar_hash_harness --impl scalar` in feature-on builds.

## Isolated Harness Results

Command set:

```bash
# Baseline (feature off)
cargo run --release --example superscalar_hash_harness -- --format json --config default --impl active --iters 2000 --warmup 200 --items 256

# Prototype active path
cargo run --release --example superscalar_hash_harness --features superscalar-accel-proto -- --format json --config default --impl active --iters 2000 --warmup 200 --items 256

# Prototype scalar reference (same build)
cargo run --release --example superscalar_hash_harness --features superscalar-accel-proto -- --format json --config default --impl scalar --iters 2000 --warmup 200 --items 256
```

Observed:

| config | impl | compute ns/call | execute ns/call | checksum parity |
| --- | --- | ---: | ---: | --- |
| default | baseline active (feature off) | 15751.539 | 1967.175 | yes |
| default | proto active (feature on) | 13574.565 | 1707.674 | yes |
| default | scalar reference (feature on) | 16151.820 | 1997.608 | yes |

Interpretation:

* Isolated cache-item synthesis (`compute_item_words_in_place`) improved by ~13.8% vs baseline active.
* In the same feature-on build, active vs scalar improved by ~16.0%.
* Checksums matched exactly across active/scalar runs.
* On the shallow `test-small` config (`cache_accesses=2`), compute-path gains were near-noise; the
  larger default config (`cache_accesses=8`) is the one that clearly crossed the 3% keep threshold.

## End-to-End Evidence

Light mode (interpreter, `perf_harness`, release, `bench-instrument`):

```bash
# baseline
cargo run --release --example perf_harness --features bench-instrument -- --mode light --jit off --iters 2 --warmup 1 --format json

# prototype
cargo run --release --example perf_harness --features "bench-instrument superscalar-accel-proto" -- --mode light --jit off --iters 2 --warmup 1 --format json
```

Observed `ns_per_hash`:

* baseline: `352393427`
* prototype: `305164511` (~13.4% faster)

Fast mode small config (`unsafe-config`, dataset path exercised):

```bash
# baseline
OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_FAST_BENCH_SMALL=1 cargo run --release --example perf_harness --features "bench-instrument unsafe-config" -- --mode fast --jit off --iters 2 --warmup 1 --threads 1 --format json

# prototype
OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_FAST_BENCH_SMALL=1 cargo run --release --example perf_harness --features "bench-instrument unsafe-config superscalar-accel-proto" -- --mode fast --jit off --iters 2 --warmup 1 --threads 1 --format json
```

Observed:

* `ns_per_hash`: `69364717` -> `68930841` (~0.63% faster, effectively neutral-positive)
* `dataset_init_ns`: `4266264595` -> `3495798691` (~18.1% faster)

## Keep/Stop Decision

Keep criteria status:

1. Isolated SuperscalarHash/cache-item measurement >=3% improvement: **met**.
2. Correctness exact vs scalar: **met**.

Broader promotion criteria:

* Single-host evidence is promising for light mode and non-regressive for fast mode on this host.
* Cross-host acceptance is **not claimed** here; rerun on the second host before promotion.
