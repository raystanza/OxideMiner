# Full Features Benchmark Workflow

This workflow is the generic local maintainer path for running the full
feature-matrix capture against `oxide-randomx`.

## Principles

- keep raw capture trees under local `perf_results/`
- do not commit host-specific capture trees to git
- do not treat one local matrix win as a parent-default change
- when a finding changes project policy, update the relevant docs in the same
  patch

## Run A Capture

From the repo root:

```bash
cargo run --release --bin full_features_benchmark --features "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto"
```

Optional explicit output directory:

```bash
cargo run --release --bin full_features_benchmark --features "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto" -- \
  --out-dir crates/oxide-randomx/perf_results/local/ff_capture
```

The tool writes:

- `meta/provenance.txt`
- `meta/summary.json`
- `meta/overview.md`
- `meta/matrix_index.csv`
- `meta/pair_index.csv`
- `meta/pair_summary.csv`

## Optional Local Authority Index

If you keep a local authority index, store it at:

`crates/oxide-randomx/perf_results/full_features_authority_index.json`

Validate it with:

```bash
cargo run --release --bin full_features_authority -- validate-index
```

Compare a new capture against the local index:

```bash
cargo run --release --bin full_features_authority -- compare --capture crates/oxide-randomx/perf_results/local/ff_capture
```

The public repo intentionally does not hardcode a committed host inventory.
Promotions from exploratory to policy-relevant evidence should be documented in
`docs/`, not inferred from a checked-in capture list.

## Promotion Checklist

If you want a result to affect project policy:

1. Confirm the supported path or experimental lane that actually changed.
2. Re-run the narrowest matching validation path.
3. Update `docs/oxideminer-integration-profile.md`, `docs/perf.md`, and any
   other affected public docs.
4. Keep the raw artifacts local unless there is a clear reason to publish a
   summarized derivative.
