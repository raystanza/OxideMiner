# OxideMiner Supported Profile Validation

This document records the validation intent for the supported
`oxide-randomx` integration profile used by OxideMiner.

## Supported Profile

- production build: `jit jit-fastregs`
- validation build: `jit jit-fastregs bench-instrument`
- supported runtime profiles:
  - `jit-fastregs`
  - `jit-conservative`
  - `interpreter`
- no vendor-split release policy

## Required Validation

Run the narrowest matching checks for the change:

```bash
cargo test -p oxide-core --features randomx --test randomx_supported_profile_smoke
cargo test -p oxide-randomx
cargo test -p oxide-randomx --features bench-instrument
cargo test -p oxide-randomx --features "jit jit-fastregs"
```

Parent-shaped lifecycle smoke:

```bash
cargo run -p oxide-randomx --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- \
  --mode both --runtime-profile jit-fastregs --format json
```

## What To Verify

- the supported build compiles and runs
- requested versus effective runtime profile reporting remains stable
- page-backing request versus realization fields remain visible
- rekey parity and lifecycle contract fields remain stable
- experimental features stay fenced unless the docs intentionally change

## Notes

- local cross-host validation data belongs in untracked `perf_results/`
- any change to supported defaults should update the public docs in the same patch
