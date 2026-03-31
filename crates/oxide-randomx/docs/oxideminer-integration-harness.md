# OxideMiner Integration Harness

`examples/oxideminer_integration.rs` is the reference lifecycle harness for the
supported OxideMiner-facing path.
If the parent repo needs a compact handoff package instead of deriving this
surface from the full repo, use `docs/oxideminer-supported-build-contract.md`
and `docs/oxideminer-supported-build-contract.json`.

## Build Contract

The harness validates the same frozen v10 build contract that parent
integrators should consume:

| Build profile | Cargo features | Use |
| --- | --- | --- |
| `production` | `jit jit-fastregs` | supported shipping profile |
| `validation` | `jit jit-fastregs bench-instrument` | harness, CI, telemetry, perf gates, and parent bring-up |
| supported runtime fallbacks | `jit-conservative`, then `interpreter` | supported fallback runtime profiles |
| non-default experimental | `simd-blockio`, `simd-xor-paths`, `threaded-interp`, `superscalar-accel-proto` | keep off in this harness |

All commands below use the `validation` build because the harness is meant to
exercise emitted telemetry and instrumentation without changing the supported
runtime path.
No `Intel` / `AMD` release split is part of this harness contract.

It intentionally follows only the supported contract:

- interpreter
- conservative JIT
- baseline `jit-fastregs`
- large-page / Linux 1GB request semantics
- emitted telemetry
- optional host-local prefetch calibration

It intentionally does **not** enable `simd-blockio`, `simd-xor-paths`,
`threaded-interp`, or `superscalar-accel-proto`.

Its job is to validate that the public API can drive the expected parent
lifecycle cleanly:

1. start from `RandomXFlags`
2. optionally apply host-local prefetch calibration
3. create a `RandomXCache`
4. create a `RandomXDataset` for Fast mode
5. create a `RandomXVm` in Light or Fast mode
6. run a short warmup plus steady-state hash loop
7. read `PerfStats` and allocation/JIT telemetry
8. rekey in place with `vm.rekey(...)`
9. compare that in-place rekey result against a full rebuild on the new key

It is intentionally not a benchmark harness. The output focuses on lifecycle
shape, deterministic fingerprints, and telemetry visibility rather than
throughput ranking.

## CLI Contract

The harness accepts only supported runtime profiles:

- `interpreter`
- `jit-conservative`
- `jit-fastregs`

That constraint is deliberate. The harness is meant to validate the supported
parent lifecycle, not arbitrary runtime flag combinations.

## CI Role

Workspace CI should use this harness only as a lightweight validation-build
smoke for the supported parent-facing lifecycle:

```bash
cargo run --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- \
  --mode light \
  --runtime-profile jit-fastregs \
  --warmup-rounds 0 \
  --steady-rounds 1 \
  --threads 1 \
  --format json
```

That GitHub-hosted runner smoke protects the supported validation build,
requested/effective runtime profile wiring, and emitted report shape. It is
separate from:

- `scripts/ci/run_ci_perf_gate.sh`, which keeps the mandatory perf threshold
  set intentionally narrow
- local full-features capture and authority workflows documented under
  `docs/perf.md`, `docs/public-capture.md`, and
  `docs/full-features-benchmark-workflow.md`
- broader OxideMiner parent validation on real hosts

## Validation Commands

Supported-path Light validation:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs
```

Supported-path Fast validation:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode fast --runtime-profile jit-fastregs
```

Conservative JIT fallback validation:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode both --runtime-profile jit-conservative --format json
```

Interpreter fallback validation:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode both --runtime-profile interpreter --format json
```

JSON output:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode both --runtime-profile jit-fastregs --format json
```

Apply a previously captured host-local calibration file:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- \
  --mode both \
  --runtime-profile jit-fastregs \
  --calibration perf_results/local/prefetch_calibration.csv
```

Notes:

- Fast mode allocates the full production dataset and is expected to consume the
  normal RandomX Fast-mode memory footprint.
- `--use-1gb-pages on` is plumbed into
  `DatasetInitOptions::with_1gb_pages(true)` for Fast mode. It also implies
  `--large-pages on`.
- Without `bench-instrument`, `PerfStats` still reads through the public API,
  but the counters are zeroed because instrumentation was not compiled in.
- If a `full_features_benchmark` matrix ranks an experimental config above the
  baseline on one host, do not translate that into harness defaults. This
  harness follows the supported path until project docs intentionally change.
  Use `docs/oxideminer-integration-profile.md`, `docs/perf.md`, and
  `docs/full-features-benchmark-workflow.md` when reviewing potential changes.

## Output

The machine-readable contract is anchored by:

- top-level `report_version`
- top-level `build_contract`
- top-level `requested_runtime_profile`
- `sessions[].requested_flags`
- `sessions[].lifecycle`
- `sessions[].page_backing.*.request`
- `sessions[].page_backing.*.realized`
- `sessions[].rekey.parity.matches`

Each session (`light` and/or `fast`) reports:

- requested versus effective runtime profile, plus any fallback reason
- explicit requested and effective runtime flags for that session
- explicit JIT request, compile-time support, and active-state reporting
- calibration status and any matched persisted prefetch row
- cache / dataset / VM build timings
- explicit page-request objects separate from realized page-backing objects
- one steady-state hash fingerprint (`first`, `last`, XOR aggregate)
- extracted `PerfStats` fields relevant to parent telemetry
- rekey timing plus an explicit parity object against a clean rebuild

`sessions[].rekey.parity.matches=true` is the key integration check for the
rekey path. It means the in-place `vm.rekey(...)` flow and a full public
rebuild produced the same hash sequence for the same workload on the new key.

`page_backing` separates request intent from realized backing. In particular:

- a large-page request can still realize as standard 4 KB pages
- a 1 GB dataset request can still realize as 2 MB huge pages
- the scratchpad can request large pages but never issues a 1 GB page request;
  `use_1gb_pages` is scoped to the Fast-mode dataset object
- Light mode reports dataset backing as not applicable rather than implying that
  Fast-mode dataset behavior was checked

Common `page_backing.*.realization` values include:

- `not_requested`
- `requested_fallback_standard_4kb`
- `requested_1gb_fallback_2mb_large_pages`
- `realized_1gb_large_pages`

Representative JSON shape:

```json
{
  "report_version": "oxideminer-integration-v2",
  "build_contract": {
    "production_features": "jit jit-fastregs",
    "validation_features": "jit jit-fastregs bench-instrument",
    "supported_runtime_profiles": [
      "interpreter",
      "jit-conservative",
      "jit-fastregs"
    ],
    "compiled_features": {
      "jit": true,
      "jit_fastregs": true,
      "bench_instrument": true
    }
  },
  "requested_runtime_profile": "jit-fastregs",
  "requested_flags": {
    "large_pages": false,
    "use_1gb_pages": false
  },
  "sessions": [
    {
      "mode": "fast",
      "lifecycle": {
        "requested_runtime_profile": "jit-fastregs",
        "effective_runtime_profile": "jit-fastregs",
        "jit": {
          "requested": true,
          "requested_fast_regs": true,
          "compiled_jit_support": true,
          "compiled_fast_regs_support": true,
          "active": true
        }
      },
      "requested_flags": {
        "large_pages": false,
        "use_1gb_pages": false
      },
      "effective_flags": {
        "large_pages": false,
        "use_1gb_pages": false
      },
      "page_backing": {
        "scratchpad": {
          "allocation": "scratchpad",
          "request": {
            "large_pages": false,
            "use_1gb_pages": false
          },
          "realized": {
            "large_pages": false,
            "huge_page_size": null,
            "description": "standard 4KB pages"
          },
          "realization": "not_requested"
        }
      },
      "rekey": {
        "parity": {
          "matches": true
        }
      }
    }
  ]
}
```

## OxideMiner Mapping

How OxideMiner should read this harness:

- Replace the fixed example keys with the parent's key or epoch source.
- Replace the example workload with the parent's real hashing inputs if needed.
- Keep the flag plumbing shape the same: env/default flags first, then optional
  calibration apply, then VM construction.
- For a real Fast-mode worker pool, build the cache and dataset once for the
  active key and fan out worker VMs with
  `RandomXVm::new_fast_shared(Arc<RandomXCache>, Arc<RandomXDataset>, ...)`.
- Use the same calibration `workload_id` during both capture and apply. The
  example defaults to `PREFETCH_CALIBRATION_WORKLOAD_ID` so it can consume the
  existing `prefetch_calibrate` artifact format directly.
- Treat Fast mode as the parent-default shape when the dataset memory cost is
  acceptable; use Light mode as the supported cache-only fallback.
- Treat experimental feature families as separate research surfaces, not as
  alternate defaults for this harness.

The harness is meant to stay reviewable. If a future change requires private
module access or experimental-only features to keep this example working, that
is a signal that the supported parent path has drifted.
