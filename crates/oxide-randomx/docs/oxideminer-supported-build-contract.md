# OxideMiner Supported Build Contract

This package is the explicit internal contract surface for OxideMiner workspace
crates consuming `oxide-randomx`.
Use this Markdown file for review and
[`docs/oxideminer-supported-build-contract.json`](oxideminer-supported-build-contract.json)
for machine-readable ingestion.

This is internal OxideMiner contract guidance for the current supported path.
It does not promise that `oxide-randomx` remains a stable standalone dependency
boundary outside OxideMiner.
Treat `schema_version`, `contract_revision`, and the owning OxideMiner revision
as the coordination tuple.

## Contract Identity

- Contract name: `oxideminer-supported-build-contract`
- Schema version: `1`
- Contract revision: `2026-03-29`
- Intended consumer: `OxideMiner workspace crates`
- Crate: `oxide-randomx` `0.1.0`
- Repository: `https://github.com/raystanza/OxideMiner.git`

Authority inputs for this package:

- `README.md`
- `docs/oxideminer-integration-profile.md`
- `docs/oxideminer-integration-harness.md`
- `examples/oxideminer_integration.rs`

## Supported Profiles

| Surface | Cargo features | Runtime profile | Modes | Purpose |
| --- | --- | --- | --- | --- |
| `production` | `jit jit-fastregs` | `jit-fastregs` | `light`, `fast` | supported shipping profile |
| `validation` | `jit jit-fastregs bench-instrument` | `jit-fastregs` | `light`, `fast` | supported CI, telemetry, perf-gate, and bring-up profile |
| fallback | `jit` | `jit-conservative` | `light`, `fast` | supported middle path when JIT is available but fast-regs is disabled or unavailable |
| fallback | none required | `interpreter` | `light`, `fast` | lowest-risk supported fallback when JIT is unavailable or intentionally disabled |

No `Intel` / `AMD` release split is part of this contract.

## Parent API Note

For Fast-mode parent integrations that need multiple worker VMs over one active
seed key, the supported public API is:

- build `RandomXCache` once for the active key
- build `RandomXDataset` once for the active key
- share both objects via `Arc`
- create one worker VM per thread with `RandomXVm::new_fast_shared(...)`

This keeps the parent on public `oxide-randomx` surfaces without copying the
Fast-mode dataset per worker.

## Supported Runtime Knobs

| Knob | Supported values | Default guidance | Notes |
| --- | --- | --- | --- |
| `mode` | `light`, `fast` | prefer `fast` when dataset memory is acceptable; use `light` as the supported cache-only fallback | both modes stay in-contract |
| `runtime_profile` | `interpreter`, `jit-conservative`, `jit-fastregs` | `jit-fastregs` | this is the parent-facing selector for interpreter, conservative JIT, and fast-regs JIT |
| `large_pages` | `off`, `on` | `off` | explicit request knob for scratchpad and Fast-mode dataset backing; confirm realized backing from emitted `page_backing.*` fields |
| `use_1gb_pages` | `off`, `on` | `off` | Linux-only Fast-mode dataset request knob; implies `large_pages`; confirm realized backing from emitted dataset page-backing fields |
| `prefetch_calibration_path` | `unset`, path to persisted calibration csv | `unset` | optional host-local override applied through the public calibration helper; keep the fixed default mapping unless the parent opts in |

## Non-Default Experimental Features

| Feature | Status | Default state |
| --- | --- | --- |
| `simd-blockio` | experimental | off |
| `simd-xor-paths` | experimental follow-up | off |
| `threaded-interp` | parked experimental closed negative result | off |
| `superscalar-accel-proto` | parked experimental research lane | off |

## Parent-Observable Output

The machine-readable parent output is emitted by
`examples/oxideminer_integration.rs` and currently reports
`report_version` = `oxideminer-integration-v2`.

Top-level fields the parent may rely on:

- `report_version`
- `build_contract`
- `requested_runtime_profile`
- `requested_flags`
- `sessions`

Per-session fields the parent may rely on:

- `mode`
- `lifecycle.requested_runtime_profile`
- `lifecycle.effective_runtime_profile`
- `lifecycle.fallback_reason`
- `lifecycle.jit.requested`
- `lifecycle.jit.requested_fast_regs`
- `lifecycle.jit.compiled_jit_support`
- `lifecycle.jit.compiled_fast_regs_support`
- `lifecycle.jit.active`
- `requested_flags`
- `effective_flags`
- `page_backing.scratchpad.request`
- `page_backing.scratchpad.realized`
- `page_backing.scratchpad.realization`
- `page_backing.dataset.request`
- `page_backing.dataset.realized`
- `page_backing.dataset.realization`
- `rekey.parity.matches`
- `lifecycle.rekey_matches_rebuild`

Telemetry fields the parent may rely on in the validation build:

- `telemetry.instrumented`
- `telemetry.hashes`
- `telemetry.program_execs`
- `telemetry.execute_program_ns_interpreter`
- `telemetry.execute_program_ns_jit`
- `telemetry.finish_iteration_ns`
- `telemetry.dataset_item_loads`
- `telemetry.scratchpad_read_bytes`
- `telemetry.scratchpad_write_bytes`
- `telemetry.jit_fastregs_prepare_ns`
- `telemetry.jit_fastregs_finish_ns`

## Example Validation Commands

- Light validation:
  `cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs`
- Fast validation:
  `cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode fast --runtime-profile jit-fastregs`

## Maintenance Note

The checked-in JSON is expected to be generated from the same typed contract
source as this document and updated in the same change whenever the supported
contract changes.
