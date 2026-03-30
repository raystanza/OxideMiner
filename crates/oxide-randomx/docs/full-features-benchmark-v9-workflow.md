# Full Features Authority Workflow

This document defines the v10 authority workflow for
`tools/full_features_benchmark.rs` and `tools/full_features_authority.rs`.

Public beta note:

- `tools/oxide_randomx_beta_capture.rs` is the public tester-facing runner.
- `tools/full_features_benchmark.rs` remains the internal authority workflow tool described by this document.
- Public beta usage and source-boundary guidance live in:
  - `docs/public-beta-capture.md`
  - `docs/public-beta-repo-boundary.md`

It exists to answer four practical questions:

1. how to build and package the benchmark
2. how to run it locally or on a remote host
3. what artifacts should come back
4. how to classify the result as authority, supporting, or exploratory evidence

Compatibility note:

- The workflow metadata is additive.
- Older `ff_*` captures remain valid historical artifacts, but they may not
  contain the `host_class_id`, `capture_evidence_tier`, rerun-group, or
  page-backing summary fields used by the in-tree v10 workflow.
- Do not silently treat missing v10-era metadata on older captures as negative
  evidence.

## Canonical Host Inventory

The v10 canonical host inventory is currently:

| `host_class_id` | Label | Expected evidence tier when clean | Rerun expectation |
| --- | --- | --- | --- |
| `amd_fam23_mod113_windows` | AMD R5 3600 / Win11 | `supporting` | `repeated_same_sha_required` |
| `amd_fam23_mod8_windows` | AMD R5 2600 / Win11 | `authority` | `single_capture_sufficient` |
| `amd_fam23_mod8_linux` | AMD R5 2600 / Ubuntu | `authority` | `single_capture_sufficient` |
| `intel_fam6_mod45_linux` | Intel Dual-Xeon / Ubuntu | `authority` | `single_capture_sufficient` |
| `intel_fam6_mod58_linux` | Intel i5 / Ubuntu | `authority` | `single_capture_sufficient` |

Rules:

- `host_tag` is still used for output directory naming, but it is not a sufficient host-class identifier because it collapses the Windows and Linux `amd_fam23_mod8` hosts.
- If a capture emits a `host_class_id` outside this table, treat it as `exploratory` until the host inventory is intentionally extended.
- AMD `23/113` Windows remains supporting-only for now because same-SHA reruns changed realized large-page backing and integrated superscalar behavior.

## Canonical Page Profiles

The workflow distinguishes requested page profiles from realized backing.

Canonical requested profiles:

| Host OS | Page profile | Role |
| --- | --- | --- |
| Windows | `pages_off` | `supporting_control` |
| Windows | `large_pages_on` | `authority_primary` |
| Linux | `pages_off` | `supporting_control` |
| Linux | `large_pages_on` | `authority_primary` |
| Linux | `huge_1g_requested` | `supporting_semantics` |

Interpretation rules:

- `large_pages_on` ABBA results are the primary interaction evidence when the capture tier is `authority`.
- `pages_off` is a control/comparison profile, not the main policy authority.
- `huge_1g_requested` is supporting semantics evidence only. It records request behavior and realized 1 GB backing, but it is not the main feature-toggle authority surface.
- Realized page backing is authoritative only when you read the emitted realized-backing fields, not the request flags alone.

## Clean Provenance

A capture is clean for v10 authority purposes only when all of these hold:

- `git_dirty=false`
- full feature bundle is compiled:
  `jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto`
- `--perf-iters 50`
- `--perf-warmup 5`
- `--threads` matches detected logical threads on the host
- the emitted page-profile set matches the canonical set for that host OS

If any of those checks fail, the capture is `exploratory` even if it ran on a canonical host.

## Evidence Classes

### `authority`

Use for policy-level interaction claims only when all are true:

- canonical host class
- clean provenance
- capture-level `capture_evidence_tier=authority`
- result comes from the `large_pages_on` ABBA surface

In practice this means:

- `meta/pair_summary.csv` rows on `large_pages_on` are the main authority rows
- the same rows in `meta/summary.json` and `meta/overview.md` should agree

### `supporting`

Use for context, controls, and semantics, but not as the sole basis for a policy change:

- `pages_off` matrix rows
- `huge_1g_requested` rows
- page-backing realization summaries
- clean captures from canonical host classes that are intentionally supporting-only, currently `amd_fam23_mod113_windows`

### `exploratory`

Use for investigation only:

- dirty tree
- modified perf settings or thread count
- non-canonical host class
- ad hoc captures that do not follow the canonical build/run contract

## Tool-Emitted Metadata vs Process Guidance

The tool now emits machine-readable metadata for facts that should travel with the capture:

- `host_class_id`
- `capture_evidence_tier`
- `clean_provenance`
- `rerun_expectation`
- `rerun_group_id`
- page-profile roles and evidence tiers
- page-backing summaries in `all_true`, `all_false`, `mixed`, or `unknown` form
- per-pair realized backing status in `meta/pair_summary.csv`, `meta/summary.json`, and `abba/.../compare.txt`

This document remains the source of truth for policy/process guidance:

- which host classes are canonical
- which host classes are authority vs supporting
- how to interpret those evidence tiers
- when repeated same-SHA reruns are mandatory

## Build And Package

Local cargo build:

```bash
cargo build --release --bin full_features_benchmark --features "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto"
```

Package for a remote Windows host:

```bash
scripts/build/build_full_features_benchmark.sh --target-host windows
```

Or on PowerShell:

```powershell
.\scripts\build\build_full_features_benchmark.ps1 -TargetHost windows
```

Package for a remote Linux host:

```bash
scripts/build/build_full_features_benchmark.sh --target-host linux
```

The package is intentionally simple: one benchmark binary plus one short run-instructions text file.

When a remote host needs a fixed rerun contract, the packagers can bake that into the instruction text without requiring a repo checkout on the target host. Relevant options and environment variables are:

- `--run-count` / `-RunCount` / `RUN_COUNT`
- `--remote-bundle-root` / `-RemoteBundleRoot` / `REMOTE_BUNDLE_ROOT`
- `--remote-run-prefix` / `-RemoteRunPrefix` / `REMOTE_RUN_PREFIX`
- `--remote-host-context-file` / `-RemoteHostContextFile` / `REMOTE_HOST_CONTEXT_FILE`

Representative AMD `23/113` Windows rerun package command:

```powershell
.\scripts\build\build_full_features_benchmark.ps1 `
  -TargetHost windows `
  -RunCount 3 `
  -RemoteBundleRoot 'C:\oxide-randomx-captures\promptv9_04_amd_fam23_mod113_20260326' `
  -RemoteRunPrefix 'ff_amd_fam23_mod113_promptv9_04' `
  -RemoteHostContextFile 'HOST_CONTEXT_NOTES.txt'
```

That still emits one executable plus one instructions file, but the instructions file now includes the fixed rerun loop, the outside-repo bundle root, and the host-context note requested for return.

## Run Locally

Representative local command from the `OxideMiner` repo root:

```bash
cargo run -p oxide-randomx --release --bin full_features_benchmark --features "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto" -- \
  --out-dir crates/oxide-randomx/perf_results/<bucket>/ff_<host>_<timestamp>
```

Useful flags:

- `--validate-only` checks the binary and compiled feature set without running the capture
- `--out-dir` is recommended when you want a deterministic destination

For authority captures, keep the defaults:

- `--perf-iters 50`
- `--perf-warmup 5`
- `--threads <logical-thread-count>`

## Run On A Remote Host

Remote host flow:

1. Build/package on a development machine.
2. Copy the packaged binary to the target host.
3. Follow the packaged instructions text exactly, including any fixed rerun count, outside-repo bundle root, and host-context note request.
4. Run it without changing the canonical perf settings unless you are deliberately doing exploratory work.
5. Preserve and return the entire emitted bundle, not just selected summaries.
6. Copy the intact returned `ff_*` directories back into this repo.
7. Read classification and page-backing status from the emitted `meta/*` artifacts before writing any memo.

## Expected Artifacts

Every new `ff_*` capture should contain:

- `meta/provenance.txt`
- `meta/manifest.txt`
- `meta/matrix_index.csv`
- `meta/pair_index.csv`
- `meta/pair_summary.csv`
- `meta/summary.json`
- `meta/overview.md`
- `matrix/...`
- `abba/runs/...`
- `abba/pairs/...`
- `superscalar/*.csv` and `superscalar/*.json`

Reading order for a new capture:

1. `meta/provenance.txt`
2. `meta/overview.md`
3. `meta/pair_summary.csv`
4. `meta/summary.json`

That order should tell you, quickly:

- what host class this was
- whether it is authority/supporting/exploratory
- whether repeated same-SHA review is required
- whether requested large/1 GB pages actually materialized

## Rerun Grouping

`rerun_group_id` exists to group captures that are intended to be compared as same-host same-settings reruns.

It is keyed from:

- `host_class_id`
- `git_sha_short`
- `rustc`
- thread count
- perf iteration/warmup settings
- page-profile set

Rules:

- On unstable hosts, compare reruns inside the same `rerun_group_id` first.
- If the group changes because SHA, compiler, or benchmark settings changed, document that explicitly before drawing stability conclusions.

## Interpreting Realized Page Backing

The tool now emits page-backing summaries with these statuses:

- `all_true`: every observed run realized the requested backing
- `all_false`: no observed run realized that backing
- `mixed`: some runs realized it and some did not
- `unknown`: the source rows did not expose a usable boolean

Use `mixed` as a caution signal:

- it means the capture needs more care than “requested pages were on”
- on unstable hosts, it is a concrete reason to keep the capture in supporting status

## Minimal Classification Checklist

For any new `ff_*` directory:

1. Read `host_class_id` and confirm whether it is canonical.
2. Read `capture_evidence_tier`.
3. Read `clean_provenance`.
4. Read `rerun_expectation` and `rerun_group_id`.
5. Read the page-backing summary before interpreting any page-profile delta.
6. Treat `large_pages_on` ABBA rows as primary only when the capture tier is `authority`.
7. Treat matrix rankings as supporting orientation, not as higher authority than ABBA.

## Current Authority Index

The checked-in machine-readable source of truth for the current full-features
authority set is:

- `crates/oxide-randomx/perf_results/full_features_authority_index_v10.json`

That index records, per `host_class_id`:

- the current authoritative capture path
- any supporting or superseded related captures
- authority classification
- indexed provenance identity
- rerun-stability status and expectation

Validate the index before changing it:

```bash
cargo run -p oxide-randomx --release --bin full_features_authority -- validate-index
```

That command proves the checked-in paths still exist and that the indexed provenance still matches the capture artifacts.

## Compare A New Capture

Compare any new or historical `ff_*` directory against the indexed authority for
its host class:

```bash
cargo run -p oxide-randomx --release --bin full_features_authority -- compare \
  --capture crates/oxide-randomx/perf_results/AMD/ff_amd_fam23_mod113_windows_20260318_210634
```

The comparer is intentionally narrow. It reads:

- `meta/provenance.txt`
- `meta/pair_summary.csv`
- `meta/matrix_index.csv`

That keeps it compatible with older captures that do not yet emit
`host_class_id`, `capture_evidence_tier`, or `rerun_group_id`.

The compare report is organized around the signals that matter for v10:

- `provenance_identity`: host/OS/compiler/SHA/settings identity
- `rerun_relationship`: `same_capture`, `same_sha_same_settings`, `same_sha_settings_drift`, or `different_sha_same_host_class`
- `realized_page_backing`: per-page-profile realized large-page and 1 GB backing summaries
- `abba_pair_deltas`: authority-capture ABBA deltas versus candidate-capture ABBA deltas, plus any realized-backing fields carried in newer pair summaries

Use that compare output before adopting a new capture or writing any memo about it.

## Intentional Update Flow

When a new capture should replace or supplement the current authority set:

1. Run `full_features_benchmark` with the v10 workflow settings.
2. Run it from the repo root with an explicit crate-local destination such as `--out-dir crates/oxide-randomx/perf_results/<bucket>/ff_<host>_<timestamp>`.
3. Run `cargo run -p oxide-randomx --release --bin full_features_authority -- compare --capture <new ff_* dir>`.
4. Review the rerun relationship, provenance identity, realized page backing, and ABBA pair deltas.
5. If the repo should adopt the new capture, edit `crates/oxide-randomx/perf_results/full_features_authority_index_v10.json` intentionally in the same patch.
6. Move the prior authority path into `related_captures` when it remains useful as rerun, supporting, or superseded context.
7. Re-run `cargo run -p oxide-randomx --release --bin full_features_authority -- validate-index`.

Update rules:

- Do not replace an authority path without also preserving the reasoning in `authority_classification`, `related_captures`, or `rerun_stability`.
- Do not silently reinterpret older captures as if they already carried v10 metadata; the comparer infers host class from provenance when needed, but that is a compatibility bridge, not a retroactive schema rewrite.
- Keep index edits reviewable. Prefer changing only the relevant entry, notes, and related capture list in the same PR as the new capture.
