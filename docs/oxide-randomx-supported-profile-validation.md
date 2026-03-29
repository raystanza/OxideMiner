# OxideMiner Supported `oxide-randomx` Host Validation

This runbook records how to validate the supported `oxide-randomx` integration
profile from the `OxideMiner` repo without turning operational host differences
into separate vendor products.

The shared contract still stays one supported profile:

- production build: `jit + jit-fastregs`
- validation build: `jit + jit-fastregs + bench-instrument`
- parent-facing runtime selector: `jit-fastregs`
- supported runtime fallbacks: `jit-conservative`, `interpreter`
- no `Intel` / `AMD` release split

## Contract Inputs Used

Run this from the `OxideMiner` repo root.
Use the internal `crates/oxide-randomx` workspace member as the contract source
of truth.

This validation pass used:

- `crates/oxide-randomx/docs/oxideminer-supported-build-contract.md`
- `crates/oxide-randomx/docs/oxideminer-supported-build-contract.json`
- `crates/oxide-randomx/docs/oxideminer-integration-harness.md`
- internal workspace member `crates/oxide-randomx`

## Host Matrix

| Host | OS | CPU | Shared profile used | Light smoke | Fast smoke | JIT observation | Page-backing observation | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| available | Windows | AMD Ryzen 5 2600, 6C/12T | same `OxideMiner` supported profile | pass | bounded fast smoke pass; full-dataset host run not completed within 10-minute tool budget | pass | pass | 2 MiB large pages realized for Light scratchpad when explicitly requested |
| unavailable | not available in this run | Intel host not available | same commands should be reused unchanged | not run | not run | not run | not run | do not claim Intel validation until this row is filled with a real host result |

This document intentionally does **not** infer vendor policy from one-host
observations.

## Repeatable Validation Steps

### 1. Parent repo validation

Run the standard parent tests first:

```bash
cargo test
```

Run the parent Light smoke with the supported profile:

```bash
cargo run -p oxide-miner -- --benchmark --threads 1 --batch-size 64 --randomx-mode light --randomx-runtime-profile jit-fastregs
```

Run the bounded parent Fast smoke:

```bash
cargo test -p oxide-core --test randomx_supported_profile_smoke
```

That targeted test validates the same supported integration shape and exercises
the shared Fast-mode parent API without requiring a full-dataset benchmark on
every host.

### 2. Internal harness observation

From the `OxideMiner` repo root, use the internal `oxide-randomx` workspace
member and the supported validation build to capture realized runtime facts on
the same host:

```bash
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --threads 1 --format json
```

To capture requested versus realized large-page behavior on the same host:

```bash
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --threads 1 --large-pages on --format json
```

If the host and time budget allow a full-dataset Fast run, use the same
contract path unchanged:

```bash
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode fast --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --threads 1 --format json
```

### 3. What to record

Record these fields from the harness JSON:

- `sessions[].lifecycle.effective_runtime_profile`
- `sessions[].lifecycle.jit.active`
- `sessions[].page_backing.scratchpad.realization`
- `sessions[].page_backing.dataset.realization`
- `sessions[].page_backing.*.realized.huge_page_size`
- `sessions[].rekey.parity.matches`

## Current Observations

Current available host:

- OS: Windows
- CPU vendor: `AuthenticAMD`
- CPU model: `AMD Ryzen 5 2600 Six-Core Processor`
- logical processors: `12`

Observed results on this host:

- `cargo test` passed in `OxideMiner`.
- The parent Light smoke completed successfully with the supported profile.
- The bounded parent Fast smoke passed through `randomx_supported_profile_smoke`.
- The internal `oxide-randomx` harness in Light mode reported:
  `effective_runtime_profile = jit-fastregs`,
  `lifecycle.jit.active = true`,
  `page_backing.scratchpad.realization = not_requested`,
  and `page_backing.scratchpad.realized.description = standard 4KB pages`
  when large pages were not requested.
- The internal `oxide-randomx` harness in Light mode with `--large-pages on` reported:
  `page_backing.scratchpad.realization = realized_2mb_large_pages`
  and `page_backing.scratchpad.realized.huge_page_size = 2097152`.
- `sessions[].rekey.parity.matches = true` in the Light harness observations.
- `use_1gb_pages` was not exercised in this run because the available host is
  Windows and that request is Linux-only for the Fast-mode dataset.
- A full-dataset Fast harness run did not complete within a 10-minute tool
  budget on this host. Treat that as an operational timing limitation for this
  environment, not as evidence for a vendor-specific product split.

## Operational Notes

- On Windows, large-page realization depends on host privileges and page
  availability. Use `scripts/windows/Enable-LargePages.ps1` and sign out or
  reboot as required by the host policy.
- On Linux, `use_1gb_pages` should only be validated on hosts that actually
  reserve 1 GiB huge pages.
- Reuse the same parent commands on AMD and Intel hosts. If outcomes differ,
  record them as operator notes unless they expose a real supported-path
  blocker.
- Do not fork release binaries by vendor based only on operational validation
  notes.
