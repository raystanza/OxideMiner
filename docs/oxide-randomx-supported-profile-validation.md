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

Run this from the `OxideMiner` repo root and verify that both `pwd` and
`cargo metadata --no-deps --format-version 1` point at the same workspace root.
Use the internal `crates/oxide-randomx` workspace member as the contract source
of truth and treat this parent doc as the repeatable host-validation runbook.

This validation pass on `2026-03-29` used:

- `crates/oxide-randomx/docs/oxideminer-supported-build-contract.md`
- `crates/oxide-randomx/docs/oxideminer-supported-build-contract.json`
- `crates/oxide-randomx/docs/oxideminer-integration-harness.md`
- parent-side runbook `docs/oxide-randomx-supported-profile-validation.md`
- internal workspace member `crates/oxide-randomx`

## Host Matrix

| Host | Date | OS | CPU | Shared profile used | Light smoke | Fast smoke | JIT observation | Page-backing observation | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| available | 2026-03-29 | Linux 6.8.0-106-generic | Intel Xeon E5-2690 0, 2 sockets, 16 cores / 32 threads | same `OxideMiner` supported profile | pass | pass | pass | pass | parent Fast smoke must include `--features randomx`; Light `--large-pages on` realized 2 MiB scratchpad pages; Fast `--use-1gb-pages on` realized 1 GiB dataset pages and 2 MiB scratchpad pages in the primary session |
| unavailable | 2026-03-29 | AMD host not available in this run | not available in this environment | same commands should be reused unchanged | not run | not run | not run | not run | do not claim cross-vendor validation until the same commands are run on a real AMD host |

This document intentionally does **not** infer vendor policy from one-host
observations.

## Repeatable Validation Steps

### 1. Verify the active workspace root and contract inputs

From the active terminal, confirm the parent repo root first:

```bash
pwd
cargo metadata --no-deps --format-version 1 | jq -r '.workspace_root'
```

Then confirm the contract artifacts being consumed by this parent run:

```bash
ls crates/oxide-randomx/docs/oxideminer-supported-build-contract.md \
   crates/oxide-randomx/docs/oxideminer-supported-build-contract.json \
   crates/oxide-randomx/docs/oxideminer-integration-harness.md \
   docs/oxide-randomx-supported-profile-validation.md
```

### 2. Parent repo validation

Run the standard parent tests first:

```bash
cargo test
```

Capture the parent Light smoke with the supported profile:

```bash
OUT_DIR="${OUT_DIR:-/tmp/oxide-host-validation}"
mkdir -p "$OUT_DIR"
RUST_LOG=info cargo run -p oxide-miner -- --benchmark --threads 1 --batch-size 64 --randomx-mode light --randomx-runtime-profile jit-fastregs --debug >"$OUT_DIR/parent-light-benchmark.log" 2>&1
rg "RandomX benchmark setup|RandomX benchmark result" "$OUT_DIR/parent-light-benchmark.log"
```

Run the bounded parent Fast smoke:

```bash
cargo test -p oxide-core --features randomx --test randomx_supported_profile_smoke
```

That targeted test validates the same supported integration shape and exercises
the shared Fast-mode parent API without requiring a full-dataset benchmark on
every host.

Important:

- `cargo test -p oxide-core --test randomx_supported_profile_smoke` is not
  sufficient on its own because the test file is gated behind
  `#![cfg(feature = "randomx")]`; without `--features randomx` it becomes a
  zero-test false pass.
- `oxide-miner --benchmark` is the parent Light smoke and throughput check, but
  it exits before the HTTP API is useful. Use a normal mining or solo session
  when you want the parent's `/api/stats` and `/metrics` surfaces.

### 3. Internal harness observation from the same parent workspace

From the `OxideMiner` repo root, use the internal `oxide-randomx` workspace
member and the supported validation build to capture realized runtime facts on
the same host:

```bash
OUT_DIR="${OUT_DIR:-/tmp/oxide-host-validation}"
mkdir -p "$OUT_DIR"
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --threads 1 --format json >"$OUT_DIR/light.json"
```

To capture requested versus realized large-page behavior on the same host:

```bash
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --threads 1 --large-pages on --format json >"$OUT_DIR/light-large-pages.json"
```

Run the full-dataset Fast harness with the same contract path unchanged:

```bash
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode fast --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --format json >"$OUT_DIR/fast.json"
```

Linux-only 1 GiB page request observation uses the same supported profile and
records the realized dataset backing instead of assuming the request succeeded:

```bash
cargo run -p oxide-randomx --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode fast --runtime-profile jit-fastregs --warmup-rounds 0 --steady-rounds 1 --use-1gb-pages on --format json >"$OUT_DIR/fast-1gb.json"
```

Notes:

- Keep `--threads 1` for the bounded Light smoke.
- Do **not** force `--threads 1` for the full Fast harness unless you are
  intentionally paying a longer wall-clock budget. Omitting `--threads` lets
  the harness use host parallelism and keeps the Fast smoke more practical on
  older CPUs without changing the supported profile.

### 4. What to record

Record these fields from the harness JSON:

- `sessions[].lifecycle.effective_runtime_profile`
- `sessions[].lifecycle.jit.active`
- `sessions[].page_backing.scratchpad.realization`
- `sessions[].page_backing.dataset.realization`
- `sessions[].page_backing.*.realized.huge_page_size`
- `sessions[].rekey.parity.matches`

From a normal parent mining or solo run, record the parent observability fields
that operators can inspect without opening the internal harness:

- log line `RandomX runtime realized`
- `/api/stats` -> `.randomx.requested` and `.randomx.realized`
- `/metrics` -> `oxide_randomx_requested_info`
- `/metrics` -> `oxide_randomx_runtime_info`
- `/metrics` -> `oxide_randomx_scratchpad_large_pages`
- `/metrics` -> `oxide_randomx_scratchpad_huge_page_size_bytes`
- `/metrics` -> `oxide_randomx_dataset_large_pages`
- `/metrics` -> `oxide_randomx_dataset_huge_page_size_bytes`

## Current Observations

Current available host on `2026-03-29`:

- OS: Linux `6.8.0-106-generic`
- CPU vendor: `GenuineIntel`
- CPU model: `Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz`
- logical processors: `32`
- NUMA nodes: `2`
- `/proc/meminfo` reported `HugePages_Total=2048`, `HugePages_Free=2048`,
  `Hugepagesize=2048 kB`
- `/sys/kernel/mm/transparent_hugepage/enabled` reported `always [madvise] never`
- `/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages` reported `4`

Observed results on this host:

- `cargo test` passed in `OxideMiner`.
- The parent Light smoke completed successfully with the supported profile and
  the captured benchmark log reported:
  `randomx_mode = light`,
  `randomx_runtime_profile = jit-fastregs`,
  `large_pages_requested = false`,
  `large_pages_predicted_supported = true`,
  and `RandomX benchmark result (approx.): 3.80 H/s over 20s`.
- The bounded parent Fast smoke passed through
  `cargo test -p oxide-core --features randomx --test randomx_supported_profile_smoke`.
- The older parent Fast smoke command without `--features randomx` ran zero
  tests on this host and should not be reused as evidence.
- The internal `oxide-randomx` harness in Light mode reported:
  `effective_runtime_profile = jit-fastregs`,
  `lifecycle.jit.active = true`,
  `page_backing.scratchpad.realization = not_requested`,
  and `page_backing.scratchpad.realized.description = standard 4KB pages`
  when large pages were not requested.
- The internal `oxide-randomx` harness in Light mode with `--large-pages on` reported:
  `page_backing.scratchpad.realization = realized_2mb_large_pages`
  and `page_backing.scratchpad.realized.huge_page_size = 2097152`.
- The internal `oxide-randomx` harness in Fast mode without page requests reported:
  `effective_runtime_profile = jit-fastregs`,
  `lifecycle.jit.active = true`,
  `page_backing.scratchpad.realization = not_requested`,
  and `page_backing.dataset.realization = not_requested`.
- The internal `oxide-randomx` harness in Fast mode with `--use-1gb-pages on`
  reported:
  `page_backing.dataset.realization = realized_1gb_large_pages`,
  `page_backing.dataset.realized.huge_page_size = 1073741824`,
  `page_backing.scratchpad.realization = realized_2mb_large_pages`,
  and `page_backing.scratchpad.realized.huge_page_size = 2097152`.
- `sessions[].rekey.parity.matches = true` in the Light and Fast harness
  observations captured during this run.
- During the Fast `--use-1gb-pages on` harness run, stderr also emitted a
  1 GiB fallback advisory during the parity-rebuild path because the harness
  briefly allocates another Fast dataset for the rebuild comparison. Treat that
  as an operational caveat for the validation workflow, not as evidence that
  the primary Fast session stopped using the shared supported profile.
- No AMD host was reachable from this environment during this validation pass,
  so this document does not claim real-host AMD validation yet.

## Operational Notes

- Reuse the same parent commands and the same supported profile on AMD and
  Intel hosts. Operational notes may differ by host, but they do not create a
  second product contract on their own.
- On Linux, large-page realization depends on host privileges, reserved huge
  pages, and host-local policy. Use `scripts/linux/enable_hugepages.sh` with
  `sudo/root`, then log out and back in so group membership changes take effect.
- On Windows, large-page realization depends on `SeLockMemoryPrivilege` and page
  availability. Use `scripts/windows/Enable-LargePages.ps1` and sign out or
  reboot as required by the host policy.
- `use_1gb_pages` is Linux-only and should be validated only on hosts that
  actually reserve 1 GiB huge pages. When the harness keeps
  `sessions[].rekey.parity.matches` enabled, its rebuild comparison may briefly
  need additional 1 GiB pages beyond the primary session.
- For the bounded Fast harness validation path, prefer the default harness
  thread count over `--threads 1`. That keeps the same supported profile while
  avoiding a needlessly long dataset-build phase on older hosts.
- For parent observability, the `oxide-miner` benchmark is a smoke command and
  throughput check. Use a normal mining or solo session when you need the
  parent's realized runtime state through `RandomX runtime realized`,
  `/api/stats`, and `/metrics`.
- Do not fork release binaries by vendor based only on operational validation
  notes.
