# oxide-randomx

A clean-room, production-grade RandomX implementation in Rust, targeting Monero defaults.

This crate is an internal OxideMiner component.
It is kept under `crates/oxide-randomx` inside the OxideMiner workspace, is
licensed with the rest of OxideMiner under `BSL-1.1`, and is not intended to be
published or consumed as a standalone public dependency.

This crate implements the full RandomX VM, dataset/cache generation, and hashing pipeline as specified in `docs/randomx-refs/specs.md`. No upstream RandomX source code was used.

## Quick Start

```rust,no_run
use oxide_randomx::{RandomXCache, RandomXConfig, RandomXFlags, RandomXVm};

# fn main() -> oxide_randomx::Result<()> {
let cfg = RandomXConfig::new();
let flags = RandomXFlags::default();
let cache = RandomXCache::new(b"my-key", &cfg)?;

// Light mode (lower memory, computed on-the-fly)
let mut vm = RandomXVm::new_light(cache, cfg, flags)?;
let hash = vm.hash(b"input data");
let hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
println!("Hash: {}", hex);
# Ok(())
# }
```

## OxideMiner Integration Profile

The v10 supported build contract is intentionally small and should be treated
as the OxideMiner-facing shipping vocabulary on current `HEAD`.
Workspace consumers should start with
[`docs/oxideminer-supported-build-contract.md`](docs/oxideminer-supported-build-contract.md)
and
[`docs/oxideminer-supported-build-contract.json`](docs/oxideminer-supported-build-contract.json)
instead of inferring the contract from the whole tree.

| Contract surface | What to build or ship | Notes |
| --- | --- | --- |
| `production` | `cargo build --release --features "jit jit-fastregs"` | supported throughput path |
| `validation` | `cargo build --release --features "jit jit-fastregs bench-instrument"` | same path plus instrumentation for CI, perf gates, and integration bring-up |
| supported runtime fallbacks | `jit-conservative`, then `interpreter` | keep the same prefetch and page-request policy |
| non-default experimental | `simd-blockio`, `simd-xor-paths`, `threaded-interp`, `superscalar-accel-proto` | not part of the shipped default path |

No `Intel` / `AMD` release split is supported on current `HEAD`.
The March 11, 2026 cross-host baseline keeps baseline `jit-fastregs` as the
best supported throughput path on AMD `23/8`, AMD `23/113`, Intel `6/45`, and
Intel `6/58`, so vendor-named binaries add release churn without evidence. If
future specialization is warranted, it should come from a narrow runtime host
classifier or deployment-local calibration / rollout policy, not vendor-specific
release artifacts.

Operationally, the current parent-facing contract remains conservative and
unchanged by the latest integrated `ff_*` sweep:

- production profile: build with `--features "jit jit-fastregs"` on JIT-capable
  x86_64 targets, request `jit=true` and `jit_fast_regs=true` at runtime, keep
  the default prefetch mapping, and treat large pages / Linux 1GB huge pages as
  explicit request knobs verified from emitted telemetry
- validation profile: build with
  `--features "jit jit-fastregs bench-instrument"` for CI, perf gates,
  telemetry/schema checks, and parent bring-up
- supported fallbacks: conservative JIT (`jit=true`, `jit_fast_regs=false`),
  then interpreter (`jit=false`)
- supported optional control: host-local prefetch calibration
- experimental or parked and off by default:
  `simd-blockio`, `simd-xor-paths`, `threaded-interp`,
  `superscalar-accel-proto`

Current authority chain:

- parent-facing profile: `docs/oxideminer-integration-profile.md`
- lifecycle harness: `docs/oxideminer-integration-harness.md`
- supported-path baseline authority:
  `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
- integrated feature-interaction authority:
  `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`
- indexed full-features host set:
  `perf_results/full_features_authority_index_v9.json`

Lifecycle harness example:

```bash
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode light --runtime-profile jit-fastregs
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode fast --runtime-profile jit-fastregs
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode both --runtime-profile jit-conservative --format json
cargo run --release --example oxideminer_integration --features "jit jit-fastregs bench-instrument" -- --mode both --runtime-profile interpreter --format json
```

The harness accepts only supported runtime profiles:
`interpreter`, `jit-conservative`, and `jit-fastregs`.
It emits a stable `report_version`, a top-level `build_contract`, per-session
requested and effective flags, explicit `lifecycle.jit` state, explicit
`page_backing.*.request` versus `page_backing.*.realized` objects, and
`rekey.parity.matches` so parent consumers can validate the supported lifecycle
without reading crate internals.

The GitHub-hosted workspace CI stays narrower than the lab authority set: the
mandatory perf gate enforces only `light_interp`, `light_jit_conservative`, and
`fast_jit_fastregs` on `ubuntu-latest`, while a separate validation-build Light
`jit-fastregs` smoke of `examples/oxideminer_integration.rs` protects the
supported validation build and emitted report shape. Those CI fixtures and
smokes are workspace regression guardrails, not AMD/Intel host authority and
not a replacement for broader OxideMiner parent validation on real hosts.

## Features

| Feature            | Description                                                                                                |
| ------------------ | ---------------------------------------------------------------------------------------------------------- |
| `jit`              | Supported x86_64 JIT backend for the conservative parent fallback path                                     |
| `jit-fastregs`     | Supported higher-throughput JIT variant for the current parent default path (requires `jit`)               |
| `bench-instrument` | Validation-build instrumentation for CI, perf gates, and parent bring-up                                   |
| `simd-blockio`     | Experimental AVX2 scratchpad block I/O (CPU-conditional; validate locally before enabling)                 |
| `simd-xor-paths`   | Experimental AVX2 XOR finish-path prototype (opt-in follow-up to `simd-blockio`)                           |
| `superscalar-accel-proto` | Parked experimental superscalar research prototype; not a near-promotion candidate                |
| `threaded-interp`  | Closed negative result; parked experimental threaded dispatch (opt-in via `OXIDE_RANDOMX_THREADED_INTERP=1`) |
| `fast-decode`      | Optimized instruction decoding (enabled by default)                                                        |
| `unsafe-config`    | Expert `RandomXConfigBuilder` for non-default parameters                                                   |

## Supported-Path Disposition Matrix

`Parent default state` below means the recommended OxideMiner-facing default,
not the raw library constructor defaults.

| Feature family | Current status | Parent default state | Current authority |
| --- | --- | --- | --- |
| Interpreter | Supported reference / lowest-risk fallback | Fallback only | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` |
| Conservative JIT | Supported performance fallback | Fallback when fast-regs is unavailable or intentionally disabled | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` |
| Baseline `jit-fastregs` | Supported recommended throughput path | Recommended default on JIT-capable x86_64 parents | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` |
| Large pages / Linux 1GB request semantics | Supported control-plane behavior; verify realized backing | Explicit request, best-effort outcome | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`, `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`, `docs/perf.md` |
| Emitted perf / allocation / prefetch telemetry | Supported observability surface | On in supported harness/examples when built with `bench-instrument` | `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`, `docs/oxideminer-integration-harness.md` |
| Host-local prefetch calibration | Supported optional host-local override | Off by default; opt-in per host | `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`, `docs/oxideminer-integration-profile.md` |
| `simd-blockio` | Experimental, CPU-conditional | Off by default | `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`, `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md` |
| `simd-xor-paths` | Experimental follow-up; exploratory direct A/B only | Off by default | `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`, `perf_results/AMD/P3_3_simd_xor_paths_disposition_2026-02-15.md` (historical exploratory base) |
| `threaded-interp` | Closed negative result; parked experimental | Off by default; runtime-gated for investigation only | `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`, `perf_results/AMD/P0_2_regression_memo_2026-02-07.md` (historical regression base) |
| `superscalar-accel-proto` | Parked experimental research lane | Off by default; feature-gated only | `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`, `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md` |

Notes:

- `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md` remains
  the default-path authority.
- `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md` is the
  current integrated feature-interaction authority. It keeps baseline
  `jit-fastregs` as the supported path, marks AMD `23/113` Windows as
  supporting-only, and treats matrix-only "best config" tables as supporting
  context rather than policy authority.
- AMD `23/113` Windows remains supporting integrated evidence with rerun-stability
  caveats, not clean-equivalent authority.

## Light vs Fast Mode

| Mode      | Memory   | Speed  | Use Case                        |
| --------- | -------- | ------ | ------------------------------- |
| **Light** | ~256 MiB | Slower | Memory-constrained environments |
| **Fast**  | ~2+ GiB  | Faster | Production mining/verification  |

```rust,no_run
use oxide_randomx::{RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm};

# fn main() -> oxide_randomx::Result<()> {
let cfg = RandomXConfig::new();
let flags = RandomXFlags::default();

// Light mode - compute dataset items on-the-fly
let cache = RandomXCache::new(b"my-key", &cfg)?;
let vm = RandomXVm::new_light(cache, cfg.clone(), flags.clone())?;

// Fast mode - pre-allocate full dataset
let cache = RandomXCache::new(b"my-key", &cfg)?;
let num_threads = 1usize;
let dataset = RandomXDataset::new(&cache, &cfg, num_threads)?;
let vm = RandomXVm::new_fast(cache, dataset, cfg, flags)?;
# Ok(())
# }
```

For parent integrations that need multiple Fast-mode worker VMs over one
dataset, build the cache and dataset once, wrap them in `Arc`, and create one
VM per worker with `RandomXVm::new_fast_shared(...)`:

```rust,no_run
use std::sync::Arc;

use oxide_randomx::{
    DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm,
};

# fn main() -> oxide_randomx::Result<()> {
let cfg = RandomXConfig::new();
let flags = RandomXFlags::default();
let cache = Arc::new(RandomXCache::new(b"my-key", &cfg)?);
let dataset = Arc::new(RandomXDataset::new_with_options(
    &cache,
    &cfg,
    DatasetInitOptions::new(1),
)?);

let worker_vm = RandomXVm::new_fast_shared(
    Arc::clone(&cache),
    Arc::clone(&dataset),
    cfg,
    flags,
)?;
# let _ = worker_vm;
# Ok(())
# }
```

## JIT Compilation

The JIT provides substantial speedup on x86_64 platforms. On current `HEAD`,
the baseline `jit-fastregs` path is the recommended parent default on the
captured host set, while conservative JIT remains the supported fallback:

```rust,no_run
use oxide_randomx::{RandomXCache, RandomXConfig, RandomXFlags, RandomXVm};

# fn main() -> oxide_randomx::Result<()> {
// Build with: cargo build --features jit
# #[cfg(feature = "jit")]
# {
let mut flags = RandomXFlags::default();
flags.jit = true;
flags.jit_fast_regs = true; // requires --features jit-fastregs

let cfg = RandomXConfig::new();
let cache = RandomXCache::new(b"my-key", &cfg)?;
let mut vm = RandomXVm::new_light(cache, cfg, flags)?;
assert!(vm.is_jit_active()); // verify JIT is running
# }
# Ok(())
# }
```

**JIT characteristics:**

- W^X memory safety (never RWX)
- 256-entry program cache per VM
- Automatic fallback to interpreter if unsupported
- Fast-regs variant maps registers to host CPU registers

## Runtime Flags

```rust
pub struct RandomXFlags {
    pub aes_ni: bool,                     // Hardware AES (auto-detected on x86_64)
    pub soft_aes: bool,                   // Force software AES
    pub prefetch: bool,                   // Enable dataset prefetching
    pub prefetch_distance: u8,            // 0-8 cachelines ahead (default: 2)
    pub prefetch_auto_tune: bool,         // Use CPU-family tuned prefetch distance
    pub scratchpad_prefetch_distance: u8, // 0-32 cachelines ahead (default: 0)
    pub large_pages_plumbing: bool,       // Large pages for scratchpad
    pub use_1gb_pages: bool,              // 1GB huge-page request knob (Linux)
    pub jit: bool,                        // Enable JIT (requires feature)
    pub jit_fast_regs: bool,              // Fast-regs JIT (requires feature)
}
```

### Environment-driven flags (`RandomXFlags::from_env()`)

`RandomXFlags::from_env()` lets applications apply runtime tuning from environment variables:

```rust,no_run
use oxide_randomx::RandomXFlags;

let mut flags = RandomXFlags::from_env();

// Optional: override specific fields after env parsing.
#[cfg(feature = "jit")]
{
    flags.jit = true;
    flags.jit_fast_regs = true;
}
```

Supported variables parsed by `from_env()`:

- `OXIDE_RANDOMX_PREFETCH_DISTANCE` (`0..=8`)
- `OXIDE_RANDOMX_PREFETCH_AUTO` (enable CPU-family auto-tune)
- `OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE` (`0..=32`)
- `OXIDE_RANDOMX_HUGE_1G` (sets `use_1gb_pages`)

Unset variables keep defaults. Out-of-range numeric values are ignored.

### Threaded Interpreter Policy (Parked Experimental)

`threaded-interp` is a closed negative result and remains parked experimental.

- Default behavior is **off**, even when compiled with `--features threaded-interp`.
- Runtime gate: set `OXIDE_RANDOMX_THREADED_INTERP=1` to enable for investigation.
- Current disposition: closed negative result on the current host set; not
  recommended for production runs.
- The integrated `ff_*` memo reinforces that every measured host regressed in
  Light interpreter mode, so the branch stays parked rather than "optional by
  default."
- Current rationale is documented in:
  - `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`
  - Historical regression base: `perf_results/AMD/P0_2_regression_memo_2026-02-07.md`
  - `perf_results/bench_apples_light_threaded_on_p0_2.csv`

### SIMD Block I/O Policy (Experimental, CPU-Conditional)

`simd-blockio` is experimental and remains opt-in.

- Default behavior is off.
- Current guidance is CPU-conditional: run host-local A/B before enabling.
- Intel Family 6 Model 45 (Xeon E5-2690 class) is now runtime-disabled by default even when built with `simd-blockio`.
- The March 11, 2026 current-`HEAD` cross-host baseline refresh did not promote `simd-blockio` into the supported parent path.
- The integrated `ff_*` memo also produced no promotive ABBA signal for guarded
  or forced `simd-blockio`, so matrix sweeps do not change the default policy.
- Measured host coverage now includes AMD `23/8`, AMD `23/113`, Intel `6/45`,
  and Intel `6/58`, but the policy remains "experimental and local-validation
  only."
- Local override for investigation only: `OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE=1`.
- Current disposition and evidence are documented in:
  - Primary policy memo: `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`
  - Current-`HEAD` cross-host baseline authority: `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
  - Integrated feature-interaction memo: `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`
  - Clean Intel duplicate-family confirmation: `perf_results/Intel/v6_10_simd_blockio_intel_family_evidence_2026-03-01.md`
  - Clean AMD duplicate-family confirmation: `perf_results/AMD/v6_11_simd_blockio_amd_family_evidence_2026-03-01.md`
  - Historical policy base: `perf_results/Intel/P1_2_simd_blockio_cross_cpu_disposition_2026-02-16.md`

### SIMD XOR Paths Policy (Experimental Follow-up)

`simd-xor-paths` is an opt-in follow-up prototype, remains experimental, and
still has only exploratory direct A/B evidence.

- Default behavior is off.
- Intended usage is with `simd-blockio` (`--features "simd-blockio simd-xor-paths"`).
- Local override for investigation only: `OXIDE_RANDOMX_SIMD_XOR_PATHS_FORCE=1`.
- Local runtime disable override: `OXIDE_RANDOMX_SIMD_XOR_PATHS_DISABLE=1`.
- Current disposition is **keep experimental** (no default-on recommendation in this pass).
- The integrated `ff_*` memo found only noise relative to forced
  `simd-blockio`, so there is still no parent-default case.
- Current rationale/evidence are documented in:
  - `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`
  - Historical exploratory base: `perf_results/AMD/P3_3_simd_xor_paths_disposition_2026-02-15.md`
  - `perf_results/v4_11_simd_xor_analysis_20260215_114322.json`

### Superscalar Accel Prototype Policy (Experimental)

`superscalar-accel-proto` remains experimental and runtime-disabled by default.

- Default behavior is off.
- Local override for investigation only: `OXIDE_RANDOMX_SUPERSCALAR_ACCEL_PROTO_FORCE=1`.
- Local runtime disable override: `OXIDE_RANDOMX_SUPERSCALAR_ACCEL_PROTO_DISABLE=1`.
- Current status is a parked research lane, not a narrow supported opt-in
  candidate.
- Clean Intel Linux and AMD Linux hosts still show real Light-mode upside, but
  AMD Windows remains mixed or rerun-sensitive, and Fast mode is still not
  promotive overall.
- Intended usage is evidence collection only; keep it feature-gated and out of
  the supported parent default path.
- Keep the scalar reference path and use
  `superscalar_hash_harness --impl scalar` for differential validation.
- Reopen only after exact correctness, repeated same-SHA stability on the
  measured hosts, material Light improvement on clean AMD and Intel authority
  hosts, no practical Fast regressions, and bounded disagreement between
  isolated and integrated behavior.
- Do not treat matrix-only "best config" rankings as policy authority for this
  branch.
- Current rationale/evidence are documented in:
  - `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`
  - `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`
  - `perf_results/AMD/P2_amd_fam23_mod113_stability_memo_2026-03-26.md`

## Large Pages

Large pages reduce TLB misses for improved performance. Support is best-effort with automatic fallback.

```rust,no_run
use oxide_randomx::{DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags};

# fn main() -> oxide_randomx::Result<()> {
// Scratchpad large pages
let flags = RandomXFlags {
    large_pages_plumbing: true,
    ..Default::default()
};

// Dataset large pages
let cfg = RandomXConfig::new();
let cache = RandomXCache::new(b"my-key", &cfg)?;
let num_threads = 1usize;
let opts = DatasetInitOptions::new(num_threads).with_large_pages(true);
let dataset = RandomXDataset::new_with_options(&cache, &cfg, opts)?;
# Ok(())
# }
```

**Platform requirements:**

- **Windows**: SeLockMemoryPrivilege (runtime attempts to enable)
- **Linux**: `mmap(MAP_HUGETLB)` or THP via `madvise(MADV_HUGEPAGE)`

### 1GB Huge-Page Request (Linux only)

Set `OXIDE_RANDOMX_HUGE_1G=1` to request 1GB huge pages. For `perf_harness`,
use it together with `--large-pages on`:

```bash
OXIDE_RANDOMX_FAST_BENCH=1 OXIDE_RANDOMX_HUGE_1G=1 cargo run --release --example perf_harness --features "bench-instrument" -- \
  --mode fast --jit off --iters 50 --warmup 5 --large-pages on --format csv --out out_1g.csv
```

Do not treat request flags as success. Verify allocation outcomes from emitted fields:

- `large_pages_1gb_requested`
- `large_pages_1gb_dataset`
- `large_pages_1gb_scratchpad`

Interpretation:

- `requested=true` and `dataset=true`: dataset actually got 1GB pages.
- `requested=true` and `dataset=false`: explicit fallback (typically to 2MB huge pages).
- `scratchpad=true/false`: scratchpad outcome is independent and must be checked separately.

Typical prerequisites for 1GB success:

- Linux boot params include `hugepagesz=1G` and enough reserved 1GB pages.
- Sufficient free contiguous memory if allocating at runtime.
- Privileges needed to change `/sys/kernel/mm/hugepages/.../nr_hugepages`.

Current reproducible evidence and troubleshooting are documented in:

- `docs/perf.md`
- `docs/perf-results-intel.md`
- `perf_results/Intel/P3_5_1gb_hugepage_success_fallback_intel_2026-02-23.md`

## Threading and Affinity

Dataset build threads can be named and pinned to cores:

```rust,no_run
use oxide_randomx::{AffinitySpec, DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset};

# fn main() -> oxide_randomx::Result<()> {
let opts = DatasetInitOptions::new(8)
    .with_thread_names(true)
    .with_affinity(AffinitySpec::Compact); // or Spread, Explicit(vec![0,2,4])

let cfg = RandomXConfig::new();
let cache = RandomXCache::new(b"my-key", &cfg)?;
let dataset = RandomXDataset::new_with_options(&cache, &cfg, opts)?;
# Ok(())
# }
```

## Benchmarking

Comprehensive benchmark scripts are included for feature comparison:

```powershell
# Windows PowerShell
.\bench_apples.ps1 -Mode fast -Iters 200 -Repeats 5
.\bench_apples.ps1 -QuickTest  # Quick sanity check
```

```bash
# Linux/macOS
./bench_apples.sh --mode fast --iters 200 --repeats 5
./bench_apples.sh --quick  # Quick sanity check
```

The scripts test all feature combinations and produce comparison tables:

| Configuration                                  | Features Tested                                       |
| ---------------------------------------------- | ----------------------------------------------------- |
| Baseline                                       | Interpreter only                                      |
| JIT Conservative                               | `jit`                                                 |
| JIT + Fast-Regs                                | `jit jit-fastregs`                                    |
| SIMD Block I/O (experimental, CPU-conditional) | `simd-blockio`                                        |
| SIMD XOR Paths (experimental follow-up)        | `simd-blockio simd-xor-paths`                         |
| Superscalar Accel Prototype                    | `superscalar-accel-proto`                             |
| Threaded Interpreter (parked experimental)     | `threaded-interp` + `OXIDE_RANDOMX_THREADED_INTERP=1` |
| Full Features                                  | All features combined                                 |

Those matrices are research surfaces, not parent-policy authority. Use the
supported-path disposition matrix above plus the cited authority memos when
deciding what should be on by default.

## Examples

```bash
# CLI hashing tool
cargo run --example rxsum -- --key-hex 00 --input-hex 00 --mode light

# Benchmarking harness
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example bench \
    --features "jit jit-fastregs bench-instrument" -- \
    --mode fast --jit on --jit-fast-regs on --iters 100 --report

# Performance harness with supported-path CSV output
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- \
    --mode light --jit on --jit-fast-regs on --iters 20 --warmup 2 --format csv
```

## Testing

```bash
# Standard test suite
cargo test

# With JIT tests
cargo test --features jit

# Full dataset test (2+ GiB allocation)
OXIDE_RANDOMX_FULL_TESTS=1 cargo test --features jit -- --ignored

# Memory safety validation
cargo miri test  # JIT paths skipped under Miri
```

## Performance Instrumentation

Build with `--features bench-instrument` for detailed metrics:

```rust,no_run
use oxide_randomx::{RandomXCache, RandomXConfig, RandomXFlags, RandomXVm};

# fn main() -> oxide_randomx::Result<()> {
let cfg = RandomXConfig::new();
let flags = RandomXFlags::default();
let cache = RandomXCache::new(b"my-key", &cfg)?;
let mut vm = RandomXVm::new_light(cache, cfg, flags)?;

let stats = vm.perf_stats();
println!("Hashes: {}", stats.hashes);
println!("JIT exec time: {} ns", stats.vm_exec_ns_jit);
println!("Scratchpad reads: {} bytes", stats.scratchpad_read_bytes);
# Ok(())
# }
```

## Documentation

| Document                                                 | Description                                                     |
| -------------------------------------------------------- | --------------------------------------------------------------- |
| [dev/ROADMAPv9.md](dev/ROADMAPv9.md)                     | Canonical v9 roadmap for the supported path and authority workflow |
| [docs/oxideminer-supported-build-contract.md](docs/oxideminer-supported-build-contract.md) | Cross-repo handoff package for OxideMiner-style parent integrations |
| [docs/oxideminer-integration-profile.md](docs/oxideminer-integration-profile.md) | Narrow parent-facing supported profile and fallback guidance |
| [docs/oxideminer-integration-harness.md](docs/oxideminer-integration-harness.md) | Public-API lifecycle harness for OxideMiner-style integration |
| [docs/perf.md](docs/perf.md)                             | Performance measurement methodology and command recipes         |
| [docs/perf-results-amd.md](docs/perf-results-amd.md)     | AMD host baseline matrix and evidence-backed disposition index  |
| [docs/perf-results-intel.md](docs/perf-results-intel.md) | Intel host baseline matrix and evidence-backed disposition index |
| [perf_results/P2_4_integrated_full_features_authority_2026-03-26.md](perf_results/P2_4_integrated_full_features_authority_2026-03-26.md) | Current integrated full-features authority memo for feature interactions and host classification |
| [perf_results/PERF_COMP.md](perf_results/PERF_COMP.md)   | Current cross-machine supported-path comparison snapshot        |
| [docs/jit.md](docs/jit.md)                               | JIT design, calling convention, W^X strategy                    |
| [docs/randomx-refs/specs.md](docs/randomx-refs/specs.md) | Full RandomX algorithm specification                            |

## Platform Support

| Platform       | Interpreter | JIT | Large Pages           |
| -------------- | ----------- | --- | --------------------- |
| x86_64 Windows | Yes         | Yes | SeLockMemoryPrivilege |
| x86_64 Linux   | Yes         | Yes | MAP_HUGETLB / THP     |
| x86_64 macOS   | Yes         | Yes | Best-effort           |
| Other          | Yes         | No  | Varies                |

## License

See the LICENSE file in the repository root for details.
