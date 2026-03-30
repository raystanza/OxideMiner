# Performance Results (Current Baselines + Historical Evidence Index)

This document is the canonical AMD-host performance-results summary for the repository.

- Measurement commands/output schema live in `docs/perf.md`.
- Planning/state disposition lives in `dev/ROADMAPv9.md`.
- Current supported-path baseline authority lives in `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`.
- Current in-tree integrated experimental-feature authority workflow lives in `docs/full-features-benchmark-v9-workflow.md`.
- Current in-tree integrated experimental-feature authority index lives in `perf_results/full_features_authority_index_v10.json`.
- Current superscalar feature disposition lives in `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`.
- Supported-path baseline snapshot lives in `perf_results/PERF_COMP.md`.
- Raw evidence and decision memos live in `perf_results/`.

## Capture Date

- v8 AMD current-`HEAD` baseline refresh capture timestamp (`amd_fam23_mod8`): `2026-03-08 22:41:08` (`20260308_224108`)
- v8 AMD current-`HEAD` baseline refresh capture timestamp (`amd_fam23_mod113`, packaged host): `2026-03-09 21:38:51` (`20260309_213850`)
- Current-head cross-host authority memo date: `2026-03-11`
- Baseline matrix capture timestamp: `2026-02-17 17:58:00` (`20260217_175800`)
- Clean prefetch refresh capture timestamp: `2026-02-28 13:11:13` (`20260228_131113`)
- Clean prefetch cross-host decision date: `2026-03-01`
- AMD Windows 1GB limitation capture timestamp: `2026-03-01 00:55:44` (`20260301_005544`)
- AMD Linux 1GB success/fallback rerun timestamp: `2026-03-07 12:55:24` (`20260307_125524`)
- AMD novel-family `simd-blockio` evidence capture tag: `20260308_144058` (manifest ISO `2026-03-08T14:40:59-04:00`)
- AMD dispatch validation capture timestamp: `2026-03-01 11:03:02` (`20260301_110302`)
- AMD `jit-fastregs` guardrail rerun timestamp: `2026-03-01 14:31:49` (`20260301_143149`)
- AMD `simd-blockio` family evidence capture timestamp: `2026-03-01 22:59:16` (`20260301_225916`)
- AMD `v7.07` superscalar prototype rerun timestamp: `2026-03-06 17:22:52` (`20260306_172252`)
- AMD `v8.05` superscalar prototype capture timestamp (`amd_fam23_mod8`): `2026-03-11 18:18:26` (`20260311_181826`)
- AMD `v8.05` superscalar support capture timestamp (`amd_fam23_mod113`): `2026-03-12 17:07:48` (`20260312_170748`)
- Superscalar cross-host decision date: `2026-03-12`
- `simd-blockio` cross-host policy refresh date: `2026-03-08`

## v8.01 Current-HEAD Baseline Refresh (AMD `23/8`, Windows 11, 2026-03-08)

Primary artifacts:

- `perf_results/AMD/v8_01_current_head_baseline_amd_fam23_mod8_2026-03-08.md`
- `perf_results/AMD/v8_01_summary_amd_fam23_mod8_20260308_224108.json`
- `perf_results/AMD/v8_01_manifest_amd_fam23_mod8_20260308_224108.txt`
- `perf_results/AMD/v8_01_host_provenance_amd_fam23_mod8_20260308_224108.txt`
- `perf_results/AMD/v8_01_commands_amd_fam23_mod8_20260308_224108.log`
- `perf_results/AMD/v8_01_perf_index_amd_fam23_mod8_20260308_224108.csv`

Host/provenance:

- host tag: `amd_fam23_mod8`
- CPU: `AMD Ryzen 5 2600 Six-Core Processor`
- processor identifier: `AMD64 Family 23 Model 8 Stepping 2, AuthenticAMD`
- OS: `Microsoft Windows 11 Home` (`WindowsVersion=2009`, build `26200`)
- git SHA: `62801e2f63a4295a39a6b69df997ba0039a104eb`
- git short SHA: `62801e2`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- detached clean worktree: `c:\Users\jimsi\source\repos\raystanza\oxide-randomx-v8_01-amd-clean-20260308_224108`
- all six CSV authority rows report `git_dirty=false`

Locked runtime parameters:

- `iters=50`
- `warmup=5`
- `threads=12`
- `inputs=6`
- `large_pages_requested=false`
- `large_pages_1gb_requested=false`
- `thread_names=false`
- `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows.
- Fast rows used `OXIDE_RANDOMX_FAST_BENCH=1`.

Current-`HEAD` matrix (CSV authority):

| Mode | Configuration | Cargo Features | Runtime JIT Flags | `ns/hash` | `hashes/sec` | CSV Artifact | JSON Artifact |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| Light | Interpreter | `bench-instrument` | `--jit off` | `322,980,108` | `3.096` | `perf_results/AMD/v8_01_current_head_light_interp_amd_fam23_mod8_20260308_224108.csv` | `perf_results/AMD/v8_01_current_head_light_interp_amd_fam23_mod8_20260308_224108.json` |
| Light | JIT conservative | `jit bench-instrument` | `--jit on --jit-fast-regs off` | `258,700,470` | `3.865` | `perf_results/AMD/v8_01_current_head_light_jit_conservative_amd_fam23_mod8_20260308_224108.csv` | `perf_results/AMD/v8_01_current_head_light_jit_conservative_amd_fam23_mod8_20260308_224108.json` |
| Light | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `250,059,837` | `3.999` | `perf_results/AMD/v8_01_current_head_light_jit_fastregs_amd_fam23_mod8_20260308_224108.csv` | `perf_results/AMD/v8_01_current_head_light_jit_fastregs_amd_fam23_mod8_20260308_224108.json` |
| Fast | Interpreter | `bench-instrument` | `--jit off` | `67,410,248` | `14.835` | `perf_results/AMD/v8_01_current_head_fast_interp_amd_fam23_mod8_20260308_224108.csv` | `perf_results/AMD/v8_01_current_head_fast_interp_amd_fam23_mod8_20260308_224108.json` |
| Fast | JIT conservative | `jit bench-instrument` | `--jit on --jit-fast-regs off` | `19,857,945` | `50.358` | `perf_results/AMD/v8_01_current_head_fast_jit_conservative_amd_fam23_mod8_20260308_224108.csv` | `perf_results/AMD/v8_01_current_head_fast_jit_conservative_amd_fam23_mod8_20260308_224108.json` |
| Fast | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `11,606,741` | `86.157` | `perf_results/AMD/v8_01_current_head_fast_jit_fastregs_amd_fam23_mod8_20260308_224108.csv` | `perf_results/AMD/v8_01_current_head_fast_jit_fastregs_amd_fam23_mod8_20260308_224108.json` |

Emitted-state verification:

- All six CSV authority rows report `prefetch_distance=2`, `prefetch_auto_tune=false`, `large_pages_requested=false`, and `large_pages_1gb_requested=false`.
- Interpreter rows report `jit_active=false`; conservative JIT rows report `jit_active=true` and `jit_fast_regs=false`; fast-regs rows report `jit_active=true` and `jit_fast_regs=true`.
- Fast rows report `large_pages_dataset=false`; light rows report dataset page fields as `n/a`, matching cache-only execution.
- Light/Fast interpreter and conservative JIT rows emit finish substages directly; fast-regs rows emit the aggregate fast-regs fields (`jit_fastregs_prepare_ns`, `jit_fastregs_finish_ns`) while finish substage fields remain `0`.
- Light fast-regs still reports the expected helper instrumentation (`jit_fastregs_light_cache_item_helper_calls=4915200`, `jit_fastregs_light_cache_item_helper_ns=70782742900`).

Local-only note:

- Compared with the earlier clean `v5` matrix on `00840a9`, current `HEAD` `62801e2` is still slower on all six rows for this host.
- Same-host deltas vs the 2026-02-17 clean `v5` matrix are now: Light interpreter `+8.27%`, Light conservative JIT `+4.94%`, Light fast-regs JIT `+4.58%`, Fast interpreter `+17.84%`, Fast conservative JIT `+86.88%`, Fast fast-regs JIT `+35.10%`.
- This section is host-specific current-`HEAD` authority for AMD `23/8` on Windows 11. It does not make cross-host claims.

## v8.01 Current-HEAD Baseline Refresh (AMD `23/113`, Windows 11 Pro, 2026-03-09)

Primary artifacts:

- `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_baseline_amd_fam23_mod113_2026-03-09.md`
- `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_summary_amd_fam23_mod113_20260309_213850.json`
- `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_manifest_amd_fam23_mod113_20260309_213850.txt`
- `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_host_provenance_amd_fam23_mod113_20260309_213850.txt`
- `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_commands_amd_fam23_mod113_20260309_213850.log`
- `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_perf_index_amd_fam23_mod113_20260309_213850.csv`

Host/provenance:

- host tag: `amd_fam23_mod113`
- CPU: `AMD64 Family 23 Model 113 Stepping 0, AuthenticAMD`
- vendor/family/model/stepping: `AuthenticAMD/23/113/0`
- OS: `Microsoft Windows 11 Pro` (`version 2009`, build `26200`)
- git SHA: `62801e2f63a4295a39a6b69df997ba0039a104eb`
- git short SHA: `62801e2`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- packaged artifact directory: `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850`
- machine-readable summary and all six CSV authority rows report `git_dirty=true`; treat this as packaged current-`HEAD` host evidence, not clean-equivalent detached-worktree authority

Locked runtime parameters:

- `iters=50`
- `warmup=5`
- `threads=12`
- `inputs=6`
- `large_pages_requested=false`
- `large_pages_1gb_requested=false`
- `thread_names=false`
- `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows.
- Fast rows used `OXIDE_RANDOMX_FAST_BENCH=1`.

Current-`HEAD` matrix (CSV authority):

| Mode | Configuration | Cargo Features | Runtime JIT Flags | `ns/hash` | `hashes/sec` | CSV Artifact | JSON Artifact |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| Light | Interpreter | `jit jit-fastregs bench-instrument` | `--jit off` | `304,611,140` | `3.283` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_light_interp_amd_fam23_mod113_20260309_213850.csv` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_light_interp_amd_fam23_mod113_20260309_213850.json` |
| Light | JIT conservative | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs off` | `237,753,308` | `4.206` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_light_jit_conservative_amd_fam23_mod113_20260309_213850.csv` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_light_jit_conservative_amd_fam23_mod113_20260309_213850.json` |
| Light | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `232,295,380` | `4.305` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_light_jit_fastregs_amd_fam23_mod113_20260309_213850.csv` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_light_jit_fastregs_amd_fam23_mod113_20260309_213850.json` |
| Fast | Interpreter | `jit jit-fastregs bench-instrument` | `--jit off` | `36,294,186` | `27.553` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_fast_interp_amd_fam23_mod113_20260309_213850.csv` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_fast_interp_amd_fam23_mod113_20260309_213850.json` |
| Fast | JIT conservative | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs off` | `19,168,356` | `52.169` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_fast_jit_conservative_amd_fam23_mod113_20260309_213850.csv` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_fast_jit_conservative_amd_fam23_mod113_20260309_213850.json` |
| Fast | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `11,658,642` | `85.773` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_fast_jit_fastregs_amd_fam23_mod113_20260309_213850.csv` | `perf_results/AMD/v8_01_capture_amd_fam23_mod113_20260309_213850/v8_01_current_head_fast_jit_fastregs_amd_fam23_mod113_20260309_213850.json` |

Emitted-state verification:

- `v8_01_summary_amd_fam23_mod113_20260309_213850.json` reports `provenance.git_dirty=true` and `git_dirty_all_csv_false=false`; all six CSV rows also report `git_dirty=true`
- All rows report `prefetch_distance=2`, `prefetch_auto_tune=false`, `large_pages_requested=false`, and `large_pages_1gb_requested=false`
- Interpreter rows report `jit_active=false`; conservative JIT rows report `jit_active=true` and `jit_fast_regs=false`; fast-regs rows report `jit_active=true` and `jit_fast_regs=true`
- Fast rows report `large_pages_dataset=false`; light rows report dataset page fields as `n/a`
- Fast-regs rows carry the aggregate fast-regs prepare / finish fields and helper counters needed for v8 authority review

Local-only note:

- This packaged host closes the measured AMD host-class gap for current `HEAD`, but it does not satisfy the clean-provenance target from `PROMPTv8_01`
- No clean same-host `v5` baseline exists for AMD `23/113`; use this section as current-`HEAD` host evidence only

## v8.05 Current-HEAD Superscalar Prototype Capture (AMD `23/8`, Windows 11, 2026-03-11)

Primary artifacts:

- `perf_results/AMD/v8_05_superscalar_prototype_amd_fam23_mod8_2026-03-11.md`
- `perf_results/AMD/v8_05_superscalar_prototype_summary_amd_fam23_mod8_20260311_181826.json`
- `perf_results/AMD/v8_05_manifest_amd_fam23_mod8_20260311_181826.txt`
- `perf_results/AMD/v8_05_host_provenance_amd_fam23_mod8_20260311_181826.txt`
- `perf_results/AMD/v8_05_commands_amd_fam23_mod8_20260311_181826.log`
- `perf_results/AMD/v8_05_perf_index_amd_fam23_mod8_20260311_181826.csv`

Host/provenance:

- host tag: `amd_fam23_mod8`
- CPU: `AMD Ryzen 5 2600 Six-Core Processor`
- processor identifier: `AMD64 Family 23 Model 8 Stepping 2, AuthenticAMD`
- OS: `Microsoft Windows 11 Home` (`WindowsVersion=2009`, build `26200`)
- git SHA: `b71a8fe74f565f8e5e8e07da3eb06eda86d6d996`
- git short SHA: `b71a8fe`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- detached clean worktree: `C:\Users\jimsi\source\repos\raystanza\oxide-randomx-v8_05-amd-clean-20260311_181826`
- all ten `perf_harness` JSON authority rows report `git_dirty=false`

Locked runtime parameters:

- isolated `superscalar_hash_harness`: `config=default`, `iters=2000`, `warmup=200`, `items=256`
- `perf_harness`: `iters=50`, `warmup=5`, `threads=12`, `large_pages_requested=false`, `large_pages_1gb_requested=false`, `thread_names=false`, `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows
- Fast rows used `OXIDE_RANDOMX_FAST_BENCH=1`

Isolated superscalar harness summary:

| Implementation | `compute_ns_per_call` | `execute_ns_per_call` | Checksum parity |
| --- | ---: | ---: | --- |
| baseline active (feature off) | `14561.886` | `1735.863` | yes |
| proto active (feature on) | `12779.632` | `1557.385` | yes |
| proto scalar reference | `14012.162` | `1829.034` | yes |

Current-`HEAD` end-to-end matrix (baseline vs prototype; lower `ns/hash` is better):

| Mode | Configuration | Baseline `ns/hash` | Proto `ns/hash` | Delta | Dataset init note |
| --- | --- | ---: | ---: | ---: | --- |
| Light | Interpreter | `313,457,256` | `296,426,351` | `+5.433%` | n/a |
| Light | JIT conservative | `259,958,382` | `244,610,621` | `+5.904%` | n/a |
| Light | JIT fast-regs | `256,070,958` | `240,859,893` | `+5.940%` | n/a |
| Fast | JIT conservative | `19,569,631` | `19,493,786` | `+0.388%` | `dataset_init_ns 53,791,077,800 -> 49,674,469,600` (`+7.653%`) |
| Fast | JIT fast-regs | `11,644,233` | `11,300,660` | `+2.951%` | `dataset_init_ns 55,055,297,000 -> 50,766,682,400` (`+7.790%`) |

Emitted-state verification:

- All ten `perf_harness` rows report `prefetch_distance=2`, `prefetch_auto_tune=false`, `large_pages_requested=false`, and `large_pages_1gb_requested=false`
- Light interpreter rows report `jit_active=false`; JIT conservative rows report `jit_active=true` and `jit_fast_regs=false`; JIT fast-regs rows report `jit_active=true` and `jit_fast_regs=true`
- Light rows report dataset page fields as `n/a`; Fast rows report `large_pages_dataset=false`
- The isolated harness passed exact checksum parity across baseline active, proto active, and proto scalar for compute, execute, and select-register outputs

Current read:

- This clean current-`HEAD` rerun keeps the prototype clearly favorable on AMD `23/8` for the isolated cache-item path and for all three measured Light-mode end-to-end configurations
- Unlike the earlier `v7.07` fast-small rerun, both measured Fast JIT configurations are non-regressive here and dataset initialization also improves materially
- This host remains a clean positive research input, but current v9 authority
  still keeps the prototype parked because the integrated Windows AMD story is
  mixed and Fast mode is not promotive overall. See
  `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`.

## v8.05 Superscalar Support Capture (AMD `23/113`, Windows 11, 2026-03-12)

Primary artifacts:

- `perf_results/AMD/v8_05_capture_amd_fam23_mod113_20260312_170748/v8_05_summary_amd_fam23_mod113_20260312_170748.json`
- `perf_results/AMD/v8_05_capture_amd_fam23_mod113_20260312_170748/v8_05_perf_index_amd_fam23_mod113_20260312_170748.csv`
- `perf_results/AMD/v8_05_capture_amd_fam23_mod113_20260312_170748/v8_05_manifest_amd_fam23_mod113_20260312_170748.txt`
- `perf_results/AMD/v8_05_capture_amd_fam23_mod113_20260312_170748/v8_05_host_provenance_amd_fam23_mod113_20260312_170748.txt`
- `perf_results/AMD/v8_05_capture_amd_fam23_mod113_20260312_170748/v8_05_commands_amd_fam23_mod113_20260312_170748.log`

Host/provenance:

- host tag: `amd_fam23_mod113`
- CPU: `AMD Ryzen 5 3600 6-Core Processor`
- processor identifier: `AMD64 Family 23 Model 113 Stepping 0, AuthenticAMD`
- OS: `Microsoft Windows 11 Pro` (`WindowsVersion=2009`, build `26200`)
- packaged runner root: `C:\Users\JRS3\Downloads\oxide-randomx-v8_05-amd-capture`
- all ten `perf_harness` JSON rows report `git_dirty=true`; use this package as supporting evidence only

Locked runtime parameters:

- isolated `superscalar_hash_harness`: `config=test-small`, `iters=2000`, `warmup=200`, `items=128`
- `perf_harness`: `iters=50`, `warmup=5`, `threads=12`, `large_pages_requested=false`, `large_pages_1gb_requested=false`, `thread_names=false`, `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows
- Fast rows used `OXIDE_RANDOMX_FAST_BENCH=1`

Isolated superscalar harness summary:

| Implementation | `compute_ns_per_call` | `execute_ns_per_call` | Checksum parity |
| --- | ---: | ---: | --- |
| baseline active (feature off) | `147.410` | `64.727` | yes |
| proto active (feature on) | `144.732` | `67.012` | yes |
| proto scalar reference | `118.013` | `62.893` | yes |

- proto active vs baseline: compute `+1.817%`, execute `-3.530%`
- proto active vs scalar reference: compute `-22.641%`, execute `-6.549%`

Packaged end-to-end matrix (baseline vs prototype; lower `ns/hash` is better):

| Mode | Configuration | Baseline `ns/hash` | Proto `ns/hash` | Delta | Dataset init note |
| --- | --- | ---: | ---: | ---: | --- |
| Light | Interpreter | `297,927,578` | `272,004,791` | `+8.701%` | n/a |
| Light | JIT conservative | `231,662,606` | `228,756,614` | `+1.254%` | n/a |
| Light | JIT fast-regs | `232,362,581` | `221,818,678` | `+4.538%` | n/a |
| Fast | JIT conservative | `19,640,594` | `18,975,256` | `+3.388%` | `dataset_init_ns` `+2.960%` |
| Fast | JIT fast-regs | `11,056,203` | `11,073,831` | `-0.159%` | `dataset_init_ns` `+9.897%` |

Current read:

- Light remains favorable in all three rows on this packaged AMD `23/113` host, but the conservative JIT Light gain is only `+1.254%`
- Fast steady-state is mixed-but-within-tolerance here (`+3.388%` conservative, `-0.159%` fast-regs)
- This package misses the clean-provenance and isolated-harness alignment of the authority hosts, and the March 12 cross-host decision uses it only as supporting novel-family evidence

## Historical v8.07 Superscalar Cross-Host Decision Checkpoint (2026-03-12)

Historical v8 checkpoint memo:

- `perf_results/P2_3_superscalar_cross_host_decision_2026-03-12.md`

Current superscalar authority:

- `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`

Current read:

- Historical v8 outcome: park `superscalar-accel-proto` as not justified for
  the supported path on the then-measured host set.
- Current v9 outcome: keep it parked as a research lane for stricter reasons:
  clean Light upside remains real, but AMD Windows stays mixed, AMD `23/113`
  is supporting-only and rerun-sensitive, and Fast mode is not promotive
  overall.
- Scalar reference coverage and the prototype integration surface stay in place;
  no default flip or production rename is justified.

## Supported-Path Baseline Authority Snapshot (v8 capture set, 2026-03-11)

Primary memo:

- `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`

Alignment summary:

- Measured current-`HEAD` host set is now AMD `23/8`, AMD `23/113`, Intel `6/45`, and Intel `6/58`
- Clean authority standard is met on AMD `23/8`, Intel `6/45`, and Intel `6/58`; AMD `23/113` remains supporting current-`HEAD` evidence because its raw artifacts report `git_dirty=true`
- Best-throughput supported ordering is unchanged from older v5/v6/v7 authority: baseline `jit-fastregs` still beats conservative JIT, and conservative JIT still beats interpreter, on every captured host class
- The parent-supported stable envelope is unchanged: interpreter, conservative JIT, and baseline `jit-fastregs` stay in scope; `simd-blockio`, `simd-xor-paths`, `threaded-interp`, and the dropped P2.2 fast-regs candidate stay outside the default path

## Historical v5 Baseline Provenance

Common run provenance (all baseline CSV rows):

- git_sha: `00840a941c5411662693d5396e19a664dbc797cf`
- git_sha_short: `00840a9`
- git_dirty: `false`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- cpu: `AMD64 Family 23 Model 8 Stepping 2, AuthenticAMD`
- cores: `12`

Common runtime parameters:

- `iters=50`
- `warmup=5`
- `threads=12`
- `inputs=6`
- `large_pages_requested=false`
- `large_pages_1gb_requested=false`
- `thread_names=false`
- `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows.
- Fast mode rows used `OXIDE_RANDOMX_FAST_BENCH=1`.

## v7.07 SuperscalarHash Prototype Rerun (AMD, 2026-03-06)

Primary memo:

- `perf_results/AMD/v7_07_superscalar_prototype_amd_fam23_mod8_2026-03-06.md`

Summary artifact:

- `perf_results/AMD/v7_07_superscalar_prototype_summary_amd_fam23_mod8_20260306_172252.json`

Host/provenance:

- CPU: `AMD64 Family 23 Model 8 Stepping 2, AuthenticAMD` (`AMD Ryzen 5 2600 Six-Core Processor`)
- OS: `Microsoft Windows 11 Home`
- git SHA: `36ed04b880ad3993b4669634ede9c637c698c15b`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- `perf_harness` provenance emitted `git_dirty=true` in this pass because capture artifacts were written under `perf_results/AMD/` during execution.

Key outcomes:

- Isolated `superscalar_hash_harness` (`default`, `iters=2000`, `warmup=200`, `items=256`):
  - baseline active: `compute_ns_per_call=14579.058`
  - proto active: `compute_ns_per_call=12363.932` (`+15.194%` faster)
  - feature-on scalar reference: `13662.749`
  - exact checksum parity across baseline/proto/scalar: **yes**
- `perf_harness` light mode (`--mode light --jit off --iters 2 --warmup 1`):
  - `ns_per_hash`: `316912341 -> 295885466` (`+6.635%` faster)
- `perf_harness` fast small (`unsafe-config`, `--mode fast --jit off --iters 2 --warmup 1 --threads 1`):
  - `ns_per_hash`: `66230300 -> 66651650` (`-0.636%`, slight regression)
  - `dataset_init_ns`: `3623923300 -> 3502906400` (`+3.339%` faster)

Decision:

- Keep criteria for prompt `v7.07` remain met on this host (`>=3%` isolated win + exact correctness).

## v7.10 AMD Novel-Family `simd-blockio` Evidence (2026-03-08)

Primary memo:

- `perf_results/AMD/v7_10_capture_amd_fam23_results/v7_10_simd_blockio_amd_novel_family_evidence_2026-03-08.md`

Primary analysis artifact:

- `perf_results/AMD/v7_10_capture_amd_fam23_results/v7_10_simd_blockio_summary_amd_fam23_mod113_20260308_144058.json`

Host identity / provenance:

- vendor/family/model: `AuthenticAMD`, family `23`, model `113`, stepping `0`
- model string: `AMD64 Family 23 Model 113 Stepping 0, AuthenticAMD`
- OS: `Microsoft Windows [Version 10.0.26200.7840]`
- packaged build `HEAD`: `93fd2558708897156ee5dd7d89b3526f95daa60d`
- packaged build provenance reports `git_dirty=true`
- provenance: `perf_results/AMD/v7_10_capture_amd_fam23_results/v7_10_novel_family_host_provenance_amd_fam23_mod113_20260308_144058.txt`

Novel-family gate result:

- This is valid AMD novel-family evidence for prompt `v7.10` because direct AMD `simd-blockio` coverage now includes `AuthenticAMD/23/113`, not just the earlier `AuthenticAMD/23/8` host class.
- It is not a duplicate-family rerun of the already-measured Ryzen 5 2600-class machine.

Outcome summary (`simd-blockio` forced vs scalar baseline, lower is better):

| Mode | `perf_harness` ABBA mean delta | Pair deltas | Direction note |
| --- | ---: | --- | --- |
| Light | `+2.97%` | `+5.55%`, `+0.35%` | consistent regression on this host |
| Fast | `-1.21%` | `-1.13%`, `-1.28%` | modest win in this method only |

Correctness / counter sanity:

- Capture-harness correctness validation passed for measured states (`checked_cases=6`; baseline scalar and forced `simd-blockio` in Light and Fast).
- All measured Light and Fast ABBA counter spans stayed `0`.

Current policy implication:

- This closes the AMD-side novel-family evidence gap for prompt `v7.10`.
- It does **not** justify AMD-wide enablement or classifier broadening by itself.
- Current cross-host authority now lives in `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`.
- That refresh keeps the classifier unchanged and freezes broader `simd-blockio` policy work pending better hosts and stronger Fast agreement.
- Cross-host promotion remains unclaimed in this AMD rerun.

## P3.5 1GB Huge-Page Outcomes (AMD Linux Host, 2026-03-07)

Status in this pass:

- This capture ran on an AMD Linux host (`Ubuntu 24.04.4 LTS`, `AuthenticAMD`) with 1GB huge-page support enabled.
- Prerequisite check passed before benchmarking: `nr_hugepages=4`, `free_hugepages=4` for `hugepages-1048576kB`.
- 2MB huge-page pool was also configured in this rerun: `nr_hugepages=2048`, `free_hugepages=2045` for `hugepages-2048kB`.
- Captured rows include:
  - non-1GB comparable (`OXIDE_RANDOMX_HUGE_1G=0`)
  - 1GB success (`OXIDE_RANDOMX_HUGE_1G=1`)
  - pressure-induced fallback (`OXIDE_RANDOMX_HUGE_1G=1` with reduced free 1GB pages)
- Pressure setup log recorded free 1GB pages dropping from `4` to `2` before fallback (`pressure_ready=1`), then staying reduced (`1`) during fallback runs.

Primary artifacts from this pass:

- `perf_results/AMD/P3_5_1gb_hugepage_success_fallback_amd_linux_2026-03-07.md`
- `perf_results/AMD/v7_12_1gb_provenance_amd_linux_20260307_125524.txt`
- `perf_results/AMD/v7_12_1gb_commands_amd_linux_20260307_125524.log`
- `perf_results/AMD/v7_12_1gb_pressure_status_amd_linux_20260307_125524.txt`
- `perf_results/AMD/v7_12_fast_interp_lp2m_cmp_amd_linux_20260307_125524.csv`
- `perf_results/AMD/v7_12_fast_interp_lp2m_cmp_amd_linux_20260307_125524.json`
- `perf_results/AMD/v7_12_fast_interp_lp1g_success_amd_linux_20260307_125524.csv`
- `perf_results/AMD/v7_12_fast_interp_lp1g_success_amd_linux_20260307_125524.json`
- `perf_results/AMD/v7_12_fast_interp_lp1g_fallback_pressure_amd_linux_20260307_125524.csv`
- `perf_results/AMD/v7_12_fast_interp_lp1g_fallback_pressure_amd_linux_20260307_125524.json`

Emitted outcome summary:

| Capture | `large_pages_requested` | `large_pages_1gb_requested` | `large_pages_dataset` | `large_pages_1gb_dataset` | `large_pages_scratchpad` | `large_pages_1gb_scratchpad` | Interpretation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Non-1GB comparable | `true` | `false` | `true` | `false` | `true` | `false` | ordinary 2MB huge pages only |
| 1GB success row | `true` | `true` | `true` | `true` | `true` | `false` | dataset 1GB success |
| 1GB fallback row (pressure, CSV) | `true` | `true` | `true` | `false` | `true` | `false` | explicit 1GB fallback to non-1GB large pages |
| 1GB fallback row (pressure, JSON) | `true` | `true` | `true` | `false` | `true` | `false` | same fallback semantics confirmed in JSON output |

Field-level takeaway:

- Treat emitted allocation fields as truth:
  - `large_pages_1gb_dataset=true` is required for 1GB success.
  - `large_pages_1gb_requested=true` alone is never treated as success.
- Fallback stderr confirms the pressure path:
  - CSV fallback: `info: 1GB huge pages requested but only 2 free (need 3 for dataset); using 2MB huge pages instead`
  - JSON fallback: `info: 1GB huge pages requested but only 1 free (need 3 for dataset); using 2MB huge pages instead`
- Unlike the earlier Linux attempt, this rerun had a working 2MB pool, so fallback stayed on large pages (`large_pages_dataset=true`) while correctly emitting `large_pages_1gb_dataset=false`.

Performance effect vs non-1GB comparable row:

| Capture | `ns_per_hash` | `hashes_per_sec` | Delta vs non-1GB comparable |
| --- | ---: | ---: | ---: |
| Non-1GB comparable | `58,248,467` | `17.1678` | baseline |
| 1GB success row | `58,382,058` | `17.1286` | `+0.2293%` ns/hash |
| 1GB fallback row (pressure, CSV) | `59,212,528` | `16.8883` | `+1.6551%` ns/hash |

Status interpretation:

- This rerun provides emitted-field evidence for success and fallback outcomes with 2MB fallback behavior available.
- Scratchpad remained non-1GB in all captured rows (`large_pages_1gb_scratchpad=false`) while still using large pages (`large_pages_scratchpad=true`).
- The older Windows-only limitation evidence remains historical context:
  - `perf_results/AMD/v6_04_P3_5_1gb_hugepage_host_limitation_amd_2026-03-01.md`

## P1.3 Prefetch Runtime Observability Update (2026-02-18)

Schema status:

- `bench` and `perf_harness` now emit effective runtime prefetch fields in human/CSV/JSON output:
  - `prefetch`
  - `prefetch_distance`
  - `prefetch_auto_tune`
  - `scratchpad_prefetch_distance`
- Field definitions and interpretation guidance are in `docs/perf.md`.

Validation artifacts currently captured in this session (Intel host, `20260218_195135`):

- `perf_results/v5_prefetch_fields_default_intel_20260218_195135.csv`
- `perf_results/v5_prefetch_fields_override_intel_20260218_195135.csv`
- `perf_results/v5_prefetch_fields_default_intel_20260218_195135.json`
- `perf_results/v5_prefetch_fields_override_intel_20260218_195135.json`
- `perf_results/v5_prefetch_fields_default_intel_20260218_195135.human.txt`
- `perf_results/v5_prefetch_fields_override_intel_20260218_195135.human.txt`
- `perf_results/v5_prefetch_fields_default_intel_20260218_195135.bench.csv`
- `perf_results/v5_prefetch_fields_override_intel_20260218_195135.bench.csv`
- `perf_results/v5_prefetch_fields_default_intel_20260218_195135.bench.json`
- `perf_results/v5_prefetch_fields_override_intel_20260218_195135.bench.json`
- `perf_results/v5_prefetch_fields_default_intel_20260218_195135.bench.human.txt`
- `perf_results/v5_prefetch_fields_override_intel_20260218_195135.bench.human.txt`

Observed effective values:

| Capture | prefetch | prefetch_distance | prefetch_auto_tune | scratchpad_prefetch_distance |
| --- | ---: | ---: | ---: | ---: |
| default | `true` | `2` | `false` | `0` |
| override (`OXIDE_RANDOMX_PREFETCH_AUTO=1`, `OXIDE_RANDOMX_PREFETCH_DISTANCE=2`, `OXIDE_RANDOMX_PREFETCH_SCRATCHPAD_DISTANCE=3`) | `true` | `2` | `true` | `3` |

Evidence note:

- The exact two-run "default vs override" observability pair was previously Intel-only.
- AMD now has clean current-head sweep evidence with emitted effective prefetch fields in:
  - `perf_results/AMD/P0_4_clean_prefetch_refresh_amd_2026-02-28.md`
  - `perf_results/AMD/v6_01_prefetch_sweep_manifest_amd_20260228_131113.csv`
- Older `v5_07` AMD sweep artifacts remain historical/exploratory input only.

## P0.4 Clean Prefetch Refresh (AMD, 2026-02-28)

Primary memo:

- `perf_results/AMD/P0_4_clean_prefetch_refresh_amd_2026-02-28.md`

Primary clean artifacts:

- `perf_results/AMD/v6_01_prefetch_sweep_manifest_amd_20260228_131113.csv`
- `perf_results/AMD/v6_01_prefetch_host_provenance_amd_20260228_131113.txt`
- `perf_results/AMD/v6_01_prefetch_commands_amd_20260228_131113.log`
- `perf_results/AMD/v6_01_prefetch_scenario_summary_amd_20260228_131113.csv`
- `perf_results/AMD/v6_01_prefetch_settings_summary_amd_20260228_131113.csv`
- `perf_results/AMD/v6_01_prefetch_summary_amd_20260228_131113.json`
- `perf_results/AMD/v6_01_prefetch_summary_amd_20260228_131113.md`

Method highlights:

- Clean detached worktree build, emitted `git_dirty=false` on all rows.
- `3` repeats per point.
- Run-order control: ascending+auto, auto+descending, seeded-random+auto.
- Light fixed sweep: full `0..8`.
- Fast fixed sweep: full `0..8`.
- Effective prefetch fields validated from emitted CSV for every run.
- Scratchpad prefetch distance held fixed at `0`.

Clean AMD summary on current `HEAD` (`8aab125`, `ns/hash`, lower is better):

| Scenario | Best fixed distance | Best fixed mean ns/hash | Auto-selected distance | Auto mean ns/hash | Delta (`auto` vs best fixed) | Noise / drift notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Light, JIT off | `1` | `313,955,417.333` | `3` | `319,788,020` | `+1.8578%` | auto CV `2.0695%`, scenario mean abs drift `2.5230%` |
| Light, JIT on (conservative) | `7` | `244,859,562` | `3` | `244,668,582` | `-0.0780%` | auto CV `1.3097%`, scenario mean abs drift `1.4869%` |
| Fast, JIT on (conservative) | `4` | `11,246,059.667` | `3` | `11,633,872` | `+3.4484%` | auto CV `2.2663%`, scenario mean abs drift `1.6295%` |

Robustness note:

- Mean and median disagree on the exact winning fixed distance in the light scenarios, which matches the observed drift.
- Mean and median both agree that `auto=3` is not the best fixed point for AMD `light_jit_off` and AMD `fast_jit_conservative` on current `HEAD`.
- `light_jit_conservative` is near-neutral/noisy and does not overturn that broader AMD-side contradiction on its own.

Current AMD guidance:

- Do **not** promote the older exploratory AMD `keep mapping` conclusion to authoritative for current `HEAD`.
- Treat the earlier `v5_07` AMD sweep as historical input only.
- This clean pass does not justify a new single AMD-wide replacement distance either, because the best fixed point is scenario-dependent and drift is non-zero.

Historical note (`v5_07`, exploratory only):

- Older exploratory AMD prefetch artifacts remain available under `perf_results/AMD/v5_07_*`.
- Those older runs reported near-ties for `auto=3`, but that result is not reproduced by the clean `v6_01` current-head refresh.

## P0.5 Clean Prefetch Cross-Host Decision (2026-03-01)

Primary memo:

- `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`

Decision:

- Keep the current `src/flags.rs` prefetch mapping unchanged in this pass.
- Confidence: `medium` for keeping the current mapping as the operational default; `low` that the current auto-selected distances are locally optimal on the two captured hosts.

Why the mapping stays unchanged:

- The clean AMD `v6_01` and Intel `v6_02` sweeps both break the older `v5_07` near-tie story.
- Neither host identifies one replacement distance that is stable across Light/Fast scenarios.
- This AMD capture host (`AMD64 Family 23 Model 8`) is grouped into the broad `AmdZen2 -> 3` bucket in `src/flags.rs`; changing that bucket from this host alone would over-generalize beyond the evidence.
- The cross-host memo keeps the mapping only as the best operational default under `ROADMAPv7.md` stability rules, not as a claim that `auto=3` is the measured AMD optimum on this host.

Operational guidance:

- Treat `perf_results/AMD/P0_4_clean_prefetch_refresh_amd_2026-02-28.md` as the AMD host authority.
- Treat `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md` as the current cross-host policy authority.
- For host-local tuning, run an explicit fixed-distance sweep rather than assuming `OXIDE_RANDOMX_PREFETCH_AUTO=1` is best for this machine.

## Historical v5 Baseline Matrix (CSV authority)

All metrics below come from CSV artifacts (JSON companions were also captured).

| Mode  | Configuration    | Cargo Features                      | Runtime JIT Flags              |     ns/hash | hashes/sec | CSV Artifact                                                          | JSON Artifact                                                          |
| ----- | ---------------- | ----------------------------------- | ------------------------------ | ----------: | ---------: | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Light | Interpreter      | `bench-instrument`                  | `--jit off`                    | 298,302,155 |      3.352 | `perf_results/AMD/v5_baseline_light_interp_20260217_175800.csv`           | `perf_results/AMD/v5_baseline_light_interp_20260217_175800.json`           |
| Light | JIT Conservative | `jit bench-instrument`              | `--jit on --jit-fast-regs off` | 246,525,565 |      4.056 | `perf_results/AMD/v5_baseline_light_jit_conservative_20260217_175800.csv` | `perf_results/AMD/v5_baseline_light_jit_conservative_20260217_175800.json` |
| Light | JIT Fast-Regs    | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on`  | 239,106,052 |      4.182 | `perf_results/AMD/v5_baseline_light_jit_fastregs_20260217_175800.csv`     | `perf_results/AMD/v5_baseline_light_jit_fastregs_20260217_175800.json`     |
| Fast  | Interpreter      | `bench-instrument`                  | `--jit off`                    |  57,205,441 |     17.481 | `perf_results/AMD/v5_baseline_fast_interp_20260217_175800.csv`            | `perf_results/AMD/v5_baseline_fast_interp_20260217_175800.json`            |
| Fast  | JIT Conservative | `jit bench-instrument`              | `--jit on --jit-fast-regs off` |  10,626,281 |     94.106 | `perf_results/AMD/v5_baseline_fast_jit_conservative_20260217_175800.csv`  | `perf_results/AMD/v5_baseline_fast_jit_conservative_20260217_175800.json`  |
| Fast  | JIT Fast-Regs    | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on`  |   8,591,447 |    116.395 | `perf_results/AMD/v5_baseline_fast_jit_fastregs_20260217_175800.csv`      | `perf_results/AMD/v5_baseline_fast_jit_fastregs_20260217_175800.json`      |

## Historical v5 Derived Comparisons (from CSV)

- Light JIT conservative vs Light interpreter: `1.210x` speedup (`17.36%` lower ns/hash).
- Light JIT fast-regs vs Light JIT conservative: `1.031x` speedup (`3.01%` lower ns/hash).
- Fast JIT conservative vs Fast interpreter: `5.383x` speedup (`81.42%` lower ns/hash).
- Fast JIT fast-regs vs Fast JIT conservative: `1.237x` speedup (`19.15%` lower ns/hash).
- Fast JIT fast-regs vs Fast interpreter: `84.98%` lower ns/hash.

## Historical v5 Exact Commands Used

PowerShell commands (executed as shown):

```powershell
# Light interpreter
$env:OXIDE_RANDOMX_HUGE_1G='0'; cargo run --release --example perf_harness --features "bench-instrument" -- --mode light --jit off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format csv --out perf_results/AMD/v5_baseline_light_interp_20260217_175800.csv
$env:OXIDE_RANDOMX_HUGE_1G='0'; cargo run --release --example perf_harness --features "bench-instrument" -- --mode light --jit off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format json --out perf_results/AMD/v5_baseline_light_interp_20260217_175800.json

# Light JIT conservative
$env:OXIDE_RANDOMX_HUGE_1G='0'; cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format csv --out perf_results/AMD/v5_baseline_light_jit_conservative_20260217_175800.csv
$env:OXIDE_RANDOMX_HUGE_1G='0'; cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format json --out perf_results/AMD/v5_baseline_light_jit_conservative_20260217_175800.json

# Light JIT fast-regs
$env:OXIDE_RANDOMX_HUGE_1G='0'; cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format csv --out perf_results/AMD/v5_baseline_light_jit_fastregs_20260217_175800.csv
$env:OXIDE_RANDOMX_HUGE_1G='0'; cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format json --out perf_results/AMD/v5_baseline_light_jit_fastregs_20260217_175800.json

# Fast interpreter
$env:OXIDE_RANDOMX_HUGE_1G='0'; $env:OXIDE_RANDOMX_FAST_BENCH='1'; cargo run --release --example perf_harness --features "bench-instrument" -- --mode fast --jit off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format csv --out perf_results/AMD/v5_baseline_fast_interp_20260217_175800.csv
$env:OXIDE_RANDOMX_HUGE_1G='0'; $env:OXIDE_RANDOMX_FAST_BENCH='1'; cargo run --release --example perf_harness --features "bench-instrument" -- --mode fast --jit off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format json --out perf_results/AMD/v5_baseline_fast_interp_20260217_175800.json

# Fast JIT conservative
$env:OXIDE_RANDOMX_HUGE_1G='0'; $env:OXIDE_RANDOMX_FAST_BENCH='1'; cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode fast --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format csv --out perf_results/AMD/v5_baseline_fast_jit_conservative_20260217_175800.csv
$env:OXIDE_RANDOMX_HUGE_1G='0'; $env:OXIDE_RANDOMX_FAST_BENCH='1'; cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode fast --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format json --out perf_results/AMD/v5_baseline_fast_jit_conservative_20260217_175800.json

# Fast JIT fast-regs
$env:OXIDE_RANDOMX_HUGE_1G='0'; $env:OXIDE_RANDOMX_FAST_BENCH='1'; cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode fast --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format csv --out perf_results/AMD/v5_baseline_fast_jit_fastregs_20260217_175800.csv
$env:OXIDE_RANDOMX_HUGE_1G='0'; $env:OXIDE_RANDOMX_FAST_BENCH='1'; cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode fast --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads 12 --large-pages off --thread-names off --affinity off --format json --out perf_results/AMD/v5_baseline_fast_jit_fastregs_20260217_175800.json
```

## Historical v5 Artifact Manifest

- `perf_results/AMD/v5_baseline_light_interp_20260217_175800.csv`
- `perf_results/AMD/v5_baseline_light_interp_20260217_175800.json`
- `perf_results/AMD/v5_baseline_light_jit_conservative_20260217_175800.csv`
- `perf_results/AMD/v5_baseline_light_jit_conservative_20260217_175800.json`
- `perf_results/AMD/v5_baseline_light_jit_fastregs_20260217_175800.csv`
- `perf_results/AMD/v5_baseline_light_jit_fastregs_20260217_175800.json`
- `perf_results/AMD/v5_baseline_fast_interp_20260217_175800.csv`
- `perf_results/AMD/v5_baseline_fast_interp_20260217_175800.json`
- `perf_results/AMD/v5_baseline_fast_jit_conservative_20260217_175800.csv`
- `perf_results/AMD/v5_baseline_fast_jit_conservative_20260217_175800.json`
- `perf_results/AMD/v5_baseline_fast_jit_fastregs_20260217_175800.csv`
- `perf_results/AMD/v5_baseline_fast_jit_fastregs_20260217_175800.json`

## Historical v5 Baseline Hygiene Note

- The baseline matrix above is clean (`git_dirty=false`) and remains the current baseline authority.
- This v5 matrix supersedes the prior v4 baseline set as canonical authority on current HEAD (`00840a9`).
- Clean current-head AMD prefetch authority now lives in the separate `v6_01` sweep artifacts under `perf_results/AMD/v6_01_*` and memo `perf_results/AMD/P0_4_clean_prefetch_refresh_amd_2026-02-28.md`.
- The older AMD `v5_07` prefetch sweep is retained as historical/exploratory context only.
- Experimental captures in this file (v4_05/v4_06/v4_11) remain decision-specific evidence and do not replace the canonical baseline unless re-captured as a full clean six-row set.

## Supported-Path Baseline Snapshot Link

- Supported-path baseline snapshot: `perf_results/PERF_COMP.md` (summary only; primary supported-path authority is `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`, and current integrated experimental policy lives in `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`).

## Experimental Feature Policy Index (Current Authority)

| Feature | Current Decision | Primary Decision Memo | Host Coverage (Direct A/B) | Provenance Quality |
| --- | --- | --- | --- | --- |
| `threaded-interp` | Closed negative result; parked experimental; runtime-default off | `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md` | AMD Family 23 direct A/B base plus v9 integrated authority host set | Historical direct A/B base is exploratory (`git_dirty=true`); current policy read comes from v9 integrated authority |
| `superscalar-accel-proto` | Parked experimental research lane; feature-gated only; scalar reference retained; not in supported path | `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md` | AMD Family 23 Model 8 + AMD Family 23 Model 113 + Intel Family 6 Model 45 + Intel Family 6 Model 58, with integrated v9 authority on AMD `23/8` Win/Linux and Intel `6/45`/`6/58` Linux | Current v9 disposition keeps the branch parked because clean Light upside is real but narrower than the v8 prototype story, Fast mode is not promotive overall, and AMD `23/113` remains supporting-only and rerun-sensitive |
| `simd-blockio` | Keep experimental; CPU-conditional; runtime-default off (Intel Fam6 Model45 auto-disabled); broader policy frozen pending better hosts/Fast stability | `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md` | AMD Family 23 Model 8 + AMD Family 23 Model 113 + Intel Family 6 Model 45 + Intel Family 6 Model 58 | `v7.11` is now the current authority: host diversity expanded to four family/model classes, but the classifier still stays unchanged because Fast remains too mixed for broader rules |
| `simd-xor-paths` | Keep experimental; no default-on recommendation; direct A/B remains exploratory | `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md` | AMD Family 23 direct A/B base plus v9 integrated authority host set | Historical direct A/B base is exploratory (`git_dirty=true`, single-family); current policy read stays non-promotive |

Policy note:

- Historical memos with older or narrower guidance are preserved for context, but policy authority is the primary memo listed above.

## P1.2 `simd-blockio` Cross-CPU Disposition Capture (2026-02-16)

Disposition chosen: **keep experimental with CPU-conditional recommendations**.

Cross-CPU capture memo (historical policy base):

- `perf_results/Intel/P1_2_simd_blockio_cross_cpu_disposition_2026-02-16.md`

Latest Intel triage addendum (runtime mitigation update):

- `perf_results/Intel/P0_3_simd_blockio_intel_fast_triage_2026-02-17.md`
- `perf_results/Intel/v5_03_intel_simd_blockio_triage_analysis_20260217_201006.json`

Historical supporting memo (Ryzen-only pass; superseded for policy authority):

- `perf_results/unlabeled/P1_2_simd_blockio_disposition_2026-02-14.md`

Host coverage in direct A/B:

- AMD Ryzen 5 2600 (`AMD Family 23`)
- Intel Xeon E5-2690 (`Intel Family 6 Model 45`)

### Cross-host outcome summary (`simd-blockio` delta vs baseline)

| Host | Light `bench_apples` median | Light `perf_harness` ABBA avg | Fast `bench_apples` median | Fast `perf_harness` ABBA avg |
| --- | ---: | ---: | ---: | ---: |
| Ryzen 5 2600 (2026-02-14) | `-1.06%` | `-1.15%` | `+0.18%` | `-4.16%` |
| Xeon E5-2690 (2026-02-16) | `+1.53%` | `-1.35%` | `+1.37%` | `+5.04%` |

Interpretation:

- Fast mode is now clearly CPU-family dependent across captured hosts.
- Measured Xeon host regresses in Fast mode (`bench_apples` and ABBA agree on slowdown).
- Light mode remains sensitive/noisy and requires host-local validation.
- Final policy remains opt-in + host-local A/B before enablement.
- 2026-02-17 Intel triage added a runtime family/model guard to keep `simd-blockio` disabled on Intel Family 6 Model 45 by default (override: `OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE=1`).

### Key new artifacts (Intel capture)

- `perf_results/v4_05_intel_bench_apples_light_20260216_173756.csv`
- `perf_results/v4_05_intel_bench_apples_fast_20260216_173756.csv`
- `perf_results/v4_05_intel_perf_light_baseline_a_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_light_simd_a_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_light_simd_b_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_light_baseline_b_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_fast_baseline_a_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_fast_simd_a_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_fast_simd_b_20260216_180859.csv`
- `perf_results/v4_05_intel_perf_fast_baseline_b_20260216_180859.csv`
- `perf_results/v4_05_intel_simd_blockio_analysis_20260216_180859.json`
- `perf_results/v4_05_intel_host_provenance_20260216_180859.txt`

## P0.3 Intel `simd-blockio` Fast-Mode Triage Addendum (2026-02-17)

Primary memo:

- `perf_results/Intel/P0_3_simd_blockio_intel_fast_triage_2026-02-17.md`

Primary analysis artifact:

- `perf_results/Intel/v5_03_intel_simd_blockio_triage_analysis_20260217_201006.json`

Host provenance:

- `perf_results/v5_03_intel_host_provenance_20260217_201006.txt`

Key measured deltas (`simd-blockio` vs baseline, lower is better):

| Capture set | Fast `bench_apples` median | Fast `perf_harness` ABBA avg |
| --- | ---: | ---: |
| Pre-mitigation (`20260217_194639` / `20260217_195918`) | `+1.82%` | `-0.01%` |
| Post-mitigation (`20260217_201006`) | `+2.56%` | `-1.32%` |
| Guard-vs-forced toggle ABBA (`20260217_203537`, forced vs guard) | n/a | `+0.46%` |

Outcome:

- `simd-blockio` remains experimental and CPU-conditional.
- Runtime mitigation is now implemented for this Intel host class:
  - Intel Family 6 Model 45 defaults to scalar path (even when `simd-blockio` is compiled).
  - local override for investigation: `OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE=1`.
- Counter spans remained zero across A/B captures, so behavior stayed algorithmically invariant.
- AMD guardrail rerun on this exact patch was not possible in this Intel-host session and remains an explicit evidence gap.

## v6.11 Clean AMD `simd-blockio` Family Evidence (2026-03-01)

Primary memo:

- `perf_results/AMD/v6_11_simd_blockio_amd_family_evidence_2026-03-01.md`

Primary analysis artifact:

- `perf_results/AMD/v6_11_simd_blockio_summary_amd_fam23_mod8_20260301_225916.json`

Repro script:

- `scripts/capture/run_v6_11_simd_blockio_amd.ps1`

Host identity:

- vendor/family/model: `AuthenticAMD`, family `23`, model `8`, stepping `2`
- CPU model string: `AMD Ryzen 5 2600 Six-Core Processor`
- current `HEAD`: `a3299a4e7ed6a79c9bad7d0c3caf339f3fa3af79`
- provenance: `perf_results/AMD/v6_11_host_provenance_amd_fam23_mod8_20260301_225916.txt`

Family-coverage value:

- This is **duplicate-family confirmation** on the same AMD Family `23` Model `8` host class as the earlier Ryzen-only evidence.
- It is not new AMD-family classifier coverage.

Clean current-head outcome summary (`simd-blockio` vs scalar baseline, lower is better):

| Mode | `bench` subset median delta | `perf_harness` ABBA mean delta | Direction note |
| --- | ---: | ---: | --- |
| Light | `-1.61%` | `-0.63%` | modest, directionally consistent win |
| Fast | `+2.78%` | `-0.36%` | not stable across methods |

Fast stability note:

- repeated Fast bench pairs were consistently regressive: `+2.83%`, `+2.55%`, `+2.78%`
- Fast ABBA pair deltas split sign: `+0.27%`, `-0.99%`
- Fast stage deltas still show a mixed picture:
  - `execute_program_ns_interpreter`: `-1.28%`
  - `prepare_iteration_ns`: `+4.97%`
  - `finish_iteration_ns`: `+34.22%`

Correctness/counter sanity:

- All measured Light and Fast ABBA counter spans stayed `0`.
- Validation passed for:
  - `cargo test --test oracle`
  - `cargo test --features "jit jit-fastregs" --test oracle`
  - `cargo test --features "simd-blockio" --test oracle`
  - `cargo test --features "simd-blockio" simd_prepare_finish_matches_scalar`
  - `cargo test --features "simd-blockio" simd_blockio_blocked_cpu_classifier_targets_xeon_model_45`

Current policy implication:

- This clean duplicate-family AMD rerun does **not** justify AMD-wide enablement or classifier broadening.
- It also does **not** justify introducing a new AMD-specific hard block from this host alone.
- Treat the result as clean confirmation that Light can be favorable on this family while Fast remains too directionally unstable for policy expansion.

## v6.12 Cross-Host `simd-blockio` Classifier Policy (Historical, 2026-03-02)

Primary memo:

- `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-02.md`

Decision:

- Keep the current `src/vm/mod.rs` classifier unchanged.
- Keep the Intel Family `6` Model `45` runtime block.
- Do **not** add AMD-family allow or block rules from the current AMD rerun.

Why policy does not broaden:

- AMD `v6.11` is duplicate-family confirmation on `AuthenticAMD` Family `23` Model `8`, not new AMD-family coverage.
- Intel `v6.10` is duplicate-family confirmation on the already-blocked `GenuineIntel` Family `6` Model `45`, not new Intel-family coverage.
- Fast remains mixed across methods:
  - AMD Fast `bench` subset median: `+2.78%`
  - AMD Fast `perf_harness` ABBA mean: `-0.36%`
  - Intel Fast forced-on vs scalar ABBA: `+1.27%`
- Direct A/B host diversity is still only two family/model classes.

Blocker classification:

- duplicate-family confirmation on both vendors
- mixed/drift-sensitive Fast results
- insufficient host diversity for safe classifier synthesis

Current policy implication:

- Keep `simd-blockio` experimental and host-local.
- Do not infer AMD-wide safety from this Ryzen-family duplicate capture.
- Historical `v6.12` requirement: collect novel-family AMD and Intel evidence before any classifier broadening pass.
- Subsequent updates: Intel `v7.09` and AMD `v7.10` satisfied that evidence requirement.
- Current cross-host authority is `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`.

## v7.11 Cross-Host `simd-blockio` Policy Refresh (2026-03-08)

Primary memo:

- `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`

Decision:

- Keep `src/vm/mod.rs` unchanged.
- Keep the Intel Family `6` Model `45` runtime block as the only hard rule.
- Freeze broader classifier work pending better host coverage and stronger Fast-mode agreement.

Cross-host synthesis snapshot (`simd-blockio` forced vs scalar baseline, lower is better):

| Host class | Evidence type | Light ABBA | Fast ABBA | Readout |
| --- | --- | ---: | ---: | --- |
| Intel `6/45` | duplicate-family | `-6.08%` | `+1.27%` | keep existing narrow block |
| Intel `6/58` | novel-family | `-2.24%` | `+7.24%` | too drift-sensitive to justify broader Intel rules |
| AMD `23/8` | duplicate-family | `-0.63%` | `-0.36%` | Fast still mixed because `bench` was `+2.78%` |
| AMD `23/113` | novel-family | `+2.97%` | `-1.21%` | Light/Fast split blocks AMD-wide inference |

Interpretation:

- Direct A/B host diversity is now genuinely broader than the `2026-03-02` memo, but it is still only two vendor families.
- Light is not stable enough to support vendor-wide enablement.
- Fast remains too mixed to broaden the classifier or to add new hard blocks.

## P1.1 Dispatch-Level Interpreter Validation (AMD, 2026-03-01)

Primary memo:

- `perf_results/AMD/P1_1_dispatch_level_interpreter_validation_amd_2026-03-01.md`

Primary analysis artifacts:

- `perf_results/AMD/v6_06_dispatch_analysis_amd_20260301_110302.json`
- `perf_results/AMD/v6_06_dispatch_perf_compare_post_vs_pre_amd_20260301_110302.txt`

Exact-patch identity:

- Pre state: `9bf81f6a9a725b327fb10ddd026a1d44a16cf22f`
- Post state: `a11022079897a7d2f76228e89be0109ff4f45e44`
- Current clean reference: `eb34f20bffb2bb28802295ed9a0dc5ee54443a79`
- The exact `a110220` diff in `src/vm/mod.rs` is the same dispatch-helper + guarded pointer-load patch described in the Intel P1.1 memo.
- `HEAD` is not patch-identical to `a110220`, so the current-head row is reference-only.

AMD-host result summary (Light interpreter; lower is better):

| Comparison | `ns_per_hash` | `execute_program_ns_interpreter` | `prepare_iteration_ns` | `finish_iteration_ns` |
| --- | ---: | ---: | ---: | ---: |
| First pair (`post1` vs `pre1`) | `-0.17%` | `-4.00%` | `-6.74%` | `+0.89%` |
| ABBA mean (`post` avg vs `pre` avg) | `+0.87%` | `-2.98%` | `-4.39%` | `+1.94%` |
| Current `HEAD` vs exact-post mean | `+0.43%` | `+1.73%` | `+1.98%` | `+0.10%` |

Interpretation:

- AMD confirms the dispatch-stage direction: `execute_program_ns_interpreter` improved in both clean post runs.
- AMD does **not** confirm the Intel end-to-end win for this exact patch set in this pass:
  - ABBA mean `ns_per_hash` regressed by `0.87%`,
  - aggregate `perf_compare` fails at threshold `0`,
  - the finish stage still dominates and moved upward enough to offset the execute-stage gain.
- Confidence is `medium` on the execute-stage improvement, and `low-to-medium` on end-to-end magnitude because the overall effect is sub-1% and the ABBA pre rows show drift.
- Current AMD guidance for this patch: treat it as a host-local execute-stage win without evidence for an AMD throughput uplift claim.

## P1.1 Dispatch-Level Interpreter Improvements (Intel Reference, 2026-02-18)

Primary memo:

- `perf_results/P1_1_dispatch_level_interpreter_improvements_2026-02-18.md`

Primary analysis artifact:

- `perf_results/v5_04_intel_dispatch_analysis_20260218_191201.json`

Intel-host result summary (Light interpreter):

- `execute_program_ns_interpreter`: `-5.74%` post vs pre
- `ns_per_hash`: `-1.63%` post vs pre

Cross-host note:

- Intel retains the original positive end-to-end result for this exact patch.
- AMD now has a clean exact-patch rerun in `perf_results/AMD/P1_1_dispatch_level_interpreter_validation_amd_2026-03-01.md`, and that rerun does **not** confirm the same end-to-end uplift.

## P2.2 JIT Fast-Regs Optimization Follow-Up (Clean AMD Guardrail, 2026-03-01)

Primary AMD memo:

- `perf_results/AMD/P2_2_jit_fastregs_clean_rerun_amd_2026-03-01.md`

Primary AMD analysis artifacts:

- `perf_results/AMD/v6_08_jit_fastregs_clean_summary_amd_20260301_143149.json`
- `perf_results/AMD/v6_08_perf_compare_fast_fastregs_candidate_vs_baseline_amd_20260301_143149.txt`
- `perf_results/AMD/v6_08_perf_compare_light_fastregs_candidate_vs_baseline_amd_20260301_143149.txt`

Final cross-host decision memo:

- `perf_results/P2_2_jit_fastregs_cross_host_decision_2026-03-01.md`

Primary Intel clean reference:

- `perf_results/Intel/P2_2_jit_fastregs_clean_rerun_intel_2026-03-01.md`

Exact patch identity:

- baseline state: `a11022079897a7d2f76228e89be0109ff4f45e44`
- patch source state: `fcb47512f74f475e5e2c61c72ba3a86669fc4c69`
- isolated AMD candidate head: `c8f5772ac7d073a59b5a8c2219eacdc37d04554a`
- generated AMD patch artifact matches the Intel clean rerun patch exactly (`patch_matches_intel_artifact=true`)

AMD-host clean result summary (lower is better):

| State | Fast conservative | Fast fast-regs | Fast uplift | Light conservative | Light fast-regs | Light uplift |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | `11,786,206.0` | `9,357,845.5` | `-20.60%` | `243,812,449.5` | `243,080,167.5` | `-0.30%` |
| Candidate | `11,894,611.5` | `9,154,557.5` | `-23.04%` | `247,202,633.0` | `244,440,679.5` | `-1.12%` |

AMD interpretation:

- AMD guardrail now exists and **passes** for this exact candidate.
- Fast stays healthy:
  - candidate fast-regs improved `-2.17%` vs clean baseline,
  - candidate Fast uplift widened by `-2.43` percentage points (`-20.60%` -> `-23.04%`),
  - conservative Fast drift was only `+0.92%`.
- Light stays healthy:
  - conservative Light moved `+1.39%`,
  - fast-regs Light moved `+0.56%`,
  - both remain below the explicit `2.0%` compare threshold,
  - candidate Light uplift stayed favorable (`-1.12%` vs `-0.30%` baseline).
- Counter shape stayed unchanged across baseline/candidate fast-regs rows:
  - Fast: `jit_fastregs_spill/reload/sync_* = 38400`, call-boundary counters `0`
  - Light: same sync counters plus `jit_fastregs_preserve_spill/reload = 9830400`
- Light conservative remains the noisiest pair in this AMD pass (`250,629,151` vs `243,776,115`), so the AMD result should be read as a guardrail pass, not as a large uplift claim.

Cross-host interpretation:

- Intel clean rerun still rejected the candidate because Fast fast-regs regressed materially there and the Intel Fast keep threshold was not met.
- AMD clean rerun shows the opposite direction: AMD is safe and modestly favorable on this host.
- Final cross-host disposition is **drop the candidate from current code**.
- Treat this AMD memo as guardrail evidence only; current authority is `perf_results/P2_2_jit_fastregs_cross_host_decision_2026-03-01.md`.

## P3.1 Prefetch Auto-Tune Sweep (Cross-Host Link, 2026-02-21)

Current cross-host memo:

- `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`

Historical cross-host memo:

- `perf_results/unlabeled/P3_1_prefetch_auto_tune_cross_host_2026-02-21.md`

Cross-host disposition state:

- The old `P3_1` memo is historical/exploratory only.
- Current authority is the clean current-head cross-host memo `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`.
- That newer memo keeps the mapping unchanged, but explicitly documents that the captured AMD and Intel hosts do not show one stable replacement distance.
- Do not treat the older rows below as current-head AMD authority.

Cross-host summary (`ns/hash`, lower is better):

| Host | Scenario | Best fixed distance | Auto-selected distance | Delta (`auto` vs best fixed) |
| --- | --- | ---: | ---: | ---: |
| Intel | Light, JIT off | `1` | `2` | `+1.25%` |
| Intel | Light, JIT on | `2` | `2` | `+0.34%` |
| Intel | Fast, JIT on | `1` | `2` | `+1.02%` |
| AMD | Light, JIT off | `5` | `3` | `+0.08%` |
| AMD | Light, JIT on | `3` | `3` | `-0.01%` |
| AMD | Fast, JIT on | `2` | `3` | `-0.04%` |

## P2.1 Interpreter Hot-Path Validation (2026-02-14)

Primary memo:

- `perf_results/P2_1_interpreter_hotpath_validation_2026-02-14.md`

Summary artifacts:

- `perf_results/v4_06_measurement_matrix_20260214_195135.csv`
- `perf_results/v4_06_measurement_summary_20260214_195135.json`

Key outcome:

- Original hotpath target (`-3%` to `-5%` in `vm_exec_ns_interpreter`) was **not met**.
- Follow-up tuning in `src/vm/mod.rs` improved Light interpreter:
  - `vm_exec_ns_interpreter`: `-1.27%` vs pre-tuning hotpath
  - `ns/hash`: `-2.59%` vs pre-tuning hotpath
- Result is a measured win, but below the original execute-stage target band.

## P3.3 SIMD XOR Paths Evaluation (2026-02-15)

Disposition chosen: **keep experimental (no-go for merge/default-on in this pass)**.

Primary memo:

- `perf_results/P3_3_simd_xor_paths_disposition_2026-02-15.md`

Summary artifacts:

- `perf_results/v4_11_bench_apples_light_20260215_105304.csv`
- `perf_results/v4_11_bench_apples_fast_20260215_111343.csv`
- `perf_results/v4_11_perf_light_baseline_a_20260215_112308.csv`
- `perf_results/v4_11_perf_light_simd_xor_a_20260215_112308.csv`
- `perf_results/v4_11_perf_light_simd_xor_b_20260215_112308.csv`
- `perf_results/v4_11_perf_light_baseline_b_20260215_112308.csv`
- `perf_results/v4_11_perf_fast_baseline_a_20260215_113639.csv`
- `perf_results/v4_11_perf_fast_simd_xor_a_20260215_113639.csv`
- `perf_results/v4_11_perf_fast_simd_xor_b_20260215_113639.csv`
- `perf_results/v4_11_perf_fast_baseline_b_20260215_113639.csv`
- `perf_results/v4_11_simd_xor_analysis_20260215_114322.json`

Key outcome:

- Light mode: small, consistent ABBA win (`-0.74%` avg ns/hash), near-neutral bench median (`-0.01%`).
- Fast mode: mixed outcome (`bench_apples` median `-2.20%`, but ABBA avg `+0.40%` with pair sign flip).
- Counter spans stayed zero across A/B, so behavior remained deterministic.
- Capture provenance caveat: this evaluation set was collected with `git_dirty=true` on a single CPU family (AMD Family 23); treat as exploratory evidence, not baseline authority.
- CPU coverage for this pass remained single-family (AMD Family 23); broader cross-CPU recommendation is deferred.
