# Performance Results (Current Baselines + Historical Evidence Index)

This document is the canonical Intel-host performance-results summary for the repository.

- Measurement commands/output schema live in `docs/perf.md`.
- Planning/state disposition lives in `dev/ROADMAPv9.md`.
- Current supported-path baseline authority lives in `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`.
- Current integrated experimental-feature authority lives in `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`.
- Current superscalar feature disposition lives in `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`.
- Supported-path baseline snapshot lives in `perf_results/PERF_COMP.md`.
- Raw evidence and decision memos live in `perf_results/`.

## Capture Date

- v8 Intel current-`HEAD` baseline refresh capture timestamp (`intel_fam6_mod45`): `2026-03-09 22:23:23` (`20260309_222323`)
- v8 Intel current-`HEAD` baseline refresh capture timestamp (`intel_fam6_mod58`): `2026-03-10 19:00:26` (`20260310_190026`)
- v8 Intel superscalar prototype capture timestamp (`intel_fam6_mod45`): `2026-03-11 19:47:11` (`20260311_194711`)
- v8 Intel superscalar prototype capture timestamp (`intel_fam6_mod58`): `2026-03-11 20:52:14` (`20260311_205214`)
- Superscalar cross-host decision date: `2026-03-12`
- Current-head cross-host authority memo date: `2026-03-11`
- Baseline matrix capture timestamp: `2026-02-17 18:14:05` (`20260217_181405`)
- Clean prefetch refresh capture timestamp: `2026-02-28 20:56:21` (`20260228_205621`)
- Clean prefetch cross-host decision date: `2026-03-01`
- Intel `simd-blockio` family evidence capture timestamp: `2026-03-01 18:55:52` (`20260301_185552`)
- `simd-blockio` cross-host policy refresh date: `2026-03-08`
- Intel novel-family `simd-blockio` gate-check timestamp: `2026-03-05 23:20:23` (`20260305_232023`)
- Intel novel-family `simd-blockio` evidence capture timestamp: `2026-03-06 19:13:18` (`20260306_191318`)

## v8.06 Superscalar Prototype Capture (Intel `6/45`, Ubuntu 24.04.4 LTS, 2026-03-11)

Primary artifacts:

- `perf_results/Intel/v8_06_superscalar_prototype_intel_fam6_mod45_2026-03-11.md`
- `perf_results/Intel/v8_06_superscalar_prototype_summary_intel_fam6_mod45_20260311_194711.json`
- `perf_results/Intel/v8_06_manifest_intel_fam6_mod45_20260311_194711.txt`
- `perf_results/Intel/v8_06_host_provenance_intel_fam6_mod45_20260311_194711.txt`
- `perf_results/Intel/v8_06_commands_intel_fam6_mod45_20260311_194711.log`
- `perf_results/Intel/v8_06_perf_index_intel_fam6_mod45_20260311_194711.csv`

Host/provenance:

- host tag: `intel_fam6_mod45`
- CPU: `Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz`
- vendor/family/model/stepping: `GenuineIntel/6/45/7`
- OS: `Ubuntu 24.04.4 LTS`
- kernel: `Linux 6.8.0-101-generic x86_64 GNU/Linux`
- git SHA: `9ab3e106cc163f44f1ec54bce99fd45050c23fee`
- git short SHA: `9ab3e10`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- detached clean worktree: `/tmp/oxide-randomx-v8_06-intel-clean-20260311_194711`
- all perf-harness JSON rows report `git_dirty=false`

Validation:

- passed: `cargo test`
- passed: `cargo test --test oracle`
- passed: `cargo test --features superscalar-accel-proto`
- passed: `cargo test --features superscalar-accel-proto --test oracle`
- passed: `cargo test --features "jit jit-fastregs superscalar-accel-proto" --test oracle`

Isolated superscalar harness (`iters=2000`, `warmup=200`, `items=256`):

| configuration | compute ns/call | execute ns/call |
| --- | ---: | ---: |
| baseline active | `16,370.778` | `2,025.179` |
| proto active | `13,292.933` | `1,640.520` |
| proto scalar reference | `16,221.783` | `2,012.713` |

- checksum parity (compute / execute / select): `true / true / true`
- proto active vs baseline: compute `+18.801%`, execute `+18.994%`
- proto active vs scalar reference: compute `+18.055%`, execute `+18.492%`

End-to-end baseline vs proto (`perf_harness`, `iters=50`, `warmup=5`, `threads=32`, `--large-pages off`, Fast rows with `OXIDE_RANDOMX_FAST_BENCH=1`):

| Mode | Config | Baseline `ns/hash` | Proto `ns/hash` | Delta | Dataset init note |
| --- | --- | ---: | ---: | ---: | --- |
| Light | Interpreter | `354,966,806` | `298,304,088` | `+15.963%` | n/a |
| Light | JIT conservative | `295,975,322` | `247,355,339` | `+16.427%` | n/a |
| Light | JIT fast-regs | `282,377,029` | `242,234,223` | `+14.216%` | n/a |
| Fast | JIT conservative | `18,516,935` | `18,034,714` | `+2.604%` | `dataset_init_ns 26,480,993,499 -> 21,671,200,953` (`+18.163%`) |
| Fast | JIT fast-regs | `11,938,497` | `11,890,247` | `+0.404%` | `dataset_init_ns 26,250,253,418 -> 21,635,030,317` (`+17.582%`) |

Interpretation:

- On this Intel `6/45` host, `superscalar-accel-proto` is favorable in isolated harness metrics and all measured end-to-end rows.
- Dataset initialization is materially faster on both measured Fast JIT rows in this run.
- This host remains one of the strongest clean Light-mode research inputs, but
  current v9 policy still keeps the branch parked rather than promoted. See
  `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`.

## v8.06 Superscalar Prototype Capture (Intel `6/58`, Ubuntu 25.10, 2026-03-11)

Primary artifacts:

- `perf_results/Intel/v8_06_superscalar_prototype_intel_fam6_mod58_2026-03-11.md`
- `perf_results/Intel/v8_06_superscalar_prototype_summary_intel_fam6_mod58_20260311_205214.json`
- `perf_results/Intel/v8_06_manifest_intel_fam6_mod58_20260311_205214.txt`
- `perf_results/Intel/v8_06_host_provenance_intel_fam6_mod58_20260311_205214.txt`
- `perf_results/Intel/v8_06_commands_intel_fam6_mod58_20260311_205214.log`
- `perf_results/Intel/v8_06_perf_index_intel_fam6_mod58_20260311_205214.csv`

Host/provenance:

- host tag: `intel_fam6_mod58`
- CPU: `Intel(R) Core(TM) i5-3360M CPU @ 2.80GHz`
- vendor/family/model/stepping: `GenuineIntel/6/58/9`
- OS: `Ubuntu 25.10`
- kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- git SHA: `cf4e08dc9323e3ea97e117a080822dcf576a622a`
- git short SHA: `cf4e08d`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- detached clean worktree: `/tmp/oxide-randomx-v8_06-intel-clean-20260311_205214`
- all perf-harness JSON rows report `git_dirty=false`

Validation:

- passed: `cargo test`
- passed: `cargo test --test oracle`
- passed: `cargo test --features superscalar-accel-proto`
- passed: `cargo test --features superscalar-accel-proto --test oracle`
- passed: `cargo test --features "jit jit-fastregs superscalar-accel-proto" --test oracle`

Isolated superscalar harness (`iters=2000`, `warmup=200`, `items=256`):

| configuration | compute ns/call | execute ns/call |
| --- | ---: | ---: |
| baseline active | `18,756.161` | `2,224.287` |
| proto active | `18,002.661` | `1,916.769` |
| proto scalar reference | `18,048.012` | `2,258.449` |

- checksum parity (compute / execute / select): `true / true / true`
- proto active vs baseline: compute `+4.017%`, execute `+13.825%`
- proto active vs scalar reference: compute `+0.251%`, execute `+15.129%`

End-to-end baseline vs proto (`perf_harness`, `iters=50`, `warmup=5`, `threads=4`, `--large-pages off`, Fast rows with `OXIDE_RANDOMX_FAST_BENCH=1`):

| Mode | Config | Baseline `ns/hash` | Proto `ns/hash` | Delta | Dataset init note |
| --- | --- | ---: | ---: | ---: | --- |
| Light | Interpreter | `409,561,690` | `349,299,019` | `+14.714%` | n/a |
| Light | JIT conservative | `340,761,718` | `285,957,302` | `+16.083%` | n/a |
| Light | JIT fast-regs | `346,315,668` | `284,375,184` | `+17.886%` | n/a |
| Fast | JIT conservative | `20,943,179` | `26,221,168` | `-25.201%` | `dataset_init_ns 270,267,857,330 -> 265,159,318,825` (`+1.890%`) |
| Fast | JIT fast-regs | `23,331,037` | `21,006,628` | `+9.963%` | `dataset_init_ns 326,103,876,099 -> 254,160,383,034` (`+22.062%`) |

Interpretation:

- On this Intel `6/58` host, `superscalar-accel-proto` is clearly favorable in isolated execute-side metrics and all three measured Light end-to-end rows.
- Fast mode is mixed on this laptop: conservative JIT regressed materially in the JSON authority pair, while Fast `jit-fastregs` improved and showed a large dataset-initialization win.
- Full-dataset Fast invocations are operationally expensive on this host (`dataset_init_ns` roughly `270s` to `326s` on the baseline rows), so dataset initialization cost must be considered alongside steady-state `ns/hash`.
- This Intel `6/58` laptop was the clean v8 blocker, but current v9 policy no
  longer rests on that single regression alone. The branch remains parked
  because Fast is still not promotive overall and the cross-host story is still
  too mixed for support.

## Historical v8.07 Superscalar Cross-Host Decision Checkpoint (2026-03-12)

Historical v8 checkpoint memo:

- `perf_results/P2_3_superscalar_cross_host_decision_2026-03-12.md`

Current superscalar authority:

- `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md`

Current read:

- Historical v8 outcome: park `superscalar-accel-proto` as not justified for
  the supported path on the then-measured host set.
- Current v9 outcome: keep it parked as a research lane because Light upside
  remains real but narrower than the old prototype story, Fast mode is not
  promotive overall, and AMD Windows still prevents a clean cross-host support
  read.
- Scalar reference coverage and the prototype integration surface stay in place;
  no default flip or production rename is justified.

## v8.02 Current-HEAD Baseline Refresh (Intel `6/45`, Ubuntu 24.04.4 LTS, 2026-03-09)

Primary artifacts:

- `perf_results/Intel/v8_02_current_head_baseline_intel_fam6_mod45_2026-03-09.md`
- `perf_results/Intel/v8_02_summary_intel_fam6_mod45_20260309_222323.json`
- `perf_results/Intel/v8_02_manifest_intel_fam6_mod45_20260309_222323.txt`
- `perf_results/Intel/v8_02_host_provenance_intel_fam6_mod45_20260309_222323.txt`
- `perf_results/Intel/v8_02_commands_intel_fam6_mod45_20260309_222323.log`
- `perf_results/Intel/v8_02_perf_index_intel_fam6_mod45_20260309_222323.csv`

Host/provenance:

- host tag: `intel_fam6_mod45`
- CPU: `Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz`
- vendor/family/model/stepping: `GenuineIntel/6/45/7`
- OS: `Ubuntu 24.04.4 LTS`
- kernel: `Linux 6.8.0-101-generic x86_64 GNU/Linux`
- git SHA: `d964e84edfad7d43898d4f126e2293a0560f5b4b`
- git short SHA: `d964e84`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- detached clean worktree: `/tmp/oxide-randomx-v8_02-intel-clean-20260309_222323`
- all six CSV authority rows report `git_dirty=false`

Locked runtime parameters:

- `iters=50`
- `warmup=5`
- `threads=32`
- `inputs=6`
- `large_pages_requested=false`
- `large_pages_1gb_requested=false`
- `thread_names=false`
- `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows.
- Fast rows used `OXIDE_RANDOMX_FAST_BENCH=1`.
- All rows used `--large-pages off`.

Current-`HEAD` matrix (CSV authority):

| Mode | Configuration | Cargo Features | Runtime JIT Flags | `ns/hash` | `hashes/sec` | CSV Artifact | JSON Artifact |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| Light | Interpreter | `bench-instrument` | `--jit off` | `356,727,023` | `2.803` | `perf_results/Intel/v8_02_current_head_light_interp_intel_fam6_mod45_20260309_222323.csv` | `perf_results/Intel/v8_02_current_head_light_interp_intel_fam6_mod45_20260309_222323.json` |
| Light | JIT conservative | `jit bench-instrument` | `--jit on --jit-fast-regs off` | `299,611,467` | `3.338` | `perf_results/Intel/v8_02_current_head_light_jit_conservative_intel_fam6_mod45_20260309_222323.csv` | `perf_results/Intel/v8_02_current_head_light_jit_conservative_intel_fam6_mod45_20260309_222323.json` |
| Light | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `289,181,672` | `3.458` | `perf_results/Intel/v8_02_current_head_light_jit_fastregs_intel_fam6_mod45_20260309_222323.csv` | `perf_results/Intel/v8_02_current_head_light_jit_fastregs_intel_fam6_mod45_20260309_222323.json` |
| Fast | Interpreter | `bench-instrument` | `--jit off` | `72,084,310` | `13.873` | `perf_results/Intel/v8_02_current_head_fast_interp_intel_fam6_mod45_20260309_222323.csv` | `perf_results/Intel/v8_02_current_head_fast_interp_intel_fam6_mod45_20260309_222323.json` |
| Fast | JIT conservative | `jit bench-instrument` | `--jit on --jit-fast-regs off` | `18,191,188` | `54.972` | `perf_results/Intel/v8_02_current_head_fast_jit_conservative_intel_fam6_mod45_20260309_222323.csv` | `perf_results/Intel/v8_02_current_head_fast_jit_conservative_intel_fam6_mod45_20260309_222323.json` |
| Fast | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `11,938,133` | `83.765` | `perf_results/Intel/v8_02_current_head_fast_jit_fastregs_intel_fam6_mod45_20260309_222323.csv` | `perf_results/Intel/v8_02_current_head_fast_jit_fastregs_intel_fam6_mod45_20260309_222323.json` |

Emitted-state verification:

- All six CSV rows report `prefetch_distance=2`, `prefetch_auto_tune=false`, `large_pages_requested=false`, and `large_pages_1gb_requested=false`.
- Interpreter rows report `jit_active=false`; conservative JIT rows report `jit_active=true` and `jit_fast_regs=false`; fast-regs rows report `jit_active=true` and `jit_fast_regs=true`.
- Fast rows report `large_pages_dataset=false`; light rows report dataset page fields as `n/a`.
- Interpreter and conservative JIT rows emit finish substage fields directly; fast-regs rows emit aggregate fast-regs fields (`jit_fastregs_prepare_ns`, `jit_fastregs_finish_ns`) while finish substage fields are `0`.
- Light fast-regs helper instrumentation is present (`jit_fastregs_light_cache_item_helper_calls=4915200`, `jit_fastregs_light_cache_item_helper_ns=82797206056`).

Local-only note:

- Compared with the earlier clean Intel v5 matrix (`00840a9`) on the same host class, current `HEAD` `d964e84` is slower on all six rows: Light interpreter `+1.3043%`, Light conservative JIT `+1.1775%`, Light fast-regs JIT `+1.4344%`, Fast interpreter `+2.1921%`, Fast conservative JIT `+61.4755%`, Fast fast-regs JIT `+16.2693%`.
- This section is host-specific current-`HEAD` authority for Intel `6/45`; it does not make cross-host synthesis claims.

## v8.02 Current-HEAD Baseline Refresh (Intel `6/58`, Ubuntu 25.10, 2026-03-10)

Primary artifacts:

- `perf_results/Intel/v8_02_current_head_baseline_intel_fam6_mod58_2026-03-10.md`
- `perf_results/Intel/v8_02_summary_intel_fam6_mod58_20260310_190026.json`
- `perf_results/Intel/v8_02_manifest_intel_fam6_mod58_20260310_190026.txt`
- `perf_results/Intel/v8_02_host_provenance_intel_fam6_mod58_20260310_190026.txt`
- `perf_results/Intel/v8_02_commands_intel_fam6_mod58_20260310_190026.log`
- `perf_results/Intel/v8_02_perf_index_intel_fam6_mod58_20260310_190026.csv`

Host/provenance:

- host tag: `intel_fam6_mod58`
- CPU: `Intel(R) Core(TM) i5-3360M CPU @ 2.80GHz`
- vendor/family/model/stepping: `GenuineIntel/6/58/9`
- OS: `Ubuntu 25.10`
- kernel: `Linux 6.17.0-14-generic x86_64 GNU/Linux`
- git SHA: `3d33ce7803ddc4c719e9771996378dcf54b6041e`
- git short SHA: `3d33ce7`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- detached clean worktree: `/tmp/oxide-randomx-v8_02-intel-clean-20260310_190026`
- all six CSV authority rows report `git_dirty=false`

Locked runtime parameters:

- `iters=50`
- `warmup=5`
- `threads=4`
- `inputs=6`
- `large_pages_requested=false`
- `large_pages_1gb_requested=false`
- `thread_names=false`
- `affinity=off`
- `OXIDE_RANDOMX_HUGE_1G=0` was set for all rows.
- Fast rows used `OXIDE_RANDOMX_FAST_BENCH=1`.
- All rows used `--large-pages off`.

Current-`HEAD` matrix (CSV authority):

| Mode | Configuration | Cargo Features | Runtime JIT Flags | `ns/hash` | `hashes/sec` | CSV Artifact | JSON Artifact |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| Light | Interpreter | `bench-instrument` | `--jit off` | `462,233,073` | `2.163` | `perf_results/Intel/v8_02_current_head_light_interp_intel_fam6_mod58_20260310_190026.csv` | `perf_results/Intel/v8_02_current_head_light_interp_intel_fam6_mod58_20260310_190026.json` |
| Light | JIT conservative | `jit bench-instrument` | `--jit on --jit-fast-regs off` | `379,348,873` | `2.636` | `perf_results/Intel/v8_02_current_head_light_jit_conservative_intel_fam6_mod58_20260310_190026.csv` | `perf_results/Intel/v8_02_current_head_light_jit_conservative_intel_fam6_mod58_20260310_190026.json` |
| Light | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `378,620,723` | `2.641` | `perf_results/Intel/v8_02_current_head_light_jit_fastregs_intel_fam6_mod58_20260310_190026.csv` | `perf_results/Intel/v8_02_current_head_light_jit_fastregs_intel_fam6_mod58_20260310_190026.json` |
| Fast | Interpreter | `bench-instrument` | `--jit off` | `99,954,813` | `10.005` | `perf_results/Intel/v8_02_current_head_fast_interp_intel_fam6_mod58_20260310_190026.csv` | `perf_results/Intel/v8_02_current_head_fast_interp_intel_fam6_mod58_20260310_190026.json` |
| Fast | JIT conservative | `jit bench-instrument` | `--jit on --jit-fast-regs off` | `25,744,920` | `38.843` | `perf_results/Intel/v8_02_current_head_fast_jit_conservative_intel_fam6_mod58_20260310_190026.csv` | `perf_results/Intel/v8_02_current_head_fast_jit_conservative_intel_fam6_mod58_20260310_190026.json` |
| Fast | JIT fast-regs | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on` | `22,854,997` | `43.754` | `perf_results/Intel/v8_02_current_head_fast_jit_fastregs_intel_fam6_mod58_20260310_190026.csv` | `perf_results/Intel/v8_02_current_head_fast_jit_fastregs_intel_fam6_mod58_20260310_190026.json` |

Emitted-state verification:

- All six CSV rows report `prefetch_distance=2`, `prefetch_auto_tune=false`, `large_pages_requested=false`, and `large_pages_1gb_requested=false`.
- Interpreter rows report `jit_active=false`; conservative JIT rows report `jit_active=true` and `jit_fast_regs=false`; fast-regs rows report `jit_active=true` and `jit_fast_regs=true`.
- Fast rows report `large_pages_dataset=false`; light rows report dataset page fields as `n/a`.
- Interpreter and conservative JIT rows emit finish substage fields directly; fast-regs rows emit aggregate fast-regs fields (`jit_fastregs_prepare_ns`, `jit_fastregs_finish_ns`) while finish substage fields are `0`.
- Light fast-regs helper instrumentation is present (`jit_fastregs_light_cache_item_helper_calls=4915200`, `jit_fastregs_light_cache_item_helper_ns=105167048599`).

Local-only note:

- This host showed visible Fast-mode run-to-run noise between paired CSV/JSON companion runs (`fast_interp` JSON vs CSV: `+16.1018%`; `fast_jit_fastregs` JSON vs CSV: `-25.1507%`). CSV rows remain the authority matrix for this capture and the host was not substituted.
- This section is host-specific current-`HEAD` authority for Intel `6/58`; it does not make cross-host synthesis claims.

## Supported-Path Baseline Authority Snapshot (v8 capture set, 2026-03-11)

Primary memo:

- `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`

Alignment summary:

- Measured current-`HEAD` host set is now Intel `6/45`, Intel `6/58`, AMD `23/8`, and AMD `23/113`
- Clean authority standard is met on Intel `6/45`, Intel `6/58`, and AMD `23/8`; AMD `23/113` remains supporting current-`HEAD` evidence because its raw artifacts report `git_dirty=true`
- Best-throughput supported ordering is unchanged from older v5/v6/v7 authority: baseline `jit-fastregs` still beats conservative JIT, and conservative JIT still beats interpreter, on every captured host class
- On Intel `6/58`, Light `jit-fastregs` is only `0.19%` better than conservative JIT, so treat that Light result as a near-tie; Fast mode still clearly favors baseline `jit-fastregs`
- The parent-supported stable envelope is unchanged: interpreter, conservative JIT, and baseline `jit-fastregs` stay in scope; `simd-blockio`, `simd-xor-paths`, `threaded-interp`, and the dropped P2.2 fast-regs candidate stay outside the default path

## Baseline Provenance

Common run provenance (all baseline CSV rows):

- git_sha: `00840a941c5411662693d5396e19a664dbc797cf`
- git_sha_short: `00840a9`
- git_dirty: `false`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- cpu: `Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz`
- cores: `32`

Common runtime parameters:

- `iters=50`
- `warmup=5`
- `threads=32`
- `inputs=6`
- `large_pages_requested=false`
- `large_pages_1gb_requested=false`
- `thread_names=false`
- `affinity=off`
- Fast mode runs used `OXIDE_RANDOMX_FAST_BENCH=1`.
- All runs used `--large-pages off`.

## P3.5 1GB Huge-Page Request Outcomes (Intel Host, 2026-02-23)

Goal: capture explicit 1GB request outcomes with both success and fallback evidence, using emitted fields as source of truth.

Primary memo:

- `perf_results/Intel/P3_5_1gb_hugepage_success_fallback_intel_2026-02-23.md`

Provenance + pressure setup:

- `perf_results/Intel/v5_08_1gb_provenance_intel_20260223_010837.txt`
- `perf_results/Intel/v5_08_1gb_pressure_status_intel_20260223_010837.txt`

Capture artifacts:

- Non-1GB comparable row:
  - `perf_results/Intel/v5_08_fast_interp_lp2m_cmp_intel_20260223_010837.csv`
  - `perf_results/Intel/v5_08_fast_interp_lp2m_cmp_intel_20260223_010837.json`
- 1GB success row:
  - `perf_results/Intel/v5_08_fast_interp_lp1g_success_intel_20260223_010837.csv`
  - `perf_results/Intel/v5_08_fast_interp_lp1g_success_intel_20260223_010837.json`
- 1GB fallback row (pressure setup):
  - `perf_results/Intel/v5_08_fast_interp_lp1g_fallback_pressure_intel_20260223_010837.csv`

Emitted field outcomes (source of truth):

| Capture | `large_pages_1gb_requested` | `large_pages_1gb_dataset` | `large_pages_1gb_scratchpad` | Interpretation |
| --- | --- | --- | --- | --- |
| Non-1GB comparable | `false` | `false` | `false` | no 1GB request |
| 1GB success row | `true` | `true` | `false` | dataset 1GB success |
| 1GB fallback row | `true` | `false` | `false` | fallback path under reduced free 1GB pages |

Observed fallback diagnostics in run stderr:

- `info: 1GB huge pages requested but only 2 free (need 3 for dataset); using 2MB huge pages instead`

Performance summary (`ns/hash`, lower is better):

| Capture | `ns_per_hash` | `hashes_per_sec` | Delta vs non-1GB comparable |
| --- | ---: | ---: | ---: |
| Non-1GB comparable (`OXIDE_RANDOMX_HUGE_1G=0`) | `60,932,298` | `16.4117` | baseline |
| 1GB success (`OXIDE_RANDOMX_HUGE_1G=1`) | `60,016,842` | `16.6620` | `-1.5024%` |
| 1GB fallback under pressure (`OXIDE_RANDOMX_HUGE_1G=1`) | `61,584,893` | `16.2377` | `+1.0710%` |

Status note:

- This capture set satisfies both success and fallback evidence requirements on this host.

## P1.3 Prefetch Runtime Observability Update (2026-02-18)

Schema status:

- `bench` and `perf_harness` now emit effective runtime prefetch fields in human/CSV/JSON output:
  - `prefetch`
  - `prefetch_distance`
  - `prefetch_auto_tune`
  - `scratchpad_prefetch_distance`
- Field definitions and interpretation guidance are in `docs/perf.md`.

Validation artifacts (Intel host, `20260218_195135`):

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

- The exact two-run "default vs override" observability pair originated on this Intel host.
- Intel now has clean current-head sweep evidence with emitted effective prefetch fields in:
  - `perf_results/Intel/P0_4_clean_prefetch_refresh_intel_2026-02-28.md`
  - `perf_results/Intel/v6_02_prefetch_sweep_manifest_intel_20260228_205621.csv`
- Older Intel `v5_07` sweep artifacts remain historical/exploratory input only.

## P0.4 Clean Prefetch Refresh (Intel, 2026-02-28)

Primary memo:

- `perf_results/Intel/P0_4_clean_prefetch_refresh_intel_2026-02-28.md`

Primary clean artifacts:

- `perf_results/Intel/v6_02_prefetch_sweep_manifest_intel_20260228_205621.csv`
- `perf_results/Intel/v6_02_prefetch_host_provenance_intel_20260228_205621.txt`
- `perf_results/Intel/v6_02_prefetch_commands_intel_20260228_205621.log`
- `perf_results/Intel/v6_02_prefetch_scenario_summary_intel_20260228_205621.csv`
- `perf_results/Intel/v6_02_prefetch_settings_summary_intel_20260228_205621.csv`
- `perf_results/Intel/v6_02_prefetch_summary_intel_20260228_205621.json`
- `perf_results/Intel/v6_02_prefetch_summary_intel_20260228_205621.md`

Method highlights:

- Clean detached worktree build, emitted `git_dirty=false` on all rows.
- `3` repeats per point.
- Run-order control: ascending+auto, auto+descending, seeded-random+auto.
- Light fixed sweep: full `0..8`.
- Fast fixed sweep: full `0..8`.
- Effective prefetch fields validated from emitted CSV for every run.
- Scratchpad prefetch distance held fixed at `0`.

Clean Intel summary on current `HEAD` (`13ac6f7`, `ns/hash`, lower is better):

| Scenario | Best fixed distance | Best fixed mean ns/hash | Auto-selected distance | Auto mean ns/hash | Delta (`auto` vs best fixed) | Noise / drift notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Light, JIT off | `0` | `366,509,620` | `2` | `381,913,886.333` | `+4.2030%` | auto CV `0.8989%`, scenario mean abs drift `4.6319%`, median delta `+6.0337%` |
| Light, JIT on (conservative) | `3` | `305,002,156.667` | `2` | `314,297,692.667` | `+3.0477%` | auto CV `4.4920%`, scenario mean abs drift `4.4700%`, median delta `+5.3434%` |
| Fast, JIT on (conservative) | `8` | `11,950,522` | `2` | `13,324,114.333` | `+11.4940%` | auto CV `22.5923%`, scenario mean abs drift `13.0669%`, median delta `-0.3908%` |

Robustness note:

- Both light scenarios now have mean and median agreement that `auto=2` is not the best fixed point on this host.
- All three mean-based `auto vs best fixed` deltas exceed the repo's practical regression tolerance (`1%` from `ROADMAPv7.md`).
- Fast mode remains high-noise and should not be overfit:
  - auto mean is much worse than best fixed because one auto run spiked to `16,798,951 ns/hash`,
  - but auto median is slightly better than the best fixed median (`-0.3908%` vs `d8`),
  - and multiple fixed distances (`d1`, `d7`) also showed large outliers.

Current Intel guidance:

- `auto=2` does **not** stand up cleanly on this Intel host anymore.
- Do **not** keep citing the exploratory `v5_07` Intel sweep as current authority.
- Do **not** claim a new single Intel default from this host alone either:
  - best fixed distance is scenario-dependent (`0`, `3`, `8` by mean),
  - Fast mode is too unstable to justify replacing `2` with `8`,
  - the clean host result is strong enough to reject the old near-tie claim, but not strong enough to nominate one replacement distance for all Intel scenarios.

Historical note (`v5_07`, exploratory only):

- Older exploratory Intel prefetch artifacts remain available under `perf_results/Intel/v5_07_*`.
- Those older runs reported small near-ties around `auto=2`, but that result is not reproduced by the clean `v6_02` current-head refresh on this same runtime code path.

## P0.5 Clean Prefetch Cross-Host Decision (2026-03-01)

Primary memo:

- `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`

Decision:

- Keep the current `src/flags.rs` prefetch mapping unchanged in this pass.
- Confidence: `medium` for keeping the current mapping as the operational default; `low` that the current auto-selected distances are locally optimal on the two captured hosts.

Why the mapping stays unchanged:

- The clean AMD `v6_01` and Intel `v6_02` sweeps both overturn the older `v5_07` near-tie story.
- Neither host identifies one replacement distance that is stable across Light/Fast scenarios.
- This Intel capture host (`Intel Family 6 Model 45`) falls through the broad `IntelSkylake -> 2` fallback bucket in `src/flags.rs`; changing that bucket from this host alone would over-generalize beyond the evidence.
- The cross-host memo keeps the mapping only as the best operational default under `ROADMAPv7.md` stability rules, not as a claim that `auto=2` is the measured Intel optimum on this host.

Operational guidance:

- Treat `perf_results/Intel/P0_4_clean_prefetch_refresh_intel_2026-02-28.md` as the Intel host authority.
- Treat `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md` as the current cross-host policy authority.
- For host-local tuning, run an explicit fixed-distance sweep rather than assuming `OXIDE_RANDOMX_PREFETCH_AUTO=1` is best for this machine.

## P3.4 Prefetch Auto-Tune Sweep Cross-Host Sync (Historical Input, 2026-02-21)

Current cross-host memo:

- `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`

Historical cross-host memo:

- `perf_results/unlabeled/P3_1_prefetch_auto_tune_cross_host_2026-02-21.md`

Authority note:

- The `P3_1` cross-host "keep mapping" conclusion is historical/exploratory only.
- Current host-level authority now lives in:
  - Intel: `perf_results/Intel/P0_4_clean_prefetch_refresh_intel_2026-02-28.md`
  - AMD: `perf_results/AMD/P0_4_clean_prefetch_refresh_amd_2026-02-28.md`
- Current cross-host policy authority now lives in `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`.
- That new memo keeps the mapping unchanged, but explicitly records that the clean host data is still too scenario-dependent to justify a family-value retune.

Historical `v5_07` cross-host disposition:

- Disposition: **keep mapping**
- Basis: worst `|auto-best|` delta `1.25%` across AMD + Intel sweep summaries.

Cross-host summary (`ns/hash`, lower is better):

| Host | Scenario | Best fixed distance | Auto-selected distance | Delta (`auto` vs best fixed) |
| --- | --- | ---: | ---: | ---: |
| Intel | Light, JIT off | `1` | `2` | `+1.25%` |
| Intel | Light, JIT on | `2` | `2` | `+0.34%` |
| Intel | Fast, JIT on | `1` | `2` | `+1.02%` |
| AMD | Light, JIT off | `5` | `3` | `+0.08%` |
| AMD | Light, JIT on | `3` | `3` | `-0.01%` |
| AMD | Fast, JIT on | `2` | `3` | `-0.04%` |

Guidance:

- Treat this table as historical context only.
- Do not use the older cross-host `keep mapping` disposition as current policy authority.
- Use `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md` as the current cross-host policy authority.

## Baseline Matrix (CSV authority)

All metrics below come from CSV artifacts (JSON companions were also captured).

| Mode  | Configuration    | Cargo Features                      | Runtime JIT Flags              |     ns/hash | hashes/sec | CSV Artifact                                                          | JSON Artifact                                                          |
| ----- | ---------------- | ----------------------------------- | ------------------------------ | ----------: | ---------: | --------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Light | Interpreter      | `bench-instrument`                  | `--jit off`                    | 352,134,236 |      2.840 | `perf_results/v5_baseline_light_interp_20260217_181405.csv`           | `perf_results/v5_baseline_light_interp_20260217_181405.json`           |
| Light | JIT Conservative | `jit bench-instrument`              | `--jit on --jit-fast-regs off` | 296,124,561 |      3.377 | `perf_results/v5_baseline_light_jit_conservative_20260217_181405.csv` | `perf_results/v5_baseline_light_jit_conservative_20260217_181405.json` |
| Light | JIT Fast-Regs    | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on`  | 285,092,406 |      3.508 | `perf_results/v5_baseline_light_jit_fastregs_20260217_181405.csv`     | `perf_results/v5_baseline_light_jit_fastregs_20260217_181405.json`     |
| Fast  | Interpreter      | `bench-instrument`                  | `--jit off`                    |  70,538,035 |     14.177 | `perf_results/v5_baseline_fast_interp_20260217_181405.csv`            | `perf_results/v5_baseline_fast_interp_20260217_181405.json`            |
| Fast  | JIT Conservative | `jit bench-instrument`              | `--jit on --jit-fast-regs off` |  11,265,603 |     88.766 | `perf_results/v5_baseline_fast_jit_conservative_20260217_181405.csv`  | `perf_results/v5_baseline_fast_jit_conservative_20260217_181405.json`  |
| Fast  | JIT Fast-Regs    | `jit jit-fastregs bench-instrument` | `--jit on --jit-fast-regs on`  |  10,267,659 |     97.393 | `perf_results/v5_baseline_fast_jit_fastregs_20260217_181405.csv`      | `perf_results/v5_baseline_fast_jit_fastregs_20260217_181405.json`      |

## Derived Comparisons (from CSV)

- Light JIT conservative vs Light interpreter: `1.189x` speedup (`15.91%` lower ns/hash).
- Light JIT fast-regs vs Light JIT conservative: `3.73%` lower ns/hash (`1.039x` speedup).
- Fast JIT conservative vs Fast interpreter: `6.261x` speedup (`84.03%` lower ns/hash).
- Fast JIT fast-regs vs Fast JIT conservative: `8.86%` lower ns/hash (`1.097x` speedup).
- Fast JIT fast-regs vs Fast interpreter: `85.44%` lower ns/hash.

## Exact Commands Used

Commands below were executed from a detached clean worktree with output directed to a temp directory outside the git tree, then copied into `perf_results/`. This preserves `git_dirty=false` across all six rows.

```bash
# clean-worktree setup (example)
git worktree add --detach /tmp/oxide-randomx-v5-baseline-clean 00840a941c5411662693d5396e19a664dbc797cf
cd /tmp/oxide-randomx-v5-baseline-clean
OUT=/tmp/oxide-randomx-v5-baseline-out
mkdir -p "$OUT"
THREADS=32

# Light interpreter
cargo run --release --example perf_harness --features "bench-instrument" -- --mode light --jit off --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format csv  --out "$OUT/v5_baseline_light_interp_20260217_181405.csv"
cargo run --release --example perf_harness --features "bench-instrument" -- --mode light --jit off --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format json --out "$OUT/v5_baseline_light_interp_20260217_181405.json"

# Light JIT conservative
cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format csv  --out "$OUT/v5_baseline_light_jit_conservative_20260217_181405.csv"
cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode light --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format json --out "$OUT/v5_baseline_light_jit_conservative_20260217_181405.json"

# Light JIT fast-regs
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format csv  --out "$OUT/v5_baseline_light_jit_fastregs_20260217_181405.csv"
cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode light --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format json --out "$OUT/v5_baseline_light_jit_fastregs_20260217_181405.json"

# Fast matrix
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "bench-instrument" -- --mode fast --jit off --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format csv  --out "$OUT/v5_baseline_fast_interp_20260217_181405.csv"
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "bench-instrument" -- --mode fast --jit off --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format json --out "$OUT/v5_baseline_fast_interp_20260217_181405.json"

OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode fast --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format csv  --out "$OUT/v5_baseline_fast_jit_conservative_20260217_181405.csv"
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "jit bench-instrument" -- --mode fast --jit on --jit-fast-regs off --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format json --out "$OUT/v5_baseline_fast_jit_conservative_20260217_181405.json"

OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode fast --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format csv  --out "$OUT/v5_baseline_fast_jit_fastregs_20260217_181405.csv"
OXIDE_RANDOMX_FAST_BENCH=1 cargo run --release --example perf_harness --features "jit jit-fastregs bench-instrument" -- --mode fast --jit on --jit-fast-regs on --iters 50 --warmup 5 --threads "$THREADS" --large-pages off --format json --out "$OUT/v5_baseline_fast_jit_fastregs_20260217_181405.json"

# copy results into repo
cp "$OUT"/v5_baseline_*_20260217_181405.* <repo>/perf_results/
```

## Artifact Manifest

- `perf_results/P0_1_rebaseline_current_head_clean_matrix_2026-02-17.md`
- `perf_results/v5_baseline_light_interp_20260217_181405.csv`
- `perf_results/v5_baseline_light_interp_20260217_181405.json`
- `perf_results/v5_baseline_light_jit_conservative_20260217_181405.csv`
- `perf_results/v5_baseline_light_jit_conservative_20260217_181405.json`
- `perf_results/v5_baseline_light_jit_fastregs_20260217_181405.csv`
- `perf_results/v5_baseline_light_jit_fastregs_20260217_181405.json`
- `perf_results/v5_baseline_fast_interp_20260217_181405.csv`
- `perf_results/v5_baseline_fast_interp_20260217_181405.json`
- `perf_results/v5_baseline_fast_jit_conservative_20260217_181405.csv`
- `perf_results/v5_baseline_fast_jit_conservative_20260217_181405.json`
- `perf_results/v5_baseline_fast_jit_fastregs_20260217_181405.csv`
- `perf_results/v5_baseline_fast_jit_fastregs_20260217_181405.json`
- `perf_results/v5_baseline_capture_20260217_181405.log`
- `perf_results/v5_baseline_provenance_20260217_181405.txt`

## Baseline Hygiene Note

- The baseline matrix above is clean (`git_dirty=false`) and remains the current baseline authority.
- Newer experimental captures in this file (v4_05/v4_06/v4_11) are decision-specific evidence and should not replace the baseline matrix unless re-captured as a full clean six-row set.
- Current HEAD (`00840a9`) now has a full clean six-row baseline matrix in `perf_results/`.

## Supported-Path Baseline Snapshot Link

- Supported-path baseline snapshot: `perf_results/PERF_COMP.md` (summary only; primary supported-path authority is `perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`, and current integrated experimental policy lives in `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md`).

## Experimental Feature Policy Index (Current Authority)

| Feature | Current Decision | Primary Decision Memo | Host Coverage (Direct A/B) | Provenance Quality |
| --- | --- | --- | --- | --- |
| `threaded-interp` | Closed negative result; parked experimental; runtime-default off | `perf_results/P2_4_integrated_full_features_authority_2026-03-26.md` | AMD Family 23 direct A/B base plus v9 integrated authority host set | Historical direct A/B base is exploratory (`git_dirty=true`); current policy read comes from v9 integrated authority |
| `superscalar-accel-proto` | Parked experimental research lane; feature-gated only; scalar reference retained; not in supported path | `perf_results/P2_5_superscalar_v9_disposition_2026-03-26.md` | AMD Family 23 Model 8 + AMD Family 23 Model 113 + Intel Family 6 Model 45 + Intel Family 6 Model 58, with integrated v9 authority on AMD `23/8` Win/Linux and Intel `6/45`/`6/58` Linux | Current v9 disposition keeps the branch parked because clean Light upside is still real, but Fast mode is not promotive overall and AMD Windows remains too mixed for support |
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

Latest clean Intel duplicate-family confirmation:

- `perf_results/Intel/v6_10_simd_blockio_intel_family_evidence_2026-03-01.md`
- `perf_results/Intel/v6_10_simd_blockio_summary_intel_fam6_mod45_20260301_185552.json`

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

## v6.10 Clean Intel `simd-blockio` Family Evidence (2026-03-01)

Primary memo:

- `perf_results/Intel/v6_10_simd_blockio_intel_family_evidence_2026-03-01.md`

Primary analysis artifact:

- `perf_results/Intel/v6_10_simd_blockio_summary_intel_fam6_mod45_20260301_185552.json`

Host identity:

- `GenuineIntel`
- family `6`
- model `45`
- `Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz`

Clean rerun outcome:

- This is duplicate-family confirmation, not novel-family evidence.
- Counter spans stayed `0` across all Light/Fast ABBA pairs.
- Light forced-on rows were favorable in this clean rerun:
  - baseline vs forced ABBA: `-6.08%`
- Fast remained unsuitable for policy broadening:
  - direct baseline vs forced ABBA: `+1.27%`
  - guarded vs forced ABBA: `-1.29%`
  - baseline vs guarded ABBA: `-0.89%`

Interpretation:

- Default guarded behavior remains safe and near-scalar on the blocked host.
- Forced-on Fast behavior is still drift-sensitive and not a stable Intel win.
- This rerun does not support any Intel classifier broadening beyond the current Family 6 Model 45 block.

## v6.12 Cross-Host `simd-blockio` Classifier Policy (Historical, 2026-03-02)

Primary memo:

- `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-02.md`

Decision:

- Keep the current `src/vm/mod.rs` classifier unchanged.
- Keep the Intel Family `6` Model `45` runtime block.
- Do **not** use the clean Intel rerun to broaden Intel-family coverage or to remove the block.

Why policy does not broaden:

- Intel `v6.10` is duplicate-family confirmation on the already-blocked host class.
- AMD `v6.11` is duplicate-family confirmation on the already-measured Ryzen Family `23` Model `8` host.
- Fast remains unstable enough to block synthesis:
  - Intel direct forced-on vs scalar Fast ABBA: `+1.27%`
  - Intel adjacent Fast pairings split sign in the same session
  - AMD Fast `bench` and ABBA still disagree on direction
- Direct A/B host diversity is still limited to AMD Family `23` Model `8` and Intel Family `6` Model `45`.

Blocker classification:

- duplicate-family confirmation on both vendors
- mixed/drift-sensitive Fast results
- insufficient host diversity for safe classifier synthesis

Current policy implication:

- Keep `simd-blockio` experimental and CPU-conditional.
- Keep the current Model `45` guard as the only hard runtime block.
- Require novel-family Intel and AMD evidence before any future classifier broadening pass.

Update note (`2026-03-08`):

- Novel-family evidence is now available on Intel `6/58` and AMD `23/113`.
- Current policy authority is `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`.
- That refresh keeps the classifier unchanged and freezes broader policy work.

## v7.09 Intel Novel-Family `simd-blockio` Attempt (Blocked, 2026-03-05)

Primary limitation memo:

- `perf_results/Intel/v7_09_simd_blockio_intel_novel_family_gap_blocked_2026-03-05.md`

Host provenance artifact:

- `perf_results/Intel/v7_09_novel_family_host_provenance_intel_20260305_232023.txt`

Outcome:

- Host identity remained `GenuineIntel` family `6` model `45` (stepping `7`), which is the already-covered blocked class.
- This prompt was intentionally stopped before duplicate-family A/B reruns.
- No new Intel novel-family `simd-blockio` policy evidence was produced from this machine.

## v7.09 Intel Novel-Family `simd-blockio` Evidence (2026-03-06)

Primary memo:

- `perf_results/Intel/v7_09_simd_blockio_intel_novel_family_evidence_2026-03-06.md`

Primary analysis artifact:

- `perf_results/Intel/v7_09_simd_blockio_summary_intel_fam6_mod58_20260306_191318.json`

Host identity:

- `GenuineIntel`
- family `6`
- model `58`
- stepping `9`
- `Intel(R) Core(TM) i5-3360M CPU @ 2.80GHz`

Outcome summary:

- This is a valid Intel novel-family capture (`6/58`, not blocked `6/45`).
- Clean provenance: captured rows report `git_dirty=false`.
- Correctness validation passed for measured states (`oracle`, `simd-blockio oracle`, and targeted `simd` tests).
- Counter spans remained `0` across all Light/Fast ABBA pairs.
- Fast mode stayed mixed/drift-sensitive:
  - baseline vs guarded ABBA: `-5.55%`
  - guarded vs forced ABBA: `-2.43%`
  - baseline vs forced ABBA: `+7.24%`

Interpretation:

- This closes the Intel-side novel-family evidence gap for prompt `v7.09`.
- This run alone is not sufficient to broaden classifier policy.
- Keep Fast interpretation conservative and keep the existing Intel `6/45` guard unchanged.
- Current cross-host authority now lives in `perf_results/P1_2_simd_blockio_cross_host_policy_2026-03-08.md`.
- That refresh keeps the classifier unchanged and freezes broader `simd-blockio` policy work pending better hosts and stronger Fast agreement.

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

## P1.1 Dispatch-Level Interpreter Improvements (2026-02-18)

Primary memo:

- `perf_results/P1_1_dispatch_level_interpreter_improvements_2026-02-18.md`

Primary analysis artifact:

- `perf_results/v5_04_intel_dispatch_analysis_20260218_191201.json`

Mechanism summary:

- Reduced dispatch overhead in `src/vm/mod.rs` by:
  - replacing several hot `src==dst` branches with branchless selectors in interpreter instruction handlers
  - switching `execute_program_match` instruction fetch to unchecked pointer loads under explicit loop bounds

Measured on Intel host (Light interpreter, `iters=100`, `warmup=10`, `threads=32`, `large-pages off`):

- clean reference capture (`git_dirty=false`): `perf_results/v5_04_clean_head_baseline_light_interp_20260218_191500.csv`
- pre-patch capture: `perf_results/v5_04_intel_pre_light_interp_20260218_190641.csv`
- post-patch capture: `perf_results/v5_04_intel_post_light_interp_20260218_191201.csv`

Post vs pre deltas:

- `execute_program_ns_interpreter`: `-5.74%`
- `ns_per_hash`: `-1.63%`
- `prepare_iteration_ns`: `+0.80%`
- `finish_iteration_ns`: `-0.65%`

Interpretation:

- Execute-stage target band (`>=3%` improvement) is met on this host.
- End-to-end `ns/hash` improved in matching direction.
- Secondary-host (AMD) patch-level rerun was not available in this session and remains an explicit evidence gap.

## P2.2 JIT Fast-Regs Optimization Follow-Up (Intel, 2026-02-21, Historical Exploratory Input)

Primary memo:

- `perf_results/P2_2_jit_fastregs_cross_host_optimization_2026-02-21.md`

Primary analysis artifacts:

- `perf_results/v5_06_intel_final_analysis_20260221_114554.json`
- `perf_results/v5_06_light_abba_replication_20260221_114554.json`
- `perf_results/v5_06_perf_compare_post3_20260221_113703.txt`

Current authoritative memos:

- `perf_results/Intel/P2_2_jit_fastregs_clean_rerun_intel_2026-03-01.md`
- `perf_results/AMD/P2_2_jit_fastregs_clean_rerun_amd_2026-03-01.md`
- `perf_results/P2_2_jit_fastregs_cross_host_decision_2026-03-01.md`

Change summary:

- Candidate optimization in JIT fast-regs path replaces dataset-base modulo-by-division with mask arithmetic (`dataset_base_mask`) in `src/vm/jit/x86_64.rs` / `src/vm/mod.rs`.

Intel-host summary (`git_dirty=true`, exploratory evidence only):

- Fast pre ABBA (`20260221_111127`): `-13.84%` (`jit-fastregs` vs conservative).
- Fast post ABBA (`20260221_113024`): `-17.43%`.
- Fast relative change vs pre: `-3.60` percentage points (more favorable to `jit-fastregs`).
- Light ABBA replication set:
  - `20260221_113703`: `+0.96%`
  - `20260221_114554`: `-1.22%`
  - combined mean: `-0.15%` (near-neutral, sign-flipping).

Counter/stage notes:

- Fast `jit_fastregs_sync_*` and spill/reload counts remained unchanged (no count reduction mechanism observed).
- Fast execute-stage relative delta improved (`execute_program_ns_jit` pre `-15.84%` -> post `-20.00%` vs conservative).

Interpretation:

- This 2026-02-21 memo is historical exploratory input only.
- The later clean Intel rerun failed the roadmap keep criterion: Fast uplift collapsed from `-15.25%` baseline to `-2.00%` candidate, while the Fast fast-regs path regressed `+16.01%`.
- AMD guardrails later passed, but that did not rescue promotion.
- Final cross-host disposition is **drop the candidate and remove the exact patch from current code** while keeping the baseline `jit-fastregs` feature opt-in.

## P3.1 Prefetch Auto-Tune Sweep (Intel, 2026-02-21, Historical Exploratory Input)

Status note:

- This exploratory `v5_07` Intel sweep is superseded by the clean `v6_02` refresh above.
- Keep it only as historical context for how the older near-tie conclusion was formed.

Current cross-host memo:

- `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`

Historical cross-host memo:

- `perf_results/unlabeled/P3_1_prefetch_auto_tune_cross_host_2026-02-21.md`

Primary Intel artifacts:

- `perf_results/v5_07_prefetch_sweep_manifest_intel_20260221_125544.csv`
- `perf_results/v5_07_prefetch_sweep_provenance_intel_20260221_125544.txt`
- `perf_results/v5_07_prefetch_summary_intel_20260221_125544.json`
- `perf_results/v5_07_prefetch_summary_intel_20260221_125544.md`

Method summary:

- Sweep points: fixed `OXIDE_RANDOMX_PREFETCH_DISTANCE=0..8` plus `OXIDE_RANDOMX_PREFETCH_AUTO=1`.
- Repeats: `3` per point.
- Run-order control: randomized order per repeat (seeded/shuffle recorded in manifest).
- Configs measured:
  - Light mode, JIT off
  - Light mode, JIT on (conservative)
  - Fast mode, JIT on (conservative)

Intel results (`ns/hash`, lower is better):

| Mode | Best Fixed Distance | Auto Selected Distance | Auto vs Best Fixed |
| --- | ---: | ---: | ---: |
| Light, JIT off | `1` | `2` | `+1.25%` |
| Light, JIT on | `2` | `2` | `+0.34%` |
| Fast, JIT on | `1` | `2` | `+1.02%` |

Noise/drift highlights:

- Effective prefetch env consumption checks passed with no schema/semantics mismatches.
- Mode-level run-order drift was modest in this run set (`-0.96%`, `+0.32%`, `+1.25%` by mode).
- Fast fixed-distance tails (`7/8`) showed higher variance than auto in this host run.

Intel host guidance from this pass:

- Auto-selected distance remained `2` (as expected for this Intel family classification path).
- Best-fixed edges (`distance=1`) in two configs were small (~1%) and within exploratory-noise band.
- Keep current Intel auto mapping as operational default.

Cross-host status:

- This historical `v5_07` interpretation is superseded by the clean current-head cross-host memo:
  - `perf_results/unlabeled/P0_5_clean_prefetch_cross_host_decision_2026-03-01.md`
- Current disposition still keeps the mapping unchanged, but only with explicit remaining uncertainty.

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
