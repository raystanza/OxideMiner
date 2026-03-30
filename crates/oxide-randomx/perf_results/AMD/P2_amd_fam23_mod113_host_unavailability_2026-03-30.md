# AMD `23/113` Host Unavailability Memo

Date: 2026-03-30

## Scope

This memo records the current v10 status of host class
`amd_fam23_mod113_windows` using only the checked-in `ff_*` authority capsules
and the current authority workflow surfaces.

It does not claim any fresh rerun evidence after the last captured
same-SHA rerun set.

## Host Identity

- host class: `amd_fam23_mod113_windows`
- host label: `AMD R5 3600 / Win11`
- CPU: `AuthenticAMD`, family `23`, model `113`, stepping `0`
- CPU model string: `AMD Ryzen 5 3600 6-Core Processor`
- OS: `Microsoft Windows 11 Pro`, version `2009`, build `26200`
- thread count: `12`
- git SHA: `17ef71850b9cfada075e52f4791f362f6f4e3e99`
- rustc: `rustc 1.93.0 (254b59607 2026-01-19)`
- rerun group:
  `amd_fam23_mod113_windows__17ef718__t12__i50w5__pages_off-large_pages_on`

## Historical Artifact Set Relied On

Primary supporting authority capsule:

- `crates/oxide-randomx/perf_results/AMD/ff_amd_fam23_mod113_windows_20260320_211512`

Same-SHA rerun reference:

- `crates/oxide-randomx/perf_results/AMD/ff_amd_fam23_mod113_windows_20260318_210634`

Workflow surfaces used to interpret them:

- `crates/oxide-randomx/perf_results/full_features_authority_index_v10.json`
- `crates/oxide-randomx/docs/full-features-benchmark-v9-workflow.md`
- `cargo run -p oxide-randomx --release --bin full_features_authority -- compare --capture crates/oxide-randomx/perf_results/AMD/ff_amd_fam23_mod113_windows_20260318_210634`

## What The Existing Evidence Shows

The March 18, 2026 and March 20, 2026 captures are same-host, same-SHA,
same-settings reruns.

Provenance identity matches across both captures:

- same `host_class_id`
- same SHA `17ef718`
- same `rustc`
- same `threads=12`
- same `perf_iters=50`
- same `perf_warmup=5`
- same page-profile set: `pages_off,large_pages_on`

The instability is concrete rather than qualitative:

1. `large_pages_on` realized page backing changed materially.
   - `2026-03-18 21:06:34 -04:00`:
     `large_pages_on` realized dataset large pages `true` and scratchpad large
     pages `true`
   - `2026-03-20 21:15:12 -04:00`:
     `large_pages_on` realized dataset large pages `false` and scratchpad large
     pages `false`
2. The primary integrated superscalar ABBA row changed materially.
   - March 18:
     `baseline_vs_superscalar_proto | JitFastRegs | Light | large_pages_on`
     delta `-3.25%`, classified `likely_signal`
   - March 20:
     the same row moved to `-0.75%`, classified `likely_noise`
3. `pages_off` remained a stable control with no large-page realization on
   either rerun, so the disagreement is concentrated in the `large_pages_on`
   authority surface rather than a whole-capture provenance mismatch.

## Current Access Limitation

The current working context establishes that remote access to this Windows host
is unavailable as of 2026-03-30.

The exact onset date of the access loss is not recorded in-tree. This memo
therefore makes only the bounded claim that the host is unavailable no later
than 2026-03-30.

## Current Classification

`amd_fam23_mod113_windows` should currently be treated as
`supporting-only`, not `authority-grade` and not purely `research-only`.

Reasoning:

- the captures are clean (`git_dirty=false`) and remain valid supporting
  historical evidence
- the same-SHA rerun disagreement prevents authority-grade treatment
- the host-access loss prevents resolving that disagreement with fresh reruns
- the evidence is still stronger than ad hoc exploratory work because the two
  checked-in capsules preserve a controlled same-SHA comparison surface

## Open Questions

These questions remain unresolved until fresh reachable hardware evidence is
available for this exact host class:

- is `large_pages_on` realization reliable on this host class or only
  opportunistic
- does integrated Light superscalar behavior stay directionally stable on
  repeated same-SHA runs
- do isolated and integrated superscalar readings converge if the host can be
  rerun under the same contract
- should this host class remain `supporting-only`, or could it ever qualify
  for authority treatment

## Reopen Conditions

Reopen this host-class classification only if one of these happens:

1. Access to the original `amd_fam23_mod113_windows` machine is restored and
   documented in-tree.
2. A fresh machine is used, but it is labeled as a different host class instead
   of being treated as the same `23/113` authority source.

If access is restored to the original host class, the minimum evidence needed
is:

1. repeated same-SHA reruns with the canonical v10 settings
2. full preserved `ff_*` authority capsules, not partial summaries
3. explicit realized page-backing fields for `pages_off` and `large_pages_on`
4. comparison through `full_features_authority -- compare`
5. an intentional update to `full_features_authority_index_v10.json`

Until then, the March 18 and March 20, 2026 capsules remain the last known
supporting evidence for AMD `23/113` Windows.
