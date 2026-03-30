# Integrated Full-Features Authority (v10)

Date: 2026-03-30

## Scope

This memo is the current integrated feature-interaction authority for the
checked-in v10 `ff_*` capsules under `crates/oxide-randomx/perf_results/`.

It synthesizes:

- `crates/oxide-randomx/perf_results/full_features_authority_index_v10.json`
- `crates/oxide-randomx/docs/full-features-benchmark-v9-workflow.md`
- the current AMD and Intel `ff_*` authority capsules preserved in-tree
- `crates/oxide-randomx/perf_results/AMD/P2_amd_fam23_mod113_host_unavailability_2026-03-30.md`
- the existing feature-specific policy memos for `threaded-interp`,
  `simd-blockio`, `simd-xor-paths`, and `superscalar-accel-proto`

This memo does not replace the supported-path baseline authority.
`crates/oxide-randomx/perf_results/P0_6_current_head_cross_host_authority_2026-03-11.md`
remains the default-path authority for interpreter, conservative JIT, and
baseline `jit-fastregs`.

## Current Host Set

The current indexed v10 host set is:

| Host class | Label | Tier | Rerun state | `large_pages_on` realized backing | Primary Light ABBA row | Current read |
| --- | --- | --- | --- | --- | --- | --- |
| `amd_fam23_mod8_windows` | AMD R5 2600 / Win11 | authority | `single_capture_currently_accepted` | dataset `all_true`, scratchpad `all_true` | `-5.75%`, `likely_signal` | clean authority host with clear Light integrated upside |
| `amd_fam23_mod8_linux` | AMD R5 2600 / Ubuntu | authority | `single_capture_currently_accepted` | dataset `all_true`, scratchpad `all_true` | `-4.50%`, `likely_signal` | clean authority host with clear Light integrated upside |
| `intel_fam6_mod45_linux` | Intel Dual-Xeon / Ubuntu | authority | `single_capture_currently_accepted` | dataset `all_true`, scratchpad `all_true` | `-3.25%`, `likely_signal` | clean authority host with clear Light integrated upside |
| `intel_fam6_mod58_linux` | Intel i5 / Ubuntu | authority | `single_capture_currently_accepted` | dataset `all_true`, scratchpad `all_true` | `-1.10%`, `likely_noise` | clean authority host, but integrated Light signal is near-neutral |
| `amd_fam23_mod113_windows` | AMD R5 3600 / Win11 | supporting | `rerun_sensitive_same_sha_host_unavailable` | `2026-03-20`: dataset `all_false`, scratchpad `all_false`; `2026-03-18` rerun: dataset `all_true`, scratchpad `all_true` | current indexed capture: `-0.75%`, `likely_noise`; rerun reference: `-3.25%`, `likely_signal` | historical supporting evidence only; same-SHA reruns disagreed and the original host is unavailable no later than `2026-03-30` |

The primary ABBA row above is the current v10 Tier 1 interaction row preserved
by the authority capsules:

- pair label:
  `baseline_vs_superscalar_proto | superscalar_proto | JitFastRegs | Light | large_pages_on`
- lower `delta_pct_candidate_vs_baseline` favors the candidate integrated
  configuration

## What v10 Changes

The current v10 workflow changes the authority surface in these specific ways:

1. The integrated host-class authority set is now explicit and reviewable
   in-tree through `full_features_authority_index_v10.json` and the checked-in
   capsules rather than through scattered host notes.
2. AMD `23/113` Windows is no longer an implicit pending rerun. It is now an
   explicit supporting-only host class with a machine-readable rerun status of
   `rerun_sensitive_same_sha_host_unavailable`.
3. Realized page-backing fields are now part of the current integrated
   authority read. Requested page profiles alone are not treated as proof that
   large or 1 GB pages actually materialized.
4. The current integrated Light superscalar read is bounded more precisely:
   three authority hosts show a likely-signal win, one authority host is
   near-neutral, and the historical AMD `23/113` Windows host remains
   unresolved because reruns changed both realized backing and the ABBA read.

## What v10 Does Not Change

The current v10 integrated authority does not change project policy on these
points:

1. The supported path remains baseline `jit-fastregs`; there is no promotion of
   an all-features experimental mix into the parent default path.
2. `threaded-interp` remains a parked experimental closed negative result.
   Historical direct evidence remains the primary basis for that decision, and
   the v10 integrated capsules add no new Tier 1 evidence that reopens it.
3. `simd-blockio` remains experimental and CPU-conditional. The March 8, 2026
   cross-host policy memo remains primary, and the v10 integrated authority
   adds no higher-tier basis to promote it into the supported parent path or to
   change the Intel Family `6` Model `45` runtime guard.
4. `simd-xor-paths` remains an experimental follow-up with exploratory direct
   A/B evidence only. The v10 integrated authority adds no Tier 1 promotion
   case.
5. `superscalar-accel-proto` remains a parked research lane rather than an
   authority-grade supported opt-in. Light upside is still real on several
   hosts, but it is not clean cross-host consensus and it is still bounded by
   non-promotive Fast results and the unresolved AMD `23/113` rerun gap.
6. The no-vendor-split decision still stands. Nothing in the current v10
   corpus justifies separate AMD and Intel supported builds, and the loss of
   access to AMD `23/113` must not be treated as evidence either for or against
   vendor-specific behavior.

## ABBA vs Matrix Interpretation

Use these interpretation rules for the current v10 integrated authority:

1. Tier 1 integrated claims come from the preserved `large_pages_on` ABBA pair
   summaries on authority hosts.
2. Matrix-only "best config" rankings remain supporting orientation only. They
   do not outrank the ABBA row and they do not outrank the supported-path
   baseline memo.
3. The checked-in v10 capsules intentionally preserve provenance, the primary
   ABBA row, and page-backing realization summaries. They do not preserve a
   full matrix-ranking surface, so policy claims must stay narrow.
4. `pages_off` remains a supporting control profile.
5. Linux `huge_1g_requested` remains supporting semantics evidence, not the
   primary interaction authority surface.

## Realized Page Outcomes

Realized backing is part of the current interpretation, not a side note.

- On the four current authority hosts, `large_pages_on` realized large pages on
  both dataset and scratchpad in the preserved authority capture.
- On `amd_fam23_mod113_windows`, the same requested `large_pages_on` profile
  realized as `all_true` on `2026-03-18` and `all_false` on `2026-03-20`. That
  backing flip is one of the primary reasons the host cannot be treated as
  authority-grade.
- On `amd_fam23_mod8_linux` and `intel_fam6_mod45_linux`,
  `huge_1g_requested` realized 1 GB backing for the dataset while the
  scratchpad remained non-1-GB large pages. This is valid Linux semantics
  evidence, but it is still supporting-only.
- On `intel_fam6_mod58_linux`, `huge_1g_requested` fell back to non-1-GB large
  pages. That fallback does not invalidate the host; it reinforces that
  realized fields must be read directly instead of inferred from request flags.

## Current Policy Read

### Supported path

The supported path remains:

1. baseline `jit-fastregs`
2. conservative JIT fallback
3. interpreter fallback

Nothing in the v10 integrated all-features authority displaces that ordering.

### Experimental features

- `threaded-interp`: keep parked and off by default.
- `simd-blockio`: keep experimental, CPU-conditional, and off by default.
- `simd-xor-paths`: keep experimental and off by default.
- `superscalar-accel-proto`: keep parked as a research lane and off by
  default.

The current integrated memo is therefore mainly a bounding memo: it records
what the all-features host set does and does not justify, rather than
introducing a new experimental default.

## Blocked Claims And Reopen Conditions

These claims remain blocked pending new reachable hardware evidence:

1. authority-grade classification for `amd_fam23_mod113_windows`
2. any claim that `large_pages_on` realizes reliably on that host class
3. any claim that the integrated Light superscalar read on AMD `23/113`
   is stable across repeated same-SHA runs
4. any claim that isolated and integrated superscalar behavior now agree well
   enough to justify promotion
5. any vendor-specific supported build split or host-family-specific supported
   default based on the current corpus

Reopen the AMD `23/113` classification only under the conditions recorded in
`crates/oxide-randomx/perf_results/AMD/P2_amd_fam23_mod113_host_unavailability_2026-03-30.md`:

1. restore access to the original host and document it in-tree, or
2. capture a different machine under a different host class instead of treating
   it as the same `23/113` authority source

Until then, AMD `23/113` Windows remains supporting-only historical evidence,
not silent consensus and not an active rerun lane.

