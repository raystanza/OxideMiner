# Superscalar Research Program

This is crate-internal research guidance for `superscalar-accel-proto`.
It is not a parent contract document and it does not promote the branch into
the supported path.

## Current Fence

- `superscalar-accel-proto` is the only active research lane in the current
  integrated crate.
- It remains feature-gated and off by default.
- `threaded-interp` stays closed negative.
- `simd-blockio` and `simd-xor-paths` stay experimental and non-default.
- No Intel-only or AMD-only supported build split is in scope.

## Required Research Inputs

Any future superscalar proposal must keep all of these in scope:

1. correctness first
2. repeated-run stability on current authority hosts
3. integrated Light improvement, not isolated-harness wins alone
4. Fast guardrails that stay non-regressive in practical use
5. reviewable implementation complexity

## Reopen Checklist

Do not advance a superscalar change beyond research review unless all of these
are satisfied:

1. Correctness
   Keep the scalar reference path in tree and preserve differential value from
   `examples/superscalar_hash_harness.rs` by comparing `--impl active` against
   `--impl scalar`.
2. Oracle coverage
   Pass `cargo test -p oxide-randomx --features superscalar-accel-proto` and
   `cargo test -p oxide-randomx --features superscalar-accel-proto --test oracle`.
3. Repeated-run stability
   Show repeated same-SHA stability on the clean authority hosts rather than on
   one favorable run.
4. Integrated Light requirement
   Show material, repeated `large_pages_on` ABBA improvement on clean AMD and
   Intel authority hosts.
5. Fast guardrail requirement
   Avoid practical Fast regressions in either steady-state `ns/hash` or
   meaningful dataset-initialization cost.
6. Complexity/reviewability
   Keep diffs narrow, invariants explicit, and the scalar fallback easy to
   audit.

## Stop Rules

Stop a proposal in this lane if any of these occur:

1. correctness parity fails
2. the scalar reference path or differential harness value is weakened
3. the favorable story depends on matrix-only rankings instead of the primary
   ABBA surface
4. Light gains appear only in isolated microbench results and not in repeated
   integrated Light measurements
5. Fast guardrails regress materially
6. the implementation grows in complexity faster than the evidence quality
7. the plan assumes fresh AMD `23/113` Windows follow-up without naming the
   current hardware limitation explicitly

## Hardware Prerequisites

Fresh AMD or Windows follow-up is not automatically available.

- AMD `23/113` Windows is currently supporting-only historical evidence with an
  unresolved rerun gap.
- Any plan that depends on new `amd_fam23_mod113_windows` evidence must treat
  restored access to the original host as an explicit prerequisite.
- If a different AMD or Windows machine is used, it must be labeled as a
  different host class instead of being substituted for `23/113`.

## Differential Harness Value

Keep these harness uses explicit:

```bash
cargo run -p oxide-randomx --release --example superscalar_hash_harness --features superscalar-accel-proto -- --impl active --format json --iters 2000 --warmup 200 --items 128

cargo run -p oxide-randomx --release --example superscalar_hash_harness --features superscalar-accel-proto -- --impl scalar --format json --iters 2000 --warmup 200 --items 128
```

The point of the harness is differential interpretation, not a replacement for
the integrated authority workflow.
