# Superscalar Research Program

This is crate-internal guidance for `superscalar-accel-proto`.
It does not promote the feature into the supported OxideMiner path.

## Current Fence

- `superscalar-accel-proto` remains feature-gated and off by default
- `threaded-interp` remains a closed negative result
- `simd-blockio` and `simd-xor-paths` remain experimental and non-default
- no vendor-split supported build policy is in scope

## Reopen Checklist

Do not advance this lane beyond research review unless all of these are true:

1. correctness parity holds against the scalar reference path
2. oracle coverage passes for the feature-gated build
3. repeated-run stability is demonstrated on the local validation set
4. integrated Light-mode wins are repeatable and not just microbench-only
5. Fast-mode guardrails remain acceptable
6. implementation complexity stays reviewable and easy to disable

## Stop Rules

Stop or park a proposal if:

1. correctness parity fails
2. the scalar reference path becomes harder to audit
3. the favorable story depends on matrix-only rankings instead of the primary
   ABBA surface
4. wins appear only in isolated microbenchmarks
5. Fast-mode behavior regresses materially
6. the proposal depends on hardware access or evidence that is not currently
   available and documented

## Differential Harness

Use the dedicated superscalar harness for differential local work:

```bash
cargo run -p oxide-randomx --release --example superscalar_hash_harness --features superscalar-accel-proto -- --impl active --format json --iters 2000 --warmup 200 --items 128

cargo run -p oxide-randomx --release --example superscalar_hash_harness --features superscalar-accel-proto -- --impl scalar --format json --iters 2000 --warmup 200 --items 128
```

The harness helps interpret isolated behavior. It does not, by itself, justify a
parent-default change.
