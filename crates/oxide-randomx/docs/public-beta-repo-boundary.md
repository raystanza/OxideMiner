# Public Beta Repo Boundary

This document defines the intended source boundary for the future public beta-tool repository.

## Goal

The public beta repo should be publishable without exposing the private authority workflow or private release-engineering metadata.

The public beta repo should contain only the code and docs needed to:

- inspect the tester-facing runner
- build the tester-facing runner
- reproduce the released tester-facing binary bundles

## Public-Safe Files

These files are the intended public-safe slice in the current private repo:

- `src/full_features_capture.rs`
- `tools/oxide_randomx_beta_capture.rs`
- `scripts/build/package_oxide_randomx_beta_capture.sh`
- `scripts/build/package_oxide_randomx_beta_capture.ps1`
- `docs/public-beta-capture.md`
- `docs/public-beta-repo-boundary.md`

These are the core export targets for a future public GitHub repo.

## Private-Only Files

These stay private:

- `tools/full_features_benchmark.rs`
- `tools/full_features_authority.rs`
- `docs/full-features-benchmark-v9-workflow.md`
- authority indexes under `perf_results/`
- private performance memos under `dev/`
- private release-engineering mappings from `beta_release_id` to private source provenance

## Current Shared Code Split

`src/full_features_capture.rs` is the shared engine layer.

It contains:

- host detection
- canonical page-profile definitions
- matrix and ABBA execution
- superscalar isolated capture
- raw artifact helpers
- public sanitization of raw perf outputs

It does not contain:

- internal authority indexing workflow
- private host-inventory policy docs
- private source-provenance mappings

## Export Checklist

When creating the public repo, copy or mirror:

1. the beta runner entrypoint
2. the shared capture engine
3. the package scripts
4. the public beta docs
5. the Cargo manifest entries needed for the public runner

Do not copy:

1. internal authority tooling
2. private performance memos
3. private `ff_*` authority artifacts
4. private release provenance notes

## Build Assumptions

The public repo will still need:

- the crate/library code required by `src/full_features_capture.rs`
- the same feature-gated runtime surface used by the public runner
- an externally supplied `OXIDE_RANDOMX_BETA_RELEASE_ID` for release builds

The release process should treat this as public metadata:

- `beta_release_id`

And treat this as private release-engineering metadata:

- the mapping from `beta_release_id` to internal source provenance

## Signing Hook

The current package scripts intentionally do not sign binaries.

The public release flow should add signing as an explicit external step:

1. build the unsigned package bundle
2. sign the binary outside the repo automation
3. regenerate or verify checksums if the signed binary changes
4. publish the signed bundle plus checksums

That keeps the source tree honest about what is and is not automated today.
