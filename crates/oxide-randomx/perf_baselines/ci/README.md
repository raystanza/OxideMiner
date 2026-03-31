# CI Perf Gate Fixtures

This directory contains the checked-in fixture set for the mandatory CI perf
gate. It is intentionally narrow:

- scope: supported-path regression guardrail only
- enforced scenarios:
  - `light_interp`
  - `light_jit_conservative`
  - `fast_jit_fastregs`
- primary metric: `ns_per_hash`
- threshold source: `crates/oxide-randomx/perf_baselines/ci/manifest.txt`

These fixtures are CI guardrails, not broad host-performance authority.

## Adjacent Validation

The same GitHub-hosted workflow also runs a lightweight
`examples/oxideminer_integration.rs` smoke on the validation build. That step
checks lifecycle wiring and emitted report shape, but it does not replace local
perf validation.

## Fixture Provenance

When refreshing fixtures, record in the same patch:

- capture date
- commit SHA
- toolchain
- whether the worktree was dirty
- repeat count
- threshold rationale

Avoid encoding machine-specific policy claims here. This README should explain
the CI guardrail process, not carry a public host inventory.

## Refresh Flow

1. Prefer running the `oxide-randomx CI` workflow with `workflow_dispatch`.
2. Inspect the downloaded candidate and compare artifacts.
3. If the shift is intentional and stable, replace the affected baseline CSV
   and update this provenance note in the same patch.
4. If you bless a non-GitHub-hosted refresh, record why it is acceptable for
   this CI guardrail.
