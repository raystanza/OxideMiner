# Scripts

Scripts are grouped by purpose:

- `build/`: packaging and cross-target build helpers for distributable binaries
  and public capture bundles
- `ci/`: automation used by CI and perf-gate checks

Local performance artifacts should be written under
`crates/oxide-randomx/perf_results/`, which is intentionally untracked.

Rule of thumb:

- add packaging helpers under `build/`
- add automated checks under `ci/`
- prefer the Rust binaries in `tools/` over ad hoc host-specific wrapper scripts
