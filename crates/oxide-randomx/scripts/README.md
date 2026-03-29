# Scripts

Scripts are grouped by purpose:

- `build/`: packaging and cross-target build helpers for distributable binaries and bundles
- `capture/`: host capture runners and evidence-collection workflows
- `ci/`: automation used by CI and perf gate checks

Rule of thumb:

- add new distributable build/package helpers under `build/`
- add host-specific evidence collection under `capture/`
- add automated checks and fixture refresh helpers under `ci/`
