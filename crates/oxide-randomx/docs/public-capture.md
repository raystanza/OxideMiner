# Public Capture

This document describes the generic outside-host capture runner.

- binary: `oxide-randomx-public-capture`
- packaging helpers:
  - `scripts/build/package_oxide_randomx_public_capture.sh`
  - `scripts/build/package_oxide_randomx_public_capture.ps1`
- embedded release identifier env var: `OXIDE_RANDOMX_CAPTURE_RELEASE_ID`

## Purpose

`oxide-randomx-public-capture` is a single-binary runner for collecting
sanitized benchmark artifacts from Windows and Linux x86_64 hosts without
shipping the full workspace checkout.

It is intentionally narrower than the local maintainer workflow:

- no automatic upload
- no background network traffic
- no wallet or mining activity
- no raw git SHA in the public artifact surface

## Profiles

- `standard`: shorter default capture
- `full`: deeper rerun profile

## Usage

```bash
./oxide-randomx-public-capture --accept-data-contract
./oxide-randomx-public-capture --profile full --accept-data-contract
./oxide-randomx-public-capture --validate-only
```

## Outputs

Each run emits:

- `README_FIRST.txt`
- `SUMMARY.txt`
- `summary.json`
- `SHARE_THIS_FILE.txt`
- `meta/`
- `matrix/`
- `abba/`
- `superscalar/`
- `oxide-randomx-public-results-<bundle_id>.zip`

The machine-readable metadata includes:

- `release_id`
- `bundle_id`
- sanitized host information
- page-backing summaries
- matrix rows, pair runs, and pair summaries

## Notes

- The runner is for local evidence collection, not for changing project
  defaults on its own.
- Any policy change still needs an intentional docs update in this repo.
