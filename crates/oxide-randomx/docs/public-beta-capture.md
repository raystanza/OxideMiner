# Public Beta Capture Runner

This document describes the public-facing beta capture runner:

- binary name: `oxide-randomx-beta-capture`

It is the tester-facing companion to the internal authority tool:

- internal tool: `full_features_benchmark`

## What It Is

`oxide-randomx-beta-capture` is the public single-binary runner for outside beta testers.

It reuses the shared capture engine extracted from the internal full-features benchmark flow, but it deliberately changes the surface area:

- smaller public CLI
- fixed profile-driven plans
- sanitized public artifacts
- no auto-upload
- automatic creation of a shareable zip file

## How It Differs From `full_features_benchmark`

`full_features_benchmark` remains the internal authority and deep-capture workflow.

The public runner is intentionally narrower:

- public runner:
  - `--profile standard|full`
  - `--out-dir PATH`
  - `--accept-data-contract`
  - `--validate-only`
- internal runner:
  - keeps authority-tier metadata
  - keeps full git provenance
  - keeps operator-facing authority workflow outputs
  - keeps deeper internal documentation expectations

The shared code boundary lives in:

- `src/full_features_capture.rs`

The public runner lives in:

- `tools/oxide_randomx_beta_capture.rs`

The internal authority wrapper lives in:

- `tools/full_features_benchmark.rs`

## Supported Scope

v1 public beta scope is intentionally narrow:

- `windows-x86_64`
- `linux-x86_64`

Do not claim support beyond that scope.

## Public Profiles

### `standard`

Default public beta profile.

It captures:

- baseline matrix on the canonical page profiles for the OS
- page-backing realization summary
- `threaded_interp` Light interpreter ABBA
- `simd-blockio` guarded ABBA on Light/Fast interpreter
- `superscalar_proto` ABBA on:
  - Light interpreter
  - Light JIT conservative
  - Light JIT fast-regs
  - Fast JIT conservative
  - Fast JIT fast-regs
- isolated superscalar microbench

### `full`

Deeper public rerun profile.

It stays close to the current internal full-features breadth:

- all current matrix rows
- full current ABBA family set
- superscalar isolated microbench

Use it for:

- reruns on interesting hosts
- same-host stability checks
- deeper follow-up after a useful `standard` run

## Startup Contract

Before heavy work starts, the public runner prints:

- `beta_release_id`
- `bundle_id`
- selected profile
- expected runtime class
- collected data categories
- excluded data categories
- explicit network statement
- output path

If `--accept-data-contract` is omitted, the runner asks the user to type `ACCEPT` before continuing.

If `--accept-data-contract` is present, the explicit prompt is skipped.

## Data Contract

### Collect

- CPU vendor, family, model, stepping, and model string
- logical thread count
- OS name, version, and build/kernel
- benchmark timings for baseline and selected experimental states
- realized page-backing results
- `beta_release_id`
- `bundle_id`

### Do Not Collect

- wallet data
- mining activity
- files outside the output directory
- browser history
- installed-application inventories
- automatic telemetry upload
- usernames or absolute local file paths in the intended public artifact surface

## Output Contract

Each public run emits:

- `README_FIRST.txt`
- `SUMMARY.txt`
- `summary.json`
- `meta/commands.log`
- `meta/manifest.txt`
- `meta/matrix_index.csv`
- `meta/pair_index.csv`
- `meta/pair_summary.csv`
- raw artifact trees under:
  - `matrix/`
  - `abba/`
  - `superscalar/`
- `SHARE_THIS_FILE.txt`
- an automatically generated share archive named like:
  - `oxide-randomx-beta-results-<bundle_id>.zip`

The share archive is the obvious file to send back. Testers do not need to zip anything manually.

## Sanitization Rules

The public runner does not intentionally expose:

- absolute executable paths
- usernames or home-directory paths
- raw private repo paths
- full private git SHAs

Instead, the public bundle uses:

- `beta_release_id`
- `bundle_id`
- relative artifact names

The internal mapping from public release ID to private source provenance stays outside the returned public bundle.

## Tester Flow

Typical run:

```bash
./oxide-randomx-beta-capture --accept-data-contract
```

Deeper rerun:

```bash
./oxide-randomx-beta-capture --profile full --accept-data-contract
```

Validation-only smoke:

```bash
./oxide-randomx-beta-capture --validate-only
```

## Operator Intake

Recommended intake order for a returned bundle:

1. read `README_FIRST.txt`
2. read `SUMMARY.txt`
3. inspect `summary.json`
4. inspect `meta/pair_summary.csv`
5. inspect interesting raw rows under `matrix/`, `abba/`, and `superscalar/`

Interpretation guidance:

- `standard` is the broad intake profile
- request `full` only for novel or interesting hosts
- internal authority classification still happens with the private workflow, not inside the public bundle
- `full_features_benchmark` remains the internal authority tool for trusted deep work

## Packaging

Use the packaging scripts for release bundles:

- shell: `scripts/build/package_oxide_randomx_beta_capture.sh`
- PowerShell: `scripts/build/package_oxide_randomx_beta_capture.ps1`

These scripts:

- build the public runner
- embed `OXIDE_RANDOMX_BETA_RELEASE_ID`
- package one binary plus one short instruction file
- emit `SHA256SUMS.txt`
- leave code signing as a manual release step outside the repo
