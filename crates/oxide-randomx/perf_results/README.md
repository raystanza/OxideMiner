# Full Features Authority Capsules

This directory is the checked-in v10 authority surface for the internal
`oxide-randomx` full-features workflow.

It is intentionally smaller than the original standalone-repo capture bundles.
The goal here is to keep the durable, reviewable inputs needed by
`tools/full_features_authority.rs` inside the `OxideMiner` tree:

- provenance identity
- primary `large_pages_on` ABBA pair summary rows
- realized page-backing summaries
- current host-class authority classification

The checked-in `ff_*` directories in this tree are therefore **authority
capsules**, not full raw bundle re-exports. They preserve the compare/update
surface needed for v10 review without dragging in every historical matrix file.

Current source of truth:

- `crates/oxide-randomx/perf_results/full_features_authority_index_v10.json`
- `crates/oxide-randomx/docs/full-features-benchmark-v9-workflow.md`
- `crates/oxide-randomx/perf_results/AMD/P2_amd_fam23_mod113_host_unavailability_2026-03-30.md`

Design notes:

- Authority capsules stay under `crates/oxide-randomx/perf_results/...` so
  repo-root runs do not spill durable artifacts into the workspace root.
- The primary comparison surface is the rounded `large_pages_on` ABBA summary
  row plus page-backing realization fields.
- AMD `23/113` Windows remains supporting-only because same-SHA reruns changed
  realized `large_pages_on` backing and the primary superscalar row.
- As of `2026-03-30`, the remote AMD `23/113` Windows host is unavailable, so
  the supporting-only classification is historical and current rerun follow-up
  is blocked.

Representative local commands from the `OxideMiner` repo root:

```bash
cargo run -p oxide-randomx --release --bin full_features_authority -- validate-index

cargo run -p oxide-randomx --release --bin full_features_authority -- compare \
  --capture crates/oxide-randomx/perf_results/AMD/ff_amd_fam23_mod113_windows_20260318_210634
```

When capturing a new run from the repo root, keep the output in-tree
explicitly:

```bash
cargo run -p oxide-randomx --release --bin full_features_benchmark --features "jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto" -- \
  --out-dir crates/oxide-randomx/perf_results/AMD/ff_amd_fam23_mod8_windows_<timestamp>
```

Intentional refresh flow:

1. Capture a new `ff_*` directory with an explicit `crates/oxide-randomx/perf_results/...` output path.
2. Compare it against the indexed host-class authority with `full_features_authority -- compare`.
3. Review provenance identity, rerun relationship, realized page backing, and ABBA delta shifts.
4. If the new capture should become current, edit `full_features_authority_index_v10.json` in the same patch.
5. Keep replaced captures in `related_captures` when they still matter as rerun or superseded context.
6. Re-run `full_features_authority -- validate-index`.
