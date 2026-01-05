# Solo Mining Design

## Overview

- Mining mode is selected via `--mode` (`pool` or `solo`) and mirrored in `config.toml` via `mode = "solo"` plus a `[solo]` table.
- Pool mining remains unchanged; solo mining uses a local `monerod` JSON-RPC endpoint and submits full blocks.

## Key Types

- `MiningMode` (CLI/config) drives backend selection.
- `solo::SoloRpcClient` handles JSON-RPC calls (`get_info`, `get_block_template`, `submit_block`).
- `solo::SoloTemplate` converts `monerod` templates into `PoolJob` plus a submit-ready block template blob.
- Existing worker loop remains unchanged and continues to accept `WorkItem { job: PoolJob, ... }`.

## Solo Flow

1. Poll `get_info` for height/sync status.
2. Poll `get_block_template` with the configured wallet + reserve size.
3. Convert the template into a `PoolJob`, broadcast to workers, and track template height/age.
4. When a worker reports a valid result, patch the nonce into the submit blob and call `submit_block`.
5. Update block counters and last-submit stats.

## Observability

- New stats include node height, template height/age, block submission results, and accepted/rejected block counts.
- Logs differentiate connection refused, unauthorized, RPC status errors, and node sync warnings.

## ZMQ

ZMQ notifications are not required for correctness; initial implementation uses polling with backoff.
The solo loop is structured so ZMQ-driven refresh can be added later without changing worker logic.
