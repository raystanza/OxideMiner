#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/capture/run_v8_06_intel_ubuntu_capture.sh [--out-dir DIR]

Runs PROMPTv8_06 capture on an Intel Ubuntu host and writes host-tagged
v8_06 artifacts.

Defaults:
  out-dir: <repo>/perf_results/Intel
EOF
}

OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE_DIR="${OUT_DIR:-$REPO_ROOT/perf_results/Intel}"
mkdir -p "$STAGE_DIR"

TS="$(date +%Y%m%d_%H%M%S)"
DATE_STAMP="$(date +%F)"
VENDOR="$(lscpu | awk -F: '/Vendor ID/ {gsub(/^ +/,"",$2); print $2; exit}')"
FAMILY="$(lscpu | awk -F: '/CPU family/ {gsub(/^ +/,"",$2); print $2; exit}')"
MODEL="$(lscpu | awk -F: '/Model:/ {gsub(/^ +/,"",$2); print $2; exit}')"
STEPPING="$(lscpu | awk -F: '/Stepping/ {gsub(/^ +/,"",$2); print $2; exit}')"
CPU_MODEL="$(lscpu | awk -F: '/Model name/ {gsub(/^ +/,"",$2); print $2; exit}')"
THREADS="$(lscpu | awk -F: '/^CPU\(s\)/ {gsub(/^ +/,"",$2); print $2; exit}')"
OS_NAME="$(awk -F= '/^PRETTY_NAME=/ {gsub(/"/,"",$2); print $2}' /etc/os-release)"
KERNEL="$(uname -srmo)"

HOST_TAG="intel_fam${FAMILY}_mod${MODEL}"
EXPECTED_HOST=0
if [[ "$VENDOR" == "GenuineIntel" && "$FAMILY" == "6" && ( "$MODEL" == "45" || "$MODEL" == "58" ) ]]; then
  EXPECTED_HOST=1
fi

SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SHORT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
RUSTC_VER="$(cd "$REPO_ROOT" && rustc --version)"
WORKTREE="/tmp/oxide-randomx-v8_06-intel-clean-${TS}"

CMDLOG="${STAGE_DIR}/v8_06_commands_${HOST_TAG}_${TS}.log"
PROV="${STAGE_DIR}/v8_06_host_provenance_${HOST_TAG}_${TS}.txt"
MANIFEST="${STAGE_DIR}/v8_06_manifest_${HOST_TAG}_${TS}.txt"
INDEXCSV="${STAGE_DIR}/v8_06_perf_index_${HOST_TAG}_${TS}.csv"
SUMMARYJSON="${STAGE_DIR}/v8_06_superscalar_prototype_summary_${HOST_TAG}_${TS}.json"
MEMO="${STAGE_DIR}/v8_06_superscalar_prototype_${HOST_TAG}_${DATE_STAMP}.md"
ARTIFACT_LIST="${STAGE_DIR}/.v8_06_artifacts_${HOST_TAG}_${TS}.txt"

note_artifact() {
  local path="$1"
  printf '%s\n' "$(basename "$path")" >> "$ARTIFACT_LIST"
}

: > "$ARTIFACT_LIST"

{
  echo "# PROMPTv8_06 Intel superscalar prototype command log"
  echo "timestamp=${TS}"
  echo "date=${DATE_STAMP}"
  echo "host_tag=${HOST_TAG}"
  echo "stage_dir=${STAGE_DIR}"
  echo "git_sha=${SHA}"
  echo "git_sha_short=${SHORT_SHA}"
  echo "rustc=${RUSTC_VER}"
} > "$CMDLOG"
note_artifact "$CMDLOG"

{
  echo "timestamp=${TS}"
  echo "date=${DATE_STAMP}"
  echo "host_tag=${HOST_TAG}"
  echo "vendor=${VENDOR}"
  echo "family=${FAMILY}"
  echo "model=${MODEL}"
  echo "stepping=${STEPPING}"
  echo "cpu_model_string=${CPU_MODEL}"
  echo "os_name=${OS_NAME}"
  echo "kernel=${KERNEL}"
  echo "logical_threads=${THREADS}"
  echo "git_sha=${SHA}"
  echo "git_sha_short=${SHORT_SHA}"
  echo "rustc=${RUSTC_VER}"
  echo "stage_dir=${STAGE_DIR}"
} > "$PROV"
note_artifact "$PROV"

if [[ "$EXPECTED_HOST" -ne 1 ]]; then
  UNEXPECTED="${STAGE_DIR}/v8_06_unexpected_host_${HOST_TAG}_${TS}.txt"
  {
    echo "prompt=PROMPTv8_06"
    echo "status=unexpected_host"
    echo "timestamp=${TS}"
    echo "host_tag=${HOST_TAG}"
    echo "vendor=${VENDOR}"
    echo "family=${FAMILY}"
    echo "model=${MODEL}"
    echo "os_name=${OS_NAME}"
  } > "$UNEXPECTED"
  note_artifact "$UNEXPECTED"
  {
    echo "prompt=PROMPTv8_06"
    echo "timestamp=${TS}"
    echo "host_tag=${HOST_TAG}"
    echo "artifacts:"
    sort -u "$ARTIFACT_LIST" | sed 's/^/- /'
  } > "$MANIFEST"
  note_artifact "$MANIFEST"
  echo "Host does not match Intel Ubuntu inventory. Wrote: $UNEXPECTED" >&2
  exit 1
fi

git -C "$REPO_ROOT" worktree add --detach "$WORKTREE" "$SHA" >/dev/null

run_step() {
  local name="$1"
  local cmd="$2"
  local log_file="$3"
  local start_ts
  start_ts="$(date --iso-8601=seconds)"
  {
    echo
    echo "[$start_ts] BEGIN ${name}"
    echo "CMD: (cd ${WORKTREE} && ${cmd})"
  } >> "$CMDLOG"
  if (cd "$WORKTREE" && bash -lc "$cmd") > "${STAGE_DIR}/${log_file}" 2>&1; then
    local end_ts
    end_ts="$(date --iso-8601=seconds)"
    echo "[$end_ts] END ${name} status=ok log=${log_file}" >> "$CMDLOG"
    note_artifact "${STAGE_DIR}/${log_file}"
  else
    local end_ts
    end_ts="$(date --iso-8601=seconds)"
    echo "[$end_ts] END ${name} status=fail log=${log_file}" >> "$CMDLOG"
    exit 1
  fi
}

run_capture() {
  local name="$1"
  local cmd="$2"
  local out_file="$3"
  local err_file="$4"
  local start_ts
  start_ts="$(date --iso-8601=seconds)"
  {
    echo
    echo "[$start_ts] BEGIN ${name}"
    echo "CMD: (cd ${WORKTREE} && ${cmd})"
  } >> "$CMDLOG"
  if (cd "$WORKTREE" && bash -lc "$cmd") > "$out_file" 2> "$err_file"; then
    local end_ts
    end_ts="$(date --iso-8601=seconds)"
    echo "[$end_ts] END ${name} status=ok" >> "$CMDLOG"
    note_artifact "$out_file"
    note_artifact "$err_file"
  else
    local end_ts
    end_ts="$(date --iso-8601=seconds)"
    echo "[$end_ts] END ${name} status=fail" >> "$CMDLOG"
    exit 1
  fi
}

run_row() {
  local label="$1" variant="$2" mode="$3" jit="$4" jit_fast_regs="$5" features="$6" fast_env="$7"
  for fmt in csv json; do
    local out_name="v8_06_perf_harness_${label}_${variant}_${HOST_TAG}_${TS}.${fmt}"
    local cmd="OXIDE_RANDOMX_HUGE_1G=0"
    if [[ -n "$fast_env" ]]; then
      cmd+=" ${fast_env}"
    fi
    cmd+=" cargo run --release --example perf_harness --features '${features}' -- --mode ${mode} --jit ${jit} --jit-fast-regs ${jit_fast_regs} --iters 50 --warmup 5 --threads ${THREADS} --large-pages off --thread-names off --affinity off --format ${fmt} --out ${STAGE_DIR}/${out_name}"
    run_capture \
      "perf_${label}_${variant}_${fmt}" \
      "$cmd" \
      "${STAGE_DIR}/${out_name}.stdout" \
      "${STAGE_DIR}/${out_name}.stderr"
    note_artifact "${STAGE_DIR}/${out_name}"
  done
}

run_step "validation_cargo_build" "cargo build" "v8_06_validation_cargo_build_${HOST_TAG}_${TS}.log"
run_step "validation_cargo_build_superscalar_proto" "cargo build --features superscalar-accel-proto" "v8_06_validation_cargo_build_superscalar_proto_${HOST_TAG}_${TS}.log"
run_step "validation_cargo_test" "cargo test" "v8_06_validation_cargo_test_${HOST_TAG}_${TS}.log"
run_step "validation_cargo_test_oracle" "cargo test --test oracle" "v8_06_validation_cargo_test_oracle_${HOST_TAG}_${TS}.log"
run_step "validation_cargo_test_superscalar_proto" "cargo test --features superscalar-accel-proto" "v8_06_validation_cargo_test_superscalar_proto_${HOST_TAG}_${TS}.log"
run_step "validation_cargo_test_superscalar_proto_oracle" "cargo test --features superscalar-accel-proto --test oracle" "v8_06_validation_cargo_test_superscalar_proto_oracle_${HOST_TAG}_${TS}.log"
run_step "validation_cargo_test_jit_jit_fastregs_superscalar_proto_oracle" "cargo test --features 'jit jit-fastregs superscalar-accel-proto' --test oracle" "v8_06_validation_cargo_test_jit_jit_fastregs_superscalar_proto_oracle_${HOST_TAG}_${TS}.log"

BASE_COMMON="--config default --iters 2000 --warmup 200 --items 256"
run_capture \
  "superscalar_hash_baseline_active_json" \
  "cargo run --quiet --release --example superscalar_hash_harness -- --format json --impl active ${BASE_COMMON}" \
  "${STAGE_DIR}/v8_06_superscalar_hash_baseline_active_${HOST_TAG}_${TS}.json" \
  "${STAGE_DIR}/v8_06_superscalar_hash_baseline_active_${HOST_TAG}_${TS}.json.stderr"
run_capture \
  "superscalar_hash_baseline_active_csv" \
  "cargo run --quiet --release --example superscalar_hash_harness -- --format csv --impl active ${BASE_COMMON}" \
  "${STAGE_DIR}/v8_06_superscalar_hash_baseline_active_${HOST_TAG}_${TS}.csv" \
  "${STAGE_DIR}/v8_06_superscalar_hash_baseline_active_${HOST_TAG}_${TS}.csv.stderr"
run_capture \
  "superscalar_hash_proto_active_json" \
  "cargo run --quiet --release --example superscalar_hash_harness --features superscalar-accel-proto -- --format json --impl active ${BASE_COMMON}" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_active_${HOST_TAG}_${TS}.json" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_active_${HOST_TAG}_${TS}.json.stderr"
run_capture \
  "superscalar_hash_proto_active_csv" \
  "cargo run --quiet --release --example superscalar_hash_harness --features superscalar-accel-proto -- --format csv --impl active ${BASE_COMMON}" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_active_${HOST_TAG}_${TS}.csv" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_active_${HOST_TAG}_${TS}.csv.stderr"
run_capture \
  "superscalar_hash_proto_scalar_json" \
  "cargo run --quiet --release --example superscalar_hash_harness --features superscalar-accel-proto -- --format json --impl scalar ${BASE_COMMON}" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_scalar_${HOST_TAG}_${TS}.json" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_scalar_${HOST_TAG}_${TS}.json.stderr"
run_capture \
  "superscalar_hash_proto_scalar_csv" \
  "cargo run --quiet --release --example superscalar_hash_harness --features superscalar-accel-proto -- --format csv --impl scalar ${BASE_COMMON}" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_scalar_${HOST_TAG}_${TS}.csv" \
  "${STAGE_DIR}/v8_06_superscalar_hash_proto_scalar_${HOST_TAG}_${TS}.csv.stderr"

run_row "light_interp" "baseline" "light" "off" "off" "bench-instrument" ""
run_row "light_interp" "proto" "light" "off" "off" "bench-instrument superscalar-accel-proto" ""
run_row "light_jit_conservative" "baseline" "light" "on" "off" "jit bench-instrument" ""
run_row "light_jit_conservative" "proto" "light" "on" "off" "jit bench-instrument superscalar-accel-proto" ""
run_row "light_jit_fastregs" "baseline" "light" "on" "on" "jit jit-fastregs bench-instrument" ""
run_row "light_jit_fastregs" "proto" "light" "on" "on" "jit jit-fastregs bench-instrument superscalar-accel-proto" ""
run_row "fast_jit_conservative" "baseline" "fast" "on" "off" "jit bench-instrument" "OXIDE_RANDOMX_FAST_BENCH=1"
run_row "fast_jit_conservative" "proto" "fast" "on" "off" "jit bench-instrument superscalar-accel-proto" "OXIDE_RANDOMX_FAST_BENCH=1"
run_row "fast_jit_fastregs" "baseline" "fast" "on" "on" "jit jit-fastregs bench-instrument" "OXIDE_RANDOMX_FAST_BENCH=1"
run_row "fast_jit_fastregs" "proto" "fast" "on" "on" "jit jit-fastregs bench-instrument superscalar-accel-proto" "OXIDE_RANDOMX_FAST_BENCH=1"

# Build perf rows and derived summary artifacts.
perf_rows_tmp="${STAGE_DIR}/.v8_06_perf_rows.json"
{
  echo "["
  first=1
  add_row() {
    local label="$1" mode="$2" config="$3" variant="$4"
    local json_file="${STAGE_DIR}/v8_06_perf_harness_${label}_${variant}_${HOST_TAG}_${TS}.json"
    local csv_artifact="v8_06_perf_harness_${label}_${variant}_${HOST_TAG}_${TS}.csv"
    local json_artifact="v8_06_perf_harness_${label}_${variant}_${HOST_TAG}_${TS}.json"
    local row
    row="$(jq -c \
      --arg label "$label" \
      --arg mode "$mode" \
      --arg config "$config" \
      --arg variant "$variant" \
      --arg csv_artifact "$csv_artifact" \
      --arg json_artifact "$json_artifact" \
      '{
        label: $label,
        mode: $mode,
        config: $config,
        variant: $variant,
        runtime_jit_flags: (if .params.jit_requested then (if .params.jit_fast_regs then "--jit on --jit-fast-regs on" else "--jit on --jit-fast-regs off" end) else "--jit off --jit-fast-regs off" end),
        csv_artifact: $csv_artifact,
        json_artifact: $json_artifact,
        git_sha: .provenance.git_sha,
        git_sha_short: .provenance.git_sha_short,
        git_dirty: .provenance.git_dirty,
        features: .provenance.features,
        cpu: .provenance.cpu,
        cores: .provenance.cores,
        rustc: .provenance.rustc,
        ns_per_hash: .results.ns_per_hash,
        hashes_per_sec: ((.results.hashes_per_sec * 1000000 | round) / 1000000),
        dataset_init_ns: (.stages.dataset_init_ns // "n/a"),
        jit_active: .results.jit_active,
        jit_fast_regs: .params.jit_fast_regs,
        large_pages_requested: .params.large_pages_requested,
        large_pages_1gb_requested: .params.large_pages_1gb_requested,
        thread_names: .params.thread_names,
        affinity: (.params.affinity // "off"),
        prefetch_distance: .params.prefetch_distance,
        prefetch_auto_tune: .params.prefetch_auto_tune
      }' "$json_file")"
    if [[ $first -eq 0 ]]; then
      echo ","
    fi
    first=0
    echo "$row"
  }

  add_row light_interp Light "Interpreter" baseline
  add_row light_interp Light "Interpreter" proto
  add_row light_jit_conservative Light "JIT conservative" baseline
  add_row light_jit_conservative Light "JIT conservative" proto
  add_row light_jit_fastregs Light "JIT fast-regs" baseline
  add_row light_jit_fastregs Light "JIT fast-regs" proto
  add_row fast_jit_conservative Fast "JIT conservative" baseline
  add_row fast_jit_conservative Fast "JIT conservative" proto
  add_row fast_jit_fastregs Fast "JIT fast-regs" baseline
  add_row fast_jit_fastregs Fast "JIT fast-regs" proto
  echo "]"
} > "$perf_rows_tmp"

jq -r '
  ([
    "label","mode","config","variant","runtime_jit_flags","csv_artifact","json_artifact","git_sha","git_sha_short","git_dirty","features","cpu","cores","rustc","ns_per_hash","hashes_per_sec","dataset_init_ns","jit_active","jit_fast_regs","large_pages_requested","large_pages_1gb_requested","thread_names","affinity","prefetch_distance","prefetch_auto_tune"
  ] | @csv),
  (.[] | [
    .label,.mode,.config,.variant,.runtime_jit_flags,.csv_artifact,.json_artifact,.git_sha,.git_sha_short,.git_dirty,.features,.cpu, (.cores|tostring),.rustc, (.ns_per_hash|tostring), (.hashes_per_sec|tostring), (.dataset_init_ns|tostring), (.jit_active|tostring), (.jit_fast_regs|tostring), (.large_pages_requested|tostring), (.large_pages_1gb_requested|tostring), (.thread_names|tostring), .affinity, (.prefetch_distance|tostring), (.prefetch_auto_tune|tostring)
  ] | @csv)
' "$perf_rows_tmp" > "$INDEXCSV"

pair_deltas_tmp="${STAGE_DIR}/.v8_06_pair_deltas.json"
jq '
  def round3: ((. * 1000) | round) / 1000;
  [
    {label:"light_interp", mode:"Light", config:"Interpreter"},
    {label:"light_jit_conservative", mode:"Light", config:"JIT conservative"},
    {label:"light_jit_fastregs", mode:"Light", config:"JIT fast-regs"},
    {label:"fast_jit_conservative", mode:"Fast", config:"JIT conservative"},
    {label:"fast_jit_fastregs", mode:"Fast", config:"JIT fast-regs"}
  ]
  | map(
      . as $meta
      | ($rows[] | select(.label == $meta.label and .variant == "baseline")) as $b
      | ($rows[] | select(.label == $meta.label and .variant == "proto")) as $p
      | {
          label: $meta.label,
          mode: $meta.mode,
          config: $meta.config,
          baseline_ns_per_hash: $b.ns_per_hash,
          proto_ns_per_hash: $p.ns_per_hash,
          speedup_pct: (((($b.ns_per_hash - $p.ns_per_hash) / $b.ns_per_hash) * 100) | round3),
          baseline_hashes_per_sec: $b.hashes_per_sec,
          proto_hashes_per_sec: $p.hashes_per_sec,
          baseline_dataset_init_ns: (if $b.dataset_init_ns == "n/a" then null else $b.dataset_init_ns end),
          proto_dataset_init_ns: (if $p.dataset_init_ns == "n/a" then null else $p.dataset_init_ns end),
          dataset_init_speedup_pct: (
            if ($b.dataset_init_ns == "n/a" or $p.dataset_init_ns == "n/a") then null
            else (((($b.dataset_init_ns - $p.dataset_init_ns) / $b.dataset_init_ns) * 100) | round3)
            end
          ),
          baseline_csv_artifact: $b.csv_artifact,
          baseline_json_artifact: $b.json_artifact,
          proto_csv_artifact: $p.csv_artifact,
          proto_json_artifact: $p.json_artifact
        }
    )
' --argjson rows "$(cat "$perf_rows_tmp")" -n > "$pair_deltas_tmp"

validation_logs_tmp="${STAGE_DIR}/.v8_06_validation_logs.json"
rg '^v8_06_validation_.*\.log$' "$ARTIFACT_LIST" | sort -u | jq -R . | jq -s . > "$validation_logs_tmp"

sup_base="${STAGE_DIR}/v8_06_superscalar_hash_baseline_active_${HOST_TAG}_${TS}.json"
sup_proto="${STAGE_DIR}/v8_06_superscalar_hash_proto_active_${HOST_TAG}_${TS}.json"
sup_scalar="${STAGE_DIR}/v8_06_superscalar_hash_proto_scalar_${HOST_TAG}_${TS}.json"

jq -n \
  --arg prompt "PROMPTv8_06" \
  --arg ts "$TS" \
  --arg date "$DATE_STAMP" \
  --arg host_tag "$HOST_TAG" \
  --arg git_sha "$SHA" \
  --arg git_sha_short "$SHORT_SHA" \
  --arg rustc "$RUSTC_VER" \
  --arg cpu_model "$CPU_MODEL" \
  --arg vendor "$VENDOR" \
  --argjson family "$FAMILY" \
  --argjson model "$MODEL" \
  --argjson stepping "$STEPPING" \
  --arg os_name "$OS_NAME" \
  --arg kernel "$KERNEL" \
  --argjson threads "$THREADS" \
  --arg clean_worktree "$WORKTREE" \
  --arg stage_dir "$STAGE_DIR" \
  --argjson validation_logs "$(cat "$validation_logs_tmp")" \
  --argjson sup_base "$(cat "$sup_base")" \
  --argjson sup_proto "$(cat "$sup_proto")" \
  --argjson sup_scalar "$(cat "$sup_scalar")" \
  --argjson perf_rows "$(cat "$perf_rows_tmp")" \
  --argjson pair_deltas "$(cat "$pair_deltas_tmp")" \
  '
  def round3: ((. * 1000) | round) / 1000;
  {
    prompt: $prompt,
    timestamp: $ts,
    date: $date,
    host_tag: $host_tag,
    provenance: {
      git_sha: $git_sha,
      git_sha_short: $git_sha_short,
      git_dirty_all_perf_json_false: (($perf_rows | map(select(.git_dirty != "false")) | length) == 0),
      rustc: $rustc,
      cpu_model_string: $cpu_model,
      vendor: $vendor,
      family: $family,
      model: $model,
      stepping: $stepping,
      os_name: $os_name,
      kernel: $kernel,
      logical_threads: $threads,
      clean_worktree: $clean_worktree,
      stage_dir: $stage_dir
    },
    runtime: {
      superscalar_iters: 2000,
      superscalar_warmup: 200,
      superscalar_items: 256,
      perf_iters: 50,
      perf_warmup: 5,
      threads: $threads,
      large_pages_requested: false,
      large_pages_1gb_requested: false,
      thread_names: false,
      affinity: "off",
      fast_mode_env: "OXIDE_RANDOMX_FAST_BENCH=1",
      huge_1g_env: "OXIDE_RANDOMX_HUGE_1G=0"
    },
    validation_logs: ($validation_logs + ["v8_06_commands_\($host_tag)_\($ts).log"]),
    isolated: {
      baseline_active: $sup_base,
      proto_active: $sup_proto,
      proto_scalar: $sup_scalar,
      checksum_parity: {
        compute_checksum: (($sup_base.compute_checksum == $sup_proto.compute_checksum) and ($sup_base.compute_checksum == $sup_scalar.compute_checksum)),
        execute_checksum: (($sup_base.execute_checksum == $sup_proto.execute_checksum) and ($sup_base.execute_checksum == $sup_scalar.execute_checksum)),
        execute_select_checksum: (($sup_base.execute_select_checksum == $sup_proto.execute_select_checksum) and ($sup_base.execute_select_checksum == $sup_scalar.execute_select_checksum))
      },
      deltas: {
        proto_active_vs_baseline_compute_speedup_pct: (((($sup_base.compute_ns_per_call - $sup_proto.compute_ns_per_call) / $sup_base.compute_ns_per_call) * 100) | round3),
        proto_active_vs_baseline_execute_speedup_pct: (((($sup_base.execute_ns_per_call - $sup_proto.execute_ns_per_call) / $sup_base.execute_ns_per_call) * 100) | round3),
        proto_active_vs_scalar_compute_speedup_pct: (((($sup_scalar.compute_ns_per_call - $sup_proto.compute_ns_per_call) / $sup_scalar.compute_ns_per_call) * 100) | round3),
        proto_active_vs_scalar_execute_speedup_pct: (((($sup_scalar.execute_ns_per_call - $sup_proto.execute_ns_per_call) / $sup_scalar.execute_ns_per_call) * 100) | round3)
      }
    },
    perf_rows: $perf_rows,
    pair_deltas: $pair_deltas
  }
' > "$SUMMARYJSON"
note_artifact "$SUMMARYJSON"
note_artifact "$INDEXCSV"
note_artifact "$MEMO"
note_artifact "$MANIFEST"

{
  echo "prompt=PROMPTv8_06"
  echo "timestamp=${TS}"
  echo "date=${DATE_STAMP}"
  echo "host_tag=${HOST_TAG}"
  echo "git_sha=${SHA}"
  echo "stage_dir=${STAGE_DIR}"
  echo "worktree=${WORKTREE}"
  echo "artifacts:"
  sort -u "$ARTIFACT_LIST" | sed 's/^/- /'
} > "$MANIFEST"

# Lightweight host memo with result table.
jq -r '
  . as $s
  | "# v8.06 Superscalar Prototype Capture (" + .host_tag + ", " + .date + ")\n\n"
    + "Host CPU: " + .provenance.cpu_model_string + " (" + .provenance.vendor + "/" + (.provenance.family|tostring) + "/" + (.provenance.model|tostring) + ")\n"
    + "OS: " + .provenance.os_name + "\n"
    + "git_sha: " + .provenance.git_sha + "\n\n"
    + "Isolated deltas:\n"
    + "- compute active vs baseline: +" + (.isolated.deltas.proto_active_vs_baseline_compute_speedup_pct|tostring) + "%\n"
    + "- execute active vs baseline: +" + (.isolated.deltas.proto_active_vs_baseline_execute_speedup_pct|tostring) + "%\n"
    + "- checksums match compute/execute/select: "
    + (if .isolated.checksum_parity.compute_checksum and .isolated.checksum_parity.execute_checksum and .isolated.checksum_parity.execute_select_checksum then "true" else "false" end)
    + "\n\n"
    + "End-to-end pair deltas (ns/hash speedup):\n"
    + (
        [
          .pair_deltas[]
          | "- " + .label + ": "
            + (if .speedup_pct >= 0 then "+" else "" end)
            + (.speedup_pct|tostring)
            + "%\n"
        ]
        | join("")
      )
    + "\nThis memo is host-specific and does not claim cross-host promotion by itself.\n"
' "$SUMMARYJSON" > "$MEMO"

rm -f "$perf_rows_tmp" "$pair_deltas_tmp" "$validation_logs_tmp" "$ARTIFACT_LIST"

echo "Output directory: ${STAGE_DIR}"
echo "Summary: ${SUMMARYJSON}"
echo "Memo: ${MEMO}"
