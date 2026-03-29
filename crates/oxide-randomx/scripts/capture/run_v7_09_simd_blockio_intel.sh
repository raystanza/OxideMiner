#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

cpu_count() {
    if command -v nproc >/dev/null 2>&1; then
        nproc
    else
        getconf _NPROCESSORS_ONLN
    fi
}

HEAD_SHA="${HEAD_SHA:-$(git -C "${ROOT_DIR}" rev-parse HEAD)}"
HOST_TAG="${HOST_TAG:-intel_host}"
THREADS="${THREADS:-$(cpu_count)}"
BENCH_ITERS="${BENCH_ITERS:-30}"
BENCH_WARMUP="${BENCH_WARMUP:-5}"
BENCH_REPEATS="${BENCH_REPEATS:-3}"
PERF_ITERS="${PERF_ITERS:-30}"
PERF_WARMUP="${PERF_WARMUP:-5}"
LARGE_PAGES="${LARGE_PAGES:-on}"
PAUSE_SEC="${PAUSE_SEC:-0.5}"
RUN_TESTS="${RUN_TESTS:-1}"
KEEP_WORKTREE="${KEEP_WORKTREE:-0}"
TS="${TS:-$(date +%Y%m%d_%H%M%S)}"

WORKTREE="${WORKTREE:-/tmp/oxide-randomx-v7_09-${HOST_TAG}-${TS}}"
TMP_OUT="${TMP_OUT:-/tmp/oxide-randomx-v7_09-${HOST_TAG}-out-${TS}}"
FINAL_OUT="${FINAL_OUT:-${ROOT_DIR}/perf_results/Intel}"

MANIFEST_FILE="${TMP_OUT}/v7_09_manifest_${HOST_TAG}_${TS}.txt"
PROVENANCE_FILE="${TMP_OUT}/v7_09_novel_family_host_provenance_${HOST_TAG}_${TS}.txt"
BENCH_INDEX_FILE="${TMP_OUT}/v7_09_bench_index_${HOST_TAG}_${TS}.csv"
PERF_INDEX_FILE="${TMP_OUT}/v7_09_perf_index_${HOST_TAG}_${TS}.csv"
SUMMARY_FILE="${TMP_OUT}/v7_09_simd_blockio_summary_${HOST_TAG}_${TS}.json"

cleanup() {
    local code=$?
    if [[ "${KEEP_WORKTREE}" != "1" ]]; then
        git -C "${ROOT_DIR}" worktree remove --force "${WORKTREE}" >/dev/null 2>&1 || true
    fi
    exit "${code}"
}
trap cleanup EXIT

mkdir -p "${TMP_OUT}" "${FINAL_OUT}"
git -C "${ROOT_DIR}" worktree remove --force "${WORKTREE}" >/dev/null 2>&1 || true
rm -rf "${WORKTREE}"
git -C "${ROOT_DIR}" worktree add --detach "${WORKTREE}" "${HEAD_SHA}" >/dev/null

LC_ALL=C
export LC_ALL

VENDOR_ID=$(lscpu | awk -F: '/Vendor ID:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
CPU_FAMILY=$(lscpu | awk -F: '/CPU family:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
CPU_MODEL=$(lscpu | awk -F: '/Model:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
CPU_STEPPING=$(lscpu | awk -F: '/Stepping:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
CPU_MODEL_NAME=$(lscpu | awk -F: '/Model name:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')

{
    echo "ts=${TS}"
    echo "head_sha=${HEAD_SHA}"
    echo "worktree_head=$(git -C "${WORKTREE}" rev-parse HEAD)"
    echo "host_tag=${HOST_TAG}"
    echo "vendor_id=${VENDOR_ID}"
    echo "cpu_family=${CPU_FAMILY}"
    echo "cpu_model=${CPU_MODEL}"
    echo "cpu_stepping=${CPU_STEPPING}"
    echo "cpu_model_name=${CPU_MODEL_NAME}"
    echo "threads=${THREADS}"
    echo "bench_iters=${BENCH_ITERS}"
    echo "bench_warmup=${BENCH_WARMUP}"
    echo "bench_repeats=${BENCH_REPEATS}"
    echo "perf_iters=${PERF_ITERS}"
    echo "perf_warmup=${PERF_WARMUP}"
    echo "large_pages=${LARGE_PAGES}"
    echo "pause_sec=${PAUSE_SEC}"
    echo "run_tests=${RUN_TESTS}"
    echo "keep_worktree=${KEEP_WORKTREE}"
    echo "worktree=${WORKTREE}"
    echo "tmp_out=${TMP_OUT}"
    echo "final_out=${FINAL_OUT}"
} > "${MANIFEST_FILE}"

{
    date -Is
    echo
    uname -a
    echo
    lscpu
    echo
    rustc -Vv
    echo
    cargo -V
    echo
    git -C "${WORKTREE}" rev-parse HEAD
    echo
    git -C "${WORKTREE}" status --short
} > "${PROVENANCE_FILE}"

echo "mode,pair_label,path,raw_log_path" > "${BENCH_INDEX_FILE}"
echo "mode,pair_label,config_label,seq,force,path,stdout_path,stderr_path" > "${PERF_INDEX_FILE}"

build_examples() {
    local label=$1
    local features=$2

    (
        cd "${WORKTREE}"
        cargo build --release --example bench --example perf_harness --features "${features}"
    ) > "${TMP_OUT}/v7_09_build_${label}_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_build_${label}_${HOST_TAG}_${TS}.stderr"

    cp "${WORKTREE}/target/release/examples/bench" "${TMP_OUT}/bench_${label}_${HOST_TAG}_${TS}"
    cp "${WORKTREE}/target/release/examples/perf_harness" "${TMP_OUT}/perf_harness_${label}_${HOST_TAG}_${TS}"
}

build_perf_compare() {
    (
        cd "${WORKTREE}"
        cargo build --release --bin perf_compare
    ) > "${TMP_OUT}/v7_09_build_perf_compare_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_build_perf_compare_${HOST_TAG}_${TS}.stderr"

    cp "${WORKTREE}/target/release/perf_compare" "${TMP_OUT}/perf_compare_${HOST_TAG}_${TS}"
}

run_test_bundle() {
    (
        cd "${WORKTREE}"
        cargo test --test oracle
    ) > "${TMP_OUT}/v7_09_oracle_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_oracle_${HOST_TAG}_${TS}.stderr"

    (
        cd "${WORKTREE}"
        cargo test --features "jit jit-fastregs" --test oracle
    ) > "${TMP_OUT}/v7_09_oracle_jit_fastregs_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_oracle_jit_fastregs_${HOST_TAG}_${TS}.stderr"

    (
        cd "${WORKTREE}"
        cargo test --features "simd-blockio" --test oracle
    ) > "${TMP_OUT}/v7_09_oracle_simd_blockio_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_oracle_simd_blockio_${HOST_TAG}_${TS}.stderr"

    (
        cd "${WORKTREE}"
        cargo test --features "simd-blockio" simd_prepare_finish_matches_scalar
    ) > "${TMP_OUT}/v7_09_simd_prepare_finish_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_simd_prepare_finish_${HOST_TAG}_${TS}.stderr"

    (
        cd "${WORKTREE}"
        cargo test --features "simd-blockio" simd_blockio_blocked_cpu_classifier_targets_xeon_model_45
    ) > "${TMP_OUT}/v7_09_simd_classifier_${HOST_TAG}_${TS}.stdout" \
      2> "${TMP_OUT}/v7_09_simd_classifier_${HOST_TAG}_${TS}.stderr"
}

bench_output_field() {
    local line=$1
    local key=$2
    sed -nE "s/.*${key}=(\"[^\"]*\"|[^ ]+).*/\\1/p" <<<"${line}" | head -n1
}

strip_quotes() {
    local value=$1
    if [[ "${value}" == \"*\" ]]; then
        value="${value#\"}"
        value="${value%\"}"
    fi
    printf '%s\n' "${value}"
}

run_bench_once() {
    local pair_label=$1
    local config_label=$2
    local exe_path=$3
    local force_flag=$4
    local mode=$5
    local repeat_idx=$6
    local order_idx=$7
    local out_csv=$8
    local raw_log=$9

    local -a env_cmd=()
    if [[ "${mode}" == "fast" ]]; then
        env_cmd+=(OXIDE_RANDOMX_FAST_BENCH=1)
    fi
    if [[ "${LARGE_PAGES}" == "on" ]]; then
        env_cmd+=(OXIDE_RANDOMX_LARGE_PAGES=1)
    fi
    if [[ "${force_flag}" == "force" ]]; then
        env_cmd+=(OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE=1)
    fi

    local output
    output="$(
        if [[ ${#env_cmd[@]} -gt 0 ]]; then
            env "${env_cmd[@]}" "${exe_path}" \
                --mode "${mode}" \
                --jit off \
                --jit-fast-regs off \
                --iters "${BENCH_ITERS}" \
                --warmup "${BENCH_WARMUP}" \
                --threads "${THREADS}" \
                --report \
                --format human
        else
            "${exe_path}" \
                --mode "${mode}" \
                --jit off \
                --jit-fast-regs off \
                --iters "${BENCH_ITERS}" \
                --warmup "${BENCH_WARMUP}" \
                --threads "${THREADS}" \
                --report \
                --format human
        fi
    )"

    local mode_line
    local prov_line
    local lp_line
    mode_line=$(grep -m1 '^mode=' <<<"${output}" || true)
    prov_line=$(grep -m1 '^provenance ' <<<"${output}" || true)
    lp_line=$(grep -m1 '^large_pages_requested=' <<<"${output}" || true)

    if [[ -z "${mode_line}" || -z "${prov_line}" || -z "${lp_line}" ]]; then
        echo "failed to parse bench output for ${pair_label}/${config_label}" >&2
        echo "${output}" >&2
        exit 1
    fi

    local ns_per_hash
    local features
    local cpu
    local git_sha_short
    local git_dirty
    local cores
    local rustc
    local lp_requested
    local lp_dataset
    local lp_scratchpad

    ns_per_hash=$(sed -nE 's/.*ns\/hash=([0-9]+).*/\1/p' <<<"${mode_line}" | head -n1)
    features=$(strip_quotes "$(bench_output_field "${prov_line}" 'features')")
    cpu=$(strip_quotes "$(bench_output_field "${prov_line}" 'cpu')")
    git_sha_short=$(strip_quotes "$(bench_output_field "${prov_line}" 'git_sha_short')")
    git_dirty=$(strip_quotes "$(bench_output_field "${prov_line}" 'git_dirty')")
    cores=$(strip_quotes "$(bench_output_field "${prov_line}" 'cores')")
    rustc=$(strip_quotes "$(bench_output_field "${prov_line}" 'rustc')")
    lp_requested=$(strip_quotes "$(bench_output_field "${lp_line}" 'large_pages_requested')")
    lp_dataset=$(strip_quotes "$(bench_output_field "${lp_line}" 'large_pages_dataset')")
    lp_scratchpad=$(strip_quotes "$(bench_output_field "${lp_line}" 'large_pages_scratchpad')")

    printf '"%s","%s","%s","%s",%d,%d,%d,"%s",%s,%s,%s,"%s","%s","%s","%s","%s"\n' \
        "${pair_label}" \
        "${config_label}" \
        "${mode}" \
        "${force_flag}" \
        "${BENCH_ITERS}" \
        "${BENCH_WARMUP}" \
        "${THREADS}" \
        "${LARGE_PAGES}" \
        "${repeat_idx}" \
        "${order_idx}" \
        "${ns_per_hash}" \
        "${features}" \
        "${cpu}" \
        "${git_sha_short}" \
        "${git_dirty}" \
        "${lp_requested}/${lp_dataset}/${lp_scratchpad}" >> "${out_csv}"

    printf -- '---- %s %s repeat=%d order=%d force=%s ----\n%s\n' \
        "${pair_label}" \
        "${config_label}" \
        "${repeat_idx}" \
        "${order_idx}" \
        "${force_flag}" \
        "${output}" >> "${raw_log}"
    printf 'bench %s %s repeat=%d order=%d -> %s ns/hash\n' \
        "${pair_label}" \
        "${config_label}" \
        "${repeat_idx}" \
        "${order_idx}" \
        "${ns_per_hash}"
}

run_bench_pair() {
    local mode=$1
    local pair_label=$2
    local left_label=$3
    local left_exe=$4
    local left_force=$5
    local right_label=$6
    local right_exe=$7
    local right_force=$8

    local out_csv="${TMP_OUT}/v7_09_bench_${mode}_${pair_label}_${HOST_TAG}_${TS}.csv"
    local raw_log="${TMP_OUT}/v7_09_bench_${mode}_${pair_label}_${HOST_TAG}_${TS}.raw.log"

    echo '"pair_label","config_label","mode","force","iters","warmup","threads","large_pages","repeat_index","run_order","ns_per_hash","features","cpu","git_sha_short","git_dirty","large_pages_triplet"' > "${out_csv}"
    : > "${raw_log}"

    for ((r=1; r<=BENCH_REPEATS; r++)); do
        if (( r % 2 == 1 )); then
            run_bench_once "${pair_label}" "${left_label}" "${left_exe}" "${left_force}" "${mode}" "${r}" 1 "${out_csv}" "${raw_log}"
            sleep "${PAUSE_SEC}"
            run_bench_once "${pair_label}" "${right_label}" "${right_exe}" "${right_force}" "${mode}" "${r}" 2 "${out_csv}" "${raw_log}"
        else
            run_bench_once "${pair_label}" "${right_label}" "${right_exe}" "${right_force}" "${mode}" "${r}" 1 "${out_csv}" "${raw_log}"
            sleep "${PAUSE_SEC}"
            run_bench_once "${pair_label}" "${left_label}" "${left_exe}" "${left_force}" "${mode}" "${r}" 2 "${out_csv}" "${raw_log}"
        fi
        sleep "${PAUSE_SEC}"
    done

    echo "${mode},${pair_label},${out_csv},${raw_log}" >> "${BENCH_INDEX_FILE}"
}

run_perf_once() {
    local mode=$1
    local pair_label=$2
    local config_label=$3
    local exe_path=$4
    local force_flag=$5
    local seq=$6

    local out_csv="${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${config_label}_${seq}_${HOST_TAG}_${TS}.csv"
    local out_stdout="${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${config_label}_${seq}_${HOST_TAG}_${TS}.stdout"
    local out_stderr="${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${config_label}_${seq}_${HOST_TAG}_${TS}.stderr"

    local -a env_cmd=()
    if [[ "${mode}" == "fast" ]]; then
        env_cmd+=(OXIDE_RANDOMX_FAST_BENCH=1)
    fi
    if [[ "${force_flag}" == "force" ]]; then
        env_cmd+=(OXIDE_RANDOMX_SIMD_BLOCKIO_FORCE=1)
    fi

    if [[ ${#env_cmd[@]} -gt 0 ]]; then
        env "${env_cmd[@]}" "${exe_path}" \
            --mode "${mode}" \
            --jit off \
            --jit-fast-regs off \
            --iters "${PERF_ITERS}" \
            --warmup "${PERF_WARMUP}" \
            --threads "${THREADS}" \
            --large-pages "${LARGE_PAGES}" \
            --thread-names off \
            --affinity off \
            --format csv \
            --out "${out_csv}" > "${out_stdout}" 2> "${out_stderr}"
    else
        "${exe_path}" \
            --mode "${mode}" \
            --jit off \
            --jit-fast-regs off \
            --iters "${PERF_ITERS}" \
            --warmup "${PERF_WARMUP}" \
            --threads "${THREADS}" \
            --large-pages "${LARGE_PAGES}" \
            --thread-names off \
            --affinity off \
            --format csv \
            --out "${out_csv}" > "${out_stdout}" 2> "${out_stderr}"
    fi

    echo "${mode},${pair_label},${config_label},${seq},${force_flag},${out_csv},${out_stdout},${out_stderr}" >> "${PERF_INDEX_FILE}"
}

combine_csv() {
    local out_path=$1
    shift
    local first=1
    : > "${out_path}"
    for csv_path in "$@"; do
        if (( first )); then
            cat "${csv_path}" > "${out_path}"
            first=0
        else
            tail -n +2 "${csv_path}" >> "${out_path}"
        fi
    done
}

run_perf_compare() {
    local label=$1
    local baseline_path=$2
    local candidate_path=$3
    local threshold_pct=$4
    local out_path="${TMP_OUT}/v7_09_perf_compare_${label}_${HOST_TAG}_${TS}.txt"

    local rc=0
    set +e
    "${TMP_OUT}/perf_compare_${HOST_TAG}_${TS}" \
        --baseline "${baseline_path}" \
        --candidate "${candidate_path}" \
        --threshold-pct "${threshold_pct}" > "${out_path}"
    rc=$?
    set -e
    printf 'exit_code=%d\n' "${rc}" >> "${out_path}"
}

run_perf_pair() {
    local mode=$1
    local pair_label=$2
    local left_label=$3
    local left_exe=$4
    local left_force=$5
    local right_label=$6
    local right_exe=$7
    local right_force=$8
    local threshold_pct=$9

    run_perf_once "${mode}" "${pair_label}" "${left_label}" "${left_exe}" "${left_force}" a1
    run_perf_once "${mode}" "${pair_label}" "${right_label}" "${right_exe}" "${right_force}" b1
    run_perf_once "${mode}" "${pair_label}" "${right_label}" "${right_exe}" "${right_force}" b2
    run_perf_once "${mode}" "${pair_label}" "${left_label}" "${left_exe}" "${left_force}" a2

    local left_combined="${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${left_label}_combined_${HOST_TAG}_${TS}.csv"
    local right_combined="${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${right_label}_combined_${HOST_TAG}_${TS}.csv"
    local pair_combined="${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_pair_matrix_${HOST_TAG}_${TS}.csv"

    combine_csv "${left_combined}" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${left_label}_a1_${HOST_TAG}_${TS}.csv" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${left_label}_a2_${HOST_TAG}_${TS}.csv"
    combine_csv "${right_combined}" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${right_label}_b1_${HOST_TAG}_${TS}.csv" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${right_label}_b2_${HOST_TAG}_${TS}.csv"
    combine_csv "${pair_combined}" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${left_label}_a1_${HOST_TAG}_${TS}.csv" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${right_label}_b1_${HOST_TAG}_${TS}.csv" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${right_label}_b2_${HOST_TAG}_${TS}.csv" \
        "${TMP_OUT}/v7_09_perf_${mode}_${pair_label}_${left_label}_a2_${HOST_TAG}_${TS}.csv"

    run_perf_compare "${mode}_${pair_label}" "${left_combined}" "${right_combined}" "${threshold_pct}"
}

if [[ "${RUN_TESTS}" == "1" ]]; then
    run_test_bundle
fi

build_examples baseline "bench-instrument"
build_examples simd "bench-instrument simd-blockio"
build_perf_compare

BASE_BENCH="${TMP_OUT}/bench_baseline_${HOST_TAG}_${TS}"
SIMD_BENCH="${TMP_OUT}/bench_simd_${HOST_TAG}_${TS}"
BASE_PERF="${TMP_OUT}/perf_harness_baseline_${HOST_TAG}_${TS}"
SIMD_PERF="${TMP_OUT}/perf_harness_simd_${HOST_TAG}_${TS}"

run_bench_pair light baseline_vs_guarded baseline_scalar "${BASE_BENCH}" off guarded_default "${SIMD_BENCH}" off
run_bench_pair light baseline_vs_forced baseline_scalar "${BASE_BENCH}" off forced_investigation "${SIMD_BENCH}" force
run_bench_pair light guarded_vs_forced guarded_default "${SIMD_BENCH}" off forced_investigation "${SIMD_BENCH}" force

run_bench_pair fast baseline_vs_forced baseline_scalar "${BASE_BENCH}" off forced_investigation "${SIMD_BENCH}" force
run_bench_pair fast guarded_vs_forced guarded_default "${SIMD_BENCH}" off forced_investigation "${SIMD_BENCH}" force
run_bench_pair fast baseline_vs_guarded baseline_scalar "${BASE_BENCH}" off guarded_default "${SIMD_BENCH}" off

run_perf_pair light baseline_vs_guarded baseline_scalar "${BASE_PERF}" off guarded_default "${SIMD_PERF}" off 1.0
run_perf_pair light guarded_vs_forced guarded_default "${SIMD_PERF}" off forced_investigation "${SIMD_PERF}" force 0.0
run_perf_pair light baseline_vs_forced baseline_scalar "${BASE_PERF}" off forced_investigation "${SIMD_PERF}" force 0.0

run_perf_pair fast baseline_vs_forced baseline_scalar "${BASE_PERF}" off forced_investigation "${SIMD_PERF}" force 0.0
run_perf_pair fast guarded_vs_forced guarded_default "${SIMD_PERF}" off forced_investigation "${SIMD_PERF}" force 0.0
run_perf_pair fast baseline_vs_guarded baseline_scalar "${BASE_PERF}" off guarded_default "${SIMD_PERF}" off 1.0

export V7_09_TS="${TS}"
export V7_09_HOST_TAG="${HOST_TAG}"
export V7_09_HEAD_SHA="${HEAD_SHA}"
export V7_09_VENDOR_ID="${VENDOR_ID}"
export V7_09_CPU_FAMILY="${CPU_FAMILY}"
export V7_09_CPU_MODEL="${CPU_MODEL}"
export V7_09_CPU_STEPPING="${CPU_STEPPING}"
export V7_09_CPU_MODEL_NAME="${CPU_MODEL_NAME}"
export V7_09_THREADS="${THREADS}"
export V7_09_BENCH_ITERS="${BENCH_ITERS}"
export V7_09_BENCH_WARMUP="${BENCH_WARMUP}"
export V7_09_BENCH_REPEATS="${BENCH_REPEATS}"
export V7_09_PERF_ITERS="${PERF_ITERS}"
export V7_09_PERF_WARMUP="${PERF_WARMUP}"
export V7_09_LARGE_PAGES="${LARGE_PAGES}"
export V7_09_FINAL_OUT="${FINAL_OUT}"
export V7_09_BENCH_INDEX_FILE="${BENCH_INDEX_FILE}"
export V7_09_PERF_INDEX_FILE="${PERF_INDEX_FILE}"
export V7_09_SUMMARY_FILE="${SUMMARY_FILE}"
export V7_09_MANIFEST_FILE="${MANIFEST_FILE}"
export V7_09_PROVENANCE_FILE="${PROVENANCE_FILE}"

python3 - <<'PY'
import csv
import json
import os
import statistics
from collections import defaultdict
from pathlib import Path

def rel(path: str) -> str:
    return str(Path("perf_results/Intel") / Path(path).name)


def mean(values):
    return statistics.fmean(values) if values else None


def median(values):
    return statistics.median(values) if values else None


def stdev(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def pct_delta(baseline, candidate):
    if baseline == 0:
        return None
    return ((candidate - baseline) / baseline) * 100.0


def row_value(row, key):
    raw = row[key]
    if raw == "n/a":
        return None
    if raw in {"true", "false"}:
        return raw == "true"
    if "." in raw:
        return float(raw)
    return int(raw)


bench_rows_by_key = {}
bench_meta_by_key = {}
with open(os.environ["V7_09_BENCH_INDEX_FILE"], newline="") as f:
    for meta in csv.DictReader(f):
        with open(meta["path"], newline="") as bf:
            rows = list(csv.DictReader(bf))
        key = (meta["mode"], meta["pair_label"])
        bench_rows_by_key[key] = rows
        bench_meta_by_key[key] = meta

perf_rows_by_key = defaultdict(dict)
with open(os.environ["V7_09_PERF_INDEX_FILE"], newline="") as f:
    for meta in csv.DictReader(f):
        with open(meta["path"], newline="") as pf:
            row = next(csv.DictReader(pf))
        perf_rows_by_key[(meta["mode"], meta["pair_label"])][(meta["config_label"], meta["seq"])] = {
            "meta": meta,
            "row": row,
        }

bench_summary = {}
for (mode, pair_label), rows in bench_rows_by_key.items():
    by_config = defaultdict(list)
    by_repeat = defaultdict(dict)
    for row in rows:
        config = row["config_label"]
        ns = int(row["ns_per_hash"])
        by_config[config].append(ns)
        by_repeat[row["repeat_index"]][config] = ns

    configs = sorted(by_config.keys())
    left = configs[0]
    right = configs[1]
    if pair_label.startswith("baseline_vs_"):
        left = "baseline_scalar"
        right = "guarded_default" if "guarded" in pair_label else "forced_investigation"
    elif pair_label == "guarded_vs_forced":
        left = "guarded_default"
        right = "forced_investigation"

    pair_deltas = []
    for repeat_idx in sorted(by_repeat, key=lambda value: int(value)):
        repeat = by_repeat[repeat_idx]
        pair_deltas.append(pct_delta(repeat[left], repeat[right]))

    def config_stats(name):
        values = by_config[name]
        avg = mean(values)
        sd = stdev(values)
        return {
            "runs": values,
            "mean_ns_per_hash": avg,
            "median_ns_per_hash": median(values),
            "stddev_ns_per_hash": sd,
            "cv_pct": None if not avg else (sd / avg) * 100.0,
        }

    left_stats = config_stats(left)
    right_stats = config_stats(right)

    bench_summary.setdefault(mode, {})[pair_label] = {
        "left_config": left,
        "right_config": right,
        "left": left_stats,
        "right": right_stats,
        "delta_pct_right_vs_left_mean": pct_delta(
            left_stats["mean_ns_per_hash"],
            right_stats["mean_ns_per_hash"],
        ),
        "pair_deltas_pct": pair_deltas,
        "artifacts": {
            "csv": rel(bench_meta_by_key[(mode, pair_label)]["path"]),
            "raw_log": rel(bench_meta_by_key[(mode, pair_label)]["raw_log_path"]),
        },
    }

perf_summary = {}
counter_keys = [
    "program_execs",
    "scratchpad_read_bytes",
    "scratchpad_write_bytes",
    "dataset_item_loads",
    "mem_read_l1",
    "mem_read_l2",
    "mem_read_l3",
    "mem_write_l1",
    "mem_write_l2",
    "mem_write_l3",
    "instr_int",
    "instr_float",
    "instr_mem",
    "instr_ctrl",
    "instr_store",
]
stage_keys = [
    "ns_per_hash",
    "prepare_iteration_ns",
    "execute_program_ns_interpreter",
    "finish_iteration_ns",
]

for (mode, pair_label), runs in perf_rows_by_key.items():
    if pair_label.startswith("baseline_vs_"):
        left = "baseline_scalar"
        right = "guarded_default" if "guarded" in pair_label else "forced_investigation"
    else:
        left = "guarded_default"
        right = "forced_investigation"

    left_rows = [runs[(left, seq)] for seq in ("a1", "a2")]
    right_rows = [runs[(right, seq)] for seq in ("b1", "b2")]

    def summarize_rows(items):
        rows = [item["row"] for item in items]
        summary = {
            "paths": [rel(item["meta"]["path"]) for item in items],
            "run_ns_per_hash": [int(row["ns_per_hash"]) for row in rows],
        }
        for key in stage_keys:
            summary[f"{key}_mean"] = mean([row_value(row, key) for row in rows])
        for key in counter_keys:
            summary[f"{key}_mean"] = mean([row_value(row, key) for row in rows])
        summary["git_dirty_values"] = sorted({row["git_dirty"] for row in rows})
        return summary

    left_summary = summarize_rows(left_rows)
    right_summary = summarize_rows(right_rows)

    pair_deltas = [
        pct_delta(row_value(left_rows[0]["row"], "ns_per_hash"), row_value(right_rows[0]["row"], "ns_per_hash")),
        pct_delta(row_value(left_rows[1]["row"], "ns_per_hash"), row_value(right_rows[1]["row"], "ns_per_hash")),
    ]
    stage_delta = {
        key: pct_delta(left_summary[f"{key}_mean"], right_summary[f"{key}_mean"])
        for key in stage_keys
    }
    counter_span = {}
    for key in counter_keys:
        values = [row_value(item["row"], key) for item in left_rows + right_rows]
        counter_span[key] = max(values) - min(values)

    left_drift = pct_delta(
        row_value(left_rows[0]["row"], "ns_per_hash"),
        row_value(left_rows[1]["row"], "ns_per_hash"),
    )
    right_drift = pct_delta(
        row_value(right_rows[0]["row"], "ns_per_hash"),
        row_value(right_rows[1]["row"], "ns_per_hash"),
    )

    perf_summary.setdefault(mode, {})[pair_label] = {
        "left_config": left,
        "right_config": right,
        "left": left_summary,
        "right": right_summary,
        "delta_pct_right_vs_left_mean": pct_delta(
            left_summary["ns_per_hash_mean"],
            right_summary["ns_per_hash_mean"],
        ),
        "stage_delta_pct_right_vs_left_mean": stage_delta,
        "pair_deltas_pct": pair_deltas,
        "left_drift_pct": left_drift,
        "right_drift_pct": right_drift,
        "counter_span": counter_span,
        "perf_compare_artifact": rel(
            f"v7_09_perf_compare_{mode}_{pair_label}_{os.environ['V7_09_HOST_TAG']}_{os.environ['V7_09_TS']}.txt"
        ),
    }

blocked_cpu_match = (
    os.environ["V7_09_VENDOR_ID"] == "GenuineIntel"
    and os.environ["V7_09_CPU_FAMILY"] == "6"
    and os.environ["V7_09_CPU_MODEL"] == "45"
)

summary = {
    "ts": os.environ["V7_09_TS"],
    "host_tag": os.environ["V7_09_HOST_TAG"],
    "head_sha": os.environ["V7_09_HEAD_SHA"],
    "host": {
        "vendor_id": os.environ["V7_09_VENDOR_ID"],
        "cpu_family": int(os.environ["V7_09_CPU_FAMILY"]),
        "cpu_model": int(os.environ["V7_09_CPU_MODEL"]),
        "cpu_stepping": int(os.environ["V7_09_CPU_STEPPING"]),
        "cpu_model_name": os.environ["V7_09_CPU_MODEL_NAME"],
        "blocked_cpu_match": blocked_cpu_match,
        "novelty": "duplicate_family_confirmation" if blocked_cpu_match else "novel_family_evidence",
        "supports_classifier_broadening": False,
    },
    "params": {
        "threads": int(os.environ["V7_09_THREADS"]),
        "large_pages": os.environ["V7_09_LARGE_PAGES"],
        "bench": {
            "iters": int(os.environ["V7_09_BENCH_ITERS"]),
            "warmup": int(os.environ["V7_09_BENCH_WARMUP"]),
            "repeats": int(os.environ["V7_09_BENCH_REPEATS"]),
        },
        "perf": {
            "iters": int(os.environ["V7_09_PERF_ITERS"]),
            "warmup": int(os.environ["V7_09_PERF_WARMUP"]),
        },
    },
    "bench": bench_summary,
    "perf": perf_summary,
    "artifacts": {
        "manifest": rel(os.environ["V7_09_MANIFEST_FILE"]),
        "provenance": rel(os.environ["V7_09_PROVENANCE_FILE"]),
        "bench_index": rel(os.environ["V7_09_BENCH_INDEX_FILE"]),
        "perf_index": rel(os.environ["V7_09_PERF_INDEX_FILE"]),
        "summary": rel(os.environ["V7_09_SUMMARY_FILE"]),
    },
}

with open(os.environ["V7_09_SUMMARY_FILE"], "w") as f:
    json.dump(summary, f, indent=2)
    f.write("\n")
PY

cp "${MANIFEST_FILE}" "${PROVENANCE_FILE}" "${BENCH_INDEX_FILE}" "${PERF_INDEX_FILE}" "${SUMMARY_FILE}" "${FINAL_OUT}/"
cp "${TMP_OUT}"/v7_09_*_"${HOST_TAG}"_"${TS}".csv "${FINAL_OUT}/"
cp "${TMP_OUT}"/v7_09_*_"${HOST_TAG}"_"${TS}".stdout "${FINAL_OUT}/"
cp "${TMP_OUT}"/v7_09_*_"${HOST_TAG}"_"${TS}".stderr "${FINAL_OUT}/"
cp "${TMP_OUT}"/v7_09_*_"${HOST_TAG}"_"${TS}".txt "${FINAL_OUT}/"
cp "${TMP_OUT}"/v7_09_*_"${HOST_TAG}"_"${TS}".raw.log "${FINAL_OUT}/"

echo "wrote artifacts to ${FINAL_OUT}"
