#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

BASE_SHA="${BASE_SHA:-a11022079897a7d2f76228e89be0109ff4f45e44}"
PATCH_SOURCE_SHA="${PATCH_SOURCE_SHA:-fcb47512f74f475e5e2c61c72ba3a86669fc4c69}"
HOST_TAG="${HOST_TAG:-intel}"
THREADS="${THREADS:-32}"
LIGHT_ITERS="${LIGHT_ITERS:-100}"
LIGHT_WARMUP="${LIGHT_WARMUP:-10}"
FAST_ITERS="${FAST_ITERS:-100}"
FAST_WARMUP="${FAST_WARMUP:-10}"
RUN_TESTS="${RUN_TESTS:-1}"
KEEP_WORKTREES="${KEEP_WORKTREES:-0}"
TS="${TS:-$(date +%Y%m%d_%H%M%S)}"

BASE_WT="${BASE_WT:-/tmp/oxide-randomx-v6_07-${HOST_TAG}-baseline-${TS}}"
CAND_WT="${CAND_WT:-/tmp/oxide-randomx-v6_07-${HOST_TAG}-candidate-${TS}}"
TMP_OUT="${TMP_OUT:-/tmp/oxide-randomx-v6_07-${HOST_TAG}-out-${TS}}"
FINAL_OUT="${FINAL_OUT:-${ROOT_DIR}/perf_results/Intel}"

PATCH_FILE="${TMP_OUT}/v6_07_p2_2_exact_candidate_${HOST_TAG}_${TS}.patch"
MANIFEST_FILE="${TMP_OUT}/v6_07_manifest_${HOST_TAG}_${TS}.txt"
PROVENANCE_FILE="${TMP_OUT}/v6_07_provenance_${HOST_TAG}_${TS}.txt"

cleanup() {
    local code=$?
    if [[ "${KEEP_WORKTREES}" != "1" ]]; then
        git -C "${ROOT_DIR}" worktree remove --force "${BASE_WT}" >/dev/null 2>&1 || true
        git -C "${ROOT_DIR}" worktree remove --force "${CAND_WT}" >/dev/null 2>&1 || true
    fi
    exit "${code}"
}
trap cleanup EXIT

mkdir -p "${TMP_OUT}" "${FINAL_OUT}"
git -C "${ROOT_DIR}" worktree remove --force "${BASE_WT}" >/dev/null 2>&1 || true
git -C "${ROOT_DIR}" worktree remove --force "${CAND_WT}" >/dev/null 2>&1 || true
rm -rf "${BASE_WT}" "${CAND_WT}"

git -C "${ROOT_DIR}" worktree add --detach "${BASE_WT}" "${BASE_SHA}" >/dev/null
git -C "${ROOT_DIR}" worktree add --detach "${CAND_WT}" "${BASE_SHA}" >/dev/null

git -C "${ROOT_DIR}" diff "${BASE_SHA}..${PATCH_SOURCE_SHA}" -- \
    src/vm/mod.rs \
    src/vm/jit/x86_64.rs > "${PATCH_FILE}"

git -C "${CAND_WT}" apply "${PATCH_FILE}"
git -C "${CAND_WT}" add src/vm/mod.rs src/vm/jit/x86_64.rs
git -C "${CAND_WT}" \
    -c commit.gpgSign=false \
    -c user.name="Codex" \
    -c user.email="codex@local" \
    commit \
    -m "v6_07 isolated P2.2 jit-fastregs candidate patch" >/dev/null
git -C "${CAND_WT}" diff --exit-code "${PATCH_SOURCE_SHA}" -- \
    src/vm/mod.rs \
    src/vm/jit/x86_64.rs >/dev/null

{
    echo "ts=${TS}"
    echo "host_tag=${HOST_TAG}"
    echo "base_sha=${BASE_SHA}"
    echo "patch_source_sha=${PATCH_SOURCE_SHA}"
    echo "baseline_head=$(git -C "${BASE_WT}" rev-parse HEAD)"
    echo "candidate_head=$(git -C "${CAND_WT}" rev-parse HEAD)"
    echo "threads=${THREADS}"
    echo "light_iters=${LIGHT_ITERS}"
    echo "light_warmup=${LIGHT_WARMUP}"
    echo "fast_iters=${FAST_ITERS}"
    echo "fast_warmup=${FAST_WARMUP}"
    echo "run_tests=${RUN_TESTS}"
    echo "keep_worktrees=${KEEP_WORKTREES}"
    echo "base_worktree=${BASE_WT}"
    echo "candidate_worktree=${CAND_WT}"
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
} > "${PROVENANCE_FILE}"

run_test_bundle() {
    local label=$1
    local wt=$2
    local log_prefix="${TMP_OUT}/v6_07_${label}_${HOST_TAG}_${TS}"

    (
        cd "${wt}"
        cargo test --test oracle
    ) > "${log_prefix}_oracle.stdout" 2> "${log_prefix}_oracle.stderr"

    (
        cd "${wt}"
        cargo test --features "jit jit-fastregs" --test oracle
    ) > "${log_prefix}_oracle_jit_fastregs.stdout" \
      2> "${log_prefix}_oracle_jit_fastregs.stderr"

    (
        cd "${wt}"
        cargo test --features "jit bench-instrument" --test jit_perf_smoke
    ) > "${log_prefix}_jit_perf_smoke.stdout" \
      2> "${log_prefix}_jit_perf_smoke.stderr"
}

run_perf() {
    local state=$1
    local wt=$2
    local mode=$3
    local variant=$4
    local seq=$5

    local iters warmup features env_prefix file_prefix
    case "${mode}" in
        light)
            iters="${LIGHT_ITERS}"
            warmup="${LIGHT_WARMUP}"
            env_prefix=""
            ;;
        fast)
            iters="${FAST_ITERS}"
            warmup="${FAST_WARMUP}"
            env_prefix="OXIDE_RANDOMX_FAST_BENCH=1"
            ;;
        *)
            echo "unsupported mode: ${mode}" >&2
            exit 1
            ;;
    esac

    case "${variant}" in
        conservative)
            features="jit bench-instrument"
            ;;
        fastregs)
            features="jit jit-fastregs bench-instrument"
            ;;
        *)
            echo "unsupported variant: ${variant}" >&2
            exit 1
            ;;
    esac

    file_prefix="${TMP_OUT}/v6_07_${state}_${mode}_jit_${variant}_${seq}_${HOST_TAG}_${TS}"

    (
        cd "${wt}"
        if [[ -n "${env_prefix}" ]]; then
            env ${env_prefix} cargo run --release --example perf_harness --features "${features}" -- \
                --mode "${mode}" \
                --jit on \
                --jit-fast-regs "$([[ "${variant}" == "fastregs" ]] && echo on || echo off)" \
                --iters "${iters}" \
                --warmup "${warmup}" \
                --threads "${THREADS}" \
                --large-pages off \
                --thread-names off \
                --affinity off \
                --format csv \
                --out "${file_prefix}.csv"
        else
            cargo run --release --example perf_harness --features "${features}" -- \
                --mode "${mode}" \
                --jit on \
                --jit-fast-regs "$([[ "${variant}" == "fastregs" ]] && echo on || echo off)" \
                --iters "${iters}" \
                --warmup "${warmup}" \
                --threads "${THREADS}" \
                --large-pages off \
                --thread-names off \
                --affinity off \
                --format csv \
                --out "${file_prefix}.csv"
        fi
    ) > "${file_prefix}.stdout" 2> "${file_prefix}.stderr"
}

run_abba_set() {
    local state=$1
    local wt=$2
    local mode=$3

    run_perf "${state}" "${wt}" "${mode}" conservative a1
    run_perf "${state}" "${wt}" "${mode}" fastregs b1
    run_perf "${state}" "${wt}" "${mode}" fastregs b2
    run_perf "${state}" "${wt}" "${mode}" conservative a2
}

if [[ "${RUN_TESTS}" == "1" ]]; then
    run_test_bundle baseline "${BASE_WT}"
    run_test_bundle candidate "${CAND_WT}"
fi

# Balance state order between modes to reduce session drift bias.
run_abba_set baseline "${BASE_WT}" fast
run_abba_set candidate "${CAND_WT}" fast
run_abba_set candidate "${CAND_WT}" light
run_abba_set baseline "${BASE_WT}" light

cp "${PATCH_FILE}" "${MANIFEST_FILE}" "${PROVENANCE_FILE}" "${FINAL_OUT}/"
cp "${TMP_OUT}"/v6_07_*_"${HOST_TAG}"_"${TS}".csv "${FINAL_OUT}/"
cp "${TMP_OUT}"/v6_07_*_"${HOST_TAG}"_"${TS}".stdout "${FINAL_OUT}/"
cp "${TMP_OUT}"/v6_07_*_"${HOST_TAG}"_"${TS}".stderr "${FINAL_OUT}/"
test_stdout=( "${TMP_OUT}"/v6_07_*_"${HOST_TAG}"_"${TS}"_*.stdout )
if ((${#test_stdout[@]} > 0)); then
    cp "${test_stdout[@]}" "${FINAL_OUT}/"
fi
test_stderr=( "${TMP_OUT}"/v6_07_*_"${HOST_TAG}"_"${TS}"_*.stderr )
if ((${#test_stderr[@]} > 0)); then
    cp "${test_stderr[@]}" "${FINAL_OUT}/"
fi

echo "wrote artifacts to ${FINAL_OUT}"
