#!/usr/bin/env bash
set -euo pipefail

crate_rel_path="crates/oxide-randomx"
manifest_path=${1:-${crate_rel_path}/perf_baselines/ci/manifest.txt}
artifact_dir=${2:-artifacts/perf-gate}
build_features=${OXIDE_RANDOMX_CI_PERF_FEATURES:-jit jit-fastregs bench-instrument}

resolve_binary() {
    local base_path="$1"
    if [[ -x "${base_path}" ]]; then
        printf '%s\n' "${base_path}"
        return
    fi
    if [[ -x "${base_path}.exe" ]]; then
        printf '%s\n' "${base_path}.exe"
        return
    fi
    printf '%s\n' "${base_path}"
}

resolve_workspace_or_crate_path() {
    local path="$1"
    if [[ -e "${path}" ]]; then
        printf '%s\n' "${path}"
        return 0
    fi
    if [[ -e "${crate_rel_path}/${path}" ]]; then
        printf '%s\n' "${crate_rel_path}/${path}"
        return 0
    fi
    return 1
}

repo_root=$(git rev-parse --show-toplevel)
cd "${repo_root}"

if [[ ! -e "${manifest_path}" ]]; then
    if resolved_manifest=$(resolve_workspace_or_crate_path "${manifest_path}"); then
        manifest_path="${resolved_manifest}"
    fi
fi

candidate_dir="${artifact_dir}/candidate"
baseline_dir="${artifact_dir}/baseline"
compare_dir="${artifact_dir}/compare"

if [[ ! -f "${manifest_path}" ]]; then
    echo "missing perf gate manifest: ${manifest_path}" >&2
    exit 2
fi

if [[ -d "ox-build/target" ]]; then
    cargo_target_dir="ox-build/target"
else
    cargo_target_dir="target"
fi

mkdir -p "${candidate_dir}" "${baseline_dir}" "${compare_dir}"
cp "${manifest_path}" "${artifact_dir}/manifest.txt"

export OXIDE_RANDOMX_GIT_SHA=${OXIDE_RANDOMX_GIT_SHA:-$(git rev-parse HEAD)}
export OXIDE_RANDOMX_GIT_SHA_SHORT=${OXIDE_RANDOMX_GIT_SHA_SHORT:-$(git rev-parse --short HEAD)}
if [[ -z "${OXIDE_RANDOMX_GIT_DIRTY:-}" ]]; then
    if [[ -n "$(git status --porcelain)" ]]; then
        export OXIDE_RANDOMX_GIT_DIRTY=true
    else
        export OXIDE_RANDOMX_GIT_DIRTY=false
    fi
fi
export OXIDE_RANDOMX_RUSTC_VERSION=${OXIDE_RANDOMX_RUSTC_VERSION:-$(rustc --version)}

cargo build --release -p oxide-randomx --bin perf_compare --example perf_harness --features "${build_features}"

harness=$(resolve_binary "./${cargo_target_dir}/release/examples/perf_harness")
compare=$(resolve_binary "./${cargo_target_dir}/release/perf_compare")

regressions=()
tool_failures=()

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "## Perf Gate"
        echo
        echo "Scope: supported-path CI guardrail only, not AMD/Intel host authority."
        echo "Failure semantics: exit \`1\` = regression, exit \`2\` = tooling/input failure."
        echo
        echo "| Scenario | Threshold | Candidate Repeats | Result |"
        echo "| --- | --- | --- | --- |"
    } > "${GITHUB_STEP_SUMMARY}"
fi

while IFS='|' read -r scenario_id baseline_path threshold_pct candidate_repeats mode jit jit_fast_regs iters warmup; do
    [[ -z "${scenario_id}" || "${scenario_id:0:1}" == "#" ]] && continue

    compare_log="${compare_dir}/${scenario_id}.txt"
    candidate_csv="${candidate_dir}/${scenario_id}.csv"
    baseline_copy="${baseline_dir}/${scenario_id}.csv"
    baseline_resolved_path="${baseline_path}"
    if [[ ! -f "${baseline_resolved_path}" ]]; then
        if resolved_baseline=$(resolve_workspace_or_crate_path "${baseline_path}"); then
            baseline_resolved_path="${resolved_baseline}"
        fi
    fi
    fast_bench_env="off"
    if [[ "${mode}" == "fast" ]]; then
        fast_bench_env="on"
    fi

    {
        echo "scenario_id=${scenario_id}"
        echo "baseline=${baseline_path}"
        echo "baseline_resolved=${baseline_resolved_path}"
        echo "threshold_pct=${threshold_pct}"
        echo "candidate_repeats=${candidate_repeats}"
        echo "scope=supported_path_ci_guardrail_only"
        echo "oxiderandomx_fast_bench=${fast_bench_env}"
        echo "command=${harness} --mode ${mode} --jit ${jit} --jit-fast-regs ${jit_fast_regs} --iters ${iters} --warmup ${warmup} --format csv"
        echo
    } > "${compare_log}"

    if [[ ! -f "${baseline_resolved_path}" ]]; then
        echo "::error title=Perf gate input failure::${scenario_id} baseline fixture is missing at ${baseline_path}"
        tool_failures+=("${scenario_id}")
        if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
            echo "| ${scenario_id} | ${threshold_pct}% | ${candidate_repeats} | input failure |" >> "${GITHUB_STEP_SUMMARY}"
        fi
        continue
    fi

    cp "${baseline_resolved_path}" "${baseline_copy}"
    rm -f "${candidate_csv}"

    for run_index in $(seq 1 "${candidate_repeats}"); do
        run_csv="${candidate_dir}/${scenario_id}.run${run_index}.csv"
        if [[ "${mode}" == "fast" ]]; then
            if [[ "${harness}" == *.exe ]]; then
                harness_win=$(wslpath -m "${harness}")
                run_csv_win=$(wslpath -m "${run_csv}")
                powershell.exe -NoProfile -Command "\$env:OXIDE_RANDOMX_FAST_BENCH='1'; & '${harness_win}' --mode ${mode} --jit ${jit} --jit-fast-regs ${jit_fast_regs} --iters ${iters} --warmup ${warmup} --format csv --out '${run_csv_win}'; exit \$LASTEXITCODE"
            else
                (
                    export OXIDE_RANDOMX_FAST_BENCH=1
                    "${harness}" \
                        --mode "${mode}" \
                        --jit "${jit}" \
                        --jit-fast-regs "${jit_fast_regs}" \
                        --iters "${iters}" \
                        --warmup "${warmup}" \
                        --format csv \
                        --out "${run_csv}" \
                        </dev/null
                )
            fi
        else
            "${harness}" \
                --mode "${mode}" \
                --jit "${jit}" \
                --jit-fast-regs "${jit_fast_regs}" \
                --iters "${iters}" \
                --warmup "${warmup}" \
                --format csv \
                --out "${run_csv}" \
                </dev/null
        fi

        if [[ "${run_index}" -eq 1 ]]; then
            cp "${run_csv}" "${candidate_csv}"
        else
            tail -n +2 "${run_csv}" >> "${candidate_csv}"
        fi
    done

    if "${compare}" --baseline "${baseline_resolved_path}" --candidate "${candidate_csv}" --threshold-pct "${threshold_pct}" </dev/null | tee -a "${compare_log}"; then
        result="pass"
    else
        status=$?
        case "${status}" in
            1)
                result="regression"
                regressions+=("${scenario_id}")
                echo "::error title=Perf regression::${scenario_id} exceeded the ${threshold_pct}% threshold"
                ;;
            2)
                result="input failure"
                tool_failures+=("${scenario_id}")
                echo "::error title=Perf gate input failure::${scenario_id} could not be compared because the baseline or candidate CSV was invalid"
                ;;
            *)
                result="unexpected failure"
                tool_failures+=("${scenario_id}")
                echo "::error title=Perf gate failure::${scenario_id} exited unexpectedly with status ${status}"
                ;;
        esac
    fi

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "| ${scenario_id} | ${threshold_pct}% | ${candidate_repeats} | ${result} |" >> "${GITHUB_STEP_SUMMARY}"
    fi
done < "${manifest_path}"

if (( ${#tool_failures[@]} > 0 )); then
    echo "perf gate encountered tooling/input failures: ${tool_failures[*]}" >&2
    exit 2
fi

if (( ${#regressions[@]} > 0 )); then
    echo "perf regressions exceeded threshold: ${regressions[*]}" >&2
    exit 1
fi

echo "perf gate passed for all supported-path scenarios"
