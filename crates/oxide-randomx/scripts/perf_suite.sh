#!/usr/bin/env bash
#
# Comprehensive performance benchmark suite for oxide-randomx (Linux/macOS)
#
# This script runs a complete series of performance benchmarks as outlined in docs/perf.md.
# It covers:
# - Light mode baseline (interpreter vs JIT)
# - JIT conservative vs fast-regs comparison
# - Fast mode (dataset) benchmarks
# - Cold vs warm JIT behavior
# - Large pages performance impact
# - Machine-readable output (CSV/JSON)
# - Validation runs
#
# Usage:
#   ./perf_suite.sh [options]
#
# Options:
#   --mode light|fast|all    Benchmark mode (default: all)
#   --iters N                Number of measured iterations (default: 100)
#   --warmup N               Number of warmup iterations (default: 10)
#   --threads N              Thread count for dataset init (default: auto)
#   --large-pages            Enable large pages
#   --1gb-pages              Enable 1GB huge pages (Linux only)
#   --output-dir DIR         Output directory base (default: ./perf_results)
#                           Results are stored in DIR/<machine-id>
#   --quick                  Quick mode with minimal iterations
#   --skip-validation        Skip validation runs
#   --skip-fast              Skip fast mode benchmarks
#   --help                   Show this help message
#
# Examples:
#   ./perf_suite.sh                           # Full suite with defaults
#   ./perf_suite.sh --mode light --quick      # Quick light-mode test
#   ./perf_suite.sh --large-pages --1gb-pages # With huge pages (Linux)

set -euo pipefail

# ============================================================================
# Default configuration
# ============================================================================
MODE="all"
ITERS=100
WARMUP=10
THREADS=0
LARGE_PAGES=false
USE_1GB_PAGES=false
OUTPUT_DIR="./perf_results"
QUICK_TEST=false
SKIP_VALIDATION=false
SKIP_FAST=false

# ============================================================================
# Color output helpers
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

log() {
    echo -e "$1"
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$SUMMARY_FILE"
}

log_color() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
    echo "$msg" >> "$SUMMARY_FILE"
}

SUITE_FAILED=false

mark_failure() {
    local msg="$1"
    SUITE_FAILED=true
    log_color "$RED" "$msg"
}

validate_output_file() {
    local step="$1"
    local path="$2"

    if [[ ! -e "$path" ]]; then
        mark_failure "        FAILED (${step}): missing output file: $path"
        return 1
    fi

    if [[ ! -s "$path" ]]; then
        mark_failure "        FAILED (${step}): empty output file: $path"
        return 1
    fi

    return 0
}

run_step() {
    local step="$1"
    shift
    local exit_code=0

    set +e
    "$@"
    exit_code=$?
    set -e

    if [[ $exit_code -ne 0 ]]; then
        mark_failure "        FAILED (${step}): command failed (exit code $exit_code): $*"
        return 1
    fi

    return 0
}

run_step_to_file() {
    local step="$1"
    local file="$2"
    shift 2
    local exit_code=0

    set +e
    "$@" > "$file"
    exit_code=$?
    set -e

    if [[ $exit_code -ne 0 ]]; then
        mark_failure "        FAILED (${step}): command failed (exit code $exit_code): $*"
        return 1
    fi

    return 0
}

run_step_to_file_all() {
    local step="$1"
    local file="$2"
    shift 2
    local exit_code=0

    set +e
    "$@" > "$file" 2>&1
    exit_code=$?
    set -e

    if [[ $exit_code -ne 0 ]]; then
        mark_failure "        FAILED (${step}): command failed (exit code $exit_code): $*"
        return 1
    fi

    return 0
}

run_step_capture() {
    local step="$1"
    local out_var="$2"
    shift 2
    local output=""
    local exit_code=0

    set +e
    output=$("$@" 2>&1)
    exit_code=$?
    set -e

    printf -v "$out_var" '%s' "$output"

    if [[ $exit_code -ne 0 ]]; then
        mark_failure "        FAILED (${step}): command failed (exit code $exit_code): $*"
        if [[ -n "$output" ]]; then
            log_color "$RED" "        $output"
        fi
        return 1
    fi

    return 0
}

# ============================================================================
# Parse command line arguments
# ============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --iters)
            ITERS="$2"
            shift 2
            ;;
        --warmup)
            WARMUP="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --large-pages)
            LARGE_PAGES=true
            shift
            ;;
        --1gb-pages)
            USE_1GB_PAGES=true
            LARGE_PAGES=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --quick)
            QUICK_TEST=true
            shift
            ;;
        --skip-validation)
            SKIP_VALIDATION=true
            shift
            ;;
        --skip-fast)
            SKIP_FAST=true
            shift
            ;;
        --help)
            head -40 "$0" | tail -35
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Quick test overrides
if $QUICK_TEST; then
    ITERS=20
    WARMUP=2
fi

# Machine id helper (stable per-machine when possible)
get_machine_id() {
    local id=""
    if [[ -r /etc/machine-id ]]; then
        id=$(cat /etc/machine-id)
    elif [[ -r /var/lib/dbus/machine-id ]]; then
        id=$(cat /var/lib/dbus/machine-id)
    elif command -v ioreg >/dev/null 2>&1; then
        id=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F\" '/IOPlatformUUID/{print $4}')
    elif command -v system_profiler >/dev/null 2>&1; then
        id=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Hardware UUID/{print $2}')
    fi

    if [[ -z "$id" ]]; then
        id=$(hostname 2>/dev/null || uname -n)
    fi

    id=$(echo "$id" | tr -cd 'A-Za-z0-9._-')
    if [[ -z "$id" ]]; then
        id="unknown-machine"
    fi

    echo "$id"
}

MACHINE_ID=$(get_machine_id)
if [[ "$(basename "$OUTPUT_DIR")" != "$MACHINE_ID" ]]; then
    OUTPUT_DIR="${OUTPUT_DIR%/}/$MACHINE_ID"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SUMMARY_FILE="$OUTPUT_DIR/perf_summary_$TIMESTAMP.txt"

# Thread arguments for fast mode commands
THREAD_ARGS=()
if [[ $THREADS -gt 0 ]]; then
    THREAD_ARGS=(--threads "$THREADS")
fi

# Set environment variables
if $LARGE_PAGES; then
    export OXIDE_RANDOMX_LARGE_PAGES=1
    log_color "$YELLOW" "Large pages: ENABLED"
else
    unset OXIDE_RANDOMX_LARGE_PAGES 2>/dev/null || true
    log_color "$GRAY" "Large pages: disabled"
fi

if $USE_1GB_PAGES; then
    export OXIDE_RANDOMX_HUGE_1G=1
    log_color "$YELLOW" "1GB huge pages: ENABLED (Linux only)"
else
    unset OXIDE_RANDOMX_HUGE_1G 2>/dev/null || true
fi

log ""
log "========================================"
log " Oxide-RandomX Performance Suite"
log "========================================"
log ""
log "Configuration:"
log "  Mode        : $MODE"
log "  Iters       : $ITERS"
log "  Warmup      : $WARMUP"
log "  Threads     : $(if [[ $THREADS -gt 0 ]]; then echo $THREADS; else echo '(auto)'; fi)"
log "  Large Pages : $LARGE_PAGES"
log "  1GB Pages   : $USE_1GB_PAGES"
log "  Machine ID  : $MACHINE_ID"
log "  Output Dir  : $OUTPUT_DIR"
log "  Timestamp   : $TIMESTAMP"
log ""

# ============================================================================
# SECTION 1: Validation (optional)
# ============================================================================
if ! $SKIP_VALIDATION; then
    log_color "$CYAN" "----------------------------------------"
    log_color "$CYAN" "SECTION 1: Validation Runs"
    log_color "$CYAN" "----------------------------------------"
    log ""

    log_color "$GRAY" "  [1.1] Light mode validation (interpreter + JIT)..."
    OUTPUT=""
    if run_step_capture "1.1 Light validation both" OUTPUT \
        cargo run --release --example bench --features "jit" -- --mode light --jit both --validate; then
        log_color "$GREEN" "        PASSED"
    else
        log_color "$RED" "        FAILED"
    fi

    log_color "$GRAY" "  [1.2] Light mode validation (JIT fast-regs)..."
    OUTPUT=""
    if run_step_capture "1.2 Light validation fast-regs" OUTPUT \
        cargo run --release --example bench --features "jit jit-fastregs" -- --mode light --jit on --jit-fast-regs on --validate; then
        log_color "$GREEN" "        PASSED"
    else
        log_color "$RED" "        FAILED"
    fi

    log ""
fi

# ============================================================================
# SECTION 2: Light Mode Benchmarks
# ============================================================================
if [[ "$MODE" == "light" || "$MODE" == "all" ]]; then
    log_color "$CYAN" "----------------------------------------"
    log_color "$CYAN" "SECTION 2: Light Mode Benchmarks"
    log_color "$CYAN" "----------------------------------------"
    log ""

    # 2.1 Interpreter baseline
    log_color "$GRAY" "  [2.1] Interpreter baseline..."
    CSV_FILE="$OUTPUT_DIR/light_interpreter_$TIMESTAMP.csv"
    if run_step_to_file "2.1 Interpreter baseline" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode light --jit off --iters $ITERS --warmup $WARMUP --report --format csv; then
        validate_output_file "2.1 Interpreter baseline" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 2.2 JIT conservative
    log_color "$GRAY" "  [2.2] JIT conservative..."
    CSV_FILE="$OUTPUT_DIR/light_jit_conservative_$TIMESTAMP.csv"
    if run_step_to_file "2.2 JIT conservative" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode light --jit on --jit-fast-regs off --iters $ITERS --warmup $WARMUP --report --format csv; then
        validate_output_file "2.2 JIT conservative" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 2.3 JIT fast-regs
    log_color "$GRAY" "  [2.3] JIT fast-regs..."
    CSV_FILE="$OUTPUT_DIR/light_jit_fastregs_$TIMESTAMP.csv"
    if run_step_to_file "2.3 JIT fast-regs" "$CSV_FILE" \
        cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- \
        --mode light --jit on --jit-fast-regs on --iters $ITERS --warmup $WARMUP --report --format csv; then
        validate_output_file "2.3 JIT fast-regs" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 2.4 Cold JIT (warmup=0)
    log_color "$GRAY" "  [2.4] Cold JIT (warmup=0)..."
    CSV_FILE="$OUTPUT_DIR/light_jit_cold_$TIMESTAMP.csv"
    if run_step_to_file "2.4 Cold JIT" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode light --jit on --iters $ITERS --warmup 0 --report --format csv; then
        validate_output_file "2.4 Cold JIT" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 2.5 Warm JIT (warmup=20)
    log_color "$GRAY" "  [2.5] Warm JIT (warmup=20)..."
    CSV_FILE="$OUTPUT_DIR/light_jit_warm_$TIMESTAMP.csv"
    if run_step_to_file "2.5 Warm JIT" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode light --jit on --iters $ITERS --warmup 20 --report --format csv; then
        validate_output_file "2.5 Warm JIT" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 2.6 Combined interpreter + JIT (both)
    log_color "$GRAY" "  [2.6] Combined (interpreter + JIT)..."
    CSV_FILE="$OUTPUT_DIR/light_both_$TIMESTAMP.csv"
    if run_step_to_file "2.6 Combined light both CSV" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode light --jit both --iters $ITERS --warmup $WARMUP --report --format csv; then
        validate_output_file "2.6 Combined light both CSV" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 2.7 JSON output for programmatic analysis
    log_color "$GRAY" "  [2.7] JSON output (combined)..."
    JSON_FILE="$OUTPUT_DIR/light_both_$TIMESTAMP.json"
    if run_step_to_file "2.7 Combined light both JSON" "$JSON_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode light --jit both --iters $ITERS --warmup $WARMUP --report --format json; then
        validate_output_file "2.7 Combined light both JSON" "$JSON_FILE" || true
    fi
    log_color "$GRAY" "        Output: $JSON_FILE"

    log ""
fi

# ============================================================================
# SECTION 3: Fast Mode Benchmarks (Dataset)
# ============================================================================
if [[ ("$MODE" == "fast" || "$MODE" == "all") && "$SKIP_FAST" == "false" ]]; then
    log_color "$CYAN" "----------------------------------------"
    log_color "$CYAN" "SECTION 3: Fast Mode Benchmarks (Dataset)"
    log_color "$CYAN" "----------------------------------------"
    log ""
    log_color "$YELLOW" "  NOTE: Fast mode allocates ~2GB for dataset initialization"
    log ""

    export OXIDE_RANDOMX_FAST_BENCH=1

    # 3.1 Interpreter baseline
    log_color "$GRAY" "  [3.1] Interpreter baseline..."
    CSV_FILE="$OUTPUT_DIR/fast_interpreter_$TIMESTAMP.csv"
    if run_step_to_file "3.1 Fast interpreter baseline" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode fast --jit off --iters $ITERS --warmup $WARMUP "${THREAD_ARGS[@]}" --report --format csv; then
        validate_output_file "3.1 Fast interpreter baseline" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 3.2 JIT conservative
    log_color "$GRAY" "  [3.2] JIT conservative..."
    CSV_FILE="$OUTPUT_DIR/fast_jit_conservative_$TIMESTAMP.csv"
    if run_step_to_file "3.2 Fast JIT conservative" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode fast --jit on --jit-fast-regs off --iters $ITERS --warmup $WARMUP "${THREAD_ARGS[@]}" --report --format csv; then
        validate_output_file "3.2 Fast JIT conservative" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 3.3 JIT fast-regs
    log_color "$GRAY" "  [3.3] JIT fast-regs..."
    CSV_FILE="$OUTPUT_DIR/fast_jit_fastregs_$TIMESTAMP.csv"
    if run_step_to_file "3.3 Fast JIT fast-regs" "$CSV_FILE" \
        cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- \
        --mode fast --jit on --jit-fast-regs on --iters $ITERS --warmup $WARMUP "${THREAD_ARGS[@]}" --report --format csv; then
        validate_output_file "3.3 Fast JIT fast-regs" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 3.4 Combined interpreter + JIT (both)
    log_color "$GRAY" "  [3.4] Combined (interpreter + JIT)..."
    CSV_FILE="$OUTPUT_DIR/fast_both_$TIMESTAMP.csv"
    if run_step_to_file "3.4 Fast combined both CSV" "$CSV_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode fast --jit both --iters $ITERS --warmup $WARMUP "${THREAD_ARGS[@]}" --report --format csv; then
        validate_output_file "3.4 Fast combined both CSV" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"

    # 3.5 JSON output
    log_color "$GRAY" "  [3.5] JSON output (combined)..."
    JSON_FILE="$OUTPUT_DIR/fast_both_$TIMESTAMP.json"
    if run_step_to_file "3.5 Fast combined both JSON" "$JSON_FILE" \
        cargo run --release --example bench --features "jit bench-instrument" -- \
        --mode fast --jit both --iters $ITERS --warmup $WARMUP "${THREAD_ARGS[@]}" --report --format json; then
        validate_output_file "3.5 Fast combined both JSON" "$JSON_FILE" || true
    fi
    log_color "$GRAY" "        Output: $JSON_FILE"

    log ""
fi

# ============================================================================
# SECTION 4: Perf Harness (Structured Measurement)
# ============================================================================
log_color "$CYAN" "----------------------------------------"
log_color "$CYAN" "SECTION 4: Perf Harness (Structured Measurement)"
log_color "$CYAN" "----------------------------------------"
log ""

# 4.1 Light mode perf harness (human)
log_color "$GRAY" "  [4.1] Light mode perf harness (human)..."
HUMAN_FILE="$OUTPUT_DIR/perf_light_human_$TIMESTAMP.txt"
if run_step_to_file_all "4.1 Perf harness light human" "$HUMAN_FILE" \
    cargo run --release --example perf_harness --features "jit bench-instrument" -- \
    --mode light --jit on --iters $ITERS --warmup $WARMUP --format human; then
    validate_output_file "4.1 Perf harness light human" "$HUMAN_FILE" || true
fi
log_color "$GRAY" "        Output: $HUMAN_FILE"

# 4.2 Light mode perf harness (CSV)
log_color "$GRAY" "  [4.2] Light mode perf harness (CSV)..."
CSV_FILE="$OUTPUT_DIR/perf_light_$TIMESTAMP.csv"
if run_step "4.2 Perf harness light CSV" \
    cargo run --release --example perf_harness --features "jit bench-instrument" -- \
    --mode light --jit on --iters $ITERS --warmup $WARMUP --format csv --out "$CSV_FILE"; then
    validate_output_file "4.2 Perf harness light CSV" "$CSV_FILE" || true
fi
log_color "$GRAY" "        Output: $CSV_FILE"

# 4.3 Light mode perf harness (JSON)
log_color "$GRAY" "  [4.3] Light mode perf harness (JSON)..."
JSON_FILE="$OUTPUT_DIR/perf_light_$TIMESTAMP.json"
if run_step "4.3 Perf harness light JSON" \
    cargo run --release --example perf_harness --features "jit bench-instrument" -- \
    --mode light --jit on --iters $ITERS --warmup $WARMUP --format json --out "$JSON_FILE"; then
    validate_output_file "4.3 Perf harness light JSON" "$JSON_FILE" || true
fi
log_color "$GRAY" "        Output: $JSON_FILE"

if [[ ("$MODE" == "fast" || "$MODE" == "all") && "$SKIP_FAST" == "false" ]]; then
    export OXIDE_RANDOMX_FAST_BENCH=1

    # 4.4 Fast mode perf harness (CSV)
    log_color "$GRAY" "  [4.4] Fast mode perf harness (CSV)..."
    CSV_FILE="$OUTPUT_DIR/perf_fast_$TIMESTAMP.csv"
    if run_step "4.4 Perf harness fast CSV" \
        cargo run --release --example perf_harness --features "jit bench-instrument" -- \
        --mode fast --jit on --iters $ITERS --warmup $WARMUP "${THREAD_ARGS[@]}" --format csv --out "$CSV_FILE"; then
        validate_output_file "4.4 Perf harness fast CSV" "$CSV_FILE" || true
    fi
    log_color "$GRAY" "        Output: $CSV_FILE"
fi

log ""

# ============================================================================
# SECTION 5: Feature Comparison Summary
# ============================================================================
log_color "$CYAN" "----------------------------------------"
log_color "$CYAN" "SECTION 5: Feature Comparison (Human Readable)"
log_color "$CYAN" "----------------------------------------"
log ""

log_color "$GRAY" "  Running comparison benchmarks..."
log ""

# Interpreter
log "  Interpreter:"
OUTPUT=""
if run_step_capture "5 Interpreter comparison" OUTPUT \
    cargo run --release --example bench --features "jit bench-instrument" -- \
    --mode light --jit off --iters $ITERS --warmup $WARMUP; then
    INTERP_LINE=$(echo "$OUTPUT" | grep "ns/hash" | head -1 || true)
    if [[ -n "$INTERP_LINE" ]]; then
        log "    $INTERP_LINE"
    else
        mark_failure "        FAILED (5 Interpreter comparison): missing ns/hash line in command output"
        log_color "$RED" "    <missing ns/hash output>"
    fi
else
    log_color "$RED" "    <command failed>"
fi

# JIT Conservative
log "  JIT Conservative:"
OUTPUT=""
if run_step_capture "5 JIT conservative comparison" OUTPUT \
    cargo run --release --example bench --features "jit bench-instrument" -- \
    --mode light --jit on --jit-fast-regs off --iters $ITERS --warmup $WARMUP; then
    JIT_LINE=$(echo "$OUTPUT" | grep "ns/hash" | head -1 || true)
    if [[ -n "$JIT_LINE" ]]; then
        log "    $JIT_LINE"
    else
        mark_failure "        FAILED (5 JIT conservative comparison): missing ns/hash line in command output"
        log_color "$RED" "    <missing ns/hash output>"
    fi
else
    log_color "$RED" "    <command failed>"
fi

# JIT Fast-Regs
log "  JIT Fast-Regs:"
OUTPUT=""
if run_step_capture "5 JIT fast-regs comparison" OUTPUT \
    cargo run --release --example bench --features "jit jit-fastregs bench-instrument" -- \
    --mode light --jit on --jit-fast-regs on --iters $ITERS --warmup $WARMUP; then
    FASTREGS_LINE=$(echo "$OUTPUT" | grep "ns/hash" | head -1 || true)
    if [[ -n "$FASTREGS_LINE" ]]; then
        log "    $FASTREGS_LINE"
    else
        mark_failure "        FAILED (5 JIT fast-regs comparison): missing ns/hash line in command output"
        log_color "$RED" "    <missing ns/hash output>"
    fi
else
    log_color "$RED" "    <command failed>"
fi

log ""

# ============================================================================
# SECTION 6: Perf Smoke Test
# ============================================================================
log_color "$CYAN" "----------------------------------------"
log_color "$CYAN" "SECTION 6: Perf Smoke Test"
log_color "$CYAN" "----------------------------------------"
log ""

export OXIDE_RANDOMX_PERF_SMOKE=1
log_color "$GRAY" "  Running perf smoke test..."
OUTPUT=""
if run_step_capture "6 Perf smoke test" OUTPUT cargo test --features bench-instrument --test perf_smoke; then
    log_color "$GREEN" "  PASSED"
else
    log_color "$RED" "  FAILED"
fi

log ""

# ============================================================================
# Summary
# ============================================================================
if [[ "$SUITE_FAILED" == "true" ]]; then
    log_color "$RED" "========================================"
    log_color "$RED" " PERFORMANCE SUITE FAILED"
    log_color "$RED" "========================================"
else
    log_color "$GREEN" "========================================"
    log_color "$GREEN" " PERFORMANCE SUITE COMPLETE"
    log_color "$GREEN" "========================================"
fi
log ""
log "Results saved to: $OUTPUT_DIR"
log "Summary file: $SUMMARY_FILE"
log ""
log "Output files:"
for f in "$OUTPUT_DIR"/*"$TIMESTAMP"*; do
    log_color "$GRAY" "  - $(basename "$f")"
done
log ""

if [[ "$SUITE_FAILED" == "true" ]]; then
    exit 1
fi
exit 0
