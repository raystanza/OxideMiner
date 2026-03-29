#!/bin/bash
set -e

# Comprehensive feature benchmark runner for oxide-randomx (Bash/Linux/macOS)
#
# What it does:
# - Builds and benchmarks multiple feature combinations to measure their impact:
#   1. Baseline (interpreter only, no optional features)
#   2. JIT enabled (conservative mode)
#   3. JIT + fast-regs enabled
#   4. SIMD block I/O enabled
#   5. Threaded interpreter enabled
#   6. Fast-decode enabled (default feature)
#   7. Full feature set (all features combined)
# - Parses ns/hash from output and prints median/mean + speedup stats.
#
# Usage examples:
#   ./bench_apples.sh --mode fast --iters 200 --warmup 10 --repeats 5
#   ./bench_apples.sh --mode fast --iters 100 --repeats 3 --large-pages
#   ./bench_apples.sh --quick  # Quick sanity check

# --- Default Configuration ---
REPO_ROOT="$(pwd)"
MODE="fast"
ITERS=200
WARMUP=10
REPEATS=5
THREADS=0
PAUSE_SEC=0.5
SAVE_CSV=false
LARGE_PAGES=false
QUICK_TEST=false
CSV_FILE="bench_features_results.csv"

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# --- Helper Functions ---

print_usage() {
    echo "Comprehensive feature benchmark runner for oxide-randomx (Bash)"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --root <path>     Path to repo root (default: current dir)"
    echo "  --mode <type>     'light' or 'fast' (default: fast)"
    echo "  --iters <n>       Number of iterations (default: 200)"
    echo "  --warmup <n>      Warmup iterations (default: 10)"
    echo "  --repeats <n>     Number of repeat cycles (default: 5)"
    echo "  --threads <n>     Number of threads (default: 0 / auto)"
    echo "  --large-pages     Enable large pages"
    echo "  --csv             Save results to $CSV_FILE"
    echo "  --quick           Quick test mode (minimal iterations)"
    echo "  --help            Show this help"
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --root)
            REPO_ROOT="$2"
            shift; shift
            ;;
        --mode)
            MODE="$2"
            shift; shift
            ;;
        --iters)
            ITERS="$2"
            shift; shift
            ;;
        --warmup)
            WARMUP="$2"
            shift; shift
            ;;
        --repeats)
            REPEATS="$2"
            shift; shift
            ;;
        --threads)
            THREADS="$2"
            shift; shift
            ;;
        --large-pages)
            LARGE_PAGES=true
            shift
            ;;
        --csv)
            SAVE_CSV=true
            shift
            ;;
        --quick)
            QUICK_TEST=true
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Quick test mode overrides
if [ "$QUICK_TEST" = true ]; then
    ITERS=20
    WARMUP=2
    REPEATS=2
fi

# Validate Mode
if [[ "$MODE" != "light" && "$MODE" != "fast" ]]; then
    echo "Error: Mode must be 'light' or 'fast'."
    exit 1
fi

# Ensure required tools are present
command -v cargo >/dev/null 2>&1 || { echo >&2 "Error: cargo is required but not installed."; exit 1; }
command -v awk >/dev/null 2>&1 || { echo >&2 "Error: awk is required."; exit 1; }

# --- Feature Configurations ---
# Format: "Name|Features|JitMode|FastRegs"
FEATURE_CONFIGS=(
    "Baseline (Interpreter)|bench-instrument|off|off"
    "JIT Conservative|jit bench-instrument|on|off"
    "JIT + Fast-Regs|jit bench-instrument jit-fastregs|on|on"
    "SIMD Block I/O|bench-instrument simd-blockio|off|off"
    "Threaded Interpreter|bench-instrument threaded-interp|off|off"
    "Fast Decode|bench-instrument fast-decode|off|off"
    "SIMD + JIT Conservative|jit bench-instrument simd-blockio|on|off"
    "SIMD + JIT + Fast-Regs|jit bench-instrument jit-fastregs simd-blockio|on|on"
    "Full Features|jit bench-instrument jit-fastregs simd-blockio fast-decode threaded-interp|on|on"
)

# --- Statistics Functions ---

get_median() {
    local file=$1
    sort -n "$file" | awk '
    {
        a[NR] = $1
    }
    END {
        n = NR
        if (n == 0) { print "NaN"; exit }
        if (n % 2 == 1) {
            print a[int((n+1)/2)]
        } else {
            print (a[n/2] + a[n/2+1]) / 2.0
        }
    }'
}

get_mean() {
    local file=$1
    awk '{ sum += $1; n++ } END { if (n > 0) print sum / n; else print "NaN" }' "$file"
}

get_stddev() {
    local file=$1
    awk '
    {
        sum += $1
        sumsq += $1 * $1
        n++
    }
    END {
        if (n < 2) { print "NaN"; exit }
        mean = sum / n
        variance = (sumsq - n * mean * mean) / (n - 1)
        if (variance < 0) variance = 0
        print sqrt(variance)
    }' "$file"
}

# --- Build Function ---

build_bench() {
    local features="$1"
    echo -e "  ${CYAN}Building bench (release) with features: $features${NC}"
    if ! cargo build --release --example bench --features "$features" 2>&1; then
        echo -e "  ${RED}Build failed${NC}"
        return 1
    fi
    return 0
}

# --- Benchmark Function ---

run_bench_once() {
    local jit_mode=$1
    local fast_regs=$2
    local temp_file=$3

    local thread_arg=""
    if [ "$THREADS" -gt 0 ]; then
        thread_arg="--threads $THREADS"
    fi

    local output
    output=$($BENCH_EXE --mode "$MODE" --jit "$jit_mode" --jit-fast-regs "$fast_regs" \
        --iters "$ITERS" --warmup "$WARMUP" --report --format human $thread_arg 2>&1)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo -e "  ${RED}Bench failed (exit $exit_code)${NC}"
        echo "$output"
        return 1
    fi

    # Parse ns/hash based on jit mode
    local ns_hash
    if [ "$jit_mode" = "off" ]; then
        ns_hash=$(echo "$output" | grep "jit=false" | grep -o 'ns/hash=[0-9]*' | cut -d= -f2)
    else
        ns_hash=$(echo "$output" | grep "jit=true" | grep -o 'ns/hash=[0-9]*' | cut -d= -f2)
    fi

    if [[ -z "$ns_hash" ]]; then
        # Fallback: try any ns/hash line
        ns_hash=$(echo "$output" | grep -o 'ns/hash=[0-9]*' | head -1 | cut -d= -f2)
    fi

    if [[ -z "$ns_hash" ]]; then
        echo -e "  ${RED}Failed to parse ns/hash${NC}"
        return 1
    fi

    echo "$ns_hash" >> "$temp_file"
    echo "$ns_hash"
}

# --- Main Execution ---

cd "$REPO_ROOT"

if [[ "$MODE" == "fast" ]]; then
    export OXIDE_RANDOMX_FAST_BENCH=1
fi

if [ "$LARGE_PAGES" = true ]; then
    export OXIDE_RANDOMX_LARGE_PAGES=1
    echo -e "${YELLOW}Large pages enabled${NC}"
fi

BENCH_EXE="./target/release/examples/bench"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Oxide-RandomX Feature Benchmark Suite${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Configuration:"
echo "  Mode        : $MODE"
echo "  Iters       : $ITERS"
echo "  Warmup      : $WARMUP"
echo "  Repeats     : $REPEATS"
echo "  Large Pages : $LARGE_PAGES"
if [ "$THREADS" -gt 0 ]; then
    echo "  Threads     : $THREADS"
else
    echo "  Threads     : (auto)"
fi
echo ""

# Create temp directory for results
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Initialize CSV if requested
if [ "$SAVE_CSV" = true ]; then
    echo "configuration,mode,iters,warmup,threads,jit_mode,fast_regs,ns_per_hash" > "$CSV_FILE"
fi

# Store summary data
declare -A CONFIG_MEDIANS
declare -A CONFIG_MEANS

# --- Run benchmarks for each configuration ---

for config in "${FEATURE_CONFIGS[@]}"; do
    IFS='|' read -r config_name features jit_mode fast_regs <<< "$config"

    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Configuration: $config_name${NC}"
    echo "  Features: $features"
    echo "  JIT: $jit_mode, Fast-Regs: $fast_regs"
    echo ""

    # Build for this configuration
    if ! build_bench "$features"; then
        echo -e "  ${YELLOW}Skipping: Build failed${NC}"
        continue
    fi

    if [[ ! -f "$BENCH_EXE" ]]; then
        echo -e "  ${RED}Error: Bench executable not found at $BENCH_EXE${NC}"
        continue
    fi

    # Create temp file for this config's results
    config_file="$TEMP_DIR/$(echo "$config_name" | tr ' ()' '___').txt"
    > "$config_file"

    for ((i=1; i<=REPEATS; i++)); do
        echo -n "  Run $i/$REPEATS: "

        ns_hash=$(run_bench_once "$jit_mode" "$fast_regs" "$config_file")
        if [ $? -eq 0 ]; then
            printf "%'d ns/hash\n" "$ns_hash"
        fi

        sleep "$PAUSE_SEC"
    done

    # Calculate stats for this config
    if [ -s "$config_file" ]; then
        median=$(get_median "$config_file")
        mean=$(get_mean "$config_file")
        stddev=$(get_stddev "$config_file")
        hps=$(awk "BEGIN { if ($median > 0) printf \"%.2f\", 1000000000 / $median; else print 0 }")

        CONFIG_MEDIANS["$config_name"]=$median
        CONFIG_MEANS["$config_name"]=$mean

        echo -e "  ${GREEN}Summary: Median=${median} ns/hash, Mean=${mean}, StdDev=${stddev}, HPS=${hps}${NC}"

        # Save to CSV
        if [ "$SAVE_CSV" = true ]; then
            while read -r ns; do
                echo "$config_name,$MODE,$ITERS,$WARMUP,$THREADS,$jit_mode,$fast_regs,$ns" >> "$CSV_FILE"
            done < "$config_file"
        fi
    fi

    echo ""
done

# --- Final Summary ---

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} FINAL SUMMARY${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Get baseline for comparison
BASELINE_MEDIAN="${CONFIG_MEDIANS["Baseline (Interpreter)"]:-}"

# Print table header
printf "%-35s %15s %15s %12s %12s\n" "Configuration" "Median ns/hash" "Mean ns/hash" "HPS" "vs Baseline"
echo "-----------------------------------------------------------------------------------------------"

for config in "${FEATURE_CONFIGS[@]}"; do
    IFS='|' read -r config_name features jit_mode fast_regs <<< "$config"

    median="${CONFIG_MEDIANS[$config_name]:-}"
    mean="${CONFIG_MEANS[$config_name]:-}"

    if [[ -z "$median" || "$median" == "NaN" ]]; then
        continue
    fi

    hps=$(awk "BEGIN { if ($median > 0) printf \"%.2f\", 1000000000 / $median; else print 0 }")

    speedup=""
    if [[ -n "$BASELINE_MEDIAN" && "$BASELINE_MEDIAN" != "NaN" && "$median" != "0" ]]; then
        speedup=$(awk "BEGIN { printf \"%.2fx\", $BASELINE_MEDIAN / $median }")
    fi

    printf "%-35s %15.0f %15.0f %12s %12s\n" "$config_name" "$median" "$mean" "$hps" "$speedup"
done

echo ""

# --- Feature Impact Analysis ---

echo -e "${CYAN}Feature Impact Analysis:${NC}"

# JIT impact
baseline="${CONFIG_MEDIANS["Baseline (Interpreter)"]:-}"
jit_cons="${CONFIG_MEDIANS["JIT Conservative"]:-}"
if [[ -n "$baseline" && -n "$jit_cons" && "$baseline" != "NaN" && "$jit_cons" != "NaN" ]]; then
    improvement=$(awk "BEGIN { printf \"%.1f\", (($baseline - $jit_cons) / $baseline) * 100 }")
    speedup=$(awk "BEGIN { printf \"%.2f\", $baseline / $jit_cons }")
    echo "  JIT vs Interpreter: ${improvement}% improvement (${speedup}x faster)"
fi

# Fast-regs impact
jit_fast="${CONFIG_MEDIANS["JIT + Fast-Regs"]:-}"
if [[ -n "$jit_cons" && -n "$jit_fast" && "$jit_cons" != "NaN" && "$jit_fast" != "NaN" ]]; then
    improvement=$(awk "BEGIN { printf \"%.1f\", (($jit_cons - $jit_fast) / $jit_cons) * 100 }")
    speedup=$(awk "BEGIN { printf \"%.2f\", $jit_cons / $jit_fast }")
    echo "  Fast-Regs vs Conservative JIT: ${improvement}% improvement (${speedup}x faster)"
fi

# SIMD impact
simd="${CONFIG_MEDIANS["SIMD Block I/O"]:-}"
if [[ -n "$baseline" && -n "$simd" && "$baseline" != "NaN" && "$simd" != "NaN" ]]; then
    improvement=$(awk "BEGIN { printf \"%.1f\", (($baseline - $simd) / $baseline) * 100 }")
    speedup=$(awk "BEGIN { printf \"%.2f\", $baseline / $simd }")
    echo "  SIMD Block I/O vs Baseline: ${improvement}% improvement (${speedup}x faster)"
fi

# Threaded interpreter impact
threaded="${CONFIG_MEDIANS["Threaded Interpreter"]:-}"
if [[ -n "$baseline" && -n "$threaded" && "$baseline" != "NaN" && "$threaded" != "NaN" ]]; then
    improvement=$(awk "BEGIN { printf \"%.1f\", (($baseline - $threaded) / $baseline) * 100 }")
    speedup=$(awk "BEGIN { printf \"%.2f\", $baseline / $threaded }")
    echo "  Threaded Interpreter vs Baseline: ${improvement}% improvement (${speedup}x faster)"
fi

# Full features impact
full="${CONFIG_MEDIANS["Full Features"]:-}"
if [[ -n "$baseline" && -n "$full" && "$baseline" != "NaN" && "$full" != "NaN" ]]; then
    improvement=$(awk "BEGIN { printf \"%.1f\", (($baseline - $full) / $baseline) * 100 }")
    speedup=$(awk "BEGIN { printf \"%.2f\", $baseline / $full }")
    echo "  Full Features vs Baseline: ${improvement}% improvement (${speedup}x faster)"
fi

echo ""

if [ "$SAVE_CSV" = true ]; then
    echo -e "${GREEN}Results saved to: $CSV_FILE${NC}"
fi
