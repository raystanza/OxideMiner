#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOST_UNAME=$(uname -s 2>/dev/null || echo unknown)
TARGET="${TARGET:-}"
TARGET_HOST="${TARGET_HOST:-}"
FEATURES="${FEATURES:-jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto}"
DIST_DIR="${DIST_DIR:-}"
RUN_COUNT="${RUN_COUNT:-1}"
REMOTE_BUNDLE_ROOT="${REMOTE_BUNDLE_ROOT:-}"
REMOTE_RUN_PREFIX="${REMOTE_RUN_PREFIX:-ff_capture}"
REMOTE_HOST_CONTEXT_FILE="${REMOTE_HOST_CONTEXT_FILE:-HOST_CONTEXT_NOTES.txt}"
WINDOWS_GNU_LINKER="${WINDOWS_GNU_LINKER:-${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}}"
LINUX_GNU_LINKER="${LINUX_GNU_LINKER:-${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-}}"
RUSTUP_BIN="${RUSTUP_BIN:-}"
CARGO_BIN="${CARGO_BIN:-}"

usage() {
    cat <<'EOT'
Usage: build_full_features_benchmark.sh [--target-host windows|linux] [--target <triple>]

Builds and packages the full_features_benchmark single-binary bundle for the selected target host.

Options:
  --target-host <host>          Target host class to package for: windows or linux
  --target <triple>             Explicit Rust target triple (overrides host inference)
  --features <features>         Cargo feature string
  --dist-dir <path>             Output directory
  --run-count <n>               Number of same-settings captures to describe in the remote instructions
  --remote-bundle-root <path>   Outside-repo bundle root to show in the remote instructions
  --remote-run-prefix <name>    Prefix used for emitted ff_* run directories in the remote instructions
  --remote-host-context-file    Host-context note filename to request in the remote instructions
  --windows-gnu-linker <path>   Windows GNU linker command/path
  --linux-gnu-linker <path>     Linux GNU linker command/path for Windows -> Linux cross-builds
  --rustup-bin <path>           rustup executable/path
  --cargo-bin <path>            cargo executable/path
  -h, --help                    Show this help

Environment overrides:
  TARGET, TARGET_HOST, FEATURES, DIST_DIR, RUN_COUNT, REMOTE_BUNDLE_ROOT,
  REMOTE_RUN_PREFIX, REMOTE_HOST_CONTEXT_FILE, WINDOWS_GNU_LINKER, LINUX_GNU_LINKER,
  CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER, CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER,
  RUSTUP_BIN, CARGO_BIN
EOT
}

host_is_windows() {
    [[ "${HOST_UNAME}" == MINGW* || "${HOST_UNAME}" == MSYS* || "${HOST_UNAME}" == CYGWIN* ]]
}

resolve_default_target() {
    if host_is_windows; then
        printf '%s\n' "x86_64-pc-windows-msvc"
    else
        printf '%s\n' "x86_64-unknown-linux-gnu"
    fi
}

resolve_windows_target() {
    if host_is_windows; then
        printf '%s\n' "x86_64-pc-windows-msvc"
    elif [[ "${CARGO_BIN}" == *.exe || "${RUSTUP_BIN}" == *.exe ]]; then
        printf '%s\n' "x86_64-pc-windows-msvc"
    elif command -v cargo.exe >/dev/null 2>&1 || command -v rustup.exe >/dev/null 2>&1; then
        printf '%s\n' "x86_64-pc-windows-msvc"
    else
        printf '%s\n' "x86_64-pc-windows-gnu"
    fi
}

resolve_target_for_host() {
    local target_host="${1,,}"

    case "${target_host}" in
        windows)
            resolve_windows_target
            ;;
        linux)
            printf '%s\n' "x86_64-unknown-linux-gnu"
            ;;
        *)
            return 1
            ;;
    esac
}

default_remote_bundle_root() {
    local platform="$1"

    case "${platform}" in
        windows)
            printf '%s\n' "C:\\oxide-randomx-captures\\full_features_benchmark_windows"
            ;;
        linux)
            printf '%s\n' "/tmp/oxide-randomx-captures/full_features_benchmark_linux"
            ;;
        *)
            return 1
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-host)
            if [[ $# -lt 2 ]]; then
                echo "error: --target-host requires a value" >&2
                exit 1
            fi
            TARGET_HOST="$2"
            shift 2
            ;;
        --target)
            if [[ $# -lt 2 ]]; then
                echo "error: --target requires a value" >&2
                exit 1
            fi
            TARGET="$2"
            shift 2
            ;;
        --features)
            if [[ $# -lt 2 ]]; then
                echo "error: --features requires a value" >&2
                exit 1
            fi
            FEATURES="$2"
            shift 2
            ;;
        --dist-dir)
            if [[ $# -lt 2 ]]; then
                echo "error: --dist-dir requires a value" >&2
                exit 1
            fi
            DIST_DIR="$2"
            shift 2
            ;;
        --run-count)
            if [[ $# -lt 2 ]]; then
                echo "error: --run-count requires a value" >&2
                exit 1
            fi
            RUN_COUNT="$2"
            shift 2
            ;;
        --remote-bundle-root)
            if [[ $# -lt 2 ]]; then
                echo "error: --remote-bundle-root requires a value" >&2
                exit 1
            fi
            REMOTE_BUNDLE_ROOT="$2"
            shift 2
            ;;
        --remote-run-prefix)
            if [[ $# -lt 2 ]]; then
                echo "error: --remote-run-prefix requires a value" >&2
                exit 1
            fi
            REMOTE_RUN_PREFIX="$2"
            shift 2
            ;;
        --remote-host-context-file)
            if [[ $# -lt 2 ]]; then
                echo "error: --remote-host-context-file requires a value" >&2
                exit 1
            fi
            REMOTE_HOST_CONTEXT_FILE="$2"
            shift 2
            ;;
        --windows-gnu-linker)
            if [[ $# -lt 2 ]]; then
                echo "error: --windows-gnu-linker requires a value" >&2
                exit 1
            fi
            WINDOWS_GNU_LINKER="$2"
            shift 2
            ;;
        --linux-gnu-linker)
            if [[ $# -lt 2 ]]; then
                echo "error: --linux-gnu-linker requires a value" >&2
                exit 1
            fi
            LINUX_GNU_LINKER="$2"
            shift 2
            ;;
        --rustup-bin)
            if [[ $# -lt 2 ]]; then
                echo "error: --rustup-bin requires a value" >&2
                exit 1
            fi
            RUSTUP_BIN="$2"
            shift 2
            ;;
        --cargo-bin)
            if [[ $# -lt 2 ]]; then
                echo "error: --cargo-bin requires a value" >&2
                exit 1
            fi
            CARGO_BIN="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -n "${TARGET}" && -n "${TARGET_HOST}" ]]; then
    echo "error: specify either TARGET/--target or TARGET_HOST/--target-host, not both" >&2
    exit 1
fi

if [[ -n "${TARGET_HOST}" ]]; then
    if ! TARGET=$(resolve_target_for_host "${TARGET_HOST}"); then
        echo "error: unsupported target host '${TARGET_HOST}' (expected windows or linux)" >&2
        exit 1
    fi
elif [[ -z "${TARGET}" ]]; then
    TARGET=$(resolve_default_target)
fi

BIN_NAME="full_features_benchmark"

case "${TARGET}" in
    *windows*)
        PLATFORM_TAG="windows"
        OUT_NAME="oxide-randomx-full-features-benchmark.exe"
        INSTRUCTIONS_NAME="RUN_ON_REMOTE_WINDOWS_HOST.txt"
        ARCHIVE_NAME="oxide-randomx-full-features-benchmark.zip"
        ;;
    *linux*)
        PLATFORM_TAG="linux"
        OUT_NAME="oxide-randomx-full-features-benchmark"
        INSTRUCTIONS_NAME="RUN_ON_REMOTE_UBUNTU_LINUX_HOST.txt"
        ARCHIVE_NAME="oxide-randomx-full-features-benchmark-linux.tar.gz"
        ;;
    *)
        echo "error: unsupported TARGET '${TARGET}' (expected a Windows or Linux target)" >&2
        exit 1
        ;;
esac

DIST_DIR="${DIST_DIR:-${ROOT_DIR}/../oxide-randomx-dist/full_features_benchmark_${PLATFORM_TAG}}"
if ! [[ "${RUN_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: RUN_COUNT/--run-count must be a positive integer" >&2
    exit 1
fi
if [[ -z "${REMOTE_RUN_PREFIX}" ]]; then
    echo "error: REMOTE_RUN_PREFIX/--remote-run-prefix must not be empty" >&2
    exit 1
fi
if [[ -z "${REMOTE_HOST_CONTEXT_FILE}" ]]; then
    echo "error: REMOTE_HOST_CONTEXT_FILE/--remote-host-context-file must not be empty" >&2
    exit 1
fi
REMOTE_BUNDLE_ROOT="${REMOTE_BUNDLE_ROOT:-$(default_remote_bundle_root "${PLATFORM_TAG}")}"

resolve_tool() {
    local current="$1"
    local bare="$2"
    local exe="$3"

    if [[ -n "${current}" ]]; then
        printf '%s\n' "${current}"
        return 0
    fi
    if command -v "${bare}" >/dev/null 2>&1; then
        command -v "${bare}"
        return 0
    fi
    if command -v "${exe}" >/dev/null 2>&1; then
        command -v "${exe}"
        return 0
    fi
    return 1
}

if ! RUSTUP_BIN=$(resolve_tool "${RUSTUP_BIN}" rustup rustup.exe); then
    echo "error: rustup is required" >&2
    exit 1
fi

if ! CARGO_BIN=$(resolve_tool "${CARGO_BIN}" cargo cargo.exe); then
    echo "error: cargo is required" >&2
    exit 1
fi

if ! "${RUSTUP_BIN}" target list --installed | grep -qx "${TARGET}"; then
    echo "error: target '${TARGET}' is not installed" >&2
    echo "install it with: ${RUSTUP_BIN} target add ${TARGET}" >&2
    exit 1
fi

if [[ "${TARGET}" == *"-windows-gnu" ]]; then
    if ! command -v "${WINDOWS_GNU_LINKER}" >/dev/null 2>&1; then
        echo "error: required Windows GNU linker '${WINDOWS_GNU_LINKER}' was not found" >&2
        echo "target '${TARGET}' requires a MinGW cross-linker." >&2
        echo "Debian/Ubuntu install hint: sudo apt-get install -y mingw-w64" >&2
        echo "or set CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER to a valid linker path." >&2
        exit 1
    fi
fi

if host_is_windows && [[ "${TARGET}" == "x86_64-unknown-linux-gnu" ]]; then
    if [[ -z "${LINUX_GNU_LINKER}" ]]; then
        echo "error: Windows -> Linux cross-build requires --linux-gnu-linker or CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER" >&2
        echo "example with Zig: --linux-gnu-linker zig" >&2
        exit 1
    fi
    if ! command -v "${LINUX_GNU_LINKER}" >/dev/null 2>&1; then
        echo "error: required Linux GNU linker '${LINUX_GNU_LINKER}' was not found" >&2
        echo "set CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER to a valid linker path/command." >&2
        exit 1
    fi
fi

echo "Building ${BIN_NAME} for ${TARGET} with features: ${FEATURES}"
(
    cd "${ROOT_DIR}"
    if [[ "${TARGET}" == *"-windows-gnu" ]]; then
        export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${WINDOWS_GNU_LINKER}"
    fi
    if host_is_windows && [[ "${TARGET}" == "x86_64-unknown-linux-gnu" ]]; then
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${LINUX_GNU_LINKER}"
    fi
    "${CARGO_BIN}" build --release --target "${TARGET}" --bin "${BIN_NAME}" --features "${FEATURES}"
)

SRC_BIN="${ROOT_DIR}/target/${TARGET}/release/${BIN_NAME}"
if [[ "${PLATFORM_TAG}" == "windows" ]]; then
    SRC_BIN="${SRC_BIN}.exe"
fi

if [[ ! -f "${SRC_BIN}" ]]; then
    echo "error: expected output missing: ${SRC_BIN}" >&2
    exit 1
fi

mkdir -p "${DIST_DIR}"
cp "${SRC_BIN}" "${DIST_DIR}/${OUT_NAME}"
if [[ "${PLATFORM_TAG}" == "linux" ]]; then
    chmod +x "${DIST_DIR}/${OUT_NAME}"
fi

run_names=()
if [[ "${RUN_COUNT}" -eq 1 ]]; then
    run_names+=("${REMOTE_RUN_PREFIX}")
else
    for ((i = 1; i <= RUN_COUNT; i++)); do
        printf -v run_name '%s_r%02d' "${REMOTE_RUN_PREFIX}" "${i}"
        run_names+=("${run_name}")
    done
fi

if [[ "${PLATFORM_TAG}" == "windows" ]]; then
    if [[ "${RUN_COUNT}" -eq 1 ]]; then
        printf -v WINDOWS_RUN_BLOCK '   .\oxide-randomx-full-features-benchmark.exe `
     --out-dir (Join-Path $bundleRoot "%s")' "${run_names[0]}"
    else
        WINDOWS_RUN_LIST=""
        for run_name in "${run_names[@]}"; do
            printf -v WINDOWS_RUN_LIST '%s     "%s"\n' "${WINDOWS_RUN_LIST}" "${run_name}"
        done
        printf -v WINDOWS_RUN_BLOCK '   $runDirs = @(
%s   )

   foreach ($runDir in $runDirs) {
     .\oxide-randomx-full-features-benchmark.exe `
       --out-dir (Join-Path $bundleRoot $runDir)
   }' "${WINDOWS_RUN_LIST}"
    fi
    cat > "${DIST_DIR}/${INSTRUCTIONS_NAME}" <<EOT
Run instructions for remote Windows host

1) Copy `oxide-randomx-full-features-benchmark.exe` to the target Windows machine.
2) Open PowerShell in that folder.
3) Pick a bundle root outside any git checkout so the raw `ff_*` directories stay intact:

   \$bundleRoot = "${REMOTE_BUNDLE_ROOT}"

4) Optional binary validation:

   .\oxide-randomx-full-features-benchmark.exe --validate-only

5) Run the capture with unchanged canonical settings:

${WINDOWS_RUN_BLOCK}

6) Record host context before returning the raw bundle:

   @'
   privilege_state=
   large_page_privilege=
   memory_pressure_notes=
   reboot_or_fresh_session=
   run_order_notes=
   '@ | Set-Content -Encoding ascii -Path (Join-Path \$bundleRoot "${REMOTE_HOST_CONTEXT_FILE}")

7) Return the entire `\$bundleRoot` directory, including every emitted `ff_*` directory and `${REMOTE_HOST_CONTEXT_FILE}`.
8) Back in the repo, preserve the raw returned bundle first, then place the intact `ff_*` directories under your local `perf_results/` tree and classify them with `docs/full-features-benchmark-workflow.md`.

Keep these settings unchanged unless you are deliberately doing exploratory work:
- `--perf-iters 50`
- `--perf-warmup 5`
- `--threads <detected logical-thread-count>`
- the packaged binary's default feature plan and page-profile set

Optional run args:
- `--out-dir C:\path\to\capture`
- `--validate-only`

This package was configured with:
- `run_count=${RUN_COUNT}`
- `bundle_root=${REMOTE_BUNDLE_ROOT}`
- `run_prefix=${REMOTE_RUN_PREFIX}`
- `host_context_file=${REMOTE_HOST_CONTEXT_FILE}`

This binary is built with:
- `jit`
- `jit-fastregs`
- `bench-instrument`
- `threaded-interp`
- `simd-blockio`
- `simd-xor-paths`
- `superscalar-accel-proto`
EOT
else
    if [[ "${RUN_COUNT}" -eq 1 ]]; then
        printf -v LINUX_RUN_BLOCK '   ./oxide-randomx-full-features-benchmark \
     --out-dir "${bundle_root}/%s"' "${run_names[0]}"
    else
        LINUX_RUN_LIST=""
        for run_name in "${run_names[@]}"; do
            printf -v LINUX_RUN_LIST '%s     "%s"\n' "${LINUX_RUN_LIST}" "${run_name}"
        done
        printf -v LINUX_RUN_BLOCK '   run_dirs=(
%s   )

   for run_dir in "${run_dirs[@]}"; do
     ./oxide-randomx-full-features-benchmark \
       --out-dir "${bundle_root}/${run_dir}"
   done' "${LINUX_RUN_LIST}"
    fi
    cat > "${DIST_DIR}/${INSTRUCTIONS_NAME}" <<EOT
Run instructions for remote Ubuntu/Debian Linux host

1) Copy `oxide-randomx-full-features-benchmark` to the target Linux machine.
2) Open a shell in that folder.
3) Pick a bundle root outside any git checkout so the raw `ff_*` directories stay intact:

   bundle_root="${REMOTE_BUNDLE_ROOT}"

4) Optional binary validation:

   ./oxide-randomx-full-features-benchmark --validate-only

5) Run the capture with unchanged canonical settings:

${LINUX_RUN_BLOCK}

6) Record host context before returning the raw bundle:

   cat > "\${bundle_root}/${REMOTE_HOST_CONTEXT_FILE}" <<'EOF'
   privilege_state=
   large_page_privilege=
   memory_pressure_notes=
   reboot_or_fresh_session=
   run_order_notes=
   EOF

7) Return the entire `\${bundle_root}` directory, including every emitted `ff_*` directory and `${REMOTE_HOST_CONTEXT_FILE}`.
8) Back in the repo, preserve the raw returned bundle first, then place the intact `ff_*` directories under your local `perf_results/` tree and classify them with `docs/full-features-benchmark-workflow.md`.

Keep these settings unchanged unless you are deliberately doing exploratory work:
- `--perf-iters 50`
- `--perf-warmup 5`
- `--threads <detected logical-thread-count>`
- the packaged binary's default feature plan and page-profile set

Optional run args:
- `--out-dir /path/to/capture`
- `--validate-only`

This package was configured with:
- `run_count=${RUN_COUNT}`
- `bundle_root=${REMOTE_BUNDLE_ROOT}`
- `run_prefix=${REMOTE_RUN_PREFIX}`
- `host_context_file=${REMOTE_HOST_CONTEXT_FILE}`

This binary is built with:
- `jit`
- `jit-fastregs`
- `bench-instrument`
- `threaded-interp`
- `simd-blockio`
- `simd-xor-paths`
- `superscalar-accel-proto`
EOT
fi

if [[ "${PLATFORM_TAG}" == "windows" ]]; then
    if command -v zip >/dev/null 2>&1; then
        (
            cd "${DIST_DIR}"
            rm -f "${ARCHIVE_NAME}"
            zip -q "${ARCHIVE_NAME}" "${OUT_NAME}" "${INSTRUCTIONS_NAME}"
        )
        echo "Wrote: ${DIST_DIR}/${ARCHIVE_NAME}"
    fi
else
    if command -v tar >/dev/null 2>&1; then
        (
            cd "${DIST_DIR}"
            rm -f "${ARCHIVE_NAME}"
            tar -czf "${ARCHIVE_NAME}" "${OUT_NAME}" "${INSTRUCTIONS_NAME}"
        )
        echo "Wrote: ${DIST_DIR}/${ARCHIVE_NAME}"
    fi
fi

echo "Wrote: ${DIST_DIR}/${OUT_NAME}"
echo "Wrote: ${DIST_DIR}/${INSTRUCTIONS_NAME}"
