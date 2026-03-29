#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOST_UNAME=$(uname -s 2>/dev/null || echo unknown)
TARGET="${TARGET:-}"
TARGET_HOST="${TARGET_HOST:-}"
FEATURES="${FEATURES:-jit jit-fastregs bench-instrument}"
DIST_DIR="${DIST_DIR:-}"
WINDOWS_GNU_LINKER="${WINDOWS_GNU_LINKER:-${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}}"
RUSTUP_BIN="${RUSTUP_BIN:-}"
CARGO_BIN="${CARGO_BIN:-}"

usage() {
    cat <<'EOT'
Usage: package_v8_01_amd_capture.sh [--target-host windows|linux] [--target <triple>]

Builds the v8 AMD capture bundle for the selected target host.

Options:
  --target-host <host>          Target host class to package for: windows or linux
  --target <triple>             Explicit Rust target triple (overrides host inference)
  --features <features>         Cargo feature string
  --dist-dir <path>             Output directory
  --windows-gnu-linker <path>   Windows GNU linker command/path
  --rustup-bin <path>           rustup executable/path
  --cargo-bin <path>            cargo executable/path
  -h, --help                    Show this help

Environment overrides:
  TARGET, TARGET_HOST, FEATURES, DIST_DIR, WINDOWS_GNU_LINKER,
  CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER, RUSTUP_BIN, CARGO_BIN
EOT
}

resolve_default_target() {
    if [[ "${HOST_UNAME}" == MINGW* || "${HOST_UNAME}" == MSYS* || "${HOST_UNAME}" == CYGWIN* ]]; then
        printf '%s\n' "x86_64-pc-windows-msvc"
    else
        printf '%s\n' "x86_64-unknown-linux-gnu"
    fi
}

resolve_windows_target() {
    if [[ "${HOST_UNAME}" == MINGW* || "${HOST_UNAME}" == MSYS* || "${HOST_UNAME}" == CYGWIN* ]]; then
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
        --windows-gnu-linker)
            if [[ $# -lt 2 ]]; then
                echo "error: --windows-gnu-linker requires a value" >&2
                exit 1
            fi
            WINDOWS_GNU_LINKER="$2"
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

BIN_NAME="v8_01_amd_capture"

case "${TARGET}" in
    *windows*)
        PLATFORM_TAG="windows"
        OUT_NAME="oxide-randomx-v8_01-amd-capture.exe"
        INSTRUCTIONS_NAME="RUN_ON_REMOTE_WINDOWS_HOST.txt"
        ARCHIVE_NAME="oxide-randomx-v8_01-amd-capture.zip"
        ;;
    *linux*)
        PLATFORM_TAG="linux"
        OUT_NAME="oxide-randomx-v8_01-amd-capture"
        INSTRUCTIONS_NAME="RUN_ON_REMOTE_UBUNTU_LINUX_HOST.txt"
        ARCHIVE_NAME="oxide-randomx-v8_01-amd-capture-linux.tar.gz"
        ;;
    *)
        echo "error: unsupported TARGET '${TARGET}' (expected a Windows or Linux target)" >&2
        exit 1
        ;;
esac

DIST_DIR="${DIST_DIR:-${ROOT_DIR}/../oxide-randomx-dist/v8_01_amd_${PLATFORM_TAG}_capture}"

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

echo "Building ${BIN_NAME} for ${TARGET} with features: ${FEATURES}"
(
    cd "${ROOT_DIR}"
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

if [[ "${PLATFORM_TAG}" == "windows" ]]; then
    cat > "${DIST_DIR}/${INSTRUCTIONS_NAME}" <<'EOT'
Run instructions for remote AMD Windows 11 owner

1) Copy `oxide-randomx-v8_01-amd-capture.exe` to the target AMD Windows machine.
2) Open PowerShell in that folder.
3) Run:

   .\oxide-randomx-v8_01-amd-capture.exe

4) Wait for completion.
5) The tool prints the artifact folder path and writes `v8_01_share_instructions_*.txt`.
6) Send the entire output folder as a zip to: raystanza@raystanza.uk

Optional run args:
- `--perf-iters 50 --perf-warmup 5`
- `--threads 12`
- `--large-pages off`
- `--validate-only`

Important:
- This single binary captures perf rows only.
- Required validation (`cargo test`, oracle runs, bench-instrument runs) must still be performed on the clean build host that produced the binary.
EOT
else
    cat > "${DIST_DIR}/${INSTRUCTIONS_NAME}" <<'EOT'
Run instructions for remote Ubuntu/Debian AMD Linux host owner

1) Copy `oxide-randomx-v8_01-amd-capture` to the target AMD Linux machine.
2) Open a shell in that folder.
3) Run:

   ./oxide-randomx-v8_01-amd-capture

4) Wait for completion.
5) The tool prints the artifact folder path and writes `v8_01_share_instructions_*.txt`.
6) Send the entire output folder as a tarball/zip to: raystanza@raystanza.uk

Optional run args:
- `--perf-iters 50 --perf-warmup 5`
- `--threads 12`
- `--large-pages off`
- `--validate-only`

Important:
- This single binary captures perf rows only.
- Required validation (`cargo test`, oracle runs, bench-instrument runs) must still be performed on the clean build host that produced the binary.
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
