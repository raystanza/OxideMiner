#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOST_UNAME=$(uname -s 2>/dev/null || echo unknown)
TARGET="${TARGET:-}"
TARGET_HOST="${TARGET_HOST:-}"
BETA_RELEASE_ID="${BETA_RELEASE_ID:-local-dev}"
FEATURES="${FEATURES:-jit jit-fastregs bench-instrument threaded-interp simd-blockio simd-xor-paths superscalar-accel-proto}"
DIST_DIR="${DIST_DIR:-}"
WINDOWS_GNU_LINKER="${WINDOWS_GNU_LINKER:-${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}}"
LINUX_GNU_LINKER="${LINUX_GNU_LINKER:-${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-}}"
RUSTUP_BIN="${RUSTUP_BIN:-}"
CARGO_BIN="${CARGO_BIN:-}"

usage() {
    cat <<'EOT'
Usage: package_oxide_randomx_beta_capture.sh [--target-host windows|linux] [--target <triple>] [--beta-release-id <id>]

Builds and packages the public beta capture bundle for the selected target host.

Options:
  --target-host <host>          Target host class to package for: windows or linux
  --target <triple>             Explicit Rust target triple (overrides host inference)
  --beta-release-id <id>        Public beta release ID embedded into the binary
  --features <features>         Cargo feature string
  --dist-dir <path>             Output directory
  --windows-gnu-linker <path>   Windows GNU linker command/path
  --linux-gnu-linker <path>     Linux GNU linker command/path for Windows -> Linux cross-builds
  --rustup-bin <path>           rustup executable/path
  --cargo-bin <path>            cargo executable/path
  -h, --help                    Show this help
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
    case "${1,,}" in
        windows) resolve_windows_target ;;
        linux) printf '%s\n' "x86_64-unknown-linux-gnu" ;;
        *) return 1 ;;
    esac
}

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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-host) TARGET_HOST="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --beta-release-id) BETA_RELEASE_ID="$2"; shift 2 ;;
        --features) FEATURES="$2"; shift 2 ;;
        --dist-dir) DIST_DIR="$2"; shift 2 ;;
        --windows-gnu-linker) WINDOWS_GNU_LINKER="$2"; shift 2 ;;
        --linux-gnu-linker) LINUX_GNU_LINKER="$2"; shift 2 ;;
        --rustup-bin) RUSTUP_BIN="$2"; shift 2 ;;
        --cargo-bin) CARGO_BIN="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument '$1'" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -n "${TARGET}" && -n "${TARGET_HOST}" ]]; then
    echo "error: specify either --target or --target-host, not both" >&2
    exit 1
fi

if [[ -n "${TARGET_HOST}" ]]; then
    TARGET=$(resolve_target_for_host "${TARGET_HOST}") || {
        echo "error: unsupported target host '${TARGET_HOST}'" >&2
        exit 1
    }
elif [[ -z "${TARGET}" ]]; then
    TARGET=$(resolve_default_target)
fi

BIN_NAME="oxide-randomx-beta-capture"
case "${TARGET}" in
    *windows*)
        PLATFORM_TAG="windows-x86_64"
        OUT_NAME="oxide-randomx-beta-capture.exe"
        INSTRUCTIONS_NAME="RUN_PUBLIC_BETA_ON_WINDOWS_HOST.txt"
        ARCHIVE_NAME="oxide-randomx-beta-capture-windows-x86_64.zip"
        ;;
    *linux*)
        PLATFORM_TAG="linux-x86_64"
        OUT_NAME="oxide-randomx-beta-capture"
        INSTRUCTIONS_NAME="RUN_PUBLIC_BETA_ON_LINUX_HOST.txt"
        ARCHIVE_NAME="oxide-randomx-beta-capture-linux-x86_64.tar.gz"
        ;;
    *)
        echo "error: unsupported target '${TARGET}'" >&2
        exit 1
        ;;
esac

DIST_DIR="${DIST_DIR:-${ROOT_DIR}/../oxide-randomx-dist/public_beta_capture_${PLATFORM_TAG}}"

RUSTUP_BIN=$(resolve_tool "${RUSTUP_BIN}" rustup rustup.exe) || {
    echo "error: rustup is required" >&2
    exit 1
}
CARGO_BIN=$(resolve_tool "${CARGO_BIN}" cargo cargo.exe) || {
    echo "error: cargo is required" >&2
    exit 1
}

if ! "${RUSTUP_BIN}" target list --installed | grep -qx "${TARGET}"; then
    echo "error: target '${TARGET}' is not installed" >&2
    exit 1
fi

if [[ "${TARGET}" == *"-windows-gnu" ]] && ! command -v "${WINDOWS_GNU_LINKER}" >/dev/null 2>&1; then
    echo "error: Windows GNU linker '${WINDOWS_GNU_LINKER}' was not found" >&2
    exit 1
fi

if host_is_windows && [[ "${TARGET}" == "x86_64-unknown-linux-gnu" ]]; then
    if [[ -z "${LINUX_GNU_LINKER}" ]] || ! command -v "${LINUX_GNU_LINKER}" >/dev/null 2>&1; then
        echo "error: Windows -> Linux cross-build requires --linux-gnu-linker" >&2
        exit 1
    fi
fi

echo "Building ${BIN_NAME} for ${TARGET} with beta release ID: ${BETA_RELEASE_ID}"
(
    cd "${ROOT_DIR}"
    export OXIDE_RANDOMX_BETA_RELEASE_ID="${BETA_RELEASE_ID}"
    if [[ "${TARGET}" == *"-windows-gnu" ]]; then
        export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="${WINDOWS_GNU_LINKER}"
    fi
    if host_is_windows && [[ "${TARGET}" == "x86_64-unknown-linux-gnu" ]]; then
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${LINUX_GNU_LINKER}"
    fi
    "${CARGO_BIN}" build --release --target "${TARGET}" --bin "${BIN_NAME}" --features "${FEATURES}"
)

SRC_BIN="${ROOT_DIR}/target/${TARGET}/release/${BIN_NAME}"
if [[ "${TARGET}" == *windows* ]]; then
    SRC_BIN="${SRC_BIN}.exe"
fi

mkdir -p "${DIST_DIR}"
cp "${SRC_BIN}" "${DIST_DIR}/${OUT_NAME}"
if [[ "${TARGET}" == *linux* ]]; then
    chmod +x "${DIST_DIR}/${OUT_NAME}"
fi

if [[ "${TARGET}" == *windows* ]]; then
    cat > "${DIST_DIR}/${INSTRUCTIONS_NAME}" <<'EOT'
Public beta run instructions for Windows x86_64

1) Copy `oxide-randomx-beta-capture.exe` to the target Windows host.
2) Open PowerShell in that folder.
3) Run:

   .\oxide-randomx-beta-capture.exe --accept-data-contract

4) The default public profile is `standard`. For a deeper rerun, use:

   .\oxide-randomx-beta-capture.exe --profile full --accept-data-contract

5) Wait for completion.
6) Send back the generated file named like:

   oxide-randomx-beta-results-<bundle_id>.zip

Notes:
- No installer is required.
- No automatic upload happens.
- Manual code signing, if used for release, happens outside this repo.
EOT
else
    cat > "${DIST_DIR}/${INSTRUCTIONS_NAME}" <<'EOT'
Public beta run instructions for Linux x86_64

1) Copy `oxide-randomx-beta-capture` to the target Linux host.
2) Open a shell in that folder.
3) Run:

   ./oxide-randomx-beta-capture --accept-data-contract

4) The default public profile is `standard`. For a deeper rerun, use:

   ./oxide-randomx-beta-capture --profile full --accept-data-contract

5) Wait for completion.
6) Send back the generated file named like:

   oxide-randomx-beta-results-<bundle_id>.zip

Notes:
- No installer is required.
- No automatic upload happens.
- Manual signing, if required by your release process, happens outside this repo.
EOT
fi

CHECKSUM_FILE="${DIST_DIR}/SHA256SUMS.txt"
if command -v sha256sum >/dev/null 2>&1; then
    (
        cd "${DIST_DIR}"
        sha256sum "${OUT_NAME}" "${INSTRUCTIONS_NAME}" > "SHA256SUMS.txt"
    )
elif command -v shasum >/dev/null 2>&1; then
    (
        cd "${DIST_DIR}"
        shasum -a 256 "${OUT_NAME}" "${INSTRUCTIONS_NAME}" > "SHA256SUMS.txt"
    )
else
    printf '%s\n' "checksum_unavailable=sha256sum_or_shasum_not_found" > "${CHECKSUM_FILE}"
fi

if [[ "${TARGET}" == *windows* ]]; then
    if command -v zip >/dev/null 2>&1; then
        (
            cd "${DIST_DIR}"
            rm -f "${ARCHIVE_NAME}"
            zip -q "${ARCHIVE_NAME}" "${OUT_NAME}" "${INSTRUCTIONS_NAME}" "SHA256SUMS.txt"
        )
    fi
else
    if command -v tar >/dev/null 2>&1; then
        (
            cd "${DIST_DIR}"
            rm -f "${ARCHIVE_NAME}"
            tar -czf "${ARCHIVE_NAME}" "${OUT_NAME}" "${INSTRUCTIONS_NAME}" "SHA256SUMS.txt"
        )
    fi
fi

echo "Manual signing step (not automated here): sign ${DIST_DIR}/${OUT_NAME} before public release if your release process requires it."
echo "Wrote: ${DIST_DIR}/${OUT_NAME}"
echo "Wrote: ${DIST_DIR}/${INSTRUCTIONS_NAME}"
echo "Wrote: ${DIST_DIR}/SHA256SUMS.txt"
if [[ -f "${DIST_DIR}/${ARCHIVE_NAME}" ]]; then
    echo "Wrote: ${DIST_DIR}/${ARCHIVE_NAME}"
fi
