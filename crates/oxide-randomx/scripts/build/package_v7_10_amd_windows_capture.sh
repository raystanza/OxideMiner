#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TARGET="${TARGET:-x86_64-pc-windows-gnu}"
FEATURES="${FEATURES:-bench-instrument simd-blockio}"
DIST_DIR="${DIST_DIR:-${ROOT_DIR}/dist/v7_10_amd_windows_capture}"
BIN_NAME="v7_10_amd_windows_capture"
RUNNER_LABEL="v7_10_amd_capture"
EXE_NAME="oxide-randomx-v7_10-amd-capture.exe"
WINDOWS_GNU_LINKER="${WINDOWS_GNU_LINKER:-${CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER:-x86_64-w64-mingw32-gcc}}"

if ! command -v rustup >/dev/null 2>&1; then
    echo "error: rustup is required" >&2
    exit 1
fi

if ! rustup target list --installed | grep -qx "${TARGET}"; then
    echo "error: target '${TARGET}' is not installed" >&2
    echo "install it with: rustup target add ${TARGET}" >&2
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

echo "Building ${RUNNER_LABEL} (bin ${BIN_NAME}) for ${TARGET} with features: ${FEATURES}"
(
    cd "${ROOT_DIR}"
    cargo build --release --target "${TARGET}" --bin "${BIN_NAME}" --features "${FEATURES}"
)

SRC_EXE="${ROOT_DIR}/target/${TARGET}/release/${BIN_NAME}.exe"
if [[ ! -f "${SRC_EXE}" ]]; then
    echo "error: expected output missing: ${SRC_EXE}" >&2
    exit 1
fi

mkdir -p "${DIST_DIR}"
cp "${SRC_EXE}" "${DIST_DIR}/${EXE_NAME}"

cat > "${DIST_DIR}/RUN_ON_REMOTE_WINDOWS_HOST.txt" <<'EOT'
Run instructions for remote AMD Windows 11 owner

1) Copy `oxide-randomx-v7_10-amd-capture.exe` to the target AMD Windows machine.
2) Open PowerShell in that folder.
3) Run:

   .\oxide-randomx-v7_10-amd-capture.exe

4) Wait for completion.
5) The tool prints the artifact folder path and also writes a `v7_10_share_instructions_*.txt` file.
6) Send the entire output folder as a zip to: raystanza@raystanza.uk

Optional run args:
- `--perf-iters 30 --perf-warmup 5`
- `--large-pages off`
- `--owner-email raystanza@raystanza.uk`
EOT

if command -v zip >/dev/null 2>&1; then
    (
        cd "${DIST_DIR}"
        rm -f oxide-randomx-v7_10-amd-capture.zip
        zip -q oxide-randomx-v7_10-amd-capture.zip "${EXE_NAME}" RUN_ON_REMOTE_WINDOWS_HOST.txt
    )
    echo "Wrote: ${DIST_DIR}/oxide-randomx-v7_10-amd-capture.zip"
fi

echo "Wrote: ${DIST_DIR}/${EXE_NAME}"
echo "Wrote: ${DIST_DIR}/RUN_ON_REMOTE_WINDOWS_HOST.txt"
