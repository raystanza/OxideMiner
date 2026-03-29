#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
FEATURES="${FEATURES:-bench-instrument simd-blockio}"
DIST_DIR="${DIST_DIR:-${ROOT_DIR}/dist/v7_10_amd_linux_capture}"
BIN_NAME="v7_10_amd_windows_capture"
RUNNER_LABEL="v7_10_amd_capture"
OUT_NAME="oxide-randomx-v7_10-amd-capture"

if ! command -v rustup >/dev/null 2>&1; then
    echo "error: rustup is required" >&2
    exit 1
fi

if ! rustup target list --installed | grep -qx "${TARGET}"; then
    echo "error: target '${TARGET}' is not installed" >&2
    echo "install it with: rustup target add ${TARGET}" >&2
    exit 1
fi

echo "Building ${RUNNER_LABEL} (bin ${BIN_NAME}) for ${TARGET} with features: ${FEATURES}"
(
    cd "${ROOT_DIR}"
    cargo build --release --target "${TARGET}" --bin "${BIN_NAME}" --features "${FEATURES}"
)

SRC_BIN="${ROOT_DIR}/target/${TARGET}/release/${BIN_NAME}"
if [[ ! -f "${SRC_BIN}" ]]; then
    echo "error: expected output missing: ${SRC_BIN}" >&2
    exit 1
fi

mkdir -p "${DIST_DIR}"
cp "${SRC_BIN}" "${DIST_DIR}/${OUT_NAME}"
chmod +x "${DIST_DIR}/${OUT_NAME}"

cat > "${DIST_DIR}/RUN_ON_REMOTE_DEBIAN_HOST.txt" <<'EOT'
Run instructions for remote Debian-based AMD Linux host owner

1) Copy `oxide-randomx-v7_10-amd-capture` to the target host.
2) Open a shell in that folder.
3) Run:

   ./oxide-randomx-v7_10-amd-capture

4) Wait for completion.
5) The tool prints the artifact folder path and writes `v7_10_share_instructions_*.txt`.
6) Send the entire output folder as a zip/tarball to: raystanza@raystanza.uk

Optional run args:
- `--perf-iters 30 --perf-warmup 5`
- `--large-pages off`
- `--owner-email raystanza@raystanza.uk`
EOT

if command -v tar >/dev/null 2>&1; then
    (
        cd "${DIST_DIR}"
        rm -f oxide-randomx-v7_10-amd-capture-linux.tar.gz
        tar -czf oxide-randomx-v7_10-amd-capture-linux.tar.gz "${OUT_NAME}" RUN_ON_REMOTE_DEBIAN_HOST.txt
    )
    echo "Wrote: ${DIST_DIR}/oxide-randomx-v7_10-amd-capture-linux.tar.gz"
fi

echo "Wrote: ${DIST_DIR}/${OUT_NAME}"
echo "Wrote: ${DIST_DIR}/RUN_ON_REMOTE_DEBIAN_HOST.txt"
