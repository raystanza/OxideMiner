#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat >&2 <<USAGE
Usage: $0 <output-file> <file> [...]
Generate SHA-256 checksums for the provided files and write them to the output file.
USAGE
  exit 1
fi

output_file="$1"
shift

temp_file="${output_file}.tmp"
rm -f "$temp_file"

for target in "$@"; do
  if [[ ! -f "$target" ]]; then
    echo "error: cannot checksum missing file '$target'" >&2
    exit 2
  fi
  sha256sum "$target" >> "$temp_file"
done

mv "$temp_file" "$output_file"
