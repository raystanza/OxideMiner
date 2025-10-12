#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <output-file> <input-file> [<input-file>...]" >&2
  exit 1
fi

output_file="$1"
shift

: > "$output_file"

if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd=(shasum -a 256)
else
  echo "Error: no SHA-256 tool available" >&2
  exit 1
fi

for input_file in "$@"; do
  if [[ ! -f "$input_file" ]]; then
    echo "Error: file '$input_file' does not exist" >&2
    exit 1
  fi
  hash_value=$("${hash_cmd[@]}" "$input_file" | awk '{print $1}')
  printf '%s  %s\n' "$hash_value" "$(basename "$input_file")" >> "$output_file"
done

chmod 0644 "$output_file"
