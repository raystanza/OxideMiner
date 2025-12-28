#!/usr/bin/env bash
#
# list_changes_linux.sh
#
# Generate a Markdown changelog for the current Git repo.
#
# Default (full history) → writes dev/changelog_full.md:
#   ./scripts/list_changes_linux.sh
#
# Latest tag only (previous_tag..latest_tag) → writes
#   dev/changelog_<previous_tag>_to_<latest_tag>.md:
#
# Flags:
#   ./scripts/list_changes_linux.sh --latest
#   ./scripts/list_changes_linux.sh --latest-only
#   ./scripts/list_changes_linux.sh -l
#

set -euo pipefail

MODE="full"

case "${1:-}" in
  --latest|--latest-only|-l)
    MODE="latest"
    ;;
  "")
    ;;
  *)
    echo "Usage: $0 [--latest|--latest-only|-l]" >&2
    exit 2
    ;;
esac

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is not installed or not on PATH." >&2
  exit 1
fi

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "Error: this script must be run inside a Git repository." >&2
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)

# Collect tags (oldest → newest by creation date)
mapfile -t TAGS_ASC < <(git tag --sort=creatordate)

if [[ "$MODE" == "latest" && ${#TAGS_ASC[@]} -eq 0 ]]; then
  echo "Warning: no tags found; falling back to full history." >&2
  MODE="full"
fi

LATEST_TAG=""
PREV_TAG=""

if [[ "$MODE" == "latest" && ${#TAGS_ASC[@]} -gt 0 ]]; then
  last_index=$(( ${#TAGS_ASC[@]} - 1 ))
  LATEST_TAG="${TAGS_ASC[$last_index]}"
  if (( ${#TAGS_ASC[@]} >= 2 )); then
    PREV_TAG="${TAGS_ASC[$((last_index - 1))]}"
  fi
fi

sanitize_tag() {
  local tag="$1"
  tag="${tag//\//_}"
  tag="${tag//\\/_}"
  tag="${tag// /_}"
  echo "$tag"
}

if [[ "$MODE" == "full" ]]; then
  OUTPUT_FILE="$REPO_ROOT/dev/changelog_full.md"
else
  safe_latest=$(sanitize_tag "$LATEST_TAG")
  if [[ -n "$PREV_TAG" ]]; then
    safe_prev=$(sanitize_tag "$PREV_TAG")
    OUTPUT_FILE="$REPO_ROOT/dev/changelog_${safe_prev}_to_${safe_latest}.md"
  else
    # Only one tag in the repo → everything up to that tag
    OUTPUT_FILE="$REPO_ROOT/dev/changelog_${safe_latest}.md"
  fi
fi

# Truncate output file
: > "$OUTPUT_FILE"

append() {
  printf '%s\n' "$*" >> "$OUTPUT_FILE"
}

append "# OxideMiner Change History"
append ""
append "- Branch: \`$BRANCH_NAME\`"
append "- Generated: $(date '+%Y-%m-%d %H:%M:%S')"
append ""

write_section_md() {
  local title="$1"
  local range="$2"

  local log_output
  log_output=$(git log --no-merges \
    --pretty=format:'%H%x01%an%x01%ad%x01%s' \
    --date=short \
    "$range" 2>/dev/null || true)

  if [[ -z "$log_output" ]]; then
    return
  fi

  append ""
  append "## $title"
  append ""

  local features="" fixes="" docs="" refactors="" chores="" other=""

  while IFS=$'\1' read -r sha author date subject; do
    [[ -z "$sha" ]] && continue

    local short_sha=${sha:0:7}
    local entry="- [$short_sha] $subject ($author, $date)"

    local s=${subject,,}

    if [[ $s == feat:* || $s == feat\(* || $s == feature:* ]]; then
      features+="$entry"$'\n'
    elif [[ $s == fix:* || $s == fix\(* || $s == bug:* || $s == bugfix:* ]]; then
      fixes+="$entry"$'\n'
    elif [[ $s == doc:* || $s == docs:* || $s == readme:* || $s == readme\(* ]]; then
      docs+="$entry"$'\n'
    elif [[ $s == refactor:* || $s == refactor\(* ]]; then
      refactors+="$entry"$'\n'
    elif [[ $s == chore:* || $s == chore\(* || $s == build:* ]]; then
      chores+="$entry"$'\n'
    else
      other+="$entry"$'\n'
    fi
  done <<< "$log_output"

  local print_cat
  print_cat() {
    local heading="$1"
    local content="$2"
    if [[ -n "$content" ]]; then
      append "### $heading"
      append ""
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        append "$line"
      done <<< "$content"
      append ""
    fi
  }

  print_cat "Features" "$features"
  print_cat "Fixes" "$fixes"
  print_cat "Docs" "$docs"
  print_cat "Refactors" "$refactors"
  print_cat "Chores / Build" "$chores"
  print_cat "Other" "$other"
}

# ----- Main section selection -----

if [[ ${#TAGS_ASC[@]} -eq 0 ]]; then
  # No tags at all → single section with full history
  write_section_md "All changes (no Git tags yet)" "HEAD"
else
  if [[ "$MODE" == "latest" ]]; then
    if [[ -n "$PREV_TAG" ]]; then
      write_section_md "Changes for $LATEST_TAG (since $PREV_TAG)" "$PREV_TAG..$LATEST_TAG"
    else
      write_section_md "Changes for $LATEST_TAG" "$LATEST_TAG"
    fi
  else
    # full mode: unreleased + each tag range, newest first
    SECTION_TITLES=()
    SECTION_RANGES=()

    last_index=$(( ${#TAGS_ASC[@]} - 1 ))
    latest="${TAGS_ASC[$last_index]}"

    SECTION_TITLES+=("Unreleased (since $latest)")
    SECTION_RANGES+=("$latest..HEAD")

    local i
    for (( i=0; i<${#TAGS_ASC[@]}; i++ )); do
      local tag="${TAGS_ASC[$i]}"
      local tag_date
      tag_date=$(git log -1 --format='%ad' --date=short "$tag")

      local range
      if (( i == 0 )); then
        range="$tag"
      else
        local prev="${TAGS_ASC[$((i-1))]}"
        range="$prev..$tag"
      fi

      SECTION_TITLES+=("$tag ($tag_date)")
      SECTION_RANGES+=("$range")
    done

    for (( i=${#SECTION_TITLES[@]}-1; i>=0; i-- )); do
      write_section_md "${SECTION_TITLES[$i]}" "${SECTION_RANGES[$i]}"
    done
  fi
fi

echo "Generated $OUTPUT_FILE"
exit 0
