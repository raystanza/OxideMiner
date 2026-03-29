#!/usr/bin/env bash
set -euo pipefail

PAGES_1G=4
PAGES_2M=0
RUNTIME=1
PERSIST=0
DRY_RUN=0

readonly HP_1G_DIR="/sys/kernel/mm/hugepages/hugepages-1048576kB"
readonly HP_2M_DIR="/sys/kernel/mm/hugepages/hugepages-2048kB"
readonly GRUB_FILE="/etc/default/grub"

readonly KB_PER_1G=$((1024 * 1024))
readonly KB_PER_2M=$((2 * 1024))

usage() {
  cat <<'EOF'
Enable Linux huge-page pools for RandomX benchmarking (Ubuntu-friendly).

Usage:
  sudo ./Enable-1GB-HugePages.sh [options]

Options:
  --pages N         Alias for --pages-1g
  --pages-1g N      Number of 1GB pages to reserve (default: 4)
                    RandomX fast dataset needs at least 3.
  --pages-2m N      Number of 2MB pages to reserve (default auto by RAM size)
                    Used by non-1GB large-page path and fallback path.
  --no-2m           Do not configure 2MB huge pages (sets --pages-2m 0)
  --persist         Persist across reboot by updating /etc/default/grub and running update-grub
  --no-runtime      Skip runtime sysfs reservation
  --dry-run         Print planned actions without changing the system
  -h, --help        Show this help

Examples:
  sudo ./Enable-1GB-HugePages.sh
  sudo ./Enable-1GB-HugePages.sh --pages-1g 4 --pages-2m 2048
  sudo ./Enable-1GB-HugePages.sh --pages-1g 4 --pages-2m 2048 --persist
EOF
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "This script must be run as root (try: sudo $0 ...)"
  fi
}

require_linux() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    die "This script only supports Linux."
  fi
}

mem_total_kb() {
  awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo
}

default_2m_pages() {
  local total_kb
  total_kb="$(mem_total_kb)"
  if (( total_kb >= 30 * 1024 * 1024 )); then
    # ~4GiB 2MB pool on >=30GiB systems.
    printf '2048'
  elif (( total_kb >= 16 * 1024 * 1024 )); then
    printf '1024'
  else
    printf '512'
  fi
}

read_sysfs_value() {
  local path="$1"
  if [[ -r "$path" ]]; then
    cat "$path"
  else
    printf 'n/a'
  fi
}

kb_to_gib() {
  local kb="$1"
  awk -v v="${kb}" 'BEGIN { printf "%.2f", v / 1024 / 1024 }'
}

show_status() {
  local total_kb reserve_kb
  total_kb="$(mem_total_kb)"
  reserve_kb=$(( PAGES_1G * KB_PER_1G + PAGES_2M * KB_PER_2M ))

  log "System memory:"
  log "  MemTotal=${total_kb} kB ($(kb_to_gib "${total_kb}") GiB)"
  log "Requested reservation:"
  log "  1GB pages=${PAGES_1G} ($(kb_to_gib "$((PAGES_1G * KB_PER_1G))") GiB)"
  log "  2MB pages=${PAGES_2M} ($(kb_to_gib "$((PAGES_2M * KB_PER_2M))") GiB)"
  log "  total=$(kb_to_gib "${reserve_kb}") GiB"
  log
  log "Kernel cmdline:"
  log "  $(cat /proc/cmdline)"
  log
  log "1GB huge pages:"
  log "  nr_hugepages=$(read_sysfs_value "${HP_1G_DIR}/nr_hugepages")"
  log "  free_hugepages=$(read_sysfs_value "${HP_1G_DIR}/free_hugepages")"
  log
  log "2MB huge pages:"
  log "  nr_hugepages=$(read_sysfs_value "${HP_2M_DIR}/nr_hugepages")"
  log "  free_hugepages=$(read_sysfs_value "${HP_2M_DIR}/free_hugepages")"
}

validate_targets() {
  local total_kb reserve_kb reserve_pct
  total_kb="$(mem_total_kb)"
  reserve_kb=$(( PAGES_1G * KB_PER_1G + PAGES_2M * KB_PER_2M ))
  reserve_pct=$(( reserve_kb * 100 / total_kb ))

  if (( reserve_pct > 70 )); then
    die "Requested huge-page reservation is ${reserve_pct}% of RAM; reduce --pages-1g/--pages-2m."
  fi

  if (( PAGES_1G < 3 )); then
    warn "Configured 1GB pages (${PAGES_1G}) are below RandomX fast dataset minimum of 3."
  fi

  if (( PAGES_2M == 0 )); then
    warn "2MB pool is set to 0; non-1GB/fallback path may drop to normal pages."
  fi
}

configure_runtime_pool() {
  local label="$1"
  local target="$2"
  local requested="$3"

  if (( DRY_RUN )); then
    log "[dry-run] echo ${requested} > ${target}"
    return
  fi

  if [[ ! -w "${target}" ]]; then
    die "Cannot write ${target} for ${label} huge pages."
  fi

  log "Setting runtime ${label} huge pages to ${requested}..."
  if ! echo "${requested}" > "${target}"; then
    die "Failed to write ${target}. Check privileges and system policy."
  fi

  local actual
  actual="$(cat "${target}")"
  if (( actual < requested )); then
    warn "${label}: kernel set nr_hugepages=${actual}, below requested ${requested}."
    warn "${label}: likely memory fragmentation or insufficient available memory."
    warn "${label}: prefer boot-time reservation with --persist and reboot."
  fi
}

configure_runtime_pages() {
  configure_runtime_pool "1GB" "${HP_1G_DIR}/nr_hugepages" "${PAGES_1G}"
  if [[ -d "${HP_2M_DIR}" ]]; then
    configure_runtime_pool "2MB" "${HP_2M_DIR}/nr_hugepages" "${PAGES_2M}"
  else
    warn "2MB huge-page sysfs directory not found: ${HP_2M_DIR}"
  fi
}

extract_grub_cmdline_default() {
  if ! grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "${GRUB_FILE}"; then
    printf ''
    return
  fi

  local raw
  raw="$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "${GRUB_FILE}" | head -n1)"
  raw="${raw#GRUB_CMDLINE_LINUX_DEFAULT=}"
  raw="${raw#\"}"
  raw="${raw%\"}"
  printf '%s' "${raw}"
}

is_managed_size_token() {
  case "$1" in
    hugepagesz=1G|hugepagesz=1g|hugepagesz=2M|hugepagesz=2m)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

build_new_cmdline() {
  local current="$1"
  local token
  local -a kept=()
  local -a tokens=()
  local pending_managed_pair=0

  # Split cmdline into tokens safely (no pathname expansion side effects).
  read -r -a tokens <<< "${current}"

  for token in "${tokens[@]}"; do
    if is_managed_size_token "${token}"; then
      pending_managed_pair=1
      continue
    fi

    if (( pending_managed_pair )); then
      if [[ "${token}" =~ ^hugepages=[0-9]+$ ]]; then
        pending_managed_pair=0
        continue
      fi
      pending_managed_pair=0
    fi

    kept+=("${token}")
  done

  kept+=("hugepagesz=1G" "hugepages=${PAGES_1G}")
  if (( PAGES_2M > 0 )); then
    kept+=("hugepagesz=2M" "hugepages=${PAGES_2M}")
  fi

  printf '%s' "${kept[*]}"
}

backup_grub_file() {
  local ts backup
  ts="$(date -u +%Y%m%d_%H%M%S)"
  backup="${GRUB_FILE}.bak.${ts}"
  cp "${GRUB_FILE}" "${backup}"
  log "Backup created: ${backup}"
}

write_grub_cmdline_default() {
  local new_cmdline="$1"
  local tmp
  tmp="$(mktemp)"

  awk -v newline="GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"" '
    BEGIN { replaced = 0 }
    /^GRUB_CMDLINE_LINUX_DEFAULT=/ {
      print newline
      replaced = 1
      next
    }
    { print }
    END {
      if (replaced == 0) {
        print newline
      }
    }
  ' "${GRUB_FILE}" > "${tmp}"

  cat "${tmp}" > "${GRUB_FILE}"
  rm -f "${tmp}"
}

configure_persistent_grub() {
  [[ -f "${GRUB_FILE}" ]] || die "${GRUB_FILE} not found. Cannot persist boot config."

  local current new_cmdline
  current="$(extract_grub_cmdline_default)"
  new_cmdline="$(build_new_cmdline "${current}")"

  if (( DRY_RUN )); then
    log "[dry-run] update ${GRUB_FILE}:"
    log "  GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\""
    log "[dry-run] update-grub"
    return
  fi

  log "Updating ${GRUB_FILE} with 1GB + 2MB huge-page kernel parameters..."
  backup_grub_file
  write_grub_cmdline_default "${new_cmdline}"

  if command -v update-grub >/dev/null 2>&1; then
    update-grub
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    warn "update-grub not found; using grub-mkconfig -o /boot/grub/grub.cfg"
    grub-mkconfig -o /boot/grub/grub.cfg
  else
    die "Neither update-grub nor grub-mkconfig was found."
  fi

  log "Persistent config updated. Reboot required for boot-time reservation."
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pages|--pages-1g)
        shift
        [[ $# -gt 0 ]] || die "$1 requires a value"
        [[ "$1" =~ ^[0-9]+$ ]] || die "--pages-1g must be a non-negative integer"
        PAGES_1G="$1"
        ;;
      --pages-2m)
        shift
        [[ $# -gt 0 ]] || die "--pages-2m requires a value"
        [[ "$1" =~ ^[0-9]+$ ]] || die "--pages-2m must be a non-negative integer"
        PAGES_2M="$1"
        ;;
      --no-2m)
        PAGES_2M=0
        ;;
      --persist)
        PERSIST=1
        ;;
      --no-runtime)
        RUNTIME=0
        ;;
      --dry-run)
        DRY_RUN=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (use --help)"
        ;;
    esac
    shift
  done
}

main() {
  # Initialize dynamic defaults once, then allow args to override.
  PAGES_2M="$(default_2m_pages)"

  parse_args "$@"
  require_linux

  if (( DRY_RUN )) && [[ "${EUID}" -ne 0 ]]; then
    warn "Running dry-run without root; no changes will be applied."
  else
    require_root
  fi

  [[ -d "${HP_1G_DIR}" ]] || die "1GB huge-page sysfs directory not found: ${HP_1G_DIR}"
  [[ -d "${HP_2M_DIR}" ]] || die "2MB huge-page sysfs directory not found: ${HP_2M_DIR}"

  validate_targets

  log "== Before =="
  show_status
  log

  if (( RUNTIME )); then
    configure_runtime_pages
    log
  fi

  if (( PERSIST )); then
    configure_persistent_grub
    log
  fi

  log "== After =="
  show_status
  log

  if (( !PERSIST )); then
    log "Note: runtime-only configuration is not persistent across reboot."
  fi

  log "Benchmark guidance:"
  log "  Use --large-pages on and OXIDE_RANDOMX_HUGE_1G=1 for 1GB attempts."
  log "  Keep 2MB pool non-zero to preserve fallback/non-1GB large-page behavior."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
