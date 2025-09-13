#!/usr/bin/env bash
# enable_hugepages.sh
# Enables persistent 2MiB HugeTLB pages on Debian, mounts /mnt/hugepages,
# creates a 'hugepages' group, adds user, and sets THP to 'madvise'.
# Defaults: reserve ~25% of RAM as hugepages (min 64 pages), THP=madvise, user=SUDO_USER.
# Usage:
#   sudo ./enable_hugepages.sh                 # defaults
#   sudo ./enable_hugepages.sh -n 1024 -u myuser -t madvise
# Options:
#   -n <NUM>   Number of 2MiB hugepages to reserve (optional).
#   -u <USER>  User to grant access to /mnt/hugepages (defaults to SUDO_USER or current).
#   -t <MODE>  THP mode: madvise|never|always (default: madvise)

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Please run as root (use sudo)." >&2
  exit 1
fi

NUM=""
USER_NAME="${SUDO_USER:-${USER:-}}"
THP_MODE="madvise"

while getopts ":n:u:t:" opt; do
  case "$opt" in
    n) NUM="$OPTARG" ;;
    u) USER_NAME="$OPTARG" ;;
    t) THP_MODE="$OPTARG" ;;
    \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
  esac
done

if [[ -z "$USER_NAME" ]]; then
  echo "ERROR: Could not determine target user. Pass with -u <user>." >&2
  exit 1
fi

if [[ ! "$THP_MODE" =~ ^(madvise|never|always)$ ]]; then
  echo "ERROR: -t must be one of: madvise|never|always" >&2
  exit 1
fi

echo "== HugePages Enabler =="
echo "Target user:         $USER_NAME"
echo "Desired THP mode:    $THP_MODE"
echo "------------------------------------------------------------"

# Compute default page count if not provided: ~25% of RAM (min 64 pages)
if [[ -z "$NUM" ]]; then
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  mem_mb=$(( mem_kb / 1024 ))
  # pages = floor((25% of MB) / 2MB) = mem_mb / 8
  pages=$(( mem_mb / 8 ))
  if (( pages < 64 )); then pages=64; fi
  NUM="$pages"
fi

echo "2MiB hugepages to reserve: $NUM"
echo "This will reserve ~$(( NUM * 2 )) MiB of RAM for HugeTLB (non-swappable)."

# Ensure hugetlbfs module present
echo "[1/7] Loading hugetlbfs kernel support (if needed)..."
modprobe hugetlbfs || true

# Reserve hugepages now and persist via sysctl
echo "[2/7] Reserving hugepages immediately via sysctl..."
sysctl -w vm.nr_hugepages="$NUM" >/dev/null

echo "[3/7] Persisting hugepages reservation in /etc/sysctl.d/99-hugepages.conf ..."
cat >/etc/sysctl.d/99-hugepages.conf <<EOF
# Reserved 2MiB HugeTLB pages
vm.nr_hugepages=$NUM
EOF
sysctl --system >/dev/null

# Create group and mountpoint
echo "[4/7] Creating 'hugepages' group and mountpoint..."
getent group hugepages >/dev/null || groupadd hugepages
usermod -aG hugepages "$USER_NAME"

mkdir -p /mnt/hugepages
gid_num=$(getent group hugepages | cut -d: -f3)

# Mount hugetlbfs and persist in fstab
echo "[5/7] Mounting /mnt/hugepages (mode=1770,gid=$gid_num) and updating /etc/fstab ..."
mountpoint -q /mnt/hugepages || mount -t hugetlbfs nodev /mnt/hugepages -o mode=1770,gid="$gid_num"
if ! grep -qE '^[^#]*\s+/mnt/hugepages\s+hugetlbfs' /etc/fstab; then
  echo "hugetlbfs  /mnt/hugepages  hugetlbfs  mode=1770,gid=$gid_num  0  0" >> /etc/fstab
fi

# Set Transparent Huge Pages policy and persist via systemd service
thp_enabled="/sys/kernel/mm/transparent_hugepage/enabled"
if [[ -e "$thp_enabled" ]]; then
  echo "[6/7] Setting Transparent Huge Pages to '$THP_MODE' now..."
  # shellcheck disable=SC2024
  echo "$THP_MODE" > "$thp_enabled" || true

  echo "Creating systemd unit to persist THP mode..."
  cat >/etc/systemd/system/thp-mode.service <<EOF
[Unit]
Description=Set Transparent Huge Pages mode
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo $THP_MODE > /sys/kernel/mm/transparent_hugepage/enabled'

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now thp-mode.service >/dev/null
else
  echo "[6/7] THP sysfs control not found; skipping THP mode setting."
fi

# Report
echo "[7/7] Verifying current state:"
grep -E 'HugePages_(Total|Free|Rsvd|Surp)' /proc/meminfo
echo "Mounts:"
mount | grep -E 'on /mnt/hugepages .* hugetlbfs' || true
if [[ -e "$thp_enabled" ]]; then
  echo "THP enabled line:"
  cat "$thp_enabled"
fi

echo ""
echo "SUCCESS."
echo "- /mnt/hugepages is ready; files created there will come from HugeTLB."
echo "- User '$USER_NAME' has been added to the 'hugepages' group (log out and back in to refresh group membership)."
echo "- HugeTLB reservation persists via /etc/sysctl.d/99-hugepages.conf."
echo "- THP mode persists via systemd (thp-mode.service)."
