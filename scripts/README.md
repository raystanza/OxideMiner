# Large/Huge Pages scripts

Automation helpers for enabling Large/Huge pages on Windows and Debian. These are **one-time ops/setup** scripts, not runtime code.

```bash
scripts/
  windows/Enable-LargePages.ps1
  linux/enable_hugepages.sh
```

## What these do

* **Windows (`Enable-LargePages.ps1`)**: Grants the **SeLockMemoryPrivilege** (“Lock pages in memory”) to a user so apps that request large pages can use them.
* **Debian (`enable_hugepages.sh`)**: Reserves **HugeTLB 2MiB** pages, mounts `/mnt/hugepages`, adds a `hugepages` group, and sets **Transparent Huge Pages (THP)** mode (default `madvise`). Persists settings.

> ⚠️ **Caution**: HugeTLB pages are **non-swappable**. Reserve only what your system can spare.

---

## Prerequisites

* **Windows**: Run PowerShell **as Administrator**.
* **Debian**: Run with **sudo/root**; systemd present (for THP persistence).

---

## Usage

### Windows (PowerShell)

```powershell
# In an elevated PowerShell in scripts/windows/
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\Enable-LargePages.ps1                 # current user
.\Enable-LargePages.ps1 -User 'MACHINE\miner'  # specific account
```

**After running**: sign out and back in (or restart the service account) so the new privilege appears in the logon token.

**Verify**:

```powershell
whoami /priv | findstr /I SeLockMemoryPrivilege
```

---

### Debian (Bash)

```bash
# In scripts/linux/
chmod +x enable_hugepages.sh
sudo ./enable_hugepages.sh                # defaults (~25% RAM, THP=madvise)
sudo ./enable_hugepages.sh -n 1024 -u myuser -t madvise
```

**Verify**:

```bash
grep -E 'HugePages_(Total|Free|Rsvd|Surp)' /proc/meminfo
mount | grep ' /mnt/hugepages '
cat /sys/kernel/mm/transparent_hugepage/enabled
```

**Note**: Log out/in so your user picks up the `hugepages` group membership (or use `newgrp hugepages`).

---

## Rollback

### Windows

* Open **Local Security Policy** → *Local Policies* → *User Rights Assignment* → **Lock pages in memory** → remove the user → `gpupdate /force`.
* Sign out/in.

### Debian

```bash
# Release HugeTLB pages now and on reboot
echo 0 | sudo tee /proc/sys/vm/nr_hugepages
sudo rm -f /etc/sysctl.d/99-hugepages.conf
sudo sysctl --system

# Unmount and remove fstab entry
sudo umount /mnt/hugepages || true
sudo sed -i '\|^[^#].\s/mnt/hugepages\s\+hugetlbfs|d' /etc/fstab
sudo rmdir /mnt/hugepages 2>/dev/null || true

# Disable THP systemd unit if created
sudo systemctl disable --now thp-mode.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/thp-mode.service
sudo systemctl daemon-reload
```

---

## Why Huge/Large Pages for RandomX (Monero) miners

RandomX intentionally hammers memory with **pseudo-random accesses** to a \~2 GiB dataset. This pattern punishes normal 4 KiB pages (lots of page-table walks and TLB misses). Enabling Huge/Large pages (2 MiB) helps by:

* **Cutting TLB misses:** Fewer pages cover the same dataset → fewer page-table lookups, less latency.
* **Smoother, higher hashrate:** Typically a **single-digit to low double-digit (%) gain** depending on CPU, RAM speed/timings, and BIOS settings.
* **Lower CPU overhead & jitter:** Fewer kernel crossings and page faults → more stable per-thread performance.
* **Better efficiency:** More hashes per watt thanks to reduced memory-management overhead.
* **Pinned memory (Windows “Lock pages”):** Prevents paging of the RandomX dataset, avoiding stalls.

Notes:

* Linux: explicit **HugeTLB** is most deterministic; THP=`madvise` generally plays nicer with other workloads.
* Windows: granting **SeLockMemoryPrivilege** merely *enables* large-page allocations; the miner still chooses to use them.
* Gains vary by hardware and BIOS (NUMA, memory channels, RAM frequency/latency).
