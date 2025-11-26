# OxideMiner: High-Performance Monero (XMR) CPU Miner in Rust

[![Release](https://github.com/raystanza/OxideMiner/actions/workflows/release.yml/badge.svg)](https://github.com/raystanza/OxideMiner/actions/workflows/release.yml)
[![Version](https://img.shields.io/github/v/release/raystanza/OxideMiner?sort=semver)](https://github.com/raystanza/OxideMiner/releases)
[![Downloads](https://img.shields.io/github/downloads/raystanza/OxideMiner/total)](https://github.com/raystanza/OxideMiner/releases)
[![License](https://img.shields.io/badge/License-BSL_1.1-orange)](LICENSE)

![OxideMiner Logo](oxideminer_logo_transparent_256.png)

**OxideMiner** is a **next-generation RandomX CPU miner** written entirely in **Rust**. Engineered for _speed, safety, and full transparency_.
It’s built to squeeze every cycle from your CPU while keeping your system secure and predictable.
No hidden payloads, no opaque binaries...just verifiable, auditable performance.

We ship a **command-line miner** with automatic CPU tuning, an **optional embedded dashboard**, and hardened controls for TLS, logging, and system friendliness. Every byte of it compiles from the code you see here.

**Performance meets integrity.** OxideMiner is what happens when modern Rust engineering meets Monero’s RandomX algorithm. Optimized for real-world rigs and safe for production hosts.

> **Note:** This is an early-stage release. Expect rough edges while we stabilize and benchmark across more hardware.
> Bug reports and tuning data are especially valuable at this stage.

---

## Table of contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
  - [Super-Quick start](Super-Quick-start)
  - [Prerequisites](#prerequisites)
  - [Build and install](#build-and-install)
  - [First run](#first-run)
- [Downloading and Verifying Releases](#downloading-and-verifying-releases)
- [Configuration](#configuration)
  - [Command-line flags](#command-line-flags)
  - [Sample `config.toml`](#sample-configtoml)
  - [Configuration warnings](#configuration-warnings)
- [Operating the miner](#operating-the-miner)
  - [Benchmark mode](#benchmark-mode)
  - [Pool connectivity](#pool-connectivity)
  - [Huge pages & affinity](#huge-pages--affinity)
  - [HTTP dashboard & API](#http-dashboard--api)
  - [Metrics reference](#metrics-reference)
- [Responsible usage](#responsible-usage)
- [Developer notes](#developer-notes)
  - [Workspace layout](#workspace-layout)
  - [Building & testing](#building--testing)
  - [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Highlights

> **TL;DR** OxideMiner aims to be _the most transparent, secure, and efficient RandomX CPU miner ever written in Rust._

- ⚡ **Rust-first CPU miner:** Built from the ground up in Rust for memory safety and predictable performance; with **no C glue, no unsafe shortcuts**. The `oxide-core` crate implements the RandomX hot loop, while `oxide-miner` orchestrates worker threads through Tokio for maximum throughput and minimal overhead.

- 🧠 **Auto-tuned intelligence:** At startup, OxideMiner introspects your CPU topology and cache sizes to pick the perfect thread count and batch size. You can always override them so you can squeeze every last drop of performance from you CPU.

- 🔒 **TLS-ready stratum client:** Secure pool connectivity via `--tls`, with optional certificate pinning and custom CA support.

- 📈 **Prometheus-compatible metrics:** The `/metrics` endpoint exposes rich counters and gauges, ready for Grafana dashboards or cluster monitoring.

- 🪶 **Clean, structured logs:** Human-readable by default, detailed under `--debug`. Rotating log files keep long runs tidy.

- 💎 **Transparent dev fee:** A fixed 1% developer fee, clearly logged and accounted for in metrics. No stealth mining, no surprises, just honesty.

- 📊 **Built-in dashboard (with themes!):** A modern, static web UI (HTML/CSS/JS fully embedded in the binary) shows hashrate, shares, uptime, connection state, and build metadata.

![Screenshot](oxideminer_themes_screenshot.png)

## Quick start

### Super-Quick start

Download a pre-built binary from the [Relases](https://github.com/raystanza/OxideMiner/releases/) page, copy and rename 'config.toml.example' -> 'config.toml', fill in your desired pool & wallet address, run the miner:

> **Windows**: .\oxide-miner.exe \
> **Linux**: ./oxide-miner

_By default OxideMiner will look for a 'config.toml' file in the same directory as the binary, but you can supply the '--config \<PATH_to_CONFIG.TOML>' argument._

>[CLI Screenshot](oxideminer_cli_screenshot.png)

### Prerequisites

> The steps below are for if you want to build from source.

- Rust toolchain via [rustup](https://rustup.rs/) (stable channel). The workspace targets Rust 2021 edition.
- A Monero-compatible mining pool endpoint and wallet address.
- Optional: elevated privileges for huge/large page support (see below).

### Build and install

```bash
# Clone the repository
git clone https://github.com/raystanza/OxideMiner.git
cd OxideMiner

# Compile an optimized binary
cargo build --release

# Copy the executable to a location on your PATH (optional, Debian Linux)
install -Dm755 target/release/oxide-miner "$HOME/.local/bin/oxide-miner"
```

The CLI can also be run directly with `cargo run -p oxide-miner --release -- <flags>` while testing changes.

### First run

Supply your pool, wallet, and optional password. Leave threads and batch size unset to accept the auto-tuned values gathered at startup.

```bash
# Example: plaintext stratum connection with HTTP dashboard on 127.0.0.1:8080

oxide-miner \
  --url <Your.Pool.of.Choice:Port> \
  --user <YOUR_MONERO_WALLET> \
  --pass rig001 \
  --api-port 8080
```

Expected startup log flow:

1. CPU introspection and auto-tune summary (threads, batch size, cache, NUMA, huge page availability).
2. RandomX dataset initialization and worker spawn.
3. Stratum handshake with the configured pool, including dev-fee scheduler announcements.
4. HTTP API availability (if `--api-port` is set.)

## Downloading and Verifying Releases

The project publishes signed release artifacts on the [GitHub Releases](https://github.com/raystanza/OxideMiner/releases) page.
Each release includes compressed binaries (`.tar.gz` for Linux, `.zip` for Windows), matching SHA-256 checksum files, and detached
GPG signatures (`.asc`). Always verify downloads before running them to protect against tampering.

### 1. Download the official artifacts

1. Visit the [Releases](https://github.com/raystanza/OxideMiner/releases) page and choose the tag you want (for example, `v1.2.3`).
2. Download the archive for your operating system and the accompanying checksum (`.sha256`). If signatures are available, download the `.asc` files as well.

### 2. Verify SHA-256 checksums

Validating checksums ensures that the file you downloaded matches what the release workflow produced.

#### Debian/Ubuntu (and other GNU/Linux distributions)

```bash
# Replace the filenames with the release assets you downloaded
sha256sum -c oxide-miner-v1.2.3-x86_64-unknown-linux-gnu.sha256
```

The command reports `OK` when the archive’s digest matches the expected value. If it fails, delete the file immediately and
re-download it from the official release page.

#### Windows 10/11 (Command Prompt)

```cmd
:: Replace the file names with the versions you downloaded
certutil -hashfile oxide-miner-v1.2.3-x86_64-pc-windows-msvc.zip SHA256
```

Compare the printed hash with the value inside `oxide-miner-v1.2.3-x86_64-pc-windows-msvc.sha256`. The values must match exactly.

#### Windows 10/11 (PowerShell)

```powershell
# Replace the file names with the versions you downloaded
Get-FileHash .\oxide-miner-v1.2.3-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

Compare the `Hash` field in the output with the value in the `.sha256` file. If they differ, do not run the binary.

### 3. Verify GPG signatures (recommended)

GPG signatures offer an additional guarantee that the release was produced by the OxideMiner maintainers.

### 1. Import the OxideMiner release signing key

We include it as `release-subkey-ci-public-20251012.asc` in this repository and on [https://raystanza.uk](https://raystanza.uk).

```bash
# Linux / macOS
curl -O https://raw.githubusercontent.com/raystanza/OxideMiner/main/release-subkey-ci-public-20251012.asc
gpg --import release-subkey-ci-public-20251012.asc

# Or fetch it by fingerprint from a keyserver
gpg --keyserver hkps://keys.openpgp.org --recv-keys FDA06CAE264DAC0D29B03F5195EDEDFDCB4DD826
```

### 2. Verify the signature for the archive (and the checksum file, if provided)

```bash
gpg --verify oxide-miner-v1.2.3-x86_64-unknown-linux-gnu.tar.gz.asc oxide-miner-v1.2.3-x86_64-unknown-linux-gnu.tar.gz
gpg --verify oxide-miner-v1.2.3-x86_64-unknown-linux-gnu.sha256.asc oxide-miner-v1.2.3-x86_64-unknown-linux-gnu.sha256
```

On Windows PowerShell, use the same commands inside `gpg` (installed with Git for Windows or Gpg4win):

```powershell
gpg --verify oxide-miner-v1.2.3-x86_64-pc-windows-msvc.zip.asc oxide-miner-v1.2.3-x86_64-pc-windows-msvc.zip
```

### 3. Confirm the signing key’s fingerprint matches the fingerprint published by the project maintainer ([@raystanza](https://github.com/raystanza/))

**If it does not**, discard the artifacts and investigate before proceeding!

Only run the miner when both the checksum and signature verifications succeed. This defense-in-depth approach reduces exposure to
malicious mirrors and supply-chain attacks.

## Configuration

### Command-line flags

Run `oxide-miner --help` (or `cargo run -p oxide-miner -- --help`) to view all options. Key flags include:

| Flag                      | Purpose                                                                           |
| ------------------------- | --------------------------------------------------------------------------------- |
| `-o, --url <HOST:PORT>`   | Mining pool endpoint (required unless `--benchmark`).                             |
| `-u, --user <ADDRESS>`    | Primary Monero wallet or subaddress.                                              |
| `-p, --pass <STRING>`     | Pool password/rig identifier (default `x`).                                       |
| `-t, --threads <N>`       | Override auto-selected worker threads.                                            |
| `--batch-size <N>`        | Manual hashes per batch (default auto recommendation).                            |
| `--no-yield`              | Disable cooperative yields between batches (less friendly to shared hosts).       |
| `--affinity`              | Pin worker threads to CPU cores.                                                  |
| `--huge-pages`            | Request large pages for RandomX dataset (requires OS support).                    |
| `--proxy <URL>`           | Route stratum traffic via SOCKS5 proxy. Format: `socks5://[user:pass@]host:port`. |
| `--tls`                   | Enable TLS for the stratum connection.                                            |
| `--tls-ca-cert <PATH>`    | Add a custom CA certificate (PEM/DER) when TLS is enabled.                        |
| `--tls-cert-sha256 <HEX>` | Pin the pool certificate by SHA-256 fingerprint.                                  |
| `--api-port <PORT>`       | Serve the dashboard/API on `127.0.0.1:<PORT>`.                                    |
| `--dashboard-dir <DIR>`   | Serve dashboard assets from disk instead of embedded versions.                    |
| `--debug`                 | Increase log verbosity and tee output to rotating files in `./logs/`.             |
| `--config <PATH>`         | Load defaults from a TOML file (defaults to `./config.toml`).                     |
| `--benchmark`             | Run the RandomX benchmark and exit (no pool connection).                          |

#### Tari backends

OxideMiner supports three Tari modes selectable via CLI flags or the `[tari]` table in `config.toml`:

- `none` (default): Tari disabled.
- `proxy`: Merge mine Tari through a local `minotari_merge_mining_proxy` (requires a Minotari node).
- `pool`: Connect directly to a Tari stratum pool (no local node required).

Key Tari flags:

- `--tari-mode <none|proxy|pool>` – select the backend.
- `--tari-pool-url <STRATUM>` / `--tari-wallet-address <ADDR>` – Tari pool endpoint and payout address (pool mode).
- `--tari-rig-id <NAME>` / `--tari-login <LOGIN>` / `--tari-password <PASS>` – optional Tari pool identity fields.
- `--tari-proxy-url <URL>` / `--tari-monero-wallet <XMR>` – merge-mining proxy endpoint and optional Monero address (proxy mode).

### Sample `config.toml`

The repository ships with [`config.toml.example`](config.toml.example). Copy it alongside the binary as `config.toml` and edit the keys you need. CLI flags always win over file settings.

```toml
# Save as config.toml next to the oxide-miner binary
pool = "pool.supportxmr.com:5555"
wallet = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS"
pass = "rig001"
threads = 8          # omit to auto-tune
api_port = 8080      # enable HTTP dashboard
huge_pages = true    # request HugeTLB / large pages if OS allows it
# dashboard_dir = "./crates/oxide-miner/assets"   # serve custom UI while developing
# tls = true
# tls_ca_cert = "/etc/ssl/certs/ca-certificates.crt"
# tls_cert_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### Configuration warnings

`parse_with_config` merges CLI arguments with the TOML file and emits warnings for unexpected keys or missing config files. Warnings print to stderr only when relevant (non-debug messages always show; debug-only items respect `--debug`). Treat these as prompts to fix typos before mining.

## Operating the miner

### Benchmark mode

Run `--benchmark` to skip pool connectivity and measure local RandomX throughput. The benchmark:

- Performs the same CPU feature detection and auto-tuning as normal operation.
- Honors manual overrides (`--threads`, `--batch-size`, `--huge-pages`, `--no-yield`).
- Executes a fixed-duration hashing loop (20 seconds) and reports hashes per second via structured logs.

> OxideMiner’s benchmark isn’t synthetic fluff. It’s the _exact_ mining loop used in production, giving you a realistic, apples-to-apples performance baseline. This is useful for validating huge-page configuration, BIOS tweaks, or regression testing after code changes.

### Pool connectivity

- OxideMiner currently targets CPU mining via the stratum protocol; no GPU offload is implemented.
- TLS is optional. When enabled, combine `--tls` with `--tls-ca-cert` for self-hosted pools or `--tls-cert-sha256` to guard against MITM attacks.
- Route pool traffic through a SOCKS5 proxy with `--proxy socks5://[user:pass@]host:port` when you need Tor/VPN privacy or to bypass network restrictions.
- Developer fee shares (1%) are scheduled deterministically and use the hard-coded donation wallet. Their acceptance/rejection counts are tracked separately in logs, metrics, and the dashboard.
- Reconnection logic backs off exponentially between attempts. Watch for log lines prefixed with `reconnect` if the pool is unavailable.

### Huge pages & affinity

RandomX benefits from large pages and deterministic thread placement. OxideMiner surfaces both knobs:

- `--huge-pages` (or `huge_pages = true`) requests 2 MiB pages for the dataset. Success depends on OS configuration; the miner will log warnings when the allocation cannot be satisfied.
- `--affinity` pins worker threads using `core_affinity` to reduce scheduler jitter.

> The options above give RandomX the low-latency memory access it was designed for and prevent CPU scheduler jitter from eating your hashrate.

Helper scripts for system setup live under [`scripts/`](scripts/):

- `scripts/linux/enable_hugepages.sh` reserves HugeTLB pages, mounts `/mnt/hugepages`, and configures Transparent Huge Pages.
- `scripts/windows/Enable-LargePages.ps1` grants the `SeLockMemoryPrivilege` required for large-page allocations on Windows.

Run these scripts with administrative privileges and review their contents before execution. Afterward you'll need to log out and log back in for changes to take effect.

### HTTP dashboard & API

Setting `--api-port` binds the HTTP server to `127.0.0.1:<PORT>`. You can reverse proxy this elsewhere if needed. The following endpoints are served:

- `/` (and `/index.html`): Embedded dashboard UI.
- `/dashboard.css`, `/dashboard.js`, `/img/*`: Embedded static assets. Override via `--dashboard-dir` for local UI development.
- `/api/stats`: JSON payload summarizing hashrate, total hashes, share counts, mining duration, system uptime (via `sysinfo`), pool metadata, and build information.
- `/metrics`: Plain-text metrics for Prometheus and similar collectors.

### Metrics reference

The `/metrics` endpoint currently exports:

```text
oxide_hashes_total <u64>
oxide_hashrate <float>
oxide_shares_accepted_total <u64>
oxide_shares_rejected_total <u64>
oxide_devfee_shares_accepted_total <u64>
oxide_devfee_shares_rejected_total <u64>
oxide_pool_connected <0|1>
oxide_tls_enabled <0|1>
version <string>
commit_hash <string>
commit_hash_short <string>
commit_timestamp <string>
build_timestamp <string>
```

Use these to drive alerting or dashboards. All counters are updated atomically in `Stats` and reflect the same values shown in the web UI.

## Responsible usage

- Mine only on hardware you own or administer with explicit permission.
- Monitor CPU temperatures, power draw, and system stability as RandomX workloads sustain near-100% utilization.
- Keep wallet addresses secure and rotate pool credentials if exposed.
- Understand local regulations regarding cryptocurrency mining.
- Be considerate on shared machines: leave `--no-yield` off unless you fully control the host, and size `--threads` to avoid starving other workloads.

## Developer notes

OxideMiner’s architecture is clean and modular. It is optimized for contribution and inspection.
Rust crates are separated into logical domains (`oxide-core` for the engine, `oxide-miner` for orchestration), ensuring the miner remains maintainable as it grows.

### Workspace layout

```bash
crates/
  oxide-core/      # Mining engine, stratum client, benchmark logic
  oxide-miner/     # CLI binary, HTTP API, configuration parsing, stats
config.toml.example  # Reference configuration
scripts/             # Huge/large page setup helpers for Linux & Windows
```

### Building & testing

Common development commands:

```bash
# Format code
cargo fmt

# Lint with warnings treated as errors
cargo clippy --all-targets -- -D warnings

# Run the full test suite (unit + async tests)
cargo test --all

# Launch the miner in debug mode with verbose logging
cargo run -p oxide-miner -- --debug --benchmark
```

The HTTP API module includes async integration tests that spin up a local server, so expect network bind permissions during `cargo test`.

### Contributing

We welcome issues and pull requests focused on performance, stability, and observability. Before opening a PR:

1. Discuss significant ideas in a GitHub issue so design constraints are documented.
2. Keep patches small and focused; document user-facing changes in the changelog once one exists.
3. Run the commands above (`fmt`, `clippy`, `test`) to maintain build hygiene.
4. Mention hardware, OS, and pool details when reporting performance data or bugs (it helps reproduce results).

## License

OxideMiner is provided under the Business Source License 1.1. Non-production use—including evaluation, internal development, and testing—is permitted under the terms described in [LICENSE](LICENSE). On **2030-01-01** (or, for any given version, the fourth anniversary of its first public release under the BSL, whichever comes first), OxideMiner will transition to the MIT License as the Change License. Commercial production deployments before that date require a separate agreement with the Licensor, Jim Sines ([@raystanza](https://github.com/raystanza)).

## Acknowledgments

- Monero Research Lab and the RandomX authors for publishing a resilient, CPU-friendly proof of work.
- The Rust ecosystem (`tokio`, `hyper`, `tracing`, `serde`, etc.) that powers the async runtime and HTTP layer.
- Early testers providing logs, CPU tuning data, and bug reports that shaped v0.1.0.

## Contact

- GitHub: [@raystanza](https://github.com/raystanza)
- Issues: [https://github.com/raystanza/OxideMiner/issues](https://github.com/raystanza/OxideMiner/issues)
