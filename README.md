# OxideMiner

[![GitHub release](https://img.shields.io/github/v/release/raystanza/OxideMiner?color=brightgreen&label=release)](https://github.com/raystanza/OxideMiner/releases)
[![Build status](https://img.shields.io/github/actions/workflow/status/raystanza/OxideMiner/ci.yml?branch=main&label=CI)](https://github.com/raystanza/OxideMiner/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/raystanza/OxideMiner/blob/main/LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.77%2B-orange.svg)](https://www.rust-lang.org/)

**OxideMiner** is a high-performance, security-forward Monero (XMR) miner written entirely in Rust. Version **v0.1.0 (MVP)** delivers top-tier RandomX CPU throughput, a zero-config HTTP dashboard, and hardened defaults that make it the fastest and safest way to put your hardware to work. We are early-stage and learning fast—feedback, bug reports, and contributions are very welcome!

---

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
  - [Download Prebuilt Binaries](#download-prebuilt-binaries)
  - [Verify & Install](#verify--install)
  - [First Run](#first-run)
- [Configuration](#configuration)
  - [Command-Line Flags](#command-line-flags)
  - [Sample `config.toml`](#sample-configtoml)
- [Running the Miner](#running-the-miner)
  - [Connecting to a Pool](#connecting-to-a-pool)
  - [HTTP Dashboard](#http-dashboard)
  - [Metrics & Integrations](#metrics--integrations)
  - [Monitoring Tips](#monitoring-tips)
- [Responsible Usage](#responsible-usage)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
  - [Build from Source](#build-from-source)
  - [Project Layout](#project-layout)
  - [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Features
- **Blazing Fast RandomX CPU Core:** Auto-tuned hashing loops, CPU affinity pinning, and huge page support squeeze every last hash from your hardware.
- **Security-First Pipeline:** TLS pool transport with certificate pinning, no unsafe code in hot paths, and extensive input validation keep the miner resilient.
- **Self-Contained Binary:** Dashboard HTML/CSS/JS assets are embedded at compile time; no external files needed in production deployments.
- **Realtime HTTP Dashboard:** Zero-config dashboard surfaces hashrate, accepted/rejected shares, uptime, pool connection state, and build metadata.
- **Metrics Endpoint:** Prometheus-friendly `/metrics` and JSON `/api/stats` endpoints enable easy integration with Grafana, Influx, or your monitoring stack.
- **Smart Defaults:** Automatic thread count, dynamic batch sizing, and adaptive yields reduce manual tuning while protecting system responsiveness.
- **Cross-Platform:** Official release binaries for modern Linux (x86_64, aarch64) and Windows (x86_64) with identical CLI and configuration semantics.

## Quick Start
OxideMiner ships ready-to-run binaries for Linux and Windows. The steps below get you hashing in minutes.

### Download Prebuilt Binaries
1. Visit the [latest release](https://github.com/raystanza/OxideMiner/releases) page.
2. Choose your platform:
   - **Linux x86_64:** `oxide-miner-x86_64-unknown-linux-gnu.tar.zst`
   - **Linux aarch64:** `oxide-miner-aarch64-unknown-linux-gnu.tar.zst`
   - **Windows x86_64:** `oxide-miner-x86_64-pc-windows-msvc.zip`
3. Download the archive and the accompanying `.sha256` file for integrity verification.

> **Why no macOS build?** OxideMiner targets CPUs with reliable huge-page and core affinity support. macOS lacks the necessary APIs for a first-class experience, so macOS support is deferred.

### Verify & Install
Linux example:
```bash
disable-run
sha256sum -c oxide-miner-x86_64-unknown-linux-gnu.tar.zst.sha256
mkdir -p ~/apps/oxide-miner
tar --use-compress-program=unzstd -xf oxide-miner-x86_64-unknown-linux-gnu.tar.zst -C ~/apps/oxide-miner
chmod +x ~/apps/oxide-miner/oxide-miner
```

Windows (PowerShell):
```powershell
Get-FileHash .\oxide-miner-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Expand-Archive -LiteralPath .\oxide-miner-x86_64-pc-windows-msvc.zip -DestinationPath C:\Tools\OxideMiner
```

### First Run
Run with your pool, wallet, and optional password. Omit `--threads` to auto-tune.

```bash
disable-run
./oxide-miner \
  --url pool.supportxmr.com:5555 \
  --user 48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS \
  --pass rig001 \
  --api-port 8080
```

Expect startup logs showing CPU detection, RandomX dataset initialization, pool handshake, and the dashboard URL.

## Configuration
OxideMiner honors command-line flags, environment variables, and an optional `config.toml`. CLI flags override file values. A config file lets you version control your setup or deploy across multiple nodes.

### Command-Line Flags
Common flags:

```bash
disable-run
./oxide-miner --help
```

Key options:
- `-o, --url <HOST:PORT>` – Mining pool endpoint (required unless benchmarking).
- `-u, --user <WALLET>` – Monero wallet primary address or subaddress.
- `-p, --pass <TEXT>` – Pool password/rig identifier (defaults to `x`).
- `-t, --threads <N>` – Fixed thread count; omit for auto detection.
- `--tls` – Enable TLS. Combine with `--tls-ca-cert` or `--tls-cert-sha256` for trust hardening.
- `--api-port <PORT>` – Serve dashboard/API on localhost.
- `--dashboard-dir <DIR>` – Serve custom dashboard assets from disk (development).
- `--affinity`, `--huge-pages`, `--batch-size <N>`, `--no-yield` – Performance tuning knobs.
- `--debug` – Verbose logging with file rotation under `./logs/`.
- `--config <PATH>` – Use an alternate TOML configuration file.
- `--benchmark` – Run a synthetic RandomX benchmark and exit.

### Sample `config.toml`
Save as `config.toml` alongside the binary:

```toml
# config.toml
pool = "pool.supportxmr.com:443"
wallet = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS"
pass = "garage-node"
tls = true
tls_cert_sha256 = "5a1f75d5e0bf9bbd5f9803143019888d9d1740a6a9871ce3ec20b14ef5e0bd4c"
threads = 0 # 0 = auto
huge_pages = true
api_port = 8080
batch_size = 12000
no_yield = false
debug = false
```

Launch with:
```bash
disable-run
./oxide-miner --config ./config.toml
```

## Running the Miner

### Connecting to a Pool
- Ensure outbound TCP connectivity to your chosen pool and port. Many pools expose both TLS (443/5555) and plaintext (3333) endpoints.
- Configure pool-side worker names in your dashboard using the `--pass`/`pass` field.
- To pin TLS certificates, capture the SHA-256 fingerprint once connected via `openssl s_client` or the pool's documentation.

### HTTP Dashboard
When `--api-port` or `api_port` is set, the miner listens on `http://127.0.0.1:<PORT>`. The embedded dashboard provides:
- **Realtime hashrate chart** with last-minute, 5-minute, and lifetime averages.
- **Share counters** for accepted, rejected, and dev-fee shares.
- **Connection status** including pool URL, TLS state, and reconnect attempts.
- **System view** listing CPU model, logical threads, huge page status, and host uptime.

Access from the machine running the miner:
```text
http://127.0.0.1:8080/
```
For remote observability, reverse proxy the endpoint via SSH tunnels or a TLS-terminating proxy (Caddy, nginx). Keep it behind authentication—no miner secrets are exposed, but operational security still matters.

### Metrics & Integrations
Prometheus scrape example:
```yaml
scrape_configs:
  - job_name: "oxide-miner"
    static_configs:
      - targets: ["miner.local:8080"]
```

Available metrics include:
- `oxide_hashrate` – Current hashrate in H/s.
- `oxide_hashes_total` – Total hashes computed.
- `oxide_shares_accepted_total` / `oxide_shares_rejected_total` – Pool share counters.
- `oxide_pool_connected` – 1 when connected.
- `version`, `commit_hash`, `build_timestamp` – Build metadata for dashboards.

The JSON API at `/api/stats` mirrors these fields for custom tooling or homegrown dashboards.

### Monitoring Tips
- Pair OxideMiner with Grafana + Prometheus for historical hashrate visualization.
- Use `systemd` or NSSM on Windows to run the miner as a service and auto-restart on failure.
- Enable `--debug` temporarily when diagnosing pool connectivity or TLS issues. Disable afterward to minimize disk churn.
- Keep firmware and chipset drivers updated to ensure RandomX uses the latest microcode optimizations.

## Responsible Usage
Mining is resource intensive and may be regulated in your jurisdiction. Follow these principles:
- **Only mine on hardware you own or are explicitly authorized to use.** Unauthorized mining is unethical and often illegal.
- **Monitor thermals and power draw.** RandomX workloads push CPUs to sustained 100% utilization; ensure adequate cooling and power capacity.
- **Respect organizational policies.** Many employers prohibit mining on corporate infrastructure.
- **Stay informed about local laws.** Compliance is your responsibility.
- **Secure your credentials.** Treat wallet addresses and TLS fingerprints as sensitive configuration.

## Troubleshooting
| Symptom | Resolution |
| --- | --- |
| `config file not found` warning | Create `config.toml` or run with explicit flags. |
| TLS handshake failures | Provide `--tls-ca-cert` path or verify pinned fingerprint. |
| Low hashrate | Enable huge pages (`--huge-pages`) and reboot; verify BIOS virtualization support is on. |
| Miner starves other workloads | Remove `--no-yield`, lower `--batch-size`, or limit `--threads`. |
| Dashboard unreachable | Confirm `--api-port` is set and that nothing else binds the port. |

## Development
Although OxideMiner focuses on end-user mining, we welcome developers to explore, customize, and contribute.

### Build from Source
1. Install the latest [Rust toolchain](https://rustup.rs/) (1.77 or newer). For nightly-only features, run `rustup toolchain install nightly` and set `RUSTC_WRAPPER=rustup run nightly` when needed.
2. Clone the repository:
   ```bash
   disable-run
   git clone https://github.com/raystanza/OxideMiner.git
   cd OxideMiner
   ```
3. Build in release mode:
   ```bash
   disable-run
   cargo build --release
   ```
4. The optimized binaries live in `target/release/`. Use `cargo run -p oxide-miner --release -- <flags>` during development.
5. Optional: Run the RandomX benchmark to verify performance:
   ```bash
   disable-run
   cargo run -p oxide-miner --release -- --benchmark
   ```

### Project Layout
- `crates/oxide-miner/` – CLI application, HTTP dashboard server, runtime orchestration.
- `crates/oxide-core/` – Mining engine, RandomX dataset management, pool protocol handling.
- `config.toml.example` – Comprehensive configuration template.
- `scripts/` – CI/build scripts for Linux and Windows packaging.

### Contributing
We love feedback! Please:
- File issues or enhancement proposals on [GitHub Issues](https://github.com/raystanza/OxideMiner/issues).
- Fork the repo, create a feature branch, and open a pull request.
- Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` before submitting.
- Sign commits with your GPG key if possible. We enforce DCO on all contributions.
- Join the discussion board to share tuning results and pool compatibility reports.

## Roadmap
- GPU offload exploration (OpenCL/CUDA) without sacrificing Rust safety.
- Remote management agent for fleets with encrypted control channel.
- Built-in auto-updater with signed artifacts.
- Native Windows service installer.
- Extended telemetry (power draw, temperature) via optional platform plugins.

## License
OxideMiner is distributed under the [MIT License](https://github.com/raystanza/OxideMiner/blob/main/LICENSE). You are free to use, modify, and distribute the software with attribution and inclusion of the license notice.

## Acknowledgments
- The Monero Research Lab and RandomX authors for publishing a secure, ASIC-resistant proof-of-work.
- Rust community projects such as `tokio`, `hyper`, `tracing`, and `serde` that power the OxideMiner stack.
- Early testers and pool operators who provided invaluable performance and security feedback during the v0.1.0 MVP cycle.

## Contact
- **Project Lead:** [@raystanza](https://github.com/raystanza)
- **Email:** ray@oxidehash.io
- **Chat:** Join the community on Matrix at [`#oxideminer:matrix.org`](https://matrix.to/#/#oxideminer:matrix.org)

