# OxideMiner

[![GitHub release](https://img.shields.io/github/v/release/raystanza/OxideMiner?color=blue&label=release)](https://github.com/raystanza/OxideMiner/releases)
[![Build Status](https://github.com/raystanza/OxideMiner/actions/workflows/ci.yml/badge.svg)](https://github.com/raystanza/OxideMiner/actions/workflows/ci.yml)
[![Rust Version](https://img.shields.io/badge/rust-1.72%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

**OxideMiner** is a high-performance, hardened Monero (XMR) miner written in Rust. Built for operators who demand uncompromising speed, observability, and safety, OxideMiner v0.1.0 (MVP) combines a tuned RandomX implementation with a compact runtime, zero unsafe defaults, and a polished HTTP dashboard for real-time insight.

---

## Why OxideMiner?

OxideMiner was created to deliver first-class mining performance without sacrificing security or ease of use. Every component is engineered in Rust for memory safety, race-free concurrency, and predictable latency under heavy load. Whether you operate a single workstation or a farm of dedicated rigs, OxideMiner lets you deploy, monitor, and scale with confidence.

---

## Features

- ⚡ **Elite performance** – CPU cache-aware RandomX kernels, adaptive batching, and optional NUMA affinity deliver top-tier hashrates with minimal jitter.
- 🛡️ **Security-first design** – TLS/TCP pool connections with certificate pinning, zero unsafe defaults, and hardened panic handling ensure safe long-term operation.
- 📊 **Live dashboard & API** – Embedded HTTP server exposes `/dashboard` for a responsive UI (hashrate, shares, job latency, uptime) and `/api/stats` for programmatic access.
- 📈 **Metrics endpoint** – Native `/metrics` endpoint exports Prometheus-compatible counters and gauges for fleet observability.
- 📦 **Self-contained binary** – Single executable ships with embedded assets (dashboard, localization, defaults) for drop-in deployment.
- 🧩 **Flexible configuration** – Comprehensive `config.toml` plus CLI overrides for quick tuning and automation.

---

## Quick Start

> **Version notice:** OxideMiner v0.1.0 is an MVP. We test relentlessly, yet edge cases may exist. Please share feedback and bug reports so we can iterate rapidly.

### 1. Download a Release Build

Pre-built binaries are published for Linux (x86_64, aarch64) and Windows (x86_64). Download the latest release from GitHub:

```bash
curl -LO https://github.com/raystanza/OxideMiner/releases/download/v0.1.0/oxide-miner-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/raystanza/OxideMiner/releases/download/v0.1.0/oxide-miner-x86_64-pc-windows-msvc.zip
```

Extract the archive and place the `oxide-miner` (`oxide-miner.exe` on Windows) binary anywhere in your `$PATH` or a dedicated directory.

```bash
tar -xzf oxide-miner-x86_64-unknown-linux-gnu.tar.gz -C /opt/oxide-miner
# Windows (PowerShell)
Expand-Archive -Path .\oxide-miner-x86_64-pc-windows-msvc.zip -DestinationPath C:\OxideMiner
```

### 2. Verify Integrity (Recommended)

Every release ships with SHA256 checksums and a detached signature. Verify before executing:

```bash
curl -LO https://github.com/raystanza/OxideMiner/releases/download/v0.1.0/oxide-miner-v0.1.0.sha256
curl -LO https://github.com/raystanza/OxideMiner/releases/download/v0.1.0/oxide-miner-v0.1.0.sha256.asc
echo "$(sha256sum oxide-miner-x86_64-unknown-linux-gnu.tar.gz)" | grep -Ff oxide-miner-v0.1.0.sha256
gpg --verify oxide-miner-v0.1.0.sha256.asc oxide-miner-v0.1.0.sha256
```

### 3. Create `config.toml`

OxideMiner reads configuration from `config.toml` beside the binary (override with `--config`). Copy the example file included in the repo or the release artifact, then adjust for your environment:

```bash
cp config.toml.example config.toml
```

A minimal configuration might look like this:

```toml
pool = "pool.supportxmr.com:5555"
wallet = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS"
pass = "rig-01"
threads = 12

[network]
tls = true
tls_cert_sha256 = "d3c1f2aa287af2bc404256746f3ab7232dd6fef1e09a79014363ce23c24ab234"

[api]
port = 8080
bind = "0.0.0.0"
```

#### Configuration Highlights

- **Pool credentials:** Specify `pool`, `wallet`, and optional `pass` to authenticate with your chosen pool.
- **Thread management:** Omit `threads` to let the miner auto-tune based on available logical cores and cache topology.
- **TLS security:** Set `tls = true` to encrypt pool communication. Provide `tls_ca_cert` or `tls_cert_sha256` for certificate pinning on untrusted networks.
- **HTTP API:** Use `api.port` (default 8080) and `api.bind` to expose the dashboard and stats endpoints.
- **Performance knobs:** Advanced users can enable huge pages (`huge_pages = true`) or adjust batch size to trade latency for throughput.

### 4. Launch the Miner

Run OxideMiner from the directory containing `config.toml`:

```bash
./oxide-miner --config ./config.toml
```

Useful command-line flags:

```bash
./oxide-miner \
  --wallet 48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS \
  --pool pool.supportxmr.com:5555 \
  --threads auto \
  --api-port 8080 \
  --log-level info
```

Flags always override values specified in `config.toml`, making it easy to reuse a shared config across rigs while customizing host-specific parameters.

### 5. Connect to Your Pool

OxideMiner supports the Stratum protocol used by popular Monero pools. Once running, the log output should display successful pool authentication and job acceptance:

```
2024-03-14T20:41:17Z  INFO oxide_miner::pool: Connected to pool.supportxmr.com:5555 (TLS)
2024-03-14T20:41:18Z  INFO oxide_miner::miner: Auto-tuned threads = 16 (L3 cache 64 MiB)
2024-03-14T20:41:32Z  INFO oxide_miner::shares: Accepted share diff=120000
```

Monitor your pool dashboard to confirm shares and payouts.

### 6. Access the Dashboard & API

Open a browser to the HTTP endpoint (defaults to <http://localhost:8080>). The dashboard includes:

- Current and 15-minute average hashrate.
- Total accepted/rejected shares.
- Longest job latency and block height.
- Worker uptime, CPU utilization, and huge page status.

For automation, hit the JSON API:

```bash
curl http://localhost:8080/api/stats | jq
```

Prometheus users can scrape `/metrics`:

```bash
curl http://localhost:8080/metrics
```

Integrate these metrics with Grafana for fleet-wide visibility.

### 7. Monitoring & Operations

- **Log files:** Structured logs stream to STDOUT and rotate daily under `./logs/` when `debug = true`.
- **Auto restart:** Use systemd, NSSM, or any supervisor to auto-restart on failure.

- **Scaling:** Combine the metrics endpoint with orchestration tools (Ansible, Salt, Kubernetes) to manage many rigs.

### Responsible Usage

Mining consumes significant CPU resources, electricity, and cooling capacity. Operate responsibly:

- Only mine on hardware you own or have explicit permission to use.
- Comply with local laws, workplace policies, and electricity agreements.
- Monitor thermals to avoid hardware degradation.
- Budget for higher utility costs and ensure adequate ventilation.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| Hashrate lower than expected | Enable huge pages, ensure BIOS virtualization is on, reduce background processes. |
| TLS handshake fails | Confirm pool supports TLS, update `tls_ca_cert`, or pin the server certificate fingerprint. |
| Dashboard unreachable | Verify `api.bind` and firewall rules, confirm the port is open, check logs for binding errors. |
| High rejected share rate | Reduce overclocking, verify network latency, ensure pool difficulty is appropriate for your rig. |

---

## For Developers (20%)

### Clone the Repository

```bash
git clone https://github.com/raystanza/OxideMiner.git
cd OxideMiner
```

### Build from Source

OxideMiner targets stable Rust 1.72+, but the RandomX backend benefits from nightly for certain CPU intrinsics. Install Rustup and the nightly toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup component add --toolchain nightly rustfmt clippy
```

Build and test:

```bash
cargo +nightly build --release
cargo +nightly test
```

Generated binaries live in `target/release/`. Copy the `config.toml.example` alongside for packaging.

### Development Workflow

- **Formatting:** `cargo +nightly fmt` (CI enforces Rustfmt).
- **Linting:** `cargo +nightly clippy --all-targets -- -D warnings`.
- **Fuzzing:** `cargo +nightly fuzz run` (requires `cargo-fuzz`).
- **Dashboard:** Assets are located in `crates/oxide-miner/assets` and embedded via `include_bytes!`.

### Contributing

1. Fork the repository and create a feature branch (`git checkout -b feature/my-improvement`).
2. Implement your changes with tests and documentation.
3. Run the full test suite (`cargo +nightly test`) and ensure linting passes.
4. Submit a pull request referencing any relevant issues. Detailed benchmark results are appreciated.

We welcome bug reports, performance traces, and documentation improvements. Please review `CONTRIBUTING.md` for code of conduct expectations.

---

## License

OxideMiner is licensed under the [MIT License](./LICENSE). See the LICENSE file for details.

## Acknowledgments

- Inspired by the open-source Monero ecosystem and projects such as XMRig, SRBMiner, and xmrig-cuda.
- Thanks to the Rust community for crates including `tokio`, `serde`, `reqwest`, and `prometheus` that power OxideMiner.
- Appreciation to early adopters for stress-testing v0.1.0 and sharing tuning insights.

## Contact

- Project homepage: <https://github.com/raystanza/OxideMiner>
- Security disclosures: security@raystanza.dev (GPG key in `SECURITY.md`)
- Chat: Join the community Matrix room at `#oxideminer:monero.social`

