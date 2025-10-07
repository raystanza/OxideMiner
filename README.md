# OxideMiner

[![GitHub stars](https://img.shields.io/github/stars/raystanza/OxideMiner?style=flat-square)](https://github.com/raystanza/OxideMiner/stargazers)
[![CI](https://github.com/raystanza/OxideMiner/actions/workflows/ci.yml/badge.svg)](https://github.com/raystanza/OxideMiner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.73%2B-orange.svg?style=flat-square)](https://www.rust-lang.org/learn/get-started)

**OxideMiner** is a high-performance, security-focused Monero (XMR) miner written entirely in Rust. Version **v0.1.0 (MVP)** delivers top-tier hashrate and hardened networking in a self-contained binary.

---

## Features

- **Blazing performance** – tuned RandomX engine with core pinning and huge page support.
- **Security-first design** – memory-safe Rust, TLS pool connections, and optional certificate pinning.
- **Real-time observability** – HTTP dashboard plus Prometheus `/metrics` endpoint.
- **Self-contained binary** – embedded assets; no external runtime required.
- **Resilient networking** – automatic reconnects and watchdog timers.
- **Operator-friendly** – human-readable `config.toml`, CLI overrides, and structured logging.

---

## Quick Start

This section covers everything you need to start mining in minutes. OxideMiner targets 64-bit Linux and Windows machines with a modern CPU (AES + 2 MB L3 cache minimum). Mining on macOS is not supported at this time.

### 1. Download a Prebuilt Binary

Grab the latest release from the [GitHub Releases](https://github.com/raystanza/OxideMiner/releases) page.

| Platform | Archive | Notes |
|----------|---------|-------|
| Windows 10/11 (x86_64) | `oxide-miner-v0.1.0-windows.zip` | Contains `oxide-miner.exe` and sample config. Requires PowerShell 5+ or CMD. |
| Linux (x86_64, glibc 2.31+) | `oxide-miner-v0.1.0-linux.tar.gz` | Statically linked binary tested on Ubuntu 22.04, Debian 12, Fedora 38. |

Extract the archive to a dedicated directory, e.g. `C:\OxideMiner` on Windows or `~/oxide-miner` on Linux. Verify the checksum published alongside the release before running the binary.

### 2. Prepare Your Configuration

OxideMiner reads settings from `config.toml` in the working directory. Start from the built-in example:

```bash
disable-run
cp config.toml.example config.toml
```

Open the file in your favorite editor and set at least the pool, wallet, and (optional) miner name:

```toml
pool = "pool.supportxmr.com:443"
wallet = "48z8R1GxSL6QRmGKv3x78JSMeBYvPVK2g9tSFoiwH4u88KPSLjnZUe6VXHKf5vrrG52uaaVYMpBBd2QQUiTY84qaSXJYVPS"
pass = "oxide-rig-01"
threads = 0               # 0 = auto-tune based on cores/cache
huge_pages = true         # requires OS huge page setup
api_port = 8080           # dashboard + metrics endpoint
```

Leave `threads` at `0` to let the miner discover the optimal core count. If you enable `huge_pages`, configure the OS first (see below).

### 3. Run the Miner

**Linux:**

```bash
./oxide-miner --config ./config.toml
```

**Windows (PowerShell):**

```powershell
PS C:\OxideMiner> .\oxide-miner.exe --config .\config.toml
```

On first launch the miner benchmarks your CPU to calibrate RandomX settings. A live hashrate appears within a few seconds.

### 4. Connect to a Pool

OxideMiner speaks the Stratum protocol used by major Monero pools. Popular choices include:

- [SupportXMR](https://supportxmr.com) – `pool.supportxmr.com:443`
- [MoneroOcean](https://moneroocean.stream) – `gulf.moneroocean.stream:20128`
- [MineXMR](https://minexmr.com) – `pool.minexmr.com:9000`

You can specify a pool on the command line, overriding the configuration file:

```bash
./oxide-miner --pool pool.minexmr.com:9000 --wallet 4A1s... --pass home-rig
```

OxideMiner fails over when the primary pool drops. Add multiple pools in `config.toml`:

```toml
[[pools]]
url = "pool.supportxmr.com:443"
pass = "rig-east"

[[pools]]
url = "pool.minexmr.com:9000"
pass = "rig-backup"
```

### 5. Monitor with the Dashboard

With `api_port` (default `8080`), OxideMiner serves an embedded dashboard and JSON API covering live hashrate, shares, connection status, and telemetry. For headless setups, query raw stats:

```bash
curl http://127.0.0.1:8080/api/stats | jq
```

Prometheus-compatible metrics are available at `http://127.0.0.1:8080/metrics`.

### 6. Enable Secure Networking

- **TLS:** Set `tls = true` to negotiate TLS 1.2/1.3 with your pool. OxideMiner ships with Mozilla’s CA bundle for common pools. Provide `tls_ca_cert` if your environment requires a custom trust store.
- **Certificate pinning:** Specify `tls_cert_sha256` to pin the pool’s leaf certificate fingerprint and protect against MITM attacks.
- **Proxy support:** Use `--socks5 127.0.0.1:9050` to route traffic through a Tor or corporate SOCKS proxy.

### 7. Optimize for Maximum Hashrate

- **Huge pages:** Configure huge pages (Linux `vm.nr_hugepages`, Windows *Lock Pages in Memory*) before launching.
- **CPU affinity:** Set `affinity = true` to pin worker threads to cores.
- **Batch size tuning:** Increase `batch_size` for high-core-count servers to reduce scheduling overhead.

Logs are printed to stdout by default and optionally to rotated files under `./logs/`. Increase verbosity with `--debug` or `debug = true` for negotiation traces, timing histograms, and huge page diagnostics.

### Responsible Usage

Mining is resource-intensive. Please:

- Only mine on hardware you own or have explicit permission to use.
- Respect all local laws, corporate policies, and energy regulations.
- Monitor thermals, power draw, and update promptly for security fixes.

---

## Advanced Configuration Reference

All options can be set via `config.toml` or overridden at runtime with CLI flags. Key flags include:

| Flag | Description |
|------|-------------|
| `--config <PATH>` | Load settings from a specific TOML file. |
| `--pool <HOST:PORT>` | Override the primary pool address. |
| `--wallet <ADDRESS>` | Override the wallet address. |
| `--pass <STRING>` | Set the miner password/rig ID. |
| `--threads <N>` | Force a thread count (0 = auto). |
| `--no-huge-pages` | Disable huge page requests even if enabled in config. |
| `--api-port <PORT>` | Serve dashboard/API on a custom port. |
| `--bind <IP>` | Bind the HTTP server to a specific interface (default 127.0.0.1). |
| `--socks5 <ADDR>` | Use a SOCKS5 proxy for pool connections. |
| `--background` | Detach and run as a background service (Linux only). |

To reload settings without stopping the miner, send `SIGHUP` (Linux) or use the Windows tray icon context menu to apply changes.

---

## Troubleshooting & FAQ

- **Low hashrate:** Ensure huge pages are active (`huge_pages_active` metric should be `1`) and disable competing workloads.
- **Connection drops:** Verify outbound TCP ports, firewalls, and enable TLS logging (`debug = true`) if certificates fail.
- **Rejected shares:** Check system clock accuracy and network latency; OxideMiner retries submissions automatically.

---

## Developer Guide

While OxideMiner focuses on end-user simplicity, contributions are welcome. The project is still early-stage (v0.1.0 MVP), so feedback and PRs can significantly shape the roadmap.

### Clone the Repository

```bash
git clone https://github.com/raystanza/OxideMiner.git
cd OxideMiner
```

### Build from Source

Prerequisites:

- Rust 1.73+ (install via [rustup](https://rustup.rs))
- C toolchain (Visual Studio Build Tools on Windows, `build-essential` on Debian/Ubuntu)
- Optional: nightly Rust for benchmarking extras (`rustup toolchain install nightly`)

Compile and run tests:

```bash
cargo build --release
cargo test
```

The optimized binary is located at `target/release/oxide-miner` (or `.exe`). To build with nightly-only features such as AVX-512 experimental kernels:

```bash
cargo +nightly build --release --features nightly-kernels
```

### Code Layout

- `crates/oxide-miner` – main binary crate, CLI, config parsing, runtime.
- `crates/randomx` – pure-Rust RandomX implementation with JIT backends.
- `crates/dashboard` – embedded dashboard assets and HTTP handlers.
- `scripts/` – helper scripts for packaging and release automation.

### Contributing

1. Fork the repository and create a feature branch.
2. Run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting PRs.
3. Open an issue for significant changes to discuss design and security implications.

Bug reports, feature ideas, and docs improvements are all appreciated. Join the discussion in [GitHub Discussions](https://github.com/raystanza/OxideMiner/discussions).

---

## License

OxideMiner is released under the MIT License.

## Acknowledgments

- Inspired by the pioneering work of the Monero community and the RandomX research team.
- Built with the help of the Rust ecosystem: `tokio`, `serde`, `axum`, and many more crates.
- Special thanks to early alpha testers who validated stability on diverse hardware.

## Contact

- Project site: [https://github.com/raystanza/OxideMiner](https://github.com/raystanza/OxideMiner)
- Security reports: security@raystanza.dev (PGP key on keys.openpgp.org)
- General inquiries: hello@raystanza.dev

