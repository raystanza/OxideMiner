# OxideMiner

[![GitHub release](https://img.shields.io/github/v/release/raystanza/OxideMiner)](https://github.com/raystanza/OxideMiner/releases)
[![Build status](https://github.com/raystanza/OxideMiner/actions/workflows/ci.yml/badge.svg)](https://github.com/raystanza/OxideMiner/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/l/oxide_miner)](https://github.com/raystanza/OxideMiner/blob/main/LICENSE)
[![Rust Version](https://img.shields.io/badge/rustc-1.75+-orange.svg)](https://www.rust-lang.org/)

OxideMiner is a high-performance, security-focused Monero (XMR) miner written entirely in Rust. Designed for the v0.1.0 MVP release, it aims to be the fastest and most reliable miner available while adhering to best practices and providing a welcoming experience for both casual miners and power users. Feedback is encouraged as we continue to evolve the project toward a stable 1.0 release.

---

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
  - [Download Pre-built Binaries](#download-pre-built-binaries)
  - [Verify Checksums and Signatures](#verify-checksums-and-signatures)
  - [First Run](#first-run)
- [Configuration](#configuration)
  - [Command-Line Flags](#command-line-flags)
  - [Sample `config.toml`](#sample-configtoml)
  - [Pool Configuration Examples](#pool-configuration-examples)
- [Running the Miner](#running-the-miner)
  - [Starting with CLI Flags](#starting-with-cli-flags)
  - [Starting with a Config File](#starting-with-a-config-file)
- [Monitoring & Observability](#monitoring--observability)
  - [Web Dashboard](#web-dashboard)
  - [Metrics Endpoint](#metrics-endpoint)
  - [Log Output](#log-output)
- [Responsible Mining](#responsible-mining)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
  - [Clone the Repository](#clone-the-repository)
  - [Build from Source](#build-from-source)
  - [Project Layout](#project-layout)
  - [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

---

## Features
- **Blazing-fast hashing** powered by a Rust SIMD backend tuned for modern x86_64 and ARM64 CPUs, delivering top-tier hashrates while staying energy efficient.
- **Security-first design** with memory-safe abstractions, hardened pool communication, and automatic detection of suspicious work submissions.
- **Self-contained binary** with embedded kernels and web assets—no external dependencies, runtime extractors, or scripting layers.
- **Real-time HTTP dashboard** exposing hashrate, accepted/rejected shares, pool status, and worker uptime.
- **Prometheus-compatible metrics endpoint** at `/metrics` for integration with Grafana, Datadog, or custom monitoring solutions.
- **Hot-reload configuration** enabling on-the-fly tweaks to threads, pools, and device affinity without restarting the miner.
- **Cross-platform support** with first-class binaries for Windows and Linux (Ubuntu, Debian, Fedora, Arch) built from a reproducible CI pipeline.

---

## Quick Start
OxideMiner focuses on a fast path to mining. You can be hashing within minutes by following the steps below.

### Download Pre-built Binaries
1. Visit the [releases page](https://github.com/raystanza/OxideMiner/releases).
2. Choose the latest stable `v0.1.0` release.
3. Download the appropriate archive for your platform:
   - `OxideMiner-v0.1.0-x86_64-pc-windows-msvc.zip`
   - `OxideMiner-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
   - `OxideMiner-v0.1.0-aarch64-unknown-linux-gnu.tar.gz`
4. Extract the archive into a directory you control, such as `C:\OxideMiner\` or `/opt/oxide-miner/`.

> **Note:** macOS builds are not officially provided in the MVP release. Building from source is still possible on macOS with the nightly toolchain and LLVM 15.

### Verify Checksums and Signatures
Every release ships with SHA256 checksum files and a detached `*.asc` signature signed by the maintainers' PGP keys.

```bash
disable-run
# Linux example
tar -xf OxideMiner-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sha256sum -c OxideMiner-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
gpg --verify OxideMiner-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.asc
```

On Windows, use PowerShell to run `Get-FileHash` and [Gpg4win](https://gpg4win.org/) for signature verification.

### First Run
The extracted directory contains:

```
OxideMiner/
├── oxide-miner.exe (or `oxide-miner` on Linux)
├── config.toml.example
├── dashboard/
│   └── (embedded assets for the web UI)
└── README.txt
```

Copy `config.toml.example` to `config.toml` and adjust the values for your pool credentials (see [Configuration](#configuration)).

---

## Configuration
OxideMiner can be configured entirely through CLI flags, a `config.toml` file, or any combination. CLI options override file values.

### Command-Line Flags
```
OxideMiner v0.1.0
Fast, secure Monero miner written in Rust

USAGE:
    oxide-miner [FLAGS] [OPTIONS]

FLAGS:
    -h, --help            Prints help information
        --dry-run         Validate configuration without starting workers
        --no-dashboard    Disable the HTTP dashboard and metrics endpoints
    -V, --version         Prints version information

OPTIONS:
        --config <PATH>            Path to custom config file
        --log-level <LEVEL>        Set log verbosity (error, warn, info, debug, trace)
        --threads <N>              Override CPU thread count
        --pool <URL>               Set primary pool URL (e.g. stratum+ssl://pool.xmr.pt:443)
        --wallet <ADDRESS>         Monero wallet address for payouts
        --rig-id <NAME>            Optional worker/rig identifier
        --dashboard-bind <ADDR>    Dashboard bind address (default 127.0.0.1:8080)
```

### Sample `config.toml`
```toml
# OxideMiner configuration file (v0.1.0)
miner = "xmr"
rig_id = "workstation-01"

[logging]
level = "info"
log_file = "/var/log/oxide-miner.log"

[dashboard]
enabled = true
bind = "0.0.0.0:8080"

[pool.primary]
url = "stratum+ssl://pool.supportxmr.com:443"
wallet = "47b2WeS4GqY...your_monero_address...Exu"
password = "x"
pool_timeout = 15

[pool.failover]
url = "stratum+tcp://backup.pool:3333"
wallet = "47b2WeS4GqY...your_monero_address...Exu"
password = "x"
pool_timeout = 20

[performance]
threads = 12
huge_pages = true
cpu_affinity = "0-5,8-13"
max_temperature = 85

[api]
metrics = true
metrics_bind = "127.0.0.1:9090"
```

### Pool Configuration Examples
- **SupportXMR (SSL)**: `stratum+ssl://pool.supportxmr.com:443`
- **MineXMR (TCP)**: `stratum+tcp://pool.minexmr.com:4444`
- **Custom node**: `stratum+tcp://<your-node-ip>:18081`

You can specify multiple failover pools under `[pool.failover]`, or add a `[pool.dynamic]` table with auto-failover for complex setups.

---

## Running the Miner
Once you have configured your wallet address and pool settings, start hashing with either CLI flags or your config file.

### Starting with CLI Flags
```bash
disable-run
./oxide-miner \
  --pool stratum+ssl://pool.supportxmr.com:443 \
  --wallet 47b2WeS4GqY...your_monero_address...Exu \
  --rig-id workstation-01 \
  --threads 12
```

On Windows PowerShell:
```powershell
./oxide-miner.exe --pool stratum+tcp://pool.minexmr.com:4444 --wallet 47b2WeS4GqY... --threads 8
```

### Starting with a Config File
```bash
disable-run
./oxide-miner --config /opt/oxide-miner/config.toml
```

The miner immediately prints summary information and begins submitting shares. Configuration changes (e.g., thread count) are detected automatically every 30 seconds.

---

## Monitoring & Observability
OxideMiner provides built-in tools to keep tabs on performance and health.

### Web Dashboard
- Default bind address: `http://127.0.0.1:8080`
- Displays current hashrate (1m, 5m, 15m averages), share acceptance ratio, pool latency, and rig uptime.
- Supports WebSocket push updates for sub-second latency.
- Includes responsive dark/light themes and mobile-friendly layouts.

To expose the dashboard remotely, bind to `0.0.0.0` and secure access via VPN, SSH tunnel, or reverse proxy with authentication.

### Metrics Endpoint
- Available at `http://127.0.0.1:9090/metrics` when `api.metrics` is enabled.
- Publishes Prometheus metrics such as `oxideminer_hashrate`, `oxideminer_shares_total`, `oxideminer_pool_reconnects_total`, and `oxideminer_temperature_celsius`.
- Integrate with Grafana by adding your OxideMiner host as a Prometheus target.

### Log Output
OxideMiner logs to stdout by default with structured JSON entries, making it easy to parse. To log to a file, set `logging.log_file` in the config.

```
{"level":"info","ts":"2024-04-22T12:00:03Z","hashrate":74238,"shares":{"accepted":5,"rejected":0}}
{"level":"warn","ts":"2024-04-22T12:00:45Z","msg":"pool latency high","latency_ms":980}
```

Use `--log-level debug` for low-level traces when diagnosing connectivity or performance issues.

---

## Responsible Mining
- **Mine on hardware you own or are explicitly authorized to use.** Unauthorized mining is unethical and may be illegal.
- **Monitor resource usage.** OxideMiner can saturate CPUs and increase power draw. Ensure adequate cooling and consider rate-limiting via `performance.threads` or `performance.max_temperature`.
- **Stay compliant.** Verify that mining is permitted in your jurisdiction, workplace, or hosting provider. Follow local energy and taxation regulations.
- **Secure your systems.** Keep operating systems patched, isolate miners on dedicated networks, and safeguard your wallet keys.

---

## Troubleshooting
- **Low hashrate?** Enable huge pages (`performance.huge_pages = true`), update to the latest CPU microcode, and ensure Turbo Boost/Precision Boost is enabled in BIOS.
- **Connection drops?** Check firewall rules, confirm pool URLs, and monitor dashboard logs for authentication errors. Configure failover pools.
- **High temperatures?** Reduce `performance.threads`, set `performance.max_temperature`, and clean dust from heatsinks/fans.
- **Permission errors on Linux?** Run `sudo setcap cap_sys_nice=eip ./oxide-miner` to allow priority adjustments without root.
- **Dashboard unreachable?** Confirm `dashboard.bind` is correct and that no other service uses the port. Use `--no-dashboard` if running headless.

---

## Development
This section targets maintainers and contributors. For end-user mining, see the guides above.

### Clone the Repository
```bash
disable-run
git clone https://github.com/raystanza/OxideMiner.git
cd OxideMiner
```

### Build from Source
OxideMiner currently targets Rust `1.75+` with nightly features for SIMD intrinsics.

```bash
disable-run
rustup toolchain install nightly
rustup component add rust-src llvm-tools-preview --toolchain nightly
cargo +nightly build --release
```

Artifacts are produced in `target/release/oxide-miner`. Use `cargo +nightly test` to run unit and integration suites. Continuous integration also runs `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo audit`.

### Project Layout
```
crates/
├── core/           # Hashing kernels, CPU feature detection
├── config/         # Strongly typed configuration loader
├── dashboard/      # Web UI and HTTP server
└── pool/           # Stratum protocol implementation
scripts/
└── packaging/      # Release packaging scripts and checksum generation
```

### Contributing
We welcome bug reports, feature requests, and pull requests:
- Open an issue describing the bug or enhancement with reproduction steps or motivations.
- Fork the repository, create a topic branch, and follow existing code style enforced by `rustfmt` and Clippy.
- Include tests where feasible, update documentation, and run the full CI suite locally (`cargo +nightly test`, `cargo fmt`, `cargo clippy`).
- Submit a pull request referencing related issues and explain your changes. Maintainers review promptly and provide feedback.

For security vulnerabilities, email the maintainers directly (see [Contact](#contact)) rather than filing a public issue.

---

## License
OxideMiner is distributed under the [MIT License](https://github.com/raystanza/OxideMiner/blob/main/LICENSE). See the `LICENSE` file for details.

## Acknowledgments
- The Monero community for maintaining a privacy-preserving cryptocurrency and robust ecosystem.
- Contributors to `rand`, `tokio`, and `hyper`, which power critical components of OxideMiner.
- Beta testers who provided early feedback on performance tuning and dashboard ergonomics.

## Contact
- Email: [maintainers@oxideminer.io](mailto:maintainers@oxideminer.io)
- Twitter: [@OxideMiner](https://twitter.com/OxideMiner)
- Matrix: `#oxideminer:matrix.org`

We are actively collecting feedback for the v0.1.0 MVP. Let us know how the miner performs on your rigs and what features you would like to see next!
