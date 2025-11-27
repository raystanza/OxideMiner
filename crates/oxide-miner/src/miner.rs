// OxideMiner/crates/oxide-miner/src/miner.rs

use crate::args::Args;
use crate::http_api::run_http_api;
use crate::stats::Stats;
use crate::util::tiny_jitter_ms;
use anyhow::{anyhow, Context, Result};
use futures::future;
use oxide_core::config::{TariMode, DEFAULT_BATCH_SIZE};
use oxide_core::stratum::{ConnectConfig, PoolJob};
use oxide_core::worker::{Share, TariWorkerSpawnConfig, WorkItem, WorkerSpawnConfig};
use oxide_core::{
    autotune_snapshot, spawn_tari_workers, spawn_workers, Config, DevFeeScheduler, HugePageStatus,
    MergeMiningTemplate, ProxyConfig, StratumClient, TariAlgorithm, TariMergeMiningClient,
    DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::{atomic::Ordering, Arc};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivePool {
    User,
    Dev,
}

impl ActivePool {
    fn is_dev(self) -> bool {
        matches!(self, ActivePool::Dev)
    }

    fn label(self) -> &'static str {
        match self {
            ActivePool::User => "user",
            ActivePool::Dev => "devfee",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PendingShare {
    is_devfee: bool,
    job_id: String,
}

#[derive(Clone, Copy)]
struct PoolConnectionSettings<'a> {
    pool: &'a str,
    wallet: &'a str,
    pass: &'a str,
    agent: &'a str,
    tls: bool,
    tls_ca_cert: Option<&'a Path>,
    tls_cert_sha256: Option<&'a [u8; 32]>,
    proxy: Option<&'a ProxyConfig>,
}

impl<'a> PoolConnectionSettings<'a> {
    fn as_connect_config(self) -> ConnectConfig<'a> {
        ConnectConfig {
            hostport: self.pool,
            wallet: self.wallet,
            pass: self.pass,
            agent: self.agent,
            use_tls: self.tls,
            custom_ca_path: self.tls_ca_cert,
            pinned_cert_sha256: self.tls_cert_sha256,
            proxy: self.proxy,
        }
    }
}

#[derive(Debug, Clone)]
struct PoolRequirements {
    monero_pool: Option<String>,
    monero_wallet: Option<String>,
    tari_pool: Option<String>,
    tari_wallet: Option<String>,
}

fn validate_tari_algorithm_for_mode(mode: TariMode, algorithm: TariAlgorithm) -> Result<()> {
    if matches!(mode, TariMode::Proxy) && algorithm == TariAlgorithm::Sha3x {
        return Err(anyhow!(
            "SHA3x is not supported in Tari proxy mode; use RandomX or switch to Tari pool mode"
        ));
    }
    Ok(())
}

fn validate_pool_requirements(args: &Args, tari_mode: TariMode) -> Result<PoolRequirements> {
    let tari_pool = args.tari_pool_url.clone();
    let tari_wallet = args.tari_wallet_address.clone();

    match tari_mode {
        TariMode::Pool => {
            let tari_pool = tari_pool.ok_or_else(|| {
                anyhow!("Tari pool mode requires --tari-pool-url or [tari].pool_url")
            })?;
            let tari_wallet = tari_wallet.ok_or_else(|| {
                anyhow!("Tari pool mode requires --tari-wallet-address or [tari].wallet_address")
            })?;

            match (&args.pool, &args.wallet) {
                (Some(pool), Some(wallet)) => Ok(PoolRequirements {
                    monero_pool: Some(pool.clone()),
                    monero_wallet: Some(wallet.clone()),
                    tari_pool: Some(tari_pool),
                    tari_wallet: Some(tari_wallet),
                }),
                (None, None) => Ok(PoolRequirements {
                    monero_pool: None,
                    monero_wallet: None,
                    tari_pool: Some(tari_pool),
                    tari_wallet: Some(tari_wallet),
                }),
                _ => Err(anyhow!(
                    "Provide both --url and --user together for Monero mining or omit both when using Tari pool mode"
                )),
            }
        }
        TariMode::None | TariMode::Proxy => {
            let pool = args
                .pool
                .clone()
                .ok_or_else(|| anyhow!("--url <POOL> is required for Monero mining"))?;
            let wallet = args
                .wallet
                .clone()
                .ok_or_else(|| anyhow!("--user <WALLET> is required for Monero mining"))?;

            Ok(PoolRequirements {
                monero_pool: Some(pool),
                monero_wallet: Some(wallet),
                tari_pool,
                tari_wallet,
            })
        }
    }
}

struct ShareContext<'a> {
    client: &'a mut StratumClient,
    stats: &'a Arc<Stats>,
    active_pool: &'a mut ActivePool,
    valid_job_ids: &'a mut HashSet<String>,
    seen_nonces: &'a mut HashMap<String, HashSet<u32>>,
    pending_shares: &'a mut HashMap<u64, PendingShare>,
    jobs_tx: &'a tokio::sync::broadcast::Sender<WorkItem>,
    dev_scheduler: &'a mut DevFeeScheduler,
    tari_client: Option<&'a TariMergeMiningClient>,
    tari_templates: &'a mut HashMap<String, MergeMiningTemplate>,
    /// Track the most recent Monero job blobs keyed by job_id so we can reconstruct a full block
    /// when submitting merge-mined solutions to the Tari proxy.
    monero_jobs: &'a mut HashMap<String, PoolJob>,
}

pub async fn run(args: Args) -> Result<()> {
    // Prefer RUST_LOG if set; otherwise use --debug to bump verbosity.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Keep oxide_core at debug when --debug is on, to capture worker details.
        if args.debug {
            EnvFilter::new("debug,oxide_core=debug")
        } else {
            EnvFilter::new("info")
        }
    });

    // -------- Logging: console + (when --debug) file ----------
    // Build a layered subscriber so we can tee to stdout and to a file.
    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(true)
        .with_ansi(true); // pretty ANSI for terminal

    // Only create the file appender when --debug is set.
    let _file_guard; // keep in scope to flush asynchronously until process exit
    if args.debug {
        // Ensure ./logs exists (ignore error if it already does)
        let _ = std::fs::create_dir_all("logs");
        // Daily-rotating file under ./logs/
        let file_appender = tracing_appender::rolling::daily("logs", "oxide-miner.log");
        let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
        _file_guard = guard;

        let file_layer = fmt::layer()
            .with_ansi(false) // no color codes in files
            .with_writer(file_writer)
            .with_target(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .with(file_layer)
            .init();

        tracing::info!("debug logging enabled; writing rotating logs under ./logs/");
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .init();
    }
    // ----------------------------------------------------------

    if args.benchmark {
        let snap = autotune_snapshot();
        let features = snap.cpu_features;
        let hp_status = snap.huge_page_status.clone();

        // Threads (auto vs custom)
        let auto_threads = snap.suggested_threads;
        let n_workers = args.threads.unwrap_or(auto_threads);
        let thread_mode = if args.threads.is_some() {
            "custom"
        } else {
            "auto"
        };

        // Batch size (auto vs custom)
        let (batch_size, batch_mode) = match args.batch_size {
            Some(n) => (n, "custom"),
            None => (snap.recommended_batch_size, "auto"),
        };

        // Huge pages (intent vs capability)
        let large_pages_supported =
            hp_status.enabled() && hp_status.dataset_fits(snap.dataset_bytes);
        let large_pages = args.huge_pages && large_pages_supported;
        if args.huge_pages && !large_pages_supported {
            warn_huge_page_limit(&hp_status, snap.dataset_bytes);
        }

        let yield_between_batches = !args.no_yield;

        // Cache/NUMA/memory context
        let l1_kib = snap.cache.l1_data.map(|lvl| (lvl.size_bytes as u64) / 1024);
        let l2_kib = snap.cache.l2.map(|lvl| (lvl.size_bytes as u64) / 1024);
        let l3_mib = snap.l3_bytes.map(|b| (b as u64) / (1024 * 1024));
        let avail_mib = snap.available_bytes / (1024 * 1024);
        let numa_known = snap.numa_nodes.is_some();
        let numa_nodes = snap.numa_nodes.unwrap_or(1);

        // Define benchmark duration
        const BENCH_SECONDS: u32 = 20;

        // Explanatory, multi-line summary for humans, with structured fields for tools.
        tracing::info!(
            // Structured fields (easy to grep/parse)
            cores = snap.physical_cores,
            l1_kib = l1_kib.unwrap_or(0),
            l2_kib = l2_kib.unwrap_or(0),
            l3_mib = l3_mib.unwrap_or(0),
            mem_avail_mib = avail_mib,
            aes = features.aes_ni,
            ssse3 = features.ssse3,
            avx2 = features.avx2,
            avx512f = features.avx512f,
            prefetch = features.prefetch_sse,
            numa_nodes,
            numa_known,
            large_pages,
            batch_size,
            batch_mode,
            recommended_batch = snap.recommended_batch_size,
            auto_threads,
            threads = n_workers,
            thread_mode,
            yield_between_batches,
            "\nRandomX benchmark setup:\n\n\
            • Benchmark duration: {} seconds (fixed).\n\
            • Threads: {} ({}). Auto chooses ~L3-capacity-per-thread to avoid cache thrash.\n\
            • Batch size: {} hashes ({}; recommended {}). Larger batches cut per-share overhead but can increase latency and memory pressure.\n\
            • CPU features: AES-NI={}, SSSE3={}, AVX2={}, AVX-512F={}, Prefetch={}.\n\
            • Cache (per core unless noted): L1={} KiB, L2={} KiB, L3={} MiB (shared). RandomX is memory-hard; more cache lets us run more threads without stalls.\n\
            • NUMA nodes: {} (known={}). On multi-socket systems, keeping threads/data local to a node reduces remote memory penalties.\n\
            • Large pages: {}.\n\
            • Yield between batches: {}.\n\
            \n\n--- structured fields for tooling below ---\n",
            BENCH_SECONDS,
            n_workers, thread_mode,
            batch_size, batch_mode, snap.recommended_batch_size,
            features.aes_ni, features.ssse3, features.avx2, features.avx512f, features.prefetch_sse,
            l1_kib.unwrap_or(0), l2_kib.unwrap_or(0), l3_mib.unwrap_or(0),
            numa_nodes, numa_known,
            large_pages,
            yield_between_batches
        );

        // Run the benchmark

        let hps = oxide_core::run_benchmark(
            n_workers,
            BENCH_SECONDS.into(),
            large_pages,
            batch_size,
            yield_between_batches,
        )
        .await?;

        // Result: concise human line + structured fields
        tracing::info!(
            "RandomX benchmark result (approx.): {:.2} H/s over {}s",
            hps,
            BENCH_SECONDS
        );

        return Ok(());
    }

    let dashboard_dir = args.dashboard_dir.clone();

    if !args.tls && (args.tls_ca_cert.is_some() || args.tls_cert_sha256.is_some()) {
        return Err(anyhow!(
            "--tls-ca-cert and --tls-cert-sha256 require --tls to be enabled"
        ));
    }

    let tls_cert_sha256 = args
        .tls_cert_sha256
        .as_ref()
        .map(|fp| {
            let normalized: String = fp
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':')
                .collect();
            let bytes = hex::decode(&normalized).with_context(|| {
                format!("invalid --tls-cert-sha256 value (expected 64 hex chars): {fp}")
            })?;
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "--tls-cert-sha256 must decode to 32 bytes (64 hex characters)"
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .transpose()?;

    let tari_mode = match args.tari_mode.as_str() {
        "none" => TariMode::None,
        "proxy" => TariMode::Proxy,
        "pool" => TariMode::Pool,
        other => return Err(anyhow!("unsupported --tari-mode value: {other}")),
    };

    let pool_requirements = validate_pool_requirements(&args, tari_mode)?;

    let tari_algorithm = args
        .tari_algorithm
        .as_deref()
        .map(TariAlgorithm::from_str)
        .unwrap_or_else(|| Ok(TariAlgorithm::default_randomx()))?;

    if matches!(tari_mode, TariMode::None) && tari_algorithm != TariAlgorithm::RandomX {
        tracing::warn!(
            algo = %tari_algorithm,
            "ignoring Tari algorithm selection because Tari mining is disabled",
        );
    }

    validate_tari_algorithm_for_mode(tari_mode, tari_algorithm)?;

    let mut cfg = Config {
        pool: pool_requirements.monero_pool.clone(),
        wallet: pool_requirements.monero_wallet.clone(),
        pass: Some(args.pass),
        threads: args.threads,
        enable_devfee: true,
        tls: args.tls,
        tls_ca_cert: args.tls_ca_cert.clone(),
        tls_cert_sha256,
        api_port: args.api_port,
        affinity: args.affinity,
        huge_pages: args.huge_pages,
        // Keep a benign placeholder; we’ll finalize after autotune snapshot
        // so we can decide between user-specified vs recommended.
        // Using DEFAULT here keeps structure consistent before we set the final value.
        batch_size: DEFAULT_BATCH_SIZE,
        yield_between_batches: !args.no_yield,
        agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
        proxy: args.proxy.clone(),
        tari: oxide_core::config::TariConfig {
            mode: tari_mode,
            enabled: Some(args.tari_merge_mining),
            pool_url: pool_requirements.tari_pool.clone(),
            wallet_address: pool_requirements.tari_wallet.clone(),
            rig_id: args.tari_rig_id.clone(),
            login: args.tari_login.clone(),
            password: args.tari_password.clone(),
            algorithm: tari_algorithm,
            merge_mining: oxide_core::config::TariMergeMiningConfig {
                proxy_url: args.tari_proxy_url.clone(),
                monero_wallet_address: args.tari_monero_wallet.clone(),
                ..Default::default()
            },
        },
    };

    let proxy_cfg = cfg
        .proxy
        .as_ref()
        .map(|url| ProxyConfig::parse(url))
        .transpose()?;

    if let Some(proxy) = proxy_cfg.as_ref() {
        tracing::info!(proxy = %proxy.redacted(), "routing stratum traffic via SOCKS5 proxy");
    }

    // Take snapshot to log how auto-tune decided thread count and batch recommendation.
    let snap = autotune_snapshot();
    let features = snap.cpu_features;
    let hp_status = snap.huge_page_status.clone();
    let auto_threads = snap.suggested_threads;
    let n_workers = cfg.threads.unwrap_or(auto_threads);

    // One-line summary that's easy to read in logs
    let l1_kib = snap.cache.l1_data.map(|lvl| (lvl.size_bytes as u64) / 1024);
    let l2_kib = snap.cache.l2.map(|lvl| (lvl.size_bytes as u64) / 1024);
    let l3_mib = snap.l3_bytes.map(|b| (b as u64) / (1024 * 1024));
    let avail_mib = snap.available_bytes / (1024 * 1024);
    let aes = features.aes_ni;
    let ssse3 = features.ssse3;
    let avx2 = features.avx2;
    let avx512f = features.avx512f;
    let prefetch = features.prefetch_sse;
    let numa_known = snap.numa_nodes.is_some();
    let numa_nodes = snap.numa_nodes.unwrap_or(1);

    // Determine batch size & mode
    // If the user provided --batch-size, that takes precedence; otherwise use the recommendation.
    let user_batch = args.batch_size; // Option<usize>
    let batch_overridden = user_batch.is_some();
    cfg.batch_size = user_batch.unwrap_or(snap.recommended_batch_size);
    let batch_mode = if batch_overridden { "custom" } else { "auto" };

    // If spawn call passes a 'large_pages' boolean, prefer user opt-in AND OS support
    // Can we actually use huge pages? (OS enabled + dataset fits)
    let large_pages_supported = hp_status.enabled() && hp_status.dataset_fits(snap.dataset_bytes);

    // Will we use huge pages? (user asked AND supported)
    let large_pages = cfg.huge_pages && large_pages_supported;

    // Warn only if the user asked for huge pages but we can’t provide them.
    if cfg.huge_pages && !large_pages_supported {
        warn_huge_page_limit(&hp_status, snap.dataset_bytes);
    }

    // Thread mode: "custom" if user provided --threads, else "auto"
    let thread_mode = if cfg.threads.is_some() {
        "custom"
    } else {
        "auto"
    };

    // Explanatory, multi-line summary for humans, with structured fields for tools.
    tracing::info!(
        // Structured fields (easy to grep/parse)
        cores = snap.physical_cores,
        l1_kib = l1_kib.unwrap_or(0),
        l2_kib = l2_kib.unwrap_or(0),
        l3_mib = l3_mib.unwrap_or(0),
        mem_avail_mib = avail_mib,
        aes,
        ssse3,
        avx2,
        avx512f,
        prefetch,
        numa_nodes,
        numa_known,
        large_pages,
        batch_size = cfg.batch_size,
        batch_mode,
        recommended_batch = snap.recommended_batch_size,
        auto_threads,
        threads = n_workers,
        thread_mode,
        yield_between_batches = cfg.yield_between_batches,
        "\nCPU tuning summary:\n\n\
        • Threads: {} ({}). Auto chooses ~L3-capacity-per-thread to avoid cache thrash.\n\
        • Batch size: {} hashes ({}; recommended {}). Larger batches cut per-share overhead but can increase latency and memory pressure.\n\
        • CPU features: AES-NI={}, SSSE3={}, AVX2={}, AVX-512F={}, Prefetch={}.\n\
        • Cache (per core unless noted): L1={} KiB, L2={} KiB, L3={} MiB (shared). RandomX is memory-hard; more cache lets us run more threads without stalls.\n\
        • NUMA nodes: {} (known={}). On multi-socket systems, keeping threads/data local to a node reduces remote memory penalties.\n\
        • Large pages: {}. Reduces TLB misses for the RandomX dataset and can improve throughput when the dataset fits.\n\
        • Yield between batches: {}. Keeps the miner friendly on shared machines.\n\
        \n\n--- structured fields for tooling below ---\n",
        n_workers, thread_mode,
        cfg.batch_size, batch_mode, snap.recommended_batch_size,
        aes, ssse3, avx2, avx512f, prefetch,
        l1_kib.unwrap_or(0), l2_kib.unwrap_or(0), l3_mib.unwrap_or(0),
        numa_nodes, numa_known,
        large_pages,
        cfg.yield_between_batches
    );

    // Optional explicit breadcrumbs, as you have:
    if let Some(user_t) = cfg.threads {
        tracing::info!("tuning override: user set threads={}", user_t);
    }
    if batch_overridden {
        tracing::info!("tuning override: user set batch_size={}", cfg.batch_size);
    }

    let tari_mode = cfg.tari.effective_mode();
    let stats = Arc::new(Stats::new(
        cfg.pool.clone().or_else(|| cfg.tari.pool_url.clone()),
        cfg.tls,
        matches!(tari_mode, TariMode::Proxy | TariMode::Pool),
        cfg.tari.pool_url.clone(),
    ));

    let (tari_jobs_tx, tari_shares_rx, _tari_workers) = if matches!(tari_mode, TariMode::Pool) {
        let (tx, _rx0) = tokio::sync::broadcast::channel(64);
        let (tari_shares_tx, tari_shares_rx) = tokio::sync::mpsc::unbounded_channel::<Share>();
        let workers = spawn_tari_workers(
            n_workers,
            TariWorkerSpawnConfig {
                jobs_tx: tx.clone(),
                shares_tx: tari_shares_tx,
                affinity: cfg.affinity,
                large_pages,
                batch_size: cfg.batch_size,
                yield_between_batches: cfg.yield_between_batches,
                hash_counter: stats.tari_hashes.clone(),
                algorithm: cfg.tari.algorithm,
            },
        )?;
        (Some(tx), Some(tari_shares_rx), Some(workers))
    } else {
        (None, None, None)
    };

    if cfg.threads.is_none() {
        tracing::info!("auto-selected {} worker threads", n_workers);
    }
    let tari_client = if matches!(tari_mode, TariMode::Proxy) {
        match TariMergeMiningClient::new(cfg.tari.merge_mining_config()) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!("failed to initialize Tari merge mining client: {e}");
                None
            }
        }
    } else {
        None
    };
    let mut tari_templates: HashMap<String, MergeMiningTemplate> = HashMap::new();
    let mut monero_jobs: HashMap<String, PoolJob> = HashMap::new();

    let monero_enabled = cfg.pool.is_some() && cfg.wallet.is_some();

    let tls = cfg.tls;
    let tls_ca_cert = cfg.tls_ca_cert.clone();
    let tls_cert_sha256 = cfg.tls_cert_sha256;

    tracing::info!("dev fee enabled at {} bps (1%)", DEV_FEE_BASIS_POINTS);

    // Optional HTTP API
    if let Some(port) = cfg.api_port {
        let s = stats.clone();
        let dir = dashboard_dir.clone();
        tokio::spawn(async move {
            run_http_api(port, s, dir).await;
        });
    }

    // Snapshot flags for the async task
    // Pool IO task with reconnect loop
    let proxy_cfg = proxy_cfg.clone();
    let pool_handle = if monero_enabled {
        let (jobs_tx, _jobs_rx0) = tokio::sync::broadcast::channel(64);
        // MPSC: shares <- workers
        let (shares_tx, shares_rx) = tokio::sync::mpsc::unbounded_channel::<Share>();

        let _workers = spawn_workers(
            n_workers,
            WorkerSpawnConfig {
                jobs_tx: jobs_tx.clone(),
                shares_tx,
                affinity: cfg.affinity,
                large_pages,
                batch_size: cfg.batch_size,
                yield_between_batches: cfg.yield_between_batches,
                hash_counter: stats.hashes.clone(),
            },
        );

        let main_pool = cfg
            .pool
            .clone()
            .expect("monero pool should exist when enabled");
        let user_wallet = cfg
            .wallet
            .clone()
            .expect("monero wallet should exist when enabled");
        let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
        let agent = cfg.agent.clone();

        Some(tokio::spawn({
            let jobs_tx = jobs_tx.clone();
            let mut shares_rx = shares_rx;
            let stats = stats.clone();
            let main_pool = main_pool.clone();
            let user_wallet = user_wallet.clone();
            let pass = pass.clone();
            let agent = agent.clone();
            let proxy_cfg = proxy_cfg.clone();

            async move {
                let tls_ca_cert = tls_ca_cert.clone();
                let tls_cert_sha256 = tls_cert_sha256;
                let mut backoff_ms = 1_000u64;
                let mut dev_scheduler = DevFeeScheduler::new();

                loop {
                    let user_connection = PoolConnectionSettings {
                        pool: &main_pool,
                        wallet: &user_wallet,
                        pass: &pass,
                        agent: &agent,
                        tls,
                        tls_ca_cert: tls_ca_cert.as_deref(),
                        tls_cert_sha256: tls_cert_sha256.as_ref(),
                        proxy: proxy_cfg.as_ref(),
                    };
                    stats.pool_connected.store(false, Ordering::Relaxed);
                    let (mut client, initial_job) =
                        match StratumClient::connect_and_login(user_connection.as_connect_config())
                            .await
                        {
                            Ok(v) => {
                                backoff_ms = 1_000;
                                stats.pool_connected.store(true, Ordering::Relaxed);
                                v
                            }
                            Err(e) => {
                                tracing::error!(
                                    "connect/login failed; retrying in {}s: {e}",
                                    backoff_ms / 1000
                                );
                                sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms = (backoff_ms * 2).min(60_000);
                                continue;
                            }
                        };

                    let mut valid_job_ids: HashSet<String> = HashSet::new();
                    let mut seen_nonces: HashMap<String, HashSet<u32>> = HashMap::new();
                    let mut pending_shares: HashMap<u64, PendingShare> = HashMap::new();
                    let mut active_pool = ActivePool::User;

                    if let Some(job) = initial_job {
                        let tari_template =
                            maybe_fetch_tari_template(tari_client.as_ref(), &stats).await;
                        let job_id = broadcast_job(
                            job,
                            active_pool.is_dev(),
                            true,
                            &jobs_tx,
                            &mut valid_job_ids,
                            &mut seen_nonces,
                            &mut tari_templates,
                            tari_template,
                            &mut monero_jobs,
                        );
                        if scheduler_tick(&mut dev_scheduler, &job_id, active_pool) {
                            let counter = dev_scheduler.counter();
                            let interval = dev_scheduler.interval();
                            tracing::info!(
                                job_id = %job_id,
                                counter,
                                interval,
                                "devfee activation triggered (initial job)"
                            );
                            match connect_with_retries(
                                PoolConnectionSettings {
                                    pool: &main_pool,
                                    wallet: DEV_WALLET_ADDRESS,
                                    pass: &pass,
                                    agent: &agent,
                                    tls,
                                    tls_ca_cert: tls_ca_cert.as_deref(),
                                    tls_cert_sha256: tls_cert_sha256.as_ref(),
                                    proxy: proxy_cfg.as_ref(),
                                },
                                3,
                                "devfee",
                            )
                            .await
                            {
                                Ok((new_client, dev_job)) => {
                                    if let Err(e) = handle_shares(
                                        None,
                                        &mut shares_rx,
                                        ShareContext {
                                            client: &mut client,
                                            stats: &stats,
                                            active_pool: &mut active_pool,
                                            valid_job_ids: &mut valid_job_ids,
                                            seen_nonces: &mut seen_nonces,
                                            pending_shares: &mut pending_shares,
                                            jobs_tx: &jobs_tx,
                                            dev_scheduler: &mut dev_scheduler,
                                            tari_client: tari_client.as_ref(),
                                            tari_templates: &mut tari_templates,
                                            monero_jobs: &mut monero_jobs,
                                        },
                                        user_connection,
                                    )
                                    .await
                                    {
                                        tracing::warn!(
                                            error = %e,
                                            "failed to flush pending shares before devfee switch"
                                        );
                                    }
                                    client = new_client;
                                    active_pool = ActivePool::Dev;
                                    reset_session(
                                        &mut valid_job_ids,
                                        &mut seen_nonces,
                                        &mut pending_shares,
                                        &mut tari_templates,
                                        &mut monero_jobs,
                                    );
                                    if let Some(job) = dev_job {
                                        let tari_template =
                                            maybe_fetch_tari_template(tari_client.as_ref(), &stats)
                                                .await;
                                        let dev_job_id = broadcast_job(
                                            job,
                                            true,
                                            true,
                                            &jobs_tx,
                                            &mut valid_job_ids,
                                            &mut seen_nonces,
                                            &mut tari_templates,
                                            tari_template,
                                            &mut monero_jobs,
                                        );
                                        tracing::info!(job_id = %dev_job_id, "devfee activated for job");
                                        let _ = scheduler_tick(
                                            &mut dev_scheduler,
                                            &dev_job_id,
                                            active_pool,
                                        );
                                    } else {
                                        tracing::debug!("devfee activated; awaiting first job");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "devfee connect failed");
                                    dev_scheduler.revert_last_job();
                                }
                            }
                        }
                    }

                    loop {
                        tokio::select! {
                            biased;
                            maybe_share = shares_rx.recv() => {
                                match maybe_share {
                                    Some(share) => {
                                        if let Err(e) = handle_shares(
                                            Some(share),
                                            &mut shares_rx,
                                            ShareContext {
                                                client: &mut client,
                                                stats: &stats,
                                                active_pool: &mut active_pool,
                                                valid_job_ids: &mut valid_job_ids,
                                                seen_nonces: &mut seen_nonces,
                                                pending_shares: &mut pending_shares,
                                                jobs_tx: &jobs_tx,
                                                dev_scheduler: &mut dev_scheduler,
                                                tari_client: tari_client.as_ref(),
                                                tari_templates: &mut tari_templates,
                                                monero_jobs: &mut monero_jobs,
                                            },
                                            user_connection,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                error = %e,
                                                "error handling share; reconnecting"
                                            );
                                            stats.pool_connected.store(false, Ordering::Relaxed);
                                            break;
                                        }
                                        continue;
                                    }
                                    None => {
                                        tracing::warn!("shares channel closed (no workers alive); stopping pool task to avoid reconnect storm");
                                        return;
                                    }
                                }
                            }

                            msg = client.read_json() => {
                                match msg {
                                    Ok(v) => {
                                        if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                            let mut trigger_dev = false;
                                            let mut trigger_job_id = String::new();
                                            if let Some(params) = v.get("params") {
                                                if let Ok(job) = serde_json::from_value::<PoolJob>(params.clone()) {
                                                    let clean = params.get("clean_jobs").and_then(|x| x.as_bool()).unwrap_or(true);
                                                    let tari_template = maybe_fetch_tari_template(
                                                        tari_client.as_ref(),
                                                        &stats,
                                                    )
                                                    .await;
                                                    let job_id = broadcast_job(
                                                        job,
                                                        active_pool.is_dev(),
                                                        clean,
                                                        &jobs_tx,
                                                        &mut valid_job_ids,
                                                        &mut seen_nonces,
                                                        &mut tari_templates,
                                                        tari_template,
                                                        &mut monero_jobs,
                                                    );
                                                    trigger_dev = scheduler_tick(&mut dev_scheduler, &job_id, active_pool);
                                                    if trigger_dev {
                                                        trigger_job_id = job_id;
                                                    }
                                                }
                                            }

                                            if trigger_dev {
                                                let counter = dev_scheduler.counter();
                                                let interval = dev_scheduler.interval();
                                                tracing::info!(
                                                    job_id = %trigger_job_id,
                                                    counter,
                                                    interval,
                                                    "devfee activation triggered"
                                                );
                                                match connect_with_retries(
                                                    PoolConnectionSettings {
                                                        pool: &main_pool,
                                                        wallet: DEV_WALLET_ADDRESS,
                                                        pass: &pass,
                                                        agent: &agent,
                                                        tls,
                                                        tls_ca_cert: tls_ca_cert.as_deref(),
                                                        tls_cert_sha256: tls_cert_sha256.as_ref(),
                                                        proxy: proxy_cfg.as_ref(),
                                                    },
                                                    3,
                                                    "devfee",
                                                ).await {
                                                    Ok((new_client, job_opt)) => {
                                                        if let Err(e) = handle_shares(
                                                            None,
                                                            &mut shares_rx,
                                                            ShareContext {
                                                                client: &mut client,
                                                                stats: &stats,
                                                                active_pool: &mut active_pool,
                                                                valid_job_ids: &mut valid_job_ids,
                                                                seen_nonces: &mut seen_nonces,
                                                                pending_shares: &mut pending_shares,
                                                                jobs_tx: &jobs_tx,
                                                                dev_scheduler: &mut dev_scheduler,
                                                                tari_client: tari_client.as_ref(),
                                                                tari_templates: &mut tari_templates,
                                                                monero_jobs: &mut monero_jobs,
                                                            },
                                                            user_connection,
                                                        )
                                                        .await
                                                        {
                                                            tracing::warn!(
                                                                error = %e,
                                                                "failed to flush pending shares before devfee switch"
                                                            );
                                                        }
                                                        client = new_client;
                                                        active_pool = ActivePool::Dev;
                                                        reset_session(
                                                            &mut valid_job_ids,
                                                            &mut seen_nonces,
                                                            &mut pending_shares,
                                                            &mut tari_templates,
                                                            &mut monero_jobs,
                                                        );
                                                        if let Some(job) = job_opt {
                                                            let tari_template =
                                                                maybe_fetch_tari_template(
                                                                    tari_client.as_ref(),
                                                                    &stats,
                                                                )
                                                                .await;
                                                            let job_id = broadcast_job(
                                                                job,
                                                                true,
                                                                true,
                                                                &jobs_tx,
                                                                &mut valid_job_ids,
                                                                &mut seen_nonces,
                                                                &mut tari_templates,
                                                                tari_template,
                                                                &mut monero_jobs,
                                                            );
                                                            tracing::info!(job_id = %job_id, "devfee activated for job");
                                                            let _ = scheduler_tick(&mut dev_scheduler, &job_id, active_pool);
                                                        } else {
                                                            tracing::debug!("devfee activated; awaiting first job");
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(error = %e, "devfee connect failed");
                                                        dev_scheduler.revert_last_job();
                                                    }
                                                }
                                            }
                                        } else if v.get("result").is_none() {
                                            if let Some(err) = v.get("error") {
                                                tracing::warn!(error = %err, "pool error response");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!("pool read error: {e}; reconnecting");
                                        sleep(Duration::from_millis(tiny_jitter_ms())).await;
                                        stats.pool_connected.store(false, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }))
    } else {
        tracing::info!("Monero pool URL and wallet not provided; Monero stratum mining disabled");
        None
    };

    let tari_pool_handle = match (tari_mode, tari_jobs_tx.clone(), tari_shares_rx) {
        (TariMode::Pool, Some(tari_jobs_tx), Some(mut tari_shares_rx)) => {
            if cfg.tari.pool_url.is_none() {
                tracing::error!("Tari pool mode selected but no --tari-pool-url provided");
                return Err(anyhow!("tari pool url missing"));
            }

            if cfg.tari.wallet_address.is_none() {
                tracing::error!("Tari pool mode selected but no --tari-wallet-address provided");
                return Err(anyhow!("tari wallet address missing"));
            }

            let tari_pool = cfg.tari.pool_url.clone().unwrap();
            let tari_wallet = cfg.tari.wallet_address.clone().unwrap();
            let tari_login = cfg
                .tari
                .login
                .clone()
                .unwrap_or_else(|| tari_wallet.clone());
            let tari_pass = cfg
                .tari
                .password
                .clone()
                .unwrap_or_else(|| cfg.pass.clone().unwrap_or_else(|| "x".to_string()));
            let tari_rig = cfg.tari.rig_id.clone();
            let tari_agent = format!("{} (tari)", cfg.agent);
            let tls_ca_cert = cfg.tls_ca_cert.clone();
            let tls_cert_sha256 = cfg.tls_cert_sha256;
            let proxy_cfg = proxy_cfg.clone();
            let stats = stats.clone();

            Some(tokio::spawn(async move {
                let mut backoff_ms = 1_000u64;
                loop {
                    let login = if let Some(rig) = tari_rig.as_ref() {
                        format!("{tari_login}.{rig}")
                    } else {
                        tari_login.clone()
                    };

                    let conn = PoolConnectionSettings {
                        pool: &tari_pool,
                        wallet: &login,
                        pass: &tari_pass,
                        agent: &tari_agent,
                        tls,
                        tls_ca_cert: tls_ca_cert.as_deref(),
                        tls_cert_sha256: tls_cert_sha256.as_ref(),
                        proxy: proxy_cfg.as_ref(),
                    };

                    stats.tari_pool_connected.store(false, Ordering::Relaxed);

                    let (mut client, initial_job) =
                        match StratumClient::connect_and_login(conn.as_connect_config()).await {
                            Ok(v) => {
                                stats.tari_pool_connected.store(true, Ordering::Relaxed);
                                backoff_ms = 1_000;
                                v
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Tari pool connect/login failed; retrying in {}s: {e}",
                                    backoff_ms / 1000
                                );
                                sleep(Duration::from_millis(backoff_ms)).await;
                                backoff_ms = (backoff_ms * 2).min(60_000);
                                continue;
                            }
                        };

                    let mut valid_job_ids: HashSet<String> = HashSet::new();
                    let mut seen_nonces: HashMap<String, HashSet<u32>> = HashMap::new();
                    let mut pending_shares: HashMap<u64, String> = HashMap::new();

                    if let Some(job) = initial_job {
                        let job_id = broadcast_simple_job(
                            job,
                            true,
                            &tari_jobs_tx,
                            &mut valid_job_ids,
                            &mut seen_nonces,
                        );
                        tracing::info!(job_id = %job_id, "received initial Tari pool job");
                    }

                    loop {
                        tokio::select! {
                            maybe_share = tari_shares_rx.recv() => {
                                let Some(share) = maybe_share else { break; };
                                if !valid_job_ids.contains(&share.job_id) {
                                    tracing::debug!(job_id = %share.job_id, "ignoring Tari share for stale job");
                                    continue;
                                }
                                let nonce_set = seen_nonces.entry(share.job_id.clone()).or_default();
                                if !nonce_set.insert(share.nonce) {
                                    tracing::debug!(job_id = %share.job_id, nonce = share.nonce, "duplicate Tari nonce");
                                    continue;
                                }

                                let nonce_hex = format!("{:08x}", share.nonce);
                                let result_hex = hex::encode(share.result);
                                match client.submit_share(&share.job_id, &nonce_hex, &result_hex).await {
                                    Ok(id) => {
                                        pending_shares.insert(id, share.job_id.clone());
                                        tracing::debug!(job_id = %share.job_id, "submitted Tari share");
                                    }
                                    Err(e) => {
                                        tracing::warn!(job_id = %share.job_id, error = %e, "failed to submit Tari share");
                                    }
                                }
                            }
                            msg = client.read_json() => {
                                match msg {
                                    Ok(v) => {
                                        if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                            if let Some(params) = v.get("params") {
                                                if let Ok(job) = serde_json::from_value::<PoolJob>(params.clone()) {
                                                    let clean = params
                                                        .get("clean")
                                                        .and_then(|c| c.as_bool())
                                                        .unwrap_or(true);
                                                    let job_id = broadcast_simple_job(
                                                        job,
                                                        clean,
                                                        &tari_jobs_tx,
                                                        &mut valid_job_ids,
                                                        &mut seen_nonces,
                                                    );
                                                    tracing::info!(job_id = %job_id, clean_jobs = clean, "new Tari pool job");
                                                }
                                            }
                                            continue;
                                        }

                                        if let Some(id) = v.get("id").and_then(|i| i.as_u64()) {
                                            if let Some(job_id) = pending_shares.remove(&id) {
                                                if v.get("result").is_some() {
                                                    stats.tari_accepted.fetch_add(1, Ordering::Relaxed);
                                                    tracing::info!(job_id = %job_id, accepted = stats.tari_accepted.load(Ordering::Relaxed), "Tari share accepted");
                                                } else {
                                                    stats.tari_rejected.fetch_add(1, Ordering::Relaxed);
                                                    tracing::warn!(job_id = %job_id, rejected = stats.tari_rejected.load(Ordering::Relaxed), "Tari share rejected");
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("Tari pool read error: {e}");
                                        stats
                                            .tari_pool_connected
                                            .store(false, Ordering::Relaxed);
                                        sleep(Duration::from_millis(tiny_jitter_ms())).await;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }))
        }
        (TariMode::Pool, _, _) => {
            tracing::warn!("Tari pool mode enabled but Tari channels were not initialized");
            None
        }
        _ => None,
    };

    // Keep the runtime alive until either the pool task ends or the user presses Ctrl+C.
    let tari_pool_future = async {
        if let Some(handle) = tari_pool_handle {
            handle.await.map_err(|e| e.into())
        } else {
            future::pending::<Result<(), anyhow::Error>>().await
        }
    };

    let pool_future = async {
        if let Some(handle) = pool_handle {
            handle.await.map_err(|e| e.into())
        } else {
            future::pending::<Result<(), anyhow::Error>>().await
        }
    };

    tokio::select! {
        res = pool_future => {
            if let Err(e) = res {
                tracing::error!("pool task ended unexpectedly: {e}");
            }
        }
        res = tari_pool_future => {
            if let Err(e) = res {
                tracing::error!("Tari pool task ended unexpectedly: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received; shutting down.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Args;
    use clap::Parser;

    #[test]
    fn tari_proxy_rejects_sha3x() {
        let err = validate_tari_algorithm_for_mode(TariMode::Proxy, TariAlgorithm::Sha3x)
            .expect_err("proxy mode must reject sha3x");
        assert!(err
            .to_string()
            .contains("SHA3x is not supported in Tari proxy mode"));
    }

    #[test]
    fn tari_pool_allows_sha3x() {
        validate_tari_algorithm_for_mode(TariMode::Pool, TariAlgorithm::Sha3x)
            .expect("pool mode should allow sha3x");
    }

    #[test]
    fn tari_pool_mode_allows_missing_monero_pool() {
        let args = Args::parse_from([
            "test",
            "--tari-mode",
            "pool",
            "--tari-pool-url",
            "stratum+tcp://tari.pool:4000",
            "--tari-wallet-address",
            "tari_wallet",
        ]);

        let reqs =
            validate_pool_requirements(&args, TariMode::Pool).expect("valid tari pool inputs");
        assert!(reqs.monero_pool.is_none());
        assert!(reqs.monero_wallet.is_none());
        assert_eq!(
            reqs.tari_pool.as_deref(),
            Some("stratum+tcp://tari.pool:4000")
        );
        assert_eq!(reqs.tari_wallet.as_deref(), Some("tari_wallet"));
    }

    #[test]
    fn tari_pool_mode_requires_tari_fields() {
        let args = Args::parse_from(["test", "--tari-mode", "pool"]);
        assert!(validate_pool_requirements(&args, TariMode::Pool).is_err());
    }

    #[test]
    fn monero_fields_required_outside_tari_pool() {
        let args = Args::parse_from(["test"]);
        assert!(validate_pool_requirements(&args, TariMode::None).is_err());
    }
}

fn warn_huge_page_limit(status: &HugePageStatus, dataset_bytes: u64) {
    if !status.supported {
        tracing::warn!(
            "Huge pages are NOT enabled; RandomX performance may be reduced. \
            Linux: configure vm.nr_hugepages; Windows: enable 'Lock pages in memory' and Large Pages."
        );
    } else if !status.has_privilege {
        tracing::warn!(
            "Huge pages support detected but the current process lacks permission. \
            Windows: grant the 'Lock pages in memory' privilege to the user running OxideMiner."
        );
    } else if !status.enabled() {
        tracing::warn!(
            "Huge pages are configured but no free huge pages are available. \
            Reserve huge pages via vm.nr_hugepages before starting the miner."
        );
    } else if !status.dataset_fits(dataset_bytes) {
        let free = status.free_bytes.unwrap_or(0);
        tracing::warn!(
            free_bytes = free,
            required_bytes = dataset_bytes,
            "Huge page pool is too small for the RandomX dataset; continuing without huge pages",
        );
    }
}

fn broadcast_job(
    mut job: PoolJob,
    is_devfee: bool,
    clean_jobs: bool,
    jobs_tx: &tokio::sync::broadcast::Sender<WorkItem>,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    tari_templates: &mut HashMap<String, MergeMiningTemplate>,
    tari_template: Option<MergeMiningTemplate>,
    monero_jobs: &mut HashMap<String, PoolJob>,
) -> String {
    if clean_jobs {
        valid_job_ids.clear();
        seen_nonces.clear();
        tari_templates.clear();
        monero_jobs.clear();
    }

    job.cache_target();
    let job_id = job.job_id.clone();
    let job_clone = job.clone();
    let _ = jobs_tx.send(WorkItem { job, is_devfee });
    valid_job_ids.insert(job_id.clone());
    if let Some(template) = tari_template {
        tari_templates.insert(job_id.clone(), template);
    }
    // Track the Monero job blob for later Tari submissions.
    monero_jobs.insert(job_id.clone(), job_clone);
    job_id
}

fn broadcast_simple_job(
    mut job: PoolJob,
    clean_jobs: bool,
    jobs_tx: &tokio::sync::broadcast::Sender<WorkItem>,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
) -> String {
    if clean_jobs {
        valid_job_ids.clear();
        seen_nonces.clear();
    }

    job.cache_target();
    let job_id = job.job_id.clone();
    let _ = jobs_tx.send(WorkItem {
        job,
        is_devfee: false,
    });
    valid_job_ids.insert(job_id.clone());
    job_id
}

fn scheduler_tick(scheduler: &mut DevFeeScheduler, job_id: &str, active_pool: ActivePool) -> bool {
    let donate = scheduler.should_donate();
    tracing::debug!(
        job_id = job_id,
        pool = active_pool.label(),
        counter = scheduler.counter(),
        interval = scheduler.interval(),
        donate,
        "devfee scheduler tick"
    );
    donate && matches!(active_pool, ActivePool::User)
}

async fn maybe_fetch_tari_template(
    client: Option<&TariMergeMiningClient>,
    stats: &Arc<Stats>,
) -> Option<MergeMiningTemplate> {
    let Some(client) = client else {
        return None;
    };

    match client.fetch_template().await {
        Ok(template) => {
            stats.tari_height.store(template.height, Ordering::Relaxed);
            stats
                .tari_difficulty
                .store(template.target_difficulty, Ordering::Relaxed);
            Some(template)
        }
        Err(oxide_core::tari::TariClientError::MissingAuxData) => {
            tracing::debug!(
                "Tari merge mining template fetch failed: proxy response missing Tari aux data"
            );
            None
        }
        Err(e) => {
            tracing::warn!("Tari merge mining template fetch failed: {e}");
            None
        }
    }
}

fn reset_session(
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    pending_shares: &mut HashMap<u64, PendingShare>,
    tari_templates: &mut HashMap<String, MergeMiningTemplate>,
    monero_jobs: &mut HashMap<String, PoolJob>,
) {
    valid_job_ids.clear();
    seen_nonces.clear();
    pending_shares.clear();
    tari_templates.clear();
    monero_jobs.clear();
}

async fn handle_shares(
    initial: Option<Share>,
    shares_rx: &mut UnboundedReceiver<Share>,
    context: ShareContext<'_>,
    connection: PoolConnectionSettings<'_>,
) -> Result<()> {
    let ShareContext {
        client,
        stats,
        active_pool,
        valid_job_ids,
        seen_nonces,
        pending_shares,
        jobs_tx,
        dev_scheduler,
        tari_client,
        tari_templates,
        monero_jobs,
    } = context;
    let mut reconnect_user = false;

    if let Some(share) = initial {
        reconnect_user |= submit_share_internal(
            share,
            client,
            stats,
            *active_pool,
            valid_job_ids,
            seen_nonces,
            pending_shares,
            tari_client,
            tari_templates,
            monero_jobs,
        )
        .await;
    }

    loop {
        match shares_rx.try_recv() {
            Ok(share) => {
                reconnect_user |= submit_share_internal(
                    share,
                    client,
                    stats,
                    *active_pool,
                    valid_job_ids,
                    seen_nonces,
                    pending_shares,
                    tari_client,
                    tari_templates,
                    monero_jobs,
                )
                .await;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                tracing::warn!("shares channel closed; no further shares will be processed");
                break;
            }
        }
    }

    if reconnect_user && matches!(*active_pool, ActivePool::Dev) {
        reconnect_user_pool(
            ShareContext {
                client,
                stats,
                active_pool,
                valid_job_ids,
                seen_nonces,
                pending_shares,
                jobs_tx,
                dev_scheduler,
                tari_client,
                tari_templates,
                monero_jobs,
            },
            connection,
        )
        .await?;
    }

    Ok(())
}

async fn submit_share_internal(
    share: Share,
    client: &mut StratumClient,
    stats: &Arc<Stats>,
    active_pool: ActivePool,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    pending_shares: &mut HashMap<u64, PendingShare>,
    tari_client: Option<&TariMergeMiningClient>,
    tari_templates: &mut HashMap<String, MergeMiningTemplate>,
    monero_jobs: &mut HashMap<String, PoolJob>,
) -> bool {
    if !valid_job_ids.contains(&share.job_id) {
        tracing::debug!(
            job_id = %share.job_id,
            "dropping stale share (invalid job_id for current session)"
        );
        return false;
    }

    let entry = seen_nonces.entry(share.job_id.clone()).or_default();
    if !entry.insert(share.nonce) {
        tracing::debug!(
            job_id = %share.job_id,
            nonce = share.nonce,
            "dropping duplicate share (already submitted)"
        );
        return false;
    }

    let nonce_hex = hex::encode(share.nonce.to_le_bytes());
    let result_hex = hex::encode(share.result);

    tracing::debug!(
        job_id = %share.job_id,
        nonce_hex = %nonce_hex,
        result_hex = %result_hex,
        is_devfee = share.is_devfee,
        "submit_share",
    );

    let monero_blob = monero_jobs.get(&share.job_id).map(|job| job.blob.as_str());

    let mut reconnect_user = false;
    if let Some(client) = tari_client {
        if let Some(tpl) = tari_templates.get(&share.job_id) {
            match client
                .submit_solution(tpl, &nonce_hex, &result_hex, monero_blob)
                .await
            {
                Ok(_) => {
                    stats.tari_accepted.fetch_add(1, Ordering::Relaxed);
                    stats.tari_height.store(tpl.height, Ordering::Relaxed);
                    stats
                        .tari_difficulty
                        .store(tpl.target_difficulty, Ordering::Relaxed);
                }
                Err(oxide_core::tari::TariClientError::InsufficientDifficulty { .. }) => {
                    tracing::debug!(
                        job_id = %share.job_id,
                        "share below Tari difficulty; not a candidate merge-mined block"
                    );
                }
                Err(e) => {
                    stats.tari_rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(job_id = %share.job_id, error = %e, "failed to submit Tari merge-mining solution");
                }
            }
        }
    }

    match client
        .submit_share(&share.job_id, &nonce_hex, &result_hex)
        .await
    {
        Ok(req_id) => {
            pending_shares.insert(
                req_id,
                PendingShare {
                    is_devfee: share.is_devfee,
                    job_id: share.job_id.clone(),
                },
            );
            if share.is_devfee {
                tracing::debug!(job_id = %share.job_id, req_id, "devfee share submitted");
            }
        }
        Err(e) => {
            tracing::error!(job_id = %share.job_id, error = %e, "submit_share error");
            if share.is_devfee {
                stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                reconnect_user = matches!(active_pool, ActivePool::Dev);
            } else {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    reconnect_user
}

async fn reconnect_user_pool(
    context: ShareContext<'_>,
    connection: PoolConnectionSettings<'_>,
) -> Result<()> {
    let ShareContext {
        client,
        stats,
        active_pool,
        valid_job_ids,
        seen_nonces,
        pending_shares,
        jobs_tx,
        dev_scheduler,
        tari_client,
        tari_templates,
        monero_jobs,
    } = context;
    let (new_client, job_opt) = connect_with_retries(connection, 5, "user").await?;

    *client = new_client;
    *active_pool = ActivePool::User;
    reset_session(
        valid_job_ids,
        seen_nonces,
        pending_shares,
        tari_templates,
        monero_jobs,
    );
    stats.pool_connected.store(true, Ordering::Relaxed);

    if let Some(job) = job_opt {
        let tari_template = maybe_fetch_tari_template(tari_client, stats).await;
        let job_id = broadcast_job(
            job,
            false,
            true,
            jobs_tx,
            valid_job_ids,
            seen_nonces,
            tari_templates,
            tari_template,
            monero_jobs,
        );
        let _ = scheduler_tick(dev_scheduler, &job_id, *active_pool);
    }

    Ok(())
}

async fn connect_with_retries(
    connection: PoolConnectionSettings<'_>,
    attempts: usize,
    purpose: &str,
) -> Result<(StratumClient, Option<PoolJob>)> {
    let mut attempt = 0usize;
    let mut delay_ms = tiny_jitter_ms();
    let mut last_err: Option<anyhow::Error> = None;

    while attempt < attempts {
        attempt += 1;
        match StratumClient::connect_and_login(connection.as_connect_config()).await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                last_err = Some(e);
                if attempt < attempts {
                    tracing::warn!(
                        attempt,
                        attempts,
                        delay_ms,
                        purpose,
                        "connection attempt failed; retrying"
                    );
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(5_000);
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("all {} connection attempts failed", purpose)))
}
