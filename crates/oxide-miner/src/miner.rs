// OxideMiner/crates/oxide-miner/src/miner.rs

use crate::args::{Args, LoadedConfigFile, MiningMode};
use crate::http_api::run_http_api;
use crate::solo::{unix_timestamp_seconds, RpcEndpoint, SoloRpcClient, SoloRpcError, SoloTemplate};
use crate::stats::{Stats, SubmitOutcome, SubmitRecord};
use crate::util::tiny_jitter_ms;
use anyhow::{anyhow, Context, Result};
use oxide_core::stratum::{ConnectConfig, PoolJob};
use oxide_core::worker::{Share, WorkItem, WorkerSpawnConfig};
use oxide_core::{
    autotune_snapshot, spawn_workers, Config, DevFeeScheduler, HugePageStatus, ProxyConfig,
    StratumClient, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{atomic::Ordering, Arc};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;

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

struct ShareContext<'a> {
    client: &'a mut StratumClient,
    stats: &'a Arc<Stats>,
    active_pool: &'a mut ActivePool,
    valid_job_ids: &'a mut HashSet<String>,
    seen_nonces: &'a mut HashMap<String, HashSet<u32>>,
    pending_shares: &'a mut HashMap<u64, PendingShare>,
    jobs_tx: &'a tokio::sync::broadcast::Sender<WorkItem>,
    dev_scheduler: &'a mut DevFeeScheduler,
}

pub async fn run(args: Args, config: Option<LoadedConfigFile>) -> Result<()> {
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

    if let Some(cfg_file) = config.as_ref() {
        log_config_overview(cfg_file, &args);
    }

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
        let l1i_kib = snap
            .cache
            .l1_instruction
            .map(|lvl| (lvl.size_bytes as u64) / 1024);
        let l2_kib = snap.cache.l2.map(|lvl| (lvl.size_bytes as u64) / 1024);
        let l3_mib = snap.l3_bytes.map(|b| (b as u64) / (1024 * 1024));
        let l3_summary = snap
            .cache
            .l3_summary()
            .unwrap_or_else(|| "unknown".to_string());
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
            l1i_kib = l1i_kib.unwrap_or(0),
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
            • Cache (per core unless noted): L1d={} KiB, L1i={} KiB, L2={} KiB, L3={}. RandomX is memory-hard; more cache lets us run more threads without stalls.\n\
            • NUMA nodes: {} (known={}). On multi-socket systems, keeping threads/data local to a node reduces remote memory penalties.\n\
            • Large pages: {}.\n\
            • Yield between batches: {}.\n\
            \n\n--- structured fields for tooling below ---\n",
            BENCH_SECONDS,
            n_workers, thread_mode,
            batch_size, batch_mode, snap.recommended_batch_size,
            features.aes_ni, features.ssse3, features.avx2, features.avx512f, features.prefetch_sse,
            l1_kib.unwrap_or(0), l1i_kib.unwrap_or(0), l2_kib.unwrap_or(0), l3_summary,
            numa_nodes, numa_known,
            large_pages,
            yield_between_batches
        );

        for detail in snap.cache.debug_lines() {
            tracing::debug!("cache_topology" = %detail);
        }
        for warning in &snap.cache.warnings {
            tracing::warn!("cache_topology_warning" = %warning);
        }
        if !args.affinity && !snap.cache.l3_instances.is_empty() {
            tracing::info!(
                l3_domains = snap.cache.l3_instances.len(),
                "detected multiple L3 cache domains; consider --affinity to pin workers per domain"
            );
        }

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
    let mode = args.mode;
    let rpc_endpoint = if matches!(mode, MiningMode::Solo) {
        Some(RpcEndpoint::new(
            &args.node_rpc_url,
            args.node_rpc_user.as_deref(),
            args.node_rpc_pass.as_deref(),
        )?)
    } else {
        None
    };

    if matches!(mode, MiningMode::Solo) {
        if let Some(zmq) = args.solo_zmq.as_ref() {
            tracing::warn!(
                zmq = %zmq,
                "solo ZMQ configured but not supported; polling RPC instead"
            );
        }
    }

    // Take snapshot to log how auto-tune decided thread count and batch recommendation.
    let snap = autotune_snapshot();
    let features = snap.cpu_features;
    let hp_status = snap.huge_page_status.clone();
    let auto_threads = snap.suggested_threads;
    let n_workers = args.threads.unwrap_or(auto_threads);

    // One-line summary that's easy to read in logs
    let l1_kib = snap.cache.l1_data.map(|lvl| (lvl.size_bytes as u64) / 1024);
    let l1i_kib = snap
        .cache
        .l1_instruction
        .map(|lvl| (lvl.size_bytes as u64) / 1024);
    let l2_kib = snap.cache.l2.map(|lvl| (lvl.size_bytes as u64) / 1024);
    let l3_mib = snap.l3_bytes.map(|b| (b as u64) / (1024 * 1024));
    let l3_summary = snap
        .cache
        .l3_summary()
        .unwrap_or_else(|| "unknown".to_string());
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
    let batch_size = user_batch.unwrap_or(snap.recommended_batch_size);
    let batch_mode = if batch_overridden { "custom" } else { "auto" };
    let yield_between_batches = !args.no_yield;

    // If spawn call passes a 'large_pages' boolean, prefer user opt-in AND OS support
    // Can we actually use huge pages? (OS enabled + dataset fits)
    let large_pages_supported = hp_status.enabled() && hp_status.dataset_fits(snap.dataset_bytes);

    // Will we use huge pages? (user asked AND supported)
    let large_pages = args.huge_pages && large_pages_supported;

    // Warn only if the user asked for huge pages but we can’t provide them.
    if args.huge_pages && !large_pages_supported {
        warn_huge_page_limit(&hp_status, snap.dataset_bytes);
    }

    // Thread mode: "custom" if user provided --threads, else "auto"
    let thread_mode = if args.threads.is_some() {
        "custom"
    } else {
        "auto"
    };

    // Explanatory, multi-line summary for humans, with structured fields for tools.
    tracing::info!(
        // Structured fields (easy to grep/parse)
        cores = snap.physical_cores,
        l1_kib = l1_kib.unwrap_or(0),
        l1i_kib = l1i_kib.unwrap_or(0),
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
        batch_size,
        batch_mode,
        recommended_batch = snap.recommended_batch_size,
        auto_threads,
        threads = n_workers,
        thread_mode,
        yield_between_batches,
        "\nCPU tuning summary:\n\n\
        • Threads: {} ({}). Auto chooses ~L3-capacity-per-thread to avoid cache thrash.\n\
        • Batch size: {} hashes ({}; recommended {}). Larger batches cut per-share overhead but can increase latency and memory pressure.\n\
        • CPU features: AES-NI={}, SSSE3={}, AVX2={}, AVX-512F={}, Prefetch={}.\n\
        • Cache (per core unless noted): L1d={} KiB, L1i={} KiB, L2={} KiB, L3={}. RandomX is memory-hard; more cache lets us run more threads without stalls.\n\
        • NUMA nodes: {} (known={}). On multi-socket systems, keeping threads/data local to a node reduces remote memory penalties.\n\
        • Large pages: {}. Reduces TLB misses for the RandomX dataset and can improve throughput when the dataset fits.\n\
        • Yield between batches: {}. Keeps the miner friendly on shared machines.\n\
        \n\n--- structured fields for tooling below ---\n",
        n_workers, thread_mode,
        batch_size, batch_mode, snap.recommended_batch_size,
        aes, ssse3, avx2, avx512f, prefetch,
        l1_kib.unwrap_or(0), l1i_kib.unwrap_or(0), l2_kib.unwrap_or(0), l3_summary,
        numa_nodes, numa_known,
        large_pages,
        yield_between_batches
    );

    for detail in snap.cache.debug_lines() {
        tracing::debug!("cache_topology" = %detail);
    }
    for warning in &snap.cache.warnings {
        tracing::warn!("cache_topology_warning" = %warning);
    }
    if !args.affinity && !snap.cache.l3_instances.is_empty() {
        tracing::info!(
            l3_domains = snap.cache.l3_instances.len(),
            "detected multiple L3 cache domains; consider --affinity to pin workers per domain"
        );
    }

    // Optional explicit breadcrumbs, as you have:
    if let Some(user_t) = args.threads {
        tracing::info!("tuning override: user set threads={}", user_t);
    }
    if batch_overridden {
        tracing::info!("tuning override: user set batch_size={}", batch_size);
    }

    // Broadcast: jobs -> workers
    let (jobs_tx, _jobs_rx0) = tokio::sync::broadcast::channel(64);
    // MPSC: shares <- workers
    let (shares_tx, mut shares_rx) = tokio::sync::mpsc::unbounded_channel::<Share>();

    if args.threads.is_none() {
        tracing::info!("auto-selected {} worker threads", n_workers);
    }

    let stats_config = config.clone();
    let stats_endpoint = match mode {
        MiningMode::Pool => args.pool.clone().unwrap_or_else(|| "<pool>".to_string()),
        MiningMode::Solo => rpc_endpoint
            .as_ref()
            .map(|endpoint| endpoint.redacted().to_string())
            .unwrap_or_else(|| "<rpc>".to_string()),
    };
    let stats_tls = matches!(mode, MiningMode::Pool) && args.tls;
    let stats = Arc::new(Stats::new(mode, stats_endpoint, stats_tls, stats_config));

    let _workers = spawn_workers(
        n_workers,
        WorkerSpawnConfig {
            jobs_tx: jobs_tx.clone(),
            shares_tx,
            affinity: args.affinity,
            large_pages,
            batch_size,
            yield_between_batches,
            hash_counter: stats.hashes.clone(),
        },
    );

    // Optional HTTP API
    if let Some(port) = args.api_port {
        let s = stats.clone();
        let dir = dashboard_dir.clone();
        let bind = args.api_bind;
        tokio::spawn(async move {
            run_http_api(bind, port, s, dir, None).await;
        });
    }

    if matches!(mode, MiningMode::Pool) {
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

        let cfg = Config {
            pool: args.pool.clone().expect("pool required for pool mode"),
            wallet: args.wallet.clone().expect("user required for pool mode"),
            pass: Some(args.pass.clone()),
            threads: args.threads,
            enable_devfee: true,
            tls: args.tls,
            tls_ca_cert: args.tls_ca_cert.clone(),
            tls_cert_sha256,
            api_port: args.api_port,
            affinity: args.affinity,
            huge_pages: args.huge_pages,
            batch_size,
            yield_between_batches,
            agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
            proxy: args.proxy.clone(),
        };

        let proxy_cfg = cfg
            .proxy
            .as_ref()
            .map(|url| ProxyConfig::parse(url))
            .transpose()?;

        if let Some(proxy) = proxy_cfg.as_ref() {
            tracing::info!(proxy = %proxy.redacted(), "routing stratum traffic via SOCKS5 proxy");
        }

        let tls = cfg.tls;
        let tls_ca_cert = cfg.tls_ca_cert.clone();
        let tls_cert_sha256 = cfg.tls_cert_sha256;

        let main_pool = cfg.pool.clone();
        let user_wallet = cfg.wallet.clone();
        let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
        let agent = cfg.agent.clone();

        tracing::info!("dev fee enabled at {} bps (1%)", DEV_FEE_BASIS_POINTS);

        // Snapshot flags for the async task
        // Pool IO task with reconnect loop
        let proxy_cfg = proxy_cfg.clone();
        let pool_handle = tokio::spawn({
            let jobs_tx = jobs_tx.clone();
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
                        let job_id = broadcast_job(
                            job,
                            active_pool.is_dev(),
                            true,
                            &jobs_tx,
                            &mut valid_job_ids,
                            &mut seen_nonces,
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
                                    );
                                    if let Some(job) = dev_job {
                                        let dev_job_id = broadcast_job(
                                            job,
                                            true,
                                            true,
                                            &jobs_tx,
                                            &mut valid_job_ids,
                                            &mut seen_nonces,
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
                                            },
                                            user_connection,
                                        )
                                        .await
                                        {
                                            tracing::warn!("reconnect failed (devfee -> user): {e}");
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
                                                    let job_id = broadcast_job(
                                                        job,
                                                        active_pool.is_dev(),
                                                        clean,
                                                        &jobs_tx,
                                                        &mut valid_job_ids,
                                                        &mut seen_nonces,
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
                                                        reset_session(&mut valid_job_ids, &mut seen_nonces, &mut pending_shares);
                                                        if let Some(job) = job_opt {
                                                            let job_id = broadcast_job(
                                                                job,
                                                                true,
                                                                true,
                                                                &jobs_tx,
                                                                &mut valid_job_ids,
                                                                &mut seen_nonces,
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
                                            continue;
                                        }

                                        if let Some(id) = v.get("id").and_then(|x| x.as_u64()) {
                                            if let Some(pending) = pending_shares.remove(&id) {
                                                let is_dev = pending.is_devfee;
                                                let mut reconnect_user = false;

                                                if let Some(res) = v.get("result") {
                                                    let ok = res.get("status").and_then(|s| s.as_str()) == Some("OK") || res.as_bool() == Some(true);
                                                    if ok {
                                                        if is_dev {
                                                            stats.dev_accepted.fetch_add(1, Ordering::Relaxed);
                                                            tracing::info!(
                                                                dev_accepted = stats.dev_accepted.load(Ordering::Relaxed),
                                                                dev_rejected = stats.dev_rejected.load(Ordering::Relaxed),
                                                                job_id = %pending.job_id,
                                                                "dev share accepted"
                                                            );
                                                            reconnect_user = true;
                                                        } else {
                                                            stats.accepted.fetch_add(1, Ordering::Relaxed);
                                                            tracing::info!(
                                                                accepted = stats.accepted.load(Ordering::Relaxed),
                                                                rejected = stats.rejected.load(Ordering::Relaxed),
                                                                job_id = %pending.job_id,
                                                                "share accepted"
                                                            );
                                                        }
                                                    } else if is_dev {
                                                        stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                                                        tracing::warn!(
                                                            dev_accepted = stats.dev_accepted.load(Ordering::Relaxed),
                                                            dev_rejected = stats.dev_rejected.load(Ordering::Relaxed),
                                                            job_id = %pending.job_id,
                                                            "dev share rejected"
                                                        );
                                                        reconnect_user = true;
                                                    } else {
                                                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                                                        tracing::warn!(
                                                            accepted = stats.accepted.load(Ordering::Relaxed),
                                                            rejected = stats.rejected.load(Ordering::Relaxed),
                                                            job_id = %pending.job_id,
                                                            "share rejected"
                                                        );
                                                    }
                                                } else if let Some(err) = v.get("error") {
                                                    if is_dev {
                                                        stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                                                        tracing::warn!(
                                                            dev_accepted = stats.dev_accepted.load(Ordering::Relaxed),
                                                            dev_rejected = stats.dev_rejected.load(Ordering::Relaxed),
                                                            job_id = %pending.job_id,
                                                            error = %err,
                                                            "dev share rejected"
                                                        );
                                                        reconnect_user = true;
                                                    } else {
                                                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                                                        tracing::warn!(
                                                            accepted = stats.accepted.load(Ordering::Relaxed),
                                                            rejected = stats.rejected.load(Ordering::Relaxed),
                                                            job_id = %pending.job_id,
                                                            error = %err,
                                                            "share rejected"
                                                        );
                                                    }
                                                } else if is_dev {
                                                    stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                                                    tracing::warn!(
                                                        job_id = %pending.job_id,
                                                        "dev share response missing result; treating as reject"
                                                    );
                                                    reconnect_user = true;
                                                } else {
                                                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                                                    tracing::warn!(
                                                        job_id = %pending.job_id,
                                                        "share response missing result; treating as reject"
                                                    );
                                                }

                                                if reconnect_user && matches!(active_pool, ActivePool::Dev) {
                                                    if let Err(e) = reconnect_user_pool(
                                                        ShareContext {
                                                            client: &mut client,
                                                            stats: &stats,
                                                            active_pool: &mut active_pool,
                                                            valid_job_ids: &mut valid_job_ids,
                                                            seen_nonces: &mut seen_nonces,
                                                            pending_shares: &mut pending_shares,
                                                            jobs_tx: &jobs_tx,
                                                            dev_scheduler: &mut dev_scheduler,
                                                        },
                                                        user_connection,
                                                    )
                                                    .await
                                                    {
                                                        tracing::warn!("reconnect failed (devfee -> user): {e}");
                                                        stats.pool_connected.store(false, Ordering::Relaxed);
                                                        break;
                                                    }
                                                }
                                                continue;
                                            }
                                        }

                                        if let Some(err) = v.get("error") {
                                            tracing::warn!(error = %err, "pool error response");
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
                    } // inner loop
                } // outer reconnect loop
            }
        });

        // Keep the runtime alive until either the pool task ends or the user presses Ctrl+C.
        tokio::select! {
            res = pool_handle => {
                if let Err(e) = res {
                    tracing::error!("pool task ended unexpectedly: {e}");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Ctrl+C received; shutting down.");
            }
        }
    } else {
        let endpoint = rpc_endpoint.expect("solo RPC endpoint missing");
        let wallet = args.solo_wallet.clone().expect("solo wallet required");
        let reserve_size = args.solo_reserve_size;

        tracing::info!("dev fee enabled at {} bps (1%)", DEV_FEE_BASIS_POINTS);

        let solo_handle = tokio::spawn(run_solo_loop(
            endpoint,
            wallet,
            reserve_size,
            jobs_tx.clone(),
            shares_rx,
            stats.clone(),
        ));

        tokio::select! {
            res = solo_handle => {
                if let Ok(Err(e)) = res {
                    tracing::error!("solo task ended with error: {e}");
                } else if let Err(e) = res {
                    tracing::error!("solo task ended unexpectedly: {e}");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Ctrl+C received; shutting down.");
            }
        }
    }

    Ok(())
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

fn log_config_overview(cfg: &LoadedConfigFile, args: &Args) {
    let mut lines = Vec::new();
    if let Some(mode) = cfg.values.mode {
        let detail = if cfg.applied.mode {
            format!("Mode (--mode): {} (from config.toml)", mode.as_str())
        } else {
            "Mode (--mode): provided in config.toml but overridden by CLI".to_string()
        };
        lines.push(detail);
    }

    if cfg.applied.pool {
        if let Some(pool) = cfg.values.pool.as_deref() {
            lines.push(format!("Pool (--url): {pool} (from config.toml)"));
        }
    } else if cfg.values.pool.is_some() {
        lines.push("Pool (--url): provided in config.toml but overridden by CLI".to_string());
    }

    if cfg.applied.wallet {
        if let Some(wallet) = cfg.values.wallet.as_deref() {
            lines.push(format!("Wallet (--user): {wallet} (from config.toml)"));
        }
    } else if cfg.values.wallet.is_some() {
        lines.push("Wallet (--user): provided in config.toml but overridden by CLI".to_string());
    }

    if cfg.applied.pass {
        lines.push("Password (--pass): set via config.toml".to_string());
    } else if cfg.values.pass.is_some() {
        lines.push("Password (--pass): provided in config.toml but overridden by CLI".to_string());
    }

    if let Some(threads) = cfg.values.threads {
        let detail = if cfg.applied.threads {
            format!("Threads (--threads): {threads} (from config.toml)")
        } else {
            format!("Threads (--threads): {threads} (config.toml, overridden by CLI)")
        };
        lines.push(detail);
    }

    if let Some(batch) = cfg.values.batch_size {
        let detail = if cfg.applied.batch_size {
            format!("Batch size (--batch-size): {batch} (from config.toml)")
        } else {
            format!("Batch size (--batch-size): {batch} (config.toml, overridden by CLI)")
        };
        lines.push(detail);
    }

    if let Some(port) = cfg.values.api_port {
        let detail = if cfg.applied.api_port {
            format!("API port (--api-port): {port} (from config.toml)")
        } else {
            format!("API port (--api-port): {port} (config.toml, overridden by CLI)")
        };
        lines.push(detail);
    }

    if let Some(bind) = cfg.values.api_bind {
        let detail = if cfg.applied.api_bind {
            format!("API bind (--api-bind): {bind} (from config.toml)")
        } else {
            format!("API bind (--api-bind): {bind} (config.toml, overridden by CLI)")
        };
        lines.push(detail);
    }

    if let Some(dir) = cfg.values.dashboard_dir.as_ref() {
        let detail = if cfg.applied.dashboard_dir {
            format!(
                "Dashboard directory (--dashboard-dir): {} (from config.toml)",
                dir.display()
            )
        } else {
            format!(
                "Dashboard directory (--dashboard-dir): {} (config.toml, overridden by CLI)",
                dir.display()
            )
        };
        lines.push(detail);
    }

    if let Some(proxy) = cfg.values.proxy.as_ref() {
        let detail = if cfg.applied.proxy {
            format!("Proxy (--proxy): {} (from config.toml)", proxy)
        } else {
            format!("Proxy (--proxy): {proxy} (config.toml, overridden by CLI)")
        };
        lines.push(detail);
    }

    if let Some(cert) = cfg.values.tls_ca_cert.as_ref() {
        let detail = if cfg.applied.tls_ca_cert {
            format!(
                "TLS CA certificate (--tls-ca-cert): {} (from config.toml)",
                cert.display()
            )
        } else {
            format!(
                "TLS CA certificate (--tls-ca-cert): {} (config.toml, overridden by CLI)",
                cert.display()
            )
        };
        lines.push(detail);
    }

    if let Some(fp) = cfg.values.tls_cert_sha256.as_ref() {
        let detail = if cfg.applied.tls_cert_sha256 {
            format!("TLS pinned certificate (--tls-cert-sha256): {fp} (from config.toml)")
        } else {
            format!(
                "TLS pinned certificate (--tls-cert-sha256): {fp} (config.toml, overridden by CLI)"
            )
        };
        lines.push(detail);
    }

    if let Some(solo) = cfg.values.solo.as_ref() {
        if let Some(url) = solo.rpc_url.as_deref() {
            let detail = if cfg.applied.solo_rpc_url {
                format!(
                    "Solo RPC URL (--node-rpc-url): {} (from config.toml)",
                    redact_url_userinfo(url)
                )
            } else {
                "Solo RPC URL (--node-rpc-url): provided in config.toml but overridden by CLI"
                    .to_string()
            };
            lines.push(detail);
        }

        if let Some(wallet) = solo.wallet.as_deref() {
            let detail = if cfg.applied.solo_wallet {
                format!("Solo wallet (--solo-wallet): {wallet} (from config.toml)")
            } else {
                "Solo wallet (--solo-wallet): provided in config.toml but overridden by CLI"
                    .to_string()
            };
            lines.push(detail);
        }

        if let Some(reserve_size) = solo.reserve_size {
            let detail = if cfg.applied.solo_reserve_size {
                format!(
                    "Solo reserve size (--solo-reserve-size): {reserve_size} (from config.toml)"
                )
            } else {
                "Solo reserve size (--solo-reserve-size): provided in config.toml but overridden by CLI"
                    .to_string()
            };
            lines.push(detail);
        }

        if let Some(zmq) = solo.zmq.as_deref() {
            let detail = if cfg.applied.solo_zmq {
                format!("Solo ZMQ (--solo-zmq): {zmq} (from config.toml)")
            } else {
                "Solo ZMQ (--solo-zmq): provided in config.toml but overridden by CLI".to_string()
            };
            lines.push(detail);
        }

        if solo.rpc_user.is_some() {
            let detail = if cfg.applied.solo_rpc_user {
                "Solo RPC user (--node-rpc-user): set via config.toml".to_string()
            } else {
                "Solo RPC user (--node-rpc-user): provided in config.toml but overridden by CLI"
                    .to_string()
            };
            lines.push(detail);
        }

        if solo.rpc_pass.is_some() {
            let detail = if cfg.applied.solo_rpc_pass {
                "Solo RPC password (--node-rpc-pass): set via config.toml".to_string()
            } else {
                "Solo RPC password (--node-rpc-pass): provided in config.toml but overridden by CLI"
                    .to_string()
            };
            lines.push(detail);
        }
    }

    let bool_line = |flag: bool, applied: bool, label: &str, lines: &mut Vec<String>| {
        if flag {
            if applied {
                lines.push(format!("{label} enabled via config.toml"));
            } else {
                lines.push(format!(
                    "{label} requested in config.toml but overridden by CLI"
                ));
            }
        }
    };

    bool_line(args.tls, cfg.applied.tls, "TLS (--tls)", &mut lines);
    bool_line(
        args.affinity,
        cfg.applied.affinity,
        "CPU affinity (--affinity)",
        &mut lines,
    );
    bool_line(
        args.huge_pages,
        cfg.applied.huge_pages,
        "Huge pages (--huge-pages)",
        &mut lines,
    );
    bool_line(
        args.no_yield,
        cfg.applied.no_yield,
        "Yields disabled (--no-yield)",
        &mut lines,
    );
    bool_line(
        args.debug,
        cfg.applied.debug,
        "Debug logging (--debug)",
        &mut lines,
    );

    let message = if lines.is_empty() {
        format!(
            "loaded configuration from {} (no values applied; all provided flags were overridden)",
            cfg.path.display()
        )
    } else {
        format!(
            "loaded configuration from {}:\n • {}",
            cfg.path.display(),
            lines.join("\n • ")
        )
    };

    tracing::info!("{message}");
}

fn redact_url_userinfo(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        Err(_) => raw.to_string(),
    }
}

fn broadcast_job(
    mut job: PoolJob,
    is_devfee: bool,
    clean_jobs: bool,
    jobs_tx: &tokio::sync::broadcast::Sender<WorkItem>,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
) -> String {
    if clean_jobs {
        valid_job_ids.clear();
        seen_nonces.clear();
    }

    if let Err(e) = job.ensure_prepared() {
        tracing::warn!(error = ?e, "dropping malformed pool job");
        return String::new();
    }
    let job_id = job.job_id.clone();
    let _ = jobs_tx.send(WorkItem { job, is_devfee });
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

fn reset_session(
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    pending_shares: &mut HashMap<u64, PendingShare>,
) {
    valid_job_ids.clear();
    seen_nonces.clear();
    pending_shares.clear();
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
        "submit_share"
    );

    let mut reconnect_user = false;
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
    } = context;
    let (new_client, job_opt) = connect_with_retries(connection, 5, "user").await?;

    *client = new_client;
    *active_pool = ActivePool::User;
    reset_session(valid_job_ids, seen_nonces, pending_shares);
    stats.pool_connected.store(true, Ordering::Relaxed);

    if let Some(job) = job_opt {
        let job_id = broadcast_job(job, false, true, jobs_tx, valid_job_ids, seen_nonces);
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

async fn run_solo_loop(
    endpoint: RpcEndpoint,
    wallet: String,
    reserve_size: u32,
    jobs_tx: tokio::sync::broadcast::Sender<WorkItem>,
    mut shares_rx: UnboundedReceiver<Share>,
    stats: Arc<Stats>,
) -> Result<()> {
    const BASE_POLL: Duration = Duration::from_secs(15);
    const MAX_BACKOFF_MS: u64 = 60_000;

    let client = SoloRpcClient::new(endpoint.clone());
    tracing::info!(
        rpc = %endpoint.redacted(),
        reserve_size,
        "solo mining enabled; polling monerod templates"
    );

    let mut current_template: Option<SoloTemplate> = None;
    let mut seen_nonces: HashSet<u32> = HashSet::new();
    let mut job_seq: u64 = 0;
    let mut backoff_ms = 1_000u64;
    let mut next_refresh = Instant::now();
    let mut dev_scheduler = DevFeeScheduler::new();
    let mut last_sync_warn = Instant::now() - Duration::from_secs(60);

    loop {
        let now = Instant::now();
        let delay = if now >= next_refresh {
            Duration::from_millis(0)
        } else {
            next_refresh - now
        };

        tokio::select! {
            maybe_share = shares_rx.recv() => {
                let Some(share) = maybe_share else {
                    tracing::warn!("shares channel closed; stopping solo task");
                    return Ok(());
                };

                let Some(template) = current_template.as_ref() else {
                    tracing::debug!(job_id = %share.job_id, "dropping share (no active solo template)");
                    continue;
                };

                if share.job_id != template.job.job_id {
                    tracing::debug!(job_id = %share.job_id, "dropping share (stale solo job_id)");
                    continue;
                }

                if !seen_nonces.insert(share.nonce) {
                    tracing::debug!(
                        job_id = %share.job_id,
                        nonce = share.nonce,
                        "dropping duplicate solo share"
                    );
                    continue;
                }

                stats.blocks_submitted.fetch_add(1, Ordering::Relaxed);
                let block_blob = match template.block_blob_with_nonce(share.nonce) {
                    Ok(blob) => blob,
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to build block blob");
                        continue;
                    }
                };
                let block_hex = hex::encode(block_blob);
                match client.submit_block(&block_hex).await {
                    Ok(result) => {
                        let outcome = if result.accepted() {
                            stats.blocks_accepted.fetch_add(1, Ordering::Relaxed);
                            SubmitOutcome::Accepted
                        } else {
                            stats.blocks_rejected.fetch_add(1, Ordering::Relaxed);
                            SubmitOutcome::Rejected
                        };

                        if share.is_devfee {
                            if result.accepted() {
                                stats.dev_accepted.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        if let Ok(mut guard) = stats.last_submit.lock() {
                            *guard = Some(SubmitRecord::new(outcome, result.message()));
                        }

                        tracing::info!(
                            job_id = %share.job_id,
                            height = template.height,
                            outcome = %outcome.as_str(),
                            is_devfee = share.is_devfee,
                            message = %result.message(),
                            "solo block submission result"
                        );
                        stats.pool_connected.store(true, Ordering::Relaxed);
                        next_refresh = Instant::now();
                    }
                    Err(err) => {
                        stats.blocks_rejected.fetch_add(1, Ordering::Relaxed);
                        if share.is_devfee {
                            stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Ok(mut guard) = stats.last_submit.lock() {
                            *guard = Some(SubmitRecord::new(SubmitOutcome::Error, err.to_string()));
                        }
                        log_solo_rpc_error(&endpoint, &err, "submit_block");
                        stats.pool_connected.store(false, Ordering::Relaxed);
                        next_refresh = Instant::now();
                    }
                }
            }
            _ = sleep(delay) => {
                match client.get_info().await {
                    Ok(info) => {
                        stats.node_height.store(info.height, Ordering::Relaxed);
                        if !info.is_synced() && last_sync_warn.elapsed() > Duration::from_secs(60) {
                            tracing::warn!(
                                height = info.height,
                                target_height = info.target_height.unwrap_or(info.height),
                                "monerod is not yet synced; solo mining templates may be stale"
                            );
                            last_sync_warn = Instant::now();
                        }
                    }
                    Err(err) => {
                        log_solo_rpc_error(&endpoint, &err, "get_info");
                    }
                }

                let is_devfee = dev_scheduler.should_donate();
                let wallet_addr = if is_devfee { DEV_WALLET_ADDRESS } else { wallet.as_str() };
                match client.get_block_template(wallet_addr, reserve_size).await {
                    Ok(template) => {
                        stats.pool_connected.store(true, Ordering::Relaxed);
                        backoff_ms = 1_000;

                        let job_id = format!("solo-{}-{}", template.height, job_seq);
                        job_seq = job_seq.wrapping_add(1);
                        match SoloTemplate::from_rpc(template, job_id) {
                            Ok(template) => {
                                let is_new = current_template
                                    .as_ref()
                                    .map(|current| {
                                        current.job.blob != template.job.blob
                                            || current.height != template.height
                                    })
                                    .unwrap_or(true);
                                if is_new {
                                    let _ = jobs_tx.send(WorkItem {
                                        job: template.job.clone(),
                                        is_devfee,
                                    });
                                    seen_nonces.clear();
                                    stats
                                        .template_height
                                        .store(template.height, Ordering::Relaxed);
                                    stats.template_timestamp.store(
                                        unix_timestamp_seconds(),
                                        Ordering::Relaxed,
                                    );
                                    if is_devfee {
                                        tracing::info!(
                                            job_id = %template.job.job_id,
                                            height = template.height,
                                            "devfee activated for solo template"
                                        );
                                    } else {
                                        tracing::info!(
                                            job_id = %template.job.job_id,
                                            height = template.height,
                                            "solo template updated"
                                        );
                                    }
                                    current_template = Some(template);
                                }
                            }
                            Err(err) => {
                                stats.pool_connected.store(false, Ordering::Relaxed);
                                dev_scheduler.revert_last_job();
                                log_solo_rpc_error(&endpoint, &err, "template decode");
                                next_refresh = Instant::now() + Duration::from_millis(backoff_ms);
                                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                                continue;
                            }
                        }
                        next_refresh = Instant::now() + BASE_POLL;
                    }
                    Err(err) => {
                        stats.pool_connected.store(false, Ordering::Relaxed);
                        dev_scheduler.revert_last_job();
                        log_solo_rpc_error(&endpoint, &err, "get_block_template");
                        next_refresh = Instant::now() + Duration::from_millis(backoff_ms);
                        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                    }
                }
            }
        }
    }
}

fn log_solo_rpc_error(endpoint: &RpcEndpoint, err: &SoloRpcError, context: &str) {
    match err {
        SoloRpcError::ConnectionRefused => {
            tracing::warn!(rpc = %endpoint.redacted(), "{context}: connection refused");
        }
        SoloRpcError::Unauthorized => {
            tracing::warn!(rpc = %endpoint.redacted(), "{context}: unauthorized");
        }
        SoloRpcError::RpcStatus(status) => {
            tracing::warn!(
                rpc = %endpoint.redacted(),
                status = %status,
                "{context}: RPC status"
            );
        }
        SoloRpcError::Rpc { code, message } => {
            tracing::warn!(
                rpc = %endpoint.redacted(),
                code,
                message = %message,
                "{context}: RPC error"
            );
        }
        _ => {
            tracing::warn!(rpc = %endpoint.redacted(), error = %err, "{context}: RPC error");
        }
    }
}
