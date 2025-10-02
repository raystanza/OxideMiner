// OxideMiner/crates/oxide-miner/src/miner.rs

use crate::args::Args;
use crate::http_api::run_http_api;
use crate::stats::Stats;
use crate::util::tiny_jitter_ms;
use anyhow::{anyhow, Context, Result};
use oxide_core::stratum::PoolJob;
use oxide_core::worker::{Share, WorkItem};
use oxide_core::{
    autotune_snapshot, cpu_has_aes, spawn_workers, Config, DevFeeScheduler, HugePageStatus,
    StratumClient, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};
use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone)]
struct PendingShare {
    is_devfee: bool,
    job_id: String,
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
        .with_writer(std::io::stdout) // pretty ANSI for terminal
        .with_target(true);

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
        let hp_status = snap.huge_page_status.clone();
        if args.huge_pages && !hp_status.dataset_fits(snap.dataset_bytes) {
            warn_huge_page_limit(&hp_status, snap.dataset_bytes);
        }
        let n_workers = args.threads.unwrap_or(snap.suggested_threads);
        let large_pages = args.huge_pages && hp_status.dataset_fits(snap.dataset_bytes);
        tracing::info!(
            "benchmark: threads={} batch_size={} large_pages={} yield={}",
            n_workers,
            args.batch_size,
            large_pages,
            !args.no_yield
        );
        let hps =
            oxide_core::run_benchmark(n_workers, 10, large_pages, args.batch_size, !args.no_yield)
                .await?;
        println!("RandomX benchmark: {:.2} H/s", hps);
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

    let cfg = Config {
        pool: args.pool.expect("pool required unless --benchmark"),
        wallet: args.wallet.expect("user required unless --benchmark"),
        pass: Some(args.pass),
        threads: args.threads,
        enable_devfee: true,
        tls: args.tls,
        tls_ca_cert: args.tls_ca_cert.clone(),
        tls_cert_sha256,
        api_port: args.api_port,
        affinity: args.affinity,
        huge_pages: args.huge_pages,
        batch_size: args.batch_size,
        yield_between_batches: !args.no_yield,
        agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
    };

    // Take snapshot to log how auto-tune decided thread count
    let snap = autotune_snapshot();
    let hp_status = snap.huge_page_status.clone();
    if !hp_status.enabled() {
        warn_huge_page_limit(&hp_status, snap.dataset_bytes);
    }
    let auto_threads = snap.suggested_threads;
    let n_workers = cfg.threads.unwrap_or(auto_threads);

    // One-line summary that's easy to read in logs
    let l3_mib = snap.l3_bytes.map(|b| (b as u64) / (1024 * 1024));
    let avail_mib = snap.available_bytes / (1024 * 1024);
    let aes = cpu_has_aes();

    // If spawn call passes a 'large_pages' boolean, prefer user opt-in AND OS support
    let large_pages = cfg.huge_pages && hp_status.dataset_fits(snap.dataset_bytes);
    if cfg.huge_pages && !large_pages && hp_status.enabled() {
        warn_huge_page_limit(&hp_status, snap.dataset_bytes);
    }

    if let Some(user_t) = cfg.threads {
        tracing::info!(
            "tuning: cores={} L3={}MiB mem_avail={}MiB aes={} hugepages={} -> threads={} (OVERRIDE; auto={})",
            snap.physical_cores,
            l3_mib.unwrap_or(0),
            avail_mib,
            aes,
            large_pages,
            user_t,
            auto_threads
        );
    } else {
        tracing::info!(
            "tuning: cores={} L3={}MiB mem_avail={}MiB aes={} hugepages={} -> threads={}",
            snap.physical_cores,
            l3_mib.unwrap_or(0),
            avail_mib,
            aes,
            large_pages,
            n_workers
        );
    }

    // Broadcast: jobs -> workers
    let (jobs_tx, _jobs_rx0) = tokio::sync::broadcast::channel(64);
    // MPSC: shares <- workers
    let (shares_tx, mut shares_rx) = tokio::sync::mpsc::unbounded_channel::<Share>();

    if cfg.threads.is_none() {
        tracing::info!("auto-selected {} worker threads", n_workers);
    }

    let stats = Arc::new(Stats::new(cfg.pool.clone(), cfg.tls));

    let tls_ca_cert = cfg.tls_ca_cert.clone();
    let tls_cert_sha256 = cfg.tls_cert_sha256;

    let _workers = spawn_workers(
        n_workers,
        jobs_tx.clone(),
        shares_tx,
        cfg.affinity,
        large_pages,
        cfg.batch_size,
        cfg.yield_between_batches,
        stats.hashes.clone(),
    );

    let main_pool = cfg.pool.clone();
    let user_wallet = cfg.wallet.clone();
    let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
    let agent = cfg.agent.clone();

    tracing::info!(
        "dev fee fixed at {} bps (1%) and always enabled",
        DEV_FEE_BASIS_POINTS,
    );

    // Optional HTTP API
    if let Some(port) = cfg.api_port {
        let s = stats.clone();
        let dir = dashboard_dir.clone();
        tokio::spawn(async move {
            run_http_api(port, s, dir).await;
        });
    }

    // Snapshot flags for the async task
    let tls = cfg.tls;

    // Pool IO task with reconnect loop
    let pool_handle = tokio::spawn({
        let jobs_tx = jobs_tx.clone();
        let stats = stats.clone();
        let main_pool = main_pool.clone();
        let user_wallet = user_wallet.clone();
        let pass = pass.clone();
        let agent = agent.clone();

        async move {
            let tls_ca_cert = tls_ca_cert.clone();
            let mut backoff_ms = 1_000u64;
            let mut dev_scheduler = Some(DevFeeScheduler::new());

            loop {
                stats.pool_connected.store(false, Ordering::Relaxed);
                let (mut client, initial_job) = match StratumClient::connect_and_login(
                    &main_pool,
                    &user_wallet,
                    &pass,
                    &agent,
                    tls,
                    tls_ca_cert.as_deref(),
                    tls_cert_sha256.as_ref(),
                )
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
                    if scheduler_tick(dev_scheduler.as_mut(), &job_id, active_pool) {
                        let counter = dev_scheduler.as_ref().map(|s| s.counter()).unwrap_or(0);
                        let interval = dev_scheduler.as_ref().map(|s| s.interval()).unwrap_or(0);
                        tracing::info!(
                            job_id = %job_id,
                            counter,
                            interval,
                            "devfee activation triggered (initial job)"
                        );
                        match connect_with_retries(
                            &main_pool,
                            DEV_WALLET_ADDRESS,
                            &pass,
                            &agent,
                            tls,
                            tls_ca_cert.as_ref(),
                            tls_cert_sha256.as_ref(),
                            3,
                            "devfee",
                        )
                        .await
                        {
                            Ok((new_client, dev_job)) => {
                                if let Err(e) = handle_shares(
                                    None,
                                    &mut shares_rx,
                                    &mut client,
                                    &stats,
                                    &mut active_pool,
                                    &mut valid_job_ids,
                                    &mut seen_nonces,
                                    &mut pending_shares,
                                    &main_pool,
                                    &user_wallet,
                                    &pass,
                                    &agent,
                                    tls,
                                    tls_ca_cert.as_ref(),
                                    tls_cert_sha256.as_ref(),
                                    &jobs_tx,
                                    dev_scheduler.as_mut(),
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
                                        dev_scheduler.as_mut(),
                                        &dev_job_id,
                                        active_pool,
                                    );
                                } else {
                                    tracing::debug!("devfee activated; awaiting first job");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "devfee connect failed");
                                if let Some(sched) = dev_scheduler.as_mut() {
                                    sched.revert_last_job();
                                }
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
                                        &mut client,
                                        &stats,
                                        &mut active_pool,
                                        &mut valid_job_ids,
                                        &mut seen_nonces,
                                        &mut pending_shares,
                                                &main_pool,
                                                &user_wallet,
                                                &pass,
                                                &agent,
                                                tls,
                                                tls_ca_cert.as_ref(),
                                                tls_cert_sha256.as_ref(),
                                                &jobs_tx,
                                                dev_scheduler.as_mut(),
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
                                                trigger_dev = scheduler_tick(dev_scheduler.as_mut(), &job_id, active_pool);
                                                if trigger_dev {
                                                    trigger_job_id = job_id;
                                                }
                                            }
                                        }

                                        if trigger_dev {
                                            let counter = dev_scheduler.as_ref().map(|s| s.counter()).unwrap_or(0);
                                            let interval = dev_scheduler.as_ref().map(|s| s.interval()).unwrap_or(0);
                                            tracing::info!(
                                                job_id = %trigger_job_id,
                                                counter,
                                                interval,
                                                "devfee activation triggered"
                                            );
                                            match connect_with_retries(
                                                &main_pool,
                                                DEV_WALLET_ADDRESS,
                                                &pass,
                                                &agent,
                                                tls,
                                                tls_ca_cert.as_ref(),
                                                tls_cert_sha256.as_ref(),
                                                3,
                                                "devfee",
                                            ).await {
                                                Ok((new_client, job_opt)) => {
                                                    if let Err(e) = handle_shares(
                                                        None,
                                                        &mut shares_rx,
                                                        &mut client,
                                                        &stats,
                                                        &mut active_pool,
                                                        &mut valid_job_ids,
                                                        &mut seen_nonces,
                                                        &mut pending_shares,
                                                        &main_pool,
                                                        &user_wallet,
                                                        &pass,
                                                        &agent,
                                                        tls,
                                                        tls_ca_cert.as_ref(),
                                                        tls_cert_sha256.as_ref(),
                                                        &jobs_tx,
                                                        dev_scheduler.as_mut(),
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
                                                        let _ = scheduler_tick(dev_scheduler.as_mut(), &job_id, active_pool);
                                                    } else {
                                                        tracing::debug!("devfee activated; awaiting first job");
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(error = %e, "devfee connect failed");
                                                    if let Some(sched) = dev_scheduler.as_mut() {
                                                        sched.revert_last_job();
                                                    }
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
                                                let ok = res.get("status").and_then(|s| s.as_str()) == Some("OK")
                                                    || res.as_bool() == Some(true);
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
                                                    &mut client,
                                                    &mut active_pool,
                                                    &main_pool,
                                                    &user_wallet,
                                                    &pass,
                                                    &agent,
                                                    tls,
                                                    tls_ca_cert.as_ref(),
                                                    tls_cert_sha256.as_ref(),
                                                    &jobs_tx,
                                                    &mut valid_job_ids,
                                                    &mut seen_nonces,
                                                    &mut pending_shares,
                                                    &stats,
                                                    dev_scheduler.as_mut(),
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

    job.cache_target();
    let job_id = job.job_id.clone();
    let _ = jobs_tx.send(WorkItem { job, is_devfee });
    valid_job_ids.insert(job_id.clone());
    job_id
}

fn scheduler_tick(
    scheduler: Option<&mut DevFeeScheduler>,
    job_id: &str,
    active_pool: ActivePool,
) -> bool {
    if let Some(sched) = scheduler {
        let donate = sched.should_donate();
        tracing::debug!(
            job_id = job_id,
            pool = active_pool.label(),
            counter = sched.counter(),
            interval = sched.interval(),
            donate,
            "devfee scheduler tick"
        );
        donate && matches!(active_pool, ActivePool::User)
    } else {
        false
    }
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
    client: &mut StratumClient,
    stats: &Arc<Stats>,
    active_pool: &mut ActivePool,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    pending_shares: &mut HashMap<u64, PendingShare>,
    main_pool: &str,
    user_wallet: &str,
    pass: &str,
    agent: &str,
    tls: bool,
    tls_ca_cert: Option<&std::path::PathBuf>,
    tls_cert_sha256: Option<&[u8; 32]>,
    jobs_tx: &tokio::sync::broadcast::Sender<WorkItem>,
    dev_scheduler: Option<&mut DevFeeScheduler>,
) -> Result<()> {
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
            client,
            active_pool,
            main_pool,
            user_wallet,
            pass,
            agent,
            tls,
            tls_ca_cert,
            tls_cert_sha256,
            jobs_tx,
            valid_job_ids,
            seen_nonces,
            pending_shares,
            stats,
            dev_scheduler,
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
    client: &mut StratumClient,
    active_pool: &mut ActivePool,
    main_pool: &str,
    user_wallet: &str,
    pass: &str,
    agent: &str,
    tls: bool,
    tls_ca_cert: Option<&std::path::PathBuf>,
    tls_cert_sha256: Option<&[u8; 32]>,
    jobs_tx: &tokio::sync::broadcast::Sender<WorkItem>,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    pending_shares: &mut HashMap<u64, PendingShare>,
    stats: &Arc<Stats>,
    dev_scheduler: Option<&mut DevFeeScheduler>,
) -> Result<()> {
    let (new_client, job_opt) = connect_with_retries(
        main_pool,
        user_wallet,
        pass,
        agent,
        tls,
        tls_ca_cert,
        tls_cert_sha256,
        5,
        "user",
    )
    .await?;

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
    pool: &str,
    wallet: &str,
    pass: &str,
    agent: &str,
    tls: bool,
    tls_ca_cert: Option<&std::path::PathBuf>,
    tls_cert_sha256: Option<&[u8; 32]>,
    attempts: usize,
    purpose: &str,
) -> Result<(StratumClient, Option<PoolJob>)> {
    let mut attempt = 0usize;
    let mut delay_ms = tiny_jitter_ms();
    let mut last_err: Option<anyhow::Error> = None;

    while attempt < attempts {
        attempt += 1;
        match StratumClient::connect_and_login(
            pool,
            wallet,
            pass,
            agent,
            tls,
            tls_ca_cert.map(|p| p.as_path()),
            tls_cert_sha256,
        )
        .await
        {
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
