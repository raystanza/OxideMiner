// OxideMiner/crates/oxide-miner/src/miner.rs

use crate::args::Args;
use crate::http_api::run_http_api;
use crate::stats::Stats;
use crate::util::tiny_jitter_ms;
use anyhow::Result;
use oxide_core::worker::{Share, WorkItem};
use oxide_core::{
    autotune_snapshot, cpu_has_aes, spawn_workers, Config, DevFeeScheduler, HugePageStatus,
    StratumClient, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};
use std::collections::{HashMap, HashSet};
use std::sync::{atomic::Ordering, Arc};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug)]
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

    let cfg = Config {
        pool: args.pool.expect("pool required unless --benchmark"),
        wallet: args.wallet.expect("user required unless --benchmark"),
        pass: Some(args.pass),
        threads: args.threads,
        enable_devfee: !args.no_devfee,
        tls: args.tls,
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
        "dev fee fixed at {} bps (1%): {}",
        DEV_FEE_BASIS_POINTS,
        cfg.enable_devfee
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
    let enable_devfee = cfg.enable_devfee;
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
            use tokio::time::{sleep, Duration};

            let mut backoff_ms = 1_000u64;
            let mut devfee = DevFeeScheduler::new();
            loop {
                stats.pool_connected.store(false, Ordering::Relaxed);
                let (mut client, initial_job) = match StratumClient::connect_and_login(
                    &main_pool,
                    &user_wallet,
                    &pass,
                    &agent,
                    tls,
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

                // Track valid job_ids for the current session to avoid submitting
                // stale shares after job clean or reconnect.
                let mut valid_job_ids: HashSet<String> = HashSet::new();
                // Track seen nonces per job to prevent duplicates.
                let mut seen_nonces: HashMap<String, HashSet<u32>> = HashMap::new();
                // Track outstanding share submissions (by request id) so we can
                // attribute accept/reject responses correctly.
                let mut pending_submissions: HashMap<u64, PendingShare> = HashMap::new();

                let mut using_dev = false;
                let mut dev_share_inflight = false;

                if let Some(job) = initial_job {
                    let job_id_for_log = job.job_id.clone();
                    let donate_now = enable_devfee && devfee.should_donate();
                    if donate_now && !using_dev {
                        tracing::info!(
                            job_id = %job_id_for_log,
                            jobs_seen = devfee.observed_jobs(),
                            pending = devfee.pending(),
                            "devfee activation triggered by login job"
                        );
                        match StratumClient::connect_and_login(
                            &main_pool,
                            DEV_WALLET_ADDRESS,
                            &pass,
                            &agent,
                            tls,
                        )
                        .await
                        {
                            Ok((dev_client, dev_job_opt)) => {
                                client = dev_client;
                                using_dev = true;
                                dev_share_inflight = false;
                                pending_submissions.clear();
                                valid_job_ids.clear();
                                seen_nonces.clear();
                                devfee.mark_started();
                                if let Some(dev_job) = dev_job_opt {
                                    if enable_devfee {
                                        let _ = devfee.should_donate();
                                    }
                                    push_job_to_workers(
                                        &jobs_tx,
                                        &mut valid_job_ids,
                                        &mut seen_nonces,
                                        dev_job,
                                        true,
                                        true,
                                    );
                                } else {
                                    tracing::debug!(
                                        "devfee login returned no job; awaiting notify"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    job_id = %job_id_for_log,
                                    error = %e,
                                    "devfee connect failed during login; continuing with user job"
                                );
                            }
                        }
                    }
                    if !using_dev {
                        push_job_to_workers(
                            &jobs_tx,
                            &mut valid_job_ids,
                            &mut seen_nonces,
                            job,
                            false,
                            true,
                        );
                    }
                }

                loop {
                    tokio::select! {
                        biased;
                        // 1) Outgoing share submissions
                        maybe_share = shares_rx.recv() => {
                            match maybe_share {
                                Some(share) => {
                                    if !valid_job_ids.contains(&share.job_id) {
                                        tracing::debug!(job_id = %share.job_id, "dropping stale share (invalid job_id for current session)");
                                        continue;
                                    }
                                    if share.is_devfee && using_dev && dev_share_inflight {
                                        tracing::debug!(job_id = %share.job_id, nonce = share.nonce, "dropping additional devfee share while awaiting response");
                                        continue;
                                    }
                                    let entry = seen_nonces.entry(share.job_id.clone()).or_default();
                                    if !entry.insert(share.nonce) {
                                        tracing::debug!(job_id = %share.job_id, nonce = share.nonce, "dropping duplicate share (already submitted)");
                                        continue;
                                    }
                                    let nonce_hex = hex::encode(share.nonce.to_le_bytes());
                                    let result_hex = hex::encode(share.result);

                                    match client.submit_share(&share.job_id, &nonce_hex, &result_hex).await {
                                        Ok(req_id) => {
                                            pending_submissions.insert(req_id, PendingShare {
                                                is_devfee: share.is_devfee,
                                                job_id: share.job_id.clone(),
                                            });
                                            if share.is_devfee {
                                                dev_share_inflight = true;
                                                tracing::info!(
                                                    job_id = %share.job_id,
                                                    nonce = share.nonce,
                                                    req_id,
                                                    "submitted devfee share"
                                                );
                                            } else {
                                                tracing::debug!(
                                                    job_id = %share.job_id,
                                                    nonce = share.nonce,
                                                    req_id,
                                                    "submitted share"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                job_id = %share.job_id,
                                                nonce = share.nonce,
                                                is_devfee = share.is_devfee,
                                                "submit_share error: {e}"
                                            );
                                        }
                                    }
                                }
                                None => {
                                    tracing::warn!("shares channel closed (no workers alive); stopping pool task to avoid reconnect storm");
                                    return;
                                }
                            }
                        }

                        // 2) Incoming pool messages
                        msg = client.read_json() => {
                            match msg {
                                Ok(v) => {
                                    if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                        if let Some(params) = v.get("params") {
                                            if let Ok(mut job) = serde_json::from_value::<oxide_core::stratum::PoolJob>(params.clone()) {
                                                job.cache_target();
                                                let clean = params.get("clean_jobs").and_then(|x| x.as_bool()).unwrap_or(true);
                                                let job_id = job.job_id.clone();
                                                let donate_now = enable_devfee && devfee.should_donate();
                                                if donate_now && !using_dev {
                                                    tracing::info!(
                                                        job_id = %job_id,
                                                        jobs_seen = devfee.observed_jobs(),
                                                        pending = devfee.pending(),
                                                        "devfee activation triggered by job"
                                                    );
                                                    match StratumClient::connect_and_login(&main_pool, DEV_WALLET_ADDRESS, &pass, &agent, tls).await {
                                                        Ok((dev_client, dev_job_opt)) => {
                                                            client = dev_client;
                                                            using_dev = true;
                                                            dev_share_inflight = false;
                                                            pending_submissions.clear();
                                                            valid_job_ids.clear();
                                                            seen_nonces.clear();
                                                            devfee.mark_started();
                                                            if let Some(dev_job) = dev_job_opt {
                                                                if enable_devfee {
                                                                    let _ = devfee.should_donate();
                                                                }
                                                                push_job_to_workers(
                                                                    &jobs_tx,
                                                                    &mut valid_job_ids,
                                                                    &mut seen_nonces,
                                                                    dev_job,
                                                                    true,
                                                                    true,
                                                                );
                                                            } else {
                                                                tracing::debug!("devfee login returned no job; awaiting notify");
                                                            }
                                                            continue;
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(
                                                                job_id = %job_id,
                                                                error = %e,
                                                                "devfee connect failed; continuing with user job"
                                                            );
                                                        }
                                                    }
                                                }
                                                push_job_to_workers(
                                                    &jobs_tx,
                                                    &mut valid_job_ids,
                                                    &mut seen_nonces,
                                                    job,
                                                    using_dev,
                                                    clean,
                                                );
                                            }
                                        }
                                        continue;
                                    }

                                    if let Some(req_id) = v.get("id").and_then(|x| x.as_u64()) {
                                        if let Some(pending) = pending_submissions.remove(&req_id) {
                                            let is_dev = pending.is_devfee;
                                            let job_id = pending.job_id;
                                            let accepted = v.get("result").map(|res| {
                                                res.get("status").and_then(|s| s.as_str()) == Some("OK") || res.as_bool() == Some(true)
                                            }).unwrap_or(false);

                                            if accepted {
                                                if is_dev {
                                                    stats.dev_accepted.fetch_add(1, Ordering::Relaxed);
                                                } else {
                                                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                                                }
                                                tracing::info!(
                                                    job_id = %job_id,
                                                    req_id,
                                                    is_devfee = is_dev,
                                                    accepted_user = stats.accepted.load(Ordering::Relaxed),
                                                    rejected_user = stats.rejected.load(Ordering::Relaxed),
                                                    accepted_dev = stats.dev_accepted.load(Ordering::Relaxed),
                                                    rejected_dev = stats.dev_rejected.load(Ordering::Relaxed),
                                                    "share accepted"
                                                );
                                            } else {
                                                if let Some(err) = v.get("error") {
                                                    if is_dev {
                                                        stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                                                    } else {
                                                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                                                    }
                                                    tracing::warn!(
                                                        job_id = %job_id,
                                                        req_id,
                                                        is_devfee = is_dev,
                                                        error = %err,
                                                        "share rejected"
                                                    );
                                                } else {
                                                    if is_dev {
                                                        stats.dev_rejected.fetch_add(1, Ordering::Relaxed);
                                                    } else {
                                                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                                                    }
                                                    tracing::warn!(
                                                        job_id = %job_id,
                                                        req_id,
                                                        is_devfee = is_dev,
                                                        "share rejected without explicit error"
                                                    );
                                                }
                                            }

                                            if is_dev {
                                                tracing::info!("devfee share complete; reconnecting to user pool");
                                                stats.pool_connected.store(false, Ordering::Relaxed);
                                                break;
                                            }
                                            continue;
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

fn push_job_to_workers(
    jobs_tx: &tokio::sync::broadcast::Sender<WorkItem>,
    valid_job_ids: &mut HashSet<String>,
    seen_nonces: &mut HashMap<String, HashSet<u32>>,
    job: oxide_core::stratum::PoolJob,
    is_devfee: bool,
    clean: bool,
) {
    if clean {
        valid_job_ids.clear();
        seen_nonces.clear();
    }

    let job_id = job.job_id.clone();
    match jobs_tx.send(WorkItem { job, is_devfee }) {
        Ok(_) => tracing::debug!(job_id = %job_id, is_devfee, "broadcast job to workers"),
        Err(e) => tracing::warn!(
            job_id = %job_id,
            error = %e,
            "failed to broadcast job to workers",
        ),
    }

    valid_job_ids.insert(job_id);
}
