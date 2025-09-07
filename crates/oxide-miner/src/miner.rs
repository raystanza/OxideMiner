use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tracing::{info, warn};

use oxide_core::worker::{Share, WorkItem};
use oxide_core::{
    autotune_snapshot, cpu_has_aes, huge_pages_enabled, spawn_workers, Config, DevFeeScheduler,
    StratumClient, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};

use crate::cli::Args;
use crate::http::run_http_api;

/// Run a local RandomX benchmark and exit.
pub async fn run_benchmark(args: &Args) -> Result<()> {
    let hp_supported = huge_pages_enabled();
    if args.huge_pages && !hp_supported {
        warn!("Huge pages are NOT enabled; RandomX performance may be reduced.");
    }
    let snap = autotune_snapshot();
    let n_workers = args.threads.unwrap_or(snap.suggested_threads);
    let large_pages = args.huge_pages && hp_supported;
    info!(
        "benchmark: threads={} batch_size={} large_pages={} yield={}",
        n_workers, args.batch_size, large_pages, !args.no_yield
    );
    let hps =
        oxide_core::run_benchmark(n_workers, 10, large_pages, args.batch_size, !args.no_yield)
            .await?;
    println!("RandomX benchmark: {:.2} H/s", hps);
    Ok(())
}

/// Main mining loop.
pub async fn run(cfg: Config) -> Result<()> {
    // Detect huge/large pages and warn once if not present
    let hp_supported = huge_pages_enabled();
    if !hp_supported {
        warn!(
            "Huge pages are NOT enabled; RandomX performance may be reduced. \nLinux: configure vm.nr_hugepages; Windows: enable 'Lock pages in memory' and Large Pages."
        );
    }

    // Take snapshot to log how auto-tune decided thread count
    let snap = autotune_snapshot();
    let auto_threads = snap.suggested_threads;
    let n_workers = cfg.threads.unwrap_or(auto_threads);

    // One-line summary that's easy to read in logs
    let l3_mib = snap.l3_bytes.map(|b| (b as u64) / (1024 * 1024));
    let avail_mib = snap.available_bytes / (1024 * 1024);
    let aes = cpu_has_aes();

    // If spawn call passes a 'large_pages' boolean, prefer user opt-in AND OS support
    let large_pages = cfg.huge_pages && hp_supported;

    if let Some(user_t) = cfg.threads {
        info!(
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
        info!(
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

    if !huge_pages_enabled() {
        warn!("huge pages are not enabled; mining performance may be reduced");
    }

    if cfg.threads.is_none() {
        info!("auto-selected {} worker threads", n_workers);
    }
    let _workers = spawn_workers(
        n_workers,
        jobs_tx.clone(),
        shares_tx,
        cfg.affinity,
        large_pages,
        cfg.batch_size,
        cfg.yield_between_batches,
    );

    let main_pool = cfg.pool.clone();
    let user_wallet = cfg.wallet.clone();
    let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
    let agent = cfg.agent.clone();

    info!(
        "dev fee fixed at {} bps (1%): {}",
        DEV_FEE_BASIS_POINTS, cfg.enable_devfee
    );

    let accepted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));

    // Optional tiny /metrics API
    if let Some(port) = cfg.api_port {
        let a = accepted.clone();
        let r = rejected.clone();
        tokio::spawn(async move {
            run_http_api(port, a, r).await;
        });
    }

    // Snapshot flags for the async task
    let enable_devfee = cfg.enable_devfee;
    let tls = cfg.tls;

    // Pool IO task with reconnect loop
    let pool_handle = tokio::spawn({
        let jobs_tx = jobs_tx.clone();
        let accepted = accepted.clone();
        let rejected = rejected.clone();
        let main_pool = main_pool.clone();
        let user_wallet = user_wallet.clone();
        let pass = pass.clone();
        let agent = agent.clone();

        async move {
            use tokio::time::{sleep, Duration};

            let mut backoff_ms = 1_000u64;
            loop {
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
                        v
                    }
                    Err(e) => {
                        eprintln!("connect/login failed: {e}");
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

                if let Some(job) = initial_job {
                    let id = job.job_id.clone();
                    let _ = jobs_tx.send(WorkItem {
                        job,
                        is_devfee: false,
                    });
                    // Seed valid job ids with the login job
                    valid_job_ids.insert(id);
                }

                let mut devfee = DevFeeScheduler::new();
                let mut using_dev = false;

                loop {
                    tokio::select! {
                        biased;
                        // 1) Outgoing share submissions
                        maybe_share = shares_rx.recv() => {
                            match maybe_share {
                                Some(share) => {
                                    // Drop stale shares whose job_id is no longer valid for this session.
                                    if !valid_job_ids.contains(&share.job_id) {
                                        tracing::debug!(job_id = %share.job_id, "dropping stale share (invalid job_id for current session)");
                                        continue;
                                    }
                                    // Drop duplicates for the same (job_id, nonce)
                                    let entry = seen_nonces.entry(share.job_id.clone()).or_default();
                                    if !entry.insert(share.nonce) {
                                        tracing::debug!(job_id = %share.job_id, nonce = share.nonce, "dropping duplicate share (already submitted)");
                                        continue;
                                    }
                                    // Submit LE nonce (8 hex) and LE result (64 hex)
                                    let nonce_hex  = hex::encode(share.nonce.to_le_bytes());
                                    let result_hex = hex::encode(share.result);

                                    tracing::debug!(
                                        job_id = %share.job_id,
                                        nonce_hex = %nonce_hex,
                                        result_hex = %result_hex,
                                        is_devfee = share.is_devfee,
                                        "submit_share",
                                    );

                                    if let Err(e) = client.submit_share(&share.job_id, &nonce_hex, &result_hex).await {
                                        eprintln!("submit error: {e}");
                                    }

                                    // After dev fee share, reconnect with user wallet
                                    if share.is_devfee && using_dev {
                                        match StratumClient::connect_and_login(&main_pool, &user_wallet, &pass, &agent, tls).await {
                                            Ok((nc, job_opt)) => {
                                                client = nc;
                                                using_dev = false;
                                                // New session: reset valid job ids and dedupe state
                                                valid_job_ids.clear();
                                                seen_nonces.clear();
                                                if let Some(job) = job_opt {
                                                    let id = job.job_id.clone();
                                                    let _ = jobs_tx.send(WorkItem { job, is_devfee: false });
                                                    valid_job_ids.insert(id);
                                                }
                                            }
                                            Err(e) => {
                                                warn!("reconnect failed (devfee -> user): {e}");
                                                sleep(Duration::from_millis(tiny_jitter_ms())).await;
                                                break; // break inner loop -> reconnect
                                            }
                                        }
                                    }
                                }
                                None => {
                                    warn!("shares channel closed (no workers alive); stopping pool task to avoid reconnect storm");
                                    return; // end the pool task instead of reconnecting
                                }
                            }
                        }

                        // 2) Incoming pool messages
                        msg = client.read_json() => {
                            match msg {
                                Ok(v) => {
                                    if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                        // dev fee scheduling: occasionally reconnect with dev wallet
                                        if enable_devfee && !using_dev && devfee.should_donate() {
                                            match StratumClient::connect_and_login(&main_pool, DEV_WALLET_ADDRESS, &pass, &agent, tls).await {
                                                Ok((dc, job_opt)) => {
                                                    client = dc;
                                                    using_dev = true;
                                                    // New session: reset valid job ids and dedupe state
                                                    valid_job_ids.clear();
                                                    seen_nonces.clear();
                                                    if let Some(job) = job_opt {
                                                        let id = job.job_id.clone();
                                                        let _ = jobs_tx.send(WorkItem { job, is_devfee: true });
                                                        valid_job_ids.insert(id);
                                                    }
                                                }
                                                Err(e) => warn!("devfee connect failed: {e}"),
                                            }
                                        } else if let Some(params) = v.get("params") {
                                            if let Ok(mut job) = serde_json::from_value::<oxide_core::stratum::PoolJob>(params.clone()) {
                                                job.cache_target();
                                                // Update valid job ids set: when clean_jobs=true, replace; else, add.
                                                let clean = params.get("clean_jobs").and_then(|x| x.as_bool()).unwrap_or(true);
                                                if clean {
                                                    valid_job_ids.clear();
                                                    seen_nonces.clear();
                                                }
                                                valid_job_ids.insert(job.job_id.clone());
                                                let _ = jobs_tx.send(WorkItem { job, is_devfee: using_dev });
                                            }
                                        }
                                        continue;
                                    }

                                    // Submit responses
                                    if let Some(res) = v.get("result") {
                                        let ok = res.get("status").and_then(|s| s.as_str()) == Some("OK")
                                            || res.as_bool() == Some(true);
                                        if ok {
                                            accepted.fetch_add(1, Ordering::Relaxed);
                                            info!(
                                                accepted = accepted.load(Ordering::Relaxed),
                                                rejected = rejected.load(Ordering::Relaxed),
                                                "share accepted",
                                            );
                                            continue;
                                        }
                                    }
                                    if let Some(err) = v.get("error") {
                                        rejected.fetch_add(1, Ordering::Relaxed);
                                        warn!(
                                            accepted = accepted.load(Ordering::Relaxed),
                                            rejected = rejected.load(Ordering::Relaxed),
                                            error = %err,
                                            "share rejected",
                                        );
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("pool read error: {e}");
                                    sleep(Duration::from_millis(tiny_jitter_ms())).await;
                                    break; // break inner loop -> reconnect
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
                eprintln!("pool task ended unexpectedly: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received; shutting down.");
        }
    }

    Ok(())
}

fn tiny_jitter_ms() -> u64 {
    // Derive a tiny jitter from the current time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.subsec_nanos() as u64;
    100 + (nanos % 500) // 100...600 ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_in_range() {
        let j = tiny_jitter_ms();
        assert!(j >= 100 && j <= 600);
    }
}
