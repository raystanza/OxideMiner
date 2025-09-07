use anyhow::Result;
use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use oxide_core::worker::{Share, WorkItem};
use oxide_core::{
    autotune_snapshot, cpu_has_aes, huge_pages_enabled, spawn_workers, Config, DevFeeScheduler,
    StratumClient, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "OxideMiner - Rust Monero RandomX CPU miner (CLI MVP)"
)]
struct Args {
    /// pool like "pool.supportxmr.com:5555"
    #[arg(short = 'o', long = "url")]
    pool: String,

    /// Your XMR wallet address
    #[arg(short = 'u', long = "user")]
    wallet: String,

    /// Pool password (often 'x')
    #[arg(short = 'p', long = "pass", default_value = "x")]
    pass: String,

    /// Number of threads (omit for auto)
    #[arg(short = 't', long = "threads")]
    threads: Option<usize>,

    /// Disable dev fee (testing builds only)
    #[arg(long = "no-devfee")]
    no_devfee: bool,

    /// Enable TLS for pool connection
    #[arg(long = "tls")]
    tls: bool,

    /// Expose a simple HTTP API on this port
    #[arg(long = "api-port")]
    api_port: Option<u16>,

    /// Pin worker threads to CPU cores
    #[arg(long = "affinity")]
    affinity: bool,

    /// Request huge pages for RandomX dataset
    #[arg(long = "huge-pages")]
    huge_pages: bool,

    /// Enable verbose debug logs; when set, also writes to ./logs/ (daily rotation)
    #[arg(long = "debug")]
    debug: bool,

    /// Hashes processed per worker batch
    #[arg(long = "batch-size", default_value_t = 10_000)]
    batch_size: usize,

    /// Disable yielding between hash batches
    #[arg(long = "no-yield")]
    no_yield: bool,
}

fn tiny_jitter_ms() -> u64 {
    // Derive a tiny jitter from the current time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.subsec_nanos() as u64;
    100 + (nanos % 500) // 100...600 ms
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

        info!("debug logging enabled; writing rotating logs under ./logs/");
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .init();
    }
    // ----------------------------------------------------------

    let cfg = Config {
        pool: args.pool,
        wallet: args.wallet,
        pass: Some(args.pass),
        threads: args.threads,
        enable_devfee: !args.no_devfee,
        tls: args.tls,
        api_port: args.api_port,
        affinity: args.affinity,
        huge_pages: args.huge_pages,
        agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
        batch_size: args.batch_size,
        no_yield: args.no_yield,
    };

    // Detect huge/large pages and warn once if not present
    let hp_supported = huge_pages_enabled();
    if !hp_supported {
        warn!(
            "Huge pages are NOT enabled; RandomX performance may be reduced. \
            Linux: configure vm.nr_hugepages; Windows: enable 'Lock pages in memory' and Large Pages."
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
        !cfg.no_yield,
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

                if let Some(job) = initial_job {
                    let _ = jobs_tx.send(WorkItem {
                        job,
                        is_devfee: false,
                    });
                }

                let mut devfee = DevFeeScheduler::new();
                let mut using_dev = false;

                loop {
                    tokio::select! {
                        // 1) Incoming pool messages
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
                                                    if let Some(job) = job_opt {
                                                        let _ = jobs_tx.send(WorkItem { job, is_devfee: true });
                                                    }
                                                }
                                                Err(e) => warn!("devfee connect failed: {e}"),
                                            }
                                        } else if let Some(params) = v.get("params") {
                                            if let Ok(job) = oxide_core::stratum::PoolJob::parse(params.clone()) {
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
                                                "share accepted"
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
                                            "share rejected"
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

                        // 2) Outgoing share submissions
                        maybe_share = shares_rx.recv() => {
                            match maybe_share {
                                Some(share) => {
                                    // Submit LE nonce (8 hex) and LE result (64 hex)
                                    let nonce_hex  = hex::encode(share.nonce.to_le_bytes());
                                    let result_hex = hex::encode(share.result);

                                    tracing::debug!(
                                        job_id = %share.job_id,
                                        nonce_hex = %nonce_hex,
                                        result_hex = %result_hex,
                                        is_devfee = share.is_devfee,
                                        "submit_share"
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
                                                if let Some(job) = job_opt {
                                                    let _ = jobs_tx.send(WorkItem { job, is_devfee: false });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_in_range() {
        let j = tiny_jitter_ms();
        assert!(j >= 100 && j <= 600);
    }
}

// Tiny /metrics endpoint (optional)
async fn run_http_api(port: u16, accepted: Arc<AtomicU64>, rejected: Arc<AtomicU64>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HTTP bind failed: {e}");
            return;
        }
    };
    info!("HTTP API listening on http://{addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("HTTP accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let a = accepted.clone();
        let r = rejected.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let a = a.clone();
                let r = r.clone();

                async move {
                    if req.method() == Method::GET && req.uri().path() == "/metrics" {
                        let body = format!(
                            "{{\"accepted\":{},\"rejected\":{}}}",
                            a.load(Ordering::Relaxed),
                            r.load(Ordering::Relaxed)
                        );
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    } else {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(404)
                                .body(Full::new(Bytes::from("not found")))
                                .unwrap(),
                        )
                    }
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("http connection error: {err}");
            }
        });
    }
}
