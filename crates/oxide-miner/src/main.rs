use anyhow::Result;
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use oxide_core::worker::{Share, WorkItem};
use oxide_core::{
    spawn_workers, Config, DevFeeScheduler, StratumClient, DEV_FEE_BASIS_POINTS, DEV_WALLET_ADDRESS,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn, Level};
use tracing_subscriber::{util::SubscriberInitExt, FmtSubscriber};

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
}

#[tokio::main]
async fn main() -> Result<()> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_env_filter("info")
        .finish()
        .init();

    let args = Args::parse();
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
    };

    // Broadcast: jobs -> workers
    let (jobs_tx, _jobs_rx0) = broadcast::channel(64);
    // MPSC: shares <- workers
    let (shares_tx, mut shares_rx) = mpsc::unbounded_channel::<Share>();

    let n_workers = cfg.threads.unwrap_or_else(|| num_cpus::get());
    let _workers = spawn_workers(
        n_workers,
        jobs_tx.clone(),
        shares_tx,
        cfg.affinity,
        cfg.huge_pages,
    );

    let main_pool = cfg.pool.clone();
    let wallet = cfg.wallet.clone();
    let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
    let agent = cfg.agent.clone();

    info!(
        "dev fee fixed at {} bps (1%): {}",
        DEV_FEE_BASIS_POINTS, cfg.enable_devfee
    );

    let accepted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));

    if let Some(port) = cfg.api_port {
        let a = accepted.clone();
        let r = rejected.clone();
        tokio::spawn(async move {
            run_http_api(port, a, r).await;
        });
    }

    tokio::spawn(async move {
        let (mut client, initial_job) =
            match StratumClient::connect_and_login(&main_pool, &wallet, &pass, &agent, cfg.tls)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("connect/login failed: {e}");
                    return;
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
                // 1) Handle pool messages (jobs, submit responses, status, errors)
                msg = client.read_json() => {
                    match msg {
                        Ok(v) => {
                            // New job?
                            if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                // dev fee scheduling
                                if cfg.enable_devfee && !using_dev && devfee.should_donate() {
                                    match StratumClient::connect_and_login(&main_pool, DEV_WALLET_ADDRESS, &pass, &agent, cfg.tls).await {
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
                                    if let Ok(job) = serde_json::from_value::<oxide_core::stratum::PoolJob>(params.clone()) {
                                        let _ = jobs_tx.send(WorkItem { job, is_devfee: using_dev });
                                    }
                                }
                                continue;
                            }

                            // Submit response patterns:
                            // - {"result":{"status":"OK", ...}}
                            // - {"result":true}
                            if let Some(res) = v.get("result") {
                                let ok = res.get("status").and_then(|s| s.as_str()) == Some("OK")
                                    || res.as_bool() == Some(true);
                                if ok {
                                    accepted.fetch_add(1, Ordering::Relaxed);
                                    info!(accepted = accepted.load(Ordering::Relaxed), rejected = rejected.load(Ordering::Relaxed), "share accepted");
                                    continue;
                                }
                            }
                            if let Some(err) = v.get("error") {
                                rejected.fetch_add(1, Ordering::Relaxed);
                                warn!(accepted = accepted.load(Ordering::Relaxed), rejected = rejected.load(Ordering::Relaxed), error = %err, "share rejected");
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("pool read error: {e}");
                            break;
                        }
                    }
                }

                // 2) A worker found a share → submit it
                maybe_share = shares_rx.recv() => {
                    match maybe_share {
                        Some(share) => {
                            // We wrote nonce into the blob as LE; submit same LE bytes as hex.
                            let nonce_hex = hex::encode(share.nonce.to_le_bytes());
                            let result_hex = hex::encode(share.result);
                            if let Err(e) = client.submit_share(&share.job_id, &nonce_hex, &result_hex).await {
                                eprintln!("submit error: {e}");
                            }
                            if share.is_devfee {
                                match StratumClient::connect_and_login(&main_pool, &wallet, &pass, &agent, cfg.tls).await {
                                    Ok((nc, job_opt)) => {
                                        client = nc;
                                        using_dev = false;
                                        if let Some(job) = job_opt {
                                            let _ = jobs_tx.send(WorkItem { job, is_devfee: false });
                                        }
                                    }
                                    Err(e) => { eprintln!("reconnect failed: {e}"); break; }
                                }
                            }
                        }
                        None => break, // all workers dropped
                    }
                }
            }
        }
    });

    // graceful shutdown on Ctrl+C
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run_http_api(port: u16, accepted: Arc<AtomicU64>, rejected: Arc<AtomicU64>) {
    let addr = ([0, 0, 0, 0], port).into();
    let make_svc = make_service_fn(move |_| {
        let a = accepted.clone();
        let r = rejected.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let a = a.clone();
                let r = r.clone();
                async move {
                    if req.method() == Method::GET && req.uri().path() == "/metrics" {
                        let body = format!(
                            "{{\"accepted\":{},\"rejected\":{}}}",
                            a.load(Ordering::Relaxed),
                            r.load(Ordering::Relaxed)
                        );
                        Ok::<_, hyper::Error>(Response::new(Body::from(body)))
                    } else {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(404)
                                .body(Body::from("not found"))
                                .unwrap(),
                        )
                    }
                }
            }))
        }
    });
    if let Err(e) = Server::bind(&addr).serve(make_svc).await {
        eprintln!("http server error: {e}");
    }
}
