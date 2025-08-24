use anyhow::Result;
use clap::Parser;
use oxide_core::{Config, StratumClient, spawn_workers, DevFeeScheduler, DEV_FEE_BASIS_POINTS};
use oxide_core::worker::{WorkItem, Share};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn, Level};
use tracing_subscriber::{FmtSubscriber, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(author, version, about="OxideMiner - Rust Monero RandomX CPU miner (CLI MVP)")]
struct Args {
    /// pool like "pool.supportxmr.com:5555"
    #[arg(short='o', long="url")]
    pool: String,

    /// Your XMR wallet address
    #[arg(short='u', long="user")]
    wallet: String,

    /// Pool password (often 'x')
    #[arg(short='p', long="pass", default_value="x")]
    pass: String,

    /// Number of threads (omit for auto)
    #[arg(short='t', long="threads")]
    threads: Option<usize>,

    /// Disable dev fee (testing builds only)
    #[arg(long="no-devfee")]
    no_devfee: bool,
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
        tls: false,
        agent: format!("OxideMiner/{}", env!("CARGO_PKG_VERSION")),
    };

    // Broadcast: jobs -> workers
    let (jobs_tx, _jobs_rx0) = broadcast::channel(64);
    // MPSC: shares <- workers
    let (shares_tx, mut shares_rx) = mpsc::unbounded_channel::<Share>();

    let n_workers = cfg.threads.unwrap_or_else(|| num_cpus::get());
    let _workers = spawn_workers(n_workers, jobs_tx.clone(), shares_tx);

    let main_pool = cfg.pool.clone();
    let wallet = cfg.wallet.clone();
    let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
    let agent = cfg.agent.clone();

    info!("dev fee fixed at {} bps (1%): {}", DEV_FEE_BASIS_POINTS, cfg.enable_devfee);

    tokio::spawn(async move {
        let (mut client, initial_job) = match StratumClient::connect_and_login(&main_pool, &wallet, &pass, &agent).await {
            Ok(v) => v,
            Err(e) => { eprintln!("connect/login failed: {e}"); return; }
        };

        if let Some(job) = initial_job {
            let _ = jobs_tx.send(WorkItem { job });
        }

        let mut accepted: u64 = 0;
        let mut rejected: u64 = 0;
        let mut _devfee = DevFeeScheduler::new(); // (not yet routing)

        loop {
            tokio::select! {
                // 1) Handle pool messages (jobs, submit responses, status, errors)
                msg = client.read_json() => {
                    match msg {
                        Ok(v) => {
                            // New job?
                            if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                if let Some(params) = v.get("params") {
                                    if let Ok(job) = serde_json::from_value::<oxide_core::stratum::PoolJob>(params.clone()) {
                                        let _ = jobs_tx.send(WorkItem { job });
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
                                    accepted += 1;
                                    info!(accepted, rejected, "share accepted");
                                    continue;
                                }
                            }
                            if let Some(err) = v.get("error") {
                                rejected += 1;
                                warn!(accepted, rejected, error = %err, "share rejected");
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
