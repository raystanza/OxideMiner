use anyhow::Result;
use clap::Parser;
use oxide_core::{Config, StratumClient, spawn_workers, DevFeeScheduler, DEV_FEE_BASIS_POINTS};
use tokio::sync::broadcast;
use tracing::{info, Level};
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

    // broadcast so every worker gets every new job
    let (tx, _rx0) = broadcast::channel(64);
    let n_workers = cfg.threads.unwrap_or_else(|| num_cpus::get());
    let _workers = spawn_workers(n_workers, tx.clone());

    let main_pool = cfg.pool.clone();
    let wallet = cfg.wallet.clone();
    let pass = cfg.pass.clone().unwrap_or_else(|| "x".into());
    let agent = cfg.agent.clone();

    let enable_devfee = cfg.enable_devfee;
    let mut devfee = DevFeeScheduler::new();
    info!("dev fee fixed at {} bps (1%): {}", DEV_FEE_BASIS_POINTS, enable_devfee);

    tokio::spawn(async move {
        let mut client = match StratumClient::connect_and_login(&main_pool, &wallet, &pass, &agent).await {
            Ok(c) => c,
            Err(e) => { eprintln!("connect/login failed: {e}"); return; }
        };

        loop {
            match client.next_job().await {
                Ok(job) => {
                    let donate_now = enable_devfee && devfee.should_donate();
                    // TODO: if donate_now, route to dev pool client instead of main pool
                    let _ = tx.send(oxide_core::worker::WorkItem { job });
                }
                Err(e) => {
                    eprintln!("pool error: {e}");
                    break;
                }
            }
        }
    });

    // graceful shutdown on Ctrl+C
    tokio::signal::ctrl_c().await?;
    Ok(())
}
