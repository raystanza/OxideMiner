use anyhow::Result;
use clap::Parser;

mod cli;
mod http;
mod logging;
mod miner;

use cli::Args;
use logging::init_logging;
use miner::{run, run_benchmark};
use oxide_core::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _guard = init_logging(args.debug);

    if args.benchmark {
        run_benchmark(&args).await?;
        return Ok(());
    }

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

    run(cfg).await
}
