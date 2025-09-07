mod args;
mod http_api;
mod miner;
mod util;

use anyhow::Result;
use args::Args;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    miner::run(args).await
}
