// OxideMiner/crates/oxide-miner/src/main.rs

mod args;
mod http_api;
mod miner;
mod stats;
mod util;

use anyhow::Result;
use args::load_args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = load_args();
    miner::run(args).await
}
