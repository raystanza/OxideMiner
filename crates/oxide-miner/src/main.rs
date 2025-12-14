// OxideMiner/crates/oxide-miner/src/main.rs

mod args;
mod http_api;
mod miner;
mod stats;
mod themes;
mod util;

use anyhow::Result;
use args::parse_with_config;

#[tokio::main]
async fn main() -> Result<()> {
    let args::ParsedArgs {
        args,
        warnings,
        config,
    } = parse_with_config();
    if !warnings.is_empty() {
        for warning in warnings {
            if warning.should_print(args.debug) {
                eprintln!("config warning: {}", warning.message());
            }
        }
    }

    miner::run(args, config).await
}
