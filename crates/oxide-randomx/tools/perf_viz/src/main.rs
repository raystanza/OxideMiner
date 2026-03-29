mod ingest;
mod model;
mod schema;
mod web;

use crate::ingest::load_dataset;
use crate::model::IngestConfig;
use crate::web::serve_web_app;
use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "perf_viz")]
#[command(about = "Developer visualization app for oxide-randomx perf_results")]
struct Args {
    #[arg(long, default_value = "perf_results")]
    root: PathBuf,

    #[arg(long, default_value_t = 512 * 1024)]
    raw_preview_max_bytes: usize,

    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    #[arg(long, default_value_t = 8765)]
    port: u16,

    #[arg(long, default_value_t = false)]
    no_open: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let root = resolve_root(&args.root)?;

    let config = IngestConfig {
        root,
        raw_preview_max_bytes: args.raw_preview_max_bytes,
    };

    let dataset = load_dataset(&config)?;
    serve_web_app(dataset, &args.host, args.port, !args.no_open).await
}

fn resolve_root(input: &Path) -> Result<PathBuf> {
    if input.exists() {
        return input
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", input.display()));
    }

    let cwd = std::env::current_dir().context("failed to get cwd")?;
    let candidates = [
        cwd.join(input),
        cwd.join("..").join(input),
        cwd.join("../..").join(input),
        cwd.join("../../..").join(input),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return candidate
                .canonicalize()
                .with_context(|| format!("failed to canonicalize {}", candidate.display()));
        }
    }

    anyhow::bail!(
        "could not find perf_results root from '{}'. tried relative candidates from cwd",
        input.display()
    );
}
