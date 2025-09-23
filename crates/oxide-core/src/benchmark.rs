// OxideMiner/crates/oxide-core/src/benchmark.rs

#[cfg(feature = "randomx")]
use anyhow::Result;
#[cfg(not(feature = "randomx"))]
use anyhow::{anyhow, Result};
use std::time::{Duration, Instant};

#[cfg(feature = "randomx")]
use tokio::task;

#[cfg(feature = "randomx")]
use crate::worker::{create_vm_for_dataset, ensure_fullmem_dataset, hash, set_large_pages};

/// Run a simple RandomX benchmark and return hashes per second.
#[cfg(feature = "randomx")]
pub async fn run_benchmark(
    threads: usize,
    seconds: u64,
    large_pages: bool,
    batch_size: usize,
    yield_between_batches: bool,
) -> Result<f64> {
    let _ = set_large_pages(large_pages);
    let duration = Duration::from_secs(seconds);
    let threads_u32 = threads as u32;

    let mut handles: Vec<task::JoinHandle<Result<u64>>> = Vec::new();
    for id in 0..threads {
        let duration = duration;
        let batch_size = batch_size;
        let threads_u32 = threads_u32;
        let yield_between_batches = yield_between_batches;
        handles.push(task::spawn(async move {
            let seed = [0u8; 32];
            let vm = {
                let (cache, dataset) = ensure_fullmem_dataset(&seed, threads_u32)?;
                create_vm_for_dataset(&cache, &dataset, None)?
            };
            let mut blob = vec![0u8; 43];
            let mut nonce = id as u32;
            let start = Instant::now();
            let mut hashes: u64 = 0;
            while start.elapsed() < duration {
                for _ in 0..batch_size {
                    // write nonce at offset 39
                    blob[39..43].copy_from_slice(&nonce.to_le_bytes());
                    let _ = hash(&vm, &blob);
                    nonce = nonce.wrapping_add(threads_u32);
                }
                hashes += batch_size as u64;
                if yield_between_batches {
                    task::yield_now().await;
                }
            }
            Ok(hashes)
        }));
    }

    let mut total: u64 = 0;
    for h in handles {
        total += h.await??;
    }
    Ok(total as f64 / seconds as f64)
}

#[cfg(not(feature = "randomx"))]
#[allow(unused_variables)]
pub async fn run_benchmark(
    threads: usize,
    seconds: u64,
    large_pages: bool,
    batch_size: usize,
    yield_between_batches: bool,
) -> Result<f64> {
    Err(anyhow!("built without RandomX support"))
}
