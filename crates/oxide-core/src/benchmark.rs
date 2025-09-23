// OxideMiner/crates/oxide-core/src/benchmark.rs

#[cfg(feature = "randomx")]
use anyhow::Result;
#[cfg(not(feature = "randomx"))]
use anyhow::{anyhow, Result};
#[cfg(feature = "randomx")]
use std::time::{Duration, Instant};

#[cfg(feature = "randomx")]
use tokio::task;

#[cfg(feature = "randomx")]
use crate::worker::{create_vm_for_dataset, ensure_fullmem_dataset, hash, set_large_pages};

#[cfg(feature = "randomx")]
const BENCHMARK_BLOB_TEMPLATE: [u8; 76] = [
    0x01, 0x00, 0xd5, 0xad, 0xc4, 0x9a, 0x05, 0x3b, 0x88, 0x18, 0xb2, 0xb6, 0x02, 0x3c, 0xd2, 0xd5,
    0x32, 0xc6, 0x77, 0x4e, 0x16, 0x4a, 0x8f, 0xca, 0xcd, 0x60, 0x36, 0x51, 0xcb, 0x3e, 0xa0, 0xcb,
    0x7f, 0x93, 0x40, 0xb2, 0x8e, 0xc0, 0x16, 0xb4, 0xbc, 0x4c, 0xa3, 0x01, 0xaa, 0x01, 0x01, 0xff,
    0x6e, 0x08, 0xac, 0xbb, 0x27, 0x02, 0xea, 0xb0, 0x30, 0x67, 0x87, 0x03, 0x49, 0x13, 0x9b, 0xee,
    0x7e, 0xab, 0x2c, 0xa2, 0xe0, 0x30, 0xa6, 0xbb, 0x73, 0xd4, 0xf6, 0x8a,
];

#[cfg(feature = "randomx")]
const BENCHMARK_NONCE_OFFSET: usize = 39;

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

    let seed = [0u8; 32];
    let (shared_cache, shared_dataset) = ensure_fullmem_dataset(&seed, threads_u32)?;

    let mut handles: Vec<task::JoinHandle<Result<u64>>> = Vec::new();
    for id in 0..threads {
        let duration = duration;
        let batch_size = batch_size;
        let threads_u32 = threads_u32;
        let yield_between_batches = yield_between_batches;
        let cache = shared_cache.clone();
        let dataset = shared_dataset.clone();
        handles.push(task::spawn(async move {
            let vm = create_vm_for_dataset(&cache, &dataset, None)?;
            let mut blob = BENCHMARK_BLOB_TEMPLATE;
            let mut nonce = id as u32;
            let start = Instant::now();
            let deadline = start + duration;
            let mut hashes: u64 = 0;
            'outer: loop {
                if Instant::now() >= deadline {
                    break;
                }
                let mut batch_hashes: u64 = 0;
                for _ in 0..batch_size {
                    blob[BENCHMARK_NONCE_OFFSET..BENCHMARK_NONCE_OFFSET + 4]
                        .copy_from_slice(&nonce.to_le_bytes());
                    let _ = hash(&vm, &blob);
                    hashes += 1;
                    batch_hashes += 1;
                    nonce = nonce.wrapping_add(threads_u32);
                    if Instant::now() >= deadline {
                        break 'outer;
                    }
                }
                if batch_hashes > 0 && tracing::enabled!(tracing::Level::DEBUG) {
                    tracing::debug!(
                        thread = id,
                        batch_hashes,
                        total_hashes = hashes,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "randomx benchmark progress"
                    );
                }
                if yield_between_batches {
                    task::yield_now().await;
                }
            }
            tracing::debug!(
                thread = id,
                total_hashes = hashes,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "randomx benchmark complete"
            );
            Ok(hashes)
        }));
    }

    let mut total: u64 = 0;
    for h in handles {
        total += h.await??;
    }
    Ok(total as f64 / duration.as_secs_f64())
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
