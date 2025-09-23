// OxideMiner/crates/oxide-core/src/benchmark.rs

#[cfg(feature = "randomx")]
use anyhow::Result;
#[cfg(not(feature = "randomx"))]
use anyhow::{anyhow, Result};
#[cfg(feature = "randomx")]
use std::sync::Arc;
#[cfg(feature = "randomx")]
use std::time::{Duration, Instant};

#[cfg(feature = "randomx")]
use tokio::sync::Barrier;
#[cfg(feature = "randomx")]
use tokio::task;

#[cfg(feature = "randomx")]
use tracing::debug;

#[cfg(feature = "randomx")]
use crate::worker::{create_vm_for_dataset, ensure_fullmem_dataset, hash, set_large_pages};

#[cfg(feature = "randomx")]
/// RandomX benchmark input template derived from a valid-sized Monero block header.
/// The nonce field (bytes 39-42) is zeroed and filled during benchmarking to mimic
/// actual mining workloads without relying on live pool data.
const SAMPLE_BLOB_HEX: &str =
    "390c8c7d7247342cd8100f2f6f770d65d670e58e0351d8ae8e4f6eac342fc231b7b08716eb3fc10000000023177494287733c28ee8ba53bdb56b8824577d53ecc28a70a61c7510a1cd89216c";

/// Run a simple RandomX benchmark and return hashes per second.
#[cfg(feature = "randomx")]
pub async fn run_benchmark(
    threads: usize,
    seconds: u64,
    large_pages: bool,
    batch_size: usize,
    yield_between_batches: bool,
) -> Result<f64> {
    if threads == 0 {
        return Ok(0.0);
    }
    let _ = set_large_pages(large_pages);
    let duration = Duration::from_secs(seconds);
    let threads_u32 = threads as u32;

    let seed = [0u8; 32];
    let (shared_cache, shared_dataset) = ensure_fullmem_dataset(&seed, threads_u32)?;
    let base_blob = hex::decode(SAMPLE_BLOB_HEX)
        .expect("SAMPLE_BLOB_HEX must be valid hex and decode to a block blob");
    assert!(
        base_blob.len() >= 43,
        "sample blob must hold a nonce at offset 39"
    );

    let barrier = Arc::new(Barrier::new(threads + 1));

    let mut handles: Vec<task::JoinHandle<Result<(u64, Duration)>>> = Vec::with_capacity(threads);
    for id in 0..threads {
        let duration = duration;
        let batch_size = batch_size;
        let threads_u32 = threads_u32;
        let yield_between_batches = yield_between_batches;
        let cache = shared_cache.clone();
        let dataset = shared_dataset.clone();
        let barrier = barrier.clone();
        let mut blob = base_blob.clone();
        handles.push(task::spawn(async move {
            let vm = create_vm_for_dataset(&cache, &dataset, None)?;
            let mut nonce = id as u32;
            let _ = barrier.wait().await;
            let start = Instant::now();
            let mut now = start;
            let deadline = start + duration;
            let mut hashes: u64 = 0;
            let mut next_report = start + Duration::from_secs(1);
            const TIME_CHECK_INTERVAL: u64 = 64;
            let mut since_last_check: u64 = 0;

            'outer: loop {
                if now >= deadline {
                    break;
                }
                for _ in 0..batch_size {
                    blob[39..43].copy_from_slice(&nonce.to_le_bytes());
                    let _ = hash(&vm, &blob);
                    hashes += 1;
                    nonce = nonce.wrapping_add(threads_u32);
                    since_last_check += 1;
                    if since_last_check >= TIME_CHECK_INTERVAL {
                        now = Instant::now();
                        if now >= deadline {
                            break 'outer;
                        }
                        since_last_check = 0;
                    }
                }
                now = Instant::now();
                if now >= next_report {
                    debug!(
                        thread_index = id,
                        total_hashes = hashes,
                        elapsed_secs = (now - start).as_secs_f64(),
                        "benchmark progress"
                    );
                    next_report = now + Duration::from_secs(1);
                }
                if yield_between_batches {
                    task::yield_now().await;
                    now = Instant::now();
                }
            }

            let elapsed = now.saturating_duration_since(start);
            debug!(
                thread_index = id,
                total_hashes = hashes,
                elapsed_secs = elapsed.as_secs_f64(),
                "benchmark thread complete"
            );
            Ok((hashes, elapsed))
        }));
    }

    let _ = barrier.wait().await;
    let bench_start = Instant::now();

    let mut total: u64 = 0;
    let mut longest = Duration::default();
    for h in handles {
        let (hashes, elapsed) = h.await??;
        total += hashes;
        if elapsed > longest {
            longest = elapsed;
        }
    }

    let elapsed_secs = longest
        .max(bench_start.elapsed())
        .as_secs_f64()
        .max(f64::EPSILON);
    Ok(total as f64 / elapsed_secs)
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
