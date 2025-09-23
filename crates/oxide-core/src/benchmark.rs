// OxideMiner/crates/oxide-core/src/benchmark.rs

#[cfg(feature = "randomx")]
use anyhow::Result;
#[cfg(not(feature = "randomx"))]
use anyhow::{anyhow, Result};
use std::time::{Duration, Instant};

#[cfg(feature = "randomx")]
use once_cell::sync::Lazy;
#[cfg(feature = "randomx")]
use tokio::task;

#[cfg(feature = "randomx")]
use crate::worker::{create_vm_for_dataset, ensure_fullmem_dataset, hash, set_large_pages};

#[cfg(feature = "randomx")]
const BENCHMARK_BLOB_HEX: &str = "0d0100000000e0c36a9dfb3d5c4a2b19ef7d1c8967452301b2c3d4e5f6172839405a6b7c8d9e0f1a2233445566778899aabbccddeeff00112233445566778899aabbccddeeff000000000000";

#[cfg(feature = "randomx")]
static BENCHMARK_BLOB: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut blob = hex::decode(BENCHMARK_BLOB_HEX).expect("valid benchmark block header hex");
    assert!(
        blob.len() >= 39 + 4,
        "benchmark blob must be large enough to hold nonce field"
    );
    blob[39..43].copy_from_slice(&[0u8; 4]);
    blob
});

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
    let effective_batch_size = batch_size.max(1);

    let seed = [0u8; 32];
    let (shared_cache, shared_dataset) = ensure_fullmem_dataset(&seed, threads_u32)?;

    let benchmark_start = Instant::now();

    let mut handles: Vec<task::JoinHandle<Result<(u64, Duration)>>> = Vec::with_capacity(threads);
    for id in 0..threads {
        let duration = duration;
        let threads_u32 = threads_u32;
        let yield_between_batches = yield_between_batches;
        let cache = shared_cache.clone();
        let dataset = shared_dataset.clone();
        let base_blob = BENCHMARK_BLOB.clone();
        let batch_size = effective_batch_size;
        handles.push(task::spawn(async move {
            let vm = create_vm_for_dataset(&cache, &dataset, None)?;
            let mut blob = base_blob;
            let mut nonce = id as u32;
            let start = Instant::now();
            let mut hashes: u64 = 0;
            let mut next_report = start + Duration::from_secs(1);
            let deadline = start + duration;
            loop {
                if Instant::now() >= deadline {
                    break;
                }
                let mut hashed_this_batch: u32 = 0;
                for _ in 0..batch_size {
                    blob[39..43].copy_from_slice(&nonce.to_le_bytes());
                    let _ = hash(&vm, &blob);
                    hashes += 1;
                    hashed_this_batch += 1;
                    nonce = nonce.wrapping_add(threads_u32);
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                if hashed_this_batch == 0 {
                    break;
                }
                let now = Instant::now();
                if now >= next_report {
                    tracing::debug!(
                        thread_id = id,
                        hashes,
                        elapsed_secs = now.duration_since(start).as_secs_f64(),
                        "benchmark progress"
                    );
                    next_report = now + Duration::from_secs(1);
                }
                if yield_between_batches {
                    task::yield_now().await;
                }
            }
            let elapsed = start.elapsed();
            tracing::debug!(
                thread_id = id,
                hashes,
                elapsed_secs = elapsed.as_secs_f64(),
                "benchmark thread complete"
            );
            Ok((hashes, elapsed))
        }));
    }

    let mut total_hashes: u64 = 0;
    let mut longest_thread = Duration::ZERO;
    for h in handles {
        let (hashes, elapsed) = h.await??;
        total_hashes += hashes;
        if elapsed > longest_thread {
            longest_thread = elapsed;
        }
    }

    let measured = benchmark_start.elapsed().max(longest_thread);
    let secs = measured.as_secs_f64();
    if secs == 0.0 {
        return Ok(0.0);
    }
    Ok(total_hashes as f64 / secs)
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
