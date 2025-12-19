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

#[cfg(feature = "randomx")]
const BENCHMARK_BLOB_TEMPLATE: [u8; 76] = [
    // Major/minor version (varint encoded), timestamp and part of the previous block hash.
    0x0c, 0x0c, 0x0b, 0xa9, 0xb0, 0xd6, 0x5d, 0x92, 0x4f, 0x8a, 0x23, 0x11, 0xa7, 0x9c, 0x4f, 0xd0,
    0x58, 0x84, 0x63, 0x1b, 0x4a, 0xc0, 0x1c, 0x8b, 0x7e, 0x90, 0x3d, 0xcc, 0xff, 0x1a, 0xbb, 0x75,
    0x09, 0x42, 0x97, 0x31, 0x6f, 0xe1, 0x58,
    // Nonce (overwritten per hash to emulate miner behaviour).
    0x00, 0x00, 0x00, 0x00,
    // Remainder of the block template (merkle root, tx count, etc.).
    0x6a, 0x02, 0x10, 0x3c, 0xdd, 0x4b, 0xe6, 0x99, 0x51, 0xab, 0xcd, 0xef, 0x03, 0x20, 0x11, 0x05,
    0xd4, 0x38, 0x8c, 0xa0, 0xfe, 0x55, 0x90, 0x72, 0x63, 0x44, 0x21, 0x7a, 0xb2, 0x6f, 0x19, 0x80,
    0x01,
];

/// Run a simple RandomX benchmark and return hashes per second.
#[cfg(feature = "randomx")]
pub async fn run_benchmark(
    threads: usize,
    seconds: u64,
    large_pages: bool,
    batch_size: usize,
    yield_between_batches: bool,
) -> Result<f64> {
    if seconds == 0 || threads == 0 || batch_size == 0 {
        return Ok(0.0);
    }

    let _ = set_large_pages(large_pages);
    let duration = Duration::from_secs(seconds);
    let threads_u32 = threads as u32;

    let seed = [0u8; 32];
    let (shared_cache, shared_dataset) = ensure_fullmem_dataset(&seed, threads_u32)?;

    let mut handles: Vec<task::JoinHandle<Result<u64>>> = Vec::new();
    for id in 0..threads {
        let cache = shared_cache.clone();
        let dataset = shared_dataset.clone();
        handles.push(task::spawn(async move {
            let vm = create_vm_for_dataset(&cache, &dataset, None)?;
            let mut blob = BENCHMARK_BLOB_TEMPLATE;
            let mut nonce = id as u32;
            let start = Instant::now();
            let mut total_hashes: u64 = 0;
            let mut now = start;
            let deadline = start + duration;

            while now < deadline {
                let mut batch_hashes: u64 = 0;
                for _ in 0..batch_size {
                    if now >= deadline {
                        break;
                    }
                    // write nonce at offset 39
                    blob[39..43].copy_from_slice(&nonce.to_le_bytes());
                    let _digest = hash(&vm, &blob);
                    total_hashes += 1;
                    batch_hashes += 1;
                    nonce = nonce.wrapping_add(threads_u32);
                    now = Instant::now();
                }

                if batch_hashes > 0 {
                    let elapsed_secs = now.duration_since(start).as_secs_f64();
                    tracing::debug!(
                        worker = id,
                        elapsed_secs,
                        batch_hashes,
                        total_hashes,
                        "benchmark progress"
                    );
                }

                if now >= deadline {
                    break;
                }

                if yield_between_batches {
                    task::yield_now().await;
                    now = Instant::now();
                }
            }

            Ok(total_hashes)
        }));
    }

    let mut total: u64 = 0;
    for h in handles {
        total += h.await??;
    }
    Ok(total as f64 / duration.as_secs_f64())
}

#[cfg(not(feature = "randomx"))]
pub async fn run_benchmark(
    _threads: usize,
    _seconds: u64,
    _large_pages: bool,
    _batch_size: usize,
    _yield_between_batches: bool,
) -> Result<f64> {
    Err(anyhow!("built without RandomX support"))
}

#[cfg(all(test, not(feature = "randomx")))]
mod tests {
    use super::run_benchmark;

    #[tokio::test]
    async fn benchmark_without_randomx_feature_errors() {
        let err = run_benchmark(1, 1, false, 1, false).await.unwrap_err();
        assert!(err.to_string().contains("RandomX"));
    }

    #[tokio::test]
    async fn benchmark_zero_inputs_short_circuits() {
        let result = run_benchmark(0, 0, false, 0, false).await;
        assert!(result.is_err());
    }
}
