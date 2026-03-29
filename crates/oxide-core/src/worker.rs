// OxideMiner/crates/oxide-core/src/worker.rs

#[cfg(feature = "randomx")]
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(feature = "randomx")]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicU64, Arc, Mutex};
#[cfg(feature = "randomx")]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};

use crate::stratum::PoolJob;

#[derive(Clone, Debug)]
pub struct WorkItem {
    pub job: PoolJob,
    pub is_devfee: bool,
}

#[derive(Clone, Debug)]
pub struct Share {
    pub job_id: String,
    pub nonce: u32,
    pub result: [u8; 32],
    pub is_devfee: bool,
}

#[derive(Clone)]
pub struct WorkerSpawnConfig {
    pub jobs_tx: broadcast::Sender<WorkItem>,
    pub shares_tx: mpsc::UnboundedSender<Share>,
    pub affinity: bool,
    pub randomx: crate::config::RandomXRuntimeConfig,
    pub randomx_runtime: Arc<Mutex<crate::config::RandomXRuntimeStatus>>,
    pub batch_size: usize,
    pub yield_between_batches: bool,
    pub hash_counter: Arc<AtomicU64>,
}

/// Spawn `n` workers; each subscribes to job broadcasts and sends shares back.
pub fn spawn_workers(n: usize, config: WorkerSpawnConfig) -> Vec<tokio::task::JoinHandle<()>> {
    let WorkerSpawnConfig {
        jobs_tx,
        shares_tx,
        affinity,
        randomx,
        randomx_runtime,
        batch_size,
        yield_between_batches,
        hash_counter,
    } = config;
    let cache_topology = if affinity {
        Some(crate::system::cache_hierarchy())
    } else {
        None
    };
    let core_ids = if affinity {
        let baseline = core_affinity::get_core_ids();
        if let (Some(ids), Some(cache)) = (baseline.clone(), cache_topology.as_ref()) {
            if let Some(reordered) = l3_aware_core_order(cache, &ids) {
                let affinity_order = reordered
                    .iter()
                    .map(|c| c.id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                tracing::debug!(
                    l3_domains = cache.l3_instances.len(),
                    order = %affinity_order,
                    "affinity core order derived from L3 domains ({})",
                    cache.l3_summary().unwrap_or_else(|| "unknown".into())
                );
                Some(reordered)
            } else {
                baseline
            }
        } else {
            baseline
        }
    } else {
        None
    };
    (0..n)
        .map(|i| {
            let mut rx = jobs_tx.subscribe();
            let worker_shares_tx = shares_tx.clone();
            let worker_core_ids = core_ids.clone();
            let worker_hash_counter = hash_counter.clone();
            let worker_randomx = randomx.clone();
            let worker_randomx_runtime = randomx_runtime.clone();
            tokio::spawn(async move {
                #[cfg(feature = "randomx")]
                {
                    if let Some(ref ids) = worker_core_ids {
                        if let Some(id) = ids.get(i % ids.len()) {
                            core_affinity::set_for_current(*id);
                        }
                    }
                    if let Err(e) = randomx_worker_loop(
                        i,
                        n,
                        &worker_randomx,
                        &worker_randomx_runtime,
                        batch_size,
                        yield_between_batches,
                        &mut rx,
                        worker_shares_tx,
                        worker_hash_counter,
                    )
                    .await
                    {
                        tracing::warn!(worker = i, error = ?e, "worker exited");
                    }
                }
                #[cfg(not(feature = "randomx"))]
                {
                    let _ = (
                        &worker_shares_tx,
                        &worker_core_ids,
                        &worker_hash_counter,
                        &worker_randomx,
                        &worker_randomx_runtime,
                    );
                    let _ = (batch_size, yield_between_batches);
                    tracing::warn!(worker = i, "built without RandomX; idle worker");
                    loop {
                        let _ = rx.recv().await;
                    }
                }
            })
        })
        .collect()
}

fn l3_aware_core_order(
    cache: &crate::system::CacheHierarchy,
    ids: &[core_affinity::CoreId],
) -> Option<Vec<core_affinity::CoreId>> {
    if cache.l3_instances.is_empty() {
        return None;
    }

    let by_id: HashMap<usize, core_affinity::CoreId> = ids.iter().map(|id| (id.id, *id)).collect();
    let mut domains: Vec<VecDeque<usize>> = cache
        .l3_instances
        .iter()
        .map(|inst| inst.shared_logical_cpus.iter().copied().collect())
        .collect();

    for domain in domains.iter_mut() {
        domain.retain(|cpu| by_id.contains_key(cpu));
    }
    domains.retain(|d| !d.is_empty());
    if domains.is_empty() {
        return None;
    }

    let mut order = Vec::new();
    let mut seen = HashSet::new();
    loop {
        let mut progressed = false;
        for domain in domains.iter_mut() {
            while let Some(cpu) = domain.pop_front() {
                if seen.insert(cpu) {
                    if let Some(id) = by_id.get(&cpu) {
                        order.push(*id);
                        progressed = true;
                    }
                    break;
                }
            }
        }
        if !progressed {
            break;
        }
    }

    if order.is_empty() {
        return None;
    }

    for id in ids {
        if !seen.contains(&id.id) {
            order.push(*id);
        }
    }

    Some(order)
}

#[cfg(feature = "randomx")]
async fn randomx_worker_loop(
    worker_id: usize,
    worker_count: usize,
    randomx: &crate::config::RandomXRuntimeConfig,
    randomx_runtime: &Arc<Mutex<crate::config::RandomXRuntimeStatus>>,
    batch_size: usize,
    yield_between_batches: bool,
    rx: &mut broadcast::Receiver<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
    hash_counter: Arc<AtomicU64>,
) -> Result<()> {
    use crate::randomx_backend::{build_fast_vm, build_light_vm};
    use crate::RandomXMode;

    let mut work: Option<WorkItem> = None;

    let mut current_seed: [u8; 32] = [0; 32];
    let mut has_seed = false;
    let mut vm = None;
    let mut blob_buf: Vec<u8> = Vec::with_capacity(128);
    let nonce_step = worker_count as u32;

    loop {
        if work.is_none() {
            work = Some(
                rx.recv()
                    .await
                    .map_err(|_| anyhow::anyhow!("job channel closed"))?,
            );
            continue;
        }

        let j = work.as_ref().unwrap().job.clone();
        let is_devfee = work.as_ref().unwrap().is_devfee;

        if !has_seed || j.seed_hash_bytes != current_seed {
            let (next_vm, realized) = match randomx.mode {
                RandomXMode::Light => build_light_vm(randomx, &j.seed_hash_bytes)?,
                RandomXMode::Fast => build_fast_vm(randomx, &j.seed_hash_bytes, worker_count)?,
            };
            if worker_id == 0 {
                if let Ok(mut status) = randomx_runtime.lock() {
                    status.set_realized(realized.clone());
                }
                tracing::info!(
                    randomx_mode = realized.mode.as_str(),
                    requested_runtime_profile = realized.requested_runtime_profile.as_str(),
                    effective_runtime_profile = realized.effective_runtime_profile.as_str(),
                    jit_active = realized.jit_active,
                    scratchpad_large_pages = realized.scratchpad_large_pages,
                    dataset_large_pages = ?realized.dataset_large_pages,
                    calibration_status = %realized.calibration_status,
                    "RandomX runtime realized"
                );
            }
            vm = Some(next_vm);
            current_seed = j.seed_hash_bytes;
            has_seed = true;
        }

        // Header/blob (reuse the buffer to avoid reallocation churn)
        blob_buf.clear();
        blob_buf.extend_from_slice(&j.blob_bytes);

        // Ensure nonce room
        if blob_buf.len() < 39 + 4 {
            tracing::warn!(
                worker = worker_id,
                blob_len = blob_buf.len(),
                "job blob too short to hold nonce at offset 39; skipping job"
            );
            work = None;
            continue;
        }

        // Stagger initial nonce to reduce overlaps across workers
        let mut nonce: u32 = ((worker_id as u32) * (worker_count as u32))
            + (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
                % 0xFFFF_0000);

        'mine: loop {
            match rx.try_recv() {
                Ok(next) => {
                    work = Some(next);
                    break 'mine;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    return Err(anyhow::anyhow!("job channel closed"));
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        worker = worker_id,
                        skipped,
                        "job channel lagged; resyncing to latest job"
                    );
                    work = None;
                    break 'mine;
                }
            }
            let vm_ref = vm.as_mut().expect("vm initialized");
            let mut need_yield = false;
            {
                let vm = vm_ref;
                let mut local_hashes: u64 = 0;
                for i in 0..batch_size {
                    put_u32_le(&mut blob_buf, 39, nonce);
                    let digest = vm.hash(&blob_buf);
                    local_hashes += 1;
                    if meets_target(&digest, &j) {
                        let le_hex = hex::encode(digest);
                        let mut be_bytes = digest;
                        be_bytes.reverse();
                        let be_hex = hex::encode(be_bytes);
                        tracing::info!(
                            worker = worker_id,
                            job_id = %j.job_id,
                            nonce,
                            hash_le = %le_hex,
                            hash_be = %be_hex,
                            target = %j.target,
                            "share found",
                        );
                        let _ = shares_tx.send(Share {
                            job_id: j.job_id.clone(),
                            nonce,
                            result: digest,
                            is_devfee,
                        });
                        // Advance nonce so we don't re-emit the same share on the next loop.
                        nonce = nonce.wrapping_add(nonce_step);
                        // After finding a share, request a cooperative yield
                        // (performed after this borrow scope to keep the future Send).
                        need_yield = true;
                        break; // exit early to yield outside borrow scope
                    }
                    nonce = nonce.wrapping_add(nonce_step);
                    // Request a cooperative yield roughly every 1024 hashes when enabled.
                    if yield_between_batches && (i & 1023 == 1023) {
                        need_yield = true;
                        break; // exit early to yield outside borrow scope
                    }
                }
                hash_counter.fetch_add(local_hashes, Ordering::Relaxed);
            }
            if need_yield || yield_between_batches {
                tokio::task::yield_now().await;
            }
        }
    }
}

#[cfg(any(feature = "randomx", test))]
#[inline]
fn put_u32_le(dst: &mut [u8], offset: usize, val: u32) {
    dst[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Monero Stratum "target" is usually a 32-bit LITTLE-endian hex (e.g., "f3220000" => 0x000022f3).
/// Compare against the hash’s MSB 32 bits for a LE digest: i.e., the **last** 4 bytes.
/// If a wider target (>8 hex chars) is provided, treat as a full 256-bit BE integer.
#[cfg(any(feature = "randomx", test))]
fn meets_target(hash: &[u8; 32], job: &PoolJob) -> bool {
    if let Some(t32) = job.target_u32 {
        let h_top_le32 = u32::from_le_bytes([hash[28], hash[29], hash[30], hash[31]]);
        return h_top_le32 <= t32;
    }

    let target_hex = &job.target;
    if target_hex.len() <= 8 {
        if let Ok(mut b) = hex::decode(target_hex) {
            if b.len() > 4 {
                b.truncate(4);
            }
            while b.len() < 4 {
                b.push(0);
            }
            let t32 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let h_top_le32 = u32::from_le_bytes([hash[28], hash[29], hash[30], hash[31]]);
            return h_top_le32 <= t32;
        }
        return false;
    }

    if let Ok(mut t) = hex::decode(target_hex) {
        if t.is_empty() || t.len() > 32 {
            return false;
        }
        if t.len() < 32 {
            let mut pad = vec![0u8; 32 - t.len()];
            pad.extend_from_slice(&t);
            t = pad;
        }
        for (hb, tb) in hash.iter().rev().zip(t.iter()) {
            if hb != tb {
                return *hb < *tb;
            }
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicU64, Arc};
    use tokio::sync::{broadcast, mpsc};

    #[tokio::test]
    async fn spawns_correct_number_of_workers() {
        let (jobs_tx, _jobs_rx) = broadcast::channel(1);
        let (shares_tx, _shares_rx) = mpsc::unbounded_channel();
        let hash_counter = Arc::new(AtomicU64::new(0));
        let handles = spawn_workers(
            3,
            WorkerSpawnConfig {
                jobs_tx,
                shares_tx,
                affinity: false,
                randomx: crate::config::RandomXRuntimeConfig::default(),
                randomx_runtime: Arc::new(Mutex::new(crate::config::RandomXRuntimeStatus::new(
                    &crate::config::RandomXRuntimeConfig::default(),
                ))),
                batch_size: 10_000,
                yield_between_batches: true,
                hash_counter,
            },
        );
        assert_eq!(handles.len(), 3);
        for h in handles {
            h.abort();
        }
    }

    #[test]
    fn l3_affinity_interleaves_across_domains() {
        let cache = crate::system::CacheHierarchy {
            l3_instances: vec![
                crate::system::L3Instance {
                    size_bytes: 32 * 1024 * 1024,
                    shared_logical_cpus: (0..4).collect(),
                },
                crate::system::L3Instance {
                    size_bytes: 32 * 1024 * 1024,
                    shared_logical_cpus: (4..8).collect(),
                },
            ],
            l3_total_bytes: Some(64 * 1024 * 1024),
            ..Default::default()
        };
        let ids: Vec<core_affinity::CoreId> =
            (0..8).map(|id| core_affinity::CoreId { id }).collect();
        let ordered = l3_aware_core_order(&cache, &ids).expect("ordered cores");
        let first_eight: Vec<usize> = ordered.iter().map(|c| c.id).collect();
        assert_eq!(first_eight, vec![0, 4, 1, 5, 2, 6, 3, 7]);
    }

    #[test]
    fn put_u32_le_writes_bytes() {
        let mut buf = [0u8; 8];
        put_u32_le(&mut buf, 2, 0x0A0B0C0D);
        assert_eq!(&buf[2..6], &[0x0D, 0x0C, 0x0B, 0x0A]);
    }

    #[test]
    fn meets_target_32bit() {
        let mut hash = [0u8; 32];
        let mut job = PoolJob {
            job_id: String::new(),
            blob: String::new(),
            target: "00000000".into(),
            seed_hash: None,
            height: None,
            algo: None,
            target_u32: None,
            seed_hash_bytes: [0; 32],
            blob_bytes: Arc::new(Vec::new()),
        };
        job.cache_target();
        assert!(meets_target(&hash, &job));
        hash[28] = 2; // h_top_le32 = 2
        job.target = "01000000".into();
        job.cache_target();
        assert!(!meets_target(&hash, &job));
    }

    #[test]
    fn meets_target_wide() {
        let hash_zero = [0u8; 32];
        let mut job = PoolJob {
            job_id: String::new(),
            blob: String::new(),
            target: "01".into(),
            seed_hash: None,
            height: None,
            algo: None,
            target_u32: None,
            seed_hash_bytes: [0; 32],
            blob_bytes: Arc::new(Vec::new()),
        };
        job.cache_target();
        assert!(meets_target(&hash_zero, &job));
        let hash_high = [0xFFu8; 32];
        assert!(!meets_target(&hash_high, &job));
        job.target = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        job.cache_target();
        assert!(meets_target(&hash_high, &job));
    }
}
