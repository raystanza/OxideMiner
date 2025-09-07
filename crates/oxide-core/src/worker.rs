use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

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

/// Spawn `n` workers; each subscribes to job broadcasts and sends shares back.
pub fn spawn_workers(
    n: usize,
    jobs_tx: broadcast::Sender<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
    affinity: bool,
    large_pages: bool,
    batch_size: usize,
) -> Vec<tokio::task::JoinHandle<()>> {
    #[cfg(feature = "randomx")]
    engine::set_large_pages(large_pages);
    let core_ids = if affinity {
        core_affinity::get_core_ids()
    } else {
        None
    };
    (0..n)
        .map(|i| {
            let mut rx = jobs_tx.subscribe();
            let shares_tx = shares_tx.clone();
            let core_ids = core_ids.clone();
            tokio::spawn(async move {
                #[cfg(feature = "randomx")]
                {
                    if let Some(ref ids) = core_ids {
                        if let Some(id) = ids.get(i % ids.len()) {
                            let _ = core_affinity::set_for_current(*id);
                        }
                    }
                    if let Err(e) = randomx_worker_loop(i, n, batch_size, &mut rx, shares_tx).await
                    {
                        warn!(worker = i, error = ?e, "worker exited");
                    }
                }
                #[cfg(not(feature = "randomx"))]
                {
                    warn!(worker = i, "built without RandomX; idle worker");
                    loop {
                        let _ = rx.recv().await;
                    }
                }
            })
        })
        .collect()
}

#[cfg(feature = "randomx")]
mod engine {
    use crate::system;
    use anyhow::Result;
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tracing::warn;

    // Thin wrappers to mirror the old shape
    #[derive(Clone)]
    pub struct Cache {
        pub(crate) inner: RandomXCache,
        pub(crate) key: Vec<u8>,
        pub(crate) _flags: RandomXFlag, // intentionally unused (for future)
    }

    #[derive(Clone)]
    pub struct Dataset {
        pub(crate) inner: RandomXDataset,
        pub(crate) _flags: RandomXFlag, // intentionally unused (for future)
        pub(crate) _key: Vec<u8>,       // intentionally unused (for future)
    }

    pub struct Vm {
        pub(crate) inner: RandomXVM,
        pub(crate) _flags: RandomXFlag, // intentionally unused (for future)
    }

    // randomx-rs exposes FLAG_* constants.
    static LARGE_PAGES: AtomicBool = AtomicBool::new(false);

    pub fn set_large_pages(enable: bool) {
        LARGE_PAGES.store(enable, Ordering::Relaxed);
    }

    fn default_flags() -> RandomXFlag {
        let mut flags = RandomXFlag::FLAG_JIT | RandomXFlag::FLAG_FULL_MEM;
        if LARGE_PAGES.load(Ordering::Relaxed) {
            flags |= RandomXFlag::FLAG_LARGE_PAGES;
        }
        if system::cpu_has_aes() {
            flags |= RandomXFlag::FLAG_HARD_AES;
        }
        flags
    }

    pub fn new_cache(flags: Option<RandomXFlag>, key: &[u8]) -> Result<Cache> {
        let mut flags = flags.unwrap_or_else(default_flags);

        // First attempt with requested flags
        let cache = match RandomXCache::new(flags, key) {
            Ok(c) => c,
            Err(e) => {
                // If large pages were requested but allocation failed, retry without them.
                if flags.contains(RandomXFlag::FLAG_LARGE_PAGES) {
                    warn!("RandomX large pages allocation failed for cache; retrying without large pages: {e}");
                    flags &= !RandomXFlag::FLAG_LARGE_PAGES;
                    RandomXCache::new(flags, key)?
                } else {
                    return Err(e.into());
                }
            }
        };
        Ok(Cache {
            inner: cache,
            key: key.to_vec(),
            _flags: flags,
        })
    }

    pub fn new_dataset(flags: Option<RandomXFlag>, cache: &Cache, threads: u32) -> Result<Dataset> {
        let mut flags = flags.unwrap_or_else(default_flags);
        // Dataset::new takes OWNED cache and a u32 thread count.
        let ds = match RandomXDataset::new(flags, cache.inner.clone(), threads) {
            Ok(d) => d,
            Err(e) => {
                if flags.contains(RandomXFlag::FLAG_LARGE_PAGES) {
                    warn!("RandomX large pages allocation failed for dataset; retrying without large pages: {e}");
                    flags &= !RandomXFlag::FLAG_LARGE_PAGES;
                    RandomXDataset::new(flags, cache.inner.clone(), threads)?
                } else {
                    return Err(e.into());
                }
            }
        };
        Ok(Dataset {
            inner: ds,
            _flags: flags,
            _key: cache.key.clone(),
        })
    }

    pub fn new_vm(
        flags: Option<RandomXFlag>,
        cache: Option<&Cache>,
        dataset: Option<&Dataset>,
    ) -> Result<Vm> {
        let flags = flags.unwrap_or_else(default_flags);
        // VM::new takes OWNED Option<RandomXCache>/<RandomXDataset>.
        let vm = RandomXVM::new(
            flags,
            cache.map(|c| c.inner.clone()),
            dataset.map(|d| d.inner.clone()),
        )?;
        Ok(Vm {
            inner: vm,
            _flags: flags,
        })
    }

    /// Calculate hash as fixed [u8;32].
    pub fn hash(vm: &Vm, input: &[u8]) -> [u8; 32] {
        let v = vm.inner.calculate_hash(input).expect("randomx hash failed");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v); // randomx is always 32 bytes
        out
    }

    // ------------------------ Thread-local dataset cache ------------------------

    #[derive(Clone)]
    pub struct Global {
        pub _flags: RandomXFlag, // intentionally unused (for future)
        pub key: Vec<u8>,
        pub cache: Cache,
        pub dataset: Dataset,
    }

    thread_local! {
        static TLS: RefCell<Option<Global>> = RefCell::new(None);
    }

    /// Ensure a FULL_MEM dataset exists for this thread + seed key.
    pub fn ensure_fullmem_dataset(seed_key: &[u8], threads: u32) -> Result<(Cache, Dataset)> {
        let flags = default_flags();

        // Fast path: same key already built on this thread
        if let Some(pair) = TLS.with(|cell| {
            cell.borrow().as_ref().and_then(|g| {
                if g.key == seed_key {
                    Some((g.cache.clone(), g.dataset.clone()))
                } else {
                    None
                }
            })
        }) {
            return Ok(pair);
        }

        // Miss or key changed: rebuild
        let cache = new_cache(Some(flags), seed_key)?;
        let dataset = new_dataset(Some(flags), &cache, threads)?;
        TLS.with(|cell| {
            *cell.borrow_mut() = Some(Global {
                _flags: flags,
                key: seed_key.to_vec(),
                cache: cache.clone(),
                dataset: dataset.clone(),
            });
        });

        Ok((cache, dataset))
    }

    /// Convenience: create a VM bound to an existing cache+dataset.
    pub fn create_vm_for_dataset(
        cache: &Cache,
        dataset: &Dataset,
        flags: Option<RandomXFlag>,
    ) -> Result<Vm> {
        new_vm(flags, Some(cache), Some(dataset))
    }
}

#[cfg(feature = "randomx")]
async fn randomx_worker_loop(
    worker_id: usize,
    worker_count: usize,
    batch_size: usize,
    rx: &mut broadcast::Receiver<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
) -> Result<()> {
    use engine::*;

    let mut work: Option<WorkItem> = None;

    // Precompute once (Send + Copy)
    let threads_u32: u32 = worker_count as u32;

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

        // Decode/normalize the seed key (Send)
        let seed_hex = j
            .seed_hash
            .as_deref()
            .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let mut seed_bytes = match hex::decode(seed_hex) {
            Ok(b) => b,
            Err(_) => Vec::new(),
        };
        if seed_bytes.len() != 32 {
            seed_bytes.resize(32, 0u8);
        }

        // Header/blob
        let mut blob =
            hex::decode(&j.blob).map_err(|e| anyhow::anyhow!("invalid job blob hex: {e}"))?;

        // Ensure nonce room
        if blob.len() < 39 + 4 {
            warn!(
                worker = worker_id,
                blob_len = blob.len(),
                "job blob too short to hold nonce at offset 39; skipping job"
            );
            work = None;
            continue;
        }

        // Per-worker nonce stride to avoid collisions; randomize start
        let mut nonce: u32 = ((worker_id as u32) * worker_count as u32)
            + (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u32
                % 0xFFFF_0000);

        'mine: loop {
            // Swap job if a newer one arrives (no await)
            if let Ok(next) = rx.try_recv() {
                work = Some(next);
                break 'mine;
            }

            // ---- IMPORTANT: keep all RandomX handles inside this block ----
            {
                // Reacquire/cache FULLMEM dataset for this thread/key.
                // These types are !Send/!Sync, but they will be dropped
                // before the next `.await`, keeping the future Send.
                let (cache, dataset) = ensure_fullmem_dataset(&seed_bytes, threads_u32)?;
                let vm = create_vm_for_dataset(&cache, &dataset, None)?;

                // Hash a batch
                for _ in 0..batch_size {
                    put_u32_le(&mut blob, 39, nonce); // Monero 32-bit nonce at offset 39
                    let digest = hash(&vm, &blob);

                    if meets_target(&digest, &j) {
                        let _ = shares_tx.send(Share {
                            job_id: j.job_id.clone(),
                            nonce,
                            result: digest,
                            is_devfee,
                        });
                        info!(
                            worker = worker_id,
                            nonce,
                            job_id = %j.job_id,
                            "share candidate"
                        );
                    } else if tracing::enabled!(tracing::Level::DEBUG) && (nonce & 0x3ff == 0) {
                        // Sample occasional hashes when debug logging is enabled
                        let mut be_bytes = digest;
                        be_bytes.reverse();
                        tracing::debug!(
                            job_id = %j.job_id,
                            nonce = nonce,
                            target = %j.target,
                            hash_le = %hex::encode(digest),
                            hash_be = %hex::encode(be_bytes),
                            "share_candidate_debug",
                        );
                    }

                    nonce = nonce.wrapping_add(worker_count as u32);
                }
            }
            // ---- All RandomX handles dropped here, BEFORE await ----

            tokio::task::yield_now().await;
        }
    }
}

#[inline]
fn put_u32_le(dst: &mut [u8], offset: usize, val: u32) {
    dst[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Check if hash meets the job's target using pre-parsed values.
fn meets_target(hash: &[u8; 32], job: &PoolJob) -> bool {
    if let Some(t32) = job.target_num {
        let h_top_le32 = u32::from_le_bytes([hash[28], hash[29], hash[30], hash[31]]);
        return h_top_le32 <= t32;
    }
    if let Some(t) = job.target_wide {
        for (hb, tb) in hash.iter().rev().zip(t.iter()) {
            if hb != tb {
                return *hb < *tb;
            }
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::{broadcast, mpsc};

    #[tokio::test]
    async fn spawns_correct_number_of_workers() {
        let (jobs_tx, _jobs_rx) = broadcast::channel(1);
        let (shares_tx, _shares_rx) = mpsc::unbounded_channel();
        let handles = spawn_workers(3, jobs_tx, shares_tx, false, false, 10_000);
        assert_eq!(handles.len(), 3);
        for h in handles {
            h.abort();
        }
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
            target_num: None,
            target_wide: None,
        };
        job.compute_target();
        assert!(meets_target(&hash, &job));
        hash[28] = 2; // h_top_le32 = 2
        job.target = "01000000".into();
        job.target_num = None;
        job.target_wide = None;
        job.compute_target();
        assert!(!meets_target(&hash, &job)); // target 1 (LE hex)
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
            target_num: None,
            target_wide: None,
        };
        job.compute_target();
        assert!(meets_target(&hash_zero, &job));
        let hash_high = [0xFFu8; 32];
        assert!(!meets_target(&hash_high, &job));
        job.target = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        job.target_num = None;
        job.target_wide = None;
        job.compute_target();
        assert!(meets_target(&hash_high, &job));
    }
}
