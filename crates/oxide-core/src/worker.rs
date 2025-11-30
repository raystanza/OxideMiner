// OxideMiner/crates/oxide-core/src/worker.rs

use anyhow::Result;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
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
    pub large_pages: bool,
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
        large_pages,
        batch_size,
        yield_between_batches,
        hash_counter,
    } = config;
    #[cfg(feature = "randomx")]
    let _ = engine::set_large_pages(large_pages);
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
            let hc = hash_counter.clone();
            tokio::spawn(async move {
                #[cfg(feature = "randomx")]
                {
                    if let Some(ref ids) = core_ids {
                        if let Some(id) = ids.get(i % ids.len()) {
                            core_affinity::set_for_current(*id);
                        }
                    }
                    if let Err(e) = randomx_worker_loop(
                        i,
                        n,
                        batch_size,
                        yield_between_batches,
                        &mut rx,
                        shares_tx,
                        hc,
                    )
                    .await
                    {
                        tracing::warn!(worker = i, error = ?e, "worker exited");
                    }
                }
                #[cfg(not(feature = "randomx"))]
                {
                    tracing::warn!(worker = i, "built without RandomX; idle worker");
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
    use crate::system::{self, RANDOMX_DATASET_BYTES};
    use anyhow::{anyhow, Result};
    use once_cell::sync::Lazy;
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
    use std::cmp;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        RwLock,
    };
    use std::thread;

    // Thin wrappers to mirror the old shape
    #[derive(Clone)]
    struct ThreadSafeCache(RandomXCache);

    // SAFETY: `RandomXCache` instances become immutable after initialization. The wrapper only
    // exposes cloning of the underlying cache, so sharing references between threads cannot race
    // on mutation or destruction. The underlying FFI object also owns its memory for the lifetime
    // of the wrapper, so transferring ownership across threads is sound.
    unsafe impl Send for ThreadSafeCache {}
    unsafe impl Sync for ThreadSafeCache {}

    impl ThreadSafeCache {
        fn clone_inner(&self) -> RandomXCache {
            self.0.clone()
        }
    }

    #[derive(Clone)]
    pub struct Cache {
        inner: ThreadSafeCache,
        pub(crate) key: Vec<u8>,
        pub(crate) _flags: RandomXFlag, // intentionally unused (for future)
    }

    #[derive(Clone)]
    pub struct Dataset {
        pub(crate) inner: RandomXDataset,
        pub(crate) _flags: RandomXFlag, // intentionally unused (for future)
        pub(crate) _key: Vec<u8>,       // intentionally unused (for future)
    }

    // RandomX cache/dataset objects are read-only after initialization and may be shared across
    // threads safely.
    // SAFETY: `Cache` and `Dataset` only expose read-only operations after construction. The
    // internal `RandomXCache`/`RandomXDataset` values are never mutated once the object is
    // initialized, and cloning produces independent handles backed by the RandomX library. Moving
    // these wrappers between threads therefore cannot introduce races, and the underlying library
    // keeps the memory alive for the lifetime of the wrapper.
    unsafe impl Send for Cache {}
    unsafe impl Sync for Cache {}
    unsafe impl Send for Dataset {}
    unsafe impl Sync for Dataset {}

    pub struct Vm {
        pub(crate) inner: RandomXVM,
        pub(crate) _flags: RandomXFlag, // intentionally unused (for future)
    }

    // RandomX VMs are not thread-safe by default, but we confine each to a single worker thread.
    // SAFETY: Each `Vm` is created and used by a single worker task. The async worker future is
    // `Send` so it may move between executor threads, but it is never accessed concurrently from
    // multiple threads, preserving the thread confinement required by `RandomXVM`.
    unsafe impl Send for Vm {}

    // randomx-rs exposes FLAG_* constants.
    static LARGE_PAGES: AtomicBool = AtomicBool::new(false);

    pub fn set_large_pages(enable: bool) -> bool {
        if !enable {
            LARGE_PAGES.store(false, Ordering::Relaxed);
            return false;
        }

        let mut status = system::huge_page_status();
        if !status.supported {
            tracing::warn!("Large pages requested but the operating system does not report support; continuing without them");
            LARGE_PAGES.store(false, Ordering::Relaxed);
            return false;
        }

        if !status.has_privilege {
            if !system::enable_large_page_privilege() {
                tracing::warn!("Large pages requested but unable to enable required privileges; continuing without large pages");
                LARGE_PAGES.store(false, Ordering::Relaxed);
                return false;
            }
            status = system::huge_page_status();
        }

        if !status.enabled() {
            let free = status.free_bytes.unwrap_or(0);
            tracing::warn!(
                free_bytes = free,
                "Large pages requested but none are currently available; continuing without large pages",
            );
            LARGE_PAGES.store(false, Ordering::Relaxed);
            return false;
        }

        if !status.dataset_fits(RANDOMX_DATASET_BYTES) {
            let free = status.free_bytes.unwrap_or(0);
            tracing::warn!(
                free_bytes = free,
                required_bytes = RANDOMX_DATASET_BYTES,
                "Large pages requested but available huge pages cannot accommodate the RandomX dataset; continuing without large pages",
            );
            LARGE_PAGES.store(false, Ordering::Relaxed);
            return false;
        }

        LARGE_PAGES.store(true, Ordering::Relaxed);
        if let Some(page) = status.page_size_bytes {
            tracing::info!(page_size_bytes = page, "RandomX large pages enabled",);
        } else {
            tracing::info!("RandomX large pages enabled");
        }
        true
    }

    fn default_flags() -> RandomXFlag {
        let mut flags = RandomXFlag::FLAG_JIT | RandomXFlag::FLAG_FULL_MEM;
        if LARGE_PAGES.load(Ordering::Relaxed) {
            flags |= RandomXFlag::FLAG_LARGE_PAGES;
        }
        let features = system::cpu_features();
        if features.aes_ni {
            flags |= RandomXFlag::FLAG_HARD_AES;
        } else {
            flags |= RandomXFlag::FLAG_SECURE;
        }
        if features.avx2 || features.avx512f {
            flags |= RandomXFlag::FLAG_ARGON2_AVX2;
        } else if features.ssse3 {
            flags |= RandomXFlag::FLAG_ARGON2_SSSE3;
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
                    tracing::warn!("RandomX large pages allocation failed for cache; retrying without large pages: {e}");
                    flags &= !RandomXFlag::FLAG_LARGE_PAGES;
                    RandomXCache::new(flags, key)?
                } else {
                    return Err(e.into());
                }
            }
        };
        Ok(Cache {
            inner: ThreadSafeCache(cache),
            key: key.to_vec(),
            _flags: flags,
        })
    }

    // Windows defaults the main thread to a 1 MiB stack, which is insufficient for RandomX dataset
    // initialization when large pages are enabled.  Spawn helper threads with a larger stack so the
    // heavy initialization work happens off the main thread.
    const DATASET_INIT_STACK_BYTES: usize = 8 * 1024 * 1024;

    fn spawn_dataset_init(
        flags: RandomXFlag,
        cache: &Cache,
        init_threads: usize,
    ) -> Result<Dataset> {
        let cache_clone = cache.clone();
        let thread_name = format!("randomx-dataset-init-{init_threads}");
        let handle = thread::Builder::new()
            .name(thread_name)
            .stack_size(DATASET_INIT_STACK_BYTES)
            .spawn(move || -> Result<Dataset, randomx_rs::RandomXError> {
                let dataset = RandomXDataset::new(flags, cache_clone.inner.clone_inner(), 0)?;
                Ok(Dataset {
                    inner: dataset,
                    _flags: flags,
                    _key: cache_clone.key.clone(),
                })
            })
            .map_err(|e| anyhow!("failed to spawn dataset init thread: {e}"))?;

        let result = handle
            .join()
            .map_err(|e| anyhow!("dataset init thread panicked: {e:?}"))?;

        Ok(result?)
    }

    pub fn new_dataset(flags: Option<RandomXFlag>, cache: &Cache, threads: u32) -> Result<Dataset> {
        let mut flags = flags.unwrap_or_else(default_flags);
        let requested = usize::try_from(threads.max(1)).unwrap_or(1);
        let init_threads = cmp::max(requested, num_cpus::get_physical());

        let ds = match spawn_dataset_init(flags, cache, init_threads) {
            Ok(d) => d,
            Err(first_err) => {
                if flags.contains(RandomXFlag::FLAG_LARGE_PAGES) {
                    tracing::warn!(
                        "RandomX large pages allocation failed for dataset; retrying without large pages: {first_err}"
                    );
                    flags &= !RandomXFlag::FLAG_LARGE_PAGES;
                    spawn_dataset_init(flags, cache, init_threads)?
                } else {
                    return Err(first_err);
                }
            }
        };

        Ok(ds)
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
            cache.map(|c| c.inner.clone_inner()),
            dataset.map(|d| d.inner.clone()),
        )?;
        Ok(Vm {
            inner: vm,
            _flags: flags,
        })
    }

    /// Calculate hash as fixed [u8;32].
    #[inline(always)]
    pub fn hash(vm: &Vm, input: &[u8]) -> [u8; 32] {
        let v = vm.inner.calculate_hash(input).expect("randomx hash failed");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v); // randomx is always 32 bytes
        out
    }

    // ------------------------ Thread-local dataset cache ------------------------

    struct SharedDataset {
        key: Vec<u8>,
        cache: Cache,
        dataset: Dataset,
    }

    impl SharedDataset {
        fn matches(&self, key: &[u8]) -> bool {
            self.key.as_slice() == key
        }

        fn clone_pair(&self) -> (Cache, Dataset) {
            (self.cache.clone(), self.dataset.clone())
        }
    }

    static GLOBAL_DATASET: Lazy<RwLock<Option<SharedDataset>>> = Lazy::new(|| RwLock::new(None));

    /// Ensure a FULL_MEM dataset exists for this process + seed key.
    pub fn ensure_fullmem_dataset(seed_key: &[u8], threads: u32) -> Result<(Cache, Dataset)> {
        {
            let guard = GLOBAL_DATASET.read().expect("dataset lock poisoned");
            if let Some(shared) = guard.as_ref() {
                if shared.matches(seed_key) {
                    return Ok(shared.clone_pair());
                }
            }
        }

        let mut guard = GLOBAL_DATASET.write().expect("dataset lock poisoned");
        if let Some(shared) = guard.as_ref() {
            if shared.matches(seed_key) {
                return Ok(shared.clone_pair());
            }
        }

        let flags = default_flags();
        let cache = new_cache(Some(flags), seed_key)?;
        let dataset = new_dataset(Some(flags), &cache, threads)?;
        *guard = Some(SharedDataset {
            key: seed_key.to_vec(),
            cache: cache.clone(),
            dataset: dataset.clone(),
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
pub use engine::{create_vm_for_dataset, ensure_fullmem_dataset, hash, set_large_pages};

#[cfg(feature = "randomx")]
async fn randomx_worker_loop(
    worker_id: usize,
    worker_count: usize,
    batch_size: usize,
    yield_between_batches: bool,
    rx: &mut broadcast::Receiver<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
    hash_counter: Arc<AtomicU64>,
) -> Result<()> {
    use engine::*;

    let mut work: Option<WorkItem> = None;

    // Precompute once (Send + Copy)
    let threads_u32: u32 = worker_count as u32;
    let mut current_seed: [u8; 32] = [0; 32];
    let mut has_seed = false;
    let mut vm: Option<Vm> = None;
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
            let (cache, dataset) = ensure_fullmem_dataset(&j.seed_hash_bytes, threads_u32)?;
            vm = Some(create_vm_for_dataset(&cache, &dataset, None)?);
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
            let vm_ref = vm.as_ref().expect("vm initialized");
            let mut need_yield = false;
            {
                let vm = vm_ref;
                let mut local_hashes: u64 = 0;
                for i in 0..batch_size {
                    put_u32_le(&mut blob_buf, 39, nonce);
                    let digest = hash(vm, &blob_buf);
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

#[inline]
fn put_u32_le(dst: &mut [u8], offset: usize, val: u32) {
    dst[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Monero Stratum "target" is usually a 32-bit LITTLE-endian hex (e.g., "f3220000" => 0x000022f3).
/// Compare against the hash’s MSB 32 bits for a LE digest: i.e., the **last** 4 bytes.
/// If a wider target (>8 hex chars) is provided, treat as a full 256-bit BE integer.
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
                large_pages: false,
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
