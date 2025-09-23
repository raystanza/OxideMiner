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

/// Spawn `n` workers; each subscribes to job broadcasts and sends shares back.
pub fn spawn_workers(
    n: usize,
    jobs_tx: broadcast::Sender<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
    affinity: bool,
    large_pages: bool,
    batch_size: usize,
    yield_between_batches: bool,
    hash_counter: Arc<AtomicU64>,
) -> Vec<tokio::task::JoinHandle<()>> {
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
                            let _ = core_affinity::set_for_current(*id);
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
    use bitflags::bitflags;
    use libc::c_ulong;
    use once_cell::sync::Lazy;
    use randomx_sys::{
        randomx_alloc_cache, randomx_alloc_dataset, randomx_calculate_hash, randomx_create_vm,
        randomx_dataset_item_count, randomx_destroy_vm, randomx_init_cache, randomx_init_dataset,
        randomx_release_cache, randomx_release_dataset,
    };
    use std::{
        cmp,
        ffi::c_void,
        ptr,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread,
    };

    const INIT_STACK_SIZE_BYTES: usize = 8 * 1024 * 1024;

    bitflags! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct RandomXFlag: u32 {
            const FLAG_DEFAULT      = 0b0000_0000;
            const FLAG_LARGE_PAGES  = 0b0000_0001;
            const FLAG_HARD_AES     = 0b0000_0010;
            const FLAG_FULL_MEM     = 0b0000_0100;
            const FLAG_JIT          = 0b0000_1000;
            const FLAG_SECURE       = 0b0001_0000;
            const FLAG_ARGON2_SSSE3 = 0b0010_0000;
            const FLAG_ARGON2_AVX2  = 0b0100_0000;
            const FLAG_ARGON2       = 0b0110_0000;
        }
    }

    impl Default for RandomXFlag {
        fn default() -> Self {
            RandomXFlag::FLAG_DEFAULT
        }
    }

    static LARGE_PAGES: AtomicBool = AtomicBool::new(false);

    pub fn set_large_pages(enable: bool) -> bool {
        if !enable {
            LARGE_PAGES.store(false, Ordering::Relaxed);
            return false;
        }

        let mut status = system::huge_page_status();
        if !status.supported {
            tracing::warn!(
                "Large pages requested but the operating system does not report support; continuing without them"
            );
            LARGE_PAGES.store(false, Ordering::Relaxed);
            return false;
        }

        if !status.has_privilege {
            if !system::enable_large_page_privilege() {
                tracing::warn!(
                    "Large pages requested but unable to enable required privileges; continuing without large pages"
                );
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
            tracing::info!(page_size_bytes = page, "RandomX large pages enabled");
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
        if system::cpu_has_aes() {
            flags |= RandomXFlag::FLAG_HARD_AES;
        }
        flags
    }

    struct CacheInner {
        ptr: *mut randomx_sys::randomx_cache,
    }

    impl Drop for CacheInner {
        fn drop(&mut self) {
            unsafe { randomx_release_cache(self.ptr) };
        }
    }

    #[derive(Clone)]
    pub struct Cache {
        inner: Arc<CacheInner>,
        key: Vec<u8>,
        _flags: RandomXFlag,
    }

    unsafe impl Send for Cache {}
    unsafe impl Sync for Cache {}

    impl Cache {
        fn ptr(&self) -> *mut randomx_sys::randomx_cache {
            self.inner.ptr
        }
    }

    struct DatasetInner {
        ptr: *mut randomx_sys::randomx_dataset,
        item_count: u64,
    }

    impl Drop for DatasetInner {
        fn drop(&mut self) {
            unsafe { randomx_release_dataset(self.ptr) };
        }
    }

    #[derive(Clone)]
    pub struct Dataset {
        inner: Arc<DatasetInner>,
        _flags: RandomXFlag,
        _key: Vec<u8>,
    }

    unsafe impl Send for Dataset {}
    unsafe impl Sync for Dataset {}

    impl Dataset {
        fn ptr(&self) -> *mut randomx_sys::randomx_dataset {
            self.inner.ptr
        }

        fn item_count(&self) -> u64 {
            self.inner.item_count
        }

        fn init_range(&self, cache: &Cache, start: u64, count: u64) -> Result<()> {
            debug_assert!(start + count <= self.item_count());
            if count == 0 {
                return Ok(());
            }
            let start = to_c_ulong(start)?;
            let count = to_c_ulong(count)?;
            unsafe { randomx_init_dataset(self.ptr(), cache.ptr(), start, count) };
            Ok(())
        }
    }

    pub struct Vm {
        ptr: *mut randomx_sys::randomx_vm,
        _cache: Option<Cache>,
        _dataset: Option<Dataset>,
        _flags: RandomXFlag,
    }

    unsafe impl Send for Vm {}

    impl Drop for Vm {
        fn drop(&mut self) {
            unsafe { randomx_destroy_vm(self.ptr) };
        }
    }

    fn to_c_ulong(value: u64) -> Result<c_ulong> {
        if value > (c_ulong::MAX as u64) {
            Err(anyhow!("dataset range {} exceeds c_ulong::MAX", value))
        } else {
            Ok(value as c_ulong)
        }
    }

    pub fn new_cache(flags: Option<RandomXFlag>, key: &[u8]) -> Result<Cache> {
        let mut attempt = flags.unwrap_or_else(default_flags);

        loop {
            let ptr = unsafe { randomx_alloc_cache(attempt.bits()) };
            if ptr.is_null() {
                if attempt.contains(RandomXFlag::FLAG_LARGE_PAGES) {
                    tracing::warn!(
                        "RandomX large pages allocation failed for cache; retrying without large pages"
                    );
                    attempt &= !RandomXFlag::FLAG_LARGE_PAGES;
                    continue;
                }
                return Err(anyhow!("Could not allocate RandomX cache"));
            }

            unsafe {
                randomx_init_cache(ptr, key.as_ptr() as *const c_void, key.len());
            }

            return Ok(Cache {
                inner: Arc::new(CacheInner { ptr }),
                key: key.to_vec(),
                _flags: attempt,
            });
        }
    }

    pub fn new_dataset(flags: Option<RandomXFlag>, cache: &Cache, threads: u32) -> Result<Dataset> {
        let mut attempt = flags.unwrap_or_else(default_flags);

        let dataset = loop {
            let ptr = unsafe { randomx_alloc_dataset(attempt.bits()) };
            if ptr.is_null() {
                if attempt.contains(RandomXFlag::FLAG_LARGE_PAGES) {
                    tracing::warn!(
                        "RandomX large pages allocation failed for dataset; retrying without large pages"
                    );
                    attempt &= !RandomXFlag::FLAG_LARGE_PAGES;
                    continue;
                }
                return Err(anyhow!("Could not allocate RandomX dataset"));
            }

            let count = unsafe { randomx_dataset_item_count() };
            if count == 0 {
                unsafe { randomx_release_dataset(ptr) };
                return Err(anyhow!("randomx_dataset_item_count returned 0"));
            }

            break Dataset {
                inner: Arc::new(DatasetInner {
                    ptr,
                    item_count: count as u64,
                }),
                _flags: attempt,
                _key: cache.key.clone(),
            };
        };

        initialize_dataset_parallel(&dataset, cache, threads)?;

        Ok(dataset)
    }

    pub fn new_vm(
        flags: Option<RandomXFlag>,
        cache: Option<&Cache>,
        dataset: Option<&Dataset>,
    ) -> Result<Vm> {
        let flags = flags.unwrap_or_else(default_flags);
        let cache_ptr = cache.map(|c| c.ptr()).unwrap_or(ptr::null_mut());
        let dataset_ptr = dataset.map(|d| d.ptr()).unwrap_or(ptr::null_mut());

        let ptr = unsafe { randomx_create_vm(flags.bits(), cache_ptr, dataset_ptr) };
        if ptr.is_null() {
            return Err(anyhow!("Failed to create RandomX VM"));
        }

        Ok(Vm {
            ptr,
            _cache: cache.cloned(),
            _dataset: dataset.cloned(),
            _flags: flags,
        })
    }

    pub fn hash(vm: &Vm, input: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            randomx_calculate_hash(
                vm.ptr,
                input.as_ptr() as *const c_void,
                input.len(),
                out.as_mut_ptr() as *mut c_void,
            );
        }
        out
    }

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

    pub fn create_vm_for_dataset(
        cache: &Cache,
        dataset: &Dataset,
        flags: Option<RandomXFlag>,
    ) -> Result<Vm> {
        new_vm(flags, Some(cache), Some(dataset))
    }

    fn initialize_dataset_parallel(
        dataset: &Dataset,
        cache: &Cache,
        requested_threads: u32,
    ) -> Result<()> {
        let total_items = dataset.item_count();
        if total_items == 0 {
            return Ok(());
        }

        let mut threads = cmp::max(requested_threads as usize, 1);
        threads = cmp::max(threads, cmp::max(num_cpus::get_physical(), 1));
        threads = cmp::min(threads, total_items as usize);
        threads = cmp::max(threads, 1);

        let base = total_items / threads as u64;
        let remainder = total_items % threads as u64;

        let mut handles = Vec::with_capacity(threads);
        let mut start = 0u64;
        for idx in 0..threads {
            let count = base + if (idx as u64) < remainder { 1 } else { 0 };
            if count == 0 {
                continue;
            }
            let cache = cache.clone();
            let dataset = dataset.clone();
            let start_item = start;
            start += count;

            let builder = thread::Builder::new()
                .name(format!("randomx-dataset-init-{idx}"))
                .stack_size(INIT_STACK_SIZE_BYTES);

            let handle = builder
                .spawn(move || -> Result<()> { dataset.init_range(&cache, start_item, count) })
                .map_err(|e| anyhow!("failed to spawn dataset init thread: {e}"))?;
            handles.push(handle);
        }

        for handle in handles {
            handle
                .join()
                .map_err(|e| anyhow!("dataset init thread panicked: {e:?}"))??;
        }

        Ok(())
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
    let mut current_seed: Option<Vec<u8>> = None;
    let mut vm: Option<Vm> = None;

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
        let _seed_hex = j
            .seed_hash
            .as_deref()
            .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let mut seed_bytes = match hex::decode(_seed_hex) {
            Ok(b) => b,
            Err(_) => Vec::new(),
        };
        if seed_bytes.len() != 32 {
            seed_bytes.resize(32, 0u8);
        }
        if current_seed.as_deref() != Some(seed_bytes.as_slice()) {
            let (cache, dataset) = ensure_fullmem_dataset(&seed_bytes, threads_u32)?;
            vm = Some(create_vm_for_dataset(&cache, &dataset, None)?);
            current_seed = Some(seed_bytes.clone());
        }

        // Header/blob
        let mut blob =
            hex::decode(&j.blob).map_err(|e| anyhow::anyhow!("invalid job blob hex: {e}"))?;

        // Ensure nonce room
        if blob.len() < 39 + 4 {
            tracing::warn!(
                worker = worker_id,
                blob_len = blob.len(),
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
                .subsec_nanos() as u32
                % 0xFFFF_0000);

        'mine: loop {
            if let Ok(next) = rx.try_recv() {
                work = Some(next);
                break 'mine;
            }
            let vm_ref = vm.as_ref().expect("vm initialized");
            let mut need_yield = false;
            {
                let vm = vm_ref;
                let mut local_hashes: u64 = 0;
                for i in 0..batch_size {
                    put_u32_le(&mut blob, 39, nonce);
                    let digest = hash(vm, &blob);
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
                        nonce = nonce.wrapping_add(worker_count as u32);
                        // After finding a share, request a cooperative yield
                        // (performed after this borrow scope to keep the future Send).
                        need_yield = true;
                        break; // exit early to yield outside borrow scope
                    }
                    nonce = nonce.wrapping_add(worker_count as u32);
                    // Request a cooperative yield roughly every 1024 hashes when enabled.
                    if yield_between_batches && (i % 1024 == 1023) {
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
            jobs_tx,
            shares_tx,
            false,
            false,
            10_000,
            true,
            hash_counter,
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
