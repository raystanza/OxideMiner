use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use crate::stratum::PoolJob;

#[derive(Clone, Debug)]
pub struct WorkItem {
    pub job: PoolJob,
}

#[derive(Clone, Debug)]
pub struct Share {
    pub job_id: String,
    pub nonce: u32,
    pub result: [u8; 32],
}

/// Spawn `n` workers; each subscribes to job broadcasts and sends shares back.
pub fn spawn_workers(
    n: usize,
    jobs_tx: broadcast::Sender<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
) -> Vec<tokio::task::JoinHandle<()>> {
    (0..n)
        .map(|i| {
            let mut rx = jobs_tx.subscribe();
            let shares_tx = shares_tx.clone();
            tokio::spawn(async move {
                #[cfg(feature = "randomx")]
                if let Err(e) = randomx_worker_loop(i, n, &mut rx, shares_tx).await {
                    eprintln!("worker {i} exited: {e:?}");
                }
                #[cfg(not(feature = "randomx"))]
                {
                    warn!(worker = i, "built without RandomX; idle worker");
                    loop { let _ = rx.recv().await; }
                }
            })
        })
        .collect()
}

#[cfg(feature = "randomx")]
mod engine {
    use anyhow::{self, Result};
    use once_cell::sync::OnceCell;
    use randomx_bindings_sys as rx;
    use std::{
        ffi::c_void,
        ptr,
        sync::{Arc, RwLock},
        thread,
    };

    // ---------- Minimal safe-ish wrappers over the C API ----------

    pub struct Dataset {
        ptr: *mut rx::randomx_dataset,
    }
    struct Cache {
        ptr: *mut rx::randomx_cache,
    }
    pub struct Vm {
        ptr: *mut rx::randomx_vm,
    }

    impl Drop for Cache {
        fn drop(&mut self) {
            unsafe {
                if !self.ptr.is_null() {
                    rx::randomx_release_cache(self.ptr);
                }
            }
        }
    }
    impl Drop for Dataset {
        fn drop(&mut self) {
            unsafe {
                if !self.ptr.is_null() {
                    rx::randomx_release_dataset(self.ptr);
                }
            }
        }
    }
    impl Drop for Vm {
        fn drop(&mut self) {
            unsafe {
                if !self.ptr.is_null() {
                    rx::randomx_destroy_vm(self.ptr);
                }
            }
        }
    }

    // Dataset is read-only after init; safe to share.
    unsafe impl Send for Dataset {}
    unsafe impl Sync for Dataset {}

    #[inline]
    fn flags_default() -> i32 {
        // Detect CPU features; returns randomx_flags (i32)
        unsafe { rx::randomx_get_flags() }
    }

    const FLAG_FULLMEM: i32 = rx::randomx_flags_RANDOMX_FLAG_FULL_MEM;
    const FLAG_JIT: i32 = rx::randomx_flags_RANDOMX_FLAG_JIT;

    fn new_cache(flags: i32, key: &[u8]) -> Result<Cache> {
        unsafe {
            let cache = rx::randomx_alloc_cache(flags);
            if cache.is_null() {
                anyhow::bail!("randomx_alloc_cache returned null");
            }
            // length cast to whatever the FFI expects
            rx::randomx_init_cache(
                cache,
                key.as_ptr() as *const c_void,
                key.len() as _,
            );
            Ok(Cache { ptr: cache })
        }
    }

    fn new_dataset(flags: i32, key: &[u8], threads: u8) -> Result<Dataset> {
        unsafe {
            let cache = new_cache(flags, key)?;
            let ds = rx::randomx_alloc_dataset(flags);
            if ds.is_null() {
                anyhow::bail!("randomx_alloc_dataset returned null");
            }

            // item counts are size_t in C; bindings may be u32/u64/usize — use `as _`.
            let total = rx::randomx_dataset_item_count() as usize;

            if threads <= 1 {
                rx::randomx_init_dataset(ds, cache.ptr, 0 as _, total as _);
            } else {
                let per = total / threads as usize;
                let last = total % threads as usize;
                let mut handles = Vec::with_capacity(threads as usize);

                // Capture raw addresses (Send) and cast back inside the worker
                let ds_addr = ds as usize;
                let cache_addr = cache.ptr as usize;

                for t in 0..threads {
                    let start = (t as usize) * per;
                    let count = if t == threads - 1 { per + last } else { per };

                    handles.push(thread::spawn(move || {
                        let ds_ptr = ds_addr as *mut rx::randomx_dataset;
                        let cache_ptr = cache_addr as *mut rx::randomx_cache;

                        // This call is lexically inside the outer unsafe { ... } of new_dataset
                        rx::randomx_init_dataset(
                            ds_ptr,
                            cache_ptr,
                            start as _,
                            count as _,
                        )
                    }));
                }
                for h in handles {
                    let _ = h.join();
                }
            }
            Ok(Dataset { ptr: ds })
        }
    }

    fn new_vm_fast(flags: i32, ds: &Dataset) -> Result<Vm> {
        unsafe {
            let vm = rx::randomx_create_vm(flags, ptr::null_mut(), ds.ptr);
            if vm.is_null() {
                anyhow::bail!("randomx_create_vm returned null");
            }
            Ok(Vm { ptr: vm })
        }
    }

    impl Vm {
        pub fn hash(&self, input: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            unsafe {
                rx::randomx_calculate_hash(
                    self.ptr,
                    input.as_ptr() as *const c_void,
                    input.len() as _, // cast to the FFI's size type
                    out.as_mut_ptr() as *mut c_void,
                );
            }
            out
        }
    }

    // ---------- Shared FULLMEM dataset keyed by 32-byte seed ----------

    #[derive(Clone)]
    pub struct SharedDataset {
        pub seed: [u8; 32],
        dataset: Arc<Dataset>, // keep type private; expose getter
    }

    impl SharedDataset {
        pub fn dataset(&self) -> &Dataset {
            &self.dataset
        }
    }

    static ACTIVE: OnceCell<RwLock<Option<SharedDataset>>> = OnceCell::new();
    fn state() -> &'static RwLock<Option<SharedDataset>> {
        ACTIVE.get_or_init(|| RwLock::new(None))
    }

    pub fn parse_seed32(hex_str: &str) -> Result<[u8; 32]> {
        let b = hex::decode(hex_str)?;
        if b.len() != 32 {
            anyhow::bail!("seed_hash must be 32 bytes");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        Ok(out)
    }

    /// Build (or reuse) the FULLMEM dataset for this seed.
    pub fn ensure_fullmem_dataset(seed_hex: &str) -> Result<SharedDataset> {
        let seed = parse_seed32(seed_hex)?;
        if let Some(cur) = state().read().unwrap().as_ref().cloned() {
            if cur.seed == seed {
                return Ok(cur);
            }
        }

        let flags = flags_default() | FLAG_FULLMEM | FLAG_JIT;
        let init_threads = u8::max(1, num_cpus::get_physical() as u8);
        let ds = new_dataset(flags, &seed, init_threads)?;
        let shared = SharedDataset { seed, dataset: Arc::new(ds) };
        *state().write().unwrap() = Some(shared.clone());
        Ok(shared)
    }

    /// Helper that returns a closure constructing a fast VM for a dataset.
    pub fn create_vm_for_dataset() -> impl Fn(&Dataset) -> Result<Vm> {
        move |ds: &Dataset| {
            let flags = flags_default() | FLAG_FULLMEM | FLAG_JIT;
            new_vm_fast(flags, ds)
        }
    }
}

#[cfg(feature = "randomx")]
async fn randomx_worker_loop(
    worker_id: usize,
    worker_count: usize,
    rx: &mut broadcast::Receiver<WorkItem>,
    shares_tx: mpsc::UnboundedSender<Share>,
) -> Result<()> {
    use engine::*;

    let mut job: Option<PoolJob> = None;

    loop {
        if job.is_none() {
            job = Some(rx.recv().await.map_err(|_| anyhow::anyhow!("job channel closed"))?.job);
            continue;
        }

        let j = job.as_ref().unwrap().clone();

        // Ensure dataset for this seed (FULLMEM)
        let seed_hex = j.seed_hash.as_deref()
            .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let shared = ensure_fullmem_dataset(seed_hex)?;
        let mk_vm = create_vm_for_dataset();

        // Hash buffer
        let mut blob = hex::decode(&j.blob)
            .map_err(|e| anyhow::anyhow!("invalid job blob hex: {e}"))?;

        // Safety: make sure the blob is long enough to write a 32-bit nonce at offset 39
        if blob.len() < 39 + 4 {
            warn!(
                worker = worker_id,
                blob_len = blob.len(),
                "job blob too short to hold nonce at offset 39; skipping job"
            );
            job = None;
            continue;
        }

        // Per-worker nonce stride to avoid collisions
        let mut nonce: u32 = worker_id as u32;

        'mine: loop {
            if let Ok(next) = rx.try_recv() {
                job = Some(next.job);
                break 'mine;
            }

            {
                // VM is strictly scoped to this block and cannot live across the await
                let vm = mk_vm(shared.dataset())?;

                // Hash a batch
                for _ in 0..1_000 {
                    put_u32_le(&mut blob, 39, nonce); // Monero 32-bit nonce at offset 39
                    let hash = vm.hash(&blob);

                    if meets_target(&hash, &j.target) {
                        let _ = shares_tx.send(Share {
                            job_id: j.job_id.clone(),
                            nonce,
                            result: hash,
                        });
                        info!(worker = worker_id, nonce, job_id = %j.job_id, "share candidate");
                    }

                    nonce = nonce.wrapping_add(worker_count as u32);
                }
            } // vm dropped here

            tokio::task::yield_now().await;
        }
    }
}

#[inline]
fn put_u32_le(dst: &mut [u8], offset: usize, val: u32) {
    dst[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Pool targets are usually 32-bit big-endian (e.g. "f3220000"),
/// compared to the hash’s most-significant 32 bits.
fn meets_target(hash: &[u8; 32], target_hex: &str) -> bool {
    if target_hex.len() <= 8 {
        if let Ok(t32) = u32::from_str_radix(target_hex, 16) {
            let h_top = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
            return h_top <= t32;
        }
        return false;
    }
    // Wider target: parse as big-endian 256-bit
    if let Ok(mut t) = hex::decode(target_hex) {
        if t.len() > 32 { return false; }
        if t.len() < 32 {
            let mut pad = vec![0u8; 32 - t.len()];
            pad.append(&mut t);
            t = pad;
        }
        return &hash[..] <= &t[..];
    }
    false
}
