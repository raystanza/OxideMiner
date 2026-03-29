//! Dataset allocation and initialization.

use std::sync::OnceLock;

use crate::blake::hash512;
use crate::cache::RandomXCache;
use crate::config::RandomXConfig;
use crate::errors::Result;
use crate::threading::AffinitySpec;
use crate::util::{AlignedBuf, HugePageSize, LargePageRequest};

/// Options for dataset initialization.
#[derive(Clone, Debug)]
pub struct DatasetInitOptions {
    /// Number of worker threads to use (clamped to at least 1).
    pub threads: usize,
    /// Request large pages for dataset allocation.
    pub large_pages: bool,
    /// Request 1GB huge pages (Linux only).
    /// Falls back to 2MB huge pages if unavailable.
    pub use_1gb_pages: bool,
    /// Whether to name dataset worker threads.
    pub thread_names: bool,
    /// Optional CPU affinity policy for dataset workers.
    pub affinity: Option<AffinitySpec>,
}

impl DatasetInitOptions {
    /// Create options with the provided thread count.
    pub fn new(threads: usize) -> Self {
        Self {
            threads: threads.max(1),
            large_pages: false,
            use_1gb_pages: false,
            thread_names: false,
            affinity: None,
        }
    }

    /// Enable or disable large-page allocation for the dataset.
    pub fn with_large_pages(mut self, enabled: bool) -> Self {
        self.large_pages = enabled;
        self
    }

    /// Request 1GB huge pages for dataset allocation (Linux only).
    ///
    /// This also enables large pages. Falls back to 2MB pages if 1GB pages
    /// are unavailable. Requires kernel configuration:
    /// `hugepagesz=1G hugepages=3`
    pub fn with_1gb_pages(mut self, enabled: bool) -> Self {
        self.use_1gb_pages = enabled;
        if enabled {
            self.large_pages = true; // 1GB pages implies large pages
        }
        self
    }

    /// Enable or disable naming dataset worker threads.
    pub fn with_thread_names(mut self, enabled: bool) -> Self {
        self.thread_names = enabled;
        self
    }

    /// Apply a thread affinity policy to dataset workers.
    pub fn with_affinity(mut self, affinity: AffinitySpec) -> Self {
        self.affinity = Some(affinity);
        self
    }
}

/// RandomX dataset backing fast-mode hashing.
pub struct RandomXDataset {
    data: AlignedBuf,
    item_count: usize,
    options: DatasetInitOptions,
}

// SAFETY: `RandomXDataset` is fully initialized before it becomes observable and
// is thereafter read-only. The backing buffer is owned by the dataset for its
// full lifetime, and the public API only exposes immutable access to dataset
// contents after construction. Sharing or moving the dataset across threads
// therefore does not permit concurrent mutation or dangling references.
unsafe impl Send for RandomXDataset {}
unsafe impl Sync for RandomXDataset {}

impl RandomXDataset {
    /// Build a dataset with a simple thread count.
    pub fn new(cache: &RandomXCache, cfg: &RandomXConfig, threads: usize) -> Result<Self> {
        Self::new_with_options(cache, cfg, DatasetInitOptions::new(threads))
    }

    /// Build a dataset with explicit initialization options.
    pub fn new_with_options(
        cache: &RandomXCache,
        cfg: &RandomXConfig,
        options: DatasetInitOptions,
    ) -> Result<Self> {
        cfg.validate()?;
        let item_count = (cfg.dataset_size() / 64) as usize;
        let request = if options.large_pages {
            if options.use_1gb_pages {
                LargePageRequest::enabled_with_size("dataset", HugePageSize::OneGigabyte)
            } else {
                LargePageRequest::enabled("dataset")
            }
        } else {
            LargePageRequest::disabled()
        };
        let mut data = AlignedBuf::new_with_large_pages(item_count * 64, 64, request)?;
        let thread_count = options.threads.max(1);
        let affinity = options.affinity.clone();
        let thread_names = options.thread_names;

        if thread_count == 1 {
            fill_range(cache, cfg, 0, item_count, data.as_mut_slice());
        } else {
            std::thread::scope(|scope| {
                let items_per_thread = item_count / thread_count;
                let extra_items = item_count % thread_count;
                let mut remaining = data.as_mut_slice();
                let mut start = 0usize;
                for t in 0..thread_count {
                    let take = items_per_thread + usize::from(t < extra_items);
                    if take == 0 {
                        break;
                    }
                    let end = start + take;
                    let bytes = take * 64;
                    let (chunk, rest) = remaining.split_at_mut(bytes);
                    remaining = rest;
                    let thread_affinity = affinity.clone();
                    let work = move || {
                        if let Some(spec) = thread_affinity.as_ref() {
                            crate::threading::apply_affinity(spec, t, thread_count);
                        }
                        fill_range(cache, cfg, start, end, chunk);
                    };
                    if thread_names {
                        let name = format!("oxide-randomx-worker-{t}");
                        std::thread::Builder::new()
                            .name(name)
                            .spawn_scoped(scope, work)
                            .expect("spawn dataset worker");
                    } else {
                        scope.spawn(work);
                    }
                    start = end;
                }
            });
        }

        Ok(Self {
            data,
            item_count,
            options,
        })
    }

    pub(crate) fn item_count(&self) -> usize {
        self.item_count
    }

    pub(crate) fn item_bytes(&self, index: usize) -> &[u8] {
        let offset = index * 64;
        &self.data.as_slice()[offset..offset + 64]
    }

    /// Returns true if large pages were used for this dataset.
    pub fn uses_large_pages(&self) -> bool {
        self.data.uses_large_pages()
    }

    /// Returns the huge page size in bytes if large pages are being used.
    ///
    /// - `Some(1073741824)` = 1GB pages
    /// - `Some(2097152)` = 2MB pages
    /// - `None` = standard 4KB pages
    pub fn huge_page_size(&self) -> Option<usize> {
        self.data.huge_page_size()
    }

    /// Returns a human-readable description of the page size being used.
    pub fn page_size_description(&self) -> &'static str {
        match self.data.huge_page_size() {
            Some(size) if size >= 1024 * 1024 * 1024 => "1GB huge pages",
            Some(size) if size >= 2 * 1024 * 1024 => "2MB huge pages",
            Some(_) => "large pages",
            None => "standard 4KB pages",
        }
    }

    /// Returns the options used to create this dataset.
    pub fn options(&self) -> &DatasetInitOptions {
        &self.options
    }
}

fn fill_range(cache: &RandomXCache, cfg: &RandomXConfig, start: usize, end: usize, out: &mut [u8]) {
    for (item_idx, chunk) in (start..end).zip(out.chunks_mut(64)) {
        let item_words = compute_item_words(cache, cfg, item_idx as u64);
        debug_assert_eq!(chunk.len(), 64);
        // Safety: dataset buffer is 64-byte aligned and chunk length is exactly 64 bytes.
        let out_words =
            unsafe { core::slice::from_raw_parts_mut(chunk.as_mut_ptr() as *mut u64, 8) };
        for (dst, word) in out_words.iter_mut().zip(item_words.iter()) {
            *dst = word.to_le();
        }
    }
}

#[inline(always)]
pub(crate) fn compute_item_words(
    cache: &RandomXCache,
    cfg: &RandomXConfig,
    item_number: u64,
) -> [u64; 8] {
    let mut regs = [0u64; 8];
    compute_item_words_in_place(cache, cfg, item_number, &mut regs);
    regs
}

#[inline(always)]
pub(crate) fn compute_item_words_in_place(
    cache: &RandomXCache,
    cfg: &RandomXConfig,
    item_number: u64,
    regs: &mut [u64; 8],
) {
    let constants = superscalar_constants();
    let programs = cache.superscalar_programs();
    let cache_items = cache.cache_item_count() as u64;
    debug_assert!(cache_items.is_power_of_two());
    let cache_mask = cache_items - 1;
    let accesses = cfg.cache_accesses() as usize;

    let r0 = (item_number + 1).wrapping_mul(6364136223846793005u64);
    *regs = [
        r0,
        r0 ^ constants[0],
        r0 ^ constants[1],
        r0 ^ constants[2],
        r0 ^ constants[3],
        r0 ^ constants[4],
        r0 ^ constants[5],
        r0 ^ constants[6],
    ];

    let mut cache_index = item_number;
    for i in 0..accesses {
        let program = programs.program(i);
        let idx = (cache_index & cache_mask) as usize;
        let cache_words = cache.cache_item_slice(idx);
        program.execute(regs);
        xor_regs_with_cache_words(regs, cache_words);
        cache_index = regs[program.select_register()];
    }
}

#[inline(always)]
fn xor_regs_with_cache_words(regs: &mut [u64; 8], cache_words: &[u64]) {
    regs[0] ^= cache_words[0];
    regs[1] ^= cache_words[1];
    regs[2] ^= cache_words[2];
    regs[3] ^= cache_words[3];
    regs[4] ^= cache_words[4];
    regs[5] ^= cache_words[5];
    regs[6] ^= cache_words[6];
    regs[7] ^= cache_words[7];
}

pub(crate) fn superscalar_constants() -> [u64; 7] {
    static CONSTS: OnceLock<[u64; 7]> = OnceLock::new();
    *CONSTS.get_or_init(|| {
        let seed = b"RandomX SuperScalarHash initialize";
        let hash = hash512(seed);
        let mut out = [0u64; 7];
        for (i, slot) in out.iter_mut().enumerate() {
            let start = 8 + i * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash[start..start + 8]);
            *slot = u64::from_le_bytes(bytes);
        }
        out[0] = out[0].wrapping_add((1u64 << 33) + 700);
        out[2] = out[2].wrapping_add(1u64 << 14);
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake::hash256;

    #[test]
    fn cache_dataset_checksums_test_small() {
        let cfg = RandomXConfig::test_small();
        let mut key = [0u8; 32];
        for (idx, byte) in key.iter_mut().enumerate() {
            *byte = idx as u8;
        }

        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let dataset = RandomXDataset::new(&cache, &cfg, 1).expect("dataset");

        let mut buf = Vec::new();
        for idx in 0..4usize {
            let words = cache.cache_item_slice(idx);
            for &word in words.iter() {
                buf.extend_from_slice(&word.to_le_bytes());
            }
        }
        let cache_hash = hash256(&buf);

        buf.clear();
        for idx in 0..4usize {
            buf.extend_from_slice(dataset.item_bytes(idx));
        }
        let dataset_hash = hash256(&buf);

        assert_eq!(
            hex(&cache_hash),
            "6c3f7abed1913b086843761e8a14a81e2f88128e28e3f765e66328305eda5be5"
        );
        assert_eq!(
            hex(&dataset_hash),
            "215704fef8cf3dc959e721652b0162b395280200b987b8bcefa895d1ec3cfd89"
        );
    }

    #[test]
    fn compute_item_words_in_place_matches_scalar_reference_for_selected_items() {
        let cfg = RandomXConfig::test_small();
        let key = test_key_with_seed(0x11);
        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let items = [0u64, 1, 2, 3, 7, 15, 31, 63, 127, 255];

        for &item_number in &items {
            let mut observed = [u64::MAX; 8];
            compute_item_words_in_place(&cache, &cfg, item_number, &mut observed);
            let expected = reference_compute_item_words_scalar(&cache, &cfg, item_number);
            assert_eq!(
                observed, expected,
                "cache-item synthesis mismatch for item={item_number}"
            );
        }
    }

    #[test]
    fn compute_item_words_in_place_matches_scalar_reference_across_program_sets() {
        let cfg = RandomXConfig::test_small();
        let items = [0u64, 5, 17, 31, 64, 255, 511, 1023];
        let key_seeds = [0x01u8, 0x55, 0xA3, 0xFE];

        for &seed in &key_seeds {
            let key = test_key_with_seed(seed);
            let cache = RandomXCache::new(&key, &cfg).expect("cache");
            for &item_number in &items {
                let mut observed = [0u64; 8];
                compute_item_words_in_place(&cache, &cfg, item_number, &mut observed);
                let expected = reference_compute_item_words_scalar(&cache, &cfg, item_number);
                assert_eq!(
                    observed, expected,
                    "cache-item synthesis mismatch for seed={seed:#04x} item={item_number}"
                );
            }
        }
    }

    fn reference_compute_item_words_scalar(
        cache: &RandomXCache,
        cfg: &RandomXConfig,
        item_number: u64,
    ) -> [u64; 8] {
        let constants = superscalar_constants();
        let programs = cache.superscalar_programs();
        let cache_items = cache.cache_item_count() as u64;
        let cache_mask = cache_items - 1;
        let accesses = cfg.cache_accesses() as usize;

        let r0 = (item_number + 1).wrapping_mul(6364136223846793005u64);
        let mut regs = [
            r0,
            r0 ^ constants[0],
            r0 ^ constants[1],
            r0 ^ constants[2],
            r0 ^ constants[3],
            r0 ^ constants[4],
            r0 ^ constants[5],
            r0 ^ constants[6],
        ];

        let mut cache_index = item_number;
        for i in 0..accesses {
            let program = programs.program(i);
            let idx = (cache_index & cache_mask) as usize;
            let cache_words = cache.cache_item_slice(idx);
            program.execute_scalar(&mut regs);
            for (reg, word) in regs.iter_mut().zip(cache_words.iter()) {
                *reg ^= *word;
            }
            cache_index = regs[program.select_register()];
        }
        regs
    }

    fn test_key_with_seed(seed: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (idx, byte) in key.iter_mut().enumerate() {
            *byte = seed.wrapping_add((idx as u8).wrapping_mul(17));
        }
        key
    }

    fn hex(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(LUT[(b >> 4) as usize] as char);
            out.push(LUT[(b & 0x0f) as usize] as char);
        }
        out
    }
}
