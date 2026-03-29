use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use oxide_randomx::prefetch_calibration::{
    apply_prefetch_calibration_for_current_host, PrefetchCalibrationApplyStatus,
    PrefetchCalibrationMode, PREFETCH_CALIBRATION_WORKLOAD_ID,
};
use oxide_randomx::{
    DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm,
};
use std::sync::{Arc, RwLock};

use crate::config::{RandomXMode, RandomXRuntimeConfig, RandomXRuntimeRealization};

struct SharedFastState {
    key: Vec<u8>,
    large_pages: bool,
    use_1gb_pages: bool,
    cache: Arc<RandomXCache>,
    dataset: Arc<RandomXDataset>,
}

impl SharedFastState {
    fn matches(&self, key: &[u8], runtime: &RandomXRuntimeConfig) -> bool {
        self.key.as_slice() == key
            && self.large_pages == (runtime.large_pages || runtime.use_1gb_pages)
            && self.use_1gb_pages == runtime.use_1gb_pages
    }
}

static SHARED_FAST_STATE: Lazy<RwLock<Option<SharedFastState>>> = Lazy::new(|| RwLock::new(None));

/// A RandomX VM that remains thread-confined but can move with a worker future.
///
/// SAFETY: OxideMiner creates one VM per worker/task and never shares it across
/// threads concurrently. The wrapper only relaxes the future-movability
/// requirement imposed by `tokio::spawn`; it does not make the VM `Sync` or
/// allow parallel access.
pub(crate) struct WorkerVm(RandomXVm);

unsafe impl Send for WorkerVm {}

impl WorkerVm {
    pub(crate) fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        self.0.hash(input)
    }
}

pub(crate) fn build_light_vm(
    runtime: &RandomXRuntimeConfig,
    key: &[u8],
) -> Result<(WorkerVm, RandomXRuntimeRealization)> {
    let cfg = RandomXConfig::new();
    let (flags, calibration_status) = resolve_flags(runtime)?;
    let cache = RandomXCache::new(key, &cfg)?;
    let vm = RandomXVm::new_light(cache, cfg, flags.clone())?;
    let realized = build_realization(
        runtime,
        &flags,
        vm.is_jit_active(),
        vm.scratchpad_uses_large_pages(),
        vm.scratchpad_huge_page_size(),
        None,
        calibration_status,
    );
    Ok((WorkerVm(vm), realized))
}

pub(crate) fn build_fast_vm(
    runtime: &RandomXRuntimeConfig,
    key: &[u8],
    threads: usize,
) -> Result<(WorkerVm, RandomXRuntimeRealization)> {
    let cfg = RandomXConfig::new();
    let (flags, calibration_status) = resolve_flags(runtime)?;
    let (cache, dataset) = shared_fast_resources(runtime, key, threads)?;
    let vm = RandomXVm::new_fast_shared(cache, dataset.clone(), cfg, flags.clone())?;
    let realized = build_realization(
        runtime,
        &flags,
        vm.is_jit_active(),
        vm.scratchpad_uses_large_pages(),
        vm.scratchpad_huge_page_size(),
        Some(dataset.as_ref()),
        calibration_status,
    );
    Ok((WorkerVm(vm), realized))
}

fn shared_fast_resources(
    runtime: &RandomXRuntimeConfig,
    key: &[u8],
    threads: usize,
) -> Result<(Arc<RandomXCache>, Arc<RandomXDataset>)> {
    {
        let guard = SHARED_FAST_STATE
            .read()
            .expect("shared fast state poisoned");
        if let Some(state) = guard.as_ref() {
            if state.matches(key, runtime) {
                return Ok((state.cache.clone(), state.dataset.clone()));
            }
        }
    }

    let mut guard = SHARED_FAST_STATE
        .write()
        .expect("shared fast state poisoned");
    if let Some(state) = guard.as_ref() {
        if state.matches(key, runtime) {
            return Ok((state.cache.clone(), state.dataset.clone()));
        }
    }

    let cfg = RandomXConfig::new();
    let cache = Arc::new(RandomXCache::new(key, &cfg)?);
    let dataset_options = DatasetInitOptions::new(threads.max(1))
        .with_large_pages(runtime.large_pages || runtime.use_1gb_pages)
        .with_1gb_pages(runtime.use_1gb_pages);
    let dataset = Arc::new(RandomXDataset::new_with_options(
        cache.as_ref(),
        &cfg,
        dataset_options,
    )?);

    *guard = Some(SharedFastState {
        key: key.to_vec(),
        large_pages: runtime.large_pages || runtime.use_1gb_pages,
        use_1gb_pages: runtime.use_1gb_pages,
        cache: cache.clone(),
        dataset: dataset.clone(),
    });

    Ok((cache, dataset))
}

fn resolve_flags(runtime: &RandomXRuntimeConfig) -> Result<(RandomXFlags, String)> {
    let mut flags = RandomXFlags::from_env();
    flags.large_pages_plumbing = runtime.large_pages || runtime.use_1gb_pages;
    flags.use_1gb_pages = runtime.use_1gb_pages;
    flags.jit = runtime.runtime_profile.jit_requested();
    flags.jit_fast_regs = runtime.runtime_profile.jit_fast_regs_requested();

    let calibration_status = if let Some(path) = runtime.prefetch_calibration_path.as_ref() {
        let outcome = apply_prefetch_calibration_for_current_host(
            path,
            calibration_mode(runtime.mode),
            &mut flags,
            PREFETCH_CALIBRATION_WORKLOAD_ID,
        )
        .map_err(|err| anyhow!(err))?;
        calibration_status_label(outcome.status).to_string()
    } else {
        "NotRequested".to_string()
    };

    Ok((flags, calibration_status))
}

fn calibration_mode(mode: RandomXMode) -> PrefetchCalibrationMode {
    match mode {
        RandomXMode::Light => PrefetchCalibrationMode::Light,
        RandomXMode::Fast => PrefetchCalibrationMode::Fast,
    }
}

fn calibration_status_label(status: PrefetchCalibrationApplyStatus) -> &'static str {
    match status {
        PrefetchCalibrationApplyStatus::Applied => "Applied",
        PrefetchCalibrationApplyStatus::NoCalibrationFile => "NoCalibrationFile",
        PrefetchCalibrationApplyStatus::NoMatchingCalibration => "NoMatchingCalibration",
    }
}

fn build_realization(
    runtime: &RandomXRuntimeConfig,
    flags: &RandomXFlags,
    jit_active: bool,
    scratchpad_large_pages: bool,
    scratchpad_huge_page_size: Option<usize>,
    dataset: Option<&RandomXDataset>,
    calibration_status: String,
) -> RandomXRuntimeRealization {
    let requested_large_pages = runtime.large_pages || runtime.use_1gb_pages;
    let effective_runtime_profile = runtime
        .runtime_profile
        .effective_from_jit_active(jit_active);

    RandomXRuntimeRealization {
        mode: runtime.mode,
        requested_runtime_profile: runtime.runtime_profile,
        effective_runtime_profile,
        fallback_reason: runtime.runtime_profile.fallback_reason(jit_active),
        jit_requested: runtime.runtime_profile.jit_requested(),
        jit_fast_regs_requested: runtime.runtime_profile.jit_fast_regs_requested(),
        jit_active,
        large_pages_requested: requested_large_pages,
        use_1gb_pages_requested: runtime.use_1gb_pages,
        scratchpad_large_pages,
        scratchpad_huge_page_size,
        scratchpad_page_description: page_size_description(scratchpad_huge_page_size).to_string(),
        scratchpad_page_realization: page_realization_label(
            requested_large_pages,
            false,
            scratchpad_large_pages,
            scratchpad_huge_page_size,
        )
        .to_string(),
        dataset_large_pages: dataset.map(RandomXDataset::uses_large_pages),
        dataset_huge_page_size: dataset.and_then(RandomXDataset::huge_page_size),
        dataset_page_description: dataset
            .map(|dataset| page_size_description(dataset.huge_page_size()).to_string()),
        dataset_page_realization: dataset.map(|dataset| {
            page_realization_label(
                requested_large_pages,
                runtime.use_1gb_pages,
                dataset.uses_large_pages(),
                dataset.huge_page_size(),
            )
            .to_string()
        }),
        prefetch_distance: flags.prefetch_distance,
        prefetch_auto_tune: flags.prefetch_auto_tune,
        scratchpad_prefetch_distance: flags.scratchpad_prefetch_distance,
        calibration_status,
    }
}

fn page_realization_label(
    requested_large_pages: bool,
    requested_1gb_pages: bool,
    realized_large_pages: bool,
    realized_huge_page_size: Option<usize>,
) -> &'static str {
    let realized_1gb = matches!(realized_huge_page_size, Some(size) if size >= 1024 * 1024 * 1024);
    let realized_2mb = matches!(realized_huge_page_size, Some(size) if size >= 2 * 1024 * 1024);

    match (
        requested_large_pages,
        requested_1gb_pages,
        realized_large_pages,
        realized_1gb,
        realized_2mb,
    ) {
        (false, false, false, _, _) => "not_requested",
        (false, false, true, true, _) => "realized_without_request_1gb",
        (false, false, true, false, true) => "realized_without_request_2mb",
        (false, false, true, false, false) => "realized_without_request_large_pages",
        (true, false, false, _, _) => "requested_fallback_standard_4kb",
        (true, false, true, true, _) => "realized_1gb_large_pages",
        (true, false, true, false, true) => "realized_2mb_large_pages",
        (true, false, true, false, false) => "realized_large_pages",
        (true, true, false, _, _) => "requested_1gb_fallback_standard_4kb",
        (true, true, true, true, _) => "realized_1gb_large_pages",
        (true, true, true, false, true) => "requested_1gb_fallback_2mb_large_pages",
        (true, true, true, false, false) => "requested_1gb_realized_nonstandard_large_pages",
        (false, true, false, _, _) => "requested_1gb_without_large_pages_fallback_standard_4kb",
        (false, true, true, true, _) => "requested_1gb_without_large_pages_realized_1gb",
        (false, true, true, false, true) => "requested_1gb_without_large_pages_fallback_2mb",
        (false, true, true, false, false) => {
            "requested_1gb_without_large_pages_realized_nonstandard_large_pages"
        }
    }
}

fn page_size_description(huge_page_size: Option<usize>) -> &'static str {
    match huge_page_size {
        Some(size) if size >= 1024 * 1024 * 1024 => "1GB huge pages",
        Some(size) if size >= 2 * 1024 * 1024 => "2MB huge pages",
        Some(_) => "large pages",
        None => "standard 4KB pages",
    }
}

#[cfg(test)]
mod tests {
    use super::page_realization_label;

    #[test]
    fn page_realization_distinguishes_1gb_dataset_fallback() {
        assert_eq!(
            page_realization_label(true, true, true, Some(2 * 1024 * 1024)),
            "requested_1gb_fallback_2mb_large_pages"
        );
        assert_eq!(
            page_realization_label(true, false, false, None),
            "requested_fallback_standard_4kb"
        );
    }
}
