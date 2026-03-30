#![cfg(feature = "randomx")]

use oxide_randomx::{
    DatasetInitOptions, RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm,
};
use std::sync::Arc;

fn supported_jit_fastregs_flags() -> RandomXFlags {
    RandomXFlags {
        jit: true,
        jit_fast_regs: true,
        ..RandomXFlags::default()
    }
}

#[test]
fn supported_profile_light_and_fast_smoke_with_shared_fast_api() {
    let cfg = RandomXConfig::test_small();
    let key = [0x42u8; 32];
    let input = b"oxide-miner-supported-profile-smoke";
    let flags = supported_jit_fastregs_flags();

    let light_cache = RandomXCache::new(&key, &cfg).expect("light cache");
    let mut light_vm =
        RandomXVm::new_light(light_cache, cfg.clone(), flags.clone()).expect("light vm");
    let light_hash = light_vm.hash(input);

    let fast_cache = Arc::new(RandomXCache::new(&key, &cfg).expect("fast cache"));
    let fast_dataset = Arc::new(
        RandomXDataset::new_with_options(fast_cache.as_ref(), &cfg, DatasetInitOptions::new(1))
            .expect("fast dataset"),
    );
    let mut fast_vm =
        RandomXVm::new_fast_shared(fast_cache, fast_dataset, cfg, flags).expect("fast vm");
    let fast_hash = fast_vm.hash(input);

    assert_eq!(light_hash.len(), 32);
    assert_eq!(fast_hash.len(), 32);
    assert_eq!(
        light_hash, fast_hash,
        "light and fast hashes should agree for the same key/input"
    );
    assert!(
        fast_vm.is_jit_active(),
        "jit-fastregs should activate in the smoke path"
    );
}
