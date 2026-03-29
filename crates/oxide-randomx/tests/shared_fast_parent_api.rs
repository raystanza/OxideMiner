use oxide_randomx::{RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm};
use std::sync::Arc;

fn make_shared_fast_parts(
    cfg: &RandomXConfig,
    key: &[u8],
) -> (Arc<RandomXCache>, Arc<RandomXDataset>) {
    let cache = Arc::new(RandomXCache::new(key, cfg).expect("cache"));
    let dataset = Arc::new(RandomXDataset::new(&cache, cfg, 1).expect("dataset"));
    (cache, dataset)
}

#[test]
fn shared_fast_constructor_matches_owned_fast_hashes() {
    let cfg = RandomXConfig::test_small();
    let key = [0x5Au8; 32];
    let input = b"shared-fast-parent-api";
    let flags = RandomXFlags::default();

    let cache_owned = RandomXCache::new(&key, &cfg).expect("owned cache");
    let dataset_owned = RandomXDataset::new(&cache_owned, &cfg, 1).expect("owned dataset");
    let mut owned_vm = RandomXVm::new_fast(cache_owned, dataset_owned, cfg.clone(), flags.clone())
        .expect("owned fast vm");

    let (shared_cache, shared_dataset) = make_shared_fast_parts(&cfg, &key);
    let mut shared_a = RandomXVm::new_fast_shared(
        Arc::clone(&shared_cache),
        Arc::clone(&shared_dataset),
        cfg.clone(),
        flags.clone(),
    )
    .expect("shared fast vm");
    let mut shared_b =
        RandomXVm::new_fast_shared(shared_cache, shared_dataset, cfg, flags).expect("vm");

    let owned_hash = owned_vm.hash(input);
    let shared_a_hash = shared_a.hash(input);
    let shared_b_hash = shared_b.hash(input);

    assert_eq!(owned_hash, shared_a_hash);
    assert_eq!(shared_a_hash, shared_b_hash);
}

#[test]
fn shared_fast_constructor_supports_multithreaded_vm_creation() {
    let cfg = RandomXConfig::test_small();
    let key = [0x33u8; 32];
    let flags = RandomXFlags::default();
    let input = b"oxide-randomx-shared-fast";
    let (shared_cache, shared_dataset) = make_shared_fast_parts(&cfg, &key);

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let cache = Arc::clone(&shared_cache);
            let dataset = Arc::clone(&shared_dataset);
            let cfg = cfg.clone();
            let flags = flags.clone();
            std::thread::spawn(move || {
                let mut vm = RandomXVm::new_fast_shared(cache, dataset, cfg, flags).expect("vm");
                vm.hash(input)
            })
        })
        .collect();

    let mut outputs = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker hash"))
        .collect::<Vec<_>>();

    let first = outputs.pop().expect("first output");
    for output in outputs {
        assert_eq!(output, first);
    }
}
