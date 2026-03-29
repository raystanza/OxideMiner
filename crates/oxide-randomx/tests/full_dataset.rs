use oxide_randomx::{RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm};

#[test]
#[ignore]
fn full_dataset_smoke() {
    if std::env::var("OXIDE_RANDOMX_FULL_TESTS").ok().as_deref() != Some("1") {
        return;
    }
    let cfg = RandomXConfig::new();
    let flags = RandomXFlags::default();
    let key = b"full-dataset";
    let cache = RandomXCache::new(key, &cfg).expect("cache");
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let dataset = RandomXDataset::new(&cache, &cfg, threads).expect("dataset");
    let mut vm = RandomXVm::new_fast(cache, dataset, cfg, flags).expect("vm");
    let _ = vm.hash(b"test input");
}
