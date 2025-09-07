use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "randomx")]
fn bench_randomx(c: &mut Criterion) {
    use randomx_rs::{RandomXFlag, RandomXCache, RandomXDataset, RandomXVM};
    let flags = RandomXFlag::FLAG_JIT | RandomXFlag::FLAG_FULL_MEM;
    let key = [0u8;32];
    let cache = RandomXCache::new(flags, &key).unwrap();
    let dataset = RandomXDataset::new(flags, cache.clone(), 1).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), Some(dataset)).unwrap();
    let mut blob = [0u8; 76];
    c.bench_function("randomx_hash", |b| b.iter(|| { vm.calculate_hash(&blob).unwrap(); }));
}
#[cfg(feature = "randomx")]
criterion_group!(benches, bench_randomx);
#[cfg(feature = "randomx")]
criterion_main!(benches);
