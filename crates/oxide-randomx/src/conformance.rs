#![cfg(not(miri))]

use crate::{RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm};
use serde::Deserialize;

#[derive(Deserialize)]
struct ConformanceCases {
    cases: Vec<ConformanceCase>,
}

#[derive(Deserialize)]
struct ConformanceCase {
    key_hex: String,
    input_hex: String,
    notes: Option<String>,
}

#[test]
fn deterministic_light_hashes() {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let cases = load_cases();
    let limit = if cfg!(miri) { 2 } else { cases.len() };

    for (idx, case) in cases.iter().take(limit).enumerate() {
        let key = hex_to_bytes(&case.key_hex);
        let input = hex_to_bytes(&case.input_hex);
        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let mut vm = RandomXVm::new_light(cache, cfg.clone(), flags.clone()).expect("vm");
        let h1 = vm.hash(&input);
        let h2 = vm.hash(&input);
        let note = case.notes.as_deref().unwrap_or("");
        assert_eq!(h1, h2, "case {} {}", idx, note);
    }
}

#[cfg(not(miri))]
#[test]
fn deterministic_fast_hashes() {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let cases = load_cases();

    for (idx, case) in cases.iter().enumerate() {
        let key = hex_to_bytes(&case.key_hex);
        let input = hex_to_bytes(&case.input_hex);
        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let dataset = RandomXDataset::new(&cache, &cfg, 1).expect("dataset");
        let mut vm = RandomXVm::new_fast(cache, dataset, cfg.clone(), flags.clone()).expect("vm");
        let h1 = vm.hash(&input);
        let h2 = vm.hash(&input);
        let note = case.notes.as_deref().unwrap_or("");
        assert_eq!(h1, h2, "case {} {}", idx, note);
    }
}

#[test]
fn rekey_is_deterministic() {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let cases = load_cases();
    let (key, input) = first_non_empty_case(&cases);

    let cache = RandomXCache::new(&key, &cfg).expect("cache");
    let mut vm = RandomXVm::new_light(cache, cfg, flags).expect("vm");
    let before = vm.hash(&input);
    vm.rekey(&key).expect("rekey");
    let after = vm.hash(&input);
    assert_eq!(before, after);
}

#[cfg(not(miri))]
#[test]
fn rekey_fast_is_deterministic() {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let cases = load_cases();
    let (key, input) = first_non_empty_case(&cases);

    let cache = RandomXCache::new(&key, &cfg).expect("cache");
    let dataset = RandomXDataset::new(&cache, &cfg, 1).expect("dataset");
    let mut vm = RandomXVm::new_fast(cache, dataset, cfg, flags).expect("vm");
    let before = vm.hash(&input);
    vm.rekey(&key).expect("rekey");
    let after = vm.hash(&input);
    assert_eq!(before, after);
}

fn load_cases() -> Vec<ConformanceCase> {
    let json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/conformance_cases.json"
    ));
    let cases: ConformanceCases = serde_json::from_str(json).expect("parse conformance cases");
    cases.cases
}

fn first_non_empty_case(cases: &[ConformanceCase]) -> (Vec<u8>, Vec<u8>) {
    for case in cases {
        if !case.key_hex.is_empty() || !case.input_hex.is_empty() {
            return (hex_to_bytes(&case.key_hex), hex_to_bytes(&case.input_hex));
        }
    }
    (Vec::new(), Vec::new())
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex length must be even");
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut bytes = hex.as_bytes().iter().copied();
    while let (Some(hi), Some(lo)) = (bytes.next(), bytes.next()) {
        out.push((from_hex(hi) << 4) | from_hex(lo));
    }
    out
}

fn from_hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
