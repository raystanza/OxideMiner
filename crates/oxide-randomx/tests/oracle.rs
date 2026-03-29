#![cfg(not(miri))]

mod common;

use common::{
    bytes_to_hex, hex_to_bytes, load_conformance_cases, load_oracle_expected, save_oracle_expected,
    OracleCase, OracleExpected,
};
use oxide_randomx::{RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm};
use std::process::Command;

const ORACLE_LIGHT_CASES: usize = 10;
const ORACLE_FAST_CASES: usize = 10;

// Golden vectors in tests/data/oracle_expected.json are generated via the
// interpreter using RandomXConfig::test_small and RandomXFlags::default.
// To regenerate:
//   RANDOMX_ORACLE_GEN=1 cargo test --test oracle -- oracle_snapshot_from_interpreter
// Or set RANDOMX_ORACLE_CMD to a compatible oracle and commit the updated JSON.

#[test]
fn oracle_expected_matches_interpreter() {
    let expected = load_oracle_expected()
        .expect("oracle_expected.json missing or empty; regenerate and commit test vectors");
    assert_expected_matches(&expected);
}

#[test]
fn oracle_snapshot_from_interpreter() {
    if std::env::var("RANDOMX_ORACLE_GEN").ok().as_deref() != Some("1") {
        return;
    }
    let cases = load_conformance_cases();
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let mut expected = OracleExpected { cases: Vec::new() };

    for case in cases.iter().take(ORACLE_LIGHT_CASES) {
        let key = hex_to_bytes(&case.key_hex);
        let input = hex_to_bytes(&case.input_hex);
        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let mut vm = RandomXVm::new_light(cache, cfg.clone(), flags.clone()).expect("vm");
        let hash_hex = bytes_to_hex(&vm.hash(&input));
        expected.cases.push(OracleCase {
            key_hex: case.key_hex.clone(),
            input_hex: case.input_hex.clone(),
            mode: "light".to_string(),
            hash_hex,
        });
    }

    for case in cases.iter().take(ORACLE_FAST_CASES) {
        let key = hex_to_bytes(&case.key_hex);
        let input = hex_to_bytes(&case.input_hex);
        let cache = RandomXCache::new(&key, &cfg).expect("cache");
        let dataset = RandomXDataset::new(&cache, &cfg, 1).expect("dataset");
        let mut vm = RandomXVm::new_fast(cache, dataset, cfg.clone(), flags.clone()).expect("vm");
        let hash_hex = bytes_to_hex(&vm.hash(&input));
        expected.cases.push(OracleCase {
            key_hex: case.key_hex.clone(),
            input_hex: case.input_hex.clone(),
            mode: "fast".to_string(),
            hash_hex,
        });
    }

    save_oracle_expected(&expected);
}

#[test]
fn oracle_snapshot_from_external() {
    let cmd = match std::env::var("RANDOMX_ORACLE_CMD") {
        Ok(cmd) => cmd,
        Err(_) => return,
    };
    let cases = load_conformance_cases();
    let mut expected = OracleExpected { cases: Vec::new() };

    for case in cases.iter().take(ORACLE_LIGHT_CASES) {
        let key_hex = case.key_hex.clone();
        let input_hex = case.input_hex.clone();
        let hash_hex = run_oracle(&cmd, &key_hex, &input_hex, "light");
        expected.cases.push(OracleCase {
            key_hex,
            input_hex,
            mode: "light".to_string(),
            hash_hex,
        });
    }

    for case in cases.iter().take(ORACLE_FAST_CASES) {
        let key_hex = case.key_hex.clone();
        let input_hex = case.input_hex.clone();
        let hash_hex = run_oracle(&cmd, &key_hex, &input_hex, "fast");
        expected.cases.push(OracleCase {
            key_hex,
            input_hex,
            mode: "fast".to_string(),
            hash_hex,
        });
    }

    save_oracle_expected(&expected);
    assert_expected_matches(&expected);
}

fn assert_expected_matches(expected: &OracleExpected) {
    let cfg = RandomXConfig::test_small();
    let flags = RandomXFlags::default();
    let threads = 1usize;
    let light_cases = expected
        .cases
        .iter()
        .filter(|case| case.mode == "light")
        .count();
    let fast_cases = expected
        .cases
        .iter()
        .filter(|case| case.mode == "fast")
        .count();
    assert!(
        light_cases >= ORACLE_LIGHT_CASES,
        "oracle_expected.json must include at least {ORACLE_LIGHT_CASES} light cases"
    );
    assert!(
        fast_cases >= ORACLE_FAST_CASES,
        "oracle_expected.json must include at least {ORACLE_FAST_CASES} fast cases"
    );

    for (idx, entry) in expected.cases.iter().enumerate() {
        let case_label = format!(
            "case {idx} mode={} key={} input={}",
            entry.mode, entry.key_hex, entry.input_hex
        );
        let key = hex_to_bytes(&entry.key_hex);
        let input = hex_to_bytes(&entry.input_hex);
        match entry.mode.as_str() {
            "light" => {
                let cache = RandomXCache::new(&key, &cfg).expect("cache");
                let mut vm = RandomXVm::new_light(cache, cfg.clone(), flags.clone()).expect("vm");
                let interp_hash = bytes_to_hex(&vm.hash(&input));
                assert_eq!(interp_hash, entry.hash_hex, "oracle mismatch {case_label}");
                #[cfg(all(feature = "jit", target_arch = "x86_64"))]
                {
                    let flags = RandomXFlags {
                        jit: true,
                        ..flags.clone()
                    };
                    let cache = RandomXCache::new(&key, &cfg).expect("cache");
                    let mut vm =
                        RandomXVm::new_light(cache, cfg.clone(), flags.clone()).expect("vm");
                    assert!(
                        vm.is_jit_active(),
                        "jit requested but not active ({case_label})"
                    );
                    let jit_hash = bytes_to_hex(&vm.hash(&input));
                    assert_eq!(jit_hash, interp_hash, "jit mismatch {case_label}");
                    #[cfg(feature = "jit-fastregs")]
                    {
                        let flags = RandomXFlags {
                            jit: true,
                            jit_fast_regs: true,
                            ..flags.clone()
                        };
                        let cache = RandomXCache::new(&key, &cfg).expect("cache");
                        let mut vm = RandomXVm::new_light(cache, cfg.clone(), flags).expect("vm");
                        assert!(
                            vm.is_jit_active(),
                            "jit-fast-regs requested but not active ({case_label})"
                        );
                        let fast_hash = bytes_to_hex(&vm.hash(&input));
                        assert_eq!(
                            fast_hash, interp_hash,
                            "jit-fast-regs mismatch {case_label}"
                        );
                    }
                }
            }
            "fast" => {
                let cache = RandomXCache::new(&key, &cfg).expect("cache");
                let dataset = RandomXDataset::new(&cache, &cfg, threads).expect("dataset");
                let mut vm =
                    RandomXVm::new_fast(cache, dataset, cfg.clone(), flags.clone()).expect("vm");
                let interp_hash = bytes_to_hex(&vm.hash(&input));
                assert_eq!(interp_hash, entry.hash_hex, "oracle mismatch {case_label}");
                #[cfg(all(feature = "jit", target_arch = "x86_64"))]
                {
                    let flags = RandomXFlags {
                        jit: true,
                        ..flags.clone()
                    };
                    let cache = RandomXCache::new(&key, &cfg).expect("cache");
                    let dataset = RandomXDataset::new(&cache, &cfg, threads).expect("dataset");
                    let mut vm = RandomXVm::new_fast(cache, dataset, cfg.clone(), flags.clone())
                        .expect("vm");
                    assert!(
                        vm.is_jit_active(),
                        "jit requested but not active ({case_label})"
                    );
                    let jit_hash = bytes_to_hex(&vm.hash(&input));
                    assert_eq!(jit_hash, interp_hash, "jit mismatch {case_label}");
                    #[cfg(feature = "jit-fastregs")]
                    {
                        let flags = RandomXFlags {
                            jit: true,
                            jit_fast_regs: true,
                            ..flags.clone()
                        };
                        let cache = RandomXCache::new(&key, &cfg).expect("cache");
                        let dataset = RandomXDataset::new(&cache, &cfg, threads).expect("dataset");
                        let mut vm =
                            RandomXVm::new_fast(cache, dataset, cfg.clone(), flags).expect("vm");
                        assert!(
                            vm.is_jit_active(),
                            "jit-fast-regs requested but not active ({case_label})"
                        );
                        let fast_hash = bytes_to_hex(&vm.hash(&input));
                        assert_eq!(
                            fast_hash, interp_hash,
                            "jit-fast-regs mismatch {case_label}"
                        );
                    }
                }
            }
            other => panic!("unknown oracle mode {other}"),
        }
    }
}

fn run_oracle(cmd: &str, key_hex: &str, input_hex: &str, mode: &str) -> String {
    let output = Command::new(cmd)
        .args([
            "--key-hex",
            key_hex,
            "--input-hex",
            input_hex,
            "--mode",
            mode,
        ])
        .output()
        .expect("oracle command");
    assert!(output.status.success(), "oracle command failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().to_string()
}
