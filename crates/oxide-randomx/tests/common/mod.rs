use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
pub struct ConformanceCase {
    pub key_hex: String,
    pub input_hex: String,
    #[allow(dead_code)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConformanceCases {
    cases: Vec<ConformanceCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleExpected {
    pub cases: Vec<OracleCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleCase {
    pub key_hex: String,
    pub input_hex: String,
    pub mode: String,
    pub hash_hex: String,
}

pub fn load_conformance_cases() -> Vec<ConformanceCase> {
    let json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/conformance_cases.json"
    ));
    let cases: ConformanceCases = serde_json::from_str(json).expect("parse conformance cases");
    cases.cases
}

pub fn load_oracle_expected() -> Option<OracleExpected> {
    let json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/oracle_expected.json"
    ));
    let expected: OracleExpected = serde_json::from_str(json).expect("parse oracle expected");
    if expected.cases.is_empty() {
        None
    } else {
        Some(expected)
    }
}

pub fn save_oracle_expected(expected: &OracleExpected) {
    let path = data_path("oracle_expected.json");
    let json = serde_json::to_string_pretty(expected).expect("serialize oracle expected");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(path, json).expect("write oracle expected");
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex length must be even");
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut iter = hex.as_bytes().iter().copied();
    while let (Some(hi), Some(lo)) = (iter.next(), iter.next()) {
        out.push((from_hex(hi) << 4) | from_hex(lo));
    }
    out
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn data_path(name: &str) -> PathBuf {
    let root = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(root).join("tests").join("data").join(name)
}

fn from_hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex"),
    }
}
