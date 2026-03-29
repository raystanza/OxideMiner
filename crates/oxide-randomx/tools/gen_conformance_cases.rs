use std::fs;
use std::io::Write;
use std::path::PathBuf;

const SEED: u64 = 0x6f78_6964_6572_7878;

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut z = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.state = z;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut offset = 0;
        while offset < len {
            let word = self.next_u64().to_le_bytes();
            let take = (len - offset).min(8);
            out[offset..offset + take].copy_from_slice(&word[..take]);
            offset += take;
        }
        out
    }
}

fn main() {
    let specs = [
        (0usize, 0usize, "empty key/input"),
        (1, 1, "single byte"),
        (2, 3, "tiny"),
        (3, 7, "short"),
        (8, 16, "small"),
        (16, 32, "medium"),
        (24, 48, "medium+"),
        (32, 64, "block"),
        (47, 127, "large"),
        (60, 192, "max key"),
    ];
    let mut rng = SplitMix64::new(SEED);
    let mut cases = Vec::with_capacity(specs.len());
    for (key_len, input_len, note) in specs {
        let key = rng.fill_bytes(key_len);
        let input = rng.fill_bytes(input_len);
        cases.push((key, input, note));
    }

    let mut out = String::new();
    out.push_str("{\"cases\":[\n");
    for (idx, (key, input, note)) in cases.iter().enumerate() {
        out.push_str("  {\"key_hex\":\"");
        out.push_str(&to_hex(key));
        out.push_str("\",\"input_hex\":\"");
        out.push_str(&to_hex(input));
        out.push_str("\",\"notes\":\"");
        out.push_str(note);
        out.push_str("\"}");
        if idx + 1 < cases.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]}\n");

    let path = output_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut file = fs::File::create(&path).expect("create conformance cases");
    file.write_all(out.as_bytes())
        .expect("write conformance cases");
    println!("wrote {}", path.display());
}

fn output_path() -> PathBuf {
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(root)
        .join("tests")
        .join("data")
        .join("conformance_cases.json")
}

fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
