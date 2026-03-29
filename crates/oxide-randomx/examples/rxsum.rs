use oxide_randomx::{RandomXCache, RandomXConfig, RandomXDataset, RandomXFlags, RandomXVm};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let mut key_hex = None;
    let mut input_hex = None;
    let mut mode = "light".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key-hex" => {
                i += 1;
                key_hex = args.get(i).cloned();
            }
            "--input-hex" => {
                i += 1;
                input_hex = args.get(i).cloned();
            }
            "--mode" => {
                i += 1;
                mode = args.get(i).cloned().unwrap_or_else(|| "light".to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let key_hex = key_hex.ok_or_else(usage)?;
    let input_hex = input_hex.ok_or_else(usage)?;
    let key = hex_to_bytes(&key_hex)?;
    let input = hex_to_bytes(&input_hex)?;

    let cfg = RandomXConfig::new();
    let flags = RandomXFlags::default();
    let cache = RandomXCache::new(&key, &cfg).map_err(|e| e.to_string())?;

    let mut vm = if mode == "fast" {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let dataset = RandomXDataset::new(&cache, &cfg, threads).map_err(|e| e.to_string())?;
        RandomXVm::new_fast(cache, dataset, cfg, flags).map_err(|e| e.to_string())?
    } else {
        RandomXVm::new_light(cache, cfg, flags).map_err(|e| e.to_string())?
    };

    let hash = vm.hash(&input);
    println!("{}", bytes_to_hex(&hash));
    Ok(())
}

fn usage() -> String {
    "usage: rxsum --key-hex <hex> --input-hex <hex> --mode light|fast".to_string()
}

fn hex_to_bytes(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_value(bytes[i])?;
        let lo = hex_value(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_value(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("hex string contains invalid character".to_string()),
    }
}
