use std::time::{SystemTime, UNIX_EPOCH};

pub fn tiny_jitter_ms() -> u64 {
    // Derive a tiny jitter from the current time.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.subsec_nanos() as u64;
    100 + (nanos % 500) // 100...600 ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_in_range() {
        let j = tiny_jitter_ms();
        assert!(j >= 100 && j <= 600);
    }
}
