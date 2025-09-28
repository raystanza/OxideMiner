// OxideMiner/crates/oxide-miner/src/stats.rs

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Shared miner statistics updated across tasks and exposed via the HTTP API.
pub struct Stats {
    pub start: Instant,
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub dev_accepted: AtomicU64,
    pub dev_rejected: AtomicU64,
    /// Total hashes computed since startup.
    pub hashes: Arc<AtomicU64>,
    pub pool_connected: AtomicBool,
    pub tls: bool,
    pub pool: String,
}

impl Stats {
    pub fn new(pool: String, tls: bool) -> Self {
        Self {
            start: Instant::now(),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            dev_accepted: AtomicU64::new(0),
            dev_rejected: AtomicU64::new(0),
            hashes: Arc::new(AtomicU64::new(0)),
            pool_connected: AtomicBool::new(false),
            tls,
            pool,
        }
    }

    /// Average hashes per second since startup.
    pub fn hashrate(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.hashes.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Stats;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn stats_initializes_counters() {
        let stats = Stats::new("pool".into(), true);
        assert_eq!(stats.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rejected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dev_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dev_rejected.load(Ordering::Relaxed), 0);
        assert!(stats.hashrate() >= 0.0);
        assert!(stats.tls);
        assert_eq!(stats.pool, "pool");
    }

    #[test]
    fn hashrate_uses_elapsed_time() {
        let stats = Stats::new("pool".into(), false);
        // Replace hashes with a pre-filled counter for deterministic check
        stats.hashes.store(1000, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(10));
        let rate = stats.hashrate();
        assert!(rate > 0.0);

        // Simulate zero hashrate when no hashes were recorded
        let manual = Stats {
            start: std::time::Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            dev_accepted: AtomicU64::new(0),
            dev_rejected: AtomicU64::new(0),
            hashes: Arc::new(AtomicU64::new(0)),
            pool_connected: AtomicBool::new(false),
            tls: false,
            pool: String::new(),
        };
        assert_eq!(manual.hashrate(), 0.0);
    }
}
