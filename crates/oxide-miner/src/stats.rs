// OxideMiner/crates/oxide-miner/src/stats.rs

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    hashrate_sample: Mutex<HashrateSample>,
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
            hashrate_sample: Mutex::new(HashrateSample::new()),
        }
    }

    /// Average hashes per second since startup.
    pub fn hashrate_avg(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.hashes.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Instantaneous hashes per second calculated from the most recent sample window.
    pub fn instant_hashrate(&self) -> f64 {
        let now = Instant::now();
        let hashes = self.hashes.load(Ordering::Relaxed);
        let mut sample = self
            .hashrate_sample
            .lock()
            .expect("hashrate sample mutex poisoned");

        let elapsed = now.saturating_duration_since(sample.last_time);
        let delta = hashes.saturating_sub(sample.last_hashes);

        sample.last_time = now;
        sample.last_hashes = hashes;

        if elapsed.is_zero() {
            0.0
        } else {
            delta as f64 / elapsed.as_secs_f64()
        }
    }

    /// Total time the miner has been running.
    pub fn mining_duration(&self) -> Duration {
        self.start.elapsed()
    }
}

#[derive(Clone, Copy, Debug)]
struct HashrateSample {
    last_hashes: u64,
    last_time: Instant,
}

impl HashrateSample {
    fn new() -> Self {
        Self {
            last_hashes: 0,
            last_time: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HashrateSample, Stats};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn stats_initializes_counters() {
        let stats = Stats::new("pool".into(), true);
        assert_eq!(stats.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rejected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dev_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dev_rejected.load(Ordering::Relaxed), 0);
        assert!(stats.hashrate_avg() >= 0.0);
        assert!(stats.tls);
        assert_eq!(stats.pool, "pool");
    }

    #[test]
    fn hashrate_avg_uses_elapsed_time() {
        let stats = Stats::new("pool".into(), false);
        // Replace hashes with a pre-filled counter for deterministic check
        stats.hashes.store(1000, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(10));
        let rate = stats.hashrate_avg();
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
            hashrate_sample: Mutex::new(HashrateSample::new()),
        };
        assert_eq!(manual.hashrate_avg(), 0.0);
    }

    #[test]
    fn instant_hashrate_tracks_recent_progress() {
        let stats = Stats::new("pool".into(), false);
        stats.hashes.store(0, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(10));
        stats.hashes.store(1000, Ordering::Relaxed);

        let inst = stats.instant_hashrate();
        assert!(inst > 0.0);

        // With no additional progress, the next instantaneous rate should be zero (or very close).
        std::thread::sleep(Duration::from_millis(5));
        let inst2 = stats.instant_hashrate();
        assert!(inst2 <= 1.0);
    }

    #[test]
    fn mining_duration_tracks_elapsed_time() {
        let stats = Stats::new("pool".into(), false);
        std::thread::sleep(Duration::from_millis(5));
        let elapsed = stats.mining_duration();
        assert!(elapsed >= Duration::from_millis(5));
        assert!(elapsed.as_secs_f64() >= 0.0);
    }
}
