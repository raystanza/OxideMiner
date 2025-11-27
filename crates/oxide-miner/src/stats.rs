// OxideMiner/crates/oxide-miner/src/stats.rs

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Shared miner statistics updated across tasks and exposed via the HTTP API.
pub struct Stats {
    pub start: Instant,
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub dev_accepted: AtomicU64,
    pub dev_rejected: AtomicU64,
    pub tari_accepted: AtomicU64,
    pub tari_rejected: AtomicU64,
    pub tari_enabled: bool,
    pub tari_pool: Option<String>,
    pub tari_height: AtomicU64,
    pub tari_difficulty: AtomicU64,
    /// Total hashes computed since startup.
    pub hashes: Arc<AtomicU64>,
    /// Hashes computed for the Tari pool (if enabled).
    pub tari_hashes: Arc<AtomicU64>,
    pub pool_connected: AtomicBool,
    pub tari_pool_connected: AtomicBool,
    pub tls: bool,
    pub pool: Option<String>,
}

impl Stats {
    pub fn new(
        pool: Option<String>,
        tls: bool,
        tari_enabled: bool,
        tari_pool: Option<String>,
    ) -> Self {
        Self {
            start: Instant::now(),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            dev_accepted: AtomicU64::new(0),
            dev_rejected: AtomicU64::new(0),
            tari_accepted: AtomicU64::new(0),
            tari_rejected: AtomicU64::new(0),
            tari_enabled,
            tari_pool,
            tari_height: AtomicU64::new(0),
            tari_difficulty: AtomicU64::new(0),
            hashes: Arc::new(AtomicU64::new(0)),
            tari_hashes: Arc::new(AtomicU64::new(0)),
            pool_connected: AtomicBool::new(false),
            tari_pool_connected: AtomicBool::new(false),
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

    pub fn tari_hashrate(&self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.tari_hashes.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Total time the miner has been running.
    pub fn mining_duration(&self) -> Duration {
        self.start.elapsed()
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
        let stats = Stats::new(Some("pool".into()), true, false, None);
        assert_eq!(stats.accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.rejected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dev_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dev_rejected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tari_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tari_rejected.load(Ordering::Relaxed), 0);
        assert!(stats.hashrate() >= 0.0);
        assert!(stats.tari_hashrate() >= 0.0);
        assert!(stats.tls);
        assert_eq!(stats.pool.as_deref(), Some("pool"));
    }

    #[test]
    fn hashrate_uses_elapsed_time() {
        let stats = Stats::new(Some("pool".into()), false, false, None);
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
            tari_accepted: AtomicU64::new(0),
            tari_rejected: AtomicU64::new(0),
            tari_enabled: false,
            tari_pool: None,
            tari_height: AtomicU64::new(0),
            tari_difficulty: AtomicU64::new(0),
            hashes: Arc::new(AtomicU64::new(0)),
            tari_hashes: Arc::new(AtomicU64::new(0)),
            pool_connected: AtomicBool::new(false),
            tari_pool_connected: AtomicBool::new(false),
            tls: false,
            pool: None,
        };
        assert_eq!(manual.hashrate(), 0.0);
    }

    #[test]
    fn mining_duration_tracks_elapsed_time() {
        let stats = Stats::new(Some("pool".into()), false, false, None);
        std::thread::sleep(Duration::from_millis(5));
        let elapsed = stats.mining_duration();
        assert!(elapsed >= Duration::from_millis(5));
        assert!(elapsed.as_secs_f64() >= 0.0);
    }
}
