// OxideMiner/crates/oxide-miner/src/stats.rs

use crate::args::{LoadedConfigFile, MiningMode};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ZMQ_FEED_MAX_ENTRIES: usize = 120;
const ZMQ_FEED_MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct ZmqFeedEntry {
    pub ts: u64,
    pub topic: String,
    pub summary: String,
}

#[derive(Debug)]
struct ZmqFeedBuffer {
    entries: VecDeque<ZmqFeedEntry>,
    bytes: usize,
}

impl ZmqFeedBuffer {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
        }
    }

    fn entry_size(entry: &ZmqFeedEntry) -> usize {
        entry.topic.len() + entry.summary.len() + 24
    }

    fn push(&mut self, entry: ZmqFeedEntry) {
        self.bytes = self.bytes.saturating_add(Self::entry_size(&entry));
        self.entries.push_back(entry);

        while self.entries.len() > ZMQ_FEED_MAX_ENTRIES || self.bytes > ZMQ_FEED_MAX_BYTES {
            if let Some(front) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(Self::entry_size(&front));
            } else {
                break;
            }
        }
    }

    fn snapshot(&self) -> Vec<ZmqFeedEntry> {
        self.entries.iter().cloned().collect()
    }
}

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
    pub mode: MiningMode,
    pub config: Option<LoadedConfigFile>,
    pub node_height: AtomicU64,
    pub template_height: AtomicU64,
    pub template_timestamp: AtomicU64,
    pub blocks_submitted: AtomicU64,
    pub blocks_accepted: AtomicU64,
    pub blocks_rejected: AtomicU64,
    pub last_submit: Mutex<Option<SubmitRecord>>,
    pub solo_zmq_enabled: bool,
    pub solo_zmq_connected: AtomicBool,
    pub solo_zmq_events_total: AtomicU64,
    pub solo_zmq_last_event_timestamp: AtomicU64,
    pub solo_zmq_last_topic: Mutex<Option<String>>,
    solo_zmq_feed: Mutex<ZmqFeedBuffer>,
    hashrate_sample: Mutex<HashrateSample>,
}

impl Stats {
    pub fn new(
        mode: MiningMode,
        pool: String,
        tls: bool,
        config: Option<LoadedConfigFile>,
        solo_zmq_enabled: bool,
    ) -> Self {
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
            mode,
            config,
            node_height: AtomicU64::new(0),
            template_height: AtomicU64::new(0),
            template_timestamp: AtomicU64::new(0),
            blocks_submitted: AtomicU64::new(0),
            blocks_accepted: AtomicU64::new(0),
            blocks_rejected: AtomicU64::new(0),
            last_submit: Mutex::new(None),
            solo_zmq_enabled,
            solo_zmq_connected: AtomicBool::new(false),
            solo_zmq_events_total: AtomicU64::new(0),
            solo_zmq_last_event_timestamp: AtomicU64::new(0),
            solo_zmq_last_topic: Mutex::new(None),
            solo_zmq_feed: Mutex::new(ZmqFeedBuffer::new()),
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

    pub fn template_age_seconds(&self) -> Option<u64> {
        let ts = self.template_timestamp.load(Ordering::Relaxed);
        if ts == 0 {
            return None;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(now.saturating_sub(ts))
    }

    pub fn push_zmq_feed_entry(&self, entry: ZmqFeedEntry) {
        if let Ok(mut guard) = self.solo_zmq_feed.try_lock() {
            guard.push(entry);
        }
    }

    pub fn zmq_recent_snapshot(&self) -> Vec<ZmqFeedEntry> {
        self.solo_zmq_feed
            .lock()
            .map(|guard| guard.snapshot())
            .unwrap_or_default()
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

#[derive(Clone, Copy, Debug)]
pub enum SubmitOutcome {
    Accepted,
    Rejected,
    Error,
}

impl SubmitOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SubmitOutcome::Accepted => "accepted",
            SubmitOutcome::Rejected => "rejected",
            SubmitOutcome::Error => "error",
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, SubmitOutcome::Accepted)
    }
}

#[derive(Clone, Debug)]
pub struct SubmitRecord {
    pub outcome: SubmitOutcome,
    pub detail: String,
    pub timestamp: u64,
}

impl SubmitRecord {
    pub fn new(outcome: SubmitOutcome, detail: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            outcome,
            detail,
            timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HashrateSample, Stats};
    use crate::args::MiningMode;
    use crate::stats::ZmqFeedBuffer;

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn stats_initializes_counters() {
        let stats = Stats::new(MiningMode::Pool, "pool".into(), true, None, false);
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
        let stats = Stats::new(MiningMode::Pool, "pool".into(), false, None, false);
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
            mode: MiningMode::Pool,
            config: None,
            node_height: AtomicU64::new(0),
            template_height: AtomicU64::new(0),
            template_timestamp: AtomicU64::new(0),
            blocks_submitted: AtomicU64::new(0),
            blocks_accepted: AtomicU64::new(0),
            blocks_rejected: AtomicU64::new(0),
            last_submit: Mutex::new(None),
            solo_zmq_enabled: false,
            solo_zmq_connected: AtomicBool::new(false),
            solo_zmq_events_total: AtomicU64::new(0),
            solo_zmq_last_event_timestamp: AtomicU64::new(0),
            solo_zmq_last_topic: Mutex::new(None),
            solo_zmq_feed: Mutex::new(ZmqFeedBuffer::new()),
            hashrate_sample: Mutex::new(HashrateSample::new()),
        };
        assert_eq!(manual.hashrate_avg(), 0.0);
    }

    #[test]
    fn instant_hashrate_tracks_recent_progress() {
        let stats = Stats::new(MiningMode::Pool, "pool".into(), false, None, false);
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
        let stats = Stats::new(MiningMode::Pool, "pool".into(), false, None, false);
        std::thread::sleep(Duration::from_millis(5));
        let elapsed = stats.mining_duration();
        assert!(elapsed >= Duration::from_millis(5));
        assert!(elapsed.as_secs_f64() >= 0.0);
    }
}
