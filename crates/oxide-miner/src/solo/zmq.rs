// OxideMiner/crates/oxide-miner/src/solo/zmq.rs

use crate::solo::unix_timestamp_seconds;
use crate::stats::Stats;
use crate::util::tiny_jitter_ms;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use zeromq::{Socket, SocketRecv, SubSocket, ZmqMessage};

/// Monerod ZMQ topics from docs/ZMQ.md (format-context-event).
pub const TOPIC_CHAIN_MAIN: &str = "json-minimal-chain_main";
pub const TOPIC_TXPOOL_ADD: &str = "json-minimal-txpool_add";

const EVENT_CHANNEL_SIZE: usize = 64;
const LOG_THROTTLE: Duration = Duration::from_secs(30);
const MAX_BACKOFF_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZmqEventKind {
    ChainMain,
    TxpoolAdd,
    MinerData,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ZmqEvent {
    pub kind: ZmqEventKind,
}

pub fn default_topics() -> Vec<String> {
    vec![TOPIC_CHAIN_MAIN.to_string(), TOPIC_TXPOOL_ADD.to_string()]
}

pub fn classify_topic(topic: &str) -> ZmqEventKind {
    let mut parts = topic.splitn(3, '-');
    let _format = parts.next();
    let _context = parts.next();
    let event = parts.next();
    match event {
        Some("chain_main") => ZmqEventKind::ChainMain,
        Some("txpool_add") => ZmqEventKind::TxpoolAdd,
        Some("miner_data") => ZmqEventKind::MinerData,
        _ => ZmqEventKind::Unknown,
    }
}

pub fn coalesce_refresh_deadline(
    current: Instant,
    now: Instant,
    cooldown_until: Instant,
    debounce: Duration,
) -> Instant {
    let mut target = now + debounce;
    if target < cooldown_until {
        target = cooldown_until;
    }
    if target < current {
        target
    } else {
        current
    }
}

pub fn spawn_zmq_watcher(
    endpoint: String,
    topics: Vec<String>,
    stats: Arc<Stats>,
    shutdown: watch::Receiver<bool>,
) -> mpsc::Receiver<ZmqEvent> {
    let (tx, rx) = mpsc::channel(EVENT_CHANNEL_SIZE);
    tokio::spawn(async move {
        run_zmq_loop(endpoint, topics, stats, shutdown, tx).await;
    });
    rx
}

struct LogLimiter {
    last: Instant,
    interval: Duration,
}

impl LogLimiter {
    fn new(interval: Duration) -> Self {
        let now = Instant::now();
        let last = now.checked_sub(interval).unwrap_or(now);
        Self { last, interval }
    }

    fn should_log(&mut self) -> bool {
        if self.last.elapsed() >= self.interval {
            self.last = Instant::now();
            true
        } else {
            false
        }
    }
}

async fn run_zmq_loop(
    endpoint: String,
    topics: Vec<String>,
    stats: Arc<Stats>,
    mut shutdown: watch::Receiver<bool>,
    tx: mpsc::Sender<ZmqEvent>,
) {
    let mut backoff_ms = 500u64;
    let mut connected = false;
    let mut connect_log = LogLimiter::new(LOG_THROTTLE);
    let mut drop_log = LogLimiter::new(LOG_THROTTLE);
    let mut decode_log = LogLimiter::new(LOG_THROTTLE);

    loop {
        if *shutdown.borrow() {
            break;
        }

        let mut socket = SubSocket::new();
        if let Err(err) = socket.connect(&endpoint).await {
            if connect_log.should_log() {
                tracing::warn!(zmq = %endpoint, error = %err, "solo ZMQ connect failed; retrying");
            }
            if wait_for_shutdown(&mut shutdown, backoff_ms).await {
                break;
            }
            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            continue;
        }

        let mut subscribed = true;
        for topic in &topics {
            if let Err(err) = socket.subscribe(topic).await {
                subscribed = false;
                if connect_log.should_log() {
                    tracing::warn!(
                        zmq = %endpoint,
                        topic = %topic,
                        error = %err,
                        "solo ZMQ subscribe failed; retrying"
                    );
                }
                break;
            }
        }

        if !subscribed {
            if wait_for_shutdown(&mut shutdown, backoff_ms).await {
                break;
            }
            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            continue;
        }

        backoff_ms = 500;
        if !connected {
            connected = true;
            stats.solo_zmq_connected.store(true, Ordering::Relaxed);
            tracing::info!(zmq = %endpoint, "solo ZMQ connected");
        }

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        if connected {
                            stats.solo_zmq_connected.store(false, Ordering::Relaxed);
                        }
                        return;
                    }
                }
                msg = socket.recv() => {
                    match msg {
                        Ok(message) => {
                            if let Some(event) = decode_event(message, stats.as_ref(), &mut decode_log) {
                                if let Err(err) = tx.try_send(event) {
                                    if tx.is_closed() {
                                        if connected {
                                            stats.solo_zmq_connected.store(false, Ordering::Relaxed);
                                        }
                                        return;
                                    }
                                    if drop_log.should_log() {
                                        tracing::warn!(
                                            zmq = %endpoint,
                                            error = %err,
                                            "solo ZMQ event backlog; dropping events"
                                        );
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            if connected {
                                stats.solo_zmq_connected.store(false, Ordering::Relaxed);
                                tracing::warn!(zmq = %endpoint, error = %err, "solo ZMQ disconnected; reconnecting");
                            } else if connect_log.should_log() {
                                tracing::warn!(zmq = %endpoint, error = %err, "solo ZMQ receive error; reconnecting");
                            }
                            break;
                        }
                    }
                }
            }
        }

        if connected {
            connected = false;
            stats.solo_zmq_connected.store(false, Ordering::Relaxed);
        }

        if wait_for_shutdown(&mut shutdown, backoff_ms).await {
            break;
        }
        backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>, backoff_ms: u64) -> bool {
    let delay = Duration::from_millis(backoff_ms + tiny_jitter_ms());
    tokio::select! {
        _ = shutdown.changed() => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

fn decode_event(
    message: ZmqMessage,
    stats: &Stats,
    decode_log: &mut LogLimiter,
) -> Option<ZmqEvent> {
    let topic_frame = message.get(0)?;
    let topic = match std::str::from_utf8(topic_frame.as_ref()) {
        Ok(topic) => topic.to_string(),
        Err(err) => {
            if decode_log.should_log() {
                tracing::warn!(error = %err, "solo ZMQ message with invalid topic");
            }
            return None;
        }
    };

    let kind = classify_topic(&topic);
    stats.solo_zmq_events_total.fetch_add(1, Ordering::Relaxed);
    stats
        .solo_zmq_last_event_timestamp
        .store(unix_timestamp_seconds(), Ordering::Relaxed);
    if let Ok(mut guard) = stats.solo_zmq_last_topic.lock() {
        *guard = Some(topic.clone());
    }

    Some(ZmqEvent { kind })
}

#[cfg(test)]
mod tests {
    use super::{classify_topic, coalesce_refresh_deadline, ZmqEventKind};
    use std::time::{Duration, Instant};

    #[test]
    fn classify_topic_maps_known_events() {
        assert_eq!(
            classify_topic("json-minimal-chain_main"),
            ZmqEventKind::ChainMain
        );
        assert_eq!(
            classify_topic("json-minimal-txpool_add"),
            ZmqEventKind::TxpoolAdd
        );
        assert_eq!(
            classify_topic("json-full-miner_data"),
            ZmqEventKind::MinerData
        );
        assert_eq!(classify_topic("garbage"), ZmqEventKind::Unknown);
    }

    #[test]
    fn coalesce_refresh_respects_cooldown_and_existing_deadline() {
        let base = Instant::now();
        let now = base + Duration::from_secs(1);
        let cooldown = base + Duration::from_secs(3);
        let current = base + Duration::from_secs(10);
        let result = coalesce_refresh_deadline(current, now, cooldown, Duration::from_secs(1));
        assert_eq!(result, cooldown);

        let current = base + Duration::from_secs(2);
        let result = coalesce_refresh_deadline(current, now, cooldown, Duration::from_secs(1));
        assert_eq!(result, current);
    }
}
