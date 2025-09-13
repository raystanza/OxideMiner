use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::response::{Html, Sse};
use axum::routing::get;
use axum::{Json, Router};
use axum::response::sse::Event;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_stream::{wrappers::IntervalStream, Stream, StreamExt};
use tracing::info;

/// Shared miner statistics exposed via the HTTP API.
pub struct ApiStats {
    pub start: Instant,
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub devfee_accepted: AtomicU64,
    pub devfee_rejected: AtomicU64,
    pub total_hashes: AtomicU64,
    pub pool: String,
    pub tls: bool,
}

impl ApiStats {
    pub fn new(pool: String, tls: bool) -> Self {
        Self {
            start: Instant::now(),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            devfee_accepted: AtomicU64::new(0),
            devfee_rejected: AtomicU64::new(0),
            total_hashes: AtomicU64::new(0),
            pool,
            tls,
        }
    }

    pub fn hashrate(&self) -> f64 {
        let secs = self.start.elapsed().as_secs_f64();
        if secs > 0.0 {
            self.total_hashes.load(Ordering::Relaxed) as f64 / secs
        } else {
            0.0
        }
    }

    fn snapshot(&self) -> StatsResponse {
        StatsResponse {
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            devfee_accepted: self.devfee_accepted.load(Ordering::Relaxed),
            devfee_rejected: self.devfee_rejected.load(Ordering::Relaxed),
            hashrate: self.hashrate(),
            pool: self.pool.clone(),
            tls: self.tls,
        }
    }
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub devfee_accepted: u64,
    pub devfee_rejected: u64,
    pub hashrate: f64,
    pub pool: String,
    pub tls: bool,
}

/// Serve a tiny HTML dashboard, JSON stats, Prometheus metrics, and optional SSE events.
pub async fn run_http_api(port: u16, stats: Arc<ApiStats>) {
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(api_stats))
        .route("/metrics", get(metrics))
        .route("/events", get(events))
        .with_state(stats.clone());

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    info!("HTTP API listening on http://{addr}");
    let listener = TcpListener::bind(addr).await.unwrap();
    let _ = axum::serve(listener, app.into_make_service()).await;
}

async fn dashboard() -> Html<&'static str> {
    const PAGE: &str = r#"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>OxideMiner</title></head><body><h1>OxideMiner</h1><pre id=\"stats\"></pre><script>
async function refresh(){const r=await fetch('/api/stats');const j=await r.json();document.getElementById('stats').textContent=JSON.stringify(j,null,2);}refresh();setInterval(refresh,1000);
</script></body></html>"#;
    Html(PAGE)
}

async fn api_stats(State(stats): State<Arc<ApiStats>>) -> Json<StatsResponse> {
    Json(stats.snapshot())
}

async fn metrics(State(stats): State<Arc<ApiStats>>) -> String {
    format!(
        "accepted {}\nrejected {}\ndevfee_accepted {}\ndevfee_rejected {}\nhashrate {}\n",
        stats.accepted.load(Ordering::Relaxed),
        stats.rejected.load(Ordering::Relaxed),
        stats.devfee_accepted.load(Ordering::Relaxed),
        stats.devfee_rejected.load(Ordering::Relaxed),
        stats.hashrate()
    )
}

async fn events(State(stats): State<Arc<ApiStats>>) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = IntervalStream::new(tokio::time::interval(Duration::from_secs(1)))
        .map(move |_| {
            let snapshot = stats.snapshot();
            let data = serde_json::to_string(&snapshot).unwrap();
            Ok(Event::default().data(data))
        });
    Sse::new(stream)
}

#[cfg(test)]
mod tests {
    use super::{run_http_api, ApiStats};
    use reqwest::Client;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn stats_and_metrics_endpoints_work() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(ApiStats::new("pool.test:0".into(), true));
        stats.accepted.store(5, Ordering::Relaxed);
        stats.rejected.store(2, Ordering::Relaxed);
        let server = tokio::spawn(run_http_api(port, stats.clone()));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/api/stats", port);
        let body: serde_json::Value = client.get(&url).send().await.unwrap().json().await.unwrap();
        assert_eq!(body["accepted"], 5);
        assert_eq!(body["rejected"], 2);

        let url = format!("http://127.0.0.1:{}/metrics", port);
        let text = client.get(&url).send().await.unwrap().text().await.unwrap();
        assert!(text.contains("accepted 5"));
        assert!(text.contains("rejected 2"));

        server.abort();
    }
}
