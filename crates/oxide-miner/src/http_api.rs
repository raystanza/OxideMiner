use axum::{
    extract::State,
    response::{sse::Event, Html, Sse},
    routing::get,
    Json, Router,
};
use tokio_stream::Stream;
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio_stream::{wrappers::IntervalStream, StreamExt};
use tracing::info;

/// Shared state for the HTTP API.
pub struct ApiState {
    pub accepted: Arc<AtomicU64>,
    pub rejected: Arc<AtomicU64>,
    pub devfee_accepted: Arc<AtomicU64>,
    pub devfee_rejected: Arc<AtomicU64>,
    pub hashes: Arc<AtomicU64>,
    pub connected: Arc<AtomicBool>,
    pub start: Instant,
    pub pool: String,
    pub tls: bool,
}

#[derive(serde::Serialize)]
struct Stats {
    hashrate: f64,
    pool: String,
    tls: bool,
    connected: bool,
    shares_accepted: u64,
    shares_rejected: u64,
    devfee_accepted: u64,
    devfee_rejected: u64,
}

fn gather(state: &ApiState) -> Stats {
    let elapsed = state.start.elapsed().as_secs_f64().max(1.0);
    let hashes = state.hashes.load(Ordering::Relaxed) as f64;
    Stats {
        hashrate: hashes / elapsed,
        pool: state.pool.clone(),
        tls: state.tls,
        connected: state.connected.load(Ordering::Relaxed),
        shares_accepted: state.accepted.load(Ordering::Relaxed),
        shares_rejected: state.rejected.load(Ordering::Relaxed),
        devfee_accepted: state.devfee_accepted.load(Ordering::Relaxed),
        devfee_rejected: state.devfee_rejected.load(Ordering::Relaxed),
    }
}

async fn stats(State(state): State<Arc<ApiState>>) -> Json<Stats> {
    Json(gather(&state))
}

async fn metrics(State(state): State<Arc<ApiState>>) -> String {
    let s = gather(&state);
    format!(
        concat!(
            "oxide_hashrate {}\n",
            "oxide_accepted_total {}\n",
            "oxide_rejected_total {}\n",
            "oxide_devfee_accepted_total {}\n",
            "oxide_devfee_rejected_total {}\n",
            "oxide_connected {}\n",
        ),
        s.hashrate,
        s.shares_accepted,
        s.shares_rejected,
        s.devfee_accepted,
        s.devfee_rejected,
        if s.connected { 1 } else { 0 },
    )
}

async fn dashboard() -> Html<&'static str> {
    // Very small dashboard that polls /api/stats every 2s
    const DASHBOARD: &str = r#"<!DOCTYPE html>
<html><head><title>OxideMiner</title></head>
<body><h1>OxideMiner</h1><pre id="stats">loading...</pre>
<script>
async function refresh(){
  const r = await fetch('/api/stats');
  const s = await r.json();
  document.getElementById('stats').textContent =
    `hashrate: ${s.hashrate.toFixed(2)} H/s\n` +
    `pool: ${s.pool} (tls: ${s.tls})\n` +
    `connected: ${s.connected}\n` +
    `accepted: ${s.shares_accepted} rejected: ${s.shares_rejected}\n` +
    `devfee accepted: ${s.devfee_accepted} devfee rejected: ${s.devfee_rejected}`;
}
setInterval(refresh,2000);refresh();
</script></body></html>"#;
    Html(DASHBOARD)
}

async fn events(State(state): State<Arc<ApiState>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = IntervalStream::new(tokio::time::interval(Duration::from_secs(1))).map(move |_| {
        let data = serde_json::to_string(&gather(&state)).unwrap();
        Ok::<_, Infallible>(Event::default().data(data))
    });
    Sse::new(stream)
}

pub async fn run_http_api(port: u16, state: Arc<ApiState>) {
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(stats))
        .route("/metrics", get(metrics))
        .route("/events", get(events))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("HTTP API listening on http://{addr}");
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HTTP bind failed: {e}");
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("HTTP server error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::{run_http_api, ApiState};
    use reqwest::Client;
    use std::sync::{atomic::{AtomicBool, AtomicU64}, Arc};
    use std::time::Instant;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn stats_endpoint_reports_counts() {
        // Pick an available port by binding to port 0 first.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let state = ApiState {
            accepted: Arc::new(AtomicU64::new(5)),
            rejected: Arc::new(AtomicU64::new(2)),
            devfee_accepted: Arc::new(AtomicU64::new(1)),
            devfee_rejected: Arc::new(AtomicU64::new(0)),
            hashes: Arc::new(AtomicU64::new(0)),
            connected: Arc::new(AtomicBool::new(true)),
            start: Instant::now(),
            pool: "pool".into(),
            tls: false,
        };
        let state = Arc::new(state);

        let server = tokio::spawn(run_http_api(port, state.clone()));
        // Give the server a moment to start
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/api/stats", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["shares_accepted"], 5);
        assert_eq!(body["shares_rejected"], 2);

        server.abort();
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_text() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let state = ApiState {
            accepted: Arc::new(AtomicU64::new(5)),
            rejected: Arc::new(AtomicU64::new(2)),
            devfee_accepted: Arc::new(AtomicU64::new(1)),
            devfee_rejected: Arc::new(AtomicU64::new(0)),
            hashes: Arc::new(AtomicU64::new(0)),
            connected: Arc::new(AtomicBool::new(true)),
            start: Instant::now(),
            pool: "pool".into(),
            tls: false,
        };
        let state = Arc::new(state);

        let server = tokio::spawn(run_http_api(port, state.clone()));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/metrics", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();
        assert!(body.contains("oxide_accepted_total 5"));

        server.abort();
    }
}

