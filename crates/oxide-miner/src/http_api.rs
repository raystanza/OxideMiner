use axum::response::sse::Event;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Sse},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_stream::{wrappers::IntervalStream, Stream, StreamExt};
use tracing::info;

pub struct Metrics {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub dev_accepted: AtomicU64,
    pub dev_rejected: AtomicU64,
    pub hashes: AtomicU64,
    pub start: Instant,
    pub pool: String,
    pub tls: bool,
}

impl Metrics {
    pub fn new(pool: String, tls: bool) -> Self {
        Self {
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            dev_accepted: AtomicU64::new(0),
            dev_rejected: AtomicU64::new(0),
            hashes: AtomicU64::new(0),
            start: Instant::now(),
            pool,
            tls,
        }
    }

    pub fn snapshot(&self) -> Stats {
        let elapsed = self.start.elapsed().as_secs_f64();
        let hashes = self.hashes.load(Ordering::Relaxed);
        let hashrate = if elapsed > 0.0 {
            hashes as f64 / elapsed
        } else {
            0.0
        };
        Stats {
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            devfee_accepted: self.dev_accepted.load(Ordering::Relaxed),
            devfee_rejected: self.dev_rejected.load(Ordering::Relaxed),
            hashrate,
            pool: self.pool.clone(),
            tls: self.tls,
            uptime: elapsed as u64,
        }
    }
}

#[derive(Serialize)]
pub struct Stats {
    pub accepted: u64,
    pub rejected: u64,
    #[serde(rename = "devfee_accepted")]
    pub devfee_accepted: u64,
    #[serde(rename = "devfee_rejected")]
    pub devfee_rejected: u64,
    pub hashrate: f64,
    pub pool: String,
    pub tls: bool,
    pub uptime: u64,
}

pub async fn run_http_api(port: u16, metrics: Arc<Metrics>) {
    let app = Router::new()
        .route("/metrics", get(prometheus))
        .route("/api/stats", get(api_stats))
        .route("/events", get(events))
        .route("/", get(dashboard))
        .with_state(metrics.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HTTP bind failed: {e}");
            return;
        }
    };
    info!("HTTP API listening on http://{addr}");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("HTTP server error: {e}");
    }
}

async fn api_stats(State(metrics): State<Arc<Metrics>>) -> Json<Stats> {
    Json(metrics.snapshot())
}

async fn prometheus(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    let snap = metrics.snapshot();
    let hashes = metrics.hashes.load(Ordering::Relaxed);
    let body = format!(
        concat!(
            "# HELP oxide_accepted_total Accepted shares\n",
            "# TYPE oxide_accepted_total counter\n",
            "oxide_accepted_total {}\n",
            "# HELP oxide_rejected_total Rejected shares\n",
            "# TYPE oxide_rejected_total counter\n",
            "oxide_rejected_total {}\n",
            "# HELP oxide_devfee_accepted_total Devfee accepted shares\n",
            "# TYPE oxide_devfee_accepted_total counter\n",
            "oxide_devfee_accepted_total {}\n",
            "# HELP oxide_devfee_rejected_total Devfee rejected shares\n",
            "# TYPE oxide_devfee_rejected_total counter\n",
            "oxide_devfee_rejected_total {}\n",
            "# HELP oxide_hashes_total Estimated hashes computed\n",
            "# TYPE oxide_hashes_total counter\n",
            "oxide_hashes_total {}\n",
            "# HELP oxide_hashrate Hashrate in H/s\n",
            "# TYPE oxide_hashrate gauge\n",
            "oxide_hashrate {}\n"
        ),
        snap.accepted,
        snap.rejected,
        snap.devfee_accepted,
        snap.devfee_rejected,
        hashes,
        snap.hashrate
    );
    (StatusCode::OK, body)
}

async fn events(
    State(metrics): State<Arc<Metrics>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let metrics = metrics.clone();
    let stream = IntervalStream::new(tokio::time::interval(std::time::Duration::from_secs(1))).map(
        move |_| {
            let data = serde_json::to_string(&metrics.snapshot()).unwrap();
            Ok(Event::default().data(data))
        },
    );
    Sse::new(stream)
}

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

#[cfg(test)]
mod tests {
    use super::{run_http_api, Metrics};
    use reqwest::Client;
    use std::sync::{atomic::Ordering, Arc};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn stats_endpoint_reports_counts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let metrics = Arc::new(Metrics::new("pool:1234".into(), true));
        metrics.accepted.store(5, Ordering::Relaxed);
        metrics.rejected.store(2, Ordering::Relaxed);

        let server = tokio::spawn(run_http_api(port, metrics.clone()));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/api/stats", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json.get("accepted").and_then(|v| v.as_u64()).unwrap(), 5);
        assert_eq!(json.get("rejected").and_then(|v| v.as_u64()).unwrap(), 2);

        let url = format!("http://127.0.0.1:{}/metrics", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let body = resp.text().await.unwrap();
        assert!(body.contains("oxide_accepted_total 5"));

        server.abort();
    }
}
