use crate::stats::Stats;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{atomic::Ordering, Arc};
use tokio::net::TcpListener;
use tracing::info;

const DASHBOARD_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html"));
const DASHBOARD_CSS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/style.css"));
const DASHBOARD_JS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/dashboard.js"));

pub async fn run_http_api(port: u16, stats: Arc<Stats>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HTTP bind failed: {e}");
            return;
        }
    };
    info!("HTTP API listening on http://{addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("HTTP accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let s = stats.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let s = s.clone();

                async move {
                    match (req.method(), req.uri().path()) {
                        (&Method::GET, "/metrics") => {
                            let mut body = String::new();
                            let accepted = s.accepted.load(Ordering::Relaxed);
                            let rejected = s.rejected.load(Ordering::Relaxed);
                            let dev_acc = s.dev_accepted.load(Ordering::Relaxed);
                            let dev_rej = s.dev_rejected.load(Ordering::Relaxed);
                            let hashes = s.hashes.load(Ordering::Relaxed);
                            let hashrate = s.hashrate();
                            let connected = if s.pool_connected.load(Ordering::Relaxed) {
                                1
                            } else {
                                0
                            };
                            let tls = if s.tls { 1 } else { 0 };
                            use std::fmt::Write;
                            writeln!(body, "oxide_hashes_total {}", hashes).ok();
                            writeln!(body, "oxide_hashrate {}", hashrate).ok();
                            writeln!(body, "oxide_shares_accepted_total {}", accepted).ok();
                            writeln!(body, "oxide_shares_rejected_total {}", rejected).ok();
                            writeln!(body, "oxide_devfee_shares_accepted_total {}", dev_acc).ok();
                            writeln!(body, "oxide_devfee_shares_rejected_total {}", dev_rej).ok();
                            writeln!(body, "oxide_pool_connected {}", connected).ok();
                            writeln!(body, "oxide_tls_enabled {}", tls).ok();
                            let mut resp = Response::new(Full::new(Bytes::from(body)));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("text/plain"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        (&Method::GET, "/api/stats") => {
                            let accepted = s.accepted.load(Ordering::Relaxed);
                            let rejected = s.rejected.load(Ordering::Relaxed);
                            let dev_acc = s.dev_accepted.load(Ordering::Relaxed);
                            let dev_rej = s.dev_rejected.load(Ordering::Relaxed);
                            let hashes = s.hashes.load(Ordering::Relaxed);
                            let hashrate = s.hashrate();
                            let resp_body = json!({
                                "hashrate": hashrate,
                                "hashes_total": hashes,
                                "pool": s.pool,
                                "connected": s.pool_connected.load(Ordering::Relaxed),
                                "tls": s.tls,
                                "shares": {
                                    "accepted": accepted,
                                    "rejected": rejected,
                                    "dev_accepted": dev_acc,
                                    "dev_rejected": dev_rej,
                                }
                            })
                            .to_string();
                            let mut resp = Response::new(Full::new(Bytes::from(resp_body)));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("application/json"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        (&Method::GET, "/") => {
                            let mut resp = Response::new(Full::new(Bytes::from_static(
                                DASHBOARD_HTML.as_bytes(),
                            )));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("text/html"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        (&Method::GET, "/style.css") => {
                            let mut resp = Response::new(Full::new(Bytes::from_static(
                                DASHBOARD_CSS.as_bytes(),
                            )));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("text/css"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        (&Method::GET, "/dashboard.js") => {
                            let mut resp = Response::new(Full::new(Bytes::from_static(
                                DASHBOARD_JS.as_bytes(),
                            )));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("application/javascript"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        _ => Ok::<_, Infallible>(
                            Response::builder()
                                .status(404)
                                .body(Full::new(Bytes::from("not found")))
                                .unwrap(),
                        ),
                    }
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("http connection error: {err}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::run_http_api;
    use crate::stats::Stats;
    use reqwest::Client;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn endpoints_report_stats() {
        // Pick an available port by binding to port 0 first.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new("pool".into(), false));
        stats.accepted.store(5, Ordering::Relaxed);
        stats.rejected.store(2, Ordering::Relaxed);
        stats.dev_accepted.store(1, Ordering::Relaxed);
        stats.hashes.store(100, Ordering::Relaxed);

        let server = tokio::spawn(run_http_api(port, stats.clone()));
        // Give the server a moment to start
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/api/stats", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["shares"]["accepted"], 5);
        assert_eq!(body["shares"]["rejected"], 2);
        assert_eq!(body["shares"]["dev_accepted"], 1);

        let url = format!("http://127.0.0.1:{}/metrics", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        assert!(text.contains("oxide_shares_accepted_total 5"));
        assert!(text.contains("oxide_devfee_shares_accepted_total 1"));

        server.abort();
    }
}
