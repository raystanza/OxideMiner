// OxideMiner/crates/oxide-miner/src/http_api.rs

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
use std::path::PathBuf;
use std::sync::{atomic::Ordering, Arc};
use sysinfo::System;
use tokio::{fs, net::TcpListener};

// Embed the dashboard assets at compile time so the binary is self-contained.
const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");
const DASHBOARD_CSS: &str = include_str!("../assets/dashboard.css");
const DASHBOARD_JS: &str = include_str!("../assets/dashboard.js");

/// Metadata for an embedded dashboard image asset.
struct EmbeddedImage {
    name: &'static str,
    bytes: &'static [u8],
    content_type: &'static str,
}

const EMBEDDED_IMAGES: &[EmbeddedImage] = &[
    EmbeddedImage {
        name: "github_link-monero_theme.png",
        bytes: include_bytes!("../assets/img/github_link-monero_theme.png"),
        content_type: "image/png",
    },
    EmbeddedImage {
        name: "json_link.png",
        bytes: include_bytes!("../assets/img/json_link.png"),
        content_type: "image/png",
    },
    EmbeddedImage {
        name: "metrics_link.png",
        bytes: include_bytes!("../assets/img/metrics_link.png"),
        content_type: "image/png",
    },
    EmbeddedImage {
        name: "monero_logo.png",
        bytes: include_bytes!("../assets/img/monero_logo.png"),
        content_type: "image/png",
    },
];

fn find_embedded_image(path: &str) -> Option<&'static EmbeddedImage> {
    path.strip_prefix("/img/")
        .and_then(|name| EMBEDDED_IMAGES.iter().find(|img| img.name == name))
}

fn content_type_for(path: &str) -> &'static str {
    match path.rsplit('.').next().map(|ext| ext.to_ascii_lowercase()) {
        Some(ext) if ext == "html" => "text/html",
        Some(ext) if ext == "css" => "text/css",
        Some(ext) if ext == "js" => "application/javascript",
        Some(ext) if ext == "png" => "image/png",
        Some(ext) if ext == "jpg" || ext == "jpeg" => "image/jpeg",
        Some(ext) if ext == "gif" => "image/gif",
        Some(ext) if ext == "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

fn ok_response(body: Bytes, content_type: &'static str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    resp
}

fn not_found_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(404)
        .body(Full::new(Bytes::from_static(b"not found")))
        .unwrap()
}

fn system_uptime_seconds() -> u64 {
    System::uptime()
}

pub async fn run_http_api(port: u16, stats: Arc<Stats>, dashboard_dir: Option<PathBuf>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("HTTP bind failed: {e}");
            return;
        }
    };
    tracing::info!("HTTP API listening on http://{addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("HTTP accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let s = stats.clone();
        let dash_dir = dashboard_dir.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let s = s.clone();
                let dash_dir = dash_dir.clone();

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
                            writeln!(body, "version {}", env!("CARGO_PKG_VERSION")).ok();
                            writeln!(
                                body,
                                "commit_hash {}",
                                option_env!("OXIDE_GIT_COMMIT").unwrap_or("")
                            )
                            .ok();
                            writeln!(
                                body,
                                "commit_hash_short {}",
                                option_env!("OXIDE_GIT_COMMIT_SHORT").unwrap_or("")
                            )
                            .ok();
                            writeln!(
                                body,
                                "commit_timestamp {}",
                                option_env!("OXIDE_GIT_COMMIT_TIMESTAMP").unwrap_or("")
                            )
                            .ok();
                            writeln!(
                                body,
                                "build_timestamp {}",
                                option_env!("OXIDE_BUILD_TIMESTAMP").unwrap_or("")
                            )
                            .ok();
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
                            let mining_duration = s.mining_duration();
                            let system_uptime = system_uptime_seconds();
                            let build = json!({
                                "version": env!("CARGO_PKG_VERSION"),
                                "commit_hash": option_env!("OXIDE_GIT_COMMIT"),
                                "commit_hash_short": option_env!("OXIDE_GIT_COMMIT_SHORT"),
                                "commit_timestamp": option_env!("OXIDE_GIT_COMMIT_TIMESTAMP"),
                                "build_timestamp": option_env!("OXIDE_BUILD_TIMESTAMP"),
                            });

                            let resp_body = json!({
                                "hashrate": hashrate,
                                "hashes_total": hashes,
                                "pool": s.pool,
                                "connected": s.pool_connected.load(Ordering::Relaxed),
                                "tls": s.tls,
                                "version": env!("CARGO_PKG_VERSION"),
                                "build": build,
                                "shares": {
                                    "accepted": accepted,
                                    "rejected": rejected,
                                    "dev_accepted": dev_acc,
                                    "dev_rejected": dev_rej,
                                },
                                "timing": {
                                    "mining_time_seconds": mining_duration.as_secs(),
                                    "system_uptime_seconds": system_uptime,
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
                        (&Method::GET, path) => {
                            if let Some(dir) = &dash_dir {
                                let file_name = if path == "/" {
                                    "dashboard.html"
                                } else {
                                    &path[1..]
                                };
                                let file_path = dir.join(file_name);
                                match fs::read(&file_path).await {
                                    Ok(contents) => {
                                        let ct = content_type_for(file_name);
                                        Ok::<_, Infallible>(ok_response(Bytes::from(contents), ct))
                                    }
                                    Err(_) => Ok::<_, Infallible>(not_found_response()),
                                }
                            } else {
                                match path {
                                    "/" => Ok::<_, Infallible>(ok_response(
                                        Bytes::from_static(DASHBOARD_HTML.as_bytes()),
                                        "text/html",
                                    )),
                                    "/dashboard.css" => Ok::<_, Infallible>(ok_response(
                                        Bytes::from_static(DASHBOARD_CSS.as_bytes()),
                                        "text/css",
                                    )),
                                    "/dashboard.js" => Ok::<_, Infallible>(ok_response(
                                        Bytes::from_static(DASHBOARD_JS.as_bytes()),
                                        "application/javascript",
                                    )),
                                    _ if path.starts_with("/img/") => {
                                        match find_embedded_image(path) {
                                            Some(image) => Ok::<_, Infallible>(ok_response(
                                                Bytes::from_static(image.bytes),
                                                image.content_type,
                                            )),
                                            None => Ok::<_, Infallible>(not_found_response()),
                                        }
                                    }
                                    _ => Ok::<_, Infallible>(not_found_response()),
                                }
                            }
                        }
                        _ => Ok::<_, Infallible>(not_found_response()),
                    }
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::error!("HTTP connection error: {err}");
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

        let server = tokio::spawn(run_http_api(port, stats.clone(), None));
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
        assert!(body["timing"]["mining_time_seconds"].as_u64().is_some());
        assert!(body["timing"]["system_uptime_seconds"].as_u64().unwrap() > 0);

        let url = format!("http://127.0.0.1:{}/metrics", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        assert!(text.contains("oxide_shares_accepted_total 5"));
        assert!(text.contains("oxide_devfee_shares_accepted_total 1"));

        let url = format!("http://127.0.0.1:{}/", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        assert!(text.contains("OxideMiner Dashboard"));

        server.abort();
    }

    #[tokio::test]
    async fn dashboard_served_from_disk() {
        // Pick an available port by binding to port 0 first.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new("pool".into(), false));

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("dashboard.html"),
            "<html><body>custom</body></html>",
        )
        .unwrap();

        let server = tokio::spawn(run_http_api(
            port,
            stats.clone(),
            Some(dir.path().to_path_buf()),
        ));
        // Give the server a moment to start
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        assert!(text.contains("custom"));

        server.abort();
    }
}
