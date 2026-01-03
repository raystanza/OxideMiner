// OxideMiner/crates/oxide-miner/src/http_api.rs

use crate::stats::Stats;
use crate::themes::{is_valid_id, ThemeCatalog};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::borrow::Cow;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{atomic::Ordering, Arc};
use sysinfo::System;
use tokio::{fs, net::TcpListener};
use url::Url;

// Embed the dashboard assets at compile time so the binary is self-contained.
const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");
const DASHBOARD_CSS: &str = include_str!("../assets/dashboard.css");
const DASHBOARD_JS: &str = include_str!("../assets/dashboard.js");
const THEMES_HTML: &str = include_str!("../assets/themes.html");
const THEMES_CSS: &str = include_str!("../assets/theme-manager.css");
const THEMES_JS: &str = include_str!("../assets/themes.js");
const THEME_MANAGER_JS: &str = include_str!("../assets/theme-manager.js");

// Embedded image assets for the dashboard. Keeping the miner binary self-contained
// avoids runtime dependencies on external files when the bundled dashboard is used.
const IMG_GITHUB_LINK_MONERO_THEME_PNG: &[u8] =
    include_bytes!("../assets/img/github_link-monero_theme.png");
const IMG_JSON_LINK_PNG: &[u8] = include_bytes!("../assets/img/json_link.png");
const IMG_METRICS_LINK_PNG: &[u8] = include_bytes!("../assets/img/metrics_link.png");
const IMG_MONERO_LOGO_PNG: &[u8] = include_bytes!("../assets/img/monero_logo.png");
const IMG_OXIDEMINER_LOGO_PNG: &[u8] = include_bytes!("../assets/img/oxideminer_logo_dash_48.png");
const IMG_FAVICON: &[u8] = include_bytes!("../assets/favicon.ico");

const THEME_COOKIE_NAME: &str = "oxideminer_theme";

#[derive(Clone, Copy)]
struct EmbeddedAsset {
    bytes: &'static [u8],
    content_type: &'static str,
}

fn embedded_asset(path: &str) -> Option<EmbeddedAsset> {
    match path {
        "/" | "/index.html" => Some(EmbeddedAsset {
            bytes: DASHBOARD_HTML.as_bytes(),
            content_type: "text/html",
        }),
        "/dashboard.css" => Some(EmbeddedAsset {
            bytes: DASHBOARD_CSS.as_bytes(),
            content_type: "text/css",
        }),
        "/dashboard.js" => Some(EmbeddedAsset {
            bytes: DASHBOARD_JS.as_bytes(),
            content_type: "application/javascript",
        }),
        "/theme-manager.js" => Some(EmbeddedAsset {
            bytes: THEME_MANAGER_JS.as_bytes(),
            content_type: "application/javascript",
        }),
        "/theme-manager.css" => Some(EmbeddedAsset {
            bytes: THEMES_CSS.as_bytes(),
            content_type: "text/css",
        }),
        "/themes.js" => Some(EmbeddedAsset {
            bytes: THEMES_JS.as_bytes(),
            content_type: "application/javascript",
        }),
        "/img/github_link-monero_theme.png" => Some(EmbeddedAsset {
            bytes: IMG_GITHUB_LINK_MONERO_THEME_PNG,
            content_type: "image/png",
        }),
        "/favicon.ico" => Some(EmbeddedAsset {
            bytes: IMG_FAVICON,
            content_type: "image/png",
        }),
        "/img/json_link.png" => Some(EmbeddedAsset {
            bytes: IMG_JSON_LINK_PNG,
            content_type: "image/png",
        }),
        "/img/metrics_link.png" => Some(EmbeddedAsset {
            bytes: IMG_METRICS_LINK_PNG,
            content_type: "image/png",
        }),
        "/img/monero_logo.png" => Some(EmbeddedAsset {
            bytes: IMG_MONERO_LOGO_PNG,
            content_type: "image/png",
        }),
        "/img/oxideminer_logo_dash_48.png" => Some(EmbeddedAsset {
            bytes: IMG_OXIDEMINER_LOGO_PNG,
            content_type: "image/png",
        }),
        _ => None,
    }
}

fn infer_content_type(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        _ => "application/octet-stream",
    }
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

fn api_socket_addr(bind_addr: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(bind_addr, port)
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn redact_url_userinfo(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        Err(_) => raw.to_string(),
    }
}

fn parse_theme_cookie(req: &Request<Incoming>) -> Option<String> {
    let cookies = req.headers().get_all(header::COOKIE);
    for val in cookies.iter() {
        let raw = match val.to_str() {
            Ok(v) => v,
            Err(_) => continue,
        };
        for part in raw.split(';') {
            let mut kv = part.splitn(2, '=');
            let name = kv.next()?.trim();
            if name != THEME_COOKIE_NAME {
                continue;
            }
            let value = kv.next().unwrap_or("").trim();
            if value.is_empty() || value.len() > 64 {
                return None;
            }
            if is_valid_id(value) {
                return Some(value.to_string());
            } else {
                return None;
            }
        }
    }
    None
}

fn is_dashboard_entry(path: &str) -> bool {
    matches!(path, "/" | "" | "/index.html" | "/dashboard.html")
}

async fn themed_dashboard_response(
    req: &Request<Incoming>,
    themes: &ThemeCatalog,
) -> Option<Response<Full<Bytes>>> {
    let theme_id = parse_theme_cookie(req)?;
    let html_path = themes.resolve_html(&theme_id)?;
    match fs::read(&html_path).await {
        Ok(contents) => {
            let mut resp = Response::new(Full::new(Bytes::from(contents)));
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            resp.headers_mut()
                .insert(header::VARY, header::HeaderValue::from_static("Cookie"));
            resp.headers_mut().insert(
                header::HeaderName::from_static("x-content-type-options"),
                header::HeaderValue::from_static("nosniff"),
            );
            Some(resp)
        }
        Err(err) => {
            tracing::warn!("Failed to read theme HTML {:?}: {err}", html_path);
            None
        }
    }
}

pub async fn run_http_api(
    bind_addr: IpAddr,
    port: u16,
    stats: Arc<Stats>,
    dashboard_dir: Option<PathBuf>,
    theme_dir: Option<PathBuf>,
) {
    let addr = api_socket_addr(bind_addr, port);
    let theme_catalog = Arc::new(ThemeCatalog::discover(theme_dir));
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(%addr, error = %e, "HTTP bind failed");
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
        let themes = theme_catalog.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let s = s.clone();
                let dash_dir = dash_dir.clone();
                let themes = themes.clone();

                async move {
                    match (req.method(), req.uri().path()) {
                        (&Method::GET, "/metrics") => {
                            let mut body = String::new();
                            let accepted = s.accepted.load(Ordering::Relaxed);
                            let rejected = s.rejected.load(Ordering::Relaxed);
                            let dev_acc = s.dev_accepted.load(Ordering::Relaxed);
                            let dev_rej = s.dev_rejected.load(Ordering::Relaxed);
                            let node_height = s.node_height.load(Ordering::Relaxed);
                            let template_height = s.template_height.load(Ordering::Relaxed);
                            let template_age = s.template_age_seconds().unwrap_or(0);
                            let blocks_submitted = s.blocks_submitted.load(Ordering::Relaxed);
                            let blocks_accepted = s.blocks_accepted.load(Ordering::Relaxed);
                            let blocks_rejected = s.blocks_rejected.load(Ordering::Relaxed);
                            let (last_status, last_success, last_ts) = s
                                .last_submit
                                .lock()
                                .ok()
                                .and_then(|guard| guard.clone())
                                .map(|record| {
                                    (
                                        record.outcome.as_str().to_string(),
                                        if record.outcome.is_success() { 1 } else { 0 },
                                        record.timestamp,
                                    )
                                })
                                .unwrap_or_else(|| ("none".to_string(), 0, 0));
                            let hashes = s.hashes.load(Ordering::Relaxed);
                            let hashrate_avg = s.hashrate_avg();
                            let instant_hashrate = s.instant_hashrate();
                            let connected = if s.pool_connected.load(Ordering::Relaxed) {
                                1
                            } else {
                                0
                            };
                            let tls = if s.tls { 1 } else { 0 };
                            use std::fmt::Write;
                            writeln!(body, "oxide_hashes_total {}", hashes).ok();
                            writeln!(body, "oxide_hashrate {}", hashrate_avg).ok();
                            writeln!(body, "oxide_hashrate_instant {}", instant_hashrate).ok();
                            writeln!(body, "oxide_shares_accepted_total {}", accepted).ok();
                            writeln!(body, "oxide_shares_rejected_total {}", rejected).ok();
                            writeln!(body, "oxide_devfee_shares_accepted_total {}", dev_acc).ok();
                            writeln!(body, "oxide_devfee_shares_rejected_total {}", dev_rej).ok();
                            writeln!(
                                body,
                                "oxide_backend_info{{mode=\"{}\",endpoint=\"{}\"}} 1",
                                s.mode.as_str(),
                                escape_label_value(&s.pool)
                            )
                            .ok();
                            writeln!(body, "oxide_node_height {}", node_height).ok();
                            writeln!(body, "oxide_template_height {}", template_height).ok();
                            writeln!(body, "oxide_template_age_seconds {}", template_age).ok();
                            writeln!(body, "oxide_blocks_submitted_total {}", blocks_submitted)
                                .ok();
                            writeln!(body, "oxide_blocks_accepted_total {}", blocks_accepted).ok();
                            writeln!(body, "oxide_blocks_rejected_total {}", blocks_rejected).ok();
                            writeln!(body, "oxide_last_submit_success {}", last_success).ok();
                            writeln!(body, "oxide_last_submit_timestamp_seconds {}", last_ts).ok();
                            writeln!(
                                body,
                                "oxide_last_submit_status{{status=\"{}\"}} 1",
                                escape_label_value(&last_status)
                            )
                            .ok();
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
                            if let Some(cfg) = &s.config {
                                let values = &cfg.values;
                                let applied = &cfg.applied;
                                let solo = values.solo.as_ref();
                                let info_labels = format!(
                                    "path=\"{}\",mode=\"{}\",pool=\"{}\",wallet=\"{}\",pass=\"{}\",threads=\"{}\",batch_size=\"{}\",affinity=\"{}\",huge_pages=\"{}\",tls=\"{}\",api_port=\"{}\",api_bind=\"{}\",proxy=\"{}\",dashboard_dir=\"{}\",no_yield=\"{}\",debug=\"{}\",solo_rpc_url=\"{}\",solo_wallet=\"{}\",solo_reserve_size=\"{}\",solo_zmq=\"{}\",solo_rpc_user_set=\"{}\",solo_rpc_pass_set=\"{}\"",
                                    escape_label_value(&cfg.path.display().to_string()),
                                    escape_label_value(values.mode.map(|m| m.as_str()).unwrap_or("")),
                                    escape_label_value(values.pool.as_deref().unwrap_or("")),
                                    escape_label_value(values.wallet.as_deref().unwrap_or("")),
                                    escape_label_value(values.pass.as_deref().unwrap_or("")),
                                    escape_label_value(&values.threads.map(|v| v.to_string()).unwrap_or_default()),
                                    escape_label_value(&values.batch_size.map(|v| v.to_string()).unwrap_or_default()),
                                    values.affinity.unwrap_or(false),
                                    values.huge_pages.unwrap_or(false),
                                    values.tls.unwrap_or(false),
                                    escape_label_value(&values.api_port.map(|v| v.to_string()).unwrap_or_default()),
                                    escape_label_value(
                                        &values
                                            .api_bind
                                            .map(|v| v.to_string())
                                            .unwrap_or_default()
                                    ),
                                    escape_label_value(values.proxy.as_deref().unwrap_or("")),
                                    escape_label_value(
                                        &values
                                            .dashboard_dir
                                            .as_ref()
                                            .map(|p| p.display().to_string())
                                            .unwrap_or_default(),
                                    ),
                                    values.no_yield.unwrap_or(false),
                                    values.debug.unwrap_or(false),
                                    escape_label_value(
                                        &redact_url_userinfo(
                                            solo.and_then(|s| s.rpc_url.as_deref()).unwrap_or("")
                                        )
                                    ),
                                    escape_label_value(
                                        solo.and_then(|s| s.wallet.as_deref()).unwrap_or("")
                                    ),
                                    escape_label_value(
                                        &solo.and_then(|s| s.reserve_size).map(|v| v.to_string()).unwrap_or_default()
                                    ),
                                    escape_label_value(
                                        solo.and_then(|s| s.zmq.as_deref()).unwrap_or("")
                                    ),
                                    solo.and_then(|s| s.rpc_user.as_ref()).is_some(),
                                    solo.and_then(|s| s.rpc_pass.as_ref()).is_some(),
                                );
                                writeln!(body, "oxide_config_info{{{}}} 1", info_labels).ok();

                                let applied_labels = format!(
                                    "mode=\"{}\",pool=\"{}\",wallet=\"{}\",pass=\"{}\",threads=\"{}\",tls=\"{}\",tls_ca_cert=\"{}\",tls_cert_sha256=\"{}\",api_port=\"{}\",api_bind=\"{}\",dashboard_dir=\"{}\",affinity=\"{}\",huge_pages=\"{}\",batch_size=\"{}\",no_yield=\"{}\",debug=\"{}\",proxy=\"{}\",solo_rpc_url=\"{}\",solo_rpc_user=\"{}\",solo_rpc_pass=\"{}\",solo_wallet=\"{}\",solo_reserve_size=\"{}\",solo_zmq=\"{}\"",
                                    applied.mode,
                                    applied.pool,
                                    applied.wallet,
                                    applied.pass,
                                    applied.threads,
                                    applied.tls,
                                    applied.tls_ca_cert,
                                    applied.tls_cert_sha256,
                                    applied.api_port,
                                    applied.api_bind,
                                    applied.dashboard_dir,
                                    applied.affinity,
                                    applied.huge_pages,
                                    applied.batch_size,
                                    applied.no_yield,
                                    applied.debug,
                                    applied.proxy,
                                    applied.solo_rpc_url,
                                    applied.solo_rpc_user,
                                    applied.solo_rpc_pass,
                                    applied.solo_wallet,
                                    applied.solo_reserve_size,
                                    applied.solo_zmq,
                                );
                                writeln!(body, "oxide_config_applied{{{}}} 1", applied_labels).ok();
                            }
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
                            let hashrate_avg = s.hashrate_avg();
                            let instant_hashrate = s.instant_hashrate();
                            let mining_duration = s.mining_duration();
                            let system_uptime = system_uptime_seconds();
                            let node_height = s.node_height.load(Ordering::Relaxed);
                            let template_height = s.template_height.load(Ordering::Relaxed);
                            let template_age = s.template_age_seconds();
                            let blocks_submitted = s.blocks_submitted.load(Ordering::Relaxed);
                            let blocks_accepted = s.blocks_accepted.load(Ordering::Relaxed);
                            let blocks_rejected = s.blocks_rejected.load(Ordering::Relaxed);
                            let last_submit = s
                                .last_submit
                                .lock()
                                .ok()
                                .and_then(|guard| guard.clone())
                                .map(|record| {
                                    json!({
                                        "outcome": record.outcome.as_str(),
                                        "detail": record.detail,
                                        "timestamp": record.timestamp,
                                    })
                                });
                            let config = s.config.as_ref().map(|cfg| {
                                json!({
                                    "path": cfg.path,
                                    "values": cfg.values,
                                    "applied": cfg.applied,
                                })
                            });
                            let build = json!({
                                "version": env!("CARGO_PKG_VERSION"),
                                "commit_hash": option_env!("OXIDE_GIT_COMMIT"),
                                "commit_hash_short": option_env!("OXIDE_GIT_COMMIT_SHORT"),
                                "commit_timestamp": option_env!("OXIDE_GIT_COMMIT_TIMESTAMP"),
                                "build_timestamp": option_env!("OXIDE_BUILD_TIMESTAMP"),
                            });

                            let resp_body = json!({
                                "mode": s.mode.as_str(),
                                "hashrate": hashrate_avg,
                                "hashrate_avg": hashrate_avg,
                                "instant_hashrate": instant_hashrate,
                                "hashes_total": hashes,
                                "pool": s.pool,
                                "connected": s.pool_connected.load(Ordering::Relaxed),
                                "tls": s.tls,
                                "version": env!("CARGO_PKG_VERSION"),
                                "build": build,
                                "config": config,
                                "shares": {
                                    "accepted": accepted,
                                    "rejected": rejected,
                                    "dev_accepted": dev_acc,
                                    "dev_rejected": dev_rej,
                                },
                                "solo": {
                                    "node_height": node_height,
                                    "template_height": template_height,
                                    "template_age_seconds": template_age,
                                    "blocks": {
                                        "submitted": blocks_submitted,
                                        "accepted": blocks_accepted,
                                        "rejected": blocks_rejected,
                                    },
                                    "last_submit": last_submit,
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
                        (&Method::GET, "/api/plugins/themes") => {
                            let payload = match serde_json::to_string(&themes.to_response()) {
                                Ok(v) => v,
                                Err(err) => {
                                    tracing::error!("Failed to serialize themes: {err}");
                                    return Ok::<_, Infallible>(not_found_response());
                                }
                            };
                            let mut resp = Response::new(Full::new(Bytes::from(payload)));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("application/json"),
                            );
                            resp.headers_mut().insert(
                                header::CACHE_CONTROL,
                                header::HeaderValue::from_static("no-store"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        (&Method::GET, "/plugins/themes") | (&Method::GET, "/plugins/themes/") => {
                            let mut resp = Response::new(Full::new(Bytes::from_static(
                                THEMES_HTML.as_bytes(),
                            )));
                            resp.headers_mut().insert(
                                header::CONTENT_TYPE,
                                header::HeaderValue::from_static("text/html"),
                            );
                            resp.headers_mut().insert(
                                header::CACHE_CONTROL,
                                header::HeaderValue::from_static("no-store"),
                            );
                            Ok::<_, Infallible>(resp)
                        }
                        (&Method::GET, path) if path.starts_with("/plugins/themes/") => {
                            let remainder = path.trim_start_matches("/plugins/themes/");
                            let mut parts = remainder.splitn(2, '/');
                            let theme_id = parts.next().unwrap_or("");
                            let rel_path = parts.next();

                            if theme_id.is_empty() || rel_path.is_none() {
                                return Ok::<_, Infallible>(not_found_response());
                            }

                            let rel = rel_path.unwrap();
                            if let Some(asset_path) = themes.resolve_asset(theme_id, rel) {
                                match fs::read(&asset_path).await {
                                    Ok(contents) => {
                                        let ct = infer_content_type(rel);
                                        let mut resp =
                                            Response::new(Full::new(Bytes::from(contents)));
                                        resp.headers_mut().insert(
                                            header::CONTENT_TYPE,
                                            header::HeaderValue::from_static(ct),
                                        );
                                        resp.headers_mut().insert(
                                            header::CACHE_CONTROL,
                                            header::HeaderValue::from_static(
                                                "public, max-age=3600, must-revalidate",
                                            ),
                                        );
                                        resp.headers_mut().insert(
                                            header::HeaderName::from_static(
                                                "x-content-type-options",
                                            ),
                                            header::HeaderValue::from_static("nosniff"),
                                        );
                                        return Ok::<_, Infallible>(resp);
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            "Failed to read theme asset {:?}: {err}",
                                            asset_path
                                        );
                                    }
                                }
                            }

                            Ok::<_, Infallible>(not_found_response())
                        }
                        (&Method::GET, path) => {
                            if let Some(dir) = &dash_dir {
                                let requested: Cow<'_, str> = if path == "/" || path.is_empty() {
                                    Cow::Borrowed("dashboard.html")
                                } else {
                                    Cow::Owned(path.trim_start_matches('/').to_string())
                                };

                                if requested.as_ref().contains("..") {
                                    return Ok::<_, Infallible>(not_found_response());
                                }

                                let file_path = dir.join(requested.as_ref());
                                match fs::read(&file_path).await {
                                    Ok(contents) => {
                                        let ct = infer_content_type(requested.as_ref());
                                        let mut resp =
                                            Response::new(Full::new(Bytes::from(contents)));
                                        resp.headers_mut().insert(
                                            header::CONTENT_TYPE,
                                            header::HeaderValue::from_static(ct),
                                        );
                                        Ok::<_, Infallible>(resp)
                                    }
                                    Err(_) => Ok::<_, Infallible>(not_found_response()),
                                }
                            } else {
                                if is_dashboard_entry(path) {
                                    if let Some(resp) =
                                        themed_dashboard_response(&req, &themes).await
                                    {
                                        return Ok::<_, Infallible>(resp);
                                    }
                                }

                                if let Some(asset) = embedded_asset(path) {
                                    let mut resp =
                                        Response::new(Full::new(Bytes::from_static(asset.bytes)));
                                    resp.headers_mut().insert(
                                        header::CONTENT_TYPE,
                                        header::HeaderValue::from_static(asset.content_type),
                                    );
                                    Ok::<_, Infallible>(resp)
                                } else {
                                    Ok::<_, Infallible>(not_found_response())
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
    use super::{api_socket_addr, run_http_api};
    use crate::args::MiningMode;
    use crate::stats::Stats;
    use hyper::header;
    use reqwest::Client;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn api_socket_addr_uses_bind_addr_and_port() {
        let addr = api_socket_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080)
        );

        let addr = api_socket_addr(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000);
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000));
    }

    #[tokio::test]
    async fn endpoints_report_stats() {
        // Pick an available port by binding to port 0 first.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new(MiningMode::Pool, "pool".into(), false, None));
        stats.accepted.store(5, Ordering::Relaxed);
        stats.rejected.store(2, Ordering::Relaxed);
        stats.dev_accepted.store(1, Ordering::Relaxed);
        stats.hashes.store(100, Ordering::Relaxed);

        let server = tokio::spawn(run_http_api(LOCALHOST, port, stats.clone(), None, None));
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

        let stats = Arc::new(Stats::new(MiningMode::Pool, "pool".into(), false, None));

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("img")).unwrap();
        std::fs::write(
            dir.path().join("dashboard.html"),
            "<html><body>custom</body></html>",
        )
        .unwrap();
        std::fs::write(dir.path().join("img").join("logo.png"), b"png").unwrap();

        let server = tokio::spawn(run_http_api(
            LOCALHOST,
            port,
            stats.clone(),
            Some(dir.path().to_path_buf()),
            None,
        ));
        // Give the server a moment to start
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        assert!(text.contains("custom"));

        let url = format!("http://127.0.0.1:{}/img/logo.png", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"png");

        server.abort();
    }

    #[tokio::test]
    async fn embedded_images_are_served() {
        use super::IMG_MONERO_LOGO_PNG;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new(MiningMode::Pool, "pool".into(), false, None));
        let server = tokio::spawn(run_http_api(LOCALHOST, port, stats, None, None));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/img/monero_logo.png", port);
        let resp = client.get(url).send().await.unwrap();
        assert!(resp.status().is_success());
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.len(), IMG_MONERO_LOGO_PNG.len());

        server.abort();
    }

    #[tokio::test]
    async fn theme_html_overrides_dashboard_when_cookie_set() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new(MiningMode::Pool, "pool".into(), false, None));

        let dir = tempfile::tempdir().unwrap();
        let theme_dir = dir.path().join("blue");
        std::fs::create_dir_all(&theme_dir).unwrap();
        std::fs::write(theme_dir.join("theme.css"), "body{background:blue;}").unwrap();
        std::fs::write(theme_dir.join("theme.html"), "<div>override-html</div>").unwrap();
        std::fs::write(
            theme_dir.join("theme.json"),
            r#"{
            "id": "blue",
            "name": "Blue",
            "version": "1.0.0",
            "entry_css": "theme.css"
        }"#,
        )
        .unwrap();

        let server = tokio::spawn(run_http_api(
            LOCALHOST,
            port,
            stats,
            None,
            Some(dir.path().to_path_buf()),
        ));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let base = format!("http://127.0.0.1:{port}/");
        let themed = client
            .get(&base)
            .header(header::COOKIE, "oxideminer_theme=blue")
            .send()
            .await
            .unwrap();
        assert!(themed.status().is_success());
        let body = themed.text().await.unwrap();
        assert!(body.contains("override-html"));

        let default_resp = client.get(&base).send().await.unwrap();
        assert!(default_resp.status().is_success());
        let default_body = default_resp.text().await.unwrap();
        assert!(default_body.contains("OxideMiner Dashboard"));

        server.abort();
    }

    #[tokio::test]
    async fn dashboard_dir_not_overridden_by_theme_cookie() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new(MiningMode::Pool, "pool".into(), false, None));

        let dash_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dash_dir.path().join("dashboard.html"),
            "<html><body>custom-dashboard</body></html>",
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let theme_dir = dir.path().join("blue");
        std::fs::create_dir_all(&theme_dir).unwrap();
        std::fs::write(theme_dir.join("theme.css"), "body{background:blue;}").unwrap();
        std::fs::write(theme_dir.join("theme.html"), "<div>override-html</div>").unwrap();
        std::fs::write(
            theme_dir.join("theme.json"),
            r#"{
            "id": "blue",
            "name": "Blue",
            "version": "1.0.0",
            "entry_css": "theme.css"
        }"#,
        )
        .unwrap();

        let server = tokio::spawn(run_http_api(
            LOCALHOST,
            port,
            stats,
            Some(dash_dir.path().to_path_buf()),
            Some(dir.path().to_path_buf()),
        ));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let url = format!("http://127.0.0.1:{}/", port);
        let themed = client
            .get(&url)
            .header(header::COOKIE, "oxideminer_theme=blue")
            .send()
            .await
            .unwrap();
        assert!(themed.status().is_success());
        let body = themed.text().await.unwrap();
        assert!(body.contains("custom-dashboard"));
        assert!(!body.contains("override-html"));

        server.abort();
    }

    #[tokio::test]
    async fn themes_api_and_assets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let stats = Arc::new(Stats::new(MiningMode::Pool, "pool".into(), false, None));

        let dir = tempfile::tempdir().unwrap();
        let theme_dir = dir.path().join("blue");
        std::fs::create_dir_all(&theme_dir).unwrap();
        std::fs::write(theme_dir.join("theme.css"), "body{background:blue;}").unwrap();
        std::fs::write(theme_dir.join("theme.js"), "console.log('hi')").unwrap();
        std::fs::write(theme_dir.join("theme.html"), "<div>hello</div>").unwrap();
        std::fs::write(theme_dir.join("preview.png"), [0u8; 4]).unwrap();
        std::fs::write(
            theme_dir.join("theme.json"),
            r#"{
            "id": "blue",
            "name": "Blue",
            "version": "1.0.0",
            "entry_css": "theme.css",
            "entry_js": "theme.js",
            "entry_html": "theme.html"
        }"#,
        )
        .unwrap();

        let server = tokio::spawn(run_http_api(
            LOCALHOST,
            port,
            stats,
            None,
            Some(dir.path().to_path_buf()),
        ));
        sleep(Duration::from_millis(50)).await;

        let client = Client::new();
        let base = format!("http://127.0.0.1:{port}");
        let resp = client
            .get(format!("{}/api/plugins/themes", base))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let text = resp.text().await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(body.as_array().unwrap().iter().any(|t| t["id"] == "blue"));

        let page = client
            .get(format!("{}/plugins/themes", base))
            .send()
            .await
            .unwrap();
        assert!(page.status().is_success());

        let css = client
            .get(format!("{}/plugins/themes/blue/theme.css", base))
            .send()
            .await
            .unwrap();
        assert!(css.status().is_success());
        assert_eq!(
            css.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/css")
        );

        let html = client
            .get(format!("{}/plugins/themes/blue/theme.html", base))
            .send()
            .await
            .unwrap();
        assert!(html.status().is_success());

        server.abort();
    }
}
