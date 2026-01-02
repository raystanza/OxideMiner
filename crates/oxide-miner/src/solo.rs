// OxideMiner/crates/oxide-miner/src/solo.rs

use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use oxide_core::stratum::PoolJob;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error as StdError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum SoloRpcError {
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("unsupported RPC URL scheme '{0}' (expected http)")]
    UnsupportedScheme(String),
    #[error("RPC unauthorized (check --node-rpc-user/--node-rpc-pass)")]
    Unauthorized,
    #[error("RPC connection refused")]
    ConnectionRefused,
    #[error("RPC HTTP status {status}: {body}")]
    HttpStatus { status: StatusCode, body: String },
    #[error("RPC transport error: {0}")]
    Transport(#[from] hyper_util::client::legacy::Error),
    #[error("RPC body error: {0}")]
    Body(#[from] hyper::Error),
    #[error("RPC response parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("RPC reported status '{0}'")]
    RpcStatus(String),
    #[error("RPC response missing result: {0}")]
    MissingResult(String),
    #[error("invalid RPC endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid RPC request: {0}")]
    InvalidRequest(String),
    #[error("invalid difficulty (must be > 0)")]
    InvalidDifficulty,
    #[error("invalid hex in {field}: {source}")]
    InvalidHex {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error("invalid template: {0}")]
    InvalidTemplate(String),
    #[error("block template too short for nonce (len={0})")]
    BlobTooShort(usize),
}

#[derive(Clone, Debug)]
pub struct RpcEndpoint {
    url: Url,
    auth: Option<BasicAuth>,
    redacted: String,
}

impl RpcEndpoint {
    pub fn new(url: &str, user: Option<&str>, pass: Option<&str>) -> Result<Self, SoloRpcError> {
        let mut parsed = Url::parse(url)?;
        if parsed.scheme() != "http" {
            return Err(SoloRpcError::UnsupportedScheme(parsed.scheme().to_string()));
        }
        if parsed.fragment().is_some() {
            return Err(SoloRpcError::InvalidEndpoint(
                "RPC URL must not include a fragment".to_string(),
            ));
        }
        if parsed.path().is_empty() || parsed.path() == "/" {
            parsed.set_path("/json_rpc");
        }

        let auth = if let Some(user) = user {
            Some(BasicAuth::new(user, pass.unwrap_or_default()))
        } else if !parsed.username().is_empty() {
            Some(BasicAuth::new(
                parsed.username(),
                parsed.password().unwrap_or_default(),
            ))
        } else {
            None
        };

        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);

        Ok(Self {
            redacted: parsed.to_string(),
            url: parsed,
            auth,
        })
    }

    pub fn redacted(&self) -> &str {
        &self.redacted
    }
}

#[derive(Clone, Debug)]
struct BasicAuth {
    user: String,
    pass: String,
}

impl BasicAuth {
    fn new(user: &str, pass: &str) -> Self {
        Self {
            user: user.to_string(),
            pass: pass.to_string(),
        }
    }

    fn header_value(&self) -> Result<hyper::header::HeaderValue, SoloRpcError> {
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.user, self.pass));
        let header = format!("Basic {token}");
        hyper::header::HeaderValue::from_str(&header)
            .map_err(|err| SoloRpcError::InvalidRequest(format!("invalid auth header: {err}")))
    }
}

pub struct SoloRpcClient {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    endpoint: RpcEndpoint,
    next_id: AtomicU64,
}

impl SoloRpcClient {
    pub fn new(endpoint: RpcEndpoint) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            client,
            endpoint,
            next_id: AtomicU64::new(1),
        }
    }

    pub async fn get_info(&self) -> Result<NodeInfo, SoloRpcError> {
        self.call("get_info", json!({})).await
    }

    pub async fn get_block_template(
        &self,
        wallet: &str,
        reserve_size: u32,
    ) -> Result<RpcBlockTemplate, SoloRpcError> {
        let params = json!({
            "wallet_address": wallet,
            "reserve_size": reserve_size,
        });
        let template: RpcBlockTemplate = self.call("get_block_template", params).await?;
        if let Some(status) = template.status.as_deref() {
            if status != "OK" {
                return Err(SoloRpcError::RpcStatus(status.to_string()));
            }
        }
        Ok(template)
    }

    pub async fn submit_block(&self, block_blob_hex: &str) -> Result<SubmitResult, SoloRpcError> {
        let params = json!([block_blob_hex]);
        self.call("submit_block", params).await
    }

    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, SoloRpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();

        let mut builder = Request::builder()
            .method("POST")
            .uri(self.endpoint.url.as_str())
            .header(hyper::header::CONTENT_TYPE, "application/json");

        if let Some(auth) = &self.endpoint.auth {
            builder = builder.header(hyper::header::AUTHORIZATION, auth.header_value()?);
        }

        let request = builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|err| SoloRpcError::InvalidRequest(err.to_string()))?;

        let response = self
            .client
            .request(request)
            .await
            .map_err(map_hyper_error)?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(SoloRpcError::Unauthorized);
        }
        let status = response.status();
        if !status.is_success() {
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(SoloRpcError::Body)?
                .to_bytes();
            let text = String::from_utf8_lossy(body.as_ref()).to_string();
            return Err(SoloRpcError::HttpStatus { status, body: text });
        }

        let body = response
            .into_body()
            .collect()
            .await
            .map_err(SoloRpcError::Body)?
            .to_bytes();
        let envelope: RpcEnvelope<R> = serde_json::from_slice(body.as_ref())?;

        if let Some(err) = envelope.error {
            return Err(SoloRpcError::Rpc {
                code: err.code,
                message: err.message,
            });
        }

        envelope
            .result
            .ok_or_else(|| SoloRpcError::MissingResult(method.to_string()))
    }
}

fn map_hyper_error(err: hyper_util::client::legacy::Error) -> SoloRpcError {
    if err.is_connect() {
        if let Some(io) = find_io_error(&err) {
            if io.kind() == std::io::ErrorKind::ConnectionRefused {
                return SoloRpcError::ConnectionRefused;
            }
        }
    }
    SoloRpcError::Transport(err)
}

fn find_io_error(err: &dyn StdError) -> Option<&std::io::Error> {
    let mut source = err.source();
    while let Some(src) = source {
        if let Some(io) = src.downcast_ref::<std::io::Error>() {
            return Some(io);
        }
        source = src.source();
    }
    None
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcErrorObject>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorObject {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct RpcBlockTemplate {
    pub blocktemplate_blob: String,
    #[serde(default)]
    pub blockhashing_blob: Option<String>,
    pub difficulty: Difficulty,
    pub height: u64,
    #[serde(default)]
    pub seed_hash: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub height: u64,
    #[serde(default)]
    pub target_height: Option<u64>,
    #[serde(default)]
    pub synchronized: Option<bool>,
    #[serde(default)]
    pub busy_syncing: Option<bool>,
}

impl NodeInfo {
    pub fn is_synced(&self) -> bool {
        if let Some(true) = self.busy_syncing {
            return false;
        }
        if let Some(false) = self.synchronized {
            return false;
        }
        if let Some(target) = self.target_height {
            if target > self.height {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Deserialize)]
pub struct SubmitResult {
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
}

impl SubmitResult {
    pub fn accepted(&self) -> bool {
        self.status.eq_ignore_ascii_case("OK")
    }

    pub fn message(&self) -> String {
        if let Some(reason) = self.reason.as_ref() {
            format!("{} ({reason})", self.status)
        } else {
            self.status.clone()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Difficulty(pub u64);

impl<'de> Deserialize<'de> for Difficulty {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DiffVisitor;

        impl<'de> serde::de::Visitor<'de> for DiffVisitor {
            type Value = Difficulty;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("u64 or string difficulty")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Difficulty(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v < 0 {
                    return Err(E::custom("difficulty must be positive"));
                }
                Ok(Difficulty(v as u64))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let parsed: u64 = s
                    .parse()
                    .map_err(|_| E::custom("difficulty string is not a valid u64"))?;
                Ok(Difficulty(parsed))
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&s)
            }
        }

        deserializer.deserialize_any(DiffVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct SoloTemplate {
    pub job: PoolJob,
    pub blocktemplate_blob: Arc<Vec<u8>>,
    pub height: u64,
}

impl SoloTemplate {
    pub fn from_rpc(template: RpcBlockTemplate, job_id: String) -> Result<Self, SoloRpcError> {
        let seed_hash = template
            .seed_hash
            .clone()
            .ok_or_else(|| SoloRpcError::InvalidTemplate("missing seed_hash".to_string()))?;
        let blob = template
            .blockhashing_blob
            .clone()
            .unwrap_or_else(|| template.blocktemplate_blob.clone());
        let target = target_from_difficulty(template.difficulty.0)?;
        let mut job = PoolJob {
            job_id,
            blob,
            target,
            seed_hash: Some(seed_hash),
            height: Some(template.height),
            algo: Some("rx/0".to_string()),
            target_u32: None,
            seed_hash_bytes: [0u8; 32],
            blob_bytes: Arc::new(Vec::new()),
        };
        job.prepare()
            .map_err(|err| SoloRpcError::InvalidTemplate(err.to_string()))?;

        let blocktemplate_blob = hex::decode(&template.blocktemplate_blob).map_err(|source| {
            SoloRpcError::InvalidHex {
                field: "blocktemplate_blob",
                source,
            }
        })?;

        Ok(Self {
            job,
            blocktemplate_blob: Arc::new(blocktemplate_blob),
            height: template.height,
        })
    }

    pub fn block_blob_with_nonce(&self, nonce: u32) -> Result<Vec<u8>, SoloRpcError> {
        let mut blob = (*self.blocktemplate_blob).clone();
        if blob.len() < 39 + 4 {
            return Err(SoloRpcError::BlobTooShort(blob.len()));
        }
        blob[39..43].copy_from_slice(&nonce.to_le_bytes());
        Ok(blob)
    }
}

pub fn target_from_difficulty(difficulty: u64) -> Result<String, SoloRpcError> {
    if difficulty == 0 {
        return Err(SoloRpcError::InvalidDifficulty);
    }
    let mut out = [0u8; 32];
    let mut remainder: u128 = 0;
    for (i, byte) in [0xFFu8; 32].iter().enumerate() {
        let value = (remainder << 8) + (*byte as u128);
        let quotient = value / difficulty as u128;
        remainder = value % difficulty as u128;
        out[i] = quotient as u8;
    }
    Ok(hex::encode(out))
}

pub fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    #[test]
    fn target_from_difficulty_handles_one() {
        let target = target_from_difficulty(1).unwrap();
        assert_eq!(
            target,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn target_from_difficulty_handles_two() {
        let target = target_from_difficulty(2).unwrap();
        assert!(target.starts_with("7f"));
        assert_eq!(target.len(), 64);
    }

    #[tokio::test]
    async fn rpc_client_parses_block_template() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let svc = service_fn(|req: Request<Incoming>| async move {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(payload["method"], "get_block_template");
                let result = json!({
                    "blocktemplate_blob": "00",
                    "blockhashing_blob": "00",
                    "difficulty": 1,
                    "height": 123,
                    "reserved_offset": 0,
                    "seed_hash": "00".repeat(32),
                    "status": "OK"
                });
                let response = json!({ "jsonrpc": "2.0", "result": result });
                let mut resp = Response::new(Full::new(Bytes::from(response.to_string())));
                *resp.status_mut() = StatusCode::OK;
                Ok::<_, Infallible>(resp)
            });
            http1::Builder::new()
                .serve_connection(io, svc)
                .await
                .unwrap();
        });

        let endpoint = RpcEndpoint::new(&format!("http://{addr}"), None, None).unwrap();
        let client = SoloRpcClient::new(endpoint);
        let template = client
            .get_block_template("wallet", 60)
            .await
            .expect("template ok");
        assert_eq!(template.height, 123);
        drop(client);
        server.await.unwrap();
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn solo_rpc_integration_smoke() {
        use std::env;

        let rpc_url = match env::var("OXIDE_MONEROD_RPC") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("OXIDE_MONEROD_RPC not set; skipping solo RPC integration test");
                return;
            }
        };
        let wallet = match env::var("OXIDE_SOLO_WALLET") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("OXIDE_SOLO_WALLET not set; skipping solo RPC integration test");
                return;
            }
        };
        let rpc_user = env::var("OXIDE_MONEROD_RPC_USER").ok();
        let rpc_pass = env::var("OXIDE_MONEROD_RPC_PASS").ok();

        let endpoint =
            RpcEndpoint::new(&rpc_url, rpc_user.as_deref(), rpc_pass.as_deref()).unwrap();
        let client = SoloRpcClient::new(endpoint);

        let info = client.get_info().await.expect("get_info ok");
        assert!(info.height > 0);

        let template = client
            .get_block_template(&wallet, 60)
            .await
            .expect("get_block_template ok");
        assert!(template.height > 0);
    }
}
