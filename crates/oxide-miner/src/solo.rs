// OxideMiner/crates/oxide-miner/src/solo.rs

pub mod zmq;

use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use oxide_core::stratum::PoolJob;
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    #[error("RPC auth error: {0}")]
    Auth(String),
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

#[derive(Clone)]
pub struct RpcEndpoint {
    url: Url,
    credentials: Option<RpcCredentials>,
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

        let credentials = if let Some(user) = user {
            Some(RpcCredentials::new(user, pass.unwrap_or_default()))
        } else if !parsed.username().is_empty() {
            Some(RpcCredentials::new(
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
            credentials,
        })
    }

    pub fn redacted(&self) -> &str {
        &self.redacted
    }

    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    fn credentials(&self) -> Option<&RpcCredentials> {
        self.credentials.as_ref()
    }

    fn digest_uri(&self) -> String {
        let path = self.url.path();
        if let Some(query) = self.url.query() {
            format!("{path}?{query}")
        } else {
            path.to_string()
        }
    }
}

impl fmt::Debug for RpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcEndpoint")
            .field("url", &self.redacted)
            .field("has_credentials", &self.credentials.is_some())
            .finish()
    }
}

#[derive(Clone)]
struct RpcCredentials {
    user: String,
    pass: String,
}

impl RpcCredentials {
    fn new(user: &str, pass: &str) -> Self {
        Self {
            user: user.to_string(),
            pass: pass.to_string(),
        }
    }
}

fn basic_auth_header(creds: &RpcCredentials) -> Result<HeaderValue, SoloRpcError> {
    let token =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", creds.user, creds.pass));
    let header = format!("Basic {token}");
    HeaderValue::from_str(&header)
        .map_err(|err| SoloRpcError::InvalidRequest(format!("invalid auth header: {err}")))
}

#[derive(Clone, Debug)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    qop: Option<String>,
    algorithm: Option<String>,
    stale: bool,
}

#[derive(Clone, Debug)]
struct DigestState {
    challenge: DigestChallenge,
    nc: u32,
}

impl DigestState {
    fn new(challenge: DigestChallenge) -> Self {
        Self { challenge, nc: 0 }
    }

    fn next_nc(&mut self) -> u32 {
        self.nc = self.nc.saturating_add(1);
        self.nc
    }
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input))
}

fn parse_digest_challenge(header: &str) -> Option<DigestChallenge> {
    let lower = header.to_ascii_lowercase();
    let start = lower.find("digest")?;
    let params = header[start + "digest".len()..].trim();
    if params.is_empty() {
        return None;
    }

    let pairs = parse_auth_params(params);
    let realm = pairs.get("realm")?.to_string();
    let nonce = pairs.get("nonce")?.to_string();
    let opaque = pairs.get("opaque").cloned();
    let qop = pairs.get("qop").cloned();
    let algorithm = pairs.get("algorithm").cloned();
    let stale = pairs
        .get("stale")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    Some(DigestChallenge {
        realm,
        nonce,
        opaque,
        qop,
        algorithm,
        stale,
    })
}

fn parse_auth_params(input: &str) -> HashMap<String, String> {
    let mut pairs = HashMap::new();
    for part in split_auth_params(input) {
        let mut iter = part.splitn(2, '=');
        let key = iter.next().unwrap_or("").trim();
        let value = iter.next().unwrap_or("").trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        let cleaned = unquote(value);
        pairs.insert(key.to_ascii_lowercase(), cleaned);
    }
    pairs
}

fn split_auth_params(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let mut escape = false;

    for ch in input.chars() {
        if escape {
            buf.push(ch);
            escape = false;
            continue;
        }
        if in_quotes && ch == '\\' {
            escape = true;
            buf.push(ch);
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            buf.push(ch);
            continue;
        }
        if ch == ',' && !in_quotes {
            if !buf.trim().is_empty() {
                parts.push(buf.trim().to_string());
            }
            buf.clear();
            continue;
        }
        buf.push(ch);
    }
    if !buf.trim().is_empty() {
        parts.push(buf.trim().to_string());
    }
    parts
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escape = false;
        for ch in inner.chars() {
            if escape {
                out.push(ch);
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        trimmed.to_string()
    }
}

fn digest_challenge_from_headers(headers: &hyper::HeaderMap) -> Option<DigestChallenge> {
    for value in headers.get_all(WWW_AUTHENTICATE).iter() {
        if let Ok(text) = value.to_str() {
            if let Some(challenge) = parse_digest_challenge(text) {
                return Some(challenge);
            }
        }
    }
    None
}

fn has_basic_challenge(headers: &hyper::HeaderMap) -> bool {
    for value in headers.get_all(WWW_AUTHENTICATE).iter() {
        if let Ok(text) = value.to_str() {
            if text.trim_start().to_ascii_lowercase().starts_with("basic") {
                return true;
            }
        }
    }
    false
}

fn select_qop(qop: Option<&str>) -> Option<&'static str> {
    let qop = qop?;
    for part in qop.split(',') {
        if part.trim().eq_ignore_ascii_case("auth") {
            return Some("auth");
        }
    }
    None
}

fn generate_cnonce() -> Result<String, SoloRpcError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|err| SoloRpcError::Auth(format!("failed to generate cnonce: {err}")))?;
    Ok(hex::encode(bytes))
}

fn build_digest_authorization(
    method: &str,
    uri: &str,
    creds: &RpcCredentials,
    challenge: &DigestChallenge,
    nc: u32,
    cnonce: &str,
) -> Result<HeaderValue, SoloRpcError> {
    let algorithm = challenge
        .algorithm
        .as_deref()
        .unwrap_or("MD5")
        .to_ascii_lowercase();
    let qop = select_qop(challenge.qop.as_deref());

    let ha1 = md5_hex(&format!(
        "{}:{}:{}",
        creds.user, challenge.realm, creds.pass
    ));
    let ha1 = if algorithm == "md5-sess" {
        md5_hex(&format!("{ha1}:{}:{cnonce}", challenge.nonce))
    } else if algorithm == "md5" {
        ha1
    } else {
        return Err(SoloRpcError::Auth(format!(
            "unsupported digest algorithm '{algorithm}'"
        )));
    };

    let ha2 = md5_hex(&format!("{method}:{uri}"));

    let response = if let Some(qop) = qop {
        let nc_value = format!("{:08x}", nc);
        md5_hex(&format!(
            "{ha1}:{}:{nc_value}:{cnonce}:{qop}:{ha2}",
            challenge.nonce
        ))
    } else {
        md5_hex(&format!("{ha1}:{}:{ha2}", challenge.nonce))
    };

    let mut header = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        creds.user, challenge.realm, challenge.nonce, uri, response
    );

    if let Some(ref opaque) = challenge.opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }

    if let Some(qop) = qop {
        let nc_value = format!("{:08x}", nc);
        header.push_str(&format!(", qop={qop}, nc={nc_value}, cnonce=\"{cnonce}\""));
    }

    if challenge.algorithm.is_some() {
        header.push_str(&format!(
            ", algorithm={}",
            challenge.algorithm.as_deref().unwrap()
        ));
    }

    HeaderValue::from_str(&header)
        .map_err(|err| SoloRpcError::Auth(format!("invalid digest header: {err}")))
}

pub struct SoloRpcClient {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    endpoint: RpcEndpoint,
    next_id: AtomicU64,
    digest: Mutex<Option<DigestState>>,
}

impl SoloRpcClient {
    pub fn new(endpoint: RpcEndpoint) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            client,
            endpoint,
            next_id: AtomicU64::new(1),
            digest: Mutex::new(None),
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

        let response = if self.endpoint.credentials().is_some() {
            self.send_with_auth("POST", &body).await?
        } else {
            self.send_request("POST", &body, None).await?
        };

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

    async fn send_request(
        &self,
        method: &str,
        body: &str,
        auth_header: Option<HeaderValue>,
    ) -> Result<hyper::Response<Incoming>, SoloRpcError> {
        let mut builder = Request::builder()
            .method(method)
            .uri(self.endpoint.url.as_str())
            .header(CONTENT_TYPE, "application/json");

        if let Some(header) = auth_header {
            builder = builder.header(AUTHORIZATION, header);
        }

        let request = builder
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|err| SoloRpcError::InvalidRequest(err.to_string()))?;

        self.client.request(request).await.map_err(map_hyper_error)
    }

    async fn send_with_auth(
        &self,
        method: &str,
        body: &str,
    ) -> Result<hyper::Response<Incoming>, SoloRpcError> {
        let creds = self.endpoint.credentials().ok_or_else(|| {
            SoloRpcError::Auth("credentials missing for authenticated request".to_string())
        })?;
        let digest_uri = self.endpoint.digest_uri();

        if let Some(header) = self.digest_header_from_cache(method, &digest_uri, creds)? {
            let response = self.send_request(method, body, Some(header)).await?;
            if response.status() != StatusCode::UNAUTHORIZED {
                return Ok(response);
            }

            let headers = response.headers().clone();
            drain_body(response).await?;
            if let Some(challenge) = digest_challenge_from_headers(&headers) {
                if challenge.stale || !self.digest_matches(&challenge)? {
                    self.set_digest_challenge(challenge)?;
                    return self
                        .send_digest_retry(method, body, &digest_uri, creds)
                        .await;
                }
            }

            if has_basic_challenge(&headers) {
                return self
                    .send_request(method, body, Some(basic_auth_header(creds)?))
                    .await;
            }

            return Err(SoloRpcError::Unauthorized);
        }

        let response = self.send_request(method, body, None).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let headers = response.headers().clone();
        drain_body(response).await?;
        if let Some(challenge) = digest_challenge_from_headers(&headers) {
            self.set_digest_challenge(challenge)?;
            return self
                .send_digest_retry(method, body, &digest_uri, creds)
                .await;
        }

        if has_basic_challenge(&headers) {
            return self
                .send_request(method, body, Some(basic_auth_header(creds)?))
                .await;
        }

        Err(SoloRpcError::Unauthorized)
    }

    async fn send_digest_retry(
        &self,
        method: &str,
        body: &str,
        digest_uri: &str,
        creds: &RpcCredentials,
    ) -> Result<hyper::Response<Incoming>, SoloRpcError> {
        let Some(header) = self.digest_header_from_cache(method, digest_uri, creds)? else {
            return Err(SoloRpcError::Auth(
                "digest challenge missing after retry".to_string(),
            ));
        };
        let response = self.send_request(method, body, Some(header)).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let headers = response.headers().clone();
        drain_body(response).await?;
        if let Some(challenge) = digest_challenge_from_headers(&headers) {
            if challenge.stale || !self.digest_matches(&challenge)? {
                self.set_digest_challenge(challenge)?;
                if let Some(header) = self.digest_header_from_cache(method, digest_uri, creds)? {
                    return self.send_request(method, body, Some(header)).await;
                }
            }
        }

        Err(SoloRpcError::Unauthorized)
    }

    fn digest_header_from_cache(
        &self,
        method: &str,
        uri: &str,
        creds: &RpcCredentials,
    ) -> Result<Option<HeaderValue>, SoloRpcError> {
        let mut guard = self
            .digest
            .lock()
            .map_err(|_| SoloRpcError::Auth("digest cache lock poisoned".to_string()))?;
        let Some(state) = guard.as_mut() else {
            return Ok(None);
        };
        let nc = state.next_nc();
        let cnonce = generate_cnonce()?;
        let header = build_digest_authorization(method, uri, creds, &state.challenge, nc, &cnonce)?;
        Ok(Some(header))
    }

    fn digest_matches(&self, challenge: &DigestChallenge) -> Result<bool, SoloRpcError> {
        let guard = self
            .digest
            .lock()
            .map_err(|_| SoloRpcError::Auth("digest cache lock poisoned".to_string()))?;
        match guard.as_ref() {
            Some(state) => Ok(state.challenge.nonce == challenge.nonce),
            None => Ok(false),
        }
    }

    fn set_digest_challenge(&self, challenge: DigestChallenge) -> Result<(), SoloRpcError> {
        let mut guard = self
            .digest
            .lock()
            .map_err(|_| SoloRpcError::Auth("digest cache lock poisoned".to_string()))?;
        *guard = Some(DigestState::new(challenge));
        Ok(())
    }
}

async fn drain_body(response: hyper::Response<Incoming>) -> Result<(), SoloRpcError> {
    let _ = response
        .into_body()
        .collect()
        .await
        .map_err(SoloRpcError::Body)?;
    Ok(())
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

    #[test]
    fn parse_digest_challenge_extracts_fields() {
        let header = "Digest realm=\"testrealm@host.com\", nonce=\"abcd\", qop=\"auth\", opaque=\"xyz\", algorithm=MD5, stale=true";
        let challenge = parse_digest_challenge(header).expect("challenge parsed");
        assert_eq!(challenge.realm, "testrealm@host.com");
        assert_eq!(challenge.nonce, "abcd");
        assert_eq!(challenge.opaque.as_deref(), Some("xyz"));
        assert_eq!(challenge.qop.as_deref(), Some("auth"));
        assert_eq!(challenge.algorithm.as_deref(), Some("MD5"));
        assert!(challenge.stale);
    }

    #[test]
    fn digest_response_matches_rfc_vector() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: None,
            stale: false,
        };
        let creds = RpcCredentials::new("Mufasa", "Circle Of Life");
        let header =
            build_digest_authorization("GET", "/dir/index.html", &creds, &challenge, 1, "0a4f113b")
                .expect("digest header");
        let header_str = header.to_str().unwrap();
        assert!(header_str.contains("response=\"6629fae49393a05397450978507c4ef1\""));
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

    #[tokio::test]
    async fn rpc_client_handles_digest_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let challenge = DigestChallenge {
            realm: "oxide".to_string(),
            nonce: "nonce123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: Some("MD5".to_string()),
            stale: false,
        };
        let creds = RpcCredentials::new("user", "pass");
        let state = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let server = tokio::spawn({
            let state = state.clone();
            let challenge = challenge.clone();
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                let io = TokioIo::new(stream);
                let creds = creds.clone();
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    let challenge = challenge.clone();
                    let creds = creds.clone();
                    async move {
                        let attempt = state.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            let mut resp = Response::new(Full::new(Bytes::from_static(b"")));
                            *resp.status_mut() = StatusCode::UNAUTHORIZED;
                            let header = format!(
                                "Digest realm=\"{}\", nonce=\"{}\", qop=\"auth\", algorithm=MD5",
                                challenge.realm, challenge.nonce
                            );
                            resp.headers_mut()
                                .insert(WWW_AUTHENTICATE, HeaderValue::from_str(&header).unwrap());
                            return Ok::<_, Infallible>(resp);
                        }

                        let auth = req
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        assert!(auth.starts_with("Digest "));
                        let params = parse_auth_params(auth.trim_start_matches("Digest").trim());
                        assert_eq!(params.get("username").map(String::as_str), Some("user"));
                        assert_eq!(
                            params.get("realm").map(String::as_str),
                            Some(challenge.realm.as_str())
                        );
                        assert_eq!(
                            params.get("nonce").map(String::as_str),
                            Some(challenge.nonce.as_str())
                        );
                        assert_eq!(params.get("qop").map(String::as_str), Some("auth"));
                        assert_eq!(params.get("uri").map(String::as_str), Some("/json_rpc"));

                        let nc = params
                            .get("nc")
                            .and_then(|v| u32::from_str_radix(v, 16).ok())
                            .unwrap();
                        let cnonce = params.get("cnonce").unwrap();
                        let expected = build_digest_authorization(
                            "POST",
                            "/json_rpc",
                            &creds,
                            &challenge,
                            nc,
                            cnonce,
                        )
                        .unwrap();
                        let expected_params = parse_auth_params(
                            expected
                                .to_str()
                                .unwrap()
                                .trim_start_matches("Digest")
                                .trim(),
                        );
                        assert_eq!(params.get("response"), expected_params.get("response"));

                        let body = json!({
                            "jsonrpc": "2.0",
                            "result": { "height": 1 }
                        });
                        let mut resp = Response::new(Full::new(Bytes::from(body.to_string())));
                        *resp.status_mut() = StatusCode::OK;
                        Ok::<_, Infallible>(resp)
                    }
                });
                http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                    .unwrap();
            }
        });

        let endpoint =
            RpcEndpoint::new(&format!("http://{addr}"), Some("user"), Some("pass")).unwrap();
        let client = SoloRpcClient::new(endpoint);
        let info = client.get_info().await.expect("digest auth get_info");
        assert_eq!(info.height, 1);
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
