// OxideMiner/crates/oxide-core/src/stratum.rs

use anyhow::{anyhow, Context, Result};
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fmt, fs,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{self, client::WebPkiVerifier},
    TlsConnector,
};
use tokio_socks::{tcp::Socks5Stream, TargetAddr};
use webpki_roots::TLS_SERVER_ROOTS;

use rustls::client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{CertificateError, SignatureScheme};
use rustls_pemfile::certs;
use rustls_webpki::Error as WebPkiError;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolJob {
    pub job_id: String,
    pub blob: String,
    pub target: String,
    pub seed_hash: Option<String>,
    pub height: Option<u64>,
    pub algo: Option<String>, // e.g. "rx/0"
    #[serde(skip)]
    pub target_u32: Option<u32>,
    /// Pre-decoded seed hash bytes to avoid hex decoding on every worker.
    #[serde(skip, default)]
    pub seed_hash_bytes: [u8; 32],
    /// Pre-decoded job blob bytes (nonce will be written into this buffer per worker).
    #[serde(skip, default)]
    pub blob_bytes: Arc<Vec<u8>>,
}

impl PoolJob {
    /// Cache a parsed little-endian u32 target if provided by the pool.
    pub fn cache_target(&mut self) {
        self.target_u32 = if self.target.len() <= 8 {
            if let Ok(mut b) = hex::decode(&self.target) {
                if b.len() > 4 {
                    b.truncate(4);
                }
                while b.len() < 4 {
                    b.push(0);
                }
                Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            } else {
                None
            }
        } else {
            None
        };
    }

    /// Decode and cache the seed hash + blob bytes so worker threads don't spend cycles in hex decoding.
    pub fn prepare(&mut self) -> Result<()> {
        self.cache_target();
        self.seed_hash_bytes = decode_seed_bytes(self.seed_hash.as_deref());
        self.blob_bytes = Arc::new(decode_blob_bytes(&self.blob)?);
        Ok(())
    }

    /// Ensure cached fields are ready (idempotent) before broadcasting to workers.
    pub fn ensure_prepared(&mut self) -> Result<()> {
        if self.blob_bytes.is_empty() {
            self.prepare()?;
        }
        Ok(())
    }
}

fn decode_seed_bytes(seed_hex: Option<&str>) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let hex_str =
        seed_hex.unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    if let Ok(mut decoded) = hex::decode(hex_str) {
        if decoded.len() > 32 {
            decoded.truncate(32);
        }
        if decoded.len() < 32 {
            decoded.resize(32, 0);
        }
        seed.copy_from_slice(&decoded);
    }
    seed
}

fn decode_blob_bytes(blob_hex: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(blob_hex.len() / 2);
    let bytes = hex::decode(blob_hex)?;
    out.extend_from_slice(&bytes);
    Ok(out)
}

#[derive(Clone)]
pub struct ProxyConfig {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyConfig {
    pub fn parse(proxy_url: &str) -> Result<Self> {
        let parsed =
            Url::parse(proxy_url).with_context(|| format!("invalid proxy URL: {proxy_url}"))?;

        if parsed.scheme() != "socks5" {
            return Err(anyhow!(
                "unsupported proxy scheme '{}' (expected socks5)",
                parsed.scheme()
            ));
        }

        if parsed.fragment().is_some() {
            return Err(anyhow!("proxy URL must not contain a fragment"));
        }

        if parsed.query().is_some() {
            return Err(anyhow!("proxy URL must not contain a query string"));
        }

        let path = parsed.path();
        if !path.is_empty() && path != "/" {
            return Err(anyhow!(
                "proxy URL must not include a path (found '{}')",
                path
            ));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("proxy URL is missing a host"))?
            .to_string();
        if host.is_empty() {
            return Err(anyhow!("proxy host must not be empty"));
        }

        let port = parsed
            .port()
            .ok_or_else(|| anyhow!("proxy URL must include a port"))?;

        let username = if parsed.username().is_empty() {
            None
        } else {
            Some(parsed.username().to_string())
        };
        let password = parsed.password().map(|p| p.to_string());

        if password.is_some() && username.is_none() {
            return Err(anyhow!("proxy password specified without username"));
        }

        Ok(Self {
            host,
            port,
            username,
            password,
        })
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn redacted(&self) -> String {
        match &self.username {
            Some(user) => format!("socks5://{}@{}", user, self.authority()),
            None => format!("socks5://{}", self.authority()),
        }
    }

    fn credentials(&self) -> Option<(&str, &str)> {
        self.username
            .as_ref()
            .map(|user| (user.as_str(), self.password.as_deref().unwrap_or("")))
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("endpoint", &self.redacted())
            .finish()
    }
}

fn display_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn parse_host_port(hostport: &str) -> Result<(String, u16)> {
    let (host_part, port_part) = hostport
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected host:port, got '{hostport}'"))?;

    let host = if host_part.starts_with('[') && host_part.ends_with(']') && host_part.len() > 2 {
        host_part[1..host_part.len() - 1].to_string()
    } else {
        host_part.trim().to_string()
    };

    if host.is_empty() {
        return Err(anyhow!("missing host in address '{hostport}'"));
    }

    let port: u16 = port_part
        .parse()
        .with_context(|| format!("invalid port '{}' in address '{hostport}'", port_part))?;

    Ok((host, port))
}

fn into_target_addr(host: &str, port: u16) -> TargetAddr<'static> {
    match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::Domain(host.to_string().into(), port),
    }
}

async fn connect_via_proxy(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    display_host: &str,
) -> Result<Socks5Stream<TcpStream>> {
    let proxy_addr = proxy.authority();
    let proxy_addr_str = proxy_addr.as_str();
    let redacted = proxy.redacted();
    let connect_result = if let Some((username, password)) = proxy.credentials() {
        Socks5Stream::connect_with_password(
            proxy_addr_str,
            into_target_addr(host, port),
            username,
            password,
        )
        .await
    } else {
        Socks5Stream::connect(proxy_addr_str, into_target_addr(host, port)).await
    };

    connect_result
        .with_context(|| format!("connect via SOCKS5 proxy {} to {}", redacted, display_host))
}

struct PinnedCertVerifier {
    inner: WebPkiVerifier,
    pinned: [u8; 32],
    fingerprint_hex: String,
}

impl PinnedCertVerifier {
    fn new(inner: WebPkiVerifier, pinned: [u8; 32]) -> Self {
        let fingerprint_hex = hex::encode(pinned);
        Self {
            inner,
            pinned,
            fingerprint_hex,
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(rustls::Error::InvalidCertificate(ref cert_err))
                if is_ca_used_as_end_entity(cert_err) =>
            {
                let actual = digest::digest(&digest::SHA256, end_entity.as_ref());
                if actual.as_ref() == self.pinned {
                    tracing::info!(
                        fingerprint = %self.fingerprint_hex,
                        "accepting pinned TLS certificate despite CAUsedAsEndEntity"
                    );
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(cert_err.clone()))
                }
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub struct StratumClient {
    reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>>,
    writer: Box<dyn io::AsyncWrite + Unpin + Send>,
    session_id: Option<String>,
    next_req_id: u64,
}

#[derive(Clone, Copy)]
pub struct ConnectConfig<'a> {
    pub hostport: &'a str,
    pub wallet: &'a str,
    pub pass: &'a str,
    pub agent: &'a str,
    pub use_tls: bool,
    pub custom_ca_path: Option<&'a Path>,
    pub pinned_cert_sha256: Option<&'a [u8; 32]>,
    pub proxy: Option<&'a ProxyConfig>,
}

impl StratumClient {
    /// Connect + login; returns (client, initial_job_if_any)
    pub async fn connect_and_login(config: ConnectConfig<'_>) -> Result<(Self, Option<PoolJob>)> {
        let ConnectConfig {
            hostport,
            wallet,
            pass,
            agent,
            use_tls,
            custom_ca_path,
            pinned_cert_sha256,
            proxy,
        } = config;
        let (host, port) = parse_host_port(hostport)?;
        let display_host = display_host_port(&host, port);

        let (reader, writer): (
            Box<dyn io::AsyncRead + Unpin + Send>,
            Box<dyn io::AsyncWrite + Unpin + Send>,
        ) = if use_tls {
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
            if let Some(path) = custom_ca_path {
                let data = fs::read(path).with_context(|| {
                    format!("read custom TLS CA certificate at {}", path.display())
                })?;
                let mut cursor = Cursor::new(&data);
                match certs(&mut cursor) {
                    Ok(pem_certs) if !pem_certs.is_empty() => {
                        let mut added = 0usize;
                        for cert in pem_certs {
                            let certificate = rustls::Certificate(cert);
                            root_cert_store.add(&certificate).with_context(|| {
                                format!("add custom TLS CA certificate from {}", path.display())
                            })?;
                            added += 1;
                        }
                        tracing::debug!(
                            path = %path.display(),
                            added,
                            "loaded custom TLS CA certificate(s)"
                        );
                    }
                    Ok(_) => {
                        let certificate = rustls::Certificate(data.clone());
                        root_cert_store.add(&certificate).with_context(|| {
                            format!("add custom TLS CA certificate from {}", path.display())
                        })?;
                        tracing::debug!(
                            path = %path.display(),
                            "loaded custom TLS CA certificate (DER)"
                        );
                    }
                    Err(err) => {
                        return Err(anyhow!(err).context(format!(
                            "parse custom TLS CA certificate at {}",
                            path.display()
                        )));
                    }
                }
            }
            let mut config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store.clone())
                .with_no_client_auth();
            if let Some(pin) = pinned_cert_sha256 {
                let verifier = Arc::new(PinnedCertVerifier::new(
                    WebPkiVerifier::new(root_cert_store, None),
                    *pin,
                ));
                config.dangerous().set_certificate_verifier(verifier);
            }
            let connector = TlsConnector::from(Arc::new(config));
            let server_name = rustls::ServerName::try_from(host.as_str())
                .map_err(|_| anyhow!("invalid server name"))?;

            if let Some(proxy_cfg) = proxy {
                let stream = connect_via_proxy(proxy_cfg, &host, port, &display_host).await?;
                let tls = connector
                    .connect(server_name.clone(), stream)
                    .await
                    .map_err(|err| {
                        map_tls_io_error(err, host.as_str(), pinned_cert_sha256.is_some())
                    })?;
                let (r, w) = io::split(tls);
                (Box::new(r), Box::new(w))
            } else {
                let stream = TcpStream::connect(display_host.as_str())
                    .await
                    .with_context(|| format!("connect to {}", display_host))?;
                let tls = connector
                    .connect(server_name.clone(), stream)
                    .await
                    .map_err(|err| {
                        map_tls_io_error(err, host.as_str(), pinned_cert_sha256.is_some())
                    })?;
                let (r, w) = io::split(tls);
                (Box::new(r), Box::new(w))
            }
        } else {
            match proxy {
                Some(proxy_cfg) => {
                    let stream = connect_via_proxy(proxy_cfg, &host, port, &display_host).await?;
                    let (r, w) = io::split(stream);
                    (Box::new(r), Box::new(w))
                }
                None => {
                    let stream = TcpStream::connect(display_host.as_str())
                        .await
                        .with_context(|| format!("connect to {}", display_host))?;
                    let (r, w) = stream.into_split();
                    (Box::new(r), Box::new(w))
                }
            }
        };

        let mut client = StratumClient {
            reader: BufReader::with_capacity(4096, reader),
            writer,
            session_id: None,
            next_req_id: 1,
        };

        // JSON-RPC login (declare algo for clarity)
        let req_id = client.take_req_id();
        let login = json!({
            "id": req_id,
            "jsonrpc": "2.0",
            "method": "login",
            "params": { "login": wallet, "pass": pass, "agent": agent, "algo": "rx/0" }
        });
        client.send_line(login.to_string()).await?;

        // Read until we see login result and/or first job
        let initial_job: Option<PoolJob> = loop {
            let line = client.read_line().await?;
            if line.is_empty() {
                return Err(anyhow!("disconnected during login"));
            }

            match serde_json::from_str::<Value>(&line) {
                Ok(v) => {
                    if let Some(obj) = v.get("result") {
                        if let Some(id) = obj.get("id").and_then(Value::as_str) {
                            client.session_id = Some(id.to_string());
                        }
                        if let Some(job_val) = obj.get("job") {
                            if let Ok(mut job) = serde_json::from_value::<PoolJob>(job_val.clone())
                            {
                                job.prepare()?;
                                tracing::info!("initial job (in login result)");
                                break Some(job);
                            }
                        }
                    }
                    if v.get("method").and_then(Value::as_str) == Some("job") {
                        if let Some(params) = v.get("params") {
                            if let Ok(mut job) = serde_json::from_value::<PoolJob>(params.clone()) {
                                job.prepare()?;
                                tracing::info!("initial job (job notify)");
                                break Some(job);
                            }
                        }
                    }
                }
                Err(_) => tracing::warn!("pool says: {}", line.trim()),
            }
        };

        Ok((client, initial_job))
    }

    /// Read the next JSON message from the pool (jobs, submit responses, etc.)
    pub async fn read_json(&mut self) -> Result<Value> {
        loop {
            let line = self.read_line().await?;
            if line.is_empty() {
                // true EOF
                return Err(anyhow!("pool closed"));
            }

            match serde_json::from_str::<Value>(&line) {
                Ok(v) => return Ok(v),
                Err(_) => {
                    // Some pools/proxies can emit banners/keepalives/garbage lines.
                    // Ignore and keep reading instead of killing the connection.
                    tracing::debug!(raw = %line.trim(), "ignoring non-JSON line from pool");
                    continue;
                }
            }
        }
    }

    /// Convenience: block until a "job" notify (unused in the new main loop, kept for completeness).
    pub async fn next_job(&mut self) -> Result<PoolJob> {
        loop {
            let v = self.read_json().await?;
            if v.get("method").and_then(Value::as_str) == Some("job") {
                if let Some(params) = v.get("params") {
                    let mut job: PoolJob =
                        serde_json::from_value(params.clone()).context("parse job params")?;
                    job.prepare()?;
                    return Ok(job);
                }
            }
        }
    }

    /// Submit a share; response will be read by the main loop via `read_json()`.
    /// `nonce_hex` = 8 hex chars (LE), `result_hex` = 64 hex chars (LE).
    pub async fn submit_share(
        &mut self,
        job_id: &str,
        nonce_hex: &str,
        result_hex: &str,
    ) -> Result<u64> {
        let sid = self
            .session_id
            .clone()
            .ok_or_else(|| anyhow!("no session id; login not completed"))?;

        let req_id = self.take_req_id();

        tracing::debug!(
            job_id = job_id,
            nonce_hex = nonce_hex,
            result_hex = result_hex,
            "submit_share"
        );

        let submit = json!({
            "id": req_id,
            "jsonrpc": "2.0",
            "method": "submit",
            "params": {
                "id": sid,
                "job_id": job_id,
                "nonce": nonce_hex,
                "result": result_hex
            }
        });

        self.send_line(submit.to_string()).await?;
        Ok(req_id)
    }

    fn take_req_id(&mut self) -> u64 {
        let id = self.next_req_id;
        self.next_req_id += 1;
        id
    }

    async fn send_line(&mut self, s: String) -> Result<()> {
        self.writer.write_all(s.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut buf = String::new();
        let n = self.reader.read_line(&mut buf).await?;
        if n == 0 {
            Ok(String::new())
        } else {
            Ok(buf)
        }
    }
}

fn tls_handshake_error(err: &rustls::Error, host: &str, pinned_configured: bool) -> anyhow::Error {
    if !pinned_configured {
        if let rustls::Error::InvalidCertificate(cert_err) = err {
            if is_ca_used_as_end_entity(cert_err) {
                return anyhow!(
                    "invalid TLS certificate presented by {host}: the pool served a CA certificate as the end-entity. \
                     Supply --tls-cert-sha256 with the server certificate's SHA-256 fingerprint to pin it explicitly."
                );
            }
        }
    }
    anyhow!(err.to_string())
}

fn map_tls_io_error(err: std::io::Error, host: &str, pinned_configured: bool) -> anyhow::Error {
    if let Some(rustls_err) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return tls_handshake_error(rustls_err, host, pinned_configured);
    }

    let err_display = err.to_string();

    if let Some(inner) = err.into_inner() {
        match inner.downcast::<rustls::Error>() {
            Ok(rustls_err) => {
                return tls_handshake_error(&rustls_err, host, pinned_configured);
            }
            Err(other) => {
                return anyhow!(other);
            }
        }
    }

    anyhow!(err_display)
}

fn is_ca_used_as_end_entity(error: &CertificateError) -> bool {
    match error {
        CertificateError::Other(inner) => {
            inner
                .downcast_ref::<WebPkiError>()
                .is_some_and(|webpki_err| matches!(webpki_err, WebPkiError::CaUsedAsEndEntity))
                || inner.to_string().contains("CaUsedAsEndEntity")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Arc;
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn request_ids_increment() {
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(io::sink());
        let mut client = StratumClient {
            reader,
            writer,
            session_id: None,
            next_req_id: 1,
        };
        assert_eq!(client.take_req_id(), 1);
        assert_eq!(client.take_req_id(), 2);
    }

    #[tokio::test]
    async fn send_line_appends_newline() {
        let (write_half, mut read_half) = io::duplex(64);
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(write_half);
        let mut client = StratumClient {
            reader,
            writer,
            session_id: None,
            next_req_id: 1,
        };
        client.send_line("ping".into()).await.unwrap();
        let mut buf = [0u8; 5];
        read_half.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping\n");
    }

    #[tokio::test]
    async fn read_json_skips_noise() {
        let (read_side, mut write_side) = io::duplex(128);
        tokio::spawn(async move {
            write_side.write_all(b"garbage\n{\"a\":1}\n").await.unwrap();
        });
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(read_side) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(io::sink());
        let mut client = StratumClient {
            reader,
            writer,
            session_id: None,
            next_req_id: 1,
        };
        let v = client.read_json().await.unwrap();
        assert_eq!(v.get("a").and_then(|x| x.as_u64()), Some(1));
    }

    #[tokio::test]
    async fn read_json_eof_errors() {
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(io::sink());
        let mut client = StratumClient {
            reader,
            writer,
            session_id: None,
            next_req_id: 1,
        };
        let err = client.read_json().await.unwrap_err();
        assert!(err.to_string().contains("pool closed"));
    }

    #[tokio::test]
    async fn next_job_parses_notify() {
        let (read_side, mut write_side) = io::duplex(256);
        tokio::spawn(async move {
            let msg = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "job",
                "params": {
                    "job_id": "job-123",
                    "blob": "00",
                    "target": "0a0b0c0d",
                    "seed_hash": null,
                    "height": null,
                    "algo": null
                }
            })
            .to_string();
            write_side.write_all(msg.as_bytes()).await.unwrap();
            write_side.write_all(b"\n").await.unwrap();
        });
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(read_side) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(io::sink());
        let mut client = StratumClient {
            reader,
            writer,
            session_id: None,
            next_req_id: 1,
        };
        let job = client.next_job().await.expect("job parsed");
        assert_eq!(job.job_id, "job-123");
        assert_eq!(job.target_u32, Some(0x0d0c0b0a));
    }

    #[tokio::test]
    async fn submit_share_requires_login() {
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(io::sink());
        let mut client = StratumClient {
            reader,
            writer,
            session_id: None,
            next_req_id: 7,
        };
        let err = client
            .submit_share(
                "job",
                "00000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("session id"));
    }

    #[tokio::test]
    async fn submit_share_writes_request() {
        let (write_half, mut read_half) = io::duplex(512);
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> = BufReader::with_capacity(
            4096,
            Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>,
        );
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(write_half);
        let mut client = StratumClient {
            reader,
            writer,
            session_id: Some("sess-1".into()),
            next_req_id: 42,
        };
        let req_id = client
            .submit_share(
                "job-1",
                "0a0b0c0d",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .await
            .expect("submit ok");
        assert_eq!(req_id, 42);

        let mut buf = vec![0u8; 256];
        let n = read_half.read(&mut buf).await.unwrap();
        let line = String::from_utf8(buf[..n].to_vec()).unwrap();
        let value: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["id"].as_u64(), Some(42));
        assert_eq!(value["method"].as_str(), Some("submit"));
        assert_eq!(value["params"]["id"].as_str(), Some("sess-1"));
        assert_eq!(value["params"]["job_id"].as_str(), Some("job-1"));
    }

    #[test]
    fn cache_target_resets_on_invalid_hex() {
        let mut job = PoolJob {
            job_id: "job".into(),
            blob: String::new(),
            target: "00000010".into(),
            seed_hash: None,
            height: None,
            algo: None,
            target_u32: None,
            seed_hash_bytes: [0; 32],
            blob_bytes: Arc::new(Vec::new()),
        };
        job.cache_target();
        assert_eq!(job.target_u32, Some(0x10000000));
        job.target = "zz".into();
        job.cache_target();
        assert_eq!(job.target_u32, None);
    }

    #[test]
    fn prepare_materializes_blob_and_seed() {
        let mut job = PoolJob {
            job_id: "id".into(),
            blob: "0a0b".into(),
            target: String::new(),
            seed_hash: Some(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into(),
            ),
            height: None,
            algo: None,
            target_u32: None,
            seed_hash_bytes: [0; 32],
            blob_bytes: Arc::new(Vec::new()),
        };

        job.prepare().expect("prepare succeeds");
        assert_eq!(job.blob_bytes.as_slice(), &[0x0a, 0x0b]);
        assert_eq!(job.seed_hash_bytes[0..4], [1, 2, 3, 4]);
    }

    #[test]
    fn cache_target_handles_truncation_and_padding() {
        let mut job = PoolJob {
            job_id: String::new(),
            blob: String::new(),
            target: "abcd123456".into(),
            seed_hash: None,
            height: None,
            algo: None,
            target_u32: Some(1),
            seed_hash_bytes: [0; 32],
            blob_bytes: Arc::new(Vec::new()),
        };
        job.cache_target();
        assert_eq!(job.target_u32, None);

        job.target = "1a2b".into();
        job.cache_target();
        assert_eq!(job.target_u32, Some(0x00002b1a));
    }

    #[tokio::test]
    async fn connect_and_login_returns_initial_job_from_result() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap(); // read one JSON line
            assert!(line.contains("\"login\""));
            let mut socket = reader.into_inner();
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "id": "session-1",
                    "job": {
                        "job_id": "job",
                        "blob": "00",
                        "target": "7f",
                        "seed_hash": null,
                        "height": 1,
                        "algo": "rx/0"
                    }
                }
            })
            .to_string();
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(b"\n").await.unwrap();
        });

        let (client, job) = StratumClient::connect_and_login(ConnectConfig {
            hostport: &addr.to_string(),
            wallet: "wallet",
            pass: "pass",
            agent: "agent",
            use_tls: false,
            custom_ca_path: None,
            pinned_cert_sha256: None,
            proxy: None,
        })
        .await
        .expect("login succeeds");
        assert!(job.is_some());
        assert_eq!(job.unwrap().target_u32, Some(0x7f));
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_and_login_waits_for_job_notify() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("\"login\""));
            let mut socket = reader.into_inner();
            let login_resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"id": "session-2"}
            })
            .to_string();
            socket.write_all(login_resp.as_bytes()).await.unwrap();
            socket.write_all(b"\n").await.unwrap();
            let job_notify = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "job",
                "params": {
                    "job_id": "notify",
                    "blob": "00",
                    "target": "01000000",
                    "seed_hash": null,
                    "height": null,
                    "algo": null
                }
            })
            .to_string();
            socket.write_all(job_notify.as_bytes()).await.unwrap();
            socket.write_all(b"\n").await.unwrap();
        });

        let (client, job) = StratumClient::connect_and_login(ConnectConfig {
            hostport: &addr.to_string(),
            wallet: "wallet",
            pass: "pass",
            agent: "agent",
            use_tls: false,
            custom_ca_path: None,
            pinned_cert_sha256: None,
            proxy: None,
        })
        .await
        .expect("login succeeds");
        assert!(job.is_some());
        assert_eq!(job.as_ref().unwrap().job_id, "notify");
        assert_eq!(client.session_id, Some("session-2".into()));
        drop(client);
        server.await.unwrap();
    }

    #[test]
    fn pooljob_roundtrip() {
        let job = PoolJob {
            job_id: "1".into(),
            blob: "deadbeef".into(),
            target: "abcd".into(),
            seed_hash: Some("seed".into()),
            height: Some(42),
            algo: Some("rx/0".into()),
            target_u32: None,
            seed_hash_bytes: [0; 32],
            blob_bytes: Arc::new(Vec::new()),
        };
        let json = serde_json::to_string(&job).unwrap();
        let de: PoolJob = serde_json::from_str(&json).unwrap();
        assert_eq!(de.job_id, "1");
        assert_eq!(de.seed_hash.as_deref(), Some("seed"));
        assert_eq!(de.height, Some(42));
    }

    #[test]
    fn proxy_config_parsing() {
        let cfg = ProxyConfig::parse("socks5://127.0.0.1:1080").expect("parse proxy without auth");
        assert_eq!(cfg.authority(), "127.0.0.1:1080");
        assert_eq!(cfg.redacted(), "socks5://127.0.0.1:1080");

        let cfg = ProxyConfig::parse("socks5://user:pass@127.0.0.1:9050")
            .expect("parse proxy with credentials");
        assert_eq!(cfg.redacted(), "socks5://user@127.0.0.1:9050");

        assert!(ProxyConfig::parse("http://127.0.0.1:1080").is_err());
        assert!(ProxyConfig::parse("socks5://:pass@127.0.0.1:9050").is_err());
    }

    #[tokio::test]
    async fn connect_via_proxy_without_auth() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (target_addr, target_handle) = spawn_echo_server().await;
        let (proxy_addr, proxy_handle) = spawn_mock_socks5_proxy(None, target_addr).await;

        let proxy = ProxyConfig::parse(&format!("socks5://{}", proxy_addr)).unwrap();
        let host = target_addr.ip().to_string();
        let display = display_host_port(&host, target_addr.port());

        let mut stream = connect_via_proxy(&proxy, &host, target_addr.port(), &display)
            .await
            .expect("proxy connect succeeds");
        stream.write_all(b"PING").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");

        drop(stream);
        proxy_handle.await.unwrap();
        target_handle.await.unwrap();
    }

    #[tokio::test]
    async fn connect_via_proxy_with_auth() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (target_addr, target_handle) = spawn_echo_server().await;
        let (proxy_addr, proxy_handle) =
            spawn_mock_socks5_proxy(Some(("alice", "secret")), target_addr).await;

        let proxy = ProxyConfig::parse(&format!("socks5://alice:secret@{}", proxy_addr)).unwrap();
        let host = target_addr.ip().to_string();
        let display = display_host_port(&host, target_addr.port());

        let mut stream = connect_via_proxy(&proxy, &host, target_addr.port(), &display)
            .await
            .expect("proxy connect succeeds");
        stream.write_all(b"TEST").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"TEST");

        drop(stream);
        proxy_handle.await.unwrap();
        target_handle.await.unwrap();
    }

    async fn spawn_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
        });
        (addr, handle)
    }

    async fn spawn_mock_socks5_proxy(
        expected_auth: Option<(&'static str, &'static str)>,
        target_addr: std::net::SocketAddr,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use std::net::{IpAddr, Ipv4Addr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let creds = expected_auth.map(|(u, p)| (u.to_string(), p.to_string()));

        let handle = tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.unwrap();

            let mut header = [0u8; 2];
            inbound.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 0x05);
            let nmethods = header[1] as usize;
            let mut methods = vec![0u8; nmethods];
            inbound.read_exact(&mut methods).await.unwrap();
            let use_auth = creds.is_some();
            let chosen = if use_auth { 0x02 } else { 0x00 };
            assert!(methods.contains(&chosen));
            inbound.write_all(&[0x05, chosen]).await.unwrap();

            if let Some((user, pass)) = &creds {
                let mut auth_header = [0u8; 2];
                inbound.read_exact(&mut auth_header).await.unwrap();
                assert_eq!(auth_header[0], 0x01);
                let ulen = auth_header[1] as usize;
                let mut username = vec![0u8; ulen];
                inbound.read_exact(&mut username).await.unwrap();
                let mut plen = [0u8; 1];
                inbound.read_exact(&mut plen).await.unwrap();
                let plen = plen[0] as usize;
                let mut password = vec![0u8; plen];
                inbound.read_exact(&mut password).await.unwrap();
                assert_eq!(username, user.as_bytes());
                assert_eq!(password, pass.as_bytes());
                inbound.write_all(&[0x01, 0x00]).await.unwrap();
            }

            let mut request = [0u8; 4];
            inbound.read_exact(&mut request).await.unwrap();
            assert_eq!(request[0], 0x05);
            assert_eq!(request[1], 0x01);
            assert_eq!(request[2], 0x00);
            match request[3] {
                0x01 => {
                    let mut addr_bytes = [0u8; 4];
                    inbound.read_exact(&mut addr_bytes).await.unwrap();
                    let addr = IpAddr::V4(Ipv4Addr::from(addr_bytes));
                    assert_eq!(addr, target_addr.ip());
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    inbound.read_exact(&mut len).await.unwrap();
                    let mut domain = vec![0u8; len[0] as usize];
                    inbound.read_exact(&mut domain).await.unwrap();
                    let domain = String::from_utf8(domain).unwrap();
                    assert_eq!(domain, target_addr.ip().to_string());
                }
                0x04 => {
                    let mut addr_bytes = [0u8; 16];
                    inbound.read_exact(&mut addr_bytes).await.unwrap();
                    let addr = IpAddr::from(addr_bytes);
                    assert_eq!(addr, target_addr.ip());
                }
                other => panic!("unexpected ATYP {other}"),
            }
            let mut port_bytes = [0u8; 2];
            inbound.read_exact(&mut port_bytes).await.unwrap();
            let port = u16::from_be_bytes(port_bytes);
            assert_eq!(port, target_addr.port());

            inbound
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            let mut upstream = TcpStream::connect(target_addr).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
        });

        (addr, handle)
    }
}
