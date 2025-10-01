// OxideMiner/crates/oxide-core/src/stratum.rs

use anyhow::{anyhow, Context, Result};
use rustls_pemfile::certs;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{io::Cursor, sync::Arc};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::rustls::client::{ServerCertVerifier, WebPkiVerifier};
use tokio_rustls::{
    rustls::{
        self, client::HandshakeSignatureValid, client::ServerCertVerified, Certificate,
        ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    },
    TlsConnector,
};
use webpki::Error as WebPkiError;
use webpki_roots::TLS_SERVER_ROOTS;

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
}

pub struct StratumClient {
    reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>>,
    writer: Box<dyn io::AsyncWrite + Unpin + Send>,
    session_id: Option<String>,
    next_req_id: u64,
}

impl StratumClient {
    /// Connect + login; returns (client, initial_job_if_any)
    pub async fn connect_and_login(
        hostport: &str,
        wallet: &str,
        pass: &str,
        agent: &str,
        use_tls: bool,
        tls_ca_cert: Option<&str>,
        tls_cert_fingerprint: Option<&str>,
    ) -> Result<(Self, Option<PoolJob>)> {
        let (reader, writer): (
            Box<dyn io::AsyncRead + Unpin + Send>,
            Box<dyn io::AsyncWrite + Unpin + Send>,
        ) = if use_tls {
            let stream = TcpStream::connect(hostport)
                .await
                .with_context(|| format!("connect to {}", hostport))?;
            let host = hostport
                .split(':')
                .next()
                .ok_or_else(|| anyhow!("invalid host"))?;
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));

            if let Some(extra_ca) = tls_ca_cert {
                load_additional_roots(extra_ca, &mut root_cert_store).await?;
            }

            let fingerprint = if let Some(fp) = tls_cert_fingerprint {
                Some(parse_fingerprint(fp)?)
            } else {
                None
            };

            let root_cert_store = Arc::new(root_cert_store);
            let base_verifier = Arc::new(WebPkiVerifier::new(root_cert_store.clone(), None));
            let verifier: Arc<dyn ServerCertVerifier> = if let Some(pin) = fingerprint {
                Arc::new(FingerprintOrWebPkiVerifier::new(base_verifier.clone(), pin))
            } else {
                base_verifier
            };

            let config = ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));
            let server_name =
                rustls::ServerName::try_from(host).map_err(|_| anyhow!("invalid server name"))?;
            let tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|err| map_tls_error(err, tls_cert_fingerprint.is_some()))?;
            let (r, w) = io::split(tls);
            (Box::new(r), Box::new(w))
        } else {
            let stream = TcpStream::connect(hostport)
                .await
                .with_context(|| format!("connect to {}", hostport))?;
            let (r, w) = stream.into_split();
            (Box::new(r), Box::new(w))
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
                                job.cache_target();
                                tracing::info!("initial job (in login result)");
                                break Some(job);
                            }
                        }
                    }
                    if v.get("method").and_then(Value::as_str) == Some("job") {
                        if let Some(params) = v.get("params") {
                            if let Ok(mut job) = serde_json::from_value::<PoolJob>(params.clone()) {
                                job.cache_target();
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
                    job.cache_target();
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

struct FingerprintOrWebPkiVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    fingerprint: [u8; 32],
}

impl FingerprintOrWebPkiVerifier {
    fn new(inner: Arc<dyn ServerCertVerifier>, fingerprint: [u8; 32]) -> Self {
        Self { inner, fingerprint }
    }
}

impl ServerCertVerifier for FingerprintOrWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &rustls::client::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(err) => {
                if tls_error_is_ca_as_leaf(&err) {
                    let mut hasher = Sha256::new();
                    hasher.update(&end_entity.0);
                    let digest = hasher.finalize();
                    if digest.as_slice() == self.fingerprint {
                        tracing::warn!(
                            "accepting TLS certificate via pinned fingerprint despite validation error: {}",
                            err
                        );
                        return Ok(ServerCertVerified::assertion());
                    }
                }
                Err(err)
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn request_scts(&self) -> bool {
        self.inner.request_scts()
    }
}

async fn load_additional_roots(path: &str, store: &mut RootCertStore) -> Result<()> {
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading TLS CA bundle at {}", path))?;
    let mut reader = Cursor::new(&data);
    let certs = certs(&mut reader).context("parsing PEM certificates")?;
    let mut added = 0usize;
    for der in certs {
        let (accepted, _) = store.add_parsable_certificates(&[der]);
        added += accepted;
    }
    if added == 0 {
        return Err(anyhow!("no valid certificates found in {}", path));
    }
    tracing::info!(path, added, "loaded additional TLS root certificates");
    Ok(())
}

fn parse_fingerprint(input: &str) -> Result<[u8; 32]> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if cleaned.len() != 64 {
        return Err(anyhow!(
            "TLS certificate fingerprint must be 64 hex characters (SHA-256)"
        ));
    }
    let bytes = hex::decode(&cleaned).context("decoding fingerprint hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("TLS fingerprint must decode to 32 bytes"))?;
    Ok(arr)
}

fn map_tls_error(err: std::io::Error, has_pin: bool) -> anyhow::Error {
    let mut hint = String::from("TLS handshake failed");
    if let Some(rustls_err) = err
        .get_ref()
        .and_then(|source| source.downcast_ref::<TlsError>())
    {
        if tls_error_is_ca_as_leaf(rustls_err) {
            if has_pin {
                hint.push_str(
                    ": presented certificate is marked as a CA even though a fingerprint was supplied",
                );
            } else {
                hint.push_str(
                    ": pool presented a certificate marked as a CA. Provide --tls-cert-fingerprint <SHA256> to pin the current certificate or --tls-ca-cert <PATH> to trust the pool's CA bundle.",
                );
            }
        }
    }
    Err::<(), _>(err).context(hint).unwrap_err()
}

fn tls_error_is_ca_as_leaf(err: &TlsError) -> bool {
    match err {
        TlsError::InvalidCertificate(rustls::CertificateError::Other(other)) => {
            other.downcast_ref::<WebPkiError>().map_or(false, |inner| {
                matches!(*inner, WebPkiError::CaUsedAsEndEntity)
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
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
        };
        job.cache_target();
        assert_eq!(job.target_u32, Some(0x10000000));
        job.target = "zz".into();
        job.cache_target();
        assert_eq!(job.target_u32, None);
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

        let (client, job) = StratumClient::connect_and_login(
            &addr.to_string(),
            "wallet",
            "pass",
            "agent",
            false,
            None,
            None,
        )
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

        let (client, job) = StratumClient::connect_and_login(
            &addr.to_string(),
            "wallet",
            "pass",
            "agent",
            false,
            None,
            None,
        )
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
        };
        let json = serde_json::to_string(&job).unwrap();
        let de: PoolJob = serde_json::from_str(&json).unwrap();
        assert_eq!(de.job_id, "1");
        assert_eq!(de.seed_hash.as_deref(), Some("seed"));
        assert_eq!(de.height, Some(42));
    }
}
