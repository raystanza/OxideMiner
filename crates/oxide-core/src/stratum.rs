use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::{
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_rustls::{rustls, TlsConnector};
use tracing::{info, warn};
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
            let mut root_cert_store = rustls::RootCertStore::empty();
            root_cert_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let server_name =
                rustls::ServerName::try_from(host).map_err(|_| anyhow!("invalid server name"))?;
            let tls = connector.connect(server_name, stream).await?;
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
                            if let Ok(mut job) = serde_json::from_value::<PoolJob>(job_val.clone()) {
                                job.cache_target();
                                info!("initial job (in login result)");
                                break Some(job);
                            }
                        }
                    }
                    if v.get("method").and_then(Value::as_str) == Some("job") {
                        if let Some(params) = v.get("params") {
                            if let Ok(mut job) = serde_json::from_value::<PoolJob>(params.clone()) {
                                job.cache_target();
                                info!("initial job (job notify)");
                                break Some(job);
                            }
                        }
                    }
                }
                Err(_) => warn!("pool says: {}", line.trim()),
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
    ) -> Result<()> {
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
        Ok(())
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
        if n == 0 { Ok(String::new()) } else { Ok(buf) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn request_ids_increment() {
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> =
            BufReader::with_capacity(4096, Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>);
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> =
            Box::new(io::sink());
        let mut client = StratumClient { reader, writer, session_id: None, next_req_id: 1 };
        assert_eq!(client.take_req_id(), 1);
        assert_eq!(client.take_req_id(), 2);
    }

    #[tokio::test]
    async fn send_line_appends_newline() {
        let (write_half, mut read_half) = io::duplex(64);
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> =
            BufReader::with_capacity(4096, Box::new(io::empty()) as Box<dyn io::AsyncRead + Unpin + Send>);
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(write_half);
        let mut client = StratumClient { reader, writer, session_id: None, next_req_id: 1 };
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
        let reader: BufReader<Box<dyn io::AsyncRead + Unpin + Send>> =
            BufReader::with_capacity(4096, Box::new(read_side) as Box<dyn io::AsyncRead + Unpin + Send>);
        let writer: Box<dyn io::AsyncWrite + Unpin + Send> = Box::new(io::sink());
        let mut client = StratumClient { reader, writer, session_id: None, next_req_id: 1 };
        let v = client.read_json().await.unwrap();
        assert_eq!(v.get("a").and_then(|x| x.as_u64()), Some(1));
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
