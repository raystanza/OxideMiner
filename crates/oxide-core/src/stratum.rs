use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolJob {
    pub job_id: String,
    pub blob: String,
    pub target: String,
    // TODO: add nonce size, height, seed hash, etc.
}

pub struct StratumClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl StratumClient {
    pub async fn connect_and_login(hostport: &str, wallet: &str, pass: &str, agent: &str) -> Result<Self> {
        let stream = TcpStream::connect(hostport).await?;
        let (r, w) = stream.into_split();

        let mut client = StratumClient {
            reader: BufReader::new(r),
            writer: w,
        };

        // JSON-RPC login (skeleton)
        let login = json!({
            "id": 1_u32,
            "jsonrpc": "2.0",
            "method": "login",
            "params": { "login": wallet, "pass": pass, "agent": agent }
        });

        client.send_line(login.to_string()).await?;

        // Read one line back just to confirm connectivity (we'll parse properly soon)
        let mut line = String::new();
        let n = client.reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("disconnected during login"));
        }
        info!("pool: {}", line.trim());

        Ok(client)
    }

    pub async fn next_job(&mut self) -> Result<PoolJob> {
        let mut line = String::new();
        loop {
            line.clear();
            if self.reader.read_line(&mut line).await? == 0 {
                return Err(anyhow!("pool closed"));
            }

            // TODO: replace this with proper JSON parsing of job notifications
            if line.contains("\"job\"") {
                return Ok(PoolJob {
                    job_id: "job-1".into(),
                    blob: "00".into(),
                    target: "ffff".into(),
                });
            } else {
                warn!("pool says: {}", line.trim());
            }
        }
    }

    pub async fn submit_share(&mut self, _job_id: &str, _nonce: u32, _result_hex: &str) -> Result<()> {
        // TODO: implement submit JSON-RPC
        Ok(())
    }

    async fn send_line(&mut self, s: String) -> Result<()> {
        self.writer.write_all(s.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }
}
