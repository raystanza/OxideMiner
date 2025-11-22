// OxideMiner/crates/oxide-core/src/tari.rs

use crate::config::TariMergeMiningConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Merge-mining template as defined by Tari RFC-0131 (Mining) and RFC-0160 (Block Binary
/// Serialization). The template is obtained from the merge-mining proxy/base node via JSON-RPC
/// `get_new_block_template` with `pow_algo = Monero`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeMiningTemplate {
    /// Unique identifier for the template returned by the proxy/base node. RFC-0160 §Mining
    /// Template specifies that the template ID must be echoed back on submission.
    pub template_id: String,
    /// Block height for which this template is valid (RFC-0131 §Merge Mining).
    pub height: u64,
    /// Target difficulty for the Tari block header (LWMA difficulty per RFC-0120 §Difficulty).
    pub target_difficulty: u64,
    /// Declared PoW algorithm; must be `Monero` for merge-mined RandomX blocks (RFC-0131 §Merge
    /// mining selection rules).
    pub pow_algo: PowAlgorithm,
    /// Serialized PoW data (hex-encoded) embedded in the Tari header as per RFC-0131 §Merge Mining
    /// Data. This contains the Monero header + merkle data needed for validation.
    pub pow_data_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PowAlgorithm {
    Monero,
    Sha3x,
}

#[derive(Debug, Error)]
pub enum TariClientError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("proxy returned error: {0}")]
    Proxy(String),
    #[error("unexpected response shape")]
    Unexpected,
    #[error("unsupported pow algorithm {0:?} for merge mining")]
    UnsupportedPow(PowAlgorithm),
    #[error("invalid or empty pow_data provided by proxy")]
    InvalidPowData,
}

/// Lightweight async client for the Tari merge mining proxy.
///
/// The proxy exposes a JSON-RPC endpoint (default `http://127.0.0.1:18089/json_rpc`). This client
/// implements the minimum calls needed for merge mining per RFC-0131: fetch a template restricted
/// to `Monero` PoW and submit a merge-mined solution tied to that template ID.
#[derive(Clone)]
pub struct TariMergeMiningClient {
    http: reqwest::Client,
    base_url: String,
    backoff: Duration,
}

impl TariMergeMiningClient {
    pub fn new(config: TariMergeMiningConfig) -> anyhow::Result<Self> {
        let timeout = Duration::from_secs(config.request_timeout_secs.max(1));
        let backoff = Duration::from_secs(config.backoff_secs.max(1));
        let http = reqwest::Client::builder().timeout(timeout).build()?;

        Ok(Self {
            http,
            base_url: config.proxy_url,
            backoff,
        })
    }

    /// Fetches a merge-mining template constrained to `pow_algo = Monero` (RFC-0131 §Merge
    /// Mining). Validates that the returned template is merge-mineable and contains PoW data.
    pub async fn fetch_template(&self) -> Result<MergeMiningTemplate, TariClientError> {
        #[derive(Serialize)]
        struct RpcRequest<'a, T> {
            jsonrpc: &'a str,
            id: u64,
            method: &'a str,
            params: T,
        }

        #[derive(Serialize)]
        struct TemplateParams<'a> {
            pow_algo: &'a str,
        }

        #[derive(Deserialize)]
        struct RpcResponse<T> {
            result: Option<T>,
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            message: String,
        }

        #[derive(Deserialize)]
        struct TemplateResult {
            template_id: String,
            header: TemplateHeader,
            target_difficulty: u64,
        }

        #[derive(Deserialize)]
        struct TemplateHeader {
            height: u64,
            pow: TemplatePow,
        }

        #[derive(Deserialize)]
        struct TemplatePow {
            pow_algo: PowAlgorithm,
            pow_data: String,
        }

        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "get_new_block_template",
            params: TemplateParams { pow_algo: "monero" },
        };

        let resp = self
            .http
            .post(format!("{}/json_rpc", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let body: RpcResponse<TemplateResult> = resp.json().await?;
        if let Some(err) = body.error {
            return Err(TariClientError::Proxy(err.message));
        }

        let tpl = body.result.ok_or(TariClientError::Unexpected)?;
        if tpl.header.pow.pow_algo != PowAlgorithm::Monero {
            return Err(TariClientError::UnsupportedPow(tpl.header.pow.pow_algo));
        }
        if tpl.header.pow.pow_data.is_empty() {
            return Err(TariClientError::InvalidPowData);
        }

        Ok(MergeMiningTemplate {
            template_id: tpl.template_id,
            height: tpl.header.height,
            target_difficulty: tpl.target_difficulty,
            pow_algo: tpl.header.pow.pow_algo,
            pow_data_hex: tpl.header.pow.pow_data,
        })
    }

    /// Submits a merge-mined solution bound to the provided template. The parameters mirror the
    /// merge-mining proxy's `submit_block` call (RFC-0131 §Submission): the template ID must match
    /// the one returned by `get_new_block_template`, and the Monero PoW hash + nonce pair are used
    /// by the proxy to finalize the Tari header.
    pub async fn submit_solution(
        &self,
        template: &MergeMiningTemplate,
        monero_nonce_hex: &str,
        monero_pow_hash: &str,
    ) -> Result<(), TariClientError> {
        #[derive(Serialize)]
        struct SubmitParams<'a> {
            template_id: &'a str,
            monero_nonce: &'a str,
            monero_pow_hash: &'a str,
        }

        #[derive(Serialize)]
        struct RpcRequest<'a, T> {
            jsonrpc: &'a str,
            id: u64,
            method: &'a str,
            params: T,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            error: Option<RpcError>,
        }

        #[derive(Deserialize)]
        struct RpcError {
            message: String,
        }

        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "submit_block",
            params: SubmitParams {
                template_id: &template.template_id,
                monero_nonce: monero_nonce_hex,
                monero_pow_hash,
            },
        };

        let resp = self
            .http
            .post(format!("{}/json_rpc", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let body: RpcResponse = resp.json().await?;
        if let Some(err) = body.error {
            return Err(TariClientError::Proxy(err.message));
        }

        Ok(())
    }

    pub fn backoff(&self) -> Duration {
        self.backoff
    }
}
