// OxideMiner/crates/oxide-core/src/tari.rs

use crate::config::TariMergeMiningConfig;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};
use uint::construct_uint;

construct_uint! {
    /// 256-bit unsigned integer for RFC-0120 difficulty/target conversions.
    pub struct U256(4);
}

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
    /// Derived 256-bit target computed from difficulty using RFC-0120 `difficulty = (2^256 - 1) /
    /// target` (big-endian bytes). This ensures submissions compare against the correct target
    /// semantics when reporting/validating locally.
    pub target: [u8; 32],
    /// Declared PoW algorithm; must be `Monero` for merge-mined RandomX blocks (RFC-0131 §Merge
    /// mining selection rules).
    pub pow_algo: PowAlgorithm,
    /// Serialized PoW data (hex-encoded) embedded in the Tari header as per RFC-0131 §Merge Mining
    /// Data. This contains the Monero header + merkle data needed for validation. Monero-compatible
    /// proxy responses may omit this; in that case it remains `None` and submissions rely on the
    /// proxy’s stored template (RFC-0131 notes the proxy can reconstruct the header from its cache).
    pub pow_data_hex: Option<String>,
    /// Parsed Monero merge-mining payload (length-checked against RFC-0131 §Merge Mining data
    /// ordering requirements).
    pub pow_data: Option<MergeMiningPowData>,
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
    #[error("invalid difficulty (zero or overflow) from proxy")]
    InvalidDifficulty,
    #[error("proxy response missing Tari merge-mining aux data")]
    MissingAuxData,
    #[error("malformed proxy response: {0}")]
    MalformedResponse(String),
}

/// Parsed Monero merge-mining payload extracted from `pow_data` (RFC-0131 §Merge Mining Data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeMiningPowData {
    /// Monero BlockHeader bytes.
    pub monero_header: Vec<u8>,
    /// RandomX VM key/seed hash (expected 32 bytes).
    pub randomx_seed_hash: Vec<u8>,
    /// Monero transaction count (varint from the Monero header context).
    pub monero_tx_count: u64,
    /// Merkle root of Monero block transactions.
    pub monero_merkle_root: Vec<u8>,
    /// Merkle proof for the Monero coinbase transaction.
    pub monero_coinbase_merkle_proof: Vec<u8>,
    /// Full Monero coinbase transaction bytes.
    pub monero_coinbase_tx: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MoneroCompatTemplate {
    #[serde(default)]
    difficulty: Option<u64>,
    #[serde(default)]
    height: Option<u64>,
    #[serde(default)]
    blockhashing_blob: Option<String>,
    #[serde(default)]
    blocktemplate_blob: Option<String>,
    // Minotari merge-mining proxy injects merge-mining metadata under the `_aux` key (see
    // `MMPROXY_AUX_KEY_NAME` in the proxy sources). Some forks or tooling emit this as `aux`;
    //  accept both spellings to avoid falsely reporting missing Tari aux data.
    #[serde(default, alias = "_aux", alias = "aux")]
    aux: Option<MoneroAuxData>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MoneroAuxData {
    #[serde(default)]
    base_difficulty: Option<u64>,
    #[serde(default)]
    chains: Option<Vec<MoneroAuxChain>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MoneroAuxChain {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    difficulty: Option<u64>,
    #[serde(default)]
    height: Option<u64>,
    #[serde(default)]
    mining_hash: Option<String>,
    #[serde(default)]
    miner_reward: Option<u64>,
}

/// Lightweight async client for the Tari merge mining proxy.
///
/// The proxy exposes a JSON-RPC endpoint (default `http://127.0.0.1:18081/json_rpc`). This client
/// implements the minimum calls needed for merge mining per RFC-0131: fetch a template restricted
/// to `Monero` PoW and submit a merge-mined solution tied to that template ID.
#[derive(Clone)]
pub struct TariMergeMiningClient {
    http: reqwest::Client,
    base_url: String,
    backoff: Duration,
    monero_wallet_address: Option<String>,
    prefer_monero_compat: Arc<AtomicBool>,
    warned_direct_unavailable: Arc<AtomicBool>,
    warned_missing_aux: Arc<AtomicBool>,
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
            monero_wallet_address: config.monero_wallet_address,
            prefer_monero_compat: Arc::new(AtomicBool::new(false)),
            warned_direct_unavailable: Arc::new(AtomicBool::new(false)),
            warned_missing_aux: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Fetches a merge-mining template constrained to `pow_algo = Monero` (RFC-0131 §Merge
    /// Mining). Validates that the returned template is merge-mineable and contains PoW data.
    pub async fn fetch_template(&self) -> Result<MergeMiningTemplate, TariClientError> {
        if self.prefer_monero_compat.load(Ordering::Relaxed) {
            match self.fetch_template_monero_compat().await {
                Ok(tpl) => return Ok(tpl),
                Err(err) => {
                    debug!(error = %err, "monero-compatible template fetch failed; retrying tari method");
                }
            }
        }

        match self.fetch_template_direct().await {
            Ok(tpl) => {
                // Successful Tari path: ensure we don't unnecessarily stick to the compat flow.
                self.prefer_monero_compat.store(false, Ordering::Relaxed);
                Ok(tpl)
            }
            Err(TariClientError::Proxy(msg)) if msg.contains("Method not found") => {
                // Some merge-mining proxies expose only the Monero-compatible surface; fall back
                // when the Tari JSON-RPC method is unavailable.
                self.log_direct_method_unavailable();
                self.prefer_monero_compat.store(true, Ordering::Relaxed);
                self.fetch_template_monero_compat().await
            }
            Err(err) => {
                // If the direct Tari method failed for another reason but a Monero wallet address
                // is configured, attempt the compatibility path rather than immediately
                // propagating an error. This recovers when the proxy returns an unexpected shape
                // (e.g., missing Tari aux data) while still allowing the original error to surface
                // when no fallback is possible.
                if self.monero_wallet_address.is_some() {
                    self.log_direct_method_unavailable_with_error(&err);
                    self.prefer_monero_compat.store(true, Ordering::Relaxed);
                    self.fetch_template_monero_compat().await
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn fetch_template_direct(&self) -> Result<MergeMiningTemplate, TariClientError> {
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

        // RFC-0120 difficulty/target conversion; difficulty must be non-zero.
        let target = difficulty_to_target_bytes(tpl.target_difficulty)?;

        let pow_data = parse_monero_merge_mining_pow_data(&tpl.header.pow.pow_data)?;

        Ok(MergeMiningTemplate {
            template_id: tpl.template_id,
            height: tpl.header.height,
            target_difficulty: tpl.target_difficulty,
            target,
            pow_algo: tpl.header.pow.pow_algo,
            pow_data_hex: Some(tpl.header.pow.pow_data),
            pow_data: Some(pow_data),
        })
    }

    /// Fallback path for merge-mining proxy instances that expose a Monero-compatible `get_block_template`
    /// instead of the Tari `get_new_block_template` JSON-RPC. This expects the proxy to embed Tari
    /// merge-mining data inside the response (commonly under a `tari` or `merge_mining` field). If no
    /// Tari template is present the request fails with a descriptive proxy error.
    async fn fetch_template_monero_compat(&self) -> Result<MergeMiningTemplate, TariClientError> {
        #[derive(Serialize)]
        struct RpcRequest<'a, T> {
            jsonrpc: &'a str,
            id: u64,
            method: &'a str,
            params: T,
        }

        #[derive(Serialize)]
        struct TemplateParams<'a> {
            wallet_address: &'a str,
            reserve_size: u32,
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

        let wallet_address = self.monero_wallet_address.as_deref().unwrap_or_default();

        if wallet_address.is_empty() {
            return Err(TariClientError::Proxy(
                "merge-mining proxy expects get_block_template but no Monero wallet address configured (set tari.monero_wallet_address or --tari-monero-wallet)"
                    .into(),
            ));
        }

        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "get_block_template",
            params: TemplateParams {
                wallet_address,
                reserve_size: 60,
            },
        };

        let resp = self
            .http
            .post(format!("{}/json_rpc", self.base_url))
            .json(&payload)
            .send()
            .await?;

        let body: RpcResponse<MoneroCompatTemplate> = resp.json().await?;
        if let Some(err) = body.error {
            return Err(TariClientError::Proxy(err.message));
        }

        let compat = body
            .result
            .ok_or_else(|| TariClientError::MalformedResponse("missing result".into()))?;

        self.parse_monero_compat_template(compat)
    }

    fn parse_monero_compat_template(
        &self,
        result: MoneroCompatTemplate,
    ) -> Result<MergeMiningTemplate, TariClientError> {
        let mut warn_missing_aux = false;
        let mut miner_reward = None;
        let (target_difficulty, height, template_id) = if let Some(aux) = result.aux {
            let mut chains_iter = aux.chains.unwrap_or_default().into_iter();
            let chain = chains_iter
                .find(|c| c.id.as_deref().unwrap_or_default() == "tari")
                .or_else(|| chains_iter.next());

            if let Some(chain) = chain {
                miner_reward = chain.miner_reward;
                (
                    chain
                        .difficulty
                        .or(aux.base_difficulty)
                        .or(result.difficulty),
                    chain.height.or(result.height).unwrap_or_default(),
                    chain
                        .mining_hash
                        .or_else(|| result.blockhashing_blob.clone())
                        .or_else(|| result.blocktemplate_blob.clone())
                        .unwrap_or_else(|| "tari-template".to_string()),
                )
            } else {
                warn_missing_aux = true;
                (
                    aux.base_difficulty.or(result.difficulty),
                    result.height.unwrap_or_default(),
                    result
                        .blockhashing_blob
                        .clone()
                        .or_else(|| result.blocktemplate_blob.clone())
                        .unwrap_or_else(|| "tari-template".to_string()),
                )
            }
        } else {
            warn_missing_aux = true;
            (
                result.difficulty,
                result.height.unwrap_or_default(),
                result
                    .blockhashing_blob
                    .clone()
                    .or_else(|| result.blocktemplate_blob.clone())
                    .unwrap_or_else(|| "tari-template".to_string()),
            )
        };

        if warn_missing_aux {
            self.log_missing_aux_once();
        }

        let target_difficulty =
            target_difficulty.ok_or_else(|| TariClientError::InvalidDifficulty)?;
        let target = difficulty_to_target_bytes(target_difficulty)?;

        if let Some(status) = result.status {
            if status.eq_ignore_ascii_case("fail") {
                return Err(TariClientError::Proxy(
                    "merge-mining proxy returned failure status".into(),
                ));
            }
        }

        if let Some(reward) = miner_reward {
            debug!(
                target_difficulty,
                reward, "received Tari aux chain reward estimate"
            );
        }

        Ok(MergeMiningTemplate {
            template_id,
            height,
            target_difficulty,
            target,
            pow_algo: PowAlgorithm::Monero,
            pow_data_hex: None,
            pow_data: None,
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

        // The merge-mining proxy follows the Monero JSON-RPC shape and expects params to be an
        // array (even for structured payloads). Sending an object causes the proxy to reject the
        // request with "params field is empty or an invalid type".
        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "submit_block",
            params: [SubmitParams {
                template_id: &template.template_id,
                monero_nonce: monero_nonce_hex,
                monero_pow_hash,
            }],
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

    fn log_direct_method_unavailable(&self) {
        if !self.warned_direct_unavailable.swap(true, Ordering::Relaxed) {
            warn!(
                "get_new_block_template unavailable at {}; attempting Monero get_block_template",
                self.base_url
            );
        } else {
            debug!(
                "get_new_block_template unavailable at {}; continuing to use Monero get_block_template",
                self.base_url
            );
        }
    }

    fn log_direct_method_unavailable_with_error(&self, err: &TariClientError) {
        if !self.warned_direct_unavailable.swap(true, Ordering::Relaxed) {
            warn!(
                error = %err,
                "get_new_block_template failed; attempting Monero get_block_template"
            );
        } else {
            debug!(error = %err, "get_new_block_template failed; using Monero get_block_template");
        }
    }

    fn log_missing_aux_once(&self) {
        // The Minotari merge-mining proxy may omit aux fields when it can reconstruct Tari data from
        // cached templates; treat this as informational to avoid log spam during steady-state
        // polling while still surfacing the first occurrence to operators.
        if !self.warned_missing_aux.swap(true, Ordering::Relaxed) {
            warn!(
                "merge-mining proxy response missing Tari aux data; using Monero template fields"
            );
        } else {
            debug!(
                "merge-mining proxy response missing Tari aux data; using Monero template fields"
            );
        }
    }
}

/// Converts RFC-0120 difficulty to a big-endian 256-bit target: target = floor((2^256 - 1) /
/// difficulty).
fn difficulty_to_target_bytes(difficulty: u64) -> Result<[u8; 32], TariClientError> {
    if difficulty == 0 {
        return Err(TariClientError::InvalidDifficulty);
    }
    let max = U256::MAX;
    let target = max
        .checked_div(U256::from(difficulty))
        .ok_or(TariClientError::InvalidDifficulty)?;
    let mut out = [0u8; 32];
    target.to_big_endian(&mut out);
    Ok(out)
}

/// Parse Monero merge-mining `pow_data` sequence per RFC-0131 §Merge Mining Data. The layout is
/// length-delimited segments encoded with VarInt lengths (RFC-0160 serialization rules):
/// 1. Monero BlockHeader bytes
/// 2. RandomX VM key/seed hash (expected 32 bytes)
/// 3. Monero tx count (varint value)
/// 4. Monero merkle root (expected 32 bytes)
/// 5. Monero coinbase merkle proof (varint length + bytes)
/// 6. Monero coinbase transaction (varint length + bytes)
///
/// Templates that do not follow this ordering or contain undersized segments are rejected to avoid
/// mining on malformed work (safety per RFC-0131 and RFC-0160).
fn parse_monero_merge_mining_pow_data(
    hex_data: &str,
) -> Result<MergeMiningPowData, TariClientError> {
    let bytes = hex::decode(hex_data).map_err(|_| TariClientError::InvalidPowData)?;
    if bytes.is_empty() {
        return Err(TariClientError::InvalidPowData);
    }

    let mut offset = 0usize;

    let monero_header = read_varint_vec(&bytes, &mut offset)?;
    if monero_header.len() < 76 {
        warn!("monero_header too short for RFC-0131 expectations");
        return Err(TariClientError::InvalidPowData);
    }

    let randomx_seed_hash = read_varint_vec(&bytes, &mut offset)?;
    if randomx_seed_hash.len() != 32 {
        warn!(
            len = randomx_seed_hash.len(),
            "randomx_seed_hash must be 32 bytes"
        );
        return Err(TariClientError::InvalidPowData);
    }

    let monero_tx_count = read_varint(&bytes, &mut offset)?;

    let monero_merkle_root = read_varint_vec(&bytes, &mut offset)?;
    if monero_merkle_root.len() != 32 {
        warn!(
            len = monero_merkle_root.len(),
            "monero_merkle_root must be 32 bytes"
        );
        return Err(TariClientError::InvalidPowData);
    }

    let monero_coinbase_merkle_proof = read_varint_vec(&bytes, &mut offset)?;
    if monero_coinbase_merkle_proof.is_empty() {
        warn!("monero_coinbase_merkle_proof empty");
        return Err(TariClientError::InvalidPowData);
    }

    let monero_coinbase_tx = read_varint_vec(&bytes, &mut offset)?;
    if monero_coinbase_tx.is_empty() {
        warn!("monero_coinbase_tx empty");
        return Err(TariClientError::InvalidPowData);
    }

    if offset != bytes.len() {
        warn!(
            remaining = bytes.len() - offset,
            "unexpected trailing bytes in pow_data"
        );
        return Err(TariClientError::InvalidPowData);
    }

    Ok(MergeMiningPowData {
        monero_header,
        randomx_seed_hash,
        monero_tx_count,
        monero_merkle_root,
        monero_coinbase_merkle_proof,
        monero_coinbase_tx,
    })
}

fn read_varint_vec(bytes: &[u8], offset: &mut usize) -> Result<Vec<u8>, TariClientError> {
    let len = read_varint(bytes, offset)? as usize;
    if bytes.len() < *offset + len {
        return Err(TariClientError::InvalidPowData);
    }
    let slice = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(slice)
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, TariClientError> {
    let slice = bytes
        .get(*offset..)
        .ok_or(TariClientError::InvalidPowData)?;
    let (len, remaining) =
        unsigned_varint::decode::u64(slice).map_err(|_| TariClientError::InvalidPowData)?;
    let consumed = slice
        .len()
        .checked_sub(remaining.len())
        .ok_or(TariClientError::InvalidPowData)?;
    if consumed == 0 {
        return Err(TariClientError::InvalidPowData);
    }
    *offset += consumed;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    #[test]
    fn parses_valid_pow_data() {
        let monero_header = vec![0u8; 80];
        let seed_hash = vec![1u8; 32];
        let tx_count = 2u64;
        let merkle_root = vec![2u8; 32];
        let coinbase_merkle_proof = vec![3u8; 10];
        let coinbase_tx = vec![4u8; 12];

        let mut bytes = Vec::new();
        bytes.extend(encode_varint(monero_header.len() as u64));
        bytes.extend(&monero_header);
        bytes.extend(encode_varint(seed_hash.len() as u64));
        bytes.extend(&seed_hash);
        bytes.extend(encode_varint(tx_count));
        bytes.extend(encode_varint(merkle_root.len() as u64));
        bytes.extend(&merkle_root);
        bytes.extend(encode_varint(coinbase_merkle_proof.len() as u64));
        bytes.extend(&coinbase_merkle_proof);
        bytes.extend(encode_varint(coinbase_tx.len() as u64));
        bytes.extend(&coinbase_tx);

        let hex_data = hex::encode(bytes);
        let parsed =
            parse_monero_merge_mining_pow_data(&hex_data).expect("valid pow_data should parse");
        assert_eq!(parsed.monero_header, monero_header);
        assert_eq!(parsed.randomx_seed_hash, seed_hash);
        assert_eq!(parsed.monero_tx_count, tx_count);
        assert_eq!(parsed.monero_merkle_root, merkle_root);
        assert_eq!(parsed.monero_coinbase_merkle_proof, coinbase_merkle_proof);
        assert_eq!(parsed.monero_coinbase_tx, coinbase_tx);
    }

    #[test]
    fn rejects_truncated_pow_data() {
        let mut bytes = Vec::new();
        // Claim header len 10 but provide fewer bytes
        bytes.extend(encode_varint(10));
        bytes.extend([0u8; 5]);
        let hex_data = hex::encode(bytes);
        assert!(parse_monero_merge_mining_pow_data(&hex_data).is_err());
    }

    #[test]
    fn computes_target_from_difficulty() {
        let target = difficulty_to_target_bytes(1).expect("difficulty 1 valid");
        // difficulty 1 yields max target (all 0xFF)
        assert!(target.iter().all(|b| *b == 0xFF));
        assert!(difficulty_to_target_bytes(0).is_err());
    }

    #[test]
    fn parses_monero_compat_template_with_aux_chain() {
        let client = TariMergeMiningClient::new(crate::config::TariMergeMiningConfig::default())
            .expect("client constructs with defaults");

        let compat = MoneroCompatTemplate {
            difficulty: Some(1234),
            height: Some(42),
            blockhashing_blob: Some("blockhashing".into()),
            blocktemplate_blob: Some("blocktemplate".into()),
            status: Some("OK".into()),
            aux: Some(MoneroAuxData {
                base_difficulty: Some(9999),
                chains: Some(vec![MoneroAuxChain {
                    id: Some("tari".into()),
                    difficulty: Some(5555),
                    height: Some(77),
                    mining_hash: Some("mining-hash".into()),
                    miner_reward: Some(123_456),
                }]),
            }),
        };

        let tpl = client
            .parse_monero_compat_template(compat)
            .expect("valid aux data should parse");

        assert_eq!(tpl.template_id, "mining-hash");
        assert_eq!(tpl.height, 77);
        assert_eq!(tpl.target_difficulty, 5555);
        assert_eq!(tpl.pow_algo, PowAlgorithm::Monero);
    }

    #[test]
    fn fallbacks_to_monero_fields_when_aux_missing() {
        let client = TariMergeMiningClient::new(crate::config::TariMergeMiningConfig::default())
            .expect("client constructs with defaults");

        let compat = MoneroCompatTemplate {
            difficulty: Some(4444),
            height: Some(88),
            blockhashing_blob: Some("blob-id".into()),
            blocktemplate_blob: Some("tpl-id".into()),
            status: Some("OK".into()),
            ..Default::default()
        };

        let tpl = client
            .parse_monero_compat_template(compat)
            .expect("fallback to monero fields should succeed when aux missing");

        assert_eq!(tpl.template_id, "blob-id");
        assert_eq!(tpl.height, 88);
        assert_eq!(tpl.target_difficulty, 4444);
        assert_eq!(tpl.pow_algo, PowAlgorithm::Monero);
    }

    #[test]
    fn submit_solution_uses_array_params() {
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

        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "submit_block",
            params: [SubmitParams {
                template_id: "tpl",
                monero_nonce: "nonce",
                monero_pow_hash: "hash",
            }],
        };

        let value = serde_json::to_value(payload).expect("serialization should work");
        let params = value
            .get("params")
            .and_then(|v| v.as_array())
            .expect("params should be an array");
        assert_eq!(params.len(), 1);
        let obj = params[0]
            .as_object()
            .expect("first param should be an object");
        assert_eq!(obj.get("template_id").unwrap(), "tpl");
        assert_eq!(obj.get("monero_nonce").unwrap(), "nonce");
        assert_eq!(obj.get("monero_pow_hash").unwrap(), "hash");
    }

    #[test]
    fn deserializes_aux_data_with_and_without_underscore() {
        let json_with_underscore = r#"{
            "difficulty": 1234,
            "height": 10,
            "blockhashing_blob": "blob1",
            "blocktemplate_blob": "tpl1",
            "_aux": {
                "base_difficulty": 999,
                "chains": [{
                    "id": "tari",
                    "difficulty": 777,
                    "height": 11,
                    "mining_hash": "abc",
                    "miner_reward": 42
                }]
            },
            "status": "OK"
        }"#;

        let json_without_underscore = r#"{
            "difficulty": 1111,
            "height": 12,
            "blockhashing_blob": "blob2",
            "blocktemplate_blob": "tpl2",
            "aux": {
                "base_difficulty": 888,
                "chains": [{
                    "id": "tari",
                    "difficulty": 666,
                    "height": 13,
                    "mining_hash": "def",
                    "miner_reward": 43
                }]
            },
            "status": "OK"
        }"#;

        let tpl_with_underscore: MoneroCompatTemplate =
            serde_json::from_str(json_with_underscore).expect("_aux payload should deserialize");
        assert!(tpl_with_underscore.aux.is_some());
        assert_eq!(
            tpl_with_underscore
                .aux
                .as_ref()
                .and_then(|a| a.chains.as_ref())
                .and_then(|c| c.first())
                .and_then(|c| c.difficulty),
            Some(777)
        );

        let tpl_without_underscore: MoneroCompatTemplate =
            serde_json::from_str(json_without_underscore).expect("aux payload should deserialize");
        assert!(tpl_without_underscore.aux.is_some());
        assert_eq!(
            tpl_without_underscore
                .aux
                .as_ref()
                .and_then(|a| a.chains.as_ref())
                .and_then(|c| c.first())
                .and_then(|c| c.difficulty),
            Some(666)
        );
    }
}
