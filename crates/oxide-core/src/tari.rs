// OxideMiner/crates/oxide-core/src/tari.rs

use crate::config::TariMergeMiningConfig;
use hex::FromHex;
use monero::{consensus, Block};
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
    /// Monero block template blob returned by the proxy (hex-encoded). Required to reconstruct a
    /// full Monero block with the found nonce for Monero-compatible `submit_block` (RFC-0132
    /// requires the proxy to accept Monero-formatted submissions).
    pub monero_blocktemplate_blob: Option<String>,
    /// Reserved offset provided by the proxy/monerod for miner-reserved bytes. Stored for
    /// completeness; blob reconstruction relies on consensus serialization instead of manual offset
    /// patching.
    pub monero_reserved_offset: Option<u64>,
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
    #[error("missing Monero block template blob for submission")]
    MissingMoneroBlob,
    #[error("failed to encode/decode Monero block: {0}")]
    MoneroEncoding(String),
    #[error("share does not meet Tari difficulty (achieved {achieved}, target {target})")]
    InsufficientDifficulty { achieved: u64, target: u64 },
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
    // Monero difficulty reported by the proxy. This is intentionally unused for Tari difficulty
    // selection because it reflects Monero, not Tari, work. Kept for completeness when
    // deserializing Monero-compatible responses.
    #[allow(dead_code)]
    #[serde(default)]
    difficulty: Option<u64>,
    #[serde(default)]
    height: Option<u64>,
    #[serde(default)]
    template_id: Option<String>,
    #[serde(default)]
    blockhashing_blob: Option<String>,
    #[serde(default)]
    blocktemplate_blob: Option<String>,
    #[serde(default)]
    reserved_offset: Option<u64>,
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
    template_id: Option<String>,
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
    warned_missing_tari_chain: Arc<AtomicBool>,
}

impl TariMergeMiningClient {
    pub fn new(config: TariMergeMiningConfig) -> anyhow::Result<Self> {
        let timeout = Duration::from_secs(config.request_timeout_secs.max(1));
        let backoff = Duration::from_secs(config.backoff_secs.max(1));
        let http = reqwest::Client::builder().timeout(timeout).build()?;

        let prefer_monero_compat = config.monero_wallet_address.is_some();

        Ok(Self {
            http,
            base_url: config.proxy_url,
            backoff,
            monero_wallet_address: config.monero_wallet_address,
            prefer_monero_compat: Arc::new(AtomicBool::new(prefer_monero_compat)),
            warned_direct_unavailable: Arc::new(AtomicBool::new(false)),
            warned_missing_aux: Arc::new(AtomicBool::new(false)),
            warned_missing_tari_chain: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Fetches a merge-mining template constrained to `pow_algo = Monero` (RFC-0131 §Merge
    /// Mining). Validates that the returned template is merge-mineable and contains PoW data.
    pub async fn fetch_template(&self) -> Result<MergeMiningTemplate, TariClientError> {
        if self.prefer_monero_compat.load(Ordering::Relaxed) {
            return self.fetch_template_monero_compat().await;
        }

        match self.fetch_template_direct().await {
            Ok(tpl) => {
                // Successful Tari path: ensure we don't unnecessarily stick to the compat flow.
                self.prefer_monero_compat.store(false, Ordering::Relaxed);
                Ok(tpl)
            }
            Err(TariClientError::Proxy(msg)) if is_method_not_found(&msg) => {
                // Some merge-mining proxies expose only the Monero-compatible surface; fall back
                // when the Tari JSON-RPC method is unavailable.
                self.log_direct_method_unavailable();
                self.prefer_monero_compat.store(true, Ordering::Relaxed);
                if self.monero_wallet_address.is_some() {
                    self.fetch_template_monero_compat().await
                } else {
                    Err(TariClientError::Proxy(msg))
                }
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
            monero_blocktemplate_blob: None,
            monero_reserved_offset: None,
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
        let aux = result.aux.ok_or_else(|| {
            self.log_missing_aux_once();
            TariClientError::MissingAuxData
        })?;

        let chains = aux.chains.unwrap_or_default();
        let chain = select_tari_chain(&chains).ok_or_else(|| {
            self.log_missing_tari_chain_once(&chains);
            TariClientError::MissingAuxData
        })?;

        let miner_reward = chain.miner_reward;

        // Prefer explicit template IDs from aux/compat, then fall back to mining_hash and
        // generic Monero fields. This makes use of both MoneroAuxChain::template_id and
        // MoneroCompatTemplate::template_id so they’re no longer “dead” fields.
        let template_id = chain
            .template_id
            .as_ref()
            .or_else(|| chain.mining_hash.as_ref())
            .or_else(|| result.template_id.as_ref())
            .or_else(|| result.blockhashing_blob.as_ref())
            .or_else(|| result.blocktemplate_blob.as_ref())
            .cloned()
            .unwrap_or_else(|| "tari-template".to_string());

        let target_difficulty = chain
            .difficulty
            .or(aux.base_difficulty)
            .ok_or_else(|| TariClientError::InvalidDifficulty)?;

        let height = chain.height.or(result.height).unwrap_or_default();
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
            monero_blocktemplate_blob: result.blocktemplate_blob,
            monero_reserved_offset: result.reserved_offset,
        })
    }

    fn log_missing_tari_chain_once(&self, chains: &[MoneroAuxChain]) {
        if self.warned_missing_tari_chain.swap(true, Ordering::Relaxed) {
            return;
        }

        let ids: Vec<String> = chains.iter().filter_map(|c| c.id.clone()).collect();

        if ids.is_empty() {
            warn!("merge-mining proxy response contained no aux chains under _aux.chains");
        } else {
            warn!(
                ?ids,
                "merge-mining proxy response missing Tari aux chain id (expected one of: tari/xtr)"
            );
        }
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
        monero_blob: Option<&str>,
    ) -> Result<(), TariClientError> {
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

        debug!(
            template_id = %template.template_id,
            monero_nonce = monero_nonce_hex,
            monero_pow_hash = monero_pow_hash,
            "submitting merge-mined block via proxy",
        );

        // Validate the share against the Tari target locally so we only submit work that the
        // merge-mining proxy/base node can plausibly accept. Tari difficulty/target semantics use
        // big-endian integers (RFC-0120); Monero RandomX hashes are little-endian, so convert
        // before comparison.
        validate_tari_pow(
            monero_pow_hash,
            &template.target,
            template.target_difficulty,
        )?;

        let solved_blob = self.build_solved_monero_blob(template, monero_nonce_hex, monero_blob)?;

        // The merge-mining proxy is Monero-compatible and expects submit_block parameters to match
        // monerod: an array of hex-encoded block blobs. Tari-specific metadata (template_id,
        // pow_hash, nonce) is logged for operators but not sent as named fields to avoid `Invalid
        // params` errors from the proxy JSON-RPC layer.
        let payload = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "submit_block",
            params: vec![solved_blob],
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

    fn build_solved_monero_blob(
        &self,
        template: &MergeMiningTemplate,
        nonce_hex: &str,
        fallback_blob: Option<&str>,
    ) -> Result<String, TariClientError> {
        let blob_hex = if let Some(blob) = template.monero_blocktemplate_blob.as_deref() {
            blob
        } else if let Some(blob) = fallback_blob {
            debug!(
                template_id = %template.template_id,
                "using Monero pool blob as fallback for merge-mined submission"
            );
            blob
        } else {
            return Err(TariClientError::MissingMoneroBlob);
        };

        let mut blob_bytes =
            Vec::from_hex(blob_hex).map_err(|e| TariClientError::MoneroEncoding(e.to_string()))?;
        let mut block: Block = consensus::deserialize(&blob_bytes)
            .map_err(|e| TariClientError::MoneroEncoding(e.to_string()))?;

        let nonce_bytes = <[u8; 4]>::from_hex(nonce_hex)
            .map_err(|e| TariClientError::MoneroEncoding(e.to_string()))?;
        block.header.nonce = u32::from_le_bytes(nonce_bytes);

        blob_bytes = consensus::serialize(&block);
        Ok(hex::encode(blob_bytes))
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
            warn!("merge-mining proxy response missing Tari aux data");
        } else {
            debug!("merge-mining proxy response missing Tari aux data");
        }
    }
}

fn is_method_not_found(msg: &str) -> bool {
    msg.contains("Method not found") || msg.contains("Unknown monerod rpc method")
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

fn validate_tari_pow(
    monero_pow_hash: &str,
    target: &[u8; 32],
    target_difficulty: u64,
) -> Result<u64, TariClientError> {
    let pow_hash_bytes: [u8; 32] = <[u8; 32]>::from_hex(monero_pow_hash)
        .map_err(|e| TariClientError::MoneroEncoding(e.to_string()))?;
    let pow_val = U256::from_big_endian(&{
        let mut be = pow_hash_bytes;
        be.reverse();
        be
    });
    if pow_val.is_zero() {
        return Err(TariClientError::InvalidPowData);
    }

    let target_val = U256::from_big_endian(target);
    let achieved = U256::MAX
        .checked_div(pow_val)
        .unwrap_or(U256::MAX)
        .min(U256::from(u64::MAX))
        .as_u64();

    debug!(
        achieved_difficulty = achieved,
        target_difficulty, "evaluated Tari merge-mining share locally",
    );

    if pow_val > target_val {
        return Err(TariClientError::InsufficientDifficulty {
            achieved,
            target: target_difficulty,
        });
    }

    Ok(achieved)
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

fn select_tari_chain<'a>(chains: &'a [MoneroAuxChain]) -> Option<&'a MoneroAuxChain> {
    const TARI_IDS: &[&str] = &["tari", "xtr", "tari-mainnet", "tari-testnet"];

    for candidate in TARI_IDS {
        if let Some(chain) = chains.iter().find(|c| {
            c.id.as_deref()
                .map(|id| id.eq_ignore_ascii_case(candidate))
                .unwrap_or(false)
        }) {
            return Some(chain);
        }
    }

    None
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
            template_id: None,
            blockhashing_blob: Some("blockhashing".into()),
            blocktemplate_blob: Some("blocktemplate".into()),
            reserved_offset: None,
            status: Some("OK".into()),
            aux: Some(MoneroAuxData {
                base_difficulty: Some(9999),
                chains: Some(vec![MoneroAuxChain {
                    id: Some("tari".into()),
                    difficulty: Some(5555),
                    height: Some(77),
                    template_id: None,
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
        assert_eq!(
            tpl.monero_blocktemplate_blob.as_deref(),
            Some("blocktemplate")
        );
    }

    #[test]
    fn parses_monero_compat_template_with_xtr_chain_id() {
        let client = TariMergeMiningClient::new(crate::config::TariMergeMiningConfig::default())
            .expect("client constructs with defaults");

        let compat = MoneroCompatTemplate {
            blocktemplate_blob: Some("tpl".into()),
            blockhashing_blob: Some("hashing".into()),
            aux: Some(MoneroAuxData {
                base_difficulty: Some(10_000),
                chains: Some(vec![MoneroAuxChain {
                    id: Some("xtr".into()),
                    difficulty: Some(20_000),
                    height: Some(5),
                    template_id: None,
                    mining_hash: Some("aux-hash".into()),
                    miner_reward: None,
                }]),
            }),
            ..Default::default()
        };

        let tpl = client
            .parse_monero_compat_template(compat)
            .expect("xtr chain id should be accepted as Tari");

        assert_eq!(tpl.height, 5);
        assert_eq!(tpl.target_difficulty, 20_000);
        assert_eq!(tpl.template_id, "aux-hash");
        assert_eq!(tpl.monero_blocktemplate_blob.as_deref(), Some("tpl"));
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

        let err = client
            .parse_monero_compat_template(compat)
            .expect_err("missing aux data must fail for Tari merge mining");

        assert!(matches!(err, TariClientError::MissingAuxData));
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

    #[test]
    fn validates_pow_against_target() {
        let target = difficulty_to_target_bytes(1_000).expect("difficulty should convert");
        // Little-endian hash representing numeric value 1.
        let pow_hash = "01".to_string() + &"00".repeat(31);
        let achieved = validate_tari_pow(&pow_hash, &target, 1_000).expect("meets Tari target");
        assert!(achieved > 0);

        // A large hash (all 0xFF) should fail the target check.
        let err = validate_tari_pow(&"ff".repeat(32), &target, 1_000)
            .expect_err("high hash should be rejected");
        assert!(matches!(
            err,
            TariClientError::InsufficientDifficulty { .. }
        ));
    }

    #[test]
    fn rejects_compat_template_without_tari_chain() {
        let client = TariMergeMiningClient::new(crate::config::TariMergeMiningConfig::default())
            .expect("client constructs with defaults");

        let compat = MoneroCompatTemplate {
            difficulty: Some(9999),
            height: Some(42),
            aux: Some(MoneroAuxData {
                base_difficulty: Some(7777),
                chains: Some(vec![MoneroAuxChain {
                    id: Some("other".into()),
                    difficulty: Some(1234),
                    height: Some(10),
                    template_id: Some("wrong".into()),
                    mining_hash: None,
                    miner_reward: None,
                }]),
            }),
            ..Default::default()
        };

        let err = client
            .parse_monero_compat_template(compat)
            .expect_err("non-Tari aux chain should be rejected");

        assert!(matches!(err, TariClientError::MissingAuxData));
    }

    #[test]
    fn validates_pow_against_large_target() {
        let target_difficulty = 681_449_638_587u64;
        let target = difficulty_to_target_bytes(target_difficulty).expect("difficulty converts");

        // Very low numeric hash value should meet even a high difficulty target.
        let pow_hash = "01".to_string() + &"00".repeat(31);
        let achieved =
            validate_tari_pow(&pow_hash, &target, target_difficulty).expect("meets target");
        assert!(achieved >= target_difficulty);

        // A hash just above the target boundary should fail.
        let err = validate_tari_pow(&"ff".repeat(32), &target, target_difficulty)
            .expect_err("hash above target should be rejected");
        assert!(matches!(
            err,
            TariClientError::InsufficientDifficulty { .. }
        ));
    }
}
