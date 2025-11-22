// OxideMiner/crates/oxide-core/src/tari.rs

use crate::config::TariMergeMiningConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::warn;
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
    /// Data. This contains the Monero header + merkle data needed for validation.
    pub pow_data_hex: String,
    /// Parsed Monero merge-mining payload (length-checked against RFC-0131 §Merge Mining data
    /// ordering requirements).
    pub pow_data: MergeMiningPowData,
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

        // RFC-0120 difficulty/target conversion; difficulty must be non-zero.
        let target = difficulty_to_target_bytes(tpl.target_difficulty)?;

        let pow_data = parse_monero_merge_mining_pow_data(&tpl.header.pow.pow_data)?;

        Ok(MergeMiningTemplate {
            template_id: tpl.template_id,
            height: tpl.header.height,
            target_difficulty: tpl.target_difficulty,
            target,
            pow_algo: tpl.header.pow.pow_algo,
            pow_data_hex: tpl.header.pow.pow_data,
            pow_data,
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
}
