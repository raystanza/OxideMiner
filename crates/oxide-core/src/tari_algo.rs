// OxideMiner/crates/oxide-core/src/tari_algo.rs

use crate::stratum::PoolJob;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{fmt, str::FromStr, sync::Arc};

#[cfg(feature = "randomx")]
use crate::worker::{create_vm_for_dataset, ensure_fullmem_dataset, hash, Vm};

/// Supported Tari proof-of-work algorithms.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TariAlgorithm {
    /// RandomX hashing (legacy/default)
    RandomX,
    /// SHA3-family hashing (placeholder for Tari SHA3x)
    Sha3x,
}

impl fmt::Display for TariAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TariAlgorithm::RandomX => write!(f, "randomx"),
            TariAlgorithm::Sha3x => write!(f, "sha3x"),
        }
    }
}

impl TariAlgorithm {
    pub fn default_randomx() -> Self {
        TariAlgorithm::RandomX
    }
}

impl FromStr for TariAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "randomx" | "rx" => Ok(TariAlgorithm::RandomX),
            "sha3x" | "sha3" => Ok(TariAlgorithm::Sha3x),
            other => Err(anyhow!("unsupported Tari algorithm: {other}")),
        }
    }
}

/// Strategy for hashing Tari headers.
pub trait TariHashAlgorithm: Send {
    /// Prepare algorithm-specific state for a new job.
    fn prepare_for_job(&mut self, job: &PoolJob, worker_count: usize) -> Result<()>;

    /// Hash the provided header bytes and return a 32-byte digest.
    fn hash_header(&mut self, header_bytes: &[u8]) -> [u8; 32];
}

/// Factory for producing Tari hashers for worker threads.
pub trait TariHasherFactory: Send + Sync {
    fn create(&self) -> Result<Box<dyn TariHashAlgorithm>>;
}

/// SHA3x placeholder implementation using SHA3-256.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3xTariHash;

impl TariHashAlgorithm for Sha3xTariHash {
    fn prepare_for_job(&mut self, _job: &PoolJob, _worker_count: usize) -> Result<()> {
        Ok(())
    }

    fn hash_header(&mut self, header_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(header_bytes);
        hasher.finalize().into()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha3xHasherFactory;

impl TariHasherFactory for Sha3xHasherFactory {
    fn create(&self) -> Result<Box<dyn TariHashAlgorithm>> {
        Ok(Box::new(Sha3xTariHash))
    }
}

/// RandomX-backed Tari hashing implementation.
#[cfg(feature = "randomx")]
pub struct RandomXTariHash {
    vm: Option<Vm>,
    current_seed: Option<Vec<u8>>,
}

#[cfg(feature = "randomx")]
impl RandomXTariHash {
    pub fn new() -> Self {
        Self {
            vm: None,
            current_seed: None,
        }
    }
}

#[cfg(feature = "randomx")]
impl TariHashAlgorithm for RandomXTariHash {
    fn prepare_for_job(&mut self, job: &PoolJob, worker_count: usize) -> Result<()> {
        let seed_hex = job
            .seed_hash
            .as_deref()
            .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let mut seed_bytes = hex::decode(seed_hex).unwrap_or_default();
        if seed_bytes.len() != 32 {
            seed_bytes.resize(32, 0);
        }

        if self.current_seed.as_deref() != Some(seed_bytes.as_slice()) {
            let (cache, dataset) = ensure_fullmem_dataset(&seed_bytes, worker_count as u32)?;
            self.vm = Some(create_vm_for_dataset(&cache, &dataset, None)?);
            self.current_seed = Some(seed_bytes);
        }

        Ok(())
    }

    fn hash_header(&mut self, header_bytes: &[u8]) -> [u8; 32] {
        let vm = self
            .vm
            .as_ref()
            .expect("RandomXTariHash::prepare_for_job must be called first");
        hash(vm, header_bytes)
    }
}

#[cfg(feature = "randomx")]
#[derive(Debug, Clone, Copy)]
pub struct RandomXTariHasherFactory;

#[cfg(feature = "randomx")]
impl TariHasherFactory for RandomXTariHasherFactory {
    fn create(&self) -> Result<Box<dyn TariHashAlgorithm>> {
        Ok(Box::new(RandomXTariHash::new()))
    }
}

/// Build a Tari hasher factory for the requested algorithm.
pub fn make_tari_hasher_factory(
    algo: TariAlgorithm,
    worker_count: usize,
) -> Result<Arc<dyn TariHasherFactory>> {
    let _ = worker_count;
    match algo {
        TariAlgorithm::Sha3x => Ok(Arc::new(Sha3xHasherFactory)),
        TariAlgorithm::RandomX => {
            #[cfg(feature = "randomx")]
            {
                Ok(Arc::new(RandomXTariHasherFactory))
            }
            #[cfg(not(feature = "randomx"))]
            {
                let _ = worker_count;
                Err(anyhow!("RandomX support not compiled in"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tari_algorithm_parse_round_trip() {
        assert_eq!(
            "randomx".parse::<TariAlgorithm>().unwrap(),
            TariAlgorithm::RandomX
        );
        assert_eq!(
            "RaNdOmX".parse::<TariAlgorithm>().unwrap(),
            TariAlgorithm::RandomX
        );
        assert_eq!(
            "sha3x".parse::<TariAlgorithm>().unwrap(),
            TariAlgorithm::Sha3x
        );
        assert_eq!(
            "SHA3X".parse::<TariAlgorithm>().unwrap(),
            TariAlgorithm::Sha3x
        );
        assert!("unknown".parse::<TariAlgorithm>().is_err());
    }

    #[test]
    fn sha3x_hash_matches_vector() {
        let mut hasher = Sha3xTariHash::default();
        hasher
            .prepare_for_job(
                &PoolJob {
                    job_id: "test".into(),
                    blob: String::new(),
                    target: String::new(),
                    seed_hash: None,
                    height: None,
                    algo: None,
                    target_u32: None,
                },
                1,
            )
            .unwrap();
        let digest = hasher.hash_header(b"abc");
        assert_eq!(
            hex::encode(digest),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[cfg(feature = "randomx")]
    #[test]
    fn randomx_and_sha3x_differ() {
        let mut rx_hasher = RandomXTariHash::new();
        let job = PoolJob {
            job_id: "test".into(),
            blob: String::new(),
            target: String::new(),
            seed_hash: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ),
            height: None,
            algo: None,
            target_u32: None,
        };
        rx_hasher.prepare_for_job(&job, 1).unwrap();

        let mut sha_hasher = Sha3xTariHash::default();
        sha_hasher.prepare_for_job(&job, 1).unwrap();

        let header = vec![0u8; 64];
        let rx_hash = rx_hasher.hash_header(&header);
        let sha_hash = sha_hasher.hash_header(&header);
        assert_ne!(rx_hash, sha_hash);
    }
}
