//! Argon2d memory filling for RandomX cache initialization.

use argon2::{Algorithm, Argon2, Block, Params, Version};

use crate::config::RandomXConfig;
use crate::errors::{RandomXError, Result};

/// Fill Argon2 blocks for the RandomX cache.
pub fn fill_memory(key: &[u8], cfg: &RandomXConfig) -> Result<Vec<Block>> {
    let params = Params::new(
        cfg.argon_memory(),
        cfg.argon_iterations(),
        cfg.argon_lanes(),
        None,
    )
    .map_err(|_| RandomXError::InvalidConfig("argon2 parameters invalid"))?;
    let block_count = params.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);

    let mut blocks = vec![Block::default(); block_count];
    argon2
        .fill_memory(key, cfg.argon_salt(), &mut blocks)
        .map_err(|_| RandomXError::InvalidConfig("argon2 fill failed"))?;

    Ok(blocks)
}
