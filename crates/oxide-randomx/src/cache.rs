//! RandomX cache generation and access.

use crate::argon2d;
use crate::config::RandomXConfig;
use crate::errors::{RandomXError, Result};
use crate::superscalar::SuperscalarProgramSet;

/// Precomputed cache derived from a RandomX key.
///
/// This cache backs light-mode hashing and dataset generation.
pub struct RandomXCache {
    blocks: Vec<argon2::Block>,
    superscalar: SuperscalarProgramSet,
}

impl RandomXCache {
    /// Build a cache for the provided key and configuration.
    ///
    /// Key length must be <= 60 bytes per RandomX spec.
    pub fn new(key: &[u8], cfg: &RandomXConfig) -> Result<Self> {
        if key.len() > 60 {
            return Err(RandomXError::InvalidKeyLength { len: key.len() });
        }
        cfg.validate()?;
        let blocks = argon2d::fill_memory(key, cfg)?;
        let superscalar = SuperscalarProgramSet::generate(key, cfg);
        Ok(Self {
            blocks,
            superscalar,
        })
    }

    pub(crate) fn cache_item_slice(&self, index: usize) -> &[u64] {
        const ITEMS_PER_BLOCK: usize = 16;
        const ITEM_MASK: usize = ITEMS_PER_BLOCK - 1;
        const WORDS_PER_ITEM: usize = 8;
        let block_index = index >> 4;
        let item_index = index & ITEM_MASK;
        let word_index = item_index * WORDS_PER_ITEM;
        let block = &self.blocks[block_index];
        &block.as_ref()[word_index..word_index + 8]
    }

    pub(crate) fn cache_item_count(&self) -> usize {
        self.blocks.len() * 16
    }

    pub(crate) fn superscalar_programs(&self) -> &SuperscalarProgramSet {
        &self.superscalar
    }
}

#[cfg(test)]
impl RandomXCache {
    #[cfg_attr(miri, allow(dead_code))]
    pub(crate) fn new_dummy(cfg: &RandomXConfig) -> Self {
        let blocks = vec![argon2::Block::default(); 1];
        let superscalar = SuperscalarProgramSet::generate(b"dummy", cfg);
        Self {
            blocks,
            superscalar,
        }
    }
}
