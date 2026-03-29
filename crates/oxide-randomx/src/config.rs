//! RandomX configuration parameters and validation helpers.

use crate::constants;
use crate::errors::{RandomXError, Result};

/// Configuration parameters for RandomX.
#[derive(Clone, Debug)]
pub struct RandomXConfig {
    argon_memory: u32,
    argon_iterations: u32,
    argon_lanes: u32,
    argon_salt: Vec<u8>,
    cache_accesses: u32,
    superscalar_latency: u32,
    dataset_base_size: u64,
    dataset_extra_size: u64,
    program_size: u32,
    program_iterations: u32,
    program_count: u32,
    jump_bits: u32,
    jump_offset: u32,
    scratchpad_l3: usize,
    scratchpad_l2: usize,
    scratchpad_l1: usize,
    freqs: InstructionFrequencies,
}

impl Default for RandomXConfig {
    fn default() -> Self {
        Self {
            argon_memory: constants::RANDOMX_ARGON_MEMORY,
            argon_iterations: constants::RANDOMX_ARGON_ITERATIONS,
            argon_lanes: constants::RANDOMX_ARGON_LANES,
            argon_salt: constants::RANDOMX_ARGON_SALT.to_vec(),
            cache_accesses: constants::RANDOMX_CACHE_ACCESSES,
            superscalar_latency: constants::RANDOMX_SUPERSCALAR_LATENCY,
            dataset_base_size: constants::RANDOMX_DATASET_BASE_SIZE,
            dataset_extra_size: constants::RANDOMX_DATASET_EXTRA_SIZE,
            program_size: constants::RANDOMX_PROGRAM_SIZE,
            program_iterations: constants::RANDOMX_PROGRAM_ITERATIONS,
            program_count: constants::RANDOMX_PROGRAM_COUNT,
            jump_bits: constants::RANDOMX_JUMP_BITS,
            jump_offset: constants::RANDOMX_JUMP_OFFSET,
            scratchpad_l3: constants::RANDOMX_SCRATCHPAD_L3,
            scratchpad_l2: constants::RANDOMX_SCRATCHPAD_L2,
            scratchpad_l1: constants::RANDOMX_SCRATCHPAD_L1,
            freqs: InstructionFrequencies::default(),
        }
    }
}

impl RandomXConfig {
    /// Small config for tests/CI; not a production RandomX parameter set.
    pub fn test_small() -> Self {
        Self {
            argon_memory: 8,
            argon_iterations: 1,
            argon_lanes: 1,
            argon_salt: constants::RANDOMX_ARGON_SALT.to_vec(),
            cache_accesses: 2,
            superscalar_latency: 20,
            dataset_base_size: 1024,
            dataset_extra_size: 0,
            program_size: 64,
            program_iterations: 400,
            program_count: 2,
            jump_bits: constants::RANDOMX_JUMP_BITS,
            jump_offset: constants::RANDOMX_JUMP_OFFSET,
            scratchpad_l1: 64,
            scratchpad_l2: 128,
            scratchpad_l3: 256,
            freqs: InstructionFrequencies::default(),
        }
    }
}

impl RandomXConfig {
    /// Create a config with RandomX/Monero defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate that configuration parameters meet RandomX constraints.
    pub fn validate(&self) -> Result<()> {
        // docs/randomx-refs/configuration.md "Permitted values"
        if !is_power_of_two(self.argon_memory)
            || self.argon_memory < 8
            || self.argon_memory > 2_097_152
        {
            return Err(RandomXError::InvalidConfig(
                "argon memory must be power of two in range 8..=2097152",
            ));
        }
        if self.argon_iterations == 0 {
            return Err(RandomXError::InvalidConfig(
                "argon iterations must be positive",
            ));
        }
        if self.argon_lanes == 0 || self.argon_lanes > 16_777_215 {
            return Err(RandomXError::InvalidConfig(
                "argon lanes must be in range 1..=16777215",
            ));
        }
        if self.argon_salt.len() < 8 {
            return Err(RandomXError::InvalidConfig(
                "argon salt must be at least 8 bytes",
            ));
        }
        if self.cache_accesses <= 1 {
            return Err(RandomXError::InvalidConfig("cache accesses must be > 1"));
        }
        if self.superscalar_latency == 0 || self.superscalar_latency > 10_000 {
            return Err(RandomXError::InvalidConfig(
                "superscalar latency must be in range 1..=10000",
            ));
        }
        // Power-of-two invariant is relied on for dataset base masking in vm paths.
        if !is_power_of_two_u64(self.dataset_base_size)
            || self.dataset_base_size < 64
            || self.dataset_base_size > 4_294_967_296
        {
            return Err(RandomXError::InvalidConfig(
                "dataset base size must be power of two in range 64..=4294967296",
            ));
        }
        if !self.dataset_extra_size.is_multiple_of(64) {
            return Err(RandomXError::InvalidConfig(
                "dataset extra size must be divisible by 64",
            ));
        }
        if self.program_size == 0
            || !self.program_size.is_multiple_of(8)
            || self.program_size < 8
            || self.program_size > 32_768
        {
            return Err(RandomXError::InvalidConfig(
                "program size must be divisible by 8 in range 8..=32768",
            ));
        }
        if self.program_iterations == 0 {
            return Err(RandomXError::InvalidConfig(
                "program iterations must be positive",
            ));
        }
        if self.program_count == 0 {
            return Err(RandomXError::InvalidConfig(
                "program count must be positive",
            ));
        }
        if self.jump_bits == 0 {
            return Err(RandomXError::InvalidConfig("jump bits must be positive"));
        }
        if self.jump_bits + self.jump_offset > 16 {
            return Err(RandomXError::InvalidConfig(
                "jump bits + jump offset must be <= 16",
            ));
        }
        if !is_power_of_two_usize(self.scratchpad_l1) || self.scratchpad_l1 < 64 {
            return Err(RandomXError::InvalidConfig(
                "scratchpad L1 must be power of two >= 64",
            ));
        }
        if !is_power_of_two_usize(self.scratchpad_l2) || self.scratchpad_l2 < self.scratchpad_l1 {
            return Err(RandomXError::InvalidConfig(
                "scratchpad L2 must be power of two >= L1",
            ));
        }
        if !is_power_of_two_usize(self.scratchpad_l3) || self.scratchpad_l3 < self.scratchpad_l2 {
            return Err(RandomXError::InvalidConfig(
                "scratchpad L3 must be power of two >= L2",
            ));
        }
        if self.freqs.total() != 256 {
            return Err(RandomXError::InvalidConfig(
                "instruction frequencies must sum to 256",
            ));
        }

        // docs/randomx-refs/configuration.md "Unsafe configurations"
        let cache_bytes =
            (self.cache_accesses as u128) * (self.argon_memory as u128) * 1024u128 + 33_554_432u128;
        let dataset_bytes = self.dataset_base_size as u128 + self.dataset_extra_size as u128;
        if cache_bytes < dataset_bytes {
            return Err(RandomXError::UnsafeConfig(
                "memory-time tradeoff condition failed",
            ));
        }

        let writes = (128u128 + (self.program_size as u128 * self.freqs.istore as u128) / 256u128)
            * (self.program_count as u128 * self.program_iterations as u128);
        if writes < self.scratchpad_l3 as u128 {
            return Err(RandomXError::UnsafeConfig("insufficient scratchpad writes"));
        }
        if self.program_count <= 1 {
            return Err(RandomXError::UnsafeConfig("program count must be > 1"));
        }
        if self.program_size < 64 {
            return Err(RandomXError::UnsafeConfig("program size must be >= 64"));
        }
        if self.program_iterations < 400 {
            return Err(RandomXError::UnsafeConfig(
                "program iterations must be >= 400",
            ));
        }
        Ok(())
    }

    /// Total dataset size in bytes (base + extra).
    pub fn dataset_size(&self) -> u64 {
        self.dataset_base_size + self.dataset_extra_size
    }

    /// Cache size in bytes.
    pub fn cache_size_bytes(&self) -> u64 {
        self.argon_memory as u64 * 1024
    }

    /// Argon2 memory size in KiB.
    pub fn argon_memory(&self) -> u32 {
        self.argon_memory
    }

    /// Argon2 iteration count.
    pub fn argon_iterations(&self) -> u32 {
        self.argon_iterations
    }

    /// Argon2 lane count.
    pub fn argon_lanes(&self) -> u32 {
        self.argon_lanes
    }

    /// Argon2 salt bytes.
    pub fn argon_salt(&self) -> &[u8] {
        &self.argon_salt
    }

    /// Number of cache accesses per hash.
    pub fn cache_accesses(&self) -> u32 {
        self.cache_accesses
    }

    /// Superscalar program latency target.
    pub fn superscalar_latency(&self) -> u32 {
        self.superscalar_latency
    }

    /// Dataset base size in bytes.
    pub fn dataset_base_size(&self) -> u64 {
        self.dataset_base_size
    }

    /// Dataset extra size in bytes.
    pub fn dataset_extra_size(&self) -> u64 {
        self.dataset_extra_size
    }

    /// Instructions per program.
    pub fn program_size(&self) -> u32 {
        self.program_size
    }

    /// Iterations per program.
    pub fn program_iterations(&self) -> u32 {
        self.program_iterations
    }

    /// Programs per hash.
    pub fn program_count(&self) -> u32 {
        self.program_count
    }

    /// Jump bit count for control flow.
    pub fn jump_bits(&self) -> u32 {
        self.jump_bits
    }

    /// Jump offset for control flow.
    pub fn jump_offset(&self) -> u32 {
        self.jump_offset
    }

    /// L1 scratchpad size in bytes.
    pub fn scratchpad_l1(&self) -> usize {
        self.scratchpad_l1
    }

    /// L2 scratchpad size in bytes.
    pub fn scratchpad_l2(&self) -> usize {
        self.scratchpad_l2
    }

    /// L3 scratchpad size in bytes.
    pub fn scratchpad_l3(&self) -> usize {
        self.scratchpad_l3
    }

    /// Instruction frequency table.
    pub fn instruction_frequencies(&self) -> &InstructionFrequencies {
        &self.freqs
    }
}

#[cfg(feature = "unsafe-config")]
#[derive(Clone, Debug)]
/// Builder for non-default/unsafe RandomX configurations.
///
/// This API is gated behind the `unsafe-config` feature.
pub struct RandomXConfigBuilder {
    config: RandomXConfig,
}

#[cfg(feature = "unsafe-config")]
impl RandomXConfigBuilder {
    /// Create a builder initialized with default parameters.
    pub fn new() -> Self {
        Self {
            config: RandomXConfig::default(),
        }
    }

    pub fn argon_memory(mut self, value: u32) -> Self {
        self.config.argon_memory = value;
        self
    }

    pub fn argon_iterations(mut self, value: u32) -> Self {
        self.config.argon_iterations = value;
        self
    }

    pub fn argon_lanes(mut self, value: u32) -> Self {
        self.config.argon_lanes = value;
        self
    }

    pub fn argon_salt(mut self, value: Vec<u8>) -> Self {
        self.config.argon_salt = value;
        self
    }

    pub fn cache_accesses(mut self, value: u32) -> Self {
        self.config.cache_accesses = value;
        self
    }

    pub fn superscalar_latency(mut self, value: u32) -> Self {
        self.config.superscalar_latency = value;
        self
    }

    pub fn dataset_base_size(mut self, value: u64) -> Self {
        self.config.dataset_base_size = value;
        self
    }

    pub fn dataset_extra_size(mut self, value: u64) -> Self {
        self.config.dataset_extra_size = value;
        self
    }

    pub fn program_size(mut self, value: u32) -> Self {
        self.config.program_size = value;
        self
    }

    pub fn program_iterations(mut self, value: u32) -> Self {
        self.config.program_iterations = value;
        self
    }

    pub fn program_count(mut self, value: u32) -> Self {
        self.config.program_count = value;
        self
    }

    pub fn jump_bits(mut self, value: u32) -> Self {
        self.config.jump_bits = value;
        self
    }

    pub fn jump_offset(mut self, value: u32) -> Self {
        self.config.jump_offset = value;
        self
    }

    pub fn scratchpad_l1(mut self, value: usize) -> Self {
        self.config.scratchpad_l1 = value;
        self
    }

    pub fn scratchpad_l2(mut self, value: usize) -> Self {
        self.config.scratchpad_l2 = value;
        self
    }

    pub fn scratchpad_l3(mut self, value: usize) -> Self {
        self.config.scratchpad_l3 = value;
        self
    }

    pub fn instruction_frequencies(mut self, value: InstructionFrequencies) -> Self {
        self.config.freqs = value;
        self
    }

    /// Validate and build the configuration.
    pub fn build(self) -> Result<RandomXConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[derive(Clone, Debug)]
/// Instruction frequency table used by program generation.
pub struct InstructionFrequencies {
    pub iadd_rs: u8,
    pub iadd_m: u8,
    pub isub_r: u8,
    pub isub_m: u8,
    pub imul_r: u8,
    pub imul_m: u8,
    pub imulh_r: u8,
    pub imulh_m: u8,
    pub ismulh_r: u8,
    pub ismulh_m: u8,
    pub imul_rcp: u8,
    pub ineg_r: u8,
    pub ixor_r: u8,
    pub ixor_m: u8,
    pub iror_r: u8,
    pub irol_r: u8,
    pub iswap_r: u8,
    pub fswap_r: u8,
    pub fadd_r: u8,
    pub fadd_m: u8,
    pub fsub_r: u8,
    pub fsub_m: u8,
    pub fscal_r: u8,
    pub fmul_r: u8,
    pub fdiv_m: u8,
    pub fsqrt_r: u8,
    pub cfround: u8,
    pub cbranch: u8,
    pub istore: u8,
}

impl InstructionFrequencies {
    /// Sum of all instruction frequencies.
    pub fn total(&self) -> u16 {
        self.iadd_rs as u16
            + self.iadd_m as u16
            + self.isub_r as u16
            + self.isub_m as u16
            + self.imul_r as u16
            + self.imul_m as u16
            + self.imulh_r as u16
            + self.imulh_m as u16
            + self.ismulh_r as u16
            + self.ismulh_m as u16
            + self.imul_rcp as u16
            + self.ineg_r as u16
            + self.ixor_r as u16
            + self.ixor_m as u16
            + self.iror_r as u16
            + self.irol_r as u16
            + self.iswap_r as u16
            + self.fswap_r as u16
            + self.fadd_r as u16
            + self.fadd_m as u16
            + self.fsub_r as u16
            + self.fsub_m as u16
            + self.fscal_r as u16
            + self.fmul_r as u16
            + self.fdiv_m as u16
            + self.fsqrt_r as u16
            + self.cfround as u16
            + self.cbranch as u16
            + self.istore as u16
    }
}

impl Default for InstructionFrequencies {
    fn default() -> Self {
        Self {
            iadd_rs: constants::FREQ_IADD_RS,
            iadd_m: constants::FREQ_IADD_M,
            isub_r: constants::FREQ_ISUB_R,
            isub_m: constants::FREQ_ISUB_M,
            imul_r: constants::FREQ_IMUL_R,
            imul_m: constants::FREQ_IMUL_M,
            imulh_r: constants::FREQ_IMULH_R,
            imulh_m: constants::FREQ_IMULH_M,
            ismulh_r: constants::FREQ_ISMULH_R,
            ismulh_m: constants::FREQ_ISMULH_M,
            imul_rcp: constants::FREQ_IMUL_RCP,
            ineg_r: constants::FREQ_INEG_R,
            ixor_r: constants::FREQ_IXOR_R,
            ixor_m: constants::FREQ_IXOR_M,
            iror_r: constants::FREQ_IROR_R,
            irol_r: constants::FREQ_IROL_R,
            iswap_r: constants::FREQ_ISWAP_R,
            fswap_r: constants::FREQ_FSWAP_R,
            fadd_r: constants::FREQ_FADD_R,
            fadd_m: constants::FREQ_FADD_M,
            fsub_r: constants::FREQ_FSUB_R,
            fsub_m: constants::FREQ_FSUB_M,
            fscal_r: constants::FREQ_FSCAL_R,
            fmul_r: constants::FREQ_FMUL_R,
            fdiv_m: constants::FREQ_FDIV_M,
            fsqrt_r: constants::FREQ_FSQRT_R,
            cfround: constants::FREQ_CFROUND,
            cbranch: constants::FREQ_CBRANCH,
            istore: constants::FREQ_ISTORE,
        }
    }
}

fn is_power_of_two(value: u32) -> bool {
    value.is_power_of_two()
}

fn is_power_of_two_u64(value: u64) -> bool {
    value.is_power_of_two()
}

fn is_power_of_two_usize(value: usize) -> bool {
    value.is_power_of_two()
}
