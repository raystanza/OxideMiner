//! RandomX constants derived from docs/randomx-refs/specs.md §1 and §5.

/// Argon2 memory size in KiB.
pub const RANDOMX_ARGON_MEMORY: u32 = 262_144;
/// Argon2 iteration count.
pub const RANDOMX_ARGON_ITERATIONS: u32 = 3;
/// Argon2 lane count.
pub const RANDOMX_ARGON_LANES: u32 = 1;
/// Argon2 salt string used by RandomX.
pub const RANDOMX_ARGON_SALT: &[u8] = b"RandomX\x03";

/// Number of cache accesses per hash.
pub const RANDOMX_CACHE_ACCESSES: u32 = 8;
/// Superscalar program latency target.
pub const RANDOMX_SUPERSCALAR_LATENCY: u32 = 170;
/// Base dataset size in bytes.
pub const RANDOMX_DATASET_BASE_SIZE: u64 = 2_147_483_648;
/// Extra dataset size in bytes.
pub const RANDOMX_DATASET_EXTRA_SIZE: u64 = 33_554_368;
/// Number of instructions per program.
pub const RANDOMX_PROGRAM_SIZE: u32 = 256;
/// Number of iterations per program.
pub const RANDOMX_PROGRAM_ITERATIONS: u32 = 2_048;
/// Number of programs per hash.
pub const RANDOMX_PROGRAM_COUNT: u32 = 8;
/// Jump bit count for control-flow.
pub const RANDOMX_JUMP_BITS: u32 = 8;
/// Jump offset for control-flow.
pub const RANDOMX_JUMP_OFFSET: u32 = 8;
/// L3 scratchpad size in bytes.
pub const RANDOMX_SCRATCHPAD_L3: usize = 2_097_152;
/// L2 scratchpad size in bytes.
pub const RANDOMX_SCRATCHPAD_L2: usize = 262_144;
/// L1 scratchpad size in bytes.
pub const RANDOMX_SCRATCHPAD_L1: usize = 16_384;

// Instruction frequencies from docs/randomx-refs/specs.md §5 (Tables 5.2.1-5.5.1).
/// Frequency for `IADD_RS`.
pub const FREQ_IADD_RS: u8 = 16;
/// Frequency for `IADD_M`.
pub const FREQ_IADD_M: u8 = 7;
/// Frequency for `ISUB_R`.
pub const FREQ_ISUB_R: u8 = 16;
/// Frequency for `ISUB_M`.
pub const FREQ_ISUB_M: u8 = 7;
/// Frequency for `IMUL_R`.
pub const FREQ_IMUL_R: u8 = 16;
/// Frequency for `IMUL_M`.
pub const FREQ_IMUL_M: u8 = 4;
/// Frequency for `IMULH_R`.
pub const FREQ_IMULH_R: u8 = 4;
/// Frequency for `IMULH_M`.
pub const FREQ_IMULH_M: u8 = 1;
/// Frequency for `ISMULH_R`.
pub const FREQ_ISMULH_R: u8 = 4;
/// Frequency for `ISMULH_M`.
pub const FREQ_ISMULH_M: u8 = 1;
/// Frequency for `IMUL_RCP`.
pub const FREQ_IMUL_RCP: u8 = 8;
/// Frequency for `INEG_R`.
pub const FREQ_INEG_R: u8 = 2;
/// Frequency for `IXOR_R`.
pub const FREQ_IXOR_R: u8 = 15;
/// Frequency for `IXOR_M`.
pub const FREQ_IXOR_M: u8 = 5;
/// Frequency for `IROR_R`.
pub const FREQ_IROR_R: u8 = 8;
/// Frequency for `IROL_R`.
pub const FREQ_IROL_R: u8 = 2;
/// Frequency for `ISWAP_R`.
pub const FREQ_ISWAP_R: u8 = 4;

/// Frequency for `FSWAP_R`.
pub const FREQ_FSWAP_R: u8 = 4;
/// Frequency for `FADD_R`.
pub const FREQ_FADD_R: u8 = 16;
/// Frequency for `FADD_M`.
pub const FREQ_FADD_M: u8 = 5;
/// Frequency for `FSUB_R`.
pub const FREQ_FSUB_R: u8 = 16;
/// Frequency for `FSUB_M`.
pub const FREQ_FSUB_M: u8 = 5;
/// Frequency for `FSCAL_R`.
pub const FREQ_FSCAL_R: u8 = 6;
/// Frequency for `FMUL_R`.
pub const FREQ_FMUL_R: u8 = 32;
/// Frequency for `FDIV_M`.
pub const FREQ_FDIV_M: u8 = 4;
/// Frequency for `FSQRT_R`.
pub const FREQ_FSQRT_R: u8 = 6;

/// Frequency for `CFROUND`.
pub const FREQ_CFROUND: u8 = 1;
/// Frequency for `CBRANCH`.
pub const FREQ_CBRANCH: u8 = 25;

/// Frequency for `ISTORE`.
pub const FREQ_ISTORE: u8 = 16;
