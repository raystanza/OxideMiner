//! Error types for RandomX operations.

use core::fmt;

/// Error type returned by RandomX operations.
#[derive(Debug)]
pub enum RandomXError {
    /// Provided key length is outside the supported range.
    InvalidKeyLength { len: usize },
    /// Configuration values are invalid or outside permitted bounds.
    InvalidConfig(&'static str),
    /// Configuration requested settings that are marked as unsafe.
    UnsafeConfig(&'static str),
    /// The requested operation is unsupported on this platform/configuration.
    Unsupported(&'static str),
    /// A memory allocation failed.
    AllocationFailed(&'static str),
    /// A caller-provided argument was invalid.
    InvalidArgument(&'static str),
}

/// Convenient result alias for RandomX operations.
pub type Result<T> = core::result::Result<T, RandomXError>;

impl fmt::Display for RandomXError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RandomXError::InvalidKeyLength { len } => {
                write!(f, "invalid key length: {}", len)
            }
            RandomXError::InvalidConfig(reason) => write!(f, "invalid config: {}", reason),
            RandomXError::UnsafeConfig(reason) => write!(f, "unsafe config: {}", reason),
            RandomXError::Unsupported(reason) => write!(f, "unsupported: {}", reason),
            RandomXError::AllocationFailed(reason) => write!(f, "allocation failed: {}", reason),
            RandomXError::InvalidArgument(reason) => write!(f, "invalid argument: {}", reason),
        }
    }
}

impl std::error::Error for RandomXError {}
