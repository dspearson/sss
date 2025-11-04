//! Error types for marker inference
//!
//! Currently, the marker inference algorithm is designed to be infallible for valid UTF-8 input.
//! Error types are defined for potential failure cases but most operations use conservative
//! fallbacks rather than failing. Future enhancements may add validation that uses these errors.

use thiserror::Error;
use super::types::Position;

/// Errors that can occur during marker inference
///
/// Note: Current implementation rarely returns errors, preferring conservative fallbacks.
/// These variants are defined for future validation enhancements.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarkerInferenceError {
    /// Invalid UTF-8 sequence detected
    ///
    /// Note: Currently unused as Rust's &str type guarantees valid UTF-8.
    /// Could be used if we accept byte slices in the future.
    #[error("Invalid UTF-8 in input at byte {0}")]
    InvalidUtf8(usize),

    /// Malformed marker syntax that cannot be parsed
    ///
    /// Note: Currently unused as parser escapes invalid markers rather than failing.
    /// Could be used for strict validation mode.
    #[error("Malformed marker at position {0}: {1}")]
    MalformedMarker(Position, String),

    /// Binary (non-text) content detected
    ///
    /// Note: Currently unused. Could be implemented to detect null bytes or
    /// other binary content indicators.
    #[error("Binary content detected at byte {0}")]
    BinaryContent(usize),

    /// Diff computation failed
    ///
    /// Note: Currently unused as the similar crate's diff algorithm doesn't fail.
    /// Reserved for future diff implementations.
    #[error("Diff computation failed: {0}")]
    DiffError(String),

    /// Internal processing error
    ///
    /// Note: Currently unused. Reserved for unexpected internal state errors.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for marker inference operations
///
/// Note: Most operations currently return Ok(_) with warnings rather than Err(_).
/// The error handling infrastructure is in place for future validation enhancements.
pub type Result<T> = std::result::Result<T, MarkerInferenceError>;
