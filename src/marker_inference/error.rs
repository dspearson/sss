//! Error types for marker inference

use thiserror::Error;
use super::types::Position;

/// Errors that can occur during marker inference
#[derive(Debug, Error)]
pub enum MarkerInferenceError {
    #[error("Invalid UTF-8 in input at byte {0}")]
    InvalidUtf8(usize),

    #[error("Malformed marker at position {0}: {1}")]
    MalformedMarker(Position, String),

    #[error("Binary content detected at byte {0}")]
    BinaryContent(usize),

    #[error("Diff computation failed: {0}")]
    DiffError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for marker inference operations
pub type Result<T> = std::result::Result<T, MarkerInferenceError>;
