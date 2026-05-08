//! Error handling helper functions to reduce code duplication
//!
//! This module provides common error handling patterns used throughout the SSS codebase
//! to maintain consistency and reduce repetitive error conversion code.
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};
use std::path::Path;

/// Convert bytes to UTF-8 string with context
///
/// # Examples
///
/// ```ignore
/// use sss::error_helpers::utf8_from_bytes;
///
/// let bytes = vec![72, 101, 108, 108, 111];
/// let result = utf8_from_bytes(bytes, "greeting");
/// assert!(result.is_ok());
/// assert_eq!(result.unwrap(), "Hello");
/// ```
pub fn utf8_from_bytes(bytes: Vec<u8>, context: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|e| anyhow!("Invalid UTF-8 in {context}: {e}"))
}

/// Read file to string with typed error message
///
/// # Examples
///
/// ```ignore
/// use sss::error_helpers::read_file_to_string;
/// use std::path::Path;
///
/// let content = read_file_to_string(Path::new("config.toml"), "config");
/// ```
pub fn read_file_to_string(path: &Path, file_type: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read {} file {}: {}", file_type, path.display(), e))
}

/// Decode base64 with typed error message
///
/// # Examples
///
/// ```ignore
/// use sss::error_helpers::decode_base64;
///
/// let decoded = decode_base64("SGVsbG8=", "greeting");
/// assert!(decoded.is_ok());
/// ```
pub fn decode_base64(encoded: &str, data_type: &str) -> Result<Vec<u8>> {
    use base64::prelude::*;
    BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| anyhow!("Failed to decode base64 {data_type}: {e}"))
}

/// Create user not found error
///
/// # Examples
///
/// ```ignore
/// use sss::error_helpers::user_not_found_error;
///
/// let err = user_not_found_error("alice");
/// assert_eq!(err.to_string(), "User 'alice' not found in project");
/// ```
#[must_use]
pub fn user_not_found_error(username: &str) -> anyhow::Error {
    anyhow!("User '{username}' not found in project")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_from_bytes() {
        let bytes = vec![72, 101, 108, 108, 111]; // "Hello"
        let result = utf8_from_bytes(bytes, "test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello");
    }

    #[test]
    fn test_utf8_from_bytes_invalid() {
        let bytes = vec![0xFF, 0xFE]; // Invalid UTF-8
        let result = utf8_from_bytes(bytes, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid UTF-8"));
    }

    #[test]
    fn test_decode_base64() {
        let result = decode_base64("SGVsbG8=", "greeting");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_decode_base64_invalid() {
        let result = decode_base64("invalid!@#", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_user_not_found_error() {
        let err = user_not_found_error("alice");
        assert_eq!(err.to_string(), "User 'alice' not found in project");
    }
}
