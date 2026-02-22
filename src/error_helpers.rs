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
/// ```
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

/// Convert bytes to UTF-8 string with simple error message
///
/// # Examples
///
/// ```
/// use sss::error_helpers::utf8_from_bytes_simple;
///
/// let bytes = vec![72, 101, 108, 108, 111];
/// assert!(utf8_from_bytes_simple(bytes).is_ok());
/// ```
pub fn utf8_from_bytes_simple(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| anyhow!("Content is not valid UTF-8"))
}

/// Read file to string with typed error message
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::read_file_to_string;
/// use std::path::Path;
///
/// let content = read_file_to_string(Path::new("config.toml"), "config");
/// ```
pub fn read_file_to_string(path: &Path, file_type: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read {} file {}: {}", file_type, path.display(), e))
}

/// Write content to file with typed error message
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::write_file;
/// use std::path::Path;
///
/// write_file(Path::new("output.txt"), "content", "output").unwrap();
/// ```
pub fn write_file(path: &Path, content: &str, file_type: &str) -> Result<()> {
    std::fs::write(path, content)
        .map_err(|e| anyhow!("Failed to write {} file {}: {}", file_type, path.display(), e))
}

/// Open file with error context
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::open_file;
/// use std::path::Path;
///
/// let file = open_file(Path::new("data.bin"));
/// ```
pub fn open_file(path: &Path) -> Result<std::fs::File> {
    std::fs::File::open(path)
        .map_err(|e| anyhow!("Failed to open file {}: {}", path.display(), e))
}

/// Read directory with error context
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::read_directory;
/// use std::path::Path;
///
/// let entries = read_directory(Path::new("/tmp"));
/// ```
pub fn read_directory(dir: &Path) -> Result<std::fs::ReadDir> {
    std::fs::read_dir(dir)
        .map_err(|e| anyhow!("Failed to read directory {}: {}", dir.display(), e))
}

/// Create directory with typed error message
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::create_directory;
/// use std::path::Path;
///
/// create_directory(Path::new("/tmp/test"), "test").unwrap();
/// ```
pub fn create_directory(path: &Path, dir_type: &str) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| anyhow!("Failed to create {dir_type} directory: {e}"))
}

/// Canonicalize path with error context
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::canonicalize_path;
/// use std::path::Path;
///
/// let canonical = canonicalize_path(Path::new("."));
/// ```
pub fn canonicalize_path(path: &Path) -> Result<std::path::PathBuf> {
    path.canonicalize()
        .map_err(|e| anyhow!("Failed to canonicalize path {}: {e}", path.display()))
}

/// Get current working directory with error context
///
/// # Examples
///
/// ```
/// use sss::error_helpers::get_current_dir;
///
/// let cwd = get_current_dir();
/// assert!(cwd.is_ok());
/// ```
pub fn get_current_dir() -> Result<std::path::PathBuf> {
    std::env::current_dir().map_err(|e| anyhow!("Failed to get current directory: {e}"))
}

/// Decode base64 with typed error message
///
/// # Examples
///
/// ```
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

/// Decode base64 for specific user with error context
///
/// # Examples
///
/// ```
/// use sss::error_helpers::decode_base64_for_user;
///
/// let decoded = decode_base64_for_user("SGVsbG8=", "key", "alice");
/// assert!(decoded.is_ok());
/// ```
pub fn decode_base64_for_user(encoded: &str, data_type: &str, username: &str) -> Result<Vec<u8>> {
    use base64::prelude::*;
    BASE64_STANDARD.decode(encoded).map_err(|e| {
        anyhow!(
            "Invalid base64 {data_type} for user '{username}': {e}"
        )
    })
}

/// Get HOME environment variable with error context
///
/// # Examples
///
/// ```
/// use sss::error_helpers::get_home_dir;
///
/// let home = get_home_dir();
/// // Result depends on environment
/// ```
pub fn get_home_dir() -> Result<String> {
    std::env::var("HOME").map_err(|_| anyhow!("HOME environment variable not set"))
}

/// Get the current username with proper precedence
///
/// Precedence order:
/// 1. `SSS_USER` environment variable (highest)
/// 2. Global config username (from user settings)
/// 3. USER/USERNAME environment variables (lowest - fallback only)
///
/// This respects the user's explicit configuration choices.
///
/// # Examples
///
/// ```no_run
/// use sss::error_helpers::get_username;
///
/// let username = get_username();
/// // Returns username based on precedence: SSS_USER > config > USER
/// ```
pub fn get_username() -> Result<String> {
    use crate::config_manager::ConfigManager;
    use crate::validation::validate_username;

    // 1. Check SSS_USER environment variable first
    if let Ok(username) = std::env::var("SSS_USER") {
        validate_username(&username)?;
        return Ok(username);
    }

    // 2. Try to load config and get default username
    if let Ok(config_manager) = ConfigManager::new()
        && let Some(username) = config_manager.get_default_username() {
            validate_username(&username)?;
            return Ok(username);
        }

    // 3. Fall back to system username (USER/USERNAME env vars)
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .map_err(|_| anyhow!("Could not determine username. Set SSS_USER environment variable or configure default username with 'sss settings username <name>'"))?;

    validate_username(&username)?;
    Ok(username)
}

/// Format a user-facing error with action guidance.
///
/// Use this to produce actionable error messages that tell the user both
/// what went wrong and what they can do to fix it.
///
/// # Examples
///
/// ```
/// use sss::error_helpers::user_error;
///
/// let err = user_error(
///     "No project configuration found",
///     "Run 'sss init' to initialise a project in the current directory",
/// );
/// assert!(err.to_string().contains("No project configuration found"));
/// assert!(err.to_string().contains("Run 'sss init'"));
/// ```
#[must_use]
pub fn user_error(what: &str, action: &str) -> anyhow::Error {
    anyhow!("{what}. {action}")
}

/// Create user not found error
///
/// # Examples
///
/// ```
/// use sss::error_helpers::user_not_found_error;
///
/// let err = user_not_found_error("alice");
/// assert_eq!(err.to_string(), "User 'alice' not found in project");
/// ```
#[must_use]
pub fn user_not_found_error(username: &str) -> anyhow::Error {
    anyhow!("User '{username}' not found in project")
}

/// Get user directories with error context
///
/// # Examples
///
/// ```
/// use sss::error_helpers::get_user_dirs;
///
/// let dirs = get_user_dirs();
/// // Result depends on platform
/// ```
pub fn get_user_dirs() -> Result<directories::UserDirs> {
    directories::UserDirs::new().ok_or_else(|| anyhow!("Could not determine user home directory"))
}

/// Get config directory with error context
///
/// # Examples
///
/// ```
/// use sss::error_helpers::get_config_dir;
///
/// let config_dir = get_config_dir();
/// // Result depends on platform
/// ```
pub fn get_config_dir() -> Result<std::path::PathBuf> {
    directories::BaseDirs::new()
        .ok_or_else(|| anyhow!("Could not determine config directory"))
        .map(|dirs| dirs.config_dir().to_path_buf())
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
    fn test_utf8_from_bytes_simple() {
        let bytes = vec![87, 111, 114, 108, 100]; // "World"
        let result = utf8_from_bytes_simple(bytes);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "World");
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
    fn test_user_error() {
        let err = user_error("Key 'mykey' not found", "Run 'sss keys list' to see available keys");
        let msg = err.to_string();
        assert!(msg.contains("Key 'mykey' not found"));
        assert!(msg.contains("Run 'sss keys list'"));
    }

    #[test]
    fn test_user_not_found_error() {
        let err = user_not_found_error("alice");
        assert_eq!(err.to_string(), "User 'alice' not found in project");
    }

    #[test]
    fn test_get_current_dir() {
        // Note: This can fail in some test environments (e.g., if CWD was deleted)
        // We just verify the function exists and returns a Result
        let _result = get_current_dir();
        // If it succeeds, verify it returns a valid path
        if let Ok(path) = get_current_dir() {
            assert!(!path.as_os_str().is_empty());
        }
    }

    #[test]
    fn test_get_username() {
        // This test depends on environment, so we just check it doesn't panic
        let _result = get_username();
    }
}
