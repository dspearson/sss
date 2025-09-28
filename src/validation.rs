use crate::error::Result;
use crate::validation_error;
use std::path::{Path, PathBuf};

/// Security constants for input validation
pub const MAX_USERNAME_LENGTH: usize = 255;
pub const MAX_KEY_ID_LENGTH: usize = 64;
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_ALIAS_NAME_LENGTH: usize = 64;

/// Validate and canonicalize a file path to prevent path traversal attacks
pub fn validate_file_path(file_path: &str) -> Result<PathBuf> {
    // Check length to prevent DoS
    if file_path.len() > MAX_PATH_LENGTH {
        return Err(validation_error!(
            "File path too long: {} characters (max: {})",
            file_path.len(),
            MAX_PATH_LENGTH
        ));
    }

    let path = Path::new(file_path);

    // Check for path traversal patterns
    if file_path.contains("..") {
        return Err(validation_error!(
            "Path contains '..' which is not allowed for security reasons"
        ));
    }

    // Check for current directory reference
    if file_path == "." {
        return Err(validation_error!("Current directory reference '.' is not allowed"));
    }

    // Check for absolute paths outside current working directory
    if path.is_absolute() {
        return Err(validation_error!(
            "Absolute paths are not allowed for security reasons"
        ));
    }

    // Check for null bytes
    if file_path.contains('\0') {
        return Err(validation_error!("Path contains null bytes"));
    }

    // Check for control characters
    if file_path.chars().any(|c| c.is_control() && c != '\t') {
        return Err(validation_error!("Path contains invalid control characters"));
    }

    // Canonicalize the path to resolve any remaining issues
    let current_dir = std::env::current_dir()
        .map_err(|e| validation_error!("Failed to get current directory: {}", e))?;

    let full_path = current_dir.join(path);
    let canonical_path = full_path.canonicalize().unwrap_or(full_path); // Allow non-existent files

    // Ensure the canonical path is still within the current directory
    if !canonical_path.starts_with(&current_dir) {
        return Err(validation_error!(
            "File path escapes current directory (security violation)"
        ));
    }

    Ok(canonical_path)
}

/// Validate a username for security and consistency
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(validation_error!("Username cannot be empty"));
    }

    if username.len() > MAX_USERNAME_LENGTH {
        return Err(validation_error!(
            "Username too long: {} characters (max: {})",
            username.len(),
            MAX_USERNAME_LENGTH
        ));
    }

    // Check for invalid characters
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(validation_error!(
            "Username contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed"
        ));
    }

    // Prevent leading/trailing dots or hyphens
    if username.starts_with('.') || username.starts_with('-') ||
       username.ends_with('.') || username.ends_with('-') {
        return Err(validation_error!(
            "Username cannot start or end with dots or hyphens"
        ));
    }

    // Prevent reserved names
    const RESERVED_NAMES: &[&str] = &[
        "root", "admin", "administrator", "system", "daemon", "nobody",
        "null", "void", "test", "guest", "anonymous"
    ];

    if RESERVED_NAMES.contains(&username.to_lowercase().as_str()) {
        return Err(validation_error!("Username '{}' is reserved", username));
    }

    Ok(())
}

/// Validate a key ID for consistency
pub fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() {
        return Err(validation_error!("Key ID cannot be empty"));
    }

    if key_id.len() > MAX_KEY_ID_LENGTH {
        return Err(validation_error!(
            "Key ID too long: {} characters (max: {})",
            key_id.len(),
            MAX_KEY_ID_LENGTH
        ));
    }

    // Key IDs should be hexadecimal
    if !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(validation_error!(
            "Key ID contains invalid characters. Only hexadecimal characters are allowed"
        ));
    }

    Ok(())
}

/// Validate an alias name
pub fn validate_alias_name(alias: &str) -> Result<()> {
    if alias.is_empty() {
        return Err(validation_error!("Alias name cannot be empty"));
    }

    if alias.len() > MAX_ALIAS_NAME_LENGTH {
        return Err(validation_error!(
            "Alias name too long: {} characters (max: {})",
            alias.len(),
            MAX_ALIAS_NAME_LENGTH
        ));
    }

    // Similar rules to username but more restrictive
    if !alias.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(validation_error!(
            "Alias name contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed"
        ));
    }

    if alias.starts_with('-') || alias.ends_with('-') {
        return Err(validation_error!("Alias name cannot start or end with hyphens"));
    }

    Ok(())
}

/// Validate Base64 input for security
pub fn validate_base64(input: &str, max_length: usize) -> Result<()> {
    if input.is_empty() {
        return Err(validation_error!("Base64 input cannot be empty"));
    }

    if input.len() > max_length {
        return Err(validation_error!(
            "Base64 input too long: {} characters (max: {})",
            input.len(),
            max_length
        ));
    }

    // Check for valid Base64 characters
    if !input.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        return Err(validation_error!("Invalid characters in Base64 input"));
    }

    // Check padding
    let padding_count = input.chars().rev().take_while(|&c| c == '=').count();
    if padding_count > 2 {
        return Err(validation_error!("Invalid Base64 padding"));
    }

    // Check that padding only appears at the end
    if let Some(first_padding) = input.find('=') {
        let expected_padding_start = input.len() - padding_count;
        if first_padding != expected_padding_start {
            return Err(validation_error!("Invalid Base64 padding position"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("user.name").is_ok());

        // Invalid usernames
        assert!(validate_username("").is_err());
        assert!(validate_username("user@domain").is_err());
        assert!(validate_username(".invalid").is_err());
        assert!(validate_username("invalid.").is_err());
        assert!(validate_username("-invalid").is_err());
        assert!(validate_username("invalid-").is_err());
        assert!(validate_username("root").is_err());
        assert!(validate_username("admin").is_err());
    }

    #[test]
    fn test_validate_key_id() {
        // Valid key IDs
        assert!(validate_key_id("abc123").is_ok());
        assert!(validate_key_id("deadbeef").is_ok());
        assert!(validate_key_id("123ABC").is_ok());

        // Invalid key IDs
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("invalid-key").is_err());
        assert!(validate_key_id("key@123").is_err());
    }

    #[test]
    fn test_validate_alias_name() {
        // Valid aliases
        assert!(validate_alias_name("prod").is_ok());
        assert!(validate_alias_name("dev_env").is_ok());
        assert!(validate_alias_name("test-user").is_ok());

        // Invalid aliases
        assert!(validate_alias_name("").is_err());
        assert!(validate_alias_name("invalid.alias").is_err());
        assert!(validate_alias_name("-invalid").is_err());
        assert!(validate_alias_name("invalid-").is_err());
    }

    #[test]
    fn test_validate_base64() {
        // Valid Base64
        assert!(validate_base64("SGVsbG8=", 100).is_ok());
        assert!(validate_base64("SGVsbG93b3JsZA==", 100).is_ok());

        // Invalid Base64
        assert!(validate_base64("", 100).is_err());
        assert!(validate_base64("Invalid@Base64", 100).is_err());
        assert!(validate_base64("SGVsbG8===", 100).is_err()); // Too much padding
        assert!(validate_base64("SGVsbG8=invalid", 100).is_err()); // Invalid characters after padding
    }

    #[test]
    fn test_validate_file_path() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Change to temp directory for testing
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_path).unwrap();

        // Valid paths
        assert!(validate_file_path("test.txt").is_ok());
        assert!(validate_file_path("subdir/test.txt").is_ok());

        // Invalid paths
        assert!(validate_file_path("../test.txt").is_err());
        assert!(validate_file_path("/absolute/path").is_err());
        assert!(validate_file_path(".").is_err());

        // Restore original directory
        std::env::set_current_dir(original_dir).unwrap();
    }
}