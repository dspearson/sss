use crate::error::Result;
use crate::validation_error;
use std::path::{Path, PathBuf};

/// Security constants for input validation
pub const MAX_USERNAME_LENGTH: usize = 255;
pub const MAX_KEY_ID_LENGTH: usize = 64;

/// Validate and canonicalize a file path with minimal restrictions
///
/// This function accepts absolute paths, relative paths, and resolves symlinks.
/// No security restrictions are enforced - it's up to the client to use safely.
///
/// Processing:
/// - Null bytes rejected (filesystem limitation)
/// - Symlinks resolved for consistent behavior
pub fn validate_file_path(file_path: &str) -> Result<PathBuf> {
    // Check for null bytes (filesystem limitation)
    if file_path.contains('\0') {
        return Err(validation_error!("Path contains null bytes"));
    }

    let path = Path::new(file_path);

    // Resolve the path
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let current_dir = std::env::current_dir()
            .map_err(|e| validation_error!("Failed to get current directory: {}", e))?;
        current_dir.join(path)
    };

    // Canonicalize to resolve symlinks for consistent behavior
    let canonical_path = full_path.canonicalize().unwrap_or(full_path);

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
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(validation_error!(
            "Username contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed"
        ));
    }

    // Prevent leading/trailing dots or hyphens
    const FORBIDDEN_BOUNDARY_CHARS: &[char] = &['.', '-'];
    if FORBIDDEN_BOUNDARY_CHARS
        .iter()
        .any(|&c| username.starts_with(c) || username.ends_with(c))
    {
        return Err(validation_error!(
            "Username cannot start or end with dots or hyphens"
        ));
    }

    // Prevent reserved names
    const RESERVED_NAMES: &[&str] = &[
        "root",
        "admin",
        "administrator",
        "system",
        "daemon",
        "nobody",
        "null",
        "void",
        "test",
        "guest",
        "anonymous",
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
    if !input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
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

    // RAII guard to ensure current directory is restored after test
    struct DirGuard {
        original: std::path::PathBuf,
    }

    impl DirGuard {
        fn new() -> std::io::Result<Self> {
            Ok(Self {
                original: std::env::current_dir()?,
            })
        }
    }

    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

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

        // Create test files
        let test_file = temp_path.join("test.txt");
        std::fs::write(&test_file, "test content").unwrap();

        let subdir = temp_path.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let subdir_file = subdir.join("test.txt");
        std::fs::write(&subdir_file, "test content").unwrap();

        // Save original directory (create guard early, before any test may have changed it)
        // Use a fallback to temp_path if current_dir fails (handles tests run in deleted directories)
        let original_dir = std::env::current_dir().unwrap_or_else(|_| temp_path.to_path_buf());

        // Change to temp directory for testing
        std::env::set_current_dir(temp_path).unwrap();

        // All valid paths should work (no restrictions)
        assert!(validate_file_path("test.txt").is_ok());
        assert!(validate_file_path("subdir/test.txt").is_ok());
        assert!(validate_file_path("../").is_ok()); // Parent directories allowed
        assert!(validate_file_path("/etc/passwd").is_ok()); // Absolute paths allowed

        // Symlinks should be resolved
        assert!(validate_file_path(test_file.to_str().unwrap()).is_ok());

        // Invalid: null bytes (filesystem limitation)
        assert!(validate_file_path("test\0file.txt").is_err());

        // Restore original directory before temp_dir cleanup
        let _ = std::env::set_current_dir(&original_dir);
    }
}
