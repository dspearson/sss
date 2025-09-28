use std::env;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Test helper to set up a temporary directory as current working directory
fn with_temp_dir<F>(test: F)
where
    F: FnOnce(&Path),
{
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let original_dir = env::current_dir().expect("Failed to get current dir");

    env::set_current_dir(temp_dir.path()).expect("Failed to change to temp dir");

    test(temp_dir.path());

    env::set_current_dir(original_dir).expect("Failed to restore original dir");
}

#[test]
fn test_validation_module_integration() {
    use sss::validation::{validate_username, validate_file_path, validate_base64};

    // Test username validation
    assert!(validate_username("valid_user").is_ok());
    assert!(validate_username("admin").is_err()); // Reserved name
    assert!(validate_username("user@invalid").is_err()); // Invalid character

    // Test file path validation
    with_temp_dir(|temp_path| {
        // Create a test file
        let test_file = temp_path.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write test file");

        // Valid relative path
        assert!(validate_file_path("test.txt").is_ok());

        // Invalid paths
        assert!(validate_file_path("../outside").is_err()); // Path traversal
        assert!(validate_file_path("/absolute/path").is_err()); // Absolute path
    });

    // Test Base64 validation
    assert!(validate_base64("SGVsbG8=", 100).is_ok()); // Valid Base64
    assert!(validate_base64("Invalid@Base64", 100).is_err()); // Invalid characters
    assert!(validate_base64("SGVsbG8===", 100).is_err()); // Too much padding
}

#[test]
fn test_rate_limiter_integration() {
    use sss::rate_limiter::{RateLimiter, get_password_rate_limiter};

    // Test creating a custom rate limiter
    let limiter = RateLimiter::new(3, 5, 10);

    // Test basic functionality
    assert!(limiter.check_attempt("user1").is_ok());

    limiter.record_failure("user1");
    assert!(limiter.check_attempt("user1").is_ok());

    limiter.record_failure("user1");
    limiter.record_failure("user1");
    assert!(limiter.check_attempt("user1").is_err()); // Should be rate limited

    // Test success clears failures
    limiter.record_success("user1");
    assert!(limiter.check_attempt("user1").is_ok());

    // Test global rate limiter access
    let global_limiter = get_password_rate_limiter();
    assert!(global_limiter.check_attempt("test_user").is_ok());
}

#[test]
fn test_config_manager_integration() {
    use sss::config_manager::ConfigManager;

    let config_manager = ConfigManager::new().expect("Failed to create config manager");

    // Test username resolution with fallbacks
    let username = config_manager.get_username(Some("cli_override"));
    assert!(username.is_ok());
    assert_eq!(username.unwrap(), "cli_override");

    // Test editor resolution
    let editor = config_manager.get_editor(Some("custom_editor"));
    assert_eq!(editor, "custom_editor");

    // Test default values
    assert!(config_manager.get_auto_lock_timeout() > 0);
    assert!(config_manager.verbosity_level() <= 3);
}

#[test]
fn test_processor_performance_optimizations() {
    use sss::crypto::RepositoryKey;
    use sss::Processor;

    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Failed to create processor");

    // Test basic processing
    let input = "This is ⊕{secret} text";
    let encrypted = processor.encrypt_content(input).expect("Failed to encrypt");
    assert!(encrypted.contains("⊠{"));
    assert!(!encrypted.contains("⊕{"));

    let decrypted = processor.decrypt_content(&encrypted).expect("Failed to decrypt");
    assert_eq!(decrypted, input);

    // Test that multiple processor instances work (testing static regex patterns)
    let processor2 = Processor::new(RepositoryKey::new()).expect("Failed to create processor2");
    let input2 = "Another ⊕{test} message";
    let encrypted2 = processor2.encrypt_content(input2).expect("Failed to encrypt");
    assert!(encrypted2.contains("⊠{"));

    // Test mixed content
    let mixed_input = "⊕{plain1} and o+{plain2}";
    let mixed_encrypted = processor.encrypt_content(mixed_input).expect("Failed to encrypt mixed");
    assert!(mixed_encrypted.contains("⊠{"));
    assert!(!mixed_encrypted.contains("⊕{"));
    assert!(!mixed_encrypted.contains("o+{"));
}

#[test]
fn test_error_handling_robustness() {
    use sss::crypto::RepositoryKey;
    use sss::Processor;

    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Failed to create processor");

    // Test with oversized content (should not crash)
    let large_marker = format!("⊕{{{}}}", "x".repeat(20000)); // Oversized marker
    let result = processor.encrypt_content(&large_marker);
    assert!(result.is_ok()); // Should handle gracefully with warning

    // Test with malformed ciphertext (should not crash)
    let malformed = "⊠{invalid_base64_content}";
    let result = processor.decrypt_content(malformed);
    assert!(result.is_ok()); // Should handle gracefully with warning

    // Test with empty content
    let empty_result = processor.process_content("");
    assert!(empty_result.is_ok());
    assert_eq!(empty_result.unwrap(), "");

    // Test with content without markers
    let no_markers = "Just plain text";
    let no_markers_result = processor.process_content(no_markers);
    assert!(no_markers_result.is_ok());
    assert_eq!(no_markers_result.unwrap(), no_markers);
}

#[test]
fn test_security_validation_coverage() {
    use sss::validation::{validate_username, validate_alias_name, validate_key_id};

    // Test comprehensive username validation
    let long_username = "x".repeat(300);
    let invalid_usernames = vec![
        "",              // Empty
        "user@domain",   // Invalid characters
        ".invalid",      // Starts with dot
        "invalid.",      // Ends with dot
        "-invalid",      // Starts with hyphen
        "invalid-",      // Ends with hyphen
        "root",          // Reserved name
        "admin",         // Reserved name
        &long_username,  // Too long
    ];

    for username in invalid_usernames {
        assert!(validate_username(username).is_err(), "Should reject username: {}", username);
    }

    // Test valid usernames
    let valid_usernames = vec!["alice", "bob123", "user_name", "user-name", "user.name"];
    for username in valid_usernames {
        assert!(validate_username(username).is_ok(), "Should accept username: {}", username);
    }

    // Test alias validation
    assert!(validate_alias_name("prod").is_ok());
    assert!(validate_alias_name("dev_env").is_ok());
    assert!(validate_alias_name("invalid.alias").is_err());

    // Test key ID validation
    assert!(validate_key_id("abc123").is_ok());
    assert!(validate_key_id("invalid-key").is_err());
}