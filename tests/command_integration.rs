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
    use sss::validation::{validate_base64, validate_file_path, validate_username};

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

        // Invalid paths (only null bytes should fail now)
        assert!(validate_file_path("test\0file.txt").is_err()); // Null bytes

        // Note: Path traversal and absolute paths are now allowed but will be
        // validated against project boundaries at runtime
    });

    // Test Base64 validation
    assert!(validate_base64("SGVsbG8=", 100).is_ok()); // Valid Base64
    assert!(validate_base64("Invalid@Base64", 100).is_err()); // Invalid characters
    assert!(validate_base64("SGVsbG8===", 100).is_err()); // Too much padding
}

#[test]
fn test_rate_limiter_integration() {
    use sss::rate_limiter::{get_password_rate_limiter, RateLimiter};

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

    let decrypted = processor
        .decrypt_content(&encrypted)
        .expect("Failed to decrypt");
    assert_eq!(decrypted, input);

    // Test that multiple processor instances work (testing static regex patterns)
    let processor2 = Processor::new(RepositoryKey::new()).expect("Failed to create processor2");
    let input2 = "Another ⊕{test} message";
    let encrypted2 = processor2
        .encrypt_content(input2)
        .expect("Failed to encrypt");
    assert!(encrypted2.contains("⊠{"));

    // Test mixed content
    let mixed_input = "⊕{plain1} and o+{plain2}";
    let mixed_encrypted = processor
        .encrypt_content(mixed_input)
        .expect("Failed to encrypt mixed");
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
    use sss::validation::{validate_key_id, validate_username};

    // Test comprehensive username validation
    let long_username = "x".repeat(300);
    let invalid_usernames = vec![
        "",             // Empty
        "user@domain",  // Invalid characters
        ".invalid",     // Starts with dot
        "invalid.",     // Ends with dot
        "-invalid",     // Starts with hyphen
        "invalid-",     // Ends with hyphen
        "root",         // Reserved name
        "admin",        // Reserved name
        &long_username, // Too long
    ];

    for username in invalid_usernames {
        assert!(
            validate_username(username).is_err(),
            "Should reject username: {}",
            username
        );
    }

    // Test valid usernames
    let valid_usernames = vec!["alice", "bob123", "user_name", "user-name", "user.name"];
    for username in valid_usernames {
        assert!(
            validate_username(username).is_ok(),
            "Should accept username: {}",
            username
        );
    }

    // Test key ID validation
    assert!(validate_key_id("abc123").is_ok());
    assert!(validate_key_id("invalid-key").is_err());
}

#[test]
fn test_cli_flag_mutual_exclusion() {
    use clap::{Arg, ArgAction, Command};

    // Create a simplified version of the CLI to test flag conflicts
    let app = Command::new("sss_test")
        .arg(
            Arg::new("in-place")
                .short('x')
                .long("in-place")
                .action(ArgAction::SetTrue)
                .conflicts_with("render")
                .conflicts_with("edit"),
        )
        .arg(
            Arg::new("render")
                .short('r')
                .long("render")
                .action(ArgAction::SetTrue)
                .conflicts_with("in-place")
                .conflicts_with("edit"),
        )
        .arg(
            Arg::new("edit")
                .short('e')
                .long("edit")
                .action(ArgAction::SetTrue)
                .conflicts_with("in-place")
                .conflicts_with("render"),
        );

    // Test that single flags work
    let result_x = app.clone().try_get_matches_from(vec!["sss_test", "-x"]);
    assert!(result_x.is_ok(), "Single -x flag should work");

    let result_r = app.clone().try_get_matches_from(vec!["sss_test", "-r"]);
    assert!(result_r.is_ok(), "Single -r flag should work");

    let result_e = app.clone().try_get_matches_from(vec!["sss_test", "-e"]);
    assert!(result_e.is_ok(), "Single -e flag should work");

    // Test that conflicting flags are rejected
    let result_xr = app
        .clone()
        .try_get_matches_from(vec!["sss_test", "-x", "-r"]);
    assert!(
        result_xr.is_err(),
        "Conflicting -x and -r flags should be rejected"
    );

    let result_xe = app
        .clone()
        .try_get_matches_from(vec!["sss_test", "-x", "-e"]);
    assert!(
        result_xe.is_err(),
        "Conflicting -x and -e flags should be rejected"
    );

    let result_re = app
        .clone()
        .try_get_matches_from(vec!["sss_test", "-r", "-e"]);
    assert!(
        result_re.is_err(),
        "Conflicting -r and -e flags should be rejected"
    );

    // Test that all three together are also rejected
    let result_all = app
        .clone()
        .try_get_matches_from(vec!["sss_test", "-x", "-r", "-e"]);
    assert!(
        result_all.is_err(),
        "All three conflicting flags should be rejected"
    );
}

#[test]
fn test_config_manager_with_custom_confdir() {
    use sss::config_manager::ConfigManager;

    // Create a temporary directory for testing
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let custom_confdir = temp_dir.path().join("custom_config");
    fs::create_dir_all(&custom_confdir).expect("Failed to create custom confdir");

    // Test creating ConfigManager with custom config directory
    let config_manager = ConfigManager::new_with_config_dir(custom_confdir.clone());
    assert!(
        config_manager.is_ok(),
        "Should create ConfigManager with custom confdir"
    );

    // The config manager should use the custom directory for settings
    let config_manager = config_manager.unwrap();

    // Test that we can set and save settings with custom confdir
    let mut mutable_manager = config_manager;
    mutable_manager
        .set_default_username(Some("testuser".to_string()))
        .expect("Failed to set username");

    // Save should work with custom confdir
    let save_result = mutable_manager.save_user_settings();
    assert!(
        save_result.is_ok(),
        "Should be able to save settings to custom confdir"
    );

    // Verify the settings file was created in the custom directory
    let settings_path = custom_confdir.join("settings.toml");
    assert!(
        settings_path.exists(),
        "Settings file should exist in custom confdir: {:?}",
        settings_path
    );
}

#[test]
fn test_fingerprint_formatting() {
    // Test the fingerprint shortening logic used in keys pubkey --fingerprint
    // This simulates what happens in keys.rs when --fingerprint flag is used

    let test_cases = vec![
        (
            "SGVsbG8gV29ybGQhVGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==",
            "SGVsbG8gV29ybGQh...",
        ),
        ("ShortKey", "ShortKey..."),
        ("1234567890123456", "1234567890123456..."),
        ("12345", "12345..."),
    ];

    for (full_key, expected_fingerprint) in test_cases {
        // Simulate the fingerprint logic from keys.rs
        let fingerprint = format!("{}...", &full_key[..16.min(full_key.len())]);

        assert_eq!(
            fingerprint, expected_fingerprint,
            "Fingerprint formatting should match expected output"
        );
    }

    // Test edge case: very short key
    let short_key = "abc";
    let short_fingerprint = format!("{}...", &short_key[..16.min(short_key.len())]);
    assert_eq!(short_fingerprint, "abc...");

    // Test that fingerprint is always shorter than original for long keys
    let long_key = "A".repeat(100);
    let long_fingerprint = format!("{}...", &long_key[..16.min(long_key.len())]);
    assert!(long_fingerprint.len() < long_key.len());
    assert_eq!(long_fingerprint.len(), 19); // 16 chars + "..."
}
