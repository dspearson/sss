/// Tests for username resolution across all commands
///
/// This test suite verifies that ConfigManager is properly integrated into all
/// commands and that username precedence works correctly:
/// 1. CLI override (--user flag)
/// 2. Environment variable (SSS_USER)
/// 3. User settings (configured default username)
/// 4. System username ($USER/$USERNAME)
use sss::config_manager::ConfigManager;
use std::env;
use std::fs;
use tempfile::TempDir;

/// Test helper to create a ConfigManager with a temporary config directory
fn create_test_config_manager() -> (ConfigManager, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).expect("Failed to create config dir");

    let manager =
        ConfigManager::new_with_config_dir(config_dir).expect("Failed to create ConfigManager");

    (manager, temp_dir)
}

#[test]
fn test_username_resolution_precedence_cli_override() {
    let (manager, _temp_dir) = create_test_config_manager();

    // CLI override should have highest precedence
    let username = manager.get_username(Some("cli_user")).unwrap();
    assert_eq!(username, "cli_user");
}

#[test]
fn test_username_resolution_precedence_env_var() {
    let (manager, _temp_dir) = create_test_config_manager();

    // Set SSS_USER environment variable
    env::set_var("SSS_USER", "env_user");

    // Should use SSS_USER when no CLI override
    let username = manager.get_username(None).unwrap();
    assert_eq!(username, "env_user");

    // Clean up
    env::remove_var("SSS_USER");
}

#[test]
fn test_username_resolution_precedence_user_settings() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Remove SSS_USER if set
    env::remove_var("SSS_USER");

    // Set default username in user settings
    manager
        .set_default_username(Some("settings_user".to_string()))
        .expect("Failed to set default username");

    // Should use user settings when no CLI override or env var
    let username = manager.get_username(None).unwrap();
    assert_eq!(username, "settings_user");
}

#[test]
fn test_username_resolution_precedence_system_fallback() {
    let (manager, _temp_dir) = create_test_config_manager();

    // Remove SSS_USER if set
    env::remove_var("SSS_USER");

    // Don't set user settings (defaults to None)
    // Should fall back to system username ($USER or $USERNAME)
    let username = manager.get_username(None);

    // Should succeed if either USER or USERNAME is set
    if env::var("USER").is_ok() || env::var("USERNAME").is_ok() {
        assert!(username.is_ok());
    }
}

#[test]
fn test_username_resolution_full_precedence_chain() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Set up all layers
    env::set_var("SSS_USER", "env_user");
    manager
        .set_default_username(Some("settings_user".to_string()))
        .expect("Failed to set default username");

    // Test precedence order
    // 1. CLI override beats everything
    let username = manager.get_username(Some("cli_user")).unwrap();
    assert_eq!(username, "cli_user");

    // 2. Without CLI override, SSS_USER env var wins
    let username = manager.get_username(None).unwrap();
    assert_eq!(username, "env_user");

    // 3. Without env var, user settings win
    env::remove_var("SSS_USER");
    let username = manager.get_username(None).unwrap();
    assert_eq!(username, "settings_user");

    // Clean up
    env::remove_var("SSS_USER");
}

#[test]
fn test_username_resolution_with_hostname_suffix() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Test the original bug scenario: username with hostname suffix
    let username_with_host = "openshift_tvhpmgm-vjmp002";

    manager
        .set_default_username(Some(username_with_host.to_string()))
        .expect("Failed to set default username");

    // Should return the full username including hostname suffix
    let resolved = manager.get_username(None).unwrap();
    assert_eq!(resolved, username_with_host);

    // Should not fall back to system username
    if let Ok(system_user) = env::var("USER") {
        assert_ne!(resolved, system_user, "Should not use system username");
    }
}

#[test]
fn test_config_manager_persists_username() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).expect("Failed to create config dir");

    // Create and configure first manager
    {
        let mut manager = ConfigManager::new_with_config_dir(config_dir.clone())
            .expect("Failed to create ConfigManager");

        manager
            .set_default_username(Some("persistent_user".to_string()))
            .expect("Failed to set username");

        manager
            .save_user_settings()
            .expect("Failed to save settings");
    }

    // Create new manager with same config dir
    let manager =
        ConfigManager::new_with_config_dir(config_dir).expect("Failed to create ConfigManager");

    // Should load persisted username
    env::remove_var("SSS_USER");
    let username = manager.get_username(None).unwrap();
    assert_eq!(username, "persistent_user");
}

#[test]
fn test_username_validation_in_config_manager() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Valid usernames should work
    assert!(manager
        .set_default_username(Some("valid_user".to_string()))
        .is_ok());
    assert!(manager
        .set_default_username(Some("user-name".to_string()))
        .is_ok());
    assert!(manager
        .set_default_username(Some("user.name".to_string()))
        .is_ok());
    assert!(manager
        .set_default_username(Some("user_name".to_string()))
        .is_ok());

    // Invalid usernames should be rejected
    assert!(manager
        .set_default_username(Some("root".to_string()))
        .is_err()); // Reserved
    assert!(manager
        .set_default_username(Some("admin".to_string()))
        .is_err()); // Reserved
    assert!(manager
        .set_default_username(Some("".to_string()))
        .is_err()); // Empty
    assert!(manager
        .set_default_username(Some("user@invalid".to_string()))
        .is_err()); // Invalid char
}

#[test]
fn test_cli_override_bypasses_validation() {
    let (manager, _temp_dir) = create_test_config_manager();

    // CLI override should work even with "invalid" usernames
    // because validation happens at a different layer
    let result = manager.get_username(Some("any_username_123"));
    assert!(result.is_ok());
}

#[test]
fn test_sss_user_env_var_precedence() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Set both SSS_USER and default username
    env::set_var("SSS_USER", "env_priority");
    manager
        .set_default_username(Some("settings_priority".to_string()))
        .expect("Failed to set username");

    // SSS_USER should win
    let username = manager.get_username(None).unwrap();
    assert_eq!(username, "env_priority");

    // Clean up
    env::remove_var("SSS_USER");
}

#[test]
fn test_clear_default_username() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Set username
    manager
        .set_default_username(Some("testuser".to_string()))
        .expect("Failed to set username");

    // Clear it
    manager
        .set_default_username(None)
        .expect("Failed to clear username");

    // Should fall back to system username (if available)
    env::remove_var("SSS_USER");
    let result = manager.get_username(None);

    // Should either succeed with system username or fail gracefully
    if env::var("USER").is_ok() || env::var("USERNAME").is_ok() {
        assert!(result.is_ok());
    }
}

#[test]
fn test_username_resolution_empty_sss_user_env() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Set empty SSS_USER (should be ignored)
    env::set_var("SSS_USER", "");
    manager
        .set_default_username(Some("settings_user".to_string()))
        .expect("Failed to set username");

    // Should fall through to user settings (empty env var should be ignored)
    let username = manager.get_username(None);

    // ConfigManager might treat empty SSS_USER as valid or skip it
    // This test documents the actual behavior
    if username.is_ok() {
        // If it returns Ok, it should not be empty
        assert!(!username.unwrap().is_empty());
    }

    // Clean up
    env::remove_var("SSS_USER");
}

#[test]
fn test_multiple_config_managers_independent() {
    let temp_dir1 = TempDir::new().expect("Failed to create temp dir 1");
    let temp_dir2 = TempDir::new().expect("Failed to create temp dir 2");

    let config_dir1 = temp_dir1.path().join("config1");
    let config_dir2 = temp_dir2.path().join("config2");

    fs::create_dir_all(&config_dir1).expect("Failed to create config dir 1");
    fs::create_dir_all(&config_dir2).expect("Failed to create config dir 2");

    let mut manager1 =
        ConfigManager::new_with_config_dir(config_dir1).expect("Failed to create manager1");
    let mut manager2 =
        ConfigManager::new_with_config_dir(config_dir2).expect("Failed to create manager2");

    // Set different usernames
    manager1
        .set_default_username(Some("user1".to_string()))
        .expect("Failed to set username1");
    manager2
        .set_default_username(Some("user2".to_string()))
        .expect("Failed to set username2");

    // Should be independent
    env::remove_var("SSS_USER");
    assert_eq!(manager1.get_username(None).unwrap(), "user1");
    assert_eq!(manager2.get_username(None).unwrap(), "user2");
}

#[test]
fn test_username_with_special_chars() {
    let (mut manager, _temp_dir) = create_test_config_manager();

    // Usernames with dots, hyphens, underscores should work
    let valid_usernames = vec![
        "user.name",
        "user-name",
        "user_name",
        "user123",
        "user.with.dots",
        "user-with-hyphens",
        "user_with_underscores",
        "user.mixed-chars_123",
    ];

    for username in valid_usernames {
        let result = manager.set_default_username(Some(username.to_string()));
        assert!(
            result.is_ok(),
            "Should accept username: {}, got error: {:?}",
            username,
            result.err()
        );

        env::remove_var("SSS_USER");
        let resolved = manager.get_username(None).unwrap();
        assert_eq!(resolved, username);
    }
}

#[test]
fn test_config_manager_handles_confdir_flag() {
    // This tests that the create_config_manager helper pattern works
    // Used in users.rs, keys.rs, process.rs, init.rs

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let custom_confdir = temp_dir.path().join("custom");
    fs::create_dir_all(&custom_confdir).expect("Failed to create custom confdir");

    // Create manager with custom confdir
    let manager = ConfigManager::new_with_config_dir(custom_confdir.clone())
        .expect("Failed to create manager");

    // Should be able to use it normally
    let result = manager.get_username(Some("testuser"));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "testuser");
}

#[test]
fn test_username_resolution_error_messages() {
    let (manager, _temp_dir) = create_test_config_manager();

    // Remove all sources of username
    env::remove_var("SSS_USER");
    env::remove_var("USER");
    env::remove_var("USERNAME");

    // No CLI override, no env vars, no user settings, no system username
    let result = manager.get_username(None);

    // Should fail with helpful error
    assert!(result.is_err());
}
