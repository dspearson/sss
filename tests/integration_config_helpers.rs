//! Integration tests for configuration loading helpers
//!
//! Tests the new load_project_config() and load_project_config_from() helpers
//! to ensure they provide consistent error messages and proper functionality.

use anyhow::Result;
use std::fs;
use tempfile::TempDir;

use sss::config::{load_project_config, load_project_config_from};
use sss::crypto::KeyPair;
use sss::project::ProjectConfig;

/// Helper to create a test ProjectConfig
fn create_test_config() -> Result<ProjectConfig> {
    let keypair = KeyPair::generate()?;
    ProjectConfig::new("testuser", &keypair.public_key)
}

/// Test that load_project_config() finds config in current directory
#[test]
fn test_load_project_config_current_dir() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path().to_path_buf();

    // Create a basic config
    let config = create_test_config()?;
    config.save_to_file(&temp_path.join(".sss.toml"))?;

    // Save original directory
    let original_dir = std::env::current_dir()?;

    // Change to temp directory
    std::env::set_current_dir(&temp_path)?;

    // Test loading
    let result = load_project_config();

    // Always restore directory, even if test fails
    std::env::set_current_dir(&original_dir).ok();

    // Now check assertions
    assert!(result.is_ok());

    let (config_path, loaded_config) = result?;
    assert!(config_path.ends_with(".sss.toml"));
    assert_eq!(loaded_config.version, config.version);

    Ok(())
}

/// Test that load_project_config() searches upward
#[test]
fn test_load_project_config_searches_upward() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path().to_path_buf();
    let subdir = temp_path.join("subdir");
    fs::create_dir(&subdir)?;

    // Create config in parent
    let config = create_test_config()?;
    config.save_to_file(&temp_path.join(".sss.toml"))?;

    // Save original directory
    let original_dir = std::env::current_dir()?;

    // Change to subdirectory
    std::env::set_current_dir(&subdir)?;

    // Should find config in parent
    let result = load_project_config();

    // Always restore directory, even if test fails
    std::env::set_current_dir(&original_dir).ok();

    // Now check test assertions
    assert!(result.is_ok());

    Ok(())
}

/// Test that load_project_config() returns helpful error when no config found
#[test]
fn test_load_project_config_no_config_error() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path().to_path_buf();

    // Save original directory
    let original_dir = std::env::current_dir()?;

    // Change to temp directory without config
    std::env::set_current_dir(&temp_path)?;

    // Should return error
    let result = load_project_config();

    // Always restore directory, even if test fails
    std::env::set_current_dir(&original_dir).ok();

    // Now check assertions
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();
    // Should contain helpful message
    assert!(
        err_msg.contains("No SSS project found") || err_msg.contains(".sss.toml"),
        "Error message: {}",
        err_msg
    );

    Ok(())
}

/// Test load_project_config_from() with specific directory
#[test]
fn test_load_project_config_from_specific_dir() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_dir = temp_dir.path().join("project");
    fs::create_dir(&project_dir)?;

    // Create config in specific directory
    let config = create_test_config()?;
    config.save_to_file(&project_dir.join(".sss.toml"))?;

    // Load from that directory
    let result = load_project_config_from(&project_dir);
    assert!(result.is_ok());

    let (config_path, loaded_config) = result?;
    assert!(config_path.ends_with(".sss.toml"));
    assert_eq!(loaded_config.version, config.version);

    Ok(())
}

/// Test load_project_config_from() searches upward from specified dir
#[test]
fn test_load_project_config_from_searches_upward() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_dir = temp_dir.path().join("project");
    let subdir = project_dir.join("subdir");
    fs::create_dir_all(&subdir)?;

    // Create config in project root
    let config = create_test_config()?;
    config.save_to_file(&project_dir.join(".sss.toml"))?;

    // Load from subdirectory - should search upward
    let result = load_project_config_from(&subdir);
    assert!(result.is_ok());

    let (config_path, _) = result?;
    assert_eq!(
        config_path.parent().unwrap(),
        project_dir,
        "Should find config in parent directory"
    );

    Ok(())
}

/// Test that both helpers return same config for same directory
#[test]
fn test_helpers_consistency() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create config
    let config = create_test_config()?;
    config.save_to_file(&temp_dir.path().join(".sss.toml"))?;

    // Save original directory
    let original_dir = std::env::current_dir()?;

    // Change to temp directory and test load_project_config()
    std::env::set_current_dir(temp_dir.path())?;
    let (path1, config1) = load_project_config()?;

    // Restore directory
    std::env::set_current_dir(&original_dir)?;

    // Now test load_project_config_from() with explicit path
    let (path2, config2) = load_project_config_from(temp_dir.path())?;

    // Both should find the same config file
    assert_eq!(path1, path2);
    assert_eq!(config1.version, config2.version);
    assert_eq!(config1.version, config.version);

    Ok(())
}

/// Test error message quality
#[test]
fn test_error_messages_are_helpful() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let result = load_project_config_from(temp_dir.path());
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();

    // Error should mention key information
    assert!(
        err_msg.contains("SSS") || err_msg.contains("sss"),
        "Should mention SSS: {}",
        err_msg
    );
    assert!(
        err_msg.contains(".sss.toml") || err_msg.contains("config"),
        "Should mention config file: {}",
        err_msg
    );
    assert!(
        err_msg.contains("init") || err_msg.contains("found"),
        "Should suggest action: {}",
        err_msg
    );

    Ok(())
}

/// Test loading config with users
#[test]
fn test_load_config_with_users() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create config with initial user
    let config = create_test_config()?;
    config.save_to_file(&temp_dir.path().join(".sss.toml"))?;

    // Load and verify
    let (_, loaded_config) = load_project_config_from(temp_dir.path())?;
    assert!(loaded_config.users.contains_key("testuser"));

    Ok(())
}

/// Test multiple nested subdirectories
#[test]
fn test_deeply_nested_search() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let deep_path = temp_dir
        .path()
        .join("level1")
        .join("level2")
        .join("level3");
    fs::create_dir_all(&deep_path)?;

    // Create config at root
    let config = create_test_config()?;
    config.save_to_file(&temp_dir.path().join(".sss.toml"))?;

    // Should find it from deep path
    let result = load_project_config_from(&deep_path);
    assert!(result.is_ok());

    let (config_path, _) = result?;
    assert_eq!(config_path.parent().unwrap(), temp_dir.path());

    Ok(())
}
