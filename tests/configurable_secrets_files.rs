use tempfile::TempDir;
use std::fs;

use sss::config_manager::ConfigManager;
use sss::crypto::KeyPair;
use sss::project::ProjectConfig;
use sss::secrets::SecretsCache;

/// Test that project config secrets_filename takes precedence
#[test]
fn test_project_config_secrets_filename_precedence() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config with custom secrets_filename
    let keypair = KeyPair::generate()?;
    let mut project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    project_config.secrets_filename = Some("my_secrets".to_string());

    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Create config manager and set user settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
    config_manager.set_secrets_filename(Some("user_secrets".to_string()));
    config_manager.save_user_settings()?;

    // Reload config manager to pick up saved settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir)?;
    config_manager.load_project(&config_path)?;

    // Project config should take precedence
    assert_eq!(config_manager.get_secrets_filename(), "my_secrets");

    Ok(())
}

/// Test that user settings secrets_filename is used when project config doesn't specify
#[test]
fn test_user_settings_secrets_filename_fallback() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config without custom secrets_filename
    let keypair = KeyPair::generate()?;
    let project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Create config manager and set user settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
    config_manager.set_secrets_filename(Some("user_secrets".to_string()));
    config_manager.save_user_settings()?;

    // Reload config manager to pick up saved settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir)?;
    config_manager.load_project(&config_path)?;

    // User settings should be used
    assert_eq!(config_manager.get_secrets_filename(), "user_secrets");

    Ok(())
}

/// Test that default secrets_filename is used when neither project nor user config specifies
#[test]
fn test_default_secrets_filename() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config without custom secrets_filename
    let keypair = KeyPair::generate()?;
    let project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Create config manager without user settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir)?;
    config_manager.load_project(&config_path)?;

    // Default should be "secrets"
    assert_eq!(config_manager.get_secrets_filename(), "secrets");

    Ok(())
}

/// Test that project config secrets_suffix takes precedence
#[test]
fn test_project_config_secrets_suffix_precedence() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config with custom secrets_suffix
    let keypair = KeyPair::generate()?;
    let mut project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    project_config.secrets_suffix = Some(".sealed".to_string());

    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Create config manager and set user settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
    config_manager.set_secrets_suffix(Some(".passwords".to_string()));
    config_manager.save_user_settings()?;

    // Reload config manager to pick up saved settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir)?;
    config_manager.load_project(&config_path)?;

    // Project config should take precedence
    assert_eq!(config_manager.get_secrets_suffix(), ".sealed");

    Ok(())
}

/// Test that user settings secrets_suffix is used when project config doesn't specify
#[test]
fn test_user_settings_secrets_suffix_fallback() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config without custom secrets_suffix
    let keypair = KeyPair::generate()?;
    let project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Create config manager and set user settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
    config_manager.set_secrets_suffix(Some(".passwords".to_string()));
    config_manager.save_user_settings()?;

    // Reload config manager to pick up saved settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir)?;
    config_manager.load_project(&config_path)?;

    // User settings should be used
    assert_eq!(config_manager.get_secrets_suffix(), ".passwords");

    Ok(())
}

/// Test that default secrets_suffix is used when neither project nor user config specifies
#[test]
fn test_default_secrets_suffix() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config without custom secrets_suffix
    let keypair = KeyPair::generate()?;
    let project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Create config manager without user settings
    let mut config_manager = ConfigManager::new_with_config_dir(config_dir)?;
    config_manager.load_project(&config_path)?;

    // Default should be ".secrets"
    assert_eq!(config_manager.get_secrets_suffix(), ".secrets");

    Ok(())
}

/// Test SecretsCache with custom suffix finds the right file
#[test]
fn test_secrets_cache_custom_suffix() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create a test file
    let test_file = project_root.join("config.yaml");
    fs::write(&test_file, "test: value")?;

    // Create a secrets file with custom suffix
    let secrets_file = project_root.join("config.yaml.sealed");
    fs::write(&secrets_file, "api_key: secret123\ndatabase_password: pass456")?;

    // Create SecretsCache with custom suffix
    let mut cache = SecretsCache::new();
    cache.set_secrets_suffix(".sealed".to_string());

    // Should find the .sealed file
    let found_file = cache.find_secrets_file(&test_file, project_root)?;
    assert_eq!(found_file, secrets_file);

    Ok(())
}

/// Test SecretsCache with custom filename finds the right file
#[test]
fn test_secrets_cache_custom_filename() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();
    let subdir = project_root.join("subdir");
    fs::create_dir_all(&subdir)?;

    // Create a test file in subdirectory
    let test_file = subdir.join("config.yaml");
    fs::write(&test_file, "test: value")?;

    // Create a secrets file with custom filename in parent directory
    let secrets_file = project_root.join("passwords");
    fs::write(&secrets_file, "api_key: secret123\ndatabase_password: pass456")?;

    // Create SecretsCache with custom filename
    let mut cache = SecretsCache::new();
    cache.set_secrets_filename("passwords".to_string());

    // Should find the passwords file in parent directory
    let found_file = cache.find_secrets_file(&test_file, project_root)?;
    assert_eq!(found_file, secrets_file);

    Ok(())
}

/// Test that suffix takes precedence over filename
#[test]
fn test_suffix_precedence_over_filename() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create a test file
    let test_file = project_root.join("config.yaml");
    fs::write(&test_file, "test: value")?;

    // Create both a suffix file and a filename file
    let suffix_file = project_root.join("config.yaml.sealed");
    fs::write(&suffix_file, "api_key: from_suffix")?;

    let filename_file = project_root.join("passwords");
    fs::write(&filename_file, "api_key: from_filename")?;

    // Create SecretsCache with both custom suffix and filename
    let mut cache = SecretsCache::new();
    cache.set_secrets_suffix(".sealed".to_string());
    cache.set_secrets_filename("passwords".to_string());

    // Suffix should take precedence (Strategy 1 before Strategy 2)
    let found_file = cache.find_secrets_file(&test_file, project_root)?;
    assert_eq!(found_file, suffix_file);

    Ok(())
}

/// Test that both config options can be set together
#[test]
fn test_both_config_options_together() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    // Create project config with both custom settings
    let keypair = KeyPair::generate()?;
    let mut project_config = ProjectConfig::new("alice", &keypair.public_key())?;
    project_config.secrets_filename = Some("passwords".to_string());
    project_config.secrets_suffix = Some(".sealed".to_string());

    let config_path = temp_dir.path().join(".sss.toml");
    project_config.save_to_file(&config_path)?;

    // Reload and verify both settings
    let loaded_config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(loaded_config.secrets_filename, Some("passwords".to_string()));
    assert_eq!(loaded_config.secrets_suffix, Some(".sealed".to_string()));

    Ok(())
}
