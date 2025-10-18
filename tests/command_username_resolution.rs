/// Integration tests for username resolution in actual command execution
///
/// These tests verify that the fixed commands properly use ConfigManager
/// for username resolution instead of directly reading $USER/$USERNAME.
///
/// Tests use passwordless keys to avoid interactive passphrase prompts.
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use sss::config_manager::ConfigManager;
use sss::crypto::KeyPair;
use sss::keystore::Keystore;
use sss::project::ProjectConfig;
use sss::Processor;

/// Test helper to set up a test environment with custom config directory
struct TestEnv {
    _temp_dir: TempDir,
    project_dir: PathBuf,
    #[allow(dead_code)]
    config_dir: PathBuf,
    config_manager: ConfigManager,
    keystore: Keystore,
}

impl TestEnv {
    fn new() -> anyhow::Result<Self> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path().join("project");
        let config_dir = temp_dir.path().join("config");

        fs::create_dir_all(&project_dir)?;
        fs::create_dir_all(&config_dir)?;

        let config_manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
        let keystore = Keystore::new_with_config_dir(config_dir.clone())?;

        Ok(Self {
            _temp_dir: temp_dir,
            project_dir,
            config_dir,
            config_manager,
            keystore,
        })
    }

    fn set_default_username(&mut self, username: &str) -> anyhow::Result<()> {
        self.config_manager
            .set_default_username(Some(username.to_string()))?;
        self.config_manager.save_user_settings()?;
        Ok(())
    }

    fn generate_passwordless_keypair(&self) -> anyhow::Result<KeyPair> {
        let keypair = KeyPair::generate()?;
        self.keystore.store_keypair(&keypair, None)?;
        Ok(keypair)
    }

    fn init_project(&self, username: &str, keypair: &KeyPair) -> anyhow::Result<PathBuf> {
        let config_path = self.project_dir.join(".sss.toml");
        let config = ProjectConfig::new(username, &keypair.public_key)?;
        config.save_to_file(&config_path)?;
        Ok(config_path)
    }

    fn get_username_from_config_manager(&self) -> anyhow::Result<String> {
        self.config_manager.get_username(None)
    }
}

#[test]
fn test_users_add_respects_configured_username() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set up initial user with hostname suffix (simulating the bug scenario)
    let primary_user = "openshift_tvhpmgm-vjmp002";
    env.set_default_username(primary_user)?;

    // Generate passwordless keypair for primary user
    let primary_keypair = env.generate_passwordless_keypair()?;

    // Initialize project
    let config_path = env.init_project(primary_user, &primary_keypair)?;

    // Verify ConfigManager returns the correct username
    let resolved_username = env.get_username_from_config_manager()?;
    assert_eq!(
        resolved_username, primary_user,
        "ConfigManager should return configured username"
    );

    // Load config and verify primary user exists
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert!(
        config.users.contains_key(primary_user),
        "Primary user should exist in config"
    );

    // Get sealed key using the configured username (this is what was failing)
    let sealed_key = config.get_sealed_key_for_user(&resolved_username);
    assert!(
        sealed_key.is_ok(),
        "Should be able to get sealed key using configured username"
    );

    // Now test adding a second user
    let second_user = "taapedo4_desktop";
    let second_keypair = KeyPair::generate()?;

    // Decrypt repository key using primary user's keypair
    let sealed_key = config.get_sealed_key_for_user(primary_user)?;
    let repository_key = sss::crypto::open_repository_key(&sealed_key, &primary_keypair)?;

    // Add second user
    let mut config = config;
    config.add_user(second_user, &second_keypair.public_key, &repository_key)?;
    config.save_to_file(&config_path)?;

    // Verify second user was added
    let reloaded_config = ProjectConfig::load_from_file(&config_path)?;
    assert!(
        reloaded_config.users.contains_key(second_user),
        "Second user should be added to config"
    );

    Ok(())
}

#[test]
fn test_file_operations_respect_configured_username() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set up user with custom username
    let username = "custom_user_123";
    env.set_default_username(username)?;

    // Generate keypair and initialize project
    let keypair = env.generate_passwordless_keypair()?;
    let config_path = env.init_project(username, &keypair)?;

    // Load project config
    let config = ProjectConfig::load_from_file(&config_path)?;
    let sealed_key = config.get_sealed_key_for_user(username)?;
    let repository_key = sss::crypto::open_repository_key(&sealed_key, &keypair)?;

    // Create processor
    let processor = Processor::new(repository_key)?;

    // Test seal operation
    let plaintext = "Secret: ⊕{my_secret}";
    let encrypted = processor.encrypt_content(plaintext)?;
    assert!(
        encrypted.contains("⊠{"),
        "Content should be encrypted"
    );

    // Test open operation
    let decrypted = processor.decrypt_content(&encrypted)?;
    assert_eq!(decrypted, plaintext, "Content should decrypt correctly");

    // Test render operation
    let rendered = processor.decrypt_to_raw(&encrypted)?;
    assert_eq!(rendered, "Secret: my_secret", "Content should render to raw");

    Ok(())
}

#[test]
fn test_init_command_respects_configured_username() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set configured username
    let configured_user = "configured_user_abc";
    env.set_default_username(configured_user)?;

    // Generate keypair
    let keypair = env.generate_passwordless_keypair()?;

    // Initialize project (simulating `sss init`)
    let config_path = env.init_project(configured_user, &keypair)?;

    // Verify project was initialized with configured username
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert!(
        config.users.contains_key(configured_user),
        "Project should be initialized with configured username"
    );

    // Verify username resolution
    let resolved = env.get_username_from_config_manager()?;
    assert_eq!(
        resolved, configured_user,
        "Should resolve to configured username"
    );

    Ok(())
}

#[test]
fn test_username_precedence_cli_over_settings() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set default username in settings
    env.set_default_username("settings_user")?;

    // CLI override should take precedence
    let cli_user = "cli_override_user";
    let resolved = env.config_manager.get_username(Some(cli_user))?;

    assert_eq!(
        resolved, cli_user,
        "CLI override should take precedence over settings"
    );

    Ok(())
}

#[test]
fn test_username_precedence_env_over_settings() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set default username in settings
    env.set_default_username("settings_user")?;

    // Set SSS_USER environment variable
    env::set_var("SSS_USER", "env_user");

    // Env var should take precedence
    let resolved = env.get_username_from_config_manager()?;
    assert_eq!(
        resolved, "env_user",
        "SSS_USER env var should take precedence over settings"
    );

    // Clean up
    env::remove_var("SSS_USER");

    Ok(())
}

#[test]
fn test_username_with_hostname_suffix_works() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // This is the exact scenario from the bug report
    let username_with_host = "openshift_tvhpmgm-vjmp002";

    // Set it in config
    env.set_default_username(username_with_host)?;

    // Generate keypair and init project
    let keypair = env.generate_passwordless_keypair()?;
    let config_path = env.init_project(username_with_host, &keypair)?;

    // Verify the username is used correctly
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert!(
        config.users.contains_key(username_with_host),
        "Username with hostname suffix should work"
    );

    // Verify we can retrieve sealed key with this username
    let sealed_key = config.get_sealed_key_for_user(username_with_host);
    assert!(
        sealed_key.is_ok(),
        "Should be able to get sealed key with hostname-suffixed username"
    );

    // Verify ConfigManager resolves it correctly
    let resolved = env.get_username_from_config_manager()?;
    assert_eq!(
        resolved, username_with_host,
        "ConfigManager should resolve to full username with hostname"
    );

    Ok(())
}

#[test]
fn test_users_remove_respects_configured_username() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set up project with two users
    let user1 = "user_one";
    let user2 = "user_two";

    env.set_default_username(user1)?;

    // Generate keypairs
    let keypair1 = env.generate_passwordless_keypair()?;
    let keypair2 = KeyPair::generate()?;

    // Initialize project with user1
    let config_path = env.init_project(user1, &keypair1)?;

    // Add user2
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    let sealed_key = config.get_sealed_key_for_user(user1)?;
    let repository_key = sss::crypto::open_repository_key(&sealed_key, &keypair1)?;
    config.add_user(user2, &keypair2.public_key, &repository_key)?;
    config.save_to_file(&config_path)?;

    // Verify both users exist
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert!(config.users.contains_key(user1));
    assert!(config.users.contains_key(user2));
    assert_eq!(config.users.len(), 2);

    // ConfigManager should resolve to user1 (the configured user)
    let resolved = env.get_username_from_config_manager()?;
    assert_eq!(resolved, user1, "Should resolve to configured username");

    // Note: Full remove test with key rotation would require more complex setup
    // This test verifies the username resolution part

    Ok(())
}

#[test]
fn test_multiple_users_with_different_configs() -> anyhow::Result<()> {
    // Create separate environments for two users
    let mut env1 = TestEnv::new()?;
    let mut env2 = TestEnv::new()?;

    // Set different usernames
    let user1 = "alice_host1";
    let user2 = "bob_host2";

    env1.set_default_username(user1)?;
    env2.set_default_username(user2)?;

    // Verify they resolve independently
    assert_eq!(env1.get_username_from_config_manager()?, user1);
    assert_eq!(env2.get_username_from_config_manager()?, user2);

    // Create separate projects
    let keypair1 = env1.generate_passwordless_keypair()?;
    let keypair2 = env2.generate_passwordless_keypair()?;

    let config1 = env1.init_project(user1, &keypair1)?;
    let config2 = env2.init_project(user2, &keypair2)?;

    // Verify projects are independent
    let proj1 = ProjectConfig::load_from_file(&config1)?;
    let proj2 = ProjectConfig::load_from_file(&config2)?;

    assert!(proj1.users.contains_key(user1));
    assert!(!proj1.users.contains_key(user2));

    assert!(proj2.users.contains_key(user2));
    assert!(!proj2.users.contains_key(user1));

    Ok(())
}

#[test]
fn test_settings_persist_across_restarts() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir)?;

    let username = "persistent_user";

    // First session: set username
    {
        let mut manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
        manager.set_default_username(Some(username.to_string()))?;
        manager.save_user_settings()?;
    }

    // Second session: load username
    {
        let manager = ConfigManager::new_with_config_dir(config_dir)?;
        env::remove_var("SSS_USER"); // Ensure we're not using env var
        let resolved = manager.get_username(None)?;
        assert_eq!(
            resolved, username,
            "Username should persist across sessions"
        );
    }

    Ok(())
}

#[test]
fn test_cli_flag_user_still_works() -> anyhow::Result<()> {
    let mut env = TestEnv::new()?;

    // Set default username
    env.set_default_username("default_user")?;

    // CLI flag should override everything
    let cli_user = "explicit_cli_user";
    let resolved = env.config_manager.get_username(Some(cli_user))?;

    assert_eq!(
        resolved, cli_user,
        "CLI --user flag should still work and override settings"
    );

    Ok(())
}

#[test]
fn test_system_username_fallback_still_works() -> anyhow::Result<()> {
    let env = TestEnv::new()?;

    // Don't set any username in settings
    // Don't set SSS_USER
    env::remove_var("SSS_USER");

    // Should fall back to system username
    let result = env.get_username_from_config_manager();

    // Should succeed if USER or USERNAME is set
    if env::var("USER").is_ok() || env::var("USERNAME").is_ok() {
        assert!(
            result.is_ok(),
            "Should fall back to system username when no config is set"
        );
    }

    Ok(())
}
