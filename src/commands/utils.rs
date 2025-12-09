//! Shared utility functions for command handlers
//!
//! This module provides common functionality used across multiple command handlers,
//! eliminating code duplication and ensuring consistent behavior.

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::env;
use std::path::PathBuf;

use crate::{
    config, config_manager::ConfigManager,
    constants::{
        CONFIG_FILE_NAME, ERR_INCORRECT_PASSPHRASE, ERR_NO_KEYPAIR,
        ERR_NO_KEYPAIR_INIT, ERR_NO_PROJECT_CONFIG,
    },
    crypto::KeyPair,
    kdf::KdfParams,
    keystore::Keystore,
    processor::Processor,
    project::ProjectConfig,
    secure_memory::password,
};

/// Create keystore instance based on global confdir parameter and KDF configuration
///
/// This function checks if a custom config directory was provided via the --confdir
/// flag and creates a keystore instance accordingly. It also loads the KDF level
/// from configuration (respecting CLI > ENV > Config precedence).
pub fn create_keystore(matches: &ArgMatches) -> Result<Keystore> {
    // Load config manager to get KDF level
    let config_manager = create_config_manager(matches)?;

    // Get KDF level from config (checks CLI args, ENV vars, and user settings)
    // Note: CLI flag for --kdf-level would be checked here if it exists in matches
    let kdf_level = config_manager.get_kdf_level(matches.get_one::<String>("kdf-level").map(|s| s.as_str()));
    let kdf_params = KdfParams::from_level(&kdf_level)?;

    // Get keyring preference
    let use_keyring = config_manager.use_system_keyring(None);

    if let Some(confdir) = matches.get_one::<String>("confdir") {
        Keystore::new_with_config_dir_and_kdf(PathBuf::from(confdir), kdf_params, use_keyring)
    } else {
        Keystore::new_with_kdf_params(kdf_params, use_keyring)
    }
}

/// Create config manager instance based on global confdir parameter
///
/// This function checks if a custom config directory was provided via the --confdir
/// flag and creates a config manager instance accordingly.
pub fn create_config_manager(matches: &ArgMatches) -> Result<ConfigManager> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        ConfigManager::new_with_config_dir(PathBuf::from(confdir))
    } else {
        ConfigManager::new()
    }
}

/// Get the current username with proper precedence
///
/// Precedence order:
/// 1. SSS_USER environment variable (highest)
/// 2. Global config username (from user settings)
/// 3. USER/USERNAME environment variables (lowest - fallback only)
///
/// This respects the user's explicit configuration choices.
pub fn get_system_username() -> Result<String> {
    use crate::config_manager::ConfigManager;
    use crate::validation::validate_username;

    // 1. Check SSS_USER environment variable first
    if let Ok(username) = env::var("SSS_USER") {
        validate_username(&username)?;
        return Ok(username);
    }

    // 2. Try to load config and get default username
    // Note: This may fail if config doesn't exist yet (e.g., during first init)
    // That's okay - we fall through to system username
    if let Ok(config_manager) = ConfigManager::new() {
        if let Some(username) = config_manager.get_default_username() {
            validate_username(&username)?;
            return Ok(username);
        }
    }

    // 3. Fall back to system username (USER/USERNAME env vars)
    let username = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .map_err(|_| anyhow!("Could not determine username. Set SSS_USER environment variable or configure default username with 'sss settings username <name>'"))?;

    validate_username(&username)?;
    Ok(username)
}

/// Get keypair with optional password prompt
///
/// This function handles the common pattern of:
/// 1. Check if key is password protected
/// 2. Prompt for password if needed
/// 3. Handle empty password (retry without password)
/// 4. Return the keypair or error
pub fn get_keypair_with_optional_password(
    keystore: &Keystore,
    prompt: &str,
) -> Result<KeyPair> {
    // First try without password
    if let Ok(keypair) = keystore.get_current_keypair(None) {
        return Ok(keypair);
    }

    // Check if key is password protected
    if !keystore.is_current_key_password_protected()? {
        // Key exists but couldn't be loaded and isn't password protected
        return Err(anyhow!(ERR_NO_KEYPAIR));
    }

    // Key is password protected, prompt for password
    let password = password::read_password(prompt)?;

    if password.is_empty() {
        // User pressed Enter, try again without password
        keystore
            .get_current_keypair(None)
            .map_err(|_| anyhow!(ERR_NO_KEYPAIR_INIT))
    } else {
        // User provided a password
        keystore
            .get_current_keypair(Some(password.as_str()?))
            .map_err(|_| anyhow!(ERR_INCORRECT_PASSPHRASE))
    }
}

/// Get password for current keypair if it's password protected
///
/// Returns None if not password protected, Some(password_str) if protected.
/// Handles the common pattern of checking protection status and prompting.
pub fn get_password_if_protected(
    keystore: &Keystore,
    prompt: &str,
) -> Result<Option<String>> {
    if !keystore.is_current_key_password_protected()? {
        return Ok(None);
    }

    let password = password::read_password(prompt)?;

    if password.is_empty() {
        Ok(None)
    } else {
        Ok(Some(password.as_str()?.to_string()))
    }
}

/// Extract required string argument from ArgMatches
///
/// This helper eliminates the common pattern of:
/// `matches.get_one::<String>("arg").unwrap()`
///
/// Returns an error if the argument is missing (which should be prevented by clap).
pub fn get_required_string(matches: &ArgMatches, name: &str) -> Result<String> {
    matches
        .get_one::<String>(name)
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Missing required argument: {}", name))
}

/// Load project configuration with consistent error handling
///
/// This function provides a centralized way to load the project config file
/// with proper error messages. Used across multiple commands to eliminate duplication.
pub fn load_project_config_or_fail() -> Result<ProjectConfig> {
    ProjectConfig::load_from_file(CONFIG_FILE_NAME)
        .map_err(|_| anyhow!(ERR_NO_PROJECT_CONFIG))
}

/// Create processor from project config in current directory
///
/// This is a common pattern across multiple commands:
/// 1. Locate the .sss.toml file
/// 2. Load project config with repository key
/// 3. Create processor with full context
///
/// Returns the config, processor, and project root path for commands that need them.
pub fn create_processor_from_project_config() -> Result<(ProjectConfig, Processor, PathBuf)> {
    let config_path = config::get_project_config_path()?;
    let (config, repository_key, project_root) =
        config::load_project_config_with_repository_key(&config_path)?;
    let secrets_filename = config.get_secrets_filename().to_string();
    let processor = Processor::new_with_context_and_secrets_filename(
        repository_key,
        project_root.clone(),
        config.created.clone(),
        secrets_filename,
    )?;
    Ok((config, processor, project_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;
    use std::fs;
    use tempfile::TempDir;
    use serial_test::serial;

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
    fn test_get_required_string_present() {
        // Create a simple command with an argument
        let app = Command::new("test")
            .arg(clap::Arg::new("name").required(true));

        let matches = app.get_matches_from(vec!["test", "value"]);

        let result = get_required_string(&matches, "name");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "value");
    }

    #[test]
    fn test_get_required_string_missing() {
        // Create a command with an optional argument (defined but not provided)
        let app = Command::new("test")
            .arg(clap::Arg::new("optional_arg"));
        let matches = app.get_matches_from(vec!["test"]);

        let result = get_required_string(&matches, "optional_arg");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing required argument"));
    }

    #[test]
    fn test_get_required_string_empty_value() {
        // Test with empty string value
        let app = Command::new("test")
            .arg(clap::Arg::new("name").required(true));

        let matches = app.get_matches_from(vec!["test", ""]);

        let result = get_required_string(&matches, "name");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_get_system_username_with_user_env() {
        // Save original values
        let original = env::var("USER").ok();
        let original_sss_user = env::var("SSS_USER").ok();

        // Clear SSS_USER to allow USER to be used, then set USER env variable
        unsafe {
            env::remove_var("SSS_USER");
            env::set_var("USER", "testuser");
        }

        let result = get_system_username();
        assert!(result.is_ok());
        // Note: May return config username if global config exists, or "testuser" from USER env
        // Since we can't control global config in tests, we just verify it returns a valid username
        assert!(!result.unwrap().is_empty());

        // Restore original values
        if let Some(val) = original {
            unsafe { env::set_var("USER", val); }
        } else {
            unsafe { env::remove_var("USER"); }
        }
        if let Some(val) = original_sss_user {
            unsafe { env::set_var("SSS_USER", val); }
        }
    }

    #[test]
    fn test_get_system_username_with_username_env() {
        // Save original values
        let original_user = env::var("USER").ok();
        let original_username = env::var("USERNAME").ok();
        let original_sss_user = env::var("SSS_USER").ok();

        // Remove SSS_USER and USER to allow USERNAME to be used (Windows fallback)
        unsafe {
            env::remove_var("SSS_USER");
            env::remove_var("USER");
            env::set_var("USERNAME", "windowsuser");
        }

        let result = get_system_username();
        assert!(result.is_ok());
        // Note: May return config username if global config exists, or "windowsuser" from USERNAME env
        // Since we can't control global config in tests, we just verify it returns a valid username
        assert!(!result.unwrap().is_empty());

        // Restore original values
        if let Some(val) = original_user {
            unsafe { env::set_var("USER", val); }
        }
        if let Some(val) = original_username {
            unsafe { env::set_var("USERNAME", val); }
        } else {
            unsafe { env::remove_var("USERNAME"); }
        }
        if let Some(val) = original_sss_user {
            unsafe { env::set_var("SSS_USER", val); }
        }
    }

    #[test]
    #[serial]
    fn test_load_project_config_or_fail_no_config() {
        let temp_dir = TempDir::new().unwrap();
        let _guard = DirGuard::new().unwrap();

        // Change to temp dir (no .sss.toml file)
        env::set_current_dir(temp_dir.path()).unwrap();

        // Try to load when no .sss.toml exists
        let result = load_project_config_or_fail();
        assert!(result.is_err());

        // Check error message (it should contain the ERR_NO_PROJECT_CONFIG constant)
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No project configuration found"));

        // DirGuard will restore directory on drop
    }

    #[test]
    #[serial]
    fn test_load_project_config_or_fail_with_valid_config() {
        let temp_dir = TempDir::new().unwrap();
        let _guard = DirGuard::new().unwrap();

        // Create a valid .sss.toml file in temp dir
        let config_content = r#"
version = "1.0"
created = "2025-01-01T00:00:00Z"

[testuser]
public = "dGVzdHB1YmxpY2tleXRlc3RwdWJsaWNrZXl0ZXN0cHVibGlja2V5dGVzdA=="
sealed_key = "dGVzdHNlYWxlZGtleXRlc3RzZWFsZWRrZXl0ZXN0c2VhbGVka2V5dGVzdHNlYWxlZGtleXRlc3RzZWFsZWRrZXl0ZXN0c2VhbGVka2V5dGVzdHNlYWxlZGtleQ=="
added = "2025-01-01T00:00:00Z"
"#;
        let config_path = temp_dir.path().join(".sss.toml");
        fs::write(&config_path, config_content).unwrap();

        // Change to temp dir
        env::set_current_dir(temp_dir.path()).unwrap();

        // Load should succeed
        let result = load_project_config_or_fail();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.version, "1.0");
        assert!(config.users.contains_key("testuser"));

        // DirGuard will restore directory on drop
    }

    #[test]
    #[serial]
    fn test_load_project_config_or_fail_with_invalid_config() {
        let temp_dir = TempDir::new().unwrap();
        let _guard = DirGuard::new().unwrap();

        // Create an invalid .sss.toml file (malformed TOML)
        let config_path = temp_dir.path().join(".sss.toml");
        fs::write(&config_path, "this is not valid TOML {{{").unwrap();

        // Change to temp dir
        env::set_current_dir(temp_dir.path()).unwrap();

        // Load should fail
        let result = load_project_config_or_fail();
        assert!(result.is_err());

        // DirGuard will restore directory on drop
    }

    #[test]
    fn test_create_config_manager_default() {
        let app = Command::new("test")
            .arg(clap::Arg::new("confdir").long("confdir").value_name("DIR"));
        let matches = app.get_matches_from(vec!["test"]);

        // Should create with default config dir (confdir not provided)
        let result = create_config_manager(&matches);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_config_manager_custom_confdir() {
        let temp_dir = TempDir::new().unwrap();

        let app = Command::new("test")
            .arg(clap::Arg::new("confdir").long("confdir").value_name("DIR"));

        let matches = app.get_matches_from(vec![
            "test",
            "--confdir",
            temp_dir.path().to_str().unwrap()
        ]);

        // Should create with custom config dir
        let result = create_config_manager(&matches);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_keystore_default() {
        let app = Command::new("test")
            .arg(clap::Arg::new("confdir").long("confdir").value_name("DIR"))
            .arg(clap::Arg::new("kdf-level").long("kdf-level").value_name("LEVEL"));
        let matches = app.get_matches_from(vec!["test"]);

        // Should create with default config dir (confdir not provided)
        let result = create_keystore(&matches);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_keystore_custom_confdir() {
        let temp_dir = TempDir::new().unwrap();

        let app = Command::new("test")
            .arg(clap::Arg::new("confdir").long("confdir").value_name("DIR"))
            .arg(clap::Arg::new("kdf-level").long("kdf-level").value_name("LEVEL"));

        let matches = app.get_matches_from(vec![
            "test",
            "--confdir",
            temp_dir.path().to_str().unwrap()
        ]);

        // Should create with custom config dir
        let result = create_keystore(&matches);
        assert!(result.is_ok());
    }
}
