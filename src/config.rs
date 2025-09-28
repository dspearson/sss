use anyhow::{anyhow, Result};
use std::path::Path;

use crate::crypto::PublicKey;
use crate::keyring_manager::KeyringManager;
use crate::project::ProjectConfig;

// Re-export for backwards compatibility
pub use crate::project::{HooksConfig, ProjectConfig as Config};

/// Default config file name in project directories
const DEFAULT_CONFIG_FILE: &str = ".sss.toml";

/// Check if a config file exists and determine its format
pub fn detect_config_format<P: AsRef<Path>>(config_path: P) -> Result<ConfigFormat> {
    if !config_path.as_ref().exists() {
        return Ok(ConfigFormat::Missing);
    }

    let config = ProjectConfig::load_from_file(&config_path)?;

    if config.is_legacy_format() {
        Ok(ConfigFormat::Legacy)
    } else if config.has_users() {
        Ok(ConfigFormat::Modern)
    } else {
        Ok(ConfigFormat::Empty)
    }
}

/// Configuration file format types
#[derive(Debug, PartialEq)]
pub enum ConfigFormat {
    Missing,
    Legacy, // Old format with raw private key
    Modern, // New format with user public keys
    Empty,  // New format but no users yet
}

/// Initialize a new project configuration
pub fn init_project_config<P: AsRef<Path>>(
    config_path: P,
    username: &str,
    public_key: &PublicKey,
) -> Result<()> {
    if config_path.as_ref().exists() {
        return Err(anyhow!(
            "{} already exists. Remove it first if you want to reinitialise.",
            config_path.as_ref().display()
        ));
    }

    let config = ProjectConfig::new(username, public_key)?;
    config.save_to_file(&config_path)?;

    println!("Created {}", config_path.as_ref().display());
    println!("Added user '{}' to project", username);

    Ok(())
}

/// Load project configuration and validate user access
pub fn load_project_config_for_user<P: AsRef<Path>>(
    config_path: P,
    username: &str,
) -> Result<(ProjectConfig, crate::crypto::Key)> {
    let format = detect_config_format(&config_path)?;

    match format {
        ConfigFormat::Missing => {
            Err(anyhow!(
                "No project configuration found at {}. Run 'sss init' to create one.",
                config_path.as_ref().display()
            ))
        }
        ConfigFormat::Legacy => {
            Err(anyhow!(
                "Legacy configuration format detected. This format is no longer supported."
            ))
        }
        ConfigFormat::Empty => {
            Err(anyhow!(
                "Project configuration exists but has no users. Add yourself with 'sss user add'."
            ))
        }
        ConfigFormat::Modern => {
            let config = ProjectConfig::load_from_file(&config_path)?;
            config.validate()?;

            // Check if user is in project
            if !config.users.contains_key(username) {
                return Err(anyhow!(
                    "User '{}' is not authorized for this project. Available users: {}",
                    username,
                    config.list_users().join(", ")
                ));
            }

            // Load user's keypair from keystore and get repository key
            let keystore = crate::keystore::Keystore::new()?;

            // Try without password first
            let user_keypair = match keystore.get_current_keypair(None) {
                Ok(keypair) => keypair,
                Err(_) => {
                    // Try with password
                    let password = rpassword::prompt_password("Enter your passphrase (or press Enter if none): ")?;
                    let password_opt = if password.is_empty() { None } else { Some(password.as_str()) };
                    keystore.get_current_keypair(password_opt)?
                }
            };

            // Get the sealed repository key for this user
            let sealed_key = config.get_sealed_key_for_user(username)?;

            // Decrypt the repository key and return it as legacy "Key" type
            let repository_key = crate::crypto::open_repository_key(&sealed_key, &user_keypair)?;

            Ok((config, repository_key))
        }
    }
}

/// Load project configuration and get repository key for a user
pub fn load_project_config_with_repository_key<P: AsRef<Path>>(
    config_path: P,
    username: &str,
) -> Result<(ProjectConfig, crate::crypto::RepositoryKey)> {
    let format = detect_config_format(&config_path)?;

    match format {
        ConfigFormat::Missing => {
            Err(anyhow!(
                "No project configuration found at {}. Run 'sss init' to create one.",
                config_path.as_ref().display()
            ))
        }
        ConfigFormat::Legacy => {
            Err(anyhow!(
                "Legacy configuration format detected. This format is no longer supported."
            ))
        }
        ConfigFormat::Empty => {
            Err(anyhow!(
                "Project configuration exists but has no users. Add yourself with 'sss user add'."
            ))
        }
        ConfigFormat::Modern => {
            let config = ProjectConfig::load_from_file(&config_path)?;
            config.validate()?;

            // Check if user is in project
            if !config.users.contains_key(username) {
                return Err(anyhow!(
                    "User '{}' is not authorized for this project. Available users: {}",
                    username,
                    config.list_users().join(", ")
                ));
            }

            // Get user's keypair from keystore
            let keystore = crate::keystore::Keystore::new()?;

            // Try without password first
            let user_keypair = match keystore.get_current_keypair(None) {
                Ok(keypair) => keypair,
                Err(_) => {
                    // Try with password
                    let password = rpassword::prompt_password("Enter your passphrase (or press Enter if none): ")?;
                    let password_opt = if password.is_empty() { None } else { Some(password.as_str()) };
                    keystore.get_current_keypair(password_opt)?
                }
            };

            // Get the sealed repository key for this user
            let sealed_key = config.get_sealed_key_for_user(username)?;

            // Decrypt the repository key
            let repository_key = crate::crypto::open_repository_key(&sealed_key, &user_keypair)?;

            Ok((config, repository_key))
        }
    }
}

/// Legacy compatibility functions
pub fn load_key() -> Result<crate::crypto::Key> {
    load_key_for_user("default")
}

pub fn load_key_for_user(user: &str) -> Result<crate::crypto::Key> {
    // Use new keystore architecture
    match load_project_config_with_repository_key(DEFAULT_CONFIG_FILE, user) {
        Ok((_config, repository_key)) => Ok(repository_key),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("No project configuration found") {
                // Fall back to old keyring system for backwards compatibility
                let keyring_manager = KeyringManager::new();
                keyring_manager
                    .load_key_with_fallback_for_user(DEFAULT_CONFIG_FILE, user)
                    .map_err(|_| {
                        anyhow!(
                            "No key found for user '{}'. Either:\n\
                            1. Generate a new keypair: sss keys generate\n\
                            2. Initialize project: sss init",
                            user
                        )
                    })
            } else {
                Err(e)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use tempfile::tempdir;

    #[test]
    fn test_detect_config_format() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join(".sss.toml");

        // Missing file
        assert_eq!(
            detect_config_format(&config_path).unwrap(),
            ConfigFormat::Missing
        );

        // Legacy format
        let legacy_content = r#"
key = "dGVzdGtleWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ="

[hooks]
"#;
        std::fs::write(&config_path, legacy_content).unwrap();
        assert_eq!(
            detect_config_format(&config_path).unwrap(),
            ConfigFormat::Legacy
        );

        // Modern format with users
        let keypair = KeyPair::generate().unwrap();
        let modern_config = ProjectConfig::new("alice", &keypair.public_key).unwrap();
        modern_config.save_to_file(&config_path).unwrap();
        assert_eq!(
            detect_config_format(&config_path).unwrap(),
            ConfigFormat::Modern
        );

        // Empty modern format
        let empty_config = ProjectConfig::default();
        empty_config.save_to_file(&config_path).unwrap();
        assert_eq!(
            detect_config_format(&config_path).unwrap(),
            ConfigFormat::Empty
        );
    }

    #[test]
    fn test_init_project_config() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join(".sss.toml");

        let keypair = KeyPair::generate().unwrap();

        // Should succeed for new file
        init_project_config(&config_path, "alice", &keypair.public_key).unwrap();
        assert!(config_path.exists());

        // Should fail if file already exists
        let result = init_project_config(&config_path, "alice", &keypair.public_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

}
