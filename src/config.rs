#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::items_after_statements)]

use anyhow::{anyhow, Result};
use std::env;
use std::path::{Path, PathBuf};

use crate::crypto::PublicKey;
use crate::keyring_manager::KeyringManager;
use crate::keystore::get_passphrase_or_prompt;
use crate::project::ProjectConfig;

// Re-export for backwards compatibility
pub use crate::project::{HooksConfig, ProjectConfig as Config};

/// Default config file name in project directories
const DEFAULT_CONFIG_FILE: &str = ".sss.toml";

/// Find SSS project root by searching upward from a specific directory
pub fn find_project_root_from(start_dir: &Path) -> Result<PathBuf> {
    let mut current_dir = start_dir.to_path_buf();

    loop {
        let config_path = current_dir.join(DEFAULT_CONFIG_FILE);
        if config_path.exists() {
            return Ok(current_dir);
        }

        match current_dir.parent() {
            Some(parent) => current_dir = parent.to_path_buf(),
            None => break,
        }
    }

    Err(anyhow!(
        "No SSS project found. Could not locate {DEFAULT_CONFIG_FILE} in {} or any parent directory.",
        start_dir.display()
    ))
}

/// Find SSS project root by searching upward for .sss.toml file
/// Similar to how git finds the repository root by searching for .git
pub fn find_project_root() -> Result<PathBuf> {
    let current_dir =
        env::current_dir().map_err(|e| anyhow!("Failed to get current directory: {e}"))?;
    find_project_root_from(&current_dir)
}

/// Get the path to the project config file
pub fn get_project_config_path() -> Result<PathBuf> {
    let project_root = find_project_root()?;
    Ok(project_root.join(DEFAULT_CONFIG_FILE))
}

/// Get project config path starting from a specific directory
pub fn get_project_config_path_from(start_dir: &Path) -> Result<PathBuf> {
    let project_root = find_project_root_from(start_dir)?;
    Ok(project_root.join(DEFAULT_CONFIG_FILE))
}

/// Load project configuration with consistent error handling
///
/// This is a convenience function that combines getting the config path
/// and loading the configuration with standardized error messages.
///
/// # Returns
///
/// Returns a tuple of (`config_path`, config) for commands that need both.
///
/// # Errors
///
/// Returns an error if:
/// - No .sss.toml is found in current or parent directories
/// - The config file cannot be loaded or parsed
///
/// # Examples
///
/// ```no_run
/// use sss::config::load_project_config;
///
/// let (config_path, config) = load_project_config()?;
/// println!("Loaded config from: {}", config_path.display());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn load_project_config() -> Result<(PathBuf, ProjectConfig)> {
    let config_path = get_project_config_path()?;
    let config = ProjectConfig::load_from_file(&config_path).map_err(|e| {
        anyhow!(
            "Failed to load SSS project configuration.\n\
             Config file: {}\n\
             Error: {}\n\n\
             Run 'sss init' to create a new project.",
            config_path.display(),
            e
        )
    })?;
    Ok((config_path, config))
}

/// Load project configuration from a specific directory
///
/// Like `load_project_config()` but starts searching from a specific directory.
///
/// # Examples
///
/// ```no_run
/// use sss::config::load_project_config_from;
/// use std::path::Path;
///
/// let source_dir = Path::new("/path/to/project");
/// let (config_path, config) = load_project_config_from(source_dir)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn load_project_config_from(start_dir: &Path) -> Result<(PathBuf, ProjectConfig)> {
    let config_path = get_project_config_path_from(start_dir)?;
    let config = ProjectConfig::load_from_file(&config_path).map_err(|e| {
        anyhow!(
            "Failed to load SSS project configuration.\n\
             Config file: {}\n\
             Error: {}\n\n\
             Run 'sss init' to create a new project.",
            config_path.display(),
            e
        )
    })?;
    Ok((config_path, config))
}

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
    println!("Added user '{username}' to project");

    Ok(())
}

/// Internal helper to load keypair with password retry logic
fn load_keypair_with_password_retry() -> Result<crate::crypto::KeyPair> {
    let keystore = crate::keystore::Keystore::new()?;

    // Try without password first
    if let Ok(keypair) = keystore.get_current_keypair(None) { Ok(keypair) } else {
        // Try with password from SSS_PASSPHRASE environment variable or prompt
        let password = get_passphrase_or_prompt(
            "Enter your passphrase (or press Enter if none): ",
        )?;
        let password_opt = if password.is_empty() {
            None
        } else {
            Some(password.as_str())
        };
        keystore.get_current_keypair(password_opt)
    }
}

/// Internal unified implementation for loading project configuration
/// This eliminates code duplication between the public API functions
fn load_project_config_internal<P: AsRef<Path>>(
    config_path: P,
    search_for_root: bool,
    use_agent: bool,
) -> Result<(ProjectConfig, crate::crypto::RepositoryKey, Option<PathBuf>)> {
    let config_path = config_path.as_ref();

    // If search_for_root is true and config_path is just the filename, search for project root
    let actual_config_path = if search_for_root && config_path == Path::new(DEFAULT_CONFIG_FILE) {
        get_project_config_path()?
    } else {
        config_path.to_path_buf()
    };

    // Extract project root (parent directory of .sss.toml) if needed
    let project_root = if search_for_root {
        Some(
            actual_config_path
                .parent()
                .ok_or_else(|| anyhow!("Config path has no parent directory"))?
                .to_path_buf()
        )
    } else {
        None
    };

    let format = detect_config_format(&actual_config_path)?;

    match format {
        ConfigFormat::Missing => Err(anyhow!(
            "No project configuration found at {}. Run 'sss init' to create one.",
            actual_config_path.display()
        )),
        ConfigFormat::Legacy => Err(anyhow!(
            "Legacy configuration format detected. This format is no longer supported."
        )),
        ConfigFormat::Empty => Err(anyhow!(
            "Project configuration exists but has no users. Add yourself with 'sss user add'."
        )),
        ConfigFormat::Modern => {
            let config = ProjectConfig::load_from_file(&actual_config_path)?;
            config.validate()?;

            let keystore = crate::keystore::Keystore::new()?;

            // Try current keypair first
            let user_keypair = load_keypair_with_password_retry()?;
            let mut username_opt = config.find_user_by_public_key(&user_keypair.public_key);
            let mut matched_keypair = user_keypair.clone();

            // If current keypair doesn't match, try all available keypairs
            if username_opt.is_none() {
                eprintln!("Current keypair not found in project, trying other available keys...");

                // Get password once for all keypairs
                let password = crate::keystore::get_passphrase_or_prompt(
                    "Enter passphrase to check all keys (or press Enter if none): ",
                )?;
                let password_opt = if password.is_empty() {
                    None
                } else {
                    Some(password.as_str())
                };

                // Try all keypairs
                if let Ok(all_keypairs) = keystore.get_all_keypairs(password_opt) {
                    for keypair in all_keypairs {
                        if let Some(username) = config.find_user_by_public_key(&keypair.public_key) {
                            eprintln!("✓ Found matching key for user: {username}");
                            username_opt = Some(username);
                            matched_keypair = keypair;
                            break;
                        }
                    }
                }
            }

            // If still no match, error out
            let username = username_opt.ok_or_else(|| anyhow!(
                "None of your keypairs are authorized for this project.\n\
                Available users: {}\n\
                Your current key: {}\n\n\
                Tip: You may need to:\n\
                  1. Ask a project admin to add your key: sss user add <username> <your-pubkey>\n\
                  2. Or switch to a different keypair: sss keys current <key-id>",
                config.list_users().join(", "),
                user_keypair.public_key.to_base64()
            ))?;

            // Get the sealed repository key for this user
            let sealed_key = config.get_sealed_key_for_user(&username)?;

            // Use the matched keypair for unsealing
            let user_keypair = matched_keypair;

            // Try to use agent if requested and available
            let repository_key = if use_agent && crate::agent::is_agent_available() {
                // Build context for agent request
                let mut context =
                    crate::agent_protocol::RequestContext::from_environment(username.clone());
                context.project_path = Some(actual_config_path.display().to_string());

                // Request unsealing from agent
                match crate::agent::unseal_with_agent(&sealed_key, context) {
                    Ok(key) => key,
                    Err(e) => {
                        eprintln!(
                            "Agent unsealing failed: {e}, falling back to local keystore"
                        );
                        // Use the already-loaded keypair
                        crate::crypto::open_repository_key(&sealed_key, &user_keypair)?
                    }
                }
            } else {
                // Use the already-loaded keypair
                crate::crypto::open_repository_key(&sealed_key, &user_keypair)?
            };

            Ok((config, repository_key, project_root))
        }
    }
}

/// Load project configuration (by matching public key)
/// This is a simpler wrapper that doesn't search for the root or use the agent
pub fn load_project_config_for_user<P: AsRef<Path>>(
    config_path: P,
) -> Result<(ProjectConfig, crate::crypto::Key)> {
    let (config, repository_key, _) = load_project_config_internal(config_path, false, false)?;
    Ok((config, repository_key))
}

/// Load project configuration and get repository key (by matching public key)
/// This version searches for the project root and supports agent-based unsealing
pub fn load_project_config_with_repository_key<P: AsRef<Path>>(
    config_path: P,
) -> Result<(ProjectConfig, crate::crypto::RepositoryKey, PathBuf)> {
    let (config, repository_key, project_root) = load_project_config_internal(config_path, true, true)?;
    // WR-02 fix: replace unwrap() with a proper error — future callers with search_for_root=false
    // would get a confusing panic rather than a clear message without this guard.
    Ok((config, repository_key, project_root.ok_or_else(|| anyhow!("Project root could not be resolved — ensure you are inside an SSS project directory"))?))
}

/// Legacy compatibility functions
pub fn load_key() -> Result<crate::crypto::Key> {
    load_key_for_user("default")
}

pub fn load_key_for_user(user: &str) -> Result<crate::crypto::Key> {
    // NOTE: user parameter is ignored - we now match by public key
    // Use new keystore architecture
    match load_project_config_with_repository_key(DEFAULT_CONFIG_FILE) {
        Ok((_config, repository_key, _project_root)) => Ok(repository_key),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("No project configuration found") {
                // Fall back to old keyring system for backwards compatibility
                let keyring_manager = KeyringManager::new();
                keyring_manager
                    .load_key_with_fallback_for_user(DEFAULT_CONFIG_FILE, user)
                    .map_err(|_| {
                        anyhow!(
                            "No key found. Either:\n\
                            1. Generate a new keypair: sss keys generate\n\
                            2. Initialize project: sss init"
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

    #[test]
    fn test_detect_config_format_surfaces_v2_version_error() {
        // SUITE-04: the actionable v2→v1 error must surface through the
        // detect_config_format chokepoint (and therefore load_project_config_internal)
        // without being wrapped or hidden.
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join(".sss.toml");
        std::fs::write(&config_path, r#"version = "2.0""#).unwrap();

        let err = detect_config_format(&config_path)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("this project requires sss v2.0 or newer"),
            "SUITE-04 error must surface through detect_config_format; got: {err}"
        );
    }
}
