use anyhow::{anyhow, Result};
use directories::UserDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// User alias mappings stored locally
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Aliases {
    /// Map from alias name to actual username
    #[serde(flatten)]
    pub mappings: HashMap<String, String>,
}

/// Manager for user aliases
pub struct AliasManager {
    aliases_path: PathBuf,
}

impl AliasManager {
    /// Create a new alias manager
    pub fn new() -> Result<Self> {
        let aliases_path = Self::get_aliases_path()?;
        Self::create_with_path(aliases_path)
    }

    /// Create a new alias manager with custom config directory
    pub fn new_with_config_dir(config_dir: PathBuf) -> Result<Self> {
        let aliases_path = config_dir.join("sss").join("aliases.toml");
        Self::create_with_path(aliases_path)
    }

    /// Internal helper to create alias manager with specific path
    fn create_with_path(aliases_path: PathBuf) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = aliases_path.parent() {
            fs::create_dir_all(parent)?;

            // Set secure permissions on the directory
            #[cfg(unix)]
            {
                let metadata = fs::metadata(parent)?;
                let mut perms = metadata.permissions();
                perms.set_mode(0o700); // Owner read/write/execute only
                fs::set_permissions(parent, perms)?;
            }
        }

        Ok(Self { aliases_path })
    }

    /// Get the path to the aliases file
    fn get_aliases_path() -> Result<PathBuf> {
        let user_dirs =
            UserDirs::new().ok_or_else(|| anyhow!("Could not determine user home directory"))?;

        #[cfg(target_os = "windows")]
        let config_dir = std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| user_dirs.home_dir().join("AppData").join("Roaming"));

        #[cfg(target_os = "macos")]
        let config_dir = user_dirs
            .home_dir()
            .join("Library")
            .join("Application Support");

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| user_dirs.home_dir().join(".config"));

        Ok(config_dir.join("sss").join("aliases.toml"))
    }

    /// Load aliases from file
    fn load_aliases(&self) -> Result<Aliases> {
        if !self.aliases_path.exists() {
            return Ok(Aliases::default());
        }

        let content = fs::read_to_string(&self.aliases_path)
            .map_err(|e| anyhow!("Failed to read aliases file: {}", e))?;

        if content.trim().is_empty() {
            return Ok(Aliases::default());
        }

        toml::from_str(&content).map_err(|e| anyhow!("Failed to parse aliases file: {}", e))
    }

    /// Save aliases to file
    fn save_aliases(&self, aliases: &Aliases) -> Result<()> {
        let content = toml::to_string_pretty(aliases)
            .map_err(|e| anyhow!("Failed to serialise aliases: {}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = self.aliases_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create aliases directory: {}", e))?;
        }

        fs::write(&self.aliases_path, content)
            .map_err(|e| anyhow!("Failed to write aliases file: {}", e))?;

        // Set secure file permissions
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&self.aliases_path)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&self.aliases_path, perms)?;
        }

        Ok(())
    }

    /// Resolve an alias or username to the actual username
    pub fn resolve(&self, alias_or_username: &str) -> Result<String> {
        let aliases = self.load_aliases()?;

        // Check if it's an alias first
        if let Some(username) = aliases.mappings.get(alias_or_username) {
            Ok(username.clone())
        } else {
            // Not an alias, return as-is
            Ok(alias_or_username.to_string())
        }
    }

    /// Add or update an alias
    pub fn add_alias(&self, alias: &str, username: &str) -> Result<()> {
        if alias.is_empty() {
            return Err(anyhow!("Alias cannot be empty"));
        }

        if username.is_empty() {
            return Err(anyhow!("Username cannot be empty"));
        }

        // Validate alias name (no spaces, reasonable characters)
        if !alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(anyhow!(
                "Alias can only contain alphanumeric characters, underscores, and hyphens"
            ));
        }

        let mut aliases = self.load_aliases()?;

        // Check if alias already exists with different username
        if let Some(existing_username) = aliases.mappings.get(alias) {
            if existing_username != username {
                return Err(anyhow!(
                    "Alias '{}' already maps to '{}'",
                    alias,
                    existing_username
                ));
            }
        }

        aliases
            .mappings
            .insert(alias.to_string(), username.to_string());
        self.save_aliases(&aliases)?;

        Ok(())
    }

    /// Remove an alias
    pub fn remove_alias(&self, alias: &str) -> Result<()> {
        let mut aliases = self.load_aliases()?;

        if aliases.mappings.remove(alias).is_none() {
            return Err(anyhow!("Alias '{}' not found", alias));
        }

        self.save_aliases(&aliases)?;
        Ok(())
    }

    /// List all aliases
    pub fn list_aliases(&self) -> Result<HashMap<String, String>> {
        let aliases = self.load_aliases()?;
        Ok(aliases.mappings)
    }

    /// Check if an alias exists
    pub fn has_alias(&self, alias: &str) -> Result<bool> {
        let aliases = self.load_aliases()?;
        Ok(aliases.mappings.contains_key(alias))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_manager() -> Result<AliasManager> {
        let temp_dir = tempdir()?;
        let aliases_path = temp_dir.path().join("aliases.toml");

        // Ensure the parent directory exists (which it should in tempdir)
        if let Some(parent) = aliases_path.parent() {
            fs::create_dir_all(parent)?;
        }

        Ok(AliasManager { aliases_path })
    }

    #[test]
    fn test_add_and_resolve_alias() -> Result<()> {
        let manager = create_test_manager()?;

        // Add alias
        manager.add_alias("me", "alice")?;

        // Resolve alias
        assert_eq!(manager.resolve("me")?, "alice");

        // Resolve non-alias
        assert_eq!(manager.resolve("bob")?, "bob");

        Ok(())
    }

    #[test]
    fn test_list_aliases() -> Result<()> {
        let manager = create_test_manager()?;

        manager.add_alias("me", "alice")?;
        manager.add_alias("work", "alice-work")?;

        let aliases = manager.list_aliases()?;
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases.get("me"), Some(&"alice".to_string()));
        assert_eq!(aliases.get("work"), Some(&"alice-work".to_string()));

        Ok(())
    }

    #[test]
    fn test_remove_alias() -> Result<()> {
        let manager = create_test_manager()?;

        manager.add_alias("me", "alice")?;
        assert!(manager.has_alias("me")?);

        manager.remove_alias("me")?;
        assert!(!manager.has_alias("me")?);

        Ok(())
    }

    #[test]
    fn test_invalid_alias_names() -> Result<()> {
        let manager = create_test_manager()?;

        // Empty alias
        assert!(manager.add_alias("", "alice").is_err());

        // Invalid characters
        assert!(manager.add_alias("my alias", "alice").is_err());
        assert!(manager.add_alias("my@alias", "alice").is_err());

        // Valid characters
        assert!(manager.add_alias("my-alias", "alice").is_ok());
        assert!(manager.add_alias("my_alias", "alice").is_ok());
        assert!(manager.add_alias("alias123", "alice").is_ok());

        Ok(())
    }

    #[test]
    fn test_duplicate_alias_protection() -> Result<()> {
        let manager = create_test_manager()?;

        manager.add_alias("me", "alice")?;

        // Same mapping is OK
        assert!(manager.add_alias("me", "alice").is_ok());

        // Different mapping should fail
        assert!(manager.add_alias("me", "bob").is_err());

        Ok(())
    }

    #[test]
    fn test_empty_file_handling() -> Result<()> {
        let manager = create_test_manager()?;

        // Ensure parent directory exists
        if let Some(parent) = manager.aliases_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create empty file
        fs::write(&manager.aliases_path, "")?;

        // Should handle empty file gracefully
        let aliases = manager.list_aliases()?;
        assert!(aliases.is_empty());

        Ok(())
    }
}
