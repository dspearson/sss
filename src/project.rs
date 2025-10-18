use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::crypto::{seal_repository_key, PublicKey, RepositoryKey};

/// A user's configuration in the project
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserConfig {
    /// User's public key (for sealing repository keys)
    pub public: String,
    /// Sealed repository symmetric key (encrypted for this user)
    pub sealed_key: String,
    /// When this user was added to the project
    #[serde(default = "default_created")]
    pub added: String,
}

/// Project-level configuration (safe for git)
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Configuration version
    #[serde(default = "default_version")]
    pub version: String,

    /// Project creation timestamp
    #[serde(default = "default_created")]
    pub created: String,

    /// Users who can decrypt/encrypt in this project
    /// Flattened to appear as `[username]` sections in TOML
    #[serde(flatten)]
    pub users: HashMap<String, UserConfig>,

    /// Git hooks configuration
    #[serde(default, skip_serializing_if = "HooksConfig::is_empty")]
    pub hooks: HooksConfig,

    /// Key rotation metadata
    #[serde(default, skip_serializing_if = "RotationMetadata::is_empty")]
    pub rotation: RotationMetadata,

    /// Migration: old-style key (should be removed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_created() -> String {
    Utc::now().to_rfc3339()
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            created: default_created(),
            users: HashMap::new(),
            hooks: HooksConfig::default(),
            rotation: RotationMetadata::default(),
            key: None,
        }
    }
}

/// Git hooks configuration
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct HooksConfig {
    pub git_pre_commit: Option<bool>,
    pub git_post_checkout: Option<bool>,
}

impl HooksConfig {
    pub fn is_empty(&self) -> bool {
        self.git_pre_commit.is_none() && self.git_post_checkout.is_none()
    }
}

/// Key rotation metadata
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RotationMetadata {
    /// Timestamp of last key rotation
    pub last_rotation: Option<String>,
    /// Number of rotations performed
    #[serde(default)]
    pub rotation_count: u32,
    /// Reason for last rotation
    pub last_rotation_reason: Option<String>,
}

impl RotationMetadata {
    pub fn is_empty(&self) -> bool {
        self.last_rotation.is_none()
            && self.rotation_count == 0
            && self.last_rotation_reason.is_none()
    }
}

impl ProjectConfig {
    /// Create a new project configuration with a single user
    /// Generates a new repository key and seals it for the user
    pub fn new(username: &str, user_public_key: &PublicKey) -> Result<Self> {
        // Generate a new repository key
        let repository_key = RepositoryKey::new();

        // Seal the repository key for this user
        let sealed_key = seal_repository_key(&repository_key, user_public_key)?;

        let user_config = UserConfig {
            public: user_public_key.to_base64(),
            sealed_key,
            added: default_created(),
        };

        let mut users = HashMap::new();
        users.insert(username.to_string(), user_config);

        Ok(Self {
            version: default_version(),
            created: default_created(),
            users,
            hooks: HooksConfig::default(),
            rotation: RotationMetadata::default(),
            key: None,
        })
    }

    /// Load project configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Failed to read project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        toml::from_str(&content).map_err(|e| anyhow!("Failed to parse project config file: {}", e))
    }

    /// Save project configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialise project config: {}", e))?;

        fs::write(&path, content).map_err(|e| {
            anyhow!(
                "Failed to write project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })
    }

    /// Add a user to the project
    /// Requires the repository key to seal it for the new user
    pub fn add_user(
        &mut self,
        username: &str,
        user_public_key: &PublicKey,
        repository_key: &RepositoryKey,
    ) -> Result<()> {
        if self.users.contains_key(username) {
            return Err(anyhow!("User '{}' already exists in project", username));
        }

        // Seal the repository key for this new user
        let sealed_key = seal_repository_key(repository_key, user_public_key)?;

        let user_config = UserConfig {
            public: user_public_key.to_base64(),
            sealed_key,
            added: default_created(),
        };

        self.users.insert(username.to_string(), user_config);
        Ok(())
    }

    /// Get the sealed repository key for a user
    pub fn get_sealed_key_for_user(&self, username: &str) -> Result<String> {
        let user_config = self
            .users
            .get(username)
            .ok_or_else(|| anyhow!("User '{}' not found in project", username))?;

        Ok(user_config.sealed_key.clone())
    }

    /// Remove a user from the project
    pub fn remove_user(&mut self, username: &str) -> Result<()> {
        if !self.users.contains_key(username) {
            return Err(anyhow!("User '{}' not found in project", username));
        }

        self.users.remove(username);
        Ok(())
    }

    /// Get the public key for a user
    pub fn get_user_public_key(&self, username: &str) -> Result<PublicKey> {
        let user_config = self
            .users
            .get(username)
            .ok_or_else(|| anyhow!("User '{}' not found in project", username))?;

        PublicKey::from_base64(&user_config.public)
    }

    /// List all users in the project
    pub fn list_users(&self) -> Vec<String> {
        let mut users: Vec<String> = self.users.keys().cloned().collect();
        users.sort();
        users
    }

    /// Find username by matching public key
    pub fn find_user_by_public_key(&self, public_key: &PublicKey) -> Option<String> {
        let public_key_str = public_key.to_base64();
        for (username, user_config) in &self.users {
            if user_config.public == public_key_str {
                return Some(username.clone());
            }
        }
        None
    }

    /// Check if this is an old-format config with a raw key
    pub fn is_legacy_format(&self) -> bool {
        self.key.is_some()
    }

    /// Get the legacy key (for migration)
    pub fn legacy_key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// Remove the legacy key (after migration)
    pub fn remove_legacy_key(&mut self) {
        self.key = None;
    }

    /// Check if the project has any users
    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// Get all public keys in the project
    pub fn get_all_public_keys(&self) -> Result<Vec<(String, PublicKey)>> {
        let mut keys = Vec::new();

        for (username, user_config) in &self.users {
            let public_key = PublicKey::from_base64(&user_config.public)?;
            keys.push((username.clone(), public_key));
        }

        Ok(keys)
    }

    /// Validate the project configuration
    pub fn validate(&self) -> Result<()> {
        // Validate all user configurations
        for (username, user_config) in &self.users {
            // Validate sealed key is valid base64
            use base64::Engine;
            base64::prelude::BASE64_STANDARD
                .decode(&user_config.sealed_key)
                .map_err(|e| anyhow!("Invalid base64 sealed key for user '{}': {}", username, e))?;

            // Validate public key
            PublicKey::from_base64(&user_config.public)
                .map_err(|e| anyhow!("Invalid public key for user '{}': {}", username, e))?;
        }

        // Warn about legacy format
        if self.is_legacy_format() {
            eprintln!("WARNING: Project config contains legacy private key. Run 'sss migrate' to upgrade.");
        }

        Ok(())
    }

    /// Update rotation metadata after a key rotation
    pub fn update_rotation_metadata(&mut self, reason: String) {
        self.rotation.last_rotation = Some(Utc::now().to_rfc3339());
        self.rotation.rotation_count += 1;
        self.rotation.last_rotation_reason = Some(reason);
    }

    /// Get rotation history information
    pub fn get_rotation_info(&self) -> String {
        if self.rotation.rotation_count == 0 {
            "No key rotations performed".to_string()
        } else {
            let last_rotation = self.rotation.last_rotation.as_deref().unwrap_or("unknown");
            let reason = self
                .rotation
                .last_rotation_reason
                .as_deref()
                .unwrap_or("unspecified");

            format!(
                "Rotations: {} | Last: {} | Reason: {}",
                self.rotation.rotation_count, last_rotation, reason
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use tempfile::NamedTempFile;

    #[test]
    fn test_project_config_creation() {
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key).unwrap();

        assert_eq!(config.users.len(), 1);
        assert!(config.users.contains_key("alice"));
        assert!(!config.is_legacy_format());
    }

    #[test]
    fn test_add_remove_users() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key).unwrap();

        // We need a repository key to add users - let's get it from the sealed key for alice
        // For testing, we'll create a dummy repository key
        let repository_key = RepositoryKey::new();

        // Add second user
        config
            .add_user("bob", &keypair2.public_key, &repository_key)
            .unwrap();
        assert_eq!(config.users.len(), 2);
        assert!(config.users.contains_key("bob"));

        // Cannot add duplicate user
        let result = config.add_user("alice", &keypair1.public_key, &repository_key);
        assert!(result.is_err());

        // Remove user
        config.remove_user("bob").unwrap();
        assert_eq!(config.users.len(), 1);
        assert!(!config.users.contains_key("bob"));

        // Cannot remove non-existent user
        let result = config.remove_user("charlie");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file_roundtrip() {
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key).unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        config.save_to_file(temp_file.path()).unwrap();

        let loaded_config = ProjectConfig::load_from_file(temp_file.path()).unwrap();
        assert_eq!(loaded_config.users.len(), config.users.len());
        assert!(loaded_config.users.contains_key("alice"));
    }

    #[test]
    fn test_legacy_format_detection() {
        let mut config = ProjectConfig::default();
        assert!(!config.is_legacy_format());

        config.key = Some("base64key".to_string());
        assert!(config.is_legacy_format());
        assert_eq!(config.legacy_key(), Some("base64key"));

        config.remove_legacy_key();
        assert!(!config.is_legacy_format());
        assert_eq!(config.legacy_key(), None);
    }

    #[test]
    fn test_config_validation() {
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key).unwrap();

        // Valid config should pass
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_format() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key).unwrap();

        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key, &repository_key)
            .unwrap();

        let toml_output = toml::to_string_pretty(&config).unwrap();
        println!("Generated TOML:\n{}", toml_output);

        // Should have user sections with key and public fields
        assert!(toml_output.contains("[alice]"));
        assert!(toml_output.contains("[bob]"));
        assert!(toml_output.contains("key ="));
        assert!(toml_output.contains("public ="));
    }

    #[test]
    fn test_get_all_public_keys() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key).unwrap();

        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key, &repository_key)
            .unwrap();

        let keys = config.get_all_public_keys().unwrap();
        assert_eq!(keys.len(), 2);

        let usernames: Vec<&str> = keys.iter().map(|(name, _)| name.as_str()).collect();
        assert!(usernames.contains(&"alice"));
        assert!(usernames.contains(&"bob"));
    }
}
