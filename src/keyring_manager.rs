use anyhow::{anyhow, Result};
use keyring::Entry;
use std::path::Path;

// Temporarily use old config for backwards compatibility
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
struct OldConfig {
    key: String,
    #[serde(default)]
    hooks: OldHooksConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct OldHooksConfig {
    git_pre_commit: Option<bool>,
    git_post_checkout: Option<bool>,
}

impl OldConfig {
    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Failed to read config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        toml::from_str(&content).map_err(|e| anyhow!("Failed to parse config file: {}", e))
    }

    fn get_key(&self) -> Result<Key> {
        Key::from_base64(&self.key)
    }
}
use crate::crypto::Key;

/// A type-safe wrapper for user profile names
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile(String);

impl UserProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for UserProfile {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
}

impl From<String> for UserProfile {
    fn from(name: String) -> Self {
        Self(name)
    }
}

const SERVICE_NAME: &str = "sss";
const DEFAULT_USER: &str = "default";

impl UserProfile {
    pub const DEFAULT: UserProfile = UserProfile(String::new());
}

impl Default for UserProfile {
    fn default() -> Self {
        Self::new(DEFAULT_USER)
    }
}

pub struct KeyringManager {
    service_name: String,
}

impl Default for KeyringManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringManager {
    pub fn new() -> Self {
        Self {
            service_name: SERVICE_NAME.to_string(),
        }
    }

    /// Store a key in the system keyring for the default user
    pub fn store_key(&self, key: &Key) -> Result<()> {
        self.store_key_for_user(DEFAULT_USER, key)
    }

    /// Store a key in the system keyring for a specific user/profile
    pub fn store_key_for_user(&self, user: &str, key: &Key) -> Result<()> {
        let entry = Entry::new(&self.service_name, user)
            .map_err(|e| anyhow!("Failed to create keyring entry for user '{}': {}", user, e))?;

        let key_b64 = key.to_base64();
        entry
            .set_password(&key_b64)
            .map_err(|e| anyhow!("Failed to store key in keyring for user '{}': {}", user, e))?;

        Ok(())
    }

    /// Retrieve a key from the system keyring for the default user
    pub fn get_key(&self) -> Result<Key> {
        self.get_key_for_user(DEFAULT_USER)
    }

    /// Retrieve a key from the system keyring for a specific user/profile
    pub fn get_key_for_user(&self, user: &str) -> Result<Key> {
        let entry = Entry::new(&self.service_name, user)
            .map_err(|e| anyhow!("Failed to create keyring entry for user '{}': {}", user, e))?;

        let key_b64 = entry.get_password().map_err(|e| {
            anyhow!(
                "Failed to retrieve key from keyring for user '{}': {}",
                user,
                e
            )
        })?;

        Key::from_base64(&key_b64)
    }

    /// Delete a key from the system keyring for the default user
    pub fn delete_key(&self) -> Result<()> {
        self.delete_key_for_user(DEFAULT_USER)
    }

    /// Delete a key from the system keyring for a specific user/profile
    pub fn delete_key_for_user(&self, user: &str) -> Result<()> {
        let entry = Entry::new(&self.service_name, user)
            .map_err(|e| anyhow!("Failed to create keyring entry for user '{}': {}", user, e))?;

        entry.delete_credential().map_err(|e| {
            anyhow!(
                "Failed to delete key from keyring for user '{}': {}",
                user,
                e
            )
        })?;

        Ok(())
    }

    /// Check if a key exists in the keyring for the default user
    pub fn has_key(&self) -> bool {
        self.has_key_for_user(DEFAULT_USER)
    }

    /// Check if a key exists in the keyring for a specific user/profile
    pub fn has_key_for_user(&self, user: &str) -> bool {
        self.get_key_for_user(user).is_ok()
    }

    /// Migrate an existing key from a config file to the keyring
    pub fn migrate_from_config<P: AsRef<Path>>(&self, config_path: P) -> Result<()> {
        self.migrate_from_config_for_user(config_path, DEFAULT_USER)
    }

    /// Migrate an existing key from a config file to the keyring for a specific user/profile
    pub fn migrate_from_config_for_user<P: AsRef<Path>>(
        &self,
        config_path: P,
        user: &str,
    ) -> Result<()> {
        if !config_path.as_ref().exists() {
            return Err(anyhow!(
                "Config file {} does not exist",
                config_path.as_ref().display()
            ));
        }

        let config = OldConfig::load_from_file(&config_path)?;
        let key = config.get_key()?;

        self.store_key_for_user(user, &key)?;

        Ok(())
    }

    /// Load key with fallback hierarchy: keyring -> config file -> environment variable -> error
    pub fn load_key_with_fallback<P: AsRef<Path>>(&self, config_path: P) -> Result<Key> {
        self.load_key_with_fallback_for_user(config_path, DEFAULT_USER)
    }

    /// Load key with fallback hierarchy for a specific user/profile
    pub fn load_key_with_fallback_for_user<P: AsRef<Path>>(
        &self,
        config_path: P,
        user: &str,
    ) -> Result<Key> {
        // Try keyring first
        if let Ok(key) = self.get_key_for_user(user) {
            return Ok(key);
        }

        // Fall back to config file
        if config_path.as_ref().exists() {
            let config = OldConfig::load_from_file(&config_path)?;
            return config.get_key();
        }

        // Fall back to environment variable
        if let Ok(env_key) = std::env::var("SSS_KEY") {
            return Key::from_base64(&env_key);
        }

        Err(anyhow!(
            "No key found for user '{}'. Key not found in keyring, config file {}, or SSS_KEY environment variable",
            user,
            config_path.as_ref().display()
        ))
    }

    /// List all users/profiles that have keys stored in the keyring
    /// Note: This is a best-effort implementation as keyring doesn't provide enumeration
    pub fn list_users(&self) -> Result<Vec<String>> {
        // The keyring crate doesn't provide a way to enumerate entries
        // This is a limitation of most keyring implementations for security reasons
        // We could maintain a separate index, but for now we'll return known users
        let mut users = Vec::new();

        if self.has_key_for_user(DEFAULT_USER) {
            users.push(DEFAULT_USER.to_string());
        }

        Ok(users)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    /// Test utility to handle keyring availability and setup/cleanup
    struct KeyringTestHelper {
        manager: KeyringManager,
        test_user: String,
    }

    impl KeyringTestHelper {
        fn new(test_name: &str) -> Self {
            let manager = KeyringManager::new();
            let test_user = format!("test_{}", test_name);

            // Clean up any existing key
            let _ = manager.delete_key_for_user(&test_user);

            Self { manager, test_user }
        }

        /// Attempt to store a key, returning None if keyring is unavailable
        fn try_store_key(&self, key: &Key) -> Option<()> {
            match self.manager.store_key_for_user(&self.test_user, key) {
                Ok(()) => {
                    // Verify we can actually retrieve it
                    if self.manager.get_key_for_user(&self.test_user).is_ok() {
                        Some(())
                    } else {
                        eprintln!("Skipping keyring test: keyring store/retrieve not working in this environment");
                        None
                    }
                }
                Err(_) => {
                    eprintln!("Skipping keyring test: keyring not available in this environment");
                    None
                }
            }
        }

        fn get_key(&self) -> Result<Key> {
            self.manager.get_key_for_user(&self.test_user)
        }

        fn has_key(&self) -> bool {
            self.manager.has_key_for_user(&self.test_user)
        }

        fn user(&self) -> &str {
            &self.test_user
        }
    }

    impl Drop for KeyringTestHelper {
        fn drop(&mut self) {
            // Clean up on drop
            let _ = self.manager.delete_key_for_user(&self.test_user);
        }
    }

    #[test]
    fn test_keyring_manager_creation() {
        let manager = KeyringManager::new();
        assert_eq!(manager.service_name, SERVICE_NAME);
    }

    #[test]
    fn test_store_and_retrieve_key() {
        let helper = KeyringTestHelper::new("user_store_retrieve");
        let key = Key::new();

        // Store the key - skip test if keyring is not available
        if helper.try_store_key(&key).is_none() {
            return;
        }

        // Retrieve and verify
        let retrieved_key = helper.get_key().unwrap();
        assert_eq!(key.to_base64(), retrieved_key.to_base64());
        // Cleanup handled by Drop
    }

    #[test]
    fn test_has_key() {
        let helper = KeyringTestHelper::new("has_key_check");
        let key = Key::new();

        // Should not have key initially
        assert!(!helper.has_key());

        // Store key - skip test if keyring is not available
        if helper.try_store_key(&key).is_none() {
            return;
        }

        // Should have key now
        assert!(helper.has_key());

        // Clean up and verify deletion
        helper.manager.delete_key_for_user(helper.user()).unwrap();
        assert!(!helper.has_key());
    }

    #[test]
    fn test_migrate_from_config() {
        let helper = KeyringTestHelper::new("migrate_config");

        // Create a test config file with legacy format
        let legacy_content = r#"
key = "dGVzdGtleWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

[hooks]
"#;
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), legacy_content).unwrap();

        // Migrate the key - skip test if keyring is not available
        if helper
            .manager
            .migrate_from_config_for_user(temp_file.path(), helper.user())
            .is_err()
        {
            eprintln!("Skipping keyring test: keyring not available in this environment");
            return;
        }

        // Verify the key was migrated
        let retrieved_key = match helper.get_key() {
            Ok(key) => key,
            Err(_) => {
                eprintln!(
                    "Skipping keyring test: keyring store/retrieve not working in this environment"
                );
                return;
            }
        };
        assert_eq!(
            "dGVzdGtleWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ=",
            retrieved_key.to_base64()
        );
        // Cleanup handled by Drop
    }

    #[test]
    fn test_fallback_hierarchy() {
        let helper = KeyringTestHelper::new("fallback_hierarchy");

        // Create a test config file with legacy format
        let legacy_content = r#"
key = "dGVzdGtleWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDE="

[hooks]
"#;
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), legacy_content).unwrap();

        // Should fall back to config file when no keyring entry exists
        let key_from_fallback = helper
            .manager
            .load_key_with_fallback_for_user(temp_file.path(), helper.user())
            .unwrap();
        assert_eq!(
            "dGVzdGtleWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
            key_from_fallback.to_base64()
        );

        // Store a different key in keyring - skip keyring part if not available
        let keyring_key = Key::new();
        if helper.try_store_key(&keyring_key).is_none() {
            eprintln!("Skipping keyring hierarchy test: keyring not available in this environment");
            return;
        }

        // Should now prefer keyring over config file
        let key_from_keyring = helper
            .manager
            .load_key_with_fallback_for_user(temp_file.path(), helper.user())
            .unwrap();
        assert_eq!(keyring_key.to_base64(), key_from_keyring.to_base64());
        assert_ne!(
            "dGVzdGtleWRhdGExMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ=",
            key_from_keyring.to_base64()
        );
        // Cleanup handled by Drop
    }
}
