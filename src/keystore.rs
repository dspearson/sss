use anyhow::{anyhow, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use directories::UserDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use crate::crypto::{KeyPair, PublicKey, SecretKey};
use crate::kdf::{DerivedKey, Salt};

/// Stored keypair file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyPair {
    pub uuid: String,
    pub public_key: String,
    pub encrypted_secret_key: String,
    pub salt: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_password_protected: bool,
}

/// Simple file-based keystore using ~/.config/sss/keys/
pub struct Keystore {
    keys_dir: PathBuf,
}

impl Keystore {
    /// Create a new keystore instance
    pub fn new() -> Result<Self> {
        let keys_dir = Self::get_keys_directory()?;
        Self::create_with_directory(keys_dir)
    }

    /// Create a new keystore instance with custom config directory
    pub fn new_with_config_dir(config_dir: PathBuf) -> Result<Self> {
        let keys_dir = config_dir.join("sss").join("keys");
        Self::create_with_directory(keys_dir)
    }

    /// Internal helper to create keystore with a specific directory
    fn create_with_directory(keys_dir: PathBuf) -> Result<Self> {
        // Ensure directory exists
        fs::create_dir_all(&keys_dir)?;

        // Set secure permissions on the directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&keys_dir)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o700); // Owner read/write/execute only
            fs::set_permissions(&keys_dir, perms)?;
        }

        Ok(Self { keys_dir })
    }

    /// Get the keys directory path
    fn get_keys_directory() -> Result<PathBuf> {
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

        Ok(config_dir.join("sss").join("keys"))
    }

    /// Store a new keypair with optional password protection
    pub fn store_keypair(&self, keypair: &KeyPair, password: Option<&str>) -> Result<String> {
        let key_id = Uuid::new_v4().to_string();

        let (encrypted_secret_key, salt, is_password_protected) = if let Some(password) = password {
            // Encrypt secret key with password-derived key
            let salt = Salt::new();
            let derived_key = DerivedKey::derive(password, &salt)?;

            let secret_key_bytes = keypair.secret_key.to_base64().into_bytes();
            let encrypted_data =
                crate::crypto::encrypt(&secret_key_bytes, &derived_key.to_encryption_key())?;

            let encrypted_secret_key = base64::prelude::BASE64_STANDARD.encode(encrypted_data);
            (encrypted_secret_key, Some(salt.to_base64()), true)
        } else {
            // Store secret key as plaintext (base64 encoded)
            (keypair.secret_key.to_base64(), None, false)
        };

        let stored_keypair = StoredKeyPair {
            uuid: key_id.clone(),
            public_key: keypair.public_key.to_base64(),
            encrypted_secret_key,
            salt,
            created_at: Utc::now(),
            is_password_protected,
        };

        // Write keypair to file
        let key_file = self.keys_dir.join(format!("{}.toml", key_id));
        let content = toml::to_string_pretty(&stored_keypair)?;
        fs::write(&key_file, content)?;

        // Set secure permissions on the key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&key_file, perms)?;
        }

        // Update "current" symlink to point to this key
        self.set_current_key(&key_id)?;

        Ok(key_id)
    }

    /// Set the current key by creating/updating the "current" symlink
    pub fn set_current_key(&self, key_id: &str) -> Result<()> {
        let current_link = self.keys_dir.join("current");
        let target = format!("{}.toml", key_id);

        // Remove existing symlink if it exists
        if current_link.exists() {
            fs::remove_file(&current_link)?;
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &current_link)?;
        }

        #[cfg(windows)]
        {
            // On Windows, create a text file containing the target filename
            fs::write(&current_link, &target)?;
        }

        Ok(())
    }

    /// Get the current (latest) keypair by following the "current" symlink
    pub fn get_current_keypair(&self, password: Option<&str>) -> Result<KeyPair> {
        let current_path = self.keys_dir.join("current");

        if !current_path.exists() {
            return Err(anyhow!(
                "No current key found. Generate one with 'sss keygen'"
            ));
        }

        let key_id = self.read_current_key_id()?;
        self.load_keypair(&key_id, password)
    }

    /// Load a specific keypair by ID
    pub fn load_keypair(&self, key_id: &str, password: Option<&str>) -> Result<KeyPair> {
        let key_file = self.keys_dir.join(format!("{}.toml", key_id));

        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {}", key_id));
        }

        let content = fs::read_to_string(&key_file)?;
        let stored_keypair: StoredKeyPair = toml::from_str(&content)?;

        self.decrypt_stored_keypair(&stored_keypair, password)
    }

    /// Get all available keypairs
    pub fn get_all_keypairs(&self, password: Option<&str>) -> Result<Vec<KeyPair>> {
        let mut keypairs = Vec::new();

        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip non-TOML files and the "current" symlink/file
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }

            let content = fs::read_to_string(&path)?;
            if let Ok(stored_keypair) = toml::from_str::<StoredKeyPair>(&content) {
                if let Ok(keypair) = self.decrypt_stored_keypair(&stored_keypair, password) {
                    keypairs.push(keypair);
                }
            }
        }

        // Sort by creation time (most recent first)
        keypairs.sort_by(|a, b| b.public_key.to_base64().cmp(&a.public_key.to_base64()));

        Ok(keypairs)
    }

    /// Get the count of stored keypairs
    pub fn count_keypairs(&self) -> Result<usize> {
        let mut count = 0;

        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "toml") {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Delete a keypair by ID
    pub fn delete_keypair(&self, key_id: &str) -> Result<()> {
        let key_file = self.keys_dir.join(format!("{}.toml", key_id));

        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {}", key_id));
        }

        fs::remove_file(&key_file)?;

        // If this was the current key, remove the current link
        let current_key_id = self.read_current_key_id();
        if current_key_id.is_ok() && current_key_id.unwrap() == key_id {
            let current_link = self.keys_dir.join("current");
            if current_link.exists() {
                fs::remove_file(&current_link)?;
            }
        }

        Ok(())
    }

    /// Get the current key ID
    pub fn get_current_key_id(&self) -> Result<String> {
        self.read_current_key_id()
    }

    /// List all available key IDs with their metadata
    pub fn list_key_ids(&self) -> Result<Vec<(String, StoredKeyPair)>> {
        let mut keys = Vec::new();

        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip non-TOML files and the "current" symlink/file
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }

            let content = fs::read_to_string(&path)?;
            if let Ok(stored_keypair) = toml::from_str::<StoredKeyPair>(&content) {
                keys.push((stored_keypair.uuid.clone(), stored_keypair));
            }
        }

        // Sort by creation time (most recent first)
        keys.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));

        Ok(keys)
    }

    /// Read the current key ID from the "current" symlink/file
    fn read_current_key_id(&self) -> Result<String> {
        let current_path = self.keys_dir.join("current");

        #[cfg(unix)]
        {
            // On Unix, read the symlink target
            let target = fs::read_link(&current_path)?;
            let filename = target
                .file_name()
                .ok_or_else(|| anyhow!("Invalid current symlink target"))?
                .to_string_lossy();

            if let Some(key_id) = filename.strip_suffix(".toml") {
                Ok(key_id.to_string())
            } else {
                Err(anyhow!("Invalid current symlink target format"))
            }
        }

        #[cfg(windows)]
        {
            // On Windows, read the file content
            let target_filename = fs::read_to_string(&current_path)?;
            if let Some(key_id) = target_filename.strip_suffix(".toml") {
                Ok(key_id.to_string())
            } else {
                Err(anyhow!("Invalid current file format"))
            }
        }
    }

    /// Decrypt a stored keypair
    fn decrypt_stored_keypair(
        &self,
        stored: &StoredKeyPair,
        password: Option<&str>,
    ) -> Result<KeyPair> {
        let public_key = PublicKey::from_base64(&stored.public_key)?;

        let secret_key = if stored.is_password_protected {
            let password =
                password.ok_or_else(|| anyhow!("Password required for encrypted key"))?;

            let salt = stored
                .salt
                .as_ref()
                .ok_or_else(|| anyhow!("Salt missing for password-protected key"))?;
            let salt = crate::kdf::Salt::from_base64(salt)?;
            let derived_key = crate::kdf::DerivedKey::derive(password, &salt)?;

            let encrypted_data =
                base64::prelude::BASE64_STANDARD.decode(&stored.encrypted_secret_key)?;
            let decrypted_data =
                crate::crypto::decrypt(&encrypted_data, &derived_key.to_encryption_key())?;

            let secret_key_b64 = String::from_utf8(decrypted_data)?;
            SecretKey::from_base64(&secret_key_b64)?
        } else {
            SecretKey::from_base64(&stored.encrypted_secret_key)?
        };

        Ok(KeyPair {
            public_key,
            secret_key,
        })
    }
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new().expect("Failed to create keystore")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a temporary keystore for testing
    fn create_temp_keystore() -> Result<(Keystore, TempDir)> {
        let temp_dir = TempDir::new()?;
        let keys_dir = temp_dir.path().to_path_buf();
        let keystore = Keystore { keys_dir };
        Ok((keystore, temp_dir))
    }

    #[test]
    fn test_store_and_retrieve_keypair() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;
        let keypair = KeyPair::generate()?;

        // Store without password
        let key_id = keystore.store_keypair(&keypair, None)?;
        assert!(!key_id.is_empty());

        // Retrieve
        let retrieved = keystore.get_current_keypair(None)?;
        assert_eq!(
            keypair.public_key.to_base64(),
            retrieved.public_key.to_base64()
        );
        assert_eq!(
            keypair.secret_key.to_base64(),
            retrieved.secret_key.to_base64()
        );

        Ok(())
    }

    #[test]
    fn test_password_protected_keypair() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;
        let keypair = KeyPair::generate()?;
        let password = "test_password_123";

        // Store with password
        let key_id = keystore.store_keypair(&keypair, Some(password))?;
        assert!(!key_id.is_empty());

        // Should fail without password
        assert!(keystore.get_current_keypair(None).is_err());

        // Should work with correct password
        let retrieved = keystore.get_current_keypair(Some(password))?;
        assert_eq!(
            keypair.public_key.to_base64(),
            retrieved.public_key.to_base64()
        );
        assert_eq!(
            keypair.secret_key.to_base64(),
            retrieved.secret_key.to_base64()
        );

        // Should fail with wrong password
        assert!(keystore
            .get_current_keypair(Some("wrong_password"))
            .is_err());

        Ok(())
    }

    #[test]
    fn test_multiple_keypairs_ordering() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;

        // Store multiple keypairs
        let keypair1 = KeyPair::generate()?;
        let keypair2 = KeyPair::generate()?;
        let keypair3 = KeyPair::generate()?;

        keystore.store_keypair(&keypair1, None)?;
        std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure different timestamps
        keystore.store_keypair(&keypair2, None)?;
        std::thread::sleep(std::time::Duration::from_millis(10));
        keystore.store_keypair(&keypair3, None)?;

        // Current should be keypair3 (latest stored)
        let current = keystore.get_current_keypair(None)?;
        assert_eq!(
            keypair3.public_key.to_base64(),
            current.public_key.to_base64()
        );

        // All should include all three keypairs
        let all = keystore.get_all_keypairs(None)?;
        assert_eq!(all.len(), 3);

        Ok(())
    }

    #[test]
    fn test_count_and_delete() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;

        assert_eq!(keystore.count_keypairs()?, 0);

        let keypair = KeyPair::generate()?;
        let key_id = keystore.store_keypair(&keypair, None)?;

        assert_eq!(keystore.count_keypairs()?, 1);

        keystore.delete_keypair(&key_id)?;
        assert_eq!(keystore.count_keypairs()?, 0);

        // Deleting non-existent key should fail
        assert!(keystore.delete_keypair("non-existent-uuid").is_err());

        Ok(())
    }
}
