#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value, // KdfParams is kept by value for API clarity
)]

use anyhow::{anyhow, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use directories::UserDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use crate::crypto::{ClassicKeyPair, KeyPair, PublicKey, SecretKey};
use crate::kdf::{DerivedKey, KdfParams, Salt};
use crate::keyring_support;

/// Stored keypair file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyPair {
    pub uuid: String,
    pub public_key: String,
    pub encrypted_secret_key: String,
    pub salt: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_password_protected: bool,
    /// Whether the secret key is stored in the system keyring instead of this file
    #[serde(default)]
    pub in_keyring: bool,
    /// Optional hybrid (X448 + sntrup761) public key, base64-encoded.
    /// Absent in classic-only keystores; `#[serde(default)]` ensures old files
    /// deserialize without error (RESEARCH.md Pitfall 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub hybrid_public_key: Option<String>,
    /// Optional hybrid secret key (encrypted or plain), base64-encoded.
    /// Encrypted iff `is_password_protected == true`; shares the same KDF salt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub hybrid_encrypted_secret_key: Option<String>,
}

/// Simple file-based keystore using ~/.config/sss/keys/
pub struct Keystore {
    keys_dir: PathBuf,
    kdf_params: KdfParams,
    use_keyring: bool,
}

impl Keystore {
    /// Create a new keystore instance with default (sensitive) KDF parameters
    pub fn new() -> Result<Self> {
        Self::new_with_kdf_params(KdfParams::sensitive(), false)
    }

    /// Create a new keystore instance with custom KDF parameters
    pub fn new_with_kdf_params(kdf_params: KdfParams, use_keyring: bool) -> Result<Self> {
        let keys_dir = Self::get_keys_directory()?;
        Self::create_with_directory(keys_dir, kdf_params, use_keyring)
    }

    /// Create a new keystore instance with custom config directory
    pub fn new_with_config_dir(config_dir: PathBuf) -> Result<Self> {
        Self::new_with_config_dir_and_kdf(config_dir, KdfParams::sensitive(), false)
    }

    /// Create a new keystore instance with custom config directory and KDF parameters
    pub fn new_with_config_dir_and_kdf(config_dir: PathBuf, kdf_params: KdfParams, use_keyring: bool) -> Result<Self> {
        let keys_dir = config_dir.join("sss").join("keys");
        Self::create_with_directory(keys_dir, kdf_params, use_keyring)
    }

    /// Internal helper to create keystore with a specific directory
    fn create_with_directory(keys_dir: PathBuf, kdf_params: KdfParams, use_keyring: bool) -> Result<Self> {
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

        // Validate keyring availability if requested
        if use_keyring && !keyring_support::is_keyring_available() {
            eprintln!("⚠️  WARNING: System keyring requested but not available!");
            eprintln!("   Falling back to file-based storage.");
            eprintln!("   Keys will be stored without password protection.");
            return Ok(Self { keys_dir, kdf_params, use_keyring: false });
        }

        Ok(Self { keys_dir, kdf_params, use_keyring })
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
        let config_dir = std::env::var("XDG_CONFIG_HOME").map_or_else(|_| user_dirs.home_dir().join(".config"), PathBuf::from);

        Ok(config_dir.join("sss").join("keys"))
    }

    /// Store a new keypair with optional password protection
    pub fn store_keypair(&self, keypair: &KeyPair, password: Option<&str>) -> Result<String> {
        let key_id = Uuid::new_v4().to_string();

        let (encrypted_secret_key, salt, is_password_protected) = if let Some(password) = password {
            // Encrypt secret key with password-derived key
            let salt = Salt::new();
            let derived_key = DerivedKey::derive_with_params(password, &salt, &self.kdf_params)?;

            let secret_key_str = keypair.secret_key()?.to_base64();
            let encrypted_secret_key =
                crate::crypto::encrypt_to_base64(&secret_key_str, &derived_key.to_encryption_key())?;
            (encrypted_secret_key, Some(salt.to_base64()), true)
        } else {
            // ⚠️  SECURITY WARNING: Storing secret key without password protection!
            // The key will be base64 encoded but NOT encrypted.
            //
            // RISKS:
            // - Anyone with filesystem access can read your private key
            // - Backups, disk images, or cloud sync may expose the key
            // - No protection if the file is accidentally shared
            //
            // RECOMMENDATIONS:
            // 1. Use password protection (recommended for most users)
            // 2. Use system keyring with SSS_USE_KEYRING=true (for headless systems)
            // 3. Ensure ~/.config/sss/keys/ has restrictive permissions (0700)
            eprintln!("\n⚠️  WARNING: Storing keypair WITHOUT password protection!");
            eprintln!("   Your private key will be accessible to anyone who can read:");
            eprintln!("   ~/.config/sss/keys/");
            eprintln!("\n   Consider using:");
            eprintln!("   - Password protection (recommended)");
            eprintln!("   - System keyring (SSS_USE_KEYRING=true)");
            eprintln!();
            (keypair.secret_key()?.to_base64(), None, false)
        };

        // Handle keyring storage if enabled and no password provided
        let (final_encrypted_key, in_keyring) = if self.use_keyring && password.is_none() {
            // Store in system keyring instead of file
            let secret_key_b64 = keypair.secret_key()?.to_base64();
            keyring_support::store_key_in_keyring(&key_id, &secret_key_b64)?;
            eprintln!("✓ Private key stored in system keyring");
            // Store placeholder in file
            ("STORED_IN_KEYRING".to_string(), true)
        } else {
            (encrypted_secret_key, false)
        };

        let stored_keypair = StoredKeyPair {
            uuid: key_id.clone(),
            public_key: keypair.public_key().to_base64(),
            encrypted_secret_key: final_encrypted_key,
            salt,
            created_at: Utc::now(),
            is_password_protected,
            in_keyring,
            hybrid_public_key: None,
            hybrid_encrypted_secret_key: None,
        };

        // Write keypair to file
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
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

    /// Set the current key by atomically replacing the "current" symlink.
    ///
    /// Uses a create-at-temp + rename pattern to avoid the TOCTOU race that
    /// occurs when multiple callers check-then-create the symlink concurrently.
    pub fn set_current_key(&self, key_id: &str) -> Result<()> {
        let current_link = self.keys_dir.join("current");
        let target = format!("{key_id}.toml");

        #[cfg(unix)]
        {
            // Write to a unique temp name then rename(2) into place.
            // rename(2) is atomic on POSIX and replaces an existing destination,
            // so no explicit remove or existence check is needed.
            let tmp_link = self.keys_dir.join(format!("current.tmp.{}", Uuid::new_v4()));
            std::os::unix::fs::symlink(&target, &tmp_link)?;
            fs::rename(&tmp_link, &current_link)?;
        }

        #[cfg(windows)]
        {
            // On Windows write to a temp path then rename into place.
            let tmp_path = self.keys_dir.join(format!("current.tmp.{}", Uuid::new_v4()));
            fs::write(&tmp_path, &target)?;
            fs::rename(&tmp_path, &current_link)?;
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
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));

        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
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
            if let Ok(stored_keypair) = toml::from_str::<StoredKeyPair>(&content)
                && let Ok(keypair) = self.decrypt_stored_keypair(&stored_keypair, password) {
                    keypairs.push(keypair);
                }
        }

        // Sort by public-key base64 for deterministic ordering.
        keypairs.sort_by(|a, b| b.public_key().to_base64().cmp(&a.public_key().to_base64()));

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
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));

        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }

        fs::remove_file(&key_file)?;

        // If this was the current key, remove the current link.
        // WR-01 fix: bind read_current_key_id once via if-let to avoid TOCTOU double-call.
        if let Ok(current_id) = self.read_current_key_id()
            && current_id == key_id {
                let current_link = self.keys_dir.join("current");
                if current_link.exists() {
                    fs::remove_file(&current_link)?;
                }
            }

        Ok(())
    }

    /// Set or change the passphrase for a keypair
    ///
    /// This can:
    /// - Add a passphrase to a passwordless key
    /// - Change the passphrase of a password-protected key
    ///
    /// # Arguments
    /// * `key_id` - The ID of the key to modify
    /// * `old_password` - Current password (None if key is not protected)
    /// * `new_password` - New password to set
    pub fn set_passphrase(
        &self,
        key_id: &str,
        old_password: Option<&str>,
        new_password: &str,
    ) -> Result<()> {
        // Load the keypair with the old password (if any)
        let keypair = self.load_keypair(key_id, old_password)?;

        // Load the stored keypair metadata to preserve other fields
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        let content = fs::read_to_string(&key_file)?;
        let mut stored: StoredKeyPair = toml::from_str(&content)?;

        // Encrypt with new password
        let salt = Salt::new();
        let derived_key = DerivedKey::derive_with_params(new_password, &salt, &self.kdf_params)?;
        let secret_key_str = keypair.secret_key()?.to_base64();
        let encrypted_secret_key =
            crate::crypto::encrypt_to_base64(&secret_key_str, &derived_key.to_encryption_key())?;

        // Re-encrypt hybrid material before stored.salt is overwritten (WR-01).
        // Reads the original salt from `stored` to re-derive the old decryption key.
        #[cfg(feature = "hybrid")]
        if let Some(ref enc_hybrid_b64) = stored.hybrid_encrypted_secret_key.clone() {
            use base64::prelude::BASE64_STANDARD;
            use zeroize::Zeroizing;
            let raw_hybrid: Zeroizing<Vec<u8>> = if let Some(ref old_pw) = old_password {
                let old_salt_str = stored
                    .salt
                    .as_ref()
                    .ok_or_else(|| anyhow!("Salt missing for password-protected hybrid key"))?;
                let old_salt = Salt::from_base64(old_salt_str)?;
                let old_dk =
                    DerivedKey::derive_with_params(old_pw, &old_salt, &self.kdf_params)?;
                let enc_bytes = BASE64_STANDARD.decode(enc_hybrid_b64)?;
                let dec = Zeroizing::new(crate::crypto::decrypt(
                    &enc_bytes,
                    &old_dk.to_encryption_key(),
                )?);
                Zeroizing::new(BASE64_STANDARD.decode(std::str::from_utf8(&dec)?)?)
            } else {
                // Was passwordless — stored as raw base64
                Zeroizing::new(BASE64_STANDARD.decode(enc_hybrid_b64)?)
            };
            let hybrid_sk_b64 = BASE64_STANDARD.encode(&raw_hybrid[..]);
            let new_enc = crate::crypto::encrypt_to_base64(
                &hybrid_sk_b64,
                &derived_key.to_encryption_key(),
            )?;
            stored.hybrid_encrypted_secret_key = Some(new_enc);
        }

        // Update the stored keypair
        stored.encrypted_secret_key = encrypted_secret_key;
        stored.salt = Some(salt.to_base64());
        stored.is_password_protected = true;

        // Write back to file
        let content = toml::to_string_pretty(&stored)?;
        fs::write(&key_file, content)?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_file, perms)?;
        }

        Ok(())
    }

    /// Remove passphrase protection from a keypair
    ///
    /// Converts a password-protected key to a passwordless key.
    /// Warning: The private key will be stored unencrypted (only base64 encoded).
    ///
    /// # Arguments
    /// * `key_id` - The ID of the key to modify
    /// * `current_password` - Current password protecting the key
    pub fn remove_passphrase(&self, key_id: &str, current_password: &str) -> Result<()> {
        // Load the keypair with the current password
        let keypair = self.load_keypair(key_id, Some(current_password))?;

        // Load the stored keypair metadata
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        let content = fs::read_to_string(&key_file)?;
        let mut stored: StoredKeyPair = toml::from_str(&content)?;

        // Decrypt hybrid material before clearing the salt (WR-02).
        // After this block, hybrid_encrypted_secret_key holds the raw sk base64 (passwordless form).
        #[cfg(feature = "hybrid")]
        if let Some(ref enc_hybrid_b64) = stored.hybrid_encrypted_secret_key.clone() {
            use base64::prelude::BASE64_STANDARD;
            use zeroize::Zeroizing;
            let salt_str = stored
                .salt
                .as_ref()
                .ok_or_else(|| anyhow!("Salt missing for password-protected hybrid key"))?;
            let salt_obj = Salt::from_base64(salt_str)?;
            let dk = DerivedKey::derive_with_params(
                current_password,
                &salt_obj,
                &self.kdf_params,
            )?;
            let enc_bytes = BASE64_STANDARD.decode(enc_hybrid_b64)?;
            let dec = Zeroizing::new(crate::crypto::decrypt(&enc_bytes, &dk.to_encryption_key())?);
            // dec is the base64 of the raw sk bytes — store it directly as passwordless form
            stored.hybrid_encrypted_secret_key =
                Some(String::from_utf8(dec.to_vec())?);
        }

        // Store secret key as plaintext (base64 encoded)
        stored.encrypted_secret_key = keypair.secret_key()?.to_base64();
        stored.salt = None;
        stored.is_password_protected = false;

        // Write back to file
        let content = toml::to_string_pretty(&stored)?;
        fs::write(&key_file, content)?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_file, perms)?;
        }

        Ok(())
    }

    /// Get the current key ID
    pub fn get_current_key_id(&self) -> Result<String> {
        self.read_current_key_id()
    }

    /// Check if the current key is password protected
    pub fn is_current_key_password_protected(&self) -> Result<bool> {
        let key_id = self.read_current_key_id()?;
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));

        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }

        let content = fs::read_to_string(&key_file)?;
        let stored_keypair: StoredKeyPair = toml::from_str(&content)?;

        Ok(stored_keypair.is_password_protected)
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

    // ─────────────────────────────────────────────────────────────────────────
    // Hybrid (dual-suite) methods — gated by `hybrid` feature (KEYSTORE-01/03/04)
    // ─────────────────────────────────────────────────────────────────────────

    /// Read the raw `StoredKeyPair` for the current identity without decrypting
    /// any secret material. Used by `handle_keys_show` to display public keys
    /// and by `store_dual_keypair` Case B to detect whether hybrid is already present.
    #[cfg(feature = "hybrid")]
    pub fn get_current_stored_raw(&self) -> Result<StoredKeyPair> {
        let key_id = self.read_current_key_id()?;
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }
        let content = fs::read_to_string(&key_file)?;
        Ok(toml::from_str(&content)?)
    }

    /// Store a dual-suite keypair with optional password protection.
    ///
    /// Handles three cases:
    ///
    /// - **Case A** (`classic_keypair = Some`, `hybrid_keypair = Some`): generates a fresh
    ///   UUID, derives one KDF key, encrypts both secrets under the same derived key.
    ///   Writes a new TOML file and calls `set_current_key`.
    ///
    /// - **Case B** (`classic_keypair = None`, `hybrid_keypair = Some`): read-modify-write
    ///   of the existing current identity. Adds hybrid material only; does NOT change the
    ///   UUID, classic fields, or salt (KEYSTORE-03). Returns an error if hybrid material
    ///   is already present.
    ///
    /// - **Case C** (`classic_keypair = Some`, `hybrid_keypair = None`): delegates to
    ///   the existing `store_keypair` by wrapping the classic keypair in `KeyPair::Classic`.
    #[cfg(feature = "hybrid")]
    pub fn store_dual_keypair(
        &self,
        classic_keypair: Option<&ClassicKeyPair>,
        hybrid_keypair: Option<&crate::crypto::HybridKeyPair>,
        password: Option<&str>,
    ) -> Result<String> {
        use base64::prelude::BASE64_STANDARD;

        match (classic_keypair, hybrid_keypair) {
            // Case C — classic only: delegate to the existing method
            (Some(classic), None) => {
                self.store_keypair(&KeyPair::Classic(classic.clone()), password)
            }

            // Case A — both keys, fresh identity file
            (Some(classic), Some(hybrid)) => {
                let key_id = uuid::Uuid::new_v4().to_string();

                let (enc_classic, enc_hybrid, stored_salt, is_protected) =
                    if let Some(pw) = password {
                        let salt = crate::kdf::Salt::new();
                        let dk = crate::kdf::DerivedKey::derive_with_params(
                            pw, &salt, &self.kdf_params,
                        )?;
                        let enc_key = dk.to_encryption_key();

                        // Classic secret — standard path (32-byte key, base64 string)
                        let classic_sk_b64 =
                            KeyPair::Classic(classic.clone()).secret_key()?.to_base64();
                        let enc_classic =
                            crate::crypto::encrypt_to_base64(&classic_sk_b64, &enc_key)?;

                        // Hybrid secret — encode directly from Zeroizing<[u8; N]> to
                        // avoid copying into a non-Zeroizing buffer (T-03-02).
                        let hybrid_sk_b64 =
                            BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref());
                        let enc_hybrid =
                            crate::crypto::encrypt_to_base64(&hybrid_sk_b64, &enc_key)?;

                        (enc_classic, enc_hybrid, Some(salt.to_base64()), true)
                    } else {
                        // Passwordless path — store raw base64 (same warning as store_keypair)
                        eprintln!("\n⚠️  WARNING: Storing dual-suite keypair WITHOUT password protection!");
                        eprintln!("   Your private keys will be accessible to anyone who can read:");
                        eprintln!("   ~/.config/sss/keys/");
                        eprintln!("\n   Consider using password protection (recommended)\n");

                        let classic_sk_b64 =
                            KeyPair::Classic(classic.clone()).secret_key()?.to_base64();
                        let hybrid_sk_b64 =
                            BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref());
                        (classic_sk_b64, hybrid_sk_b64, None, false)
                    };

                let stored = StoredKeyPair {
                    uuid: key_id.clone(),
                    public_key: KeyPair::Classic(classic.clone()).public_key().to_base64(),
                    encrypted_secret_key: enc_classic,
                    salt: stored_salt,
                    created_at: chrono::Utc::now(),
                    is_password_protected: is_protected,
                    in_keyring: false,
                    hybrid_public_key: Some(
                        BASE64_STANDARD.encode(&hybrid.public_bytes),
                    ),
                    hybrid_encrypted_secret_key: Some(enc_hybrid),
                };

                let key_file = self.keys_dir.join(format!("{key_id}.toml"));
                let content = toml::to_string_pretty(&stored)?;
                fs::write(&key_file, content)?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = fs::metadata(&key_file)?;
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    fs::set_permissions(&key_file, perms)?;
                }

                self.set_current_key(&key_id)?;
                Ok(key_id)
            }

            // Case B — hybrid only: upgrade existing classic identity
            (None, Some(hybrid)) => {
                let key_id = self.read_current_key_id()?;
                let key_file = self.keys_dir.join(format!("{key_id}.toml"));
                if !key_file.exists() {
                    return Err(anyhow!("Key file not found: {key_id}"));
                }

                let content = fs::read_to_string(&key_file)?;
                let mut stored: StoredKeyPair = toml::from_str(&content)?;

                // Guard: refuse to overwrite existing hybrid material (T-03-03)
                if stored.hybrid_public_key.is_some() {
                    return Err(anyhow!(
                        "hybrid keypair already present in this identity; \
                         use --suite both to replace"
                    ));
                }

                // Encrypt new hybrid material under the EXISTING salt (KEYSTORE-04).
                // We re-derive only to encrypt the new hybrid secret; the classic
                // material is not touched.
                let enc_hybrid = if stored.is_password_protected {
                    let pw = password.ok_or_else(|| {
                        anyhow!("Password required to add hybrid material to a protected identity")
                    })?;
                    let salt_str = stored.salt.as_ref().ok_or_else(|| {
                        anyhow!("Salt missing for password-protected key")
                    })?;
                    let salt = crate::kdf::Salt::from_base64(salt_str)?;
                    let dk = crate::kdf::DerivedKey::derive_with_params(
                        pw, &salt, &self.kdf_params,
                    )?;
                    let hybrid_sk_b64 =
                        BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref());
                    crate::crypto::encrypt_to_base64(
                        &hybrid_sk_b64,
                        &dk.to_encryption_key(),
                    )?
                } else {
                    // Passwordless — store raw base64
                    BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref())
                };

                // Append hybrid fields — all classic fields are untouched (KEYSTORE-03)
                stored.hybrid_public_key =
                    Some(BASE64_STANDARD.encode(&hybrid.public_bytes));
                stored.hybrid_encrypted_secret_key = Some(enc_hybrid);

                let updated_content = toml::to_string_pretty(&stored)?;
                fs::write(&key_file, updated_content)?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = fs::metadata(&key_file)?;
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    fs::set_permissions(&key_file, perms)?;
                }

                Ok(key_id)
            }

            // Neither key provided — nothing to store
            (None, None) => Err(anyhow!(
                "store_dual_keypair called with neither classic nor hybrid keypair"
            )),
        }
    }

    /// Load and decrypt a hybrid keypair from a stored identity file.
    ///
    /// Returns `Err` if the file has no hybrid material, or if decryption fails.
    #[cfg(feature = "hybrid")]
    pub fn load_hybrid_keypair(
        &self,
        key_id: &str,
        password: Option<&str>,
    ) -> Result<crate::crypto::HybridKeyPair> {
        use base64::prelude::BASE64_STANDARD;
        use crate::constants::HYBRID_SECRET_KEY_SIZE;
        use crate::constants::HYBRID_PUBLIC_KEY_SIZE;
        use zeroize::Zeroizing;

        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }

        let content = fs::read_to_string(&key_file)?;
        let stored: StoredKeyPair = toml::from_str(&content)?;

        // Guard: no hybrid material stored
        let hybrid_pub_b64 = stored.hybrid_public_key.ok_or_else(|| {
            anyhow!(
                "your keystore has no hybrid keypair; \
                 run `sss keygen --suite hybrid` to add one"
            )
        })?;
        let hybrid_enc_sk_b64 = stored.hybrid_encrypted_secret_key.ok_or_else(|| {
            anyhow!("hybrid encrypted secret key missing from identity file")
        })?;

        // Decrypt the hybrid secret material using the same path as classic.
        // All intermediates are Zeroizing so secret bytes don't linger on the heap (WR-03).
        let raw_secret_bytes: Zeroizing<Vec<u8>> = if stored.is_password_protected {
            let pw = password.ok_or_else(|| {
                anyhow!("Password required for encrypted key")
            })?;
            let salt_str = stored.salt.as_ref().ok_or_else(|| {
                anyhow!("Salt missing for password-protected key")
            })?;
            let salt = crate::kdf::Salt::from_base64(salt_str)?;
            let dk = crate::kdf::DerivedKey::derive_with_params(
                pw, &salt, &self.kdf_params,
            )?;
            let enc_bytes = BASE64_STANDARD.decode(&hybrid_enc_sk_b64)?;
            let decrypted = Zeroizing::new(crate::crypto::decrypt(&enc_bytes, &dk.to_encryption_key())?);
            // decrypted is the base64 string of the raw secret bytes
            Zeroizing::new(BASE64_STANDARD.decode(std::str::from_utf8(&decrypted)?)?)
        } else {
            // Passwordless — stored as raw base64
            Zeroizing::new(BASE64_STANDARD.decode(&hybrid_enc_sk_b64)?)
        };

        if raw_secret_bytes.len() != HYBRID_SECRET_KEY_SIZE {
            return Err(anyhow!(
                "hybrid secret key wrong length: expected {} bytes, got {}",
                HYBRID_SECRET_KEY_SIZE,
                raw_secret_bytes.len()
            ));
        }

        // Reconstruct public bytes
        let pub_bytes_raw = BASE64_STANDARD.decode(&hybrid_pub_b64)?;
        if pub_bytes_raw.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "hybrid public key wrong length: expected {} bytes, got {}",
                HYBRID_PUBLIC_KEY_SIZE,
                pub_bytes_raw.len()
            ));
        }
        let mut public_bytes = [0u8; HYBRID_PUBLIC_KEY_SIZE];
        public_bytes.copy_from_slice(&pub_bytes_raw);

        // Reconstruct secret bytes into Zeroizing<[u8; N]> (T-03-05)
        let mut secret_array = [0u8; HYBRID_SECRET_KEY_SIZE];
        secret_array.copy_from_slice(&raw_secret_bytes);
        let secret_bytes = Zeroizing::new(secret_array);

        Ok(crate::crypto::HybridKeyPair { public_bytes, secret_bytes })
    }

    /// Decrypt a stored keypair
    fn decrypt_stored_keypair(
        &self,
        stored: &StoredKeyPair,
        password: Option<&str>,
    ) -> Result<KeyPair> {
        let public_key = PublicKey::from_base64(&stored.public_key)?;

        let secret_key = if stored.in_keyring {
            // Retrieve from system keyring
            let secret_key_b64 = keyring_support::get_key_from_keyring(&stored.uuid)?;
            SecretKey::from_base64(&secret_key_b64)?
        } else if stored.is_password_protected {
            let password =
                password.ok_or_else(|| anyhow!("Password required for encrypted key"))?;

            let salt = stored
                .salt
                .as_ref()
                .ok_or_else(|| anyhow!("Salt missing for password-protected key"))?;
            let salt = crate::kdf::Salt::from_base64(salt)?;
            let derived_key = crate::kdf::DerivedKey::derive_with_params(password, &salt, &self.kdf_params)?;

            let encrypted_data =
                base64::prelude::BASE64_STANDARD.decode(&stored.encrypted_secret_key)?;
            let decrypted_data =
                crate::crypto::decrypt(&encrypted_data, &derived_key.to_encryption_key())?;

            let secret_key_b64 = String::from_utf8(decrypted_data)?;
            SecretKey::from_base64(&secret_key_b64)?
        } else {
            SecretKey::from_base64(&stored.encrypted_secret_key)?
        };

        Ok(KeyPair::Classic(ClassicKeyPair {
            public_key,
            secret_key,
        }))
    }
}

/// Get password/passphrase from `SSS_PASSPHRASE` environment variable or prompt user
///
/// This is the primary method for obtaining passphrases for password-protected keys.
/// It checks the `SSS_PASSPHRASE` environment variable first (useful for automation and testing),
/// then falls back to an interactive prompt if not set.
///
/// In non-interactive mode (`SSS_NONINTERACTIVE=1` or --non-interactive flag), this function
/// will fail if `SSS_PASSPHRASE` is not set, rather than prompting the user.
///
/// # Arguments
/// * `prompt` - The prompt to show when environment variable is not set
///
/// # Returns
/// * `Result<String>` - The password/passphrase
///
/// # Examples
/// ```no_run
/// use sss::keystore::get_passphrase_or_prompt;
///
/// // With environment variable set:
/// // SSS_PASSPHRASE="my-secret" cargo run
///
/// // Or interactive prompt:
/// let passphrase = get_passphrase_or_prompt("Enter passphrase: ").unwrap();
///
/// // Non-interactive mode (will fail if SSS_PASSPHRASE not set):
/// // sss --non-interactive keys list
/// ```
pub fn get_passphrase_or_prompt(prompt: &str) -> Result<String> {
    // Check SSS_PASSPHRASE environment variable first
    if let Ok(passphrase) = std::env::var("SSS_PASSPHRASE") {
        return Ok(passphrase);
    }

    // Check if we're in non-interactive mode
    if std::env::var("SSS_NONINTERACTIVE").is_ok() {
        return Err(anyhow!(
            "Non-interactive mode enabled but SSS_PASSPHRASE environment variable is not set. \
             Either set SSS_PASSPHRASE or remove --non-interactive flag."
        ));
    }

    // Fall back to interactive prompt
    rpassword::prompt_password(prompt).map_err(|e| anyhow!("Failed to read passphrase: {e}"))
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
        let keystore = Keystore {
            keys_dir,
            kdf_params: KdfParams::sensitive(),
            use_keyring: false,
        };
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
            keypair.public_key().to_base64(),
            retrieved.public_key().to_base64()
        );
        assert_eq!(
            keypair.secret_key()?.to_base64(),
            retrieved.secret_key()?.to_base64()
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
            keypair.public_key().to_base64(),
            retrieved.public_key().to_base64()
        );
        assert_eq!(
            keypair.secret_key()?.to_base64(),
            retrieved.secret_key()?.to_base64()
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
            keypair3.public_key().to_base64(),
            current.public_key().to_base64()
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

    // ─────────────────────────────────────────────────────────────────────────
    // Task 1 TDD RED: dual-suite struct extension behavioural assertions
    // These tests will not compile until the StoredKeyPair fields and Keystore
    // methods introduced in Task 1 are in place.
    // ─────────────────────────────────────────────────────────────────────────

    /// Classic-only StoredKeyPair has hybrid fields set to None (backward compat).
    #[test]
    fn test_stored_keypair_hybrid_fields_default_none() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;
        let keypair = KeyPair::generate()?;
        let key_id = keystore.store_keypair(&keypair, None)?;

        let key_file = keystore.keys_dir.join(format!("{key_id}.toml"));
        let content = std::fs::read_to_string(&key_file)?;
        let stored: StoredKeyPair = toml::from_str(&content)?;

        // Both new hybrid fields must default to None on a classic-only file
        assert!(stored.hybrid_public_key.is_none(),
            "hybrid_public_key should be None for classic-only identity");
        assert!(stored.hybrid_encrypted_secret_key.is_none(),
            "hybrid_encrypted_secret_key should be None for classic-only identity");

        Ok(())
    }

    /// get_current_stored_raw returns the raw StoredKeyPair without decrypting.
    #[cfg(feature = "hybrid")]
    #[test]
    fn test_get_current_stored_raw_returns_stored_keypair() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;
        let keypair = KeyPair::generate()?;
        let key_id = keystore.store_keypair(&keypair, Some("testpass"))?;

        let raw = keystore.get_current_stored_raw()?;
        assert_eq!(raw.uuid, key_id);
        assert_eq!(raw.public_key, keypair.public_key().to_base64());
        assert!(raw.hybrid_public_key.is_none());

        Ok(())
    }

    /// load_hybrid_keypair on a classic-only file returns the expected error.
    #[cfg(feature = "hybrid")]
    #[test]
    fn test_load_hybrid_keypair_on_classic_only_errors() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;
        let keypair = KeyPair::generate()?;
        let key_id = keystore.store_keypair(&keypair, None)?;

        let result = keystore.load_hybrid_keypair(&key_id, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no hybrid keypair"),
            "error message must contain 'no hybrid keypair'");

        Ok(())
    }
}
