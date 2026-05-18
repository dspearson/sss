// Why: KdfParams is kept by value for API clarity (audited Phase 21 Plan 21-02).
// Why: crypto-idiomatic naming uses _sk/_pk suffixes (e.g. ed448_sk vs ed448_pk,
// mldsa_sk vs mldsa_pk) — renaming to satisfy similar_names would obscure the
// public-key vs secret-key distinction in dual-suite signature flows. The 4
// production-side sites + 6 test-side sites collectively trigger this lint.
#![allow(clippy::needless_pass_by_value, clippy::similar_names)]

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

    // ── new in v2 (Phase 18, PQSIG-03) ─────────────────────────────────────
    /// On-disk schema version. `1` = legacy unsigned (no `[signature]` table);
    /// `2` = signed (has `[signature]`); `≥3` = future, current builds reject.
    /// MUST always be present in deser output regardless of feature flags so
    /// non-hybrid builds can detect a v2 entry and refuse cleanly (T-18-02-04).
    /// Pitfall 5: `#[serde(default = "default_format_version")]` is REQUIRED —
    /// a bare `#[serde(default)]` would call `Default::default()` returning 0
    /// for `u32`, breaking legacy-file dispatch (D-10).
    #[serde(default = "default_format_version")]
    pub format_version: u32,

    /// Per-entry Ed448 signing public key (base64). Present only on v2 entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig_ed448_public_key: Option<String>,

    /// Per-entry Ed448 signing secret key, encrypted under the same KDF-derived
    /// KEK as `encrypted_secret_key` (D-07). Base64-encoded ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig_ed448_encrypted_secret_key: Option<String>,

    /// Per-entry ML-DSA-65 signing public key (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig_mldsa65_public_key: Option<String>,

    /// Per-entry ML-DSA-65 signing secret key, encrypted (D-07).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig_mldsa65_encrypted_secret_key: Option<String>,

    /// AND-composition signature (Ed448 + ML-DSA-65) over the canonical payload
    /// from `keystore::sig::build_signed_payload`. Stored as a TOML sub-table
    /// `[signature]` with `ed448` and `mldsa65` string fields (D-09).
    ///
    /// Source-level `#[cfg(feature = "hybrid")]` (not just `cfg_attr(serde(skip))`)
    /// because `KeystoreEntrySig` is itself gated behind the `hybrid` feature
    /// (sig.rs has `#![cfg(feature = "hybrid")]`); referencing it from a
    /// non-hybrid build would fail to compile. A non-hybrid build that reads a
    /// v2 TOML entry will see `format_version=2` and reject in 18-03 dispatch
    /// before any sig field is consulted.
    #[cfg(feature = "hybrid")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<crate::keystore::sig::KeystoreEntrySig>,
}

/// Default format version for legacy keystore entries.
/// Pre-Phase-18 entries omit the `format_version` TOML key entirely;
/// serde calls this fn to populate the field as `1`.
/// Pitfall 5: must be a free function reference for `#[serde(default = "...")]`,
/// not `#[serde(default)]` (which would call `u32::default()` and yield 0).
fn default_format_version() -> u32 { 1 }

/// Simple file-based keystore using ~/.config/sss/keys/
pub struct Keystore {
    /// Directory holding the per-identity TOML files.
    /// Phase 18-03: elevated to `pub(crate)` so the import/export handlers
    /// (`src/commands/keys.rs::handle_keys_import` / `handle_keys_export`)
    /// can resolve destination paths verbatim without re-deriving them.
    pub(crate) keys_dir: PathBuf,
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
        fs::create_dir_all(&keys_dir)
            .map_err(|e| anyhow!("keystore: dir-create {}: {e}", keys_dir.display()))?;

        // Set secure permissions on the directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&keys_dir)
                .map_err(|e| anyhow!("keystore: stat keys-dir {}: {e}", keys_dir.display()))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o700); // Owner read/write/execute only
            fs::set_permissions(&keys_dir, perms)
                .map_err(|e| anyhow!("keystore: set-permissions on keys-dir {}: {e}", keys_dir.display()))?;
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
            let derived_key = DerivedKey::derive_with_params(password, &salt, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive (store_keypair): {e}"))?;

            let secret_key_str = keypair.secret_key()?.to_base64();
            let encrypted_secret_key =
                crate::crypto::encrypt_to_base64(&secret_key_str, &derived_key.to_encryption_key())
                    .map_err(|e| anyhow!("keystore: aead-encrypt-secret-key (store_keypair): {e}"))?;
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
            keyring_support::store_key_in_keyring(&key_id, &secret_key_b64)
                .map_err(|e| anyhow!("keystore: keyring-store for key_id={key_id}: {e}"))?;
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
            // Phase 18 / PQSIG-03 schema fields. classic-only `store_keypair`
            // emits `format_version: 1` (legacy unsigned); 18-03 will introduce
            // a v2-emitting path on the dual-suite branch.
            format_version: 1,
            sig_ed448_public_key: None,
            sig_ed448_encrypted_secret_key: None,
            sig_mldsa65_public_key: None,
            sig_mldsa65_encrypted_secret_key: None,
            #[cfg(feature = "hybrid")]
            signature: None,
        };

        // Write keypair to file
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        let content = toml::to_string_pretty(&stored_keypair)
            .map_err(|e| anyhow!("keystore: serialise stored-keypair toml for key_id={key_id}: {e}"))?;
        fs::write(&key_file, content)
            .map_err(|e| anyhow!("keystore: write key file {} for key_id={key_id}: {e}", key_file.display()))?;

        // Set secure permissions on the key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)
                .map_err(|e| anyhow!("keystore: stat key file {} for key_id={key_id}: {e}", key_file.display()))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&key_file, perms)
                .map_err(|e| anyhow!("keystore: set-permissions on key file {} for key_id={key_id}: {e}", key_file.display()))?;
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
            std::os::unix::fs::symlink(&target, &tmp_link)
                .map_err(|e| anyhow!("keystore: symlink current.tmp -> {target}: {e}"))?;
            fs::rename(&tmp_link, &current_link)
                .map_err(|e| anyhow!("keystore: rename current.tmp -> current: {e}"))?;
        }

        #[cfg(windows)]
        {
            // On Windows write to a temp path then rename into place.
            let tmp_path = self.keys_dir.join(format!("current.tmp.{}", Uuid::new_v4()));
            fs::write(&tmp_path, &target)
                .map_err(|e| anyhow!("keystore: write current.tmp: {}", e))?;
            fs::rename(&tmp_path, &current_link)
                .map_err(|e| anyhow!("keystore: rename current.tmp -> current: {}", e))?;
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
        // 18-03: get_current_keypair preserves prior behaviour — refuses to
        // load unsigned legacy entries silently. Callers wanting legacy
        // access must invoke `load_keypair(.., true)` directly.
        self.load_keypair(&key_id, password, false)
    }

    /// Load a specific keypair by ID.
    ///
    /// Phase 18-03 (PQSIG-02 / D-10): adds `allow_unsigned` parameter and
    /// `format_version` dispatch.
    /// - `format_version == 1` + `allow_unsigned == false` → hard error.
    /// - `format_version == 1` + `allow_unsigned == true`  → proceed (legacy read).
    /// - `format_version == 2` → invoke `verify_stored_signature` (hybrid only).
    /// - `format_version >= 3` → hard error (`unsupported format_version`).
    ///
    /// All v2 verify-failures (missing signature, missing pubkey, decode/parse
    /// failure, sig verify failure) collapse into the canonical D-20 error
    /// string. No sub-cause leakage.
    pub fn load_keypair(&self, key_id: &str, password: Option<&str>, allow_unsigned: bool) -> Result<KeyPair> {
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));

        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }

        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file for key_id={key_id}: {e}"))?;
        let stored_keypair: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml for key_id={key_id}: {e}"))?;

        // Phase 18 / D-10 format_version dispatch.
        match stored_keypair.format_version {
            1 => {
                if !allow_unsigned {
                    return Err(anyhow!(
                        "keystore: entry {key_id} is unsigned legacy format; pass --allow-unsigned to read or run `sss keys upgrade {key_id}` to re-sign"
                    ));
                }
                // Proceed without verify.
            }
            2 => {
                #[cfg(feature = "hybrid")]
                {
                    self.verify_stored_signature(&stored_keypair, &key_file)?;
                }
                #[cfg(not(feature = "hybrid"))]
                {
                    return Err(anyhow!(
                        "keystore: entry {} is signed (format_version=2) but the current build does not include the `hybrid` feature; rebuild with --features hybrid",
                        key_id
                    ));
                }
            }
            v => {
                return Err(anyhow!(
                    "keystore: unsupported format_version {v} for {key_id}; upgrade sss"
                ));
            }
        }

        self.decrypt_stored_keypair(&stored_keypair, password)
    }

    /// Get all available keypairs
    pub fn get_all_keypairs(&self, password: Option<&str>) -> Result<Vec<KeyPair>> {
        let mut keypairs = Vec::new();

        for entry in fs::read_dir(&self.keys_dir)
            .map_err(|e| anyhow!("keystore: read keys-dir {}: {}", self.keys_dir.display(), e))?
        {
            let entry = entry
                .map_err(|e| anyhow!("keystore: iter keys-dir entry {}: {}", self.keys_dir.display(), e))?;
            let path = entry.path();

            // Skip non-TOML files and the "current" symlink/file
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }

            let content = fs::read_to_string(&path)
                .map_err(|e| anyhow!("keystore: read key file {}: {e}", path.display()))?;
            if let Ok(stored_keypair) = toml::from_str::<StoredKeyPair>(&content)
                && let Ok(keypair) = self.decrypt_stored_keypair(&stored_keypair, password) {
                    keypairs.push(keypair);
                }
        }

        // Sort by public-key base64 for deterministic ordering.
        keypairs.sort_by_key(|kp| std::cmp::Reverse(kp.public_key().to_base64()));

        Ok(keypairs)
    }

    /// Get the count of stored keypairs
    pub fn count_keypairs(&self) -> Result<usize> {
        let mut count = 0;

        for entry in fs::read_dir(&self.keys_dir)
            .map_err(|e| anyhow!("keystore: read keys-dir {}: {}", self.keys_dir.display(), e))?
        {
            let entry = entry
                .map_err(|e| anyhow!("keystore: iter keys-dir entry {}: {}", self.keys_dir.display(), e))?;
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

        fs::remove_file(&key_file)
            .map_err(|e| anyhow!("keystore: remove key file for key_id={key_id}: {e}"))?;

        // If this was the current key, remove the current link.
        // WR-01 fix: bind read_current_key_id once via if-let to avoid TOCTOU double-call.
        if let Ok(current_id) = self.read_current_key_id()
            && current_id == key_id {
                let current_link = self.keys_dir.join("current");
                if current_link.exists() {
                    fs::remove_file(&current_link)
                        .map_err(|e| anyhow!("keystore: remove current symlink for key_id={key_id}: {e}"))?;
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
        // Load the keypair with the old password (if any).
        // 18-03: pass `allow_unsigned: true` — passphrase mutation MUST work on
        // legacy v1 entries on disk; the upgrade-to-v2 workflow is a separate
        // user-initiated step (deferred to 18-04). Verification of v2 entries
        // still happens inside `load_keypair` regardless of this flag.
        let keypair = self.load_keypair(key_id, old_password, true)?;

        // Load the stored keypair metadata to preserve other fields
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file for key_id={key_id} (set_passphrase): {e}"))?;
        let mut stored: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml for key_id={key_id} (set_passphrase): {e}"))?;

        // Encrypt with new password
        let salt = Salt::new();
        let derived_key = DerivedKey::derive_with_params(new_password, &salt, &self.kdf_params)
            .map_err(|e| anyhow!("keystore: kdf-derive (new passphrase) for key_id={key_id}: {e}"))?;
        let secret_key_str = keypair.secret_key()?.to_base64();
        let encrypted_secret_key =
            crate::crypto::encrypt_to_base64(&secret_key_str, &derived_key.to_encryption_key())
                .map_err(|e| anyhow!("keystore: aead-encrypt-secret-key (set_passphrase) for key_id={key_id}: {e}"))?;

        // Re-encrypt hybrid material before stored.salt is overwritten (WR-01).
        // Reads the original salt from `stored` to re-derive the old decryption key.
        #[cfg(feature = "hybrid")]
        if let Some(ref enc_hybrid_b64) = stored.hybrid_encrypted_secret_key.clone() {
            use base64::prelude::BASE64_STANDARD;
            use zeroize::Zeroizing;
            let raw_hybrid: Zeroizing<Vec<u8>> = if let Some(old_pw) = old_password {
                let old_salt_str = stored
                    .salt
                    .as_ref()
                    .ok_or_else(|| anyhow!("Salt missing for password-protected hybrid key"))?;
                let old_salt = Salt::from_base64(old_salt_str)
                    .map_err(|e| anyhow!("keystore: salt-decode (set_passphrase, old) for key_id={key_id}: {e}"))?;
                let old_dk =
                    DerivedKey::derive_with_params(old_pw, &old_salt, &self.kdf_params)
                        .map_err(|e| anyhow!("keystore: kdf-derive (old passphrase) for key_id={key_id}: {e}"))?;
                let enc_bytes = BASE64_STANDARD.decode(enc_hybrid_b64)
                    .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-key (set_passphrase, old) for key_id={key_id}: {e}"))?;
                let dec = Zeroizing::new(crate::crypto::decrypt(
                    &enc_bytes,
                    &old_dk.to_encryption_key(),
                )
                    .map_err(|e| anyhow!("keystore: aead-decrypt-hybrid (set_passphrase, old) for key_id={key_id}: {e}"))?);
                Zeroizing::new(BASE64_STANDARD.decode(
                    std::str::from_utf8(&dec)
                        .map_err(|e| anyhow!("keystore: utf8-decrypted-hybrid (set_passphrase) for key_id={key_id}: {e}"))?
                )
                    .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-inner (set_passphrase) for key_id={key_id}: {e}"))?)
            } else {
                // Was passwordless — stored as raw base64
                Zeroizing::new(BASE64_STANDARD.decode(enc_hybrid_b64)
                    .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-key (set_passphrase, passwordless) for key_id={key_id}: {e}"))?)
            };
            let hybrid_sk_b64 = BASE64_STANDARD.encode(&raw_hybrid[..]);
            let new_enc = crate::crypto::encrypt_to_base64(
                &hybrid_sk_b64,
                &derived_key.to_encryption_key(),
            )
                .map_err(|e| anyhow!("keystore: aead-encrypt-hybrid (set_passphrase) for key_id={key_id}: {e}"))?;
            stored.hybrid_encrypted_secret_key = Some(new_enc);
        }

        // Update the stored keypair
        stored.encrypted_secret_key = encrypted_secret_key;
        stored.salt = Some(salt.to_base64());
        stored.is_password_protected = true;

        // Write back to file
        let content = toml::to_string_pretty(&stored)
            .map_err(|e| anyhow!("keystore: serialise stored-keypair toml for key_id={key_id} (set_passphrase): {e}"))?;
        fs::write(&key_file, content)
            .map_err(|e| anyhow!("keystore: write key file for key_id={key_id} (set_passphrase): {e}"))?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)
                .map_err(|e| anyhow!("keystore: stat key file for key_id={key_id} (set_passphrase): {e}"))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_file, perms)
                .map_err(|e| anyhow!("keystore: set-permissions on key file for key_id={key_id} (set_passphrase): {e}"))?;
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
        // Load the keypair with the current password.
        // 18-03: pass `allow_unsigned: true` — passphrase removal MUST work on
        // legacy v1 entries on disk; the upgrade-to-v2 workflow is a separate
        // user-initiated step (deferred to 18-04). Verification of v2 entries
        // still happens inside `load_keypair` regardless of this flag.
        let keypair = self.load_keypair(key_id, Some(current_password), true)?;

        // Load the stored keypair metadata
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file for key_id={key_id} (remove_passphrase): {e}"))?;
        let mut stored: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml for key_id={key_id} (remove_passphrase): {e}"))?;

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
            let salt_obj = Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode (remove_passphrase) for key_id={key_id}: {e}"))?;
            let dk = DerivedKey::derive_with_params(
                current_password,
                &salt_obj,
                &self.kdf_params,
            )
                .map_err(|e| anyhow!("keystore: kdf-derive (remove_passphrase) for key_id={key_id}: {e}"))?;
            let enc_bytes = BASE64_STANDARD.decode(enc_hybrid_b64)
                .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-key (remove_passphrase) for key_id={key_id}: {e}"))?;
            let dec = Zeroizing::new(crate::crypto::decrypt(&enc_bytes, &dk.to_encryption_key())
                .map_err(|e| anyhow!("keystore: aead-decrypt-hybrid (remove_passphrase) for key_id={key_id}: {e}"))?);
            // dec is the base64 of the raw sk bytes — store it directly as passwordless form
            stored.hybrid_encrypted_secret_key =
                Some(String::from_utf8(dec.to_vec())
                    .map_err(|e| anyhow!("keystore: utf8-decrypted-hybrid (remove_passphrase) for key_id={key_id}: {e}"))?);
        }

        // Store secret key as plaintext (base64 encoded)
        stored.encrypted_secret_key = keypair.secret_key()?.to_base64();
        stored.salt = None;
        stored.is_password_protected = false;

        // Write back to file
        let content = toml::to_string_pretty(&stored)
            .map_err(|e| anyhow!("keystore: serialise stored-keypair toml for key_id={key_id} (remove_passphrase): {e}"))?;
        fs::write(&key_file, content)
            .map_err(|e| anyhow!("keystore: write key file for key_id={key_id} (remove_passphrase): {e}"))?;

        // Set secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)
                .map_err(|e| anyhow!("keystore: stat key file for key_id={key_id} (remove_passphrase): {e}"))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_file, perms)
                .map_err(|e| anyhow!("keystore: set-permissions on key file for key_id={key_id} (remove_passphrase): {e}"))?;
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

        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file (is_current_key_password_protected) for key_id={key_id}: {e}"))?;
        let stored_keypair: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml (is_current_key_password_protected) for key_id={key_id}: {e}"))?;

        Ok(stored_keypair.is_password_protected)
    }

    /// List all available key IDs with their metadata
    pub fn list_key_ids(&self) -> Result<Vec<(String, StoredKeyPair)>> {
        let mut keys = Vec::new();

        for entry in fs::read_dir(&self.keys_dir)
            .map_err(|e| anyhow!("keystore: read keys-dir {}: {}", self.keys_dir.display(), e))?
        {
            let entry = entry
                .map_err(|e| anyhow!("keystore: iter keys-dir entry {}: {}", self.keys_dir.display(), e))?;
            let path = entry.path();

            // Skip non-TOML files and the "current" symlink/file
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }

            let content = fs::read_to_string(&path)
                .map_err(|e| anyhow!("keystore: read key file {}: {e}", path.display()))?;
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
            let target = fs::read_link(&current_path)
                .map_err(|e| anyhow!("keystore: read current symlink {}: {e}", current_path.display()))?;
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
            let target_filename = fs::read_to_string(&current_path)
                .map_err(|e| anyhow!("keystore: read current file {:?}: {}", current_path, e))?;
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
    /// any secret material. Used by `handle_keys_pubkey` to display public keys
    /// and by `store_dual_keypair` Case B to detect whether hybrid is already present.
    pub fn get_current_stored_raw(&self) -> Result<StoredKeyPair> {
        let key_id = self.read_current_key_id()?;
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }
        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file (get_current_stored_raw) for key_id={key_id}: {e}"))?;
        toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml (get_current_stored_raw) for key_id={key_id}: {e}"))
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
    // Why: 267 lines is the natural shape of store_dual_keypair — the function
    // covers Cases A (both classic+hybrid), B (hybrid-only), and C (classic-only)
    // with KDF derivation, AEAD encryption, dual-suite signature generation, and
    // atomic disk write. Each case has its own logical block that maps to the
    // doc-comment cases above. Splitting into sub-fns would duplicate the
    // KDF/encrypt/sign/write sequence three times.
    #[allow(clippy::too_many_lines)]
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
                use crate::keystore::sig::{build_signed_payload, sign_entry};
                use trelis_primitives::{
                    Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme,
                };
                use zeroize::Zeroizing;

                let key_id = uuid::Uuid::new_v4().to_string();

                // PQSIG-02 — generate per-entry sig keypairs (D-06)
                let ed448_sk = Ed448Standard::generate()
                    .map_err(|e| anyhow!("keystore: Ed448 sig keygen (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;
                let ed448_pk = Ed448Standard::verifying_key(&ed448_sk);
                let ed448_pk_b64 = BASE64_STANDARD
                    .encode(Ed448Standard::verifying_key_to_bytes(&ed448_pk));
                let ed448_sk_bytes = Zeroizing::new(
                    Ed448Standard::signing_key_to_bytes(&ed448_sk).to_vec(),
                );

                let mldsa_sk = MlDsa65Fips204::generate()
                    .map_err(|e| anyhow!("keystore: ML-DSA-65 sig keygen (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;
                let mldsa_pk = MlDsa65Fips204::verifying_key(&mldsa_sk);
                let mldsa_pk_b64 = BASE64_STANDARD
                    .encode(MlDsa65Fips204::verifying_key_to_bytes(&mldsa_pk));
                let mldsa_sk_bytes = Zeroizing::new(
                    MlDsa65Fips204::signing_key_to_bytes(&mldsa_sk).to_vec(),
                );

                let (
                    enc_classic,
                    enc_hybrid,
                    enc_sig_ed448,
                    enc_sig_mldsa,
                    stored_salt,
                    is_protected,
                ) = if let Some(pw) = password {
                    let salt = crate::kdf::Salt::new();
                    let dk = crate::kdf::DerivedKey::derive_with_params(
                        pw, &salt, &self.kdf_params,
                    )
                        .map_err(|e| anyhow!("keystore: kdf-derive (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;
                    let enc_key = dk.to_encryption_key();

                    // Classic secret — standard path (32-byte key, base64 string)
                    let classic_sk_b64 =
                        KeyPair::Classic(classic.clone()).secret_key()?.to_base64();
                    let enc_classic =
                        crate::crypto::encrypt_to_base64(&classic_sk_b64, &enc_key)
                            .map_err(|e| anyhow!("keystore: aead-encrypt-secret-key (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    // Hybrid secret — encode directly from Zeroizing<[u8; N]> to
                    // avoid copying into a non-Zeroizing buffer (T-03-02).
                    let hybrid_sk_b64 =
                        BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref());
                    let enc_hybrid =
                        crate::crypto::encrypt_to_base64(&hybrid_sk_b64, &enc_key)
                            .map_err(|e| anyhow!("keystore: aead-encrypt-hybrid (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    // Sig secrets — encrypted under the same KEK (D-07)
                    let sig_ed448_sk_b64 =
                        BASE64_STANDARD.encode(&ed448_sk_bytes[..]);
                    let enc_sig_ed448 = crate::crypto::encrypt_to_base64(
                        &sig_ed448_sk_b64,
                        &enc_key,
                    )
                        .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    let sig_mldsa_sk_b64 =
                        BASE64_STANDARD.encode(&mldsa_sk_bytes[..]);
                    let enc_sig_mldsa = crate::crypto::encrypt_to_base64(
                        &sig_mldsa_sk_b64,
                        &enc_key,
                    )
                        .map_err(|e| anyhow!("keystore: aead-encrypt-sig-mldsa65 (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    (
                        enc_classic,
                        enc_hybrid,
                        enc_sig_ed448,
                        enc_sig_mldsa,
                        Some(salt.to_base64()),
                        true,
                    )
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
                    let sig_ed448_sk_b64 =
                        BASE64_STANDARD.encode(&ed448_sk_bytes[..]);
                    let sig_mldsa_sk_b64 =
                        BASE64_STANDARD.encode(&mldsa_sk_bytes[..]);
                    (
                        classic_sk_b64,
                        hybrid_sk_b64,
                        sig_ed448_sk_b64,
                        sig_mldsa_sk_b64,
                        None,
                        false,
                    )
                };

                // Pitfall 1 — single timestamp shared by struct field AND signed payload
                let created_at = chrono::Utc::now();
                let public_key_b64 =
                    KeyPair::Classic(classic.clone()).public_key().to_base64();
                let hybrid_public_key_b64 = BASE64_STANDARD.encode(hybrid.public_bytes);

                // D-08 / D-19 canonical payload (identity-bearing public fields only)
                let payload = build_signed_payload(
                    &key_id,
                    &public_key_b64,
                    Some(&hybrid_public_key_b64),
                    Some(&ed448_pk_b64),
                    Some(&mldsa_pk_b64),
                    &created_at.to_rfc3339(),
                );
                let sig = sign_entry(&ed448_sk, &mldsa_sk, &payload)
                    .map_err(|e| anyhow!("keystore: sign-entry (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                let stored = StoredKeyPair {
                    uuid: key_id.clone(),
                    public_key: public_key_b64,
                    encrypted_secret_key: enc_classic,
                    salt: stored_salt,
                    created_at,
                    is_password_protected: is_protected,
                    in_keyring: false,
                    hybrid_public_key: Some(hybrid_public_key_b64),
                    hybrid_encrypted_secret_key: Some(enc_hybrid),
                    // Phase 18 / PQSIG-02 — sign-on-write (D-10 v2)
                    format_version: 2,
                    sig_ed448_public_key: Some(ed448_pk_b64),
                    sig_ed448_encrypted_secret_key: Some(enc_sig_ed448),
                    sig_mldsa65_public_key: Some(mldsa_pk_b64),
                    sig_mldsa65_encrypted_secret_key: Some(enc_sig_mldsa),
                    signature: Some(sig),
                };

                let key_file = self.keys_dir.join(format!("{key_id}.toml"));
                let content = toml::to_string_pretty(&stored)
                    .map_err(|e| anyhow!("keystore: serialise stored-keypair toml (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;
                fs::write(&key_file, content)
                    .map_err(|e| anyhow!("keystore: write key file (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = fs::metadata(&key_file)
                        .map_err(|e| anyhow!("keystore: stat key file (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    fs::set_permissions(&key_file, perms)
                        .map_err(|e| anyhow!("keystore: set-permissions on key file (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;
                }

                self.set_current_key(&key_id)?;
                Ok(key_id)
            }

            // Case B — hybrid only: upgrade existing classic identity
            (None, Some(hybrid)) => {
                use crate::keystore::sig::{build_signed_payload, sign_entry};
                use trelis_primitives::{
                    Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme,
                };
                use zeroize::Zeroizing;

                let key_id = self.read_current_key_id()?;
                let key_file = self.keys_dir.join(format!("{key_id}.toml"));
                if !key_file.exists() {
                    return Err(anyhow!("Key file not found: {key_id}"));
                }

                let content = fs::read_to_string(&key_file)
                    .map_err(|e| anyhow!("keystore: read key file (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                let mut stored: StoredKeyPair = toml::from_str(&content)
                    .map_err(|e| anyhow!("keystore: parse-stored-toml (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                // Guard: refuse to overwrite existing hybrid material (T-03-03)
                if stored.hybrid_public_key.is_some() {
                    return Err(anyhow!(
                        "hybrid keypair already present in this identity; \
                         use --suite both to replace"
                    ));
                }

                // PQSIG-02 — generate per-entry sig keypairs (D-06)
                let ed448_sk = Ed448Standard::generate()
                    .map_err(|e| anyhow!("keystore: Ed448 sig keygen (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                let ed448_pk = Ed448Standard::verifying_key(&ed448_sk);
                let ed448_pk_b64 = BASE64_STANDARD
                    .encode(Ed448Standard::verifying_key_to_bytes(&ed448_pk));
                let ed448_sk_bytes = Zeroizing::new(
                    Ed448Standard::signing_key_to_bytes(&ed448_sk).to_vec(),
                );

                let mldsa_sk = MlDsa65Fips204::generate()
                    .map_err(|e| anyhow!("keystore: ML-DSA-65 sig keygen (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                let mldsa_pk = MlDsa65Fips204::verifying_key(&mldsa_sk);
                let mldsa_pk_b64 = BASE64_STANDARD
                    .encode(MlDsa65Fips204::verifying_key_to_bytes(&mldsa_pk));
                let mldsa_sk_bytes = Zeroizing::new(
                    MlDsa65Fips204::signing_key_to_bytes(&mldsa_sk).to_vec(),
                );

                // Encrypt new hybrid + sig material under the EXISTING salt (KEYSTORE-04).
                // We re-derive only to encrypt the new secrets; the classic
                // material is not touched.
                let (enc_hybrid, enc_sig_ed448, enc_sig_mldsa) =
                    if stored.is_password_protected {
                        let pw = password.ok_or_else(|| {
                            anyhow!("Password required to add hybrid material to a protected identity")
                        })?;
                        let salt_str = stored.salt.as_ref().ok_or_else(|| {
                            anyhow!("Salt missing for password-protected key")
                        })?;
                        let salt = crate::kdf::Salt::from_base64(salt_str)
                            .map_err(|e| anyhow!("keystore: salt-decode (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                        let dk = crate::kdf::DerivedKey::derive_with_params(
                            pw, &salt, &self.kdf_params,
                        )
                            .map_err(|e| anyhow!("keystore: kdf-derive (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                        let enc_key = dk.to_encryption_key();

                        let hybrid_sk_b64 =
                            BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref());
                        let enc_h = crate::crypto::encrypt_to_base64(
                            &hybrid_sk_b64,
                            &enc_key,
                        )
                            .map_err(|e| anyhow!("keystore: aead-encrypt-hybrid (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                        let sig_ed448_sk_b64 =
                            BASE64_STANDARD.encode(&ed448_sk_bytes[..]);
                        let enc_e = crate::crypto::encrypt_to_base64(
                            &sig_ed448_sk_b64,
                            &enc_key,
                        )
                            .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                        let sig_mldsa_sk_b64 =
                            BASE64_STANDARD.encode(&mldsa_sk_bytes[..]);
                        let enc_m = crate::crypto::encrypt_to_base64(
                            &sig_mldsa_sk_b64,
                            &enc_key,
                        )
                            .map_err(|e| anyhow!("keystore: aead-encrypt-sig-mldsa65 (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                        (enc_h, enc_e, enc_m)
                    } else {
                        // Passwordless — store raw base64
                        let enc_h =
                            BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref());
                        let enc_e =
                            BASE64_STANDARD.encode(&ed448_sk_bytes[..]);
                        let enc_m =
                            BASE64_STANDARD.encode(&mldsa_sk_bytes[..]);
                        (enc_h, enc_e, enc_m)
                    };

                // Append hybrid + sig fields — all classic fields are untouched (KEYSTORE-03)
                let hybrid_public_key_b64 = BASE64_STANDARD.encode(hybrid.public_bytes);
                stored.hybrid_public_key = Some(hybrid_public_key_b64.clone());
                stored.hybrid_encrypted_secret_key = Some(enc_hybrid);

                // Phase 18 / PQSIG-02 — sign-on-write (D-10 v2)
                stored.format_version = 2;
                stored.sig_ed448_public_key = Some(ed448_pk_b64.clone());
                stored.sig_ed448_encrypted_secret_key = Some(enc_sig_ed448);
                stored.sig_mldsa65_public_key = Some(mldsa_pk_b64.clone());
                stored.sig_mldsa65_encrypted_secret_key = Some(enc_sig_mldsa);

                // D-08 / D-19 canonical payload (identity-bearing public fields only)
                // Pitfall 1 — use the SAME `created_at` already on the struct, not a new now()
                let payload = build_signed_payload(
                    &stored.uuid,
                    &stored.public_key,
                    Some(&hybrid_public_key_b64),
                    Some(&ed448_pk_b64),
                    Some(&mldsa_pk_b64),
                    &stored.created_at.to_rfc3339(),
                );
                let sig = sign_entry(&ed448_sk, &mldsa_sk, &payload)
                    .map_err(|e| anyhow!("keystore: sign-entry (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                stored.signature = Some(sig);

                let updated_content = toml::to_string_pretty(&stored)
                    .map_err(|e| anyhow!("keystore: serialise stored-keypair toml (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                fs::write(&key_file, updated_content)
                    .map_err(|e| anyhow!("keystore: write key file (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let metadata = fs::metadata(&key_file)
                        .map_err(|e| anyhow!("keystore: stat key file (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    fs::set_permissions(&key_file, perms)
                        .map_err(|e| anyhow!("keystore: set-permissions on key file (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;
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
    /// Phase 18-03 (PQSIG-02 / D-10 / D-11): adds `allow_unsigned` parameter and
    /// `format_version` dispatch. Same ladder as `load_keypair`:
    /// - `format_version == 1` + `allow_unsigned == false` → hard error.
    /// - `format_version == 1` + `allow_unsigned == true`  → proceed (legacy read).
    /// - `format_version == 2` → invoke `verify_stored_signature` (D-11).
    /// - `format_version >= 3` → hard error.
    ///
    /// Returns `Err` if the file has no hybrid material, or if decryption fails.
    #[cfg(feature = "hybrid")]
    pub fn load_hybrid_keypair(
        &self,
        key_id: &str,
        password: Option<&str>,
        allow_unsigned: bool,
    ) -> Result<crate::crypto::HybridKeyPair> {
        use base64::prelude::BASE64_STANDARD;
        use crate::constants::HYBRID_SECRET_KEY_SIZE;
        use crate::constants::HYBRID_PUBLIC_KEY_SIZE;
        use zeroize::Zeroizing;

        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }

        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
        let stored: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml (load_hybrid_keypair) for key_id={key_id}: {e}"))?;

        // Phase 18 / D-10 format_version dispatch (mirrors load_keypair).
        match stored.format_version {
            1 => {
                if !allow_unsigned {
                    return Err(anyhow!(
                        "keystore: entry {key_id} is unsigned legacy format; pass --allow-unsigned to read or run `sss keys upgrade {key_id}` to re-sign"
                    ));
                }
                // Proceed without verify.
            }
            2 => {
                self.verify_stored_signature(&stored, &key_file)?;
            }
            v => {
                return Err(anyhow!(
                    "keystore: unsupported format_version {v} for {key_id}; upgrade sss"
                ));
            }
        }

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
            let salt = crate::kdf::Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
            let dk = crate::kdf::DerivedKey::derive_with_params(
                pw, &salt, &self.kdf_params,
            )
                .map_err(|e| anyhow!("keystore: kdf-derive (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
            let enc_bytes = BASE64_STANDARD.decode(&hybrid_enc_sk_b64)
                .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-key (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
            let decrypted = Zeroizing::new(crate::crypto::decrypt(&enc_bytes, &dk.to_encryption_key())
                .map_err(|e| anyhow!("keystore: aead-decrypt-hybrid (load_hybrid_keypair) for key_id={key_id}: {e}"))?);
            // decrypted is the base64 string of the raw secret bytes
            Zeroizing::new(BASE64_STANDARD.decode(
                std::str::from_utf8(&decrypted)
                    .map_err(|e| anyhow!("keystore: utf8-decrypted-hybrid (load_hybrid_keypair) for key_id={key_id}: {e}"))?
            )
                .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-inner (load_hybrid_keypair) for key_id={key_id}: {e}"))?)
        } else {
            // Passwordless — stored as raw base64
            Zeroizing::new(BASE64_STANDARD.decode(&hybrid_enc_sk_b64)
                .map_err(|e| anyhow!("keystore: base64-decode-hybrid-secret-key (load_hybrid_keypair, passwordless) for key_id={key_id}: {e}"))?)
        };

        if raw_secret_bytes.len() != HYBRID_SECRET_KEY_SIZE {
            return Err(anyhow!(
                "hybrid secret key wrong length: expected {} bytes, got {}",
                HYBRID_SECRET_KEY_SIZE,
                raw_secret_bytes.len()
            ));
        }

        // Reconstruct public bytes
        let pub_bytes_raw = BASE64_STANDARD.decode(&hybrid_pub_b64)
            .map_err(|e| anyhow!("keystore: base64-decode-hybrid-public-key (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
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

    /// Load and decrypt the sig keypair (Ed448 + ML-DSA-65 signing keys) for the
    /// current user from their keystore entry.
    ///
    /// Phase 19-02 (PQSIG-05): Wave 0 prerequisite. Returns the two signing keys
    /// used to AND-compose envelope signatures. The `username` parameter is accepted
    /// for API clarity but the implementation resolves the current key-ID from the
    /// keystore's own current-key pointer — the caller is always the authenticated
    /// user whose key is already loaded.
    ///
    /// Decryption mirrors `load_hybrid_keypair`:
    /// - password-protected: derive KEK → AEAD-decrypt → inner-base64-decode → parse key bytes
    /// - passwordless: outer-base64-decode → parse key bytes directly
    ///
    /// Returns `Err` if the current key has no sig material (`format_version` < 2 or
    /// fields absent) or if decryption / key-parse fails.
    #[cfg(feature = "hybrid")]
    pub fn load_sig_keypair(
        &self,
        _username: &str,
        password: Option<&str>,
    ) -> Result<(
        trelis_primitives::Ed448SigningKey,
        trelis_primitives::MlDsa65SigningKey,
    )> {
        use base64::prelude::BASE64_STANDARD;
        use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};
        use zeroize::Zeroizing;

        let key_id = self.get_current_key_id()?;
        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        if !key_file.exists() {
            return Err(anyhow!("Key file not found: {key_id}"));
        }

        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file (load_sig_keypair) for key_id={key_id}: {e}"))?;
        let stored: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml (load_sig_keypair) for key_id={key_id}: {e}"))?;

        // Guard: sig material only exists in format_version >= 2 entries.
        // format_version == 1 entries were created before Phase 18 sig keys.
        if stored.format_version < 2 {
            return Err(anyhow!(
                "keystore: entry {} has no sig keypair (format_version={}); \
                 run `sss keys upgrade {}` to generate sig keys",
                key_id, stored.format_version, key_id
            ));
        }

        // Obtain KEK material once (shared by both sig keys).
        // For password-protected entries: derive the key-encryption key.
        // For passwordless entries: no KEK needed — keys stored as plain base64.
        let kek: Option<crate::crypto::RepositoryKey> = if stored.is_password_protected {
            let pw = password.ok_or_else(|| {
                anyhow!("Password required for encrypted key")
            })?;
            let salt_str = stored.salt.as_ref().ok_or_else(|| {
                anyhow!("Salt missing for password-protected key")
            })?;
            let salt = crate::kdf::Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode (load_sig_keypair) for key_id={key_id}: {e}"))?;
            let dk = crate::kdf::DerivedKey::derive_with_params(pw, &salt, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive (load_sig_keypair) for key_id={key_id}: {e}"))?;
            Some(dk.to_encryption_key())
        } else {
            None
        };

        // Decrypt helper: given a base64-encoded (possibly AEAD-encrypted) field,
        // return raw key bytes in a Zeroizing buffer.
        let decrypt_sig_key_bytes = |field_b64: &str, field_name: &str| -> Result<Zeroizing<Vec<u8>>> {
            if let Some(ref enc_key) = kek {
                // Password-protected: outer b64 → AEAD decrypt → inner b64 → raw bytes
                let enc_bytes = BASE64_STANDARD.decode(field_b64)
                    .map_err(|e| anyhow!("keystore: base64-decode-{field_name} (load_sig_keypair) for key_id={key_id}: {e}"))?;
                let decrypted = Zeroizing::new(
                    crate::crypto::decrypt(&enc_bytes, enc_key)
                        .map_err(|e| anyhow!("keystore: aead-decrypt-{field_name} (load_sig_keypair) for key_id={key_id}: {e}"))?
                );
                let inner_b64 = std::str::from_utf8(&decrypted)
                    .map_err(|e| anyhow!("keystore: utf8-{field_name} (load_sig_keypair) for key_id={key_id}: {e}"))?;
                Ok(Zeroizing::new(
                    BASE64_STANDARD.decode(inner_b64)
                        .map_err(|e| anyhow!("keystore: base64-decode-{field_name}-inner (load_sig_keypair) for key_id={key_id}: {e}"))?
                ))
            } else {
                // Passwordless: plain base64 → raw bytes
                Ok(Zeroizing::new(
                    BASE64_STANDARD.decode(field_b64)
                        .map_err(|e| anyhow!("keystore: base64-decode-{field_name} (load_sig_keypair, passwordless) for key_id={key_id}: {e}"))?
                ))
            }
        };

        // Ed448 signing key
        let ed448_enc_sk = stored.sig_ed448_encrypted_secret_key.as_deref().ok_or_else(|| {
            anyhow!(
                "keystore: sig_ed448_encrypted_secret_key absent for key_id={key_id}; \
                 run `sss keys upgrade {key_id}` to add sig keys"
            )
        })?;
        let ed448_sk_bytes = decrypt_sig_key_bytes(ed448_enc_sk, "sig_ed448_sk")?;
        let ed448_sk = Ed448Standard::signing_key_from_bytes(&ed448_sk_bytes)
            .map_err(|e| anyhow!("keystore: parse-ed448-sig-signing-key for key_id={key_id}: {e}"))?;

        // ML-DSA-65 signing key
        let mldsa_enc_sk = stored.sig_mldsa65_encrypted_secret_key.as_deref().ok_or_else(|| {
            anyhow!(
                "keystore: sig_mldsa65_encrypted_secret_key absent for key_id={key_id}; \
                 run `sss keys upgrade {key_id}` to add sig keys"
            )
        })?;
        let mldsa_sk_bytes = decrypt_sig_key_bytes(mldsa_enc_sk, "sig_mldsa65_sk")?;
        let mldsa_sk = MlDsa65Fips204::signing_key_from_bytes(&mldsa_sk_bytes)
            .map_err(|e| anyhow!("keystore: parse-mldsa65-sig-signing-key for key_id={key_id}: {e}"))?;

        Ok((ed448_sk, mldsa_sk))
    }

    /// Re-sign a `format_version=1` (legacy unsigned) entry in place,
    /// promoting it to `format_version=2` (signed) without changing identity.
    ///
    /// Phase 18-04 / PQSIG-03 transition path. Generates fresh per-entry
    /// Ed448 + ML-DSA-65 sig keypairs, encrypts the sig SKs under the
    /// EXISTING KEK (D-07; passwordless entries store base64 raw), bumps
    /// `format_version` to 2, populates the four sig fields, builds the
    /// canonical signed payload (D-08), and produces an AND-composition
    /// signature via `keystore::sig::sign_entry`.
    ///
    /// Atomic write via `tempfile::NamedTempFile::new_in(parent).persist(target)`
    /// so a crash mid-write never produces a half-written entry (D-15).
    /// **Pitfall 4**: MUST use `new_in(parent)` — `NamedTempFile::new()` defaults
    /// to `/tmp` which is a different filesystem on most Linux installs and
    /// `.persist()` would fail with `EXDEV` (cross-device link).
    ///
    /// Refuses (without writing) if `format_version >= 2`; the caller (CLI)
    /// surfaces this as a no-op message. Refuses if `format_version` is
    /// neither 1 nor 2 (future schema). Probes the existing KEK by
    /// decrypting `encrypted_secret_key` so a wrong passphrase fails BEFORE
    /// any write, leaving the v1 file untouched.
    ///
    /// T-18-04-03: raw sig SK bytes are wrapped in `Zeroizing<Vec<u8>>` and
    /// dropped at end-of-scope.
    // Why: 129 lines is the natural shape of in-place upgrade — read stored
    // keypair → decrypt → generate fresh sig keypairs → build signed payload →
    // re-encrypt with current KDF → atomic write-and-replace. Sequential
    // narrative; splitting would obscure the transactional sequence.
    #[allow(clippy::too_many_lines)]
    #[cfg(feature = "hybrid")]
    pub fn upgrade_keypair_in_place(
        &self,
        key_id: &str,
        password: Option<&str>,
    ) -> Result<()> {
        use crate::keystore::sig::{build_signed_payload, sign_entry};
        use base64::prelude::BASE64_STANDARD;
        use std::io::Write;
        use trelis_primitives::{
            Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme,
        };
        use zeroize::Zeroizing;

        let key_file = self.keys_dir.join(format!("{key_id}.toml"));
        if !key_file.exists() {
            return Err(anyhow!(
                "keystore: upgrade target key file not found: {}",
                key_file.display()
            ));
        }

        // Read on-disk TOML directly (bypasses load_keypair so we can read a
        // v1 entry without --allow-unsigned).
        let content = fs::read_to_string(&key_file)
            .map_err(|e| anyhow!("keystore: read key file (upgrade) for key_id={key_id}: {e}"))?;
        let mut stored: StoredKeyPair = toml::from_str(&content)
            .map_err(|e| anyhow!("keystore: parse-stored-toml (upgrade) for key_id={key_id}: {e}"))?;

        // Refuse already-signed entries (D-17): upgrade IS the upgrade path
        // for v1 → v2; there is no v2 → v2 re-sign mode.
        if stored.format_version >= 2 {
            return Err(anyhow!(
                "keystore: entry {} is already signed (format_version={}); upgrade is a no-op",
                key_id, stored.format_version
            ));
        }
        if stored.format_version != 1 {
            return Err(anyhow!(
                "keystore: unsupported format_version {} for upgrade (expected 1)",
                stored.format_version
            ));
        }

        // Probe the existing KEK by decrypting encrypted_secret_key — a wrong
        // passphrase MUST fail before any write happens (T-18-04-04).
        // Passwordless entries skip this probe (no KEK to validate).
        if stored.is_password_protected {
            let pw = password.ok_or_else(|| {
                anyhow!("Password required to upgrade protected key {key_id}")
            })?;
            let salt_str = stored
                .salt
                .as_ref()
                .ok_or_else(|| anyhow!("Salt missing for password-protected key {key_id}"))?;
            let salt = crate::kdf::Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode (upgrade) for key_id={key_id}: {e}"))?;
            let dk = crate::kdf::DerivedKey::derive_with_params(pw, &salt, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive (upgrade) for key_id={key_id}: {e}"))?;
            let enc_bytes = BASE64_STANDARD
                .decode(&stored.encrypted_secret_key)
                .map_err(|e| anyhow!("keystore: base64-decode-secret-key (upgrade) for key_id={key_id}: {e}"))?;
            let _probe = Zeroizing::new(
                crate::crypto::decrypt(&enc_bytes, &dk.to_encryption_key())
                    .map_err(|_| anyhow!("keystore: passphrase verification failed for {key_id}"))?,
            );
        }

        // Generate fresh per-entry sig keypairs (D-06).
        let ed448_sk = Ed448Standard::generate()
            .map_err(|e| anyhow!("keystore: Ed448 sig keygen (upgrade) for key_id={key_id}: {e}"))?;
        let ed448_pk = Ed448Standard::verifying_key(&ed448_sk);
        let ed448_pk_b64 =
            BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(&ed448_pk));
        let ed448_sk_bytes =
            Zeroizing::new(Ed448Standard::signing_key_to_bytes(&ed448_sk).to_vec());

        let mldsa_sk = MlDsa65Fips204::generate()
            .map_err(|e| anyhow!("keystore: ML-DSA-65 sig keygen (upgrade) for key_id={key_id}: {e}"))?;
        let mldsa_pk = MlDsa65Fips204::verifying_key(&mldsa_sk);
        let mldsa_pk_b64 =
            BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(&mldsa_pk));
        let mldsa_sk_bytes =
            Zeroizing::new(MlDsa65Fips204::signing_key_to_bytes(&mldsa_sk).to_vec());

        // Encrypt sig SKs under the existing KEK (protected) or store base64
        // raw (passwordless) — matches the precedent in store_dual_keypair
        // Case A/B for D-07 consistency.
        let (sig_ed448_sk_field, sig_mldsa_sk_field) = if stored.is_password_protected {
            // Re-derive KEK (we already validated the passphrase above).
            // Why: password and salt are validated as Some(_) in the preceding
            // is_password_protected branch (see passphrase validation earlier in
            // this fn body). HARDEN-01 / 08-01.
            #[allow(clippy::expect_used)]
            let pw = password.expect("checked above");
            #[allow(clippy::expect_used)]
            let salt_str = stored.salt.as_ref().expect("checked above");
            let salt = crate::kdf::Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode-2 (upgrade) for key_id={key_id}: {e}"))?;
            let dk = crate::kdf::DerivedKey::derive_with_params(pw, &salt, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive-2 (upgrade) for key_id={key_id}: {e}"))?;
            let enc_key = dk.to_encryption_key();

            let sig_ed448_sk_b64 = BASE64_STANDARD.encode(&ed448_sk_bytes[..]);
            let enc_sig_ed448 =
                crate::crypto::encrypt_to_base64(&sig_ed448_sk_b64, &enc_key)
                    .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (upgrade) for key_id={key_id}: {e}"))?;

            let sig_mldsa_sk_b64 = BASE64_STANDARD.encode(&mldsa_sk_bytes[..]);
            let enc_sig_mldsa =
                crate::crypto::encrypt_to_base64(&sig_mldsa_sk_b64, &enc_key)
                    .map_err(|e| anyhow!("keystore: aead-encrypt-sig-mldsa65 (upgrade) for key_id={key_id}: {e}"))?;

            (enc_sig_ed448, enc_sig_mldsa)
        } else {
            (
                BASE64_STANDARD.encode(&ed448_sk_bytes[..]),
                BASE64_STANDARD.encode(&mldsa_sk_bytes[..]),
            )
        };

        // Bump schema + populate sig fields.
        stored.format_version = 2;
        stored.sig_ed448_public_key = Some(ed448_pk_b64.clone());
        stored.sig_ed448_encrypted_secret_key = Some(sig_ed448_sk_field);
        stored.sig_mldsa65_public_key = Some(mldsa_pk_b64.clone());
        stored.sig_mldsa65_encrypted_secret_key = Some(sig_mldsa_sk_field);

        // Canonical D-08 payload (identity-bearing public fields only).
        // T-18-04-05: uuid + public_key + hybrid_public_key + created_at
        // are byte-preserved from the v1 entry.
        let payload = build_signed_payload(
            &stored.uuid,
            &stored.public_key,
            stored.hybrid_public_key.as_deref(),
            stored.sig_ed448_public_key.as_deref(),
            stored.sig_mldsa65_public_key.as_deref(),
            &stored.created_at.to_rfc3339(),
        );
        let sig = sign_entry(&ed448_sk, &mldsa_sk, &payload)
            .map_err(|e| anyhow!("keystore: sign-entry (upgrade) for key_id={key_id}: {e}"))?;
        stored.signature = Some(sig);

        let new_content = toml::to_string_pretty(&stored)
            .map_err(|e| anyhow!("keystore: serialise stored-keypair toml (upgrade) for key_id={key_id}: {e}"))?;

        // Atomic write via NamedTempFile::new_in(parent).persist(target) (D-15).
        // Pitfall 4: MUST be `new_in(parent_dir)` — `new()` defaults to /tmp,
        // .persist() then fails with EXDEV (cross-device link) on most Linux.
        let parent = key_file.parent().ok_or_else(|| {
            anyhow!("keystore: cannot resolve parent dir of {}", key_file.display())
        })?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| anyhow!("keystore: tempfile-create (upgrade) for key_id={key_id}: {e}"))?;
        tmp.write_all(new_content.as_bytes())
            .map_err(|e| anyhow!("keystore: tempfile-write (upgrade) for key_id={key_id}: {e}"))?;
        tmp.flush()
            .map_err(|e| anyhow!("keystore: tempfile-flush (upgrade) for key_id={key_id}: {e}"))?;
        tmp.persist(&key_file)
            .map_err(|e| anyhow!("keystore: tempfile-persist (upgrade) for key_id={key_id}: {e}"))?;

        // Restore 0o600 permissions (NamedTempFile defaults are mode 0o600 on
        // Unix already, but persist() onto an existing 0o600 file may pick up
        // umask-derived perms on some platforms — be explicit).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_file)
                .map_err(|e| anyhow!("keystore: stat key file (upgrade) for key_id={key_id}: {e}"))?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_file, perms)
                .map_err(|e| anyhow!("keystore: set-permissions on key file (upgrade) for key_id={key_id}: {e}"))?;
        }

        Ok(())
    }

    /// Verify an entry's AND-composition signature.
    ///
    /// Phase 18-03 / D-11 + D-20: ALL sub-cause errors (missing signature,
    /// missing pubkey, base64 decode fail, key-parse fail, sig-verify fail)
    /// collapse into the IDENTICAL canonical D-20 error string per T-18-03-04
    /// (no sub-cause leakage to attackers).
    ///
    /// `pub(crate)` so the import/export handlers in `commands/keys.rs` can
    /// invoke it without re-implementing the dispatch logic.
    // Why: kept as &self method for API parity with other KeyStore methods that
    // dispatch verification; the call sites at lines 369 and 1144 already pass
    // self. Refactoring to associated fn would require call-site rewrites
    // across the keystore module without semantic gain.
    #[cfg(feature = "hybrid")]
    #[allow(clippy::unused_self)]
    pub(crate) fn verify_stored_signature(
        &self,
        stored: &StoredKeyPair,
        file: &std::path::Path,
    ) -> Result<()> {
        use crate::keystore::sig::{build_signed_payload, verify_entry};
        use base64::prelude::BASE64_STANDARD;
        use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};

        // Canonical D-20 error string. Repeated verbatim in EVERY error arm
        // below per T-18-03-04 (sub-cause leak prevention).
        let canonical_err = || {
            anyhow!(
                "keystore: signature verification failed for {} (file: {}) — entry rejected; if this is expected after a format upgrade run `sss keys upgrade {}`",
                stored.uuid,
                file.display(),
                stored.uuid
            )
        };

        let sig = stored.signature.as_ref().ok_or_else(canonical_err)?;

        let ed448_pk_b64 = stored
            .sig_ed448_public_key
            .as_ref()
            .ok_or_else(canonical_err)?;
        let ed448_pk_bytes = BASE64_STANDARD
            .decode(ed448_pk_b64.as_bytes())
            .map_err(|_| canonical_err())?;
        let ed448_pk = Ed448Standard::verifying_key_from_bytes(&ed448_pk_bytes)
            .map_err(|_| canonical_err())?;

        let mldsa_pk_b64 = stored
            .sig_mldsa65_public_key
            .as_ref()
            .ok_or_else(canonical_err)?;
        let mldsa_pk_bytes = BASE64_STANDARD
            .decode(mldsa_pk_b64.as_bytes())
            .map_err(|_| canonical_err())?;
        let mldsa_pk = MlDsa65Fips204::verifying_key_from_bytes(&mldsa_pk_bytes)
            .map_err(|_| canonical_err())?;

        // Pitfall 1: pass `created_at.to_rfc3339()` — same encoding used in
        // `store_dual_keypair`. Deterministic; round-trips via chrono::serde.
        let payload = build_signed_payload(
            &stored.uuid,
            &stored.public_key,
            stored.hybrid_public_key.as_deref(),
            stored.sig_ed448_public_key.as_deref(),
            stored.sig_mldsa65_public_key.as_deref(),
            &stored.created_at.to_rfc3339(),
        );

        verify_entry(&ed448_pk, &mldsa_pk, &payload, sig).map_err(|_| canonical_err())
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
            let secret_key_b64 = keyring_support::get_key_from_keyring(&stored.uuid)
                .map_err(|e| anyhow!("keystore: keyring-fetch for key_id={}: {}", stored.uuid, e))?;
            SecretKey::from_base64(&secret_key_b64)
                .map_err(|e| anyhow!("keystore: parse-secret-key (keyring) for key_id={}: {}", stored.uuid, e))?
        } else if stored.is_password_protected {
            let password =
                password.ok_or_else(|| anyhow!("Password required for encrypted key"))?;

            let salt = stored
                .salt
                .as_ref()
                .ok_or_else(|| anyhow!("Salt missing for password-protected key"))?;
            let salt = crate::kdf::Salt::from_base64(salt)
                .map_err(|e| anyhow!("keystore: salt-decode (decrypt_stored_keypair) for key_id={}: {}", stored.uuid, e))?;
            let derived_key = crate::kdf::DerivedKey::derive_with_params(password, &salt, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive (decrypt_stored_keypair) for key_id={}: {}", stored.uuid, e))?;

            let encrypted_data =
                base64::prelude::BASE64_STANDARD.decode(&stored.encrypted_secret_key)
                    .map_err(|e| anyhow!("keystore: base64-decode-secret-key (decrypt_stored_keypair) for key_id={}: {}", stored.uuid, e))?;
            // HARDEN-04 / 08-04: the decrypted plaintext is the base64 of the
            // raw secret-key bytes — wrap in Zeroizing<Vec<u8>> so the buffer
            // is cleared on drop (T-08-16). The follow-on `secret_key_b64`
            // String is wrapped for the same reason.
            let decrypted_data: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
                crate::crypto::decrypt(&encrypted_data, &derived_key.to_encryption_key())
                    .map_err(|e| anyhow!("keystore: aead-decrypt-secret-key (decrypt_stored_keypair) for key_id={}: {}", stored.uuid, e))?
            );

            let secret_key_b64: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
                String::from_utf8(decrypted_data.to_vec())
                    .map_err(|e| anyhow!("keystore: utf8-decrypted-secret-key (decrypt_stored_keypair) for key_id={}: {}", stored.uuid, e))?
            );
            SecretKey::from_base64(&secret_key_b64)
                .map_err(|e| anyhow!("keystore: parse-secret-key (decrypt_stored_keypair, pw) for key_id={}: {}", stored.uuid, e))?
        } else {
            SecretKey::from_base64(&stored.encrypted_secret_key)
                .map_err(|e| anyhow!("keystore: parse-secret-key (decrypt_stored_keypair, passwordless) for key_id={}: {}", stored.uuid, e))?
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

        // Store without password (classic store_keypair → format_version=1)
        let key_id = keystore.store_keypair(&keypair, None)?;
        assert!(!key_id.is_empty());

        // 18-03: classic store_keypair writes format_version=1; pass
        // allow_unsigned=true to bypass the legacy-unsigned guard.
        let retrieved = keystore.load_keypair(&key_id, None, true)?;
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

        // Store with password (classic store_keypair → format_version=1)
        let key_id = keystore.store_keypair(&keypair, Some(password))?;
        assert!(!key_id.is_empty());

        // 18-03: classic store_keypair writes format_version=1; pass
        // allow_unsigned=true to bypass the legacy-unsigned guard.

        // Should fail without password (password gate fires before signature gate
        // in load_keypair → decrypt_stored_keypair).
        assert!(keystore.load_keypair(&key_id, None, true).is_err());

        // Should work with correct password
        let retrieved = keystore.load_keypair(&key_id, Some(password), true)?;
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
            .load_keypair(&key_id, Some("wrong_password"), true)
            .is_err());

        Ok(())
    }

    #[test]
    fn test_multiple_keypairs_ordering() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;

        // Store multiple keypairs (classic store_keypair → format_version=1)
        let keypair1 = KeyPair::generate()?;
        let keypair2 = KeyPair::generate()?;
        let keypair3 = KeyPair::generate()?;

        let _id1 = keystore.store_keypair(&keypair1, None)?;
        std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure different timestamps
        let _id2 = keystore.store_keypair(&keypair2, None)?;
        std::thread::sleep(std::time::Duration::from_millis(10));
        let id3 = keystore.store_keypair(&keypair3, None)?;

        // 18-03: classic store_keypair writes format_version=1; load most-recent
        // entry directly with allow_unsigned=true (get_current_keypair routes
        // through allow_unsigned=false and would reject the v1 legacy entry).
        let current = keystore.load_keypair(&id3, None, true)?;
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

    /// Classic-only `StoredKeyPair` has hybrid fields set to None (backward compat).
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

    /// `get_current_stored_raw` returns the raw `StoredKeyPair` without decrypting.
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

    /// `load_hybrid_keypair` on a classic-only file returns the expected error.
    #[cfg(feature = "hybrid")]
    #[test]
    fn test_load_hybrid_keypair_on_classic_only_errors() -> Result<()> {
        let (keystore, _temp_dir) = create_temp_keystore()?;
        let keypair = KeyPair::generate()?;
        let key_id = keystore.store_keypair(&keypair, None)?;

        // 18-03: classic store_keypair writes format_version=1; pass
        // allow_unsigned=true so the dispatch lets us reach the
        // "no hybrid material" guard rather than rejecting on format_version=1.
        let result = keystore.load_hybrid_keypair(&key_id, None, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no hybrid keypair"),
            "error message must contain 'no hybrid keypair'");

        Ok(())
    }

    // -------------------------------------------------------------------------
    // TEST-08: Property-based round-trip tests (Phase 14 / Plan 14-03 / D-04)
    //
    // Placed inline (not in tests/keystore_integration_tests.rs) because
    // KdfParams is pub(crate) after CLEAN-03 (Plan 11-04), making it unreachable
    // from integration-test crates. The inline mod uses `use super::*` which
    // brings KdfParams into scope without widening any public API.
    // -------------------------------------------------------------------------

    /// Faster temp keystore for property tests — uses `KdfParams::interactive()`
    /// (N=32768) rather than the sensitive default to keep per-case latency low.
    fn create_temp_keystore_interactive() -> Result<(Keystore, TempDir)> {
        let temp_dir = TempDir::new()?;
        let keys_dir = temp_dir.path().to_path_buf();
        let keystore = Keystore {
            keys_dir,
            kdf_params: KdfParams::interactive(),
            use_keyring: false,
        };
        Ok((keystore, temp_dir))
    }

    /// Strategy: optional non-empty printable-ASCII password (1-31 chars) or None.
    /// None exercises the passwordless path. 0-length passwords are excluded
    /// because the API maps them the same as None but proptest can't infer that.
    fn keystore_password_strategy()
        -> impl proptest::strategy::Strategy<Value = Option<String>>
    {
        use proptest::strategy::Strategy as _;
        proptest::option::of(
            proptest::collection::vec(proptest::char::range(' ', '~'), 1..32usize)
                .prop_map(|v: Vec<char>| v.into_iter().collect::<String>()),
        )
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 50,
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        /// TEST-08: keystore round-trip property — for any classic KeyPair and any
        /// password (or no password), storing and loading must recover bit-identical
        /// public-key and secret-key bytes.
        ///
        /// Phase 14 / Plan 14-03 / D-04. Why: regressions in keystore serialisation
        /// (e.g. nonce drift, salt re-use, format-version mismatch) surface as
        /// non-equality in the round-trip; the property catches them before the
        /// shipping binary touches a real keystore.
        #[test]
        fn prop_keystore_classic_roundtrip(password in keystore_password_strategy()) {
            let (keystore, _temp_dir) =
                create_temp_keystore_interactive().expect("temp keystore");
            let keypair = KeyPair::generate().expect("classic keypair generate");
            let pw_ref = password.as_deref();

            let key_id = keystore
                .store_keypair(&keypair, pw_ref)
                .expect("store classic keypair");
            // 18-03: classic store_keypair writes format_version=1; pass
            // allow_unsigned=true to load.
            let retrieved = keystore
                .load_keypair(&key_id, pw_ref, true)
                .expect("load classic keypair");

            proptest::prop_assert_eq!(
                keypair.public_key().to_base64(),
                retrieved.public_key().to_base64(),
                "public key round-trip must be byte-identical"
            );
            proptest::prop_assert_eq!(
                keypair.secret_key().unwrap().to_base64(),
                retrieved.secret_key().unwrap().to_base64(),
                "secret key round-trip must be byte-identical"
            );
        }
    }

    #[cfg(feature = "hybrid")]
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 30,
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        /// TEST-08: hybrid keystore round-trip property — for any dual-suite
        /// (ClassicKeyPair + HybridKeyPair) identity and any password, storing
        /// via store_dual_keypair and loading via load_hybrid_keypair must recover
        /// bit-identical hybrid public-key bytes.
        ///
        /// Phase 14 / Plan 14-03 / D-04. Why: regressions in the dual-store path
        /// (e.g. wrong AEAD offset for hybrid_encrypted_secret_key, or public-key
        /// serialisation drift) would silently produce unloadable identity files
        /// only on the hybrid path; the property catches them pre-shipping.
        ///
        /// Note: store_keypair does not accept KeyPair::Hybrid (the Phase 3
        /// "dual-suite keystore support" note in its error message). The correct
        /// store API for hybrid material is store_dual_keypair.
        #[test]
        fn prop_keystore_hybrid_roundtrip(password in keystore_password_strategy()) {
            use crate::crypto::hybrid::HybridKeyPair;

            let (keystore, _temp_dir) =
                create_temp_keystore_interactive().expect("temp keystore");

            let classic_kp = ClassicKeyPair::generate().expect("classic kp generate");
            let hybrid_kp = HybridKeyPair::generate().expect("hybrid kp generate");
            let expected_pub_bytes = hybrid_kp.public_key().as_bytes().to_vec();
            let pw_ref = password.as_deref();

            let key_id = keystore
                .store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), pw_ref)
                .expect("store dual keypair");
            // 18-03: store_dual_keypair Case A now emits format_version=2,
            // so the standard verify-on-read path applies. allow_unsigned=false.
            let loaded_hybrid = keystore
                .load_hybrid_keypair(&key_id, pw_ref, false)
                .expect("load hybrid keypair");

            let loaded_pub_bytes = loaded_hybrid.public_key().as_bytes().to_vec();
            proptest::prop_assert_eq!(
                loaded_pub_bytes,
                expected_pub_bytes,
                "hybrid public key bytes must be bit-identical after round-trip"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 18 / PQSIG-03 — backward-compatibility deserialization tests for
    // the extended `StoredKeyPair` schema (format_version + 4 sig fields +
    // signature). v1 (legacy unsigned) and v2.0/v2.1 (hybrid-but-unsigned)
    // TOML files MUST continue to deserialize without error as
    // format_version=1 / signature=None. See plan 18-02 success criteria.
    // ─────────────────────────────────────────────────────────────────────────

    /// v1 minimal TOML (no `format_version`, no hybrid_*, no sig_*) deserializes
    /// with `format_version == 1` (default fn) and all sig-related fields absent.
    /// Closes T-18-02-02 (format_version-absent must default to 1, NOT 0).
    #[test]
    fn deser_v1_minimal_no_format_version() {
        let toml_str = r#"
uuid = "test-uuid-v1"
public_key = "abc123"
encrypted_secret_key = "encrypted-blob"
salt = "salt-blob"
created_at = "2026-01-01T00:00:00Z"
is_password_protected = true
"#;
        let stored: StoredKeyPair =
            toml::from_str(toml_str).expect("v1 minimal deser must succeed");
        assert_eq!(
            stored.format_version, 1,
            "missing format_version must default to 1 (Pitfall 5 / T-18-02-02)"
        );
        #[cfg(feature = "hybrid")]
        {
            assert!(stored.signature.is_none(), "v1 has no signature");
            assert!(stored.sig_ed448_public_key.is_none());
            assert!(stored.sig_ed448_encrypted_secret_key.is_none());
            assert!(stored.sig_mldsa65_public_key.is_none());
            assert!(stored.sig_mldsa65_encrypted_secret_key.is_none());
        }
    }

    /// Phase 7+ hybrid entry pre-Phase-18 (v2.0/v2.1): has `hybrid_public_key`
    /// and `hybrid_encrypted_secret_key` but NO `format_version` and NO sig_*
    /// fields. Must deserialize as `format_version=1` (legacy unsigned) with
    /// hybrid fields populated and signature absent.
    #[cfg(feature = "hybrid")]
    #[test]
    fn deser_v2_0_hybrid_no_signature() {
        let toml_str = r#"
uuid = "test-uuid-v20"
public_key = "abc123"
encrypted_secret_key = "encrypted-blob"
salt = "salt-blob"
created_at = "2026-01-01T00:00:00Z"
is_password_protected = true
hybrid_public_key = "hybrid-pk-b64"
hybrid_encrypted_secret_key = "hybrid-sk-encrypted"
"#;
        let stored: StoredKeyPair = toml::from_str(toml_str)
            .expect("v2.0 hybrid (pre-Phase-18) deser must succeed");
        assert_eq!(
            stored.format_version, 1,
            "v2.0 hybrid pre-Phase-18 entries are legacy unsigned (D-10)"
        );
        assert!(stored.hybrid_public_key.is_some());
        assert!(stored.hybrid_encrypted_secret_key.is_some());
        assert!(stored.signature.is_none());
        assert!(stored.sig_ed448_public_key.is_none());
        assert!(stored.sig_mldsa65_public_key.is_none());
    }

    /// Round-trip a `format_version=1, signature=None` `StoredKeyPair` through
    /// serde and assert the serialized form contains NO `[signature]` table
    /// and NO `sig_*` field lines. Closes T-18-02-03 (no phantom fields).
    #[cfg(feature = "hybrid")]
    #[test]
    fn ser_v1_omits_signature_table() {
        let v1 = StoredKeyPair {
            uuid: "u".into(),
            public_key: "p".into(),
            encrypted_secret_key: "e".into(),
            salt: Some("s".into()),
            created_at: chrono::Utc::now(),
            is_password_protected: false,
            in_keyring: false,
            hybrid_public_key: None,
            hybrid_encrypted_secret_key: None,
            format_version: 1,
            sig_ed448_public_key: None,
            sig_ed448_encrypted_secret_key: None,
            sig_mldsa65_public_key: None,
            sig_mldsa65_encrypted_secret_key: None,
            signature: None,
        };
        let toml_str = toml::to_string(&v1).expect("v1 serialise must succeed");
        assert!(
            !toml_str.contains("[signature]"),
            "v1 serialised form must not contain [signature] table; got: {toml_str}"
        );
        assert!(
            !toml_str.contains("sig_ed448"),
            "v1 must not emit sig_ed448_* fields; got: {toml_str}"
        );
        assert!(
            !toml_str.contains("sig_mldsa65"),
            "v1 must not emit sig_mldsa65_* fields; got: {toml_str}"
        );
    }

    /// Construct a fully-populated v2 entry, serialize → contains
    /// `format_version = 2`, `[signature]` table, and the 4 sig field lines;
    /// deserialize → byte-identical recovery.
    #[cfg(feature = "hybrid")]
    #[test]
    fn round_trip_v2_full() {
        let v2 = StoredKeyPair {
            uuid: "u".into(),
            public_key: "p".into(),
            encrypted_secret_key: "e".into(),
            salt: Some("s".into()),
            created_at: chrono::Utc::now(),
            is_password_protected: true,
            in_keyring: false,
            hybrid_public_key: Some("hpk".into()),
            hybrid_encrypted_secret_key: Some("hsk".into()),
            format_version: 2,
            sig_ed448_public_key: Some("ed-pk".into()),
            sig_ed448_encrypted_secret_key: Some("ed-sk-enc".into()),
            sig_mldsa65_public_key: Some("ml-pk".into()),
            sig_mldsa65_encrypted_secret_key: Some("ml-sk-enc".into()),
            signature: Some(crate::keystore::sig::KeystoreEntrySig {
                ed448: "ed-sig-b64".into(),
                mldsa65: "ml-sig-b64".into(),
            }),
        };
        let toml_str = toml::to_string(&v2).expect("v2 serialise must succeed");
        assert!(
            toml_str.contains("format_version = 2"),
            "v2 must emit format_version = 2; got: {toml_str}"
        );
        assert!(
            toml_str.contains("[signature]"),
            "v2 must emit [signature] table; got: {toml_str}"
        );
        assert!(
            toml_str.contains("sig_ed448_public_key"),
            "v2 must emit sig_ed448_public_key; got: {toml_str}"
        );
        assert!(
            toml_str.contains("sig_mldsa65_public_key"),
            "v2 must emit sig_mldsa65_public_key; got: {toml_str}"
        );

        let round_tripped: StoredKeyPair =
            toml::from_str(&toml_str).expect("v2 round-trip deser must succeed");
        assert_eq!(round_tripped.format_version, 2);
        assert!(round_tripped.signature.is_some());
        assert_eq!(
            round_tripped.signature.as_ref().unwrap().ed448,
            "ed-sig-b64"
        );
        assert_eq!(
            round_tripped.signature.as_ref().unwrap().mldsa65,
            "ml-sig-b64"
        );
        assert_eq!(
            round_tripped.sig_ed448_public_key.as_deref(),
            Some("ed-pk")
        );
        assert_eq!(
            round_tripped.sig_mldsa65_public_key.as_deref(),
            Some("ml-pk")
        );
    }

    /// Explicit `format_version = 2` TOML (signed entry shape) deserializes
    /// with all sig fields populated. Confirms forward-compatibility when
    /// 18-03 wires the actual sign-on-write path.
    #[cfg(feature = "hybrid")]
    #[test]
    fn deser_explicit_format_version_2() {
        let toml_str = r#"
uuid = "test"
public_key = "p"
encrypted_secret_key = "e"
salt = "s"
created_at = "2026-01-01T00:00:00Z"
is_password_protected = false
format_version = 2
sig_ed448_public_key = "ed-pk"
sig_ed448_encrypted_secret_key = "ed-sk-enc"
sig_mldsa65_public_key = "ml-pk"
sig_mldsa65_encrypted_secret_key = "ml-sk-enc"

[signature]
ed448 = "ed-sig"
mldsa65 = "ml-sig"
"#;
        let stored: StoredKeyPair =
            toml::from_str(toml_str).expect("v2 explicit deser must succeed");
        assert_eq!(stored.format_version, 2);
        assert!(stored.signature.is_some());
        assert_eq!(stored.signature.as_ref().unwrap().ed448, "ed-sig");
        assert_eq!(stored.signature.as_ref().unwrap().mldsa65, "ml-sig");
        assert_eq!(stored.sig_ed448_public_key.as_deref(), Some("ed-pk"));
    }

    /// `default_format_version()` returns 1 (the legacy-unsigned schema marker).
    /// Drift-detector for any accidental change to the default value.
    #[test]
    fn default_format_version_is_one() {
        assert_eq!(default_format_version(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 19-02 / PQSIG-05 — load_sig_keypair round-trip tests
    //
    // Verify that sig signing keys written by store_dual_keypair (Case A,
    // format_version=2) can be decrypted back by load_sig_keypair for both
    // password-protected and passwordless identities.
    // ─────────────────────────────────────────────────────────────────────────

    /// Passwordless round-trip: `store_dual_keypair` (passwordless) → `load_sig_keypair`.
    /// The sig SK stored as plain base64; `load_sig_keypair` must reconstruct valid
    /// `Ed448SigningKey` and `MlDsa65SigningKey` objects that produce verifiable signatures.
    #[cfg(feature = "hybrid")]
    #[test]
    fn load_sig_keypair_round_trip_passwordless() {
        use crate::crypto::hybrid::HybridKeyPair;
        use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};

        let (keystore, _tmp) = create_temp_keystore_interactive().expect("temp keystore");
        let classic_kp = ClassicKeyPair::generate().expect("classic kp");
        let hybrid_kp = HybridKeyPair::generate().expect("hybrid kp");

        // store_dual_keypair passwordless path stores sig SKs as plain base64
        let _key_id = keystore
            .store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), None)
            .expect("store_dual_keypair passwordless");

        // load_sig_keypair must return (Ed448SigningKey, MlDsa65SigningKey)
        let (ed448_sk, mldsa_sk) = keystore
            .load_sig_keypair("alice", None)
            .expect("load_sig_keypair passwordless");

        // Round-trip: sign a test payload with each key and verify it loads
        let payload = b"test-payload-for-sig-roundtrip";
        let ed448_pk = Ed448Standard::verifying_key(&ed448_sk);
        let ed448_sig = Ed448Standard::sign_with_context(
            &ed448_sk,
            payload,
            b"test-context",
        )
        .expect("Ed448 sign");
        assert!(
            Ed448Standard::verify_with_context(&ed448_pk, payload, b"test-context", &ed448_sig),
            "Ed448 sig must verify after load_sig_keypair passwordless round-trip"
        );

        let mldsa_pk = MlDsa65Fips204::verifying_key(&mldsa_sk);
        let mldsa_sig = MlDsa65Fips204::sign_with_context(
            &mldsa_sk,
            payload,
            b"test-context",
        )
        .expect("ML-DSA-65 sign");
        MlDsa65Fips204::verify_with_context(&mldsa_pk, payload, b"test-context", &mldsa_sig)
            .expect("ML-DSA-65 sig must verify after load_sig_keypair passwordless round-trip");
    }

    /// Password-protected round-trip: `store_dual_keypair` (pw) → `load_sig_keypair(pw)`.
    /// The sig SK stored AEAD-encrypted; `load_sig_keypair` must decrypt and reconstruct.
    #[cfg(feature = "hybrid")]
    #[test]
    fn load_sig_keypair_round_trip_password_protected() {
        use crate::crypto::hybrid::HybridKeyPair;
        use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};

        let (keystore, _tmp) = create_temp_keystore_interactive().expect("temp keystore");
        let classic_kp = ClassicKeyPair::generate().expect("classic kp");
        let hybrid_kp = HybridKeyPair::generate().expect("hybrid kp");
        let pw = "test-sig-keypair-pw-42";

        let _key_id = keystore
            .store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), Some(pw))
            .expect("store_dual_keypair pw-protected");

        let (ed448_sk, mldsa_sk) = keystore
            .load_sig_keypair("alice", Some(pw))
            .expect("load_sig_keypair pw-protected");

        let payload = b"test-payload-for-sig-roundtrip-pw";
        let ed448_pk = Ed448Standard::verifying_key(&ed448_sk);
        let ed448_sig = Ed448Standard::sign_with_context(
            &ed448_sk,
            payload,
            b"test-context",
        )
        .expect("Ed448 sign");
        assert!(
            Ed448Standard::verify_with_context(&ed448_pk, payload, b"test-context", &ed448_sig),
            "Ed448 sig must verify after load_sig_keypair pw round-trip"
        );

        let mldsa_pk = MlDsa65Fips204::verifying_key(&mldsa_sk);
        let mldsa_sig = MlDsa65Fips204::sign_with_context(
            &mldsa_sk,
            payload,
            b"test-context",
        )
        .expect("ML-DSA-65 sign");
        MlDsa65Fips204::verify_with_context(&mldsa_pk, payload, b"test-context", &mldsa_sig)
            .expect("ML-DSA-65 sig must verify after load_sig_keypair pw round-trip");
    }

    /// Wrong password must fail `load_sig_keypair` (AEAD authentication failure).
    #[cfg(feature = "hybrid")]
    #[test]
    fn load_sig_keypair_wrong_password_fails() {
        use crate::crypto::hybrid::HybridKeyPair;

        let (keystore, _tmp) = create_temp_keystore_interactive().expect("temp keystore");
        let classic_kp = ClassicKeyPair::generate().expect("classic kp");
        let hybrid_kp = HybridKeyPair::generate().expect("hybrid kp");
        let pw = "correct-password-here";

        keystore
            .store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), Some(pw))
            .expect("store_dual_keypair");

        let result = keystore.load_sig_keypair("alice", Some("wrong-password"));
        assert!(result.is_err(), "wrong password must fail load_sig_keypair");
        let err = result.err().expect("checked is_err above");
        assert!(
            err.to_string().contains("aead") || err.to_string().contains("decrypt"),
            "wrong password must produce AEAD error, got: {err}"
        );
    }
}
