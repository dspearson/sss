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

use zeroize::Zeroizing;

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

            let secret_key_str: Zeroizing<String> =
                Zeroizing::new(keypair.secret_key()?.to_base64());
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
            let secret_key_b64: Zeroizing<String> =
                Zeroizing::new(keypair.secret_key()?.to_base64());
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
        // Phase 38-03 (REM-04): format_version=3 is the new signed format —
        // KDF params (kdf_ops_limit, kdf_mem_limit) are included in the
        // payload. Dispatch arm mirrors format_version=2.
        match stored_keypair.format_version {
            1 => {
                if !allow_unsigned {
                    return Err(anyhow!(
                        "keystore: entry {key_id} is unsigned legacy format; pass --allow-unsigned to read or run `sss keys upgrade {key_id}` to re-sign"
                    ));
                }
                // Proceed without verify.
            }
            2 | 3 => {
                #[cfg(feature = "hybrid")]
                {
                    self.verify_stored_signature(&stored_keypair, &key_file)?;
                }
                #[cfg(not(feature = "hybrid"))]
                {
                    return Err(anyhow!(
                        "keystore: entry {key_id} is signed (format_version={}) but the current build does not include the `hybrid` feature; rebuild with --features hybrid",
                        stored_keypair.format_version
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
    // Why: set_passphrase performs a complete re-encryption cycle — load old key,
    // re-derive new KDF, AEAD-encrypt, rebuild StoredKeyPair, re-sign (hybrid),
    // and atomic-write.  The logic is a linear sequence with no natural split
    // point that wouldn't require passing ~6 intermediate values.
    #[allow(clippy::too_many_lines)]
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
        let secret_key_str: Zeroizing<String> =
            Zeroizing::new(keypair.secret_key()?.to_base64());
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
            let hybrid_sk_b64: Zeroizing<String> =
                Zeroizing::new(BASE64_STANDARD.encode(&raw_hybrid[..]));
            let new_enc = crate::crypto::encrypt_to_base64(
                &hybrid_sk_b64,
                &derived_key.to_encryption_key(),
            )
                .map_err(|e| anyhow!("keystore: aead-encrypt-hybrid (set_passphrase) for key_id={key_id}: {e}"))?;
            stored.hybrid_encrypted_secret_key = Some(new_enc);
        }

        // CR-02 (Phase 38-04): re-encrypt sig SKs and re-sign under updated KDF params
        // BEFORE stored.salt is overwritten. For format_version=3 entries, the signed
        // payload includes kdf_ops_limit/kdf_mem_limit keyed off is_password_protected.
        // After this function, is_password_protected becomes true and the KDF sentinel
        // changes from 0/0 to real params — the stored signature must be updated, or
        // the entry will fail verification on the next load.
        //
        // The sig SKs are also encrypted under the KEK; they must be re-encrypted here
        // (same pattern as hybrid_encrypted_secret_key above) so decrypt_sig_keys
        // in load_keypair can still read them after the salt changes.
        #[cfg(feature = "hybrid")]
        if stored.format_version >= 3 {
            use base64::prelude::BASE64_STANDARD;
            use crate::keystore::sig::{build_signed_payload, sign_entry};
            use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};
            use zeroize::Zeroizing;

            let ed448_enc_field = stored
                .sig_ed448_encrypted_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: sig_ed448_encrypted_secret_key missing on v3 entry {key_id}"))?
                .clone();
            let mldsa_enc_field = stored
                .sig_mldsa65_encrypted_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: sig_mldsa65_encrypted_secret_key missing on v3 entry {key_id}"))?
                .clone();

            // Decrypt sig SKs under the OLD KEK (before salt is overwritten).
            let (ed448_sk_raw, mldsa_sk_raw): (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) =
                if let Some(old_pw) = old_password {
                    // Was password-protected — decrypt with old password + old salt.
                    let old_salt_str = stored
                        .salt
                        .as_ref()
                        .ok_or_else(|| anyhow!("keystore: salt missing for protected v3 entry {key_id} (set_passphrase)"))?;
                    let old_salt = Salt::from_base64(old_salt_str)
                        .map_err(|e| anyhow!("keystore: salt-decode-sig (set_passphrase, old) for key_id={key_id}: {e}"))?;
                    let old_dk = DerivedKey::derive_with_params(old_pw, &old_salt, &self.kdf_params)
                        .map_err(|e| anyhow!("keystore: kdf-derive-sig (set_passphrase, old) for key_id={key_id}: {e}"))?;
                    let old_enc_key = old_dk.to_encryption_key();

                    let enc_ed448 = BASE64_STANDARD.decode(&ed448_enc_field)
                        .map_err(|e| anyhow!("keystore: b64-decode-sig-ed448 (set_passphrase) for key_id={key_id}: {e}"))?;
                    let dec_ed448_b64 = Zeroizing::new(
                        crate::crypto::decrypt(&enc_ed448, &old_enc_key)
                            .map_err(|_| anyhow!("keystore: aead-decrypt-sig-ed448 (set_passphrase) for {key_id}"))?,
                    );
                    let ed448_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(
                            std::str::from_utf8(&dec_ed448_b64)
                                .map_err(|e| anyhow!("keystore: sig-ed448-utf8 (set_passphrase): {e}"))?,
                        )
                            .map_err(|e| anyhow!("keystore: sig-ed448-b64inner (set_passphrase): {e}"))?,
                    );

                    let enc_mldsa = BASE64_STANDARD.decode(&mldsa_enc_field)
                        .map_err(|e| anyhow!("keystore: b64-decode-sig-mldsa65 (set_passphrase) for key_id={key_id}: {e}"))?;
                    let dec_mldsa_b64 = Zeroizing::new(
                        crate::crypto::decrypt(&enc_mldsa, &old_enc_key)
                            .map_err(|_| anyhow!("keystore: aead-decrypt-sig-mldsa65 (set_passphrase) for {key_id}"))?,
                    );
                    let mldsa_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(
                            std::str::from_utf8(&dec_mldsa_b64)
                                .map_err(|e| anyhow!("keystore: sig-mldsa65-utf8 (set_passphrase): {e}"))?,
                        )
                            .map_err(|e| anyhow!("keystore: sig-mldsa65-b64inner (set_passphrase): {e}"))?,
                    );

                    (ed448_raw, mldsa_raw)
                } else {
                    // Was passwordless — sig SKs stored as plain base64 of raw bytes.
                    let ed448_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(&ed448_enc_field)
                            .map_err(|e| anyhow!("keystore: b64-decode-sig-ed448-plain (set_passphrase): {e}"))?,
                    );
                    let mldsa_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(&mldsa_enc_field)
                            .map_err(|e| anyhow!("keystore: b64-decode-sig-mldsa65-plain (set_passphrase): {e}"))?,
                    );
                    (ed448_raw, mldsa_raw)
                };

            // Re-encrypt sig SKs under the NEW KEK (new password + new salt).
            let new_enc_key = derived_key.to_encryption_key();
            let ed448_sk_b64: Zeroizing<String> =
                Zeroizing::new(BASE64_STANDARD.encode(&ed448_sk_raw[..]));
            let new_enc_ed448 = crate::crypto::encrypt_to_base64(&ed448_sk_b64, &new_enc_key)
                .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (set_passphrase) for key_id={key_id}: {e}"))?;
            let mldsa_sk_b64: Zeroizing<String> =
                Zeroizing::new(BASE64_STANDARD.encode(&mldsa_sk_raw[..]));
            let new_enc_mldsa = crate::crypto::encrypt_to_base64(&mldsa_sk_b64, &new_enc_key)
                .map_err(|e| anyhow!("keystore: aead-encrypt-sig-mldsa65 (set_passphrase) for key_id={key_id}: {e}"))?;
            stored.sig_ed448_encrypted_secret_key = Some(new_enc_ed448);
            stored.sig_mldsa65_encrypted_secret_key = Some(new_enc_mldsa);

            // Reconstruct signing-key objects and re-sign with is_password_protected=true
            // and the new KDF cost params.
            let ed448_sk = Ed448Standard::signing_key_from_bytes(&ed448_sk_raw)
                .map_err(|e| anyhow!("keystore: ed448-sk-from-bytes (set_passphrase) for {key_id}: {e}"))?;
            let mldsa_sk = MlDsa65Fips204::signing_key_from_bytes(&mldsa_sk_raw)
                .map_err(|e| anyhow!("keystore: mldsa65-sk-from-bytes (set_passphrase) for {key_id}: {e}"))?;

            // After the update below, is_password_protected=true → use real KDF params.
            let payload = build_signed_payload(
                &stored.uuid,
                &stored.public_key,
                stored.hybrid_public_key.as_deref(),
                stored.sig_ed448_public_key.as_deref(),
                stored.sig_mldsa65_public_key.as_deref(),
                &stored.created_at.to_rfc3339(),
                self.kdf_params.ops_limit,
                self.kdf_params.mem_limit,
            );
            stored.signature = Some(
                sign_entry(&ed448_sk, &mldsa_sk, &payload)
                    .map_err(|e| anyhow!("keystore: sign-entry (set_passphrase) for key_id={key_id}: {e}"))?,
            );
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
    // Why: remove_passphrase performs AEAD-decrypt, rebuild of a passwordless
    // StoredKeyPair (with all optional sig fields), re-sign (hybrid), and
    // atomic-write — a linear sequence with no clean helper boundary.
    #[allow(clippy::too_many_lines)]
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

        // CR-02 (Phase 38-04): re-decrypt sig SKs under the current KEK, store them as
        // plain base64 (passwordless form), and re-sign under the updated 0/0 KDF sentinel
        // BEFORE stored.salt is cleared. For format_version=3 entries, the signed payload
        // includes kdf_ops_limit/kdf_mem_limit. After removal, is_password_protected=false
        // → the verifier reconstructs the payload with 0/0. The stored signature still
        // covers the real params — verification fails permanently unless re-signed here.
        #[cfg(feature = "hybrid")]
        if stored.format_version >= 3 {
            use base64::prelude::BASE64_STANDARD;
            use crate::keystore::sig::{build_signed_payload, sign_entry};
            use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};
            use zeroize::Zeroizing;

            let ed448_enc_field = stored
                .sig_ed448_encrypted_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: sig_ed448_encrypted_secret_key missing on v3 entry {key_id}"))?
                .clone();
            let mldsa_enc_field = stored
                .sig_mldsa65_encrypted_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: sig_mldsa65_encrypted_secret_key missing on v3 entry {key_id}"))?
                .clone();

            // Decrypt sig SKs under the current KEK (salt still valid here).
            let salt_str = stored
                .salt
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: salt missing for protected v3 entry {key_id} (remove_passphrase)"))?;
            let salt_obj = Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode-sig (remove_passphrase) for key_id={key_id}: {e}"))?;
            let dk = DerivedKey::derive_with_params(current_password, &salt_obj, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive-sig (remove_passphrase) for key_id={key_id}: {e}"))?;
            let enc_key = dk.to_encryption_key();

            let enc_ed448 = BASE64_STANDARD.decode(&ed448_enc_field)
                .map_err(|e| anyhow!("keystore: b64-decode-sig-ed448 (remove_passphrase) for key_id={key_id}: {e}"))?;
            let dec_ed448_b64 = Zeroizing::new(
                crate::crypto::decrypt(&enc_ed448, &enc_key)
                    .map_err(|_| anyhow!("keystore: aead-decrypt-sig-ed448 (remove_passphrase) for {key_id}"))?,
            );
            let ed448_sk_raw = Zeroizing::new(
                BASE64_STANDARD.decode(
                    std::str::from_utf8(&dec_ed448_b64)
                        .map_err(|e| anyhow!("keystore: sig-ed448-utf8 (remove_passphrase): {e}"))?,
                )
                    .map_err(|e| anyhow!("keystore: sig-ed448-b64inner (remove_passphrase): {e}"))?,
            );

            let enc_mldsa = BASE64_STANDARD.decode(&mldsa_enc_field)
                .map_err(|e| anyhow!("keystore: b64-decode-sig-mldsa65 (remove_passphrase) for key_id={key_id}: {e}"))?;
            let dec_mldsa_b64 = Zeroizing::new(
                crate::crypto::decrypt(&enc_mldsa, &enc_key)
                    .map_err(|_| anyhow!("keystore: aead-decrypt-sig-mldsa65 (remove_passphrase) for {key_id}"))?,
            );
            let mldsa_sk_raw = Zeroizing::new(
                BASE64_STANDARD.decode(
                    std::str::from_utf8(&dec_mldsa_b64)
                        .map_err(|e| anyhow!("keystore: sig-mldsa65-utf8 (remove_passphrase): {e}"))?,
                )
                    .map_err(|e| anyhow!("keystore: sig-mldsa65-b64inner (remove_passphrase): {e}"))?,
            );

            // Switch sig SK storage to passwordless form (plain base64 of raw bytes).
            stored.sig_ed448_encrypted_secret_key =
                Some(BASE64_STANDARD.encode(&ed448_sk_raw[..]));
            stored.sig_mldsa65_encrypted_secret_key =
                Some(BASE64_STANDARD.encode(&mldsa_sk_raw[..]));

            // Re-sign with is_password_protected=false → 0/0 sentinel.
            let ed448_sk = Ed448Standard::signing_key_from_bytes(&ed448_sk_raw)
                .map_err(|e| anyhow!("keystore: ed448-sk-from-bytes (remove_passphrase) for {key_id}: {e}"))?;
            let mldsa_sk = MlDsa65Fips204::signing_key_from_bytes(&mldsa_sk_raw)
                .map_err(|e| anyhow!("keystore: mldsa65-sk-from-bytes (remove_passphrase) for {key_id}: {e}"))?;

            // Passwordless sentinel: kdf_ops_limit=0, kdf_mem_limit=0.
            let payload = build_signed_payload(
                &stored.uuid,
                &stored.public_key,
                stored.hybrid_public_key.as_deref(),
                stored.sig_ed448_public_key.as_deref(),
                stored.sig_mldsa65_public_key.as_deref(),
                &stored.created_at.to_rfc3339(),
                0u64,
                0usize,
            );
            stored.signature = Some(
                sign_entry(&ed448_sk, &mldsa_sk, &payload)
                    .map_err(|e| anyhow!("keystore: sign-entry (remove_passphrase) for key_id={key_id}: {e}"))?,
            );
        }

        // Store secret key as plaintext (base64 encoded).
        // REM-21 / CR-03: wrap the to_base64() return in Zeroizing so the secret-key
        // bytes are volatile-overwritten when the temporary drops, rather than lingering
        // in heap pages. The clone into stored.encrypted_secret_key is unavoidable for
        // the on-disk TOML write path; only the intermediate is zeroed here.
        let secret_key_b64: zeroize::Zeroizing<String> =
            zeroize::Zeroizing::new(keypair.secret_key()?.to_base64());
        stored.encrypted_secret_key.clone_from(&*secret_key_b64);
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
                    let classic_sk_b64: Zeroizing<String> =
                        Zeroizing::new(KeyPair::Classic(classic.clone()).secret_key()?.to_base64());
                    let enc_classic =
                        crate::crypto::encrypt_to_base64(&classic_sk_b64, &enc_key)
                            .map_err(|e| anyhow!("keystore: aead-encrypt-secret-key (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    // Hybrid secret — encode directly from Zeroizing<[u8; N]> to
                    // avoid copying into a non-Zeroizing buffer (T-03-02).
                    let hybrid_sk_b64: Zeroizing<String> =
                        Zeroizing::new(BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref()));
                    let enc_hybrid =
                        crate::crypto::encrypt_to_base64(&hybrid_sk_b64, &enc_key)
                            .map_err(|e| anyhow!("keystore: aead-encrypt-hybrid (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    // Sig secrets — encrypted under the same KEK (D-07)
                    let sig_ed448_sk_b64: Zeroizing<String> =
                        Zeroizing::new(BASE64_STANDARD.encode(&ed448_sk_bytes[..]));
                    let enc_sig_ed448 = crate::crypto::encrypt_to_base64(
                        &sig_ed448_sk_b64,
                        &enc_key,
                    )
                        .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (store_dual_keypair Case A) for key_id={key_id}: {e}"))?;

                    let sig_mldsa_sk_b64: Zeroizing<String> =
                        Zeroizing::new(BASE64_STANDARD.encode(&mldsa_sk_bytes[..]));
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

                    let classic_sk_b64: Zeroizing<String> =
                        Zeroizing::new(KeyPair::Classic(classic.clone()).secret_key()?.to_base64());
                    let hybrid_sk_b64: Zeroizing<String> =
                        Zeroizing::new(BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref()));
                    let sig_ed448_sk_b64: Zeroizing<String> =
                        Zeroizing::new(BASE64_STANDARD.encode(&ed448_sk_bytes[..]));
                    let sig_mldsa_sk_b64: Zeroizing<String> =
                        Zeroizing::new(BASE64_STANDARD.encode(&mldsa_sk_bytes[..]));
                    (
                        (*classic_sk_b64).clone(),
                        (*hybrid_sk_b64).clone(),
                        (*sig_ed448_sk_b64).clone(),
                        (*sig_mldsa_sk_b64).clone(),
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
                // REM-04 (Phase 38-03): fields 7-8 = KDF cost params.
                // For password-protected entries: sign the actual Argon2id cost.
                // For passwordless entries: sign the 0/0 sentinel (no KDF applied).
                let (kdf_ops, kdf_mem) = if is_protected {
                    (self.kdf_params.ops_limit, self.kdf_params.mem_limit)
                } else {
                    // Passwordless sentinel: 0/0 (no KDF was applied).
                    (0u64, 0usize)
                };
                let payload = build_signed_payload(
                    &key_id,
                    &public_key_b64,
                    Some(&hybrid_public_key_b64),
                    Some(&ed448_pk_b64),
                    Some(&mldsa_pk_b64),
                    &created_at.to_rfc3339(),
                    kdf_ops,
                    kdf_mem,
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
                    // Phase 38-03 / REM-04 — format_version=3 for new entries with KDF params signed
                    format_version: 3,
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

                        let hybrid_sk_b64: Zeroizing<String> =
                            Zeroizing::new(BASE64_STANDARD.encode(hybrid.secret_bytes.as_ref()));
                        let enc_h = crate::crypto::encrypt_to_base64(
                            &hybrid_sk_b64,
                            &enc_key,
                        )
                            .map_err(|e| anyhow!("keystore: aead-encrypt-hybrid (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                        let sig_ed448_sk_b64: Zeroizing<String> =
                            Zeroizing::new(BASE64_STANDARD.encode(&ed448_sk_bytes[..]));
                        let enc_e = crate::crypto::encrypt_to_base64(
                            &sig_ed448_sk_b64,
                            &enc_key,
                        )
                            .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (store_dual_keypair Case B) for key_id={key_id}: {e}"))?;

                        let sig_mldsa_sk_b64: Zeroizing<String> =
                            Zeroizing::new(BASE64_STANDARD.encode(&mldsa_sk_bytes[..]));
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
                // Phase 38-03 / REM-04 — format_version=3 for new entries with KDF params signed
                stored.format_version = 3;
                stored.sig_ed448_public_key = Some(ed448_pk_b64.clone());
                stored.sig_ed448_encrypted_secret_key = Some(enc_sig_ed448);
                stored.sig_mldsa65_public_key = Some(mldsa_pk_b64.clone());
                stored.sig_mldsa65_encrypted_secret_key = Some(enc_sig_mldsa);

                // D-08 / D-19 canonical payload (identity-bearing public fields only)
                // Pitfall 1 — use the SAME `created_at` already on the struct, not a new now()
                // REM-04 (Phase 38-03): fields 7-8 = KDF cost params.
                // For password-protected entries: sign the actual Argon2id cost.
                // For passwordless entries: sign the 0/0 sentinel (no KDF applied).
                let (kdf_ops_b, kdf_mem_b) = if stored.is_password_protected {
                    (self.kdf_params.ops_limit, self.kdf_params.mem_limit)
                } else {
                    // Passwordless sentinel: 0/0 (no KDF was applied).
                    (0u64, 0usize)
                };
                let payload = build_signed_payload(
                    &stored.uuid,
                    &stored.public_key,
                    Some(&hybrid_public_key_b64),
                    Some(&ed448_pk_b64),
                    Some(&mldsa_pk_b64),
                    &stored.created_at.to_rfc3339(),
                    kdf_ops_b,
                    kdf_mem_b,
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
    /// - `format_version == 3` → invoke `verify_stored_signature` (Phase 38-03 / REM-04).
    /// - `format_version >= 4` → hard error.
    ///
    /// Returns `Err` if the file has no hybrid material, or if decryption fails.
    // Why: load_hybrid_keypair handles format_version dispatch (1/2/3/≥4),
    // conditional AEAD-decrypt or base64-decode, signature verification for v2/v3,
    // and secret-material reconstruction with zeroisation.  Each branch
    // depends on intermediate decrypted material; extracting helpers would
    // require passing zeroizing buffers across call boundaries.
    #[cfg_attr(feature = "hybrid", allow(clippy::too_many_lines))]
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
        // Phase 38-03 (REM-04): format_version=3 added — KDF params in payload.
        match stored.format_version {
            1 => {
                if !allow_unsigned {
                    return Err(anyhow!(
                        "keystore: entry {key_id} is unsigned legacy format; pass --allow-unsigned to read or run `sss keys upgrade {key_id}` to re-sign"
                    ));
                }
                // Proceed without verify.
            }
            2 | 3 => {
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

        // Derive the key-encryption key (KEK) once, shared across hybrid + sig
        // slot decryption and the REM-03 re-derivation checks.
        // For passwordless entries: `kek = None` — keys stored as plain base64.
        let kek: Option<crate::crypto::RepositoryKey> = if stored.is_password_protected {
            let pw = password.ok_or_else(|| {
                anyhow!("Password required for encrypted key")
            })?;
            let salt_str = stored.salt.as_ref().ok_or_else(|| {
                anyhow!("Salt missing for password-protected key")
            })?;
            let salt = crate::kdf::Salt::from_base64(salt_str)
                .map_err(|e| anyhow!("keystore: salt-decode (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
            let dk = crate::kdf::DerivedKey::derive_with_params(pw, &salt, &self.kdf_params)
                .map_err(|e| anyhow!("keystore: kdf-derive (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
            Some(dk.to_encryption_key())
        } else {
            None
        };

        // Decrypt helper: given a base64-encoded (possibly AEAD-encrypted) field,
        // return raw key bytes in a Zeroizing buffer. Mirrors load_sig_keypair.
        let decrypt_field = |field_b64: &str, label: &str| -> Result<Zeroizing<Vec<u8>>> {
            if let Some(ref enc_key) = kek {
                let enc_bytes = BASE64_STANDARD.decode(field_b64)
                    .map_err(|e| anyhow!("keystore: base64-decode-{label} (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
                let decrypted = Zeroizing::new(
                    crate::crypto::decrypt(&enc_bytes, enc_key)
                        .map_err(|e| anyhow!("keystore: aead-decrypt-{label} (load_hybrid_keypair) for key_id={key_id}: {e}"))?
                );
                // decrypted is the base64 string of the raw key bytes
                let inner_b64 = std::str::from_utf8(&decrypted)
                    .map_err(|e| anyhow!("keystore: utf8-{label} (load_hybrid_keypair) for key_id={key_id}: {e}"))?;
                Ok(Zeroizing::new(
                    BASE64_STANDARD.decode(inner_b64)
                        .map_err(|e| anyhow!("keystore: base64-decode-{label}-inner (load_hybrid_keypair) for key_id={key_id}: {e}"))?
                ))
            } else {
                // Passwordless — plain base64
                Ok(Zeroizing::new(
                    BASE64_STANDARD.decode(field_b64)
                        .map_err(|e| anyhow!("keystore: base64-decode-{label} (load_hybrid_keypair, passwordless) for key_id={key_id}: {e}"))?
                ))
            }
        };

        // Decrypt the hybrid secret material.
        // All intermediates are Zeroizing so secret bytes don't linger on the heap (WR-03).
        let raw_secret_bytes = decrypt_field(&hybrid_enc_sk_b64, "hybrid-sk")?;

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

        // REM-03 (CRY-09) — Hybrid KEM slot: re-derive the public key from the
        // recovered secret bytes and verify it matches the stored (signed) field.
        {
            use trelis_hybrid::kem::HybridKemKeypair;
            use subtle::ConstantTimeEq;

            let kem_check = HybridKemKeypair::from_bytes(&raw_secret_bytes[..])
                .map_err(|e| anyhow!("keystore: hybrid KEM reconstruct (rederive check) for key_id={key_id}: {e}"))?;
            let derived_pk_bytes = kem_check.public_key().to_bytes();
            if derived_pk_bytes.as_ref().len() != pub_bytes_raw.len()
                || derived_pk_bytes.as_ref().ct_eq(&pub_bytes_raw).unwrap_u8() != 1
            {
                return Err(anyhow!(
                    "keystore entry corrupt or tampered: public key mismatch (hybrid slot)"
                ));
            }
        }

        // REM-03 (CRY-09) — Ed448 + ML-DSA-65 sig slots (if present in this
        // entry). Classic-only entries have these fields as None; guard with
        // `if let Some(...)` so they are not falsely rejected.
        //
        // The sig public keys are signed (part of `StoredKeyPair.signature`), so
        // an attacker who swaps the sig-encrypted-secret-key ciphertext would be
        // caught here: we decrypt the ciphertext, re-derive the verifying key, and
        // compare it to the signed stored public key.
        {
            use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};
            use subtle::ConstantTimeEq;

            if let Some(stored_ed448_pk_b64) = stored.sig_ed448_public_key.as_deref()
                && let Some(enc_ed448_sk_b64) = stored.sig_ed448_encrypted_secret_key.as_deref() {
                    let ed448_sk_bytes = decrypt_field(enc_ed448_sk_b64, "sig-ed448-sk")?;
                    let ed448_sk = Ed448Standard::signing_key_from_bytes(&ed448_sk_bytes)
                        .map_err(|e| anyhow!("keystore: parse-ed448-sk (rederive) for key_id={key_id}: {e}"))?;
                    let vk = Ed448Standard::verifying_key(&ed448_sk);
                    let derived_ed448_pk = Ed448Standard::verifying_key_to_bytes(&vk);
                    let stored_ed448_pk = BASE64_STANDARD.decode(stored_ed448_pk_b64)
                        .map_err(|e| anyhow!("keystore: base64-decode-ed448-pk (rederive) for key_id={key_id}: {e}"))?;
                    if derived_ed448_pk.as_ref().len() != stored_ed448_pk.len()
                        || derived_ed448_pk.as_ref().ct_eq(&stored_ed448_pk).unwrap_u8() != 1
                    {
                        return Err(anyhow!(
                            "keystore entry corrupt or tampered: public key mismatch (Ed448 slot)"
                        ));
                    }
                }

            if let Some(stored_mldsa_pk_b64) = stored.sig_mldsa65_public_key.as_deref()
                && let Some(enc_mldsa_sk_b64) = stored.sig_mldsa65_encrypted_secret_key.as_deref() {
                    let mldsa_sk_bytes = decrypt_field(enc_mldsa_sk_b64, "sig-mldsa65-sk")?;
                    let mldsa_sk = MlDsa65Fips204::signing_key_from_bytes(&mldsa_sk_bytes)
                        .map_err(|e| anyhow!("keystore: parse-mldsa65-sk (rederive) for key_id={key_id}: {e}"))?;
                    let vk = MlDsa65Fips204::verifying_key(&mldsa_sk);
                    let derived_mldsa_pk = MlDsa65Fips204::verifying_key_to_bytes(&vk);
                    let stored_mldsa_pk = BASE64_STANDARD.decode(stored_mldsa_pk_b64)
                        .map_err(|e| anyhow!("keystore: base64-decode-mldsa65-pk (rederive) for key_id={key_id}: {e}"))?;
                    if derived_mldsa_pk.as_ref().len() != stored_mldsa_pk.len()
                        || derived_mldsa_pk.as_ref().ct_eq(&stored_mldsa_pk).unwrap_u8() != 1
                    {
                        return Err(anyhow!(
                            "keystore entry corrupt or tampered: public key mismatch (ML-DSA-65 slot)"
                        ));
                    }
                }
        }

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
    // Why: load_sig_keypair handles both password-protected and passwordless
    // paths for two key types (Ed448 + ML-DSA-65), each needing AEAD-decrypt
    // or base64-decode followed by key-parse.  Splitting would require passing
    // zeroizing intermediate buffers across call boundaries without clarity gain.
    #[cfg_attr(feature = "hybrid", allow(clippy::too_many_lines))]
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
        //
        // IN-01 (Phase 38-04): The `< 2` bound is intentionally asymmetric with the
        // `2 | 3` arms used elsewhere in the dispatch ladder. Using `< 2` here
        // (rather than `== 1`) is forward-compatible: any future format_version still
        // has sig material (Phase 18 established sig keys from v2 onwards), so the
        // guard correctly admits v4+ entries without a code change. The `2 | 3` arms
        // in load_keypair / verify_stored_signature are explicit because they dispatch
        // on payload schema differences — this guard only tests presence of sig fields.
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

        // REM-03 (CRY-09) — Ed448 + ML-DSA-65 sig slots: re-derive each
        // verifying key from the recovered signing key bytes and compare against
        // the stored (signed) public key fields.
        //
        // load_sig_keypair already requires format_version >= 2 (guard at the top
        // of this function), so sig_*_public_key fields are expected to be Some
        // for all entries that reach this point. The `if let Some(...)` guards
        // handle any edge cases where fields might be absent despite format_version=2.
        {
            use subtle::ConstantTimeEq;

            if let Some(stored_ed448_pk_b64) = stored.sig_ed448_public_key.as_deref() {
                let vk = Ed448Standard::verifying_key(&ed448_sk);
                let derived_ed448_pk = Ed448Standard::verifying_key_to_bytes(&vk);
                let stored_ed448_pk = BASE64_STANDARD.decode(stored_ed448_pk_b64)
                    .map_err(|e| anyhow!("keystore: base64-decode-ed448-pk (rederive, load_sig_keypair) for key_id={key_id}: {e}"))?;
                if derived_ed448_pk.as_ref().len() != stored_ed448_pk.len()
                    || derived_ed448_pk.as_ref().ct_eq(&stored_ed448_pk).unwrap_u8() != 1
                {
                    return Err(anyhow!(
                        "keystore entry corrupt or tampered: public key mismatch (Ed448 slot)"
                    ));
                }
            }

            if let Some(stored_mldsa_pk_b64) = stored.sig_mldsa65_public_key.as_deref() {
                let vk = MlDsa65Fips204::verifying_key(&mldsa_sk);
                let derived_mldsa_pk = MlDsa65Fips204::verifying_key_to_bytes(&vk);
                let stored_mldsa_pk = BASE64_STANDARD.decode(stored_mldsa_pk_b64)
                    .map_err(|e| anyhow!("keystore: base64-decode-mldsa65-pk (rederive, load_sig_keypair) for key_id={key_id}: {e}"))?;
                if derived_mldsa_pk.as_ref().len() != stored_mldsa_pk.len()
                    || derived_mldsa_pk.as_ref().ct_eq(&stored_mldsa_pk).unwrap_u8() != 1
                {
                    return Err(anyhow!(
                        "keystore entry corrupt or tampered: public key mismatch (ML-DSA-65 slot)"
                    ));
                }
            }
        }

        Ok((ed448_sk, mldsa_sk))
    }

    /// Re-sign a `format_version=1` or `format_version=2` entry in place,
    /// promoting it to `format_version=3` without changing identity.
    ///
    /// Phase 18-04 / PQSIG-03 transition path, updated Phase 38-03 (REM-04).
    /// For v1 → v3: generates fresh per-entry Ed448 + ML-DSA-65 sig keypairs,
    /// encrypts the sig SKs under the EXISTING KEK (D-07; passwordless entries
    /// store base64 raw), bumps `format_version` to 3, populates the four sig
    /// fields, builds the 8-field payload (including KDF params), and signs.
    /// For v2 → v3: reuses the existing sig keypairs (no rotation), re-signs
    /// with the updated 8-field payload after verifying the existing v2 signature.
    /// The canonical signed payload (D-08) is rebuilt in all cases and an
    /// AND-composition signature is produced via `keystore::sig::sign_entry`.
    ///
    /// Atomic write via `tempfile::NamedTempFile::new_in(parent).persist(target)`
    /// so a crash mid-write never produces a half-written entry (D-15).
    /// **Pitfall 4**: MUST use `new_in(parent)` — `NamedTempFile::new()` defaults
    /// to `/tmp` which is a different filesystem on most Linux installs and
    /// `.persist()` would fail with `EXDEV` (cross-device link).
    ///
    /// Refuses (without writing) if `format_version >= 3`; the caller (CLI)
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

        // Refuse already-signed v3 entries (D-17): upgrade is the migration path
        // for v1/v2 → v3; there is no v3 → v3 re-sign mode.
        // Phase 38-03 (REM-04): v2 entries are re-signed to v3 (adds KDF params
        // to the signed payload); v1 entries generate fresh sig keypairs then sign.
        if stored.format_version >= 3 {
            return Err(anyhow!(
                "keystore: entry {} is already signed (format_version={}); upgrade is a no-op",
                key_id, stored.format_version
            ));
        }
        if stored.format_version != 1 && stored.format_version != 2 {
            return Err(anyhow!(
                "keystore: unsupported format_version {} for upgrade (expected 1 or 2)",
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

        // Phase 38-03 (REM-04): branch on source version.
        //
        // v1 → v3: generate fresh per-entry sig keypairs (D-06), encrypt them,
        //          populate sig fields, build 8-field payload, sign.
        // v2 → v3: reuse the existing sig keypairs (no rotation) — decrypt the
        //          stored sig SKs, build the new 8-field payload (adds KDF params),
        //          re-sign. Sig pub keys are unchanged; only `format_version` and
        //          the signature blob are updated.
        let (ed448_sk, mldsa_sk) = if stored.format_version == 1 {
            // ── v1 → v3: generate fresh sig keypairs ─────────────────────────

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

            // Encrypt sig SKs under the existing KEK (protected) or store
            // base64 raw (passwordless) — matches store_dual_keypair D-07.
            let (sig_ed448_sk_field, sig_mldsa_sk_field) = if stored.is_password_protected {
                // Re-derive KEK. password and salt already validated above.
                #[allow(clippy::expect_used)]
                let pw = password.expect("checked above");
                #[allow(clippy::expect_used)]
                let salt_str = stored.salt.as_ref().expect("checked above");
                let salt = crate::kdf::Salt::from_base64(salt_str)
                    .map_err(|e| anyhow!("keystore: salt-decode-2 (upgrade) for key_id={key_id}: {e}"))?;
                let dk = crate::kdf::DerivedKey::derive_with_params(pw, &salt, &self.kdf_params)
                    .map_err(|e| anyhow!("keystore: kdf-derive-2 (upgrade) for key_id={key_id}: {e}"))?;
                let enc_key = dk.to_encryption_key();

                let sig_ed448_sk_b64: Zeroizing<String> =
                    Zeroizing::new(BASE64_STANDARD.encode(&ed448_sk_bytes[..]));
                let enc_sig_ed448 =
                    crate::crypto::encrypt_to_base64(&sig_ed448_sk_b64, &enc_key)
                        .map_err(|e| anyhow!("keystore: aead-encrypt-sig-ed448 (upgrade) for key_id={key_id}: {e}"))?;

                let sig_mldsa_sk_b64: Zeroizing<String> =
                    Zeroizing::new(BASE64_STANDARD.encode(&mldsa_sk_bytes[..]));
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

            // Populate sig fields (v1 had none).
            stored.sig_ed448_public_key = Some(ed448_pk_b64);
            stored.sig_ed448_encrypted_secret_key = Some(sig_ed448_sk_field);
            stored.sig_mldsa65_public_key = Some(mldsa_pk_b64);
            stored.sig_mldsa65_encrypted_secret_key = Some(sig_mldsa_sk_field);

            (ed448_sk, mldsa_sk)
        } else {
            // ── v2 → v3: decrypt existing sig keypairs (no rotation) ─────────
            // T-38-03: sig pub keys are unchanged; only the signed payload
            // (now including KDF params) and the signature blob are updated.

            // WR-03 (Phase 38-04): verify the existing v2 signature BEFORE re-signing.
            // Without this check, an attacker who crafted a format_version=2 entry with
            // arbitrary sig keypairs (skipping the v1-context verification) could cause
            // `upgrade` to promote their chosen keys to v3 without any integrity check.
            // `verify_stored_signature` now dispatches on format_version=2 → v1 context,
            // so this call correctly verifies the 6-field, v1-context signature.
            self.verify_stored_signature(&stored, &key_file)
                .map_err(|e| anyhow!("keystore: v2 signature verification failed for {key_id} (WR-03 guard): {e}"))?;

            let ed448_enc_field = stored
                .sig_ed448_encrypted_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: sig_ed448_encrypted_secret_key missing on v2 entry {key_id}"))?;
            let mldsa_enc_field = stored
                .sig_mldsa65_encrypted_secret_key
                .as_ref()
                .ok_or_else(|| anyhow!("keystore: sig_mldsa65_encrypted_secret_key missing on v2 entry {key_id}"))?;

            let (ed448_sk_bytes, mldsa_sk_bytes): (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) =
                if stored.is_password_protected {
                    // Decrypt sig SKs using the existing KEK.
                    #[allow(clippy::expect_used)]
                    let pw = password.expect("checked above");
                    #[allow(clippy::expect_used)]
                    let salt_str = stored.salt.as_ref().expect("checked above");
                    let salt = crate::kdf::Salt::from_base64(salt_str)
                        .map_err(|e| anyhow!("keystore: salt-decode-2 (upgrade-v2) for key_id={key_id}: {e}"))?;
                    let dk = crate::kdf::DerivedKey::derive_with_params(pw, &salt, &self.kdf_params)
                        .map_err(|e| anyhow!("keystore: kdf-derive-2 (upgrade-v2) for key_id={key_id}: {e}"))?;
                    let enc_key = dk.to_encryption_key();

                    let enc_ed448 = BASE64_STANDARD.decode(ed448_enc_field)
                        .map_err(|e| anyhow!("keystore: base64-decode-sig-ed448 (upgrade-v2) for key_id={key_id}: {e}"))?;
                    let dec_ed448_b64_bytes = Zeroizing::new(
                        crate::crypto::decrypt(&enc_ed448, &enc_key)
                            .map_err(|_| anyhow!("keystore: aead-decrypt-sig-ed448 (upgrade-v2) for {key_id}"))?,
                    );
                    // The plaintext is base64(raw_sk_bytes); decode it.
                    let dec_ed448_b64_str = std::str::from_utf8(&dec_ed448_b64_bytes)
                        .map_err(|e| anyhow!("keystore: sig-ed448-utf8 (upgrade-v2): {e}"))?;
                    let ed448_sk_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(dec_ed448_b64_str)
                            .map_err(|e| anyhow!("keystore: sig-ed448-b64decode-inner (upgrade-v2): {e}"))?,
                    );

                    let enc_mldsa = BASE64_STANDARD.decode(mldsa_enc_field)
                        .map_err(|e| anyhow!("keystore: base64-decode-sig-mldsa65 (upgrade-v2) for key_id={key_id}: {e}"))?;
                    let dec_mldsa_b64_bytes = Zeroizing::new(
                        crate::crypto::decrypt(&enc_mldsa, &enc_key)
                            .map_err(|_| anyhow!("keystore: aead-decrypt-sig-mldsa65 (upgrade-v2) for {key_id}"))?,
                    );
                    let dec_mldsa_b64_str = std::str::from_utf8(&dec_mldsa_b64_bytes)
                        .map_err(|e| anyhow!("keystore: sig-mldsa65-utf8 (upgrade-v2): {e}"))?;
                    let mldsa_sk_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(dec_mldsa_b64_str)
                            .map_err(|e| anyhow!("keystore: sig-mldsa65-b64decode-inner (upgrade-v2): {e}"))?,
                    );

                    (ed448_sk_raw, mldsa_sk_raw)
                } else {
                    // Passwordless: sig SKs are stored as plain base64 of raw bytes.
                    let ed448_sk_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(ed448_enc_field)
                            .map_err(|e| anyhow!("keystore: base64-decode-sig-ed448-plain (upgrade-v2): {e}"))?,
                    );
                    let mldsa_sk_raw = Zeroizing::new(
                        BASE64_STANDARD.decode(mldsa_enc_field)
                            .map_err(|e| anyhow!("keystore: base64-decode-sig-mldsa65-plain (upgrade-v2): {e}"))?,
                    );
                    (ed448_sk_raw, mldsa_sk_raw)
                };

            // Reconstruct signing-key objects from raw bytes.
            let ed448_sk = Ed448Standard::signing_key_from_bytes(&ed448_sk_bytes)
                .map_err(|e| anyhow!("keystore: ed448-sk-from-bytes (upgrade-v2) for {key_id}: {e}"))?;
            let mldsa_sk = MlDsa65Fips204::signing_key_from_bytes(&mldsa_sk_bytes)
                .map_err(|e| anyhow!("keystore: mldsa65-sk-from-bytes (upgrade-v2) for {key_id}: {e}"))?;

            (ed448_sk, mldsa_sk)
        };

        // Bump schema to v3 (the version that carries KDF params in the payload).
        stored.format_version = 3;

        // Canonical D-08 payload (identity-bearing public fields only).
        // T-18-04-05: uuid + public_key + hybrid_public_key + created_at
        // are byte-preserved from the v1/v2 entry.
        //
        // REM-04 (Phase 38-03): fields 7-8 = KDF cost params. For password-protected
        // entries, sign the actual Argon2id cost (self.kdf_params). For passwordless
        // entries (is_password_protected=false), no KDF was applied — sign the 0/0
        // sentinel (kdf_ops_limit=0, kdf_mem_limit=0). This must match the sentinel
        // logic in verify_stored_signature.
        let (kdf_ops, kdf_mem) = if stored.is_password_protected {
            (self.kdf_params.ops_limit, self.kdf_params.mem_limit)
        } else {
            // Passwordless sentinel: 0/0 (no KDF applied).
            (0u64, 0usize)
        };
        let payload = build_signed_payload(
            &stored.uuid,
            &stored.public_key,
            stored.hybrid_public_key.as_deref(),
            stored.sig_ed448_public_key.as_deref(),
            stored.sig_mldsa65_public_key.as_deref(),
            &stored.created_at.to_rfc3339(),
            kdf_ops,
            kdf_mem,
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
        use crate::keystore::sig::{
            build_signed_payload, build_signed_payload_v1,
            verify_entry_with_context,
            KEYSTORE_SIG_CONTEXT, KEYSTORE_SIG_CONTEXT_V1,
        };
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

        // CR-01 (Phase 38-04): dispatch on format_version to choose the correct
        // payload schema AND context bytes.
        //
        // format_version=2 entries were signed BEFORE REM-04 extended the payload
        // to 8 fields and bumped the context to v2. They MUST be verified with:
        //   - the 6-field payload (no kdf_ops, no kdf_mem)
        //   - KEYSTORE_SIG_CONTEXT_V1 ("sss-keystore-entry-sig-v1")
        // Applying the v2 context to a v2 entry is a guaranteed failure; the
        // format_version field on disk is the authoritative indicator.
        //
        // format_version=3 entries (REM-04) use:
        //   - the 8-field payload (includes kdf_ops_limit, kdf_mem_limit)
        //   - KEYSTORE_SIG_CONTEXT ("sss-keystore-entry-sig-v2")
        //
        // This dispatch makes format_version=2 entries loadable so `sss keys upgrade`
        // can promote them to v3; without it they would be permanently inaccessible.
        match stored.format_version {
            2 => {
                // 6-field payload, v1 context — the schema signed by Phase 18 binaries.
                let payload = build_signed_payload_v1(
                    &stored.uuid,
                    &stored.public_key,
                    stored.hybrid_public_key.as_deref(),
                    stored.sig_ed448_public_key.as_deref(),
                    stored.sig_mldsa65_public_key.as_deref(),
                    &stored.created_at.to_rfc3339(),
                );
                verify_entry_with_context(
                    &ed448_pk, &mldsa_pk, &payload, sig, KEYSTORE_SIG_CONTEXT_V1,
                )
                .map_err(|_| canonical_err())
            }
            3 => {
                // 8-field payload, v2 context — the schema signed by Phase 38+ binaries.
                // Pitfall 1: pass `created_at.to_rfc3339()` — same encoding used in
                // `store_dual_keypair`. Deterministic; round-trips via chrono::serde.
                //
                // REM-04 (Phase 38-03): fields 7-8 = KDF cost params. For password-protected
                // entries, sign the actual Argon2id cost (self.kdf_params). For passwordless
                // entries (is_password_protected=false), no KDF was applied — sign the 0/0
                // sentinel. The same sentinel logic is applied in all signing paths
                // (upgrade_keypair_in_place, store_dual_keypair) so signer and verifier agree.
                let (kdf_ops, kdf_mem) = if stored.is_password_protected {
                    (self.kdf_params.ops_limit, self.kdf_params.mem_limit)
                } else {
                    // Passwordless sentinel: kdf_ops_limit=0, kdf_mem_limit=0 (no KDF applied).
                    (0u64, 0usize)
                };
                let payload = build_signed_payload(
                    &stored.uuid,
                    &stored.public_key,
                    stored.hybrid_public_key.as_deref(),
                    stored.sig_ed448_public_key.as_deref(),
                    stored.sig_mldsa65_public_key.as_deref(),
                    &stored.created_at.to_rfc3339(),
                    kdf_ops,
                    kdf_mem,
                );
                verify_entry_with_context(
                    &ed448_pk, &mldsa_pk, &payload, sig, KEYSTORE_SIG_CONTEXT,
                )
                .map_err(|_| canonical_err())
            }
            // format_version=1 entries do not reach here (load_keypair dispatches
            // on format_version before calling verify_stored_signature); format_version
            // >= 4 entries are also rejected by load_keypair before reaching here.
            // This arm is unreachable in correct call sequences but is kept defensive.
            _ => Err(canonical_err()),
        }
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

        // REM-03 (CRY-09): Re-derive the X25519 public key from the recovered
        // secret key and assert it matches the stored (signed) public_key field.
        // A substituted AEAD ciphertext whose recovered secret does not match the
        // stored public key is rejected here before any further use.
        //
        // Guard: `stored.public_key` is always present (it is not Option); the
        // classic slot is always populated, so we do not guard with `if let`.
        {
            use base64::prelude::BASE64_STANDARD;
            use subtle::ConstantTimeEq;

            let stored_pk_bytes = BASE64_STANDARD
                .decode(&stored.public_key)
                .map_err(|e| anyhow!("keystore: base64-decode-public-key (rederive classic) for key_id={}: {}", stored.uuid, e))?;

            let mut derived_pk = [0u8; libsodium_sys::crypto_scalarmult_BYTES as usize];
            // SAFETY: `derived_pk` is a 32-byte output buffer matching
            // `crypto_scalarmult_BYTES`. `secret_key.as_bytes()` is a valid
            // 32-byte scalar (`SECRET_KEY_SIZE == crypto_box_SECRETKEYBYTES ==
            // 32`). libsodium is initialised by `ensure_sodium_init()` which is
            // called in every generate/from_seed path; the keystore itself
            // initialises it at construction time. Returns 0 on success.
            #[cfg(not(miri))]
            let rc = unsafe {
                libsodium_sys::crypto_scalarmult_base(
                    derived_pk.as_mut_ptr(),
                    secret_key.as_bytes().as_ptr(),
                )
            };
            // Miri stub: crypto_scalarmult_base is FFI; ASAN (Phase 23
            // MEMSAFE-03) covers this path under non-miri builds. Under miri
            // the derived key stays zero-initialised and `rc=0` so the check
            // is a no-op (identity postcondition; acceptable because we are not
            // testing libsodium under miri).
            #[cfg(miri)]
            let rc: i32 = 0;

            if rc != 0 {
                return Err(anyhow!(
                    "keystore entry corrupt or tampered: public key re-derivation failed (classic slot)"
                ));
            }

            let len_ok = stored_pk_bytes.len() == derived_pk.len();
            let bytes_ok = if len_ok {
                derived_pk
                    .ct_eq(stored_pk_bytes.as_slice())
                    .unwrap_u8()
                    == 1
            } else {
                false
            };
            if !len_ok || !bytes_ok {
                return Err(anyhow!(
                    "keystore entry corrupt or tampered: public key mismatch (classic slot)"
                ));
            }
        }

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
    // Why: HybridKeyPair contains Ed448SigningKey which doesn't impl Debug, so
    // expect_err() (which requires T: Debug) cannot be used here. The is_err()
    // assertion on the preceding line makes the .err().expect() infallible.
    #[allow(clippy::err_expect)]
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

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 38-02 / REM-03 — ciphertext-substitution rejection tests
    //
    // Each test generates two entries with the SAME password so AEAD decryption
    // succeeds after the swap; detection relies entirely on the post-decrypt
    // public-key re-derivation check added in Tasks 1 and 2.
    // A positive control (unmodified entry) opens Ok in each test.
    // ─────────────────────────────────────────────────────────────────────────

    /// REM-03 / T-38-06: substituting the classic `encrypted_secret_key` (and its
    /// `salt` + `is_password_protected`) with material from a different classic
    /// entry (same password) must be rejected with "public key mismatch (classic
    /// slot)".  An unmodified entry still opens Ok (positive control).
    #[test]
    fn classic_ciphertext_substitution_rejected() -> Result<()> {
        let (keystore, _tmp) = create_temp_keystore_interactive()?;
        let pw = "test-substitution-pw";

        // Positive control: generate entry A and verify it opens normally.
        let kp_a = ClassicKeyPair::generate()?;
        let id_a = keystore
            .store_keypair(&KeyPair::Classic(kp_a.clone()), Some(pw))
            .expect("store A");
        let loaded_ok = keystore.load_keypair(&id_a, Some(pw), true);
        assert!(
            loaded_ok.is_ok(),
            "positive control must open Ok before substitution"
        );

        // Generate entry B with the same password (so its ciphertext decrypts
        // under the same KEK derivation that A would use).
        let kp_b = ClassicKeyPair::generate()?;
        let id_b = keystore
            .store_keypair(&KeyPair::Classic(kp_b), Some(pw))
            .expect("store B");

        // Read both TOML files from disk.
        let path_a = keystore.keys_dir.join(format!("{id_a}.toml"));
        let path_b = keystore.keys_dir.join(format!("{id_b}.toml"));
        let content_a = std::fs::read_to_string(&path_a)?;
        let content_b = std::fs::read_to_string(&path_b)?;
        let mut stored_a: StoredKeyPair = toml::from_str(&content_a)?;
        let stored_b: StoredKeyPair = toml::from_str(&content_b)?;

        // Substitute: overwrite A's ciphertext fields with B's.
        stored_a.encrypted_secret_key = stored_b.encrypted_secret_key.clone();
        stored_a.salt = stored_b.salt.clone();
        stored_a.is_password_protected = stored_b.is_password_protected;

        // Write tampered A back to disk.
        let tampered = toml::to_string_pretty(&stored_a)?;
        std::fs::write(&path_a, tampered)?;

        // Attempt to open: AEAD decryption succeeds (same password / KEK),
        // but re-derivation must catch the mismatch and return Err.
        let result = keystore.load_keypair(&id_a, Some(pw), true);
        assert!(
            result.is_err(),
            "substituted classic ciphertext must be rejected"
        );
        let err = result.expect_err("checked is_err above");
        assert!(
            err.to_string().contains("classic slot"),
            "error must name the classic slot, got: {err}"
        );
        assert!(
            err.to_string().contains("mismatch") || err.to_string().contains("corrupt"),
            "error must indicate mismatch/corruption, got: {err}"
        );

        Ok(())
    }

    /// REM-03 / T-38-08: substituting one entry's `sig_ed448_encrypted_secret_key`
    /// with the corresponding field from a different passwordless dual-suite entry
    /// must be rejected with "public key mismatch (Ed448 slot)".
    ///
    /// Passwordless entries store sig keys as plain base64 (no AEAD), so the
    /// substituted bytes decode cleanly; detection relies entirely on the
    /// post-decrypt re-derivation check.  An unmodified entry opens Ok
    /// (positive control).
    // Why: HybridKeyPair contains Ed448SigningKey which doesn't impl Debug, so
    // expect_err() (which requires T: Debug) cannot be used here. The is_err()
    // assertion on the preceding line makes the .err().expect() infallible.
    #[allow(clippy::err_expect)]
    #[cfg(feature = "hybrid")]
    #[test]
    fn sig_ciphertext_substitution_rejected() -> Result<()> {
        use crate::crypto::hybrid::HybridKeyPair;

        let (keystore, _tmp) = create_temp_keystore_interactive()?;

        // Create two passwordless dual-suite entries (sig keys stored as plain
        // base64 — no AEAD wrapping, so swapping them is a pure re-derivation
        // failure rather than an AEAD failure).
        let classic_a = ClassicKeyPair::generate()?;
        let hybrid_a = HybridKeyPair::generate()?;
        let id_a = keystore
            .store_dual_keypair(Some(&classic_a), Some(&hybrid_a), None)
            .expect("store dual A passwordless");

        let classic_b = ClassicKeyPair::generate()?;
        let hybrid_b = HybridKeyPair::generate()?;
        let id_b = keystore
            .store_dual_keypair(Some(&classic_b), Some(&hybrid_b), None)
            .expect("store dual B passwordless");

        // Positive control: set current to A and verify it opens normally.
        keystore
            .set_current_key(&id_a)
            .expect("set current to A for positive control");
        let ok_before = keystore.load_sig_keypair("alice", None);
        assert!(
            ok_before.is_ok(),
            "positive control — entry A must load before substitution; err={:?}",
            ok_before.err()
        );

        // Read both TOML files.
        let path_a = keystore.keys_dir.join(format!("{id_a}.toml"));
        let path_b = keystore.keys_dir.join(format!("{id_b}.toml"));
        let content_a = std::fs::read_to_string(&path_a)?;
        let content_b = std::fs::read_to_string(&path_b)?;

        let mut stored_a: StoredKeyPair = toml::from_str(&content_a)?;
        let stored_b: StoredKeyPair = toml::from_str(&content_b)?;

        // Substitute B's Ed448 sig key (plain base64) into A's entry.
        // A's sig_ed448_public_key remains A's; the recovered secret from B
        // will re-derive B's verifying key, causing the mismatch.
        stored_a.sig_ed448_encrypted_secret_key = stored_b.sig_ed448_encrypted_secret_key.clone();

        let tampered = toml::to_string_pretty(&stored_a)?;
        std::fs::write(&path_a, tampered)?;

        // Entry A is already "current"; load_sig_keypair must now reject it.
        let result = keystore.load_sig_keypair("alice", None);
        assert!(
            result.is_err(),
            "substituted Ed448 sig key must be rejected"
        );
        let err = result.err().expect("checked is_err above");
        assert!(
            err.to_string().contains("Ed448 slot"),
            "error must name the Ed448 slot, got: {err}"
        );
        assert!(
            err.to_string().contains("mismatch") || err.to_string().contains("corrupt"),
            "error must indicate mismatch/corruption, got: {err}"
        );

        let _ = id_b; // suppress unused warning
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 38-04 — CR-01 / CR-02 regression tests
    //
    // CR-01: format_version=2 entries (signed with v1 context, 6-field payload)
    //        must remain loadable under the v1 verification path and must be
    //        upgradeable to format_version=3.
    //
    // CR-02: changing the passphrase or removing it from a format_version=3
    //        entry must re-sign the entry so it loads successfully afterwards
    //        (without --allow-unsigned).
    // ─────────────────────────────────────────────────────────────────────────

    /// CR-01 regression: a synthetic `format_version=2` entry (signed with v1 context
    /// and the 6-field payload) must load successfully via `load_keypair` without
    /// triggering the D-20 rejection error.
    ///
    /// After loading, `upgrade_keypair_in_place` must promote it to `format_version=3`
    /// and the upgraded entry must load under the v2 verification path.
    // Why: end-to-end regression for v2→v3 upgrade path; requires synthetic v2 entry
    // construction, load, upgrade, and re-verify — splitting would break the shared
    // keypair state.
    #[allow(clippy::too_many_lines)]
    #[test]
    #[cfg(feature = "hybrid")]
    fn cr01_format_version_2_loads_and_upgrades() -> Result<()> {
        use crate::keystore::sig::{
            build_signed_payload_v1, KeystoreEntrySig,
            KEYSTORE_SIG_CONTEXT_V1,
        };
        use base64::prelude::BASE64_STANDARD;
        use trelis_primitives::{
            Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme,
        };

        let (keystore, _tmp) = create_temp_keystore_interactive()?;

        // Build a realistic format_version=2 entry. Sign it with the v1 context
        // (b"sss-keystore-entry-sig-v1") and the 6-field payload — exactly how
        // Phase 18 binaries signed entries before REM-04.
        let classic_kp = crate::crypto::ClassicKeyPair::generate()?;
        let ed448_sk = Ed448Standard::generate()
            .map_err(|e| anyhow!("Ed448 keygen: {e}"))?;
        let ed448_pk = Ed448Standard::verifying_key(&ed448_sk);
        let ed448_pk_b64 = BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(&ed448_pk));
        let mldsa_sk = MlDsa65Fips204::generate()
            .map_err(|e| anyhow!("ML-DSA keygen: {e}"))?;
        let mldsa_pk = MlDsa65Fips204::verifying_key(&mldsa_sk);
        let mldsa_pk_b64 = BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(&mldsa_pk));

        let uuid = uuid::Uuid::new_v4().to_string();
        // ClassicKeyPair has pub fields (not methods); access directly.
        let public_key_b64 = classic_kp.public_key.to_base64();
        // Use a plain base64 secret key (passwordless entry) so we avoid KDF overhead.
        let secret_key_b64 = classic_kp.secret_key.to_base64();
        let created_at = chrono::Utc::now();
        let created_at_rfc3339 = created_at.to_rfc3339();

        // 6-field payload (v1 schema — no kdf_ops, no kdf_mem).
        let payload_v1 = build_signed_payload_v1(
            &uuid,
            &public_key_b64,
            None, // no hybrid in this synthetic entry
            Some(&ed448_pk_b64),
            Some(&mldsa_pk_b64),
            &created_at_rfc3339,
        );

        // Sign with v1 context (b"sss-keystore-entry-sig-v1") via the raw
        // trelis_primitives API — mirroring what Phase 18 sign_entry used before
        // REM-04 changed the context constant.
        let ed448_sig_bytes = Ed448Standard::sign_with_context(&ed448_sk, &payload_v1, KEYSTORE_SIG_CONTEXT_V1)
            .map_err(|e| anyhow!("Ed448 sign v1: {e}"))?;
        let mldsa_sig_bytes = MlDsa65Fips204::sign_with_context(&mldsa_sk, &payload_v1, KEYSTORE_SIG_CONTEXT_V1)
            .map_err(|e| anyhow!("ML-DSA sign v1: {e}"))?;
        let sig = KeystoreEntrySig {
            ed448: BASE64_STANDARD.encode(Ed448Standard::signature_to_bytes(&ed448_sig_bytes)),
            mldsa65: BASE64_STANDARD.encode(MlDsa65Fips204::signature_to_bytes(&mldsa_sig_bytes)),
        };

        // Construct and write the format_version=2 TOML file.
        let stored_v2 = StoredKeyPair {
            uuid: uuid.clone(),
            public_key: public_key_b64.clone(),
            encrypted_secret_key: secret_key_b64.clone(),
            salt: None,
            created_at,
            is_password_protected: false,
            in_keyring: false,
            hybrid_public_key: None,
            hybrid_encrypted_secret_key: None,
            format_version: 2, // the version under test
            signature: Some(sig),
            sig_ed448_public_key: Some(ed448_pk_b64.clone()),
            sig_ed448_encrypted_secret_key: Some(
                BASE64_STANDARD.encode(Ed448Standard::signing_key_to_bytes(&ed448_sk))
            ),
            sig_mldsa65_public_key: Some(mldsa_pk_b64.clone()),
            sig_mldsa65_encrypted_secret_key: Some(
                BASE64_STANDARD.encode(MlDsa65Fips204::signing_key_to_bytes(&mldsa_sk))
            ),
        };

        let toml_content = toml::to_string_pretty(&stored_v2)?;
        let key_file = keystore.keys_dir.join(format!("{uuid}.toml"));
        std::fs::write(&key_file, &toml_content)?;

        // Point the current-key pointer at this entry.
        let current_key_file = keystore.keys_dir.join("current_key");
        std::fs::write(&current_key_file, &uuid)?;

        // CR-01 assertion: load_keypair must succeed under format_version=2 verification.
        let loaded = keystore.load_keypair(&uuid, None, false);
        assert!(
            loaded.is_ok(),
            "CR-01: format_version=2 entry must load successfully; got: {:?}",
            loaded.err()
        );

        // CR-01 + WR-03 assertion: upgrade must succeed (verifies v2 sig before re-signing)
        // and result in a loadable format_version=3 entry.
        keystore.upgrade_keypair_in_place(&uuid, None)?;
        let upgraded_content = std::fs::read_to_string(&key_file)?;
        let upgraded: StoredKeyPair = toml::from_str(&upgraded_content)?;
        assert_eq!(
            upgraded.format_version, 3,
            "CR-01: upgrade_keypair_in_place must produce format_version=3"
        );

        let after_upgrade = keystore.load_keypair(&uuid, None, false);
        assert!(
            after_upgrade.is_ok(),
            "CR-01: upgraded format_version=3 entry must load successfully; got: {:?}",
            after_upgrade.err()
        );

        // T-38-03 (a): sig keys must be UNCHANGED — v2→v3 upgrade must not rotate
        // sig keypairs; only the signed payload gains KDF params.
        assert_eq!(
            upgraded.sig_ed448_public_key.as_deref(),
            Some(ed448_pk_b64.as_str()),
            "CR-01/T-38-03: Ed448 sig pub key must be UNCHANGED after v2→v3 upgrade"
        );
        assert_eq!(
            upgraded.sig_mldsa65_public_key.as_deref(),
            Some(mldsa_pk_b64.as_str()),
            "CR-01/T-38-03: ML-DSA-65 sig pub key must be UNCHANGED after v2→v3 upgrade"
        );

        // T-38-03 (b): second upgrade call must return the no-op error — a v3 entry
        // is already at the latest format version and must not be re-upgraded.
        let second_upgrade = keystore.upgrade_keypair_in_place(&uuid, None);
        assert!(
            second_upgrade.is_err(),
            "CR-01/T-38-03: second upgrade on a v3 entry must return the no-op error"
        );
        let err_msg = second_upgrade.unwrap_err().to_string();
        assert!(
            err_msg.contains("already") && err_msg.contains("no-op"),
            "CR-01/T-38-03: no-op error must mention 'already' and 'no-op'; got: {err_msg}"
        );

        Ok(())
    }

    /// CR-02 regression: removing a passphrase from a `format_version=3` entry must
    /// produce an entry that loads under the strict (`allow_unsigned=false`) path.
    /// Before this fix, `remove_passphrase` did not re-sign, so the stored signature
    /// covered real KDF params (e.g. ops=3) while the verifier reconstructed 0/0
    /// — a guaranteed mismatch that permanently locked the key.
    #[test]
    #[cfg(feature = "hybrid")]
    fn cr02_remove_passphrase_entry_still_loads() -> Result<()> {
        use crate::crypto::hybrid::HybridKeyPair;

        let (keystore, _tmp) = create_temp_keystore_interactive()?;
        let classic_kp = crate::crypto::ClassicKeyPair::generate()?;
        let hybrid_kp = HybridKeyPair::generate()?;
        let pw = "test-passphrase-cr02";

        // store_dual_keypair writes a format_version=3 entry with a real signature.
        let key_id = keystore
            .store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), Some(pw))?;

        // Sanity: should load before passphrase removal.
        keystore.load_keypair(&key_id, Some(pw), false)
            .expect("CR-02: entry must load before remove_passphrase");

        // Remove passphrase — this MUST re-sign under the 0/0 sentinel.
        keystore.remove_passphrase(&key_id, pw)
            .expect("CR-02: remove_passphrase must succeed");

        // After removal, load without password under strict verification.
        // Without the CR-02 fix this fails with the D-20 signature error.
        let loaded = keystore.load_keypair(&key_id, None, false);
        assert!(
            loaded.is_ok(),
            "CR-02: entry must load after remove_passphrase without --allow-unsigned; got: {:?}",
            loaded.err()
        );

        Ok(())
    }

    /// CR-02 regression (`set_passphrase`): adding a passphrase to a passwordless
    /// `format_version=3` entry must produce an entry that loads under the strict path.
    /// The stored signature previously covered the 0/0 KDF sentinel; after
    /// `set_passphrase` it must cover the real KDF params.
    #[test]
    #[cfg(feature = "hybrid")]
    fn cr02_set_passphrase_entry_still_loads() -> Result<()> {
        use crate::crypto::hybrid::HybridKeyPair;

        let (keystore, _tmp) = create_temp_keystore_interactive()?;
        let classic_kp = crate::crypto::ClassicKeyPair::generate()?;
        let hybrid_kp = HybridKeyPair::generate()?;

        // Start passwordless so format_version=3 signature covers 0/0 sentinel.
        let key_id = keystore
            .store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), None)?;

        keystore.load_keypair(&key_id, None, false)
            .expect("CR-02: passwordless entry must load before set_passphrase");

        let new_pw = "new-passphrase-cr02";
        keystore.set_passphrase(&key_id, None, new_pw)
            .expect("CR-02: set_passphrase must succeed");

        // After adding passphrase, load with password under strict verification.
        let loaded = keystore.load_keypair(&key_id, Some(new_pw), false);
        assert!(
            loaded.is_ok(),
            "CR-02: entry must load after set_passphrase without --allow-unsigned; got: {:?}",
            loaded.err()
        );

        Ok(())
    }
}
