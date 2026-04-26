#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
use anyhow::{anyhow, Result};
use chrono::Utc;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::crypto::{ClassicSuite, CryptoSuite, PublicKey, RepositoryKey, Suite};
use crate::{error_helpers, toml_helpers};

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

    /// Custom secrets filename (defaults to "secrets" if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_filename: Option<String>,

    /// Custom secrets file suffix (defaults to ".secrets" if not set)
    /// Example: ".sealed" would make "config.yaml.sealed" a valid secrets file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_suffix: Option<String>,

    /// Gitignore-style patterns for files to ignore in project-wide operations
    /// Multiple patterns separated by spaces or commas
    /// Example: "*.log build/ temp*.txt"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore: Option<String>,

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

/// Resolve a `.sss.toml` `version` string to a `Suite`, with an
/// actionable error for versions this binary does not support.
///
/// v2.0 gets special handling (this binary is v1; hybrid isn't wired
/// until Phase 2) — we surface the upgrade prompt directly here so
/// every load path emits the same single-line message (SUITE-04).
/// Phase 2 will collapse this into `Suite::from_version` directly
/// once `HybridSuite` is implemented.
fn resolve_suite_from_version(version: &str) -> Result<Suite> {
    match version {
        "1.0" => Ok(Suite::Classic),
        "2.0" => Err(anyhow!(
            "this project requires sss v2.0 or newer (.sss.toml version = \"2.0\"); upgrade sss or run with a newer binary"
        )),
        other => Err(anyhow!(
            "unknown .sss.toml version {:?}: expected \"1.0\" or \"2.0\"",
            other
        )),
    }
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            created: default_created(),
            users: HashMap::new(),
            hooks: HooksConfig::default(),
            rotation: RotationMetadata::default(),
            secrets_filename: None,
            secrets_suffix: None,
            ignore: None,
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
    #[must_use] 
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
    #[must_use] 
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

        // Seal the repository key for this user via the CryptoSuite trait
        // (ClassicSuite is the only concrete suite in Phase 1; Phase 2 will
        // route this through `config.suite()?` once HybridSuite lands).
        let sealed_key = ClassicSuite.seal_repo_key(&repository_key, user_public_key)?;

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
            secrets_filename: None,
            secrets_suffix: None,
            ignore: None,
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

        let config: Self = toml_helpers::parse_toml(&content, "project")?;

        // Version gate — run BEFORE returning the parsed config so callers
        // never operate on a file they don't understand. Emits the SUITE-04
        // actionable error for `version = "2.0"` against this v1 binary.
        resolve_suite_from_version(&config.version)?;

        Ok(config)
    }

    /// Save project configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml_helpers::serialize_toml(self, "project config")?;

        fs::write(&path, content).map_err(|e| {
            anyhow!(
                "Failed to write project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })
    }

    /// Resolve the crypto `Suite` for this project from the `version` field.
    ///
    /// Maps `version = "1.0"` → `Suite::Classic`. Any other value —
    /// including `"2.0"` against this v1 binary, or future/malformed
    /// versions — produces an actionable error telling the user to
    /// upgrade `sss`.
    ///
    /// v1 binaries encountering `version = "2.0"` will see exactly:
    /// `this project requires sss v2.0 or newer (.sss.toml version = "2.0"); upgrade sss or run with a newer binary`
    pub fn suite(&self) -> Result<Suite> {
        resolve_suite_from_version(&self.version)
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
            return Err(anyhow!("User '{username}' already exists in project"));
        }

        // Seal the repository key for this new user via the CryptoSuite trait.
        let sealed_key = ClassicSuite.seal_repo_key(repository_key, user_public_key)?;

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
            .ok_or_else(|| error_helpers::user_not_found_error(username))?;

        Ok(user_config.sealed_key.clone())
    }

    /// Remove a user from the project
    pub fn remove_user(&mut self, username: &str) -> Result<()> {
        if !self.users.contains_key(username) {
            return Err(anyhow!("User '{username}' not found in project"));
        }

        self.users.remove(username);
        Ok(())
    }

    /// Get the public key for a user
    pub fn get_user_public_key(&self, username: &str) -> Result<PublicKey> {
        let user_config = self
            .users
            .get(username)
            .ok_or_else(|| error_helpers::user_not_found_error(username))?;

        // Phase 2 Plan 02-02: decode via the repo's declared suite so a v2
        // config with hybrid-length `public` bytes lands as `PublicKey::Hybrid`
        // (only reachable with the `hybrid` feature compiled in).
        PublicKey::decode_base64_for_suite(&user_config.public, self.suite()?)
    }

    /// List all users in the project
    #[must_use] 
    pub fn list_users(&self) -> Vec<String> {
        let mut users: Vec<String> = self.users.keys().cloned().collect();
        users.sort();
        users
    }

    /// Find username by matching public key
    #[must_use] 
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
    #[must_use] 
    pub fn is_legacy_format(&self) -> bool {
        self.key.is_some()
    }

    /// Get the legacy key (for migration)
    #[must_use] 
    pub fn legacy_key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// Remove the legacy key (after migration)
    pub fn remove_legacy_key(&mut self) {
        self.key = None;
    }

    /// Check if the project has any users
    #[must_use] 
    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// Get all public keys in the project.
    ///
    /// Phase 2 Plan 02-02: decodes via `self.suite()?` so v2 configs produce
    /// `PublicKey::Hybrid` variants (feature-gated). Decoding once per call
    /// caches the suite lookup so a malformed `version` field is reported
    /// exactly once at the top of the iteration.
    pub fn get_all_public_keys(&self) -> Result<Vec<(String, PublicKey)>> {
        let suite = self.suite()?;
        let mut keys = Vec::new();

        for (username, user_config) in &self.users {
            let public_key = PublicKey::decode_base64_for_suite(&user_config.public, suite)?;
            keys.push((username.clone(), public_key));
        }

        Ok(keys)
    }

    /// Get ignore patterns as a vector of strings
    ///
    /// Returns the individual patterns from the ignore field as a vector,
    /// split by whitespace or commas. Useful for display and editing.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log build/ !important.log".to_string());
    /// let patterns = config.get_ignore_pattern_strings();
    /// assert_eq!(patterns, vec!["*.log", "build/", "!important.log"]);
    /// ```
    #[must_use] 
    pub fn get_ignore_pattern_strings(&self) -> Vec<String> {
        match &self.ignore {
            Some(s) => s
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .map(std::string::ToString::to_string)
                .collect(),
            None => vec![],
        }
    }

    /// Set ignore patterns from a vector of pattern strings
    ///
    /// Joins the patterns with spaces into a single string for storage.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// let mut config = ProjectConfig::default();
    /// config.set_ignore_patterns(vec!["*.log".to_string(), "build/".to_string()]);
    /// assert_eq!(config.ignore, Some("*.log build/".to_string()));
    /// ```
    #[allow(clippy::needless_pass_by_value)] // Vec ownership consumed for API simplicity with many callers
    pub fn set_ignore_patterns(&mut self, patterns: Vec<String>) {
        if patterns.is_empty() {
            self.ignore = None;
        } else {
            self.ignore = Some(patterns.join(" "));
        }
    }

    /// Parse ignore patterns from the config and build a `GlobSet`
    ///
    /// Supports gitignore-style patterns:
    /// - Simple patterns: `*.log`, `build/`, `temp*.txt`
    /// - Negation with `!`: `*.db !important.db` (matches all .db files except important.db)
    /// - Space or comma separated: `*.log build/ *.tmp`
    ///
    /// # Returns
    ///
    /// Returns (`GlobSet`, `GlobSet`) where:
    /// - First `GlobSet` contains positive patterns to match files to ignore
    /// - Second `GlobSet` contains negation patterns that override ignores (files matching these should NOT be ignored)
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log build/ !important.log".to_string());
    /// let (ignore_set, negations) = config.parse_ignore_patterns().unwrap();
    /// ```
    pub fn parse_ignore_patterns(&self) -> Result<(GlobSet, GlobSet)> {
        let Some(ignore_str) = &self.ignore else {
            return Ok((GlobSet::empty(), GlobSet::empty()));
        };

        let mut positive_builder = GlobSetBuilder::new();
        let mut negative_builder = GlobSetBuilder::new();

        // Split by whitespace or commas
        let patterns: Vec<&str> = ignore_str
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .collect();

        for pattern in patterns {
            if let Some(neg_pattern) = pattern.strip_prefix('!') {
                // Negation pattern - files matching this should NOT be ignored
                if !neg_pattern.is_empty() {
                    // Transform directory patterns: "dir/" -> "dir/**"
                    let glob_pattern = if neg_pattern.ends_with('/') {
                        format!("{neg_pattern}**")
                    } else {
                        neg_pattern.to_string()
                    };

                    let glob = Glob::new(&glob_pattern).map_err(|e| {
                        anyhow!("Invalid negation ignore pattern '{neg_pattern}': {e}")
                    })?;
                    negative_builder.add(glob);
                }
            } else {
                // Positive pattern - files matching this should be ignored
                // Transform directory patterns: "dir/" -> "dir/**"
                let glob_pattern = if pattern.ends_with('/') {
                    format!("{pattern}**")
                } else {
                    pattern.to_string()
                };

                let glob =
                    Glob::new(&glob_pattern).map_err(|e| anyhow!("Invalid ignore pattern '{pattern}': {e}"))?;
                positive_builder.add(glob);
            }
        }

        let positive_set = positive_builder
            .build()
            .map_err(|e| anyhow!("Failed to build ignore GlobSet: {e}"))?;
        let negative_set = negative_builder
            .build()
            .map_err(|e| anyhow!("Failed to build negation GlobSet: {e}"))?;

        Ok((positive_set, negative_set))
    }

    /// Check if a file path should be ignored based on the ignore patterns
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to check (can be relative or absolute)
    ///
    /// # Returns
    ///
    /// Returns `true` if the file should be ignored, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// # use std::path::Path;
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log !important.log".to_string());
    ///
    /// assert!(config.should_ignore(Path::new("debug.log")).unwrap());
    /// assert!(!config.should_ignore(Path::new("important.log")).unwrap());
    /// assert!(!config.should_ignore(Path::new("data.txt")).unwrap());
    /// ```
    pub fn should_ignore(&self, path: &Path) -> Result<bool> {
        let (positive_set, negative_set) = self.parse_ignore_patterns()?;

        // If no patterns, don't ignore
        if positive_set.is_empty() {
            return Ok(false);
        }

        // Check if path matches any ignore pattern (try both full path and filename)
        let matches_ignore = positive_set.is_match(path)
            || path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| positive_set.is_match(name));

        // If doesn't match ignore patterns, don't ignore
        if !matches_ignore {
            return Ok(false);
        }

        // Check if path matches any negation pattern (should NOT be ignored)
        if !negative_set.is_empty() {
            let matches_negation = negative_set.is_match(path)
                || path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| negative_set.is_match(name));

            if matches_negation {
                return Ok(false); // Negation overrides ignore
            }
        }

        // Matches ignore and doesn't match negation
        Ok(true)
    }

    /// Validate the project configuration
    pub fn validate(&self) -> Result<()> {
        let suite = self.suite()?;
        // Validate all user configurations
        for (username, user_config) in &self.users {
            // Validate sealed key is valid base64
            use base64::Engine;
            base64::prelude::BASE64_STANDARD
                .decode(&user_config.sealed_key)
                .map_err(|e| anyhow!("Invalid base64 sealed key for user '{username}': {e}"))?;

            // Validate public key — route through suite-aware decode so hybrid-
            // length public keys (1214 bytes encoded) are not rejected by the
            // classic-only 32-byte check.
            PublicKey::decode_base64_for_suite(&user_config.public, suite)
                .map_err(|e| anyhow!("Invalid public key for user '{username}': {e}"))?;
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
    #[must_use] 
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

    /// Get the secrets filename (defaults to "secrets" if not configured)
    #[must_use] 
    pub fn get_secrets_filename(&self) -> &str {
        self.secrets_filename.as_deref().unwrap_or("secrets")
    }

    /// Set the secrets filename
    pub fn set_secrets_filename(&mut self, filename: String) {
        self.secrets_filename = Some(filename);
    }

    /// Clear the secrets filename (use default)
    pub fn clear_secrets_filename(&mut self) {
        self.secrets_filename = None;
    }

    /// Get the ignore patterns as a single string
    #[must_use] 
    pub fn get_ignore_patterns(&self) -> Option<&str> {
        self.ignore.as_deref()
    }

    /// Clear the ignore patterns
    pub fn clear_ignore_patterns(&mut self) {
        self.ignore = None;
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
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

        assert_eq!(config.users.len(), 1);
        assert!(config.users.contains_key("alice"));
        assert!(!config.is_legacy_format());
    }

    #[test]
    fn test_add_remove_users() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();

        // We need a repository key to add users - let's get it from the sealed key for alice
        // For testing, we'll create a dummy repository key
        let repository_key = RepositoryKey::new();

        // Add second user
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();
        assert_eq!(config.users.len(), 2);
        assert!(config.users.contains_key("bob"));

        // Cannot add duplicate user
        let result = config.add_user("alice", &keypair1.public_key(), &repository_key);
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
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

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
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

        // Valid config should pass
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_format() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();

        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
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

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();

        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();

        let keys = config.get_all_public_keys().unwrap();
        assert_eq!(keys.len(), 2);

        let usernames: Vec<&str> = keys.iter().map(|(name, _)| name.as_str()).collect();
        assert!(usernames.contains(&"alice"));
        assert!(usernames.contains(&"bob"));
    }

    // --- SUITE-02 / SUITE-04: .sss.toml version gate ---

    #[test]
    fn test_load_from_file_rejects_v2_with_actionable_error() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "2.0"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let err = ProjectConfig::load_from_file(tmp.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("this project requires sss v2.0 or newer"),
            "expected SUITE-04 actionable message, got: {err}"
        );
        assert!(
            err.contains("2.0"),
            "error must quote the offending version: {err}"
        );
        assert!(
            err.contains("upgrade sss"),
            "error must tell user to upgrade: {err}"
        );
    }

    #[test]
    fn test_load_from_file_accepts_v1() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "1.0"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        assert!(ProjectConfig::load_from_file(tmp.path()).is_ok());
    }

    #[test]
    fn test_load_from_file_defaults_missing_version_to_v1() {
        // No `version` field → serde default → "1.0" → loads successfully.
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let cfg = ProjectConfig::load_from_file(tmp.path()).unwrap();
        assert_eq!(cfg.version, "1.0");
    }

    #[test]
    fn test_load_from_file_rejects_unknown_version() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "99.99"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let err = ProjectConfig::load_from_file(tmp.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown .sss.toml version"), "got: {err}");
        assert!(err.contains("99.99"), "got: {err}");
    }

    #[test]
    fn test_load_from_file_single_line_error_for_v2() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), r#"version = "2.0""#).unwrap();
        let err = ProjectConfig::load_from_file(tmp.path())
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains('\n'),
            "SUITE-04 requires a single-line error; got multiline: {err:?}"
        );
    }

    #[test]
    fn test_project_config_suite_returns_classic_for_v1() {
        let mut cfg = ProjectConfig::default();
        cfg.version = "1.0".to_string();
        assert_eq!(cfg.suite().unwrap(), Suite::Classic);
    }

    #[test]
    fn test_project_config_suite_returns_error_for_v2() {
        let mut cfg = ProjectConfig::default();
        cfg.version = "2.0".to_string();
        let err = cfg.suite().unwrap_err().to_string();
        assert!(err.contains("this project requires sss v2.0 or newer"));
    }

    #[test]
    fn test_project_config_suite_returns_error_for_unknown() {
        let mut cfg = ProjectConfig::default();
        cfg.version = "3.14".to_string();
        let err = cfg.suite().unwrap_err().to_string();
        assert!(err.contains("unknown .sss.toml version"));
    }

    // --- SUITE-01 Plan 01-04: ClassicSuite round-trip via production path ---

    #[test]
    fn test_project_new_seals_via_classic_suite_round_trip() {
        // ProjectConfig::new now seals via ClassicSuite (the CryptoSuite trait);
        // this test proves the trait-based open path reads what the trait-based
        // seal path writes, on the wire-format stored in .sss.toml.
        use crate::crypto::CryptoSuite;
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();
        let sealed = config.get_sealed_key_for_user("alice").unwrap();

        let suite = ClassicSuite;
        let opened = suite.open_repo_key(&sealed, &keypair).unwrap();
        // Round-trip check: re-seal with the same key, must be openable.
        let resealed = suite.seal_repo_key(&opened, &keypair.public_key()).unwrap();
        let reopened = suite.open_repo_key(&resealed, &keypair).unwrap();
        assert_eq!(opened.to_base64(), reopened.to_base64());
    }

    // --- Phase 2 Plan 02-02: suite-aware public-key decode path ---

    #[test]
    fn test_get_user_public_key_decodes_via_suite_to_classic_variant_for_v1_config() {
        use crate::crypto::PublicKey;
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();
        // Default ProjectConfig::new stamps version = "1.0" so the decoder
        // routes through Suite::Classic and yields PublicKey::Classic(..)
        let pk = config.get_user_public_key("alice").unwrap();
        match pk {
            PublicKey::Classic(_) => (),
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(_) => {
                panic!("v1.0 config must decode to PublicKey::Classic");
            }
        }
    }

    #[test]
    fn test_get_all_public_keys_routes_through_suite() {
        use crate::crypto::PublicKey;
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();
        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();

        let keys = config.get_all_public_keys().unwrap();
        assert_eq!(keys.len(), 2);
        for (_, pk) in keys {
            match pk {
                PublicKey::Classic(_) => (),
                #[cfg(feature = "hybrid")]
                PublicKey::Hybrid(_) => {
                    panic!("v1.0 config must decode every public key to PublicKey::Classic");
                }
            }
        }
    }

    // --- Plan 04-01: hybrid_public field + v2 suite gate ---

    #[test]
    fn test_load_from_file_accepts_v2() {
        // After Plan 04-01 gate change, version = "2.0" must load as Ok.
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "2.0"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let cfg = ProjectConfig::load_from_file(tmp.path())
            .expect("v2.0 file must load without error after gate change");
        assert_eq!(
            cfg.suite().unwrap(),
            Suite::Hybrid,
            "v2.0 must resolve to Suite::Hybrid"
        );
    }

    #[test]
    fn test_project_config_suite_returns_hybrid_for_v2() {
        let mut cfg = ProjectConfig::default();
        cfg.version = "2.0".to_string();
        assert_eq!(
            cfg.suite().unwrap(),
            Suite::Hybrid,
            "suite() must return Suite::Hybrid for version = \"2.0\""
        );
    }

    #[test]
    fn test_userconfig_hybrid_public_roundtrips() {
        // A v1-format file (no hybrid_public) deserialises with hybrid_public = None.
        let tmp_none = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp_none.path(),
            r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let cfg_none = ProjectConfig::load_from_file(tmp_none.path()).unwrap();
        let alice_none = cfg_none.users.get("alice").unwrap();
        #[cfg(feature = "hybrid")]
        assert!(
            alice_none.hybrid_public.is_none(),
            "hybrid_public must be None when absent in TOML"
        );
        // On non-hybrid builds the field is serde(skip) so it won't appear;
        // we just check the user loaded correctly.
        let _ = alice_none;

        // A file with hybrid_public = "abc123" deserialises correctly.
        let tmp_some = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp_some.path(),
            r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
hybrid_public = "abc123"
"#,
        )
        .unwrap();
        let cfg_some = ProjectConfig::load_from_file(tmp_some.path()).unwrap();
        let alice_some = cfg_some.users.get("alice").unwrap();
        #[cfg(feature = "hybrid")]
        assert_eq!(
            alice_some.hybrid_public.as_deref(),
            Some("abc123"),
            "hybrid_public must round-trip correctly"
        );
        let _ = alice_some;
    }
}
