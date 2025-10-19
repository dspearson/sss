use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{decrypt_from_base64, RepositoryKey};

/// Regex for parsing secrets file format
/// Supports: name: value, "name": value, name: "value", "name": "value"
/// Also supports: name: 'value', 'name': 'value'
static SECRETS_LINE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*(?:"([^"]*)"|'([^']*)'|(.*))\s*$"#)
        .expect("Failed to compile secrets line regex")
});

/// SecretsCache manages loading and caching of secrets from files
pub struct SecretsCache {
    cache: HashMap<PathBuf, HashMap<String, String>>,
    repository_key: Option<RepositoryKey>,
}

impl Default for SecretsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretsCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            repository_key: None,
        }
    }

    /// Create a new SecretsCache with a repository key for unsealing encrypted secrets files
    pub fn with_repository_key(repository_key: RepositoryKey) -> Self {
        Self {
            cache: HashMap::new(),
            repository_key: Some(repository_key),
        }
    }

    /// Load secrets from a file and cache them
    /// If the file is sealed (encrypted), it will be temporarily unsealed in memory
    fn load_secrets_file<P: AsRef<Path>>(&mut self, path: P) -> Result<&HashMap<String, String>> {
        let path = path.as_ref().to_path_buf();

        // Check if already cached
        if self.cache.contains_key(&path) {
            return Ok(self.cache.get(&path).unwrap());
        }

        // Load and parse the secrets file
        let secrets = self.parse_secrets_file_with_unseal(&path)?;
        self.cache.insert(path.clone(), secrets);
        Ok(self.cache.get(&path).unwrap())
    }

    /// Parse secrets file, automatically unsealing if encrypted
    fn parse_secrets_file_with_unseal<P: AsRef<Path>>(&self, path: P) -> Result<HashMap<String, String>> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read secrets file {}: {}", path.display(), e))?;

        // Check if content looks encrypted - starts with ⊠{
        let looks_encrypted = content.trim().starts_with("⊠{");

        if looks_encrypted {
            // Try to unseal it
            if let Some(ref key) = self.repository_key {
                match decrypt_secrets_content(content.trim(), key) {
                    Ok(decrypted) => {
                        // Parse the decrypted content
                        return parse_secrets_content(&decrypted, path);
                    }
                    Err(_) => {
                        // Decryption failed, try parsing as-is
                        return parse_secrets_content(&content, path);
                    }
                }
            } else {
                return Err(anyhow!(
                    "Secrets file {} appears to be encrypted but no repository key available for unsealing",
                    path.display()
                ));
            }
        }

        // Not encrypted, parse directly
        parse_secrets_content(&content, path)
    }

    /// Find secrets file using the lookup hierarchy
    /// Searches for: $filename.secrets, secrets, ../secrets, up to git root
    pub fn find_secrets_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        project_root: &Path,
    ) -> Result<PathBuf> {
        let file_path = file_path.as_ref();

        // Get the directory containing the file
        let file_dir = file_path
            .parent()
            .ok_or_else(|| anyhow!("Cannot determine parent directory"))?;

        // Strategy 1: Look for $filename.secrets in the same directory
        let filename_secrets = file_path.with_extension("secrets");
        if filename_secrets.exists() {
            return Ok(filename_secrets);
        }

        // Strategy 2: Search for "secrets" file upward to project root
        let mut current_dir = file_dir.to_path_buf();
        loop {
            let secrets_path = current_dir.join("secrets");
            if secrets_path.exists() {
                return Ok(secrets_path);
            }

            // Stop if we've reached the project root
            if current_dir == project_root {
                break;
            }

            // Move up one directory
            match current_dir.parent() {
                Some(parent) => current_dir = parent.to_path_buf(),
                None => break,
            }
        }

        Err(anyhow!(
            "No secrets file found for {}. Searched: {}.secrets and 'secrets' up to project root.",
            file_path.display(),
            file_path.display()
        ))
    }

    /// Lookup a secret value by name
    pub fn lookup_secret<P: AsRef<Path>>(
        &mut self,
        secret_name: &str,
        file_path: P,
        project_root: &Path,
    ) -> Result<String> {
        // Find the secrets file
        let secrets_file = self.find_secrets_file(file_path, project_root)?;

        // Load secrets from the file
        let secrets = self.load_secrets_file(&secrets_file)?;

        // Look up the secret
        secrets
            .get(secret_name)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "Secret '{}' not found in {}",
                    secret_name,
                    secrets_file.display()
                )
            })
    }
}

/// Decrypt secrets file content, handling encrypted marker
fn decrypt_secrets_content(content: &str, key: &RepositoryKey) -> Result<String> {
    let content = content.trim();

    // Check if content has the encrypted secrets marker
    if content.starts_with("⊠{") && content.ends_with('}') {
        // Extract the base64 content between the braces
        // Skip '⊠{' (4 bytes: 3 for ⊠, 1 for {) and remove trailing '}'
        let encrypted_content = &content[4..content.len() - 1];
        decrypt_from_base64(encrypted_content, key)
    } else {
        Err(anyhow!("Secrets file is not encrypted or has invalid format"))
    }
}

/// Parse secrets content string into a HashMap
/// Format: name: value (with optional quotes around name and/or value)
fn parse_secrets_content(content: &str, path: &Path) -> Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse the line
        if let Some(caps) = SECRETS_LINE_REGEX.captures(line) {
            // Extract key (from first matching group among groups 1, 2, 3)
            let key = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .map(|m| m.as_str().trim())
                .ok_or_else(|| {
                    anyhow!(
                        "Failed to parse key on line {} in {}: {}",
                        line_num + 1,
                        path.display(),
                        line
                    )
                })?;

            // Extract value (from first matching group among groups 4, 5, 6)
            let value = caps
                .get(4)
                .or_else(|| caps.get(5))
                .or_else(|| caps.get(6))
                .map(|m| m.as_str().trim())
                .unwrap_or("");

            secrets.insert(key.to_string(), value.to_string());
        } else {
            return Err(anyhow!(
                "Invalid secrets file format on line {} in {}: {}",
                line_num + 1,
                path.display(),
                line
            ));
        }
    }

    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_parse_secrets_file_basic() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        // Create secrets content with various formats
        let content = r#"# This is a comment
plain_key: plain value
quoted_key: "quoted value"
"key_with_quotes": value without quotes
"both_quoted": "both quoted"
single_key: 'single quoted'
'single_quoted_key': single value

trailing_spaces: value with trailing
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("plain_key").unwrap(), "plain value");
        assert_eq!(secrets.get("quoted_key").unwrap(), "quoted value");
        assert_eq!(secrets.get("key_with_quotes").unwrap(), "value without quotes");
        assert_eq!(secrets.get("both_quoted").unwrap(), "both quoted");
        assert_eq!(secrets.get("single_key").unwrap(), "single quoted");
        assert_eq!(secrets.get("single_quoted_key").unwrap(), "single value");
        assert_eq!(secrets.get("trailing_spaces").unwrap(), "value with trailing");
    }

    #[test]
    fn test_parse_secrets_file_empty_value() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = "empty_value:\nempty_quoted: \"\"\n";
        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("empty_value").unwrap(), "");
        assert_eq!(secrets.get("empty_quoted").unwrap(), "");
    }

    #[test]
    fn test_parse_secrets_file_with_colons_in_value() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = "url: https://example.com:8080\ntime: 12:34:56\n";
        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("url").unwrap(), "https://example.com:8080");
        assert_eq!(secrets.get("time").unwrap(), "12:34:56");
    }

    #[test]
    fn test_secrets_cache_lookup() {
        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create secrets file
        let secrets_file = project_root.join("secrets");
        let mut file = fs::File::create(&secrets_file).unwrap();
        writeln!(file, "api_key: secret123").unwrap();
        writeln!(file, "password: pass456").unwrap();
        drop(file);

        // Create a test file
        let test_file = project_root.join("config.txt");
        fs::write(&test_file, "test").unwrap();

        let mut cache = SecretsCache::new();

        // Lookup secrets
        let api_key = cache
            .lookup_secret("api_key", &test_file, project_root)
            .unwrap();
        assert_eq!(api_key, "secret123");

        let password = cache
            .lookup_secret("password", &test_file, project_root)
            .unwrap();
        assert_eq!(password, "pass456");
    }

    #[test]
    fn test_find_secrets_file_hierarchy() {
        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create directory structure: project/subdir/
        let subdir = project_root.join("subdir");
        fs::create_dir(&subdir).unwrap();

        // Create a file in subdir
        let test_file = subdir.join("config.txt");
        fs::write(&test_file, "test").unwrap();

        // Test 1: file.secrets in same directory
        let file_secrets = test_file.with_extension("secrets");
        fs::write(&file_secrets, "key: value").unwrap();

        let cache = SecretsCache::new();
        let found = cache.find_secrets_file(&test_file, project_root).unwrap();
        assert_eq!(found, file_secrets);

        // Clean up for next test
        fs::remove_file(&file_secrets).unwrap();

        // Test 2: secrets file in same directory
        let subdir_secrets = subdir.join("secrets");
        fs::write(&subdir_secrets, "key: value").unwrap();

        let found = cache.find_secrets_file(&test_file, project_root).unwrap();
        assert_eq!(found, subdir_secrets);

        // Test 3: secrets file in parent directory (project root)
        let root_secrets = project_root.join("secrets");
        fs::write(&root_secrets, "key: value").unwrap();

        // With subdir secrets still present, should find that first
        let found = cache.find_secrets_file(&test_file, project_root).unwrap();
        assert_eq!(found, subdir_secrets);

        // Remove subdir secrets, should find root secrets
        fs::remove_file(&subdir_secrets).unwrap();
        let found = cache.find_secrets_file(&test_file, project_root).unwrap();
        assert_eq!(found, root_secrets);
    }

    #[test]
    fn test_secrets_cache_not_found() {
        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        let test_file = project_root.join("config.txt");
        fs::write(&test_file, "test").unwrap();

        let cache = SecretsCache::new();

        // Should fail when no secrets file exists
        let result = cache.find_secrets_file(&test_file, project_root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No secrets file found"));
    }

    #[test]
    fn test_parse_secrets_invalid_format() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let result = parse_secrets_content("this is not valid format", &secrets_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid secrets file format"));
    }

    #[test]
    fn test_sealed_secrets_file_unsealing() {
        use crate::crypto::RepositoryKey;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create a repository key
        let key = RepositoryKey::new();

        // Create plaintext secrets
        let plaintext_secrets = "api_key: my_secret\npassword: secure123\n";

        // Encrypt (seal) the secrets with marker
        let encrypted_secrets = crate::crypto::encrypt_to_base64(plaintext_secrets, &key).unwrap();
        let sealed_content = format!("⊠{{{}}}", encrypted_secrets);

        // Write the encrypted secrets to a file
        let secrets_file = project_root.join("secrets");
        std::fs::write(&secrets_file, &sealed_content).unwrap();

        // Create a secrets cache with the repository key
        let mut cache = SecretsCache::with_repository_key(key);

        // Try to load the sealed secrets file - should automatically unseal
        let secrets = cache.load_secrets_file(&secrets_file).unwrap();

        // Should have decrypted and parsed the secrets
        assert_eq!(secrets.get("api_key").unwrap(), "my_secret");
        assert_eq!(secrets.get("password").unwrap(), "secure123");
    }

    #[test]
    fn test_sealed_secrets_lookup() {
        use crate::crypto::RepositoryKey;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        let key = RepositoryKey::new();

        // Create and seal a secrets file - use "secrets" so it will be found
        let plaintext = "token: secret_token_123\n";
        let encrypted = crate::crypto::encrypt_to_base64(plaintext, &key).unwrap();
        let sealed_content = format!("⊠{{{}}}", encrypted);

        let secrets_file = project_root.join("secrets");
        std::fs::write(&secrets_file, &sealed_content).unwrap();

        // Create test file
        let test_file = project_root.join("config.txt");
        std::fs::write(&test_file, "test").unwrap();

        // Create cache with key
        let mut cache = SecretsCache::with_repository_key(key);

        // Lookup should work even though the file is sealed
        let token = cache.lookup_secret("token", &test_file, project_root).unwrap();
        assert_eq!(token, "secret_token_123");
    }
}
