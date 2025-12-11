use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{decrypt_from_base64, RepositoryKey};

/// Regex for parsing secrets file format - single-line values
/// Supports: name: value, "name": value, name: "value", "name": "value"
/// Also supports: name: 'value', 'name': 'value'
static SECRETS_LINE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*(?:"([^"]*)"|'([^']*)'|(.*))\s*$"#)
        .expect("Failed to compile secrets line regex")
});

/// Regex for parsing YAML-style multi-line value indicator
/// Matches: key: | or "key": | or 'key': |
static MULTILINE_INDICATOR_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^\s*(?:"([^"]+)"|'([^']+)'|([^:\s][^:]*?))\s*:\s*\|\s*$"#)
        .expect("Failed to compile multiline indicator regex")
});

/// SecretsCache manages loading and caching of secrets from files
pub struct SecretsCache {
    cache: HashMap<PathBuf, HashMap<String, String>>,
    repository_key: Option<RepositoryKey>,
    secrets_filename: String,
    secrets_suffix: String,
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
            secrets_filename: "secrets".to_string(),
            secrets_suffix: ".secrets".to_string(),
        }
    }

    /// Create a new SecretsCache with a repository key for unsealing encrypted secrets files
    pub fn with_repository_key(repository_key: RepositoryKey) -> Self {
        Self {
            cache: HashMap::new(),
            repository_key: Some(repository_key),
            secrets_filename: "secrets".to_string(),
            secrets_suffix: ".secrets".to_string(),
        }
    }

    /// Create a new SecretsCache with a repository key and custom secrets filename
    pub fn with_repository_key_and_filename(repository_key: RepositoryKey, secrets_filename: String) -> Self {
        Self {
            cache: HashMap::new(),
            repository_key: Some(repository_key),
            secrets_filename,
            secrets_suffix: ".secrets".to_string(),
        }
    }

    /// Create a new SecretsCache with a repository key and custom secrets filename and suffix
    pub fn with_repository_key_and_config(
        repository_key: RepositoryKey,
        secrets_filename: String,
        secrets_suffix: String,
    ) -> Self {
        Self {
            cache: HashMap::new(),
            repository_key: Some(repository_key),
            secrets_filename,
            secrets_suffix,
        }
    }

    /// Set the secrets filename
    pub fn set_secrets_filename(&mut self, filename: String) {
        self.secrets_filename = filename;
    }

    /// Set the secrets file suffix
    pub fn set_secrets_suffix(&mut self, suffix: String) {
        self.secrets_suffix = suffix;
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
    /// Searches for: $filename{secrets_suffix}, {secrets_filename}, ../{secrets_filename}, up to git root
    pub fn find_secrets_file<P: AsRef<Path>>(
        &self,
        file_path: P,
        project_root: &Path,
    ) -> Result<PathBuf> {
        let file_path = file_path.as_ref();

        // Resolve file_path relative to project_root
        // If file_path is absolute, use it as-is. Otherwise, join with project_root.
        let resolved_file_path = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            project_root.join(file_path)
        };

        // Get the directory containing the file
        let file_dir = resolved_file_path
            .parent()
            .ok_or_else(|| anyhow!("Cannot determine parent directory"))?;

        // Strategy 1: Look for $filename{secrets_suffix} in the same directory
        // E.g., if file is "config.yaml" and suffix is ".sealed", look for "config.yaml.sealed"
        let filename_with_suffix = PathBuf::from(format!(
            "{}{}",
            resolved_file_path.display(),
            self.secrets_suffix
        ));
        if filename_with_suffix.exists() {
            return Ok(filename_with_suffix);
        }

        // Strategy 2: Search for configured secrets file upward to project root
        let mut current_dir = file_dir.to_path_buf();
        loop {
            let secrets_path = current_dir.join(&self.secrets_filename);
            if secrets_path.exists() {
                return Ok(secrets_path);
            }

            // Stop if we've reached the project root
            if current_dir == project_root {
                break;
            }

            // Move up one directory
            match current_dir.parent() {
                Some(parent) => {
                    current_dir = parent.to_path_buf();
                },
                None => break,
            }
        }

        Err(anyhow!(
            "No secrets file found for {}. Searched: {}{} and '{}' up to project root.",
            file_path.display(),
            file_path.display(),
            self.secrets_suffix,
            self.secrets_filename
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
/// Supports both single-line and YAML-style multi-line values:
/// - Single-line: name: value
/// - Multi-line:  name: |
///                  line1
///                  line2
pub fn parse_secrets_content(content: &str, path: &Path) -> Result<HashMap<String, String>> {
    let mut secrets = HashMap::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let line_num = i + 1;

        // Skip empty lines and comments (but only if not inside a multi-line value)
        if line.trim().is_empty() || line.trim().starts_with('#') {
            i += 1;
            continue;
        }

        // Check for multi-line indicator (key: |)
        if let Some(caps) = MULTILINE_INDICATOR_REGEX.captures(line) {
            // Extract key
            let key = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .map(|m| m.as_str().trim())
                .ok_or_else(|| {
                    anyhow!(
                        "Failed to parse key on line {} in {}: {}",
                        line_num,
                        path.display(),
                        line
                    )
                })?;

            // Collect multi-line value
            i += 1;
            let (value, lines_consumed) = collect_multiline_value(&lines[i..], line_num)?;
            secrets.insert(key.to_string(), value);
            i += lines_consumed;
            continue;
        }

        // Try to parse as single-line format
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
                        line_num,
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
            i += 1;
        } else {
            return Err(anyhow!(
                "Invalid secrets file format on line {} in {}: {}",
                line_num,
                path.display(),
                line
            ));
        }
    }

    Ok(secrets)
}

/// Collect a multi-line value (YAML-style with indentation)
/// Returns (value, number_of_lines_consumed)
fn collect_multiline_value(lines: &[&str], _start_line: usize) -> Result<(String, usize)> {
    if lines.is_empty() {
        // Empty multi-line value
        return Ok((String::new(), 0));
    }

    // Determine the base indentation from the first non-empty line
    let mut base_indent = None;
    let mut value_lines = Vec::new();
    let mut lines_consumed = 0;

    for line in lines {
        // Check if this line is part of the multi-line value
        // It should be indented or empty
        if line.trim().is_empty() {
            // Empty lines are included in multi-line values
            value_lines.push(String::new());
            lines_consumed += 1;
            continue;
        }

        // Calculate indentation
        let indent = line.len() - line.trim_start().len();

        // If we haven't set base indentation yet, use this line's indentation
        if base_indent.is_none() {
            if indent == 0 {
                // Non-indented line means end of multi-line value
                break;
            }
            base_indent = Some(indent);
        }

        // Check if line is still indented at least to base level
        if indent < base_indent.unwrap() {
            // Dedented line means end of multi-line value
            break;
        }

        // Add the line with relative indentation preserved
        let relative_indent = indent - base_indent.unwrap();
        let dedented = format!("{}{}", " ".repeat(relative_indent), line.trim_start());
        value_lines.push(dedented);
        lines_consumed += 1;
    }

    // Join lines with newlines
    let value = value_lines.join("\n");
    Ok((value, lines_consumed))
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

        // Test 1: file.secrets in same directory (suffix appended, not replacing extension)
        let file_secrets = PathBuf::from(format!("{}.secrets", test_file.display()));
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

    #[test]
    fn test_multiline_value_basic() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#"private_key: |
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA
  -----END RSA PRIVATE KEY-----
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(
            secrets.get("private_key").unwrap(),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        );
    }

    #[test]
    fn test_multiline_value_with_empty_lines() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#"certificate: |
  -----BEGIN CERTIFICATE-----
  line1

  line3
  -----END CERTIFICATE-----
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();
        let cert = secrets.get("certificate").unwrap();

        assert!(cert.contains("line1"));
        assert!(cert.contains("line3"));
        // Should preserve empty line between line1 and line3
        assert_eq!(cert.matches('\n').count(), 4); // 4 newlines total
    }

    #[test]
    fn test_multiline_value_with_nested_indentation() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#"json_config: |
  {
    "nested": {
      "key": "value"
    }
  }
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();
        let json = secrets.get("json_config").unwrap();

        // Should preserve relative indentation
        assert!(json.contains("  \"nested\": {"));
        assert!(json.contains("    \"key\": \"value\""));
    }

    #[test]
    fn test_mixed_single_and_multiline() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#"# Mixed format test
simple_key: simple_value
multiline_key: |
  line1
  line2
another_simple: another_value
another_multiline: |
  block1
  block2
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("simple_key").unwrap(), "simple_value");
        assert_eq!(secrets.get("multiline_key").unwrap(), "line1\nline2");
        assert_eq!(secrets.get("another_simple").unwrap(), "another_value");
        assert_eq!(secrets.get("another_multiline").unwrap(), "block1\nblock2");
    }

    #[test]
    fn test_multiline_empty_value() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#"empty_multiline: |
next_key: value
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("empty_multiline").unwrap(), "");
        assert_eq!(secrets.get("next_key").unwrap(), "value");
    }

    #[test]
    fn test_multiline_quoted_key() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#""my key": |
  value1
  value2
'single quoted': |
  value3
  value4
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("my key").unwrap(), "value1\nvalue2");
        assert_eq!(secrets.get("single quoted").unwrap(), "value3\nvalue4");
    }

    #[test]
    fn test_multiline_ssh_key_realistic() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        // Realistic SSH private key format
        let content = r#"ssh_private_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
  QyNTUxOQAAACDqZ3qJVZHqHQKBqQxFqH+jHqQxFqH+jHqQxFqH+jHqQxFqAAAAAJgM8uE
  -----END OPENSSH PRIVATE KEY-----

api_key: simple_api_key_value
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        let ssh_key = secrets.get("ssh_private_key").unwrap();
        assert!(ssh_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // Note: YAML | indicator preserves trailing newlines, so we check with trim_end()
        assert!(ssh_key.trim_end().ends_with("-----END OPENSSH PRIVATE KEY-----"));
        assert!(ssh_key.contains("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"));

        assert_eq!(secrets.get("api_key").unwrap(), "simple_api_key_value");
    }

    #[test]
    fn test_multiline_database_config() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        let content = r#"database_config: |
  host=localhost
  port=5432
  user=admin
  password=secret
  dbname=myapp
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();
        let config = secrets.get("database_config").unwrap();

        assert!(config.contains("host=localhost"));
        assert!(config.contains("port=5432"));
        assert!(config.contains("password=secret"));
    }

    #[test]
    fn test_multiline_preserves_trailing_spaces() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        // Note: trailing spaces after "value  " should be preserved
        let content = "trailing: |\n  value  \n  next\n";

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();
        let value = secrets.get("trailing").unwrap();

        // The value should preserve "value  " with trailing spaces
        let lines: Vec<&str> = value.split('\n').collect();
        assert_eq!(lines[0], "value  ");
        assert_eq!(lines[1], "next");
    }

    #[test]
    fn test_backward_compatibility_all_single_line() {
        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("secrets");

        // All existing single-line tests should still work
        let content = r#"# Comment
plain_key: plain value
quoted_key: "quoted value"
"key_with_quotes": value without quotes
url: https://example.com:8080
empty_value:
"#;

        let secrets = parse_secrets_content(content, &secrets_file).unwrap();

        assert_eq!(secrets.get("plain_key").unwrap(), "plain value");
        assert_eq!(secrets.get("quoted_key").unwrap(), "quoted value");
        assert_eq!(secrets.get("key_with_quotes").unwrap(), "value without quotes");
        assert_eq!(secrets.get("url").unwrap(), "https://example.com:8080");
        assert_eq!(secrets.get("empty_value").unwrap(), "");
    }
}
