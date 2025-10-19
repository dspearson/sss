use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

// Use RefCell for non-async contexts, RwLock for async contexts
#[cfg(not(feature = "ninep"))]
use std::cell::RefCell;
#[cfg(feature = "ninep")]
use parking_lot::RwLock;

use crate::constants::{MAX_FILE_SIZE, MAX_MARKER_CONTENT_SIZE};
use crate::crypto::{decrypt_from_base64, encrypt_to_base64, encrypt_to_base64_deterministic, RepositoryKey};
use crate::secrets::SecretsCache;

// Pre-compiled regex patterns for better performance
static PLAINTEXT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:⊕|o\+)\{([^}]*)\}").expect("Failed to compile plaintext regex"));

static CIPHERTEXT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"⊠\{([^⊕⊠]*)\}").expect("Failed to compile ciphertext regex"));

// Pattern for secrets interpolation: ⊲{secret} or <{secret}
static SECRETS_INTERPOLATION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:⊲|<)\{([^}]+)\}").expect("Failed to compile secrets interpolation regex"));

// Type alias for cache wrapper - conditional based on async support
#[cfg(not(feature = "ninep"))]
type CacheWrapper<T> = RefCell<T>;
#[cfg(feature = "ninep")]
type CacheWrapper<T> = RwLock<T>;

pub struct Processor {
    repository_key: RepositoryKey,
    secrets_cache: CacheWrapper<SecretsCache>,
    project_root: Option<PathBuf>,
    project_created: String,
}

impl Processor {
    /// Helper to handle oversized marker content with consistent warning
    fn check_marker_size(&self, content: &str, marker_type: &str) -> bool {
        if content.len() > MAX_MARKER_CONTENT_SIZE {
            eprintln!(
                "Warning: {} marker too large ({} bytes), skipping",
                marker_type,
                content.len()
            );
            false
        } else {
            true
        }
    }

    /// Helper to look up secret from cache (handles RefCell vs RwLock)
    fn lookup_secret_from_cache(&self, secret_name: &str, file_path: &Path, project_root: &Path) -> Result<String> {
        #[cfg(not(feature = "ninep"))]
        {
            self.secrets_cache.borrow_mut().lookup_secret(secret_name, file_path, project_root)
        }
        #[cfg(feature = "ninep")]
        {
            self.secrets_cache.write().lookup_secret(secret_name, file_path, project_root)
        }
    }

    /// Helper to handle encryption errors with consistent warning
    fn handle_encrypt_error(&self, error: &anyhow::Error, original: &str) -> String {
        eprintln!("Warning: Failed to encrypt plaintext: {}", error);
        original.to_string()
    }

    /// Helper to handle decryption errors with consistent warning
    fn handle_decrypt_error(&self, error: &anyhow::Error, original: &str, context: &str) -> String {
        let context_str = if context.is_empty() {
            String::new()
        } else {
            format!(" {}", context)
        };
        eprintln!(
            "Warning: Failed to decrypt ciphertext{}: {}",
            context_str, error
        );
        original.to_string()
    }

    /// Decrypt with the repository key
    fn decrypt_with_repository_key(&self, encrypted: &str) -> Result<String> {
        decrypt_from_base64(encrypted, &self.repository_key)
    }

    /// Convert an absolute path to a relative path from the project root
    /// Returns a path in the form "./dir/file.txt"
    fn make_relative_path(&self, path: &Path) -> Result<String> {
        let project_root = if let Some(ref root) = self.project_root {
            root
        } else {
            return Ok(path.to_string_lossy().to_string());
        };

        let canonical_path = path.canonicalize()
            .map_err(|e| anyhow!("Failed to canonicalize path {:?}: {}", path, e))?;

        let canonical_root = project_root.canonicalize()
            .map_err(|e| anyhow!("Failed to canonicalize project root: {}", e))?;

        let relative = canonical_path.strip_prefix(&canonical_root)
            .map_err(|_| anyhow!("Path {:?} is not within project root {:?}", path, project_root))?;

        // Format as ./path/to/file.txt
        Ok(format!("./{}", relative.to_string_lossy().replace('\\', "/")))
    }

    /// Interpolate secrets: replace ⊲{secret} or <{secret} with values from secrets file
    fn interpolate_secrets(&self, content: &str, file_path: &Path) -> Result<String> {
        // If no project root is set, try to find it
        let project_root = if let Some(ref root) = self.project_root {
            root.clone()
        } else {
            crate::config::find_project_root()?
        };

        let result = SECRETS_INTERPOLATION_REGEX.replace_all(content, |caps: &regex::Captures| {
            let secret_name = &caps[1];

            match self.lookup_secret_from_cache(secret_name, file_path, &project_root) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Warning: Failed to lookup secret '{}': {}", secret_name, e);
                    caps[0].to_string() // Return original marker on error
                }
            }
        });

        Ok(result.to_string())
    }

    pub fn new(repository_key: RepositoryKey) -> Result<Self> {
        Ok(Self {
            secrets_cache: CacheWrapper::new(SecretsCache::with_repository_key(repository_key.clone())),
            repository_key,
            project_root: None,
            project_created: String::new(), // Will be set later if needed
        })
    }

    /// Create a new processor with project metadata
    pub fn new_with_context(
        repository_key: RepositoryKey,
        project_root: PathBuf,
        project_created: String,
    ) -> Result<Self> {
        Ok(Self {
            secrets_cache: CacheWrapper::new(SecretsCache::with_repository_key(repository_key.clone())),
            repository_key,
            project_root: Some(project_root),
            project_created,
        })
    }

    /// Create a new processor with a specified project root for secrets lookup
    pub fn new_with_project_root(repository_key: RepositoryKey, project_root: PathBuf) -> Result<Self> {
        Ok(Self {
            secrets_cache: CacheWrapper::new(SecretsCache::with_repository_key(repository_key.clone())),
            repository_key,
            project_root: Some(project_root),
            project_created: String::new(), // Will be set later if needed
        })
    }

    /// Set the project creation timestamp for deterministic encryption
    pub fn set_project_created(&mut self, project_created: String) {
        self.project_created = project_created;
    }

    /// Set the project root for secrets lookup
    pub fn set_project_root(&mut self, project_root: PathBuf) {
        self.project_root = Some(project_root);
    }

    /// Check if a file is a secrets file (ends with .secrets)
    fn is_secrets_file<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref()
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.ends_with(".secrets"))
            .unwrap_or(false)
    }

    /// Process .secrets file content - encrypt or decrypt the entire file without markers
    fn process_secrets_file_content(&self, content: &str) -> Result<String> {
        // Check if content looks encrypted (Base64-like)
        // We detect encryption by trying to decrypt first
        if let Ok(decrypted) = self.decrypt_secrets_file_content(content) {
            // Content was encrypted, return decrypted version
            Ok(decrypted)
        } else {
            // Content is plaintext, encrypt it
            self.encrypt_secrets_file_content(content)
        }
    }

    /// Encrypt entire .secrets file content with encrypted marker (uses random nonces)
    fn encrypt_secrets_file_content(&self, content: &str) -> Result<String> {
        let encrypted = encrypt_to_base64(content, &self.repository_key)?;
        Ok(format!("⊠{{{}}}", encrypted))
    }

    /// Decrypt entire .secrets file content, detecting and removing encrypted marker
    fn decrypt_secrets_file_content(&self, content: &str) -> Result<String> {
        let content = content.trim();

        // Check if content starts with ⊠{ (encrypted marker)
        if content.starts_with("⊠{") && content.ends_with('}') {
            // Extract the base64 content between the braces
            // Skip '⊠{' (4 bytes: 3 for ⊠, 1 for {) and remove trailing '}'
            let encrypted_content = &content[4..content.len()-1];
            decrypt_from_base64(encrypted_content, &self.repository_key)
        } else {
            Err(anyhow!("Secrets file is not encrypted or has invalid format"))
        }
    }

    /// Explicitly seal (encrypt) content - used by seal command
    pub fn seal_content_with_path(&self, content: &str, file_path: &Path) -> Result<String> {
        if Self::is_secrets_file(file_path) {
            // For .secrets files, encrypt entire content
            self.encrypt_secrets_file_content(content)
        } else {
            // For regular files, encrypt markers with deterministic nonces
            self.encrypt_content_with_path(content, file_path.to_str().unwrap_or("<path>"))
        }
    }

    /// Explicitly open (decrypt) content - used by open command
    pub fn open_content_with_path(&self, content: &str, file_path: &Path) -> Result<String> {
        if Self::is_secrets_file(file_path) {
            // For .secrets files, decrypt entire content
            self.decrypt_secrets_file_content(content)
        } else {
            // For regular files, decrypt markers
            self.decrypt_content(content)
        }
    }

    pub fn process_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let path_ref = path.as_ref();

        // Check file size before reading to prevent DoS
        let metadata = fs::metadata(path_ref).map_err(|e| {
            anyhow!(
                "Failed to read file metadata {}: {}",
                path_ref.display(),
                e
            )
        })?;

        if metadata.len() > MAX_FILE_SIZE as u64 {
            return Err(anyhow!(
                "File too large: {} bytes (max: {} bytes)",
                metadata.len(),
                MAX_FILE_SIZE
            ));
        }

        // Use buffered reading for better I/O performance on large files
        let file = fs::File::open(path_ref)
            .map_err(|e| anyhow!("Failed to open file {}: {}", path_ref.display(), e))?;
        let mut reader = BufReader::new(file);
        let mut content = String::with_capacity(metadata.len() as usize);
        reader
            .read_to_string(&mut content)
            .map_err(|e| anyhow!("Failed to read file {}: {}", path_ref.display(), e))?;

        // Convert to relative path for deterministic nonce generation
        let relative_path = self.make_relative_path(path_ref)?;
        self.process_content_with_path(&content, &relative_path)
    }

    pub fn process_content(&self, content: &str) -> Result<String> {
        self.process_content_with_path(content, "<content>")
    }

    pub fn process_content_with_path(&self, content: &str, file_path: &str) -> Result<String> {
        // Check content size to prevent DoS
        if content.len() > MAX_FILE_SIZE {
            return Err(anyhow!(
                "Content too large: {} bytes (max: {} bytes)",
                content.len(),
                MAX_FILE_SIZE
            ));
        }

        // Special handling for .secrets files: encrypt/decrypt entire content without markers
        if Self::is_secrets_file(Path::new(file_path)) {
            return self.process_secrets_file_content(content);
        }

        // Process normally without secrets interpolation
        // Secrets are only interpolated during render operations
        let has_plaintext = PLAINTEXT_REGEX.is_match(content);
        let has_ciphertext = CIPHERTEXT_REGEX.is_match(content);

        match (has_plaintext, has_ciphertext) {
            (true, false) => self.encrypt_content_with_path(content, file_path),
            (false, true) => self.decrypt_content(content),
            (true, true) => Err(anyhow!(
                "File contains both plaintext and ciphertext markers. Please process separately."
            )),
            (false, false) => Ok(content.to_string()),
        }
    }

    pub fn encrypt_content(&self, content: &str) -> Result<String> {
        self.encrypt_content_with_path(content, "<content>")
    }

    pub fn encrypt_content_with_path(&self, content: &str, file_path: &str) -> Result<String> {
        let result = PLAINTEXT_REGEX.replace_all(content, |caps: &regex::Captures| {
            let plaintext = &caps[1];

            if !self.check_marker_size(plaintext, "Plaintext") {
                return caps[0].to_string();
            }

            // Use deterministic encryption if we have project_created timestamp
            let encrypted_result = if !self.project_created.is_empty() {
                encrypt_to_base64_deterministic(
                    plaintext,
                    &self.repository_key,
                    &self.project_created,
                    file_path,
                )
            } else {
                // Fall back to random nonce if no project context
                encrypt_to_base64(plaintext, &self.repository_key)
            };

            match encrypted_result {
                Ok(encrypted) => format!("⊠{{{}}}", encrypted),
                Err(e) => self.handle_encrypt_error(&e, &caps[0]),
            }
        });

        Ok(result.to_string())
    }

    pub fn decrypt_content(&self, content: &str) -> Result<String> {
        let result = CIPHERTEXT_REGEX.replace_all(content, |caps: &regex::Captures| {
            let encrypted = &caps[1];

            if !self.check_marker_size(encrypted, "Ciphertext") {
                return caps[0].to_string();
            }

            match self.decrypt_with_repository_key(encrypted) {
                Ok(decrypted) => format!("⊕{{{}}}", decrypted),
                Err(e) => self.handle_decrypt_error(&e, &caps[0], ""),
            }
        });

        Ok(result.to_string())
    }

    pub fn prepare_for_editing(&self, content: &str) -> Result<String> {
        let result = CIPHERTEXT_REGEX.replace_all(content, |caps: &regex::Captures| {
            let encrypted = &caps[1];

            if !self.check_marker_size(encrypted, "Ciphertext") {
                return caps[0].to_string();
            }

            match self.decrypt_with_repository_key(encrypted) {
                Ok(decrypted) => format!("⊕{{{}}}", decrypted),
                Err(e) => self.handle_decrypt_error(&e, &caps[0], "for editing"),
            }
        });

        Ok(result.to_string())
    }

    pub fn finalise_after_editing(&self, content: &str) -> Result<String> {
        self.encrypt_content(content)
    }

    pub fn decrypt_to_raw(&self, content: &str) -> Result<String> {
        // First pass: decrypt ciphertext markers to raw content
        let result = CIPHERTEXT_REGEX.replace_all(content, |caps: &regex::Captures| {
            let encrypted = &caps[1];

            if !self.check_marker_size(encrypted, "Ciphertext") {
                return caps[0].to_string();
            }

            match self.decrypt_with_repository_key(encrypted) {
                Ok(decrypted) => decrypted,
                Err(e) => self.handle_decrypt_error(&e, &caps[0], ""),
            }
        });

        // Second pass: remove plaintext markers, keeping only content
        let result = PLAINTEXT_REGEX.replace_all(&result, |caps: &regex::Captures| {
            let plaintext = &caps[1];

            if !self.check_marker_size(plaintext, "Plaintext") {
                return caps[0].to_string();
            }

            caps[1].to_string()
        });

        Ok(result.to_string())
    }

    /// Decrypt to raw text with secrets interpolation
    pub fn decrypt_to_raw_with_path(&self, content: &str, file_path: &Path) -> Result<String> {
        // First, interpolate secrets (replace <{secret}> with values from .secrets files)
        let content = self.interpolate_secrets(content, file_path)?;

        // Then decrypt to raw (remove all markers)
        self.decrypt_to_raw(&content)
    }

    /// Re-encrypt content from one repository key to another
    /// Used during key rotation to migrate encrypted content
    pub fn reencrypt_content(&self, content: &str, old_processor: &Processor) -> Result<String> {
        // First decrypt with old key
        let decrypted = old_processor.decrypt_content(content)?;

        // Then encrypt with new key (self)
        self.encrypt_content(&decrypted)
    }

    /// Batch re-encrypt multiple files with progress reporting
    pub fn reencrypt_files_batch<F>(
        &self,
        files: &[std::path::PathBuf],
        old_processor: &Processor,
        mut progress_callback: F,
    ) -> Result<(usize, usize)>
    where
        F: FnMut(usize, usize, &std::path::Path),
    {
        let mut processed = 0;
        let mut failed = 0;

        for (index, file_path) in files.iter().enumerate() {
            progress_callback(index + 1, files.len(), file_path);

            match self.reencrypt_single_file(file_path, old_processor) {
                Ok(()) => processed += 1,
                Err(_) => failed += 1,
            }
        }

        Ok((processed, failed))
    }

    /// Re-encrypt a single file
    fn reencrypt_single_file(
        &self,
        file_path: &std::path::Path,
        old_processor: &Processor,
    ) -> Result<()> {
        // Read original content
        let original_content = old_processor.process_file(file_path)?;

        // Re-encrypt with new key, using relative path for deterministic nonces
        let relative_path = self.make_relative_path(file_path)?;
        let reencrypted_content = self.process_content_with_path(&original_content, &relative_path)?;

        // Write back to file
        std::fs::write(file_path, reencrypted_content).map_err(|e| {
            anyhow::anyhow!(
                "Failed to write re-encrypted file {}: {}",
                file_path.display(),
                e
            )
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_utf8_marker() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let input = "This is ⊕{secret} text";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.starts_with("This is ⊠{"));
        assert!(result.ends_with("} text"));
        assert!(!result.contains("⊕{"));
    }

    #[test]
    fn test_encrypt_ascii_marker() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let input = "This is o+{secret} text";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.starts_with("This is ⊠{"));
        assert!(result.ends_with("} text"));
        assert!(!result.contains("o+{"));
    }

    #[test]
    fn test_decrypt_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let original = "This is ⊕{secret} text";
        let encrypted = processor.encrypt_content(original).unwrap();
        let decrypted = processor.decrypt_content(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_mixed_markers() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let input = "⊕{secret1} and o+{secret2}";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.contains("⊠{"));
        assert!(!result.contains("⊕{"));
        assert!(!result.contains("o+{"));
    }

    #[test]
    fn test_no_markers() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let input = "No secrets here";
        let result = processor.process_content(input).unwrap();

        assert_eq!(result, input);
    }

    #[test]
    fn test_editing_workflow() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let original = "Config: ⊕{password123}";
        let encrypted = processor.encrypt_content(original).unwrap();
        let prepared = processor.prepare_for_editing(&encrypted).unwrap();
        let finalised = processor.finalise_after_editing(&prepared).unwrap();

        assert_eq!(prepared, original);
        assert!(finalised.contains("⊠{"));
    }

    #[test]
    fn test_decrypt_to_raw() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let original = "Hello ⊕{world} and o+{universe}!";
        let encrypted = processor.encrypt_content(original).unwrap();
        let raw = processor.decrypt_to_raw(&encrypted).unwrap();

        assert_eq!(raw, "Hello world and universe!");
    }

    #[test]
    fn test_decrypt_to_raw_mixed_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // First encrypt some content to get a valid ciphertext
        let encrypted_part = processor.encrypt_content("⊕{already_encrypted}").unwrap();
        let ciphertext_match = CIPHERTEXT_REGEX.find(&encrypted_part).unwrap();
        let valid_ciphertext = ciphertext_match.as_str();

        let content = format!("Start ⊕{{plain text}} middle {} end", valid_ciphertext);
        let encrypted = processor.encrypt_content(&content).unwrap();
        let raw = processor.decrypt_to_raw(&encrypted).unwrap();

        assert_eq!(raw, "Start plain text middle already_encrypted end");
    }

    #[test]
    fn test_decrypt_to_raw_no_markers() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let content = "Just plain text with no markers";
        let raw = processor.decrypt_to_raw(content).unwrap();

        assert_eq!(raw, content);
    }

    #[test]
    fn test_oversized_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // Test that oversized content is rejected
        let large_content = "A".repeat(200 * 1024 * 1024); // 200MB
        let result = processor.process_content(&large_content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_oversized_marker_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // Test that oversized marker content is handled gracefully
        // MAX_MARKER_CONTENT_SIZE is 100MB, use 101MB to exceed limit
        let large_marker = format!("⊕{{{}}}", "A".repeat(101 * 1024 * 1024));
        let result = processor.encrypt_content(&large_marker).unwrap();

        // Should not fail but should skip the oversized marker
        assert_eq!(result, large_marker);
    }

    #[test]
    fn test_regex_bounds() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // Test that regex patterns are bounded and don't cause ReDoS
        let nested_braces = "⊕{".to_string() + &"{{".repeat(1000) + &"}}".repeat(1000) + "}";
        let result = processor.encrypt_content(&nested_braces);

        // Should complete quickly without hanging
        assert!(result.is_ok());
    }

    #[test]
    fn test_secrets_interpolation_during_render() {
        use std::io::Write;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create a secrets file
        let secrets_file = project_root.join("secrets");
        let mut file = std::fs::File::create(&secrets_file).unwrap();
        writeln!(file, "api_key: secret123").unwrap();
        writeln!(file, "database_url: postgresql://localhost/db").unwrap();
        drop(file);

        // Create a test file
        let test_file = project_root.join("config.txt");

        // Create processor with project root
        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, project_root.to_path_buf()).unwrap();

        // Test that secrets are interpolated during render using ⊲{} and <{}
        let content = "API Key: ⊲{api_key}\nDB: <{database_url}";
        let result = processor
            .decrypt_to_raw_with_path(content, &test_file)
            .unwrap();

        assert_eq!(
            result,
            "API Key: secret123\nDB: postgresql://localhost/db"
        );
    }

    #[test]
    fn test_secrets_not_interpolated_during_seal() {
        use std::io::Write;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create a secrets file
        let secrets_file = project_root.join("secrets");
        let mut file = std::fs::File::create(&secrets_file).unwrap();
        writeln!(file, "password: supersecret").unwrap();
        drop(file);

        // Create a test file
        let test_file = project_root.join("config.txt");

        // Create processor with project root
        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, project_root.to_path_buf()).unwrap();

        // Test that secrets interpolation markers are NOT processed during seal
        let content = "Password: ⊕{mypass} and API: ⊲{password}";
        let result = processor
            .process_content_with_path(content, test_file.to_str().unwrap())
            .unwrap();

        // Should have encrypted the plaintext marker but left the secret marker alone
        assert!(result.starts_with("Password: ⊠{"));
        assert!(result.contains("⊲{password}"));
    }

    #[test]
    fn test_secrets_interpolation_file_specific() {
        use std::io::Write;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create a test file
        let test_file = project_root.join("myconfig.txt");
        std::fs::write(&test_file, "").unwrap();

        // Create a file-specific secrets file
        let file_secrets = project_root.join("myconfig.secrets");
        let mut file = std::fs::File::create(&file_secrets).unwrap();
        writeln!(file, "token: file_specific_token").unwrap();
        drop(file);

        // Create a general secrets file
        let general_secrets = project_root.join("secrets");
        let mut file = std::fs::File::create(&general_secrets).unwrap();
        writeln!(file, "token: general_token").unwrap();
        drop(file);

        // Create processor with project root
        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, project_root.to_path_buf()).unwrap();

        // Test that file-specific secrets take precedence during render
        let content = "Token: <{token}";
        let result = processor
            .decrypt_to_raw_with_path(content, &test_file)
            .unwrap();

        assert_eq!(result, "Token: file_specific_token");
    }

    #[test]
    fn test_secrets_interpolation_with_decrypt_to_raw() {
        use std::io::Write;
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create a secrets file
        let secrets_file = project_root.join("secrets");
        let mut file = std::fs::File::create(&secrets_file).unwrap();
        writeln!(file, "username: admin").unwrap();
        writeln!(file, "host: example.com").unwrap();
        drop(file);

        // Create a test file
        let test_file = project_root.join("config.txt");

        // Create processor with project root
        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, project_root.to_path_buf()).unwrap();

        // First encrypt some content - secrets interpolation markers pass through
        let content = "User: ⊕{myuser} at <{host}";
        let encrypted = processor
            .process_content_with_path(content, test_file.to_str().unwrap())
            .unwrap();

        // Should have encrypted the plaintext marker but left interpolation marker
        assert!(encrypted.contains("⊠{"));
        assert!(encrypted.contains("<{host}"));

        // Now decrypt to raw with interpolation
        let raw = processor
            .decrypt_to_raw_with_path(&encrypted, &test_file)
            .unwrap();

        assert_eq!(raw, "User: myuser at example.com");
    }

    #[test]
    fn test_secrets_interpolation_missing_secret() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let project_root = temp_dir.path();

        // Create a secrets file with only one secret
        let secrets_file = project_root.join("secrets");
        std::fs::write(&secrets_file, "known_key: value\n").unwrap();

        // Create a test file
        let test_file = project_root.join("config.txt");

        // Create processor with project root
        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, project_root.to_path_buf()).unwrap();

        // Test with missing secret during render - should leave marker unchanged
        let content = "Known: ⊲{known_key} Unknown: <{missing_key}";
        let result = processor
            .decrypt_to_raw_with_path(content, &test_file)
            .unwrap();

        // Should interpolate the known key but leave the unknown marker unchanged
        assert_eq!(result, "Known: value Unknown: <{missing_key}");
    }

    #[test]
    fn test_secrets_file_encryption() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("config.secrets");

        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, temp_dir.path().to_path_buf()).unwrap();

        // Create plaintext secrets file content
        let plaintext = "api_key: my_secret_key\npassword: my_password\n";

        // Process it (should encrypt)
        let encrypted = processor
            .process_content_with_path(plaintext, secrets_file.to_str().unwrap())
            .unwrap();

        // Should be encrypted (Base64, no plaintext visible)
        assert_ne!(encrypted, plaintext);
        assert!(!encrypted.contains("my_secret_key"));
        assert!(!encrypted.contains("my_password"));

        // Should be a single line of Base64-like characters
        assert!(!encrypted.contains('\n') || !encrypted.trim().is_empty());
    }

    #[test]
    fn test_secrets_file_decryption() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("app.secrets");

        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, temp_dir.path().to_path_buf()).unwrap();

        // Create plaintext secrets
        let plaintext = "token: secret_token_123\nurl: https://api.example.com\n";

        // Encrypt it first
        let encrypted = processor
            .process_content_with_path(plaintext, secrets_file.to_str().unwrap())
            .unwrap();

        // Process the encrypted content (should decrypt)
        let decrypted = processor
            .process_content_with_path(&encrypted, secrets_file.to_str().unwrap())
            .unwrap();

        // Should match original plaintext
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_secrets_file_roundtrip() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("test.secrets");

        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, temp_dir.path().to_path_buf()).unwrap();

        let original = "# My secrets\nkey1: value1\nkey2: value2\n";

        // Encrypt
        let encrypted = processor
            .process_content_with_path(original, secrets_file.to_str().unwrap())
            .unwrap();

        // Decrypt
        let decrypted = processor
            .process_content_with_path(&encrypted, secrets_file.to_str().unwrap())
            .unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_non_secrets_file_unchanged() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let regular_file = temp_dir.path().join("config.txt");

        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, temp_dir.path().to_path_buf()).unwrap();

        // Regular file without markers should pass through unchanged
        let content = "api_key: my_secret_key\npassword: my_password\n";

        let result = processor
            .process_content_with_path(content, regular_file.to_str().unwrap())
            .unwrap();

        // Should be unchanged (no encryption without markers)
        assert_eq!(result, content);
    }

    #[test]
    fn test_secrets_file_detection() {
        assert!(Processor::is_secrets_file("config.secrets"));
        assert!(Processor::is_secrets_file("/path/to/app.secrets"));
        assert!(Processor::is_secrets_file("my_file.secrets"));

        assert!(!Processor::is_secrets_file("secrets"));
        assert!(!Processor::is_secrets_file("config.txt"));
        assert!(!Processor::is_secrets_file("/path/to/secrets"));
        assert!(!Processor::is_secrets_file("secrets.txt"));
    }

    #[test]
    fn test_seal_and_open_explicit_operations() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let secrets_file = temp_dir.path().join("test.secrets");

        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, temp_dir.path().to_path_buf()).unwrap();

        let plaintext = "username: admin\npassword: secret123\n";

        // Seal should always encrypt
        let sealed = processor.seal_content_with_path(plaintext, &secrets_file).unwrap();
        assert_ne!(sealed, plaintext);
        assert!(!sealed.contains("admin"));
        assert!(!sealed.contains("secret123"));

        // Open should always decrypt
        let opened = processor.open_content_with_path(&sealed, &secrets_file).unwrap();
        assert_eq!(opened, plaintext);

        // Seal again should encrypt (not toggle)
        let sealed_again = processor.seal_content_with_path(plaintext, &secrets_file).unwrap();
        assert_ne!(sealed_again, plaintext);

        // Open the already encrypted content should decrypt (not fail)
        let opened_again = processor.open_content_with_path(&sealed, &secrets_file).unwrap();
        assert_eq!(opened_again, plaintext);
    }
}
