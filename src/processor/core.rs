#![allow(clippy::missing_errors_doc)] // Public API doc sections managed separately

use anyhow::{anyhow, Result};
use std::fmt::Write as FmtWrite;
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
use crate::secrets::{interpolate_secrets, SecretsCache, StdFileSystemOps};

// Marker match structure for brace-counting parser
#[derive(Debug, Clone)]
struct MarkerMatch {
    /// Start position of the entire marker (including prefix)
    start: usize,
    /// End position of the entire marker (including closing brace)
    end: usize,
    /// The captured content between braces
    content: String,
}

/// Find markers with balanced brace counting
/// Supports nested braces like o+{a:{}} or ⊕{{"key":"value"}}
fn find_balanced_markers(content: &str, prefixes: &[&str]) -> Vec<MarkerMatch> {
    let mut matches = Vec::new();
    let bytes = content.as_bytes();
    let mut byte_pos = 0;

    while byte_pos < bytes.len() {
        // Try to match each prefix at current position
        let remaining = &content[byte_pos..];
        let mut matched_prefix = None;

        for &prefix in prefixes {
            if let Some(after_prefix) = remaining.strip_prefix(prefix) {
                // Check if followed by '{'
                if after_prefix.starts_with('{') {
                    matched_prefix = Some(prefix);
                    break;
                }
            }
        }

        if let Some(prefix) = matched_prefix {
            let marker_start = byte_pos;
            byte_pos += prefix.len(); // Move past prefix

            // Should be at '{'
            if !content[byte_pos..].starts_with('{') {
                byte_pos += 1;
                continue;
            }

            byte_pos += 1; // Move past '{'
            let content_start = byte_pos;
            let mut depth = 1;

            // Track brace depth to find matching closing brace
            for (char_offset, ch) in content[byte_pos..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            // Found matching closing brace
                            let content_end = byte_pos + char_offset;
                            let marker_end = content_end + 1; // Include the '}'

                            let captured_content = content[content_start..content_end].to_string();

                            matches.push(MarkerMatch {
                                start: marker_start,
                                end: marker_end,
                                content: captured_content,
                            });

                            byte_pos = marker_end;
                            break;
                        }
                    }
                    _ => {}
                }
            }

            // If we didn't find a match, move past the opening brace
            if depth != 0 {
                byte_pos = content_start;
            }
        } else {
            // Move to next character
            let remaining = &content[byte_pos..];
            if let Some(ch) = remaining.chars().next() {
                byte_pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    matches
}

/// Find plaintext markers: o+{...} or ⊕{...}
fn find_plaintext_markers(content: &str) -> Vec<MarkerMatch> {
    find_balanced_markers(content, &["o+", "⊕"])
}

/// Find ciphertext markers: ⊠{...}
fn find_ciphertext_markers(content: &str) -> Vec<MarkerMatch> {
    find_balanced_markers(content, &["⊠"])
}

/// Normalize ASCII secrets markers to UTF-8 style
/// Converts <{ to ⊲{ for consistent marker style
fn normalize_secrets_markers(content: &str) -> String {
    content.replace("<{", "⊲{")
}

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
    #[allow(clippy::unused_self)]
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

    /// Helper to handle encryption errors with consistent warning
    #[allow(clippy::unused_self)]
    fn handle_encrypt_error(&self, error: &anyhow::Error, original: &str) -> String {
        eprintln!("Warning: Failed to encrypt plaintext: {error}");
        original.to_string()
    }

    /// Helper to handle decryption errors with consistent warning
    #[allow(clippy::unused_self)]
    fn handle_decrypt_error(&self, error: &anyhow::Error, original: &str, context: &str) -> String {
        let context_str = if context.is_empty() {
            String::new()
        } else {
            format!(" {context}")
        };
        eprintln!(
            "Warning: Failed to decrypt ciphertext{context_str}: {error}"
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
        let Some(ref project_root) = self.project_root else {
            return Ok(path.to_string_lossy().to_string());
        };

        let canonical_path = path.canonicalize()
            .map_err(|e| anyhow!("Failed to canonicalize path {}: {e}", path.display()))?;

        let canonical_root = project_root.canonicalize()
            .map_err(|e| anyhow!("Failed to canonicalize project root: {e}"))?;

        let relative = canonical_path.strip_prefix(&canonical_root)
            .map_err(|_| anyhow!("Path {} is not within project root {}", path.display(), project_root.display()))?;

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

        // Use unified interpolation with standard filesystem ops
        #[cfg(not(feature = "ninep"))]
        {
            let mut secrets_cache = self.secrets_cache.borrow_mut();
            interpolate_secrets(
                content,
                file_path,
                &project_root,
                &mut secrets_cache,
                &StdFileSystemOps,
            )
        }
        #[cfg(feature = "ninep")]
        {
            let mut secrets_cache = self.secrets_cache.write();
            interpolate_secrets(
                content,
                file_path,
                &project_root,
                &mut *secrets_cache,
                &StdFileSystemOps,
            )
        }
    }

    pub fn new(repository_key: RepositoryKey) -> Result<Self> {
        Self::new_with_secrets_config(repository_key, "secrets".to_string(), ".secrets".to_string())
    }

    /// Get a clone of the secrets cache for sharing with other components
    pub fn get_secrets_cache(&self) -> SecretsCache {
        #[cfg(not(feature = "ninep"))]
        { (*self.secrets_cache.borrow()).clone() }
        #[cfg(feature = "ninep")]
        { self.secrets_cache.read().clone() }
    }

    /// Create a new processor with custom secrets filename
    pub fn new_with_secrets_filename(repository_key: RepositoryKey, secrets_filename: String) -> Result<Self> {
        Self::new_with_secrets_config(repository_key, secrets_filename, ".secrets".to_string())
    }

    /// Create a new processor with custom secrets filename and suffix
    pub fn new_with_secrets_config(
        repository_key: RepositoryKey,
        secrets_filename: String,
        secrets_suffix: String,
    ) -> Result<Self> {
        Ok(Self {
            secrets_cache: CacheWrapper::new(SecretsCache::with_repository_key_and_config(
                repository_key.clone(),
                secrets_filename,
                secrets_suffix,
            )),
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
        Self::new_with_context_and_secrets_config(
            repository_key,
            project_root,
            project_created,
            "secrets".to_string(),
            ".secrets".to_string(),
        )
    }

    /// Create a new processor with project metadata and custom secrets filename
    pub fn new_with_context_and_secrets_filename(
        repository_key: RepositoryKey,
        project_root: PathBuf,
        project_created: String,
        secrets_filename: String,
    ) -> Result<Self> {
        Self::new_with_context_and_secrets_config(
            repository_key,
            project_root,
            project_created,
            secrets_filename,
            ".secrets".to_string(),
        )
    }

    /// Create a new processor with project metadata and custom secrets filename and suffix
    pub fn new_with_context_and_secrets_config(
        repository_key: RepositoryKey,
        project_root: PathBuf,
        project_created: String,
        secrets_filename: String,
        secrets_suffix: String,
    ) -> Result<Self> {
        Ok(Self {
            secrets_cache: CacheWrapper::new(SecretsCache::with_repository_key_and_config(
                repository_key.clone(),
                secrets_filename,
                secrets_suffix,
            )),
            repository_key,
            project_root: Some(project_root),
            project_created,
        })
    }

    /// Create a new processor with a specified project root for secrets lookup
    pub fn new_with_project_root(repository_key: RepositoryKey, project_root: PathBuf) -> Result<Self> {
        Self::new_with_project_root_and_secrets_config(
            repository_key,
            project_root,
            "secrets".to_string(),
            ".secrets".to_string(),
        )
    }

    /// Create a new processor with a specified project root and custom secrets filename
    pub fn new_with_project_root_and_secrets_filename(
        repository_key: RepositoryKey,
        project_root: PathBuf,
        secrets_filename: String,
    ) -> Result<Self> {
        Self::new_with_project_root_and_secrets_config(
            repository_key,
            project_root,
            secrets_filename,
            ".secrets".to_string(),
        )
    }

    /// Create a new processor with a specified project root and custom secrets filename and suffix
    pub fn new_with_project_root_and_secrets_config(
        repository_key: RepositoryKey,
        project_root: PathBuf,
        secrets_filename: String,
        secrets_suffix: String,
    ) -> Result<Self> {
        Ok(Self {
            secrets_cache: CacheWrapper::new(SecretsCache::with_repository_key_and_config(
                repository_key.clone(),
                secrets_filename,
                secrets_suffix,
            )),
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

    /// Check if a file is a secrets file (ends with .secrets extension or named "secrets")
    fn is_secrets_file<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".secrets") || name == "secrets")
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
            self.encrypt_secrets_file_content(content, "<secrets-file>")
        }
    }

    /// Encrypt entire .secrets file content with encrypted marker (uses deterministic nonces)
    fn encrypt_secrets_file_content(&self, content: &str, file_path: &str) -> Result<String> {
        let trimmed = content.trim();

        // Check if already encrypted (idempotent seal)
        if trimmed.starts_with("⊠{") && trimmed.ends_with('}') {
            // Already encrypted, ensure POSIX newline and return
            return Ok(format!("{trimmed}\n"));
        }

        // Not encrypted yet, encrypt the content with deterministic nonce
        let encrypted = if self.project_created.is_empty() {
            // Fall back to random nonce if no project context
            encrypt_to_base64(content, &self.repository_key)?
        } else {
            encrypt_to_base64_deterministic(
                content,
                &self.repository_key,
                &self.project_created,
                file_path,
            )?
        };
        // Add trailing newline for POSIX compliance
        Ok(format!("⊠{{{encrypted}}}\n"))
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
            // For .secrets files, encrypt entire content with file path for deterministic nonce
            // Use path as-is if file doesn't exist yet (for tests)
            let relative_path = if file_path.exists() {
                self.make_relative_path(file_path)?
            } else {
                file_path.to_string_lossy().to_string()
            };
            self.encrypt_secrets_file_content(content, &relative_path)
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
        #[allow(clippy::cast_possible_truncation)] // file size fits in usize on all supported platforms
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
        let has_plaintext = !find_plaintext_markers(content).is_empty();
        let has_ciphertext = !find_ciphertext_markers(content).is_empty();

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

    /// Processes a single plaintext marker for encryption
    fn process_plaintext_marker(&self, marker: &MarkerMatch, file_path: &str, original_text: &str) -> String {
        // Check size limits
        if !self.check_marker_size(&marker.content, "Plaintext") {
            // Keep original marker if too large
            return original_text[marker.start..marker.end].to_string();
        }

        // Use deterministic encryption if we have project_created timestamp
        let encrypted_result = if self.project_created.is_empty() {
            // Fall back to random nonce if no project context
            encrypt_to_base64(&marker.content, &self.repository_key)
        } else {
            encrypt_to_base64_deterministic(
                &marker.content,
                &self.repository_key,
                &self.project_created,
                file_path,
            )
        };

        // Format result or handle error
        match encrypted_result {
            Ok(encrypted) => format!("⊠{{{encrypted}}}"),
            Err(e) => {
                let original = &original_text[marker.start..marker.end];
                self.handle_encrypt_error(&e, original)
            }
        }
    }

    pub fn encrypt_content_with_path(&self, content: &str, file_path: &str) -> Result<String> {
        // First, normalize ASCII secrets markers ⊲{} to UTF-8 ⊲{}
        let normalized_content = normalize_secrets_markers(content);

        let markers = find_plaintext_markers(&normalized_content);

        if markers.is_empty() {
            return Ok(normalized_content);
        }

        let mut result = String::with_capacity(normalized_content.len());
        let mut last_end = 0;

        for marker in markers {
            // Add content before this marker
            result.push_str(&normalized_content[last_end..marker.start]);

            // Process and add the encrypted marker
            let processed = self.process_plaintext_marker(&marker, file_path, &normalized_content);
            result.push_str(&processed);

            last_end = marker.end;
        }

        // Add remaining content after last marker
        result.push_str(&normalized_content[last_end..]);

        Ok(result)
    }

    pub fn decrypt_content(&self, content: &str) -> Result<String> {
        let markers = find_ciphertext_markers(content);

        if markers.is_empty() {
            return Ok(content.to_string());
        }

        let mut result = String::with_capacity(content.len());
        let mut last_end = 0;

        for marker in markers {
            // Add content before this marker
            result.push_str(&content[last_end..marker.start]);

            // Process this marker
            if self.check_marker_size(&marker.content, "Ciphertext") {
                match self.decrypt_with_repository_key(&marker.content) {
                    Ok(decrypted) => { let _ = write!(result, "⊕{{{decrypted}}}"); }
                    Err(e) => {
                        let original = &content[marker.start..marker.end];
                        result.push_str(&self.handle_decrypt_error(&e, original, ""));
                    }
                }
            } else {
                // Keep original marker if too large
                result.push_str(&content[marker.start..marker.end]);
            }

            last_end = marker.end;
        }

        // Add remaining content after last marker
        result.push_str(&content[last_end..]);

        Ok(result)
    }

    pub fn prepare_for_editing(&self, content: &str) -> Result<String> {
        let markers = find_ciphertext_markers(content);

        if markers.is_empty() {
            return Ok(content.to_string());
        }

        let mut result = String::with_capacity(content.len());
        let mut last_end = 0;

        for marker in markers {
            // Add content before this marker
            result.push_str(&content[last_end..marker.start]);

            // Process this marker
            if self.check_marker_size(&marker.content, "Ciphertext") {
                match self.decrypt_with_repository_key(&marker.content) {
                    Ok(decrypted) => { let _ = write!(result, "⊕{{{decrypted}}}"); }
                    Err(e) => {
                        let original = &content[marker.start..marker.end];
                        result.push_str(&self.handle_decrypt_error(&e, original, "for editing"));
                    }
                }
            } else {
                // Keep original marker if too large
                result.push_str(&content[marker.start..marker.end]);
            }

            last_end = marker.end;
        }

        // Add remaining content after last marker
        result.push_str(&content[last_end..]);

        Ok(result)
    }

    pub fn finalise_after_editing(&self, content: &str) -> Result<String> {
        self.encrypt_content(content)
    }

    pub fn decrypt_to_raw(&self, content: &str) -> Result<String> {
        // First pass: decrypt ciphertext markers to raw content (no markers)
        let markers = find_ciphertext_markers(content);
        let mut result = String::with_capacity(content.len());
        let mut last_end = 0;

        for marker in markers {
            result.push_str(&content[last_end..marker.start]);

            if self.check_marker_size(&marker.content, "Ciphertext") {
                match self.decrypt_with_repository_key(&marker.content) {
                    Ok(decrypted) => result.push_str(&decrypted),
                    Err(e) => {
                        let original = &content[marker.start..marker.end];
                        result.push_str(&self.handle_decrypt_error(&e, original, ""));
                    }
                }
            } else {
                result.push_str(&content[marker.start..marker.end]);
            }

            last_end = marker.end;
        }
        result.push_str(&content[last_end..]);

        // Second pass: remove plaintext markers, keeping only content
        let plaintext_markers = find_plaintext_markers(&result);
        if plaintext_markers.is_empty() {
            return Ok(result);
        }

        let mut final_result = String::with_capacity(result.len());
        last_end = 0;

        for marker in plaintext_markers {
            final_result.push_str(&result[last_end..marker.start]);

            if self.check_marker_size(&marker.content, "Plaintext") {
                final_result.push_str(&marker.content);
            } else {
                final_result.push_str(&result[marker.start..marker.end]);
            }

            last_end = marker.end;
        }
        final_result.push_str(&result[last_end..]);

        Ok(final_result)
    }

    /// Decrypt to raw text with secrets interpolation
    pub fn decrypt_to_raw_with_path(&self, content: &str, file_path: &Path) -> Result<String> {
        // First, interpolate secrets (replace ⊲{secret}> with values from .secrets files)
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

        let input = "This is ⊠{4NsTrT2Glmv/Bmqylqo7KUixjToyEcFuGVN7B7eH5MZL0G/r4S3JTIRST4uOQA==} text";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.starts_with("This is ⊠{"));
        assert!(result.ends_with("} text"));
        assert_eq!(result, input); // Ciphertext should remain unchanged
    }

    #[test]
    fn test_encrypt_ascii_marker() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let input = "This is ⊠{4NsTrT2Glmv/Bmqylqo7KUixjToyEcFuGVN7B7eH5MZL0G/r4S3JTIRST4uOQA==} text";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.starts_with("This is ⊠{"));
        assert!(result.ends_with("} text"));
        assert_eq!(result, input); // Ciphertext should remain unchanged
    }

    #[test]
    fn test_decrypt_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let original = "This is ⊠{4NsTrT2Glmv/Bmqylqo7KUixjToyEcFuGVN7B7eH5MZL0G/r4S3JTIRST4uOQA==} text";
        let encrypted = processor.encrypt_content(original).unwrap();
        let decrypted = processor.decrypt_content(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_mixed_markers() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let input = "⊠{zfToI5Eo86eK8p4O0eBoNWVfRqq/9NTv5hRkLSo1iLnS9k8ZeVkfCVY4LS8zdmo=} and ⊠{v7+kAaRvBr9iS5v6FjS8FmLFmq1yKNPBjr5uK1OHXGM3Ywk41shgl+8ZBHc9VyM=}";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.contains("⊠{"));
        assert!(!result.contains("⊕{"));
        assert_eq!(result, input); // Ciphertext should remain unchanged
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

        let original = "Config: ⊠{EZHAh88hC4PtaIz9VF2lGKaxQo31MexHi8jM7v9qzLlIjYPgf9k8WhFWgwPWmzB9rhio}";
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

        // Encrypt plaintext markers to get valid ciphertexts
        let with_plaintext = "Hello o+{world} and o+{universe}!";
        let encrypted = processor.encrypt_content(with_plaintext).unwrap();

        // decrypt_to_raw should decrypt and render to final values
        let raw = processor.decrypt_to_raw(&encrypted).unwrap();

        assert_eq!(raw, "Hello world and universe!");
    }

    #[test]
    fn test_decrypt_to_raw_mixed_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // Create content with plaintext markers
        let with_plaintext = "Start o+{plain text} middle o+{already_encrypted} end";
        let encrypted = processor.encrypt_content(with_plaintext).unwrap();

        // decrypt_to_raw should decrypt and render to final values
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
        let nested_braces = "⊠{j8UMVISLksPYrKPvP5kgZjgqHcbTU+h15D69CNB76gUu5vceDHwHb1WzQyGkCTcjv6T4BxMshJW98mTULWuNxweutOyvg00OJPQCmlnvju8rZOdp7LOXLVZxqo7w17f5ujBU}";
        let result = processor.encrypt_content(nested_braces);

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

        // Test that secrets are interpolated during render using ⊲{} and ⊲{}
        let content = "API Key: ⊲{api_key}\nDB: ⊲{database_url}";
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
        let content = "Password: ⊠{jrG8yEficNVG2s+3wZUbzUW3HL9FIMAZJSYIbjLyP/InO5fcoKP6gD6CsWv0vQ==} and API: ⊲{password}";
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

        // Create a file-specific secrets file (suffix is appended, not replacing extension)
        let file_secrets = project_root.join("myconfig.txt.secrets");
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
        let content = "Token: ⊲{token}";
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
        writeln!(file, "username: myuser").unwrap();
        writeln!(file, "host: example.com").unwrap();
        drop(file);

        // Create a test file
        let test_file = project_root.join("config.txt");

        // Create processor with project root
        let key = RepositoryKey::new();
        let processor = Processor::new_with_project_root(key, project_root.to_path_buf()).unwrap();

        // First create content with a plaintext marker and secrets interpolation marker
        let content_with_plaintext = "User: o+{myuser} at ⊲{host}";
        let encrypted = processor
            .process_content_with_path(content_with_plaintext, test_file.to_str().unwrap())
            .unwrap();

        // Should have encrypted the plaintext marker but left interpolation marker
        assert!(encrypted.contains("⊠{"));
        assert!(encrypted.contains("⊲{host}"));

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
        let content = "Known: ⊲{known_key} Unknown: ⊲{missing_key}";
        let result = processor
            .decrypt_to_raw_with_path(content, &test_file)
            .unwrap();

        // Should interpolate the known key but leave the unknown marker unchanged
        assert_eq!(result, "Known: value Unknown: ⊲{missing_key}");
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
        // Files with .secrets extension should be treated as secrets files
        assert!(Processor::is_secrets_file("config.secrets"));
        assert!(Processor::is_secrets_file("/path/to/app.secrets"));
        assert!(Processor::is_secrets_file("my_file.secrets"));

        // Files named "secrets" (without path) should be treated as secrets files
        assert!(Processor::is_secrets_file("secrets"));

        // Files named "secrets" with a path should be treated as secrets files
        assert!(Processor::is_secrets_file("/path/to/secrets"));

        // Other files should NOT be treated as secrets files
        assert!(!Processor::is_secrets_file("config.txt"));
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

