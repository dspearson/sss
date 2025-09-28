use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::constants::{MAX_FILE_SIZE, MAX_MARKER_CONTENT_SIZE};
use crate::crypto::{decrypt_from_base64, encrypt_to_base64, RepositoryKey};

// Pre-compiled regex patterns for better performance
static PLAINTEXT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:⊕|o\+)\{([^}]*)\}")
        .expect("Failed to compile plaintext regex")
});

static CIPHERTEXT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"⊠\{([^⊕⊠]*)\}")
        .expect("Failed to compile ciphertext regex")
});

// Buffer pool for reducing allocations
thread_local! {
    static STRING_BUFFER: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(4096));
}

pub struct Processor {
    repository_key: RepositoryKey,
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

    /// Helper to handle encryption errors with consistent warning
    fn handle_encrypt_error(&self, error: &anyhow::Error, original: &str) -> String {
        eprintln!("Warning: Failed to encrypt plaintext: {}", error);
        original.to_string()
    }

    /// Helper to handle decryption errors with consistent warning
    fn handle_decrypt_error(&self, error: &anyhow::Error, original: &str, context: &str) -> String {
        eprintln!(
            "Warning: Failed to decrypt ciphertext{}: {}",
            if context.is_empty() {
                ""
            } else {
                &format!(" {}", context)
            },
            error
        );
        original.to_string()
    }

    /// Decrypt with the repository key
    fn decrypt_with_repository_key(&self, encrypted: &str) -> Result<String> {
        decrypt_from_base64(encrypted, &self.repository_key)
    }
    pub fn new(repository_key: RepositoryKey) -> Result<Self> {
        Ok(Self { repository_key })
    }

    pub fn process_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        // Check file size before reading to prevent DoS
        let metadata = fs::metadata(&path).map_err(|e| {
            anyhow!(
                "Failed to read file metadata {}: {}",
                path.as_ref().display(),
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
        let file = fs::File::open(&path)
            .map_err(|e| anyhow!("Failed to open file {}: {}", path.as_ref().display(), e))?;
        let mut reader = BufReader::new(file);
        let mut content = String::with_capacity(metadata.len() as usize);
        reader.read_to_string(&mut content)
            .map_err(|e| anyhow!("Failed to read file {}: {}", path.as_ref().display(), e))?;

        self.process_content(&content)
    }

    pub fn process_content(&self, content: &str) -> Result<String> {
        // Check content size to prevent DoS
        if content.len() > MAX_FILE_SIZE {
            return Err(anyhow!(
                "Content too large: {} bytes (max: {} bytes)",
                content.len(),
                MAX_FILE_SIZE
            ));
        }

        let has_plaintext = PLAINTEXT_REGEX.is_match(content);
        let has_ciphertext = CIPHERTEXT_REGEX.is_match(content);

        match (has_plaintext, has_ciphertext) {
            (true, false) => self.encrypt_content(content),
            (false, true) => self.decrypt_content(content),
            (true, true) => Err(anyhow!(
                "File contains both plaintext and ciphertext markers. Please process separately."
            )),
            (false, false) => Ok(content.to_string()),
        }
    }

    pub fn encrypt_content(&self, content: &str) -> Result<String> {
        let result = PLAINTEXT_REGEX
            .replace_all(content, |caps: &regex::Captures| {
                let plaintext = &caps[1];

                if !self.check_marker_size(plaintext, "Plaintext") {
                    return caps[0].to_string();
                }

                match encrypt_to_base64(plaintext, &self.repository_key) {
                    Ok(encrypted) => format!("⊠{{{}}}", encrypted),
                    Err(e) => self.handle_encrypt_error(&e, &caps[0]),
                }
            });

        Ok(result.to_string())
    }

    pub fn decrypt_content(&self, content: &str) -> Result<String> {
        let result = CIPHERTEXT_REGEX
            .replace_all(content, |caps: &regex::Captures| {
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
        let result = CIPHERTEXT_REGEX
            .replace_all(content, |caps: &regex::Captures| {
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
        let result = CIPHERTEXT_REGEX
            .replace_all(content, |caps: &regex::Captures| {
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
        let result = PLAINTEXT_REGEX
            .replace_all(&result, |caps: &regex::Captures| {
                let plaintext = &caps[1];

                if !self.check_marker_size(plaintext, "Plaintext") {
                    return caps[0].to_string();
                }

                caps[1].to_string()
            });

        Ok(result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_utf8_marker() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        let input = "This is ⊕{secret} text";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.starts_with("This is ⊠{"));
        assert!(result.ends_with("} text"));
        assert!(!result.contains("⊕{"));
    }

    #[test]
    fn test_encrypt_ascii_marker() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        let input = "This is o+{secret} text";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.starts_with("This is ⊠{"));
        assert!(result.ends_with("} text"));
        assert!(!result.contains("o+{"));
    }

    #[test]
    fn test_decrypt_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        let original = "This is ⊕{secret} text";
        let encrypted = processor.encrypt_content(original).unwrap();
        let decrypted = processor.decrypt_content(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_mixed_markers() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        let input = "⊕{secret1} and o+{secret2}";
        let result = processor.encrypt_content(input).unwrap();

        assert!(result.contains("⊠{"));
        assert!(!result.contains("⊕{"));
        assert!(!result.contains("o+{"));
    }

    #[test]
    fn test_no_markers() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        let input = "No secrets here";
        let result = processor.process_content(input).unwrap();

        assert_eq!(result, input);
    }

    #[test]
    fn test_editing_workflow() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

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
        let processor = Processor::new(key).unwrap();

        let original = "Hello ⊕{world} and o+{universe}!";
        let encrypted = processor.encrypt_content(original).unwrap();
        let raw = processor.decrypt_to_raw(&encrypted).unwrap();

        assert_eq!(raw, "Hello world and universe!");
    }

    #[test]
    fn test_decrypt_to_raw_mixed_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

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
        let processor = Processor::new(key).unwrap();

        let content = "Just plain text with no markers";
        let raw = processor.decrypt_to_raw(content).unwrap();

        assert_eq!(raw, content);
    }

    #[test]
    fn test_oversized_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        // Test that oversized content is rejected
        let large_content = "A".repeat(200 * 1024 * 1024); // 200MB
        let result = processor.process_content(&large_content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_oversized_marker_content() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        // Test that oversized marker content is handled gracefully
        let large_marker = format!("⊕{{{}}}", "A".repeat(15000));
        let result = processor.encrypt_content(&large_marker).unwrap();

        // Should not fail but should skip the oversized marker
        assert_eq!(result, large_marker);
    }

    #[test]
    fn test_regex_bounds() {
        let key = RepositoryKey::new();
        let processor = Processor::new(key).unwrap();

        // Test that regex patterns are bounded and don't cause ReDoS
        let nested_braces = "⊕{".to_string() + &"{{".repeat(1000) + &"}}".repeat(1000) + "}";
        let result = processor.encrypt_content(&nested_braces);

        // Should complete quickly without hanging
        assert!(result.is_ok());
    }
}
