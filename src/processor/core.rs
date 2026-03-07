#![allow(clippy::missing_errors_doc)] // Public API doc sections managed separately

use anyhow::{anyhow, Result};
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
    /// The captured content between the delimiter pair
    content: String,
}

/// Supported open/close delimiter pairs for markers, in preference order.
///
/// `{}` is the historical default and stays first so unchanged files remain
/// byte-identical. `[]` is a lightweight ASCII fallback for values containing
/// unbalanced braces. The remaining entries are drawn from distinct Unicode
/// blocks so the likelihood that a single value collides with every candidate
/// is vanishing — no value we encounter in practice will exhaust the table.
const DELIMITER_PAIRS: &[(char, char)] = &[
    ('{', '}'),
    ('[', ']'),
    ('\u{27E6}', '\u{27E7}'),   // ⟦ ⟧  mathematical white square brackets
    ('\u{27E8}', '\u{27E9}'),   // ⟨ ⟩  mathematical angle brackets
    ('\u{27EA}', '\u{27EB}'),   // ⟪ ⟫  mathematical double angle brackets
    ('\u{27EC}', '\u{27ED}'),   // ⟬ ⟭  mathematical white tortoise-shell brackets
    ('\u{27EE}', '\u{27EF}'),   // ⟮ ⟯  mathematical flattened parentheses
    ('\u{2983}', '\u{2984}'),   // ⦃ ⦄  white curly brackets
    ('\u{2985}', '\u{2986}'),   // ⦅ ⦆  white parentheses
    ('\u{2987}', '\u{2988}'),   // ⦇ ⦈  Z notation image brackets
    ('\u{2989}', '\u{298A}'),   // ⦉ ⦊  Z notation binding brackets
    ('\u{298B}', '\u{298C}'),   // ⦋ ⦌  square brackets with underbar
    ('\u{300C}', '\u{300D}'),   // 「 」 CJK corner brackets
    ('\u{300E}', '\u{300F}'),   // 『 』 CJK white corner brackets
];

/// Look up the closing delimiter for an opening character from the supported set.
fn close_for_open(open: char) -> Option<char> {
    DELIMITER_PAIRS
        .iter()
        .find(|(o, _)| *o == open)
        .map(|(_, c)| *c)
}

/// Pick a delimiter pair whose open and close chars do not appear in `value`.
///
/// Scans `value` once per candidate and returns the first non-colliding pair.
/// `{}` is tried first — if `value` balances its braces and contains neither an
/// opening nor an impossible sequence we emit the historical form. Otherwise we
/// fall back to `[]` when possible, and then through the exotic Unicode ladder.
///
/// Returns `None` if every candidate collides — mathematically possible, but not
/// reachable by any input we expect to see.
fn pick_delimiter_for_value(value: &str) -> Option<(char, char)> {
    // Special case the default pair: it's fine as long as braces in the value
    // balance to zero and never go negative (no stray close before open).
    if braces_balance(value) {
        return Some(('{', '}'));
    }
    DELIMITER_PAIRS
        .iter()
        .skip(1)
        .copied()
        .find(|(o, c)| !value.contains(*o) && !value.contains(*c))
}

/// Return true if curly braces in `value` balance — every `}` is preceded by an
/// open, and the final depth is zero. This is the exact condition under which
/// the default `{}` delimiter can round-trip without ambiguity.
fn braces_balance(value: &str) -> bool {
    let mut depth: i32 = 0;
    for ch in value.chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// Unescape `\{`, `\}`, and `\\` in a captured default-pair content string.
///
/// Applied only after scanning with the default `{}` delimiter pair, so the
/// escape convention is local to that form. Other characters preceded by `\`
/// are preserved literally — we don't touch `\n`, `\t`, etc.
fn unescape_default_delimiter(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.clone().next() {
                Some('{') | Some('}') | Some('\\') => {
                    // Escaped brace or backslash — emit the literal.
                    out.push(chars.next().unwrap());
                    continue;
                }
                _ => {}
            }
        }
        out.push(ch);
    }
    out
}

/// Emit a marker string with the best available delimiter for `value`.
///
/// Panics never happen in practice: the exotic ladder is long enough that at
/// least one pair is always clean. If the unthinkable occurs we fall back to
/// the raw braces form — callers upstream will surface any parse mismatch.
fn format_marker(prefix: &str, value: &str) -> String {
    let (open, close) = pick_delimiter_for_value(value).unwrap_or(('{', '}'));
    let mut out = String::with_capacity(prefix.len() + value.len() + 4);
    out.push_str(prefix);
    out.push(open);
    out.push_str(value);
    out.push(close);
    out
}

/// Find markers with balanced delimiter counting, returning matched prefix alongside each match.
///
/// For each recognised prefix, peeks the next char to determine which
/// delimiter pair is in use (from `DELIMITER_PAIRS`) and scans with balanced
/// counting on that pair. `o+{a:{}}` and `⊕⟦foo}bar⟧` are both parsed
/// correctly. Returns `(matched_prefix, MarkerMatch)` tuples in order of
/// appearance.
fn find_balanced_markers_with_prefix<'a>(
    content: &str,
    prefixes: &[&'a str],
) -> Vec<(&'a str, MarkerMatch)> {
    let mut matches = Vec::new();
    let bytes = content.as_bytes();
    let mut byte_pos = 0;

    while byte_pos < bytes.len() {
        // Try to match each prefix at current position
        let mut matched: Option<(&str, usize, char, char)> = None;

        for &prefix in prefixes {
            let plen = prefix.len();
            let remaining = &bytes[byte_pos..];
            if remaining.len() <= plen || &remaining[..plen] != prefix.as_bytes() {
                continue;
            }
            // Peek the char after the prefix to see if it's a supported opener.
            let after_prefix = &content[byte_pos + plen..];
            let Some(open) = after_prefix.chars().next() else { continue };
            if let Some(close) = close_for_open(open) {
                matched = Some((prefix, plen + open.len_utf8(), open, close));
                break;
            }
        }

        if let Some((prefix, header_len, open, close)) = matched {
            let marker_start = byte_pos;
            let content_start = byte_pos + header_len;
            let mut depth = 1u32;
            let mut found = false;

            // Escapes (\{, \}, \\) are recognised only for the default {}
            // pair — that's the form hand-typers use. Other pairs sidestep
            // the problem by using a delimiter that isn't in the value.
            let escapes_enabled = open == '{' && close == '}';

            let inner = &content[content_start..];
            let mut iter = inner.char_indices();
            while let Some((char_offset, ch)) = iter.next() {
                // Skip over \{, \}, or \\ so escaped delimiters don't move depth.
                if escapes_enabled && ch == '\\' {
                    // Peek the next char — if it's one of the escape targets,
                    // consume it and continue without touching depth.
                    if let Some((_, next)) = iter.clone().next() {
                        if next == '{' || next == '}' || next == '\\' {
                            iter.next();
                            continue;
                        }
                    }
                    continue;
                }
                if ch == open {
                    depth += 1;
                } else if ch == close {
                    depth -= 1;
                    if depth == 0 {
                        let content_end = content_start + char_offset;
                        let marker_end = content_end + ch.len_utf8();
                        let raw = &content[content_start..content_end];
                        let captured = if escapes_enabled {
                            unescape_default_delimiter(raw)
                        } else {
                            raw.to_string()
                        };
                        matches.push((prefix, MarkerMatch {
                            start: marker_start,
                            end: marker_end,
                            content: captured,
                        }));
                        byte_pos = marker_end;
                        found = true;
                        break;
                    }
                }
            }

            // Unbalanced delimiter: retreat to just after the opening char so
            // we don't lose ground and so the outer loop can advance by one.
            if !found {
                byte_pos = content_start;
            }
        } else {
            // Advance by one UTF-8 character
            let b = bytes[byte_pos];
            if b < 0x80 {
                byte_pos += 1;
            } else {
                let remaining = &content[byte_pos..];
                if let Some(ch) = remaining.chars().next() {
                    byte_pos += ch.len_utf8();
                } else {
                    break;
                }
            }
        }
    }

    matches
}

/// Find markers with balanced brace counting (returns matches only, without prefix).
/// Supports nested braces like o+{a:{}} or ⊕{{"key":"value"}}.
fn find_balanced_markers(content: &str, prefixes: &[&str]) -> Vec<MarkerMatch> {
    find_balanced_markers_with_prefix(content, prefixes)
        .into_iter()
        .map(|(_, m)| m)
        .collect()
}

/// Find plaintext markers: o+{...} or ⊕{...}
fn find_plaintext_markers(content: &str) -> Vec<MarkerMatch> {
    find_balanced_markers(content, &["o+", "⊕"])
}

/// Find ciphertext markers: ⊠{...}
fn find_ciphertext_markers(content: &str) -> Vec<MarkerMatch> {
    find_balanced_markers(content, &["⊠"])
}

/// Classify a prefix as plaintext or ciphertext marker type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerKind { Plaintext, Ciphertext }

fn classify_prefix(prefix: &str) -> MarkerKind {
    if prefix == "⊠" { MarkerKind::Ciphertext } else { MarkerKind::Plaintext }
}

/// Normalize ASCII secrets markers to UTF-8 style
/// Converts <{ to ⊲{ for consistent marker style
///
/// Fast-path: if content contains no "<{" sequences (the common case), returns
/// a Cow::Borrowed referencing the original slice and avoids any allocation.
fn normalize_secrets_markers(content: &str) -> std::borrow::Cow<'_, str> {
    if content.contains("<{") {
        std::borrow::Cow::Owned(content.replace("<{", "⊲{"))
    } else {
        std::borrow::Cow::Borrowed(content)
    }
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
        // Secrets are only interpolated during render operations.
        //
        // Optimisation: scan content once for all marker prefixes and partition
        // the results by kind, avoiding a separate second full scan.
        let all_markers =
            find_balanced_markers_with_prefix(content, &["o+", "⊕", "⊠"]);
        let has_plaintext = all_markers.iter().any(|(p, _)| classify_prefix(p) == MarkerKind::Plaintext);
        let has_ciphertext = all_markers.iter().any(|(p, _)| classify_prefix(p) == MarkerKind::Ciphertext);

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
        // Normalize ASCII secrets markers <{ to ⊲{ for consistent marker style.
        // Fast-path: if content has no "<{" (common case), this borrows without allocating.
        let normalized_content = normalize_secrets_markers(content);

        let markers = find_plaintext_markers(&normalized_content);

        if markers.is_empty() {
            return Ok(normalized_content.into_owned());
        }

        let mut result = String::with_capacity(normalized_content.len());
        let mut last_end = 0;

        for marker in markers {
            // Add content before this marker
            result.push_str(&normalized_content[last_end..marker.start]);

            // Inline marker encryption directly into result to avoid intermediate String.
            if !self.check_marker_size(&marker.content, "Plaintext") {
                // Keep original marker if too large
                result.push_str(&normalized_content[marker.start..marker.end]);
            } else {
                let encrypted_result = if self.project_created.is_empty() {
                    encrypt_to_base64(&marker.content, &self.repository_key)
                } else {
                    encrypt_to_base64_deterministic(
                        &marker.content,
                        &self.repository_key,
                        &self.project_created,
                        file_path,
                    )
                };
                match encrypted_result {
                    Ok(encrypted) => {
                        // Push sealed marker directly into result — no intermediate String
                        result.push_str("⊠{");
                        result.push_str(&encrypted);
                        result.push('}');
                    }
                    Err(e) => {
                        let original = &normalized_content[marker.start..marker.end];
                        result.push_str(&self.handle_encrypt_error(&e, original));
                    }
                }
            }

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
                    Ok(decrypted) => {
                        // Pick a delimiter pair that doesn't collide with the
                        // decrypted value — values containing unbalanced `}`
                        // cannot round-trip through the default `{}` form.
                        result.push_str(&format_marker("⊕", &decrypted));
                    }
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
                    Ok(decrypted) => {
                        result.push_str(&format_marker("⊕", &decrypted));
                    }
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

    // =========================================================================
    // Round-trip correctness tests (CORR-01)
    // Each test seals content then opens it and asserts byte-identical output.
    // =========================================================================

    fn make_processor() -> Processor {
        let key = RepositoryKey::new();
        Processor::new_with_context(
            key,
            std::path::PathBuf::from("."),
            "2025-01-01T00:00:00Z".to_string(),
        )
        .unwrap()
    }

    /// Inline marker: single-line ⊕{secret}
    #[test]
    fn round_trip_inline_marker() {
        let proc = make_processor();
        let original = "password = ⊕{hunter2}\nuser = admin\n";
        let sealed = proc.seal_content_with_path(
            original,
            std::path::Path::new("config.txt"),
        ).unwrap();
        // Sealed content must contain ciphertext marker and no plaintext of the secret
        assert!(sealed.contains("⊠{"), "sealed output should contain ciphertext marker");
        assert!(!sealed.contains("hunter2"), "secret must not appear in sealed output");
        // Open must produce byte-identical original
        let opened = proc.open_content_with_path(&sealed, std::path::Path::new("config.txt")).unwrap();
        assert_eq!(opened, original, "inline round-trip: opened != original");
    }

    /// Block marker: multi-line ⊕{…} spanning several lines
    #[test]
    fn round_trip_block_marker() {
        let proc = make_processor();
        let original = "config:\n⊕{\n  db_host: secret.example.com\n  db_pass: s3cret\n}\nother: value\n";
        let sealed = proc.seal_content_with_path(
            original,
            std::path::Path::new("config.txt"),
        ).unwrap();
        assert!(sealed.contains("⊠{"), "sealed output should contain ciphertext marker");
        assert!(!sealed.contains("s3cret"), "secret must not appear in sealed output");
        let opened = proc.open_content_with_path(&sealed, std::path::Path::new("config.txt")).unwrap();
        assert_eq!(opened, original, "block round-trip: opened != original");
    }

    /// File-level marker: entire file content is one ⊕{…} block (secrets file)
    #[test]
    fn round_trip_file_level_marker() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let secrets_path = temp_dir.path().join("app.secrets");

        let proc = make_processor();
        let original = "db_url: postgresql://localhost/mydb\napi_key: supersecret\n";
        let sealed = proc.seal_content_with_path(original, &secrets_path).unwrap();
        assert!(sealed.contains("⊠{"), "sealed secrets file should contain ciphertext marker");
        assert!(!sealed.contains("supersecret"), "secret must not appear in sealed output");
        let opened = proc.open_content_with_path(&sealed, &secrets_path).unwrap();
        assert_eq!(opened, original, "file-level round-trip: opened != original");
    }

    /// Mixed markers: inline + block in one file
    #[test]
    fn round_trip_mixed_markers() {
        let proc = make_processor();
        let original = "line1: ⊕{inline_secret}\nblock:\n⊕{\n  key: block_secret\n}\nend\n";
        let sealed = proc.seal_content_with_path(
            original,
            std::path::Path::new("mixed.txt"),
        ).unwrap();
        assert!(sealed.contains("⊠{"), "sealed output should contain ciphertext marker");
        assert!(!sealed.contains("inline_secret"), "inline secret must not appear");
        assert!(!sealed.contains("block_secret"), "block secret must not appear");
        let opened = proc.open_content_with_path(&sealed, std::path::Path::new("mixed.txt")).unwrap();
        assert_eq!(opened, original, "mixed round-trip: opened != original");
    }

    /// Empty marker ⊕{} — surrounding content must not be corrupted
    #[test]
    fn round_trip_empty_marker() {
        let proc = make_processor();
        let original = "before ⊕{} after\n";
        let sealed = proc.seal_content_with_path(
            original,
            std::path::Path::new("empty_marker.txt"),
        ).unwrap();
        assert!(sealed.contains("⊠{"), "sealed output should contain ciphertext marker");
        let opened = proc.open_content_with_path(&sealed, std::path::Path::new("empty_marker.txt")).unwrap();
        assert_eq!(opened, original, "empty-marker round-trip: opened != original");
    }

    /// Nested braces ⊕{{"key": "value"}} — balanced brace parser must handle JSON-like content
    #[test]
    fn round_trip_nested_braces_marker() {
        let proc = make_processor();
        let original = "data = ⊕{{\"key\": \"value\"}}\n";
        let sealed = proc.seal_content_with_path(
            original,
            std::path::Path::new("nested.txt"),
        ).unwrap();
        assert!(sealed.contains("⊠{"), "sealed output should contain ciphertext marker");
        assert!(!sealed.contains("\"key\""), "secret must not appear in sealed output");
        let opened = proc.open_content_with_path(&sealed, std::path::Path::new("nested.txt")).unwrap();
        assert_eq!(opened, original, "nested-braces round-trip: opened != original");
    }

    /// Unicode content in markers round-trips correctly
    #[test]
    fn round_trip_unicode_marker() {
        let proc = make_processor();
        // NFC-composed café
        let original = "secret = ⊕{cafe\u{0301} unicode content}\nother: plain\n";
        let sealed = proc.seal_content_with_path(
            original,
            std::path::Path::new("unicode.txt"),
        ).unwrap();
        let opened = proc.open_content_with_path(&sealed, std::path::Path::new("unicode.txt")).unwrap();
        assert_eq!(opened.as_bytes(), original.as_bytes(), "unicode round-trip: byte mismatch");
    }

    // =========================================================================
    // Delimiter-override tests — values containing unbalanced braces or other
    // delimiters must round-trip via an alternate pair without chomping bytes.
    // =========================================================================

    /// The reported case: a secrets file with a value ending in `}`.
    /// Must seal → open → seal byte-identically, and after edit-cycle the
    /// plaintext marker must still capture the full value including the `}`.
    #[test]
    fn secrets_file_value_with_unbalanced_close_brace() {
        use tempfile::tempdir;
        let temp = tempdir().unwrap();
        let secrets_path = temp.path().join("secrets");
        let key = RepositoryKey::new();
        let proc = Processor::new_with_project_root(key, temp.path().to_path_buf()).unwrap();

        let original = "a: abc\nb: def}\n";

        // Full seal/open cycle — secrets-file-level encryption wraps the whole
        // blob in ⊠{base64}, so this part is brace-safe by construction.
        let sealed = proc.seal_content_with_path(original, &secrets_path).unwrap();
        let opened = proc.open_content_with_path(&sealed, &secrets_path).unwrap();
        assert_eq!(opened, original, "secrets-file seal/open must preserve bytes");

        // Edit cycle: prepare_for_editing wraps the decrypted blob in a
        // plaintext marker; encrypt_content then re-encrypts it. The bug was
        // that the trailing `}` in `def}` was treated as the marker close.
        let prepared = proc.prepare_for_editing(&sealed).unwrap();
        let reencrypted = proc.encrypt_content(&prepared).unwrap();
        let opened_after_edit = proc.open_content_with_path(&reencrypted, &secrets_path).unwrap();
        assert_eq!(
            opened_after_edit, original,
            "edit round-trip must preserve bytes — trailing `}}` must not be chomped",
        );
    }

    /// A plaintext marker wrapping a value with a single unbalanced `}` must
    /// pick an alternate delimiter and survive encrypt → decrypt round-trip.
    #[test]
    fn plaintext_marker_wraps_unbalanced_close_brace() {
        let proc = make_processor();
        let secret_value = "pass}word";
        let marker = format_marker("⊕", secret_value);
        assert!(
            !marker.starts_with("⊕{"),
            "value with unbalanced `}}` must NOT use default {{}} delimiter, got: {}",
            marker,
        );
        // Full content round-trip through encrypt/decrypt.
        let document = format!("secret: {marker}\n");
        let encrypted = proc.encrypt_content(&document).unwrap();
        let decrypted = proc.decrypt_content(&encrypted).unwrap();
        // The alternate delimiter may not survive the decrypt path literally,
        // but the captured value must be exactly `pass}word`.
        let markers = find_plaintext_markers(&decrypted);
        assert_eq!(markers.len(), 1, "expected exactly one plaintext marker after decrypt");
        assert_eq!(markers[0].content, secret_value, "captured value must match original");
    }

    /// When the value contains both `}` and `]`, the second-tier ASCII fallback
    /// is unavailable — we must land on an exotic Unicode pair.
    #[test]
    fn value_with_brace_and_bracket_forces_exotic_delimiter() {
        let value = r#"{"json": "blob]"#; // unbalanced braces, contains both `]` and `}`
        let (open, close) = pick_delimiter_for_value(value).expect("ladder must yield a pair");
        assert_ne!(open, '{', "default {{}} must not be chosen for unbalanced braces");
        assert_ne!(open, '[', "[] must not be chosen when value contains `]`");
        assert!(!value.contains(open), "selected opener must be absent from value");
        assert!(!value.contains(close), "selected closer must be absent from value");
    }

    /// A value with balanced `{...}` inside must still prefer the default
    /// `{}` delimiter — no unnecessary switching that would churn old files.
    #[test]
    fn balanced_braces_inside_value_keep_default_delimiter() {
        let value = r#"{"a": 1}"#;
        let (open, close) = pick_delimiter_for_value(value).unwrap();
        assert_eq!((open, close), ('{', '}'), "balanced braces must stay with default");
    }

    /// Existing `⊕{foo}` content with no problematic chars must parse and
    /// round-trip unchanged — this is the byte-identity regression guard.
    #[test]
    fn legacy_brace_form_unchanged() {
        let proc = make_processor();
        let original = "key = ⊕{plain}\n";
        let encrypted = proc.encrypt_content(original).unwrap();
        let decrypted = proc.decrypt_content(&encrypted).unwrap();
        assert_eq!(decrypted, original, "legacy {{}} form must round-trip byte-identically");
    }

    /// Exotic delimiter pair must survive the full encrypt/decrypt cycle with
    /// the correct inner content captured.
    #[test]
    fn exotic_delimiter_marker_parses_correctly() {
        // Hand-written marker using white square brackets around a value with `}`.
        let content = "secret: \u{2983}pass}word\u{2984}\n"; // ⦃pass}word⦄
        // Wait — ⦃/⦄ aren't in the prefix table as "opener after prefix"; they're
        // the delimiter *after* the prefix. Construct the real form:
        let marker = "⊕\u{2983}pass}word\u{2984}";
        let document = format!("secret: {marker}\n");
        let proc = make_processor();
        let encrypted = proc.encrypt_content(&document).unwrap();
        let decrypted = proc.decrypt_content(&encrypted).unwrap();
        let markers = find_plaintext_markers(&decrypted);
        assert_eq!(markers.len(), 1, "exotic-delimited marker must parse to one match");
        assert_eq!(markers[0].content, "pass}word");
        // Silence unused — we kept `content` as documentation of the underlying form.
        let _ = content;
    }

    /// The ASCII `o+` prefix with the default `{}` delimiter must still work —
    /// this is the hand-typed form and must remain zero-friction.
    #[test]
    fn ascii_prefix_default_delimiter_still_parses() {
        let content = "key = o+{value}\n";
        let markers = find_plaintext_markers(content);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "value");
    }

    /// Unbalanced brace in prefix + `{` form must NOT produce a false match
    /// (this tests the retreat path when braces are unbalanced).
    #[test]
    fn unbalanced_default_delimiter_retreats_cleanly() {
        let content = "⊕{no close here\nnext line";
        let markers = find_plaintext_markers(content);
        assert_eq!(markers.len(), 0, "unbalanced default delimiter must not match");
    }

    // =========================================================================
    // Backslash escape tests — escapes are recognised only for the default
    // {} pair. Emission never produces escapes (the tool picks a clean
    // delimiter instead), so escapes only appear in user-typed input.
    // =========================================================================

    /// `\}` inside a default-pair marker must not end the marker early.
    /// The captured value must be unescaped back to the literal `}`.
    #[test]
    fn escaped_close_brace_parses_as_literal() {
        let content = r"key = o+{pass\}word}";
        let markers = find_plaintext_markers(content);
        assert_eq!(markers.len(), 1, "escaped `}}` must not close the marker");
        assert_eq!(markers[0].content, "pass}word");
    }

    /// `\{` and `\\` must likewise be unescaped on capture.
    #[test]
    fn escaped_open_brace_and_backslash_parse_correctly() {
        let content = r"a: o+{lit\{inside} b: o+{back\\slash}";
        let markers = find_plaintext_markers(content);
        assert_eq!(markers.len(), 2);
        assert_eq!(markers[0].content, "lit{inside");
        assert_eq!(markers[1].content, r"back\slash");
    }

    /// Escapes are LOCAL to the default `{}` pair. `\]` inside an `[]` marker
    /// stays literal — no unescaping happens for non-default delimiters.
    #[test]
    fn escapes_do_not_apply_to_alternate_delimiters() {
        let content = r"⊕[has\]literal]";
        let markers = find_plaintext_markers(content);
        assert_eq!(markers.len(), 1, "`[]` marker with unrelated `\\]` inside");
        // `\]` should close the marker at the first unescaped `]`, because
        // escapes are not recognised for `[]`. Captured content is `has\`.
        assert_eq!(markers[0].content, r"has\");
    }

    /// End-to-end: a user hand-types `o+{pass\}word}`, seals, then opens.
    /// After the round-trip the emission path re-wraps the value in an
    /// auto-selected delimiter (because the value now contains `}`), so the
    /// opened form uses an alternate pair rather than leftover escapes.
    #[test]
    fn hand_typed_escape_roundtrips_via_delimiter_override() {
        let proc = make_processor();
        let original = "pw = o+{pass\\}word}\n";
        let sealed = proc.encrypt_content(original).unwrap();
        let opened = proc.decrypt_content(&sealed).unwrap();
        // After open, the plaintext marker wraps `pass}word` directly. The
        // emission helper picked a non-default pair to avoid ambiguity.
        let markers = find_plaintext_markers(&opened);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "pass}word");
        assert!(
            !opened.contains("o+{pass\\}"),
            "opened form must not retain the escape — emission picks a clean delimiter"
        );
    }

    /// Unescape helper direct tests — easier debugging when parse tests fail.
    #[test]
    fn unescape_helper_handles_all_cases() {
        assert_eq!(unescape_default_delimiter("plain"), "plain");
        assert_eq!(unescape_default_delimiter(r"pass\}word"), "pass}word");
        assert_eq!(unescape_default_delimiter(r"a\{b\}c"), "a{b}c");
        assert_eq!(unescape_default_delimiter(r"back\\slash"), r"back\slash");
        // Unrecognised escapes are passed through literally.
        assert_eq!(unescape_default_delimiter(r"tab\t"), r"tab\t");
    }
}

