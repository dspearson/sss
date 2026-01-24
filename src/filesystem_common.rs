//! Common utilities for filesystem implementations (FUSE, 9P, `WinFSP`)
//!
//! This module provides shared functionality used across different filesystem
//! backends to avoid code duplication.

/// Check if content contains encrypted SSS markers (⊠{})
///
/// This is used to determine if a file needs decryption.
///
/// # Examples
///
/// ```
/// use sss::filesystem_common::has_encrypted_markers;
///
/// assert!(has_encrypted_markers("Some ⊠{encrypted} text"));
/// assert!(!has_encrypted_markers("Plain text"));
/// ```
#[must_use] 
pub fn has_encrypted_markers(content: &str) -> bool {
    content.contains("⊠{")
}

/// Check if content contains any SSS markers (encrypted, plaintext, OR interpolation)
///
/// This checks for all marker types:
/// - `⊠{}` - Sealed/encrypted markers
/// - `⊕{}` - Opened/plaintext markers (canonical form)
/// - `o+{}` - Opened/plaintext markers (ASCII alternative)
/// - `[*{}` - Legacy marker syntax
/// - `⊲{}` - Interpolation markers (secrets references)
/// - `<{}` - Alternative interpolation marker syntax
///
/// # Examples
///
/// ```
/// use sss::filesystem_common::has_any_markers;
///
/// assert!(has_any_markers("⊠{encrypted}"));
/// assert!(has_any_markers("⊕{plaintext}"));
/// assert!(has_any_markers("o+{plaintext}"));
/// assert!(has_any_markers("⊲{secret_ref}"));
/// assert!(!has_any_markers("No markers here"));
/// ```
#[must_use] 
pub fn has_any_markers(content: &str) -> bool {
    content.contains("⊠{")
        || content.contains("⊕{")
        || content.contains("[*{")
        || content.contains("o+{")
        || content.contains("⊲{")  // Interpolation markers
        || content.contains("<{")   // Alternative interpolation marker syntax
}

/// Check if content contains well-formed (balanced) SSS markers.
///
/// Unlike `has_any_markers` which only checks for opening sequences like `⊠{`,
/// this verifies at least one marker has balanced braces (e.g. `⊠{...}`).
/// Files that merely mention marker characters in strings or grep patterns
/// will return false, avoiding false-positive processing.
#[must_use] 
pub fn has_balanced_markers(content: &str) -> bool {
    // Prefixes to look for, in order of priority
    const PREFIXES: &[&str] = &["⊠", "⊕", "⊲", "[*", "o+", "<"];

    let bytes = content.as_bytes();
    let mut byte_pos = 0;

    while byte_pos < bytes.len() {
        let remaining = &content[byte_pos..];

        let mut matched = false;
        for &prefix in PREFIXES {
            if let Some(after_prefix) = remaining.strip_prefix(prefix)
                && after_prefix.starts_with('{') {
                    // Found a potential marker opening — check for balanced close
                    let open_pos = byte_pos + prefix.len() + 1; // past prefix + '{'
                    let mut depth = 1u32;
                    for (i, ch) in content[open_pos..].char_indices() {
                        match ch {
                            '{' => depth += 1,
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    // Must have non-empty content
                                    if i > 0 {
                                        return true;
                                    }
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    // Unbalanced — skip past this prefix+'{' and keep scanning
                    byte_pos = open_pos;
                    matched = true;
                    break;
                }
        }

        if !matched {
            if let Some(ch) = remaining.chars().next() {
                byte_pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    false
}

/// Marker patterns as byte sequences for efficient scanning
/// This avoids String conversion for files without markers
pub const MARKER_PATTERNS: &[&str] = &["⊠{", "⊕{", "[*{", "o+{", "⊲{", "<{"];

/// Check if raw bytes contain any SSS markers
///
/// This performs byte-level scanning to detect markers without UTF-8 conversion,
/// which is faster and preserves exact file content for non-marked files.
///
/// All marker types are checked:
/// - `⊠{` - Sealed/encrypted markers (3-byte UTF-8: \xe2\x8a\xa0)
/// - `⊕{` - Opened/plaintext markers (3-byte UTF-8: \xe2\x8a\x95)
/// - `⊲{` - Interpolation markers (3-byte UTF-8: \xe2\x8a\xb2)
/// - `[*{` - Legacy marker syntax (2-byte ASCII)
/// - `o+{` - ASCII alternative markers (2-byte ASCII)
/// - `<{` - Alternative interpolation syntax (2-byte ASCII)
///
/// # Examples
///
/// ```
/// use sss::filesystem_common::has_any_markers_bytes;
///
/// assert!(has_any_markers_bytes("⊠{encrypted}".as_bytes()));
/// assert!(has_any_markers_bytes("⊕{plaintext}".as_bytes()));
/// assert!(has_any_markers_bytes("⊲{secret}".as_bytes()));
/// assert!(!has_any_markers_bytes(b"No markers"));
/// ```
#[must_use] 
pub fn has_any_markers_bytes(bytes: &[u8]) -> bool {
    // Define all marker byte sequences
    // Note: UTF-8 sequences for Unicode markers are 3 bytes followed by '{'
    const MARKER_BYTES: &[&[u8]] = &[
        b"\xe2\x8a\xa0{",  // ⊠{  (sealed/encrypted)
        b"\xe2\x8a\x95{",  // ⊕{  (opened/plaintext)
        b"\xe2\x8a\xb2{",  // ⊲{  (interpolation)
        b"[*{",            // [*{ (legacy)
        b"o+{",            // o+{ (ASCII alternative)
        b"<{",             // <{  (alternative interpolation)
    ];

    // Check for each marker pattern
    for marker in MARKER_BYTES {
        if bytes.windows(marker.len()).any(|w| w == *marker) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_encrypted_markers() {
        assert!(has_encrypted_markers("Some ⊠{secret} text"));
        assert!(has_encrypted_markers("⊠{encrypted}"));
        assert!(!has_encrypted_markers("Plain text"));
        assert!(!has_encrypted_markers("⊕{plaintext}"));
    }

    #[test]
    fn test_has_any_markers() {
        assert!(has_any_markers("⊠{sealed}"));
        assert!(has_any_markers("⊕{opened}"));
        assert!(has_any_markers("o+{ascii}"));
        assert!(has_any_markers("[*{legacy}"));
        assert!(has_any_markers("⊲{interpolation}"));
        assert!(has_any_markers("<{interpolation}"));
        assert!(!has_any_markers("No markers"));
    }

    #[test]
    fn test_multiple_markers() {
        assert!(has_any_markers("Text ⊠{a} and ⊕{b}"));
        assert!(has_encrypted_markers("⊠{a} ⊠{b}"));
    }

    #[test]
    fn test_has_any_markers_bytes() {
        // Test all marker types
        assert!(has_any_markers_bytes("⊠{sealed}".as_bytes()));
        assert!(has_any_markers_bytes("⊕{opened}".as_bytes()));
        assert!(has_any_markers_bytes("⊲{interpolation}".as_bytes()));
        assert!(has_any_markers_bytes(b"[*{legacy}"));
        assert!(has_any_markers_bytes(b"o+{ascii}"));
        assert!(has_any_markers_bytes(b"<{alt}"));

        // Test no markers
        assert!(!has_any_markers_bytes(b"No markers here"));
        assert!(!has_any_markers_bytes(b"Plain text file"));

        // Test partial matches should not trigger
        assert!(!has_any_markers_bytes(b"\xe2\x8a\xa0"));  // ⊠ without {
        assert!(!has_any_markers_bytes(b"[*"));             // [* without {
        assert!(!has_any_markers_bytes(b"<"));              // < without {
    }

    #[test]
    fn test_marker_detection_consistency() {
        // Verify byte and string versions stay in sync
        for marker in MARKER_PATTERNS {
            let content = format!("test {}secret}}", marker);
            assert!(has_any_markers(&content), "String version should detect marker: {}", marker);
            assert!(has_any_markers_bytes(content.as_bytes()), "Byte version should detect marker: {}", marker);
        }
    }

    #[test]
    fn test_byte_detection_with_binary_data() {
        // Test that markers are detected even in files with binary data
        let mut data = vec![0x00, 0xFF, 0x7F];
        data.extend_from_slice("⊠{secret}".as_bytes());
        data.extend_from_slice(&[0x00, 0x01, 0x02]);
        assert!(has_any_markers_bytes(&data));
    }
}
