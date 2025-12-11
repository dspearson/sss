//! Common utilities for filesystem implementations (FUSE, 9P, WinFSP)
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
pub fn has_any_markers(content: &str) -> bool {
    content.contains("⊠{")
        || content.contains("⊕{")
        || content.contains("[*{")
        || content.contains("o+{")
        || content.contains("⊲{")  // Interpolation markers
        || content.contains("<{")   // Alternative interpolation marker syntax
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
}
