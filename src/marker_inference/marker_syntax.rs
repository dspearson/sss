//! Shared marker syntax utilities
//!
//! Common functions for detecting, parsing, and handling marker syntax
//! used by both parser.rs and validator.rs.

/// Marker format type
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MarkerFormat {
    /// o+{...} format (easy to type)
    OPlus,
    /// ⊕{...} format (canonical)
    Circled,
}

impl MarkerFormat {
    /// Length of the opening syntax in bytes
    pub fn prefix_len(self) -> usize {
        match self {
            MarkerFormat::OPlus => 3,   // "o+{"
            MarkerFormat::Circled => "⊕{".len(),
        }
    }

    /// Opening syntax as string
    pub fn prefix(self) -> &'static str {
        match self {
            MarkerFormat::OPlus => "o+{",
            MarkerFormat::Circled => "⊕{",
        }
    }

    /// Escaped form of the opening syntax
    pub fn escaped(self) -> &'static str {
        match self {
            MarkerFormat::OPlus => "o+\\{",
            MarkerFormat::Circled => "⊕\\{",
        }
    }

    /// Length of the escaped form in bytes
    #[allow(dead_code)]
    pub fn escaped_len(self) -> usize {
        match self {
            MarkerFormat::OPlus => 4,   // "o+\\{"
            MarkerFormat::Circled => "⊕\\{".len(),
        }
    }
}

/// Detect marker format at current position
///
/// Returns Some(format) if text starts with marker opening, None otherwise.
pub fn detect_marker_start(text: &str) -> Option<MarkerFormat> {
    if text.starts_with("o+{") {
        Some(MarkerFormat::OPlus)
    } else if text.starts_with("⊕{") {
        Some(MarkerFormat::Circled)
    } else {
        None
    }
}

/// Check if position starts with escaped marker
///
/// Returns Some((escaped_str, byte_len)) if text starts with escaped marker.
pub fn is_escaped_marker(text: &str) -> Option<(&'static str, usize)> {
    if text.starts_with("o+\\{") {
        Some(("o+\\{", 4))
    } else if text.starts_with("⊕\\{") {
        Some(("⊕\\{", "⊕\\{".len()))
    } else {
        None
    }
}

/// Find the position of the first unescaped closing brace
///
/// Skips over escaped braces (\}) and returns the byte offset of the
/// first unescaped } character, or None if not found.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(find_unescaped_close("hello}"), Some(5));
/// assert_eq!(find_unescaped_close("text \\} more}"), Some(12));
/// assert_eq!(find_unescaped_close("no closing"), None);
/// ```
pub fn find_unescaped_close(text: &str) -> Option<usize> {
    let mut pos = 0;
    while pos < text.len() {
        if text[pos..].starts_with("\\}") {
            // Escaped closing brace - skip it
            pos += 2;
        } else if text[pos..].starts_with('}') {
            // Unescaped closing brace - found it
            return Some(pos);
        } else {
            // Regular character - advance by UTF-8 character length
            let ch = text[pos..].chars().next().unwrap();
            pos += ch.len_utf8();
        }
    }
    None
}

/// Check if content contains nested marker syntax
///
/// Returns true if the content contains any marker opening (o+{ or ⊕{).
pub fn contains_nested_markers(content: &str) -> bool {
    content.contains("o+{") || content.contains("⊕{")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_format_methods() {
        assert_eq!(MarkerFormat::OPlus.prefix_len(), 3);
        assert_eq!(MarkerFormat::Circled.prefix_len(), "⊕{".len());
        assert_eq!(MarkerFormat::OPlus.prefix(), "o+{");
        assert_eq!(MarkerFormat::Circled.prefix(), "⊕{");
        assert_eq!(MarkerFormat::OPlus.escaped(), "o+\\{");
        assert_eq!(MarkerFormat::Circled.escaped(), "⊕\\{");
    }

    #[test]
    fn test_detect_marker_start() {
        assert_eq!(detect_marker_start("o+{test}"), Some(MarkerFormat::OPlus));
        assert_eq!(detect_marker_start("⊕{test}"), Some(MarkerFormat::Circled));
        assert_eq!(detect_marker_start("regular text"), None);
        assert_eq!(detect_marker_start("o+\\{escaped}"), None);
    }

    #[test]
    fn test_is_escaped_marker() {
        assert_eq!(is_escaped_marker("o+\\{test}"), Some(("o+\\{", 4)));
        assert_eq!(is_escaped_marker("⊕\\{test}"), Some(("⊕\\{", "⊕\\{".len())));
        assert_eq!(is_escaped_marker("o+{test}"), None);
        assert_eq!(is_escaped_marker("regular"), None);
    }

    #[test]
    fn test_find_unescaped_close() {
        assert_eq!(find_unescaped_close("hello}"), Some(5));
        assert_eq!(find_unescaped_close("text \\} more}"), Some(12));
        assert_eq!(find_unescaped_close("no closing"), None);
        assert_eq!(find_unescaped_close("日本語}"), Some("日本語".len()));
    }

    #[test]
    fn test_contains_nested_markers() {
        assert!(contains_nested_markers("outer o+{inner}"));
        assert!(contains_nested_markers("outer ⊕{inner}"));
        assert!(!contains_nested_markers("no markers here"));
        assert!(!contains_nested_markers("o+\\{escaped}"));
    }
}
