//! User marker validation (Step 3)
//!
//! Validate and escape invalid user-inserted markers in edited text.

use super::types::{UserMarker, ValidatedEdit};

/// Validate user-inserted markers in edited text
///
/// Validates markers and escapes invalid ones. Returns ValidatedEdit with:
/// - text: Edited text with invalid markers escaped
/// - user_markers: Valid user-inserted markers
/// - warnings: List of validation warnings
pub fn validate_user_markers(edited: &str) -> ValidatedEdit {
    let mut validated = String::new();
    let mut user_markers = Vec::new();
    let mut warnings = Vec::new();
    let mut pos = 0;

    while pos < edited.len() {
        // Check for escaped markers
        if edited[pos..].starts_with("o+\\{") {
            validated.push_str("o+\\{");
            pos += 4;
            continue;
        } else if edited[pos..].starts_with("⊕\\{") {
            validated.push_str("⊕\\{");
            pos += "⊕\\{".len();
            continue;
        }

        // Check for marker start
        let is_oplus = edited[pos..].starts_with("o+{");
        let is_circled = edited[pos..].starts_with("⊕{");

        if is_oplus || is_circled {
            let marker_start = pos;
            let prefix_len = if is_oplus { 3 } else { "⊕{".len() };

            if let Some(close_pos) = find_matching_close(&edited[pos + prefix_len..]) {
                let content_start = pos + prefix_len;
                let abs_close = content_start + close_pos;
                let content = &edited[content_start..abs_close];

                // Check for nested markers
                if content.contains("o+{") || content.contains("⊕{") {
                    // Nested markers - escape inner markers
                    let escaped_content = content
                        .replace("o+{", "o+\\{")
                        .replace("⊕{", "⊕\\{");

                    if is_oplus {
                        validated.push_str("o+{");
                    } else {
                        validated.push_str("⊕{");
                    }
                    validated.push_str(&escaped_content);
                    validated.push('}');
                    pos = abs_close + 1;
                    warnings.push(format!("Escaped nested marker at position {}", content_start));
                } else {
                    // Valid marker
                    user_markers.push(UserMarker {
                        start: validated.len(),
                        end: validated.len() + prefix_len + content.len() + 1,
                        content: content.to_string(),
                    });
                    validated.push_str(&edited[marker_start..abs_close + 1]);
                    pos = abs_close + 1;
                }
            } else {
                // Unclosed marker - escape it
                if is_oplus {
                    validated.push_str("o+\\{");
                    pos += 3;
                } else {
                    validated.push_str("⊕\\{");
                    pos += "⊕{".len();
                }
                warnings.push(format!("Escaped unclosed marker at position {}", marker_start));
            }
        } else {
            // Regular character
            let ch = edited[pos..].chars().next().unwrap();
            validated.push(ch);
            pos += ch.len_utf8();
        }
    }

    ValidatedEdit {
        text: validated,
        user_markers,
        warnings,
    }
}

/// Find the position of matching closing brace
fn find_matching_close(text: &str) -> Option<usize> {
    let mut pos = 0;
    while pos < text.len() {
        if text[pos..].starts_with("\\}") {
            pos += 2;
        } else if text[pos..].starts_with('}') {
            return Some(pos);
        } else {
            let ch = text[pos..].chars().next().unwrap();
            pos += ch.len_utf8();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_marker() {
        let result = validate_user_markers("text o+{secret} more");
        assert_eq!(result.text, "text o+{secret} more");
        assert_eq!(result.user_markers.len(), 1);
        assert_eq!(result.user_markers[0].content, "secret");
        assert_eq!(result.warnings.len(), 0);
    }

    #[test]
    fn test_unclosed_marker() {
        let result = validate_user_markers("text o+{unclosed");
        assert_eq!(result.text, "text o+\\{unclosed");
        assert_eq!(result.user_markers.len(), 0);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_nested_marker() {
        let result = validate_user_markers("o+{outer o+{inner}}");
        assert!(result.text.contains("o+\\{inner"));
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_already_escaped() {
        let result = validate_user_markers("o+\\{literal}");
        assert_eq!(result.text, "o+\\{literal}");
        assert_eq!(result.user_markers.len(), 0);
        assert_eq!(result.warnings.len(), 0);
    }
}
