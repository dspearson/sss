//! Marker parsing (Step 1)
//!
//! Extract all `o+{...}` and `⊕{...}` markers from source text and generate rendered version.

use super::error::Result;
use super::types::Marker;

/// Parse markers from source text
///
/// Returns (rendered_text, markers) where:
/// - rendered_text: Source with markers removed (what user sees)
/// - markers: Vector of Marker structs with position information
///
/// # Examples
///
/// ```ignore
/// let (rendered, markers) = parse_markers("text o+{secret} more").unwrap();
/// assert_eq!(rendered, "text secret more");
/// assert_eq!(markers.len(), 1);
/// ```
pub fn parse_markers(source: &str) -> Result<(String, Vec<Marker>)> {
    let mut markers = Vec::new();
    let mut rendered = String::new();
    let mut source_pos = 0;
    let mut rendered_pos = 0;

    while source_pos < source.len() {
        // Check for escaped markers (both formats)
        if source[source_pos..].starts_with("o+\\{") {
            // Escaped o+{ format
            rendered.push_str("o+\\{");
            source_pos += 4;
            rendered_pos += 4;
        } else if source[source_pos..].starts_with("⊕\\{") {
            // Escaped ⊕{ format
            rendered.push_str("⊕\\{");
            source_pos += "⊕\\{".len();
            rendered_pos += "⊕\\{".len();
        } else if source[source_pos..].starts_with("o+{") || source[source_pos..].starts_with("⊕{") {
            // Potential marker start (either format)
            let is_oplus = source[source_pos..].starts_with("o+{");
            let marker_start = source_pos;
            let prefix_len = if is_oplus { 3 } else { "⊕{".len() };
            let content_start = source_pos + prefix_len;

            // Find matching }
            if let Some(close_pos) = find_unescaped_close(&source[content_start..]) {
                let abs_close = content_start + close_pos;
                let content = &source[content_start..abs_close];

                // Check for nested markers (both formats)
                if content.contains("o+{") || content.contains("⊕{") {
                    // Nested markers not allowed - escape the outer marker and skip entire marker
                    if is_oplus {
                        rendered.push_str("o+\\{");
                        rendered_pos += 4;
                    } else {
                        rendered.push_str("⊕\\{");
                        rendered_pos += "⊕\\{".len();
                    }
                    // Add the content and closing brace
                    rendered.push_str(content);
                    rendered.push('}');
                    rendered_pos += content.len() + 1;
                    source_pos = abs_close + 1;
                } else {
                    // Valid marker
                    markers.push(Marker {
                        source_start: marker_start,
                        source_end: abs_close + 1,
                        rendered_start: rendered_pos,
                        rendered_end: rendered_pos + content.len(),
                        content: content.to_string(),
                    });
                    rendered.push_str(content);
                    rendered_pos += content.len();
                    source_pos = abs_close + 1;
                }
            } else {
                // Unclosed marker - escape it
                if is_oplus {
                    rendered.push_str("o+\\{");
                    source_pos += 3;
                    rendered_pos += 4;
                } else {
                    rendered.push_str("⊕\\{");
                    source_pos += "⊕{".len();
                    rendered_pos += "⊕\\{".len();
                }
            }
        } else {
            // Regular character
            let ch = source[source_pos..].chars().next().unwrap();
            rendered.push(ch);
            let ch_len = ch.len_utf8();
            source_pos += ch_len;
            rendered_pos += ch_len;
        }
    }

    Ok((rendered, markers))
}

/// Find the position of the first unescaped closing brace
fn find_unescaped_close(text: &str) -> Option<usize> {
    let mut pos = 0;
    while pos < text.len() {
        if text[pos..].starts_with("\\}") {
            // Escaped closing brace
            pos += 2;
        } else if text[pos..].starts_with('}') {
            return Some(pos);
        } else {
            // Advance by one character
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
    fn test_parse_simple_marker() {
        let (rendered, markers) = parse_markers("text o+{secret} more").unwrap();
        assert_eq!(rendered, "text secret more");
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "secret");
        assert_eq!(markers[0].source_start, 5);
        assert_eq!(markers[0].source_end, 15); // Fixed: exclusive end position
    }

    #[test]
    fn test_parse_escaped_marker() {
        let (rendered, markers) = parse_markers("text o+\\{literal}").unwrap();
        assert_eq!(rendered, "text o+\\{literal}");
        assert_eq!(markers.len(), 0);
    }

    #[test]
    fn test_parse_unclosed_marker() {
        let (rendered, markers) = parse_markers("text o+{unclosed").unwrap();
        assert_eq!(rendered, "text o+\\{unclosed");
        assert_eq!(markers.len(), 0);
    }

    #[test]
    fn test_parse_nested_marker() {
        let (rendered, markers) = parse_markers("o+{outer o+{inner}}").unwrap();
        // Outer should be escaped due to nesting
        assert_eq!(rendered, "o+\\{outer o+{inner}}");
        assert_eq!(markers.len(), 0);
    }

    #[test]
    fn test_parse_both_formats() {
        let (rendered, markers) = parse_markers("o+{a} ⊕{b}").unwrap();
        assert_eq!(rendered, "a b");
        assert_eq!(markers.len(), 2);
        assert_eq!(markers[0].content, "a");
        assert_eq!(markers[1].content, "b");
    }

    #[test]
    fn test_parse_empty_marker() {
        let (rendered, markers) = parse_markers("o+{}").unwrap();
        assert_eq!(rendered, "");
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "");
    }

    #[test]
    fn test_parse_unicode() {
        let (rendered, markers) = parse_markers("o+{日本語}").unwrap();
        assert_eq!(rendered, "日本語");
        assert_eq!(markers[0].content, "日本語");
    }

    #[test]
    fn test_parse_escaped_close_brace() {
        let (rendered, markers) = parse_markers("o+{text \\} more}").unwrap();
        assert_eq!(rendered, "text \\} more");
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].content, "text \\} more");
    }
}
