//! Marker parsing (Step 1)
//!
//! Extract all `o+{...}` and `⊕{...}` markers from source text and generate rendered version.
#![allow(clippy::unnecessary_wraps)] // Result return matches module-wide error handling contract

use super::error::Result;
use super::marker_syntax::{
    contains_nested_markers, detect_marker_start, find_unescaped_close, is_escaped_marker,
    MarkerFormat,
};
use super::types::Marker;

/// Parse markers from source text
///
/// Returns (`rendered_text`, markers) where:
/// - `rendered_text`: Source with markers removed (what user sees)
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
        let remaining = &source[source_pos..];

        // Check for escaped markers first
        if let Some((escaped, len)) = is_escaped_marker(remaining) {
            rendered.push_str(escaped);
            source_pos += len;
            rendered_pos += len;
            continue;
        }

        // Check for marker start
        if let Some(format) = detect_marker_start(remaining) {
            let marker_start = source_pos;
            let prefix_len = format.prefix_len();
            let content_start = source_pos + prefix_len;

            // Find matching closing brace
            if let Some(close_pos) = find_unescaped_close(&source[content_start..]) {
                let abs_close = content_start + close_pos;
                let content = &source[content_start..abs_close];

                // Check for nested markers (not allowed)
                if contains_nested_markers(content) {
                    handle_nested_marker(format, content, &mut rendered, &mut rendered_pos);
                    source_pos = abs_close + 1;
                } else {
                    // Valid marker - add to list
                    add_valid_marker(
                        &mut markers,
                        marker_start,
                        abs_close + 1,
                        rendered_pos,
                        content,
                    );
                    rendered.push_str(content);
                    rendered_pos += content.len();
                    source_pos = abs_close + 1;
                }
            } else {
                // Unclosed marker - escape it
                rendered.push_str(format.escaped());
                source_pos += prefix_len;
                rendered_pos += format.escaped().len();
            }
        } else {
            // Regular character - copy it
            let ch = remaining.chars().next().unwrap();
            rendered.push(ch);
            let ch_len = ch.len_utf8();
            source_pos += ch_len;
            rendered_pos += ch_len;
        }
    }

    Ok((rendered, markers))
}

/// Handle a nested marker by escaping it
fn handle_nested_marker(
    format: MarkerFormat,
    content: &str,
    rendered: &mut String,
    rendered_pos: &mut usize,
) {
    rendered.push_str(format.escaped());
    rendered.push_str(content);
    rendered.push('}');
    *rendered_pos += format.escaped().len() + content.len() + 1;
}

/// Add a valid marker to the markers list
fn add_valid_marker(
    markers: &mut Vec<Marker>,
    marker_start: usize,
    marker_end: usize,
    rendered_start: usize,
    content: &str,
) {
    markers.push(Marker {
        source_start: marker_start,
        source_end: marker_end,
        rendered_start,
        rendered_end: rendered_start + content.len(),
        content: content.to_string(),
    });
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
