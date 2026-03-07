//! User marker validation (Step 3)
//!
//! Validate and escape invalid user-inserted markers in edited text.

use super::marker_syntax::{
    contains_nested_markers, detect_marker_start, find_unescaped_close, is_escaped_marker,
    MarkerFormat,
};
use super::types::{UserMarker, ValidatedEdit};

/// Validate user-inserted markers in edited text
///
/// Validates markers and escapes invalid ones. Returns `ValidatedEdit` with:
/// - text: Edited text with invalid markers escaped
/// - `user_markers`: Valid user-inserted markers
/// - warnings: List of validation warnings
pub fn validate_user_markers(edited: &str) -> ValidatedEdit {
    let mut validated = String::new();
    let mut user_markers = Vec::new();
    let mut warnings = Vec::new();
    let mut pos = 0;

    while pos < edited.len() {
        let remaining = &edited[pos..];

        // Check for escaped markers first
        if let Some((escaped, len)) = is_escaped_marker(remaining) {
            validated.push_str(escaped);
            pos += len;
            continue;
        }

        // Check for marker start
        if let Some((format, open, close)) = detect_marker_start(remaining) {
            pos = process_marker(
                edited,
                format,
                open,
                close,
                pos,
                &mut validated,
                &mut user_markers,
                &mut warnings,
            );
        } else {
            // Regular character
            let ch = remaining.chars().next().unwrap();
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

/// Process a detected marker (valid or invalid)
fn process_marker(
    edited: &str,
    format: MarkerFormat,
    open: char,
    close: char,
    pos: usize,
    validated: &mut String,
    user_markers: &mut Vec<UserMarker>,
    warnings: &mut Vec<String>,
) -> usize {
    let marker_start = pos;
    // Header is the prefix ("o+" / "⊕") plus the opening delimiter char.
    let header_len = format.prefix_len() + open.len_utf8();
    let content_start = pos + header_len;

    if let Some(close_pos) = find_unescaped_close(&edited[content_start..], close) {
        let abs_close = content_start + close_pos;
        let content = &edited[content_start..abs_close];
        let marker_end = abs_close + close.len_utf8();

        if contains_nested_markers(content) {
            // Nested markers - escape and warn
            handle_nested_user_marker(format, content, content_start, validated, warnings);
            marker_end
        } else {
            // Valid marker - add to list
            add_user_marker(
                &edited[marker_start..marker_end],
                header_len,
                content,
                validated,
                user_markers,
            );
            marker_end
        }
    } else {
        // Unclosed marker - escape and warn
        handle_unclosed_marker(format, marker_start, validated, warnings);
        pos + header_len
    }
}

/// Handle a marker with nested markers by escaping the inner ones
fn handle_nested_user_marker(
    format: MarkerFormat,
    content: &str,
    content_start: usize,
    validated: &mut String,
    warnings: &mut Vec<String>,
) {
    let escaped_content = content.replace("o+{", "o+\\{").replace("⊕{", "⊕\\{");

    validated.push_str(format.prefix());
    validated.push_str(&escaped_content);
    validated.push('}');
    warnings.push(format!(
        "Escaped nested marker at position {content_start}"
    ));
}

/// Handle an unclosed marker by escaping it
fn handle_unclosed_marker(
    format: MarkerFormat,
    marker_start: usize,
    validated: &mut String,
    warnings: &mut Vec<String>,
) {
    validated.push_str(format.escaped());
    warnings.push(format!(
        "Escaped unclosed marker at position {marker_start}"
    ));
}

/// Add a valid user marker to the list
fn add_user_marker(
    _marker_text: &str,
    _prefix_len: usize,
    content: &str,
    validated: &mut String,
    user_markers: &mut Vec<UserMarker>,
) {
    // Record the position where content will be in the validated text
    let marker_start = validated.len();
    user_markers.push(UserMarker {
        start: marker_start,
        end: marker_start + content.len(), // Just the content, no marker syntax
        content: content.to_string(),
    });
    // Only add the CONTENT to validated text, not the marker syntax
    // The reconstructor will add ⊕{...} markers later
    validated.push_str(content);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_marker() {
        let result = validate_user_markers("text o+{secret} more");
        // Marker syntax should be stripped, only content remains
        assert_eq!(result.text, "text secret more");
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
