/// Marker match structure for brace-counting parser
///
/// Represents a matched marker in content with its position and captured content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerMatch {
    /// Start position of the entire marker (including prefix)
    pub start: usize,
    /// End position of the entire marker (including closing brace)
    pub end: usize,
    /// The captured content between braces
    pub content: String,
}

/// Find markers with balanced brace counting
///
/// Supports nested braces like `o+{a:{}}` or `⊕{{"key":"value"}}`.
/// This function scans through content looking for marker prefixes followed by balanced braces.
///
/// # Arguments
/// * `content` - The text content to search for markers
/// * `prefixes` - List of marker prefixes to search for (e.g., ["⊕", "⊠", "o+"])
///
/// # Returns
/// Vector of `MarkerMatch` instances found in the content, in order of appearance
///
/// # Algorithm
/// 1. Scan through content byte-by-byte
/// 2. Try to match each prefix at the current position
/// 3. If prefix matches and is followed by `{`, start brace counting
/// 4. Track brace depth: increment on `{`, decrement on `}`
/// 5. When depth reaches 0, we've found the matching closing brace
/// 6. Extract the content between the braces and create a MarkerMatch
///
/// # Examples
/// ```
/// use sss::processor::find_balanced_markers;
///
/// let content = "Hello ⊕{world} and ⊠{nested:{value}}";
/// let matches = find_balanced_markers(content, &["⊕", "⊠"]);
/// assert_eq!(matches.len(), 2);
/// assert_eq!(matches[0].content, "world");
/// assert_eq!(matches[1].content, "nested:{value}");
/// ```
pub fn find_balanced_markers(content: &str, prefixes: &[&str]) -> Vec<MarkerMatch> {
    let mut matches = Vec::new();
    let bytes = content.as_bytes();
    let mut byte_pos = 0;

    while byte_pos < bytes.len() {
        // Try to match each prefix at current position
        if let Some((_prefix, marker)) = try_match_marker_at_position(content, byte_pos, prefixes) {
            byte_pos = marker.end;
            matches.push(marker);
        } else {
            // No match, advance by one UTF-8 character
            byte_pos += advance_one_char(&content[byte_pos..]);
        }
    }

    matches
}

/// Try to match a marker at the given position
///
/// # Returns
/// `Some((prefix, marker))` if a marker was found, `None` otherwise
fn try_match_marker_at_position<'a>(
    content: &'a str,
    byte_pos: usize,
    prefixes: &'a [&'a str],
) -> Option<(&'a str, MarkerMatch)> {
    let remaining = &content[byte_pos..];

    // Try each prefix
    for &prefix in prefixes {
        if let Some(marker) = try_parse_marker_with_prefix(content, byte_pos, prefix, remaining) {
            return Some((prefix, marker));
        }
    }

    None
}

/// Try to parse a marker starting with the given prefix
fn try_parse_marker_with_prefix(
    content: &str,
    byte_pos: usize,
    prefix: &str,
    remaining: &str,
) -> Option<MarkerMatch> {
    // Check if prefix matches
    let after_prefix = remaining.strip_prefix(prefix)?;

    // Check if followed by '{'
    if !after_prefix.starts_with('{') {
        return None;
    }

    // Parse the balanced braces
    parse_balanced_braces(content, byte_pos, prefix.len())
}

/// Parse balanced braces starting from the given position
///
/// Assumes we're positioned at the opening '{' after the prefix.
fn parse_balanced_braces(content: &str, marker_start: usize, prefix_len: usize) -> Option<MarkerMatch> {
    let mut byte_pos = marker_start + prefix_len; // Skip past prefix

    // Should be at '{'
    if !content[byte_pos..].starts_with('{') {
        return None;
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

                    return Some(MarkerMatch {
                        start: marker_start,
                        end: marker_end,
                        content: captured_content,
                    });
                }
            }
            _ => {}
        }
    }

    // Unbalanced braces - no match
    None
}

/// Advance by one UTF-8 character
///
/// Returns the number of bytes in the first character.
fn advance_one_char(s: &str) -> usize {
    if let Some(ch) = s.chars().next() {
        ch.len_utf8()
    } else {
        1 // Fallback (should not happen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_simple_markers() {
        let content = "Hello ⊕{world} and ⊠{test}";
        let matches = find_balanced_markers(content, &["⊕", "⊠"]);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].content, "world");
        assert_eq!(matches[1].content, "test");
    }

    #[test]
    fn test_find_nested_markers() {
        let content = "Nested ⊕{outer:{inner}} marker";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "outer:{inner}");
    }

    #[test]
    fn test_find_deeply_nested_markers() {
        let content = r#"⊕{{"key":{"nested":"value"}}}"#;
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, r#"{"key":{"nested":"value"}}"#);
    }

    #[test]
    fn test_find_multiple_prefixes() {
        let content = "⊕{plain} and ⊠{sealed} and o+{opened}";
        let matches = find_balanced_markers(content, &["⊕", "⊠", "o+"]);

        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].content, "plain");
        assert_eq!(matches[1].content, "sealed");
        assert_eq!(matches[2].content, "opened");
    }

    #[test]
    fn test_no_markers() {
        let content = "No markers here";
        let matches = find_balanced_markers(content, &["⊕", "⊠"]);

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_unbalanced_braces() {
        let content = "⊕{unbalanced content";
        let matches = find_balanced_markers(content, &["⊕"]);

        // Should not match unbalanced braces
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_marker_positions() {
        let content = "Start ⊕{test} end";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 6); // Position of ⊕ (after "Start ")
        assert_eq!(matches[0].end, 15); // Position after } (⊕ is 3 bytes + {test} is 6 bytes)
        assert_eq!(&content[matches[0].start..matches[0].end], "⊕{test}");
    }

    #[test]
    fn test_empty_content() {
        let content = "";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_empty_marker() {
        let content = "⊕{}";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "");
    }

    #[test]
    fn test_marker_at_start() {
        let content = "⊕{start} text";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "start");
        assert_eq!(matches[0].start, 0);
    }

    #[test]
    fn test_marker_at_end() {
        let content = "text ⊕{end}";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "end");
        assert_eq!(matches[0].end, content.len());
    }

    #[test]
    fn test_consecutive_markers() {
        let content = "⊕{first}⊕{second}";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].content, "first");
        assert_eq!(matches[1].content, "second");
    }

    #[test]
    fn test_prefix_without_brace() {
        let content = "⊕ without brace and ⊕{with brace}";
        let matches = find_balanced_markers(content, &["⊕"]);

        // Should only match the second one
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "with brace");
    }

    #[test]
    fn test_utf8_content() {
        let content = "⊕{日本語} and ⊕{emoji:🎉}";
        let matches = find_balanced_markers(content, &["⊕"]);

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].content, "日本語");
        assert_eq!(matches[1].content, "emoji:🎉");
    }
}
