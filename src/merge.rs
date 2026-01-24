//! Smart merge and reconstruction algorithms for sss
//!
//! This module provides intelligent merging of encrypted content with edited versions,
//! preserving encryption markers for unchanged lines while handling additions/deletions.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_many_lines,      // reconstruction functions are long by necessity
    clippy::format_collect,      // push_str(&format!()) kept for readability in marker building
)]

use anyhow::Result;
use std::fmt::Write as FmtWrite;
use similar::TextDiff;
use regex::Regex;

/// Count the number of complete markers in content (both ⊕{} and ⊠{})
fn count_markers(content: &str) -> usize {
    // Use DOTALL mode to match multiline markers
    let marker_re = Regex::new(r"(?s)(⊕|⊠)\{.*?\}").unwrap();
    marker_re.find_iter(content).count()
}

/// Check if markers are balanced (count opening vs closing)
fn markers_balanced(content: &str) -> bool {
    let opening_count = content.matches("⊕{").count() + content.matches("⊠{").count();

    // Count closing braces that are part of markers
    // This is approximate - we're checking if we have at least as many complete markers
    let complete_markers = count_markers(content);

    // If we have opening markers but no complete markers, they're unbalanced
    if opening_count > 0 && complete_markers == 0 {
        return false;
    }

    // If we have unclosed markers
    if opening_count > complete_markers {
        return false;
    }

    true
}

/// Simple check: does content have any marker indicators
fn has_markers(content: &str) -> bool {
    content.contains("⊕{") || content.contains("⊠{") ||
    content.contains("o+{") || content.contains("[*{")
}

/// Reconstruct a line with markers - handles both single and multi-marker lines
///
/// Algorithm: Text inserted adjacent to a marker region should be included in that marker
fn reconstruct_multimarker_line(old_opened: &str, old_rendered: &str, new_rendered: &str) -> Option<String> {
    // Parse markers from old_opened to build a map of which positions are in markers
    // Returns: Vec<(start_pos_in_rendered, end_pos_in_rendered, marker_type)>
    let mut marker_regions = Vec::new();
    let mut rendered_pos = 0;

    // Use a simpler approach: find all markers with balanced braces
    let marker_re = Regex::new(r"(?s)(⊕|⊠|o\+|\[\*)\{").unwrap();

    let mut search_start = 0;
    while let Some(mat) = marker_re.find_at(old_opened, search_start) {
        let marker_start = mat.start();
        let marker_type = &old_opened[marker_start..mat.end()-1]; // Exclude the {
        let mut i = mat.end();
        let mut brace_count = 1;
        let content_start = i;

        // Find matching closing brace
        let chars: Vec<char> = old_opened.chars().collect();
        while i < chars.len() && brace_count > 0 {
            if chars[i] == '{' {
                brace_count += 1;
            } else if chars[i] == '}' {
                brace_count -= 1;
            }
            if brace_count > 0 {
                i += 1;
            }
        }

        if brace_count == 0 {
            // Successfully found matching brace at position i
            let content_end = i;
            let content: String = chars[content_start..content_end].iter().collect();

            // rendered_pos tracks where we are in the rendered string
            // Add non-marker text before this marker
            let prefix_len = old_opened[search_start..marker_start].chars().count();
            rendered_pos += prefix_len;

            // Add this marker region
            let content_len = content.chars().count();
            marker_regions.push((rendered_pos, rendered_pos + content_len, marker_type.to_string()));
            rendered_pos += content_len;

            search_start = i + 1; // Skip past closing brace
        } else {
            // Unmatched brace
            return None;
        }
    }

    // Now use character-level diff to reconstruct with markers
    let diff = similar::TextDiff::from_chars(old_rendered, new_rendered);
    let mut result = String::new();
    let mut old_pos = 0;
    let mut current_marker: Option<String> = None;
    let mut marker_content = String::new();

    for change in diff.iter_all_changes() {
        let ch = change.value().chars().next().unwrap();

        match change.tag() {
            similar::ChangeTag::Equal => {
                // Check if this position is in a marker
                let in_marker = marker_regions.iter()
                    .find(|(start, end, _)| old_pos >= *start && old_pos < *end)
                    .map(|(_, _, marker_type)| marker_type.clone());

                if let Some(marker_type) = in_marker {
                    // Inside marker
                    if current_marker.as_ref() == Some(&marker_type) {
                        // Continue same marker
                        marker_content.push(ch);
                    } else {
                        // Close previous marker if any
                        if let Some(prev_marker) = current_marker.take() {
                            let _ = write!(result, "{prev_marker}{{{marker_content}}}");
                            marker_content.clear();
                        }
                        // Start new marker
                        current_marker = Some(marker_type);
                        marker_content.push(ch);
                    }
                } else {
                    // Not in marker
                    // Close previous marker if any
                    if let Some(prev_marker) = current_marker.take() {
                        let _ = write!(result, "{prev_marker}{{{marker_content}}}");
                        marker_content.clear();
                    }
                    result.push(ch);
                }

                old_pos += 1;
            }
            similar::ChangeTag::Delete => {
                old_pos += 1;
            }
            similar::ChangeTag::Insert => {
                // Inserted text: check if adjacent position (left or right) is in a marker
                // Edge case: if both left AND right are in markers (inserting between markers),
                // don't include in either marker

                let left_marker = if old_pos > 0 {
                    marker_regions.iter()
                        .find(|(start, end, _)| old_pos > *start && old_pos <= *end)
                        .map(|(_, _, marker_type)| marker_type.clone())
                } else {
                    None
                };

                let right_marker = marker_regions.iter()
                    .find(|(start, end, _)| old_pos >= *start && old_pos < *end)
                    .map(|(_, _, marker_type)| marker_type.clone());

                // If between different markers, prefer left marker (include in first marker for security)
                // Otherwise use whichever marker is adjacent
                let adjacent_marker = match (left_marker.as_ref(), right_marker.as_ref()) {
                    (Some(left), Some(right)) if left != right => Some(left.clone()), // Between different markers - use left
                    (Some(marker), _) | (_, Some(marker)) => Some(marker.clone()), // Adjacent to one marker
                    (None, None) => None, // Not adjacent to any marker
                };

                if let Some(marker_type) = adjacent_marker {
                    // Adjacent to marker, include in marker
                    if current_marker.as_ref() == Some(&marker_type) {
                        marker_content.push(ch);
                    } else {
                        // Close previous marker if any
                        if let Some(prev_marker) = current_marker.take() {
                            let _ = write!(result, "{prev_marker}{{{marker_content}}}");
                            marker_content.clear();
                        }
                        // Start new marker with this inserted char
                        current_marker = Some(marker_type);
                        marker_content.push(ch);
                    }
                } else {
                    // Not adjacent to any marker (or between different markers)
                    // Close previous marker if any
                    if let Some(prev_marker) = current_marker.take() {
                        let _ = write!(result, "{prev_marker}{{{marker_content}}}");
                        marker_content.clear();
                    }
                    result.push(ch);
                }
            }
        }
    }

    // Close final marker if any
    if let Some(marker_type) = current_marker {
        let _ = write!(result, "{marker_type}{{{marker_content}}}");
    }

    Some(result)
}

/// Smart reconstruction: given new rendered content, reconstruct markers from old version
///
/// This algorithm preserves encryption markers (⊕{} or ⊠{}) for unchanged lines,
/// enabling clean git diffs and avoiding unnecessary re-encryption.
///
/// # Algorithm
///
/// 1. Diff `rendered_old` vs `rendered_new` to identify changes
/// 2. For EQUAL lines: use old version with markers intact
/// 3. For INSERT lines: use new content as-is (no markers)
/// 4. For DELETE lines: skip them
///
/// # Arguments
///
/// * `rendered_new` - New content after editing (fully rendered, no markers)
/// * `opened_old` - Old content with plaintext markers (⊕{plaintext})
/// * `rendered_old` - Old content fully rendered (no markers) for comparison
///
/// # Returns
///
/// Reconstructed content with markers preserved for unchanged lines
///
/// # Example
///
/// ```text
/// rendered_old:  "password: secret123\nhost: example.com"
/// opened_old:    "password: ⊕{secret123}\nhost: example.com"
/// rendered_new:  "password: secret123\nhost: example.com\ntimeout: 30"
///
/// Result:        "password: ⊕{secret123}\nhost: example.com\ntimeout: 30"
///                            ^^^^^^^^^^^^^^ marker preserved!  ^^^^^^^^^^^^^^ new line, no marker
/// ```
pub fn smart_reconstruct(
    rendered_new: &str,
    opened_old: &str,
    rendered_old: &str,
) -> Result<String> {
    // Special case: if the entire old content was a single marker (possibly multiline), preserve it
    let marker_re = Regex::new(r"(?s)^(⊕|⊠)\{(.*)\}$").unwrap(); // (?s) = DOTALL mode
    let opened_old_trimmed = opened_old.trim();
    let rendered_old_trimmed = rendered_old.trim();

    if let Some(captures) = marker_re.captures(opened_old_trimmed) {
        let old_content = &captures[2];
        // Check if the rendered old content matches what was inside the marker
        if old_content == rendered_old_trimmed {
            // The entire file was a single encrypted value (possibly multiline)
            // Wrap the new content in a plaintext marker
            return Ok(format!("⊕{{{}}}", rendered_new.trim()));
        }
    }

    // General case: line-by-line diff
    let opened_old_lines: Vec<&str> = opened_old.lines().collect();
    let rendered_old_lines: Vec<&str> = rendered_old.lines().collect();
    let diff = TextDiff::from_lines(rendered_old, rendered_new);

    let mut result_lines = Vec::new();
    let mut old_line_idx = 0;
    let mut pending_delete: Option<(usize, &str, &str)> = None; // (index, opened, rendered)

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Equal => {
                pending_delete = None;
                // Line unchanged - use old version with markers intact
                if old_line_idx < opened_old_lines.len() {
                    result_lines.push(opened_old_lines[old_line_idx].to_string());
                    old_line_idx += 1;
                }
            }
            similar::ChangeTag::Delete => {
                // Remember this deletion in case next is an insert (modification)
                let opened = if old_line_idx < opened_old_lines.len() {
                    opened_old_lines[old_line_idx]
                } else {
                    ""
                };
                let rendered = if old_line_idx < rendered_old_lines.len() {
                    rendered_old_lines[old_line_idx]
                } else {
                    ""
                };
                pending_delete = Some((old_line_idx, opened, rendered));
                old_line_idx += 1;
            }
            similar::ChangeTag::Insert => {
                let new_line = change.value().trim_end_matches('\n');

                // Check if this insert follows a delete (likely a modification)
                if let Some((_idx, old_opened, old_rendered)) = pending_delete {
                    pending_delete = None;

                    // Check if the old line was entirely within a marker
                    if let Some(caps) = marker_re.captures(old_opened.trim()) {
                        let old_content = &caps[2];
                        if old_content == old_rendered.trim() {
                            // Old line was entirely encrypted, wrap new content too
                            result_lines.push(format!("⊕{{{new_line}}}"));
                            continue;
                        }
                    }

                    // Check if old line had any markers (partial markers)
                    // If so, try to preserve marker on the changed content
                    // This implements: "region being written, if inside a marker, extend that marker"
                    if has_markers(old_opened) {
                        // Try to reconstruct multi-marker lines by mapping rendered positions to markers
                        if let Some(reconstructed) = reconstruct_multimarker_line(old_opened, old_rendered, new_line) {
                            result_lines.push(reconstructed);
                            continue;
                        }
                        // Fallback: treat as new line without markers
                        result_lines.push(new_line.to_string());
                        continue;
                    }
                }

                // Default: insert without markers
                pending_delete = None;
                result_lines.push(new_line.to_string());
            }
        }
    }

    let result = result_lines.join("\n");

    // Safety check: ensure markers are properly balanced
    // This prevents broken markers like "⊕{test content" with no closing brace
    if has_markers(&result) && !markers_balanced(&result) {
        // Markers are unbalanced - fall back to wrapping entire content
        return Ok(format!("⊕{{{}}}", rendered_new.trim()));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_reconstruct_unchanged() {
        let rendered_old = "password: secret123\nhost: example.com";
        let opened_old = "password: ⊕{secret123}\nhost: example.com";
        let rendered_new = "password: secret123\nhost: example.com";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // All lines unchanged, markers should be preserved
        assert_eq!(result, "password: ⊕{secret123}\nhost: example.com");
    }

    #[test]
    fn test_smart_reconstruct_addition() {
        let rendered_old = "password: secret123\nhost: example.com";
        let opened_old = "password: ⊕{secret123}\nhost: example.com";
        let rendered_new = "password: secret123\nhost: example.com\ntimeout: 30";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // New line added, should have no marker
        assert_eq!(result, "password: ⊕{secret123}\nhost: example.com\ntimeout: 30");
    }

    #[test]
    fn test_smart_reconstruct_change() {
        let rendered_old = "password: secret123\nhost: example.com";
        let opened_old = "password: ⊕{secret123}\nhost: example.com";
        let rendered_new = "password: newsecret\nhost: example.com";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // First line changed - marker is extended to cover the new content
        // Following the principle: "region being written, if inside a marker, extend that marker"
        // Second line unchanged
        assert_eq!(result, "password: ⊕{newsecret}\nhost: example.com");
    }

    #[test]
    fn test_smart_reconstruct_single_line_entirely_encrypted() {
        // Test the case from the user's example
        let rendered_old = "test content";
        let opened_old = "⊕{test content}";
        let rendered_new = "test edited content here";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // Entire file was encrypted, should preserve marker around new content
        assert_eq!(result, "⊕{test edited content here}");
    }

    #[test]
    fn test_smart_reconstruct_multiline_marker() {
        // Test multiline marker (user's bug report)
        let rendered_old = "test content\nhere";
        let opened_old = "⊕{test content\nhere}";
        let rendered_new = "test content";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // Entire file was a multiline encrypted marker, should preserve marker
        assert_eq!(result, "⊕{test content}");
    }

    #[test]
    fn test_smart_reconstruct_prevents_marker_loss() {
        // Test that we don't lose markers during complex edits
        let rendered_old = "line1\nline2\nline3";
        let opened_old = "⊕{line1}\n⊕{line2}\n⊕{line3}";
        let rendered_new = "line1\nnewline\nline3";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // We had 3 markers, if we lose some, fallback to wrapping entire content
        let result_marker_count = count_markers(&result);
        assert!(result_marker_count >= 3 || result == "⊕{line1\nnewline\nline3}");
    }

    #[test]
    fn test_smart_reconstruct_prevents_unbalanced_markers() {
        // Simulate a case where line-by-line diff would create unbalanced markers
        // This would happen if we have ⊕{multiline\ncontent} and delete the content line
        let rendered_old = "multiline\ncontent";
        let opened_old = "⊕{multiline\ncontent}";
        // Line-by-line would try to keep "⊕{multiline" and delete "content}"
        // But we prevent this

        let rendered_new = "multiline";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // Must be balanced - either keep full marker or wrap entire content
        assert!(markers_balanced(&result));
        // Should be: ⊕{multiline}
        assert_eq!(result, "⊕{multiline}");
    }

    #[test]
    fn test_smart_reconstruct_line_entirely_encrypted() {
        // Test multi-line file where one line is entirely encrypted
        let rendered_old = "host: example.com\nsecret123\nport: 8080";
        let opened_old = "host: example.com\n⊕{secret123}\nport: 8080";
        let rendered_new = "host: example.com\nnewsecret456\nport: 8080";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // Middle line was entirely encrypted and changed, should preserve marker
        assert_eq!(result, "host: example.com\n⊕{newsecret456}\nport: 8080");
    }

    #[test]
    fn test_smart_reconstruct_deletion() {
        let rendered_old = "password: secret123\napi_key: key456\nhost: example.com";
        let opened_old = "password: ⊕{secret123}\napi_key: ⊕{key456}\nhost: example.com";
        let rendered_new = "password: secret123\nhost: example.com";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // Middle line deleted, markers preserved for remaining lines
        assert_eq!(result, "password: ⊕{secret123}\nhost: example.com");
    }

    #[test]
    fn test_smart_reconstruct_multiple_changes() {
        let rendered_old = "password: secret123\napi_key: key456\nhost: example.com";
        let opened_old = "password: ⊕{secret123}\napi_key: ⊕{key456}\nhost: example.com";
        let rendered_new = "password: secret123\napi_key: newkey\nhost: newhost.com\ntimeout: 30";

        let result = smart_reconstruct(rendered_new, opened_old, rendered_old).unwrap();

        // password: unchanged, marker preserved
        // api_key: changed, marker lost
        // host: changed, no marker to preserve
        // timeout: added, no marker
        assert_eq!(result, "password: ⊕{secret123}\napi_key: newkey\nhost: newhost.com\ntimeout: 30");
    }
}
