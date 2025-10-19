/// Smart merge and reconstruction algorithms for sss
///
/// This module provides intelligent merging of encrypted content with edited versions,
/// preserving encryption markers for unchanged lines while handling additions/deletions.
use anyhow::Result;
use similar::TextDiff;

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
    let opened_old_lines: Vec<&str> = opened_old.lines().collect();
    let diff = TextDiff::from_lines(rendered_old, rendered_new);

    let mut result_lines = Vec::new();
    let mut old_line_idx = 0;

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Equal => {
                // Line unchanged - use old version with markers intact
                if old_line_idx < opened_old_lines.len() {
                    result_lines.push(opened_old_lines[old_line_idx].to_string());
                    old_line_idx += 1;
                }
            }
            similar::ChangeTag::Insert => {
                // Line added - use as-is (no markers)
                result_lines.push(change.value().trim_end_matches('\n').to_string());
            }
            similar::ChangeTag::Delete => {
                // Line deleted - skip it
                old_line_idx += 1;
            }
        }
    }

    Ok(result_lines.join("\n"))
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

        // First line changed, marker is lost (intentional - line was modified)
        // Second line unchanged, marker preserved
        assert_eq!(result, "password: newsecret\nhost: example.com");
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
