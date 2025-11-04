//! Diff computation (Step 2)
//!
//! Compute the differences between rendered and edited text using the similar crate.

use super::error::Result;
use super::types::ChangeHunk;
use similar::{ChangeTag, TextDiff};

/// Compute diff between rendered and edited text
///
/// Returns a vector of ChangeHunk structs representing the modifications.
pub fn compute_diff(rendered: &str, edited: &str) -> Result<Vec<ChangeHunk>> {
    let diff = TextDiff::from_chars(rendered, edited);
    let mut changes = Vec::new();
    let mut current_change: Option<ChangeHunk> = None;

    let mut rendered_pos = 0;

    for change in diff.iter_all_changes() {
        let value = change.value();

        match change.tag() {
            ChangeTag::Equal => {
                // Flush any current change
                if let Some(ch) = current_change.take() {
                    changes.push(ch);
                }
                // Advance positions
                rendered_pos += value.len();
            }
            ChangeTag::Delete => {
                // Start or extend change
                if let Some(ref mut ch) = current_change {
                    ch.old_content.push_str(value);
                    ch.rendered_end = rendered_pos + value.len();
                } else {
                    current_change = Some(ChangeHunk {
                        rendered_start: rendered_pos,
                        rendered_end: rendered_pos + value.len(),
                        old_content: value.to_string(),
                        new_content: String::new(),
                    });
                }
                rendered_pos += value.len();
            }
            ChangeTag::Insert => {
                // Start or extend change
                if let Some(ref mut ch) = current_change {
                    ch.new_content.push_str(value);
                } else {
                    current_change = Some(ChangeHunk {
                        rendered_start: rendered_pos,
                        rendered_end: rendered_pos,
                        old_content: String::new(),
                        new_content: value.to_string(),
                    });
                }
                // Note: edited_pos tracking not needed for current algorithm
            }
        }
    }

    // Flush any remaining change
    if let Some(ch) = current_change {
        changes.push(ch);
    }

    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_changes() {
        let changes = compute_diff("hello world", "hello world").unwrap();
        assert_eq!(changes.len(), 0);
    }

    #[test]
    fn test_simple_replacement() {
        // Use strings with no common characters to ensure single change
        let changes = compute_diff("abc", "xyz").unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_content, "abc");
        assert_eq!(changes[0].new_content, "xyz");
        assert_eq!(changes[0].rendered_start, 0);
        assert_eq!(changes[0].rendered_end, 3);
    }

    #[test]
    fn test_insertion() {
        let changes = compute_diff("hello", "hello world").unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_content, "");
        assert_eq!(changes[0].new_content, " world");
    }

    #[test]
    fn test_deletion() {
        let changes = compute_diff("hello world", "hello").unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_content, " world");
        assert_eq!(changes[0].new_content, "");
    }

    #[test]
    fn test_multiple_changes() {
        let changes = compute_diff("a b c", "a x c").unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_content, "b");
        assert_eq!(changes[0].new_content, "x");
    }
}
