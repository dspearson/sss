//! Diff computation (Step 2)
//!
//! Compute the differences between rendered and edited text using the similar crate.
#![allow(clippy::unnecessary_wraps)] // Result return matches trait/API contract for error propagation

use super::error::Result;
use super::types::ChangeHunk;
use similar::{ChangeTag, TextDiff};

/// Compute diff between rendered and edited text
///
/// Uses the Myers diff algorithm to find the minimal set of changes.
/// Consecutive insertions and deletions are merged into single `ChangeHunk` entries.
///
/// Returns a vector of `ChangeHunk` structs representing the modifications.
pub fn compute_diff(rendered: &str, edited: &str) -> Result<Vec<ChangeHunk>> {
    let diff = TextDiff::from_chars(rendered, edited);
    let mut changes = Vec::new();
    let mut pending_change: Option<ChangeHunk> = None;
    let mut rendered_pos = 0;

    for change in diff.iter_all_changes() {
        let value = change.value();

        match change.tag() {
            ChangeTag::Equal => {
                // Equal sections mark change boundaries - flush any pending change
                flush_pending_change(&mut pending_change, &mut changes);
                rendered_pos += value.len();
            }
            ChangeTag::Delete => {
                // Deletion: content removed from rendered text
                handle_deletion(
                    value,
                    rendered_pos,
                    &mut pending_change,
                );
                rendered_pos += value.len();
            }
            ChangeTag::Insert => {
                // Insertion: content added to edited text (no rendered position change)
                handle_insertion(value, rendered_pos, &mut pending_change);
            }
        }
    }

    // Flush any remaining pending change
    flush_pending_change(&mut pending_change, &mut changes);

    Ok(changes)
}

/// Flush a pending change to the changes list
fn flush_pending_change(pending: &mut Option<ChangeHunk>, changes: &mut Vec<ChangeHunk>) {
    if let Some(ch) = pending.take() {
        changes.push(ch);
    }
}

/// Handle a deletion in the diff
fn handle_deletion(value: &str, rendered_pos: usize, pending: &mut Option<ChangeHunk>) {
    if let Some(ch) = pending {
        // Extend existing change with more deleted content
        ch.old_content.push_str(value);
        ch.rendered_end = rendered_pos + value.len();
    } else {
        // Start new change
        *pending = Some(ChangeHunk {
            rendered_start: rendered_pos,
            rendered_end: rendered_pos + value.len(),
            old_content: value.to_string(),
            new_content: String::new(),
        });
    }
}

/// Handle an insertion in the diff
fn handle_insertion(value: &str, rendered_pos: usize, pending: &mut Option<ChangeHunk>) {
    if let Some(ch) = pending {
        // Extend existing change with inserted content
        ch.new_content.push_str(value);
    } else {
        // Start new change (pure insertion)
        *pending = Some(ChangeHunk {
            rendered_start: rendered_pos,
            rendered_end: rendered_pos,
            old_content: String::new(),
            new_content: value.to_string(),
        });
    }
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
