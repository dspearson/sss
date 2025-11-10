//! Paired delimiter handling (Step 7)
//!
//! Ensure opening and closing delimiters are both marked or both unmarked.

use super::types::{DelimiterPair, Marker};

/// Validate paired delimiters
///
/// Ensures that both delimiters of a pair are excluded from markers per spec section 8.
/// Returns a list of warnings for any delimiter pairs that were adjusted.
pub fn validate_delimiters(text: &str, markers: &mut Vec<Marker>) -> Vec<String> {
    let mut warnings = Vec::new();
    let pairs = vec![
        ('"', '"'),
        ('\'', '\''),
        ('[', ']'),
        ('{', '}'),
        ('(', ')'),
        ('<', '>'),
    ];

    for (open, close) in pairs {
        let delimiter_pairs = find_delimiter_pairs(text, open, close);

        for pair in delimiter_pairs {
            let open_marked = is_char_marked(pair.open_pos, markers);
            let close_marked = is_char_marked(pair.close_pos, markers);

            // Per spec section 8: delimiters should be OUTSIDE markers
            // If either delimiter is marked, shrink marker to exclude both
            if open_marked || close_marked {
                shrink_marker_to_exclude_pair(&pair, markers);
                warnings.push(format!(
                    "Delimiter pair '{}' at positions {}-{}, shrunk marker to exclude delimiters (per spec section 8)",
                    open, pair.open_pos, pair.close_pos
                ));
            }
        }
    }

    warnings
}

/// Find all paired delimiters in text
fn find_delimiter_pairs(text: &str, open: char, close: char) -> Vec<DelimiterPair> {
    let mut pairs = Vec::new();

    // Handle symmetric delimiters (like quotes) differently
    if open == close {
        let mut in_pair = false;
        let mut pair_start = 0;

        for (pos, ch) in text.char_indices() {
            if ch == open {
                if in_pair {
                    // Closing delimiter
                    pairs.push(DelimiterPair {
                        open_pos: pair_start,
                        close_pos: pos,
                        open_char: open,
                        close_char: close,
                    });
                    in_pair = false;
                } else {
                    // Opening delimiter
                    pair_start = pos;
                    in_pair = true;
                }
            }
        }
    } else {
        // Asymmetric delimiters use stack-based matching
        let mut stack = Vec::new();

        for (pos, ch) in text.char_indices() {
            if ch == open {
                stack.push(pos);
            } else if ch == close
                && let Some(open_pos) = stack.pop() {
                    pairs.push(DelimiterPair {
                        open_pos,
                        close_pos: pos,
                        open_char: open,
                        close_char: close,
                    });
                }
        }
    }

    // Process innermost pairs first (shortest span)
    pairs.sort_by_key(|p| p.close_pos - p.open_pos);

    pairs
}

/// Check if a character position is marked
fn is_char_marked(pos: usize, markers: &[Marker]) -> bool {
    markers
        .iter()
        .any(|m| m.source_start <= pos && pos < m.source_end)
}

/// Shrink marker to exclude both delimiters of a pair (per spec section 8)
fn shrink_marker_to_exclude_pair(pair: &DelimiterPair, markers: &mut Vec<Marker>) {
    // Find markers that include either delimiter
    let indices_to_update: Vec<usize> = markers
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            // Check if marker includes the opening delimiter
            let includes_open = m.source_start <= pair.open_pos && pair.open_pos < m.source_end;
            // Check if marker includes the closing delimiter
            let includes_close = m.source_start <= pair.close_pos && pair.close_pos < m.source_end;
            includes_open || includes_close
        })
        .map(|(idx, _)| idx)
        .collect();

    // Update each marker to exclude both delimiters
    for idx in indices_to_update.iter().rev() {
        let marker = &mut markers[*idx];

        // Shrink to exclude delimiters
        let mut new_start = marker.source_start;
        let mut new_end = marker.source_end;

        // If opening delimiter is at or before start, move start past it
        if new_start <= pair.open_pos && pair.open_pos < new_end {
            new_start = pair.open_pos + 1;
        }

        // If closing delimiter is before or at end, move end before it
        if new_start <= pair.close_pos && pair.close_pos < new_end {
            new_end = pair.close_pos;
        }

        // Update marker if it still has content after shrinking
        if new_start < new_end {
            marker.source_start = new_start;
            marker.source_end = new_end;
            marker.rendered_start = new_start;
            marker.rendered_end = new_end;
            // Clear content so reconstructor re-extracts from text with new boundaries
            marker.content.clear();
        } else {
            // Marker would be empty after shrinking, remove it
            markers.remove(*idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_delimiter_pairs() {
        let pairs = find_delimiter_pairs("\"hello\"", '"', '"');
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].open_pos, 0);
        assert_eq!(pairs[0].close_pos, 6);
    }

    #[test]
    fn test_nested_pairs() {
        let pairs = find_delimiter_pairs("[a [b] c]", '[', ']');
        assert_eq!(pairs.len(), 2);
        // Innermost first
        assert_eq!(pairs[0].open_pos, 3);
        assert_eq!(pairs[0].close_pos, 5);
    }

    #[test]
    fn test_is_char_marked() {
        let markers = vec![Marker {
            source_start: 0,
            source_end: 5,
            rendered_start: 0,
            rendered_end: 5,
            content: "hello".to_string(),
        }];

        assert!(is_char_marked(0, &markers));
        assert!(is_char_marked(2, &markers));
        assert!(is_char_marked(4, &markers));
        assert!(!is_char_marked(5, &markers));
        assert!(!is_char_marked(10, &markers));
    }
}
