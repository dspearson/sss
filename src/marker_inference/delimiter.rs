//! Paired delimiter handling (Step 7)
//!
//! Ensure opening and closing delimiters are both marked or both unmarked.

use super::types::{DelimiterPair, Marker};

/// Validate paired delimiters
///
/// Ensures that both delimiters of a pair are marked or both are unmarked.
/// Returns a list of warnings for any unmatched delimiter pairs.
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

            if open_marked != close_marked {
                // Expand marker to cover both delimiters (conservative)
                expand_marker_to_cover_pair(&pair, markers);
                warnings.push(format!(
                    "Unmatched delimiter pair '{}' at positions {}-{}, expanded marker",
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

/// Expand marker to cover both delimiters of a pair
fn expand_marker_to_cover_pair(pair: &DelimiterPair, markers: &mut Vec<Marker>) {
    // Find markers that overlap the pair
    let overlapping: Vec<usize> = markers
        .iter()
        .enumerate()
        .filter(|(_, m)| {
            (m.source_start <= pair.open_pos && pair.open_pos < m.source_end)
                || (m.source_start <= pair.close_pos && pair.close_pos < m.source_end)
        })
        .map(|(idx, _)| idx)
        .collect();

    if overlapping.is_empty() {
        // No existing marker, create one covering the pair
        markers.push(Marker {
            source_start: pair.open_pos,
            source_end: pair.close_pos + 1,
            rendered_start: pair.open_pos,
            rendered_end: pair.close_pos + 1,
            content: String::new(), // Will be filled by reconstruction
        });
    } else {
        // Expand existing marker(s) to cover both delimiters
        let min_start = overlapping
            .iter()
            .map(|&idx| markers[idx].source_start)
            .min()
            .unwrap()
            .min(pair.open_pos);
        let max_end = overlapping
            .iter()
            .map(|&idx| markers[idx].source_end)
            .max()
            .unwrap()
            .max(pair.close_pos + 1);

        // Remove old markers (in reverse order to preserve indices)
        for &idx in overlapping.iter().rev() {
            markers.remove(idx);
        }

        // Add expanded marker
        markers.push(Marker {
            source_start: min_start,
            source_end: max_end,
            rendered_start: min_start,
            rendered_end: max_end,
            content: String::new(), // Will be filled by reconstruction
        });
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
