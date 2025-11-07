//! Content propagation (Step 6)
//!
//! Find all unmarked instances of marked content and mark them.

use super::types::Marker;
use aho_corasick::AhoCorasick;
use std::collections::HashSet;

/// Propagate markers to all unmarked duplicates
///
/// If any instance of content is marked, all instances must be marked for security.
pub fn propagate_markers(text: &str, markers: &[Marker]) -> Vec<Marker> {
    let mut result = markers.to_vec();
    let mut seen_content = HashSet::new();

    // Collect all unique marked content
    for marker in markers {
        if !marker.content.is_empty() {
            seen_content.insert(marker.content.clone());
        }
    }

    if seen_content.is_empty() {
        return result;
    }

    // Use Aho-Corasick for efficient multi-pattern matching
    let patterns: Vec<&str> = seen_content.iter().map(|s| s.as_str()).collect();

    // Build the automaton - return early if patterns are empty or invalid
    let ac = match AhoCorasick::new(&patterns) {
        Ok(ac) => ac,
        Err(_) => return result,
    };

    // Find all occurrences
    for mat in ac.find_iter(text) {
        let start = mat.start();
        let end = mat.end();
        let pattern_idx = mat.pattern().as_usize();
        let content = patterns[pattern_idx];

        // Check if this position is already marked
        if !is_position_marked(start, end, &result) {
            result.push(Marker {
                source_start: start,
                source_end: end,
                rendered_start: start,
                rendered_end: end,
                content: content.to_string(),
            });
        }
    }

    // Sort markers by position
    result.sort_by_key(|m| m.source_start);

    result
}

/// Check if a position range is already marked
fn is_position_marked(start: usize, end: usize, markers: &[Marker]) -> bool {
    markers.iter().any(|m| {
        // Check if [start, end) is fully contained within marker
        m.source_start <= start && end <= m.source_end
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_propagate_to_duplicate() {
        let text = "secret and secret";
        let markers = vec![Marker {
            source_start: 0,
            source_end: 6,
            rendered_start: 0,
            rendered_end: 6,
            content: "secret".to_string(),
        }];

        let result = propagate_markers(text, &markers);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].source_start, 0);
        assert_eq!(result[1].source_start, 11);
    }

    #[test]
    fn test_no_duplicates() {
        let text = "unique content here";
        let markers = vec![Marker {
            source_start: 0,
            source_end: 6,
            rendered_start: 0,
            rendered_end: 6,
            content: "unique".to_string(),
        }];

        let result = propagate_markers(text, &markers);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_empty_markers() {
        let text = "some text";
        let markers = vec![];

        let result = propagate_markers(text, &markers);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_already_marked_duplicate() {
        let text = "secret and secret";
        let markers = vec![
            Marker {
                source_start: 0,
                source_end: 6,
                rendered_start: 0,
                rendered_end: 6,
                content: "secret".to_string(),
            },
            Marker {
                source_start: 11,
                source_end: 17,
                rendered_start: 11,
                rendered_end: 17,
                content: "secret".to_string(),
            },
        ];

        let result = propagate_markers(text, &markers);
        // Should not add duplicates
        assert_eq!(result.len(), 2);
    }
}
