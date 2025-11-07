//! Change mapping to source positions (Step 4)
//!
//! Map changes from rendered coordinates back to source coordinates.

use super::types::{ChangeHunk, Marker, MappedChange, Position};

/// Map changes from rendered coordinates to source coordinates
pub fn map_changes_to_source(
    changes: Vec<ChangeHunk>,
    markers: &[Marker],
) -> Vec<MappedChange> {
    let mut mapped = Vec::new();

    for change in changes {
        // Find all markers that overlap or are adjacent to this change
        let overlapping: Vec<usize> = markers
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                ranges_overlap_or_adjacent(
                    m.rendered_start,
                    m.rendered_end,
                    change.rendered_start,
                    change.rendered_end,
                )
            })
            .map(|(idx, _)| idx)
            .collect();

        // Convert rendered positions to source positions
        let source_start = rendered_to_source_pos(change.rendered_start, markers);
        let source_end = rendered_to_source_pos(change.rendered_end, markers);

        mapped.push(MappedChange {
            source_start,
            source_end,
            rendered_start: change.rendered_start,
            rendered_end: change.rendered_end,
            new_content: change.new_content,
            overlapping_markers: overlapping,
        });
    }

    mapped
}

/// Check if two ranges overlap or are adjacent
fn ranges_overlap_or_adjacent(
    start1: usize,
    end1: usize,
    start2: usize,
    end2: usize,
) -> bool {
    // Overlap: ranges share any positions
    // Adjacent: end of one equals start of the other
    !(end1 < start2 || end2 < start1) || end1 == start2 || end2 == start1
}

/// Convert rendered position to source position
fn rendered_to_source_pos(rendered_pos: Position, markers: &[Marker]) -> Position {
    let mut source_pos = rendered_pos;

    // Add marker syntax overhead for all markers before this position
    for marker in markers {
        if marker.rendered_start < rendered_pos {
            // Calculate the overhead added by this marker
            let marker_overhead =
                (marker.source_end - marker.source_start) - (marker.rendered_end - marker.rendered_start);
            source_pos += marker_overhead;
        }
    }

    source_pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap_or_adjacent(0, 5, 3, 8));
        assert!(ranges_overlap_or_adjacent(3, 8, 0, 5));
    }

    #[test]
    fn test_ranges_adjacent() {
        assert!(ranges_overlap_or_adjacent(0, 5, 5, 10));
        assert!(ranges_overlap_or_adjacent(5, 10, 0, 5));
    }

    #[test]
    fn test_ranges_separate() {
        assert!(!ranges_overlap_or_adjacent(0, 5, 6, 10));
        assert!(!ranges_overlap_or_adjacent(6, 10, 0, 5));
    }

    #[test]
    fn test_rendered_to_source_pos() {
        let markers = vec![
            Marker {
                source_start: 0,
                source_end: 10,  // "o+{secret}" = 10 bytes
                rendered_start: 0,
                rendered_end: 6,  // "secret" = 6 bytes
                content: "secret".to_string(),
            },
        ];

        // Position 6 in rendered is position 10 in source (after the marker)
        assert_eq!(rendered_to_source_pos(6, &markers), 10);
    }
}
