//! Marker expansion rules (Step 5)
//!
//! Apply the 5 core expansion rules to determine which content should be marked.

use super::types::{Marker, MappedChange, UserMarker};

/// Apply expansion rules to determine which content should be marked
///
/// # Rules
///
/// 1. **Replacement of Marked Content**: Change spans multiple markers → mark entire span
/// 2. **Adjacent Modifications**: Change adjacent to single marker → expand that marker
/// 3. **Ambiguous Adjacency (Left-Bias)**: Adjacent to multiple markers → merge with left
/// 4. **Preservation of Separate Markers**: Change affects only one → preserve separation
/// 5. **Unmarked Content Modifications**: No adjacent/overlapping markers → handled by propagation
pub fn apply_expansion_rules(
    changes: Vec<MappedChange>,
    original_markers: &[Marker],
    user_markers: &[UserMarker],
    edited_text: &str,
) -> Vec<Marker> {
    // Convert user markers to standard Marker format
    let mut all_source_markers = original_markers.to_vec();

    // Add user markers as new markers
    for um in user_markers {
        all_source_markers.push(Marker {
            source_start: um.start,
            source_end: um.end,
            rendered_start: um.start,
            rendered_end: um.end,
            content: um.content.clone(),
        });
    }

    // Group changes by their overlapping markers
    use std::collections::HashMap;
    let mut marker_changes: HashMap<Vec<usize>, Vec<&MappedChange>> = HashMap::new();

    for change in &changes {
        let key = change.overlapping_markers.clone();
        marker_changes.entry(key).or_insert_with(Vec::new).push(change);
    }

    let mut new_markers = Vec::new();

    for (overlapping, grouped_changes) in marker_changes {
        if overlapping.is_empty() {
            // Rule 5: Unmarked content modification
            // Will be handled by propagation pass
            continue;
        } else if overlapping.len() == 1 && overlapping[0] < original_markers.len() {
            // Rule 2 or 4: Changes affecting single marker
            let marker = &original_markers[overlapping[0]];

            // Sort changes by rendered_start to process them in order
            let mut sorted_changes = grouped_changes.clone();
            sorted_changes.sort_by_key(|c| c.rendered_start);

            // Compute the new bounds by accounting for size changes
            let new_start = marker.rendered_start.min(sorted_changes[0].rendered_start);

            // Compute end position by tracking cumulative size delta
            let mut cumulative_delta = 0;
            for change in sorted_changes {
                let old_len = change.rendered_end - change.rendered_start;
                let size_change = change.new_content.len() as isize - old_len as isize;
                cumulative_delta += size_change;
            }

            // The new end is the old end plus the cumulative size delta
            let new_end = (marker.rendered_end as isize + cumulative_delta) as usize;

            // Extract content from edited text
            let content = if new_start < edited_text.len() && new_end <= edited_text.len() {
                edited_text[new_start..new_end].to_string()
            } else {
                // Fallback: use marker content if extraction fails
                marker.content.clone()
            };

            new_markers.push(Marker {
                source_start: new_start,
                source_end: new_end,
                rendered_start: new_start,
                rendered_end: new_end,
                content,
            });
        } else {
            // Rule 1: Multiple markers involved
            // Use the first change to compute boundaries (they're all in the same group)
            let change = grouped_changes[0];
            let (start, end) = find_change_boundaries(change, edited_text, original_markers);

            // Extract content from edited text
            let content = if start < edited_text.len() && end <= edited_text.len() {
                edited_text[start..end].to_string()
            } else {
                change.new_content.clone()
            };

            new_markers.push(Marker {
                source_start: start,
                source_end: end,
                rendered_start: start,
                rendered_end: end,
                content,
            });
        }
    }

    // Add user markers
    for um in user_markers {
        new_markers.push(Marker {
            source_start: um.start,
            source_end: um.end,
            rendered_start: um.start,
            rendered_end: um.end,
            content: um.content.clone(),
        });
    }

    // Merge overlapping markers
    new_markers = merge_overlapping_markers(new_markers);

    new_markers
}

/// Expand a marker to cover a change
fn expand_marker_for_change(
    marker: &Marker,
    change: &MappedChange,
    edited_text: &str,
) -> Marker {
    // Determine the new bounds
    let new_start = marker.rendered_start.min(change.rendered_start);
    let new_end = marker.rendered_end.max(change.rendered_end);

    // Extract content from edited text
    let content = if new_start < edited_text.len() && new_end <= edited_text.len() {
        edited_text[new_start..new_end].to_string()
    } else {
        change.new_content.clone()
    };

    Marker {
        source_start: new_start,
        source_end: new_end,
        rendered_start: new_start,
        rendered_end: new_end,
        content,
    }
}

/// Find boundaries for a change that spans multiple markers
fn find_change_boundaries(
    change: &MappedChange,
    _edited_text: &str,
    markers: &[Marker],
) -> (usize, usize) {
    // Find the leftmost start and rightmost end of all overlapping markers
    let mut min_start = change.rendered_start;
    let mut max_end = change.rendered_end;

    for &marker_idx in &change.overlapping_markers {
        if marker_idx < markers.len() {
            let marker = &markers[marker_idx];
            min_start = min_start.min(marker.rendered_start);
            max_end = max_end.max(marker.rendered_end);
        }
    }

    // Extend to include the change itself
    min_start = min_start.min(change.rendered_start);
    max_end = max_end.max(change.rendered_start + change.new_content.len());

    (min_start, max_end)
}

/// Merge overlapping markers
fn merge_overlapping_markers(mut markers: Vec<Marker>) -> Vec<Marker> {
    if markers.is_empty() {
        return markers;
    }

    // Sort markers by start position
    markers.sort_by_key(|m| m.source_start);

    let mut merged = Vec::new();
    let mut current = markers[0].clone();

    for marker in markers.into_iter().skip(1) {
        if marker.source_start <= current.source_end {
            // Overlapping or adjacent - merge
            let old_end = current.source_end;
            current.source_end = current.source_end.max(marker.source_end);
            current.rendered_end = current.rendered_end.max(marker.rendered_end);

            // Only concatenate if markers don't fully overlap (avoid duplicates)
            if marker.source_start >= old_end {
                // Adjacent or partially overlapping - concatenate
                current.content.push_str(&marker.content);
            } else if marker.source_end > old_end {
                // Overlapping - only add the non-overlapping part
                let overlap = old_end - marker.source_start;
                if overlap < marker.content.len() {
                    current.content.push_str(&marker.content[overlap..]);
                }
            }
            // If marker is fully contained, don't add anything
        } else {
            // Non-overlapping - push current and start new
            merged.push(current);
            current = marker;
        }
    }
    merged.push(current);

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_overlapping() {
        let markers = vec![
            Marker {
                source_start: 0,
                source_end: 5,
                rendered_start: 0,
                rendered_end: 5,
                content: "hello".to_string(),
            },
            Marker {
                source_start: 3,
                source_end: 8,
                rendered_start: 3,
                rendered_end: 8,
                content: "world".to_string(),
            },
        ];

        let merged = merge_overlapping_markers(markers);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source_start, 0);
        assert_eq!(merged[0].source_end, 8);
    }

    #[test]
    fn test_no_overlap() {
        let markers = vec![
            Marker {
                source_start: 0,
                source_end: 5,
                rendered_start: 0,
                rendered_end: 5,
                content: "hello".to_string(),
            },
            Marker {
                source_start: 10,
                source_end: 15,
                rendered_start: 10,
                rendered_end: 15,
                content: "world".to_string(),
            },
        ];

        let merged = merge_overlapping_markers(markers);
        assert_eq!(merged.len(), 2);
    }
}
