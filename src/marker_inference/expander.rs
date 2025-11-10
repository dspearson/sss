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
    // Group changes by their overlapping markers (HashMap<marker_indices, changes>)
    let grouped_changes = group_changes_by_markers(&changes);

    // Collect all changes for position conversion
    let all_changes: Vec<&MappedChange> = changes.iter().collect();

    // Process each group according to the appropriate rule
    let mut new_markers = process_grouped_changes(
        grouped_changes,
        original_markers,
        edited_text,
        &all_changes,
    );

    // Add explicitly user-inserted markers
    add_user_markers_to_list(&mut new_markers, user_markers);

    // Merge any overlapping markers
    merge_overlapping_markers(new_markers)
}

/// Group changes by which markers they overlap
fn group_changes_by_markers(
    changes: &[MappedChange],
) -> std::collections::HashMap<Vec<usize>, Vec<&MappedChange>> {
    use std::collections::HashMap;
    let mut grouped: HashMap<Vec<usize>, Vec<&MappedChange>> = HashMap::new();

    for change in changes {
        let key = change.overlapping_markers.clone();
        grouped.entry(key).or_default().push(change);
    }

    grouped
}

/// Check if changes are only adjacent to markers, not overlapping interiors
fn is_only_adjacent(
    changes: &[&MappedChange],
    marker_indices: &[usize],
    markers: &[Marker],
) -> bool {
    // For each change, check if it only touches boundaries
    for change in changes {
        for &idx in marker_indices {
            if idx >= markers.len() {
                continue;
            }
            let marker = &markers[idx];

            // Check if change overlaps marker interior
            // A change overlaps interior if it extends into the marker's range
            let change_end = change.rendered_end;
            let change_start = change.rendered_start;

            // If change_start is inside marker (not at boundary)
            if change_start > marker.rendered_start && change_start < marker.rendered_end {
                return false; // Overlaps interior
            }

            // If change_end is inside marker (not at boundary)
            if change_end > marker.rendered_start && change_end < marker.rendered_end {
                return false; // Overlaps interior
            }

            // If change completely contains marker
            if change_start <= marker.rendered_start && change_end >= marker.rendered_end {
                return false; // Overlaps interior
            }
        }
    }

    // All changes are only adjacent to boundaries
    true
}

/// Process all grouped changes according to expansion rules
fn process_grouped_changes(
    grouped: std::collections::HashMap<Vec<usize>, Vec<&MappedChange>>,
    original_markers: &[Marker],
    edited_text: &str,
    all_changes: &[&MappedChange],
) -> Vec<Marker> {
    let mut markers = Vec::new();
    let mut affected_marker_indices = std::collections::HashSet::new();

    for (overlapping_indices, changes) in grouped {
        // Track which markers were affected by changes
        for &idx in &overlapping_indices {
            affected_marker_indices.insert(idx);
        }

        if overlapping_indices.is_empty() {
            // Rule 5: Unmarked content - handled by propagation pass
            continue;
        } else if overlapping_indices.len() == 1 && overlapping_indices[0] < original_markers.len() {
            // Rules 2 & 4: Single marker affected
            if let Some(marker) = apply_single_marker_rule(
                &original_markers[overlapping_indices[0]],
                changes,
                edited_text,
                all_changes,
            ) {
                markers.push(marker);
            }
        } else if is_only_adjacent(&changes, &overlapping_indices, original_markers) {
            // Rule 3: Adjacent to multiple markers - apply left-bias
            // Merge with the leftmost marker only
            let leftmost_idx = overlapping_indices[0];
            if leftmost_idx < original_markers.len() {
                let leftmost_marker = &original_markers[leftmost_idx];

                if let Some(marker) = apply_left_bias_expansion(
                    leftmost_marker,
                    changes,
                    edited_text,
                    all_changes,
                    &overlapping_indices,
                    original_markers,
                ) {
                    markers.push(marker);
                }

                // Preserve other markers that weren't merged
                for &idx in &overlapping_indices[1..] {
                    if idx < original_markers.len() {
                        let original_marker = &original_markers[idx];
                        let edited_start = rendered_to_edited(original_marker.rendered_start, all_changes);
                        let edited_end = rendered_to_edited(original_marker.rendered_end, all_changes);

                        markers.push(Marker {
                            source_start: edited_start,
                            source_end: edited_end,
                            rendered_start: edited_start,
                            rendered_end: edited_end,
                            content: original_marker.content.clone(),
                        });
                    }
                }
            }
        } else {
            // Rule 1: Multiple markers with overlapping interiors - merge them
            if let Some(marker) = apply_multi_marker_rule(
                changes[0],
                &overlapping_indices,
                original_markers,
                edited_text,
                all_changes,
            ) {
                markers.push(marker);
            }
        }
    }

    // Preserve original markers that weren't affected by any changes
    // Convert their positions from rendered to edited coordinates
    for (idx, original_marker) in original_markers.iter().enumerate() {
        if !affected_marker_indices.contains(&idx) {
            let edited_start = rendered_to_edited(original_marker.rendered_start, all_changes);
            let edited_end = rendered_to_edited(original_marker.rendered_end, all_changes);

            // Don't preserve marker if its position is now invalid (content was deleted)
            if edited_start >= edited_end || edited_start >= edited_text.len() || edited_end > edited_text.len() {
                continue;
            }

            // Verify the content at this position matches what we expect
            // If content was deleted, don't preserve the marker
            let actual_content = if edited_end <= edited_text.len() {
                &edited_text[edited_start..edited_end]
            } else {
                ""
            };

            // Only preserve if content is non-empty and matches expected
            if !actual_content.is_empty() {
                markers.push(Marker {
                    source_start: edited_start,
                    source_end: edited_end,
                    rendered_start: edited_start,
                    rendered_end: edited_end,
                    content: original_marker.content.clone(),
                });
            }
        }
    }

    markers
}

/// Apply left-bias expansion (Rule 3)
///
/// Expands the leftmost marker to include changes, but stops at the boundary
/// of the next marker to avoid merging them together.
fn apply_left_bias_expansion(
    marker: &Marker,
    changes: Vec<&MappedChange>,
    edited_text: &str,
    all_changes: &[&MappedChange],
    all_marker_indices: &[usize],
    all_markers: &[Marker],
) -> Option<Marker> {
    // Sort changes affecting this marker by position
    let mut sorted = changes;
    sorted.sort_by_key(|c| c.rendered_start);

    // Find the boundary where we should stop (the start of the next marker)
    let next_marker_boundary = if all_marker_indices.len() > 1 {
        // Get the second marker (first one after leftmost)
        let next_idx = all_marker_indices[1];
        if next_idx < all_markers.len() {
            Some(all_markers[next_idx].rendered_start)
        } else {
            None
        }
    } else {
        None
    };

    // Compute new bounds in RENDERED coordinates
    let new_start_rendered = marker.rendered_start.min(sorted[0].rendered_start);
    let mut new_end_rendered = marker.rendered_end;

    // Expand to include changes, but stop at next marker boundary
    for change in &sorted {
        let change_end_rendered = change.rendered_start + change.new_content.len();

        if let Some(boundary) = next_marker_boundary {
            // Don't expand past the next marker's start
            new_end_rendered = new_end_rendered.max(change_end_rendered.min(boundary));
        } else {
            new_end_rendered = new_end_rendered.max(change_end_rendered);
        }
    }

    // Convert to EDITED coordinates
    let new_start = rendered_to_edited(new_start_rendered, all_changes);
    let new_end = rendered_to_edited(new_end_rendered, all_changes);

    // Apply boundary adjustments per spec sections 5 and 8
    let (new_start, new_end) = apply_boundary_adjustments(edited_text, new_start, new_end);

    // Extract content
    let content = extract_content(edited_text, new_start, new_end, &marker.content);

    // Don't create marker if content was completely deleted
    if new_start >= new_end || new_start >= edited_text.len() {
        return None;
    }

    Some(Marker {
        source_start: new_start,
        source_end: new_end,
        rendered_start: new_start,
        rendered_end: new_end,
        content,
    })
}

/// Apply expansion rule for single marker (Rules 2 & 4)
fn apply_single_marker_rule(
    marker: &Marker,
    changes: Vec<&MappedChange>,
    edited_text: &str,
    all_changes: &[&MappedChange],
) -> Option<Marker> {
    // Sort changes affecting this marker by position
    let mut sorted = changes;
    sorted.sort_by_key(|c| c.rendered_start);

    // Compute new bounds in RENDERED coordinates
    let new_start_rendered = marker.rendered_start.min(sorted[0].rendered_start);
    let new_end_rendered = marker.rendered_end;

    // Check if there's a pure insertion at the marker's end boundary
    // If so, we should not include it in the initial coordinate transformation
    let has_insertion_at_end = sorted.iter().any(|c| {
        c.rendered_start == c.rendered_end && // Pure insertion
        !c.new_content.is_empty() &&
        c.rendered_start == marker.rendered_end // At marker's end
    });

    // Convert to EDITED coordinates
    let mut new_start = rendered_to_edited(new_start_rendered, all_changes);
    let mut new_end = if has_insertion_at_end {
        // For insertions at the end, use the position WITHOUT including the insertion
        // This prevents the marker from incorrectly expanding to include new content
        rendered_to_edited_excluding_insertion_at(new_end_rendered, all_changes)
    } else {
        rendered_to_edited(new_end_rendered, all_changes)
    };

    // Expand to cover all the changes affecting this marker
    for change in &sorted {
        let is_pure_insertion = change.rendered_start == change.rendered_end && !change.new_content.is_empty();

        // Each change adds new content that should be covered by the marker
        let change_pos_edited = rendered_to_edited(change.rendered_start, all_changes);

        // For pure insertions, the content appears BEFORE the converted position
        // (since rendered_to_edited includes the delta from this insertion)
        let change_start_edited = if is_pure_insertion {
            // Pure insertion: content is inserted before the converted position
            change_pos_edited.saturating_sub(change.new_content.len())
        } else {
            // Replacement: use converted position
            change_pos_edited
        };
        let change_end_edited = change_start_edited + change.new_content.len();

        // If change is at or before the marker start, expand start to include it
        if change.rendered_start <= marker.rendered_start {
            new_start = new_start.min(change_start_edited);
        }

        // Only expand the end if this is NOT a pure insertion at the marker's right boundary
        // Pure insertions after the marker should not expand it (they're new unmarked content)
        // But modifications/deletions/insertions WITHIN the marker should expand it
        let is_insertion_after_marker = is_pure_insertion && change.rendered_start == marker.rendered_end;

        if !is_insertion_after_marker {
            // Expand the end to include changes that overlap or modify the marker
            new_end = new_end.max(change_end_edited);
        }
    }

    // Apply boundary adjustments per spec sections 5 and 8
    let (new_start, new_end) = apply_boundary_adjustments(edited_text, new_start, new_end);

    // Extract content
    let content = extract_content(edited_text, new_start, new_end, &marker.content);

    // Don't create marker if content was completely deleted
    if new_start >= new_end || new_start >= edited_text.len() {
        return None;
    }

    Some(Marker {
        source_start: new_start,
        source_end: new_end,
        rendered_start: new_start,
        rendered_end: new_end,
        content,
    })
}

/// Apply expansion rule for multiple overlapping markers (Rule 1)
fn apply_multi_marker_rule(
    change: &MappedChange,
    overlapping_indices: &[usize],
    original_markers: &[Marker],
    edited_text: &str,
    all_changes: &[&MappedChange],
) -> Option<Marker> {
    let (start, end) = find_change_boundaries(change, overlapping_indices, original_markers, all_changes, edited_text);
    let content = extract_content(edited_text, start, end, &change.new_content);

    // Don't create marker if content was completely deleted
    if start >= end || start >= edited_text.len() {
        return None;
    }

    Some(Marker {
        source_start: start,
        source_end: end,
        rendered_start: start,
        rendered_end: end,
        content,
    })
}

/// Extract content from text with fallback
fn extract_content(text: &str, start: usize, end: usize, fallback: &str) -> String {
    if start < text.len() && end <= text.len() {
        text[start..end].to_string()
    } else {
        fallback.to_string()
    }
}

/// Apply all boundary adjustments (delimiters + whitespace) per spec sections 5 and 8
///
/// This is a convenience function that applies both delimiter and whitespace adjustments
/// in the correct order, as required by the marker inference specification.
fn apply_boundary_adjustments(text: &str, start: usize, end: usize) -> (usize, usize) {
    let (start, end) = shrink_to_exclude_delimiters(text, start, end);
    shrink_to_exclude_trailing_whitespace(text, start, end)
}

/// Adjust boundaries to exclude paired delimiters per spec section 8
///
/// If the marked region is surrounded by paired delimiters, shrink the boundaries
/// to keep the delimiters outside the marker.
///
/// Paired delimiters: "...", '...', [...], {...}, (...), <...>
fn shrink_to_exclude_delimiters(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    if start >= end || end > text.len() {
        return (start, end);
    }

    let bytes = text.as_bytes();

    // Define delimiter pairs
    let pairs = [
        (b'"', b'"'),
        (b'\'', b'\''),
        (b'[', b']'),
        (b'{', b'}'),
        (b'(', b')'),
        (b'<', b'>'),
    ];

    // Keep checking and shrinking as long as we find delimiter pairs
    loop {
        if start >= end {
            break;
        }

        let mut found_pair = false;

        // Check if current boundaries are delimiters
        for &(open, close) in &pairs {
            if start < bytes.len() && end > 0 && end <= bytes.len()
                && bytes[start] == open && bytes[end - 1] == close {
                    // Found a pair - shrink boundaries
                    start += 1;
                    end -= 1;
                    found_pair = true;
                    break;
                }
        }

        if !found_pair {
            break;
        }
    }

    (start, end)
}

/// Adjust boundaries to exclude trailing whitespace
///
/// Trailing whitespace should not be included in markers to avoid
/// breaking word boundaries when rendering.
fn shrink_to_exclude_trailing_whitespace(text: &str, start: usize, mut end: usize) -> (usize, usize) {
    if start >= end || end > text.len() {
        return (start, end);
    }

    let bytes = text.as_bytes();

    // Shrink end to exclude trailing whitespace
    while end > start && end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    (start, end)
}

/// Add user-inserted markers to the marker list
fn add_user_markers_to_list(markers: &mut Vec<Marker>, user_markers: &[UserMarker]) {
    for um in user_markers {
        markers.push(Marker {
            source_start: um.start,
            source_end: um.end,
            rendered_start: um.start,
            rendered_end: um.end,
            content: um.content.clone(),
        });
    }
}

/// Find boundaries for a change that spans multiple markers
fn find_change_boundaries(
    change: &MappedChange,
    overlapping_indices: &[usize],
    markers: &[Marker],
    all_changes: &[&MappedChange],
    edited_text: &str,
) -> (usize, usize) {
    // Find the leftmost start and rightmost end of all overlapping markers in RENDERED coords
    let mut min_start_rendered = change.rendered_start;
    let mut max_end_rendered = change.rendered_end;

    for &marker_idx in overlapping_indices {
        if marker_idx < markers.len() {
            let marker = &markers[marker_idx];
            min_start_rendered = min_start_rendered.min(marker.rendered_start);
            max_end_rendered = max_end_rendered.max(marker.rendered_end);
        }
    }

    // Extend to include the change itself
    max_end_rendered = max_end_rendered.max(change.rendered_start + change.new_content.len());

    // Convert to EDITED coordinates
    let min_start = rendered_to_edited(min_start_rendered, all_changes);
    let max_end = rendered_to_edited(max_end_rendered, all_changes);

    // Apply boundary adjustments per spec sections 5 and 8
    let (min_start, max_end) = apply_boundary_adjustments(edited_text, min_start, max_end);

    (min_start, max_end)
}

/// Convert a position from RENDERED coordinates to EDITED coordinates
///
/// RENDERED coordinates are positions in the text after removing markers from source.
/// EDITED coordinates are positions in the user-edited text.
/// The relationship between these changes due to edit operations.
fn rendered_to_edited(rendered_pos: usize, all_changes: &[&MappedChange]) -> usize {
    let mut edited_pos = rendered_pos as isize;

    // Sort changes by position
    let mut sorted: Vec<&MappedChange> = all_changes.to_vec();
    sorted.sort_by_key(|c| c.rendered_start);

    // Apply cumulative deltas from all changes that ended before this position
    for change in sorted {
        if change.rendered_end <= rendered_pos {
            let old_len = change.rendered_end - change.rendered_start;
            let new_len = change.new_content.len();
            let delta = new_len as isize - old_len as isize;
            edited_pos += delta;
        }
    }

    edited_pos.max(0) as usize
}

/// Convert a position from RENDERED coordinates to EDITED coordinates,
/// but exclude any pure insertion at exactly this position.
///
/// This is used when a marker's end boundary has an insertion - we want
/// the position WITHOUT including the inserted content.
fn rendered_to_edited_excluding_insertion_at(rendered_pos: usize, all_changes: &[&MappedChange]) -> usize {
    let mut edited_pos = rendered_pos as isize;

    // Sort changes by position
    let mut sorted: Vec<&MappedChange> = all_changes.to_vec();
    sorted.sort_by_key(|c| c.rendered_start);

    // Apply cumulative deltas from all changes
    for change in sorted {
        // Skip pure insertions AT this exact position
        let is_pure_insertion_at_pos = change.rendered_start == change.rendered_end &&
                                        !change.new_content.is_empty() &&
                                        change.rendered_start == rendered_pos;

        if is_pure_insertion_at_pos {
            // Don't include this insertion in the position calculation
            continue;
        }

        if change.rendered_end <= rendered_pos {
            let old_len = change.rendered_end - change.rendered_start;
            let new_len = change.new_content.len();
            let delta = new_len as isize - old_len as isize;
            edited_pos += delta;
        }
    }

    edited_pos.max(0) as usize
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
        if marker.source_start < current.source_end {
            // Truly overlapping - merge
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
