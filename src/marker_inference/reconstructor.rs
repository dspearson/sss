//! Output reconstruction (Step 8)
//!
//! Reconstruct text with markers in canonical ⊕{...} format, auto-selecting
//! an alternate delimiter pair when the content contains unbalanced `}`.

use super::marker_syntax::pick_delimiter;
use super::types::Marker;

/// Reconstruct text with markers in canonical format
///
/// Takes the edited text and markers, and outputs text with markers in the
/// `⊕{...}` canonical form. For values containing unbalanced braces, picks
/// a non-colliding delimiter pair from `pick_delimiter` so the marker
/// survives a subsequent parse-round-trip without chomping bytes.
pub fn reconstruct_with_markers(text: &str, markers: &[Marker]) -> String {
    if markers.is_empty() {
        return text.to_string();
    }

    // Pre-allocate capacity: text length + worst-case per-marker overhead.
    // ⊕ is 3 bytes; exotic delimiters up to 3 bytes each → 9 bytes max.
    let estimated_capacity = text.len() + (markers.len() * 9);
    let mut output = String::with_capacity(estimated_capacity);
    let mut pos = 0;

    // Sort markers by position
    let mut sorted_markers = markers.to_vec();
    sorted_markers.sort_by_key(|m| m.source_start);

    for marker in sorted_markers {
        // Clamp marker indices to text.len() and floor to UTF-8 char boundary.
        // Defends against upstream marker-construction bugs (in apply_marker_rule
        // / rendered_to_edited) that can produce OOB or mid-codepoint indices
        // when fuzz inputs combine multi-byte UTF-8 with unbalanced delimiters.
        // Discovered by the marker_scanner libFuzzer harness in plan 17-02
        // (artifact crash-0895563c...): a marker arrived with source_start=25
        // against a 24-byte rendered text, panicking the slice at this site.
        let source_start = clamp_to_char_boundary(text, marker.source_start);
        let source_end = clamp_to_char_boundary(text, marker.source_end);

        // Add any text before this marker
        if pos < source_start {
            output.push_str(&text[pos..source_start]);
        }

        // Extract content from text if not already set
        let content = if !marker.content.is_empty() {
            marker.content.clone()
        } else if source_start < source_end {
            text[source_start..source_end].to_string()
        } else {
            String::new()
        };

        // Skip empty markers (but preserve whitespace-only markers per spec)
        // Empty markers should be removed entirely, but whitespace is meaningful
        if content.is_empty() {
            pos = source_end;
            continue;
        }

        // Emit with a delimiter pair that doesn't collide with the content.
        let (open, close) = pick_delimiter(&content);
        output.push('⊕');
        output.push(open);
        output.push_str(&content);
        output.push(close);

        pos = source_end;
    }

    // Add any remaining text after last marker
    if pos < text.len() {
        output.push_str(&text[pos..]);
    }

    output
}

/// Clamp a byte index to `text.len()` and floor to the nearest preceding UTF-8
/// char boundary.
///
/// Distinct from `expander.rs::floor_char_boundary`, which passes OOB indices
/// through unchanged because `apply_marker_rule` relies on
/// `new_end > edited_text.len()` as a deletion-detection signal. The
/// reconstructor only consumes indices for str slicing, with no deletion
/// signal — so clamping to `text.len()` is the safe choice here.
fn clamp_to_char_boundary(text: &str, idx: usize) -> usize {
    let mut idx = idx.min(text.len());
    while idx > 0 && !text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconstruct_simple() {
        let text = "password: secret123";
        let markers = vec![Marker {
            source_start: 10,
            source_end: 19,
            rendered_start: 10,
            rendered_end: 19,
            content: "secret123".to_string(),
        }];

        let result = reconstruct_with_markers(text, &markers);
        assert_eq!(result, "password: ⊕{secret123}");
    }

    #[test]
    fn test_reconstruct_multiple() {
        let text = "user: admin pass: secret";
        let markers = vec![
            Marker {
                source_start: 6,
                source_end: 11,
                rendered_start: 6,
                rendered_end: 11,
                content: "admin".to_string(),
            },
            Marker {
                source_start: 18,
                source_end: 24,
                rendered_start: 18,
                rendered_end: 24,
                content: "secret".to_string(),
            },
        ];

        let result = reconstruct_with_markers(text, &markers);
        assert_eq!(result, "user: ⊕{admin} pass: ⊕{secret}");
    }

    #[test]
    fn test_reconstruct_no_markers() {
        let text = "public text";
        let markers = vec![];

        let result = reconstruct_with_markers(text, &markers);
        assert_eq!(result, "public text");
    }

    #[test]
    fn test_reconstruct_entire_text() {
        let text = "secret";
        let markers = vec![Marker {
            source_start: 0,
            source_end: 6,
            rendered_start: 0,
            rendered_end: 6,
            content: "secret".to_string(),
        }];

        let result = reconstruct_with_markers(text, &markers);
        assert_eq!(result, "⊕{secret}");
    }
}
