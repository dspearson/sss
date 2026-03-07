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
        // Add any text before this marker
        if pos < marker.source_start {
            output.push_str(&text[pos..marker.source_start]);
        }

        // Extract content from text if not already set
        let content = if !marker.content.is_empty() {
            marker.content.clone()
        } else if marker.source_start < text.len() && marker.source_end <= text.len() {
            text[marker.source_start..marker.source_end].to_string()
        } else {
            String::new()
        };

        // Skip empty markers (but preserve whitespace-only markers per spec)
        // Empty markers should be removed entirely, but whitespace is meaningful
        if content.is_empty() {
            pos = marker.source_end;
            continue;
        }

        // Emit with a delimiter pair that doesn't collide with the content.
        let (open, close) = pick_delimiter(&content);
        output.push('⊕');
        output.push(open);
        output.push_str(&content);
        output.push(close);

        pos = marker.source_end;
    }

    // Add any remaining text after last marker
    if pos < text.len() {
        output.push_str(&text[pos..]);
    }

    output
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
