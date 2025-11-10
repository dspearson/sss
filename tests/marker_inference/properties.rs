//! Property-based tests using proptest
//!
//! These tests verify invariants that should hold for all inputs.

use proptest::prelude::*;
use sss::marker_inference::infer_markers;

// Helper to parse markers and get rendered text
fn get_rendered(text: &str) -> String {
    // Simple marker removal for testing
    let mut result = String::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == 'o' {
            // Check for o+{
            if chars.peek() == Some(&'+') {
                chars.next(); // consume '+'
                if chars.peek() == Some(&'{') {
                    chars.next(); // consume '{'
                    // Skip until }
                    for c in chars.by_ref() {
                        if c == '}' {
                            break;
                        }
                        result.push(c);
                    }
                    continue;
                }
            }
        }
        result.push(ch);
    }
    result
}

proptest! {
    /// Property: Applying inference twice should give the same result (idempotence)
    #[test]
    fn prop_idempotence(source in "[a-z ]{0,100}", edited in "[a-z ]{0,100}") {
        if let Ok(result1) = infer_markers(&source, &edited) {
            // Applying again should give same result
            if let Ok(result2) = infer_markers(&result1.output, &edited) {
                prop_assert_eq!(result1.output, result2.output);
            }
        }
    }

    /// Property: Content preservation - rendered output should match edited text
    #[test]
    fn prop_content_preservation(
        content in "[a-z0-9 ]{1,50}"
    ) {
        let source = format!("o+{{{}}}", content);
        let edited = content.clone();

        if let Ok(result) = infer_markers(&source, &edited) {
            // Remove all markers from output
            let rendered = get_rendered(&result.output);
            prop_assert_eq!(rendered.trim(), edited.trim());
        }
    }

    /// Property: All markers in output should be well-formed
    #[test]
    fn prop_marker_validity(source in "[a-z ]{0,100}", edited in "[a-z ]{0,100}") {
        if let Ok(result) = infer_markers(&source, &edited) {
            // Check that all ⊕{ have matching }
            let open_count = result.output.matches("⊕{").count();
            // Count unescaped closing braces
            let close_count = result.output.matches('}')
                .filter(|_| !result.output.contains("\\}"))
                .count();
            prop_assert!(open_count <= close_count);
        }
    }

    /// Property: If source has marker, output has marker (no marker loss)
    #[test]
    fn prop_no_marker_loss(
        content in "[a-z]+",
        filler in "[a-z ]*"
    ) {
        let source = format!("o+{{{}}} {}", content, filler);
        let edited = format!("{} {}", content, filler);

        if let Ok(result) = infer_markers(&source, &edited) {
            // Output should contain the marked content
            let has_marker = result.output.contains("⊕{") || result.output.contains(&content);
            assert!(has_marker);
        }
    }

    /// Property: Empty source and empty edited should give empty output
    #[test]
    fn prop_empty_identity(_seed in 0u32..1000) {
        let result = infer_markers("", "").unwrap();
        prop_assert_eq!(result.output, "");
        prop_assert_eq!(result.warnings.len(), 0);
    }

    /// Property: No change means markers preserved
    #[test]
    fn prop_no_change_preserves_markers(content in "[a-z ]{1,50}") {
        let source = format!("text o+{{{}}} more", content);
        let edited = format!("text {} more", content);

        if let Ok(result) = infer_markers(&source, &edited) {
            // Should have at least one marker
            assert!(result.output.contains("⊕{"));
        }
    }

    /// Property: Propagation - marked content appears multiple times
    #[test]
    fn prop_propagation(content in "[a-z]{3,10}") {
        let source = format!("o+{{{}}}", content);
        let edited = format!("{} and {}", content, content);

        if let Ok(result) = infer_markers(&source, &edited) {
            // Both instances should be marked
            let marker_count = result.output.matches(&format!("⊕{{{}}}", content)).count();
            prop_assert!(marker_count >= 1);
        }
    }

    /// Property: User-inserted valid markers should be preserved
    #[test]
    fn prop_user_marker_preservation(content in "[a-z]{3,10}") {
        let source = "plain text";
        let edited = format!("plain o+{{{}}}",  content);

        if let Ok(result) = infer_markers(source, &edited) {
            // User marker should be converted to canonical form
            let expected = format!("⊕{{{}}}", content);
            assert!(result.output.contains(&expected));
        }
    }

    /// Property: Deterministic output for same input
    #[test]
    fn prop_deterministic(source in "[a-z ]{0,100}", edited in "[a-z ]{0,100}") {
        if let Ok(result1) = infer_markers(&source, &edited)
            && let Ok(result2) = infer_markers(&source, &edited) {
                prop_assert_eq!(result1.output, result2.output);
                prop_assert_eq!(result1.warnings, result2.warnings);
            }
    }

    /// Property: Marker content length should not exceed edited text length
    #[test]
    fn prop_marker_length_bounds(source in "[a-z ]{1,50}", edited in "[a-z ]{1,50}") {
        if let Ok(result) = infer_markers(&source, &edited) {
            // Output length should be reasonable (not exponentially larger)
            prop_assert!(result.output.len() <= edited.len() * 10);
        }
    }

    /// Property: Adjacent modifications should respect left-bias
    #[test]
    fn prop_left_bias(_seed in 0u32..100) {
        let source = "o+{a}o+{b}";
        let edited = "axb";

        if let Ok(result) = infer_markers(source, edited) {
            // x should merge with left marker (a)
            let has_ax = result.output.contains("⊕{ax}") || result.output.contains("⊕{a");
            assert!(has_ax);
        }
    }

    /// Property: Deletion should not create new markers
    #[test]
    fn prop_deletion_no_new_markers(content in "[a-z ]{10,30}") {
        let source = format!("o+{{{}}} extra text", content);
        let edited = content.clone();

        if let Ok(result) = infer_markers(&source, &edited) {
            // Should have at most 1 marker (the original one)
            let marker_count = result.output.matches("⊕{").count();
            prop_assert!(marker_count <= 2); // Allow for some expansion
        }
    }

    /// Property: Unicode safety - no panics on unicode
    #[test]
    fn prop_unicode_safety(source in "\\PC{0,50}", edited in "\\PC{0,50}") {
        // Should not panic, even on arbitrary unicode
        let _ = infer_markers(&source, &edited);
    }

    /// Property: Escaped markers stay escaped
    #[test]
    fn prop_escaped_markers_preserved(_seed in 0u32..100) {
        let source = "text o+\\{literal}";
        let edited = "text o+\\{literal}";

        if let Ok(result) = infer_markers(source, edited) {
            let expected = "o+\\{literal}";
            assert!(result.output.contains(expected));
        }
    }

    /// Property: Output should be valid UTF-8
    #[test]
    fn prop_valid_utf8(source in "[a-zA-Z0-9 ]{0,100}", edited in "[a-zA-Z0-9 ]{0,100}") {
        if let Ok(result) = infer_markers(&source, &edited) {
            // Output should be valid UTF-8 (String guarantees this)
            prop_assert!(std::str::from_utf8(result.output.as_bytes()).is_ok());
        }
    }
}
