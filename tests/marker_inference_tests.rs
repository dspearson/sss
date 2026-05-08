//! Marker Inference Specification Compliance Tests
//!
//! Tests to verify exact compliance with docs/marker-design.md

use sss::marker_inference::infer_markers;

// Include additional test modules
mod marker_inference;

/// Section 8.3 Example 1: Consistent Marking
///
/// Spec quote: "Both quotes outside marker, content inside marked"
///
/// Source:  key: "o+{value}"
/// Edited:  key: "newvalue"
/// Result:  key: "⊕{newvalue}"
#[test]
fn test_section_8_3_example_1_consistent_marking() {
    let source = r#"key: "o+{value}""#;
    let edited = r#"key: "newvalue""#;

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // Verify quotes are OUTSIDE the marker
    assert!(
        result.output.contains(r#"key: "⊕{newvalue}""#)
            || result.output.contains(r#"key: "o+{newvalue}""#),
        "Delimiters should be outside marker. Got: {}",
        result.output
    );

    // Ensure quotes are NOT inside the marker
    assert!(
        !result.output.contains(r#"⊕{"newvalue"}"#)
            && !result.output.contains(r#"o+{"newvalue"}"#),
        "Delimiters should NOT be inside marker. Got: {}",
        result.output
    );
}

/// Section 8.3 Example 2: Unmatched Delimiters
///
/// Spec quote: "Closing quote missing, mark anyway (security over syntax)"
///
/// Source:  key: "o+{value}"
/// Edited:  key: "value
/// Result:  key: "⊕{value}
/// Warning: "Unmatched delimiter pair..."
#[test]
fn test_section_8_3_example_2_unmatched_delimiters() {
    let source = r#"key: "o+{value}""#;
    let edited = r#"key: "value"#; // Missing closing quote

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // Should still mark the content
    assert!(
        result.output.contains(r#"key: "⊕{value}"#)
            || result.output.contains(r#"key: "o+{value}"#),
        "Content should be marked despite unmatched delimiter. Got: {}",
        result.output
    );

    // Should have a warning about delimiters (though behavior may vary)
    println!("Warnings: {:?}", result.warnings);
}

/// Section 8.3 Example 3: Nested Delimiters
///
/// Spec quote: "Inner pair (single quotes) processed first, stays together"
///
/// Source:  outer: "inner: 'o+{secret}'"
/// Edited:  outer: "inner: 'modified'"
/// Result:  outer: "inner: '⊕{modified}'"
#[test]
fn test_section_8_3_example_3_nested_delimiters() {
    let source = r#"outer: "inner: 'o+{secret}'""#;
    let edited = r#"outer: "inner: 'modified'""#;

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // Both delimiter pairs should be outside the marker
    assert!(
        result.output.contains(r#"outer: "inner: '⊕{modified}'""#)
            || result.output.contains(r#"outer: "inner: 'o+{modified}'""#),
        "Both delimiter pairs should be outside marker. Got: {}",
        result.output
    );

    // Ensure single quotes are not inside the marker
    assert!(
        !result.output.contains(r#"⊕{'modified'}"#)
            && !result.output.contains(r#"o+{'modified'}"#),
        "Single quotes should NOT be inside marker. Got: {}",
        result.output
    );

    // Ensure double quotes are not inside the marker
    assert!(
        !result.output.contains(r#"⊕{"inner"#)
            && !result.output.contains(r#"o+{"inner"#),
        "Double quotes should NOT be inside marker. Got: {}",
        result.output
    );
}

/// Section 5.3 Rule 3: Ambiguous Adjacency (Left-Bias)
///
/// Spec quote: "Changed region adjacent to multiple markers → merge with leftmost"
///
/// Source:  o+{a}o+{b}
/// Edited:  axb  (insert "x" between "a" and "b")
/// Result:  ⊕{ax}⊕{b}  (NOT ⊕{a}⊕{xb})
#[test]
fn test_section_5_3_rule_3_left_bias() {
    let source = "o+{a}o+{b}";
    let edited = "axb";

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // The insertion "x" should be merged with the LEFT marker (a)
    // Result should be: ⊕{ax}⊕{b}
    // NOT: ⊕{a}⊕{xb}

    // Check that "ax" is marked together
    let has_ax_marked = result.output.contains("⊕{ax}") || result.output.contains("o+{ax}");

    // Check that "b" is marked separately
    let has_b_marked = result.output.contains("⊕{b}") || result.output.contains("o+{b}");

    assert!(
        has_ax_marked && has_b_marked,
        "Left-bias: 'x' should merge with 'a' (left marker), not 'b'. Got: {}",
        result.output
    );

    // Ensure "xb" is NOT marked together (would violate left-bias)
    let has_xb_marked = result.output.contains("⊕{xb}") || result.output.contains("o+{xb}");
    assert!(
        !has_xb_marked,
        "Left-bias violation: 'xb' should NOT be marked together. Got: {}",
        result.output
    );
}

/// Section 5.3 Rule 3: Ambiguous Adjacency with Space
///
/// Variant: What if there's a space between markers?
///
/// Source:  o+{a} o+{b}
/// Edited:  ax b  (insert "x" after "a", before space)
/// Result:  ⊕{ax} ⊕{b}
#[test]
fn test_section_5_3_rule_3_left_bias_with_space() {
    let source = "o+{a} o+{b}";
    let edited = "ax b";

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // The insertion "x" is adjacent to "a", should merge left
    let has_ax_marked = result.output.contains("⊕{ax}") || result.output.contains("o+{ax}");
    let has_b_marked = result.output.contains("⊕{b}") || result.output.contains("o+{b}");

    assert!(
        has_ax_marked && has_b_marked,
        "Left-bias with space: 'x' should merge with 'a'. Got: {}",
        result.output
    );
}

/// Section 5.1 Rule 1: Replacement of Marked Content
///
/// Spec: "Changed region overlaps one or more marked regions → expand markers
/// to encompass entire changed region, bounded by unchanged text"
///
/// Source:  prefix o+{target} suffix
/// Edited:  prefix replaced suffix
/// Result:  prefix ⊕{replaced} suffix
#[test]
fn test_section_5_1_rule_1_replacement() {
    let source = "prefix o+{target} suffix";
    let edited = "prefix replaced suffix";

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // The changed region should be marked, bounded by unchanged "prefix" and "suffix"
    let marked_content =
        result.output.contains("⊕{replaced}") || result.output.contains("o+{replaced}");

    assert!(
        marked_content,
        "Replaced content should be marked. Got: {}",
        result.output
    );

    // Unchanged boundaries should remain unmarked
    assert!(
        result.output.starts_with("prefix") && result.output.ends_with("suffix"),
        "Unchanged boundaries should be preserved. Got: {}",
        result.output
    );
}

/// Section 5.2 Rule 2: Adjacent Modifications
///
/// Spec: "Changed region adjacent to exactly one marked region → expand that marker"
///
/// Source:  o+{hello} world
/// Edited:  hello! world  (insert "!" after "hello")
/// Result:  ⊕{hello!} world
#[test]
fn test_section_5_2_rule_2_adjacent_modification() {
    let source = "o+{hello} world";
    let edited = "hello! world";

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // The marker should expand to include the adjacent insertion
    assert!(
        result.output.contains("⊕{hello!}") || result.output.contains("o+{hello!}"),
        "Adjacent insertion should expand marker. Got: {}",
        result.output
    );
}

/// Section 5.4 Rule 4: Preservation of Separate Markers
///
/// Spec: "Multiple marked regions with changed region affecting only one
/// → preserve separation"
///
/// Source:  o+{first} o+{second}
/// Edited:  changed second
/// Result:  ⊕{changed} ⊕{second}
#[test]
fn test_section_5_4_rule_4_preserve_separation() {
    let source = "o+{first} o+{second}";
    let edited = "changed second";

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // Both markers should exist separately
    let has_changed = result.output.contains("⊕{changed}") || result.output.contains("o+{changed}");
    let has_second = result.output.contains("⊕{second}") || result.output.contains("o+{second}");

    assert!(
        has_changed && has_second,
        "Separate markers should be preserved. Got: {}",
        result.output
    );
}

/// Section 7.3: Content Propagation
///
/// Spec: "If marked content appears elsewhere, mark all instances"
///
/// Source:  o+{secret} and secret again
/// Edited:  secret and secret again
/// Result:  ⊕{secret} and ⊕{secret} again
#[test]
fn test_section_7_3_content_propagation() {
    let source = "o+{secret} and secret again";
    let edited = "secret and secret again";

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // Count marker occurrences
    let marked_count = result.output.matches("⊕{").count() + result.output.matches("o+{").count();

    assert!(
        marked_count >= 2,
        "Content propagation should mark all instances. Only {} markers found. Got: {}",
        marked_count,
        result.output
    );
}

// Regression: infer_markers must not panic on inputs where upstream byte
// arithmetic produces byte indices that land mid-codepoint. Discovered by
// the marker_scanner libFuzzer harness in plan 17-02 (artifact
// crash-6a3af57c0d74ab29f9f62afed8a24b8f56d1cbd3). The crash hit
// src/marker_inference/expander.rs:575 — str slice with end=14 falling
// inside the 3-byte ⊕ glyph at bytes 13..16. Fixed in 17-02a by flooring
// start/end to char boundaries in apply_boundary_adjustments.
#[test]
fn test_infer_markers_no_panic_on_mid_codepoint_byte_index() {
    let input: &[u8] = b"prefix o+{abc} mi\xe2\x8a\x95\x10prr\x01\x11\x00\x00erfecx\nix\n";
    let s = std::str::from_utf8(input).expect("crash artifact is valid UTF-8");
    // Both Ok and Err are acceptable; only a panic would be a regression.
    let _ = infer_markers(s, s);
}

// Regression: reconstruct_with_markers must not panic when upstream marker
// construction produces OOB or mid-codepoint source_start/source_end byte
// indices. Discovered by the marker_scanner libFuzzer harness in plan 17-02
// (artifact crash-0895563c5d1471c8db6910f8ff7e7d4e43997419). The crash hit
// src/marker_inference/reconstructor.rs:33 — text[pos..marker.source_start]
// with source_start=25 against a 24-byte text. Fixed in 17-02b by clamping
// marker indices to text.len() and flooring to char boundaries before slicing.
#[test]
fn test_infer_markers_no_panic_on_marker_source_start_oob() {
    let input: &[u8] = b"_key: \xe2\x8a\x95{myl\x00\x00\x00ecret}o+{unte+{}#";
    let s = std::str::from_utf8(input).expect("crash artifact is valid UTF-8");
    // Both Ok and Err are acceptable; only a panic would be a regression.
    let _ = infer_markers(s, s);
}

// Regression: the original-marker preservation pass in expander.rs must not
// panic when rendered_to_edited produces mid-codepoint byte indices for an
// unaffected marker. Discovered by the marker_scanner libFuzzer harness in
// plan 17-02 (artifact crash-dfaf916089fead0109ef7fc7b8900e91b87e0703). The
// crash hit src/marker_inference/expander.rs:237 — str slice into edited_text
// where rendered_to_edited had landed inside a multi-byte ⊕ sequence. Fixed
// in 17-02c by flooring edited_start/edited_end to char boundaries before the
// bounds check.
#[test]
fn test_infer_markers_no_panic_on_unaffected_marker_mid_codepoint() {
    let input: &[u8] = b"{{+{{\x07\x07\x07}\xe2\x8a\x95{cx}+o+{{}\xe2\x8a\x95{{ixu.\xe2\x8a\x95\\{cx}+c.\xe2\x8a\x95\\.";
    let s = std::str::from_utf8(input).expect("crash artifact is valid UTF-8");
    // Both Ok and Err are acceptable; only a panic would be a regression.
    let _ = infer_markers(s, s);
}
