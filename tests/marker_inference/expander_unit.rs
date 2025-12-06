//! Unit tests for marker inference expander module
//!
//! These tests focus on internal expander logic, edge cases,
//! and boundary conditions to improve test coverage.

use sss::marker_inference::infer_markers;

#[test]
fn test_empty_source_and_edited() {
    // Both empty
    let result = infer_markers("", "").expect("Should handle empty strings");
    assert_eq!(result.output, "");
}

#[test]
fn test_empty_source_with_content() {
    // Empty source, content added
    let result = infer_markers("", "new content").expect("Should handle empty source");
    assert_eq!(result.output, "new content");
}

#[test]
fn test_content_to_empty() {
    // Content deleted completely - marker is preserved
    let result = infer_markers("o+{content}", "").expect("Should handle deletion to empty");
    // When content is deleted, inference may preserve the marker
    assert!(result.output.is_empty() || result.output.contains("⊕{"));
}

#[test]
fn test_marker_with_empty_content() {
    // Marker with no content inside
    let result = infer_markers("o+{}", "").expect("Should handle empty marker");
    // Empty markers may be preserved as is
    assert!(result.output.is_empty() || result.output == "⊕{}");
}

#[test]
fn test_single_character_marker() {
    // Single character marked
    let result = infer_markers("o+{x}", "x").expect("Should handle single char");
    assert!(result.output.contains("{x}"));
}

#[test]
fn test_single_character_edit() {
    // Single character change
    let result = infer_markers("o+{a}", "b").expect("Should handle single char edit");
    assert!(result.output.contains("{b}"));
}

#[test]
fn test_unicode_emoji_in_markers() {
    // Unicode emoji content
    let result = infer_markers("o+{🔐secret}", "🔐secret").expect("Should handle emoji");
    assert!(result.output.contains("🔐secret"));
}

#[test]
fn test_unicode_multibyte_boundary() {
    // Unicode at marker boundary
    let result = infer_markers("o+{café}", "café").expect("Should handle unicode boundary");
    assert!(result.output.contains("café"));
}

#[test]
fn test_nested_delimiter_asymmetry() {
    // Nested delimiters with different types
    let result = infer_markers("o+{[value]}", "(value)").expect("Should handle asymmetric delimiters");
    assert!(result.output.contains("{(value)}") || result.output.contains("value"));
}

#[test]
fn test_multiple_spaces_preservation() {
    // Multiple consecutive spaces
    let result = infer_markers("o+{a    b}", "a    b").expect("Should preserve spaces");
    assert!(result.output.contains("a    b"));
}

#[test]
fn test_tabs_and_spaces_mixed() {
    // Mixed whitespace
    let result = infer_markers("o+{a\tb\tc}", "a\tb\tc").expect("Should handle tabs");
    assert!(result.output.contains("\t"));
}

#[test]
fn test_newline_in_marker() {
    // Newline within marker
    let result = infer_markers("o+{line1\nline2}", "line1\nline2").expect("Should handle newlines");
    assert!(result.output.contains("line1\nline2"));
}

#[test]
fn test_crlf_line_endings() {
    // Windows line endings
    let result = infer_markers("o+{line1\r\nline2}", "line1\r\nline2").expect("Should handle CRLF");
    assert!(result.output.contains("line1") && result.output.contains("line2"));
}

#[test]
fn test_marker_at_start_of_line() {
    // Marker at line start
    let result = infer_markers("o+{start}middle end", "start middle end").expect("Should handle line start");
    assert!(result.output.contains("{start}"));
}

#[test]
fn test_marker_at_end_of_line() {
    // Marker at line end
    let result = infer_markers("start middle o+{end}", "start middle end").expect("Should handle line end");
    assert!(result.output.contains("{end}"));
}

#[test]
fn test_three_adjacent_markers() {
    // Three markers in a row
    let result = infer_markers("o+{a}o+{b}o+{c}", "axbxc").expect("Should handle three adjacent");

    // Should apply left-bias twice: x merges with a, second x merges with resulting marker
    // Or they stay separate - either way, content should be preserved
    assert!(result.output.contains("a") && result.output.contains("b") && result.output.contains("c"));
}

#[test]
fn test_insertion_between_three_markers() {
    // Insert between second and third marker
    let result = infer_markers("o+{a}o+{b}o+{c}", "abXc").expect("Should handle insertion");
    assert!(result.output.contains("X") || result.output.contains("x"));
}

#[test]
fn test_very_long_marker_content() {
    // Large content in marker
    let long_content = "a".repeat(10000);
    let source = format!("o+{{{}}}", long_content);
    let result = infer_markers(&source, &long_content).expect("Should handle long content");
    assert!(result.output.contains(&long_content));
}

#[test]
fn test_many_small_markers() {
    // Many small markers
    let mut source = String::new();
    let mut expected = String::new();
    for i in 0..100 {
        source.push_str(&format!("o+{{x{}}} ", i));
        expected.push_str(&format!("x{} ", i));
    }
    let result = infer_markers(&source, &expected).expect("Should handle many markers");
    assert!(result.output.contains("x0") && result.output.contains("x99"));
}

#[test]
fn test_marker_syntax_variants() {
    // Test both o+{} and ⊕{} syntax
    let result1 = infer_markers("o+{secret}", "secret").expect("Should handle o+{}");
    let result2 = infer_markers("⊕{secret}", "secret").expect("Should handle ⊕{}");

    // Both should produce markers
    assert!(result1.output.contains("secret"));
    assert!(result2.output.contains("secret"));
}

#[test]
fn test_mixed_marker_formats() {
    // Mix of o+{} and ⊕{} in same file
    let result = infer_markers("o+{first} ⊕{second}", "first second").expect("Should handle mixed formats");
    assert!(result.output.contains("first") && result.output.contains("second"));
}

#[test]
fn test_escaped_braces_in_content() {
    // Content with literal braces (not markers)
    let result = infer_markers("o+{func()}", "func()").expect("Should handle braces");
    assert!(result.output.contains("func()"));
}

#[test]
fn test_regex_special_chars() {
    // Content with regex special characters
    let result = infer_markers("o+{.*+?[]{}|}", ".*+?[]{}|").expect("Should handle regex chars");
    assert!(result.output.contains(".*+?"));
}

#[test]
fn test_html_tags_in_content() {
    // HTML-like content
    let result = infer_markers("o+{<div>content</div>}", "<div>content</div>")
        .expect("Should handle HTML");
    // Content should be preserved (either marked or unmarked)
    assert!(result.output.contains("content") &&
            (result.output.contains("<div>") || result.output.contains("div")));
}

#[test]
fn test_sql_injection_like_content() {
    // SQL-like content (test robustness)
    let result = infer_markers("o+{'; DROP TABLE users;--}", "'; DROP TABLE users;--")
        .expect("Should handle SQL-like content");
    assert!(result.output.contains("DROP TABLE"));
}

#[test]
fn test_path_separators() {
    // File paths
    let result = infer_markers("o+{/path/to/file}", "/path/to/file").expect("Should handle paths");
    assert!(result.output.contains("/path/to/file"));
}

#[test]
fn test_url_content() {
    // URL content
    let result = infer_markers("o+{https://example.com/api?key=value}", "https://example.com/api?key=value")
        .expect("Should handle URLs");
    assert!(result.output.contains("https://"));
}

#[test]
fn test_json_content() {
    // JSON-like content
    let result = infer_markers(r#"o+{{"key":"value"}}"#, r#"{"key":"value"}"#)
        .expect("Should handle JSON");
    assert!(result.output.contains("key") && result.output.contains("value"));
}

#[test]
fn test_base64_content() {
    // Base64-like content
    let result = infer_markers("o+{SGVsbG8gV29ybGQ=}", "SGVsbG8gV29ybGQ=")
        .expect("Should handle base64");
    assert!(result.output.contains("SGVsbG8"));
}

#[test]
fn test_delimiter_only_on_one_side() {
    // Quote only at start
    let result = infer_markers(r#"o+{"value}"#, r#""value"#).expect("Should handle partial delimiter");
    // Should handle gracefully
    assert!(result.output.contains("value"));
}

#[test]
fn test_mismatched_delimiters() {
    // Mismatched delimiter types
    let result = infer_markers("o+{(value]}", "(value]").expect("Should handle mismatched");
    assert!(result.output.contains("value"));
}

#[test]
fn test_extremely_nested_delimiters() {
    // Deeply nested
    let result = infer_markers("o+{((((value))))}", "((((value))))").expect("Should handle deep nesting");
    assert!(result.output.contains("value"));
}

#[test]
fn test_trailing_whitespace_various_types() {
    // Different trailing whitespace
    let result1 = infer_markers("o+{value }", "value ").expect("Should handle space");
    let result2 = infer_markers("o+{value\t}", "value\t").expect("Should handle tab");
    let _result3 = infer_markers("o+{value\n}", "value\n").expect("Should handle newline");

    // Verify content is preserved
    assert!(result1.output.contains("value"));
    assert!(result2.output.contains("value"));
}

#[test]
fn test_leading_whitespace() {
    // Leading whitespace
    let result = infer_markers("o+{ value}", " value").expect("Should handle leading space");
    assert!(result.output.contains("value"));
}

#[test]
fn test_only_whitespace_marker() {
    // Marker containing only whitespace
    let _result = infer_markers("o+{   }", "   ").expect("Should handle whitespace-only");
    // Should handle (might be empty or preserved) - just verify it doesn't panic
}

#[test]
fn test_insertion_at_very_start() {
    // Insert at position 0
    let result = infer_markers("o+{content}", "XXXcontent").expect("Should handle start insertion");
    assert!(result.output.contains("XXX") && result.output.contains("content"));
}

#[test]
fn test_insertion_at_very_end() {
    // Insert at end
    let result = infer_markers("o+{content}", "contentXXX").expect("Should handle end insertion");
    assert!(result.output.contains("content") && result.output.contains("XXX"));
}

#[test]
fn test_deletion_from_start() {
    // Delete from start
    let result = infer_markers("o+{REMOVED_content}", "content").expect("Should handle start deletion");
    assert!(result.output.contains("content"));
}

#[test]
fn test_deletion_from_end() {
    // Delete from end
    let result = infer_markers("o+{content_REMOVED}", "content").expect("Should handle end deletion");
    assert!(result.output.contains("content"));
}

#[test]
fn test_deletion_from_middle() {
    // Delete from middle
    let result = infer_markers("o+{con_REMOVED_tent}", "content").expect("Should handle middle deletion");
    assert!(result.output.contains("content"));
}

#[test]
fn test_replacement_with_longer_text() {
    // Replace with longer
    let result = infer_markers("o+{short}", "much longer text").expect("Should handle expansion");
    assert!(result.output.contains("much longer text"));
}

#[test]
fn test_replacement_with_shorter_text() {
    // Replace with shorter
    let result = infer_markers("o+{very long original text}", "short").expect("Should handle contraction");
    assert!(result.output.contains("short"));
}

#[test]
fn test_complete_text_reversal() {
    // Reverse entire content
    let result = infer_markers("o+{abc}", "cba").expect("Should handle reversal");
    assert!(result.output.contains("cba"));
}

#[test]
fn test_case_change_only() {
    // Only case changes
    let result = infer_markers("o+{Secret}", "SECRET").expect("Should handle case change");
    assert!(result.output.contains("SECRET"));
}

#[test]
fn test_multiple_edits_same_marker() {
    // Multiple changes to one marker
    let result = infer_markers("o+{old_value_here}", "new_different_content")
        .expect("Should handle multiple edits");
    assert!(result.output.contains("new_different_content"));
}

#[test]
fn test_warning_generation() {
    // Test that warnings are generated for edge cases
    // This might generate warnings but should still succeed
    let result = infer_markers("o+{(mismatched]}", "(mismatched]")
        .expect("Should handle with warnings");

    // Might have warnings but should complete
    assert!(!result.output.is_empty());
}

#[test]
fn test_special_unicode_spaces() {
    // Non-breaking space and other unicode spaces
    let nbsp = "\u{00A0}";
    let result = infer_markers(&format!("o+{{value{}}}", nbsp), &format!("value{}", nbsp))
        .expect("Should handle unicode spaces");
    assert!(result.output.contains("value"));
}

#[test]
fn test_zero_width_characters() {
    // Zero-width joiner/non-joiner
    let zwj = "\u{200D}";
    let result = infer_markers(&format!("o+{{val{}ue}}", zwj), &format!("val{}ue", zwj))
        .expect("Should handle zero-width chars");
    assert!(result.output.contains("val") && result.output.contains("ue"));
}

#[test]
fn test_rtl_text() {
    // Right-to-left text (Arabic/Hebrew)
    let result = infer_markers("o+{مرحبا}", "مرحبا").expect("Should handle RTL");
    assert!(result.output.contains("مرحبا"));
}

#[test]
fn test_combined_unicode_graphemes() {
    // Combined characters (e + combining acute = é)
    let result = infer_markers("o+{café}", "café").expect("Should handle combined chars");
    assert!(result.output.contains("café"));
}
