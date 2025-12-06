//! Edge case tests from Section 9 of the design document

use sss::marker_inference::infer_markers;

// ============================================================================
// Section 9.1: Marker Syntax Edge Cases
// ============================================================================

#[test]
fn test_empty_marker() {
    let source = "text o+{} more";
    let edited = "text  more";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "text  more");
}

#[test]
fn test_whitespace_only_marker() {
    let source = "text o+{   } more";
    let edited = "text    more";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{   }"));
}

#[test]
fn test_newlines_in_marker() {
    let source = "o+{line1\nline2}";
    let edited = "line1\nline2";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{line1\nline2}"));
}

#[test]
fn test_unicode_in_marker() {
    let source = "o+{日本語}";
    let edited = "日本語";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{日本語}");
}

#[test]
fn test_escaped_close_brace() {
    let source = "o+{text \\} more}";
    let edited = "text \\} more";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{text \\} more}"));
}

#[test]
fn test_already_escaped() {
    let source = "o+\\{literal}";
    let edited = "o+\\{literal}";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "o+\\{literal}");
}

#[test]
fn test_double_escape() {
    let source = "o+\\\\{text}";
    let edited = "o+\\\\{text}";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "o+\\\\{text}");
}

// ============================================================================
// Section 9.2: Nesting and Recursion
// ============================================================================

#[test]
fn test_simple_nesting() {
    let source = "o+{a o+{b}}";
    let edited = "a o+\\{b}";
    let result = infer_markers(source, edited).unwrap();
    // Outer marker was escaped during parsing
    assert!(result.output.contains("o+\\{"));
}

#[test]
fn test_deep_nesting() {
    let source = "o+{a o+{b o+{c}}}";
    let edited = "a o+\\{b o+\\{c}}";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("o+\\{"));
}

#[test]
fn test_mixed_format_nesting() {
    let source = "o+{a ⊕{b}}";
    let edited = "a ⊕\\{b}";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕\\{b}") || result.output.contains("o+\\{"));
}

// ============================================================================
// Section 9.3: Deletion Edge Cases
// ============================================================================

#[test]
fn test_delete_marked_content() {
    let source = "o+{secret} text";
    let edited = "text";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "text");
}

#[test]
fn test_delete_around_marker() {
    let source = "prefix o+{keep} suffix";
    let edited = "o+{keep}";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{keep}");
}

#[test]
fn test_delete_everything_except_marker() {
    let source = "lots o+{keep} text";
    let edited = "keep";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{keep}");
}

#[test]
fn test_delete_part_of_marker() {
    let source = "o+{longtext}";
    let edited = "long";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{long}");
}

// ============================================================================
// Section 9.4: Adjacent Marker Edge Cases
// ============================================================================

#[test]
fn test_insert_between_adjacent() {
    let source = "o+{a}o+{b}";
    let edited = "axb";
    let result = infer_markers(source, edited).unwrap();
    // Left-bias: x merges with a
    assert!(result.output.contains("⊕{ax}"));
    assert!(result.output.contains("⊕{b}"));
}

#[test]
fn test_insert_at_boundary() {
    let source = "o+{a}o+{b}";
    let edited = "abc";
    let result = infer_markers(source, edited).unwrap();
    // c should merge with b (right side)
    assert!(result.output.contains("⊕{a}"));
    assert!(result.output.contains("⊕{bc}"));
}

#[test]
fn test_replace_both_adjacent() {
    let source = "o+{a}o+{b}";
    let edited = "replaced";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{replaced}");
}

#[test]
fn test_modify_first_only() {
    let source = "o+{a}o+{b}";
    let edited = "axb";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{ax}"));
    assert!(result.output.contains("⊕{b}"));
}

#[test]
fn test_modify_second_only() {
    let source = "o+{a}o+{b}";
    let edited = "abx";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{a}"));
    assert!(result.output.contains("⊕{bx}"));
}

// ============================================================================
// Section 9.5: Delimiter Edge Cases
// ============================================================================

#[test]
fn test_unmatched_open_quote() {
    let source = "\"o+{text}";
    let edited = "\"text";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{text}"));
}

#[test]
fn test_unmatched_close_quote() {
    let source = "o+{text}\"";
    let edited = "text\"";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{text}"));
}

#[test]
fn test_escaped_delimiter() {
    let source = "\"o+{text \\\"}";
    let edited = "\"text \\\"";
    let result = infer_markers(source, edited).unwrap();
    // Escaped \" is not a delimiter
    assert!(result.output.contains("⊕{text"));
}

#[test]
fn test_empty_delimiter_pair() {
    let source = "\"\"";
    let edited = "\"\"";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "\"\"");
}

#[test]
fn test_nested_same_type_delimiters() {
    let source = "\"outer \"inner\" outer\"";
    let edited = "\"outer \"inner\" outer\"";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("outer"));
}

// ============================================================================
// Section 9.6: Propagation Edge Cases
// ============================================================================

#[test]
fn test_partial_match_no_propagation() {
    let source = "o+{password}";
    let edited = "password and pass";
    let result = infer_markers(source, edited).unwrap();
    // "pass" should NOT be marked (partial match)
    assert!(result.output.contains("⊕{password}"));
    assert!(result.output.contains(" and pass"));
}

#[test]
fn test_case_difference_no_propagation() {
    let source = "o+{Secret}";
    let edited = "Secret and secret";
    let result = infer_markers(source, edited).unwrap();
    // "secret" should NOT be marked (case differs)
    assert!(result.output.contains("⊕{Secret}"));
    assert!(result.output.contains(" and secret"));
}

#[test]
fn test_whitespace_difference_no_propagation() {
    let source = "o+{a  b}";
    let edited = "a  b and a b";
    let result = infer_markers(source, edited).unwrap();
    // "a b" should NOT be marked (whitespace differs)
    assert!(result.output.contains("⊕{a  b}"));
}

#[test]
fn test_empty_content_no_propagation() {
    let source = "o+{} text";
    let edited = " text";
    let result = infer_markers(source, edited).unwrap();
    // Empty marker should not propagate
    assert_eq!(result.warnings.len(), 0);
}

// ============================================================================
// Section 9.7: File-Level Edge Cases
// ============================================================================

#[test]
fn test_empty_file() {
    let source = "";
    let edited = "";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "");
}

#[test]
fn test_file_entirely_marked() {
    let source = "o+{entire file}";
    let edited = "entire file";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{entire file}");
}

#[test]
fn test_no_markers_in_source() {
    let source = "plain text";
    let edited = "modified text";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "modified text");
}

#[test]
fn test_only_whitespace() {
    let source = "   \n\t  ";
    let edited = "   \n\t  ";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "   \n\t  ");
}

// ============================================================================
// Section 9.8: Boundary Detection Edge Cases
// ============================================================================

#[test]
fn test_no_boundaries_entire_file() {
    let source = "o+{all}";
    let edited = "new all";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{new all}");
}

#[test]
fn test_boundary_at_start() {
    let source = "prefix o+{a} o+{b}";
    let edited = "prefix new";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.starts_with("prefix"));
    assert!(result.output.contains("⊕{new}"));
}

#[test]
fn test_boundary_at_end() {
    let source = "o+{a} o+{b} suffix";
    let edited = "new suffix";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{new}"));
    assert!(result.output.ends_with(" suffix"));
}

#[test]
fn test_multiple_independent_changes() {
    let source = "o+{a} x o+{b} y o+{c}";
    let edited = "a new1 b new2 c";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{a}"));
    assert!(result.output.contains("⊕{b}"));
    assert!(result.output.contains("⊕{c}"));
}

// ============================================================================
// Additional Complex Edge Cases
// ============================================================================

#[test]
fn test_emoji_in_marker() {
    let source = "o+{🔒secret🔒}";
    let edited = "🔒secret🔒";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{🔒secret🔒}");
}

#[test]
fn test_very_long_content() {
    let long_content = "x".repeat(10000);
    let source = format!("o+{{{}}}", long_content);
    let edited = long_content.clone();
    let result = infer_markers(&source, &edited).unwrap();
    assert!(result.output.contains(&format!("⊕{{{}}}", long_content)));
}

#[test]
fn test_many_small_markers() {
    let mut source = String::new();
    let mut edited = String::new();
    for i in 0..100 {
        source.push_str(&format!("o+{{s{}}} ", i));
        edited.push_str(&format!("s{} ", i));
    }
    let result = infer_markers(&source, &edited).unwrap();
    // All should be marked
    for i in 0..100 {
        assert!(result.output.contains(&format!("⊕{{s{}}}", i)));
    }
}

#[test]
fn test_marker_with_special_chars() {
    // Per spec section 9.1, literal { and } must be escaped as \{ and \}
    let source = "o+{@#$%^&*()[]\\{\\}\\|;:'\",.<>?/}";
    let edited = "@#$%^&*()[]{}\\|;:'\",.<>?/";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{@#$%^&*()[]{}"));
}

#[test]
fn test_circled_plus_format() {
    let source = "⊕{secret}";
    let edited = "secret";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{secret}");
}

#[test]
fn test_mixed_circled_and_oplus() {
    let source = "o+{a} ⊕{b}";
    let edited = "a b";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{a}"));
    assert!(result.output.contains("⊕{b}"));
}

#[test]
fn test_user_adds_invalid_marker() {
    let source = "text";
    let edited = "text o+{unclosed";
    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "text o+\\{unclosed");
    assert!(!result.warnings.is_empty());
}

#[test]
fn test_marker_spanning_lines() {
    let source = "o+{line1\nline2\nline3}";
    let edited = "modified1\nmodified2\nmodified3";
    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{modified1\nmodified2\nmodified3}"));
}

// ============================================================================
// Section 9.7: Additional File-Level Edge Cases
// ============================================================================

#[test]
fn test_binary_content_with_null_bytes() {
    // Strings in Rust cannot contain null bytes in the middle easily
    // But we can test the behavior if edited text has unusual characters
    let source = "text o+{secret} more";
    let edited = "text secret\x00 with nulls";

    let result = infer_markers(source, edited).unwrap();
    // Should handle without crashing - null bytes in UTF-8 strings are technically valid
    assert!(result.output.contains("⊕{secret"));
}

#[test]
fn test_mixed_line_endings_crlf() {
    let source = "line1\ro+{secret}\r\nline3\n";
    let edited = "line1\rnewsecret\r\nline3\n";

    let result = infer_markers(source, edited).unwrap();
    // Should handle mixed line endings gracefully
    assert!(result.output.contains("⊕{newsecret}"));
}

#[test]
fn test_mixed_line_endings_all_types() {
    let source = "unix\no+{mac}\rwindows\r\nend";
    let edited = "unix\nmodified\rwindows\r\nend";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{modified}"));
}

// ============================================================================
// Performance & Stress Tests (Section 12)
// ============================================================================

#[test]
fn test_large_file_with_many_markers() {
    // Create a file with 100 markers
    let mut source = String::new();
    let mut edited = String::new();

    for i in 0..100 {
        source.push_str(&format!("key{}: o+{{secret{}}} ", i, i));
        edited.push_str(&format!("key{}: newsecret{} ", i, i));
    }

    let start = std::time::Instant::now();
    let result = infer_markers(&source, &edited).unwrap();
    let elapsed = start.elapsed();

    // Should complete in reasonable time (< 100ms for 100 markers)
    assert!(elapsed < std::time::Duration::from_millis(100));
    assert_eq!(result.output.matches("⊕{newsecret").count(), 100);
}

#[test]
fn test_many_small_changes() {
    // File with 50 small changes
    let mut source = String::new();
    let mut edited = String::new();

    for i in 0..50 {
        source.push_str(&format!("o+{{val{}}} ", i));
        edited.push_str(&format!("new{} ", i));
    }

    let result = infer_markers(&source, &edited).unwrap();
    assert!(result.output.matches("⊕{new").count() >= 40);
}

// ============================================================================
// Security & Robustness Tests (Section 13)
// ============================================================================

#[test]
fn test_many_overlapping_changes() {
    let source = "o+{aaaaa} o+{bbbbb} o+{ccccc}";
    let edited = "xxxxx yyyyy zzzzz";

    let result = infer_markers(source, edited).unwrap();
    // Should handle overlapping changes to multiple markers
    assert!(result.output.contains("⊕{"));
}

#[test]
fn test_empty_source_with_content_edit() {
    let source = "";
    let edited = "new content o+{secret}";

    let result = infer_markers(source, edited).unwrap();
    // User marker should be recognized
    assert!(result.output.contains("⊕{secret}"));
}

#[test]
fn test_pathological_propagation() {
    // Same content appears many times
    let source = "o+{x} text";
    let edited = "x x x x x x x x x x x x x x x";

    let result = infer_markers(source, edited).unwrap();
    // Should mark all instances
    let x_count = result.output.matches("⊕{x}").count();
    assert!(x_count >= 10);
}

#[test]
fn test_marker_at_file_boundaries() {
    let source1 = "o+{start}middle";
    let edited1 = "newstart middle";
    let result1 = infer_markers(source1, edited1).unwrap();
    assert!(result1.output.starts_with("⊕{newstart}"));

    let source2 = "middle o+{end}";
    let edited2 = "middle newend";
    let result2 = infer_markers(source2, edited2).unwrap();
    assert!(result2.output.ends_with("⊕{newend}"));
}

#[test]
fn test_all_delimiters_mixed() {
    let source = r#"o+{text "with" 'various' [delimiters] {nested} (parens) <angles>}"#;
    let edited = r#"text "with" 'various' [delimiters] {nested} (parens) <angles>"#;

    let result = infer_markers(source, edited).unwrap();
    // Should handle all delimiter types
    assert!(result.output.contains("⊕{"));
}

#[test]
fn test_rapid_successive_markers() {
    let source = "o+{a}o+{b}o+{c}o+{d}o+{e}";
    let edited = "a1b2c3d4e5";

    let result = infer_markers(source, edited).unwrap();
    // Should handle markers with no spacing
    assert!(result.output.matches("⊕{").count() >= 3);
}
