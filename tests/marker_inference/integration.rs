//! Integration tests with examples from Appendix B of the design document

use sss::marker_inference::infer_markers;

#[test]
fn test_simple_modification() {
    let source = "A o+{strange day} for a o+{walk}";
    let edited = "A nasty day for a stroll outside";

    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "A ⊕{nasty day} for a ⊕{stroll outside}");
    assert_eq!(result.warnings.len(), 0);
}

#[test]
fn test_content_movement() {
    let source = "Here's a o+{secret}. And other stuff.";
    let edited = "Other stuff. Here's a secret.";

    let result = infer_markers(source, edited).unwrap();
    // The secret should still be marked
    assert!(result.output.contains("⊕{secret}"));
}

#[test]
fn test_multiple_region_replacement() {
    let source = "o+{a} middle o+{b}";
    let edited = "replaced";

    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{replaced}");
}

#[test]
fn test_adjacent_markers() {
    let source = "o+{a}o+{b}";
    let edited = "axb";

    let result = infer_markers(source, edited).unwrap();
    // Left-bias: x should merge with 'a'
    assert!(result.output.contains("⊕{ax}"));
    assert!(result.output.contains("⊕{b}"));
}

#[test]
fn test_content_propagation() {
    let source = "o+{secret} and public";
    let edited = "secret and secret";

    let result = infer_markers(source, edited).unwrap();
    // Both instances of "secret" should be marked
    let marker_count = result.output.matches("⊕{secret}").count();
    assert_eq!(marker_count, 2);
}

#[test]
fn test_delimiter_handling() {
    let source = "key: \"o+{value}\"";
    let edited = "key: \"modified\"";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{modified}"));
}

#[test]
fn test_complete_rewrite() {
    let source = "o+{SSH KEY CONTENT}";
    let edited = "COMPLETELY NEW KEY";

    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "⊕{COMPLETELY NEW KEY}");
}

#[test]
fn test_user_inserted_marker() {
    let source = "public text";
    let edited = "public o+{new secret}";

    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "public ⊕{new secret}");
}

#[test]
fn test_unclosed_user_marker() {
    let source = "public text";
    let edited = "public o+{unclosed";

    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "public o+\\{unclosed");
    assert_eq!(result.warnings.len(), 1);
}

#[test]
fn test_nested_user_marker() {
    let source = "text";
    let edited = "o+{outer o+{inner}}";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("o+\\{inner"));
    assert_eq!(result.warnings.len(), 1);
}

#[test]
fn test_user_marker_with_propagation() {
    let source = "public secret public";
    let edited = "public o+{secret} secret";

    let result = infer_markers(source, edited).unwrap();
    // Both instances should be marked
    let marker_count = result.output.matches("⊕{secret}").count();
    assert_eq!(marker_count, 2);
}

#[test]
fn test_mixed_marker_formats() {
    let source = "old: o+{secret1}";
    let edited = "old: ⊕{secret1} new: o+{secret2}";

    let result = infer_markers(source, edited).unwrap();
    // Both should be in canonical format
    assert!(result.output.contains("⊕{secret1}"));
    assert!(result.output.contains("⊕{secret2}"));
}

#[test]
fn test_password_replacement() {
    let source = "password: o+{secret123}";
    let edited = "password: newsecret456";

    let result = infer_markers(source, edited).unwrap();
    assert_eq!(result.output, "password: ⊕{newsecret456}");
}

#[test]
fn test_unmarked_content_stays_unmarked() {
    let source = "o+{a} middle o+{b}";
    let edited = "a modified b";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{a}"));
    assert!(result.output.contains("modified"));
    assert!(result.output.contains("⊕{b}"));
}

#[test]
fn test_empty_marker() {
    let source = "text o+{} more";
    let edited = "text content more";

    let result = infer_markers(source, edited).unwrap();
    // Empty marker should expand to include "content"
    assert!(result.output.contains("⊕{content}"));
}

#[test]
fn test_unicode_content() {
    let source = "password: o+{秘密123}";
    let edited = "password: 新秘密456";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{新秘密456}"));
}

#[test]
fn test_multiline_marker() {
    let source = "o+{line1\nline2\nline3}";
    let edited = "newline1\nnewline2\nnewline3";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{newline1\nnewline2\nnewline3}"));
}

#[test]
fn test_adjacent_modification_left() {
    let source = "o+{a} b";
    let edited = "ax b";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{ax}"));
}

#[test]
fn test_adjacent_modification_right() {
    let source = "a o+{b}";
    let edited = "a bx";

    let result = infer_markers(source, edited).unwrap();
    assert!(result.output.contains("⊕{bx}"));
}
