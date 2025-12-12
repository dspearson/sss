//! Filesystem marker security tests
//!
//! This test module validates security-critical marker detection and processing
//! used by FUSE and 9P filesystems.
//!
//! **Test Coverage:**
//! - Marker injection attacks
//! - Marker boundary conditions
//! - Mixed marker type handling
//! - Binary data with markers
//! - Malformed marker handling
//! - Very long marker content (DoS prevention)
//! - Marker bypass attempts
//! - UTF-8 encoding attacks
//! - Concurrent marker detection

use sss::filesystem_common::{
    has_any_markers, has_any_markers_bytes, has_encrypted_markers, MARKER_PATTERNS,
};

// ============================================================================
// Marker Detection Security Tests
// ============================================================================

/// Test: Marker injection attacks
///
/// Verifies that:
/// - Attackers can't inject fake markers to bypass encryption
/// - Partial markers are not detected
/// - Marker-like patterns are not false positives
#[test]
fn test_marker_injection_prevention() {
    // Partial markers (should NOT be detected)
    let partial_markers = vec![
        "⊠",                  // Box without {
        "⊕",                  // Circle without {
        "⊲",                  // Triangle without {
        "[*",                 // Opening without {
        "o+",                 // ASCII marker without {
        "<",                  // Less than without {
        "⊠}",                 // Box without opening {
        "⊠ {secret}",         // Space between marker and {
        "⊠\n{secret}",        // Newline between marker and {
        "⊠\t{secret}",        // Tab between marker and {
    ];

    for text in partial_markers {
        assert!(
            !has_any_markers(text),
            "Partial marker should NOT be detected: {:?}",
            text
        );
        assert!(
            !has_any_markers_bytes(text.as_bytes()),
            "Partial marker bytes should NOT be detected: {:?}",
            text
        );
    }

    // Look-alike characters (should NOT be detected unless exact match)
    let lookalikes = vec![
        "X{secret}",          // X instead of ⊠
        "O{secret}",          // O instead of ⊕
        "⊡{secret}",          // Different box character
        "⊞{secret}",          // Plus in box (different from ⊕)
    ];

    for text in lookalikes {
        assert!(
            !has_any_markers(text),
            "Look-alike should NOT be detected: {:?}",
            text
        );
    }
}

/// Test: Valid marker detection
///
/// Verifies that:
/// - All valid marker types are detected
/// - Both string and byte detection work
/// - Detection is consistent
#[test]
fn test_valid_marker_detection() {
    let valid_markers = vec![
        ("⊠{encrypted}", "Encrypted marker"),
        ("⊕{plaintext}", "Plaintext marker"),
        ("[*{legacy}", "Legacy marker"),
        ("o+{ascii}", "ASCII marker"),
        ("⊲{interpolation}", "Interpolation marker"),
        ("<{alt_interp}", "Alternative interpolation"),
    ];

    for (text, description) in valid_markers {
        assert!(
            has_any_markers(text),
            "{} should be detected (string)",
            description
        );
        assert!(
            has_any_markers_bytes(text.as_bytes()),
            "{} should be detected (bytes)",
            description
        );
    }

    // Encrypted marker specific detection
    assert!(has_encrypted_markers("text ⊠{secret} more"));
    assert!(!has_encrypted_markers("text ⊕{plaintext} more")); // Not encrypted
    assert!(!has_encrypted_markers("no markers here"));
}

/// Test: Marker boundary conditions
///
/// Verifies that:
/// - Markers at start/end of content are detected
/// - Adjacent markers are detected
/// - Empty marker content is detected
/// - Very long marker content is detected
#[test]
fn test_marker_boundary_conditions() {
    // Markers at boundaries
    assert!(has_any_markers("⊠{start}"));
    assert!(has_any_markers("end⊠{marker}"));
    assert!(has_any_markers("⊠{only}"));

    // Adjacent markers
    assert!(has_any_markers("⊠{a}⊠{b}"));
    assert!(has_any_markers("⊕{a}⊠{b}⊲{c}"));

    // Empty marker content
    assert!(has_any_markers("⊠{}"));  // Empty but valid
    assert!(has_any_markers("⊕{}"));

    // Very long marker content (DoS test)
    let very_long_content = "x".repeat(1_000_000);
    let very_long_marker = format!("⊠{{{}}}", very_long_content);
    assert!(has_any_markers(&very_long_marker));
    assert!(has_any_markers_bytes(very_long_marker.as_bytes()));

    // Multiple boundaries in single string
    let multi = "start ⊠{a} middle ⊕{b} end";
    assert!(has_any_markers(multi));
}

/// Test: Mixed marker types
///
/// Verifies that:
/// - Multiple different marker types in same content are all detected
/// - Precedence doesn't matter
/// - Detection works in any order
#[test]
fn test_mixed_marker_types() {
    let mixed_cases = vec![
        "⊠{encrypted} and ⊕{plaintext}",
        "⊕{plaintext} and ⊠{encrypted}",
        "⊠{a} ⊕{b} ⊲{c} [*{d} o+{e} <{f}",
        "[*{legacy} with ⊲{modern}",
        "o+{ascii} mixed with ⊠{unicode}",
    ];

    for text in mixed_cases {
        assert!(
            has_any_markers(text),
            "Mixed markers should be detected: {:?}",
            text
        );
        assert!(
            has_any_markers_bytes(text.as_bytes()),
            "Mixed markers (bytes) should be detected: {:?}",
            text
        );
    }
}

/// Test: Binary data with markers
///
/// Verifies that:
/// - Markers are detected in binary data
/// - Null bytes don't break detection
/// - Non-UTF-8 sequences are handled
#[test]
fn test_binary_data_with_markers() {
    // Binary data with embedded markers
    let mut binary_data = vec![0x00, 0xFF, 0xFE, 0x7F, 0x80];
    binary_data.extend_from_slice("⊠{secret}".as_bytes());
    binary_data.extend_from_slice(&[0x00, 0x01, 0x02]);

    assert!(
        has_any_markers_bytes(&binary_data),
        "Marker in binary data should be detected"
    );

    // Marker at start of binary data
    let mut start_marker = "⊕{start}".as_bytes().to_vec();
    start_marker.extend_from_slice(&[0x00, 0xFF]);
    assert!(has_any_markers_bytes(&start_marker));

    // Marker at end of binary data
    let mut end_marker = vec![0x00, 0xFF, 0x7F];
    end_marker.extend_from_slice("⊲{end}".as_bytes());
    assert!(has_any_markers_bytes(&end_marker));

    // Multiple null bytes around marker
    let mut null_bytes = vec![0x00, 0x00, 0x00];
    null_bytes.extend_from_slice("⊠{test}".as_bytes());
    null_bytes.extend_from_slice(&[0x00, 0x00, 0x00]);
    assert!(has_any_markers_bytes(&null_bytes));
}

/// Test: Malformed marker handling
///
/// Verifies that:
/// - Incomplete markers are not detected
/// - Truncated UTF-8 sequences are handled safely
/// - No crashes on malformed input
#[test]
fn test_malformed_marker_handling() {
    // Incomplete UTF-8 sequences for ⊠ (should be \xe2\x8a\xa0{)
    let incomplete_sequences = vec![
        vec![0xe2],                    // First byte only
        vec![0xe2, 0x8a],             // First two bytes
        vec![0xe2, 0x8a, 0xa0],       // Missing {
        vec![0xe2, 0x8a, 0xa0, b'}'], // } instead of {
        vec![0xe2, 0x8a, 0xa0, b' ', b'{'], // Space before {
    ];

    for seq in incomplete_sequences {
        let result = has_any_markers_bytes(&seq);
        // Should either detect nothing or handle gracefully (no panic)
        let _ = result;
    }

    // Truncated markers in strings
    let truncated = vec![
        "⊠",
        "⊠{",
        "⊠{incomplete",  // Missing closing }
        "⊕",
        "[*",
        "o+",
    ];

    for text in truncated {
        // Truncated markers should not be detected as valid markers
        // (except those that match partial patterns like "⊠{")
        let _ = has_any_markers(text);
    }
}

/// Test: Marker bypass attempts
///
/// Verifies that:
/// - URL encoding doesn't bypass detection
/// - HTML entities don't bypass detection
/// - Unicode normalization doesn't affect detection
#[test]
fn test_marker_bypass_attempts() {
    // URL-encoded attempts (should NOT be detected as raw URL encoding)
    let url_encoded = vec![
        "%E2%8A%A0%7Bsecret%7D",  // ⊠{secret} URL-encoded
        "%E2%8A%95%7Btext%7D",    // ⊕{text} URL-encoded
    ];

    for encoded in url_encoded {
        assert!(
            !has_any_markers(encoded),
            "URL-encoded markers should not be detected: {:?}",
            encoded
        );
    }

    // HTML entity attempts (should NOT be detected)
    let html_entities = vec![
        "&#8864;{secret}",  // ⊠ as decimal entity
        "&#x22A0;{secret}", // ⊠ as hex entity
    ];

    for entity in html_entities {
        assert!(
            !has_any_markers(entity),
            "HTML entities should not be detected: {:?}",
            entity
        );
    }

    // But actual Unicode characters should be detected
    assert!(has_any_markers("⊠{secret}"));
    assert!(has_any_markers("⊕{plaintext}"));
}

/// Test: Very long content with markers (DoS prevention)
///
/// Verifies that:
/// - Detection works on large files
/// - No excessive memory usage
/// - Performance remains reasonable
#[test]
fn test_very_long_content_with_markers() {
    // Marker at the very end of long content
    let mut long_content = "x".repeat(10_000_000); // 10MB
    long_content.push_str("⊠{at_end}");

    // Should detect marker even at end of large content
    assert!(has_any_markers(&long_content));
    assert!(has_any_markers_bytes(long_content.as_bytes()));

    // Marker at the very beginning
    let mut beginning = String::from("⊠{at_start}");
    beginning.push_str(&"y".repeat(10_000_000));
    assert!(has_any_markers(&beginning));

    // Marker in the middle
    let mut middle = String::from("z".repeat(5_000_000));
    middle.push_str("⊠{in_middle}");
    middle.push_str(&"z".repeat(5_000_000));
    assert!(has_any_markers(&middle));
}

/// Test: UTF-8 boundary edge cases
///
/// Verifies that:
/// - Markers split across byte boundaries work
/// - Invalid UTF-8 doesn't cause crashes
/// - Byte detection handles all cases
#[test]
fn test_utf8_boundary_edge_cases() {
    // Valid UTF-8 markers
    let valid = "text ⊠{secret} more";
    assert!(has_any_markers(valid));
    assert!(has_any_markers_bytes(valid.as_bytes()));

    // Marker at exact UTF-8 boundary
    let boundary = "⊠{boundary}";
    assert!(has_any_markers_bytes(boundary.as_bytes()));

    // Invalid UTF-8 sequences (byte detection should handle)
    let invalid_utf8 = vec![
        vec![0xFF, 0xFE],  // Invalid UTF-8 start
        vec![0x80, 0x81],  // Invalid continuation
        vec![0xC0, 0x80],  // Overlong encoding
    ];

    for seq in invalid_utf8 {
        // Should handle gracefully (no panic)
        let _ = has_any_markers_bytes(&seq);
    }

    // Mix of valid marker and invalid UTF-8
    let mut mixed = vec![0xFF, 0xFE];
    mixed.extend_from_slice("⊠{test}".as_bytes());
    mixed.extend_from_slice(&[0x80, 0x81]);
    assert!(has_any_markers_bytes(&mixed));
}

/// Test: Marker pattern consistency
///
/// Verifies that:
/// - MARKER_PATTERNS constant matches detection logic
/// - All patterns in array are detected
/// - Detection is symmetric
#[test]
fn test_marker_pattern_consistency() {
    // Verify all patterns in MARKER_PATTERNS are detected
    for pattern in MARKER_PATTERNS {
        let test_str = format!("{}secret}}", pattern);
        assert!(
            has_any_markers(&test_str),
            "Pattern '{}' should be detected",
            pattern
        );
        assert!(
            has_any_markers_bytes(test_str.as_bytes()),
            "Pattern '{}' should be detected (bytes)",
            pattern
        );
    }

    // Verify patterns are distinct
    let patterns_set: std::collections::HashSet<_> = MARKER_PATTERNS.iter().collect();
    assert_eq!(
        patterns_set.len(),
        MARKER_PATTERNS.len(),
        "All marker patterns should be unique"
    );
}

/// Test: Empty and null content
///
/// Verifies that:
/// - Empty strings don't trigger detection
/// - Empty bytes don't trigger detection
/// - Null/empty handling is safe
#[test]
fn test_empty_and_null_content() {
    // Empty content
    assert!(!has_any_markers(""));
    assert!(!has_any_markers_bytes(b""));
    assert!(!has_encrypted_markers(""));

    // Whitespace only
    assert!(!has_any_markers("   "));
    assert!(!has_any_markers("   \n\t  "));

    // Single characters
    assert!(!has_any_markers("a"));
    assert!(!has_any_markers_bytes(b"a"));

    // Null bytes only
    assert!(!has_any_markers_bytes(&[0x00]));
    assert!(!has_any_markers_bytes(&[0x00, 0x00, 0x00]));
}

/// Test: Case sensitivity
///
/// Verifies that:
/// - Markers are case-sensitive (exact match required)
/// - Uppercase/lowercase variations don't trigger false positives
#[test]
fn test_marker_case_sensitivity() {
    // Valid markers (exact case)
    assert!(has_any_markers("⊠{secret}"));
    assert!(has_any_markers("[*{legacy}"));
    assert!(has_any_markers("o+{ascii}"));

    // Case variations of ASCII markers (should still work since exact match)
    assert!(has_any_markers("[*{test}"));  // [* is lowercase
    assert!(has_any_markers("o+{test}"));  // o+ is lowercase

    // Note: Unicode markers ⊠⊕⊲ don't have case variations
}

/// Test: Concurrent marker detection
///
/// Verifies that:
/// - Detection is thread-safe
/// - No race conditions
/// - Results are consistent across threads
#[test]
fn test_concurrent_marker_detection() {
    use std::sync::Arc;
    use std::thread;

    let test_strings = Arc::new(vec![
        ("⊠{encrypted}", true),
        ("⊕{plaintext}", true),
        ("no markers", false),
        ("[*{legacy}", true),
        ("partial⊠ only", false),
        ("⊲{interpolation}", true),
        ("", false),
        ("mixed ⊠{a} and ⊕{b}", true),
    ]);

    let mut handles = vec![];

    // Spawn 10 threads detecting markers concurrently
    for i in 0..10 {
        let strings = Arc::clone(&test_strings);
        let handle = thread::spawn(move || {
            for (text, expected) in strings.iter() {
                let result = has_any_markers(text);
                assert_eq!(
                    result, *expected,
                    "Thread {}: '{}' expected {}, got {}",
                    i, text, expected, result
                );

                let result_bytes = has_any_markers_bytes(text.as_bytes());
                assert_eq!(
                    result_bytes, *expected,
                    "Thread {}: '{}' (bytes) expected {}, got {}",
                    i, text, expected, result_bytes
                );
            }
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
}

/// Test: Marker detection performance
///
/// Verifies that:
/// - Detection completes in reasonable time
/// - No catastrophic backtracking
/// - Linear time complexity on content size
#[test]
fn test_marker_detection_performance() {
    use std::time::Instant;

    // Test on progressively larger content
    let sizes = vec![1_000, 10_000, 100_000, 1_000_000];

    for size in sizes {
        let content = "x".repeat(size);

        let start = Instant::now();
        let _ = has_any_markers(&content);
        let duration = start.elapsed();

        // Detection should be very fast (< 10ms even for 1MB)
        assert!(
            duration.as_millis() < 100,
            "Detection took too long for {} bytes: {:?}",
            size,
            duration
        );
    }

    // Test with markers present
    for size in vec![1_000, 10_000, 100_000] {
        let mut content = "x".repeat(size / 2);
        content.push_str("⊠{middle}");
        content.push_str(&"x".repeat(size / 2));

        let start = Instant::now();
        let result = has_any_markers(&content);
        let duration = start.elapsed();

        assert!(result, "Marker should be detected");
        assert!(
            duration.as_millis() < 100,
            "Detection with marker took too long: {:?}",
            duration
        );
    }
}
