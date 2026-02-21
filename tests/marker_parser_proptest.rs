//! Property-based tests for the marker parser (TEST-06).
//!
//! Uses the `proptest` crate to generate adversarial inputs — arbitrary UTF-8
//! strings, brace-heavy strings, well-formed markers, and binary-like content —
//! and verifies that `find_balanced_markers` never panics and always upholds its
//! documented invariants.

use proptest::prelude::*;
use sss::processor::find_balanced_markers;

/// The set of marker prefixes used throughout the test suite.
const PREFIXES: &[&str] = &["o+", "\u{2295}", "\u{2A02}"];

// ─────────────────────────────────────────────────────────────────────────────
// Strategies
// ─────────────────────────────────────────────────────────────────────────────

/// Arbitrary UTF-8 string (any valid Unicode scalar values, any length 0-500).
fn arb_utf8() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..500)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Strings biased toward braces, marker prefixes, and mixed Unicode.
fn arb_brace_heavy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            // Brace characters
            Just('{'),
            Just('}'),
            // Marker prefix characters
            Just('o'),
            Just('+'),
            // Unicode marker prefix chars (first byte of multi-byte sequences)
            Just('\u{2295}'),
            Just('\u{2A02}'),
            // Printable ASCII
            prop::char::range('!', '~'),
            // Whitespace
            prop_oneof![Just(' '), Just('\n'), Just('\t')],
        ],
        0..400,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Generate well-formed marker strings: prefix + `{` + content_without_unbalanced_braces + `}`.
/// Content is printable ASCII without `{` or `}`.
fn arb_well_formed_marker() -> impl Strategy<Value = (String, String)> {
    let prefix_strategy = prop_oneof![
        Just("o+".to_string()),
        Just("\u{2295}".to_string()),
        Just("\u{2A02}".to_string()),
    ];
    let content_strategy = prop::collection::vec(
        prop::char::range('!', '~').prop_filter("no braces", |c| *c != '{' && *c != '}'),
        1..50,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>());

    (prefix_strategy, content_strategy)
}

/// Adversarial strings: deeply nested braces, unterminated braces, mixed UTF-8.
fn arb_adversarial() -> impl Strategy<Value = String> {
    prop_oneof![
        // Deeply nested braces
        (1usize..=20usize).prop_map(|n| {
            let opens: String = std::iter::repeat('{').take(n).collect();
            let closes: String = std::iter::repeat('}').take(n).collect();
            format!("o+{opens}{closes}")
        }),
        // Unterminated braces
        (1usize..=20usize).prop_map(|n| {
            let opens: String = std::iter::repeat('{').take(n).collect();
            format!("o+{opens}")
        }),
        // Mixed UTF-8 with braces
        prop::collection::vec(
            prop_oneof![
                Just('{'),
                Just('}'),
                Just('\u{2295}'),
                Just('\u{2A02}'),
                any::<char>(),
            ],
            0..300,
        )
        .prop_map(|chars| chars.into_iter().collect()),
        // Only closing braces (stress test for underflow guard)
        (0usize..=50usize).prop_map(|n| {
            let closes: String = std::iter::repeat('}').take(n).collect();
            format!("o+{closes}")
        }),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Property tests
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Property 1: find_balanced_markers never panics on arbitrary UTF-8 input.
    #[test]
    fn no_panic_on_arbitrary_utf8(s in arb_utf8()) {
        let _ = find_balanced_markers(&s, PREFIXES);
    }

    /// Property 2: find_balanced_markers never panics on brace-heavy input.
    #[test]
    fn no_panic_on_brace_heavy_input(s in arb_brace_heavy()) {
        let _ = find_balanced_markers(&s, PREFIXES);
    }

    /// Property 3: find_balanced_markers never panics on adversarial input.
    #[test]
    fn no_panic_on_adversarial_input(s in arb_adversarial()) {
        let _ = find_balanced_markers(&s, PREFIXES);
    }

    /// Property 4: every returned MarkerMatch has start < end and valid byte positions.
    #[test]
    fn markers_have_valid_positions(s in arb_utf8()) {
        let matches = find_balanced_markers(&s, PREFIXES);
        for m in &matches {
            prop_assert!(
                m.start < m.end,
                "start ({}) must be < end ({})",
                m.start,
                m.end
            );
            prop_assert!(
                m.end <= s.len(),
                "end ({}) must be <= input length ({})",
                m.end,
                s.len()
            );
            // The byte slice must be valid UTF-8 (it is a sub-slice of a valid UTF-8 string).
            prop_assert!(
                std::str::from_utf8(s[m.start..m.end].as_bytes()).is_ok(),
                "Marker byte range must be valid UTF-8"
            );
        }
    }

    /// Property 5: well-formed markers embedded in random text are always detected.
    #[test]
    fn well_formed_markers_always_detected(
        prefix_and_content in arb_well_formed_marker(),
        before in arb_utf8(),
        after in arb_utf8(),
    ) {
        let (prefix, content) = prefix_and_content;
        let marker = format!("{prefix}{{{content}}}");
        let input = format!("{before}{marker}{after}");

        let prefixes: Vec<&str> = PREFIXES.to_vec();
        let matches = find_balanced_markers(&input, &prefixes);

        // There must be at least one match, and one of them must have `content` as its content.
        prop_assert!(
            !matches.is_empty(),
            "Well-formed marker must be detected in: {:?}",
            input
        );
        prop_assert!(
            matches.iter().any(|m| m.content == content),
            "No match found with content {:?} in matches: {:?}",
            content,
            matches
        );
    }

    /// Property 6: returned matches are non-overlapping and in ascending start order.
    #[test]
    fn markers_non_overlapping_and_ordered(s in arb_utf8()) {
        let matches = find_balanced_markers(&s, PREFIXES);
        for window in matches.windows(2) {
            let prev = &window[0];
            let next = &window[1];
            prop_assert!(
                next.start >= prev.end,
                "Matches must not overlap: prev.end={}, next.start={}",
                prev.end,
                next.start
            );
            prop_assert!(
                next.start >= prev.start,
                "Matches must be in ascending start order"
            );
        }
    }

    /// Property 7: empty prefix list always returns an empty vec.
    #[test]
    fn empty_prefixes_returns_empty(s in arb_utf8()) {
        let matches = find_balanced_markers(&s, &[]);
        prop_assert!(
            matches.is_empty(),
            "Empty prefix list must always yield empty result, got: {:?}",
            matches
        );
    }

    /// Property 8: arbitrary byte sequences (converted via lossy UTF-8) do not cause panics.
    #[test]
    fn no_panic_on_binary_content(bytes in prop::collection::vec(any::<u8>(), 0..500)) {
        let s = String::from_utf8_lossy(&bytes).into_owned();
        let _ = find_balanced_markers(&s, PREFIXES);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic edge-case sanity checks
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod deterministic {
    use super::*;

    #[test]
    fn single_well_formed_marker_detected() {
        let matches = find_balanced_markers("o+{hello}", PREFIXES);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "hello");
    }

    #[test]
    fn deeply_nested_braces_no_panic() {
        // 100 levels of nesting — must not overflow or panic.
        let opens: String = std::iter::repeat('{').take(100).collect();
        let closes: String = std::iter::repeat('}').take(100).collect();
        let input = format!("o+{opens}content{closes}");
        let _ = find_balanced_markers(&input, PREFIXES);
    }

    #[test]
    fn unterminated_braces_no_panic_and_no_match() {
        let input = "o+{unterminated";
        let matches = find_balanced_markers(input, PREFIXES);
        assert!(matches.is_empty(), "Unterminated brace must not produce a match");
    }

    #[test]
    fn consecutive_markers_are_independent() {
        let input = "o+{first}o+{second}o+{third}";
        let matches = find_balanced_markers(input, PREFIXES);
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].content, "first");
        assert_eq!(matches[1].content, "second");
        assert_eq!(matches[2].content, "third");
    }

    #[test]
    fn empty_input_no_panic() {
        let matches = find_balanced_markers("", PREFIXES);
        assert!(matches.is_empty());
    }

    #[test]
    fn unicode_prefix_marker_detected() {
        // ⊕ (U+2295) is one of our prefixes.
        let input = "\u{2295}{value}";
        let matches = find_balanced_markers(input, PREFIXES);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].content, "value");
    }
}
