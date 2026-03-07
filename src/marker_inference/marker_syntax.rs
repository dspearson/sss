//! Shared marker syntax utilities
//!
//! Common functions for detecting, parsing, and handling marker syntax
//! used by both parser.rs and validator.rs.

/// Marker format type
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MarkerFormat {
    /// o+{...} format (easy to type)
    OPlus,
    /// ⊕{...} format (canonical)
    Circled,
}

impl MarkerFormat {
    /// Length of the opening syntax in bytes (prefix only, not including delimiter)
    pub fn prefix_len(self) -> usize {
        match self {
            MarkerFormat::OPlus => 2,   // "o+"
            MarkerFormat::Circled => "⊕".len(),
        }
    }

    /// Opening syntax as string (default `{` form — used for emitting
    /// escape fallbacks when a marker is unclosed or nested).
    pub fn prefix(self) -> &'static str {
        match self {
            MarkerFormat::OPlus => "o+{",
            MarkerFormat::Circled => "⊕{",
        }
    }

    /// Escaped form of the opening syntax — used when a marker is invalid
    /// and we want to preserve the bytes literally.
    pub fn escaped(self) -> &'static str {
        match self {
            MarkerFormat::OPlus => "o+\\{",
            MarkerFormat::Circled => "⊕\\{",
        }
    }

    /// Length of the escaped form in bytes
    #[allow(dead_code)]
    pub fn escaped_len(self) -> usize {
        match self {
            MarkerFormat::OPlus => 4,   // "o+\\{"
            MarkerFormat::Circled => "⊕\\{".len(),
        }
    }
}

/// Supported open/close delimiter pairs for markers, in preference order.
///
/// Shares its intent with `src/processor/core.rs::DELIMITER_PAIRS` — a value
/// wrapped on one side is parseable on the other. `{}` stays first so
/// existing files are byte-identical; the remaining pairs are chosen from
/// distinct Unicode blocks so no single content collides with every entry.
pub const DELIMITER_PAIRS: &[(char, char)] = &[
    ('{', '}'),
    ('[', ']'),
    ('\u{27E6}', '\u{27E7}'),   // ⟦ ⟧
    ('\u{27E8}', '\u{27E9}'),   // ⟨ ⟩
    ('\u{27EA}', '\u{27EB}'),   // ⟪ ⟫
    ('\u{27EC}', '\u{27ED}'),   // ⟬ ⟭
    ('\u{27EE}', '\u{27EF}'),   // ⟮ ⟯
    ('\u{2983}', '\u{2984}'),   // ⦃ ⦄
    ('\u{2985}', '\u{2986}'),   // ⦅ ⦆
    ('\u{2987}', '\u{2988}'),   // ⦇ ⦈
    ('\u{2989}', '\u{298A}'),   // ⦉ ⦊
    ('\u{298B}', '\u{298C}'),   // ⦋ ⦌
    ('\u{300C}', '\u{300D}'),   // 「 」
    ('\u{300E}', '\u{300F}'),   // 『 』
];

/// Look up the closing delimiter for an opening character from the supported set.
pub fn close_for_open(open: char) -> Option<char> {
    DELIMITER_PAIRS
        .iter()
        .find(|(o, _)| *o == open)
        .map(|(_, c)| *c)
}

/// Pick a delimiter pair whose open and close chars do not appear in `value`.
///
/// `{}` is preferred when braces in `value` balance, otherwise we walk the
/// ladder. Falls back to `{}` if every candidate collides — unreachable in
/// practice given the table's breadth.
pub fn pick_delimiter(value: &str) -> (char, char) {
    if braces_balance(value) {
        return ('{', '}');
    }
    DELIMITER_PAIRS
        .iter()
        .skip(1)
        .copied()
        .find(|(o, c)| !value.contains(*o) && !value.contains(*c))
        .unwrap_or(('{', '}'))
}

/// Return true if curly braces in `value` balance — every `}` is preceded by
/// an open, and the final depth is zero.
fn braces_balance(value: &str) -> bool {
    let mut depth: i32 = 0;
    for ch in value.chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

/// Detect a marker opening at the current position.
///
/// Returns `Some((format, open_char, close_char))` when `text` starts with
/// a recognised prefix (`o+` or `⊕`) immediately followed by a supported
/// opening delimiter character. The caller uses `open_char`/`close_char` to
/// parameterise the subsequent balanced-delimiter scan.
pub fn detect_marker_start(text: &str) -> Option<(MarkerFormat, char, char)> {
    let (format, after_prefix) = if let Some(rest) = text.strip_prefix("o+") {
        (MarkerFormat::OPlus, rest)
    } else if let Some(rest) = text.strip_prefix('⊕') {
        (MarkerFormat::Circled, rest)
    } else {
        return None;
    };
    let open = after_prefix.chars().next()?;
    let close = close_for_open(open)?;
    Some((format, open, close))
}

/// Check if position starts with an escaped marker
///
/// Returns `Some((escaped_str`, `byte_len`)) if text starts with escaped
/// marker in the default `{` form. Alternate delimiters don't need escape
/// support — the chooser avoids them if the value contains a collision.
pub fn is_escaped_marker(text: &str) -> Option<(&'static str, usize)> {
    if text.starts_with("o+\\{") {
        Some(("o+\\{", 4))
    } else if text.starts_with("⊕\\{") {
        Some(("⊕\\{", "⊕\\{".len()))
    } else {
        None
    }
}

/// Find the position of the first unmatched closing delimiter.
///
/// For the default `}` close char, `\}` is treated as an escape and skipped.
/// For alternate close chars (e.g. `]`, `⟧`, `⦄`) no escape logic applies
/// — the delimiter is chosen precisely because `value` doesn't contain it,
/// so there's no ambiguity to escape.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(find_unescaped_close("hello}", '}'), Some(5));
/// assert_eq!(find_unescaped_close("text \\} more}", '}'), Some(12));
/// assert_eq!(find_unescaped_close("foo⦄bar", '⦄'), Some(3));
/// ```
pub fn find_unescaped_close(text: &str, close: char) -> Option<usize> {
    let escapes_enabled = close == '}';
    let mut pos = 0;
    while pos < text.len() {
        if escapes_enabled && text[pos..].starts_with("\\}") {
            pos += 2;
            continue;
        }
        let ch = text[pos..].chars().next().unwrap();
        if ch == close {
            return Some(pos);
        }
        pos += ch.len_utf8();
    }
    None
}

/// Check if content contains nested marker syntax (any recognised opener).
///
/// Returns true if content contains any prefix (`o+` or `⊕`) immediately
/// followed by a supported opener char from `DELIMITER_PAIRS`.
pub fn contains_nested_markers(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut byte_pos = 0;
    while byte_pos < bytes.len() {
        let rest = &content[byte_pos..];
        let after_prefix = if rest.starts_with("o+") {
            Some(&rest[2..])
        } else if rest.starts_with('⊕') {
            Some(&rest['⊕'.len_utf8()..])
        } else {
            None
        };
        if let Some(after) = after_prefix {
            if let Some(ch) = after.chars().next() {
                if DELIMITER_PAIRS.iter().any(|(o, _)| *o == ch) {
                    return true;
                }
            }
        }
        // Advance one char
        let ch = rest.chars().next().unwrap();
        byte_pos += ch.len_utf8();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_format_methods() {
        assert_eq!(MarkerFormat::OPlus.prefix_len(), 2);
        assert_eq!(MarkerFormat::Circled.prefix_len(), "⊕".len());
        assert_eq!(MarkerFormat::OPlus.prefix(), "o+{");
        assert_eq!(MarkerFormat::Circled.prefix(), "⊕{");
        assert_eq!(MarkerFormat::OPlus.escaped(), "o+\\{");
        assert_eq!(MarkerFormat::Circled.escaped(), "⊕\\{");
    }

    #[test]
    fn test_detect_marker_start_default_pair() {
        let (fmt, o, c) = detect_marker_start("o+{test}").unwrap();
        assert_eq!(fmt, MarkerFormat::OPlus);
        assert_eq!((o, c), ('{', '}'));
        let (fmt, o, c) = detect_marker_start("⊕{test}").unwrap();
        assert_eq!(fmt, MarkerFormat::Circled);
        assert_eq!((o, c), ('{', '}'));
    }

    #[test]
    fn test_detect_marker_start_alternate_pairs() {
        let (fmt, o, c) = detect_marker_start("o+[foo]").unwrap();
        assert_eq!(fmt, MarkerFormat::OPlus);
        assert_eq!((o, c), ('[', ']'));
        let (fmt, o, c) = detect_marker_start("⊕⦃foo⦄").unwrap();
        assert_eq!(fmt, MarkerFormat::Circled);
        assert_eq!((o, c), ('\u{2983}', '\u{2984}'));
    }

    #[test]
    fn test_detect_marker_start_no_match() {
        assert!(detect_marker_start("regular text").is_none());
        assert!(detect_marker_start("o+\\{escaped}").is_none(), "escaped form has `\\` not an opener");
        assert!(detect_marker_start("⊕xfoo").is_none(), "x is not a supported opener");
    }

    #[test]
    fn test_is_escaped_marker() {
        assert_eq!(is_escaped_marker("o+\\{test}"), Some(("o+\\{", 4)));
        assert_eq!(is_escaped_marker("⊕\\{test}"), Some(("⊕\\{", "⊕\\{".len())));
        assert_eq!(is_escaped_marker("o+{test}"), None);
        assert_eq!(is_escaped_marker("regular"), None);
    }

    #[test]
    fn test_find_unescaped_close_default() {
        assert_eq!(find_unescaped_close("hello}", '}'), Some(5));
        assert_eq!(find_unescaped_close("text \\} more}", '}'), Some(12));
        assert_eq!(find_unescaped_close("no closing", '}'), None);
        assert_eq!(find_unescaped_close("日本語}", '}'), Some("日本語".len()));
    }

    #[test]
    fn test_find_unescaped_close_alternate() {
        // No escape handling for non-default close chars — `\]` is just two chars.
        assert_eq!(find_unescaped_close("foo]", ']'), Some(3));
        assert_eq!(find_unescaped_close("foo\\]", ']'), Some(4));
        assert_eq!(find_unescaped_close("foo⦄bar", '\u{2984}'), Some(3));
    }

    #[test]
    fn test_contains_nested_markers() {
        assert!(contains_nested_markers("outer o+{inner}"));
        assert!(contains_nested_markers("outer ⊕{inner}"));
        assert!(contains_nested_markers("outer o+[inner]"),   "alternate pair counts as nested");
        assert!(contains_nested_markers("outer ⊕⦃inner⦄"),    "exotic pair counts as nested");
        assert!(!contains_nested_markers("no markers here"));
        assert!(!contains_nested_markers("o+\\{escaped}"),    "escaped form does not count");
    }

    #[test]
    fn test_pick_delimiter_default_when_balanced() {
        assert_eq!(pick_delimiter("plain"), ('{', '}'));
        assert_eq!(pick_delimiter(r#"{"json": "blob"}"#), ('{', '}'), "balanced braces stay default");
    }

    #[test]
    fn test_pick_delimiter_switches_on_unbalanced() {
        let (o, c) = pick_delimiter("pass}word");
        assert_ne!((o, c), ('{', '}'));
        assert!(!"pass}word".contains(o));
        assert!(!"pass}word".contains(c));
    }
}
