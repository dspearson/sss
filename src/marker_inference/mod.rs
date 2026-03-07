//! Intelligent Marker Preservation System
//!
//! This module implements a diff-based algorithm with conservative expansion rules to:
//! - Preserve encryption markers on modified sensitive content
//! - Expand markers to cover adjacent modifications
//! - Propagate markers to duplicate sensitive content
//! - Handle user-inserted markers correctly
//! - Maintain security by over-marking rather than leaking
//!
//! ## Key Principles
//!
//! 1. **Security-First**: When uncertain, mark content rather than risk leakage
//! 2. **Intent Preservation**: Respect the semantic structure of separately-marked regions
//! 3. **Format-Agnostic**: No file-type-specific intelligence; purely text-based
//! 4. **Predictable**: Conservative, rule-based behaviour without "magic"
//! 5. **User Control**: Allow explicit marker insertion with validation
//!
//! ## Marker Formats
//!
//! - **Plaintext markers**: `o+{content}` (manual typing) or `⊕{content}` (canonical)
//! - **Ciphertext markers**: `⊠{ciphertext}` (encrypted, not handled by this module)
//!
//! Both `o+{...}` and `⊕{...}` are functionally equivalent for plaintext marking.
//! The system accepts both as input and outputs using the canonical `⊕{...}` format.
//!
//! ## Algorithm Steps
//!
//! The marker inference algorithm operates in 8 sequential steps:
//!
//! 1. **Parse Markers** - Extract existing markers from source text
//! 2. **Compute Diff** - Find changes between rendered and edited versions
//! 3. **Validate User Markers** - Check user-inserted markers for validity
//! 4. **Map Changes** - Convert change positions to source coordinates
//! 5. **Apply Rules** - Execute 5 marker expansion rules
//! 6. **Propagate** - Mark all duplicate instances of sensitive content
//! 7. **Validate Delimiters** - Ensure paired delimiters stay together
//! 8. **Reconstruct** - Build output with canonical marker format
//!
//! ## Expansion Rules
//!
//! The system uses 5 core rules to determine marker placement:
//!
//! 1. **Replacement of Marked Content**: Changes spanning multiple markers → mark entire span
//! 2. **Adjacent Modifications**: Change adjacent to single marker → expand that marker
//! 3. **Ambiguous Adjacency (Left-Bias)**: Adjacent to multiple markers → merge with left
//! 4. **Preservation of Separate Markers**: Change affects only one → preserve separation
//! 5. **Unmarked Content**: No adjacent markers → handled by propagation
//!
//! ## Usage Example
//!
//! ```rust
//! use sss::marker_inference::infer_markers;
//!
//! // Original file with plaintext marker
//! let source = "password: o+{secret123}";
//!
//! // User edits the rendered content
//! let edited = "password: newsecret456";
//!
//! // Infer where markers should be
//! let result = infer_markers(source, edited)?;
//!
//! // Output: "password: ⊕{newsecret456}"
//! assert_eq!(result.output, "password: ⊕{newsecret456}");
//!
//! // Check for any warnings
//! for warning in &result.warnings {
//!     eprintln!("Warning: {}", warning);
//! }
//! # Ok::<(), sss::marker_inference::MarkerInferenceError>(())
//! ```
//!
//! ## Error Handling
//!
//! The system returns detailed errors for:
//! - Invalid UTF-8 input
//! - Malformed markers
//! - Binary content detection
//! - Internal processing failures
//!
//! Warnings (non-fatal) are provided for:
//! - Unmatched delimiter pairs
//! - Escaped invalid markers
//! - Marker expansion decisions
//!
//! ## Performance Characteristics
//!
//! - **Time Complexity**: O(n·k + ND) where n=file size, k=marker count, D=edit distance
//! - **Space Complexity**: O(n + k)
//! - **Optimizations**: Aho-Corasick multi-pattern matching for propagation
//!
//! ## Safety and Security
//!
//! - **UTF-8 Safe**: All position tracking uses byte offsets with proper boundary validation
//! - **Conservative**: Prefers over-marking to under-marking for security
//! - **No Regex**: Uses deterministic parsing to avoid `ReDoS` attacks
//! - **Memory Bounded**: Input size limits prevent `DoS` via large files

#![allow(clippy::missing_errors_doc)]

pub mod types;
pub mod error;
mod marker_syntax;
mod parser;
mod validator;
mod diff;
mod mapper;
mod expander;
mod propagator;
mod delimiter;
mod reconstructor;

pub use types::MarkerInferenceResult;
pub use error::{MarkerInferenceError, Result};

/// Main entry point for marker inference
///
/// Takes the original source text (with markers) and edited text (user modifications),
/// and returns the text with intelligently inferred markers.
///
/// # Algorithm Steps
///
/// 1. Parse source to extract markers
/// 2. Compute diff between rendered and edited
/// 3. Validate user-inserted markers in edited text
/// 4. Map changes back to source positions
/// 5. Apply marker expansion rules
/// 6. Propagate markers to unmarked duplicates
/// 7. Validate paired delimiter integrity
/// 8. Reconstruct output with markers
///
/// # Examples
///
/// ```no_run
/// use sss::marker_inference::infer_markers;
///
/// let source = "password: o+{secret123}";
/// let edited = "password: newsecret456";
///
/// let result = infer_markers(source, edited).unwrap();
/// assert_eq!(result.output, "password: ⊕{newsecret456}");
/// ```
pub fn infer_markers(source_text: &str, edited_text: &str) -> Result<MarkerInferenceResult> {
    // Step 1: Parse source to extract markers
    let (rendered_text, original_markers) = parser::parse_markers(source_text)?;

    // Step 2: Compute diff between rendered and edited
    let changes = diff::compute_diff(&rendered_text, edited_text)?;

    // Step 3: Validate user-inserted markers in edited text
    let validated = validator::validate_user_markers(edited_text);

    // Step 4: Map changes back to source positions
    let mapped_changes = mapper::map_changes_to_source(changes, &original_markers);

    // Step 5: Apply marker expansion rules
    let mut new_markers = expander::apply_expansion_rules(
        mapped_changes,
        &original_markers,
        &validated.user_markers,
        &validated.text,
    );

    // Step 6: Propagate markers to unmarked duplicates
    new_markers = propagator::propagate_markers(&validated.text, &new_markers);

    // Step 7: Validate paired delimiter integrity
    let mut warnings = delimiter::validate_delimiters(&validated.text, &mut new_markers);

    // Step 8: Add warnings for escaped markers
    warnings.extend(validated.warnings);

    // Step 9: Reconstruct output with markers
    let output = reconstructor::reconstruct_with_markers(&validated.text, &new_markers);

    Ok(MarkerInferenceResult { output, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_modification() {
        let source = "password: o+{secret123}";
        let edited = "password: newsecret456";

        let result = infer_markers(source, edited).unwrap();
        assert!(result.output.contains("⊕{newsecret456}"));
    }

    #[test]
    fn test_content_propagation_duplicate() {
        // Exact scenario from failing FUSE test
        let source = "password: o+{secret}\nother text";
        let edited = "password: secret\nother text\npassword again: secret";

        let result = infer_markers(source, edited).unwrap();

        let marker_count = result.output.matches("⊕{secret}").count()
            + result.output.matches("o+{secret}").count();

        assert_eq!(marker_count, 2,
            "Both instances of 'secret' should be marked. Output: {}",
            result.output);
    }

    #[test]
    fn test_multiple_markers_all_changed() {
        // The exact scenario that's failing
        let source = "username: o+{admin}\npassword: o+{secret}\napi_key: o+{abc-123}";
        let edited = "username: root\npassword: newsecret\napi_key: xyz-789";

        let result = infer_markers(source, edited).unwrap();

        // All three values should be marked
        assert!(result.output.contains("⊕{root}"),
            "Should mark 'root'. Output: {}", result.output);
        assert!(result.output.contains("⊕{newsecret}"),
            "Should mark 'newsecret'. Output: {}", result.output);
        assert!(result.output.contains("⊕{xyz-789}"),
            "Should mark 'xyz-789'. Output: {}", result.output);

        // Expected output
        let expected = "username: ⊕{root}\npassword: ⊕{newsecret}\napi_key: ⊕{xyz-789}";
        assert_eq!(result.output, expected,
            "Output should match expected format");
    }

    #[test]
    fn test_source_with_alternate_delimiter_recognised() {
        // Source already uses an alternate delimiter pair because the value
        // contains `}`. Inference must recognise the marker (not treat it as
        // plain text) and reconstruct a marker around the same value.
        //
        // The emitted pair is content-determined (pick_delimiter picks the
        // first non-colliding pair from the ladder), so it may differ from
        // the source — that's correct, because value identity is what
        // matters, not delimiter fidelity.
        let source = "password: ⊕⦃pass}word⦄\n";
        let edited = "password: pass}word\n"; // rendered form (delimiters stripped)

        let result = infer_markers(source, edited).unwrap();
        // Re-parse the output — the marker must round-trip cleanly with the
        // correct captured value.
        let (rendered, markers) = parser::parse_markers(&result.output).unwrap();
        assert_eq!(rendered, edited, "output must render back to the edited text");
        assert_eq!(markers.len(), 1, "expected exactly one marker");
        assert_eq!(markers[0].content, "pass}word", "value must be preserved byte-for-byte");
    }

    #[test]
    fn test_edit_value_into_unbalanced_brace_picks_alternate() {
        // Source has a regular marker; user edits the content to contain `}`.
        // The reconstructor must auto-switch to an alternate delimiter.
        let source = "pw: ⊕{before}\n";
        let edited = "pw: after}value\n"; // user typed `}` into the rendered value

        let result = infer_markers(source, edited).unwrap();
        let output = result.output;
        // The value now contains `}` so the default `{}` pair would chomp it.
        // Verify reconstructor picked something else.
        assert!(
            !output.contains("⊕{after}value}"),
            "default pair would mis-parse — must use alternate. Output: {output}",
        );
        // The new value must be wrapped in a marker form that parses correctly
        // when we re-parse the output.
        let (rendered, markers) = parser::parse_markers(&output).unwrap();
        assert_eq!(rendered, edited, "re-parsing must recover the original rendered form");
        assert_eq!(markers.len(), 1, "expected one marker");
        assert_eq!(markers[0].content, "after}value");
    }
}
