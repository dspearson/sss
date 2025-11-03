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

pub mod types;
pub mod error;
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
}
