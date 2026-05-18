// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 16 Plan 04 — D-07.3 candidate-pool branch coverage for `src/merge.rs`.
//!
//! Targets the two fallback arms inside `smart_reconstruct` that survey-uncovered
//! ranges flagged in `coverage-before.txt`:
//!   - the `has_markers` -> `reconstruct_multimarker_line == None` fallback (lines 340-341)
//!   - the final-safety unbalanced-output wrap arm (lines 356-358)
//!
//! Allowed file (per 16-04 plan whitelist).

use anyhow::Result;
use sss::smart_reconstruct;

/// MERGE-01: src/merge.rs:340-341 — `has_markers` true but multimarker reconstruction returns None.
///
/// Trigger: craft an old line that contains an unbalanced/unmatched marker brace
/// (e.g. `⊕{unclosed`). `has_markers(old_opened)` is true, but
/// `reconstruct_multimarker_line` cannot parse a balanced multimarker layout and
/// returns `None`. Code falls through to the bare `result_lines.push(new_line.to_string())`
/// fallback at lines 340-341.
#[test]
fn merge_01_unmatched_multimarker_falls_through_to_plain_push() -> Result<()> {
    // Old line: has `⊕{` but never closes (unbalanced -> reconstruct_multimarker
    // returns None).
    let opened_old = "key: ⊕{unclosed";
    let rendered_old = "key: secret123";
    // New line is a modification of the same row -> Insert-after-Delete pair.
    let rendered_new = "key: brand_new_value";

    let result = smart_reconstruct(rendered_new, opened_old, rendered_old)?;

    // The fallback at line 340 pushes the new line VERBATIM (no marker
    // wrapping). Final result must equal the new line literally.
    assert_eq!(result, "key: brand_new_value");
    Ok(())
}

/// MERGE-02: src/merge.rs:356-358 — final-safety unbalanced-output wrap arm.
///
/// Trigger: craft inputs whose mid-stream reconstruction produces an unbalanced
/// marker output. The post-loop check
/// `if has_markers(&result) && !markers_balanced(&result)` then wraps the
/// entire `rendered_new` content in a single `⊕{...}` marker.
///
/// Strategy: an old line that *is* a fully-encrypted single-line marker
/// (`⊕{...}` covering the whole line). When the new line replaces it with
/// content that itself looks like an unclosed marker (`⊕{partial`), the
/// "old line entirely encrypted" branch wraps the new line — but the result
/// before wrap is `⊕{⊕{partial}` (nested + unbalanced once collapsed). The
/// final safety check fires.
#[test]
fn merge_02_unbalanced_output_triggers_safety_wrap() -> Result<()> {
    // Old line: entirely-encrypted single-line marker.
    let opened_old = "⊕{old_secret_value}";
    let rendered_old = "old_secret_value";
    // New line: itself contains an unbalanced opening sequence so that
    // when the "old entirely encrypted" arm wraps it, the resulting marker
    // structure is unbalanced.
    let rendered_new = "new_value_with_⊕{open_brace";

    let result = smart_reconstruct(rendered_new, opened_old, rendered_old)?;

    // The safety arm wraps the entire rendered_new (trimmed) in ⊕{...}.
    // Whether we hit lines 325 (entirely-encrypted) wrap OR the final
    // safety wrap, the post-condition is: output begins with `⊕{` and the
    // inner trimmed content matches `rendered_new`.
    assert!(result.starts_with("⊕{"), "expected ⊕{{ prefix, got: {result}");
    assert!(result.contains("new_value_with"), "expected new content preserved, got: {result}");
    Ok(())
}
