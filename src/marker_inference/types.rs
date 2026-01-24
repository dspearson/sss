//! Data structures for marker inference
//!
//! This module defines the core data types used throughout the marker inference algorithm.
//! All position tracking uses byte offsets (not character indices) for UTF-8 safety.

/// Position in text (byte offset, UTF-8 aware)
///
/// All positions are byte offsets into UTF-8 encoded strings. Use `str::char_indices()`
/// when iterating to ensure correct boundary handling.
pub type Position = usize;

/// A marked region in the source text
///
/// Tracks both source positions (with marker syntax) and rendered positions
/// (content only) to enable bidirectional mapping during inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// Start position in source text (byte offset, inclusive)
    pub source_start: Position,
    /// End position in source text (byte offset, exclusive)
    pub source_end: Position,
    /// Start position in rendered text (byte offset, inclusive)
    pub rendered_start: Position,
    /// End position in rendered text (byte offset, exclusive)
    pub rendered_end: Position,
    /// The content within the marker (what user sees)
    pub content: String,
}

/// A change detected by diff algorithm
///
/// Represents a single diff operation (insert, delete, or replacement)
/// in rendered text coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeHunk {
    /// Start position in rendered text (byte offset)
    pub rendered_start: Position,
    /// End position in rendered text (byte offset, exclusive)
    pub rendered_end: Position,
    /// Original content (from rendered text, may be empty for insertions)
    pub old_content: String,
    /// New content (from edited text, may be empty for deletions)
    pub new_content: String,
}

/// A change mapped back to source coordinates
///
/// Extends `ChangeHunk` with source position information and identifies
/// which original markers overlap or are adjacent to this change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedChange {
    /// Start position in source text (byte offset)
    pub source_start: Position,
    /// End position in source text (byte offset, exclusive)
    pub source_end: Position,
    /// Start position in rendered text (byte offset)
    pub rendered_start: Position,
    /// End position in rendered text (byte offset, exclusive)
    pub rendered_end: Position,
    /// New content to insert
    pub new_content: String,
    /// Indices of markers that overlap or are adjacent to this change
    pub overlapping_markers: Vec<usize>,
}

/// User-inserted marker (validated)
///
/// Represents a marker that the user explicitly added to the edited text.
/// These are validated for correct syntax and merged with inferred markers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMarker {
    /// Position in edited text where marker starts (byte offset)
    pub start: Position,
    /// Position in edited text where marker ends, after closing } (byte offset, exclusive)
    pub end: Position,
    /// Content within the marker
    pub content: String,
}

/// Result of user marker validation
///
/// Contains the validated text with any invalid markers escaped,
/// along with the list of valid user-inserted markers and warnings.
#[derive(Debug)]
pub struct ValidatedEdit {
    /// Edited text with invalid markers escaped
    pub text: String,
    /// Valid user-inserted markers found in edited text
    pub user_markers: Vec<UserMarker>,
    /// Warnings generated during validation (e.g., "escaped unclosed marker")
    pub warnings: Vec<String>,
}

/// Result of the marker inference process
///
/// The final output of `infer_markers()` containing the text with inferred
/// markers in canonical ⊕{...} format, plus any warnings generated.
#[derive(Debug, PartialEq, Eq)]
pub struct MarkerInferenceResult {
    /// The text with markers applied in canonical ⊕{...} format
    pub output: String,
    /// List of warnings (e.g., unmatched delimiters, escaped markers)
    pub warnings: Vec<String>,
}

/// Paired delimiter information
///
/// Represents a matched pair of opening and closing delimiters found in text.
/// Used to ensure both delimiters are marked or unmarked together for security.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelimiterPair {
    /// Position of opening delimiter (byte offset)
    pub open_pos: usize,
    /// Position of closing delimiter (byte offset)
    pub close_pos: usize,
    /// Opening delimiter character
    pub open_char: char,
    /// Closing delimiter character
    pub close_char: char,
}
