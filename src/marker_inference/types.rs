//! Data structures for marker inference

/// Position in text (byte offset, UTF-8 aware)
pub type Position = usize;

/// A marked region in the source text
#[derive(Debug, Clone, PartialEq)]
pub struct Marker {
    /// Start position in source text
    pub source_start: Position,
    /// End position in source text (exclusive)
    pub source_end: Position,
    /// Start position in rendered text
    pub rendered_start: Position,
    /// End position in rendered text (exclusive)
    pub rendered_end: Position,
    /// The content within the marker
    pub content: String,
}

/// A change detected by diff algorithm
#[derive(Debug, Clone)]
pub struct ChangeHunk {
    /// Start position in rendered text
    pub rendered_start: Position,
    /// End position in rendered text (exclusive)
    pub rendered_end: Position,
    /// Original content (from rendered text)
    pub old_content: String,
    /// New content (from edited text)
    pub new_content: String,
}

/// A change mapped back to source coordinates
#[derive(Debug, Clone)]
pub struct MappedChange {
    /// Start position in source text
    pub source_start: Position,
    /// End position in source text (exclusive)
    pub source_end: Position,
    /// Start position in rendered text
    pub rendered_start: Position,
    /// End position in rendered text (exclusive)
    pub rendered_end: Position,
    /// New content to insert
    pub new_content: String,
    /// Indices of markers that overlap this change
    pub overlapping_markers: Vec<usize>,
}

/// User-inserted marker (validated)
#[derive(Debug, Clone)]
pub struct UserMarker {
    /// Position in edited text where marker starts
    pub start: Position,
    /// Position in edited text where marker ends (after })
    pub end: Position,
    /// Content within the marker
    pub content: String,
}

/// Result of user marker validation
#[derive(Debug)]
pub struct ValidatedEdit {
    /// Edited text with invalid markers escaped
    pub text: String,
    /// Valid user-inserted markers
    pub user_markers: Vec<UserMarker>,
    /// Warnings generated during validation
    pub warnings: Vec<String>,
}

/// Result of the marker inference process
#[derive(Debug)]
pub struct MarkerInferenceResult {
    /// The text with markers applied
    pub output: String,
    /// List of warnings (e.g., unmatched delimiters)
    pub warnings: Vec<String>,
}

/// Paired delimiter information
#[derive(Debug)]
pub struct DelimiterPair {
    pub open_pos: usize,
    pub close_pos: usize,
    pub open_char: char,
    pub close_char: char,
}
