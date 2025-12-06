// Processor component modules
//
// This module organizes the Processor implementation into focused components:
// - `core`: Main Processor implementation (transitional)
// - `marker_parser`: Marker finding and parsing with balanced brace counting
// - `secrets_handler`: Secrets lookup, caching, and interpolation (TODO)

pub mod core;
pub mod marker_parser;
// pub mod secrets_handler; // TODO: Extract from core

// Re-export main Processor and commonly used types
pub use core::Processor;
pub use marker_parser::{find_balanced_markers, MarkerMatch};
