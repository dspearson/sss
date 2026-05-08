#![no_main]
use libfuzzer_sys::fuzz_target;
use sss::marker_inference::infer_markers;

// Fuzz target: marker scanner via the PUBLIC infer_markers wrapper.
// We pass the same buffer for both arguments (file_text and content) because
// the harness is exercising parser robustness, not differential behaviour
// between the two inputs. The internal parse_markers function is private
// (mod parser is private at src/marker_inference/mod.rs:104), so this is
// the only legal entry point from outside the crate.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = infer_markers(s, s);
    }
});
