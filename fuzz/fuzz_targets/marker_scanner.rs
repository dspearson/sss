#![no_main]
use libfuzzer_sys::fuzz_target;

// Wave 2 (17-02-02) replaces this body with the marker_inference::infer_markers harness.
fuzz_target!(|_data: &[u8]| {
    // Stub — see plan 17-02 for the populated body.
});
