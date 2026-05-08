#![no_main]
use libfuzzer_sys::fuzz_target;

// Wave 2 (17-02-01) replaces this body with the ProjectConfig TOML deser harness.
// The stub returns immediately so the binary builds; libFuzzer is not yet exercised.
fuzz_target!(|_data: &[u8]| {
    // Stub — see plan 17-02 for the populated body.
});
