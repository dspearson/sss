#![no_main]
use libfuzzer_sys::fuzz_target;

// Wave 2 (17-02-03) replaces this body with the keystore::StoredKeyPair TOML+JSON deser harness.
fuzz_target!(|_data: &[u8]| {
    // Stub — see plan 17-02 for the populated body.
});
