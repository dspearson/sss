#![no_main]
use libfuzzer_sys::fuzz_target;
use sss::keystore::StoredKeyPair;

// Fuzz target: keystore deser surface. StoredKeyPair derives Serialize +
// Deserialize and the on-disk format can be either TOML (legacy / hybrid
// migration path) or JSON (newer keystore writes). Exercise both.
//
// Per CONTEXT D-04, fuzz the deser layer ONLY — no passphrase, no I/O, no
// crypto. Each call must either succeed returning a well-formed value or
// return Err — never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<StoredKeyPair>(s);
        let _ = serde_json::from_str::<StoredKeyPair>(s);
    }
});
