#![no_main]
use libfuzzer_sys::fuzz_target;
use sss::project::ProjectConfig;

// Fuzz target: ProjectConfig TOML deser must not panic on arbitrary bytes.
// Errors are expected and acceptable; only panics indicate a fuzz finding.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<ProjectConfig>(s);
    }
});
