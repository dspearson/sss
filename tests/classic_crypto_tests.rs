//! Phase 16 Plan 04 — D-07.3 candidate-pool branch coverage for `src/crypto/classic.rs`.
//!
//! Targets two reachable error arms exposed via the public crypto API:
//!   - CLASSIC-01: `SecretKey::from_base64` invalid-length arm (lines 246-251)
//!   - CLASSIC-02: `RepositoryKey::from_bytes` invalid-length arm (lines 100-107)
//!
//! Both branches are flagged uncovered in `coverage-before.txt` and are direct
//! constructor-validation paths, so each test is fast and deterministic.
//!
//! Allowed file (per 16-04 plan whitelist).

use sss::crypto::{RepositoryKey, SecretKey};

/// CLASSIC-01: src/crypto/classic.rs:246-251 — base64 decodes to wrong length.
///
/// Trigger: a base64 string that decodes to a non-`SECRET_KEY_SIZE` byte count.
/// `SECRET_KEY_SIZE` is the X25519 secret key size (32 bytes); we deliberately
/// pass a 4-byte payload so the length check at line 246 fires and the
/// `anyhow!("Invalid secret key length: expected {}, got {}")` arm at lines
/// 247-251 returns `Err`.
#[test]
fn classic_01_secret_key_from_base64_rejects_invalid_length() {
    use base64::prelude::*;
    // 4-byte payload, base64-encoded — clearly not a 32-byte secret key.
    let too_short = BASE64_STANDARD.encode([0u8; 4]);
    let err = SecretKey::from_base64(&too_short)
        .expect_err("expected error: secret key length mismatch");

    let msg = format!("{err}");
    assert!(
        msg.contains("Invalid secret key length"),
        "unexpected error message: {msg}"
    );
}

/// CLASSIC-02: src/crypto/classic.rs:100-107 — raw byte slice is wrong length.
///
/// Trigger: pass a 3-byte slice to `RepositoryKey::from_bytes`. The guard at
/// line 101 (`bytes.len() != SYMMETRIC_KEY_SIZE`) fires and the
/// `anyhow!("Invalid key size: {} bytes (expected: {})")` arm at lines
/// 102-106 returns `Err`.
#[test]
fn classic_02_repository_key_from_bytes_rejects_invalid_length() {
    let too_short = [0xAAu8; 3];
    let err = RepositoryKey::from_bytes(&too_short)
        .expect_err("expected error: repository key size mismatch");

    let msg = format!("{err}");
    assert!(
        msg.contains("Invalid key size"),
        "unexpected error message: {msg}"
    );
}
