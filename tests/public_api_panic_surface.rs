//! HARDEN-05 — public-API panic-surface regression suite (Phase 8 / Plan 05).
//!
//! Goal: every type re-exported from `src/lib.rs` is exercised with caller-facing
//! valid-but-edge-case inputs and asserted to return `Result::Err(_)` (or an Ok
//! smoke-test value) instead of panicking. A panic in any of these tests is a
//! HARDEN-05 violation; report it via `08-05-SUMMARY.md` and either:
//!   - close it under HARDEN-01 (caller-facing input → `?`), OR
//!   - explicitly accept it with rationale.
//!
//! Coverage: every line of `src/lib.rs:39-48` (the `pub use` block) gets at least
//! one row. Section comments below mirror the matrix in
//! `/tmp/sss-08-05-entry-points.md` (working file) and the `## Tested Entry Points`
//! section of `08-05-SUMMARY.md`.
//!
//! The 8th re-export, `pub use ninep_fs::SssNinepFS` (cfg-gated behind
//! `feature = "ninep"`), is recorded as feature-gated; the smoke check below in
//! `reexport_compile_check` uses a `cfg`-gated import to enforce the export.
//!
//! Per CONTEXT.md (Phase 8 HARDEN-05 discretion clause): tests live in `tests/`
//! ONLY — no `pub` items are downgraded to `pub(crate)` here. That is CLEAN-03
//! (Phase 11). Phase 11 candidates are recorded in `08-05-SUMMARY.md`.

#![allow(clippy::needless_borrow, clippy::expect_fun_call)]

use base64::Engine;
use std::path::PathBuf;
use tempfile::tempdir;

use sss::config;
use sss::crypto;
use sss::processor::Processor;
use sss::{Config, KeyPair, KeyringManager, Keystore, ProjectConfig, RepositoryKey, SssError};

// ===========================================================================
// RepositoryKey  (src/lib.rs:40 — `pub use crypto::{KeyPair, RepositoryKey}`)
// ===========================================================================

#[test]
fn repository_key_new_does_not_panic() {
    let _k = RepositoryKey::new();
}

#[test]
fn repository_key_from_bytes_too_short_returns_err() {
    let result = RepositoryKey::from_bytes(&[0u8; 5]);
    assert!(result.is_err(), "expected Err for length-5 input; got Ok");
}

#[test]
fn repository_key_from_bytes_too_long_returns_err() {
    let result = RepositoryKey::from_bytes(&[0u8; 100]);
    assert!(result.is_err(), "expected Err for length-100 input; got Ok");
}

#[test]
fn repository_key_from_bytes_empty_returns_err() {
    let result = RepositoryKey::from_bytes(&[]);
    assert!(result.is_err(), "expected Err for empty input; got Ok");
}

#[test]
fn repository_key_from_bytes_exact_zeros_returns_ok() {
    // A 32-byte all-zero buffer is a valid byte-length input. We verify that
    // `from_bytes` does NOT panic on degenerate-but-correct-length input.
    // This is NOT a security claim about zero keys; it is a panic-surface check.
    let result = RepositoryKey::from_bytes(&[0u8; 32]);
    assert!(result.is_ok(), "32-byte zero input must parse without panic");
}

#[test]
fn repository_key_from_base64_invalid_chars_returns_err() {
    let result = RepositoryKey::from_base64("not-base64-!@#$");
    assert!(result.is_err());
}

#[test]
fn repository_key_from_base64_empty_returns_err() {
    let result = RepositoryKey::from_base64("");
    assert!(result.is_err());
}

#[test]
fn repository_key_from_base64_wrong_length_returns_err() {
    // Valid base64 of a 5-byte buffer — wrong length for RepositoryKey.
    let s = base64::engine::general_purpose::STANDARD.encode(&[0u8; 5]);
    let result = RepositoryKey::from_base64(&s);
    assert!(result.is_err());
}

#[test]
fn repository_key_from_base64_huge_returns_err() {
    // 100 KiB of base64; decodes cleanly but length != 32.
    let s = base64::engine::general_purpose::STANDARD.encode(&vec![0u8; 100_000]);
    let result = RepositoryKey::from_base64(&s);
    assert!(result.is_err());
}

#[test]
fn repository_key_to_base64_round_trip_does_not_panic() {
    let k = RepositoryKey::new();
    let s = k.to_base64();
    let _k2 = RepositoryKey::from_base64(&s).expect("round-trip must succeed");
}

#[test]
fn repository_key_rotate_does_not_panic() {
    let k = RepositoryKey::new();
    let (_old, _new) = k.rotate();
}

// ===========================================================================
// KeyPair  (src/lib.rs:40)
// ===========================================================================

#[test]
fn keypair_generate_does_not_panic() {
    let _kp = KeyPair::generate().expect("generate should succeed under normal conditions");
}

#[test]
fn keypair_from_seed_empty_returns_err() {
    let result = KeyPair::from_seed(&[]);
    assert!(result.is_err(), "expected Err for empty seed; got Ok");
}

#[test]
fn keypair_from_seed_too_short_returns_err() {
    // libsodium's crypto_box_SEEDBYTES = 32; 8 bytes must fail.
    let result = KeyPair::from_seed(&[0u8; 8]);
    assert!(result.is_err(), "expected Err for 8-byte seed; got Ok");
}

#[test]
fn keypair_from_seed_too_long_returns_err() {
    let result = KeyPair::from_seed(&[0u8; 100]);
    assert!(result.is_err(), "expected Err for 100-byte seed; got Ok");
}

#[test]
fn keypair_from_seed_exact_length_zero_seed_does_not_panic() {
    // 32 bytes of zero is a valid input length. This is a panic-surface
    // assertion only — we are NOT claiming zero seeds produce safe keys.
    let result = KeyPair::from_seed(&[0u8; 32]);
    assert!(result.is_ok(), "32-byte zero seed must parse without panic");
}

#[test]
fn keypair_public_key_does_not_panic() {
    let kp = KeyPair::generate().expect("generate");
    let _pk = kp.public_key();
}

#[test]
fn keypair_secret_key_does_not_panic() {
    let kp = KeyPair::generate().expect("generate");
    let _sk = kp.secret_key().expect("classic keypair has a SecretKey");
}

// ===========================================================================
// config::load_key / load_key_for_user
// (src/lib.rs:39 — `pub use config::{load_key, load_key_for_user, Config}`)
// ===========================================================================
//
// These are env-/CWD-driven and may legitimately Err on the test environment.
// The test asserts they don't panic; the Err branch is fine.

#[test]
fn load_key_does_not_panic() {
    // SAFETY of test: relies on whatever env/CWD state the test runner has.
    // Both Ok and Err are acceptable; the assertion is "no panic".
    let _ = config::load_key();
}

#[test]
fn load_key_for_user_empty_does_not_panic() {
    let _ = config::load_key_for_user("");
}

#[test]
fn load_key_for_user_long_does_not_panic() {
    let long_user = "a".repeat(10_000);
    let _ = config::load_key_for_user(&long_user);
}

#[test]
fn load_key_for_user_special_chars_does_not_panic() {
    let _ = config::load_key_for_user("user/with\\slashes and spaces");
}

#[test]
fn load_key_for_user_unicode_does_not_panic() {
    let _ = config::load_key_for_user("üsér_with_emoji_🔑");
}

#[test]
fn load_key_for_user_null_byte_does_not_panic() {
    // Null byte inside a Rust &str is legal at the language level; what we
    // assert is that the public API doesn't panic when handed such input.
    let _ = config::load_key_for_user("user\0with\0nulls");
}

// ===========================================================================
// ProjectConfig (also tests `Config` alias)  (src/lib.rs:39 + lib.rs:45)
// ===========================================================================

fn fresh_classic_keypair() -> KeyPair {
    KeyPair::generate().expect("classic keypair generation must succeed for fresh tests")
}

#[test]
fn project_config_new_with_classic_keypair_does_not_panic() {
    let kp = fresh_classic_keypair();
    let result = ProjectConfig::new("alice", &kp.public_key());
    assert!(result.is_ok());
}

#[test]
fn project_config_new_empty_username_does_not_panic() {
    let kp = fresh_classic_keypair();
    // ProjectConfig::new accepts any string as username and panics nowhere
    // along the path. The current contract is "Ok with possibly-degenerate
    // username"; we assert no panic, not the Ok/Err disposition.
    let _ = ProjectConfig::new("", &kp.public_key());
}

#[test]
fn project_config_load_from_nonexistent_path_returns_err() {
    let nonexistent = PathBuf::from(format!(
        "/tmp/sss-test-does-not-exist-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_nanos()
    ));
    let result = ProjectConfig::load_from_file(&nonexistent);
    assert!(result.is_err());
}

#[test]
fn project_config_load_from_directory_returns_err() {
    let dir = tempdir().expect("tempdir");
    let result = ProjectConfig::load_from_file(dir.path());
    assert!(result.is_err());
}

#[test]
fn project_config_load_from_empty_path_returns_err() {
    // Empty path is invalid but must not panic.
    let result = ProjectConfig::load_from_file("");
    assert!(result.is_err());
}

#[test]
fn project_config_load_from_garbage_toml_returns_err() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("garbage.toml");
    std::fs::write(&path, "this is :: not :: valid toml \0\0").expect("write garbage");
    let result = ProjectConfig::load_from_file(&path);
    assert!(result.is_err());
}

#[test]
fn config_alias_compile_check() {
    // `Config` is re-exported as a type alias for `ProjectConfig`. This test
    // exists purely to ensure the alias is reachable from `sss::Config` and
    // compiles. If `pub use config::{..., Config}` is removed, this fails to
    // build, which is the desired regression behaviour.
    fn assert_alias<T>() {}
    assert_alias::<Config>();
}

// ===========================================================================
// Processor  (src/lib.rs:44 — `pub use processor::Processor`)
// ===========================================================================

fn fresh_processor() -> Processor {
    Processor::new(RepositoryKey::new()).expect("new processor with random key")
}

#[test]
fn processor_new_with_random_key_does_not_panic() {
    let _p = fresh_processor();
}

#[test]
fn processor_new_with_context_does_not_panic() {
    let dir = tempdir().expect("tempdir");
    let _p = Processor::new_with_context(
        RepositoryKey::new(),
        dir.path().to_path_buf(),
        "2025-01-01T00:00:00Z".to_string(),
    )
    .expect("processor with context");
}

#[test]
fn processor_new_with_project_root_does_not_panic() {
    let dir = tempdir().expect("tempdir");
    let _p = Processor::new_with_project_root(RepositoryKey::new(), dir.path().to_path_buf())
        .expect("processor with project root");
}

#[test]
fn processor_encrypt_empty_content_does_not_panic() {
    let p = fresh_processor();
    let _ = p.encrypt_content("");
}

#[test]
fn processor_encrypt_huge_content_does_not_panic() {
    // 100 KiB — well under MAX_FILE_SIZE (100 MiB); ensures the marker scanner
    // walks an unusually long string without panicking.
    let p = fresh_processor();
    let huge = "x".repeat(100_000);
    let _ = p.encrypt_content(&huge);
}

#[test]
fn processor_encrypt_unicode_does_not_panic() {
    let p = fresh_processor();
    let _ = p.encrypt_content("Hello 🌍 ⊕{secret-with-unicode-üfoo} end");
}

#[test]
fn processor_decrypt_garbage_content_does_not_panic() {
    let p = fresh_processor();
    let _ = p.decrypt_content("this is not valid sss output at all");
}

#[test]
fn processor_decrypt_empty_does_not_panic() {
    let p = fresh_processor();
    let _ = p.decrypt_content("");
}

#[test]
fn processor_decrypt_truncated_marker_does_not_panic() {
    // Looks like a ciphertext marker but the base64 inside is invalid /
    // unbalanced. The decryption path may produce Ok (with marker preserved
    // as an error message) or Err — what we assert is "no panic".
    let p = fresh_processor();
    let _ = p.decrypt_content("⊠{not-valid-base64-here!}");
}

#[test]
fn processor_process_content_invalid_marker_does_not_panic() {
    let p = fresh_processor();
    let _ = p.process_content("<!--SSS:bogus--> some text");
}

#[test]
fn processor_process_content_empty_does_not_panic() {
    let p = fresh_processor();
    let _ = p.process_content("");
}

#[test]
fn processor_process_content_huge_input_does_not_panic() {
    // 50 KiB — well under MAX_FILE_SIZE; exercises the marker scanner against
    // a long input without crossing the size guard.
    let p = fresh_processor();
    let huge = "<!--SSS:test--> ".to_string() + &"x".repeat(50_000);
    let _ = p.process_content(&huge);
}

#[test]
fn processor_process_content_oversize_returns_err() {
    // process_content has a documented MAX_FILE_SIZE (100 MiB) cap. We feed
    // 101 MiB of `x` and assert Err — the panic-surface assertion is implicit
    // (no panic on the size-guard path).
    let p = fresh_processor();
    // Build the 101 MiB input from a 1 MiB chunk to keep test memory sane.
    let chunk = "x".repeat(1024 * 1024);
    let mut huge = String::with_capacity(101 * 1024 * 1024);
    for _ in 0..101 {
        huge.push_str(&chunk);
    }
    let result = p.process_content(&huge);
    assert!(result.is_err(), "expected Err for content exceeding MAX_FILE_SIZE");
}

#[test]
fn processor_prepare_for_editing_no_markers_does_not_panic() {
    let p = fresh_processor();
    let _ = p.prepare_for_editing("no markers here").expect("ok smoke");
}

#[test]
fn processor_decrypt_to_raw_no_markers_does_not_panic() {
    let p = fresh_processor();
    let _ = p.decrypt_to_raw("no markers here").expect("ok smoke");
}

#[test]
fn processor_mixed_markers_returns_err() {
    // process_content rejects content carrying both plaintext and ciphertext
    // marker styles. The relevant code path is the (true,true) match arm in
    // src/processor/core.rs:699-701.
    let p = fresh_processor();
    let result = p.process_content("⊕{plain} and ⊠{ciphertext}");
    assert!(result.is_err(), "expected Err on mixed marker types");
}

#[test]
fn processor_process_content_with_path_garbage_does_not_panic() {
    let p = fresh_processor();
    let _ = p.process_content_with_path("<!--SSS:test-->", "../../etc/passwd");
}

// ===========================================================================
// Keystore  (src/lib.rs:43 — `pub use keystore::Keystore`)
// ===========================================================================
//
// These touch the user's real `~/.config/sss/` keystore on the test environment.
// The smoke tests assert "no panic" on every entry point; the Ok/Err split is
// determined by whether the user has a populated keystore at test time. Heavy
// state-mutation tests (store_keypair, set_passphrase, ...) live in
// `tests/keystore_integration_tests.rs` with proper isolation.

#[test]
fn keystore_new_does_not_panic() {
    let _ = Keystore::new();
}

#[test]
fn keystore_count_keypairs_does_not_panic() {
    if let Ok(ks) = Keystore::new() {
        let _ = ks.count_keypairs();
    }
}

#[test]
fn keystore_list_key_ids_does_not_panic() {
    if let Ok(ks) = Keystore::new() {
        let _ = ks.list_key_ids();
    }
}

#[test]
fn keystore_load_keypair_nonexistent_id_does_not_panic() {
    // Use a Keystore rooted in an isolated tempdir so we don't disturb the
    // user's real ~/.config/sss/ keystore.
    let dir = tempdir().expect("tempdir");
    if let Ok(ks) = Keystore::new_with_config_dir(dir.path().to_path_buf()) {
        let result = ks.load_keypair("does-not-exist", None, true);
        assert!(result.is_err());
    }
}

// ===========================================================================
// KeyringManager  (src/lib.rs:42 — `pub use keyring_manager::KeyringManager`)
// ===========================================================================
//
// The OS keyring is shared mutable state; we restrict tests to the read-only
// surface (`new`, `has_key_for_user`, `load_key_with_fallback*`) to avoid
// silently mutating the user's real credential store.

#[test]
fn keyring_manager_new_does_not_panic() {
    let _km = KeyringManager::new();
}

#[test]
fn keyring_manager_has_key_for_user_empty_does_not_panic() {
    let km = KeyringManager::new();
    let _ = km.has_key_for_user("");
}

#[test]
fn keyring_manager_has_key_for_user_unicode_does_not_panic() {
    let km = KeyringManager::new();
    let _ = km.has_key_for_user("üser🔑");
}

#[test]
fn keyring_manager_load_key_with_fallback_nonexistent_path_does_not_panic() {
    let km = KeyringManager::new();
    let nonexistent = PathBuf::from(format!(
        "/tmp/sss-test-does-not-exist-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_nanos()
    ));
    let _ = km.load_key_with_fallback(&nonexistent);
}

// ===========================================================================
// SssError / Result  (src/lib.rs:41 — `pub use error::{Result, SssError}`)
// ===========================================================================

#[test]
fn sss_error_display_does_not_panic() {
    // Exercise every variant once. Display is the user-visible surface; a
    // panic here would surface to every error message in the binary.
    let variants = [
        SssError::Crypto("c".into()),
        SssError::Keystore("k".into()),
        SssError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "nf")),
        SssError::Config("cfg".into()),
        SssError::Validation("v".into()),
        SssError::Project("p".into()),
        SssError::Auth("a".into()),
        SssError::Processing("pr".into()),
        SssError::Editor("e".into()),
        SssError::Network("n".into()),
    ];
    for v in &variants {
        let _ = format!("{v}");
    }
}

#[test]
fn sss_error_from_io_does_not_panic() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let _: SssError = io.into();
}

// ===========================================================================
// Re-export accessibility (compile-time guard)
// ===========================================================================
//
// This test exists to catch accidental removal of any `pub use` line in
// `src/lib.rs:39-48`. If any re-exported symbol becomes unreachable via
// `sss::*`, this fails to compile, which is the desired regression behaviour.

#[test]
fn reexport_compile_check() {
    // src/lib.rs:39 — config::{load_key, load_key_for_user, Config}
    let _: fn() -> anyhow::Result<crypto::Key> = config::load_key;
    let _: fn(&str) -> anyhow::Result<crypto::Key> = config::load_key_for_user;
    fn assert_type<T>() {}
    assert_type::<Config>();

    // src/lib.rs:40 — crypto::{KeyPair, RepositoryKey}
    let _: fn() -> RepositoryKey = RepositoryKey::new;
    let _: fn() -> anyhow::Result<KeyPair> = KeyPair::generate;

    // src/lib.rs:41 — error::{Result, SssError}
    assert_type::<sss::Result<()>>();
    assert_type::<SssError>();

    // src/lib.rs:42 — keyring_manager::KeyringManager
    let _: fn() -> KeyringManager = KeyringManager::new;

    // src/lib.rs:43 — keystore::Keystore
    let _: fn() -> anyhow::Result<Keystore> = Keystore::new;

    // src/lib.rs:44 — processor::Processor
    let _: fn(RepositoryKey) -> anyhow::Result<Processor> = Processor::new;

    // src/lib.rs:45 — project::ProjectConfig
    assert_type::<ProjectConfig>();

    // src/lib.rs:48 (cfg-gated) — ninep_fs::SssNinepFS
    #[cfg(feature = "ninep")]
    {
        assert_type::<sss::SssNinepFS>();
    }
}
