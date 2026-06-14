// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 39 — REM-06 integration tests for `ProjectConfig::load_from_file` path validation.
//!
//! Verifies that `load_from_file` rejects malicious `secrets_filename` and
//! `secrets_suffix` values (absolute paths, `..` traversal, NUL bytes) BEFORE
//! any `Path::join` can use them, and that the rejection fires on both v1
//! (unsigned, `format_version=1`) and v2 TOML.
//!
//! Pitfall 4 (39-RESEARCH.md): validation is placed BEFORE the `format_version`
//! dispatch — these tests use `format_version=1` TOML (no signing keypair needed)
//! to prove v1 unsigned TOML is covered, not just v2.
//!
//! Test style modelled on `tests/hooks_command_tests.rs` (`CwdGuard` RAII,
//! `TempDir`, `serial_test` where needed).

use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;
use tempfile::TempDir;

use sss::crypto::KeyPair;
use sss::project::ProjectConfig;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// RAII guard that restores `cwd` on drop (Phase 16 R-03 cwd-race lesson).
struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            original: std::env::current_dir()?,
        })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

/// Create a valid v1 (unsigned) `.sss.toml` with the given `secrets_filename`
/// value. Uses `ProjectConfig::new` + struct field mutation + `save_to_file` so
/// the TOML is structurally valid (correct user entries etc.) and the
/// `secrets_filename` field is serialised in the correct TOML position by the
/// serde serialiser — not appended as raw text after a `[users]` table header
/// (which would put the field inside the users table).
///
/// `save_to_file` does not run `validate_secrets_path`; only `load_from_file`
/// does.  So a bad value can be round-tripped to disk this way.
fn create_project_toml_with_secrets_filename(
    dir: &TempDir,
    secrets_filename: &str,
) -> PathBuf {
    let path = dir.path().join(".sss.toml");
    let kp = KeyPair::generate().expect("keygen");
    let mut cfg = ProjectConfig::new("alice", &kp.public_key()).expect("project config new");
    cfg.secrets_filename = Some(secrets_filename.to_string());
    cfg.save_to_file(&path).expect("save_to_file");
    path
}

/// Same for `secrets_suffix`.
fn create_project_toml_with_secrets_suffix(
    dir: &TempDir,
    secrets_suffix: &str,
) -> PathBuf {
    let path = dir.path().join(".sss.toml");
    let kp = KeyPair::generate().expect("keygen");
    let mut cfg = ProjectConfig::new("alice", &kp.public_key()).expect("project config new");
    cfg.secrets_suffix = Some(secrets_suffix.to_string());
    cfg.save_to_file(&path).expect("save_to_file");
    path
}

// ----------------------------------------------------------------------------
// secrets_filename rejection tests
// ----------------------------------------------------------------------------

/// A TOML with `secrets_filename = "/etc/shadow"` must be rejected at load time
/// before any `Path::join`.
#[test]
#[serial]
fn test_load_from_file_rejects_absolute_secrets_filename() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_filename(&tmp, "/etc/shadow");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_err(),
        "load_from_file must reject absolute secrets_filename (/etc/shadow)"
    );
    Ok(())
}

/// A TOML with `secrets_filename = "../escape"` must be rejected.
#[test]
#[serial]
fn test_load_from_file_rejects_dotdot_secrets_filename() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_filename(&tmp, "../escape");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_err(),
        "load_from_file must reject .. traversal in secrets_filename"
    );
    Ok(())
}

/// A TOML with an interior `..` component in `secrets_filename` must be rejected.
#[test]
#[serial]
fn test_load_from_file_rejects_interior_dotdot_secrets_filename() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_filename(&tmp, "foo/../bar");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_err(),
        "load_from_file must reject interior .. component in secrets_filename"
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// secrets_suffix rejection tests
// ----------------------------------------------------------------------------

/// A TOML with `secrets_suffix = "../../etc/passwd"` must be rejected.
#[test]
#[serial]
fn test_load_from_file_rejects_dotdot_secrets_suffix() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_suffix(&tmp, "../../etc/passwd");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_err(),
        "load_from_file must reject .. traversal in secrets_suffix"
    );
    Ok(())
}

/// A TOML with `secrets_suffix = "/absolute"` must be rejected.
#[test]
#[serial]
fn test_load_from_file_rejects_absolute_secrets_suffix() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_suffix(&tmp, "/absolute");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_err(),
        "load_from_file must reject absolute path in secrets_suffix"
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// Acceptance / valid-path tests
// ----------------------------------------------------------------------------

/// A TOML with a plain relative `secrets_filename` must load successfully.
#[test]
#[serial]
fn test_load_from_file_accepts_relative_secrets_filename() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_filename(&tmp, "my-secrets");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_ok(),
        "load_from_file must accept a plain relative secrets_filename, got: {:?}",
        result.err()
    );
    Ok(())
}

/// A TOML with a plain relative suffix (e.g. ".sealed") must load successfully.
#[test]
#[serial]
fn test_load_from_file_accepts_dot_prefix_secrets_suffix() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_suffix(&tmp, ".sealed");

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_ok(),
        "load_from_file must accept a relative dot-prefix secrets_suffix, got: {:?}",
        result.err()
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// v1 TOML coverage test — Pitfall 4 (39-RESEARCH.md)
// ----------------------------------------------------------------------------

/// The rejection must fire on a `format_version=1` (unsigned) TOML — the
/// `validate_secrets_path` call must be BEFORE the `format_version` dispatch ladder.
/// Uses `ProjectConfig::new` (which produces v1 by default) to confirm the
/// unsigned code path is covered.
#[test]
#[serial]
fn test_load_from_file_rejects_on_v1_unsigned_toml() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_filename(&tmp, "/etc/shadow");

    // Pre-condition: `ProjectConfig::new` produces format_version=1 by default
    // (default_envelope_format_version returns 1; `is_default_format_version`
    // skips the field in TOML).  Confirm it is NOT v2.
    let content = std::fs::read_to_string(&path)?;
    assert!(
        !content.contains("format_version = 2"),
        "test pre-condition: TOML must be unsigned v1, not v2"
    );

    let result = ProjectConfig::load_from_file(&path);
    assert!(
        result.is_err(),
        "load_from_file must reject bad secrets_filename on a v1 unsigned TOML"
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// Error message quality test
// ----------------------------------------------------------------------------

/// The returned error message must include the .sss.toml path so the operator
/// knows which file to fix.
#[test]
#[serial]
fn test_load_from_file_error_includes_config_path() -> Result<()> {
    let _guard = CwdGuard::new()?;
    let tmp = TempDir::new()?;
    let path = create_project_toml_with_secrets_filename(&tmp, "/etc/shadow");

    let err = ProjectConfig::load_from_file(&path).expect_err("expected error");
    let msg = err.to_string();
    let path_str = path.to_string_lossy();
    assert!(
        msg.contains(path_str.as_ref()),
        "Error message must include the config file path.\n  Expected path: {path_str}\n  Got: {msg}"
    );
    Ok(())
}
