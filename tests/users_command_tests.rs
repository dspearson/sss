//! Phase 16b — USERS-NN integration tests for `src/commands/users.rs`.
//!
//! Tier 2 placement per phase 16b D-18 (sibling integration tests). These
//! complement the in-source `mod tests` block in `src/commands/users.rs`
//! by exercising the `handle_users` dispatcher and individual handlers
//! against a TempDir-rooted `.sss.toml` project.
//!
//! All tests call directly into `sss::commands::users::handle_users` (or the
//! pub-via-module-reachable internals) — no subprocess spawning, no
//! `assert_cmd`. Tests that mutate cwd use an RAII guard.

use anyhow::Result;
use clap::{Arg, ArgMatches, Command};
use serial_test::serial;
use sss::crypto::KeyPair;
use sss::project::ProjectConfig;
use std::path::Path;
use tempfile::TempDir;

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

/// RAII guard that restores `cwd` on drop. Phase 16 R-03 cwd-race lesson —
/// every test that mutates `std::env::current_dir` MUST install this before
/// mutating.
struct CwdGuard {
    original: std::path::PathBuf,
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

/// Build a TempDir with a seeded `.sss.toml` containing a single classic user.
/// Returns the TempDir (which owns the temp directory's lifetime) and the
/// generated KeyPair (kept so callers can use the public key in tests).
fn setup_users_project(seed_user: &str) -> (TempDir, KeyPair) {
    let tmp = tempfile::tempdir().expect("tempdir create");
    let kp = KeyPair::generate().expect("keypair generate");
    let cfg = ProjectConfig::new(seed_user, &kp.public_key()).expect("config new");
    cfg.save_to_file(tmp.path().join(".sss.toml"))
        .expect("save config");
    (tmp, kp)
}

/// Top-level `sss` matches with `--confdir` declared but unset.
fn build_main_matches() -> ArgMatches {
    Command::new("sss")
        .arg(Arg::new("confdir").long("confdir"))
        .get_matches_from(["sss"])
}

/// Build a `sss users <subcommand>` ArgMatches mirroring the real clap tree
/// from `src/main.rs`. Includes only the subcommands the tests below exercise.
fn build_users_matches(args: &[&str]) -> ArgMatches {
    let app = Command::new("users")
        .subcommand(Command::new("list"))
        .subcommand(
            Command::new("add")
                .arg(Arg::new("username").required(true))
                .arg(Arg::new("public-key").required(true)),
        )
        .subcommand(
            Command::new("remove").arg(Arg::new("username").required(true)),
        )
        .subcommand(
            Command::new("info").arg(Arg::new("username").required(true)),
        )
        .subcommand(
            Command::new("add-hybrid-key")
                .arg(Arg::new("username").required(true))
                .arg(Arg::new("hybrid-pubkey").required(true)),
        );
    app.get_matches_from(args)
}

/// Run a closure with `cwd` pinned to `path`. Restores cwd on drop.
fn with_cwd<F: FnOnce() -> Result<()>>(path: &Path, f: F) -> Result<()> {
    let _g = CwdGuard::new()?;
    std::env::set_current_dir(path)?;
    f()
}

// ----------------------------------------------------------------------------
// users_NN — sibling integration tests
// ----------------------------------------------------------------------------

/// users_01 — `users list` against a seeded project routes through the
/// dispatcher and returns Ok.
#[test]
#[serial]
fn users_01_list_seeded_project_returns_ok() -> Result<()> {
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let matches = build_users_matches(&["users", "list"]);
        sss::commands::users::handle_users(&main, &matches)?;
        Ok(())
    })
}

/// users_02 — `users info <known-user>` succeeds for a seeded user.
#[test]
#[serial]
fn users_02_info_known_user_returns_ok() -> Result<()> {
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let matches = build_users_matches(&["users", "info", "alice"]);
        sss::commands::users::handle_users(&main, &matches)?;
        Ok(())
    })
}

/// users_03 — `users info <unknown-user>` returns an Err whose message names
/// the missing user.  Error-message regression test.
#[test]
#[serial]
fn users_03_info_unknown_user_errors_with_not_found() -> Result<()> {
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let matches = build_users_matches(&["users", "info", "ghost"]);
        let err = sss::commands::users::handle_users(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'ghost'") && err.contains("not found"),
            "error must call out missing user; got: {err}"
        );
        Ok(())
    })
}

/// users_04 — `users add <user> <bad-base64>` errors before touching disk.
/// Drives the base64 validation branch in handle_users_add.
#[test]
#[serial]
fn users_04_add_invalid_base64_errors() -> Result<()> {
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let matches =
            build_users_matches(&["users", "add", "bob", "@@@not_base64@@@"]);
        let err = sss::commands::users::handle_users(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid base64"),
            "expected 'invalid base64' in error; got: {err}"
        );
        Ok(())
    })
}

/// users_05 — `users remove <unknown-user>` errors with "not found".  Drives
/// the membership-check branch in handle_users_remove.
#[test]
#[serial]
fn users_05_remove_unknown_user_errors() -> Result<()> {
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let matches = build_users_matches(&["users", "remove", "ghost"]);
        let err = sss::commands::users::handle_users(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'ghost'") && err.contains("not found"),
            "expected missing-user error; got: {err}"
        );
        Ok(())
    })
}

/// users_06 — `users remove <last-user>` errors with the last-user guard.
/// Drives the `users.len() == 1` branch in handle_users_remove.
#[test]
#[serial]
fn users_06_remove_last_user_errors() -> Result<()> {
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let matches = build_users_matches(&["users", "remove", "alice"]);
        let err = sss::commands::users::handle_users(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Cannot remove the last user"),
            "expected last-user guard message; got: {err}"
        );
        Ok(())
    })
}

/// users_07 — Bare `sss users` (no subcommand) returns the dispatcher's
/// guidance error listing every available subcommand. Error-message
/// regression: must mention `add-hybrid-key` so the v2 hybrid path remains
/// discoverable.
#[test]
fn users_07_no_subcommand_errors_with_guidance() -> Result<()> {
    let main = build_main_matches();
    // Build a "users" matches that has no subcommand attached.
    let users_app = Command::new("users")
        .subcommand(Command::new("list"))
        .subcommand(
            Command::new("add")
                .arg(Arg::new("username").required(true))
                .arg(Arg::new("public-key").required(true)),
        );
    let matches = users_app.get_matches_from(["users"]);
    let err = sss::commands::users::handle_users(&main, &matches)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("No subcommand provided"),
        "error must lead with 'No subcommand provided'; got: {err}"
    );
    assert!(
        err.contains("add-hybrid-key"),
        "error must list the add-hybrid-key subcommand; got: {err}"
    );
    Ok(())
}

/// users_08 — `users add-hybrid-key` with a wrong-length key errors with
/// "1214" (the canonical hybrid pub-key byte count). Hybrid-only.
#[test]
#[serial]
#[cfg(feature = "hybrid")]
fn users_08_add_hybrid_key_wrong_length_errors() -> Result<()> {
    use base64::Engine as _;
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        // 100 bytes — neither the classic 32 nor the hybrid 1214.
        let short = base64::prelude::BASE64_STANDARD.encode(vec![0u8; 100]);
        let matches = build_users_matches(&[
            "users",
            "add-hybrid-key",
            "alice",
            short.as_str(),
        ]);
        let err = sss::commands::users::handle_users(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("1214"),
            "expected hybrid-key length error citing 1214; got: {err}"
        );
        Ok(())
    })
}

/// users_09 — `users add-hybrid-key` with a correct 1214-byte key persists
/// `hybrid_public` in the user's record. Hybrid-only.
#[test]
#[serial]
#[cfg(feature = "hybrid")]
fn users_09_add_hybrid_key_correct_length_persists_pubkey() -> Result<()> {
    use base64::Engine as _;
    use sss::constants::HYBRID_PUBLIC_KEY_SIZE;
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let valid_b64 = base64::prelude::BASE64_STANDARD
            .encode(vec![0x42u8; HYBRID_PUBLIC_KEY_SIZE]);
        let matches = build_users_matches(&[
            "users",
            "add-hybrid-key",
            "alice",
            valid_b64.as_str(),
        ]);
        sss::commands::users::handle_users(&main, &matches)?;
        // Reload and confirm the field is set.
        let saved =
            ProjectConfig::load_from_file(tmp.path().join(".sss.toml"))?;
        assert_eq!(
            saved.users.get("alice").unwrap().hybrid_public.as_deref(),
            Some(valid_b64.as_str()),
            "hybrid_public must be persisted after add-hybrid-key"
        );
        Ok(())
    })
}

/// users_10 — `users add-hybrid-key <unknown-user> <valid-key>` errors with
/// "not found". Drives the user-lookup branch inside the hybrid arm.
#[test]
#[serial]
#[cfg(feature = "hybrid")]
fn users_10_add_hybrid_key_unknown_user_errors() -> Result<()> {
    use base64::Engine as _;
    use sss::constants::HYBRID_PUBLIC_KEY_SIZE;
    let (tmp, _kp) = setup_users_project("alice");
    with_cwd(tmp.path(), || {
        let main = build_main_matches();
        let valid_b64 = base64::prelude::BASE64_STANDARD
            .encode(vec![0x42u8; HYBRID_PUBLIC_KEY_SIZE]);
        let matches = build_users_matches(&[
            "users",
            "add-hybrid-key",
            "ghost",
            valid_b64.as_str(),
        ]);
        let err = sss::commands::users::handle_users(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'ghost'") && err.contains("not found"),
            "expected unknown-user error; got: {err}"
        );
        Ok(())
    })
}
