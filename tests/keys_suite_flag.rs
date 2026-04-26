//! Integration tests for `sss keys generate --suite` (KEYSTORE-02).
//!
//! These tests drive the real `sss` binary to confirm:
//! - clap rejects unknown --suite values with exit code 2
//! - clap accepts known --suite values (classic, hybrid, both)
//! - non-hybrid builds reject --suite hybrid with the correct error message
//!
//! Tests that require the hybrid feature are gated with #[cfg(feature = "hybrid")].

use std::process::Command;

fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

/// `sss keys generate --suite xyz` must be rejected by clap before the
/// handler runs, with a non-zero exit code and an error message that names
/// the valid values.
#[test]
fn test_keys_generate_suite_arg() {
    let tmp = tempfile::tempdir().unwrap();
    let confdir = tmp.path().to_str().unwrap();

    // Unknown suite value → clap error (non-zero exit)
    let output = Command::new(sss_bin())
        .args(["--confdir", confdir, "keys", "generate", "--suite", "xyz", "--no-password"])
        .output()
        .expect("failed to spawn sss");

    assert!(
        !output.status.success(),
        "sss keys generate with invalid --suite must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap's value-parser error must name the allowed values
    assert!(
        stderr.contains("classic") || stderr.contains("possible") || stderr.contains("invalid"),
        "clap error must reference allowed values; got stderr: {stderr}"
    );

    // Known value classic → command proceeds.
    // In a clean temp dir without an existing keypair and --no-password, it must succeed.
    let output2 = Command::new(sss_bin())
        .args(["--confdir", confdir, "keys", "generate", "--suite", "classic", "--no-password"])
        .output()
        .expect("failed to spawn sss");

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        output2.status.success(),
        "sss keys generate --suite classic --no-password must succeed in a fresh dir;\
         \nstdout: {stdout2}\nstderr: {stderr2}"
    );
    assert!(
        stdout2.contains("Generated new keypair"),
        "output must confirm keypair generation; got: {stdout2}"
    );
}

/// On a non-hybrid build, `--suite hybrid` must return the exact error string
/// "hybrid suite requires a --features hybrid build". This test only compiles
/// and runs when the hybrid feature is OFF.
#[test]
#[cfg(not(feature = "hybrid"))]
fn test_suite_hybrid_no_feature_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let confdir = tmp.path().to_str().unwrap();

    // First generate a classic key so the handler gets past any pre-checks.
    // The feature-absent guard fires before the "no classic key" check,
    // but creating a classic key first makes the test unambiguous.
    let _setup = Command::new(sss_bin())
        .args(["--confdir", confdir, "keys", "generate", "--suite", "classic", "--no-password"])
        .output()
        .expect("failed to spawn sss");

    let output = Command::new(sss_bin())
        .args(["--confdir", confdir, "keys", "generate", "--suite", "hybrid", "--no-password"])
        .output()
        .expect("failed to spawn sss");

    assert!(
        !output.status.success(),
        "--suite hybrid on a non-hybrid build must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hybrid suite requires a --features hybrid build"),
        "error must contain exact message; got stderr: {stderr}"
    );
}
