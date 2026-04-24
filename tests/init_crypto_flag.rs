//! Integration tests for `sss init --crypto` (SUITE-03).
//!
//! These tests drive the real `sss` binary via `std::process::Command`
//! to confirm clap-level value validation and the `--help` surface. They
//! are deliberately scoped to the clap layer so they do not depend on
//! keystore state — only the CLI's argument parsing is exercised.

use std::process::Command;

/// Resolve the built sss binary path. Cargo sets `CARGO_BIN_EXE_<name>`
/// automatically for every `[[bin]]` target when integration tests run.
fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

#[test]
fn init_rejects_invalid_crypto_value() {
    // clap's `value_parser(["classic", "hybrid"])` must reject any other
    // value at the parsing layer — before handle_init ever runs — and the
    // error message must name the allowed values so the user can correct it.
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(sss_bin())
        .current_dir(tmp.path())
        .args(["init", "--crypto", "nonsense", "test-user"])
        .output()
        .expect("failed to spawn sss");

    assert!(
        !output.status.success(),
        "sss init with invalid --crypto must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // clap's value-parser error mentions the valid values.
    assert!(
        stderr.contains("classic") && stderr.contains("hybrid"),
        "clap error must name the allowed values; got stderr: {stderr}"
    );
}

#[test]
fn init_accepts_classic_default_help() {
    // `sss init --help` must document the --crypto flag and list both
    // allowed values, so users discover the opt-in without reading docs.
    let output = Command::new(sss_bin())
        .args(["init", "--help"])
        .output()
        .expect("failed to spawn sss");

    assert!(output.status.success(), "sss init --help must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--crypto"),
        "help must list --crypto; got: {stdout}"
    );
    assert!(
        stdout.contains("classic") && stdout.contains("hybrid"),
        "help must mention both allowed values; got: {stdout}"
    );
}
