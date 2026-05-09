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

/// AUDIT-02: confirm `sss init` (no flags) creates a v2.0 hybrid repo by
/// default after the v2.2 default flip.
///
/// Mirrors the isolated-HOME + dual-suite-keygen setup used by
/// `tests/envelope_signature_negative_paths.rs::sign_on_write_init`, then
/// invokes `sss init alice` with no `--crypto` flag and asserts that the
/// resulting `.sss.toml` is a v2.0 (hybrid) project with a populated
/// `[envelope.sig]` table.
#[cfg(feature = "hybrid")]
#[test]
fn init_no_flags_defaults_to_hybrid() {
    let project_dir = tempfile::tempdir().expect("project tempdir");
    let home_dir = tempfile::tempdir().expect("home tempdir");

    // Generate both classic and hybrid keypairs (mirrors UserEnv setup in
    // envelope_signature_negative_paths.rs:98-111).
    let keygen = Command::new(sss_bin())
        .env("HOME", home_dir.path())
        .env("XDG_CONFIG_HOME", home_dir.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "alice")
        .current_dir(project_dir.path())
        .args([
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--suite",
            "both",
            "--no-password",
        ])
        .output()
        .expect("dual-suite keygen");
    assert!(
        keygen.status.success(),
        "dual-suite keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    // sss init alice — NO --crypto flag (asserts the post-AUDIT-02 default).
    let output = Command::new(sss_bin())
        .env("HOME", home_dir.path())
        .env("XDG_CONFIG_HOME", home_dir.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "alice")
        .current_dir(project_dir.path())
        .args(["--kdf-level", "interactive", "init", "alice"])
        .output()
        .expect("sss init");
    assert!(
        output.status.success(),
        "sss init failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let toml_path = project_dir.path().join(".sss.toml");
    let toml = std::fs::read_to_string(&toml_path).expect("read .sss.toml");
    assert!(
        toml.contains("version = \"2.0\""),
        "expected version = \"2.0\" in .sss.toml, got:\n{}",
        toml
    );
    assert!(
        toml.contains("[envelope.sig]"),
        "expected [envelope.sig] table in .sss.toml, got:\n{}",
        toml
    );
}
