use anyhow::{anyhow, Result};
use std::env;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

// Why: Use the canonical `env!("CARGO_BIN_EXE_sss")` (see tests/migrate_e2e.rs:14
// and tests/keys_suite_flag.rs:13) to locate the test-runtime sss binary.
// Cargo guarantees the bin is built (with the test's own feature set) before
// the integration test runs, so an explicit `cargo build --bins` sub-process
// is unnecessary and harmful — the sub-cargo inherits no feature flags and
// overwrote target/debug/sss with a non-hybrid bin during workspace test runs.
fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

#[test]
fn test_ssse_symlink_behaviour() -> Result<()> {
    let temp_dir = tempdir()?;
    let work_dir = temp_dir.path();
    let config_dir = temp_dir.path().join("config");

    // Initialize test project with passwordless keys using system username
    let system_user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or("testuser".to_string());

    // Generate passwordless keys first
    let output = run_sss_in_dir(
        &["keys", "generate", "--suite", "classic", "--no-password", "--force"],
        work_dir,
        &config_dir,
    )?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to generate test keys: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Initialize the project with the system username (what ssse would use)
    let output = run_sss_in_dir(&["init", &system_user], work_dir, &config_dir)?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to initialize test project: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Create test file with plaintext marker
    let test_content = "Secret: ⊕{password123}";
    let test_file = work_dir.join("test.txt");
    fs::write(&test_file, test_content)?;

    // Test ssse symlink behavior by calling with ssse in args[0]
    // This simulates how ssse would be called
    let mut cmd = Command::new(sss_bin());

    // The key is that argv[0] should contain "ssse"
    // We simulate this by using a symlink-like approach
    cmd.arg("--confdir");
    cmd.arg(&config_dir);
    cmd.arg("--edit"); // ssse behavior
    cmd.arg("test.txt");
    cmd.current_dir(work_dir);
    cmd.env("SSS_PASSPHRASE", "");

    let output = cmd.output()?;

    // ssse edit mode might fail due to no editor, but should not crash with username issues
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Should not fail due to username validation issues
        assert!(
            !stderr.contains("reserved"),
            "ssse failed due to username issue: {}",
            stderr
        );
    }

    Ok(())
}

/// Run sss binary in a specific directory with custom config directory
fn run_sss_in_dir(
    args: &[&str],
    work_dir: &std::path::Path,
    config_dir: &std::path::Path,
) -> Result<std::process::Output> {
    let mut cmd = Command::new(sss_bin());

    // Add --confdir argument first
    cmd.arg("--confdir");
    cmd.arg(config_dir);
    cmd.args(args);
    cmd.current_dir(work_dir);

    // Set SSS_PASSPHRASE for non-interactive password handling in tests
    cmd.env("SSS_PASSPHRASE", "");

    Ok(cmd.output()?)
}
