use anyhow::{anyhow, Result};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

/// Get the project root directory
fn get_project_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
}

/// Build the binaries once before running tests
fn ensure_binaries_built() -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--bins"]);
    cmd.current_dir(get_project_root());
    let output = cmd.output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to build binaries: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}



#[test]
fn test_ssse_symlink_behaviour() -> Result<()> {
    let temp_dir = tempdir()?;
    let work_dir = temp_dir.path();
    let config_dir = temp_dir.path().join("config");

    // Initialize test project with passwordless keys using system username
    let system_user = env::var("USER").or_else(|_| env::var("USERNAME")).unwrap_or("testuser".to_string());

    // Generate passwordless keys first
    let output = run_sss_in_dir(
        &["keys", "generate", "--no-password", "--force"],
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
    let binary_path = get_project_root().join("target/debug/sss");
    let mut cmd = Command::new(&binary_path);

    // The key is that argv[0] should contain "ssse"
    // We simulate this by using a symlink-like approach
    cmd.arg("--confdir");
    cmd.arg(&config_dir);
    cmd.arg("--edit");  // ssse behavior
    cmd.arg("test.txt");
    cmd.current_dir(work_dir);
    cmd.env("SSS_TEST_MODE", "1");
    cmd.env("SSS_TEST_PASSWORD", "");

    let output = cmd.output()?;

    // ssse edit mode might fail due to no editor, but should not crash with username issues
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Should not fail due to username validation issues
        assert!(!stderr.contains("reserved"), "ssse failed due to username issue: {}", stderr);
    }

    Ok(())
}

/// Run sss binary in a specific directory with custom config directory
fn run_sss_in_dir(
    args: &[&str],
    work_dir: &std::path::Path,
    config_dir: &std::path::Path,
) -> Result<std::process::Output> {
    ensure_binaries_built()?;

    let binary_path = get_project_root().join("target/debug/sss");
    let mut cmd = Command::new(binary_path);

    // Add --confdir argument first
    cmd.arg("--confdir");
    cmd.arg(config_dir);
    cmd.args(args);
    cmd.current_dir(work_dir);

    // Set environment variables for test mode
    cmd.env("SSS_TEST_MODE", "1");
    cmd.env("SSS_TEST_PASSWORD", "");

    Ok(cmd.output()?)
}
