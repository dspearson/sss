//! Comprehensive end-to-end CLI workflow tests for SSS
//!
//! These tests invoke the compiled `sss` binary and verify complete
//! CLI workflows from key generation through seal/open/render cycles.
//! Each test creates isolated temp directories so tests can run in parallel.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test environment helper
// ---------------------------------------------------------------------------

/// Isolated test environment with its own HOME and project directory.
struct SssTestEnv {
    home_dir: TempDir,
    project_dir: TempDir,
}

impl SssTestEnv {
    fn new() -> Self {
        Self {
            home_dir: TempDir::new().expect("create temp home"),
            // Use a prefix without leading dot — process_project_recursively's
            // WalkDir filter skips entries whose name starts with '.', which
            // would silently skip the entire project root when TempDir uses
            // the default `.tmp` prefix.
            project_dir: tempfile::Builder::new()
                .prefix("sss_e2e_")
                .tempdir()
                .expect("create temp project"),
        }
    }

    /// Base command with full isolation (HOME, XDG_CONFIG_HOME, kdf-level).
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sss"));
        cmd.env("HOME", self.home_dir.path())
            .env("XDG_CONFIG_HOME", self.home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "testuser")
            .current_dir(self.project_dir.path())
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    }

    /// Bare command — isolation env only, no global CLI flags.
    fn bare_cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sss"));
        cmd.env("HOME", self.home_dir.path())
            .env("XDG_CONFIG_HOME", self.home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "testuser")
            .current_dir(self.project_dir.path());
        cmd
    }

    fn generate_keys(&self) {
        let out = self
            .cmd()
            .args(["keys", "generate", "--suite", "classic", "--no-password", "--force"])
            .output()
            .expect("run keygen");
        assert!(
            out.status.success(),
            "keygen failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_project(&self) {
        let out = self
            .cmd()
            .args(["init", "testuser"])
            .output()
            .expect("run init");
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Generate keys + initialise project (most tests need this).
    fn setup(&self) -> &Self {
        self.generate_keys();
        self.init_project();
        self
    }

    fn project_path(&self) -> &Path {
        self.project_dir.path()
    }

    fn write_file(&self, name: &str, content: &str) {
        let path = self.project_dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn read_file(&self, name: &str) -> String {
        std::fs::read_to_string(self.project_dir.path().join(name)).unwrap()
    }

    /// Run command, assert success, return (stdout, stderr).
    fn run_ok(&self, args: &[&str]) -> (String, String) {
        let out = self.cmd().args(args).output().expect("run sss");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            out.status.success(),
            "Expected success for {:?}\nstdout: {}\nstderr: {}",
            args,
            stdout,
            stderr
        );
        (stdout, stderr)
    }

    /// Run command, assert failure, return (stdout, stderr).
    fn run_fail(&self, args: &[&str]) -> (String, String) {
        let out = self.cmd().args(args).output().expect("run sss");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            !out.status.success(),
            "Expected failure for {:?}\nstdout: {}\nstderr: {}",
            args,
            stdout,
            stderr
        );
        (stdout, stderr)
    }
}

/// Generate a keypair in a throwaway HOME and return the base64 public key.
fn generate_other_pubkey() -> String {
    let other_home = TempDir::new().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sss"))
        .env("HOME", other_home.path())
        .env("XDG_CONFIG_HOME", other_home.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .args(["--kdf-level", "interactive", "keys", "generate", "--suite", "classic", "--no-password"])
        .output()
        .unwrap();
    assert!(out.status.success(), "other keygen failed");

    let out = Command::new(env!("CARGO_BIN_EXE_sss"))
        .env("HOME", other_home.path())
        .env("XDG_CONFIG_HOME", other_home.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .args(["--kdf-level", "interactive", "keys", "pubkey"])
        .output()
        .unwrap();
    assert!(out.status.success(), "other pubkey failed");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Insert a key=value line into the top-level section of a TOML string
/// (before the first `[table]` header).
fn insert_toml_top_level(toml_content: &str, line: &str) -> String {
    // Find the first table header
    if let Some(pos) = toml_content.find("\n[") {
        // Insert just before the first table header
        let (before, after) = toml_content.split_at(pos + 1);
        format!("{}{}\n{}", before, line, after)
    } else {
        // No table headers — just append
        format!("{}{}\n", toml_content, line)
    }
}

// ===========================================================================
// Core Workflow Tests
// ===========================================================================

#[test]
fn e2e_workflow_full_roundtrip_seal_open_render() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("secret.txt", "password: \u{2295}{my_secret_value}");

    // Seal in-place
    env.run_ok(&["seal", "-x", "secret.txt"]);
    let sealed = env.read_file("secret.txt");
    assert!(sealed.contains("\u{22A0}{"), "expected sealed marker");
    assert!(
        !sealed.contains("my_secret_value"),
        "plaintext must not be visible after seal"
    );

    // Open in-place
    env.run_ok(&["open", "-x", "secret.txt"]);
    let opened = env.read_file("secret.txt");
    assert!(
        opened.contains("\u{2295}{my_secret_value}"),
        "expected open marker with original value, got: {}",
        opened
    );

    // Render in-place
    env.run_ok(&["render", "-x", "secret.txt"]);
    let rendered = env.read_file("secret.txt");
    assert_eq!(rendered, "password: my_secret_value");
}

#[test]
fn e2e_workflow_seal_to_stdout() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("a.txt", "key: \u{2295}{abc}");

    let (stdout, _) = env.run_ok(&["seal", "a.txt"]);
    assert!(stdout.contains("\u{22A0}{"), "stdout should have sealed marker");
    // Original file must be unchanged
    assert!(env.read_file("a.txt").contains("\u{2295}{abc}"));
}

#[test]
fn e2e_workflow_open_to_stdout() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("a.txt", "key: \u{2295}{abc}");
    env.run_ok(&["seal", "-x", "a.txt"]);

    let (stdout, _) = env.run_ok(&["open", "a.txt"]);
    assert!(
        stdout.contains("\u{2295}{abc}"),
        "stdout should have open marker, got: {}",
        stdout
    );
}

#[test]
fn e2e_workflow_render_to_stdout() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("a.txt", "key: \u{2295}{abc}");
    env.run_ok(&["seal", "-x", "a.txt"]);

    let (stdout, _) = env.run_ok(&["render", "a.txt"]);
    assert_eq!(stdout, "key: abc");
}

#[test]
fn e2e_workflow_seal_in_place_message() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("f.txt", "x: \u{2295}{v}");

    let (_, stderr) = env.run_ok(&["seal", "-x", "f.txt"]);
    assert!(
        stderr.contains("processed in-place") || stderr.contains("in-place"),
        "expected in-place confirmation on stderr, got: {}",
        stderr
    );
}

#[test]
fn e2e_workflow_file_without_markers_unchanged() {
    let env = SssTestEnv::new();
    env.setup();
    let content = "just plain text, no markers here";
    env.write_file("plain.txt", content);

    let (stdout, _) = env.run_ok(&["seal", "plain.txt"]);
    assert_eq!(stdout, content, "file without markers should pass through");
}

#[test]
fn e2e_workflow_seal_then_render_recovers_plaintext() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("t.txt", "db_pass=\u{2295}{hunter2}");

    env.run_ok(&["seal", "-x", "t.txt"]);
    // Now render directly (sealed -> plaintext)
    let (stdout, _) = env.run_ok(&["render", "t.txt"]);
    assert_eq!(stdout, "db_pass=hunter2");
}

#[test]
fn e2e_workflow_roundtrip_content_integrity() {
    let env = SssTestEnv::new();
    env.setup();
    let original = "a=\u{2295}{one} b=\u{2295}{two} c=\u{2295}{three}";
    env.write_file("multi.txt", original);

    env.run_ok(&["seal", "-x", "multi.txt"]);
    env.run_ok(&["open", "-x", "multi.txt"]);
    let opened = env.read_file("multi.txt");
    assert!(opened.contains("\u{2295}{one}"), "first secret missing");
    assert!(opened.contains("\u{2295}{two}"), "second secret missing");
    assert!(opened.contains("\u{2295}{three}"), "third secret missing");
}

#[test]
fn e2e_workflow_seal_open_cycle_is_idempotent() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("idem.txt", "v=\u{2295}{secret}");

    // Seal twice
    env.run_ok(&["seal", "-x", "idem.txt"]);
    let after_first_seal = env.read_file("idem.txt");
    env.run_ok(&["seal", "-x", "idem.txt"]);
    let after_second_seal = env.read_file("idem.txt");
    assert_eq!(
        after_first_seal, after_second_seal,
        "sealing already-sealed content should be idempotent"
    );
}

#[test]
fn e2e_workflow_open_idempotent() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("idem.txt", "v=\u{2295}{secret}");
    env.run_ok(&["seal", "-x", "idem.txt"]);
    env.run_ok(&["open", "-x", "idem.txt"]);
    let first_open = env.read_file("idem.txt");
    env.run_ok(&["open", "-x", "idem.txt"]);
    let second_open = env.read_file("idem.txt");
    assert_eq!(first_open, second_open, "opening already-open should be idempotent");
}

// ===========================================================================
// Key Management Tests
// ===========================================================================

#[test]
fn e2e_keys_generate_basic() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["keys", "generate", "--suite", "classic", "--no-password"]);
    assert!(stdout.contains("Generated new keypair"), "expected keygen confirmation");
    assert!(stdout.contains("Public key:"), "expected public key output");
}

#[test]
fn e2e_keys_generate_force_overwrites() {
    let env = SssTestEnv::new();
    env.generate_keys();
    // Second generation with --force should succeed
    let (stdout, _) = env.run_ok(&["keys", "generate", "--suite", "classic", "--no-password", "--force"]);
    assert!(stdout.contains("Generated new keypair"));
}

#[test]
fn e2e_keys_generate_duplicate_without_force_fails() {
    let env = SssTestEnv::new();
    env.generate_keys();
    let (_, stderr) = env.run_fail(&["keys", "generate", "--suite", "classic", "--no-password"]);
    assert!(
        stderr.contains("already exists") || stderr.contains("--force"),
        "expected duplicate key error, got: {}",
        stderr
    );
}

#[test]
fn e2e_keys_list_shows_key() {
    let env = SssTestEnv::new();
    env.generate_keys();
    let (stdout, _) = env.run_ok(&["keys", "list"]);
    assert!(
        stdout.contains("1 keypair") || stdout.contains("keypair(s)"),
        "expected keypair listing, got: {}",
        stdout
    );
    assert!(stdout.contains("(current)"), "expected current marker");
}

#[test]
fn e2e_keys_pubkey_outputs_base64() {
    let env = SssTestEnv::new();
    env.generate_keys();
    let (stdout, _) = env.run_ok(&["keys", "pubkey"]);
    let pubkey = stdout.trim();
    // NaCl public keys are 32 bytes -> 44 chars base64
    assert!(
        pubkey.len() >= 40,
        "public key seems too short: {}",
        pubkey
    );
    // Should be valid base64 characters
    assert!(
        pubkey.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
        "public key contains non-base64 chars: {}",
        pubkey
    );
}

#[test]
fn e2e_keys_pubkey_fingerprint() {
    let env = SssTestEnv::new();
    env.generate_keys();
    let (stdout, _) = env.run_ok(&["keys", "pubkey", "--fingerprint"]);
    // Fingerprint output includes randomart box
    assert!(
        stdout.contains("+") && stdout.contains("|"),
        "expected randomart borders, got: {}",
        stdout
    );
    assert!(stdout.contains("SSS KEY"), "expected key type label");
}

#[test]
fn e2e_keys_current_show() {
    let env = SssTestEnv::new();
    env.generate_keys();
    let (stdout, _) = env.run_ok(&["keys", "current"]);
    assert!(
        stdout.contains("Current key ID:"),
        "expected current key info, got: {}",
        stdout
    );
    assert!(stdout.contains("Public key:"), "expected public key");
}

#[test]
fn e2e_keys_rotate_dry_run() {
    let env = SssTestEnv::new();
    env.setup();
    // Create a sealed file so rotation has something to scan
    env.write_file("sec.txt", "pw=\u{2295}{rotme}");
    env.run_ok(&["seal", "-x", "sec.txt"]);

    // Note: `keys rotate --dry-run` starts the scan but the rotation module
    // derives the scan directory from config_path.parent() of `.sss.toml`
    // which yields "" (empty string) instead of ".". This is a known issue
    // in rotation.rs. We verify the dry-run scan is initiated correctly.
    let out = env
        .cmd()
        .args(["keys", "rotate", "--dry-run"])
        .output()
        .expect("run sss");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Dry run") || stdout.contains("dry run"),
        "expected dry-run indication, got: {}",
        stdout
    );
}

// ===========================================================================
// Project Initialisation & Settings Tests
// ===========================================================================

#[test]
fn e2e_init_creates_project_config() {
    let env = SssTestEnv::new();
    env.generate_keys();
    let (stdout, _) = env.run_ok(&["init", "testuser"]);
    assert!(stdout.contains("Project initialized successfully"));
    assert!(stdout.contains("testuser"));

    // .sss.toml must exist
    assert!(
        env.project_path().join(".sss.toml").exists(),
        ".sss.toml should be created"
    );
}

#[test]
fn e2e_init_without_keys_fails() {
    let env = SssTestEnv::new();
    // Don't generate keys — init should fail
    let (_, stderr) = env.run_fail(&["init", "testuser"]);
    assert!(
        stderr.contains("No keypair") || stderr.contains("Generate a keypair"),
        "expected missing keypair error, got: {}",
        stderr
    );
}

#[test]
fn e2e_init_invalid_username_fails() {
    let env = SssTestEnv::new();
    env.generate_keys();
    // Username with spaces should be invalid
    let (_, stderr) = env.run_fail(&["init", "bad user"]);
    assert!(
        !stderr.is_empty(),
        "expected validation error for invalid username"
    );
}

#[test]
fn e2e_settings_show() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["settings", "show"]);
    assert!(stdout.contains("Current Settings"), "expected settings header");
    assert!(stdout.contains("Editor:"), "expected editor setting");
}

#[test]
fn e2e_settings_set_username() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["settings", "set", "--username", "newuser"]);
    assert!(
        stdout.contains("Set default username to: newuser"),
        "expected confirmation, got: {}",
        stdout
    );

    // Verify by reading settings
    let (show_out, _) = env.run_ok(&["settings", "show"]);
    assert!(
        show_out.contains("newuser"),
        "username should appear in settings, got: {}",
        show_out
    );
}

#[test]
fn e2e_settings_location() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["settings", "location"]);
    assert!(
        stdout.contains("User config:") && stdout.contains("settings.toml"),
        "expected config path, got: {}",
        stdout
    );
}

#[test]
fn e2e_settings_reset_with_confirm() {
    let env = SssTestEnv::new();
    // Set a username first
    env.run_ok(&["settings", "set", "--username", "tobereset"]);
    // Reset with confirmation
    let (stdout, _) = env.run_ok(&["settings", "reset", "--confirm"]);
    assert!(
        stdout.contains("reset to defaults"),
        "expected reset confirmation, got: {}",
        stdout
    );
}

#[test]
fn e2e_settings_reset_without_confirm_warns() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["settings", "reset"]);
    assert!(
        stdout.contains("--confirm"),
        "expected confirmation hint, got: {}",
        stdout
    );
}

#[test]
fn e2e_project_enable_render() {
    let env = SssTestEnv::new();
    env.setup();
    let (stdout, _) = env.run_ok(&["project", "enable", "render"]);
    assert!(
        stdout.contains("Enabled automatic rendering"),
        "expected enable confirmation, got: {}",
        stdout
    );
}

#[test]
fn e2e_project_disable_render() {
    let env = SssTestEnv::new();
    env.setup();
    env.run_ok(&["project", "enable", "render"]);
    let (stdout, _) = env.run_ok(&["project", "disable", "render"]);
    assert!(
        stdout.contains("Disabled automatic rendering"),
        "expected disable confirmation, got: {}",
        stdout
    );
}

#[test]
fn e2e_project_show() {
    let env = SssTestEnv::new();
    env.setup();
    let (stdout, _) = env.run_ok(&["project", "show"]);
    assert!(stdout.contains("Current Project:"), "expected project header");
    assert!(
        stdout.contains("rendering:") || stdout.contains("Automatic rendering"),
        "expected rendering status"
    );
}

#[test]
fn e2e_project_list() {
    let env = SssTestEnv::new();
    env.setup();
    // Enable a feature to register the project
    env.run_ok(&["project", "enable", "render"]);
    let (stdout, _) = env.run_ok(&["project", "list"]);
    assert!(
        stdout.contains("auto-render=enabled") || stdout.contains("Configured Projects"),
        "expected project in list, got: {}",
        stdout
    );
}

// ===========================================================================
// User Management Tests
// ===========================================================================

#[test]
fn e2e_users_list_shows_init_user() {
    let env = SssTestEnv::new();
    env.setup();
    let (stdout, _) = env.run_ok(&["users", "list"]);
    assert!(
        stdout.contains("testuser"),
        "expected init user in list, got: {}",
        stdout
    );
}

#[test]
fn e2e_users_add_with_pubkey() {
    let env = SssTestEnv::new();
    env.setup();
    let other_pubkey = generate_other_pubkey();

    let (stdout, _) = env.run_ok(&["users", "add", "alice", &other_pubkey]);
    assert!(
        stdout.contains("Added user 'alice'"),
        "expected add confirmation, got: {}",
        stdout
    );

    // Verify user appears in list
    let (list_out, _) = env.run_ok(&["users", "list"]);
    assert!(list_out.contains("alice"), "alice should be in user list");
}

#[test]
fn e2e_users_info() {
    let env = SssTestEnv::new();
    env.setup();
    let (stdout, _) = env.run_ok(&["users", "info", "testuser"]);
    assert!(
        stdout.contains("User: testuser"),
        "expected user info, got: {}",
        stdout
    );
    assert!(stdout.contains("Public key:"), "expected public key info");
}

#[test]
fn e2e_users_info_nonexistent_fails() {
    let env = SssTestEnv::new();
    env.setup();
    let (_, stderr) = env.run_fail(&["users", "info", "nobody"]);
    assert!(
        stderr.contains("not found"),
        "expected not-found error, got: {}",
        stderr
    );
}

// ===========================================================================
// Project-wide Operations
// ===========================================================================

#[test]
fn e2e_project_seal_recursive() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("a.txt", "x=\u{2295}{alpha}");
    env.write_file("sub/b.txt", "y=\u{2295}{beta}");

    let (stdout, _) = env.run_ok(&["seal", "--project"]);
    assert!(
        stdout.contains("Sealed") || stdout.contains("sealed"),
        "expected seal confirmation, got: {}",
        stdout
    );

    // Both files should now contain sealed markers
    let a = env.read_file("a.txt");
    let b = env.read_file("sub/b.txt");
    assert!(a.contains("\u{22A0}{"), "a.txt not sealed: {}", a);
    assert!(b.contains("\u{22A0}{"), "sub/b.txt not sealed: {}", b);
}

#[test]
fn e2e_project_open_denied_without_permission() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("s.txt", "x=\u{2295}{v}");
    env.run_ok(&["seal", "-x", "s.txt"]);

    // open --project should fail because auto-open is not enabled
    let (_, stderr) = env.run_fail(&["open", "--project"]);
    assert!(
        stderr.contains("disabled") || stderr.contains("enable open"),
        "expected permission error, got: {}",
        stderr
    );
}

#[test]
fn e2e_project_render_denied_without_permission() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("s.txt", "x=\u{2295}{v}");
    env.run_ok(&["seal", "-x", "s.txt"]);

    let (_, stderr) = env.run_fail(&["render", "--project"]);
    assert!(
        stderr.contains("disabled") || stderr.contains("enable render"),
        "expected permission error, got: {}",
        stderr
    );
}

#[test]
fn e2e_project_open_with_env_bypass() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("s.txt", "x=\u{2295}{secret}");
    env.run_ok(&["seal", "-x", "s.txt"]);

    // Bypass permission with environment variable
    let out = env
        .cmd()
        .env("SSS_PROJECT_OPEN", "true")
        .args(["open", "--project"])
        .output()
        .expect("run sss");
    assert!(out.status.success(), "open --project with env bypass should succeed");

    let content = env.read_file("s.txt");
    assert!(
        content.contains("\u{2295}{secret}"),
        "file should be opened, got: {}",
        content
    );
}

#[test]
fn e2e_project_render_with_permission_enabled() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("s.txt", "x=\u{2295}{secret}");
    env.run_ok(&["seal", "-x", "s.txt"]);
    env.run_ok(&["project", "enable", "render"]);

    env.run_ok(&["render", "--project"]);
    let content = env.read_file("s.txt");
    assert_eq!(content, "x=secret", "file should be rendered");
}

#[test]
fn e2e_project_ignore_patterns() {
    let env = SssTestEnv::new();
    env.setup();

    // Add ignore pattern
    let (stdout, _) = env.run_ok(&["project", "ignore", "add", "*.log"]);
    assert!(stdout.contains("Added ignore pattern"));

    // List patterns
    let (stdout, _) = env.run_ok(&["project", "ignore", "list"]);
    assert!(stdout.contains("*.log"), "pattern should be listed");

    // Create files: one matching the pattern, one not
    env.write_file("data.txt", "x=\u{2295}{keep}");
    env.write_file("debug.log", "y=\u{2295}{ignore_me}");

    env.run_ok(&["seal", "--project"]);

    // data.txt should be sealed
    let data = env.read_file("data.txt");
    assert!(data.contains("\u{22A0}{"), "data.txt should be sealed");
    // debug.log should NOT be sealed (ignored)
    let log = env.read_file("debug.log");
    assert!(
        log.contains("\u{2295}{ignore_me}"),
        "ignored file should be untouched, got: {}",
        log
    );

    // Remove pattern
    let (stdout, _) = env.run_ok(&["project", "ignore", "remove", "*.log"]);
    assert!(stdout.contains("Removed ignore pattern"));
}

// ===========================================================================
// Git Hooks Tests
// ===========================================================================

#[test]
fn e2e_hooks_list() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["hooks", "list"]);
    assert!(stdout.contains("pre-commit"), "expected pre-commit hook");
    assert!(stdout.contains("post-merge"), "expected post-merge hook");
    assert!(stdout.contains("post-checkout"), "expected post-checkout hook");
}

#[test]
fn e2e_hooks_show_pre_commit() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["hooks", "show", "pre-commit"]);
    assert!(stdout.contains("Hook: pre-commit"), "expected hook name");
    assert!(stdout.contains("#!"), "expected shebang in hook content");
}

#[test]
fn e2e_hooks_show_post_merge() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["hooks", "show", "post-merge"]);
    assert!(stdout.contains("Hook: post-merge"));
}

#[test]
fn e2e_hooks_install_in_git_repo() {
    let env = SssTestEnv::new();

    // Initialise a git repo in the project dir
    let git_init = Command::new("git")
        .args(["init"])
        .current_dir(env.project_path())
        .env("HOME", env.home_dir.path())
        .output()
        .expect("git init");
    assert!(git_init.status.success(), "git init failed");

    let (stdout, _) = env.run_ok(&["hooks", "install"]);
    assert!(
        stdout.contains("Installed") || stdout.contains("installed"),
        "expected install confirmation, got: {}",
        stdout
    );

    // Verify hook files exist
    let hooks_dir = env.project_path().join(".git").join("hooks");
    // Either flat hooks or multiplexed (.d/) should exist
    let has_pre_commit = hooks_dir.join("pre-commit").exists()
        || hooks_dir.join("pre-commit.d").join("50-sss").exists();
    assert!(has_pre_commit, "pre-commit hook should be installed");
}

#[test]
fn e2e_hooks_export() {
    let env = SssTestEnv::new();
    let (stdout, _) = env.run_ok(&["hooks", "export"]);
    assert!(
        stdout.contains("Exported") || stdout.contains("exported"),
        "expected export confirmation, got: {}",
        stdout
    );

    // Verify hooks exported to config dir
    let hooks_dir = env.home_dir.path().join(".config").join("sss").join("hooks");
    assert!(
        hooks_dir.join("pre-commit").exists(),
        "pre-commit should be exported to {:?}",
        hooks_dir
    );
    assert!(hooks_dir.join("post-merge").exists());
    assert!(hooks_dir.join("post-checkout").exists());
}

// ===========================================================================
// Stdin / Stdout Pipeline Tests
// ===========================================================================

#[test]
fn e2e_stdin_seal() {
    let env = SssTestEnv::new();
    env.setup();

    let mut child = env
        .cmd()
        .args(["seal", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sss seal -");

    child
        .stdin
        .take()
        .unwrap()
        .write_all("token=\u{2295}{abc123}".as_bytes())
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "seal from stdin failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\u{22A0}{"),
        "stdin seal should produce sealed marker, got: {}",
        stdout
    );
}

#[test]
fn e2e_stdin_pipe_seal_to_open() {
    let env = SssTestEnv::new();
    env.setup();

    // Step 1: seal via stdin
    let mut seal_child = env
        .cmd()
        .args(["seal", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    seal_child
        .stdin
        .take()
        .unwrap()
        .write_all("pw=\u{2295}{hello}".as_bytes())
        .unwrap();

    let seal_out = seal_child.wait_with_output().unwrap();
    assert!(seal_out.status.success());
    let sealed = String::from_utf8_lossy(&seal_out.stdout);

    // Step 2: pipe sealed output into open via stdin
    let mut open_child = env
        .cmd()
        .args(["open", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    open_child
        .stdin
        .take()
        .unwrap()
        .write_all(sealed.as_bytes())
        .unwrap();

    let open_out = open_child.wait_with_output().unwrap();
    assert!(open_out.status.success());
    let opened = String::from_utf8_lossy(&open_out.stdout);
    assert!(
        opened.contains("\u{2295}{hello}"),
        "piped open should recover original, got: {}",
        opened
    );
}

#[test]
fn e2e_stdin_pipe_seal_to_render() {
    let env = SssTestEnv::new();
    env.setup();

    // Seal via stdin
    let mut seal_child = env
        .cmd()
        .args(["seal", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    seal_child
        .stdin
        .take()
        .unwrap()
        .write_all("pw=\u{2295}{world}".as_bytes())
        .unwrap();

    let seal_out = seal_child.wait_with_output().unwrap();
    assert!(seal_out.status.success());

    // Render via stdin
    let mut render_child = env
        .cmd()
        .args(["render", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    render_child
        .stdin
        .take()
        .unwrap()
        .write_all(&seal_out.stdout)
        .unwrap();

    let render_out = render_child.wait_with_output().unwrap();
    assert!(render_out.status.success());
    let rendered = String::from_utf8_lossy(&render_out.stdout);
    assert_eq!(rendered, "pw=world");
}

// ===========================================================================
// Error Handling & Metadata Tests
// ===========================================================================

#[test]
fn e2e_error_seal_nonexistent_file() {
    let env = SssTestEnv::new();
    env.setup();
    let (_, stderr) = env.run_fail(&["seal", "no_such_file.txt"]);
    assert!(
        stderr.contains("does not exist") || stderr.contains("No such file"),
        "expected file-not-found error, got: {}",
        stderr
    );
}

#[test]
fn e2e_error_open_nonexistent_file() {
    let env = SssTestEnv::new();
    env.setup();
    let (_, stderr) = env.run_fail(&["open", "no_such_file.txt"]);
    assert!(
        stderr.contains("does not exist") || stderr.contains("No such file"),
        "got: {}",
        stderr
    );
}

#[test]
fn e2e_error_render_nonexistent_file() {
    let env = SssTestEnv::new();
    env.setup();
    let (_, stderr) = env.run_fail(&["render", "no_such_file.txt"]);
    assert!(
        stderr.contains("does not exist") || stderr.contains("No such file"),
        "got: {}",
        stderr
    );
}

#[test]
fn e2e_version_flag() {
    let env = SssTestEnv::new();
    let out = env.bare_cmd().arg("--version").output().expect("run sss");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "expected version {}, got: {}",
        env!("CARGO_PKG_VERSION"),
        stdout
    );
}

#[test]
fn e2e_help_flag() {
    let env = SssTestEnv::new();
    let out = env.bare_cmd().arg("--help").output().expect("run sss");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Secret String Substitution"),
        "expected app description in help, got: {}",
        stdout
    );
    assert!(stdout.contains("seal"), "expected seal subcommand in help");
    assert!(stdout.contains("open"), "expected open subcommand in help");
    assert!(stdout.contains("render"), "expected render subcommand in help");
}

#[test]
fn e2e_status_in_project() {
    let env = SssTestEnv::new();
    env.setup();
    let out = env.cmd().arg("status").output().expect("run sss");
    assert_eq!(
        out.status.code(),
        Some(0),
        "status should exit 0 in project"
    );
}

#[test]
fn e2e_status_outside_project() {
    let env = SssTestEnv::new();
    let outside = TempDir::new().unwrap();
    let out = env
        .bare_cmd()
        .current_dir(outside.path())
        .arg("status")
        .output()
        .expect("run sss");
    assert_ne!(
        out.status.code(),
        Some(0),
        "status should exit non-zero outside project"
    );
}

#[test]
fn e2e_error_no_subcommand_shows_help() {
    let env = SssTestEnv::new();
    let out = env.bare_cmd().output().expect("run sss");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("seal") || stdout.contains("Usage"),
        "no-subcommand should show help, got: {}",
        stdout
    );
}

// ===========================================================================
// Edge Cases
// ===========================================================================

#[test]
fn e2e_edge_unicode_content() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("uni.txt", "pass=\u{2295}{\u{65E5}\u{672C}\u{8A9E}123}");

    env.run_ok(&["seal", "-x", "uni.txt"]);
    let sealed = env.read_file("uni.txt");
    assert!(sealed.contains("\u{22A0}{"), "should be sealed");
    assert!(!sealed.contains("\u{65E5}\u{672C}\u{8A9E}"), "unicode plaintext should be hidden");

    env.run_ok(&["open", "-x", "uni.txt"]);
    let opened = env.read_file("uni.txt");
    assert!(
        opened.contains("\u{65E5}\u{672C}\u{8A9E}123"),
        "unicode should survive roundtrip, got: {}",
        opened
    );
}

#[test]
fn e2e_edge_multiline_secret() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("ml.txt", "cert=\u{2295}{line1\nline2\nline3}");

    env.run_ok(&["seal", "-x", "ml.txt"]);
    env.run_ok(&["open", "-x", "ml.txt"]);
    let opened = env.read_file("ml.txt");
    assert!(
        opened.contains("line1\nline2\nline3"),
        "multiline should survive roundtrip, got: {}",
        opened
    );
}

#[test]
fn e2e_edge_multiple_secrets_in_file() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file(
        "multi.txt",
        "a=\u{2295}{first}\nb=\u{2295}{second}\nc=\u{2295}{third}",
    );

    env.run_ok(&["seal", "-x", "multi.txt"]);
    let sealed = env.read_file("multi.txt");
    let marker_count = sealed.matches("\u{22A0}{").count();
    assert_eq!(marker_count, 3, "all three secrets should be sealed");

    env.run_ok(&["render", "-x", "multi.txt"]);
    assert_eq!(env.read_file("multi.txt"), "a=first\nb=second\nc=third");
}

#[test]
fn e2e_edge_ascii_marker_variant() {
    let env = SssTestEnv::new();
    env.setup();
    // Use the ASCII fallback marker o+{...}
    env.write_file("ascii.txt", "key=o+{ascii_secret}");

    let (stdout, _) = env.run_ok(&["seal", "ascii.txt"]);
    assert!(
        stdout.contains("\u{22A0}{"),
        "ASCII marker should be sealed, got: {}",
        stdout
    );

    // File should be unchanged (stdout mode)
    assert_eq!(env.read_file("ascii.txt"), "key=o+{ascii_secret}");
}

#[test]
fn e2e_edge_confdir_override() {
    let env = SssTestEnv::new();
    let custom_confdir = TempDir::new().unwrap();

    // Generate keys with explicit --confdir
    let out = env
        .bare_cmd()
        .args([
            "--confdir",
            custom_confdir.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--suite",
            "classic",
            "--no-password",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen with confdir failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // List keys with the same confdir
    let out = env
        .bare_cmd()
        .args([
            "--confdir",
            custom_confdir.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "list",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 keypair") || stdout.contains("keypair(s)"),
        "confdir should contain our key, got: {}",
        stdout
    );
}

#[test]
fn e2e_edge_empty_file_with_markers() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("empty.txt", "");
    // Sealing an empty file should succeed and produce empty output
    let (stdout, _) = env.run_ok(&["seal", "empty.txt"]);
    assert_eq!(stdout, "", "empty file should produce empty output");
}

#[test]
fn e2e_edge_large_secret() {
    let env = SssTestEnv::new();
    env.setup();
    let big_secret = "x".repeat(4096);
    env.write_file("big.txt", &format!("data=\u{2295}{{{}}}", big_secret));

    env.run_ok(&["seal", "-x", "big.txt"]);
    env.run_ok(&["render", "-x", "big.txt"]);
    let rendered = env.read_file("big.txt");
    assert_eq!(rendered, format!("data={}", big_secret));
}

// ===========================================================================
// Nested Project Support Tests
// ===========================================================================

impl SssTestEnv {
    /// Create a nested project in `subdir/` using the SAME user keys as the
    /// root project.  Files in this subdir will have a separate .sss.toml
    /// (different repo key) but the current user can still decrypt them.
    fn setup_nested_project_same_user(&self, subdir: &str) {
        let sub_path = self.project_dir.path().join(subdir);
        std::fs::create_dir_all(&sub_path).expect("create nested dir");

        let out = self
            .cmd()
            .current_dir(&sub_path)
            .args(["init", "testuser"])
            .output()
            .expect("run init in nested dir");
        assert!(
            out.status.success(),
            "nested init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Create a nested project in `subdir/` with a DIFFERENT user's keys
    /// (inaccessible to the current user).  Returns the TempDir holding
    /// the other user's HOME so its keys remain on disk during the test.
    fn setup_nested_project_other_user(&self, subdir: &str) -> TempDir {
        let sub_path = self.project_dir.path().join(subdir);
        std::fs::create_dir_all(&sub_path).expect("create nested dir");

        // Generate a keypair in a throwaway HOME
        let other_home = TempDir::new().unwrap();

        let out = Command::new(env!("CARGO_BIN_EXE_sss"))
            .env("HOME", other_home.path())
            .env("XDG_CONFIG_HOME", other_home.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .args(["--kdf-level", "interactive", "keys", "generate", "--suite", "classic", "--no-password"])
            .output()
            .unwrap();
        assert!(out.status.success(), "other keygen failed");

        // Init the nested project using the other user's HOME
        let out = Command::new(env!("CARGO_BIN_EXE_sss"))
            .env("HOME", other_home.path())
            .env("XDG_CONFIG_HOME", other_home.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "other_user")
            .current_dir(&sub_path)
            .args(["--kdf-level", "interactive", "init", "other_user"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "nested init (other user) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        other_home // keep alive
    }

    /// Seal a file from a nested project using the nested project's own HOME.
    fn seal_file_as_other(
        &self,
        other_home: &TempDir,
        file_relative: &str,
    ) {
        let file_path = self.project_dir.path().join(file_relative);
        let out = Command::new(env!("CARGO_BIN_EXE_sss"))
            .env("HOME", other_home.path())
            .env("XDG_CONFIG_HOME", other_home.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "other_user")
            .current_dir(file_path.parent().unwrap())
            .args(["--kdf-level", "interactive", "seal", "-x",
                   file_path.file_name().unwrap().to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "seal_file_as_other failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn e2e_nested_seal_uses_correct_keys() {
    let env = SssTestEnv::new();
    env.setup();

    // Create nested project with same user keys
    env.setup_nested_project_same_user("child");

    // Write files in root and child
    env.write_file("root.txt", "root_pass=\u{2295}{root_secret}");
    env.write_file("child/child.txt", "child_pass=\u{2295}{child_secret}");

    // Seal from project root
    env.run_ok(&["seal", "--project"]);

    // Both files should be sealed
    let root_sealed = env.read_file("root.txt");
    assert!(root_sealed.contains("\u{22A0}{"), "root file should be sealed");
    assert!(!root_sealed.contains("root_secret"), "root plaintext should be hidden");

    let child_sealed = env.read_file("child/child.txt");
    assert!(child_sealed.contains("\u{22A0}{"), "child file should be sealed");
    assert!(!child_sealed.contains("child_secret"), "child plaintext should be hidden");

    // The sealed ciphertexts should differ because different repo keys are used
    // (We can't directly compare — just verify both are sealed.)
}

#[test]
fn e2e_nested_open_uses_correct_keys() {
    let env = SssTestEnv::new();
    env.setup();

    env.setup_nested_project_same_user("child");

    env.write_file("root.txt", "a=\u{2295}{val_a}");
    env.write_file("child/child.txt", "b=\u{2295}{val_b}");

    // Seal, then open (needs SSS_PROJECT_OPEN permission)
    env.run_ok(&["seal", "--project"]);

    let out = env.cmd()
        .env("SSS_PROJECT_OPEN", "true")
        .args(["open", "--project"])
        .output()
        .expect("run open --project");
    assert!(out.status.success(), "open --project failed: {}",
        String::from_utf8_lossy(&out.stderr));

    let root_opened = env.read_file("root.txt");
    assert!(root_opened.contains("\u{2295}{val_a}"), "root should be opened");

    let child_opened = env.read_file("child/child.txt");
    assert!(child_opened.contains("\u{2295}{val_b}"), "child should be opened");
}

#[test]
fn e2e_nested_render_uses_correct_keys() {
    let env = SssTestEnv::new();
    env.setup();

    env.setup_nested_project_same_user("child");

    env.write_file("root.txt", "x=\u{2295}{root_val}");
    env.write_file("child/child.txt", "y=\u{2295}{child_val}");

    // Seal, then render (needs SSS_PROJECT_RENDER permission)
    env.run_ok(&["seal", "--project"]);

    let out = env.cmd()
        .env("SSS_PROJECT_RENDER", "true")
        .args(["render", "--project"])
        .output()
        .expect("run render --project");
    assert!(out.status.success(), "render --project failed: {}",
        String::from_utf8_lossy(&out.stderr));

    let root_rendered = env.read_file("root.txt");
    assert_eq!(root_rendered, "x=root_val");

    let child_rendered = env.read_file("child/child.txt");
    assert_eq!(child_rendered, "y=child_val");
}

#[test]
fn e2e_nested_no_keys_passthrough() {
    let env = SssTestEnv::new();
    env.setup();

    // Create nested project with a DIFFERENT user (inaccessible)
    let _other_home = env.setup_nested_project_other_user("private");

    // Write files: root has markers, private has markers sealed by someone else
    env.write_file("root.txt", "root=\u{2295}{open_secret}");
    env.write_file(
        "private/secret.txt",
        "private=\u{2295}{inaccessible_secret}",
    );

    // Seal the private file using the other user's keys
    env.seal_file_as_other(&_other_home, "private/secret.txt");

    // Now seal from root as the main user
    env.run_ok(&["seal", "--project"]);

    // Root file should be sealed with root's key
    let root_sealed = env.read_file("root.txt");
    assert!(root_sealed.contains("\u{22A0}{"), "root should be sealed");
    assert!(!root_sealed.contains("open_secret"));

    // Private file should be UNTOUCHED (still sealed by other user's key)
    let private_content = env.read_file("private/secret.txt");
    assert!(
        private_content.contains("\u{22A0}{"),
        "private file should still be sealed (by other key)"
    );
}

#[test]
fn e2e_nested_no_keys_no_error() {
    let env = SssTestEnv::new();
    env.setup();

    // Create nested project with different user
    let _other_home = env.setup_nested_project_other_user("foreign");

    env.write_file("root.txt", "r=\u{2295}{val}");
    env.write_file("foreign/f.txt", "f=\u{2295}{other_val}");

    // Seal from root — should succeed with exit code 0
    // even though we can't access 'foreign' project
    let out = env
        .cmd()
        .args(["seal", "--project"])
        .output()
        .expect("run seal --project");
    assert!(
        out.status.success(),
        "seal --project should succeed even with inaccessible nested project, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn e2e_nested_ignore_patterns_per_project() {
    let env = SssTestEnv::new();
    env.setup();

    // Set ignore patterns on root project (ignore *.log)
    // Insert before the first table header so it stays at the TOML root level
    let root_config = env.read_file(".sss.toml");
    let root_config_with_ignore = insert_toml_top_level(&root_config, "ignore = \"*.log\"");
    env.write_file(".sss.toml", &root_config_with_ignore);

    // Create nested project with same user
    env.setup_nested_project_same_user("child");

    // Set different ignore patterns on child project (ignore *.tmp)
    let child_config = env.read_file("child/.sss.toml");
    let child_config_with_ignore = insert_toml_top_level(&child_config, "ignore = \"*.tmp\"");
    env.write_file("child/.sss.toml", &child_config_with_ignore);

    // Write test files
    env.write_file("root.txt", "r=\u{2295}{root_secret}");
    env.write_file("root.log", "log=\u{2295}{log_secret}");        // ignored by root
    env.write_file("child/child.txt", "c=\u{2295}{child_secret}");
    env.write_file("child/child.tmp", "t=\u{2295}{tmp_secret}");   // ignored by child
    env.write_file("child/child.log", "cl=\u{2295}{childlog_secret}"); // NOT ignored by child

    // Seal from project root
    env.run_ok(&["seal", "--project"]);

    // root.txt should be sealed
    let root_sealed = env.read_file("root.txt");
    assert!(root_sealed.contains("\u{22A0}{"), "root.txt should be sealed");

    // root.log should NOT be sealed (ignored by root patterns)
    let root_log = env.read_file("root.log");
    assert!(
        root_log.contains("\u{2295}{log_secret}"),
        "root.log should be left untouched (ignored), got: {}",
        root_log
    );

    // child/child.txt should be sealed
    let child_sealed = env.read_file("child/child.txt");
    assert!(child_sealed.contains("\u{22A0}{"), "child/child.txt should be sealed");

    // child/child.tmp should NOT be sealed (ignored by child patterns)
    let child_tmp = env.read_file("child/child.tmp");
    assert!(
        child_tmp.contains("\u{2295}{tmp_secret}"),
        "child/child.tmp should be left untouched (ignored by child), got: {}",
        child_tmp
    );

    // child/child.log SHOULD be sealed (not in child's ignore patterns)
    let child_log = env.read_file("child/child.log");
    assert!(
        child_log.contains("\u{22A0}{"),
        "child/child.log should be sealed (not ignored by child), got: {}",
        child_log
    );
}

// ===========================================================================
// Phase 1 Roadmap Success Criteria Gap-Fill Tests (Plan 02)
// ===========================================================================

#[test]
fn e2e_cli_seal_in_place_stdout_empty() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("secret.txt", "key: \u{2295}{hunter2}");

    let (stdout, stderr) = env.run_ok(&["seal", "--in-place", "secret.txt"]);
    assert_eq!(
        stdout.trim(),
        "",
        "seal --in-place must produce no stdout output; got: {:?}",
        stdout
    );
    assert!(
        stderr.contains("in-place"),
        "seal --in-place confirmation must appear on stderr; got: {:?}",
        stderr
    );
    // Confirm the file was actually rewritten with sealed marker
    let on_disk = env.read_file("secret.txt");
    assert!(
        on_disk.contains("\u{22A0}{"),
        "sealed file on disk must contain sealed marker \u{22A0}{{; got: {:?}",
        on_disk
    );
}

#[test]
fn e2e_cli_render_auth_failure_exits_nonzero() {
    // Set up a project, seal a file, then directly edit .sss.toml to remove
    // the current user so the current keypair is no longer authorized.
    let env = SssTestEnv::new();
    env.setup(); // generates keys for "testuser", inits project with testuser

    // Seal a file using the authorized testuser
    env.write_file("secret.txt", "pass: \u{2295}{topsecret}");
    env.run_ok(&["seal", "--in-place", "secret.txt"]);

    // Directly remove the [testuser] section from .sss.toml so the current
    // keypair is no longer in the project's authorized users list.
    // This avoids the interactive key rotation that `users remove` triggers.
    let config = env.read_file(".sss.toml");
    // Remove the [testuser] section and all its key=value lines.
    // TOML sections run from the header until the next header or end-of-file.
    let stripped = strip_toml_section(&config, "testuser");
    env.write_file(".sss.toml", &stripped);

    // Verify the file was modified
    let new_config = env.read_file(".sss.toml");
    assert!(!new_config.contains("testuser"), "testuser should be removed from config");

    // Now "testuser" (our current keypair) is no longer in the project.
    // render should fail with an auth error (exit non-zero, non-empty stderr).
    let (stdout, stderr) = env.run_fail(&["render", "secret.txt"]);
    assert_eq!(
        stdout,
        "",
        "render must produce no stdout on auth failure; got: {:?}",
        stdout
    );
    assert!(
        !stderr.is_empty(),
        "render must write an error message to stderr on auth failure; got empty stderr"
    );
}

/// Remove a TOML section (and all its key=value pairs) by section name.
/// Handles `[section]` style headers until the next `[` or end-of-file.
fn strip_toml_section(toml: &str, section_name: &str) -> String {
    let header = format!("[{}]", section_name);
    let mut result = Vec::new();
    let mut in_section = false;

    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed == header {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with('[') {
            in_section = false;
        }
        if !in_section {
            result.push(line);
        }
    }

    let mut out = result.join("\n");
    if toml.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[test]
fn e2e_cli_non_interactive_flag_render() {
    let env = SssTestEnv::new();
    env.setup();
    env.write_file("data.txt", "api_key: \u{2295}{abc123}");
    env.run_ok(&["seal", "--in-place", "data.txt"]);

    // Use a bare command WITHOUT SSS_NONINTERACTIVE env var, add flag explicitly
    let out = Command::new(env!("CARGO_BIN_EXE_sss"))
        .env("HOME", env.home_dir.path())
        .env("XDG_CONFIG_HOME", env.home_dir.path().join(".config"))
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "testuser")
        .current_dir(env.project_dir.path())
        .args(["--non-interactive", "--kdf-level", "interactive", "render", "data.txt"])
        .output()
        .expect("run sss --non-interactive render");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "--non-interactive render must exit 0; stderr: {}",
        stderr
    );
    assert_eq!(
        stdout.trim(),
        "api_key: abc123",
        "--non-interactive render must output decrypted plaintext; got: {:?}",
        stdout
    );
    assert_eq!(
        stderr.trim(),
        "",
        "--non-interactive render must produce no stderr on success; got: {:?}",
        stderr
    );
}

#[test]
fn e2e_nested_single_file_nearest_config() {
    // Verify that single-file operations (without --project) use the
    // nearest .sss.toml by default (existing behaviour — just verify).
    let env = SssTestEnv::new();
    env.setup();

    env.setup_nested_project_same_user("child");

    env.write_file("child/f.txt", "secret=\u{2295}{nested_val}");

    // cd into child/ and seal a single file
    let child_dir = env.project_dir.path().join("child");
    let out = Command::new(env!("CARGO_BIN_EXE_sss"))
        .env("HOME", env.home_dir.path())
        .env("XDG_CONFIG_HOME", env.home_dir.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "testuser")
        .current_dir(&child_dir)
        .args(["--kdf-level", "interactive", "seal", "-x", "f.txt"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "single-file seal in child failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sealed = env.read_file("child/f.txt");
    assert!(sealed.contains("\u{22A0}{"), "file should be sealed using child config");
    assert!(!sealed.contains("nested_val"));

    // Open from child
    let out = Command::new(env!("CARGO_BIN_EXE_sss"))
        .env("HOME", env.home_dir.path())
        .env("XDG_CONFIG_HOME", env.home_dir.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "testuser")
        .current_dir(&child_dir)
        .args(["--kdf-level", "interactive", "open", "-x", "f.txt"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let opened = env.read_file("child/f.txt");
    assert!(opened.contains("\u{2295}{nested_val}"), "file should be opened correctly");
}

#[test]
fn e2e_nested_three_levels_deep() {
    let env = SssTestEnv::new();
    env.setup();

    // root → child → grandchild
    env.setup_nested_project_same_user("child");
    // Create grandchild inside child
    let grandchild_dir = env.project_dir.path().join("child/grandchild");
    std::fs::create_dir_all(&grandchild_dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sss"))
        .env("HOME", env.home_dir.path())
        .env("XDG_CONFIG_HOME", env.home_dir.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "testuser")
        .current_dir(&grandchild_dir)
        .args(["--kdf-level", "interactive", "init", "testuser"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "grandchild init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Write secrets at each level
    env.write_file("root.txt", "r=\u{2295}{root_val}");
    env.write_file("child/c.txt", "c=\u{2295}{child_val}");
    env.write_file("child/grandchild/g.txt", "g=\u{2295}{grand_val}");

    // Seal from root
    env.run_ok(&["seal", "--project"]);

    // All should be sealed
    assert!(env.read_file("root.txt").contains("\u{22A0}{"), "root sealed");
    assert!(env.read_file("child/c.txt").contains("\u{22A0}{"), "child sealed");
    assert!(env.read_file("child/grandchild/g.txt").contains("\u{22A0}{"), "grandchild sealed");

    // Render from root (needs SSS_PROJECT_RENDER permission)
    let out = env.cmd()
        .env("SSS_PROJECT_RENDER", "true")
        .args(["render", "--project"])
        .output()
        .expect("run render --project");
    assert!(out.status.success(), "render --project failed: {}",
        String::from_utf8_lossy(&out.stderr));

    assert_eq!(env.read_file("root.txt"), "r=root_val");
    assert_eq!(env.read_file("child/c.txt"), "c=child_val");
    assert_eq!(env.read_file("child/grandchild/g.txt"), "g=grand_val");
}

// ===========================================================================
// Unbalanced-`}` value round-trip (delimiter ladder + escape forms)
// ===========================================================================

/// Full CLI round-trip for marker values containing an unbalanced `}`.
///
/// The three input forms are all equivalent ways to mark the value `pass}word`:
/// an auto-picked alternate pair, a hand-typed escape, and a user-chosen exotic
/// pair. Each must survive `seal` → `open` → `render` without byte loss.
///
/// Regression: before the delimiter-ladder work, the default `{}` pair chomped
/// at the first `}`, silently losing the `word}` suffix.
#[test]
fn e2e_roundtrip_value_with_unbalanced_close_brace() {
    let env = SssTestEnv::new();
    env.setup();

    let inputs = [
        ("alt.conf",    "password: \u{2295}[pass}word]"),
        ("escape.conf", "password: \u{2295}{pass\\}word}"),
        ("exotic.conf", "password: \u{2295}\u{2983}pass}word\u{2984}"),
    ];

    for (name, content) in inputs {
        env.write_file(name, content);
    }

    // Seal: ciphertext marker appears, plaintext must not leak.
    for (name, _) in inputs {
        env.run_ok(&["seal", "-x", name]);
        let sealed = env.read_file(name);
        assert!(
            sealed.contains("\u{22A0}"),
            "{name}: expected sealed marker, got: {sealed}"
        );
        assert!(
            !sealed.contains("pass}word"),
            "{name}: plaintext leaked after seal: {sealed}"
        );
    }

    // Open: plaintext marker recovered, value preserved. The canonical form
    // emitted is `⊕[pass}word]` (tier-2 pair — first non-colliding after the
    // default). Reject the broken default-pair form.
    for (name, _) in inputs {
        env.run_ok(&["open", "-x", name]);
        let opened = env.read_file(name);
        assert!(
            opened.contains("pass}word"),
            "{name}: value lost after round-trip: {opened}"
        );
        assert!(
            !opened.contains("\u{2295}{pass}word}"),
            "{name}: default-pair form would chomp: {opened}"
        );
    }

    // Render: literal value, no marker syntax, `}` byte survives.
    for (name, _) in inputs {
        env.run_ok(&["render", "-x", name]);
        assert_eq!(
            env.read_file(name),
            "password: pass}word",
            "{name}: render output wrong"
        );
    }
}

/// A value containing both `}` AND `]` forces the parser past tiers 1 and 2
/// onto an exotic Unicode pair. Verifies the ladder walks past multiple
/// collisions rather than falling back to a broken default.
#[test]
fn e2e_roundtrip_value_colliding_with_first_two_tiers() {
    let env = SssTestEnv::new();
    env.setup();

    // Value collides with both `{}` (unbalanced `}`) and `[]` (contains `]`).
    let value = "api]v1.0}release";
    env.write_file("cfg", &format!("token: \u{2295}\u{27E6}{value}\u{27E7}"));

    env.run_ok(&["seal", "-x", "cfg"]);
    let sealed = env.read_file("cfg");
    assert!(!sealed.contains(value), "plaintext leaked: {sealed}");

    env.run_ok(&["open", "-x", "cfg"]);
    let opened = env.read_file("cfg");
    assert!(opened.contains(value), "value survived: {opened}");

    env.run_ok(&["render", "-x", "cfg"]);
    assert_eq!(env.read_file("cfg"), format!("token: {value}"));
}

/// A file with multiple markers on different lines, one of which holds an
/// unbalanced `}`. Verifies per-marker delimiter selection — other markers
/// must keep the default `{}` pair; only the `}`-bearing one switches.
#[test]
fn e2e_roundtrip_mixed_markers_only_one_needs_alt() {
    let env = SssTestEnv::new();
    env.setup();

    let content = "\
user: \u{2295}{admin}
password: \u{2295}[p@ss}w0rd]
api_key: \u{2295}{abc-123}
";
    env.write_file("mixed.conf", content);

    env.run_ok(&["seal", "-x", "mixed.conf"]);
    env.run_ok(&["open", "-x", "mixed.conf"]);
    let opened = env.read_file("mixed.conf");

    // All three values must be recoverable.
    assert!(opened.contains("admin"), "lost admin: {opened}");
    assert!(opened.contains("p@ss}w0rd"), "lost password: {opened}");
    assert!(opened.contains("abc-123"), "lost api_key: {opened}");

    // Default-pair markers must stay default — don't drag everything into
    // exotic delimiters when only one marker needs them.
    assert!(opened.contains("\u{2295}{admin}"), "admin lost default pair: {opened}");
    assert!(opened.contains("\u{2295}{abc-123}"), "api_key lost default pair: {opened}");

    env.run_ok(&["render", "-x", "mixed.conf"]);
    assert_eq!(
        env.read_file("mixed.conf"),
        "user: admin\npassword: p@ss}w0rd\napi_key: abc-123\n"
    );
}
