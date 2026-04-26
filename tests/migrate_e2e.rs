//! End-to-end migration test (TEST-04).
//!
//! Drives the real sss binary through the complete migration workflow:
//!   3-user v1 repo → sss migrate → v2 repo → each user renders with byte-identical plaintext.
//!
//! Only compiled and run with --features hybrid (requires HybridCryptoSuite + sss migrate).

#![cfg(feature = "hybrid")]

use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

// ---------------------------------------------------------------------------
// Per-user helper — each user gets an isolated HOME directory
// ---------------------------------------------------------------------------

struct UserEnv {
    home_dir: TempDir,
    pub username: String,
    /// Classic (X25519) base64 public key, captured from `keys generate --suite classic`.
    /// Empty string until generate_keys() is called.
    classic_pk: String,
    /// Hybrid base64 public key, captured from stdout of `keys generate --suite hybrid`.
    /// Empty string until generate_keys() is called.
    hybrid_pk: String,
}

impl UserEnv {
    fn new(username: &str) -> Self {
        Self {
            home_dir: TempDir::new().expect("create temp home"),
            username: username.to_string(),
            classic_pk: String::new(),
            hybrid_pk: String::new(),
        }
    }

    /// Base command for this user, running in the given project directory.
    fn cmd(&self, project_dir: &Path) -> Command {
        let mut cmd = Command::new(sss_bin());
        cmd.env("HOME", self.home_dir.path())
            .env("XDG_CONFIG_HOME", self.home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", &self.username)
            .current_dir(project_dir)
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    }

    /// Generate classic + hybrid keypairs for this user.
    ///
    /// Captures stdout of `keys generate --suite hybrid` and parses the
    /// "Hybrid public key: <base64>" line (1 space after colon, as printed
    /// by src/commands/keys.rs handle_keys_generate_command --suite hybrid).
    /// Stores the result in self.hybrid_pk for later use by hybrid_pubkey().
    ///
    /// Do NOT call `sss keys show` to retrieve the hybrid pubkey — keys show
    /// only emits ASCII randomart and never prints the "Hybrid public key:" line.
    fn generate_keys(&mut self) {
        // Classic keypair first — hybrid requires an existing classic keypair.
        // Parse "Public key: <base64>" from stdout to avoid calling `sss keys pubkey`
        // later, which in hybrid builds returns the hybrid key when there is no project.
        let out = self.cmd(self.home_dir.path())
            .args(["keys", "generate", "--suite", "classic", "--no-password"])
            .output()
            .expect("classic keygen");
        assert!(
            out.status.success(),
            "classic keygen failed for {}: {}",
            self.username,
            String::from_utf8_lossy(&out.stderr)
        );
        let classic_stdout = String::from_utf8_lossy(&out.stdout);
        for line in classic_stdout.lines() {
            if let Some(pk) = line.strip_prefix("Public key: ") {
                self.classic_pk = pk.trim().to_string();
                break;
            }
        }
        assert!(
            !self.classic_pk.is_empty(),
            "could not parse 'Public key: ' from classic keygen for {}:\n{}",
            self.username,
            classic_stdout
        );

        // Hybrid keypair (added alongside existing classic — different suite slot).
        // Capture stdout: it contains the "Hybrid public key: <base64>" line we need.
        let out = self.cmd(self.home_dir.path())
            .args(["keys", "generate", "--suite", "hybrid", "--no-password"])
            .output()
            .expect("hybrid keygen");
        assert!(
            out.status.success(),
            "hybrid keygen failed for {}: {}",
            self.username,
            String::from_utf8_lossy(&out.stderr)
        );

        // Parse "Hybrid public key: <base64>" from stdout.
        // src/commands/keys.rs line 129: println!("Hybrid public key: {hybrid_pk_b64}");
        // — exactly 1 space after the colon.
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some(pk) = line.strip_prefix("Hybrid public key: ") {
                let key = pk.trim().to_string();
                assert!(
                    !key.is_empty(),
                    "parsed hybrid pubkey is empty for {}; stdout was:\n{}",
                    self.username,
                    stdout
                );
                self.hybrid_pk = key;
                return;
            }
        }
        panic!(
            "could not find 'Hybrid public key: ' in `sss keys generate --suite hybrid` \
             output for {}:\nstdout: {}\nstderr: {}",
            self.username,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Return the classic (X25519) base64 public key for this user.
    /// Value is captured from `keys generate --suite classic` stdout; call generate_keys() first.
    fn classic_pubkey(&self) -> String {
        assert!(
            !self.classic_pk.is_empty(),
            "classic_pk is empty for {}; call generate_keys() before classic_pubkey()",
            self.username
        );
        self.classic_pk.clone()
    }

    /// Return the hybrid base64 public key for this user.
    ///
    /// Returns the value captured during generate_keys(). Panics if generate_keys()
    /// was not called first.
    fn hybrid_pubkey(&self) -> String {
        assert!(
            !self.hybrid_pk.is_empty(),
            "hybrid_pk is empty for {}; call generate_keys() before hybrid_pubkey()",
            self.username
        );
        self.hybrid_pk.clone()
    }
}

// ---------------------------------------------------------------------------
// TEST-04: multi-user migration test
// ---------------------------------------------------------------------------

#[test]
fn e2e_migrate_three_user_repo_all_users_can_render() {
    // Create three users and one shared project directory.
    let mut alice   = UserEnv::new("alice");
    let mut bob     = UserEnv::new("bob");
    let mut charlie = UserEnv::new("charlie");
    let project_dir = TempDir::new().expect("create project dir");
    let project_path = project_dir.path();

    // -----------------------------------------------------------------------
    // Step 1: Generate classic + hybrid keypairs for all three users.
    //         generate_keys() captures and stores each user's hybrid pubkey.
    // -----------------------------------------------------------------------
    alice.generate_keys();
    bob.generate_keys();
    charlie.generate_keys();

    // -----------------------------------------------------------------------
    // Step 2: Init project as alice (creates v1.0 .sss.toml)
    // -----------------------------------------------------------------------
    let out = alice.cmd(project_path)
        .args(["init", "alice"])
        .output()
        .expect("init alice");
    assert!(
        out.status.success(),
        "init failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Confirm version is 1.0
    let config_content = std::fs::read_to_string(project_path.join(".sss.toml")).unwrap();
    assert!(
        config_content.contains("version = \"1.0\""),
        "init must produce v1.0 config; got: {}",
        config_content
    );

    // -----------------------------------------------------------------------
    // Step 3: Add bob and charlie as classic users
    // -----------------------------------------------------------------------
    let bob_classic_pk = bob.classic_pubkey();
    let charlie_classic_pk = charlie.classic_pubkey();

    let out = alice.cmd(project_path)
        .args(["users", "add", "bob", &bob_classic_pk])
        .output()
        .expect("users add bob");
    assert!(
        out.status.success(),
        "users add bob failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let out = alice.cmd(project_path)
        .args(["users", "add", "charlie", &charlie_classic_pk])
        .output()
        .expect("users add charlie");
    assert!(
        out.status.success(),
        "users add charlie failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // -----------------------------------------------------------------------
    // Step 4: Register hybrid public keys for all three users.
    //         hybrid_pubkey() returns the value stored during generate_keys().
    // -----------------------------------------------------------------------
    let alice_hybrid_pk   = alice.hybrid_pubkey();
    let bob_hybrid_pk     = bob.hybrid_pubkey();
    let charlie_hybrid_pk = charlie.hybrid_pubkey();

    for (username, hybrid_pk) in [
        ("alice",   &alice_hybrid_pk),
        ("bob",     &bob_hybrid_pk),
        ("charlie", &charlie_hybrid_pk),
    ] {
        let out = alice.cmd(project_path)
            .args(["users", "add-hybrid-key", username, hybrid_pk.as_str()])
            .output()
            .expect("users add-hybrid-key");
        assert!(
            out.status.success(),
            "add-hybrid-key failed for {}:\nstdout: {}\nstderr: {}",
            username,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // -----------------------------------------------------------------------
    // Step 5: Seal a file with a known secret as alice (v1 repo)
    // -----------------------------------------------------------------------
    let secret_file = project_path.join("secret.txt");
    // Write open-marker form: ⊕{migration_test_secret} (U+2295 is the open marker)
    std::fs::write(&secret_file, "db_pass=\u{2295}{migration_test_secret}").unwrap();

    let out = alice.cmd(project_path)
        .args(["seal", "-x", "secret.txt"])
        .output()
        .expect("seal");
    assert!(
        out.status.success(),
        "seal failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Record the pre-migration file content (MIGRATE-02: must be byte-identical after migrate)
    let sealed_bytes_before = std::fs::read(&secret_file).unwrap();
    let sealed_content_before = String::from_utf8_lossy(&sealed_bytes_before).to_string();
    assert!(
        sealed_content_before.contains("\u{22A0}{"),
        "file must be sealed before migration; content: {}",
        sealed_content_before
    );

    // -----------------------------------------------------------------------
    // Step 6: Run sss migrate as alice
    // -----------------------------------------------------------------------
    let out = alice.cmd(project_path)
        .args(["migrate"])
        .output()
        .expect("migrate");
    assert!(
        out.status.success(),
        "migrate failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // -----------------------------------------------------------------------
    // Step 7: Verify .sss.toml is now version 2.0
    // -----------------------------------------------------------------------
    let config_after = std::fs::read_to_string(project_path.join(".sss.toml")).unwrap();
    assert!(
        config_after.contains("version = \"2.0\""),
        ".sss.toml must be version 2.0 after migration; got: {}",
        config_after
    );

    // -----------------------------------------------------------------------
    // Step 8: Verify sealed file content is BYTE-IDENTICAL (MIGRATE-02)
    // -----------------------------------------------------------------------
    let sealed_bytes_after = std::fs::read(&secret_file).unwrap();
    assert_eq!(
        sealed_bytes_before, sealed_bytes_after,
        "sss migrate must not modify sealed file content (MIGRATE-02)"
    );

    // -----------------------------------------------------------------------
    // Step 9: Each user independently renders the file — byte-identical plaintext
    // -----------------------------------------------------------------------
    for user in [&alice, &bob, &charlie] {
        let out = user.cmd(project_path)
            .args(["render", "secret.txt"])
            .output()
            .expect("render");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{} could not render after migration:\nstdout: {}\nstderr: {}",
            user.username, stdout, stderr
        );
        assert_eq!(
            stdout.trim_end_matches('\n'),
            "db_pass=migration_test_secret",
            "{} render output is not byte-identical to pre-migration plaintext;\
             \nstdout: {}\nstderr: {}",
            user.username, stdout, stderr
        );
    }
}
