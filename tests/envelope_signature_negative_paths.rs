//! Sign-on-write integration tests (Phase 19-02, PQSIG-05).
//!
//! Drives the real sss binary through each mutating CLI verb and asserts the
//! resulting `.sss.toml` carries a valid `[envelope.sig]` table. All four call
//! sites must produce a freshly-signed v2 envelope on disk (D-14, D-17):
//!   1. `sss init --crypto hybrid`      (sign_on_write_init)
//!   2. `sss user add <bob>`            (sign_on_write_user_add)
//!   3. `sss user remove <bob>`         (sign_on_write_user_remove)
//!   4. `sss migrate --to hybrid`       (sign_on_write_migrate)
//!
//! Each test runs in an isolated temp directory with its own HOME (so no test
//! bleeds keystore state into another). Uses the subprocess pattern from
//! tests/migrate_e2e.rs — NOT sss::cli::run (that symbol does not exist in
//! the library API).

#![cfg(feature = "hybrid")]

use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

// ---------------------------------------------------------------------------
// Isolated user environment — each test gets its own HOME so keystores never
// bleed between runs. Mirrors the UserEnv helper in tests/migrate_e2e.rs.
// ---------------------------------------------------------------------------

struct UserEnv {
    home_dir: TempDir,
}

impl UserEnv {
    fn new() -> Self {
        Self {
            home_dir: TempDir::new().expect("create temp home"),
        }
    }

    /// Build a Command for the sss binary running in `project_dir`, with an
    /// isolated HOME and all interactive prompts suppressed.
    fn cmd(&self, project_dir: &Path) -> Command {
        let mut cmd = Command::new(sss_bin());
        cmd.env("HOME", self.home_dir.path())
            .env("XDG_CONFIG_HOME", self.home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "alice")
            .current_dir(project_dir)
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse `.sss.toml` from `dir` and return the raw TOML string + parsed config.
fn load_toml(dir: &Path) -> (String, sss::project::ProjectConfig) {
    let toml_str = std::fs::read_to_string(dir.join(".sss.toml"))
        .expect("read .sss.toml");
    let cfg: sss::project::ProjectConfig = toml::from_str(&toml_str)
        .expect("parse .sss.toml");
    (toml_str, cfg)
}

/// Assert envelope sig is present and non-empty; return the sig fields.
fn assert_sig_present(cfg: &sss::project::ProjectConfig, context: &str) {
    let sig = cfg
        .envelope
        .as_ref()
        .and_then(|e| e.sig.as_ref())
        .unwrap_or_else(|| panic!("{context}: [envelope.sig] table must be present"));
    assert!(
        !sig.ed448.is_empty(),
        "{context}: Ed448 leg must be non-empty"
    );
    assert!(
        !sig.mldsa65.is_empty(),
        "{context}: ML-DSA-65 leg must be non-empty"
    );
}

// ---------------------------------------------------------------------------
// Task 19-02-01 — sss init --crypto hybrid produces a signed envelope
// ---------------------------------------------------------------------------

#[test]
fn sign_on_write_init() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate both classic and hybrid keypairs in one call (--suite both).
    // Sequential classic-then-hybrid fails under SSS_NONINTERACTIVE because the
    // hybrid generator re-checks for a classic keypair via get_current_keypair(None)
    // which can fail in non-interactive mode even after a successful classic generate.
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(
        out.status.success(),
        "dual-suite keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // sss init --crypto hybrid alice
    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init");
    assert!(
        out.status.success(),
        "sss init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Assertions
    let (toml_str, cfg) = load_toml(project_dir.path());
    assert!(
        toml_str.contains("[envelope.sig]"),
        "init must produce [envelope.sig]; got:\n{toml_str}"
    );
    assert_eq!(cfg.format_version, 2, "init must set format_version = 2");
    assert_sig_present(&cfg, "sign_on_write_init");
    assert!(
        cfg.users["alice"].sig_ed448_public.is_some(),
        "alice's sig_ed448_public must be populated"
    );
    assert!(
        cfg.users["alice"].sig_mldsa65_public.is_some(),
        "alice's sig_mldsa65_public must be populated"
    );

    // Envelope must verify via the try-all-users path.
    sss::envelope_sig::verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("sign_on_write_init: envelope must verify");
}

// ---------------------------------------------------------------------------
// Task 19-02-02 — sss user add re-signs the envelope
// ---------------------------------------------------------------------------

#[test]
fn sign_on_write_user_add() {
    let project_dir = TempDir::new().expect("project tempdir");
    let alice_env = UserEnv::new();
    let bob_env = UserEnv::new();

    // Alice: generate both suites in one call (avoids SSS_NONINTERACTIVE issue
    // with sequential classic-then-hybrid keygen).
    let out = alice_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("alice dual-suite keygen");
    assert!(out.status.success(), "alice keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Bob: generate both suites in one call.
    let out = bob_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("bob dual-suite keygen");
    assert!(out.status.success(), "bob keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Alice inits the hybrid project.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init");
    assert!(out.status.success(), "sss init failed: {}", String::from_utf8_lossy(&out.stderr));

    // Alice adds Bob using his classic pubkey (hybrid project, classic public key length
    // will be rejected — need to use bob's hybrid pubkey).
    // First get Bob's hybrid pubkey.
    let out = bob_env
        .cmd(project_dir.path())
        .args(["keys", "pubkey"])
        .output()
        .expect("bob keys pubkey");
    assert!(out.status.success(), "bob keys pubkey failed: {}", String::from_utf8_lossy(&out.stderr));
    let bob_hybrid_pk = String::from_utf8_lossy(&out.stdout).trim().to_string();

    // Alice adds Bob with his hybrid pubkey.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["user", "add", "bob", &bob_hybrid_pk])
        .output()
        .expect("sss user add bob");
    assert!(
        out.status.success(),
        "sss user add bob failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Assertions
    let (_toml_str, cfg) = load_toml(project_dir.path());
    assert!(
        cfg.users.contains_key("bob"),
        "bob must be present after user add"
    );
    assert_sig_present(&cfg, "sign_on_write_user_add");

    // Envelope must verify (alice's sig pubkeys are in the config).
    sss::envelope_sig::verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("sign_on_write_user_add: envelope must verify");

}

// ---------------------------------------------------------------------------
// Task 19-02-03 — sss user remove re-signs after RotationManager finishes
// ---------------------------------------------------------------------------

#[test]
fn sign_on_write_user_remove() {
    let project_dir = TempDir::new().expect("project tempdir");
    let alice_env = UserEnv::new();
    let bob_env = UserEnv::new();

    // Alice + Bob: generate both suites in one call each.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("alice dual-suite keygen");
    assert!(out.status.success(), "alice keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = bob_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("bob dual-suite keygen");
    assert!(out.status.success(), "bob keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Alice inits the hybrid project.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init");
    assert!(out.status.success(), "sss init failed: {}", String::from_utf8_lossy(&out.stderr));

    // Get Bob's hybrid pubkey and add him.
    let out = bob_env
        .cmd(project_dir.path())
        .args(["keys", "pubkey"])
        .output()
        .expect("bob keys pubkey");
    assert!(out.status.success(), "bob keys pubkey failed: {}", String::from_utf8_lossy(&out.stderr));
    let bob_hybrid_pk = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let out = alice_env
        .cmd(project_dir.path())
        .args(["user", "add", "bob", &bob_hybrid_pk])
        .output()
        .expect("sss user add bob");
    assert!(out.status.success(), "sss user add bob failed: {}", String::from_utf8_lossy(&out.stderr));

    // Alice removes Bob (triggers RotationManager + re-sign).
    let out = alice_env
        .cmd(project_dir.path())
        .args(["user", "remove", "bob"])
        .output()
        .expect("sss user remove bob");
    assert!(
        out.status.success(),
        "sss user remove bob failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Assertions
    let (_toml_str, cfg) = load_toml(project_dir.path());
    assert!(
        !cfg.users.contains_key("bob"),
        "bob must be removed after user remove"
    );
    assert_sig_present(&cfg, "sign_on_write_user_remove");

    // Post-rotation envelope must verify.
    sss::envelope_sig::verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("sign_on_write_user_remove: envelope must verify");
}

// ---------------------------------------------------------------------------
// Task 19-02-04 — sss migrate produces a signed v2 envelope
// ---------------------------------------------------------------------------

#[test]
fn sign_on_write_migrate() {
    let project_dir = TempDir::new().expect("project tempdir");
    let alice_env = UserEnv::new();

    // Alice: generate classic keypair first.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "classic", "--no-password"])
        .output()
        .expect("alice classic keygen");
    assert!(out.status.success(), "classic keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Init in classic mode (no signature expected initially).
    let out = alice_env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "classic", "alice"])
        .output()
        .expect("sss init classic");
    assert!(out.status.success(), "sss init classic failed: {}", String::from_utf8_lossy(&out.stderr));

    // Alice generates hybrid keypair (needed for migration).
    let out = alice_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "hybrid", "--no-password"])
        .output()
        .expect("alice hybrid keygen");
    assert!(out.status.success(), "hybrid keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Capture Alice's hybrid pubkey and register it (needed for sss migrate).
    let out = alice_env
        .cmd(project_dir.path())
        .args(["keys", "pubkey"])
        .output()
        .expect("alice keys pubkey");
    assert!(out.status.success(), "keys pubkey failed: {}", String::from_utf8_lossy(&out.stderr));
    let alice_hybrid_pk = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let out = alice_env
        .cmd(project_dir.path())
        .args(["user", "add-hybrid-key", "alice", &alice_hybrid_pk])
        .output()
        .expect("add-hybrid-key");
    assert!(out.status.success(), "add-hybrid-key failed: {}", String::from_utf8_lossy(&out.stderr));

    // Migrate to hybrid — must produce a v2 signed envelope.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["migrate"])
        .output()
        .expect("sss migrate");
    assert!(
        out.status.success(),
        "sss migrate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Assertions
    let (_toml_str, cfg) = load_toml(project_dir.path());
    assert_eq!(cfg.format_version, 2, "migrate must set format_version = 2");
    assert_sig_present(&cfg, "sign_on_write_migrate");

    // Migrated envelope must verify.
    sss::envelope_sig::verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("sign_on_write_migrate: envelope must verify");
}
