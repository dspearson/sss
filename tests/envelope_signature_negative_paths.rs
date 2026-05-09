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
        .args(["users", "add", "bob", &bob_hybrid_pk])
        .output()
        .expect("sss users add bob");
    assert!(
        out.status.success(),
        "sss users add bob failed: {}",
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
        .args(["users", "add", "bob", &bob_hybrid_pk])
        .output()
        .expect("sss users add bob");
    assert!(out.status.success(), "sss users add bob failed: {}", String::from_utf8_lossy(&out.stderr));

    // Alice removes Bob (triggers RotationManager + re-sign).
    let out = alice_env
        .cmd(project_dir.path())
        .args(["users", "remove", "bob"])
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
// Task 19-03-01 — verify_passes_round_trip: production loader verifies fresh envelope
// ---------------------------------------------------------------------------

/// Drives `sss init --crypto hybrid` then reloads via `ProjectConfig::load_from_file`
/// (the production path with format_version dispatch + signature verification).
/// Verifies that a freshly-signed v2 envelope verifies cleanly on read-back (T-19-05).
#[test]
fn verify_passes_round_trip() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate both suites in one call.
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Init hybrid project — sign-on-write produces format_version=2.
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

    // Read back through the production loader (verify-on-read MUST pass).
    let toml_path = project_dir.path().join(".sss.toml");
    let cfg = sss::project::ProjectConfig::load_from_file(&toml_path)
        .expect("freshly-signed envelope must verify");
    assert_eq!(cfg.format_version, 2, "v2 init must set format_version=2");
    assert!(cfg.envelope.is_some(), "v2 envelope must carry [envelope.sig]");
}

// ---------------------------------------------------------------------------
// Task 19-04-01 — upgrade_sig_round_trip: v1 classic envelope → signed v2 (PQSIG-06)
// ---------------------------------------------------------------------------

/// Drives `sss init --crypto classic` (produces format_version=1, no sig) then
/// runs `sss envelope upgrade-sig` and asserts:
/// 1. format_version promoted to 2.
/// 2. [envelope.sig] table populated with non-empty Ed448 + ML-DSA-65 legs.
/// 3. alice's sig_ed448_public is set.
/// 4. The upgraded envelope verifies via the production loader (T-19-04).
#[test]
fn upgrade_sig_round_trip() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate both suites so the keystore has sig keypairs available.
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Init in classic mode → format_version=1, no [envelope.sig].
    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "classic", "alice"])
        .output()
        .expect("sss init classic");
    assert!(
        out.status.success(),
        "sss init classic failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify pre-condition: format_version=1, no sig.
    let (pre_str, pre_cfg) = load_toml(project_dir.path());
    assert_eq!(pre_cfg.format_version, 1, "init --crypto classic must produce format_version=1");
    assert!(
        pre_cfg.envelope.as_ref().and_then(|e| e.sig.as_ref()).is_none(),
        "classic init must produce no [envelope.sig]; got:\n{pre_str}"
    );

    // Run upgrade-sig.
    let out = env
        .cmd(project_dir.path())
        .args(["envelope", "upgrade-sig"])
        .output()
        .expect("sss envelope upgrade-sig");
    assert!(
        out.status.success(),
        "upgrade-sig failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Assert post-conditions.
    let (_post_str, post_cfg) = load_toml(project_dir.path());
    assert_eq!(post_cfg.format_version, 2, "upgrade-sig must promote to format_version=2");
    assert_sig_present(&post_cfg, "upgrade_sig_round_trip");
    assert!(
        post_cfg.users["alice"].sig_ed448_public.is_some(),
        "upgrade-sig must populate alice's sig_ed448_public"
    );

    // Verify-on-read must succeed against the upgraded envelope.
    let toml_path = project_dir.path().join(".sss.toml");
    sss::project::ProjectConfig::load_from_file(&toml_path)
        .expect("upgraded envelope must verify via production loader");
}

// ---------------------------------------------------------------------------
// Task 19-04-02 — upgrade_sig_idempotent: re-running on a v2 envelope is a no-op
// ---------------------------------------------------------------------------

/// Init with --crypto hybrid (format_version=2, signed). Snapshot bytes. Re-run
/// upgrade-sig. Assert:
/// 1. Exit code 0 (clean).
/// 2. On-disk .sss.toml bytes unchanged (no re-sign, no whitespace shuffle).
/// This validates the "no-op skip" idempotency semantic chosen in envelope.rs:
/// format_version >= 2 → print "already signed" and return Ok without file touch.
/// mtime is preserved because we never call write_atomic on already-signed envelopes.
#[test]
fn upgrade_sig_idempotent() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate both suites.
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Init with hybrid → produces format_version=2 signed envelope directly.
    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init hybrid");
    assert!(
        out.status.success(),
        "sss init hybrid failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Snapshot the signed envelope bytes.
    let before = std::fs::read(project_dir.path().join(".sss.toml"))
        .expect("read .sss.toml before re-run");

    // Re-run upgrade-sig on an already-signed envelope — must be a no-op.
    let out = env
        .cmd(project_dir.path())
        .args(["envelope", "upgrade-sig"])
        .output()
        .expect("sss envelope upgrade-sig (re-run)");
    assert!(
        out.status.success(),
        "upgrade-sig re-run must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Byte-exact check: file must not have been rewritten.
    let after = std::fs::read(project_dir.path().join(".sss.toml"))
        .expect("read .sss.toml after re-run");
    assert_eq!(
        before, after,
        "upgrade-sig on an already-signed envelope must not modify the file"
    );

    // Stdout must contain "already signed".
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("already signed"),
        "upgrade-sig re-run must print 'already signed'; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Task 19-02-04 — sss migrate produces a signed v2 envelope
// ---------------------------------------------------------------------------

#[test]
fn sign_on_write_migrate() {
    let project_dir = TempDir::new().expect("project tempdir");
    let alice_env = UserEnv::new();

    // Alice: generate both classic and hybrid keypairs atomically (--suite both).
    // --suite classic produces an unsigned v1 file that init refuses to load;
    // --suite both produces a signed v2 dual-keypair file that init accepts.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("alice both keygen");
    assert!(out.status.success(), "both keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Extract the hybrid public key from keygen stdout (line: "Hybrid public key:  <b64>").
    // We cannot use `keys pubkey` here because we are in a v1 project (classic mode),
    // which causes `keys pubkey` to return the classic key rather than the hybrid one.
    let keygen_stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let alice_hybrid_pk = keygen_stdout
        .lines()
        .find(|l| l.contains("Hybrid public key:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(str::trim)
        .expect("keygen --suite both must print 'Hybrid public key: ...'")
        .to_string();

    // Init in classic mode (no signature expected initially).
    // The dual keypair created above satisfies init's requirement for a classic key.
    let out = alice_env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "classic", "alice"])
        .output()
        .expect("sss init classic");
    assert!(out.status.success(), "sss init classic failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = alice_env
        .cmd(project_dir.path())
        .args(["users", "add-hybrid-key", "alice", &alice_hybrid_pk])
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
