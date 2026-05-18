// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Sign-on-write integration tests (Phase 19-02, PQSIG-05).
//!
//! Drives the real sss binary through each mutating CLI verb and asserts the
//! resulting `.sss.toml` carries a valid `[envelope.sig]` table. All four call
//! sites must produce a freshly-signed v2 envelope on disk (D-14, D-17):
//!   1. `sss init --crypto hybrid`      (`sign_on_write_init`)
//!   2. `sss user add <bob>`            (`sign_on_write_user_add`)
//!   3. `sss user remove <bob>`         (`sign_on_write_user_remove`)
//!   4. `sss migrate --to hybrid`       (`sign_on_write_migrate`)
//!
//! Each test runs in an isolated temp directory with its own HOME (so no test
//! bleeds keystore state into another). Uses the subprocess pattern from
//! `tests/migrate_e2e.rs` — NOT `sss::cli::run` (that symbol does not exist in
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
/// (the production path with `format_version` dispatch + signature verification).
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

/// Drives `sss init --crypto classic` (produces `format_version=1`, no sig) then
/// runs `sss envelope upgrade-sig` and asserts:
/// 1. `format_version` promoted to 2.
/// 2. [envelope.sig] table populated with non-empty Ed448 + ML-DSA-65 legs.
/// 3. alice's `sig_ed448_public` is set.
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

/// Init with --crypto hybrid (`format_version=2`, signed). Snapshot bytes. Re-run
/// upgrade-sig. Assert:
/// 1. Exit code 0 (clean).
/// 2. On-disk .sss.toml bytes unchanged (no re-sign, no whitespace shuffle).
/// This validates the "no-op skip" idempotency semantic chosen in envelope.rs:
/// `format_version` >= 2 → print "already signed" and return Ok without file touch.
/// mtime is preserved because we never call `write_atomic` on already-signed envelopes.
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
// Task 19-05-NEG-01 — Tamper Ed448 leg → load_from_file errors naming "Ed448" (T-19-06)
// ---------------------------------------------------------------------------

/// Build a freshly-signed v2 hybrid envelope, mutate one byte of the Ed448 sig
/// leg (which is a base64 `String` — must decode-mutate-encode, NOT index directly),
/// write back via raw TOML bypass (no re-signing), then assert `load_from_file`
/// returns an error whose text contains "Ed448" (D-20 / T-19-06).
///
/// Uses subprocess only for setup (keygen + init). The tamper and verify-fail
/// steps call the library directly so they do not go through the process boundary.
#[test]
fn neg_01_ed448_tamper() {
    use base64::{Engine as _, prelude::BASE64_STANDARD};

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

    // Init hybrid — produces a signed v2 envelope.
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

    // Read the TOML, mutate the Ed448 sig leg, write back (bypasses sign-on-write).
    let toml_path = project_dir.path().join(".sss.toml");
    let toml_str = std::fs::read_to_string(&toml_path).expect("read .sss.toml");
    let mut cfg: sss::project::ProjectConfig = toml::from_str(&toml_str).expect("parse .sss.toml");

    {
        let sig = cfg
            .envelope
            .as_mut()
            .and_then(|e| e.sig.as_mut())
            .expect("envelope.sig must be present after hybrid init");
        // Decode base64 → mutate byte 0 → re-encode. Direct indexing of the
        // String is WRONG (Ed448 sig is base64, not raw bytes). Pitfall 9.
        let mut bytes = BASE64_STANDARD
            .decode(sig.ed448.as_bytes())
            .expect("Ed448 sig must be valid base64");
        bytes[0] ^= 0x01;
        sig.ed448 = BASE64_STANDARD.encode(&bytes);
    }

    // Serialise and write back without calling sign_envelope (raw bypass).
    let mutated = toml::to_string(&cfg).expect("re-serialise mutated cfg");
    std::fs::write(&toml_path, mutated).expect("write mutated .sss.toml");

    // load_from_file must now fail with the Ed448 leg named in the error (D-20).
    let err = sss::project::ProjectConfig::load_from_file(&toml_path)
        .expect_err("tampered Ed448 leg must fail verification");
    let s = format!("{err:#}");
    assert!(
        s.contains("Ed448"),
        "error must name the failing Ed448 leg; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// Task 19-05-NEG-02 — Tamper ML-DSA-65 leg → load_from_file errors naming "ML-DSA-65" (T-19-06)
// ---------------------------------------------------------------------------

/// Mirror of NEG-01 for the ML-DSA-65 leg. Ed448 is untouched, so it passes;
/// only the ML-DSA-65 decode-mutate-encode tamper should trigger the failure.
/// The verifier in `envelope_sig.rs` checks Ed448 before ML-DSA-65 (D-05); with
/// Ed448 clean, the ML-DSA-65 failure surfaces. (Pitfall 3.)
#[test]
fn neg_02_mldsa65_tamper() {
    use base64::{Engine as _, prelude::BASE64_STANDARD};

    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init hybrid");
    assert!(out.status.success(), "sss init hybrid failed: {}", String::from_utf8_lossy(&out.stderr));

    let toml_path = project_dir.path().join(".sss.toml");
    let toml_str = std::fs::read_to_string(&toml_path).expect("read .sss.toml");
    let mut cfg: sss::project::ProjectConfig = toml::from_str(&toml_str).expect("parse .sss.toml");

    {
        let sig = cfg
            .envelope
            .as_mut()
            .and_then(|e| e.sig.as_mut())
            .expect("envelope.sig must be present after hybrid init");
        // Mutate the ML-DSA-65 leg; leave Ed448 untouched.
        let mut bytes = BASE64_STANDARD
            .decode(sig.mldsa65.as_bytes())
            .expect("ML-DSA-65 sig must be valid base64");
        bytes[0] ^= 0x01;
        sig.mldsa65 = BASE64_STANDARD.encode(&bytes);
    }

    let mutated = toml::to_string(&cfg).expect("re-serialise mutated cfg");
    std::fs::write(&toml_path, mutated).expect("write mutated .sss.toml");

    let err = sss::project::ProjectConfig::load_from_file(&toml_path)
        .expect_err("tampered ML-DSA-65 leg must fail verification");
    let s = format!("{err:#}");
    assert!(
        s.contains("ML-DSA-65") || s.contains("ML-DSA"),
        "error must name the failing ML-DSA-65 leg; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// Task 19-05-NEG-03 — Tamper signed payload (per-user sealed_key) → verify fails (T-19-07)
// ---------------------------------------------------------------------------

/// Mutate the **payload** (a field inside the canonical signed bytes) without
/// touching either signature leg. `sealed_key` is base64 String — must
/// decode-mutate-encode (Pitfall 9). `cfg.sealed_key` does NOT exist at the
/// top level; sealed material lives per-user (Pitfall 10).
#[test]
fn neg_03_payload_tamper() {
    use base64::{Engine as _, prelude::BASE64_STANDARD};

    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init hybrid");
    assert!(out.status.success(), "sss init hybrid failed: {}", String::from_utf8_lossy(&out.stderr));

    let toml_path = project_dir.path().join(".sss.toml");
    let toml_str = std::fs::read_to_string(&toml_path).expect("read .sss.toml");
    let mut cfg: sss::project::ProjectConfig = toml::from_str(&toml_str).expect("parse .sss.toml");

    // Tamper the payload: flip one byte of the first user's sealed_key.
    // The sig table is NOT touched — the tamper must be detected via payload mismatch.
    {
        let user = cfg
            .users
            .values_mut()
            .next()
            .expect("at least one user must exist after init");
        let mut bytes = BASE64_STANDARD
            .decode(user.sealed_key.as_bytes())
            .expect("user.sealed_key must be valid base64");
        bytes[0] ^= 0x01;
        user.sealed_key = BASE64_STANDARD.encode(&bytes);
    }

    let mutated = toml::to_string(&cfg).expect("re-serialise mutated cfg");
    std::fs::write(&toml_path, mutated).expect("write mutated .sss.toml");

    let err = sss::project::ProjectConfig::load_from_file(&toml_path)
        .expect_err("payload tamper must fail verification even with sig table intact");
    let s = format!("{err:#}");
    // The verifier must detect the payload mismatch; error should mention verification.
    assert!(
        s.contains("verification") || s.contains("verify") || s.contains("envelope"),
        "payload tamper must produce a verification error; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// Task 19-05-NEG-04 — Unsigned v2 envelope → byte-exact D-10 actionable string (T-19-04, PQSIG-06)
// ---------------------------------------------------------------------------

/// Build a classic (v1) unsigned envelope then attempt `sss users add bob <key>`.
/// `require_signed` fires because `format_version=1`; error propagates to stderr.
/// Assert stderr contains the byte-exact D-10 string (PQSIG-06).
///
/// The D-10 expected text uses the ABSOLUTE path to `.sss.toml` because
/// `get_project_config_path()` resolves from the subprocess cwd (the temp project dir)
/// and returns `<project_dir>/.sss.toml` — an absolute path. The relative `.sss.toml`
/// form would only appear if a caller passed a relative path directly; `get_project_config_path`
/// never does that when the cwd is an absolute temp dir.
///
/// A dummy 32-byte classic public key (base64) is supplied so the key-decode step
/// succeeds and `require_signed` is reached (Pitfall 2 of execution plan 19-05).
#[test]
fn neg_04_unsigned_v2_exact_string() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate both suites (classic + hybrid sig keypairs must be present in keystore
    // for the subprocess's require_signed path to work).
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Init in classic mode → format_version=1, no [envelope.sig].
    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "classic", "alice"])
        .output()
        .expect("sss init classic");
    assert!(out.status.success(), "sss init classic failed: {}", String::from_utf8_lossy(&out.stderr));

    // Verify pre-condition: format_version=1.
    let (_, pre_cfg) = load_toml(project_dir.path());
    assert_eq!(pre_cfg.format_version, 1, "classic init must produce format_version=1");

    // Attempt `sss users add bob <dummy-32-byte-classic-key>`. The classic key
    // is 32 zero bytes base64-encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    // (43 A chars + 1 padding '=' = 44 chars total = 32 bytes).
    // Key decode succeeds; require_signed fires before any keystore access.
    let dummy_classic_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let out = env
        .cmd(project_dir.path())
        .args(["users", "add", "bob", dummy_classic_key])
        .output()
        .expect("sss users add bob");

    // The command MUST fail (require_signed returns Err).
    assert!(
        !out.status.success(),
        "users add on unsigned envelope must fail; got exit 0"
    );

    // The D-10 error propagates through the process boundary as stderr text.
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Build the byte-exact expected D-10 string.
    // get_project_config_path() resolves to the absolute path of `.sss.toml`
    // inside the subprocess's cwd (project_dir).
    let envelope_path = project_dir.path().join(".sss.toml");
    let expected = format!(
        "{}: unsigned envelope (format_version=1); run `sss envelope upgrade-sig` to sign in place",
        envelope_path.display()
    );

    // The stderr may contain "Error: " prefix and/or extra context lines from anyhow.
    // Find the line that contains the D-10 text and assert it matches exactly.
    let matching_line = stderr
        .lines()
        .find(|line| line.contains("unsigned envelope"));
    let matching_line = matching_line.unwrap_or_else(|| {
        panic!(
            "no line in stderr contains 'unsigned envelope'; got:\n{stderr}\nexpected line: {expected}"
        )
    });

    // Strip a leading "Error: " prefix if the CLI wraps the error.
    let trimmed = matching_line
        .trim_start_matches("Error: ")
        .trim();

    assert_eq!(
        trimmed,
        expected,
        "D-10 error string must match byte-for-byte;\n  expected: {expected}\n  got:      {trimmed}"
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
        .and_then(|l| l.split_once(':').map(|x| x.1))
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
