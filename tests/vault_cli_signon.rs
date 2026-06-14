// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Sign-on-write CLI integration tests for vault commands (Phase 46, plan 46-03).
//!
//! Proves VCFG-04 and VCLI-04:
//!   - `sss project vault set-address` re-signs to `format_version=3`
//!   - `sss project vault add-binding` + `set-auth` re-sign to v3 on each write
//!   - `sss project vault set-address <non-https>` is rejected before any write
//!   - `sss envelope upgrade-sig` on a no-vault v1 repo promotes to `format_version=2`
//!   - `sss envelope upgrade-sig` on a vault repo promotes to `format_version=3`
//!   - `sss envelope upgrade-sig` is idempotent on an already-correct-version repo
//!   - `sss envelope upgrade-sig` refuses a v3→v2 downgrade (vault removed, target=2
//!     but current=3) with a non-zero exit and actionable stderr
//!
//! Subprocess harness: isolated HOME per test, `SSS_NONINTERACTIVE=1`, `SSS_PASSPHRASE=""`,
//! `NO_COLOR=1`, `--kdf-level interactive`. Mirrors `envelope_signature_negative_paths.rs`.

#![cfg(feature = "hybrid")]

use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Binary under test
// ---------------------------------------------------------------------------

fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

// ---------------------------------------------------------------------------
// Isolated user environment — each test gets its own HOME so keystores never
// bleed between runs.
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
    let toml_str = fs::read_to_string(dir.join(".sss.toml")).expect("read .sss.toml");
    let cfg: sss::project::ProjectConfig =
        toml::from_str(&toml_str).expect("parse .sss.toml as ProjectConfig");
    (toml_str, cfg)
}

/// Assert `[envelope.sig]` table is present with non-empty Ed448 + ML-DSA-65 legs.
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

/// Init a hybrid project (keygen both suites + sss init --crypto hybrid alice).
fn init_hybrid_project(env: &UserEnv, project_dir: &Path) {
    let out = env
        .cmd(project_dir)
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("dual-suite keygen");
    assert!(
        out.status.success(),
        "dual-suite keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = env
        .cmd(project_dir)
        .args(["init", "--crypto", "hybrid", "alice"])
        .output()
        .expect("sss init");
    assert!(
        out.status.success(),
        "sss init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Test: sss project vault set-address writes + re-signs to format_version=3
// ---------------------------------------------------------------------------

#[test]
fn vault_set_address_signs_to_v3() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();
    init_hybrid_project(&env, project_dir.path());

    // Confirm the init produced format_version=2 (no vault yet).
    let (_, cfg_before) = load_toml(project_dir.path());
    assert_eq!(
        cfg_before.format_version, 2,
        "init should produce format_version=2"
    );
    assert!(
        cfg_before.vault.is_none(),
        "no vault table should exist after plain init"
    );

    // Run set-address.
    let out = env
        .cmd(project_dir.path())
        .args(["project", "vault", "set-address", "https://v.example:8200"])
        .output()
        .expect("sss project vault set-address");
    assert!(
        out.status.success(),
        "set-address failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Reload and verify.
    let (toml_str, cfg) = load_toml(project_dir.path());
    assert_eq!(
        cfg.format_version, 3,
        "set-address must promote to format_version=3; got toml:\n{toml_str}"
    );
    let vault = cfg.vault.as_ref().expect("vault table must exist after set-address");
    assert_eq!(
        vault.address.as_deref(),
        Some("https://v.example:8200"),
        "vault.address must be set to the provided value"
    );
    assert_sig_present(&cfg, "vault_set_address_signs_to_v3");

    // The envelope must verify cleanly under v3.
    sss::envelope_sig::verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("envelope must verify under v3 after set-address");
}

// ---------------------------------------------------------------------------
// Test: add-binding and set-auth each re-sign to v3; file stays valid after each
// ---------------------------------------------------------------------------

#[test]
fn vault_add_binding_and_set_auth_re_sign() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();
    init_hybrid_project(&env, project_dir.path());

    // set-address first so we have a vault table.
    let out = env
        .cmd(project_dir.path())
        .args(["project", "vault", "set-address", "https://vault.example.com"])
        .output()
        .expect("set-address");
    assert!(
        out.status.success(),
        "set-address failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // add-binding.
    let out = env
        .cmd(project_dir.path())
        .args([
            "project",
            "vault",
            "add-binding",
            "kv",
            "--mount",
            "secret",
            "--default-field",
            "value",
        ])
        .output()
        .expect("add-binding");
    assert!(
        out.status.success(),
        "add-binding failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify after add-binding.
    let (_, cfg_after_binding) = load_toml(project_dir.path());
    assert_eq!(cfg_after_binding.format_version, 3, "add-binding must keep format_version=3");
    assert_sig_present(&cfg_after_binding, "vault_add_binding");
    let vault_b = cfg_after_binding.vault.as_ref().expect("vault table missing after add-binding");
    assert!(
        vault_b.bindings.contains_key("kv"),
        "binding 'kv' must be present after add-binding"
    );
    sss::envelope_sig::verify_envelope_signature(&cfg_after_binding, Path::new(".sss.toml"))
        .expect("envelope must verify after add-binding");

    // set-auth.
    let out = env
        .cmd(project_dir.path())
        .args([
            "project",
            "vault",
            "set-auth",
            "--method",
            "approle",
            "--role-id",
            "rid",
            "--secret-id-secret",
            "sid",
        ])
        .output()
        .expect("set-auth");
    assert!(
        out.status.success(),
        "set-auth failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify after set-auth.
    let (_, cfg_after_auth) = load_toml(project_dir.path());
    assert_eq!(cfg_after_auth.format_version, 3, "set-auth must keep format_version=3");
    assert_sig_present(&cfg_after_auth, "vault_set_auth");
    let auth = cfg_after_auth
        .vault
        .as_ref()
        .and_then(|v| v.auth.as_ref())
        .expect("vault.auth must exist after set-auth");
    assert_eq!(auth.method.as_deref(), Some("approle"), "vault.auth.method must be 'approle'");
    assert_eq!(auth.role_id.as_deref(), Some("rid"), "vault.auth.role_id must be 'rid'");
    sss::envelope_sig::verify_envelope_signature(&cfg_after_auth, Path::new(".sss.toml"))
        .expect("envelope must verify after set-auth");
}

// ---------------------------------------------------------------------------
// Test: set-address with non-https URL is rejected; exit non-zero; no write
// ---------------------------------------------------------------------------

#[test]
fn vault_set_address_rejects_http_scheme() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();
    init_hybrid_project(&env, project_dir.path());

    // Capture mtime before the rejected attempt.
    let mtime_before = fs::metadata(project_dir.path().join(".sss.toml"))
        .expect("stat .sss.toml")
        .modified()
        .expect("mtime");

    let out = env
        .cmd(project_dir.path())
        .args(["project", "vault", "set-address", "http://insecure.example.com"])
        .output()
        .expect("set-address http");

    // Must be non-zero exit.
    assert!(
        !out.status.success(),
        "set-address with http:// must fail; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Stderr must name the field `address` (T-39-04: field-named only, no URL echoed).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("address"),
        "stderr must name the 'address' field; got: {stderr}"
    );

    // The insecure URL itself must NOT appear in stderr (T-39-04).
    assert!(
        !stderr.contains("http://insecure.example.com"),
        "stderr must NOT echo the URL value; got: {stderr}"
    );

    // File must be unchanged (mtime not modified).
    let mtime_after = fs::metadata(project_dir.path().join(".sss.toml"))
        .expect("stat .sss.toml after")
        .modified()
        .expect("mtime after");
    assert_eq!(
        mtime_before, mtime_after,
        "file must be unchanged after a rejected set-address"
    );
}

// ---------------------------------------------------------------------------
// Test: upgrade-sig on a no-vault v1 repo promotes to format_version=2
// ---------------------------------------------------------------------------

#[test]
fn upgrade_sig_no_vault_promotes_to_v2() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate keys.
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Init WITHOUT --crypto hybrid so we get a format_version=1 (classic unsigned) repo.
    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "classic", "alice"])
        .output()
        .expect("sss init classic");
    assert!(
        out.status.success(),
        "init --crypto classic failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Confirm format_version=1.
    let (_, cfg_before) = load_toml(project_dir.path());
    assert_eq!(
        cfg_before.format_version, 1,
        "classic init must produce format_version=1"
    );
    assert!(cfg_before.vault.is_none(), "no vault on classic init");

    // Run upgrade-sig.
    let out = env
        .cmd(project_dir.path())
        .args(["envelope", "upgrade-sig"])
        .output()
        .expect("envelope upgrade-sig");
    assert!(
        out.status.success(),
        "upgrade-sig failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Must promote to format_version=2 (no vault present).
    let (toml_str, cfg) = load_toml(project_dir.path());
    assert_eq!(
        cfg.format_version, 2,
        "upgrade-sig on no-vault repo must produce format_version=2; got:\n{toml_str}"
    );
    assert_sig_present(&cfg, "upgrade_sig_no_vault_promotes_to_v2");
    // A no-vault upgrade-sig produces a format_version=2 envelope, signed under the v2
    // context — it MUST verify under the v2 arm (verify_envelope_signature_v2), matching
    // the production loader's `2 =>` dispatch. (Verifying under the v3 arm would fail.)
    sss::envelope_sig::verify_envelope_signature_v2(&cfg, Path::new(".sss.toml"))
        .expect("fv=2 envelope must verify under the v2 context after upgrade-sig");
}

// ---------------------------------------------------------------------------
// Test: upgrade-sig on a vault repo promotes to format_version=3
// ---------------------------------------------------------------------------

#[test]
fn upgrade_sig_with_vault_promotes_to_v3() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();

    // Generate keys.
    let out = env
        .cmd(project_dir.path())
        .args(["keys", "generate", "--suite", "both", "--no-password"])
        .output()
        .expect("keygen");
    assert!(out.status.success(), "keygen failed: {}", String::from_utf8_lossy(&out.stderr));

    // Classic init → format_version=1.
    let out = env
        .cmd(project_dir.path())
        .args(["init", "--crypto", "classic", "alice"])
        .output()
        .expect("sss init classic");
    assert!(out.status.success(), "init classic failed: {}", String::from_utf8_lossy(&out.stderr));

    // Manually inject a [vault] table into .sss.toml.
    let config_path = project_dir.path().join(".sss.toml");
    let mut toml_content = fs::read_to_string(&config_path).expect("read .sss.toml");
    toml_content.push_str("\n[vault]\naddress = \"https://injected.example.com\"\n");
    fs::write(&config_path, &toml_content).expect("write .sss.toml with vault");

    // Confirm format_version=1 with vault.
    let (_, cfg_before) = load_toml(project_dir.path());
    assert_eq!(cfg_before.format_version, 1, "still v1 before upgrade-sig");
    assert!(cfg_before.vault.is_some(), "vault table must be present after injection");

    // Run upgrade-sig — must promote to v3 (vault present).
    let out = env
        .cmd(project_dir.path())
        .args(["envelope", "upgrade-sig"])
        .output()
        .expect("envelope upgrade-sig");
    assert!(
        out.status.success(),
        "upgrade-sig with vault failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (toml_str, cfg) = load_toml(project_dir.path());
    assert_eq!(
        cfg.format_version, 3,
        "upgrade-sig on vault repo must produce format_version=3; got:\n{toml_str}"
    );
    assert_sig_present(&cfg, "upgrade_sig_with_vault_promotes_to_v3");
    sss::envelope_sig::verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("envelope must verify under v3 context");
}

// ---------------------------------------------------------------------------
// Test: upgrade-sig is idempotent — second run on an already-correct-version repo
// prints "already signed" and leaves the file mtime unchanged
// ---------------------------------------------------------------------------

#[test]
fn upgrade_sig_idempotent_on_v3_vault_repo() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();
    init_hybrid_project(&env, project_dir.path());

    // Add a vault table and run set-address to get to v3.
    let out = env
        .cmd(project_dir.path())
        .args(["project", "vault", "set-address", "https://v.example:8200"])
        .output()
        .expect("set-address");
    assert!(
        out.status.success(),
        "set-address failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (_, cfg_after_set) = load_toml(project_dir.path());
    assert_eq!(cfg_after_set.format_version, 3, "must be v3 after set-address");

    // Capture mtime before the idempotent run.
    let mtime_before = fs::metadata(project_dir.path().join(".sss.toml"))
        .expect("stat")
        .modified()
        .expect("mtime");

    // Second upgrade-sig on a v3 vault repo — must be idempotent.
    let out = env
        .cmd(project_dir.path())
        .args(["envelope", "upgrade-sig"])
        .output()
        .expect("upgrade-sig second run");
    assert!(
        out.status.success(),
        "idempotent upgrade-sig failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Must print "already signed at format_version=3".
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("already signed at format_version=3"),
        "idempotent run must print 'already signed at format_version=3'; got: {stdout}"
    );

    // File must be unchanged (mtime not touched).
    let mtime_after = fs::metadata(project_dir.path().join(".sss.toml"))
        .expect("stat after")
        .modified()
        .expect("mtime after");
    assert_eq!(
        mtime_before, mtime_after,
        "idempotent upgrade-sig must not touch the file"
    );
}

// ---------------------------------------------------------------------------
// Test: upgrade-sig refuses a v3→v2 downgrade (vault removed from .sss.toml
// while current format_version is still 3) — non-zero exit, file unchanged
// ---------------------------------------------------------------------------

#[test]
fn upgrade_sig_refuses_downgrade_v3_to_v2() {
    let project_dir = TempDir::new().expect("project tempdir");
    let env = UserEnv::new();
    init_hybrid_project(&env, project_dir.path());

    // Set a vault address to get to v3.
    let out = env
        .cmd(project_dir.path())
        .args(["project", "vault", "set-address", "https://v.example:8200"])
        .output()
        .expect("set-address");
    assert!(
        out.status.success(),
        "set-address failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (_, cfg_v3) = load_toml(project_dir.path());
    assert_eq!(cfg_v3.format_version, 3, "must be v3 after set-address");

    // Now simulate the user manually removing the [vault] block from .sss.toml
    // while format_version stays at 3 (the file is now inconsistent).
    let config_path = project_dir.path().join(".sss.toml");
    let toml_content = fs::read_to_string(&config_path).expect("read .sss.toml");
    // Strip the [vault] section — remove all lines starting with [vault] and following
    // lines until the next section heading.
    let patched: String = {
        let mut out_lines: Vec<&str> = Vec::new();
        let mut in_vault_section = false;
        for line in toml_content.lines() {
            if line.starts_with("[vault") {
                in_vault_section = true;
                continue;
            }
            if in_vault_section && line.starts_with('[') {
                // Entering a new section — vault block is over.
                in_vault_section = false;
            }
            if !in_vault_section {
                out_lines.push(line);
            }
        }
        out_lines.join("\n") + "\n"
    };
    fs::write(&config_path, &patched).expect("write patched .sss.toml");

    // Verify the patch: format_version=3 but no [vault] table.
    let (_, cfg_patched) = load_toml(project_dir.path());
    assert_eq!(
        cfg_patched.format_version, 3,
        "format_version must still be 3 after manual vault removal"
    );
    assert!(
        cfg_patched.vault.is_none(),
        "vault table must be absent after manual removal"
    );

    // Capture mtime before the rejected downgrade attempt.
    let mtime_before = fs::metadata(&config_path).expect("stat").modified().expect("mtime");

    // upgrade-sig must refuse the downgrade.
    let out = env
        .cmd(project_dir.path())
        .args(["envelope", "upgrade-sig"])
        .output()
        .expect("upgrade-sig downgrade attempt");

    assert!(
        !out.status.success(),
        "upgrade-sig must exit non-zero on a v3→v2 downgrade attempt; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Stderr must contain a reference to the version mismatch / downgrade.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains('3') && (stderr.contains('2') || stderr.contains("target") || stderr.contains("downgrade")),
        "downgrade-rejection error must mention the versions or 'downgrade'; got: {stderr}"
    );

    // File must be unchanged (mtime not touched).
    let mtime_after = fs::metadata(&config_path).expect("stat after").modified().expect("mtime after");
    assert_eq!(
        mtime_before, mtime_after,
        "file must be unchanged after a rejected downgrade attempt"
    );
}
