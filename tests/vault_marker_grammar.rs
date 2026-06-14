// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Vault reference marker grammar + byte-preservation integration tests.
//!
//! Plan 46-01 (VREF-01..05): proves that:
//! - `parse_vault_reference` splits `[binding:]path#field@version` correctly.
//! - `VAULT_INTERPOLATION_REGEX` captures vault refs from both Unicode (⊳) and ASCII (>) forms.
//! - `sss seal` preserves `⊳{…}` byte-for-byte on disk.
//! - `sss seal` normalises the `>{}` ASCII alias to `⊳{}` (mirroring `<{` → `⊲{`).
//! - `sss open` leaves the preserved `⊳{}` marker byte-identical.
//! - A malformed `⊳{}` reference is reported; the original marker text is returned, not "".
//!
//! Group 1 (`parse_*`, `regex_*`) — unit-style assertions on the library API;
//!   run on the DEFAULT feature set (no `--features vault`) to prove R4.
//!
//! Group 2 (`e2e_*`) — end-to-end byte-preservation via the real sss binary.
//!   Each test calls the `CARGO_BIN_EXE_sss` subprocess pattern with an isolated
//!   HOME / `SSS_PASSPHRASE` / `NO_COLOR` / `--kdf-level interactive` environment,
//!   exactly as the analog harness in `tests/envelope_signature_negative_paths.rs`.

use sss::vault::resolver::{
    parse_vault_reference, VaultRefError, VaultReference, VAULT_INTERPOLATION_REGEX,
};
#[cfg(feature = "hybrid")]
use std::process::Command;
#[cfg(feature = "hybrid")]
use tempfile::TempDir;

/// Sub-process vault tests require the hybrid feature so that `keys generate --suite classic`
/// emits a signed (`format_version` >= 2) entry that `sss init` accepts.
/// The sign-on-write path in `src/commands/keys.rs` is `#[cfg(feature = "hybrid")]`-gated.
#[cfg(feature = "hybrid")]
fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

// ---------------------------------------------------------------------------
// Isolated subprocess environment — mirrors tests/envelope_signature_negative_paths.rs
// ---------------------------------------------------------------------------

#[cfg(feature = "hybrid")]
struct UserEnv {
    home_dir: TempDir,
}

#[cfg(feature = "hybrid")]
impl UserEnv {
    fn new() -> Self {
        Self {
            home_dir: TempDir::new().expect("create temp home"),
        }
    }

    fn cmd(&self, project_dir: &std::path::Path) -> Command {
        let mut cmd = Command::new(sss_bin());
        cmd.env("HOME", self.home_dir.path())
            .env("XDG_CONFIG_HOME", self.home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "alice")
            // Allow sss open --project without the interactive enable step.
            .env("SSS_PROJECT_OPEN", "true")
            .current_dir(project_dir)
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    }
}

/// Initialise a minimal sss project: keygen + init in `dir`, return a `UserEnv`.
///
/// Uses `--crypto classic` for `init` because the branch-level default (`--crypto hybrid`)
/// requires a hybrid keypair that we do not generate here.  The `#[cfg(feature = "hybrid")]`
/// guard on the call sites mirrors the sign-on-write backport in `src/commands/keys.rs`:
/// on non-hybrid builds `store_keypair` emits a `format_version=1` entry that the load gate
/// rejects, so there is no point calling this helper there.
#[cfg(feature = "hybrid")]
fn init_project(dir: &std::path::Path) -> UserEnv {
    let env = UserEnv::new();

    let out = env
        .cmd(dir)
        .args(["keys", "generate", "--suite", "classic", "--no-password", "--force"])
        .output()
        .expect("keygen");
    assert!(
        out.status.success(),
        "keygen failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // --crypto classic: we have only a classic keypair above; hybrid init requires
    // a hybrid keypair which we deliberately omit to keep the setup minimal.
    let out = env
        .cmd(dir)
        .args(["init", "alice", "--crypto", "classic"])
        .output()
        .expect("init");
    assert!(
        out.status.success(),
        "init failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    env
}

// ===========================================================================
// Group 1 — library API assertions (run under DEFAULT features, proving R4)
// ===========================================================================

// ── VAULT_INTERPOLATION_REGEX ────────────────────────────────────────────────

#[test]
fn regex_captures_unicode_vault_ref() {
    let hay = "⊳{secret#f}";
    let caps = VAULT_INTERPOLATION_REGEX.captures(hay).unwrap();
    assert_eq!(&caps[1], "secret#f");
}

#[test]
fn regex_captures_ascii_alias() {
    let hay = ">{secret#f}";
    let caps = VAULT_INTERPOLATION_REGEX.captures(hay).unwrap();
    assert_eq!(&caps[1], "secret#f");
}

#[test]
fn regex_ascii_and_unicode_capture_identically() {
    // Both alias forms must produce identical capture group 1.
    let unicode = "⊳{kv:app/db#password@2}";
    let ascii = ">{kv:app/db#password@2}";
    let uc = VAULT_INTERPOLATION_REGEX.captures(unicode).unwrap();
    let ac = VAULT_INTERPOLATION_REGEX.captures(ascii).unwrap();
    assert_eq!(&uc[1], &ac[1]);
}

// ── parse_vault_reference — well-formed cases ─────────────────────────────────

#[test]
fn parse_path_only() {
    assert_eq!(
        parse_vault_reference("secret/data/app").unwrap(),
        VaultReference {
            binding: None,
            path: "secret/data/app".to_owned(),
            field: None,
            version: None,
        }
    );
}

#[test]
fn parse_binding_path_field() {
    assert_eq!(
        parse_vault_reference("kv:secret/app#password").unwrap(),
        VaultReference {
            binding: Some("kv".to_owned()),
            path: "secret/app".to_owned(),
            field: Some("password".to_owned()),
            version: None,
        }
    );
}

#[test]
fn parse_path_field_version() {
    assert_eq!(
        parse_vault_reference("secret/app#password@3").unwrap(),
        VaultReference {
            binding: None,
            path: "secret/app".to_owned(),
            field: Some("password".to_owned()),
            version: Some(3),
        }
    );
}

#[test]
fn parse_all_four_components() {
    assert_eq!(
        parse_vault_reference("db:secret/app#pw@2").unwrap(),
        VaultReference {
            binding: Some("db".to_owned()),
            path: "secret/app".to_owned(),
            field: Some("pw".to_owned()),
            version: Some(2),
        }
    );
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn parse_empty_is_error() {
    assert_eq!(
        parse_vault_reference(""),
        Err(VaultRefError::EmptyReference)
    );
}

#[test]
fn parse_bad_version_is_error_not_silent_latest() {
    // An unparseable @version must be an explicit error, NOT "silently use latest".
    let err = parse_vault_reference("secret/app@notanumber").unwrap_err();
    assert!(
        matches!(err, VaultRefError::InvalidVersion(_)),
        "expected InvalidVersion, got: {err}"
    );
}

// ── Preserve-verbatim: malformed ref → original marker text, never empty ─────

#[test]
fn malformed_ref_original_bytes_not_empty() {
    // This tests the library contract: when parse_vault_reference returns Err,
    // the caller (interpolate_vault_refs) must return the original marker text.
    // In Phase 46 interpolate_vault_refs is an identity function, so we verify
    // the parse itself errors and the identity stub preserves the input.
    let bad_ref = "secret/app@notanumber";
    assert!(parse_vault_reference(bad_ref).is_err());

    // The interpolation stub must return original content unchanged.
    let input = "⊳{secret/app@notanumber}";
    let output = sss::vault::resolver::interpolate_vault_refs(input);
    assert_eq!(output, input, "interpolate_vault_refs must not return empty on bad ref");
}

// ── Colon edge cases ──────────────────────────────────────────────────────────

#[test]
fn slash_in_pre_colon_segment_keeps_colon_in_path() {
    // "secret/prod:8200" — '/' before ':' means NOT a binding.
    let r = parse_vault_reference("secret/prod:8200").unwrap();
    assert_eq!(r.binding, None);
    assert_eq!(r.path, "secret/prod:8200");
}

// ===========================================================================
// Group 2 — end-to-end byte-preservation via the real sss binary
// ===========================================================================

/// `sss seal` followed by `sss open` leaves `⊳{secret/prod#api_key}` byte-identical.
///
/// Requires `--features hybrid`: on non-hybrid builds `keys generate --suite classic`
/// emits a `format_version=1` entry that `sss init` refuses to load.
/// The sign-on-write backport (master bce2ac4, applied locally) is `#[cfg(feature = "hybrid")]`
/// so it only activates in hybrid builds.
#[cfg(feature = "hybrid")]
#[test]
fn e2e_vault_marker_preserved_through_seal_and_open() {
    let project_dir = tempfile::Builder::new()
        .prefix("sss_vault_")
        .tempdir()
        .expect("project tempdir");
    let env = init_project(project_dir.path());

    let file_path = project_dir.path().join("config.yaml");
    let marker = "⊳{secret/prod#api_key}";
    std::fs::write(&file_path, format!("api_key: {marker}\n")).expect("write test file");

    // sss seal --project (seal all files in the project directory)
    let out = env
        .cmd(project_dir.path())
        .args(["seal", "--project"])
        .output()
        .expect("sss seal");
    assert!(
        out.status.success(),
        "sss seal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // After seal the vault marker must be byte-identical on disk.
    let on_disk = std::fs::read_to_string(&file_path).expect("read after seal");
    assert!(
        on_disk.contains(marker),
        "vault marker must survive sss seal byte-identical; on-disk: {on_disk:?}"
    );

    // sss open --project
    let out = env
        .cmd(project_dir.path())
        .args(["open", "--project"])
        .output()
        .expect("sss open");
    assert!(
        out.status.success(),
        "sss open failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // After open the vault marker must still be byte-identical.
    let after_open = std::fs::read_to_string(&file_path).expect("read after open");
    assert!(
        after_open.contains(marker),
        "vault marker must survive sss open byte-identical; after open: {after_open:?}"
    );
}

/// Mixed-marker file: `sss seal` encrypts `⊕{}` but preserves `⊳{}`.
///
/// Requires `--features hybrid` for the same reason as
/// `e2e_vault_marker_preserved_through_seal_and_open` (sign-on-write backport).
#[cfg(feature = "hybrid")]
#[test]
fn e2e_mixed_marker_seal_encrypts_plaintext_preserves_vault() {
    let project_dir = tempfile::Builder::new()
        .prefix("sss_vault_")
        .tempdir()
        .expect("project tempdir");
    let env = init_project(project_dir.path());

    let file_path = project_dir.path().join("mixed.yaml");
    std::fs::write(
        &file_path,
        "vault_key: ⊳{secret/prod#api_key}\nplaintext: ⊕{topsecret}\n",
    )
    .expect("write mixed file");

    let out = env
        .cmd(project_dir.path())
        .args(["seal", "--project"])
        .output()
        .expect("sss seal mixed");
    assert!(
        out.status.success(),
        "sss seal (mixed) failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let on_disk = std::fs::read_to_string(&file_path).expect("read after seal");

    // Vault marker must survive unchanged.
    assert!(
        on_disk.contains("⊳{secret/prod#api_key}"),
        "vault marker must survive seal; got: {on_disk:?}"
    );
    // Plaintext marker must have been encrypted.
    assert!(
        on_disk.contains("⊠{"),
        "plaintext marker must be encrypted; got: {on_disk:?}"
    );
    assert!(
        !on_disk.contains("⊕{topsecret}"),
        "original plaintext marker must not appear after seal; got: {on_disk:?}"
    );
}

/// `sss seal` normalises the `>{}` ASCII vault alias to `⊳{}` on disk,
/// exactly mirroring how `<{` is normalised to `⊲{` in the live codebase.
///
/// Requires `--features hybrid` for the same reason as
/// `e2e_vault_marker_preserved_through_seal_and_open` (sign-on-write backport).
#[cfg(feature = "hybrid")]
#[test]
fn e2e_vault_ascii_alias_normalised_to_unicode_on_seal() {
    let project_dir = tempfile::Builder::new()
        .prefix("sss_vault_")
        .tempdir()
        .expect("project tempdir");
    let env = init_project(project_dir.path());

    let file_path = project_dir.path().join("alias.yaml");
    // Write the ASCII alias form.
    std::fs::write(&file_path, "api: >{secret/prod#api_key}\n").expect("write alias file");

    let out = env
        .cmd(project_dir.path())
        .args(["seal", "--project"])
        .output()
        .expect("sss seal alias");
    assert!(
        out.status.success(),
        "sss seal (alias) failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let on_disk = std::fs::read_to_string(&file_path).expect("read after seal");

    // After seal the on-disk bytes must contain the Unicode preferred form.
    // This is the SAME normalisation the live codebase applies to <{ → ⊲{:
    // normalize_secrets_markers in processor/core.rs does content.replace("<{", "⊲{"),
    // and normalize_vault_markers does the identical thing for >{.
    assert!(
        on_disk.contains("⊳{secret/prod#api_key}"),
        "vault ASCII alias >{{ must be normalised to ⊳{{ on seal; got: {on_disk:?}"
    );
}

/// After a seal that normalised `>{}` to `⊳{}`, `sss open` leaves the Unicode
/// form byte-identical (no second normalisation on the open path).
///
/// Requires `--features hybrid` for the same reason as
/// `e2e_vault_marker_preserved_through_seal_and_open` (sign-on-write backport).
#[cfg(feature = "hybrid")]
#[test]
fn e2e_open_preserves_unicode_vault_marker_after_alias_normalisation() {
    let project_dir = tempfile::Builder::new()
        .prefix("sss_vault_")
        .tempdir()
        .expect("project tempdir");
    let env = init_project(project_dir.path());

    let file_path = project_dir.path().join("alias_open.yaml");
    // Write with plain text + vault alias alongside a real secret.
    std::fs::write(
        &file_path,
        "vault_ref: >{secret/prod#api_key}\npassword: ⊕{hunter2}\n",
    )
    .expect("write test file");

    // Seal.
    let out = env
        .cmd(project_dir.path())
        .args(["seal", "--project"])
        .output()
        .expect("sss seal (alias+plaintext)");
    assert!(
        out.status.success(),
        "seal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sealed = std::fs::read_to_string(&file_path).expect("read after seal");
    assert!(
        sealed.contains("⊳{secret/prod#api_key}"),
        "vault marker must be Unicode after seal; got: {sealed:?}"
    );

    // Open.
    let out = env
        .cmd(project_dir.path())
        .args(["open", "--project"])
        .output()
        .expect("sss open (after alias seal)");
    assert!(
        out.status.success(),
        "open failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after_open = std::fs::read_to_string(&file_path).expect("read after open");
    assert!(
        after_open.contains("⊳{secret/prod#api_key}"),
        "vault marker must survive open byte-identical; got: {after_open:?}"
    );
}
