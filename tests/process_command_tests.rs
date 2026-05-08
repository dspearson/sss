//! Sibling integration tests for `src/commands/process.rs` handlers.
//!
//! Phase 16b-03 / TEST-11 — direct in-process exercise of the verb-level
//! dispatchers (`handle_seal`, `handle_open`, `handle_render`, `handle_edit`,
//! `handle_process`) without spawning the binary. The FUSE-mount edit arm is
//! intentionally skipped per Phase 16b D-08 (untestable without a real mount).
//!
//! Each test that touches the cwd is wrapped in a `DirGuard` to restore the
//! prior working directory and uses `serial_test::serial` to prevent
//! interleaving of cwd-mutating tests, mirroring the precedent in
//! `tests/verb_commands.rs` and `src/commands/utils.rs:DirGuard`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Arg, ArgAction, Command};
use serial_test::serial;
use tempfile::TempDir;

use sss::commands::{handle_edit, handle_open, handle_process, handle_render, handle_seal};
use sss::crypto::KeyPair;
use sss::keystore::Keystore;
use sss::project::ProjectConfig;

// ---------------------------------------------------------------------------
// RAII helpers
// ---------------------------------------------------------------------------

/// Restore working directory on Drop.
struct DirGuard(PathBuf);

impl DirGuard {
    fn enter<P: AsRef<Path>>(target: P) -> Result<Self> {
        let prev = env::current_dir()?;
        env::set_current_dir(target.as_ref())?;
        Ok(Self(prev))
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.0);
    }
}

/// Restore env var (or unset) on Drop.
struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = env::var(key).ok();
        unsafe { env::set_var(key, value); }
        Self { key, prev }
    }

    fn unset(key: &'static str) -> Self {
        let prev = env::var(key).ok();
        unsafe { env::remove_var(key); }
        Self { key, prev: prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => unsafe { env::set_var(self.key, v); },
            None => unsafe { env::remove_var(self.key); },
        }
    }
}

// ---------------------------------------------------------------------------
// Argument-builder helpers — match the clap declarations in `src/main.rs`.
// ---------------------------------------------------------------------------

/// Build a clap `ArgMatches` for the seal/open/render subcommands.
fn build_sub_matches(operation: &'static str, args: &[&str]) -> clap::ArgMatches {
    Command::new(operation)
        .arg(
            Arg::new("file")
                .help("File to process")
                .required_unless_present("project"),
        )
        .arg(
            Arg::new("in-place")
                .long("in-place")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("project")
                .long("project")
                .action(ArgAction::SetTrue)
                .conflicts_with("file"),
        )
        .get_matches_from(std::iter::once(operation).chain(args.iter().copied()))
}

/// Build matches for the `process` verb — supports --in-place / --render / --edit.
fn build_process_matches(args: &[&str]) -> clap::ArgMatches {
    Command::new("process")
        .arg(Arg::new("file").required(false))
        .arg(Arg::new("in-place").long("in-place").action(ArgAction::SetTrue))
        .arg(Arg::new("render").long("render").action(ArgAction::SetTrue))
        .arg(Arg::new("edit").long("edit").action(ArgAction::SetTrue))
        .get_matches_from(std::iter::once("process").chain(args.iter().copied()))
}

/// Build matches for the `edit` subcommand (file always required).
fn build_edit_matches(args: &[&str]) -> clap::ArgMatches {
    Command::new("edit")
        .arg(Arg::new("file").required(true))
        .get_matches_from(std::iter::once("edit").chain(args.iter().copied()))
}

/// Build matches for the parent application — only used as a placeholder
/// where the handlers ignore the main matches.
fn build_main_matches() -> clap::ArgMatches {
    Command::new("sss").get_matches_from(["sss"])
}

// ---------------------------------------------------------------------------
// Project + keystore scaffolding (XDG_CONFIG_HOME override keeps the test
// keystore isolated from the developer's real ~/.config/sss/keys).
// ---------------------------------------------------------------------------

struct ProjectFixture {
    _tmp: TempDir,
    project_dir: PathBuf,
    _xdg_guard: EnvGuard,
    _editor_guard: EnvGuard,
    _agent_guard: EnvGuard,
}

impl ProjectFixture {
    fn new() -> Result<Self> {
        let tmp = TempDir::new()?;
        let xdg = tmp.path().join(".config");
        fs::create_dir_all(&xdg)?;
        let project_dir = tmp.path().join("project");
        fs::create_dir_all(&project_dir)?;

        // Force the keystore lookup into our temp tree.
        let xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.to_str().expect("utf8 xdg"));
        // /bin/true exits cleanly without modifying the temp file — used for the
        // edit-no-changes path.
        let editor_guard = EnvGuard::set("EDITOR", "/bin/true");
        // Defensive: don't let a developer's running sss-agent satisfy the
        // unseal request — we want the local-keystore code path under test.
        let agent_guard = EnvGuard::unset("SSH_AUTH_SOCK");

        // Generate + store a passwordless classic keypair.
        let keystore = Keystore::new()?;
        let keypair = KeyPair::generate()?;
        keystore.store_keypair(&keypair, None)?;

        // Build a v1 (Classic) project config containing this user.
        let mut config = ProjectConfig::default();
        let repo_key = sss::crypto::RepositoryKey::new();
        config.add_user("testuser", &keypair.public_key(), &repo_key)?;
        config.save_to_file(project_dir.join(".sss.toml"))?;

        Ok(Self {
            _tmp: tmp,
            project_dir,
            _xdg_guard: xdg_guard,
            _editor_guard: editor_guard,
            _agent_guard: agent_guard,
        })
    }
}

// ---------------------------------------------------------------------------
// process_NN_<scenario> tests
// ---------------------------------------------------------------------------

/// 01: handle_process with no file argument surfaces the documented
/// "No file specified" guidance for the user.
#[test]
#[serial]
fn process_01_handle_process_no_file_returns_guidance_error() {
    let matches = build_process_matches(&[]);
    let err = handle_process(&matches).expect_err("expected error when file omitted");
    let msg = err.to_string();
    assert!(msg.contains("No file specified"), "unexpected message: {msg}");
    assert!(msg.contains("sss process"), "guidance missing usage hint: {msg}");
}

/// 02: stdin + --in-place is rejected by the stdin guard before any
/// project-config lookup happens. Uses the canonical `ERR_STDIN_IN_PLACE`.
#[test]
#[serial]
fn process_02_handle_process_stdin_in_place_rejected() {
    let matches = build_process_matches(&["-", "--in-place"]);
    let err = handle_process(&matches).expect_err("expected stdin+in-place rejection");
    assert!(
        err.to_string().contains("Cannot use --in-place with stdin"),
        "unexpected message: {err}"
    );
}

/// 03: stdin + --edit is rejected at the same guard.
#[test]
#[serial]
fn process_03_handle_process_stdin_edit_rejected() {
    let matches = build_process_matches(&["-", "--edit"]);
    let err = handle_process(&matches).expect_err("expected stdin+edit rejection");
    assert!(
        err.to_string().contains("Cannot use --edit with stdin"),
        "unexpected message: {err}"
    );
}

/// 04: handle_edit with file = "-" surfaces the dedicated stdin-edit error
/// before any filesystem access.
#[test]
#[serial]
fn process_04_handle_edit_stdin_rejected() {
    let main = build_main_matches();
    let sub = build_edit_matches(&["-"]);
    let err = handle_edit(&main, &sub).expect_err("expected stdin rejection");
    assert!(
        err.to_string().contains("Cannot use edit mode with stdin"),
        "unexpected message: {err}"
    );
}

/// 05: handle_edit on a nonexistent file produces a "does not exist"
/// hint without panicking. Uses an absolute path so cwd is irrelevant.
#[test]
#[serial]
fn process_05_handle_edit_nonexistent_file_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let missing = tmp.path().join("absent.txt");
    let main = build_main_matches();
    let sub = build_edit_matches(&[missing.to_str().expect("utf8")]);
    let err = handle_edit(&main, &sub).expect_err("expected missing-file error");
    let msg = err.to_string();
    assert!(
        msg.contains("does not exist") || msg.contains("No project configuration"),
        "unexpected message: {msg}"
    );
    Ok(())
}

/// 06: handle_seal called outside any sss project surfaces the
/// "No project configuration found" error from the config loader.
/// Confirms that `process_file_or_stdin` propagates the loader error
/// faithfully (covers the early-return arm).
#[test]
#[serial]
fn process_06_handle_seal_outside_project_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let _dir = DirGuard::enter(tmp.path())?;
    let target = tmp.path().join("any.txt");
    fs::write(&target, "no markers here")?;

    let main = build_main_matches();
    let sub = build_sub_matches("seal", &[target.to_str().expect("utf8")]);
    let err = handle_seal(&main, &sub).expect_err("expected loader error outside project");
    let msg = err.to_string();
    assert!(
        msg.contains("No project configuration") || msg.contains("project"),
        "unexpected message: {msg}"
    );
    Ok(())
}

/// 07: handle_render --project surfaces the disabled-by-default permission
/// gate when `sss project enable render` has never been run. Exercises the
/// `process_project_recursively("render")` permission arm.
#[test]
#[serial]
fn process_07_handle_render_project_flag_blocked_by_default() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;
    // Make sure no override env vars are set.
    let _g1 = EnvGuard::unset("SSS_PROJECT_RENDER");

    let main = build_main_matches();
    let sub = build_sub_matches("render", &["--project"]);
    let err = handle_render(&main, &sub).expect_err("expected permission-gate error");
    let msg = err.to_string();
    assert!(
        msg.contains("disabled") || msg.contains("project enable"),
        "unexpected message: {msg}"
    );
    Ok(())
}

/// 08: handle_open --project equally requires `sss project enable open`.
#[test]
#[serial]
fn process_08_handle_open_project_flag_blocked_by_default() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;
    let _g1 = EnvGuard::unset("SSS_PROJECT_OPEN");

    let main = build_main_matches();
    let sub = build_sub_matches("open", &["--project"]);
    let err = handle_open(&main, &sub).expect_err("expected permission-gate error");
    let msg = err.to_string();
    assert!(
        msg.contains("disabled") || msg.contains("project enable"),
        "unexpected message: {msg}"
    );
    Ok(())
}

/// 09: handle_seal --project is unconditionally allowed (no permission gate
/// required, per process_project_recursively's arm match). With an empty
/// project tree this completes successfully — exercising the recursive
/// walker's no-op path.
#[test]
#[serial]
fn process_09_handle_seal_project_flag_walks_empty_tree() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;

    let main = build_main_matches();
    let sub = build_sub_matches("seal", &["--project"]);
    handle_seal(&main, &sub)?;
    Ok(())
}

/// 10: handle_seal on a real file with plaintext markers, in-place, in a
/// configured project — exercises the success branch of `process_file_or_stdin`
/// for `--in-place`. Uses the cwd-confined fixture; the absolute path keeps
/// `validate_file_path` deterministic.
#[test]
#[serial]
fn process_10_handle_seal_in_place_seals_plaintext_markers() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;

    let target = fx.project_dir.join("doc.txt");
    let original = "secret = \u{2295}{my-plaintext-secret}\n";
    fs::write(&target, original)?;

    let main = build_main_matches();
    let sub = build_sub_matches(
        "seal",
        &[target.to_str().expect("utf8"), "--in-place"],
    );
    handle_seal(&main, &sub)?;

    let after = fs::read_to_string(&target)?;
    assert!(
        after.contains("\u{22a0}{"),
        "expected sealed marker after in-place seal: {after}"
    );
    assert!(!after.contains("\u{2295}{"), "plaintext marker should be gone: {after}");
    Ok(())
}

/// 11: handle_open round-trips the previously sealed file back to plaintext
/// markers (to-stdout default). Verifies that handle_open + the project
/// keystore plumbing is exercised end-to-end.
#[test]
#[serial]
fn process_11_handle_open_in_place_decrypts_to_plaintext_markers() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;

    let target = fx.project_dir.join("doc.txt");
    fs::write(&target, "secret = \u{2295}{another-plaintext}\n")?;

    let main = build_main_matches();
    // Seal first.
    let seal_sub = build_sub_matches(
        "seal",
        &[target.to_str().expect("utf8"), "--in-place"],
    );
    handle_seal(&main, &seal_sub)?;
    let sealed = fs::read_to_string(&target)?;
    assert!(sealed.contains("\u{22a0}{"), "precondition: sealed: {sealed}");

    // Now open in-place and confirm we get back a plaintext marker.
    let open_sub = build_sub_matches(
        "open",
        &[target.to_str().expect("utf8"), "--in-place"],
    );
    handle_open(&main, &open_sub)?;
    let opened = fs::read_to_string(&target)?;
    assert!(
        opened.contains("\u{2295}{") || opened.contains("o+{"),
        "expected plaintext marker after open: {opened}"
    );
    Ok(())
}

/// 12: handle_render in-place strips markers from a sealed file, leaving
/// only the raw secret value behind. Covers the render arm of
/// `process_file_or_stdin`.
#[test]
#[serial]
fn process_12_handle_render_in_place_strips_markers() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;

    let target = fx.project_dir.join("doc.txt");
    fs::write(&target, "k = \u{2295}{render-target}\n")?;

    let main = build_main_matches();
    handle_seal(
        &main,
        &build_sub_matches("seal", &[target.to_str().expect("utf8"), "--in-place"]),
    )?;

    handle_render(
        &main,
        &build_sub_matches("render", &[target.to_str().expect("utf8"), "--in-place"]),
    )?;
    let rendered = fs::read_to_string(&target)?;
    assert!(!rendered.contains("\u{22a0}{"), "rendered output kept sealed marker: {rendered}");
    assert!(!rendered.contains("\u{2295}{"), "rendered output kept plaintext marker: {rendered}");
    assert!(rendered.contains("render-target"), "rendered output missing raw value: {rendered}");
    Ok(())
}

/// 13: handle_edit on a sealed file with `EDITOR=/bin/true` exits cleanly and
/// re-seals the unchanged plaintext. The ciphertext envelope rotates (fresh
/// AEAD nonce on every seal) but the round-tripped plaintext must be
/// byte-identical to what we wrote in.
#[test]
#[serial]
fn process_13_handle_edit_regular_no_editor_changes_preserves_plaintext() -> Result<()> {
    let fx = ProjectFixture::new()?;
    let _dir = DirGuard::enter(&fx.project_dir)?;

    let target = fx.project_dir.join("doc.txt");
    let original = "k = \u{2295}{edit-roundtrip}\n";
    fs::write(&target, original)?;

    let main = build_main_matches();
    handle_seal(
        &main,
        &build_sub_matches("seal", &[target.to_str().expect("utf8"), "--in-place"]),
    )?;
    let pre_edit_sealed = fs::read_to_string(&target)?;
    assert!(
        pre_edit_sealed.contains("\u{22A0}{"),
        "seal didn't produce a sealed marker: {pre_edit_sealed}"
    );

    handle_edit(
        &main,
        &build_edit_matches(&[target.to_str().expect("utf8")]),
    )?;
    let post_edit_sealed = fs::read_to_string(&target)?;
    assert!(
        post_edit_sealed.contains("\u{22A0}{"),
        "post-edit file lost sealed marker: {post_edit_sealed}"
    );

    // Round-trip via handle_open --in-place to verify plaintext preservation.
    handle_open(
        &main,
        &build_sub_matches("open", &[target.to_str().expect("utf8"), "--in-place"]),
    )?;
    let plaintext = fs::read_to_string(&target)?;
    assert_eq!(
        plaintext, original,
        "edit with no editor changes must preserve plaintext after round-trip"
    );
    Ok(())
}
