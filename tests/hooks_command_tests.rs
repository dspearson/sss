//! Phase 16b — HOOKS-NN integration tests for `src/commands/hooks.rs`.
//!
//! Tier 2 placement per phase 16b D-18 (sibling integration tests). These
//! complement the in-source `mod tests` block in `src/commands/hooks.rs`
//! by exercising `handle_hooks` against TempDir-rooted git worktrees.
//!
//! All tests call directly into `sss::commands::hooks::handle_hooks` via the
//! public re-export — no subprocess spawning, no `assert_cmd`. Each test that
//! mutates the working directory uses an RAII guard to restore it, per the
//! phase 16 R-03 cwd-race lesson.

use anyhow::Result;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serial_test::serial;
use std::path::Path;
use tempfile::TempDir;

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

/// RAII guard that restores `cwd` on drop. Phase 16 R-03 cwd-race lesson — every
/// test that mutates `std::env::current_dir` MUST install this before mutating.
struct CwdGuard {
    original: std::path::PathBuf,
}

impl CwdGuard {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            original: std::env::current_dir()?,
        })
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

/// Set up a TempDir-rooted git worktree so `find_git_dir` succeeds.  Creates
/// `.git/` as a directory plus a stub `.git/HEAD` so it looks like a real
/// repository to find_git_dir's `is_dir()` branch.
fn setup_git_worktree(tmp: &TempDir) -> Result<()> {
    let git = tmp.path().join(".git");
    std::fs::create_dir(&git)?;
    std::fs::create_dir(git.join("hooks"))?;
    std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n")?;
    Ok(())
}

/// Build a top-level ArgMatches that mirrors the bare `sss` invocation. The
/// hooks dispatcher only inspects the inner subcommand matches, so this can
/// be empty.
fn empty_main_matches() -> ArgMatches {
    Command::new("sss").get_matches_from(["sss"])
}

/// Build a `sss hooks <subcommand>` ArgMatches that mirrors the real clap
/// tree from `src/main.rs`.  The shape is intentionally identical (required
/// args + flag bools) so the dispatcher routing logic is exercised faithfully.
fn build_hooks_matches(args: &[&str]) -> ArgMatches {
    let app = Command::new("hooks")
        .subcommand(
            Command::new("install")
                .arg(
                    Arg::new("template")
                        .long("template")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("multiplex")
                        .long("multiplex")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(Command::new("export"))
        .subcommand(Command::new("list"))
        .subcommand(
            Command::new("show").arg(Arg::new("hook").required(true)),
        );
    app.get_matches_from(args)
}

/// Run a closure with `cwd` pinned to `path`.  Restores cwd on drop.
fn with_cwd<F: FnOnce() -> Result<()>>(path: &Path, f: F) -> Result<()> {
    let _g = CwdGuard::new()?;
    std::env::set_current_dir(path)?;
    f()
}

// ----------------------------------------------------------------------------
// hooks_NN — sibling integration tests
// ----------------------------------------------------------------------------

/// hooks_01 — install writes the canonical hook set into a TempDir-rooted
/// git worktree's `.git/hooks/` directory.
#[test]
#[serial]
fn hooks_01_install_writes_hooks_to_git_dir() -> Result<()> {
    let tmp = TempDir::new()?;
    setup_git_worktree(&tmp)?;
    with_cwd(tmp.path(), || {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "install"]);
        sss::commands::hooks::handle_hooks(&main, &matches)?;
        // Each canonical hook lands in .git/hooks/<name>.
        for name in ["pre-commit", "post-merge", "post-checkout"] {
            let p = tmp.path().join(".git/hooks").join(name);
            assert!(p.exists(), "missing installed hook: {}", p.display());
        }
        Ok(())
    })
}

/// hooks_02 — install with `--multiplex` writes the `.d/` layout instead of
/// flat hook files.  We assert both the wrapper and the `50-sss` script.
#[test]
#[serial]
fn hooks_02_install_multiplex_writes_dotd_layout() -> Result<()> {
    let tmp = TempDir::new()?;
    setup_git_worktree(&tmp)?;
    with_cwd(tmp.path(), || {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "install", "--multiplex"]);
        sss::commands::hooks::handle_hooks(&main, &matches)?;
        for name in ["pre-commit", "post-merge", "post-checkout"] {
            let dotd = tmp.path().join(".git/hooks").join(format!("{name}.d"));
            let inner = dotd.join("50-sss");
            let wrapper = tmp.path().join(".git/hooks").join(name);
            assert!(dotd.is_dir(), "missing .d for {name}");
            assert!(inner.exists(), "missing 50-sss for {name}");
            assert!(wrapper.exists(), "missing wrapper for {name}");
        }
        Ok(())
    })
}

/// hooks_03 — list subcommand prints without error.  We don't capture stdout
/// here (the embedded hook contents are already covered by the in-source test
/// for the `HOOKS` table); we only assert dispatcher routing returns `Ok`.
#[test]
fn hooks_03_list_returns_ok() -> Result<()> {
    let main = empty_main_matches();
    let matches = build_hooks_matches(&["hooks", "list"]);
    sss::commands::hooks::handle_hooks(&main, &matches)?;
    Ok(())
}

/// hooks_04 — `show <known-hook>` returns Ok.  Use a real hook name from the
/// embedded HOOKS list.
#[test]
fn hooks_04_show_known_hook_returns_ok() -> Result<()> {
    let main = empty_main_matches();
    let matches = build_hooks_matches(&["hooks", "show", "pre-commit"]);
    sss::commands::hooks::handle_hooks(&main, &matches)?;
    Ok(())
}

/// hooks_05 — `show <unknown-hook>` returns Err with a "not found" message.
/// Error-message regression: guards against silent renames of the error text.
#[test]
fn hooks_05_show_unknown_hook_errors_with_not_found() -> Result<()> {
    let main = empty_main_matches();
    let matches = build_hooks_matches(&["hooks", "show", "absolutely-not-real"]);
    let err = sss::commands::hooks::handle_hooks(&main, &matches)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not found"),
        "error must mention 'not found'; got: {err}"
    );
    Ok(())
}

/// hooks_06 — install errors when cwd is not inside a git repository.
/// Drives `find_git_dir`'s ancestor-walk error branch.
#[test]
#[serial]
fn hooks_06_install_errors_outside_git_repo() -> Result<()> {
    let tmp = TempDir::new()?;
    // Deliberately do NOT create `.git`.
    with_cwd(tmp.path(), || {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "install"]);
        let err = sss::commands::hooks::handle_hooks(&main, &matches)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Not in a git repository"),
            "expected 'Not in a git repository'; got: {err}"
        );
        Ok(())
    })
}

/// hooks_07 — re-running `install` against an already-populated hooks dir
/// skips colliding files (check_existing == true on the per-repo path).
/// The pre-existing content must survive untouched.
#[test]
#[serial]
fn hooks_07_install_skips_existing_hooks_on_collision() -> Result<()> {
    let tmp = TempDir::new()?;
    setup_git_worktree(&tmp)?;
    let preexisting = tmp.path().join(".git/hooks/pre-commit");
    std::fs::write(&preexisting, "preexisting\n")?;
    with_cwd(tmp.path(), || {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "install"]);
        sss::commands::hooks::handle_hooks(&main, &matches)?;
        // Pre-existing hook content must be preserved.
        let kept = std::fs::read_to_string(&preexisting)?;
        assert_eq!(kept, "preexisting\n", "pre-existing hook must not be overwritten");
        // The other two hooks must have been installed.
        for name in ["post-merge", "post-checkout"] {
            let p = tmp.path().join(".git/hooks").join(name);
            assert!(p.exists(), "{name} must have been installed");
        }
        Ok(())
    })
}

/// hooks_08 — install auto-detects existing multiplex layout and respects it
/// even without `--multiplex`.  This drives the `is_multiplexed` short-circuit
/// inside `install_hooks_to_repo`.
#[test]
#[serial]
fn hooks_08_install_auto_detects_existing_multiplex() -> Result<()> {
    let tmp = TempDir::new()?;
    setup_git_worktree(&tmp)?;
    // Pre-create a `.d` directory for one of the canonical hooks. The
    // detector flips on the existence of any `<name>.d` for any HOOKS entry.
    std::fs::create_dir(tmp.path().join(".git/hooks/pre-commit.d"))?;
    with_cwd(tmp.path(), || {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "install"]);
        sss::commands::hooks::handle_hooks(&main, &matches)?;
        // Because layout was already multiplex, the new hooks land in `.d/`.
        assert!(
            tmp.path().join(".git/hooks/pre-commit.d/50-sss").exists(),
            "pre-commit.d/50-sss must be installed under multiplex layout"
        );
        Ok(())
    })
}
