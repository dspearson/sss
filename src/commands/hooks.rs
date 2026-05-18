use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// Embed hook files at compile time
const PRE_COMMIT_HOOK: &str = include_str!("../../githooks/pre-commit");
const POST_MERGE_HOOK: &str = include_str!("../../githooks/post-merge");
const POST_CHECKOUT_HOOK: &str = include_str!("../../githooks/post-checkout");

/// Hook metadata
struct Hook {
    name: &'static str,
    content: &'static str,
    description: &'static str,
}

const HOOKS: &[Hook] = &[
    Hook {
        name: "pre-commit",
        content: PRE_COMMIT_HOOK,
        description: "Seals files with plaintext markers and checks for security violations",
    },
    Hook {
        name: "post-merge",
        content: POST_MERGE_HOOK,
        description: "Renders encrypted files after git pull/merge",
    },
    Hook {
        name: "post-checkout",
        content: POST_CHECKOUT_HOOK,
        description: "Renders encrypted files after git checkout",
    },
];

pub fn handle_hooks(_main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("install", sub_matches)) => {
            let use_template = sub_matches.get_flag("template");
            let use_multiplex = sub_matches.get_flag("multiplex");

            if use_template {
                install_hooks_to_template(use_multiplex)
            } else {
                install_hooks_to_repo(use_multiplex)
            }
        }
        Some(("export", _)) => export_hooks_to_config(),
        Some(("show", sub_matches)) => {
            if let Some(hook_name) = sub_matches.get_one::<String>("hook") {
                show_hook(hook_name)
            } else {
                list_hooks()
            }
        }
        Some(("list", _)) => list_hooks(),
        None => show_hooks_info(),
        _ => unreachable!(),
    }
}

/// Generate a wrapper script that runs all hooks in a .d/ directory
fn generate_hook_wrapper(hook_name: &str) -> String {
    format!(
        r#"#!/bin/bash
# Multiplexed git hook wrapper for {hook_name}
# Runs all executable scripts in {hook_name}.d/ in sorted order

set -e

hook_dir="$(dirname "$0")/{hook_name}.d"

if [ ! -d "$hook_dir" ]; then
    exit 0
fi

for hook in "$hook_dir"/*; do
    if [ -x "$hook" ]; then
        "$hook" "$@" || exit $?
    fi
done

exit 0
"#
    )
}

/// Check if a hooks directory is already using multiplexed structure
fn is_multiplexed(hooks_dir: &Path) -> bool {
    HOOKS
        .iter()
        .any(|hook| hooks_dir.join(format!("{}.d", hook.name)).is_dir())
}

/// Install hooks to a directory with multiplex support
// Why: hook_dir = path to a single hook file; hooks_dir = parent directory containing all hooks; intentionally distinct names per the install/export API contract.
#[allow(clippy::similar_names)]
fn install_hooks_to_directory(
    hooks_dir: &PathBuf,
    use_multiplex: bool,
    check_existing: bool,
) -> Result<(usize, usize)> {
    fs::create_dir_all(hooks_dir)
        .map_err(|e| anyhow!("Failed to create hooks directory: {e}"))?;

    let mut installed_count = 0;
    let mut skipped_count = 0;

    let already_multiplexed = is_multiplexed(hooks_dir);
    let should_multiplex = use_multiplex || already_multiplexed;

    if should_multiplex {
        // Install in multiplexed mode
        for hook in HOOKS {
            let hook_dir = hooks_dir.join(format!("{}.d", hook.name));
            let wrapper_path = hooks_dir.join(hook.name);
            let hook_script_path = hook_dir.join("50-sss");

            // Create .d directory
            fs::create_dir_all(&hook_dir)?;

            // Check if sss hook already exists in .d/
            if check_existing && hook_script_path.exists() {
                println!("⚠ Skipping {} (already exists in {}.d/)", hook.name, hook.name);
                skipped_count += 1;
                continue;
            }

            // Write sss hook to .d/50-sss
            fs::write(&hook_script_path, hook.content)
                .map_err(|e| anyhow!("Failed to write hook {}: {}", hook.name, e))?;

            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&hook_script_path)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&hook_script_path, perms)?;
            }

            // Create or update wrapper script
            if !wrapper_path.exists() || !check_existing {
                fs::write(&wrapper_path, generate_hook_wrapper(hook.name))?;

                #[cfg(unix)]
                {
                    let mut perms = fs::metadata(&wrapper_path)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&wrapper_path, perms)?;
                }
            }

            println!("✓ Installed {} (multiplexed: {}.d/50-sss)", hook.name, hook.name);
            installed_count += 1;
        }
    } else {
        // Install flat hooks
        for hook in HOOKS {
            let hook_path = hooks_dir.join(hook.name);

            if check_existing && hook_path.exists() {
                println!("⚠ Skipping {} (already exists)", hook.name);
                skipped_count += 1;
                continue;
            }

            fs::write(&hook_path, hook.content)
                .map_err(|e| anyhow!("Failed to write hook {}: {}", hook.name, e))?;

            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&hook_path)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&hook_path, perms)?;
            }

            println!("✓ Installed {} - {}", hook.name, hook.description);
            installed_count += 1;
        }
    }

    Ok((installed_count, skipped_count))
}

/// Install hooks to the current git repository
fn install_hooks_to_repo(use_multiplex: bool) -> Result<()> {
    // Check if we're in a git repository
    let git_dir = find_git_dir()?;
    let hooks_dir = git_dir.join("hooks");

    // Default to multiplex mode for per-repo installations
    let should_multiplex = use_multiplex || is_multiplexed(&hooks_dir);

    println!("Installing sss git hooks to: {}", hooks_dir.display());
    if should_multiplex {
        println!("Using multiplexed structure (.d/ directories)");
    }
    println!();

    let (installed_count, skipped_count) =
        install_hooks_to_directory(&hooks_dir, should_multiplex, true)?;

    println!();
    println!(
        "Summary: {installed_count} installed, {skipped_count} skipped"
    );

    if installed_count > 0 {
        println!();
        println!("Hooks installed successfully!");
        println!();
        println!("Note: The post-merge and post-checkout hooks use 'sss render --project',");
        println!("which recursively renders all files in the project.");
        println!("To enable automatic rendering after git operations:");
        println!("  sss project enable render");
    }

    Ok(())
}

/// Install hooks to git template directory (for future clones)
fn install_hooks_to_template(use_multiplex: bool) -> Result<()> {
    use std::process::Command;

    // Check if template directory is already configured
    let template_dir = Command::new("git")
        .args(["config", "--global", "--get", "init.templateDir"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok().map(|s| {
                    let trimmed = s.trim();
                    // Expand tilde
                    if let Some(stripped) = trimmed.strip_prefix("~/") {
                        if let Some(home) = dirs::home_dir() {
                            home.join(stripped)
                        } else {
                            PathBuf::from(trimmed)
                        }
                    } else {
                        PathBuf::from(trimmed)
                    }
                })
            } else {
                None
            }
        });

    let hooks_dir = if let Some(template) = template_dir {
        println!("Found existing git template directory: {}", template.display());
        template.join("hooks")
    } else {
        // No template directory configured, use default
        let default_template = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("sss")
            .join("git-template");

        println!("No git template directory configured.");
        println!("Installing to: {}", default_template.display());
        println!();
        println!("To enable for future clones, run:");
        println!(
            "  git config --global init.templateDir {}",
            default_template.display()
        );
        println!();

        default_template.join("hooks")
    };

    // Check if hooks already exist (Option A: warn and skip unless --multiplex)
    let has_existing_hooks = HOOKS.iter().any(|hook| {
        let flat_path = hooks_dir.join(hook.name);
        let multiplex_path = hooks_dir.join(format!("{}.d/50-sss", hook.name));
        flat_path.exists() || multiplex_path.exists()
    });

    if has_existing_hooks && !use_multiplex {
        println!("Warning: Hooks already exist in template directory.");
        println!("Existing hooks:");
        for hook in HOOKS {
            let flat_path = hooks_dir.join(hook.name);
            let multiplex_path = hooks_dir.join(format!("{}.d/50-sss", hook.name));
            if flat_path.exists() {
                println!("  - {}", hook.name);
            } else if multiplex_path.exists() {
                println!("  - {} (multiplexed)", hook.name);
            }
        }
        println!();
        println!("To install sss hooks, either:");
        println!("  1. Remove existing hooks and run again");
        println!("  2. Use --multiplex to integrate with existing hooks:");
        println!("     sss hooks install --template --multiplex");
        return Err(anyhow!("Template directory already contains hooks"));
    }

    // Check if already multiplexed
    let already_multiplexed = is_multiplexed(&hooks_dir);
    let should_multiplex = use_multiplex || already_multiplexed;

    if should_multiplex {
        println!("Using multiplexed structure (.d/ directories)");
        println!();
    }

    let (installed_count, skipped_count) =
        install_hooks_to_directory(&hooks_dir, should_multiplex, !use_multiplex)?;

    println!();
    println!(
        "Summary: {installed_count} installed, {skipped_count} skipped"
    );

    if installed_count > 0 {
        println!();
        println!("Hooks installed to template directory successfully!");
        println!("These hooks will be copied to all future git clones and inits.");
    }

    Ok(())
}

/// Export hooks to ~/.config/sss/hooks/ for use with git templates or core.hooksPath
fn export_hooks_to_config() -> Result<()> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not determine config directory"))?
        .join("sss")
        .join("hooks");

    // Create hooks directory
    fs::create_dir_all(&config_dir)
        .map_err(|e| anyhow!("Failed to create hooks directory: {e}"))?;

    println!("Exporting sss git hooks to: {}", config_dir.display());
    println!();

    for hook in HOOKS {
        let hook_path = config_dir.join(hook.name);

        // Write hook file
        fs::write(&hook_path, hook.content)
            .map_err(|e| anyhow!("Failed to write hook {}: {}", hook.name, e))?;

        // Make executable (Unix only)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&hook_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)?;
        }

        println!("✓ Exported {} - {}", hook.name, hook.description);
    }

    println!();
    println!("Hooks exported successfully!");
    println!();
    println!("To use these hooks globally, you have two options:");
    println!();
    println!("Option 1: Set global hooks directory (Git 2.9+)");
    println!("  git config --global core.hooksPath {}", config_dir.display());
    println!("  Note: This will override hooks in individual repositories!");
    println!();
    println!("Option 2: Set as template directory");
    println!("  git config --global init.templateDir ~/.config/sss/git-template");
    println!("  mkdir -p ~/.config/sss/git-template/hooks");
    println!("  cp {}/* ~/.config/sss/git-template/hooks/", config_dir.display());
    println!("  Note: Only applies to newly cloned/initialized repositories.");
    println!();
    println!("Option 3: Install per-repository (recommended)");
    println!("  cd /path/to/your/repo");
    println!("  sss hooks install");
    println!();
    println!("Caveats:");
    println!("  • Global hooks (Option 1) apply to ALL repositories, not just sss projects");
    println!("  • The hooks check for 'sss' command and skip gracefully if not in an sss project");
    println!("  • Template directory (Option 2) only affects new repositories");
    println!("  • Per-repository installation (Option 3) gives you full control");

    Ok(())
}

/// Show information about available hooks without installing
fn show_hooks_info() -> Result<()> {
    println!("sss Git Hooks Management");
    println!("========================");
    println!();
    println!("Available commands:");
    println!("  sss hooks install  - Install hooks to current git repository");
    println!("  sss hooks export   - Export hooks to ~/.config/sss/hooks/");
    println!("  sss hooks list     - List available hooks");
    println!("  sss hooks show     - Show hook contents");
    println!();
    println!("Available hooks:");
    for hook in HOOKS {
        println!("  {} - {}", hook.name, hook.description);
    }
    println!();
    println!("For detailed information: sss hooks <command> --help");
    Ok(())
}

/// List all available hooks
fn list_hooks() -> Result<()> {
    println!("Available sss Git Hooks:");
    println!("=======================");
    println!();
    for hook in HOOKS {
        println!("{}", hook.name);
        println!("  Description: {}", hook.description);
        println!("  Lines: {}", hook.content.lines().count());
        println!();
    }
    Ok(())
}

/// Show the contents of a specific hook
fn show_hook(hook_name: &str) -> Result<()> {
    let hook = HOOKS
        .iter()
        .find(|h| h.name == hook_name)
        .ok_or_else(|| anyhow!("Hook '{hook_name}' not found"))?;

    println!("Hook: {}", hook.name);
    println!("Description: {}", hook.description);
    println!("---");
    println!("{}", hook.content);

    Ok(())
}

/// Find the .git directory for the current repository
// Why: git_dir, gitdir_line, gitdir are all distinct git path concepts (git_dir = .git directory path; gitdir_line = first line of .git file in a worktree; gitdir = repository root); intentionally distinct names.
#[allow(clippy::similar_names)]
fn find_git_dir() -> Result<PathBuf> {
    let current_dir = std::env::current_dir()?;
    let mut dir = current_dir.as_path();

    loop {
        let git_dir = dir.join(".git");
        if git_dir.exists() {
            // Handle .git being a file (for worktrees)
            if git_dir.is_file() {
                let content = fs::read_to_string(&git_dir)?;
                if let Some(gitdir_line) = content.lines().find(|l| l.starts_with("gitdir:")) {
                    let gitdir = gitdir_line.trim_start_matches("gitdir:").trim();
                    return Ok(dir.join(gitdir));
                }
            } else if git_dir.is_dir() {
                return Ok(git_dir);
            }
        }

        dir = dir
            .parent()
            .ok_or_else(|| anyhow!("Not in a git repository"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    // RAII guard to restore cwd after a test that mutates it.
    // Phase 16 R-03 cwd-race lesson: every cwd-mutating test must restore.
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

    #[test]
    #[serial]
    fn test_find_git_dir_in_repo() {
        // When this test runs, it should be inside a git repository
        // (the sss project itself is a git repo)
        let result = find_git_dir();
        assert!(result.is_ok());

        let git_dir = result.unwrap();
        assert!(git_dir.exists());
        assert!(git_dir.to_string_lossy().contains(".git"));
    }

    #[test]
    fn test_hook_list_returns_all_hooks() {
        // Verify all expected hooks are in the list
        let hook_names: Vec<&str> = HOOKS.iter().map(|h| h.name).collect();
        assert!(hook_names.contains(&"pre-commit"));
        assert!(hook_names.contains(&"post-merge"));
        assert!(hook_names.contains(&"post-checkout"));

        // Each hook should have non-empty content
        for hook in HOOKS {
            assert!(!hook.content.is_empty());
            // Hooks use perl for compatibility
            assert!(hook.content.starts_with("#!"));
        }
    }

    // ---- 16b-04 Tier 1 in-source tests for hooks.rs helpers ----

    // generate_hook_wrapper coverage

    #[test]
    fn test_generate_hook_wrapper_pre_commit_includes_shebang() {
        let out = generate_hook_wrapper("pre-commit");
        assert!(
            out.starts_with("#!/bin/bash\n"),
            "wrapper must begin with bash shebang; got: {out}"
        );
    }

    #[test]
    fn test_generate_hook_wrapper_post_merge_includes_correct_hook_name() {
        let out = generate_hook_wrapper("post-merge");
        assert!(out.contains("post-merge"), "wrapper must mention post-merge");
        assert!(
            out.contains("post-merge.d"),
            "wrapper must reference the .d directory; got: {out}"
        );
    }

    #[test]
    fn test_generate_hook_wrapper_post_checkout_dispatches_dotd_dir() {
        let out = generate_hook_wrapper("post-checkout");
        // The dispatcher pattern executes every executable inside post-checkout.d/
        assert!(out.contains("hook_dir=\"$(dirname \"$0\")/post-checkout.d\""));
        assert!(out.contains("for hook in \"$hook_dir\"/*"));
        assert!(out.contains("if [ -x \"$hook\" ]"));
    }

    #[test]
    fn test_generate_hook_wrapper_arbitrary_name_substitutes_into_dispatch() {
        // generate_hook_wrapper is a pure formatter — any string flows through.
        let out = generate_hook_wrapper("custom-hook");
        assert!(out.contains("custom-hook"));
        assert!(out.contains("custom-hook.d"));
    }

    // is_multiplexed coverage

    #[test]
    fn test_is_multiplexed_returns_false_on_empty_dir() -> Result<()> {
        let tmp = TempDir::new()?;
        assert!(!is_multiplexed(tmp.path()));
        Ok(())
    }

    #[test]
    fn test_is_multiplexed_returns_true_when_dotd_directory_present() -> Result<()> {
        let tmp = TempDir::new()?;
        // Marker is the existence of a `<hook>.d` directory for any known hook.
        std::fs::create_dir(tmp.path().join("pre-commit.d"))?;
        assert!(is_multiplexed(tmp.path()));
        Ok(())
    }

    #[test]
    fn test_is_multiplexed_ignores_unrelated_dotd_directories() -> Result<()> {
        let tmp = TempDir::new()?;
        // A .d directory whose name does NOT match a known hook must not flip
        // the multiplex flag.
        std::fs::create_dir(tmp.path().join("unrelated.d"))?;
        assert!(!is_multiplexed(tmp.path()));
        Ok(())
    }

    // install_hooks_to_directory coverage

    #[test]
    fn test_install_hooks_to_directory_flat_writes_all_hooks() -> Result<()> {
        let tmp = TempDir::new()?;
        let hooks_dir = tmp.path().join("hooks");
        let (installed, skipped) =
            install_hooks_to_directory(&hooks_dir, false, false)?;
        assert_eq!(installed, 3);
        assert_eq!(skipped, 0);
        for hook in HOOKS {
            let p = hooks_dir.join(hook.name);
            assert!(p.exists(), "missing hook file: {}", hook.name);
        }
        Ok(())
    }

    #[test]
    fn test_install_hooks_to_directory_flat_skips_existing_when_check_set() -> Result<()> {
        let tmp = TempDir::new()?;
        let hooks_dir = tmp.path().join("hooks");
        // Pre-create a colliding file in the hooks dir.
        std::fs::create_dir_all(&hooks_dir)?;
        std::fs::write(hooks_dir.join("pre-commit"), "existing\n")?;
        let (installed, skipped) =
            install_hooks_to_directory(&hooks_dir, false, true)?;
        // pre-commit should be skipped; the other two installed.
        assert_eq!(installed, 2);
        assert_eq!(skipped, 1);
        let preserved = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
        assert_eq!(preserved, "existing\n", "pre-existing hook must be preserved");
        Ok(())
    }

    #[test]
    fn test_install_hooks_to_directory_multiplex_creates_dotd_layout() -> Result<()> {
        let tmp = TempDir::new()?;
        let hooks_dir = tmp.path().join("hooks");
        let (installed, skipped) =
            install_hooks_to_directory(&hooks_dir, true, false)?;
        assert_eq!(installed, 3);
        assert_eq!(skipped, 0);
        for hook in HOOKS {
            let dotd = hooks_dir.join(format!("{}.d", hook.name));
            let wrapper = hooks_dir.join(hook.name);
            let inner = dotd.join("50-sss");
            assert!(dotd.is_dir(), "missing .d dir for {}", hook.name);
            assert!(inner.exists(), "missing 50-sss for {}", hook.name);
            assert!(wrapper.exists(), "missing wrapper for {}", hook.name);
        }
        Ok(())
    }

    #[test]
    fn test_install_hooks_to_directory_multiplex_skips_existing_50_sss() -> Result<()> {
        let tmp = TempDir::new()?;
        let hooks_dir = tmp.path().join("hooks");
        // Pre-create the multiplex layout for pre-commit with a 50-sss collision.
        let dotd = hooks_dir.join("pre-commit.d");
        std::fs::create_dir_all(&dotd)?;
        std::fs::write(dotd.join("50-sss"), "existing-script\n")?;
        let (installed, skipped) =
            install_hooks_to_directory(&hooks_dir, true, true)?;
        // pre-commit.d/50-sss should be skipped; the other two installed.
        assert_eq!(installed, 2);
        assert_eq!(skipped, 1);
        let preserved = std::fs::read_to_string(dotd.join("50-sss"))?;
        assert_eq!(preserved, "existing-script\n");
        Ok(())
    }

    #[test]
    fn test_install_hooks_to_directory_auto_detects_existing_multiplex() -> Result<()> {
        // When use_multiplex=false but the dir is already multiplexed, the
        // function must respect that layout (should_multiplex = false || true).
        let tmp = TempDir::new()?;
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(hooks_dir.join("pre-commit.d"))?;
        let (installed, skipped) =
            install_hooks_to_directory(&hooks_dir, false, false)?;
        assert_eq!(installed, 3);
        assert_eq!(skipped, 0);
        // Because layout was already multiplex, files land under `.d/`.
        assert!(hooks_dir.join("pre-commit.d/50-sss").exists());
        Ok(())
    }

    // export_hooks_to_config coverage — covered indirectly by the existing
    // baseline (the function is fully covered per the audit).  Add a smoke
    // test that exercises the public-byte content of the embedded hooks
    // (regression on hook-content drift).

    #[test]
    fn test_embedded_hook_contents_start_with_shebang() {
        // Every embedded hook must ship with a #! shebang line.  Pre-commit
        // is perl; post-merge and post-checkout are bash.  This regression
        // test guards against accidental binary inclusion or shebang drift.
        for hook in HOOKS {
            let first_line = hook
                .content
                .lines()
                .next()
                .expect("hook must have at least one line");
            assert!(
                first_line.starts_with("#!"),
                "{} must start with a shebang; got: {}",
                hook.name,
                first_line
            );
        }
    }

    // find_git_dir coverage

    #[test]
    #[serial]
    fn test_find_git_dir_in_temp_repo_finds_dotgit_directory() -> Result<()> {
        let _g = CwdGuard::new()?;
        let tmp = TempDir::new()?;
        std::fs::create_dir(tmp.path().join(".git"))?;
        std::env::set_current_dir(tmp.path())?;
        let result = find_git_dir()?;
        // canonicalise both sides so symlink-resolution differences (e.g. /var
        // → /private/var on macOS) don't cause spurious mismatches.
        let got = result.canonicalize()?;
        let want = tmp.path().join(".git").canonicalize()?;
        assert_eq!(got, want);
        Ok(())
    }

    #[test]
    #[serial]
    fn test_find_git_dir_handles_dotgit_file_pointer_for_worktree() -> Result<()> {
        let _g = CwdGuard::new()?;
        let tmp = TempDir::new()?;
        // Where the real .git lives.
        let real_git = tmp.path().join("real-git");
        std::fs::create_dir(&real_git)?;
        // Worktree directory with a .git *file* pointing at real_git.
        let worktree = tmp.path().join("worktree");
        std::fs::create_dir(&worktree)?;
        let pointer = format!("gitdir: {}\n", real_git.display());
        std::fs::write(worktree.join(".git"), pointer)?;
        std::env::set_current_dir(&worktree)?;
        let result = find_git_dir()?;
        // The resolved path joins the worktree with the gitdir line value
        // verbatim — assert the gitdir component shows up.
        assert!(
            result.to_string_lossy().contains(real_git.to_string_lossy().as_ref()),
            "result should contain real_git path; got {result:?}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_find_git_dir_errors_outside_any_repo() -> Result<()> {
        let _g = CwdGuard::new()?;
        // A TempDir under /tmp has no .git in any ancestor (verified at plan
        // time: `/`, `/tmp`, `/var/tmp` have no `.git`).
        let tmp = TempDir::new()?;
        std::env::set_current_dir(tmp.path())?;
        let result = find_git_dir();
        assert!(result.is_err(), "expected error outside repo, got: {result:?}");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("Not in a git repository"),
            "error must mention 'Not in a git repository'; got: {err_str}"
        );
        Ok(())
    }

    // show_hook coverage — error path on unknown hook name.

    #[test]
    fn test_show_hook_unknown_returns_not_found_error() {
        let result = show_hook("absolutely-not-a-real-hook");
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("not found"),
            "error must mention 'not found'; got: {err_str}"
        );
    }

    #[test]
    fn test_show_hook_known_hook_returns_ok() {
        // pre-commit is a known hook from the embedded HOOKS table; show_hook
        // writes to stdout and returns Ok.  We assert only that it succeeds —
        // stdout content isn't worth capturing here since the embedded text
        // is already covered by the test_hook_list_returns_all_hooks check.
        let result = show_hook("pre-commit");
        assert!(result.is_ok());
    }

    // list_hooks / show_hooks_info coverage — no inputs, no failure modes.

    #[test]
    fn test_list_hooks_returns_ok() {
        let result = list_hooks();
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_hooks_info_returns_ok() {
        let result = show_hooks_info();
        assert!(result.is_ok());
    }

    // ---- 16b-04 Tier 1: handle_hooks dispatcher routing ----

    /// Build ArgMatches matching the real `sss hooks <subcommand>` clap tree.
    fn build_hooks_matches(args: &[&str]) -> ArgMatches {
        use clap::{Arg, Command};
        let app = Command::new("hooks")
            .subcommand(
                Command::new("install")
                    .arg(Arg::new("template").long("template").action(clap::ArgAction::SetTrue))
                    .arg(Arg::new("multiplex").long("multiplex").action(clap::ArgAction::SetTrue)),
            )
            .subcommand(Command::new("export"))
            .subcommand(
                Command::new("show").arg(Arg::new("hook").required(false)),
            )
            .subcommand(Command::new("list"));
        app.get_matches_from(args)
    }

    fn empty_main_matches() -> ArgMatches {
        use clap::Command;
        Command::new("sss").get_matches_from(["sss"])
    }

    #[test]
    fn test_handle_hooks_no_subcommand_prints_info() {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks"]);
        let result = handle_hooks(&main, &matches);
        // show_hooks_info() returns Ok — dispatcher must too.
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_hooks_list_routes_to_list_hooks() {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "list"]);
        let result = handle_hooks(&main, &matches);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_hooks_show_with_unknown_hook_returns_error() {
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "show", "absolutely-not-real"]);
        let result = handle_hooks(&main, &matches);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("not found"), "got: {err_str}");
    }

    #[test]
    fn test_handle_hooks_show_without_hook_arg_lists() {
        // When `hook` arg is absent, dispatcher falls back to list_hooks.
        let main = empty_main_matches();
        let matches = build_hooks_matches(&["hooks", "show"]);
        let result = handle_hooks(&main, &matches);
        assert!(result.is_ok());
    }
}
