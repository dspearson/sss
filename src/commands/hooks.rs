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
"#,
        hook_name = hook_name
    )
}

/// Check if a hooks directory is already using multiplexed structure
fn is_multiplexed(hooks_dir: &Path) -> bool {
    HOOKS
        .iter()
        .any(|hook| hooks_dir.join(format!("{}.d", hook.name)).is_dir())
}

/// Install hooks to a directory with multiplex support
fn install_hooks_to_directory(
    hooks_dir: &PathBuf,
    use_multiplex: bool,
    check_existing: bool,
) -> Result<(usize, usize)> {
    fs::create_dir_all(hooks_dir)
        .map_err(|e| anyhow!("Failed to create hooks directory: {}", e))?;

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
        "Summary: {} installed, {} skipped",
        installed_count, skipped_count
    );

    if installed_count > 0 {
        println!();
        println!("Hooks installed successfully!");
        println!();
        println!("Note: The post-merge and post-checkout hooks use 'sss render --project',");
        println!("which requires project permission. To enable automatic rendering:");
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
        "Summary: {} installed, {} skipped",
        installed_count, skipped_count
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
        .map_err(|e| anyhow!("Failed to create hooks directory: {}", e))?;

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
        .ok_or_else(|| anyhow!("Hook '{}' not found", hook_name))?;

    println!("Hook: {}", hook.name);
    println!("Description: {}", hook.description);
    println!("---");
    println!("{}", hook.content);

    Ok(())
}

/// Find the .git directory for the current repository
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

    #[test]
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

    // Note: Most of handle_hooks() involves:
    // - File I/O to write hooks to .git/hooks/
    // - Setting executable permissions
    // - Reading embedded hook content
    // Integration tests verify the full hook installation workflow
}
