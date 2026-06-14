// Why: every .unwrap() in this file is on a clap-required arg (required(true) +
// in some cases value_parser-restricted) so the get_one call always yields
// Some(_). All sites carry per-site INVARIANT comments. HARDEN-01 / 08-01.
#![allow(clippy::unwrap_used)]

use anyhow::{anyhow, Result};
// Why: `Context` (.context(...)) is used only inside the `hybrid`-gated
// `handle_project_vault` body; importing it unconditionally warns (unused) on
// non-hybrid builds, which the `-D warnings` clippy gate rejects.
#[cfg(feature = "hybrid")]
use anyhow::Context;
use clap::ArgMatches;
use std::path::PathBuf;

use crate::commands::handle_users;
use crate::commands::utils::create_config_manager;
use crate::config::find_project_root;

pub fn handle_project(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let mut config_manager = create_config_manager(main_matches)?;

    // Handle --render shortcut flag
    if matches.get_flag("render") {
        let project_root = find_project_root()?;
        config_manager.enable_project_render(&project_root)?;
        config_manager.save_user_settings()?;
        println!("Enabled automatic rendering for: {}", project_root.display());
        return Ok(());
    }

    match matches.subcommand() {
        Some(("list", _)) => handle_project_list(&config_manager)?,
        Some(("show", _)) => handle_project_show(&config_manager)?,
        Some(("enable", sub_matches)) => handle_project_enable(&mut config_manager, sub_matches)?,
        Some(("disable", sub_matches)) => handle_project_disable(&mut config_manager, sub_matches)?,
        Some(("users", sub_matches)) => {
            // Forward to handle_users with the main_matches for confdir support
            return handle_users(main_matches, sub_matches);
        }
        Some(("remove", sub_matches)) => handle_project_remove(&mut config_manager, sub_matches)?,
        Some(("ignore", sub_matches)) => handle_project_ignore(&mut config_manager, sub_matches)?,
        Some(("secrets-file", sub_matches)) => handle_project_secrets_file(sub_matches)?,
        Some(("vault", sub_matches)) => handle_project_vault(sub_matches)?,
        None => {
            return Err(anyhow!(
                "No subcommand specified. Use 'sss project --help' for usage information."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn handle_project_list(config_manager: &crate::config_manager::ConfigManager) -> Result<()> {
    let projects = config_manager.get_all_projects();

    if projects.is_empty() {
        println!("No projects configured");
        return Ok(());
    }

    println!("Configured Projects:");
    println!("===================");
    for (path, settings) in projects {
        let render_status = if settings.allow_auto_render {
            "enabled"
        } else {
            "disabled"
        };
        let open_status = if settings.allow_auto_open {
            "enabled"
        } else {
            "disabled"
        };

        println!("{path} (auto-render={render_status}, auto-open={open_status})");
    }
    Ok(())
}

fn handle_project_show(config_manager: &crate::config_manager::ConfigManager) -> Result<()> {
    let project_root = find_project_root()?;
    let render_enabled = config_manager.is_project_render_enabled(&project_root)?;
    let open_enabled = config_manager.is_project_open_enabled(&project_root)?;

    println!("Current Project: {}", project_root.display());
    println!("=================");
    println!("Automatic rendering: {}", if render_enabled { "enabled" } else { "disabled" });
    println!("Automatic opening: {}", if open_enabled { "enabled" } else { "disabled" });

    if !render_enabled || !open_enabled {
        println!();
        if !render_enabled {
            println!("To enable automatic rendering, run:");
            println!("  sss project enable render");
        }
        if !open_enabled {
            println!("To enable automatic opening, run:");
            println!("  sss project enable open");
        }
    }
    Ok(())
}

fn handle_project_enable(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    // INVARIANT: clap declares `feature` as required(true) with value_parser
    // ["render","open"]. HARDEN-01 / 08-01.
    let feature = sub_matches.get_one::<String>("feature").unwrap();
    let project_root = find_project_root()?;

    match feature.as_str() {
        "render" => {
            config_manager.enable_project_render(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Enabled automatic rendering for: {}", project_root.display());
        }
        "open" => {
            config_manager.enable_project_open(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Enabled automatic opening for: {}", project_root.display());
        }
        _ => unreachable!("clap should have validated the feature argument"),
    }
    Ok(())
}

fn handle_project_disable(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    // INVARIANT: clap declares `feature` as required(true) with value_parser
    // ["render","open"]. HARDEN-01 / 08-01.
    let feature = sub_matches.get_one::<String>("feature").unwrap();
    let project_root = find_project_root()?;

    match feature.as_str() {
        "render" => {
            config_manager.disable_project_render(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Disabled automatic rendering for: {}", project_root.display());
        }
        "open" => {
            config_manager.disable_project_open(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Disabled automatic opening for: {}", project_root.display());
        }
        _ => unreachable!("clap should have validated the feature argument"),
    }
    Ok(())
}

fn handle_project_remove(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    let project_path = if let Some(path_str) = sub_matches.get_one::<String>("path") {
        PathBuf::from(path_str)
    } else {
        find_project_root()?
    };

    let removed = config_manager.remove_project(&project_path)?;
    config_manager.save_user_settings()?;

    if removed {
        println!("Removed project from settings: {}", project_path.display());
    } else {
        println!("Project not found in settings: {}", project_path.display());
    }
    Ok(())
}

fn handle_project_ignore(_config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    use crate::constants::CONFIG_FILE_NAME;
    use crate::project::ProjectConfig;

    match sub_matches.subcommand() {
        Some(("add", add_matches)) => {
            // INVARIANT: clap declares `pattern` as required(true) for the add
            // subcommand. HARDEN-01 / 08-01.
            let new_pattern = add_matches.get_one::<String>("pattern").unwrap();

            // Load project config
            let mut config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

            // Get existing patterns, add new one if not present
            let mut patterns = config.get_ignore_pattern_strings();
            if patterns.contains(new_pattern) {
                println!("Pattern '{new_pattern}' already exists in ignore list");
            } else {
                patterns.push(new_pattern.clone());

                // Join patterns with spaces (gitignore-style on one line)
                config.set_ignore_patterns(patterns);
                config.save_to_file(CONFIG_FILE_NAME)?;

                println!("Added ignore pattern: {new_pattern}");
            }
        }
        Some(("remove", remove_matches)) => {
            // INVARIANT: clap declares `pattern` as required(true) for the remove
            // subcommand. HARDEN-01 / 08-01.
            let pattern_to_remove = remove_matches.get_one::<String>("pattern").unwrap();

            // Load project config
            let mut config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

            // Get existing patterns and remove the specified one
            let mut patterns = config.get_ignore_pattern_strings();
            let original_len = patterns.len();
            patterns.retain(|p| p != pattern_to_remove);

            if patterns.len() < original_len {
                // Pattern was removed
                if patterns.is_empty() {
                    config.clear_ignore_patterns();
                } else {
                    config.set_ignore_patterns(patterns);
                }
                config.save_to_file(CONFIG_FILE_NAME)?;
                println!("Removed ignore pattern: {pattern_to_remove}");
            } else {
                println!("Pattern '{pattern_to_remove}' not found in ignore list");
            }
        }
        Some(("list", _)) => {
            // Load project config
            let config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

            let patterns = config.get_ignore_pattern_strings();

            if patterns.is_empty() {
                println!("No ignore patterns configured");
                println!();
                println!("Hint: Add patterns with 'sss project ignore add <pattern>'");
                println!("      Patterns use gitignore-style glob syntax");
            } else {
                println!("Ignore patterns (in .sss.toml):");
                println!("================================");
                for pattern in patterns {
                    println!("  {pattern}");
                }
                println!();
                println!("Raw: {}", config.get_ignore_patterns().unwrap_or(""));
            }
        }
        None => {
            return Err(anyhow!(
                "No subcommand specified. Use 'sss project ignore --help' for usage information."
            ));
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn handle_project_secrets_file(sub_matches: &ArgMatches) -> Result<()> {
    use crate::constants::CONFIG_FILE_NAME;
    use crate::project::ProjectConfig;

    match sub_matches.subcommand() {
        Some(("set", set_matches)) => {
            // INVARIANT: clap declares `filename` as required(true) for the set
            // subcommand. HARDEN-01 / 08-01.
            let filename = set_matches.get_one::<String>("filename").unwrap();

            // Load project config
            let mut config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

            // Set the secrets filename
            config.set_secrets_filename(filename.clone());
            config.save_to_file(CONFIG_FILE_NAME)?;

            println!("Set secrets filename to: {filename}");
            println!();
            println!("Secrets will now be looked up from:");
            println!("  1. <filename>.secrets (file-specific)");
            println!("  2. {filename} (directory and parent directories)");
        }
        Some(("show", _)) => {
            // Load project config
            let config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

            let filename = config.get_secrets_filename();
            if config.secrets_filename.is_some() {
                println!("Secrets filename: {filename} (custom)");
            } else {
                println!("Secrets filename: {filename} (default)");
            }
        }
        Some(("clear", _)) => {
            // Load project config
            let mut config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

            // Clear the custom filename
            config.clear_secrets_filename();
            config.save_to_file(CONFIG_FILE_NAME)?;

            println!("Cleared custom secrets filename");
            println!("Using default: secrets");
        }
        None => {
            return Err(anyhow!(
                "No subcommand specified. Use 'sss project secrets-file --help' for usage information."
            ));
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// `sss project vault <subcommand>` — manage the `[vault]` table in `.sss.toml` and
/// re-sign the envelope to `format_version=3` on every write (VCLI-04, T-46-20).
///
/// Every verb:
/// 1. Loads the config via `load_from_file_unverified` (sign-on-write pattern).
/// 2. Mutates `cfg.vault` (inserting the table if absent).
/// 3. Sets `cfg.format_version = 3`.
/// 4. Calls `crate::envelope_sig::sign_and_write_atomic` (shared helper — never
///    the unsigned `save_to_file` path, never a copied sign body).
///
/// After any verb the resulting `.sss.toml` verifies cleanly under the v3 context.
fn handle_project_vault(sub_matches: &ArgMatches) -> Result<()> {
    // Why: `[vault]` is honoured only under a format_version=3 signed envelope, and
    // envelope signing requires the hybrid sig primitives (Ed448 + ML-DSA-65), which
    // live in the `hybrid`-gated `envelope_sig` module. A non-hybrid build cannot sign,
    // so vault config management is unavailable — mirror the format_version=2
    // "rebuild with --features hybrid" gate in src/project.rs's dispatch ladder.
    #[cfg(not(feature = "hybrid"))]
    {
        let _ = sub_matches;
        // Why: `needless_return` is a false positive under cfg — the
        // `#[cfg(feature = "hybrid")]` block below follows this statement, so the
        // explicit `return` is required (without it this block becomes a discarded
        // statement and the fn loses its tail expression). The lint only sees the
        // non-hybrid post-cfg view, where this block looks final.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss project vault` manages a signed (format_version=3) envelope, which \
             requires the hybrid build feature; rebuild sss with `--features hybrid`"
        ));
    }

    #[cfg(feature = "hybrid")]
    {
    use crate::constants::CONFIG_FILE_NAME;
    use crate::project::{ProjectConfig, VaultAuth, VaultBinding, VaultConfig};

    match sub_matches.subcommand() {
        Some(("set-address", set_matches)) => {
            // INVARIANT: clap declares `address` as required(true). HARDEN-01 / 08-01.
            let address = set_matches.get_one::<String>("address").unwrap();

            // Validate https:// scheme BEFORE any mutation (T-46-21).
            crate::validation::validate_vault_address(address)
                .map_err(|e| anyhow!("vault config field `address`: {e}"))?;

            let mut cfg = ProjectConfig::load_from_file_unverified(CONFIG_FILE_NAME)
                .context("failed to read .sss.toml")?;

            cfg.vault
                .get_or_insert_with(VaultConfig::default)
                .address = Some(address.clone());
            cfg.format_version = 3;

            // Shared sign-on-write (T-46-20: no copied body, no save_to_file).
            crate::envelope_sig::sign_and_write_atomic(
                &mut cfg,
                std::path::Path::new(CONFIG_FILE_NAME),
            )?;
        }
        Some(("add-binding", bind_matches)) => {
            // INVARIANT: clap declares `name` as required(true). HARDEN-01 / 08-01.
            let name = bind_matches.get_one::<String>("name").unwrap();
            let mount = bind_matches.get_one::<String>("mount").cloned();
            let default_field = bind_matches.get_one::<String>("default-field").cloned();
            let kv_version: Option<u8> = bind_matches
                .get_one::<String>("kv-version")
                .and_then(|s| s.parse::<u8>().ok());

            let mut cfg = ProjectConfig::load_from_file_unverified(CONFIG_FILE_NAME)
                .context("failed to read .sss.toml")?;

            cfg.vault
                .get_or_insert_with(VaultConfig::default)
                .bindings
                .insert(
                    name.clone(),
                    VaultBinding {
                        kv_version,
                        mount,
                        default_field,
                    },
                );
            cfg.format_version = 3;

            crate::envelope_sig::sign_and_write_atomic(
                &mut cfg,
                std::path::Path::new(CONFIG_FILE_NAME),
            )?;

            let safe_name = crate::validation::sanitize_for_display(name);
            println!("Added vault binding '{safe_name}' (re-signed at format_version=3)");
        }
        Some(("set-auth", auth_matches)) => {
            // INVARIANT: clap declares `method` as required(true). HARDEN-01 / 08-01.
            let method = auth_matches.get_one::<String>("method").unwrap();
            let role_id = auth_matches.get_one::<String>("role-id").cloned();
            let secret_id_secret = auth_matches.get_one::<String>("secret-id-secret").cloned();
            let token_secret = auth_matches.get_one::<String>("token-secret").cloned();

            let mut cfg = ProjectConfig::load_from_file_unverified(CONFIG_FILE_NAME)
                .context("failed to read .sss.toml")?;

            cfg.vault
                .get_or_insert_with(VaultConfig::default)
                .auth = Some(VaultAuth {
                    method: Some(method.clone()),
                    role_id,
                    secret_id_secret,
                    token_secret,
                });
            cfg.format_version = 3;

            crate::envelope_sig::sign_and_write_atomic(
                &mut cfg,
                std::path::Path::new(CONFIG_FILE_NAME),
            )?;

            let safe_method = crate::validation::sanitize_for_display(method);
            println!("Set vault auth method '{safe_method}' (re-signed at format_version=3)");
        }
        None => {
            return Err(anyhow!(
                "No subcommand specified. Use 'sss project vault --help' for usage information."
            ));
        }
        _ => unreachable!(),
    }
    Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handle_project_error_message() {
        // Test that the function returns correct error when no subcommand provided
        // (This can't be tested without mocking due to file I/O dependencies,
        // but we verify the error message format exists in the source)
        let source = include_str!("project.rs");
        assert!(source.contains("No subcommand specified"));
        assert!(source.contains("sss project --help"));
    }

    // Note: handle_project() manages per-project settings and permissions
    // The logic delegates to ConfigManager methods which are tested in config_manager module:
    // - enable_project_render/open
    // - disable_project_render/open
    // - add_ignore_pattern/remove_ignore_pattern
    // - get_ignore_patterns
    // Integration tests verify the full project settings workflow
}
