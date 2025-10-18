use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use std::env;

use sss::commands::{
    handle_agent, handle_edit, handle_hooks, handle_init, handle_keygen_deprecated, handle_keys,
    handle_open, handle_project, handle_render, handle_seal, handle_settings, handle_status,
    handle_users,
};
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
use sss::commands::handle_mount;
#[cfg(feature = "ninep")]
use sss::commands::handle_serve9p;

#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
fn add_fuse_commands(app: Command) -> Command {
    app.subcommand(
        Command::new("mount")
            .about("Mount sss project with transparent rendering (Linux/macOS)")
            .arg(
                Arg::new("source")
                    .help("Source directory (sss project). Defaults to current directory with --in-place")
                    .required_unless_present("in-place"),
            )
            .arg(
                Arg::new("mountpoint")
                    .help("Mountpoint directory. Ignored with --in-place (uses source)")
                    .required_unless_present("in-place"),
            )
            .arg(
                Arg::new("in-place")
                    .long("in-place")
                    .help("Mount over the source directory itself (overlay mount). Uses current directory if source not specified")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("foreground")
                    .long("foreground")
                    .help("Run in foreground (don't daemonize)")
                    .action(clap::ArgAction::SetTrue),
            )
            .arg(
                Arg::new("read-only")
                    .long("read-only")
                    .help("Mount read-only")
                    .action(clap::ArgAction::SetTrue),
            ),
    )
}

#[cfg(not(all(any(target_os = "linux", target_os = "macos"), feature = "fuse")))]
fn add_fuse_commands(app: Command) -> Command {
    app
}

#[cfg(feature = "ninep")]
fn add_ninep_commands(app: Command) -> Command {
    app.subcommand(
        Command::new("serve9p")
            .about("Start 9P server for transparent sss encryption")
            .arg(
                Arg::new("address")
                    .help("Listen address (tcp:host:port or unix:path)")
                    .required(true)
                    .value_parser(clap::value_parser!(String))
                    .help_heading("NETWORK"),
            )
            .arg(
                Arg::new("directory")
                    .short('d')
                    .long("directory")
                    .help("Project directory to export (default: current directory)")
                    .value_parser(clap::value_parser!(String))
                    .help_heading("FILESYSTEM"),
            )
            .arg(
                Arg::new("user")
                    .short('u')
                    .long("user")
                    .help("Username for authentication (default: from settings or prompt)")
                    .value_parser(clap::value_parser!(String))
                    .help_heading("AUTHENTICATION"),
            )
            .after_help(
                "EXAMPLES:\n    \
                 sss serve9p tcp:0.0.0.0:564\n    \
                 sss serve9p unix:/tmp/sss-9p.sock\n    \
                 sss serve9p tcp:localhost:5640 -d /path/to/project -u alice\n\n\
                 MOUNTING:\n    \
                 # Linux (v9fs)\n    \
                 mount -t 9p -o trans=tcp,port=564 127.0.0.1 /mnt/project\n\n    \
                 # Using 9pfuse (macOS/Linux)\n    \
                 9pfuse 'tcp!localhost!564' /mnt/project\n\n\
                 FILE ACCESS MODES:\n    \
                 file         - Rendered view (fully decrypted)\n    \
                 file.open    - Opened view (with ⊕{} markers)\n    \
                 file.sealed  - Sealed view (with ⊠{} markers)"
            ),
    )
}

#[cfg(not(feature = "ninep"))]
fn add_ninep_commands(app: Command) -> Command {
    app
}

fn add_agent_commands(app: Command) -> Command {
    // Agent commands are experimental and require SSS_DEVEL_MODE=1
    if std::env::var("SSS_DEVEL_MODE").unwrap_or_default() != "1" {
        return app;
    }

    app.subcommand(
        Command::new("agent")
            .about("Agent management operations (EXPERIMENTAL)")
            .subcommand(
                Command::new("start")
                    .about("Start the agent daemon")
                    .arg(
                        Arg::new("foreground")
                            .long("foreground")
                            .help("Run in foreground (don't daemonize)")
                            .action(clap::ArgAction::SetTrue),
                    )
                    .arg(
                        Arg::new("key-id")
                            .long("key-id")
                            .value_name("ID")
                            .help("Specific key ID to load"),
                    ),
            )
            .subcommand(Command::new("stop").about("Stop the agent daemon"))
            .subcommand(Command::new("status").about("Check agent status"))
            .subcommand(Command::new("lock").about("Lock agent (deny all requests)"))
            .subcommand(Command::new("unlock").about("Unlock agent"))
            .subcommand(
                Command::new("policies")
                    .about("Manage agent policies")
                    .subcommand(Command::new("list").about("List all policies"))
                    .subcommand(
                        Command::new("add")
                            .about("Add a host to allowed list")
                            .arg(
                                Arg::new("hostname")
                                    .help("Hostname to allow")
                                    .required(true),
                            )
                            .arg(
                                Arg::new("project")
                                    .long("project")
                                    .value_name("PATH")
                                    .help("Restrict to specific project path"),
                            ),
                    )
                    .subcommand(
                        Command::new("remove")
                            .about("Remove a host from policies")
                            .arg(
                                Arg::new("hostname")
                                    .help("Hostname to remove")
                                    .required(true),
                            ),
                    )
                    .subcommand(Command::new("clear").about("Clear all policies")),
            ),
    )
}

fn create_cli_app() -> Command {
    let app = Command::new("sss")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Secret String Substitution - Transparent encryption tool")
        .arg(
            Arg::new("confdir")
                .long("confdir")
                .value_name("DIR")
                .help("Override config directory location")
                .global(true),
        )
        .subcommand(
            Command::new("init").about("Initialize a new project").arg(
                Arg::new("username")
                    .help("Username for the project")
                    .required(false),
            ),
        )
        .subcommand(
            Command::new("keygen")
                .about("Generate a new keypair (deprecated, use 'keys generate')")
                .arg(
                    Arg::new("force")
                        .long("force")
                        .help("Overwrite existing keypair")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("no-password")
                        .long("no-password")
                        .help("Generate keypair without password protection")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("keys")
                .about("Key management operations")
                .subcommand(
                    Command::new("generate")
                        .about("Generate a new keypair")
                        .arg(
                            Arg::new("force")
                                .long("force")
                                .help("Overwrite existing keypair")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-password")
                                .long("no-password")
                                .help("Generate keypair without password protection")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(Command::new("list").about("List your private keys"))
                .subcommand(
                    Command::new("pubkey")
                        .about("Show your public key")
                        .arg(
                            Arg::new("fingerprint")
                                .long("fingerprint")
                                .help("Show key fingerprint instead of full key")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("user")
                                .short('u')
                                .long("user")
                                .value_name("USERNAME")
                                .help("Show public key for a specific user in the project"),
                        ),
                )
                .subcommand(
                    Command::new("delete").about("Delete a keypair").arg(
                        Arg::new("name")
                            .help("Key name or ID to delete")
                            .required(true),
                    ),
                )
                .subcommand(
                    Command::new("current")
                        .about("Show or set current keypair")
                        .arg(
                            Arg::new("name")
                                .help("Key name or ID to set as current")
                                .required(false),
                        ),
                )
                .subcommand(
                    Command::new("rotate")
                        .about("Rotate repository encryption key")
                        .arg(
                            Arg::new("force")
                                .long("force")
                                .help("Skip confirmation prompt")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-backup")
                                .long("no-backup")
                                .help("Skip creating backup files")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .help("Show what would be done without making changes")
                                .action(clap::ArgAction::SetTrue),
                        ),
                ),
        )
        .subcommand(
            Command::new("users")
                .about("User management operations")
                .subcommand(Command::new("list").about("List project users"))
                .subcommand(
                    Command::new("add")
                        .about("Add a user to the project")
                        .arg(Arg::new("username").help("Username to add").required(true))
                        .arg(
                            Arg::new("public-key")
                                .help("User's public key (base64 or file path)")
                                .required(true),
                        ),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a user from the project")
                        .arg(
                            Arg::new("username")
                                .help("Username to remove")
                                .required(true),
                        ),
                )
                .subcommand(
                    Command::new("info")
                        .about("Show information about a user")
                        .arg(
                            Arg::new("username")
                                .help("Username to show info for")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            Command::new("hooks")
                .about("Git hooks management")
                .subcommand(
                    Command::new("install")
                        .about("Install git hooks")
                        .arg(
                            Arg::new("template")
                                .long("template")
                                .help("Install to git template directory (affects future clones)")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("multiplex")
                                .long("multiplex")
                                .help("Use multiplexed hook structure (.d/ directories)")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("export")
                        .about("Export hooks to ~/.config/sss/hooks/"),
                )
                .subcommand(
                    Command::new("list")
                        .about("List available hooks"),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show contents of a specific hook")
                        .arg(
                            Arg::new("hook")
                                .help("Hook name to show")
                                .required(true),
                        ),
                ),
        )
        .subcommand(
            Command::new("settings")
                .about("Manage user settings and preferences")
                .subcommand(Command::new("show").about("Show current settings"))
                .subcommand(
                    Command::new("set")
                        .about("Set configuration values")
                        .arg(
                            Arg::new("username")
                                .long("username")
                                .value_name("USERNAME")
                                .help("Set default username (use 'none' to clear)"),
                        )
                        .arg(
                            Arg::new("editor")
                                .long("editor")
                                .value_name("EDITOR")
                                .help("Set preferred editor (use 'none' to clear)"),
                        )
                        .arg(
                            Arg::new("coloured")
                                .long("coloured")
                                .value_name("BOOL")
                                .value_parser(clap::value_parser!(bool))
                                .help("Enable/disable coloured output"),
                        ),
                )
                .subcommand(
                    Command::new("reset")
                        .about("Reset all settings to defaults")
                        .arg(
                            Arg::new("confirm")
                                .long("confirm")
                                .help("Confirm the reset operation")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(Command::new("location").about("Show configuration file locations")),
        )
        .subcommand(
            Command::new("project")
                .about("Manage project-specific settings")
                .arg(
                    Arg::new("render")
                        .long("render")
                        .help("Enable automatic rendering for this project (shortcut)")
                        .action(clap::ArgAction::SetTrue),
                )
                .subcommand(Command::new("list").about("List all configured projects"))
                .subcommand(Command::new("show").about("Show settings for current project"))
                .subcommand(
                    Command::new("enable")
                        .about("Enable a feature for this project")
                        .arg(
                            Arg::new("feature")
                                .help("Feature to enable (render or open)")
                                .required(true)
                                .value_parser(["render", "open"]),
                        ),
                )
                .subcommand(
                    Command::new("disable")
                        .about("Disable a feature for this project")
                        .arg(
                            Arg::new("feature")
                                .help("Feature to disable (render or open)")
                                .required(true)
                                .value_parser(["render", "open"]),
                        ),
                )
                .subcommand(
                    Command::new("users")
                        .about("Manage project users")
                        .subcommand(Command::new("list").about("List project users"))
                        .subcommand(
                            Command::new("add")
                                .about("Add a user to the project")
                                .arg(Arg::new("username").help("Username to add").required(true))
                                .arg(
                                    Arg::new("public-key")
                                        .help("User's public key (base64 or file path)")
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            Command::new("remove")
                                .about("Remove a user from the project")
                                .arg(
                                    Arg::new("username")
                                        .help("Username to remove")
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            Command::new("info")
                                .about("Show information about a user")
                                .arg(
                                    Arg::new("username")
                                        .help("Username to show info for")
                                        .required(true),
                                ),
                        ),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove project from settings")
                        .arg(
                            Arg::new("path")
                                .help("Project path to remove (default: current project)")
                                .required(false),
                        ),
                )
                .subcommand(
                    Command::new("ignore")
                        .about("Manage ignore patterns for project-wide operations")
                        .subcommand(
                            Command::new("add")
                                .about("Add a glob pattern to ignore list")
                                .arg(
                                    Arg::new("pattern")
                                        .help("Glob pattern to ignore (e.g., '*.log', 'build/**')")
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            Command::new("remove")
                                .about("Remove a pattern from ignore list")
                                .arg(
                                    Arg::new("pattern")
                                        .help("Pattern to remove")
                                        .required(true),
                                ),
                        )
                        .subcommand(Command::new("list").about("Show all ignore patterns")),
                ),
        )
        .subcommand(
            Command::new("status")
                .about("Show SSS project status")
                .long_about("Check if current directory is in an SSS project. Exits 0 with project root path if in project, exits 1 if not in project.")
        )
        .subcommand(
            Command::new("seal")
                .about("Encrypt plaintext markers in file")
                .arg(
                    Arg::new("file")
                        .help("File to process (use '-' for stdin)")
                        .required(true),
                )
                .arg(
                    Arg::new("in-place")
                        .short('x')
                        .long("in-place")
                        .help("Modify file in-place (default: output to stdout)")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("open")
                .about("Decrypt ciphertext to plaintext markers")
                .arg(
                    Arg::new("file")
                        .help("File to process (use '-' for stdin)")
                        .required(true),
                )
                .arg(
                    Arg::new("in-place")
                        .short('x')
                        .long("in-place")
                        .help("Modify file in-place (default: output to stdout)")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("render")
                .about("Decrypt to raw text (remove all markers)")
                .arg(
                    Arg::new("file")
                        .help("File to process (use '-' for stdin)")
                        .required(true),
                )
                .arg(
                    Arg::new("in-place")
                        .short('x')
                        .long("in-place")
                        .help("Modify file in-place (default: output to stdout)")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("edit")
                .about("Edit file with automatic encrypt/decrypt")
                .arg(
                    Arg::new("file")
                        .help("File to edit")
                        .required(true),
                ),
        );

    let app = add_fuse_commands(app);
    let app = add_ninep_commands(app);
    add_agent_commands(app)
}

fn main() -> Result<()> {
    // Special case: if called as "ssse", handle editor mode
    let args: Vec<String> = env::args().collect();
    if let Some(program_name) = args[0].split('/').next_back() {
        if program_name == "ssse" || program_name == "ssse.exe" {
            if args.len() != 2 {
                return Err(anyhow!("Usage: ssse <file>"));
            }
            let file_path = &args[1];
            // Use actual system username instead of hardcoded "default"
            let username = env::var("USER")
                .or_else(|_| env::var("USERNAME"))
                .unwrap_or_else(|_| "user".to_string());

            // Call edit command directly
            let edit_matches = create_cli_app()
                .get_matches_from(vec!["sss", "edit", "--user", &username, file_path]);
            if let Some((_, sub_matches)) = edit_matches.subcommand() {
                return handle_edit(&edit_matches, sub_matches);
            }
            return Err(anyhow!("Failed to process editor mode"));
        }
    }

    let matches = create_cli_app().get_matches();

    // Handle commands
    match matches.subcommand() {
        Some(("init", sub_matches)) => handle_init(&matches, sub_matches),
        Some(("keygen", sub_matches)) => handle_keygen_deprecated(&matches, sub_matches),
        Some(("keys", sub_matches)) => handle_keys(&matches, sub_matches),
        Some(("users", sub_matches)) => handle_users(&matches, sub_matches),
        Some(("hooks", sub_matches)) => handle_hooks(&matches, sub_matches),
        Some(("settings", sub_matches)) => handle_settings(&matches, sub_matches),
        Some(("project", sub_matches)) => handle_project(&matches, sub_matches),
        Some(("agent", sub_matches)) => handle_agent(sub_matches),
        Some(("status", _)) => handle_status(&matches),
        Some(("seal", sub_matches)) => handle_seal(&matches, sub_matches),
        Some(("open", sub_matches)) => handle_open(&matches, sub_matches),
        Some(("render", sub_matches)) => handle_render(&matches, sub_matches),
        Some(("edit", sub_matches)) => handle_edit(&matches, sub_matches),
        #[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
        Some(("mount", sub_matches)) => handle_mount(&matches, sub_matches),
        #[cfg(feature = "ninep")]
        Some(("serve9p", sub_matches)) => handle_serve9p(sub_matches),
        None => {
            // No subcommand - show help
            let mut app = create_cli_app();
            app.print_help()?;
            println!();
            Ok(())
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_cli_app_has_expected_structure() {
        let app = create_cli_app();

        // Verify app name and version
        assert_eq!(app.get_name(), "sss");
        assert_eq!(app.get_version(), Some(env!("CARGO_PKG_VERSION")));

        // Verify global arguments
        let confdir_arg = app.get_arguments().find(|a| a.get_id() == "confdir");
        assert!(confdir_arg.is_some(), "confdir global argument should exist");
    }

    #[test]
    fn test_create_cli_app_has_core_subcommands() {
        let app = create_cli_app();

        // Core subcommands that should always be present
        let subcommands: Vec<_> = app.get_subcommands().map(|s| s.get_name()).collect();

        assert!(subcommands.contains(&"init"), "init subcommand should exist");
        assert!(subcommands.contains(&"keys"), "keys subcommand should exist");
        assert!(subcommands.contains(&"status"), "status subcommand should exist");
        assert!(subcommands.contains(&"seal"), "seal subcommand should exist");
        assert!(subcommands.contains(&"open"), "open subcommand should exist");
        assert!(subcommands.contains(&"render"), "render subcommand should exist");
        assert!(subcommands.contains(&"edit"), "edit subcommand should exist");
        assert!(subcommands.contains(&"project"), "project subcommand should exist");
        assert!(subcommands.contains(&"settings"), "settings subcommand should exist");
        assert!(subcommands.contains(&"hooks"), "hooks subcommand should exist");
    }

    #[test]
    #[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
    fn test_fuse_commands_available_when_enabled() {
        let app = create_cli_app();
        let subcommands: Vec<_> = app.get_subcommands().map(|s| s.get_name()).collect();

        assert!(subcommands.contains(&"mount"), "mount subcommand should exist with fuse feature on Linux/macOS");
    }

    #[test]
    #[cfg(not(all(any(target_os = "linux", target_os = "macos"), feature = "fuse")))]
    fn test_fuse_commands_unavailable_when_disabled() {
        let app = create_cli_app();
        let subcommands: Vec<_> = app.get_subcommands().map(|s| s.get_name()).collect();

        assert!(!subcommands.contains(&"mount"), "mount subcommand should not exist without fuse feature");
    }

    #[test]
    #[cfg(feature = "ninep")]
    fn test_ninep_commands_available_when_enabled() {
        let app = create_cli_app();
        let subcommands: Vec<_> = app.get_subcommands().map(|s| s.get_name()).collect();

        assert!(subcommands.contains(&"serve9p"), "serve9p subcommand should exist with ninep feature");
    }

    #[test]
    #[cfg(not(feature = "ninep"))]
    fn test_ninep_commands_unavailable_when_disabled() {
        let app = create_cli_app();
        let subcommands: Vec<_> = app.get_subcommands().map(|s| s.get_name()).collect();

        assert!(!subcommands.contains(&"serve9p"), "serve9p subcommand should not exist without ninep feature");
    }

    #[test]
    fn test_deprecated_keygen_command_exists() {
        let app = create_cli_app();
        let subcommands: Vec<_> = app.get_subcommands().map(|s| s.get_name()).collect();

        // Verify deprecated keygen command still exists for backwards compatibility
        assert!(subcommands.contains(&"keygen"), "deprecated keygen subcommand should exist");
    }

    // Note: The main() function and command routing logic are tested via integration tests.
    // These unit tests verify the CLI structure is correctly built.
}
