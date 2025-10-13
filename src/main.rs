use anyhow::{anyhow, Result};
use clap::{Arg, Command};
use std::env;

use sss::commands::{
    handle_agent, handle_edit, handle_init, handle_keygen_deprecated, handle_keys, handle_open,
    handle_process, handle_render, handle_seal, handle_settings, handle_status, handle_users,
};

fn create_cli_app() -> Command {
    Command::new("sss")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Secret String Substitution - Transparent encryption tool")
        .arg(
            Arg::new("confdir")
                .long("confdir")
                .value_name("DIR")
                .help("Override config directory location")
                .global(true),
        )
        .arg(
            Arg::new("file")
                .value_name("FILE")
                .help("File to process (use '-' for stdin)")
                .required(false),
        )
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .value_name("USERNAME")
                .help("Username or alias for encryption/decryption"),
        )
        .arg(
            Arg::new("in-place")
                .short('x')
                .long("in-place")
                .help("Modify file in-place")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("render")
                .conflicts_with("edit"),
        )
        .arg(
            Arg::new("render")
                .short('r')
                .long("render")
                .help("Render encrypted content to raw text")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("in-place")
                .conflicts_with("edit"),
        )
        .arg(
            Arg::new("edit")
                .short('e')
                .long("edit")
                .help("Edit file with automatic encrypt/decrypt")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("in-place")
                .conflicts_with("render"),
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
                    Command::new("pubkey").about("Show your public key").arg(
                        Arg::new("fingerprint")
                            .long("fingerprint")
                            .help("Show key fingerprint instead of full key")
                            .action(clap::ArgAction::SetTrue),
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
                            Arg::new("colored")
                                .long("colored")
                                .value_name("BOOL")
                                .value_parser(clap::value_parser!(bool))
                                .help("Enable/disable colored output"),
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
            Command::new("agent")
                .about("Agent management operations")
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
                    Arg::new("user")
                        .short('u')
                        .long("user")
                        .value_name("USERNAME")
                        .help("Username for encryption"),
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
                    Arg::new("user")
                        .short('u')
                        .long("user")
                        .value_name("USERNAME")
                        .help("Username for decryption"),
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
                    Arg::new("user")
                        .short('u')
                        .long("user")
                        .value_name("USERNAME")
                        .help("Username for decryption"),
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
                )
                .arg(
                    Arg::new("user")
                        .short('u')
                        .long("user")
                        .value_name("USERNAME")
                        .help("Username for encryption/decryption"),
                ),
        )
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

            // Create a minimal ArgMatches for editor mode
            let dummy_matches = create_cli_app()
                .get_matches_from(vec!["sss", "--user", &username, "--edit", file_path]);
            return handle_process(&dummy_matches);
        }
    }

    let matches = create_cli_app().get_matches();

    // Handle commands
    match matches.subcommand() {
        Some(("init", sub_matches)) => handle_init(&matches, sub_matches),
        Some(("keygen", sub_matches)) => handle_keygen_deprecated(&matches, sub_matches),
        Some(("keys", sub_matches)) => handle_keys(&matches, sub_matches),
        Some(("users", sub_matches)) => handle_users(&matches, sub_matches),
        Some(("settings", sub_matches)) => handle_settings(&matches, sub_matches),
        Some(("agent", sub_matches)) => handle_agent(sub_matches),
        Some(("status", _)) => handle_status(&matches),
        Some(("seal", sub_matches)) => handle_seal(&matches, sub_matches),
        Some(("open", sub_matches)) => handle_open(&matches, sub_matches),
        Some(("render", sub_matches)) => handle_render(&matches, sub_matches),
        Some(("edit", sub_matches)) => handle_edit(&matches, sub_matches),
        None => {
            // Handle file processing (legacy mode)
            if matches.get_one::<String>("file").is_some() {
                handle_process(&matches)
            } else {
                // No file and no subcommand - show help
                let mut app = create_cli_app();
                app.print_help()?;
                println!();
                Ok(())
            }
        }
        _ => unreachable!(),
    }
}
