use anyhow::Result;
use clap::ArgMatches;
use std::path::PathBuf;

use crate::aliases::AliasManager;

/// Create alias manager instance based on global confdir parameter
fn create_alias_manager(matches: &ArgMatches) -> Result<AliasManager> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        AliasManager::new_with_config_dir(PathBuf::from(confdir))
    } else {
        AliasManager::new()
    }
}

pub fn handle_aliases(
    main_matches: &ArgMatches,
    matches: &ArgMatches,
) -> Result<()> {
    let alias_manager = create_alias_manager(main_matches)?;

    match matches.subcommand() {
        Some(("list", _)) => {
            let aliases = alias_manager.list_aliases()?;
            if aliases.is_empty() {
                println!("No aliases configured");
            } else {
                println!("Configured aliases:");
                for (alias, username) in aliases {
                    println!("  {} -> {}", alias, username);
                }
            }
        }
        Some(("add", sub_matches)) => {
            let alias = sub_matches.get_one::<String>("alias").unwrap();
            let username = sub_matches.get_one::<String>("username").unwrap();

            alias_manager.add_alias(alias, username)?;
            println!("Added alias '{}' -> '{}'", alias, username);
        }
        Some(("remove", sub_matches)) => {
            let alias = sub_matches.get_one::<String>("alias").unwrap();

            alias_manager.remove_alias(alias)?;
            println!("Removed alias '{}'", alias);
        }
        None => {
            // No subcommand provided, show available subcommands
            eprintln!("Error: No subcommand provided");
            eprintln!();
            eprintln!("Available subcommands:");
            eprintln!("  list        List user aliases");
            eprintln!("  add         Add new alias");
            eprintln!("  remove      Remove alias");
            eprintln!();
            eprintln!("Use 'sss aliases <subcommand> --help' for more information on a subcommand.");
            std::process::exit(1);
        }
        _ => unreachable!(),
    }

    Ok(())
}