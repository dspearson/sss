use anyhow::Result;
use clap::ArgMatches;
use std::process;

use crate::config::find_project_root;

pub fn handle_status(_matches: &ArgMatches) -> Result<()> {
    match find_project_root() {
        Ok(project_root) => {
            // Project found - print the path and exit with code 0
            println!("{}", project_root.display());
            process::exit(0);
        }
        Err(_) => {
            // No project found - exit with code 1
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    // Note: handle_status() calls process::exit() which makes it difficult to unit test
    // directly. The function is simple and delegates to find_project_root() which is
    // tested in the config module. Integration tests verify the full behavior.
}
