pub mod agent;
pub mod hooks;
pub mod init;
pub mod keys;
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub mod mount;
#[cfg(feature = "ninep")]
pub mod ninep;
pub mod process;
pub mod project;
pub mod settings;
pub mod status;
pub mod users;
pub mod utils;

pub use agent::handle_agent;
pub use hooks::handle_hooks;
pub use init::handle_init;
pub use keys::{handle_keygen_deprecated, handle_keys};
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub use mount::handle_mount;
#[cfg(feature = "ninep")]
pub use ninep::handle_serve9p;
pub use process::{handle_edit, handle_open, handle_process, handle_render, handle_seal};
pub use project::handle_project;
pub use settings::handle_settings;
pub use status::handle_status;
pub use users::handle_users;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_exports_available() {
        // This module just re-exports command handlers
        // Verify the core exports are accessible (compile-time check)

        // Two-parameter handlers (main_matches, sub_matches)
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_init;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_keys;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_users;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_project;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_settings;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_hooks;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_seal;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_open;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_render;
        let _: fn(&clap::ArgMatches, &clap::ArgMatches) -> anyhow::Result<()> = handle_edit;

        // Single-parameter handlers (matches only)
        let _: fn(&clap::ArgMatches) -> anyhow::Result<()> = handle_agent;
        let _: fn(&clap::ArgMatches) -> anyhow::Result<()> = handle_status;
        let _: fn(&clap::ArgMatches) -> anyhow::Result<()> = handle_process;
    }
}
