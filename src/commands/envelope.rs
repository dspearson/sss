//! `sss envelope` subcommand group (Phase 19, D-11, PQSIG-06).
//!
//! Exposes: `sss envelope upgrade-sig`, which retro-fits a hybrid AND-composition
//! signature onto a legacy un-signed (`format_version=1`) `.sss.toml` envelope,
//! promoting it to `format_version=2` (no vault) or `format_version=3` (vault
//! present) atomically. Idempotent; refuses a silent version downgrade.
//!
//! Future verbs (rotate-sig, dump-sig) can join this group cleanly per D-11.

use anyhow::{anyhow, Context, Result};

use crate::project::ProjectConfig;

/// Dispatch `sss envelope <subcommand>` from `main.rs`.
///
/// `sub_matches` is the `ArgMatches` for the `envelope` subcommand; inspect its
/// subcommand to pick the right handler.
pub fn handle_envelope(
    _main_matches: &clap::ArgMatches,
    sub_matches: &clap::ArgMatches,
) -> Result<()> {
    match sub_matches.subcommand() {
        Some(("upgrade-sig", _)) => handle_envelope_upgrade_sig(),
        Some((unknown, _)) => Err(anyhow!("unknown envelope subcommand: {unknown}")),
        None => {
            eprintln!("Usage: sss envelope <subcommand>");
            eprintln!("Available subcommands: upgrade-sig");
            Err(anyhow!("no envelope subcommand provided"))
        }
    }
}

/// `sss envelope upgrade-sig` — retro-fit a hybrid signature onto a v1 envelope.
///
/// ## Version selection (VCFG-04)
///
/// - `[vault]` table absent → target `format_version = 2` (classic signed envelope).
/// - `[vault]` table present → target `format_version = 3` (vault-fields covered).
///
/// ## Idempotency
///
/// If the current version already equals the target, prints "already signed at
/// `format_version={N}`; nothing to do" and exits 0 without touching the file
/// (mtime preserved).
///
/// ## Downgrade rejection
///
/// If the current version EXCEEDS the target (e.g. a v3 file whose `[vault]` table
/// was removed so the target would now be 2) this command returns a non-zero error
/// instructing the user to act — the file is left unchanged (T-46-23).
fn handle_envelope_upgrade_sig() -> Result<()> {
    let config_path = crate::config::get_project_config_path()
        .context("could not locate .sss.toml in current or parent directory")?;

    // Use load_from_file_unverified so we can read a v1 OR a v2 envelope that
    // the production loader would reject (e.g. hybrid v1, or a v2 sig under the
    // old context that is being re-signed to v3).  The whole point of upgrade-sig
    // is to read the raw state and THEN sign it correctly.
    let mut cfg = ProjectConfig::load_from_file_unverified(&config_path)
        .context("failed to read .sss.toml")?;

    // Target version depends on whether a [vault] table is present (VCFG-04).
    let target_version: u32 = if cfg.vault.is_some() { 3 } else { 2 };

    // Idempotency: already at the correct target version → clean exit, no file touch.
    if cfg.format_version == target_version {
        println!(
            "{}: already signed at format_version={}; nothing to do",
            config_path.display(),
            target_version
        );
        return Ok(());
    }

    // Downgrade guard (T-46-23): refuse a silent version downgrade.
    // Example: file is v3 (has [vault]), user removed [vault] manually → target
    // would be 2, but we must NOT silently strip vault-field coverage.
    if cfg.format_version > target_version {
        return Err(anyhow!(
            "{}: current format_version={} exceeds target {}; \
            to downgrade, remove [vault] from .sss.toml first and confirm you \
            want to lose vault-field signature coverage",
            config_path.display(),
            cfg.format_version,
            target_version,
        ));
    }

    // Promote to the target version and delegate all sign-on-write work to the
    // shared helper (T-46-20: no copied sign body, no unsigned write path).
    cfg.format_version = target_version;
    crate::envelope_sig::sign_and_write_atomic(&mut cfg, &config_path)?;

    Ok(())
}
