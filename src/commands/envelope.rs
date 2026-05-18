//! `sss envelope` subcommand group (Phase 19, D-11, PQSIG-06).
//!
//! Currently exposes a single verb: `sss envelope upgrade-sig`, which retro-fits
//! a hybrid AND-composition signature onto a legacy un-signed (`format_version=1`)
//! `.sss.toml` envelope, promoting it to `format_version=2` in place, atomically.
//!
//! Future verbs (rotate-sig, dump-sig) can join this group cleanly per D-11.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

use crate::commands::utils::{get_password_if_protected, get_system_username};
use crate::config::write_atomic;
use crate::envelope_sig;
use crate::keystore::Keystore;
use crate::project::{EnvelopeMeta, ProjectConfig};

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
/// Idempotency: if `format_version >= 2` the envelope is already signed; prints a
/// one-liner and exits 0 without touching the file. The on-disk bytes are left
/// byte-identical so `mtime` is preserved across re-runs.
fn handle_envelope_upgrade_sig() -> Result<()> {
    let config_path = crate::config::get_project_config_path()
        .context("could not locate .sss.toml in current or parent directory")?;

    // Load via the production loader.
    //   format_version == 1, classic: Ok — no sig enforced.
    //   format_version == 1, hybrid:  Err — PQSIG-06 actionable error (correct
    //       behaviour; the user must first be in the right directory and have a
    //       keystore). We want to intercept v1 BEFORE the loader rejects hybrid v1.
    //
    // Because the production loader (plan 19-03) rejects hybrid v1 envelopes with
    // the PQSIG-06 error, we must bypass the format_version gate for the upgrade
    // path. Use load_from_file_unverified so we can read the current state and
    // decide whether to sign it.
    let mut cfg = ProjectConfig::load_from_file_unverified(&config_path)
        .context("failed to read .sss.toml")?;

    // Idempotency check: already signed → clean exit, no file touch.
    if cfg.format_version >= 2 {
        println!(
            "{}: already signed (format_version={}); nothing to do",
            config_path.display(),
            cfg.format_version
        );
        return Ok(());
    }

    // Resolve the writing user via the system-username heuristic (Pitfall 1):
    //   SSS_USER > config default username > USER/USERNAME env var.
    let writer_username = get_system_username()
        .context("could not determine invoking username for upgrade-sig")?;

    // Ensure the writer is actually listed in the envelope.
    if !cfg.users.contains_key(&writer_username) {
        return Err(anyhow!(
            "user '{}' is not present in {}; cannot sign as an unlisted user",
            writer_username,
            config_path.display()
        ));
    }

    // Open the keystore and load the sig keypair.
    let keystore = Keystore::new()
        .context("failed to open keystore for upgrade-sig")?;

    let password_str = get_password_if_protected(
        &keystore,
        "Enter your passphrase to sign the envelope (or press Enter if none): ",
    )
    .context("could not obtain passphrase for upgrade-sig")?;

    let (ed_sk, pq_sk) = keystore
        .load_sig_keypair(&writer_username, password_str.as_deref())
        .context("failed to load sig keypair from keystore")?;

    // Promote envelope to format_version=2.
    cfg.format_version = 2;

    // Populate writer's per-user sig pubkeys (Option<String> base64, D-06).
    // Use the same API that users.rs uses: sk.verifying_key().as_bytes().
    if let Some(u) = cfg.users.get_mut(&writer_username) {
        if u.sig_ed448_public.is_none() {
            u.sig_ed448_public = Some(BASE64_STANDARD.encode(ed_sk.verifying_key().as_bytes()));
        }
        if u.sig_mldsa65_public.is_none() {
            u.sig_mldsa65_public = Some(BASE64_STANDARD.encode(pq_sk.verifying_key().as_bytes()));
        }
    }

    // Build canonical payload (payload-first per locked plan 19-00, Pitfall 9).
    let payload = envelope_sig::build_envelope_payload(&cfg);
    let sig = envelope_sig::sign_envelope(&ed_sk, &pq_sk, &payload)
        .context("envelope signing failed during upgrade-sig")?;

    // Set cfg.envelope.sig (envelope is Option<EnvelopeMeta>, Pitfall 7).
    cfg.envelope
        .get_or_insert_with(EnvelopeMeta::default)
        .sig = Some(sig);

    write_atomic(&cfg, &config_path)
        .context("atomic write of upgraded envelope failed")?;

    println!(
        "{}: upgraded to format_version=2, signed by '{}'",
        config_path.display(),
        writer_username
    );
    Ok(())
}
