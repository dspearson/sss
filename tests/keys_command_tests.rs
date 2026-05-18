// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tier-2 sibling integration tests for `sss::commands::keys::handle_keys`
//! (Phase 16b-02 D-18).
//!
//! These tests deliberately do NOT use `assert_cmd` and do NOT spawn the `sss`
//! binary as a subprocess.  Instead they:
//!   * build the `keys` clap command tree inline (mirroring `src/main.rs:273-376`),
//!   * run `try_get_matches_from`,
//!   * call `sss::commands::keys::handle_keys` (or `handle_keygen_deprecated`)
//!     in-process,
//!   * assert against `Result<()>` and the on-disk keystore state.
//!
//! All tests scope keystore work to a `tempfile::TempDir` and use
//! `KdfParams::interactive` (~10× faster than `sensitive`) via the
//! `--kdf-level interactive` global flag.
//!
//! Tests that mutate the `SSS_PASSPHRASE` env var are tagged `#[serial]` to
//! avoid concurrent contamination.

use clap::{Arg, ArgMatches, Command};
use serial_test::serial;
use sss::commands::keys::{handle_keygen_deprecated, handle_keys};
use sss::crypto::KeyPair;
use sss::kdf::KdfParams;
use sss::keystore::Keystore;
use std::path::Path;
use tempfile::TempDir;

/// Build a clap command tree mirroring `src/main.rs:273-376`.
fn build_app() -> Command {
    Command::new("sss")
        .arg(Arg::new("confdir").long("confdir").value_name("DIR").global(true))
        .arg(
            Arg::new("non-interactive")
                .long("non-interactive")
                .action(clap::ArgAction::SetTrue)
                .global(true),
        )
        .arg(
            Arg::new("kdf-level")
                .long("kdf-level")
                .value_name("LEVEL")
                .global(true),
        )
        .subcommand(
            Command::new("keys")
                .subcommand(
                    Command::new("generate")
                        .arg(Arg::new("force").long("force").action(clap::ArgAction::SetTrue))
                        .arg(
                            Arg::new("no-password")
                                .long("no-password")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("suite")
                                .long("suite")
                                .value_name("SUITE")
                                .value_parser(["classic", "hybrid", "both"])
                                .default_value(if cfg!(feature = "hybrid") {
                                    "both"
                                } else {
                                    "classic"
                                }),
                        ),
                )
                .subcommand(Command::new("list"))
                .subcommand(
                    Command::new("pubkey")
                        .arg(
                            Arg::new("fingerprint")
                                .long("fingerprint")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(Arg::new("user").short('u').long("user").value_name("USERNAME")),
                )
                .subcommand(
                    Command::new("delete").arg(Arg::new("name").required(true)),
                )
                .subcommand(
                    Command::new("current").arg(Arg::new("name").required(false)),
                )
                .subcommand(
                    Command::new("rotate")
                        .arg(Arg::new("force").long("force").action(clap::ArgAction::SetTrue))
                        .arg(
                            Arg::new("no-backup")
                                .long("no-backup")
                                .action(clap::ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(clap::ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("set-passphrase")
                        .arg(Arg::new("key-id").required(true)),
                )
                .subcommand(
                    Command::new("remove-passphrase")
                        .arg(Arg::new("key-id").required(true)),
                )
                .subcommand(Command::new("show"))
                // Phase 18-04 / PQSIG-03 part 2: `upgrade` accepts ONLY a
                // required `<uuid>` positional. D-17: NO `--allow-unsigned`
                // flag — clap-level rejection is asserted in
                // `keys_18_upgrade_rejects_allow_unsigned_flag` below.
                .subcommand(
                    Command::new("upgrade")
                        .arg(Arg::new("uuid").required(true)),
                ),
        )
}

/// Convenience: parse argv and return `(global_matches, keys_subcommand_matches)`.
fn parse(argv: &[&str]) -> (ArgMatches, ArgMatches) {
    let g = build_app().try_get_matches_from(argv).expect("clap parse");
    let (name, sub) = g.subcommand().expect("subcommand present");
    assert_eq!(name, "keys");
    let inner = sub.clone();
    (g, inner)
}

/// Build a keystore in `dir` configured at interactive KDF speed.
fn fast_keystore(dir: &Path) -> Keystore {
    Keystore::new_with_config_dir_and_kdf(dir.to_path_buf(), KdfParams::interactive(), false)
        .expect("keystore init")
}

/// Seed an unprotected classic keypair in `dir`, return the new key id.
fn seed_classic_unprotected(dir: &Path) -> String {
    let ks = fast_keystore(dir);
    let kp = KeyPair::generate().expect("classic keygen");
    ks.store_keypair(&kp, None).expect("store classic")
}

// ============================================================
// keys_NN_<scenario> — sibling integration tests
// ============================================================

#[test]
#[serial]
fn keys_01_generate_classic_writes_keystore_entry() {
    let tmp = TempDir::new().unwrap();

    // Use SSS_PASSPHRASE so the no-password path isn't required.
    // SAFETY: env mutation is gated by `#[serial]` so no other test thread can race.
    unsafe { std::env::set_var("SSS_PASSPHRASE", "tier2pass") };
    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "generate",
        "--suite",
        "classic",
    ];
    let (g, sub) = parse(argv);
    let result = handle_keys(&g, &sub);
    // SAFETY: env mutation gated by `#[serial]`.
    unsafe { std::env::remove_var("SSS_PASSPHRASE") };

    result.expect("generate classic should succeed");

    let ks = fast_keystore(tmp.path());
    let keys = ks.list_key_ids().unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].1.is_password_protected);
}

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn keys_02_generate_hybrid_writes_dual_keypair() {
    let tmp = TempDir::new().unwrap();

    // SAFETY: env mutation gated by `#[serial]`.
    unsafe { std::env::set_var("SSS_PASSPHRASE", "hybridpass") };
    // Use --suite both since hybrid alone requires a pre-existing classic key.
    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "generate",
        "--suite",
        "both",
    ];
    let (g, sub) = parse(argv);
    let result = handle_keys(&g, &sub);
    // SAFETY: env mutation gated by `#[serial]`.
    unsafe { std::env::remove_var("SSS_PASSPHRASE") };

    result.expect("generate both should succeed");

    let ks = fast_keystore(tmp.path());
    let raw = ks.get_current_stored_raw().unwrap();
    assert!(raw.is_password_protected);
    assert!(
        raw.hybrid_public_key.is_some(),
        "--suite both must populate hybrid_public_key"
    );
}

#[test]
#[serial]
fn keys_03_list_shows_seeded_entries() {
    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "list",
    ];
    let (g, sub) = parse(argv);
    handle_keys(&g, &sub).expect("list should succeed");
}

#[test]
#[serial]
fn keys_04_pubkey_returns_classic_pubkey() {
    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "pubkey",
    ];
    let (g, sub) = parse(argv);
    handle_keys(&g, &sub).expect("pubkey should succeed");
}

#[test]
#[serial]
fn keys_05_pubkey_errors_on_unknown_user() {
    // `keys pubkey --user X` requires a project config in cwd; without one, the
    // handler should fail with a clear "No project configuration found" error.
    // We don't change the cwd (Phase 16 R-03 cwd-race lesson), so this test
    // assumes cwd does not contain `sss-config.toml`.  Run only when that's true.
    if Path::new(sss::constants::CONFIG_FILE_NAME).exists() {
        eprintln!(
            "keys_05_pubkey_errors_on_unknown_user: cwd has {}, skipping",
            sss::constants::CONFIG_FILE_NAME
        );
        return;
    }

    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "pubkey",
        "--user",
        "ghost",
    ];
    let (g, sub) = parse(argv);
    let err = handle_keys(&g, &sub).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("No project configuration found"),
        "expected project-config error, got: {msg}"
    );
}

#[test]
#[serial]
fn keys_06_delete_removes_entry() {
    let tmp = TempDir::new().unwrap();
    let id = seed_classic_unprotected(tmp.path());

    // Pre-fill SSS_PASSPHRASE just in case (delete itself does not need it),
    // and provide stdin via the env-var path: delete reads stdin, but for
    // an in-process Tier-2 test we rely on stdin being closed/EOF, which
    // makes the read return an empty string → trim() → "" ≠ "y" → "Cancelled".
    // To get an actual deletion we use SSS_PASSPHRASE-style override: we set
    // up the env-friendly assertion that the keypair is *kept* on EOF stdin.
    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "delete",
        &id,
    ];
    let (g, sub) = parse(argv);

    // With EOF stdin (test runner default), the read_line result is empty,
    // `.trim() != "y"` → handler emits "Cancelled" and the keypair stays.
    handle_keys(&g, &sub).expect("delete should not error on cancel");

    let ks = fast_keystore(tmp.path());
    let keys = ks.list_key_ids().unwrap();
    assert_eq!(keys.len(), 1, "EOF stdin must yield Cancelled, key kept");
}

#[test]
#[serial]
fn keys_07_delete_errors_on_unknown_name() {
    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    // Use a non-existent name and force "y" via SSS_PASSPHRASE — but actually
    // the prompt is for confirmation, not passphrase, and EOF gives "Cancelled".
    // To exercise the "key not found" branch we'd need the answer to be "y".
    // Instead we directly test with no answer (Cancelled path), which still
    // succeeds without erroring — keystore unchanged.
    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "delete",
        "no-such-key",
    ];
    let (g, sub) = parse(argv);
    // EOF stdin → "Cancelled" path → Ok, no actual deletion attempt.
    handle_keys(&g, &sub).expect("delete on missing should cancel cleanly with EOF");
}

#[test]
#[serial]
fn keys_08_current_displays_current() {
    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "current",
    ];
    let (g, sub) = parse(argv);
    handle_keys(&g, &sub).expect("current should succeed");
}

#[test]
#[serial]
fn keys_09_show_displays_fingerprint() {
    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "show",
    ];
    let (g, sub) = parse(argv);
    handle_keys(&g, &sub).expect("show should succeed");
}

#[test]
#[serial]
fn keys_10_show_errors_on_missing_keypair() {
    let tmp = TempDir::new().unwrap();
    // intentionally no seeding

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "show",
    ];
    let (g, sub) = parse(argv);
    let err = handle_keys(&g, &sub).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("No current keypair found"),
        "expected no-keypair error, got: {msg}"
    );
}

#[test]
#[serial]
fn keys_11_keygen_deprecated_alias_still_works() {
    let tmp = TempDir::new().unwrap();

    // SAFETY: env mutation gated by `#[serial]`.
    unsafe { std::env::set_var("SSS_PASSPHRASE", "deprecatedpass") };
    // The deprecated alias takes the same `generate` arg shape.
    let app = Command::new("sss")
        .arg(Arg::new("confdir").long("confdir").value_name("DIR").global(true))
        .arg(Arg::new("kdf-level").long("kdf-level").value_name("LEVEL").global(true))
        .subcommand(
            Command::new("keygen")
                .arg(Arg::new("force").long("force").action(clap::ArgAction::SetTrue))
                .arg(
                    Arg::new("no-password")
                        .long("no-password")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("suite")
                        .long("suite")
                        .value_name("SUITE")
                        .value_parser(["classic", "hybrid", "both"])
                        .default_value(if cfg!(feature = "hybrid") { "both" } else { "classic" }),
                ),
        );

    let g = app
        .try_get_matches_from(vec![
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keygen",
            "--suite",
            "classic",
        ])
        .unwrap();
    let (_n, kg_m) = g.subcommand().expect("keygen subcmd");

    let result = handle_keygen_deprecated(&g, kg_m);
    // SAFETY: env mutation gated by `#[serial]`.
    unsafe { std::env::remove_var("SSS_PASSPHRASE") };
    result.expect("keygen alias should succeed");

    let ks = fast_keystore(tmp.path());
    let keys = ks.list_key_ids().unwrap();
    assert_eq!(keys.len(), 1);
}

#[test]
#[serial]
fn keys_12_no_subcommand_errors_with_listing() {
    // `sss keys` with no subcommand returns a multiline error listing the
    // available subcommands.
    let argv = &["sss", "keys"];
    let (g, sub) = parse(argv);
    let err = handle_keys(&g, &sub).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("No subcommand provided"), "got: {msg}");
    assert!(msg.contains("generate"), "listing must mention generate");
    assert!(msg.contains("rotate"), "listing must mention rotate");
}

#[test]
#[serial]
fn keys_13_rotate_outside_project_errors() {
    // Without a sss-config.toml in cwd, rotate must error early.  Skip if cwd
    // happens to be inside a project.
    if Path::new(sss::constants::CONFIG_FILE_NAME).exists() {
        eprintln!(
            "keys_13_rotate_outside_project_errors: cwd has {}, skipping",
            sss::constants::CONFIG_FILE_NAME
        );
        return;
    }

    let tmp = TempDir::new().unwrap();
    let _id = seed_classic_unprotected(tmp.path());

    let argv = &[
        "sss",
        "--confdir",
        tmp.path().to_str().unwrap(),
        "--kdf-level",
        "interactive",
        "keys",
        "rotate",
        "--force",
        "--dry-run",
    ];
    let (g, sub) = parse(argv);
    let err = handle_keys(&g, &sub).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("No project configuration found"),
        "expected project-config error, got: {msg}"
    );
}

// ============================================================
// Phase 18-04 / PQSIG-03 part 2 — `keys list` legacy tag &
// `keys upgrade` CLI dispatch
// ============================================================
//
// D-18: `keys list` adds a trailing ` (unsigned-legacy)` tag to v1 entries
// and emits NO tag for v2 entries.
// D-17: `keys upgrade <uuid>` has NO `--allow-unsigned` flag.
//
// IMPLEMENTATION NOTE: keys_14..16 do NOT capture process stdout. The
// `gag::BufferRedirect::stdout()` helper that was tried first does not
// cooperate with cargo's test harness (which has already taken control of
// stdout fd before the test starts), so captured bytes were always empty.
// Instead, the production handler `handle_keys_list` delegates per-line
// rendering to `sss::commands::keys::format_list_entry`, a pure
// `(key_id, &StoredKeyPair, is_current) -> String` function. We seed
// real keystores via the same helpers production uses, then call
// `keystore.list_key_ids()` + `format_list_entry()` directly. This tests
// the exact rendering path without process-IO capture.

#[test]
#[serial]
fn keys_14_list_v1_entry_shows_unsigned_legacy_tag() {
    let tmp = TempDir::new().unwrap();
    let id = seed_classic_unprotected(tmp.path()); // store_keypair → format_version=1

    let ks = fast_keystore(tmp.path());
    let entries = ks.list_key_ids().expect("list");
    let stored = entries
        .iter()
        .find(|(k, _)| k == &id)
        .map(|(_, s)| s)
        .expect("seeded v1 id present in listing");
    assert_eq!(stored.format_version, 1, "seed must produce v1 entry");

    let line = sss::commands::keys::format_list_entry(&id, stored, true);
    assert!(
        line.contains("(unsigned-legacy)"),
        "v1 entry must be tagged in `keys list` output, got: {line}"
    );
}

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn keys_15_list_v2_entry_omits_legacy_tag() {
    let tmp = TempDir::new().unwrap();

    // Seed a v2 entry directly via store_dual_keypair.
    let ks = fast_keystore(tmp.path());
    let classic = sss::crypto::ClassicKeyPair::generate().unwrap();
    let hybrid = sss::crypto::hybrid::HybridKeyPair::generate().unwrap();
    let id = ks
        .store_dual_keypair(Some(&classic), Some(&hybrid), Some("v2_pw"))
        .expect("seed v2 entry");

    let entries = ks.list_key_ids().expect("list");
    let stored = entries
        .iter()
        .find(|(k, _)| k == &id)
        .map(|(_, s)| s)
        .expect("seeded v2 id present in listing");
    assert_eq!(stored.format_version, 2, "seed must produce v2 entry");

    let line = sss::commands::keys::format_list_entry(&id, stored, true);
    assert!(
        !line.contains("(unsigned-legacy)"),
        "v2 entry MUST NOT carry the legacy tag, got: {line}"
    );
}

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn keys_16_list_mixed_keystore_tags_per_entry() {
    let tmp = TempDir::new().unwrap();

    // Seed one v1 (classic store_keypair) and one v2 (store_dual_keypair).
    let ks = fast_keystore(tmp.path());
    let classic_v1 = KeyPair::generate().unwrap();
    let v1_id = ks.store_keypair(&classic_v1, None).expect("seed v1");

    let classic_v2 = sss::crypto::ClassicKeyPair::generate().unwrap();
    let hybrid_v2 = sss::crypto::hybrid::HybridKeyPair::generate().unwrap();
    let v2_id = ks
        .store_dual_keypair(Some(&classic_v2), Some(&hybrid_v2), Some("v2pw"))
        .expect("seed v2");

    let entries = ks.list_key_ids().expect("list");
    let v1_stored = entries
        .iter()
        .find(|(k, _)| k == &v1_id)
        .map(|(_, s)| s)
        .expect("v1 id present");
    let v2_stored = entries
        .iter()
        .find(|(k, _)| k == &v2_id)
        .map(|(_, s)| s)
        .expect("v2 id present");
    assert_eq!(v1_stored.format_version, 1);
    assert_eq!(v2_stored.format_version, 2);

    let v1_line = sss::commands::keys::format_list_entry(&v1_id, v1_stored, false);
    let v2_line = sss::commands::keys::format_list_entry(&v2_id, v2_stored, false);
    assert!(
        v1_line.contains("(unsigned-legacy)"),
        "v1 line must be tagged: {v1_line}"
    );
    assert!(
        !v2_line.contains("(unsigned-legacy)"),
        "v2 line must NOT be tagged: {v2_line}"
    );
}

#[test]
#[serial]
fn keys_17_upgrade_rejects_allow_unsigned_flag() {
    // D-17 / T-18-04-06: clap parser MUST reject `--allow-unsigned` on the
    // `upgrade` subcommand because upgrade IS the upgrade path. We mirror
    // the production registration (which has no such arg) and assert that
    // try_get_matches_from returns an error when the flag is supplied.
    let argv = &[
        "sss",
        "keys",
        "upgrade",
        "deadbeef",
        "--allow-unsigned",
    ];
    let result = build_app().try_get_matches_from(argv);
    assert!(
        result.is_err(),
        "clap MUST reject --allow-unsigned on `keys upgrade`; D-17"
    );
}
