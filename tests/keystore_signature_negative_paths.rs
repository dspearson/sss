//! Negative-path tests for keystore entry signature verification (Phase 18 / PQSIG-01..03).
//!
//! Each test:
//! 1. Generates a v2 signed keystore entry in a tempdir-isolated keystore via
//!    the production `Keystore::store_dual_keypair` Case-A path (sign-on-write).
//! 2. Surgically mutates ONE field on disk (TOML string-replace, not regenerate).
//! 3. Reloads via `Keystore::load_keypair` (`allow_unsigned=false` → v2 hard-verify).
//! 4. Asserts `Err(_)` whose message contains the canonical D-20 substring
//!    `signature verification failed`.
//!
//! Belt-and-braces feature gating (Phase 15 D-13 + D-11 precedent):
//!   - source-level `#![cfg(feature = "hybrid")]` (this file) AND
//!   - `Cargo.toml` `[[test]] required-features = ["hybrid"]`
//! → default `cargo test` cleanly skips this binary.
//!
//! NEG-02 vs NEG-03 are SEPARATE test functions to prove AND-composition
//! leg-independence: if NEG-02 passes silently when NEG-03 doesn't, the AND
//! has degenerated to "Ed448 only" and ML-DSA-65 is decorative.

#![cfg(feature = "hybrid")]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use tempfile::TempDir;
use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};

use sss::crypto::hybrid::HybridKeyPair;
use sss::crypto::ClassicKeyPair;
use sss::kdf::KdfParams;
use sss::keystore::{build_signed_payload, Keystore, KeystoreEntrySig, StoredKeyPair};

/// Test passphrase used across all negative-path tests; never persisted outside tempdirs.
const TEST_PASSPHRASE: &str = "neg-path-test-pw-2026";

/// Canonical context bytes for keystore-entry signing (must match
/// `sss::keystore::KEYSTORE_SIG_CONTEXT`). Hard-coded here to make NEG-05
/// (wrong-context proof) self-explanatory.
const KEYSTORE_CONTEXT: &[u8] = b"sss-keystore-entry-sig-v1";

/// Phase 19's envelope-signing context. Used by NEG-05 to forge a signature
/// that is well-formed but bound to the wrong protocol — verify must reject.
const WRONG_CONTEXT: &[u8] = b"sss-toml-envelope-sig-v1";

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Create an isolated keystore in a fresh tempdir.
/// `KdfParams::interactive()` keeps Argon2id fast for test latency budget.
fn create_temp_keystore() -> Result<(Keystore, TempDir)> {
    let temp_dir = TempDir::new()?;
    let keystore = Keystore::new_with_config_dir_and_kdf(
        temp_dir.path().to_path_buf(),
        KdfParams::interactive(),
        false,
    )?;
    Ok((keystore, temp_dir))
}

/// Build the on-disk path for an entry given the tempdir root.
/// `Keystore::keys_dir` is `pub(crate)` (D-03 wiring choice), so external
/// integration tests reconstruct the path by mirroring `new_with_config_dir_and_kdf`'s
/// `config_dir.join("sss").join("keys")` derivation.
fn entry_path(temp_dir_root: &Path, key_id: &str) -> PathBuf {
    temp_dir_root
        .join("sss")
        .join("keys")
        .join(format!("{key_id}.toml"))
}

/// Generate a fresh v2 hybrid signed entry via the production sign-on-write path.
/// Returns `(uuid, on_disk_path, expected_passphrase)`.
fn write_fresh_v2_entry(
    keystore: &Keystore,
    temp_dir: &TempDir,
) -> Result<(String, PathBuf, &'static str)> {
    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;
    let key_id =
        keystore.store_dual_keypair(Some(&classic), Some(&hybrid), Some(TEST_PASSPHRASE))?;
    let path = entry_path(temp_dir.path(), &key_id);
    Ok((key_id, path, TEST_PASSPHRASE))
}

/// Flip the first ASCII alphanumeric char of a base64 field's value in place.
/// Targets `field = "..."` patterns at the top level of a flat TOML.
fn flip_first_b64_char_in_field(toml_text: &str, field: &str) -> String {
    let needle = format!("{field} = \"");
    let Some(pos) = toml_text.find(&needle) else {
        panic!("flip_first_b64_char_in_field: field `{field}` not found in TOML");
    };
    let value_start = pos + needle.len();
    let mut chars: Vec<char> = toml_text.chars().collect();
    // Locate first alphanumeric char after value_start.
    let mut byte_offset = 0usize;
    let mut char_idx_target: Option<usize> = None;
    for (i, c) in chars.iter().enumerate() {
        if byte_offset >= value_start && c.is_ascii_alphanumeric() {
            char_idx_target = Some(i);
            break;
        }
        byte_offset += c.len_utf8();
    }
    let idx = char_idx_target.expect("no alphanumeric char in target field's value");
    let original = chars[idx];
    chars[idx] = if original == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

/// Flip the first ASCII alphanumeric char of a sub-table field's value in place.
/// Targets `[signature]\n field = "..."` patterns. The `subtable_field` should be
/// `"signature.ed448"` or `"signature.mldsa65"` — we split on `.` and search for
/// the leaf key after the `[parent]` header.
fn flip_first_b64_char_in_subtable_field(toml_text: &str, subtable_field: &str) -> String {
    let parts: Vec<&str> = subtable_field.splitn(2, '.').collect();
    assert_eq!(parts.len(), 2, "expected `parent.leaf` form");
    let header = format!("[{}]", parts[0]);
    let leaf = parts[1];
    let header_pos = toml_text
        .find(&header)
        .unwrap_or_else(|| panic!("missing `[{}]` header in TOML", parts[0]));
    let after_header = &toml_text[header_pos + header.len()..];
    let leaf_needle = format!("{leaf} = \"");
    let leaf_pos_in_after = after_header
        .find(&leaf_needle)
        .unwrap_or_else(|| panic!("leaf field `{leaf}` not found under `[{}]`", parts[0]));
    let absolute_value_start = header_pos + header.len() + leaf_pos_in_after + leaf_needle.len();
    let mut chars: Vec<char> = toml_text.chars().collect();
    let mut byte_offset = 0usize;
    let mut char_idx_target: Option<usize> = None;
    for (i, c) in chars.iter().enumerate() {
        if byte_offset >= absolute_value_start && c.is_ascii_alphanumeric() {
            char_idx_target = Some(i);
            break;
        }
        byte_offset += c.len_utf8();
    }
    let idx = char_idx_target.expect("no alphanumeric char in target subtable field's value");
    let original = chars[idx];
    chars[idx] = if original == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

/// Assert that `Keystore::load_keypair(...)` returns Err whose message contains
/// the canonical D-20 substring `signature verification failed` (or, for the
/// missing-sig case, `missing signature` per the plan's NEG-04 acceptance).
fn assert_load_rejects(keystore: &Keystore, uuid: &str, passphrase: &str) {
    let res = keystore.load_keypair(uuid, Some(passphrase), /* allow_unsigned */ false);
    match res {
        Ok(_) => panic!("expected load_keypair to fail for uuid={uuid}, but it succeeded"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("signature verification failed") || msg.contains("missing signature"),
                "unexpected error message for uuid={uuid}: {msg}"
            );
        }
    }
}

// ─── NEG-01: tampered public_key ────────────────────────────────────────────
//
// Mutate one base64 char of the classic encryption `public_key` field.
// The signed payload's pk_b64 slot will no longer match → verify rejects.
// Proves D-08 covers `public_key`.
#[test]
fn neg_01_tampered_public_key_fails_verify() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (uuid, path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    let original = fs::read_to_string(&path)?;
    let mutated = flip_first_b64_char_in_field(&original, "public_key");
    fs::write(&path, mutated)?;

    assert_load_rejects(&keystore, &uuid, passphrase);
    Ok(())
}

// ─── NEG-02: tampered Ed448 signature leg ───────────────────────────────────
//
// Mutate one base64 char of `[signature]/ed448`. Ed448 leg of AND-composition
// fails to verify → entry rejected even if ML-DSA-65 leg still verifies.
// SEPARATE test from NEG-03 — proves Ed448 leg is wired and load-checked.
#[test]
fn neg_02_tampered_ed448_sig_fails_verify() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (uuid, path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    let original = fs::read_to_string(&path)?;
    let mutated = flip_first_b64_char_in_subtable_field(&original, "signature.ed448");
    fs::write(&path, mutated)?;

    assert_load_rejects(&keystore, &uuid, passphrase);
    Ok(())
}

// ─── NEG-03: tampered ML-DSA-65 signature leg ───────────────────────────────
//
// Mutate one base64 char of `[signature]/mldsa65`. ML-DSA-65 leg of
// AND-composition fails → entry rejected even if Ed448 leg verifies.
// SEPARATE test from NEG-02 — proves ML-DSA-65 leg is not decorative
// (the existential proof that AND has not degenerated to Ed448-only).
#[test]
fn neg_03_tampered_mldsa65_sig_fails_verify() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (uuid, path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    let original = fs::read_to_string(&path)?;
    let mutated = flip_first_b64_char_in_subtable_field(&original, "signature.mldsa65");
    fs::write(&path, mutated)?;

    assert_load_rejects(&keystore, &uuid, passphrase);
    Ok(())
}

// ─── NEG-04: missing signature on v2 entry ──────────────────────────────────
//
// Strip the entire `[signature]` sub-table from the on-disk TOML.
// `format_version = 2` plus a None signature is a hard reject per D-10.
// `verify_stored_signature` collapses missing-sig into the canonical D-20
// `signature verification failed` substring (no sub-cause leak — T-18-03-04).
#[test]
fn neg_04_missing_signature_on_v2_fails() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (uuid, path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    let original = fs::read_to_string(&path)?;
    // The serialised v2 entry ends with:
    //   ...
    //   [signature]
    //   ed448 = "..."
    //   mldsa65 = "..."
    // Remove everything from the `[signature]` header onward.
    let sig_pos = original
        .find("\n[signature]")
        .expect("v2 entry must contain `[signature]` block");
    let truncated = &original[..sig_pos];
    fs::write(&path, truncated)?;

    assert_load_rejects(&keystore, &uuid, passphrase);
    Ok(())
}

// ─── NEG-05 (bonus): wrong sig context (proves D-05 domain separation) ──────
//
// Forge a v2 signature using `WRONG_CONTEXT` (Phase 19's envelope context)
// instead of `KEYSTORE_CONTEXT`. The on-disk entry is internally consistent
// (sig pubkeys match the forged sigs) — but verify_with_context will reject
// because context bytes are folded into Ed448 RFC 8032 §8.1 and ML-DSA-65
// FIPS 204 §5.1 ctx parameter natively. This is the only way to detect a
// cross-protocol confusion attack.
#[test]
fn neg_05_wrong_context_fails_verify() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (uuid, path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    // Read the on-disk entry; we'll overwrite the four sig fields with a
    // self-consistent forged-context tuple.
    let original = fs::read_to_string(&path)?;
    let mut entry: StoredKeyPair = toml::from_str(&original)?;

    // Generate fresh sig keypairs JUST for this forgery. The on-disk encrypted
    // sig secret keys are untouched (they belong to the original keypair) —
    // but verify only consults the on-disk PUB keys + the on-disk sig. We
    // overwrite both sides so the entry is internally consistent except for
    // context binding.
    let ed448_sk =
        Ed448Standard::generate().map_err(|e| anyhow::anyhow!("Ed448 keygen: {e}"))?;
    let ed448_vk = Ed448Standard::verifying_key(&ed448_sk);
    let ed448_pk_b64 = BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(&ed448_vk));

    let mldsa_sk =
        MlDsa65Fips204::generate().map_err(|e| anyhow::anyhow!("ML-DSA-65 keygen: {e}"))?;
    let mldsa_vk = MlDsa65Fips204::verifying_key(&mldsa_sk);
    let mldsa_pk_b64 =
        BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(&mldsa_vk));

    // Build canonical payload over the ABOUT-TO-BE-WRITTEN sig pubkey fields
    // (the entry's other identity fields are unchanged).
    let payload = build_signed_payload(
        &entry.uuid,
        &entry.public_key,
        entry.hybrid_public_key.as_deref(),
        Some(&ed448_pk_b64),
        Some(&mldsa_pk_b64),
        &entry.created_at.to_rfc3339(),
    );

    // Sign with the WRONG context.
    let ed448_sig = Ed448Standard::sign_with_context(&ed448_sk, &payload, WRONG_CONTEXT)
        .map_err(|e| anyhow::anyhow!("Ed448 sign_with_context: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::sign_with_context(&mldsa_sk, &payload, WRONG_CONTEXT)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 sign_with_context: {e}"))?;

    let ed448_sig_b64 = BASE64_STANDARD.encode(Ed448Standard::signature_to_bytes(&ed448_sig));
    let mldsa_sig_b64 =
        BASE64_STANDARD.encode(MlDsa65Fips204::signature_to_bytes(&mldsa_sig));

    // Overwrite both pub-key fields and the signature on disk.
    entry.sig_ed448_public_key = Some(ed448_pk_b64);
    entry.sig_mldsa65_public_key = Some(mldsa_pk_b64);
    entry.signature = Some(KeystoreEntrySig {
        ed448: ed448_sig_b64,
        mldsa65: mldsa_sig_b64,
    });

    let serialised = toml::to_string_pretty(&entry)?;
    fs::write(&path, serialised)?;

    // Confirm we did NOT accidentally re-use the production context.
    debug_assert_ne!(WRONG_CONTEXT, KEYSTORE_CONTEXT);

    assert_load_rejects(&keystore, &uuid, passphrase);
    Ok(())
}

// ─── NEG-06 (bonus): mutated created_at (proves D-08 covers timestamp) ──────
//
// Roll back the `created_at` ISO-8601 string by changing the year prefix
// `"20..."` → `"19..."`. The signed payload's created_at slot will no longer
// match → verify rejects. Proves D-08 covers the timestamp field.
#[test]
fn neg_06_mutated_created_at_fails_verify() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (uuid, path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    let original = fs::read_to_string(&path)?;
    // Rewrite e.g. `created_at = "2026-05-09T...` → `created_at = "1926-05-09T...`.
    // `replacen` (1 hit) is safe: `created_at = "20` only appears once on a
    // fresh entry created in 2026.
    let mutated = original.replacen("created_at = \"20", "created_at = \"19", 1);
    assert_ne!(
        original, mutated,
        "expected `created_at = \"20...\"` to appear exactly once; surgical mutation failed"
    );
    fs::write(&path, mutated)?;

    assert_load_rejects(&keystore, &uuid, passphrase);
    Ok(())
}

// ─── NEG-07 (bonus): mutated uuid (proves D-08 covers uuid) ─────────────────
//
// Mutate the last hex digit of the `uuid` field, then rename the on-disk file
// to match the new uuid (so `load_keypair(new_uuid)` finds and parses it).
// The signed payload's uuid slot will no longer match → verify rejects.
// Proves D-08 covers the uuid field.
#[test]
fn neg_07_mutated_uuid_fails_verify() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let (orig_uuid, orig_path, passphrase) = write_fresh_v2_entry(&keystore, &temp_dir)?;

    // Generate a new uuid by swapping the LAST hex digit (0..9 ↔ 1, a..f ↔ b).
    let last_char = orig_uuid
        .chars()
        .last()
        .expect("uuid must be non-empty");
    let replacement = match last_char {
        '0' => '1',
        '1' => '2',
        'a' => 'b',
        'b' => 'c',
        '9' => '8',
        'f' => 'e',
        _ => '0',
    };
    let mut new_uuid_chars: Vec<char> = orig_uuid.chars().collect();
    let last_idx = new_uuid_chars.len() - 1;
    new_uuid_chars[last_idx] = replacement;
    let new_uuid: String = new_uuid_chars.into_iter().collect();
    assert_ne!(orig_uuid, new_uuid, "uuid mutation produced same string");

    // Read, mutate uuid in TOML, write to NEW path matching new uuid, remove
    // old path so load by new_uuid hits the mutated entry.
    let original = fs::read_to_string(&orig_path)?;
    let mutated = original.replacen(
        &format!("uuid = \"{orig_uuid}\""),
        &format!("uuid = \"{new_uuid}\""),
        1,
    );
    assert_ne!(
        original, mutated,
        "expected exactly one `uuid = \"...\"` line to substitute; surgical mutation failed"
    );

    let new_path = entry_path(temp_dir.path(), &new_uuid);
    fs::write(&new_path, mutated)?;
    fs::remove_file(&orig_path)?;

    assert_load_rejects(&keystore, &new_uuid, passphrase);
    Ok(())
}
