//! Hybrid AND-composition signatures over the `.sss.toml` envelope (Phase 19, PQSIG-04).
//!
//! Combines `trelis_primitives::Ed448Standard` (RFC 8032 SHAKE256) with
//! `trelis_primitives::MlDsa65Fips204` (FIPS 204) via AND composition:
//! BOTH signatures must verify; either failure rejects the envelope.
//!
//! Domain-separation context: `b"sss-toml-envelope-sig-v3"` (D-02, Phase 46, plan 46-02).
//! Context v2 `b"sss-toml-envelope-sig-v2"` is retained as a verify-only constant for the
//! `format_version=2` dispatch arm — existing v2-signed repos remain readable.
//! Canonical payload: length-prefixed concat of identity-bearing fields (D-03).
//! Payload schema v3 adds vault fields after the hooks fields (Phase 46, plan 46-02).
//!
//! See `docs/CRYPTOGRAPHY.md` §"Envelope Signatures (v3)" for the
//! authoritative format spec (added in plan unit 19-05, updated in 38-01, 46-02).

use anyhow::{anyhow, Context, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::path::Path;
use trelis_primitives::{
    Ed448Scheme, Ed448SigningKey, Ed448Standard, Ed448VerifyingKey,
    MlDsa65Fips204, MlDsa65SigningKey, MlDsa65VerifyingKey, MlDsaScheme,
};

use crate::project::{EnvelopeMeta, EnvelopeSig, ProjectConfig};

/// Domain-separation context for `.sss.toml` envelope signatures, schema v3 (D-02, Phase 46).
///
/// Bumped to `v3` in plan 46-02 to extend the signed payload schema with vault fields
/// (`vault.address`, `vault.namespace`, `vault.default_binding`, `vault.tls_ca_secret`,
/// `vault.bindings` count + per-binding fields, `vault.auth` fields). Any signature
/// produced under the v2 context fails cryptographic verification here (fail-closed;
/// no try-v2-then-v3 fallback). Repos adopting `[vault]` must run
/// `sss envelope upgrade-sig` to re-sign under the v3 context.
///
/// MUST be byte-distinct from `crate::keystore::sig::KEYSTORE_SIG_CONTEXT` and from
/// `ENVELOPE_SIG_CONTEXT_V2` to prevent cross-context replay (T-19-01, T-46-01).
/// Drift-detector test below pins the bytes; any change must update both this test AND
/// `docs/CRYPTOGRAPHY.md` §"Envelope Signatures (v3)".
pub const ENVELOPE_SIG_CONTEXT: &[u8] = b"sss-toml-envelope-sig-v3";

/// Domain-separation context for schema v2 signatures — the legacy schema-v2 payload's
/// domain separator on BOTH the sign and verify sides.
///
/// Used for (a) **SIGNING** `format_version <= 2` configs (selected via
/// `context_for_format_version`) AND (b) **verifying** `format_version=2` envelopes
/// (via `verify_envelope_signature_v2`). A non-vault repo stays at `format_version=2`
/// (no force-bump on routine re-sign), so its envelope is both signed and verified under
/// THIS context over the byte-stable legacy (no-vault) payload. Existing v2-signed repos
/// therefore continue to READ/verify unchanged on a v3.0 binary (VSIG-01).
///
/// MUST be byte-distinct from `ENVELOPE_SIG_CONTEXT` (v3) and from
/// `crate::keystore::sig::KEYSTORE_SIG_CONTEXT` to prevent cross-context replay
/// (T-19-01, T-46-01). The drift-detector test below pins the bytes; the VALUE is
/// unchanged by Phase 46.1.
pub const ENVELOPE_SIG_CONTEXT_V2: &[u8] = b"sss-toml-envelope-sig-v2";

/// Single source of truth for **sign-side** context selection by `format_version`.
///
/// Returns `ENVELOPE_SIG_CONTEXT_V2` (the legacy schema-v2 domain separator) for
/// `fv <= 2`, and `ENVELOPE_SIG_CONTEXT` (the vault-inclusive v3 domain separator)
/// for `fv >= 3`. This pairs with the verify-side selection, which lives in the
/// `src/project.rs` `format_version` dispatch ladder (`2 =>` calls
/// `verify_envelope_signature_v2` under the v2 context; `3 =>` calls
/// `verify_envelope_signature` under the v3 context). Keeping the two in lock-step is
/// what guarantees a signature is verifiable only under the arm matching its payload
/// SCHEMA — a v2 signature over the legacy payload cannot be accepted by the v3 arm and
/// vice versa (T-46.1-02 cross-context separation).
///
/// `pub` because the production sign callers live outside this module
/// (`src/config.rs` init, `src/commands/{users,migrate}.rs`).
#[must_use]
pub fn context_for_format_version(fv: u32) -> &'static [u8] {
    if fv >= 3 {
        ENVELOPE_SIG_CONTEXT
    } else {
        ENVELOPE_SIG_CONTEXT_V2
    }
}

/// Length-prefix a single byte slice into the buffer. Layout: `(len_u32_be, bytes)`.
fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    // Why: envelope-sig wire format is u32 length-prefixed. Real envelope fields
    // (users map, sealed_key strings, public_key strings) are bounded well below
    // u32::MAX (4 GiB) by .sss.toml structure; truncation is impossible.
    #[allow(clippy::cast_possible_truncation)]
    let bytes_len = bytes.len() as u32;
    buf.extend_from_slice(&bytes_len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Length-prefix an `Option<&str>`; `None` becomes `(0_u32_be, 0 bytes)`.
fn push_lp_opt(buf: &mut Vec<u8>, opt: Option<&str>) {
    push_lp(buf, opt.unwrap_or("").as_bytes());
}

/// Canonical signed-payload encoding (D-03, schema v3 per Phase 46 plan 46-02).
///
/// Field order is FIXED:
///   1. version
///   2. created
///   3. `format_version` (decimal-string encoding)
///   4. `secrets_filename` (`Option<String>` → `push_lp_opt`)
///   5. `secrets_suffix`   (`Option<String>` → `push_lp_opt`)
///   6. ignore             (`Option<String>` → `push_lp_opt`)
///   7. `hooks.git_pre_commit`    (`Option<bool>` → "true"/"false"/None)
///   8. `hooks.git_post_checkout` (`Option<bool>` → "true"/"false"/None)
///
///   Vault region (fields 9-18) — emitted **ONLY for `format_version >= 3`** (Phase 46.1,
///   plan 46.1-01). For `format_version <= 2` NOTHING is emitted between field 8 and the
///   per-user loop, so the output is byte-identical to the legacy schema-v2 layout
///   (fields 1-8 then the per-user loop, no vault region, no count). The gate is purely on
///   the version number, NOT on `config.vault.is_some()` and NOT on the `vault` Cargo
///   feature — an fv=3 config emits the vault region (all-None/zero when `vault` is absent)
///   on any build, preserving R4 feature-independence (VCFG-02). None/zero when vault
///   config absent:
///
///   9. `vault.address`          (`Option<String>` → `push_lp_opt`)
///  10. `vault.namespace`        (`Option<String>` → `push_lp_opt`)
///  11. `vault.default_binding`  (`Option<String>` → `push_lp_opt`)
///  12. `vault.tls_ca_secret`    (`Option<String>` → `push_lp_opt`)
///  13. `vault.bindings` count   (`u32` BE; 0 when None)
///  14. per-binding (BTree-sorted by name):
///      `binding_name`, `kv_version` (decimal-string / ""), mount, `default_field`
///  15. `vault.auth.method`         (`Option<String>` → `push_lp_opt`)
///  16. `vault.auth.role_id`        (`Option<String>` → `push_lp_opt`)
///  17. `vault.auth.secret_id_secret` (`Option<String>` → `push_lp_opt`)
///  18. `vault.auth.token_secret`   (`Option<String>` → `push_lp_opt`)
///
///   Per-user loop:
///
///  19. per-user (sorted by username):
///      username, public, `sealed_key`, added, `hybrid_public`,
///      `sig_ed448_public`, `sig_mldsa65_public`
///
/// Each variable-length field is preceded by a `u32`-BE length prefix to
/// prevent length-extension / boundary-shift attacks (T-19-02).
/// Absent `Option<String>` fields encode as 4 zero bytes (D-03).
/// `Option<bool>` hook fields: `Some(true)` → `"true"`, `Some(false)` → `"false"`,
/// `None` → 4 zero bytes (consistent with `push_lp_opt(None)` for `Option<&str>`).
///
/// R4 constraint: the vault region is gated on `format_version >= 3` (NOT on the `vault`
/// Cargo feature), so a non-vault build encodes an fv=3 envelope's vault region identically
/// to a vault build and verifies it identically. `config.vault` is parsed regardless of
/// features, so the branch is purely the version number.
///
/// Note: `ProjectConfig.users` is `HashMap` (see src/project.rs).
/// Iteration order is non-deterministic, so we collect keys and sort
/// before emitting (Pitfall 11 from 19-PATTERNS.md).
#[must_use]
pub fn build_envelope_payload(config: &ProjectConfig) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    push_lp(&mut buf, config.version.as_bytes());   // field 1
    push_lp(&mut buf, config.created.as_bytes());   // field 2

    // Field 3: format_version encoded as a decimal string (Pitfall 6: decimal-string
    // encoding is consistent with other integer-valued fields in this codebase; a raw
    // u32-BE value would be a different encoding and must not be mixed).
    push_lp(&mut buf, config.format_version.to_string().as_bytes()); // field 3

    // Fields 4-6: security-relevant file-scope config (REM-02, PAR-14/PAR-06).
    push_lp_opt(&mut buf, config.secrets_filename.as_deref()); // field 4
    push_lp_opt(&mut buf, config.secrets_suffix.as_deref());   // field 5
    push_lp_opt(&mut buf, config.ignore.as_deref());           // field 6

    // Fields 7-8: hook flags (Pitfall 1: HooksConfig has Option<bool>, not Option<String>;
    // encode via bool-to-str map so push_lp_opt receives Option<&str> as required).
    push_lp_opt(
        &mut buf,
        config.hooks.git_pre_commit
            .map(|b| if b { "true" } else { "false" }),
    ); // field 7
    push_lp_opt(
        &mut buf,
        config.hooks.git_post_checkout
            .map(|b| if b { "true" } else { "false" }),
    ); // field 8

    // Fields 9-18: vault region (Phase 46, plan 46-02) — emitted ONLY for
    // format_version >= 3 (Phase 46.1, plan 46.1-01). For fv <= 2 we emit NOTHING here,
    // so the bytes between field 8 and the per-user loop are byte-identical to the legacy
    // schema-v2 layout (no vault region, no count field) — the backward-compat contract
    // for existing v2.x repos (T-46.1-01 / T-46.1-03).
    // The gate is on the version number, NOT config.vault.is_some() and NOT the `vault`
    // Cargo feature: an fv=3 config emits the region (all-None/zero when [vault] absent)
    // on every build, preserving R4 feature-independence (VCFG-02).
    if config.format_version >= 3 {
        let (vault_address, vault_namespace, vault_default_binding, vault_tls_ca_secret, vault_bindings, vault_auth) =
            match config.vault.as_ref() {
                Some(vc) => (
                    vc.address.as_deref(),
                    vc.namespace.as_deref(),
                    vc.default_binding.as_deref(),
                    vc.tls_ca_secret.as_deref(),
                    Some(&vc.bindings),
                    vc.auth.as_ref(),
                ),
                None => (None, None, None, None, None, None),
            };
        push_lp_opt(&mut buf, vault_address);           // field  9
        push_lp_opt(&mut buf, vault_namespace);         // field 10
        push_lp_opt(&mut buf, vault_default_binding);   // field 11
        push_lp_opt(&mut buf, vault_tls_ca_secret);     // field 12

        // Field 13: bindings count (u32 BE).
        // BTreeMap ensures iteration order is deterministic (key-sorted) — load-bearing.
        let bindings_count = vault_bindings.map_or(0u32, |b| {
            // Why: binding count is bounded by .sss.toml structure well below u32::MAX.
            #[allow(clippy::cast_possible_truncation)]
            { b.len() as u32 }
        });
        buf.extend_from_slice(&bindings_count.to_be_bytes()); // field 13

        // Field 14: per-binding loop (BTree-sorted by binding name for determinism).
        if let Some(bindings) = vault_bindings {
            for (name, binding) in bindings {
                push_lp(&mut buf, name.as_bytes());
                // kv_version encoded as decimal string ("" when None — consistent with push_lp_opt).
                // The owned String must outlive the push_lp_opt call, so we allocate here
                // rather than in a closure to avoid borrow-check issues with temporary lifetimes.
                let kv_version_str = binding.kv_version.map(|v| v.to_string());
                push_lp_opt(&mut buf, kv_version_str.as_deref());
                push_lp_opt(&mut buf, binding.mount.as_deref());
                push_lp_opt(&mut buf, binding.default_field.as_deref());
            }
        }

        // Fields 15-18: vault.auth fields.
        push_lp_opt(&mut buf, vault_auth.and_then(|a| a.method.as_deref()));           // field 15
        push_lp_opt(&mut buf, vault_auth.and_then(|a| a.role_id.as_deref()));          // field 16
        push_lp_opt(&mut buf, vault_auth.and_then(|a| a.secret_id_secret.as_deref())); // field 17
        push_lp_opt(&mut buf, vault_auth.and_then(|a| a.token_secret.as_deref()));     // field 18
    }

    // Fields 19+: per-user loop (unchanged from schema v2).
    let mut usernames: Vec<&String> = config.users.keys().collect();
    usernames.sort();
    for username in usernames {
        let uc = &config.users[username];
        push_lp(&mut buf, username.as_bytes());
        push_lp(&mut buf, uc.public.as_bytes());
        push_lp(&mut buf, uc.sealed_key.as_bytes());
        push_lp(&mut buf, uc.added.as_bytes());
        push_lp_opt(&mut buf, uc.hybrid_public.as_deref());
        push_lp_opt(&mut buf, uc.sig_ed448_public.as_deref());
        push_lp_opt(&mut buf, uc.sig_mldsa65_public.as_deref());
    }
    buf
}

/// Sign a canonical envelope payload with both Ed448 and ML-DSA-65 (AND-composition).
/// Returns the assembled `EnvelopeSig` (defined in `src/project.rs`) ready for serde.
///
/// The signing context is selected by `format_version` via
/// `context_for_format_version(format_version)` for BOTH legs: an `fv <= 2` config signs
/// under `ENVELOPE_SIG_CONTEXT_V2` (legacy schema-v2 payload), an `fv >= 3` config signs
/// under `ENVELOPE_SIG_CONTEXT` (vault-inclusive payload). This pairs with the verify-side
/// dispatch in `src/project.rs` so a signature is verifiable only under the arm matching
/// its payload schema. Callers MUST pass the SAME `format_version` they used to build
/// `payload` via `build_envelope_payload`.
///
/// Mirrors `src/keystore/sig.rs::sign_entry` — same call shape, prefixes errors with
/// `envelope:`.
pub fn sign_envelope(
    ed448_sk: &Ed448SigningKey,
    mldsa_sk: &MlDsa65SigningKey,
    payload: &[u8],
    format_version: u32,
) -> Result<EnvelopeSig> {
    let ed448_sig = Ed448Standard::sign_with_context(ed448_sk, payload, context_for_format_version(format_version))
        .map_err(|e| anyhow!("envelope: Ed448 sign failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::sign_with_context(mldsa_sk, payload, context_for_format_version(format_version))
        .map_err(|e| anyhow!("envelope: ML-DSA-65 sign failed: {e}"))?;
    Ok(EnvelopeSig {
        ed448: BASE64_STANDARD.encode(Ed448Standard::signature_to_bytes(&ed448_sig)),
        mldsa65: BASE64_STANDARD.encode(MlDsa65Fips204::signature_to_bytes(&mldsa_sig)),
    })
}

/// Verify an `EnvelopeSig` against payload + verifying keys using the supplied `context`.
/// Returns `Err` if EITHER leg fails (AND-composition).
///
/// CRITICAL (mirrors src/keystore/sig.rs):
///   - `Ed448::verify_with_context` returns `bool` (use `if !`)
///   - ML-DSA-65::verify_with_context returns `Result<()>` (use `.map_err`)
///
/// Both shapes are wrapped into the same `envelope:`-prefixed error so
/// NEG-01/NEG-02 can pin the failing leg by substring match.
///
/// This is an inner helper used by `verify_envelope` (v3) and
/// `verify_envelope_signature_v2` (v2). It is not `pub` — callers must go
/// through the context-selecting wrappers to prevent accidental v2/v3 mix-up.
fn verify_envelope_with_context(
    ed448_pk: &Ed448VerifyingKey,
    mldsa_pk: &MlDsa65VerifyingKey,
    payload: &[u8],
    sig: &EnvelopeSig,
    context: &[u8],
) -> Result<()> {
    let ed448_sig_bytes = BASE64_STANDARD
        .decode(sig.ed448.as_bytes())
        .map_err(|e| anyhow!("envelope: Ed448 sig base64 decode failed: {e}"))?;
    let ed448_sig = Ed448Standard::signature_from_bytes(&ed448_sig_bytes)
        .map_err(|e| anyhow!("envelope: Ed448 sig parse failed: {e}"))?;
    if !Ed448Standard::verify_with_context(ed448_pk, payload, context, &ed448_sig) {
        return Err(anyhow!(
            "envelope: Ed448 leg of AND-composition signature verification failed"
        ));
    }

    let mldsa_sig_bytes = BASE64_STANDARD
        .decode(sig.mldsa65.as_bytes())
        .map_err(|e| anyhow!("envelope: ML-DSA-65 sig base64 decode failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::signature_from_bytes(&mldsa_sig_bytes)
        .map_err(|e| anyhow!("envelope: ML-DSA-65 sig parse failed: {e}"))?;
    MlDsa65Fips204::verify_with_context(mldsa_pk, payload, context, &mldsa_sig)
        .map_err(|e| {
            anyhow!("envelope: ML-DSA-65 leg of AND-composition signature verification failed: {e}")
        })?;

    Ok(())
}

/// Verify an `EnvelopeSig` against payload + verifying keys under the **v3** context.
///
/// Use this for `format_version=3` envelopes. For `format_version=2` envelopes, use
/// `verify_envelope_signature_v2` which drives the v2-context `verify_envelope_signature`
/// path via `ENVELOPE_SIG_CONTEXT_V2`.
pub fn verify_envelope(
    ed448_pk: &Ed448VerifyingKey,
    mldsa_pk: &MlDsa65VerifyingKey,
    payload: &[u8],
    sig: &EnvelopeSig,
) -> Result<()> {
    verify_envelope_with_context(ed448_pk, mldsa_pk, payload, sig, ENVELOPE_SIG_CONTEXT)
}

/// Try-all-users verifier (D-05).
///
/// Iterates `config.users` sorted by username. For each user that advertises
/// BOTH `sig_ed448_public` and `sig_mldsa65_public`, attempts to verify the
/// envelope signature with their pubkeys. First successful verify wins.
/// All-fail returns a hard error listing every attempted username.
///
/// `_path` is reserved for richer error messages (loader passes the file path
/// through). The current body uses it via the caller's `with_context`.
pub fn verify_envelope_signature(config: &ProjectConfig, _path: &Path) -> Result<()> {
    let payload = build_envelope_payload(config);
    let sig = config
        .envelope
        .as_ref()
        .and_then(|e| e.sig.as_ref())
        .ok_or_else(|| anyhow!("envelope: missing [envelope.sig] table"))?;

    // HashMap iteration is non-deterministic — sort by username for replayable
    // behaviour and stable error-message ordering (D-05; Pitfall 11 of 19-PATTERNS.md).
    let mut sorted_users: Vec<(&String, &crate::project::UserConfig)> =
        config.users.iter().collect();
    sorted_users.sort_by_key(|(name, _)| name.as_str());

    // Collect per-user errors so the final "all-fail" message names which leg
    // failed for each user (NEG-01/NEG-02 assert the leg name appears in the
    // error; T-19-06 mitigation: AND-composition is visible in error output).
    let mut attempted: Vec<(&str, String)> = Vec::new();
    for (username, user) in sorted_users {
        let (Some(ed_pk_b64), Some(ml_pk_b64)) =
            (user.sig_ed448_public.as_deref(), user.sig_mldsa65_public.as_deref())
        else {
            attempted.push((username.as_str(), "no sig pubkeys".to_string()));
            continue;
        };
        let Ok(ed_pk_bytes) = BASE64_STANDARD.decode(ed_pk_b64.as_bytes()) else {
            attempted.push((username.as_str(), "Ed448 pubkey base64 decode failed".to_string()));
            continue;
        };
        let Ok(ml_pk_bytes) = BASE64_STANDARD.decode(ml_pk_b64.as_bytes()) else {
            attempted.push((username.as_str(), "ML-DSA-65 pubkey base64 decode failed".to_string()));
            continue;
        };
        let Ok(ed_pk) = Ed448Standard::verifying_key_from_bytes(&ed_pk_bytes) else {
            attempted.push((username.as_str(), "Ed448 pubkey parse failed".to_string()));
            continue;
        };
        let Ok(ml_pk) = MlDsa65Fips204::verifying_key_from_bytes(&ml_pk_bytes) else {
            attempted.push((username.as_str(), "ML-DSA-65 pubkey parse failed".to_string()));
            continue;
        };

        match verify_envelope(&ed_pk, &ml_pk, &payload, sig) {
            Ok(()) => {
                // REM-26 (CRY-12): emit the resolved signer at debug level so the
                // accepted signer is observable without changing the return value or
                // the first-match-wins iteration logic.  Full signer-identity binding
                // is deferred (locked decision); this satisfies the observability goal.
                log::debug!("envelope signature verified for signer={username}");
                return Ok(());
            }
            Err(e) => {
                attempted.push((username.as_str(), e.to_string()));
            }
        }
    }

    let detail = attempted
        .iter()
        .map(|(name, reason)| format!("{name}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ");
    Err(anyhow!(
        "envelope: signature verification failed for all attempted users: {detail}"
    ))
}

/// Try-all-users verifier for **`format_version=2`** envelopes (verify-only, v2 context).
///
/// Identical to `verify_envelope_signature` but uses `ENVELOPE_SIG_CONTEXT_V2`
/// (`b"sss-toml-envelope-sig-v2"`) so that existing v2-signed repos continue to
/// READ/verify unchanged after the v3 context bump.
///
/// MUST NOT be used for new signing — all new envelopes must use `sign_envelope`
/// which drives `ENVELOPE_SIG_CONTEXT` (v3). This function is `format_version=2`
/// dispatch-only; it is called exclusively from the `2 =>` arm in `src/project.rs`.
///
/// The `_path` parameter is reserved for richer error messages.
pub fn verify_envelope_signature_v2(config: &ProjectConfig, _path: &Path) -> Result<()> {
    let payload = build_envelope_payload(config);
    let sig = config
        .envelope
        .as_ref()
        .and_then(|e| e.sig.as_ref())
        .ok_or_else(|| anyhow!("envelope: missing [envelope.sig] table"))?;

    let mut sorted_users: Vec<(&String, &crate::project::UserConfig)> =
        config.users.iter().collect();
    sorted_users.sort_by_key(|(name, _)| name.as_str());

    let mut attempted: Vec<(&str, String)> = Vec::new();
    for (username, user) in sorted_users {
        let (Some(ed_pk_b64), Some(ml_pk_b64)) =
            (user.sig_ed448_public.as_deref(), user.sig_mldsa65_public.as_deref())
        else {
            attempted.push((username.as_str(), "no sig pubkeys".to_string()));
            continue;
        };
        let Ok(ed_pk_bytes) = BASE64_STANDARD.decode(ed_pk_b64.as_bytes()) else {
            attempted.push((username.as_str(), "Ed448 pubkey base64 decode failed".to_string()));
            continue;
        };
        let Ok(ml_pk_bytes) = BASE64_STANDARD.decode(ml_pk_b64.as_bytes()) else {
            attempted.push((username.as_str(), "ML-DSA-65 pubkey base64 decode failed".to_string()));
            continue;
        };
        let Ok(ed_pk) = Ed448Standard::verifying_key_from_bytes(&ed_pk_bytes) else {
            attempted.push((username.as_str(), "Ed448 pubkey parse failed".to_string()));
            continue;
        };
        let Ok(ml_pk) = MlDsa65Fips204::verifying_key_from_bytes(&ml_pk_bytes) else {
            attempted.push((username.as_str(), "ML-DSA-65 pubkey parse failed".to_string()));
            continue;
        };

        match verify_envelope_with_context(&ed_pk, &ml_pk, &payload, sig, ENVELOPE_SIG_CONTEXT_V2) {
            Ok(()) => {
                log::debug!("envelope v2 signature verified for signer={username}");
                return Ok(());
            }
            Err(e) => {
                attempted.push((username.as_str(), e.to_string()));
            }
        }
    }

    let detail = attempted
        .iter()
        .map(|(name, reason)| format!("{name}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ");
    Err(anyhow!(
        "envelope: v2 signature verification failed for all attempted users: {detail}"
    ))
}

/// Shared sign-on-write helper — used by both `sss envelope upgrade-sig` and
/// `sss project vault *` so the two paths cannot drift apart (T-46-20, VCFG-04,
/// VCLI-04).
///
/// # Contract
///
/// The caller MUST set `cfg.format_version` to the target version (2 or 3) before
/// calling this function. This helper does NOT choose or modify `format_version`; it
/// only signs whatever `cfg` carries and persists the result atomically.
///
/// ## Steps performed
///
/// 1. Resolve the writing username via `get_system_username` (`SSS_USER` › config › USER).
/// 2. Require the writer to be listed in `cfg.users` (sign-as-unknown is an error).
/// 3. Open the keystore; prompt for passphrase if the key is password-protected.
/// 4. Load the Ed448 + ML-DSA-65 signing keypair for the writer.
/// 5. Populate `cfg.users[writer].sig_ed448_public` / `sig_mldsa65_public` from the
///    loaded signing key if those fields are not yet set (first-time sig registration).
/// 6. Build the canonical payload via `build_envelope_payload(cfg)` (vault region gated
///    on `cfg.format_version >= 3`).
/// 7. Sign under `context_for_format_version(cfg.format_version)` — v2 context for a
///    no-vault `upgrade-sig` (`cfg.format_version == 2`), v3 context for `project vault *`
///    / vault `upgrade-sig` (`cfg.format_version == 3`).
/// 8. Set `cfg.envelope.sig` to the produced `EnvelopeSig`.
/// 9. Atomically write `cfg` to `path` via `crate::config::write_atomic`.
///
/// On success, prints `"{path}: upgraded to format_version={N}, signed by '{writer}'"`.
pub fn sign_and_write_atomic(cfg: &mut ProjectConfig, path: &Path) -> Result<()> {
    use crate::commands::utils::{get_password_if_protected, get_system_username};
    use crate::keystore::Keystore;

    // Step 1: resolve writer.
    let writer_username = get_system_username()
        .context("could not determine invoking username for sign-on-write")?;

    // Step 2: writer must be listed in the envelope.
    if !cfg.users.contains_key(&writer_username) {
        return Err(anyhow!(
            "user '{}' is not present in {}; cannot sign as an unlisted user",
            writer_username,
            path.display()
        ));
    }

    // Step 3: open keystore + optional passphrase.
    let keystore = Keystore::new()
        .context("failed to open keystore for sign-on-write")?;

    let password_str = get_password_if_protected(
        &keystore,
        "Enter your passphrase to sign the envelope (or press Enter if none): ",
    )
    .context("could not obtain passphrase for sign-on-write")?;

    // Step 4: load signing keypair.
    let (ed_sk, pq_sk) = keystore
        .load_sig_keypair(&writer_username, password_str.as_deref())
        .context("failed to load sig keypair from keystore")?;

    // Step 5: populate per-user sig pubkeys (Option<String> base64, D-06).
    if let Some(u) = cfg.users.get_mut(&writer_username) {
        if u.sig_ed448_public.is_none() {
            u.sig_ed448_public = Some(BASE64_STANDARD.encode(ed_sk.verifying_key().as_bytes()));
        }
        if u.sig_mldsa65_public.is_none() {
            u.sig_mldsa65_public = Some(BASE64_STANDARD.encode(pq_sk.verifying_key().as_bytes()));
        }
    }

    // Step 6: build canonical payload (vault region gated on cfg.format_version >= 3).
    let payload = build_envelope_payload(cfg);

    // Step 7: sign under the context matching cfg.format_version (v2 for fv=2 no-vault
    // upgrade-sig, v3 for fv=3 vault upgrade-sig / project vault).
    let sig = sign_envelope(&ed_sk, &pq_sk, &payload, cfg.format_version)
        .context("envelope signing failed in sign_and_write_atomic")?;

    // Step 8: attach sig to envelope meta.
    cfg.envelope
        .get_or_insert_with(EnvelopeMeta::default)
        .sig = Some(sig);

    // Step 9: atomic write.
    crate::config::write_atomic(cfg, path)
        .context("atomic write failed in sign_and_write_atomic")?;

    println!(
        "{}: upgraded to format_version={}, signed by '{}'",
        path.display(),
        cfg.format_version,
        writer_username,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn envelope_sig_context_byte_exact() {
        // Drift-detector: any future change that mutates ENVELOPE_SIG_CONTEXT must
        // update both this test AND docs/CRYPTOGRAPHY.md §"Envelope Signatures (v3)".
        // Bumped to v3 in plan 46-02 — vault fields added to the signed payload schema.
        assert_eq!(ENVELOPE_SIG_CONTEXT, b"sss-toml-envelope-sig-v3");

        // v2 context is retained for the format_version=2 verify-only arm.
        // Pinned here so any accidental mutation is caught immediately.
        assert_eq!(ENVELOPE_SIG_CONTEXT_V2, b"sss-toml-envelope-sig-v2");

        // v3 and v2 contexts must be byte-distinct (cross-context replay guard).
        assert_ne!(
            ENVELOPE_SIG_CONTEXT, ENVELOPE_SIG_CONTEXT_V2,
            "v3 and v2 contexts must be byte-distinct (T-46-01)"
        );

        // Cross-context-replay guard (T-19-01): MUST differ from keystore context.
        assert_ne!(
            ENVELOPE_SIG_CONTEXT,
            crate::keystore::KEYSTORE_SIG_CONTEXT,
            "envelope and keystore signature contexts MUST be byte-distinct (T-19-01)"
        );
        assert_ne!(
            ENVELOPE_SIG_CONTEXT_V2,
            crate::keystore::KEYSTORE_SIG_CONTEXT,
            "envelope v2 and keystore signature contexts MUST be byte-distinct (T-19-01)"
        );
    }

    #[test]
    fn context_for_format_version_maps_fv_to_context() {
        // Sign-side context selection MUST track the verify-side dispatch ladder in
        // src/project.rs: fv<=2 → v2 context (legacy schema-v2 payload), fv>=3 → v3
        // context (vault-inclusive payload). Pinning the boundary HERE catches a broken
        // vault-region/context pairing at Task 1, not only at the Task 3 integration tests.
        assert_eq!(context_for_format_version(1), ENVELOPE_SIG_CONTEXT_V2);
        assert_eq!(context_for_format_version(2), ENVELOPE_SIG_CONTEXT_V2);
        assert_eq!(context_for_format_version(3), ENVELOPE_SIG_CONTEXT);
        assert_eq!(context_for_format_version(4), ENVELOPE_SIG_CONTEXT);
        assert_eq!(context_for_format_version(u32::MAX), ENVELOPE_SIG_CONTEXT);
        // fv 1 and 2 share the v2 context (both omit the vault region).
        assert_eq!(
            context_for_format_version(1),
            context_for_format_version(2),
            "fv=1 and fv=2 must select the same (v2) context"
        );
        // The v2 and v3 contexts are byte-distinct (cross-context separation, T-46.1-02).
        assert_ne!(context_for_format_version(2), context_for_format_version(3));
    }

    #[test]
    fn fv2_payload_omits_vault_region() {
        // Structural lock at Task 1: an fv=2 config (vault: None) and an fv=3 config that
        // is identical EXCEPT format_version + vault:None must differ by exactly the
        // all-None vault region (36 bytes: 4×push_lp_opt(None)=16 + 4-byte zero count +
        // 4×push_lp_opt(None) auth=16). NOTE: field 3 (format_version decimal string) is
        // a single byte "2" vs "3" in BOTH, so it does not change length — the ONLY length
        // delta is the gated vault region. This catches a regression that re-adds the
        // vault region to the fv<=2 path.
        use crate::project::{ProjectConfig, UserConfig};
        use std::collections::HashMap;

        let mut users = HashMap::new();
        users.insert("alice".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: None,
            sig_mldsa65_public: None,
        });

        // ProjectConfig is not Clone, so build the two configs independently. They differ
        // ONLY in format_version (2 vs 3); both carry vault: None and the same single user.
        let fv2 = ProjectConfig {
            version: "2.0".to_string(),
            format_version: 2,
            created: "2026-05-09T00:00:00Z".to_string(),
            users: users.clone(),
            vault: None,
            ..ProjectConfig::default()
        };
        let fv3 = ProjectConfig {
            version: "2.0".to_string(),
            format_version: 3,
            created: "2026-05-09T00:00:00Z".to_string(),
            users,
            vault: None,
            ..ProjectConfig::default()
        };

        let p2 = build_envelope_payload(&fv2);
        let p3 = build_envelope_payload(&fv3);
        assert_eq!(
            p3.len() - p2.len(),
            36,
            "fv=3 (vault:None) payload must be exactly 36 bytes (all-None vault region) \
             longer than the fv=2 payload; fv=2 must emit NO vault region"
        );
        // The fv=2 payload is a strict byte-prefix of the fv=3 payload up to field 8
        // (everything before the gated region is identical), and its tail (per-user loop)
        // matches the fv=3 tail — i.e. fv=2 == fields 1-8 + per-user loop with the 36-byte
        // vault region spliced out of the fv=3 form.
        assert!(p2.len() < p3.len(), "fv=2 payload must be strictly shorter");
    }

    #[test]
    fn build_envelope_payload_deterministic() {
        use crate::project::{ProjectConfig, UserConfig};
        use std::collections::HashMap;

        let mut users = HashMap::new();
        users.insert("alice".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: None,
            sig_mldsa65_public: None,
        });
        let cfg = ProjectConfig {
            version: "2.0".to_string(),
            created: "2026-05-09T00:00:00Z".to_string(),
            users,
            ..ProjectConfig::default()
        };

        let p1 = build_envelope_payload(&cfg);
        let p2 = build_envelope_payload(&cfg);
        assert_eq!(p1, p2, "build_envelope_payload must be deterministic for fixed input");

        // Sanity: leading bytes are the length-prefixed `version` (3-byte string "2.0").
        assert_eq!(&p1[0..4], &[0, 0, 0, 3]);
        assert_eq!(&p1[4..7], b"2.0");
    }

    /// Test: `verify_envelope_signature` iterates users in sorted order (alice → bob → zelda),
    /// skips users without sig pubkeys, tries wrong pubkeys and continues, then succeeds on
    /// the first user whose pubkey matches (zelda). Validates D-05 / Pitfall 4.
    #[test]
    fn verify_envelope_signature_iterates_users() {
        use crate::project::{EnvelopeMeta, ProjectConfig, UserConfig};
        use std::collections::HashMap;

        // Generate one real signing keypair (used to sign).
        let real_ed = Ed448Standard::generate().unwrap();
        let real_ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(
            &Ed448Standard::verifying_key(&real_ed),
        );
        let real_pq = MlDsa65Fips204::generate().unwrap();
        let real_pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(
            &MlDsa65Fips204::verifying_key(&real_pq),
        );
        let real_ed_pk_b64 = BASE64_STANDARD.encode(real_ed_pk_bytes);
        let real_pq_pk_b64 = BASE64_STANDARD.encode(real_pq_pk_bytes);

        // Generate one wrong keypair (advertised by user "bob" — won't verify).
        let wrong_ed = Ed448Standard::generate().unwrap();
        let wrong_ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(
            &Ed448Standard::verifying_key(&wrong_ed),
        );
        let wrong_pq = MlDsa65Fips204::generate().unwrap();
        let wrong_pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(
            &MlDsa65Fips204::verifying_key(&wrong_pq),
        );

        // 3 users sorted alphabetically:
        //   alice — legacy (no sig pubkey) → skipped
        //   bob   — wrong sig pubkey → verify fails, continue
        //   zelda — real sig pubkey → verify succeeds
        let mut users = HashMap::new();
        users.insert("alice".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: None,    // ← skipped (legacy)
            sig_mldsa65_public: None,
        });
        users.insert("bob".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some(BASE64_STANDARD.encode(wrong_ed_pk_bytes)),  // ← wrong
            sig_mldsa65_public: Some(BASE64_STANDARD.encode(wrong_pq_pk_bytes)),
        });
        users.insert("zelda".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some(real_ed_pk_b64.clone()),  // ← correct
            sig_mldsa65_public: Some(real_pq_pk_b64.clone()),
        });

        let mut cfg = ProjectConfig {
            version: "2.0".to_string(),
            format_version: 2,
            created: "2026-05-09T00:00:00Z".to_string(),
            users,
            envelope: None,
            ..ProjectConfig::default()
        };
        let payload = build_envelope_payload(&cfg);
        // fv=2 config: sign under the v2 context (via context_for_format_version(2)) and
        // verify under the matching v2 arm, mirroring the production fv=2 loader dispatch.
        let sig = sign_envelope(&real_ed, &real_pq, &payload, cfg.format_version).unwrap();
        cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

        // Sorted iteration:
        //   alice → skipped (no sig pubkey)
        //   bob   → continues (wrong sig pubkey, verify_envelope returns Err)
        //   zelda → succeeds (first match wins)
        verify_envelope_signature_v2(&cfg, std::path::Path::new("/dev/null")).unwrap();
    }

    /// Test: mutating each newly-signed config field (REM-02) without re-signing
    /// causes `verify_envelope_signature` to return `Err` (per-field tamper rejection).
    ///
    /// Covers all five newly-signed fields added in plan 38-01 (REM-01/02):
    ///   - `secrets_filename`  (field 4 in the v2 payload)
    ///   - `secrets_suffix`    (field 5)
    ///   - ignore              (field 6)
    ///   - `hooks.git_pre_commit` (field 7)
    ///   - `hooks.git_post_checkout` (field 8)
    ///
    /// WR-02 (Phase 38-04): `base_cfg` sets BOTH hook fields to `Some(...)` so that
    /// field 8 contributes distinct bytes to the payload. A coding error that swaps
    /// fields 7 and 8 in `build_envelope_payload` would otherwise be undetectable
    /// (both `None` → identical payload regardless of order).
    ///
    /// Each field is mutated in turn without calling `sign_envelope` again; the
    /// signature table from the original signing is left untouched, so the
    /// verification must detect the payload mismatch and return `Err`.
    // Why: exhaustive per-field tamper test covers 5 signed fields, each with setup,
    // mutation, and assertion; splitting would obscure the shared signing context.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn new_fields_tamper_rejects() {
        use crate::project::{EnvelopeMeta, HooksConfig, ProjectConfig, UserConfig};
        use std::collections::HashMap;
        use std::path::Path;

        // Generate one real signing keypair.
        let ed_sk = Ed448Standard::generate().unwrap();
        let ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(
            &Ed448Standard::verifying_key(&ed_sk),
        );
        let pq_sk = MlDsa65Fips204::generate().unwrap();
        let pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(
            &MlDsa65Fips204::verifying_key(&pq_sk),
        );

        let mut users = HashMap::new();
        users.insert("alice".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some(BASE64_STANDARD.encode(ed_pk_bytes)),
            sig_mldsa65_public: Some(BASE64_STANDARD.encode(pq_pk_bytes)),
        });

        // Build the canonical signed configuration.
        // WR-02 (Phase 38-04): both hook fields are set to Some(...) so that
        // field 8 (git_post_checkout) contributes distinct bytes to the payload
        // and a field-swap bug between positions 7 and 8 cannot escape detection.
        let base_cfg = ProjectConfig {
            version: "2.0".to_string(),
            format_version: 2,
            created: "2026-05-09T00:00:00Z".to_string(),
            users: users.clone(),
            secrets_filename: Some("real.env".to_string()),
            secrets_suffix: Some(".enc".to_string()),
            ignore: Some("node_modules".to_string()),
            hooks: HooksConfig {
                git_pre_commit: Some(true),
                git_post_checkout: Some(false), // non-None: field 8 has distinct bytes
            },
            ..ProjectConfig::default()
        };

        // Sign the original payload under the v2 context (base_cfg is fv=2). Verifying the
        // tampered variants under the matching v2 arm ensures each rejection is due to the
        // mutated field, not a sign/verify context mismatch.
        let original_payload = build_envelope_payload(&base_cfg);
        let sig = sign_envelope(&ed_sk, &pq_sk, &original_payload, base_cfg.format_version).unwrap();

        // Helper: build a config variant with the given sig table and verify.
        let verify_tampered = |mut cfg: ProjectConfig| -> bool {
            cfg.envelope = Some(EnvelopeMeta { sig: Some(sig.clone()) });
            verify_envelope_signature_v2(&cfg, Path::new("/dev/null")).is_err()
        };

        // --- Field 4: secrets_filename tamper ---
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: Some("evil.env".to_string()), // TAMPERED
                secrets_suffix: base_cfg.secrets_suffix.clone(),
                ignore: base_cfg.ignore.clone(),
                hooks: base_cfg.hooks.clone(),
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "tampered secrets_filename must cause verify_envelope_signature to return Err"
            );
        }

        // --- Field 5: secrets_suffix tamper ---
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: base_cfg.secrets_filename.clone(),
                secrets_suffix: Some(".evil".to_string()), // TAMPERED
                ignore: base_cfg.ignore.clone(),
                hooks: base_cfg.hooks.clone(),
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "tampered secrets_suffix must cause verify_envelope_signature to return Err"
            );
        }

        // --- Field 6: ignore tamper ---
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: base_cfg.secrets_filename.clone(),
                secrets_suffix: base_cfg.secrets_suffix.clone(),
                ignore: Some("evil_dir/".to_string()), // TAMPERED
                hooks: base_cfg.hooks.clone(),
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "tampered ignore must cause verify_envelope_signature to return Err"
            );
        }

        // --- Field 7: hooks.git_pre_commit tamper (Some(true) → Some(false)) ---
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: base_cfg.secrets_filename.clone(),
                secrets_suffix: base_cfg.secrets_suffix.clone(),
                ignore: base_cfg.ignore.clone(),
                hooks: HooksConfig {
                    git_pre_commit: Some(false), // TAMPERED (was Some(true))
                    git_post_checkout: Some(false),
                },
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "tampered hooks.git_pre_commit must cause verify_envelope_signature to return Err"
            );
        }

        // --- Field 7: hooks.git_pre_commit tamper (Some(true) → None) ---
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: base_cfg.secrets_filename.clone(),
                secrets_suffix: base_cfg.secrets_suffix.clone(),
                ignore: base_cfg.ignore.clone(),
                hooks: HooksConfig {
                    git_pre_commit: None, // TAMPERED (was Some(true))
                    git_post_checkout: Some(false),
                },
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "hooks.git_pre_commit set to None must cause verify_envelope_signature to return Err"
            );
        }

        // --- Field 8: hooks.git_post_checkout tamper (Some(false) → Some(true)) ---
        // WR-02 (Phase 38-04): field 8 was always None in base_cfg before this fix,
        // making it impossible to detect field-swap bugs between positions 7 and 8.
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: base_cfg.secrets_filename.clone(),
                secrets_suffix: base_cfg.secrets_suffix.clone(),
                ignore: base_cfg.ignore.clone(),
                hooks: HooksConfig {
                    git_pre_commit: Some(true),
                    git_post_checkout: Some(true), // TAMPERED (was Some(false))
                },
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "tampered hooks.git_post_checkout must cause verify_envelope_signature to return Err"
            );
        }

        // --- Field 8: hooks.git_post_checkout tamper (Some(false) → None) ---
        {
            let mut tampered = ProjectConfig {
                version: base_cfg.version.clone(),
                format_version: base_cfg.format_version,
                created: base_cfg.created.clone(),
                users: users.clone(),
                secrets_filename: base_cfg.secrets_filename.clone(),
                secrets_suffix: base_cfg.secrets_suffix.clone(),
                ignore: base_cfg.ignore.clone(),
                hooks: HooksConfig {
                    git_pre_commit: Some(true),
                    git_post_checkout: None, // TAMPERED (was Some(false))
                },
                ..ProjectConfig::default()
            };
            tampered.envelope = None;
            assert!(
                verify_tampered(tampered),
                "hooks.git_post_checkout set to None must cause verify_envelope_signature to return Err"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 50,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn round_trip_arbitrary_envelope(
            version_suffix in "[0-9]{1,2}",
            username in "[a-z]{3,12}",
            public_b64 in "[A-Za-z0-9+/=]{20,80}",
            sealed_b64 in "[A-Za-z0-9+/=]{20,200}",
        ) {
            use crate::project::{EnvelopeMeta, ProjectConfig, UserConfig};
            use std::collections::HashMap;

            let ed448_sk = Ed448Standard::generate().unwrap();
            let ed448_pk_bytes = Ed448Standard::verifying_key_to_bytes(
                &Ed448Standard::verifying_key(&ed448_sk),
            );
            let ed448_pk = Ed448Standard::verifying_key_from_bytes(&ed448_pk_bytes).unwrap();

            let mldsa_sk = MlDsa65Fips204::generate().unwrap();
            let mldsa_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(
                &MlDsa65Fips204::verifying_key(&mldsa_sk),
            );
            let mldsa_pk = MlDsa65Fips204::verifying_key_from_bytes(&mldsa_pk_bytes).unwrap();

            let mut users = HashMap::new();
            users.insert(username.clone(), UserConfig {
                public: public_b64.clone(),
                sealed_key: sealed_b64.clone(),
                added: "2026-05-09T00:00:00Z".to_string(),
                hybrid_public: None,
                sig_ed448_public: Some(BASE64_STANDARD.encode(ed448_pk_bytes)),
                sig_mldsa65_public: Some(BASE64_STANDARD.encode(mldsa_pk_bytes)),
            });

            // fv=3 (vault: None) so this round-trip exercises the v3 sign+verify path:
            // sign_envelope(fv=3) selects the v3 context, and verify_envelope /
            // verify_envelope_signature (both v3) accept it. The vault region is emitted
            // all-None for an fv=3 config with no [vault], per the format_version gate.
            let mut cfg = ProjectConfig {
                version: format!("2.{version_suffix}"),
                format_version: 3,
                created: "2026-05-09T00:00:00Z".to_string(),
                users,
                vault: None,
                ..ProjectConfig::default()
            };

            let payload = build_envelope_payload(&cfg);
            let sig = sign_envelope(&ed448_sk, &mldsa_sk, &payload, cfg.format_version).unwrap();
            cfg.envelope = Some(EnvelopeMeta { sig: Some(sig.clone()) });

            // Direct verify (single-user happy path).
            verify_envelope(&ed448_pk, &mldsa_pk, &payload, &sig).unwrap();
            // Try-all-users verify (sees the user's advertised pubkey, succeeds).
            verify_envelope_signature(&cfg, std::path::Path::new("/dev/null")).unwrap();
        }
    }

    /// Test: all-fail path lists every attempted username in the error message (D-05).
    ///
    /// 3 users (alice, bob, carol) all advertise the *wrong* sig pubkey.
    /// The real signer's pubkey is not present in the envelope.
    /// `verify_envelope_signature` must return an error that names all three users
    /// and includes "verification failed for all attempted users".
    #[test]
    fn verify_all_fail_lists_users() {
        use crate::project::{EnvelopeMeta, ProjectConfig, UserConfig};
        use std::collections::HashMap;

        // Real signer — never advertised by any user.
        let real_ed = Ed448Standard::generate().unwrap();
        let real_pq = MlDsa65Fips204::generate().unwrap();

        // Wrong signer — advertised by every user.
        let wrong_ed = Ed448Standard::generate().unwrap();
        let wrong_ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(
            &Ed448Standard::verifying_key(&wrong_ed),
        );
        let wrong_pq = MlDsa65Fips204::generate().unwrap();
        let wrong_pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(
            &MlDsa65Fips204::verifying_key(&wrong_pq),
        );
        let wrong_ed_pk_b64 = BASE64_STANDARD.encode(wrong_ed_pk_bytes);
        let wrong_pq_pk_b64 = BASE64_STANDARD.encode(wrong_pq_pk_bytes);

        let mut users = HashMap::new();
        for name in &["alice", "bob", "carol"] {
            users.insert((*name).to_string(), UserConfig {
                public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                added: "2026-05-09T00:00:00Z".to_string(),
                hybrid_public: None,
                sig_ed448_public: Some(wrong_ed_pk_b64.clone()),
                sig_mldsa65_public: Some(wrong_pq_pk_b64.clone()),
            });
        }
        let mut cfg = ProjectConfig {
            version: "2.0".to_string(),
            format_version: 2,
            created: "2026-05-09T00:00:00Z".to_string(),
            users,
            envelope: None,
            ..ProjectConfig::default()
        };
        let payload = build_envelope_payload(&cfg);
        // fv=2 config: sign under v2 and verify under the matching v2 arm. All users
        // advertise the WRONG pubkey, so every leg fails on pubkey mismatch (not context)
        // and the all-fail error lists each attempted username.
        let sig = sign_envelope(&real_ed, &real_pq, &payload, cfg.format_version).unwrap();
        cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

        let err = verify_envelope_signature_v2(&cfg, std::path::Path::new("/dev/null"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("alice"), "error must list alice, got: {err}");
        assert!(err.contains("bob"),   "error must list bob, got: {err}");
        assert!(err.contains("carol"), "error must list carol, got: {err}");
        assert!(
            err.contains("verification failed for all attempted users"),
            "error must announce all-fail, got: {err}"
        );
    }

    /// Test: `verify_envelope_signature` returns `Ok` for the matched user even
    /// after the REM-26 debug-log addition (non-behavioral verification).
    ///
    /// The signer identity is emitted via `tracing::debug!` on the matched-user
    /// return path (`tracing-test` is not a dev-dependency; behavioral assertion
    /// via return value is sufficient per the plan).  This test is distinct from
    /// `verify_envelope_signature_iterates_users` in that it documents the REM-26
    /// requirement explicitly and guards the return-value invariant.
    ///
    /// REM-26 / CRY-12: the resolved signer is observable via `RUST_LOG=debug`
    /// or any tracing subscriber; the policy decision (first-match-wins) is
    /// documented in `docs/security-model.md §Envelope Signature: First-Match-Wins`.
    #[test]
    fn test_verify_envelope_signer_log_does_not_break_verification() {
        use crate::project::{EnvelopeMeta, ProjectConfig, UserConfig};
        use std::collections::HashMap;

        // One real signing keypair; single user "carol" advertises it.
        let real_ed = Ed448Standard::generate().unwrap();
        let real_ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(
            &Ed448Standard::verifying_key(&real_ed),
        );
        let real_pq = MlDsa65Fips204::generate().unwrap();
        let real_pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(
            &MlDsa65Fips204::verifying_key(&real_pq),
        );

        let mut users = HashMap::new();
        users.insert("carol".to_string(), UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-06-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some(BASE64_STANDARD.encode(real_ed_pk_bytes)),
            sig_mldsa65_public: Some(BASE64_STANDARD.encode(real_pq_pk_bytes)),
        });

        let mut cfg = ProjectConfig {
            version: "2.0".to_string(),
            format_version: 2,
            created: "2026-06-09T00:00:00Z".to_string(),
            users,
            envelope: None,
            ..ProjectConfig::default()
        };
        let payload = build_envelope_payload(&cfg);
        // fv=2 config: sign + verify under the matching v2 context.
        let sig = sign_envelope(&real_ed, &real_pq, &payload, cfg.format_version).unwrap();
        cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

        // REM-26: verify must return Ok; tracing::debug!(signer = %username, ...)
        // is emitted on the matched-user arm but does not affect the return value.
        let result = verify_envelope_signature_v2(&cfg, std::path::Path::new("/dev/null"));
        assert!(result.is_ok(), "REM-26: signer debug log must not break verification: {result:?}");
    }
}
