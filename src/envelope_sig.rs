//! Hybrid AND-composition signatures over the `.sss.toml` envelope (Phase 19, PQSIG-04).
//!
//! Combines `trelis_primitives::Ed448Standard` (RFC 8032 SHAKE256) with
//! `trelis_primitives::MlDsa65Fips204` (FIPS 204) via AND composition:
//! BOTH signatures must verify; either failure rejects the envelope.
//!
//! Domain-separation context: `b"sss-toml-envelope-sig-v1"` (D-02).
//! Canonical payload: length-prefixed concat of identity-bearing fields (D-03).
//!
//! See `docs/CRYPTOGRAPHY.md` §"Envelope Signatures (v2)" for the
//! authoritative format spec (added in plan unit 19-05).

#![cfg(feature = "hybrid")]
// Why: signing primitives use trelis-primitives types that are gated on the
// `hybrid` feature in this crate's Cargo.toml.

use anyhow::{anyhow, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::path::Path;
use trelis_primitives::{
    Ed448Scheme, Ed448SigningKey, Ed448Standard, Ed448VerifyingKey,
    MlDsa65Fips204, MlDsa65SigningKey, MlDsa65VerifyingKey, MlDsaScheme,
};

use crate::project::{EnvelopeSig, ProjectConfig};

/// Domain-separation context for `.sss.toml` envelope signatures (D-02).
///
/// MUST be byte-distinct from `crate::keystore::sig::KEYSTORE_SIG_CONTEXT`
/// to prevent cross-context replay (T-19-01). Drift-detector test below
/// pins the bytes; any change must update both this test AND
/// `docs/CRYPTOGRAPHY.md` §"Envelope Signatures (v2)".
pub const ENVELOPE_SIG_CONTEXT: &[u8] = b"sss-toml-envelope-sig-v1";

/// Length-prefix a single byte slice into the buffer. Layout: `(len_u32_be, bytes)`.
fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Length-prefix an `Option<&str>`; `None` becomes `(0_u32_be, 0 bytes)`.
fn push_lp_opt(buf: &mut Vec<u8>, opt: Option<&str>) {
    push_lp(buf, opt.unwrap_or("").as_bytes());
}

/// Canonical signed-payload encoding (D-03).
///
/// Field order is FIXED:
///   1. version
///   2. created
///   3. per-user (sorted by username):
///      username, public, sealed_key, added, hybrid_public,
///      sig_ed448_public, sig_mldsa65_public
///
/// Each variable-length field is preceded by a `u32`-BE length prefix to
/// prevent length-extension / boundary-shift attacks (T-19-02).
/// Absent `Option<String>` fields encode as 4 zero bytes (D-03).
///
/// Note: `ProjectConfig.users` is `HashMap` (see src/project.rs).
/// Iteration order is non-deterministic, so we collect keys and sort
/// before emitting (Pitfall 11 from 19-PATTERNS.md).
pub fn build_envelope_payload(config: &ProjectConfig) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    push_lp(&mut buf, config.version.as_bytes());
    push_lp(&mut buf, config.created.as_bytes());

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
/// Mirrors `src/keystore/sig.rs::sign_entry` — same call shape,
/// substitutes `ENVELOPE_SIG_CONTEXT` and prefixes errors with `envelope:`.
pub fn sign_envelope(
    ed448_sk: &Ed448SigningKey,
    mldsa_sk: &MlDsa65SigningKey,
    payload: &[u8],
) -> Result<EnvelopeSig> {
    let ed448_sig = Ed448Standard::sign_with_context(ed448_sk, payload, ENVELOPE_SIG_CONTEXT)
        .map_err(|e| anyhow!("envelope: Ed448 sign failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::sign_with_context(mldsa_sk, payload, ENVELOPE_SIG_CONTEXT)
        .map_err(|e| anyhow!("envelope: ML-DSA-65 sign failed: {e}"))?;
    Ok(EnvelopeSig {
        ed448: BASE64_STANDARD.encode(Ed448Standard::signature_to_bytes(&ed448_sig)),
        mldsa65: BASE64_STANDARD.encode(MlDsa65Fips204::signature_to_bytes(&mldsa_sig)),
    })
}

/// Verify an `EnvelopeSig` against payload + verifying keys.
/// Returns `Err` if EITHER leg fails (AND-composition).
///
/// CRITICAL (mirrors src/keystore/sig.rs):
///   - Ed448::verify_with_context returns `bool` (use `if !`)
///   - ML-DSA-65::verify_with_context returns `Result<()>` (use `.map_err`)
/// Both shapes are wrapped into the same `envelope:`-prefixed error so
/// NEG-01/NEG-02 can pin the failing leg by substring match.
pub fn verify_envelope(
    ed448_pk: &Ed448VerifyingKey,
    mldsa_pk: &MlDsa65VerifyingKey,
    payload: &[u8],
    sig: &EnvelopeSig,
) -> Result<()> {
    let ed448_sig_bytes = BASE64_STANDARD
        .decode(sig.ed448.as_bytes())
        .map_err(|e| anyhow!("envelope: Ed448 sig base64 decode failed: {e}"))?;
    let ed448_sig = Ed448Standard::signature_from_bytes(&ed448_sig_bytes)
        .map_err(|e| anyhow!("envelope: Ed448 sig parse failed: {e}"))?;
    if !Ed448Standard::verify_with_context(ed448_pk, payload, ENVELOPE_SIG_CONTEXT, &ed448_sig) {
        return Err(anyhow!(
            "envelope: Ed448 leg of AND-composition signature verification failed"
        ));
    }

    let mldsa_sig_bytes = BASE64_STANDARD
        .decode(sig.mldsa65.as_bytes())
        .map_err(|e| anyhow!("envelope: ML-DSA-65 sig base64 decode failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::signature_from_bytes(&mldsa_sig_bytes)
        .map_err(|e| anyhow!("envelope: ML-DSA-65 sig parse failed: {e}"))?;
    MlDsa65Fips204::verify_with_context(mldsa_pk, payload, ENVELOPE_SIG_CONTEXT, &mldsa_sig)
        .map_err(|e| {
            anyhow!("envelope: ML-DSA-65 leg of AND-composition signature verification failed: {e}")
        })?;

    Ok(())
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
            Ok(()) => return Ok(()),
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
        "envelope: signature verification failed for all attempted users: {}",
        detail
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn envelope_sig_context_byte_exact() {
        // Drift-detector: any future change that mutates this constant must
        // update both this test AND docs/CRYPTOGRAPHY.md §"Envelope Signatures (v2)".
        assert_eq!(ENVELOPE_SIG_CONTEXT, b"sss-toml-envelope-sig-v1");
        // Cross-context-replay guard (T-19-01): MUST differ from keystore context.
        assert_ne!(
            ENVELOPE_SIG_CONTEXT,
            crate::keystore::KEYSTORE_SIG_CONTEXT,
            "envelope and keystore signature contexts MUST be byte-distinct (T-19-01)"
        );
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

    /// Test: verify_envelope_signature iterates users in sorted order (alice → bob → zelda),
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
        let real_ed_pk_b64 = BASE64_STANDARD.encode(&real_ed_pk_bytes);
        let real_pq_pk_b64 = BASE64_STANDARD.encode(&real_pq_pk_bytes);

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
            sig_ed448_public: Some(BASE64_STANDARD.encode(&wrong_ed_pk_bytes)),  // ← wrong
            sig_mldsa65_public: Some(BASE64_STANDARD.encode(&wrong_pq_pk_bytes)),
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
        let sig = sign_envelope(&real_ed, &real_pq, &payload).unwrap();
        cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

        // Sorted iteration:
        //   alice → skipped (no sig pubkey)
        //   bob   → continues (wrong sig pubkey, verify_envelope returns Err)
        //   zelda → succeeds (first match wins)
        verify_envelope_signature(&cfg, std::path::Path::new("/dev/null")).unwrap();
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
                sig_ed448_public: Some(BASE64_STANDARD.encode(&ed448_pk_bytes)),
                sig_mldsa65_public: Some(BASE64_STANDARD.encode(&mldsa_pk_bytes)),
            });

            let mut cfg = ProjectConfig {
                version: format!("2.{version_suffix}"),
                created: "2026-05-09T00:00:00Z".to_string(),
                users,
                ..ProjectConfig::default()
            };

            let payload = build_envelope_payload(&cfg);
            let sig = sign_envelope(&ed448_sk, &mldsa_sk, &payload).unwrap();
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
    /// verify_envelope_signature must return an error that names all three users
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
        let wrong_ed_pk_b64 = BASE64_STANDARD.encode(&wrong_ed_pk_bytes);
        let wrong_pq_pk_b64 = BASE64_STANDARD.encode(&wrong_pq_pk_bytes);

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
        // Sign with the real keypair (none of the users advertise it).
        let sig = sign_envelope(&real_ed, &real_pq, &payload).unwrap();
        cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

        let err = verify_envelope_signature(&cfg, std::path::Path::new("/dev/null"))
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
}
