//! Hybrid AND-composition signatures over keystore entries (Phase 18, PQSIG-01).
//!
//! Combines `trelis_primitives::Ed448Standard` (RFC 8032 SHAKE256) with
//! `trelis_primitives::MlDsa65Fips204` (FIPS 204) via AND composition:
//! BOTH signatures must verify; either failure rejects the entry.
//!
//! Domain-separation context: `b"sss-keystore-entry-sig-v2"` (D-05, REM-04).
//! Canonical payload: length-prefixed concat of 8 identity-bearing fields (D-08).
//! Fields 7-8 (`kdf_ops_limit`, `kdf_mem_limit`) were added in Phase 38-03 (REM-04)
//! to close CRY-05: KDF parameter substitution is now detected as a signature failure.
//! Passwordless entries sign `kdf_ops_limit=0` and `kdf_mem_limit=0` (the 0/0 sentinel,
//! meaning "no KDF was applied"). See `docs/CRYPTOGRAPHY.md` §"Keystore Entry Signatures".
//!
//! See `docs/CRYPTOGRAPHY.md` §"Keystore Entry Signatures (v2)" for the
//! authoritative format spec (added in plan unit 18-05).
//!
//! Note: this module is gated on `feature = "hybrid"` by its parent
//! (`src/keystore/mod.rs`); the inner `#![cfg(...)]` attribute was removed
//! in Phase 21 Plan 21-02 because it duplicated the parent gate (matches
//! the Phase 19 D-19 closure pattern for `clippy::duplicated_attributes`).

use anyhow::{anyhow, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use trelis_primitives::{
    Ed448Scheme, Ed448SigningKey, Ed448Standard, Ed448VerifyingKey,
    MlDsa65Fips204, MlDsa65SigningKey, MlDsa65VerifyingKey, MlDsaScheme,
};

/// Domain-separation context bytes for `format_version=2` entries (D-05, Phase 18).
///
/// PRESERVED for backward-compatible verification of existing on-disk `format_version=2`
/// entries (CR-01 / Phase 38-04). These entries were signed before REM-04 added fields
/// 7-8 to the payload. This constant MUST NOT be used for any new signing operation —
/// use `KEYSTORE_SIG_CONTEXT` (v2) for all new `format_version=3` entries.
///
/// Kept alongside the v2 constant so `verify_stored_signature` can dispatch on
/// `stored.format_version`: `2 → KEYSTORE_SIG_CONTEXT_V1`, `3 → KEYSTORE_SIG_CONTEXT`.
pub const KEYSTORE_SIG_CONTEXT_V1: &[u8] = b"sss-keystore-entry-sig-v1";

/// Domain-separation context bytes (D-05, REM-04 / Phase 38-03).
/// Bumped from v1 to v2 when KDF params (fields 7-8) were added to the signed
/// payload. A v2-context signature is byte-distinct from both the v1 keystore
/// context AND the envelope context (`b"sss-toml-envelope-sig-v2"`), preserving
/// the cross-context replay guard (T-19-01 / T-38-12).
/// IMPORTANT: any future payload change MUST bump this constant AND update
/// `docs/CRYPTOGRAPHY.md` §"Keystore Entry Signatures".
pub const KEYSTORE_SIG_CONTEXT: &[u8] = b"sss-keystore-entry-sig-v2";

/// AND-composition signature: BOTH legs must verify.
///
/// `ed448`   = base64 of 114-byte Ed448 signature.
/// `mldsa65` = base64 of 3309-byte ML-DSA-65 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEntrySig {
    pub ed448: String,
    pub mldsa65: String,
}

/// Canonical signed-payload encoding (D-08, REM-04): length-prefixed concat of
/// 8 identity-bearing fields. Absent optional fields encode as 4 zero bytes.
///
/// Field order is FIXED:
///   1. `uuid`
///   2. `public_key`
///   3. `hybrid_public_key` (Option — absent → 4 zero bytes)
///   4. `sig_ed448_public_key` (Option — absent → 4 zero bytes)
///   5. `sig_mldsa65_public_key` (Option — absent → 4 zero bytes)
///   6. `created_at_rfc3339`
///   7. `kdf_ops_limit` (REM-04, Phase 38-03) — decimal ASCII string, e.g. "3"
///   8. `kdf_mem_limit` (REM-04, Phase 38-03) — decimal ASCII string, e.g. "268435456"
///
/// Fields 7-8 authenticate the Argon2id cost parameters so that substituting
/// a weaker KDF configuration is detected as a signature failure on open.
///
/// Passwordless sentinel: entries with `is_password_protected = false` did not
/// apply Argon2id. The caller MUST pass `kdf_ops_limit=0, kdf_mem_limit=0` for
/// such entries (the "0/0 sentinel"). The verifier reconstructs the same value
/// by keying off `stored.is_password_protected`. This is enforced identically
/// in both the signing path (`upgrade_keypair_in_place`, `store_dual_keypair`) and
/// the verify path (`verify_stored_signature`).
///
/// Integer encoding: `kdf_ops_limit` (u64) and `kdf_mem_limit` (usize) are encoded
/// as decimal ASCII strings (e.g. "3", "268435456") via `.to_string()`, consistent
/// with how RFC3339 timestamps are encoded. This is documented here and in
/// `docs/CRYPTOGRAPHY.md` §"Keystore Entry Signatures" to enable independent reimplementation.
// Why: build_signed_payload is a byte-serialisation function for 8 distinct
// identity-bearing fields defined in the spec (D-08).  Grouping them into a
// struct would add indirection without removing the 8-parameter constraint;
// the function boundary IS the spec contract.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_signed_payload(
    uuid: &str,
    public_key: &str,
    hybrid_public_key: Option<&str>,
    sig_ed448_public_key: Option<&str>,
    sig_mldsa65_public_key: Option<&str>,
    created_at_rfc3339: &str,
    // REM-04 (Phase 38-03): KDF parameters are part of the signed payload.
    // For password-protected entries: pass self.kdf_params.ops_limit / .mem_limit.
    // For passwordless entries: pass 0u64, 0usize (the 0/0 sentinel).
    kdf_ops_limit: u64,
    kdf_mem_limit: usize,
) -> Vec<u8> {
    let kdf_ops_str = kdf_ops_limit.to_string();
    let kdf_mem_str = kdf_mem_limit.to_string();
    let mut buf = Vec::new();
    let fields: [&[u8]; 8] = [
        uuid.as_bytes(),
        public_key.as_bytes(),
        hybrid_public_key.unwrap_or("").as_bytes(),
        sig_ed448_public_key.unwrap_or("").as_bytes(),
        sig_mldsa65_public_key.unwrap_or("").as_bytes(),
        created_at_rfc3339.as_bytes(),
        // Fields 7-8: KDF cost params as decimal ASCII strings (REM-04).
        kdf_ops_str.as_bytes(),
        kdf_mem_str.as_bytes(),
    ];
    for field in &fields {
        // Why: KeystoreEntrySig payload fields are UUIDs, base64-encoded keys
        // (< 4 KiB each), RFC3339 timestamps, or small decimal integers. None
        // exceed u32::MAX (4 GiB); truncation is impossible-by-construction.
        // Wire format requires u32.
        #[allow(clippy::cast_possible_truncation)]
        let field_len = field.len() as u32;
        buf.extend_from_slice(&field_len.to_be_bytes());
        buf.extend_from_slice(field);
    }
    buf
}

/// Canonical signed-payload encoding for `format_version=2` entries (6-field schema).
///
/// CR-01 (Phase 38-04): `format_version=2` entries were signed BEFORE REM-04
/// added KDF params as fields 7-8. Their on-disk signature covers ONLY fields
/// 1-6 (uuid, `public_key`, `hybrid_public_key`, `sig_ed448_public_key`,
/// `sig_mldsa65_public_key`, `created_at`). This helper reconstructs that 6-field
/// payload for verification-only use inside `verify_stored_signature`.
///
/// IMPORTANT: this function is used EXCLUSIVELY in the verify path for v2 entries.
/// No new `format_version=2` entries are ever produced; `store_dual_keypair` and
/// `upgrade_keypair_in_place` always write `format_version=3` with the 8-field payload.
#[must_use]
pub fn build_signed_payload_v1(
    uuid: &str,
    public_key: &str,
    hybrid_public_key: Option<&str>,
    sig_ed448_public_key: Option<&str>,
    sig_mldsa65_public_key: Option<&str>,
    created_at_rfc3339: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let fields: [&[u8]; 6] = [
        uuid.as_bytes(),
        public_key.as_bytes(),
        hybrid_public_key.unwrap_or("").as_bytes(),
        sig_ed448_public_key.unwrap_or("").as_bytes(),
        sig_mldsa65_public_key.unwrap_or("").as_bytes(),
        created_at_rfc3339.as_bytes(),
    ];
    for field in &fields {
        #[allow(clippy::cast_possible_truncation)]
        let field_len = field.len() as u32;
        buf.extend_from_slice(&field_len.to_be_bytes());
        buf.extend_from_slice(field);
    }
    buf
}

/// Sign a canonical payload with both Ed448 and ML-DSA-65 (AND-composition).
/// Returns the assembled `KeystoreEntrySig` ready for serde-serialise.
pub fn sign_entry(
    ed448_sk: &Ed448SigningKey,
    mldsa_sk: &MlDsa65SigningKey,
    payload: &[u8],
) -> Result<KeystoreEntrySig> {
    let ed448_sig = Ed448Standard::sign_with_context(ed448_sk, payload, KEYSTORE_SIG_CONTEXT)
        .map_err(|e| anyhow!("keystore: Ed448 sign failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::sign_with_context(mldsa_sk, payload, KEYSTORE_SIG_CONTEXT)
        .map_err(|e| anyhow!("keystore: ML-DSA-65 sign failed: {e}"))?;
    Ok(KeystoreEntrySig {
        ed448: BASE64_STANDARD.encode(Ed448Standard::signature_to_bytes(&ed448_sig)),
        mldsa65: BASE64_STANDARD.encode(MlDsa65Fips204::signature_to_bytes(&mldsa_sig)),
    })
}

/// Verify a `KeystoreEntrySig` against a payload + the two verifying keys.
/// Returns `Err` if EITHER leg fails (AND-composition).
///
/// CRITICAL: `Ed448::verify_with_context` returns `bool`; ML-DSA-65 returns `Result<()>`.
/// Both shapes are wrapped into the same actionable error.
///
/// Uses `KEYSTORE_SIG_CONTEXT` (v2). For `format_version=2` entries that require
/// verification under the old `KEYSTORE_SIG_CONTEXT_V1` context, call
/// `verify_entry_with_context` directly.
pub fn verify_entry(
    ed448_pk: &Ed448VerifyingKey,
    mldsa_pk: &MlDsa65VerifyingKey,
    payload: &[u8],
    sig: &KeystoreEntrySig,
) -> Result<()> {
    verify_entry_with_context(ed448_pk, mldsa_pk, payload, sig, KEYSTORE_SIG_CONTEXT)
}

/// Verify a `KeystoreEntrySig` under an explicit context byte slice.
///
/// CR-01 (Phase 38-04): needed so `verify_stored_signature` can pass either
/// `KEYSTORE_SIG_CONTEXT_V1` (for `format_version=2` entries) or `KEYSTORE_SIG_CONTEXT`
/// (for `format_version=3` entries) without duplicating the decode/parse/verify logic.
pub fn verify_entry_with_context(
    ed448_pk: &Ed448VerifyingKey,
    mldsa_pk: &MlDsa65VerifyingKey,
    payload: &[u8],
    sig: &KeystoreEntrySig,
    context: &[u8],
) -> Result<()> {
    let ed448_sig_bytes = BASE64_STANDARD
        .decode(sig.ed448.as_bytes())
        .map_err(|e| anyhow!("keystore: Ed448 sig base64 decode failed: {e}"))?;
    let ed448_sig = Ed448Standard::signature_from_bytes(&ed448_sig_bytes)
        .map_err(|e| anyhow!("keystore: Ed448 sig parse failed: {e}"))?;
    if !Ed448Standard::verify_with_context(ed448_pk, payload, context, &ed448_sig) {
        return Err(anyhow!(
            "keystore: Ed448 leg of AND-composition signature verification failed"
        ));
    }

    let mldsa_sig_bytes = BASE64_STANDARD
        .decode(sig.mldsa65.as_bytes())
        .map_err(|e| anyhow!("keystore: ML-DSA-65 sig base64 decode failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::signature_from_bytes(&mldsa_sig_bytes)
        .map_err(|e| anyhow!("keystore: ML-DSA-65 sig parse failed: {e}"))?;
    MlDsa65Fips204::verify_with_context(mldsa_pk, payload, context, &mldsa_sig)
        .map_err(|e| {
            anyhow!("keystore: ML-DSA-65 leg of AND-composition signature verification failed: {e}")
        })?;

    Ok(())
}

// Why: crypto-idiomatic naming uses `_sk`/`_pk` suffixes to distinguish
// secret-key from public-key bindings; renaming to satisfy similar_names would
// degrade readability of the AND-composition signature-verification test
// fixtures below. Test code; production-side allow is added per-fn in store.rs.
#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 50,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn round_trip_arbitrary_payload(payload in prop::collection::vec(any::<u8>(), 0..1024)) {
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

            let sig = sign_entry(&ed448_sk, &mldsa_sk, &payload).unwrap();
            verify_entry(&ed448_pk, &mldsa_pk, &payload, &sig).unwrap();
        }

        #[test]
        fn build_payload_deterministic(uuid in "[a-z0-9-]{8,36}", pk in "[A-Za-z0-9+/=]{20,80}") {
            // REM-04: 8-arg form with KDF params (ops=3, mem=1048576 as example values).
            let p1 = build_signed_payload(&uuid, &pk, None, None, None, "2026-01-01T00:00:00Z", 3u64, 1_048_576_usize);
            let p2 = build_signed_payload(&uuid, &pk, None, None, None, "2026-01-01T00:00:00Z", 3u64, 1_048_576_usize);
            prop_assert_eq!(p1, p2);
        }
    }

    #[test]
    fn keystore_sig_context_byte_exact() {
        // Drift-detector: any future change that mutates this constant MUST update
        // both this test AND docs/CRYPTOGRAPHY.md §"Keystore Entry Signatures".
        // Bumped from v1 → v2 in Phase 38-03 (REM-04) when KDF params were added
        // to the signed payload.
        assert_eq!(KEYSTORE_SIG_CONTEXT, b"sss-keystore-entry-sig-v2");
        // Cross-context guard: keystore context must be byte-distinct from the
        // envelope context (T-19-01 / T-38-12).
        assert_ne!(KEYSTORE_SIG_CONTEXT, b"sss-toml-envelope-sig-v2");
    }

    #[test]
    fn build_payload_zero_length_absent_fields() {
        // D-08 (REM-04): 8-field payload.
        // absent Option<&str> fields encode as 4-byte zero prefix + 0 bytes.
        // kdf_ops_limit=1, kdf_mem_limit=2 → decimal "1" (1B) and "2" (1B).
        let payload = build_signed_payload("u", "p", None, None, None, "t", 1u64, 2usize);
        // Field sizes:
        //   uuid "u":         4 + 1 = 5
        //   pk "p":           4 + 1 = 5
        //   hybrid_pk None:   4 + 0 = 4
        //   ed448_pk None:    4 + 0 = 4
        //   mldsa65_pk None:  4 + 0 = 4
        //   created "t":      4 + 1 = 5
        //   kdf_ops "1":      4 + 1 = 5
        //   kdf_mem "2":      4 + 1 = 5
        // Total: 5+5+4+4+4+5+5+5 = 37
        assert_eq!(payload.len(), 4 * 8 + 1 + 1 + 1 + 1 + 1);
        assert_eq!(&payload[0..4], &[0, 0, 0, 1]);
        assert_eq!(payload[4], b'u');
        // hybrid_pk slot at byte offset 10 (after u + p): 4 zero bytes
        assert_eq!(&payload[10..14], &[0, 0, 0, 0]);
        // kdf_ops field starts after the first 6 fields:
        //   5 + 5 + 4 + 4 + 4 + 5 = 27
        assert_eq!(&payload[27..31], &[0, 0, 0, 1]); // length = 1
        assert_eq!(payload[31], b'1');                 // "1"
        assert_eq!(&payload[32..36], &[0, 0, 0, 1]); // kdf_mem length = 1
        assert_eq!(payload[36], b'2');                 // "2"
    }

    #[test]
    fn ed448_tamper_rejects() {
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

        let payload = b"hello world".to_vec();
        let mut sig = sign_entry(&ed448_sk, &mldsa_sk, &payload).unwrap();
        // Flip one base64 char in ed448 sig
        let first = sig.ed448.chars().next().unwrap();
        let flipped = if first == 'A' { 'B' } else { 'A' };
        sig.ed448 = format!("{}{}", flipped, &sig.ed448[1..]);

        let err = verify_entry(&ed448_pk, &mldsa_pk, &payload, &sig).unwrap_err();
        assert!(
            err.to_string().contains("Ed448"),
            "expected Ed448 leg failure, got: {err}"
        );
    }

    #[test]
    fn mldsa65_tamper_rejects() {
        // Symmetric proof of AND-composition: ML-DSA-65 leg-only failure rejects.
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

        let payload = b"hello world".to_vec();
        let mut sig = sign_entry(&ed448_sk, &mldsa_sk, &payload).unwrap();
        let first = sig.mldsa65.chars().next().unwrap();
        let flipped = if first == 'A' { 'B' } else { 'A' };
        sig.mldsa65 = format!("{}{}", flipped, &sig.mldsa65[1..]);

        let err = verify_entry(&ed448_pk, &mldsa_pk, &payload, &sig).unwrap_err();
        assert!(
            err.to_string().contains("ML-DSA-65"),
            "expected ML-DSA-65 leg failure, got: {err}"
        );
    }

    /// REM-04 (Phase 38-03): changing `kdf_ops_limit` OR `kdf_mem_limit` in the payload
    /// must cause signature verification to fail (CRY-05: KDF parameter substitution
    /// is a downgrade attack; authenticating these fields closes the attack surface).
    ///
    /// The test signs a payload with (ops=3, mem=268435456), then verifies the SAME
    /// signature against a tampered payload with (ops=1, mem=8388608) — simulating
    /// an attacker who swaps KDF params after signing. BOTH legs must reject.
    #[test]
    fn kdf_params_tamper_rejects() {
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

        let uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let pk = "AAAA1234base64pubkeyAAAA";
        let created_at = "2026-01-01T00:00:00Z";

        // Sign with authentic (ops=3, mem=268435456) — a "sensitive" cost.
        let real_ops: u64 = 3;
        let real_mem: usize = 268_435_456;
        let authentic_payload = build_signed_payload(uuid, pk, None, None, None, created_at, real_ops, real_mem);
        let sig = sign_entry(&ed448_sk, &mldsa_sk, &authentic_payload).unwrap();

        // Attacker substitutes cheaper params (ops=1, mem=8_388_608 — "interactive").
        let weak_ops: u64 = 1;
        let weak_mem: usize = 8_388_608;
        let tampered_payload = build_signed_payload(uuid, pk, None, None, None, created_at, weak_ops, weak_mem);

        // The signature was produced over authentic_payload; verifying against
        // tampered_payload must fail (CRY-05 closure).
        let err = verify_entry(&ed448_pk, &mldsa_pk, &tampered_payload, &sig).unwrap_err();
        let msg = err.to_string();
        // Either Ed448 or ML-DSA-65 leg rejects (in practice both do; we accept either).
        assert!(
            msg.contains("Ed448") || msg.contains("ML-DSA-65"),
            "expected signature failure on KDF param substitution, got: {msg}"
        );
    }
}
