//! Hybrid AND-composition signatures over keystore entries (Phase 18, PQSIG-01).
//!
//! Combines `trelis_primitives::Ed448Standard` (RFC 8032 SHAKE256) with
//! `trelis_primitives::MlDsa65Fips204` (FIPS 204) via AND composition:
//! BOTH signatures must verify; either failure rejects the entry.
//!
//! Domain-separation context: `b"sss-keystore-entry-sig-v1"` (D-05).
//! Canonical payload: length-prefixed concat of 6 identity-bearing fields (D-08).
//!
//! See `docs/CRYPTOGRAPHY.md` §"Keystore Entry Signatures (v2)" for the
//! authoritative format spec (added in plan unit 18-05).

#![cfg(feature = "hybrid")]
// Why: signing primitives use trelis-primitives types that are gated on the
// `hybrid` feature in this crate's Cargo.toml.

use anyhow::{anyhow, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use trelis_primitives::{
    Ed448Scheme, Ed448SigningKey, Ed448Standard, Ed448VerifyingKey,
    MlDsa65Fips204, MlDsa65SigningKey, MlDsa65VerifyingKey, MlDsaScheme,
};

/// Domain-separation context bytes (D-05).
/// Phase 19 will use `b"sss-toml-envelope-sig-v1"` for envelope signatures.
pub const KEYSTORE_SIG_CONTEXT: &[u8] = b"sss-keystore-entry-sig-v1";

/// AND-composition signature: BOTH legs must verify.
///
/// `ed448`   = base64 of 114-byte Ed448 signature.
/// `mldsa65` = base64 of 3309-byte ML-DSA-65 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreEntrySig {
    pub ed448: String,
    pub mldsa65: String,
}

/// Canonical signed-payload encoding (D-08): length-prefixed concat of
/// 6 identity-bearing fields. Absent optional fields encode as 4 zero bytes.
///
/// Field order is FIXED: uuid, public_key, hybrid_public_key,
/// sig_ed448_public_key, sig_mldsa65_public_key, created_at_rfc3339.
pub fn build_signed_payload(
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
    for field in fields.iter() {
        buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
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
/// CRITICAL: Ed448::verify_with_context returns `bool`; ML-DSA-65 returns `Result<()>`.
/// Both shapes are wrapped into the same actionable error.
pub fn verify_entry(
    ed448_pk: &Ed448VerifyingKey,
    mldsa_pk: &MlDsa65VerifyingKey,
    payload: &[u8],
    sig: &KeystoreEntrySig,
) -> Result<()> {
    let ed448_sig_bytes = BASE64_STANDARD
        .decode(sig.ed448.as_bytes())
        .map_err(|e| anyhow!("keystore: Ed448 sig base64 decode failed: {e}"))?;
    let ed448_sig = Ed448Standard::signature_from_bytes(&ed448_sig_bytes)
        .map_err(|e| anyhow!("keystore: Ed448 sig parse failed: {e}"))?;
    if !Ed448Standard::verify_with_context(ed448_pk, payload, KEYSTORE_SIG_CONTEXT, &ed448_sig) {
        return Err(anyhow!(
            "keystore: Ed448 leg of AND-composition signature verification failed"
        ));
    }

    let mldsa_sig_bytes = BASE64_STANDARD
        .decode(sig.mldsa65.as_bytes())
        .map_err(|e| anyhow!("keystore: ML-DSA-65 sig base64 decode failed: {e}"))?;
    let mldsa_sig = MlDsa65Fips204::signature_from_bytes(&mldsa_sig_bytes)
        .map_err(|e| anyhow!("keystore: ML-DSA-65 sig parse failed: {e}"))?;
    MlDsa65Fips204::verify_with_context(mldsa_pk, payload, KEYSTORE_SIG_CONTEXT, &mldsa_sig)
        .map_err(|e| {
            anyhow!("keystore: ML-DSA-65 leg of AND-composition signature verification failed: {e}")
        })?;

    Ok(())
}

#[cfg(test)]
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
            let p1 = build_signed_payload(&uuid, &pk, None, None, None, "2026-01-01T00:00:00Z");
            let p2 = build_signed_payload(&uuid, &pk, None, None, None, "2026-01-01T00:00:00Z");
            prop_assert_eq!(p1, p2);
        }
    }

    #[test]
    fn keystore_sig_context_byte_exact() {
        // Drift-detector: any Phase 19 / future change that mutates this constant
        // must update both this test AND docs/CRYPTOGRAPHY.md.
        assert_eq!(KEYSTORE_SIG_CONTEXT, b"sss-keystore-entry-sig-v1");
    }

    #[test]
    fn build_payload_zero_length_absent_fields() {
        // D-08: absent Option<&str> fields encode as 4-byte zero prefix + 0 bytes.
        let payload = build_signed_payload("u", "p", None, None, None, "t");
        // u (4-len + 1 byte) + p (4+1) + None×3 (4+0 each) + "t" (4+1) = 16 + 12 + 5 = 33
        // [0,0,0,1, 'u', 0,0,0,1, 'p', 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1, 't']
        assert_eq!(payload.len(), 4 * 6 + 1 + 1 + 0 + 0 + 0 + 1);
        assert_eq!(&payload[0..4], &[0, 0, 0, 1]);
        assert_eq!(payload[4], b'u');
        // hybrid_pk slot at byte offset 10 (after u + p): 4 zero bytes
        assert_eq!(&payload[10..14], &[0, 0, 0, 0]);
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
}
