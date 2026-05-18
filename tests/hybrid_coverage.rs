// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Direct coverage of every public method on `HybridCryptoSuite`, `HybridKeyPair`,
//! and `HybridPublicKey` (TEST-07).
//!
//! Why: complements the property-test surface in `tests/cross_suite_property_test.rs`
//! with one deterministic test per public method, so a tarpaulin baseline reaches
//! every branch and a regression in any single method surfaces immediately.
//!
//! Phase 14 / Plan 14-02 / D-02.

#![cfg(feature = "hybrid")]

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use sss::crypto::{ClassicSuite, CryptoSuite, KeyPair, PublicKey, RepositoryKey};
use sss::crypto::{HybridCryptoSuite, HybridKeyPair, HybridPublicKey};

// Wire-format constants (mirror src/constants.rs).
const HYBRID_PUBLIC_KEY_SIZE: usize = 1214;
const HYBRID_ENCAPSULATION_SIZE: usize = 1095;
const HYBRID_SEALED_KEY_NONCE_SIZE: usize = 24;

// --- HybridPublicKey::from_bytes ---

#[test]
fn hybrid_public_key_from_bytes_correct_length_returns_ok() {
    let exact = vec![0x42u8; HYBRID_PUBLIC_KEY_SIZE];
    let result = HybridPublicKey::from_bytes(&exact);
    assert!(result.is_ok(), "from_bytes must accept an exact-length slice");
    assert_eq!(result.unwrap().as_bytes(), exact.as_slice());
}

#[test]
fn hybrid_public_key_from_bytes_too_short_returns_err() {
    // Why: from_bytes is the length-gate used by PublicKey::decode_base64_for_suite;
    // a truncated key must be rejected before any KEM operation touches trelis.
    let result = HybridPublicKey::from_bytes(&[0u8; 10]);
    assert!(result.is_err(), "from_bytes must reject a too-short slice");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("wrong length"), "expected 'wrong length', got: {msg}");
}

#[test]
fn hybrid_public_key_from_bytes_too_long_returns_err() {
    // Why: a buffer longer than HYBRID_PUBLIC_KEY_SIZE would silently truncate
    // in a permissive API; the strict gate forces callers to supply exact wire bytes.
    let too_long = vec![0u8; HYBRID_PUBLIC_KEY_SIZE + 1];
    let result = HybridPublicKey::from_bytes(&too_long);
    assert!(result.is_err(), "from_bytes must reject a too-long slice");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("wrong length"), "expected 'wrong length', got: {msg}");
}

#[test]
fn hybrid_public_key_from_bytes_empty_returns_err() {
    // Why: an empty slice must be rejected; proves the check is not length >= 0.
    let result = HybridPublicKey::from_bytes(&[]);
    assert!(result.is_err(), "from_bytes must reject an empty slice");
}

// --- HybridPublicKey::as_bytes ---

#[test]
fn hybrid_public_key_as_bytes_roundtrip_with_from_bytes() {
    let kp = HybridKeyPair::generate().expect("keypair generation");
    let pk = kp.public_key();
    let bytes = pk.as_bytes().to_vec();
    let pk2 = HybridPublicKey::from_bytes(&bytes).expect("round-trip from_bytes");
    assert_eq!(pk.as_bytes(), pk2.as_bytes(), "as_bytes round-trip must be byte-identical");
}

// --- HybridPublicKey::from_bytes_unchecked ---
// from_bytes_unchecked is #[cfg(test)] on the crate side so it is not callable
// from integration tests. We cover its byte-preservation contract via from_bytes
// with an exact-size input — the observable post-condition is identical.

#[test]
fn hybrid_public_key_from_bytes_unchecked_preserves_bytes() {
    let data = vec![0xABu8; HYBRID_PUBLIC_KEY_SIZE];
    let pk = HybridPublicKey::from_bytes(&data).expect("exact-size from_bytes");
    assert_eq!(pk.as_bytes(), data.as_slice());
}

// --- HybridKeyPair::generate ---

#[test]
fn hybrid_key_pair_generate_does_not_panic() {
    let result = HybridKeyPair::generate();
    assert!(result.is_ok(), "HybridKeyPair::generate() must return Ok");
}

// --- HybridKeyPair::public_key ---

#[test]
fn hybrid_key_pair_public_key_extracts_consistently() {
    let kp = HybridKeyPair::generate().expect("keypair generation");
    let pk1 = kp.public_key();
    let pk2 = kp.public_key();
    assert_eq!(pk1.as_bytes(), pk2.as_bytes(), "public_key() must be byte-identical on repeated calls");
}

// --- HybridCryptoSuite (CryptoSuite trait impl) ---

#[test]
fn hybrid_crypto_suite_seal_open_roundtrip_recovers_repo_key() {
    let kp = HybridKeyPair::generate().expect("keypair generation");
    let repo_key = RepositoryKey::new();
    let hybrid_pk = PublicKey::Hybrid(kp.public_key());
    let hybrid_kp = KeyPair::Hybrid(kp);
    let sealed = HybridCryptoSuite.seal_repo_key(&repo_key, &hybrid_pk).expect("seal");
    let opened = HybridCryptoSuite.open_repo_key(&sealed, &hybrid_kp).expect("open");
    assert_eq!(repo_key.to_base64(), opened.to_base64(), "round-trip must recover the original RepositoryKey");
}

#[test]
fn hybrid_crypto_suite_seal_rejects_classic_public_key_returns_err() {
    // Why: a Classic public key contains 32-byte X25519 material; running KEM
    // encapsulation on it would be undefined behaviour in trelis. The guard at
    // hybrid.rs:145-152 must fire before any trelis call reaches the FFI boundary.
    let classic_kp = KeyPair::generate().expect("classic keypair generation");
    let classic_pk = classic_kp.public_key();
    let result = HybridCryptoSuite.seal_repo_key(&RepositoryKey::new(), &classic_pk);
    assert!(result.is_err(), "hybrid seal must reject classic public key");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("version mismatch") || msg.contains("classic public key"),
        "expected version-mismatch error, got: {msg}"
    );
}

#[test]
fn hybrid_crypto_suite_open_rejects_classic_keypair_returns_err() {
    // Why: a ClassicKeyPair holds 32-byte X25519 secret material; passing it to
    // the hybrid opener would feed wrong-sized bytes to trelis KEM decapsulation.
    // The variant guard at hybrid.rs:224-228 must reject it before any FFI call.
    let classic_kp = KeyPair::generate().expect("classic keypair generation");
    let result = HybridCryptoSuite.open_repo_key("any-string", &classic_kp);
    assert!(result.is_err(), "hybrid open must reject a classic keypair");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("version mismatch") || msg.contains("classic"),
        "expected version-mismatch error, got: {msg}"
    );
}

#[test]
fn hybrid_crypto_suite_open_rejects_wrong_length_sealed_key_returns_err() {
    // Why: the wire-format parser at hybrid.rs:240-246 checks an exact byte count;
    // any deviation must fail before KEM or AEAD is attempted.
    let kp = HybridKeyPair::generate().expect("keypair generation");
    let hybrid_kp = KeyPair::Hybrid(kp);
    let short_encoded = BASE64_STANDARD.encode([0u8; 16]);
    let result = HybridCryptoSuite.open_repo_key(&short_encoded, &hybrid_kp);
    assert!(result.is_err(), "hybrid open must reject a wrong-length sealed key");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("wrong length"), "expected 'wrong length', got: {msg}");
}

#[test]
fn hybrid_crypto_suite_open_detects_aead_tamper_returns_err() {
    // Why: any byte-flip in the AEAD ciphertext region must trigger Poly1305 MAC
    // failure at hybrid.rs:276-281 — the authenticated-encryption guarantee.
    let kp = HybridKeyPair::generate().expect("keypair generation");
    let repo_key = RepositoryKey::new();
    let hybrid_pk = PublicKey::Hybrid(kp.public_key());
    let hybrid_kp = KeyPair::Hybrid(kp);
    let sealed = HybridCryptoSuite.seal_repo_key(&repo_key, &hybrid_pk).expect("seal");
    let mut decoded = BASE64_STANDARD.decode(&sealed).expect("base64 decode");
    decoded[HYBRID_ENCAPSULATION_SIZE + HYBRID_SEALED_KEY_NONCE_SIZE + 5] ^= 0xFF;
    let tampered = BASE64_STANDARD.encode(&decoded);
    let result = HybridCryptoSuite.open_repo_key(&tampered, &hybrid_kp);
    assert!(result.is_err(), "hybrid open must detect AEAD ciphertext tamper");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("authentication or decryption error"),
        "expected 'authentication or decryption error', got: {msg}"
    );
}

// --- Cross-suite regression guard ---

#[test]
fn classic_suite_still_seals_and_opens_with_hybrid_feature_enabled() {
    // Regression guard: importing hybrid types must not affect the classic suite.
    let kp = KeyPair::generate().expect("classic keypair");
    let repo_key = RepositoryKey::new();
    let sealed = ClassicSuite.seal_repo_key(&repo_key, &kp.public_key()).expect("classic seal");
    let opened = ClassicSuite.open_repo_key(&sealed, &kp).expect("classic open");
    assert_eq!(repo_key.to_base64(), opened.to_base64());
}
