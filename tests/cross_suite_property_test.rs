//! Property test: the shared-AEAD byte-identical invariant (TEST-01).
//!
//! For any random K, project_timestamp, file_path and plaintext:
//!   ClassicSuite.seal + open -> K_classic
//!   HybridCryptoSuite.seal + open -> K_hybrid
//!   K_classic == K_hybrid == original K (bit-for-bit)
//!   encrypt_to_base64_deterministic(plaintext, K_classic, ts, path)
//!     == encrypt_to_base64_deterministic(plaintext, K_hybrid, ts, path)
//!
//! Failure: proptest shrinks the (K, path, ts, plaintext) tuple to a minimal
//! counter-example and prints it.
//!
//! The entire file is compiled only with `--features hybrid` (both suites
//! must be available simultaneously for the comparison to be meaningful).

#![cfg(feature = "hybrid")]

use proptest::prelude::*;
use sss::crypto::{
    encrypt_to_base64_deterministic, ClassicSuite, CryptoSuite, KeyPair, PublicKey, RepositoryKey,
};
use sss::crypto::{HybridCryptoSuite, HybridKeyPair};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Strategy: a fresh random RepositoryKey (libsodium randombytes internally).
/// proptest cannot generate arbitrary byte arrays as RepositoryKey directly
/// without an Arbitrary impl, so we use any::<u8>() as a seed to invoke
/// ::new() once per case. Each proptest case gets a freshly-generated key.
fn repo_key_strategy() -> impl Strategy<Value = RepositoryKey> {
    any::<u8>().prop_map(|_| RepositoryKey::new())
}

/// Strategy: a non-empty path string (simulate a file path).
fn path_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[a-zA-Z0-9_/.-]{1,64}").unwrap()
}

/// Strategy: a timestamp string in ISO 8601 format.
fn timestamp_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex(
        r"20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z",
    )
    .unwrap()
}

/// Strategy: arbitrary plaintext (printable ASCII for test speed).
fn plaintext_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::char::range(' ', '~'), 0..512)
        .prop_map(|chars| chars.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        ..ProptestConfig::default()
    })]

    /// Core invariant (TEST-01): for random K, path, timestamp and plaintext,
    /// the AEAD ciphertext produced after classic-wrapping K is byte-identical
    /// to the ciphertext produced after hybrid-wrapping K.
    ///
    /// This proves that migration is safe: in-file ciphertexts are untouched
    /// by migrating the per-user wraps from classic to hybrid. Only the
    /// sealed_key entries in .sss.toml differ; the file content is unchanged.
    #[test]
    fn prop_aead_byte_identical_across_suites(
        repo_key in repo_key_strategy(),
        path     in path_strategy(),
        ts       in timestamp_strategy(),
        plaintext in plaintext_strategy(),
    ) {
        // --- Seal K for a fresh classic keypair, then unseal it ---
        let classic_kp = KeyPair::generate().unwrap();
        let sealed_classic = ClassicSuite
            .seal_repo_key(&repo_key, &classic_kp.public_key())
            .unwrap();
        let k_classic = ClassicSuite
            .open_repo_key(&sealed_classic, &classic_kp)
            .unwrap();

        // --- Seal K for a fresh hybrid keypair, then unseal it ---
        let hybrid_kp = HybridKeyPair::generate().unwrap();
        let hybrid_pk = PublicKey::Hybrid(hybrid_kp.public_key());
        let sealed_hybrid = HybridCryptoSuite
            .seal_repo_key(&repo_key, &hybrid_pk)
            .unwrap();
        let hybrid_kp_wrapped = KeyPair::Hybrid(hybrid_kp);
        let k_hybrid = HybridCryptoSuite
            .open_repo_key(&sealed_hybrid, &hybrid_kp_wrapped)
            .unwrap();

        // --- The unsealed keys must be bit-for-bit identical to the original K ---
        prop_assert_eq!(
            k_classic.to_base64(),
            repo_key.to_base64(),
            "ClassicSuite round-trip must recover the original K"
        );
        prop_assert_eq!(
            k_hybrid.to_base64(),
            repo_key.to_base64(),
            "HybridCryptoSuite round-trip must recover the original K"
        );

        // --- Key is identical: `Key` is a type alias for `RepositoryKey`, so
        //     k_classic and k_hybrid are directly usable as &Key arguments. ---
        //
        // Argument order: (plaintext, key, project_timestamp, file_path)
        // ts   maps to project_timestamp (3rd arg)
        // path maps to file_path         (4th arg)

        let ct_classic = encrypt_to_base64_deterministic(
            &plaintext,
            &k_classic,
            &ts,
            &path,
        )
        .unwrap();

        let ct_hybrid = encrypt_to_base64_deterministic(
            &plaintext,
            &k_hybrid,
            &ts,
            &path,
        )
        .unwrap();

        prop_assert_eq!(
            ct_classic,
            ct_hybrid,
            "AEAD ciphertext must be byte-identical regardless of which suite wrapped K\n\
             K: {}\n\
             path: {}\n\
             ts: {}\n\
             plaintext_len: {}",
            repo_key.to_base64(),
            path,
            ts,
            plaintext.len()
        );
    }
}
