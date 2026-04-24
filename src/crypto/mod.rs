//! Cryptographic primitives for sss.
//!
//! This module is organised as a directory-module (Phase 1 of the v2.0
//! crypto-suite abstraction work). Re-exports from `classic` preserve the
//! historical `crate::crypto::{seal_repository_key, open_repository_key,
//! RepositoryKey, PublicKey, KeyPair, SecretKey, Key, encrypt, decrypt, ...}`
//! surface verbatim so no caller (in this crate or in tests) needs to change.
//!
//! The `CryptoSuite` trait and `Suite` dispatch enum are the integration
//! points Phase 2's hybrid implementation will plug into.
pub mod classic;
#[cfg(feature = "hybrid")]
pub mod hybrid;
pub mod suite;

pub use classic::{
    decrypt, decrypt_from_base64, encrypt, encrypt_to_base64,
    encrypt_to_base64_deterministic, open_repository_key, seal_repository_key, ClassicKeyPair,
    ClassicSuite, Key, KeyPair, PublicKey, RepositoryKey, SecretKey,
};
pub use suite::{CryptoSuite, Suite};

#[cfg(feature = "hybrid")]
pub use hybrid::{HybridCryptoSuite, HybridKeyPair, HybridPublicKey};

// Keep the internal `encrypt_internal` reachable from keystore etc. exactly
// as before — it was `pub(crate)` in the old flat module and must remain so.
#[allow(unused_imports)]
pub(crate) use classic::encrypt_internal;

/// Build a `Box<dyn CryptoSuite>` for the given `Suite` selector. Central
/// dispatch point for every caller that holds a `Suite` from
/// `ProjectConfig::suite()` and needs the matching implementation.
///
/// Feature-off behaviour: `Suite::Hybrid` with `hybrid` disabled returns the
/// Phase 1 actionable error — never silently falls back to classic.
pub fn suite_for(suite: Suite) -> anyhow::Result<Box<dyn CryptoSuite>> {
    match suite {
        Suite::Classic => Ok(Box::new(ClassicSuite)),
        #[cfg(feature = "hybrid")]
        Suite::Hybrid => Ok(Box::new(HybridCryptoSuite)),
        #[cfg(not(feature = "hybrid"))]
        Suite::Hybrid => Err(anyhow::anyhow!(
            "hybrid suite requires the `hybrid` feature — rebuild with --features hybrid"
        )),
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;

    #[test]
    fn test_suite_for_classic_returns_classic_suite() {
        let suite = suite_for(Suite::Classic).unwrap();
        // Black-box check — can seal/open a classic round-trip.
        let kp = KeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let sealed = suite.seal_repo_key(&repo_key, &kp.public_key()).unwrap();
        let opened = suite.open_repo_key(&sealed, &kp).unwrap();
        assert_eq!(repo_key.to_base64(), opened.to_base64());
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn test_suite_for_hybrid_returns_hybrid_suite() {
        let suite = suite_for(Suite::Hybrid).unwrap();
        let hkp = hybrid::HybridKeyPair::generate().unwrap();
        let pk = PublicKey::Hybrid(hkp.public_key());
        let kp = KeyPair::Hybrid(hkp);
        let repo_key = RepositoryKey::new();
        let sealed = suite.seal_repo_key(&repo_key, &pk).unwrap();
        let opened = suite.open_repo_key(&sealed, &kp).unwrap();
        assert_eq!(repo_key.to_base64(), opened.to_base64());
    }

    #[cfg(not(feature = "hybrid"))]
    #[test]
    fn test_suite_for_hybrid_errors_without_feature() {
        // `Box<dyn CryptoSuite>` is not `Debug`, so we cannot `unwrap_err()`.
        // Match out the error arm explicitly.
        let err = match suite_for(Suite::Hybrid) {
            Ok(_) => panic!("expected Err when hybrid feature is off"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("hybrid suite requires the `hybrid` feature"));
        assert!(err.contains("--features hybrid"));
    }
}
