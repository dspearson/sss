#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};

use super::classic::{KeyPair, PublicKey, RepositoryKey};

/// Cryptographic suite abstraction for per-user repository-key wrap/unwrap.
///
/// Implementors wrap the 32-byte `RepositoryKey` for a specific user's
/// `PublicKey` (produces a base64 string stored in `.sss.toml`) and
/// unwrap it back given the matching `KeyPair`.
///
/// Invariants across implementations:
/// - `open_repo_key(seal_repo_key(K, pk), kp where kp.public == pk) == K` (round-trip).
/// - Wrong keypair MUST return `Err`, never silently wrong data.
/// - Byte-for-byte output of `seal_repo_key` is determined by the concrete impl; classic is
///   libsodium `crypto_box_seal` output, base64-standard encoded.
/// - No secret material leaks past drop — all secret-bearing types implement `ZeroizeOnDrop`.
pub trait CryptoSuite {
    /// Wrap `repo_key` for `user_public_key`. Returns the base64-encoded sealed bytes.
    fn seal_repo_key(
        &self,
        repo_key: &RepositoryKey,
        user_public_key: &PublicKey,
    ) -> Result<String>;

    /// Unwrap a sealed key (as produced by `seal_repo_key`) using `user_keypair`.
    fn open_repo_key(
        &self,
        sealed_key: &str,
        user_keypair: &KeyPair,
    ) -> Result<RepositoryKey>;
}

/// Dispatch selector — maps `.sss.toml` `version` values to the concrete suite.
///
/// `"1.0"` → `Classic` (libsodium `crypto_box_seal`, current default).
/// `"2.0"` → `Hybrid` (trelis X448 + sntrup761 → BLAKE3; implementation lands in Phase 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Classic,
    Hybrid,
}

impl Suite {
    /// Parse a `.sss.toml` `version` string into a `Suite`.
    ///
    /// Unknown versions (including malformed, empty, or future versions
    /// beyond this binary's awareness) return an actionable error rather
    /// than defaulting silently.
    pub fn from_version(version: &str) -> Result<Self> {
        match version {
            "1.0" => Ok(Suite::Classic),
            "2.0" => Ok(Suite::Hybrid),
            other => Err(anyhow!(
                "unknown .sss.toml version {:?}: expected \"1.0\" or \"2.0\"",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_version_classic() {
        assert_eq!(Suite::from_version("1.0").unwrap(), Suite::Classic);
    }

    #[test]
    fn test_from_version_hybrid() {
        assert_eq!(Suite::from_version("2.0").unwrap(), Suite::Hybrid);
    }

    #[test]
    fn test_from_version_unknown_returns_error() {
        let err = Suite::from_version("99.0").unwrap_err().to_string();
        assert!(err.contains("unknown .sss.toml version"));
        assert!(err.contains("99.0"));
    }

    #[test]
    fn test_from_version_empty_returns_error() {
        assert!(Suite::from_version("").is_err());
    }

    #[test]
    fn test_trait_object_safety() {
        // Compile-time check: CryptoSuite must be object-safe so Phase 2
        // can pick a suite at runtime (Box<dyn CryptoSuite>).
        fn _assert_object_safe(_s: &dyn CryptoSuite) {}
    }
}
