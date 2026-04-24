//! Hybrid post-quantum KEM suite — `X448 + sntrup761` encapsulation -> BLAKE3 KDF -> libsodium XChaCha20-Poly1305.
//!
//! trelis is experimental / unaudited upstream. This entire module is gated
//! behind the `hybrid` Cargo feature (default OFF) so `cargo build` and the
//! existing release matrix continue to link only libsodium.
//!
//! Plan 02-02 introduces ONLY the type declarations and module wiring.
//! Plan 02-03 adds `impl CryptoSuite for HybridCryptoSuite` with the
//! seal/open wire-format machinery, and Plan 02-04 adds the byte-identical-
//! ciphertext test and the zeroise-on-drop poison-pattern test.
#![cfg(feature = "hybrid")]
#![allow(clippy::missing_errors_doc)]

use zeroize::{Zeroize, ZeroizeOnDrop};

// NOTE: The trelis type names used below are placeholders that Plan 02-03
// resolves against the actual trelis_hybrid API (exact function/struct
// names depend on the pinned commit resolved in 02-01). For Plan 02-02 we
// only need the TYPE SHAPE — two byte-carrying structs with the correct
// zeroise discipline.

/// Hybrid public key: concatenated X448 public scalar || sntrup761 public key.
///
/// Wire format: `base64(X448_PUB || SNTRUP761_PUB)`. Total length is fixed
/// at compile time from the trelis KEM parameters; the constants are
/// introduced in Plan 02-03 (`HYBRID_PUBLIC_KEY_SIZE`). For 02-02 we hold
/// the bytes as a `Vec<u8>` so the type declaration compiles without
/// hard-coding a size — 02-03 swaps this to `[u8; HYBRID_PUBLIC_KEY_SIZE]`.
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    pub(crate) bytes: Vec<u8>,
}

impl HybridPublicKey {
    /// Construct from raw bytes. Length validation is added in Plan 02-03
    /// once the trelis KEM param constants are imported.
    #[must_use]
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Hybrid keypair: both secret scalars (X448 + sntrup761) kept together.
///
/// Secret material MUST be zeroised on drop — this is the PQCRYPTO-04
/// contract. The `secret_bytes` field holds the full concatenated secret
/// material (`X448_SECRET || SNTRUP761_SECRET`); 02-03 replaces the `Vec<u8>`
/// with the precise `Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>` form and
/// wires the actual `trelis_hybrid::HybridKemKeypair::generate()` call.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    #[zeroize(skip)]
    pub(crate) public_bytes: Vec<u8>,
    pub(crate) secret_bytes: Vec<u8>,
}

impl HybridKeyPair {
    /// Stub accessor — returns a borrowed view of the public component as a
    /// `HybridPublicKey`. 02-03 swaps to a concrete X448+sntrup761 generator.
    #[must_use]
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey::from_bytes_unchecked(self.public_bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_public_key_is_clone_and_send_sync() {
        fn _assert_send_sync<T: Send + Sync + 'static>() {}
        _assert_send_sync::<HybridPublicKey>();
        _assert_send_sync::<HybridKeyPair>();
    }

    #[test]
    fn test_hybrid_keypair_drops_zero_secret_bytes() {
        // Construct with a known marker pattern, then drop by shadowing.
        // The poison-pattern test in 02-04 is the full contract; this is
        // a smoke test that the ZeroizeOnDrop derive compiles and runs.
        let kp = HybridKeyPair {
            public_bytes: vec![0x11; 4],
            secret_bytes: vec![0xAA; 8],
        };
        // Exercise drop; real verification (memory inspection) is 02-04.
        drop(kp);
    }
}
