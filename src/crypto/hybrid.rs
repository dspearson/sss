//! Hybrid post-quantum KEM suite — `X448 + sntrup761` encapsulation -> BLAKE3 KDF -> libsodium XChaCha20-Poly1305.
//!
//! trelis is experimental / unaudited upstream. This entire module is gated
//! behind the `hybrid` Cargo feature (default OFF) so `cargo build` and the
//! existing release matrix continue to link only libsodium.
//!
//! Plan 02-02 introduced the type declarations and module wiring.
//! Plan 02-03 upgrades the type shapes to fixed-size arrays (driven by the
//! resolved trelis KEM param sizes), lands `impl CryptoSuite for
//! HybridCryptoSuite` with the seal/open wire-format machinery, and wires
//! the `Suite::Hybrid` dispatch arm.
//!
//! Wire format (base64-encoded in `.sss.toml`):
//! `encap (1095B) || nonce24 (24B) || AEAD_ct+tag (48B)` — total 1167 bytes
//! plaintext before base64.
#![cfg(feature = "hybrid")]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

use libsodium_sys as sodium;

use crate::constants::{
    HYBRID_ENCAPSULATION_SIZE, HYBRID_KEM_CONTEXT, HYBRID_PUBLIC_KEY_SIZE,
    HYBRID_SEALED_KEY_NONCE_SIZE, HYBRID_SEALED_KEY_TAG_SIZE, HYBRID_SECRET_KEY_SIZE,
};
use crate::crypto::classic::{ensure_sodium_init, KeyPair, PublicKey, RepositoryKey};
use crate::crypto::suite::CryptoSuite;

// trelis-hybrid KEM types. Resolved against the pinned commit
// 5374dff482ba94a94695794b5e4554f908eb0d4d (see Cargo.toml banner).
use trelis_hybrid::kem::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};

/// Symmetric key size (32 bytes) — the plaintext wrapped by the hybrid AEAD.
/// Matches `sodium::crypto_secretbox_xchacha20poly1305_KEYBYTES`. We hard-code
/// it here because the classic module's const is private; keeping the literal
/// local avoids a cross-module visibility change.
const HYBRID_REPO_KEY_PLAINTEXT_SIZE: usize = 32;

/// Hybrid public key: concatenated X448 public scalar || sntrup761 public key.
/// Total length fixed at compile time by `HYBRID_PUBLIC_KEY_SIZE`.
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    pub(crate) bytes: [u8; HYBRID_PUBLIC_KEY_SIZE],
}

impl HybridPublicKey {
    /// Construct from an exact-length byte slice. Returns `Err` if the
    /// length does not match `HYBRID_PUBLIC_KEY_SIZE` — this is the
    /// length-gate used by `PublicKey::decode_base64_for_suite`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err(anyhow!(
                "hybrid public key wrong length: expected {} bytes, got {}",
                HYBRID_PUBLIC_KEY_SIZE,
                bytes.len()
            ));
        }
        let mut arr = [0u8; HYBRID_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Construct from an owned `Vec<u8>` without a hard length failure.
    ///
    /// Kept for API-shape stability with the 02-02 stub — pads/truncates to
    /// `HYBRID_PUBLIC_KEY_SIZE` so any pre-existing caller that built a
    /// `HybridPublicKey` from an arbitrary-length buffer continues to
    /// compile. New code SHOULD use [`HybridPublicKey::from_bytes`] for the
    /// length-checked path.
    #[must_use]
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        let mut arr = [0u8; HYBRID_PUBLIC_KEY_SIZE];
        let n = bytes.len().min(HYBRID_PUBLIC_KEY_SIZE);
        arr[..n].copy_from_slice(&bytes[..n]);
        Self { bytes: arr }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Hybrid keypair. Secret material is held inside `Zeroizing<..>` so it
/// zeroises on drop (delegated field-level zeroisation — no struct-level
/// `ZeroizeOnDrop` derive because `public_bytes` does not need zeroising).
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    pub(crate) public_bytes: [u8; HYBRID_PUBLIC_KEY_SIZE],
    pub(crate) secret_bytes: Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>,
}

impl HybridKeyPair {
    /// Generate a fresh X448 + sntrup761 hybrid keypair using trelis.
    /// Secret material is wrapped in `Zeroizing<..>` for drop-time zeroise.
    pub fn generate() -> Result<Self> {
        let kem = HybridKemKeypair::generate()
            .map_err(|e| anyhow!("hybrid keypair generation failed: {e}"))?;

        // Serialise the public bytes in the canonical X448 || sntrup761 order.
        let public_bytes = kem.public_key().to_bytes();
        debug_assert_eq!(public_bytes.len(), HYBRID_PUBLIC_KEY_SIZE);

        // Secret bytes go straight into Zeroizing<..> — never copied to a
        // non-zeroising location. `kem` itself is `ZeroizeOnDrop` upstream,
        // so dropping it at end of scope zeroises the internal secrets.
        let secret_array = kem.to_bytes();
        debug_assert_eq!(secret_array.len(), HYBRID_SECRET_KEY_SIZE);
        let secret_bytes = Zeroizing::new(secret_array);

        Ok(Self { public_bytes, secret_bytes })
    }

    /// Borrowed public-key view for the outer `PublicKey::Hybrid` wrapper.
    #[must_use]
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey { bytes: self.public_bytes }
    }

    /// For tests only — exposes a read-only view of the secret bytes so the
    /// poison-pattern zeroise test in Plan 02-04 can observe drop behaviour.
    #[cfg(test)]
    pub(crate) fn secret_bytes_for_test(&self) -> &Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]> {
        &self.secret_bytes
    }
}

/// Hybrid post-quantum cryptographic suite: X448 + sntrup761 KEM -> BLAKE3 KDF
/// -> libsodium XChaCha20-Poly1305 AEAD wrap of the 32-byte repository key.
#[derive(Debug, Default, Clone, Copy)]
pub struct HybridCryptoSuite;

impl CryptoSuite for HybridCryptoSuite {
    fn seal_repo_key(
        &self,
        repo_key: &RepositoryKey,
        user_public_key: &PublicKey,
    ) -> Result<String> {
        ensure_sodium_init();

        // Variant match — reject classic public keys loudly rather than
        // silently attempting KEM encapsulation with non-hybrid bytes.
        let hybrid_pub = match user_public_key {
            PublicKey::Hybrid(h) => h,
            PublicKey::Classic(_) => {
                return Err(anyhow!(
                    "hybrid suite cannot seal for a classic public key — \
                     version mismatch (.sss.toml version = \"1.0\" requires \
                     the classic suite; either use the classic keypair for \
                     this user or run `sss migrate` to upgrade the repo)"
                ));
            }
        };

        // Step 1 — Reconstruct the trelis public key and encapsulate.
        let trelis_pub = HybridKemPublicKey::from_bytes(&hybrid_pub.bytes)
            .map_err(|e| anyhow!("trelis public key parse failed: {e}"))?;
        let (shared, encapsulation) = trelis_pub
            .encapsulate()
            .map_err(|e| anyhow!("hybrid KEM encapsulate failed: {e}"))?;
        let encap_bytes = encapsulation.to_bytes();
        debug_assert_eq!(encap_bytes.len(), HYBRID_ENCAPSULATION_SIZE);

        // Step 2 — Derive the AEAD key. Context string is load-bearing
        // wire format; see HYBRID_KEM_CONTEXT doc comment.
        let aead_key: Zeroizing<[u8; 32]> =
            Zeroizing::new(blake3::derive_key(HYBRID_KEM_CONTEXT, shared.as_bytes()));

        // Step 3 — Random 24-byte nonce for XChaCha20-Poly1305.
        let mut nonce = [0u8; HYBRID_SEALED_KEY_NONCE_SIZE];
        unsafe {
            sodium::randombytes_buf(
                nonce.as_mut_ptr().cast::<std::ffi::c_void>(),
                HYBRID_SEALED_KEY_NONCE_SIZE,
            );
        }

        // Step 4 — AEAD-seal the 32-byte repository key. Plaintext sits in
        // a Zeroizing<..> so it is cleared from the stack on drop.
        let plaintext: Zeroizing<[u8; HYBRID_REPO_KEY_PLAINTEXT_SIZE]> =
            Zeroizing::new(repo_key.to_bytes());
        let mut ciphertext =
            vec![0u8; HYBRID_REPO_KEY_PLAINTEXT_SIZE + HYBRID_SEALED_KEY_TAG_SIZE];
        let ret = unsafe {
            sodium::crypto_secretbox_xchacha20poly1305_easy(
                ciphertext.as_mut_ptr(),
                plaintext.as_ptr(),
                HYBRID_REPO_KEY_PLAINTEXT_SIZE as u64,
                nonce.as_ptr(),
                aead_key.as_ptr(),
            )
        };
        if ret != 0 {
            return Err(anyhow!(
                "hybrid AEAD seal failed (libsodium returned {})",
                ret
            ));
        }

        // Step 5 — Concatenate `encap || nonce || ct+tag` and base64-encode.
        let mut out = Vec::with_capacity(
            HYBRID_ENCAPSULATION_SIZE
                + HYBRID_SEALED_KEY_NONCE_SIZE
                + HYBRID_REPO_KEY_PLAINTEXT_SIZE
                + HYBRID_SEALED_KEY_TAG_SIZE,
        );
        out.extend_from_slice(&encap_bytes);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        use base64::prelude::*;
        Ok(BASE64_STANDARD.encode(&out))
    }

    fn open_repo_key(
        &self,
        sealed_key: &str,
        user_keypair: &KeyPair,
    ) -> Result<RepositoryKey> {
        ensure_sodium_init();

        let hybrid_kp = match user_keypair {
            KeyPair::Hybrid(h) => h,
            KeyPair::Classic(_) => {
                return Err(anyhow!(
                    "hybrid suite cannot open a classic-sealed key — version mismatch"
                ));
            }
        };

        // Step 1 — Base64-decode and split the wire format.
        use base64::prelude::*;
        let decoded = BASE64_STANDARD
            .decode(sealed_key)
            .map_err(|e| anyhow!("base64 decode of hybrid sealed key failed: {e}"))?;
        let expected_len = HYBRID_ENCAPSULATION_SIZE
            + HYBRID_SEALED_KEY_NONCE_SIZE
            + HYBRID_REPO_KEY_PLAINTEXT_SIZE
            + HYBRID_SEALED_KEY_TAG_SIZE;
        if decoded.len() != expected_len {
            return Err(anyhow!(
                "hybrid sealed key wrong length: expected {}, got {}",
                expected_len,
                decoded.len()
            ));
        }
        let (encap_slice, rest) = decoded.split_at(HYBRID_ENCAPSULATION_SIZE);
        let (nonce_bytes, ciphertext) = rest.split_at(HYBRID_SEALED_KEY_NONCE_SIZE);

        // Step 2 — Reconstruct the trelis keypair from its secret bytes and
        // the encapsulation from its wire bytes, then decapsulate.
        let kem = HybridKemKeypair::from_bytes(&hybrid_kp.secret_bytes[..])
            .map_err(|e| anyhow!("trelis keypair reconstruct failed: {e}"))?;
        let encapsulation = HybridEncapsulation::from_bytes(encap_slice)
            .map_err(|e| anyhow!("hybrid encapsulation parse failed: {e}"))?;
        let shared = kem
            .decapsulate(&encapsulation)
            .map_err(|e| anyhow!("hybrid KEM decapsulate failed: {e}"))?;

        // Step 3 — Derive the AEAD key (same context as seal).
        let aead_key: Zeroizing<[u8; 32]> =
            Zeroizing::new(blake3::derive_key(HYBRID_KEM_CONTEXT, shared.as_bytes()));

        // Step 4 — AEAD-open. Plaintext buffer sits in Zeroizing<..>.
        let mut plaintext: Zeroizing<[u8; HYBRID_REPO_KEY_PLAINTEXT_SIZE]> =
            Zeroizing::new([0u8; HYBRID_REPO_KEY_PLAINTEXT_SIZE]);
        let ret = unsafe {
            sodium::crypto_secretbox_xchacha20poly1305_open_easy(
                plaintext.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                nonce_bytes.as_ptr(),
                aead_key.as_ptr(),
            )
        };
        if ret != 0 {
            // Generic message — do not leak which layer failed (nonce vs
            // tag vs ciphertext) to keep the error surface minimal for
            // tamper-detection callers.
            return Err(anyhow!(
                "hybrid AEAD open failed: authentication or decryption error"
            ));
        }

        RepositoryKey::from_bytes(&plaintext[..])
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
    fn test_hybrid_public_key_wrong_length_rejected() {
        let too_short = vec![0u8; HYBRID_PUBLIC_KEY_SIZE - 1];
        let err = HybridPublicKey::from_bytes(&too_short).unwrap_err().to_string();
        assert!(err.contains("wrong length"));
        assert!(err.contains(&HYBRID_PUBLIC_KEY_SIZE.to_string()));
    }

    #[test]
    fn test_hybrid_public_key_exact_length_accepted() {
        let exact = vec![0x42u8; HYBRID_PUBLIC_KEY_SIZE];
        let pk = HybridPublicKey::from_bytes(&exact).unwrap();
        assert_eq!(pk.as_bytes().len(), HYBRID_PUBLIC_KEY_SIZE);
        assert_eq!(pk.as_bytes()[0], 0x42);
    }

    #[test]
    fn test_hybrid_keypair_secret_bytes_type_is_zeroizing() {
        let kp = HybridKeyPair {
            public_bytes: [0x11u8; HYBRID_PUBLIC_KEY_SIZE],
            secret_bytes: Zeroizing::new([0xAAu8; HYBRID_SECRET_KEY_SIZE]),
        };
        let secret_ref = kp.secret_bytes_for_test();
        assert_eq!(secret_ref[0], 0xAA);
        assert_eq!(secret_ref.len(), HYBRID_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_keypair_public_key_accessor_roundtrips_bytes() {
        let public_bytes = [0x77u8; HYBRID_PUBLIC_KEY_SIZE];
        let kp = HybridKeyPair {
            public_bytes,
            secret_bytes: Zeroizing::new([0u8; HYBRID_SECRET_KEY_SIZE]),
        };
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes(), public_bytes.as_slice());
    }

    #[test]
    fn test_hybrid_suite_seal_open_round_trips_repo_key() {
        let kp = HybridKeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let public = PublicKey::Hybrid(kp.public_key());
        let keypair = KeyPair::Hybrid(kp);
        let suite = HybridCryptoSuite;
        let sealed = suite.seal_repo_key(&repo_key, &public).unwrap();
        let opened = suite.open_repo_key(&sealed, &keypair).unwrap();
        assert_eq!(repo_key.to_base64(), opened.to_base64());
    }

    #[test]
    fn test_hybrid_suite_wrong_keypair_errors() {
        let kp1 = HybridKeyPair::generate().unwrap();
        let kp2 = HybridKeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let public1 = PublicKey::Hybrid(kp1.public_key());
        let keypair2 = KeyPair::Hybrid(kp2);
        let suite = HybridCryptoSuite;
        let sealed = suite.seal_repo_key(&repo_key, &public1).unwrap();
        assert!(suite.open_repo_key(&sealed, &keypair2).is_err());
    }

    #[test]
    fn test_hybrid_suite_rejects_classic_public_key() {
        let classic_pub = PublicKey::Classic([0u8; 32]);
        let repo_key = RepositoryKey::new();
        let err = HybridCryptoSuite
            .seal_repo_key(&repo_key, &classic_pub)
            .unwrap_err()
            .to_string();
        assert!(err.contains("hybrid suite cannot seal for a classic public key"));
    }

    #[test]
    fn test_hybrid_suite_rejects_classic_keypair() {
        let classic_kp = KeyPair::Classic(
            crate::crypto::classic::ClassicKeyPair::generate().unwrap(),
        );
        let err = HybridCryptoSuite
            .open_repo_key("fake-sealed", &classic_kp)
            .unwrap_err()
            .to_string();
        assert!(err.contains("hybrid suite cannot open a classic"));
    }

    #[test]
    fn test_hybrid_sealed_key_has_expected_length() {
        let kp = HybridKeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let public = PublicKey::Hybrid(kp.public_key());
        let sealed = HybridCryptoSuite.seal_repo_key(&repo_key, &public).unwrap();
        use base64::prelude::*;
        let decoded = BASE64_STANDARD.decode(&sealed).unwrap();
        assert_eq!(
            decoded.len(),
            HYBRID_ENCAPSULATION_SIZE
                + HYBRID_SEALED_KEY_NONCE_SIZE
                + HYBRID_REPO_KEY_PLAINTEXT_SIZE
                + HYBRID_SEALED_KEY_TAG_SIZE
        );
    }

    #[test]
    fn test_hybrid_open_rejects_tampered_ciphertext() {
        let kp = HybridKeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let public = PublicKey::Hybrid(kp.public_key());
        let keypair = KeyPair::Hybrid(kp);
        let sealed = HybridCryptoSuite.seal_repo_key(&repo_key, &public).unwrap();
        use base64::prelude::*;
        let mut decoded = BASE64_STANDARD.decode(&sealed).unwrap();
        // Flip a byte inside the AEAD ciphertext region (past encap + nonce).
        let ct_start = HYBRID_ENCAPSULATION_SIZE + HYBRID_SEALED_KEY_NONCE_SIZE;
        decoded[ct_start] ^= 0x01;
        let tampered = BASE64_STANDARD.encode(&decoded);
        assert!(HybridCryptoSuite.open_repo_key(&tampered, &keypair).is_err());
    }

    #[test]
    fn test_hybrid_open_rejects_tampered_nonce() {
        let kp = HybridKeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let public = PublicKey::Hybrid(kp.public_key());
        let keypair = KeyPair::Hybrid(kp);
        let sealed = HybridCryptoSuite.seal_repo_key(&repo_key, &public).unwrap();
        use base64::prelude::*;
        let mut decoded = BASE64_STANDARD.decode(&sealed).unwrap();
        // Flip a byte in the nonce region.
        decoded[HYBRID_ENCAPSULATION_SIZE] ^= 0x01;
        let tampered = BASE64_STANDARD.encode(&decoded);
        assert!(HybridCryptoSuite.open_repo_key(&tampered, &keypair).is_err());
    }
}
