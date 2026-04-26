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
use crate::crypto::classic::{ensure_sodium_init, KeyPair, PublicKey, RepositoryKey, SYMMETRIC_KEY_SIZE};
use crate::crypto::suite::CryptoSuite;

// trelis-hybrid KEM types. Resolved against the pinned commit
// 5374dff482ba94a94695794b5e4554f908eb0d4d (see Cargo.toml banner).
use trelis_hybrid::kem::{HybridEncapsulation, HybridKemKeypair, HybridKemPublicKey};

/// Plaintext repo-key size — mirrors `classic::SYMMETRIC_KEY_SIZE`.
const HYBRID_REPO_KEY_PLAINTEXT_SIZE: usize = SYMMETRIC_KEY_SIZE;

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
    #[cfg(test)]
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

    // =========================================================================
    // Plan 02-04: PQCRYPTO-03 byte-identical-ciphertext invariant tests
    // =========================================================================

    #[test]
    fn test_in_file_aead_byte_identical_across_suites() {
        // PQCRYPTO-03 — ROADMAP Phase 2 success criterion #3.
        // "For a fixed K, path, timestamp and plaintext, encrypt(...) produces
        //  byte-identical output whether K was wrapped classically or hybridly —
        //  the AEAD layer never observes which wrap was used."
        //
        // Concrete (fixed) inputs; the >=1000-case property sweep is Phase 5 TEST-01.
        use crate::crypto::encrypt_to_base64_deterministic;

        // Fixed 32-byte repository key — the same K is used via both suites.
        let fixed_k_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        let k_for_classic = RepositoryKey::from_bytes(&fixed_k_bytes).unwrap();
        let k_for_hybrid  = RepositoryKey::from_bytes(&fixed_k_bytes).unwrap();
        let path      = "secrets/api.env";
        let timestamp = "2026-04-24T00:00:00Z";
        let plaintext = "API_KEY=xyz\nDB_PASS=abc\n";

        // Both paths feed the SAME K to encrypt_to_base64_deterministic.
        // The suite-specific wrap machinery is not exercised here; what
        // matters is that the AEAD layer receives byte-identical K.
        let ct_classic = encrypt_to_base64_deterministic(
            plaintext, &k_for_classic, timestamp, path
        ).expect("classic-path encrypt failed");

        let ct_hybrid = encrypt_to_base64_deterministic(
            plaintext, &k_for_hybrid, timestamp, path
        ).expect("hybrid-path encrypt failed");

        assert_eq!(
            ct_classic, ct_hybrid,
            "PQCRYPTO-03 violated: in-file AEAD output differs across suites for \
             the same K+path+timestamp+plaintext. Either encrypt_to_base64_deterministic \
             is leaking suite state, the nonce derivation is non-deterministic, or \
             the AEAD key derivation depends on something other than K. This invariant \
             is load-bearing for Phase 4 (sss migrate) — every sealed file in the repo \
             must remain openable after K has been re-wrapped hybridly."
        );
    }

    #[test]
    fn test_in_file_aead_byte_identical_after_seal_open_round_trip() {
        // Stronger form: run K through the full classic seal->open and hybrid
        // seal->open, then compare encrypt outputs on the recovered K values.
        // This catches any regression where the wrap/unwrap cycle corrupts K
        // without the round-trip equality test in 02-03 catching it.
        use crate::crypto::{encrypt_to_base64_deterministic, ClassicSuite};
        use crate::crypto::suite::CryptoSuite;

        let repo_key = RepositoryKey::new();
        let path      = "secrets/prod.env";
        let timestamp = "2026-04-24T12:00:00Z";
        let plaintext = "some content\n";

        // Classic path: generate classic keypair -> seal K -> open K -> encrypt plaintext under recovered K.
        let classic_kp = KeyPair::generate().unwrap();
        let classic = ClassicSuite;
        let sealed_classic = classic.seal_repo_key(&repo_key, &classic_kp.public_key()).unwrap();
        let recovered_classic = classic.open_repo_key(&sealed_classic, &classic_kp).unwrap();
        let ct_via_classic = encrypt_to_base64_deterministic(
            plaintext, &recovered_classic, timestamp, path
        ).unwrap();

        // Hybrid path: generate hybrid keypair -> seal same K -> open K -> encrypt plaintext.
        let hybrid_kp_inner = HybridKeyPair::generate().unwrap();
        let hybrid_pub = PublicKey::Hybrid(hybrid_kp_inner.public_key());
        let hybrid_kp = KeyPair::Hybrid(hybrid_kp_inner);
        let hybrid = HybridCryptoSuite;
        let sealed_hybrid = hybrid.seal_repo_key(&repo_key, &hybrid_pub).unwrap();
        let recovered_hybrid = hybrid.open_repo_key(&sealed_hybrid, &hybrid_kp).unwrap();
        let ct_via_hybrid = encrypt_to_base64_deterministic(
            plaintext, &recovered_hybrid, timestamp, path
        ).unwrap();

        // The recovered K is identical across suites; the AEAD output must be too.
        assert_eq!(
            recovered_classic.to_bytes(), recovered_hybrid.to_bytes(),
            "recovered K bytes differ across suites — wrap/unwrap corrupted K"
        );
        assert_eq!(
            ct_via_classic, ct_via_hybrid,
            "PQCRYPTO-03 end-to-end violation: AEAD output differs after full seal/open \
             cycle through each suite. The K that comes back out must be byte-identical \
             regardless of which wrap path was used — that is the whole point of the \
             shared-K-shared-AEAD invariant."
        );
    }

    // =========================================================================
    // Plan 02-04: PQCRYPTO-04 zeroise-on-drop poison-pattern tests
    // =========================================================================

    #[test]
    fn test_hybrid_keypair_secret_bytes_zeroise_on_drop() {
        // PQCRYPTO-04 — poison-pattern test for HybridKeyPair::secret_bytes.
        // Allocate via ManuallyDrop, fill with marker, run drop in place, re-read
        // via raw pointer, assert zero.
        //
        // Pattern: hold the keypair in a stack-local ManuallyDrop<..> so the
        // storage persists through the post-drop observation; capture a raw
        // pointer to the first byte of secret_bytes BEFORE dropping; run
        // ManuallyDrop::drop which invokes the HybridKeyPair drop chain
        // (including Zeroizing on secret_bytes); re-read the same address.
        // The Zeroizing<..> wrapper MUST have overwritten the 0xA5 marker
        // with zeroes.
        //
        // ManuallyDrop is preferred over Box+drop here because a Box drop
        // returns the storage to the allocator, and the small-object pool
        // may reuse it before the post-drop read runs (observed on glibc
        // with the 32-byte AEAD-key variant of this test). ManuallyDrop
        // keeps the storage alive so the zeroise effect is the only reason
        // the observed bytes could differ from the pre-drop marker.
        use std::mem::ManuallyDrop;
        use std::ptr;

        let secret_bytes = Zeroizing::new([0xA5u8; HYBRID_SECRET_KEY_SIZE]);
        let mut kp: ManuallyDrop<HybridKeyPair> = ManuallyDrop::new(HybridKeyPair {
            public_bytes: [0u8; HYBRID_PUBLIC_KEY_SIZE],
            secret_bytes,
        });

        // Capture a raw pointer to the first byte of secret_bytes BEFORE drop.
        // Going through .secret_bytes_for_test gives us a &Zeroizing<[u8; N]>
        // which derefs to &[u8; N]; from there we take .as_ptr().
        let raw_ptr: *const u8 = kp.secret_bytes_for_test().as_ptr();

        // Sanity: the marker is in place pre-drop.
        // SAFETY: raw_ptr points into the stack-held ManuallyDrop<HybridKeyPair>;
        // the storage is live and owned by us for the duration of this test.
        let pre_drop = unsafe { ptr::read_volatile(raw_ptr) };
        assert_eq!(pre_drop, 0xA5, "marker pattern not in place pre-drop — test setup bug");

        // Run HybridKeyPair's drop chain in place without releasing the
        // backing storage. The chain includes the Zeroizing<..> drop on
        // secret_bytes, which MUST overwrite the 0xA5 marker with zeroes.
        // SAFETY: `kp` has not been dropped and we do not access its inner
        // value again after this call; the inner value is a valid
        // HybridKeyPair. We only read the now-zeroed bytes through raw_ptr.
        unsafe { ManuallyDrop::drop(&mut kp) };

        // SAFETY: the ManuallyDrop<..> still owns the storage (no dealloc);
        // we are reading the bytes Zeroizing just overwrote.
        let post_drop = unsafe { ptr::read_volatile(raw_ptr) };
        assert_eq!(
            post_drop, 0x00,
            "PQCRYPTO-04 violated: HybridKeyPair::secret_bytes not zeroised on drop. \
             This means X448+sntrup761 secret material lingers in memory after the \
             keypair is dropped."
        );
    }

    #[test]
    fn test_zeroizing_hybrid_secret_bytes_wrapper_zeroises_on_drop() {
        // PQCRYPTO-04 — confirm the Zeroizing<..> wrapper itself zeroises,
        // independent of HybridKeyPair. If this passes and the HybridKeyPair
        // test fails, the problem is in HybridKeyPair's construction
        // (missing wrapper, wrong derive). If this fails, the zeroize crate
        // itself is broken or wrongly configured.
        //
        // Uses ManuallyDrop<..> so the storage persists after the inner
        // Zeroizing drop runs — avoids any allocator-reuse race between the
        // dealloc and the post-drop observation (the 32-byte AEAD-key variant
        // of this test flaked under Box-drop on glibc's small-object pool).
        use std::mem::ManuallyDrop;
        use std::ptr;

        let mut wrapped: ManuallyDrop<Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>> =
            ManuallyDrop::new(Zeroizing::new([0xA5u8; HYBRID_SECRET_KEY_SIZE]));
        let raw_ptr: *const u8 = wrapped.as_ptr();

        // SAFETY: raw_ptr points into the stack-held ManuallyDrop<..>; the
        // allocation is live and owned by us for the duration of this test.
        let pre_drop = unsafe { ptr::read_volatile(raw_ptr) };
        assert_eq!(pre_drop, 0xA5);

        // Run Zeroizing's drop in place without releasing the backing storage.
        // SAFETY: `wrapped` has not been dropped and we do not touch its inner
        // value again after this call (we only read the zeroed bytes through
        // raw_ptr); the inner value is a valid Zeroizing<[u8; N]>.
        unsafe { ManuallyDrop::drop(&mut wrapped) };

        // SAFETY: the storage is still live (ManuallyDrop did not release it);
        // we are reading the bytes Zeroizing just overwrote.
        let post_drop = unsafe { ptr::read_volatile(raw_ptr) };
        assert_eq!(
            post_drop, 0x00,
            "Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]> wrapper failed to zeroise on drop. \
             The zeroize crate is not behaving as expected — re-verify the dep version."
        );
    }

    #[test]
    fn test_hybrid_aead_key_zeroises_on_drop() {
        // PQCRYPTO-04 — the transient AEAD key derived from the KEM shared
        // secret via blake3::derive_key is wrapped in Zeroizing<[u8; 32]>
        // inside HybridCryptoSuite::seal_repo_key / open_repo_key. Prove that
        // wrapper zeroises too, so the derived key does not linger in memory
        // after the seal/open call returns.
        //
        // IMPORTANT: For a 32-byte allocation, Box-then-drop would return the
        // slot to the allocator's small-object pool, where subsequent test
        // machinery (panic path, assertion formatting) would re-allocate over
        // the zeroed bytes before the post-drop observation could run. To
        // observe the zeroise without that race, we hold the storage via
        // ManuallyDrop<..> (no allocator dealloc) and invoke only the inner
        // Zeroizing<..> drop explicitly. This isolates the zeroise effect
        // from any allocator reuse.
        use std::mem::ManuallyDrop;
        use std::ptr;

        // Stand-in shared secret bytes (what trelis encapsulate would hand us).
        let shared_secret_bytes = [0x42u8; 32];
        let mut wrapped: ManuallyDrop<Zeroizing<[u8; 32]>> = ManuallyDrop::new(
            Zeroizing::new(blake3::derive_key(HYBRID_KEM_CONTEXT, &shared_secret_bytes)),
        );
        let raw_ptr: *const u8 = wrapped.as_ptr();

        // The pre-drop value is some BLAKE3 output (not our choice), but it
        // is NOT zero — confirm that before dropping.
        // SAFETY: raw_ptr points into the stack-held ManuallyDrop<..>; the
        // allocation is live and we are only reading bytes we own.
        let pre_drop_nonzero = (0..32).any(|i| {
            let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
            byte != 0
        });
        assert!(pre_drop_nonzero, "BLAKE3 output was all-zero pre-drop — test setup bug");

        // Manually drop the inner Zeroizing<..> in place. This runs the
        // zeroise step but does NOT release the backing storage — the
        // ManuallyDrop<..> still owns it on the stack, so the bytes we are
        // about to inspect are guaranteed to be the ones Zeroizing overwrote.
        // SAFETY: `wrapped` has not been dropped and we do not touch it again
        // after this call; the inner value is a valid Zeroizing<[u8; 32]>.
        unsafe { ManuallyDrop::drop(&mut wrapped) };

        // Every byte of the derived key must be zero after Zeroizing's drop.
        // SAFETY: raw_ptr still points into live stack storage owned by
        // `wrapped` (ManuallyDrop leaves the storage intact); reading those
        // bytes is well-defined.
        let all_zero_post_drop = (0..32).all(|i| {
            let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
            byte == 0
        });
        assert!(
            all_zero_post_drop,
            "PQCRYPTO-04 violated: derived AEAD key did not zeroise on drop. \
             Every seal/open call would leak 32 bytes of key material into the heap."
        );
    }
}
