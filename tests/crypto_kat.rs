// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Known-answer tests (KAT) for XChaCha20-Poly1305 secretbox — default feature arm.
//!
//! # Gap Documentation (TEST-14)
//!
//! **No authoritative external KAT exists for `crypto_secretbox_xchacha20poly1305_easy`.**
//!
//! sss uses `crypto_secretbox_xchacha20poly1305_easy` (libsodium's non-AEAD secretbox
//! variant, which prepends the 16-byte MAC to the ciphertext).  This function is
//! distinct from — and format-incompatible with — the AEAD construction:
//!
//! * The libsodium test suite (`test/default/secretbox_easy.c`) tests only
//!   `crypto_secretbox_easy` (the default XSalsa20-Poly1305 variant), **not** the
//!   XChaCha20 variant.  No `secretbox_xchacha20.c` test file exists in the libsodium
//!   source tree.
//!
//! * The IETF draft-irtf-cfrg-xchacha-03 §A.1 vector applies to
//!   `AEAD_XChaCha20_Poly1305` — i.e., `crypto_aead_xchacha20poly1305_ietf_*` — which
//!   uses a **different wire format** from the secretbox API (AEAD embeds the tag at
//!   the end and supports additional authenticated data; secretbox prepends the MAC and
//!   has no AAD). The IETF vector therefore **cannot** be verified with
//!   `crypto_secretbox_xchacha20poly1305_easy`.
//!   [libsodium discussion #1101](https://github.com/jedisct1/libsodium/discussions/1101)
//!   [IETF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)
//!
//! The frozen vector below is therefore a **regression freeze**, not a
//! cross-implementation KAT.  It was generated once at test-write time by calling the
//! production libsodium FFI function with fixed inputs, recording the output, and
//! committing it here.  Its purpose is to detect silent implementation drift: if a
//! libsodium update or platform change alters the byte-stable output of this function,
//! the assertion fails at `cargo test` time.

use libsodium_sys as sodium;

// Mirror the private/pub(crate) constants from src/crypto/classic.rs.
// We cannot import them directly because they are not pub; test-local redefinition
// is the established convention (see tests/hybrid_coverage.rs lines 22-24).
const KEY_SIZE: usize = 32;   // crypto_secretbox_xchacha20poly1305_KEYBYTES
const NONCE_SIZE: usize = 24; // crypto_secretbox_xchacha20poly1305_NONCEBYTES
const MAC_SIZE: usize = 16;   // crypto_secretbox_xchacha20poly1305_MACBYTES

// ─── Frozen regression vector ────────────────────────────────────────────────
//
// Generated at test-write time (2026-06-04) by calling
// crypto_secretbox_xchacha20poly1305_easy with the key, nonce, and plaintext
// below and recording the output.  These bytes are the ground-truth for
// regression detection.

/// Fixed 32-byte key used for all crypto_kat secretbox tests.
const KAT_KEY: [u8; KEY_SIZE] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Fixed 24-byte nonce used for the byte-freeze test.
const KAT_NONCE: [u8; NONCE_SIZE] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
];

/// Fixed plaintext for the byte-freeze test.
const KAT_PLAINTEXT: &[u8] =
    b"known-answer-test for sss crypto_secretbox_xchacha20poly1305_easy";

/// Frozen expected ciphertext (MAC prepended, as per secretbox wire format).
/// Length = KAT_PLAINTEXT.len() + MAC_SIZE = 65 + 16 = 81 bytes.
/// Generated once at test-write time; asserted on every run.
const KAT_EXPECTED_CIPHERTEXT: [u8; 81] = [
    0x17, 0xa8, 0x1d, 0x0f, 0x2e, 0x9b, 0xa5, 0x83,
    0x34, 0xf5, 0xc8, 0x74, 0x2e, 0x67, 0x39, 0xc7,
    0xf1, 0x23, 0x23, 0xa0, 0x33, 0xbe, 0x31, 0x1f,
    0x6e, 0x7f, 0x3c, 0x72, 0xb0, 0xb2, 0xa8, 0x01,
    0x4a, 0x4e, 0xbb, 0x6a, 0x98, 0x37, 0x61, 0xc6,
    0x5d, 0xc0, 0x97, 0xe9, 0x8d, 0xcf, 0x2a, 0x0f,
    0xdb, 0x41, 0xe0, 0x7c, 0xd1, 0x97, 0xf3, 0x43,
    0xcf, 0x74, 0x54, 0x80, 0x4d, 0x07, 0xe3, 0x57,
    0xc3, 0x6a, 0x58, 0xb3, 0x52, 0x54, 0x75, 0xbb,
    0x93, 0x04, 0xf6, 0x34, 0xb0, 0x44, 0xc2, 0xaf,
    0x26,
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Initialise libsodium exactly once.
///
/// Mirrors the `ensure_sodium_init()` pattern in src/crypto/classic.rs.
fn sodium_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    // SAFETY: `sodium_init()` is thread-safe per libsodium docs; the `Once`
    // guard ensures it is called exactly once across the process. A negative
    // return means libsodium cannot initialise — no recovery is possible, so
    // panicking (test context) is appropriate.
    INIT.call_once(|| unsafe {
        assert!(
            sodium::sodium_init() >= 0,
            "libsodium sodium_init() failed"
        );
    });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Byte-freeze KAT: fixed (key, nonce, plaintext) → frozen ciphertext.
///
/// Calls `crypto_secretbox_xchacha20poly1305_easy` directly — the same FFI
/// function the production `encrypt_internal` / `encrypt` paths in
/// src/crypto/classic.rs call (lines 709 and 762).
#[test]
fn kat_xchacha20poly1305_secretbox_regression_freeze() {
    sodium_init();

    let mlen = KAT_PLAINTEXT.len() as u64;
    let clen = KAT_PLAINTEXT.len() + MAC_SIZE;
    let mut ciphertext = vec![0u8; clen];

    // SAFETY: `ciphertext` is sized to plaintext.len() + MAC_SIZE, exactly the
    // byte count `crypto_secretbox_xchacha20poly1305_easy` writes on success.
    // `KAT_PLAINTEXT`/`KAT_NONCE`/`KAT_KEY` are valid pointers of the
    // expected sizes (KEY_SIZE=32, NONCE_SIZE=24). libsodium is initialised by
    // the preceding `sodium_init()` call. Returns 0 on success.
    let ret = unsafe {
        sodium::crypto_secretbox_xchacha20poly1305_easy(
            ciphertext.as_mut_ptr(),
            KAT_PLAINTEXT.as_ptr(),
            mlen,
            KAT_NONCE.as_ptr(),
            KAT_KEY.as_ptr(),
        )
    };
    assert_eq!(ret, 0, "crypto_secretbox_xchacha20poly1305_easy returned non-zero");
    assert_eq!(
        ciphertext.as_slice(),
        KAT_EXPECTED_CIPHERTEXT.as_slice(),
        "XChaCha20-Poly1305 ciphertext does not match frozen regression vector"
    );
}

/// Open KAT: `_open_easy` on the frozen ciphertext returns the original plaintext.
#[test]
fn kat_xchacha20poly1305_secretbox_open_roundtrip() {
    sodium_init();

    let clen = KAT_EXPECTED_CIPHERTEXT.len() as u64;
    let plaintext_len = KAT_EXPECTED_CIPHERTEXT.len() - MAC_SIZE;
    let mut plaintext = vec![0u8; plaintext_len];

    // SAFETY: `plaintext` is sized to ciphertext.len() - MAC_SIZE, the exact
    // byte count `crypto_secretbox_xchacha20poly1305_open_easy` writes on
    // success. All pointers are valid with consistent (ptr, len) pairs.
    // Returns 0 on success; non-zero indicates MAC failure.
    let ret = unsafe {
        sodium::crypto_secretbox_xchacha20poly1305_open_easy(
            plaintext.as_mut_ptr(),
            KAT_EXPECTED_CIPHERTEXT.as_ptr(),
            clen,
            KAT_NONCE.as_ptr(),
            KAT_KEY.as_ptr(),
        )
    };
    assert_eq!(ret, 0, "crypto_secretbox_xchacha20poly1305_open_easy failed on frozen ciphertext");
    assert_eq!(
        plaintext.as_slice(),
        KAT_PLAINTEXT,
        "decrypted plaintext does not match original"
    );
}

/// Production-path round-trip: `sss::crypto::encrypt` then `sss::crypto::decrypt`.
///
/// The production `encrypt` function derives a deterministic nonce internally,
/// so this test exercises the full high-level path without pinning a specific
/// nonce — it is a round-trip correctness check, not a byte-freeze.
#[test]
fn kat_xchacha20poly1305_production_path_roundtrip() {
    use sss::crypto::{decrypt, encrypt, RepositoryKey};

    let key = RepositoryKey::from_bytes(&KAT_KEY).unwrap();
    let plaintext = b"production-path round-trip test payload";
    let timestamp = "2026-06-04T00:00:00Z";
    let file_path = "./test-kat.yml";

    let ciphertext = encrypt(plaintext, &key, timestamp, file_path).unwrap();
    let recovered = decrypt(&ciphertext, &key).unwrap();

    assert_eq!(
        recovered.as_slice(),
        plaintext,
        "production encrypt/decrypt round-trip failed"
    );
}

/// Tamper resistance: flipping one byte of the frozen ciphertext causes MAC rejection.
#[test]
fn kat_xchacha20poly1305_tamper_rejects() {
    sodium_init();

    let mut tampered = KAT_EXPECTED_CIPHERTEXT;
    // Flip the last byte (deep in the ciphertext body, not just the MAC prefix)
    tampered[KAT_EXPECTED_CIPHERTEXT.len() - 1] ^= 0xff;

    let clen = tampered.len() as u64;
    let plaintext_len = tampered.len() - MAC_SIZE;
    let mut plaintext = vec![0u8; plaintext_len];

    // SAFETY: same invariants as kat_xchacha20poly1305_secretbox_open_roundtrip;
    // we expect non-zero (MAC rejection) here.
    let ret = unsafe {
        sodium::crypto_secretbox_xchacha20poly1305_open_easy(
            plaintext.as_mut_ptr(),
            tampered.as_ptr(),
            clen,
            KAT_NONCE.as_ptr(),
            KAT_KEY.as_ptr(),
        )
    };
    assert_ne!(
        ret,
        0,
        "crypto_secretbox_xchacha20poly1305_open_easy should reject tampered ciphertext"
    );
}
