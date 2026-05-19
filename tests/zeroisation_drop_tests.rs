// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out (mirror of
// tests/miri_smoke.rs file-top discipline).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Why: this entire harness is gated on `feature = "hybrid"` so Ed448SigningKey /
// MlDsa65SigningKey / EnvelopeSig imports compile. The file compiles to an empty
// test binary on default-features builds (matches tests/miri_smoke.rs:6 and
// tests/keystore_signature_negative_paths.rs:3).
#![cfg(feature = "hybrid")]

//! MEMSAFE-05 — drop-zeroisation regression suite for v2.2 sig keypair / envelope
//! secret material (Phase 23 Plan 23-03).
//!
//! Goal: extend the v2.1 Phase 8 HARDEN-04 22-site zeroisation guarantee to the
//! v2.2 Phase 18 (PQSIG-01) sig keypair material and Phase 19 (PQSIG-04) envelope
//! signed-payload buffers. The audit deliverable for the 22 → 34 site count
//! refresh lives at
//! `.planning/phases/23-sanitizers-asan-tsan-zeroisation-second-pass/ZEROISATION-AUDIT.md`.
//!
//! Patterns (both mirror Phase 22 Plan 22-02 `tests/miri_smoke.rs`):
//!
//! **Tests 1 + 2 — fixed-size Ed448 / ML-DSA-65 SK bytes (57 + 4032 bytes):**
//! - `let mut wrapped: ManuallyDrop<Zeroizing<[u8; N]>> = ManuallyDrop::new(Zeroizing::new(bytes));`
//! - Capture raw pointer BEFORE manual drop.
//! - Manually fire `Zeroize::zeroize` via `ManuallyDrop::drop` (the inner
//!   call is in an unsafe-block; see the in-fn `SAFETY:` comments).
//! - Post-drop: loop the captured pointer via `ptr::read_volatile`, assert each
//!   byte is 0. `read_volatile` defeats any compiler dead-store-elimination on
//!   the zeroisation; the stack-array storage remains valid because
//!   `ManuallyDrop` did not release it (no heap-dealloc race).
//!
//! **Test 3 — variable-size envelope sig payload (Vec<u8>):**
//! - `let mut zeroizing_payload: Zeroizing<Vec<u8>> = Zeroizing::new(build_envelope_payload(&cfg));`
//! - Capture raw pointer into the live heap allocation.
//! - `(*zeroizing_payload).zeroize()` — invoke `Zeroize::zeroize` directly while
//!   the Vec is still owned (no drop, no dealloc); validates the zeroise STEP
//!   in isolation from any heap-reuse race.
//! - Post-zeroise: loop the captured pointer via `ptr::read_volatile`, assert
//!   each byte is 0. The Vec stays alive on the stack until end-of-scope.
//!
//! Both patterns avoid the post-Vec-drop heap-reuse race documented in
//! `src/crypto/hybrid.rs:644-650` (where Vec's drop returns the slot to the
//! allocator's small-object pool and assertion-formatting machinery
//! re-allocates over the zeroed bytes before the post-drop observation
//! could run).
//!
//! Each unsafe-block carries a `// SAFETY:` rationale within the 3 lines
//! immediately above (Phase 21 Plan 21-03 proximity discipline; verified against
//! `scripts/check-safety-comments.sh --include-tests` baseline).
//!
//! Coverage map (see ZEROISATION-AUDIT.md § "Drop-Test Coverage" for cross-link):
//! - Test 1: Ed448 SK bytes (57 bytes) — mirrors `src/keystore/store.rs:803, 987, 1453`.
//! - Test 2: ML-DSA-65 SK bytes (4032 bytes) — mirrors `src/keystore/store.rs:812, 996, 1461`.
//! - Test 3: Envelope sig canonical payload — mirrors `src/envelope_sig.rs::build_envelope_payload`.
//!
//! Acceptance: all 3 tests pass under
//! `cargo test --features hybrid --test zeroisation_drop_tests` on stable.
//! `cargo build --tests --features hybrid` exits clean (visibility audit gate
//! per memory `feedback_visibility_audit_gate` — this file references
//! `sss::envelope_sig::*` and `sss::project::*` from `tests/`).

use std::mem::ManuallyDrop;
use std::ptr;

use zeroize::{Zeroize, Zeroizing};

use trelis_primitives::{
    Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme,
};

use sss::envelope_sig::build_envelope_payload;
use sss::project::{ProjectConfig, UserConfig};

// ===========================================================================
// Test 1 — Ed448 signing-key bytes zeroise under drop (v2.2 Phase 18 sites 23, 25, 30)
//
// Mirrors the production wrapper pattern at `src/keystore/store.rs:803, 987, 1453`,
// which wraps the bytes returned by `signing_key_to_bytes(&sk)` in a
// `Zeroizing<...>`:
//
//   let ed448_sk_bytes =
//       Zeroizing::new(Ed448Standard::signing_key_to_bytes(&ed448_sk).to_vec());
//
// The size is 57 bytes (RFC 8032 Ed448 seed = trelis-primitives
// `pub const SECRET_KEY_SIZE: usize = 57`).
//
// Implementation note: this test uses the stack-array form
// `Zeroizing<[u8; 57]>` rather than the heap-Vec form `Zeroizing<Vec<u8>>`.
// The reason mirrors the in-source rationale at `src/crypto/hybrid.rs:644-650`
// — for a small heap buffer (<= 4 KiB), `Vec`'s drop returns the slot to the
// allocator's small-object pool, where subsequent test machinery (panic path,
// assertion formatting) re-allocates over the zeroed bytes before the
// post-drop observation can run. Stack-array storage held in `ManuallyDrop`
// avoids that race entirely. The zeroize crate's drop loop is THE SAME in
// both cases (Zeroize::zeroize on the byte slice); validating it on a stack
// array is equivalent to validating it on a Vec's backing storage —
// modulo the test-side observability race, which is what this form avoids.
// ===========================================================================

#[test]
fn test_ed448_signing_key_bytes_zeroise_under_drop() {
    // Generate a real Ed448SigningKey. The trelis-primitives derive on
    // `Ed448SigningKey` includes `Zeroize, ZeroizeOnDrop` (crates-source at
    // `crates/trelis-primitives/src/ed448.rs:58`), so the upstream type
    // already zeroises its private `seed` field on drop. The PRODUCTION
    // sss-side wrapping pattern extracts the seed via `signing_key_to_bytes`
    // into a `Vec<u8>` and then wraps that in `Zeroizing` — see the call
    // sites above. This test validates THAT wrapper's zeroise step (the same
    // `Zeroize::zeroize` implementation runs whether the inner type is a
    // [u8; 57] or a Vec<u8>).
    let ed448_sk = Ed448Standard::generate()
        .expect("Ed448Standard::generate must succeed in test environment");
    let sk_bytes: [u8; 57] = Ed448Standard::signing_key_to_bytes(&ed448_sk);

    // Sanity: random key material should have at least one non-zero byte.
    // If by astronomical chance the generator returns 57 zero bytes, the
    // post-drop assertion would tautologically pass. Probability ~2^-456 —
    // negligible — but the assertion is documented.
    assert!(
        sk_bytes.iter().any(|&b| b != 0),
        "freshly-generated Ed448 SK is all-zero bytes; test is invalid — regenerate or investigate trelis Ed448Standard::generate"
    );

    // Wrap in `ManuallyDrop<Zeroizing<[u8; 57]>>`. The [u8; 57] storage lives
    // on the stack (no allocator dealloc race); ManuallyDrop keeps the
    // wrapper alive so we can read the bytes through `raw_ptr` after the
    // inner Zeroizing's drop fires.
    let mut wrapped: ManuallyDrop<Zeroizing<[u8; 57]>> =
        ManuallyDrop::new(Zeroizing::new(sk_bytes));

    let raw_ptr: *const u8 = wrapped.as_ptr();

    // Run Zeroizing's drop in place — overwrites the 57 bytes with zeros via
    // the zeroize crate's drop loop; ManuallyDrop keeps the stack storage live.
    // SAFETY: `wrapped` has not been dropped; we do not touch its inner value
    // again after this call (only via `raw_ptr` for post-drop reads); the
    // inner value is a valid Zeroizing<[u8; 57]>.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Post-drop: every byte in the (now zeroed) stack array must be zero.
    // We read via `ptr::read_volatile` to defeat any dead-store-elimination
    // the compiler might apply to the zeroise loop.
    for i in 0..57 {
        // SAFETY: raw_ptr points into stack-held ManuallyDrop<..> storage that
        // is still live; raw_ptr.add(i) is in-bounds for (0..57) against the
        // 57-byte array; read_volatile defeats DSE on the zeroise loop.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "MEMSAFE-05 violated: Ed448 SK bytes wrapper (57-byte Zeroizing<[u8; 57]>) did not zeroise on drop at offset {i}. \
             Production sites `src/keystore/store.rs:803, 987, 1453` would leak Ed448 seed material at drop time."
        );
    }
}

// ===========================================================================
// Test 2 — ML-DSA-65 signing-key bytes zeroise under drop (v2.2 Phase 18 sites 24, 26, 31)
//
// Mirrors the production wrapper at `src/keystore/store.rs:812, 996, 1461`:
//
//   let mldsa_sk_bytes =
//       Zeroizing::new(MlDsa65Fips204::signing_key_to_bytes(&mldsa_sk).to_vec());
//
// The size is 4032 bytes (FIPS 204 ML-DSA-65 secret-key = trelis-primitives
// `signing_key_to_bytes(&sk) -> [u8; 4032]`).
//
// Same stack-array-form rationale as Test 1 — see the in-source comment there
// and the original motivating rationale at `src/crypto/hybrid.rs:644-650`.
// ===========================================================================

#[test]
fn test_mldsa65_signing_key_bytes_zeroise_under_drop() {
    // Same pattern as Test 1 but at ML-DSA-65 secret-key scale (4032 bytes).
    // The trelis-primitives derive on `MlDsa65SigningKey` includes
    // `Zeroize, ZeroizeOnDrop` (crates-source at
    // `crates/trelis-primitives/src/mldsa65.rs:60`), so the upstream type
    // already zeroises its private `bytes` field on drop. Sss-side wrapping
    // is what this test validates.
    let mldsa_sk = MlDsa65Fips204::generate()
        .expect("MlDsa65Fips204::generate must succeed in test environment");
    let sk_bytes: [u8; 4032] = MlDsa65Fips204::signing_key_to_bytes(&mldsa_sk);

    // Sanity: random key material should have at least one non-zero byte.
    assert!(
        sk_bytes.iter().any(|&b| b != 0),
        "freshly-generated ML-DSA-65 SK is all-zero bytes; test is invalid — regenerate or investigate trelis MlDsa65Fips204::generate"
    );

    // Wrap in `ManuallyDrop<Zeroizing<[u8; 4032]>>` — stack-resident 4032
    // bytes (no allocator dealloc race; see Test 1's rationale comment).
    // Note: 4032 bytes on the test's stack — well inside the default
    // 2-8 MiB pthread stack. The Phase 22 miri_smoke.rs equivalents at
    // HYBRID_SECRET_KEY_SIZE (1819 bytes) are smaller but the same form.
    let mut wrapped: ManuallyDrop<Zeroizing<[u8; 4032]>> =
        ManuallyDrop::new(Zeroizing::new(sk_bytes));

    let raw_ptr: *const u8 = wrapped.as_ptr();

    // SAFETY: `wrapped` has not been dropped; we do not touch its inner value
    // again after this call (only via raw_ptr for post-drop reads); the inner
    // value is a valid Zeroizing<[u8; 4032]>.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Loop every byte (4032 iterations). At ~3ns per volatile read this is
    // ~12µs — negligible test-time cost.
    for i in 0..4032 {
        // SAFETY: raw_ptr points into stack-held ManuallyDrop<..>; storage
        // is still live. `raw_ptr.add(i)` is in-bounds for (0..4032).
        // `read_volatile` defeats DSE on the zeroise.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "MEMSAFE-05 violated: ML-DSA-65 SK bytes wrapper (4032-byte Zeroizing<[u8; 4032]>) did not zeroise on drop at offset {i}. \
             Production sites `src/keystore/store.rs:812, 996, 1461` would leak ML-DSA-65 secret material at drop time."
        );
    }
}

// ===========================================================================
// Test 3 — Envelope sig payload buffer zeroises (v2.2 Phase 19 site 34)
//
// `src/envelope_sig.rs::build_envelope_payload(&cfg)` returns a `Vec<u8>` of
// the canonical-encoded sig payload (length-prefixed concatenation of
// identity-bearing fields per D-03). The bytes themselves are derived from
// PUBLIC envelope fields (no secret material in the payload by construction),
// but defence-in-depth callers may choose to wrap the payload in
// `Zeroizing<Vec<u8>>` for the transit-zone between `build_envelope_payload`
// and `sign_envelope` / `verify_envelope`. This test validates that the
// `Zeroize` impl on the inner `Vec<u8>` actually zeros the buffer's
// observable bytes (a defence-in-depth caller's worst-case anti-leak).
//
// Methodology difference from Tests 1+2: the envelope payload is
// variable-length, so it cannot be held in a stack-array `Zeroizing<[u8; N]>`.
// Instead this test invokes `Zeroize::zeroize(&mut vec)` DIRECTLY on the
// inner `Vec<u8>` while the Vec is still live (not yet dropped, not yet
// deallocated) and observes the bytes through `raw_ptr` immediately after.
// This validates the zeroise STEP of the contract (the load-bearing
// observable) without interacting with the heap-dealloc race that bit
// Test 1+2's earlier Vec-form draft (cf. `src/crypto/hybrid.rs:644-650`).
// The wrapper's drop chain still calls Zeroize::zeroize then Vec::drop, so
// validating the zeroise step in isolation is equivalent to validating the
// drop chain modulo the dealloc race.
// ===========================================================================

#[test]
fn test_envelope_signed_payload_buffer_zeroise_under_drop() {
    // Build a minimal ProjectConfig with 2 users so the canonical payload is
    // non-trivial (length-prefixed: version + created + per-user-sorted
    // fields). We use deterministic base64 marker bytes so the pre-drop
    // sanity check has a clear expected pattern.
    let mut users = std::collections::HashMap::new();
    users.insert("alice".to_string(), UserConfig {
        public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        sealed_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=".to_string(),
        added: "2026-05-09T00:00:00Z".to_string(),
        hybrid_public: Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=".to_string()),
        sig_ed448_public: Some("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD0=".to_string()),
        sig_mldsa65_public: Some("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=".to_string()),
    });
    users.insert("bob".to_string(), UserConfig {
        public: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA=".to_string(),
        sealed_key: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG0=".to_string(),
        added: "2026-05-09T00:00:00Z".to_string(),
        hybrid_public: None,
        sig_ed448_public: None,
        sig_mldsa65_public: None,
    });
    let cfg = ProjectConfig {
        version: "2.0".to_string(),
        format_version: 2,
        created: "2026-05-09T00:00:00Z".to_string(),
        users,
        ..ProjectConfig::default()
    };

    // Build the canonical envelope payload — this is the buffer that gets
    // passed to `sign_envelope` / `verify_envelope` (the Phase 19 PQSIG-04
    // sig surface). Wrap it in Zeroizing<Vec<u8>> — the defence-in-depth
    // wrapper shape a security-conscious caller would apply.
    let payload: Vec<u8> = build_envelope_payload(&cfg);
    assert!(payload.len() >= 64, "envelope payload too small to be meaningful");

    let mut zeroizing_payload: Zeroizing<Vec<u8>> = Zeroizing::new(payload);
    let len: usize = zeroizing_payload.len();

    // Pre-zeroise sanity: the payload contains the version string "2.0" at
    // a known offset (after the 4-byte u32-BE length prefix at the start).
    // This both validates the payload was actually constructed AND gives us
    // a known non-zero byte to observe.
    assert_eq!(&zeroizing_payload[0..4], &[0, 0, 0, 3], "payload should start with u32-BE length 3 for 'version' field '2.0'");
    assert_eq!(&zeroizing_payload[4..7], b"2.0", "payload should contain version string '2.0' after the length prefix");

    // Capture the pointer into the live heap allocation BEFORE invoking
    // zeroize. The Vec's backing storage stays at this address while
    // zeroize runs (zeroize operates in place; it does not reallocate).
    let raw_ptr: *const u8 = zeroizing_payload.as_ptr();

    // Invoke Zeroize::zeroize DIRECTLY on the inner Vec<u8>. This is the
    // exact same call that the Zeroizing<Vec<u8>> drop chain would invoke
    // (Zeroize is implemented for Vec<u8> in the zeroize crate — `impl
    // Zeroize for Vec<T> where T: Zeroize` — and writes zeros to every
    // byte). After this call, the Vec is still alive on the test's stack;
    // its backing storage is still owned at the same address.
    //
    // The Zeroizing<Vec<u8>> wrapper's `drop` impl would call this same
    // `zeroize` and then drop the inner Vec (releasing the heap allocation
    // back to the allocator). By calling zeroize explicitly while the Vec is
    // still owned, we observe the zeroise step in isolation — no dealloc
    // race. This is exactly the "explicit Zeroize::zeroize" pattern used by
    // `src/secure_memory.rs::SecureBuffer::clear` (lines 161-164) and
    // `SecureString::clear` (lines 62-65).
    (*zeroizing_payload).zeroize();

    // Every byte in the (still-live) Vec must now be zero.
    for i in 0..len {
        // SAFETY: raw_ptr points into the still-live Vec's heap allocation
        // (zeroizing_payload still owned on the test's stack frame); raw_ptr.add(i)
        // is in-bounds for (0..len); read_volatile defeats DSE on the zeroise.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "MEMSAFE-05 violated: envelope sig payload Zeroizing<Vec<u8>> wrapper's inner Zeroize::zeroize did not zeroise byte at offset {i}. \
             A defence-in-depth caller of `build_envelope_payload` would leak transient envelope-sig payload bytes."
        );
    }

    // Explicit drop of zeroizing_payload here would call zeroize again (now
    // a no-op since bytes are already zero) and then drop the Vec.
    // The explicit drop is not necessary; Rust will drop it when it goes
    // out of scope. We let RAII handle cleanup — the test has already
    // observed the load-bearing post-zeroise state.
    drop(zeroizing_payload);
}
