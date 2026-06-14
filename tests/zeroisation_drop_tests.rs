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

// ===========================================================================
// Tests 5–7 — trelis ZeroizeOnDrop regression suite (REM-30 / MEM-16)
//
// BACKGROUND — the MEM-16 gap these tests close:
//   Tests 1+2 above validate the SSS-SIDE `Zeroizing<[u8; N]>` WRAPPER that
//   wraps a COPY of the bytes extracted via `signing_key_to_bytes(&sk)`.
//   They do NOT exercise the trelis types' OWN `ZeroizeOnDrop` derive on
//   their internal field.  A defective trelis derive (e.g. `#[zeroize(skip)]`
//   accidentally applied to the secret field, or a derive macro regression)
//   would be undetected by Tests 1+2 because those tests never drop a live
//   trelis signing-key instance.
//
//   These three tests close that gap by dropping REAL trelis type instances
//   and observing the type's own secret field zero.  A defective upstream
//   `ZeroizeOnDrop` derive fails them.
//
// Test 5: `Ed448SigningKey` — observe own `seed` field ([u8; 57]) zeroed after drop.
// Test 6: `MlDsa65SigningKey` — observe own `bytes` field ([u8; 4032]) zeroed after drop.
// Test 7: `HybridKemKeypair` — drop-without-UB + reachable-secret zeroise
//         (no-flat-accessor limitation documented in the test comment).
// ===========================================================================

// ===========================================================================
// Test 5 — trelis Ed448SigningKey own seed field zeroises on drop (REM-30/MEM-16)
//
// WHAT IS TESTED:
//   This test drops a REAL `Ed448SigningKey` instance and observes that trelis's
//   OWN `ZeroizeOnDrop` derive zeroed the `seed: [u8; 57]` field.  This is the
//   MEM-16 gap: if trelis's derive were defective (e.g. the field were skipped),
//   57 bytes of Ed448 seed material would linger in memory after every key drop.
//
// TECHNIQUE:
//   `Ed448SigningKey` is `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` with field
//   `seed: [u8; 57]` exposed via `pub fn seed(&self) -> &[u8; 57]`.  We wrap
//   the key in `ManuallyDrop` to keep the stack storage live past the explicit
//   drop, capture `raw_ptr` into the LIVE FIELD before firing `ManuallyDrop::drop`,
//   then read the field bytes via `ptr::read_volatile` to defeat dead-store
//   elimination.  The fact that `raw_ptr` was obtained BEFORE the drop and points
//   into the ManuallyDrop-owned storage (not a separately-copied buffer) is what
//   makes this test sensitive to the trelis derive: if the derive is a no-op the
//   bytes are unchanged.
//
// IMPORT ROUTE:
//   `Ed448SigningKey` is re-exported from `trelis_primitives` (confirmed at pinned
//   SHA 5374dff: `pub use ed448::Ed448SigningKey`).  `Ed448Standard::generate()`
//   internally calls `Ed448SigningKey::generate()` — we call the type directly for
//   clarity.
// ===========================================================================

#[test]
fn test_trelis_ed448_signing_key_own_seed_zeroises_on_drop() {
    use trelis_primitives::Ed448SigningKey;

    // Generate a real Ed448SigningKey.  Its internal `seed: [u8; 57]` field holds
    // the secret material that `ZeroizeOnDrop` must zero on drop.
    let sk = Ed448SigningKey::generate()
        .expect("Ed448SigningKey::generate must succeed in test environment");

    // Wrap in ManuallyDrop to keep the struct's stack storage live after we
    // explicitly fire the inner drop via `ManuallyDrop::drop`.
    let mut wrapped: ManuallyDrop<Ed448SigningKey> = ManuallyDrop::new(sk);

    // Capture a pointer into the LIVE `seed` field BEFORE firing the drop.
    // `seed()` returns `&[u8; SECRET_KEY_SIZE]` (57 bytes) referencing the
    // field byte-for-byte inside the struct on the stack.  After `ManuallyDrop::drop`
    // runs the `ZeroizeOnDrop` derive, those 57 bytes must be zero.
    //
    // `(*wrapped)` is a safe deref of ManuallyDrop (ManuallyDrop::deref is safe).
    // We immediately convert the returned reference to `*const u8`; the raw pointer
    // is valid for the lifetime of the ManuallyDrop storage (which persists until
    // end of scope because ManuallyDrop does not release storage on drop).
    let raw_ptr: *const u8 = (*wrapped).seed().as_ptr();

    // Pre-drop sanity: at least one byte must be non-zero.  A freshly-generated
    // Ed448 seed is a random 57-byte value; probability of all-zero ~2^-456.
    // If this fires, the generator is broken — not the test.
    let any_nonzero = (0..57).any(|i| {
        // SAFETY: raw_ptr points into the live ManuallyDrop-owned stack storage;
        // offset i is bounded by (0..57) against the 57-byte field.
        unsafe { ptr::read_volatile(raw_ptr.add(i)) != 0 }
    });
    assert!(
        any_nonzero,
        "REM-30/MEM-16: freshly-generated Ed448SigningKey seed is all-zero — \
         test is vacuous; investigate Ed448SigningKey::generate"
    );

    // Fire trelis's ZeroizeOnDrop derive on the LIVE key.  This calls
    // `Zeroize::zeroize` on the struct (which zeroes the `seed` field in-place)
    // via the derived `Drop::drop` impl.  ManuallyDrop does NOT release the
    // backing storage — the bytes we are about to read are exactly those that
    // the ZeroizeOnDrop derive wrote.
    //
    // SAFETY: `wrapped` has not been dropped; we do not touch its inner value
    // again after this call (only via raw_ptr for post-drop reads); the inner
    // value is a valid `Ed448SigningKey`.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Post-drop: every byte of the (now zeroed) `seed` field must be zero.
    // `ptr::read_volatile` defeats any dead-store-elimination the compiler might
    // apply to the zeroise loop emitted by the `ZeroizeOnDrop` derive.
    for i in 0..57 {
        // SAFETY: raw_ptr still points into live ManuallyDrop storage (ManuallyDrop
        // does not release it); raw_ptr.add(i) is in-bounds for (0..57) against
        // the 57-byte `seed` field; read_volatile defeats DSE.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "REM-30/MEM-16 violated: trelis Ed448SigningKey ZeroizeOnDrop derive did \
             NOT zeroise the `seed` field at offset {i}. \
             A defective upstream ZeroizeOnDrop on Ed448SigningKey would cause 57 bytes \
             of Ed448 seed material to linger in memory after every key drop. \
             Check trelis-primitives Ed448SigningKey derive (pinned SHA 5374dff)."
        );
    }
}

// ===========================================================================
// Test 6 — trelis MlDsa65SigningKey own bytes field zeroises on drop (REM-30/MEM-16)
//
// WHAT IS TESTED:
//   This test drops a REAL `MlDsa65SigningKey` instance and observes that trelis's
//   OWN `ZeroizeOnDrop` derive zeroed the `bytes: [u8; 4032]` field.  The MEM-16
//   gap: if the derive were defective, 4032 bytes of ML-DSA-65 secret key material
//   would linger in memory after every signing-key drop.
//
// TECHNIQUE:
//   Same ManuallyDrop + ptr::read_volatile methodology as Test 5.
//   `MlDsa65SigningKey` is `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` with field
//   `bytes: [u8; 4032]` exposed via `pub fn as_bytes(&self) -> &[u8; 4032]`.
//
// NOTE: 4032 bytes on the stack is within normal pthread limits (well under
//   the default 2–8 MiB).  This matches the existing Test 2 (which uses a local
//   [u8; 4032] copy) — the only difference is that here the 4032-byte storage IS
//   the live signing-key struct field, not a separately-copied array.
// ===========================================================================

#[test]
fn test_trelis_mldsa65_signing_key_own_bytes_zeroises_on_drop() {
    use trelis_primitives::MlDsa65SigningKey;

    // Generate a real MlDsa65SigningKey.  Its internal `bytes: [u8; 4032]` field
    // holds the ML-DSA-65 secret key material.
    let sk = MlDsa65SigningKey::generate()
        .expect("MlDsa65SigningKey::generate must succeed in test environment");

    let mut wrapped: ManuallyDrop<MlDsa65SigningKey> = ManuallyDrop::new(sk);

    // Capture a pointer into the LIVE `bytes` field via `as_bytes()`.
    // `(*wrapped)` is a safe ManuallyDrop deref; the returned &[u8; 4032]
    // references the inner struct's field; the *const u8 is valid for the lifetime
    // of the ManuallyDrop storage.
    let raw_ptr: *const u8 = (*wrapped).as_bytes().as_ptr();

    // Pre-drop sanity.
    let any_nonzero = (0..4032).any(|i| {
        // SAFETY: raw_ptr points into the live ManuallyDrop-owned stack storage;
        // offset i is bounded by (0..4032).
        unsafe { ptr::read_volatile(raw_ptr.add(i)) != 0 }
    });
    assert!(
        any_nonzero,
        "REM-30/MEM-16: freshly-generated MlDsa65SigningKey is all-zero — \
         test is vacuous; investigate MlDsa65SigningKey::generate"
    );

    // Fire trelis's ZeroizeOnDrop derive on the LIVE key.
    //
    // SAFETY: `wrapped` has not been dropped; we do not touch its inner value
    // again after this call (only via raw_ptr for post-drop reads); the inner
    // value is a valid `MlDsa65SigningKey`.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Post-drop: every byte of the 4032-byte `bytes` field must be zero.
    for i in 0..4032 {
        // SAFETY: raw_ptr still points into live ManuallyDrop storage; raw_ptr.add(i)
        // is in-bounds for (0..4032); read_volatile defeats DSE.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "REM-30/MEM-16 violated: trelis MlDsa65SigningKey ZeroizeOnDrop derive did \
             NOT zeroise the `bytes` field at offset {i}. \
             A defective upstream ZeroizeOnDrop on MlDsa65SigningKey would cause 4032 bytes \
             of ML-DSA-65 secret key material to linger in memory after every key drop. \
             Check trelis-primitives MlDsa65SigningKey derive (pinned SHA 5374dff)."
        );
    }
}

// ===========================================================================
// Test 7 — trelis HybridKemKeypair drops without UB; derived secret zeroise
//           observed on reachable buffer (REM-30/MEM-16 best-effort)
//
// LIMITATION — why the direct ManuallyDrop observation used in Tests 5+6 does
// not apply here:
//   `HybridKemKeypair` (trelis-hybrid/src/kem.rs, pinned SHA 5374dff) is
//   `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` with fields:
//     `x448_secret: X448Secret`      (nested secret type, NOT a flat byte array)
//     `sntrup_secret: Sntrup761SecretKey` (nested secret type, NOT a flat byte array)
//   There is NO pub accessor on the keypair that exposes a flat `&[u8; N]` over
//   EITHER nested field.  `to_bytes()` exists but it COPIES the bytes out into a
//   new stack array — it cannot be used to obtain a pointer into the LIVE nested
//   fields for post-drop observation.  The internal `x448_secret.as_bytes()` and
//   `sntrup_secret.as_bytes()` are accessible on the component types, but those
//   types are private fields on `HybridKemKeypair` at the pinned SHA and are not
//   exposed via a pub accessor on the keypair.
//
//   This limitation is the T-42-14 accepted disposition in the threat register.
//   The authoritative check of the nested-field ZeroizeOnDrop derive is AUDIT-01.
//
// WHAT THIS TEST PROVIDES:
//   (a) Drop-without-UB — confirms trelis's ZeroizeOnDrop derive compiles and
//       runs through a complete drop sequence on a real generated keypair without
//       undefined behaviour (miri / ASan would catch violations here).
//   (b) Reachable-secret buffer zeroise — uses `generate_from_seed` + `to_bytes`
//       to obtain a flat copy of the secret key bytes, wraps this copy in
//       `Zeroizing`, and confirms the copy zeroises.  The copy is a distinct
//       buffer from the keypair's internal fields; it validates that the byte
//       content was non-zero and can be zeroised, but does NOT observe the
//       keypair's own x448_secret / sntrup_secret fields being zeroed.
//       This matches the existing Test 1+2 pattern exactly and is explicitly
//       documented as sss-side wrapper validation, not trelis-field validation.
//
// WHY NOT OBSERVE to_bytes() AFTER drop:
//   `to_bytes()` allocates a fresh [u8; 1819] stack array and copies the fields
//   into it BEFORE dropping.  After `ManuallyDrop::drop`, the copy is already
//   separate from the now-zeroed fields.  Reading the copy post-drop tells us
//   nothing about whether the fields were zeroed.  The TEST that matters would
//   need a pointer INTO x448_secret.as_bytes() on the live keypair — that
//   accessor is not pub on HybridKemKeypair at this SHA.
// ===========================================================================

#[test]
fn test_trelis_hybrid_kem_keypair_drop_without_ub_and_reachable_secret_zeroise() {
    use trelis_hybrid::kem::{HybridKemKeypair, SECRET_KEY_SIZE};

    // (a) Drop-without-UB: generate a real HybridKemKeypair and let it drop
    //     naturally.  If trelis's ZeroizeOnDrop derive has UB (e.g. double-free,
    //     stack misalignment in the nested-type drops), ASan / miri catch it here.
    //     This verifies the derive is at least structurally sound.
    {
        let _keypair = HybridKemKeypair::generate()
            .expect("HybridKemKeypair::generate must succeed in test environment");
        // `_keypair` drops at end of this block — fires x448_secret + sntrup_secret
        // ZeroizeOnDrop derives on the nested types.
    }

    // (b) Reachable-secret zeroise: use a deterministic seed so the generated bytes
    //     are reproducible; extract via to_bytes() (a flat copy) and confirm the
    //     copy is non-zero then zeroises.
    //
    // NOTE — LIMITATION: the bytes observed here are a COPY extracted from the
    // keypair BEFORE it dropped; they are NOT the live x448_secret / sntrup_secret
    // fields of the keypair.  This replicates the sss-side Zeroizing-wrapper
    // validation shape (Tests 1+2), NOT the live-field observation shape (Tests 5+6).
    // The authoritative check of HybridKemKeypair's nested-field ZeroizeOnDrop
    // is AUDIT-01 (backlog).  See the test header comment for the full limitation
    // explanation (T-42-14).
    let seed = [0x42u8; 32];
    let keypair = HybridKemKeypair::generate_from_seed(&seed);
    let sk_bytes_copy: [u8; SECRET_KEY_SIZE] = keypair.to_bytes();

    // Pre-zeroise sanity: the deterministic seed must produce non-zero bytes.
    // (A seed of 0x42...42 generates a real X448+sntrup761 keypair; the bytes
    // are definitely not all-zero unless the generator is broken.)
    assert!(
        sk_bytes_copy.iter().any(|&b| b != 0),
        "REM-30/MEM-16: HybridKemKeypair::to_bytes returned all-zero bytes from \
         seed 0x42*32 — test is vacuous; investigate HybridKemKeypair::generate_from_seed"
    );

    // Wrap the copy in ManuallyDrop<Zeroizing<...>> and confirm the Zeroizing
    // wrapper zeroses it.  This validates the sss-side wrapping pattern
    // (see src/crypto/hybrid.rs HybridKeyPair.secret_bytes) can zero this size
    // of buffer.
    let mut wrapped: ManuallyDrop<Zeroizing<[u8; SECRET_KEY_SIZE]>> =
        ManuallyDrop::new(Zeroizing::new(sk_bytes_copy));

    let raw_ptr: *const u8 = wrapped.as_ptr();

    // SAFETY: `wrapped` has not been dropped; we do not touch its inner value
    // again after this call (only via raw_ptr for post-drop reads); the inner
    // value is a valid Zeroizing<[u8; SECRET_KEY_SIZE]>.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    for i in 0..SECRET_KEY_SIZE {
        // SAFETY: raw_ptr points into the stack-held ManuallyDrop storage that
        // is still live; raw_ptr.add(i) is in-bounds for (0..SECRET_KEY_SIZE)
        // against the 1819-byte array; read_volatile defeats DSE.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "REM-30/MEM-16: sss-side Zeroizing<[u8; SECRET_KEY_SIZE]> wrapper over \
             HybridKemKeypair::to_bytes() copy did not zeroise at offset {i}. \
             NOTE: this validates the sss-side wrapper, NOT trelis's internal field \
             ZeroizeOnDrop (see test comment for T-42-14 limitation). \
             AUDIT-01 is the authoritative check for the nested x448_secret/sntrup_secret \
             field zeroise."
        );
    }

    // Let keypair drop here (end of block).  Together with part (a), both a
    // generate() and a generate_from_seed() path are exercised through drop.
    drop(keypair);
}

// ===========================================================================
// Test 4 — FUSE render-cache / per-handle plaintext buffer zeroises on drop (REM-15)
//
// Mirrors the production `PlaintextBuf` (`Zeroizing<Vec<u8>>`) type used by
// `SssFS::render_cache` and `FileHandle::cached_content` after the Phase 41
// Plan 01 changes to `src/fuse/fs.rs`.
//
// The test is type-level proof: it validates that the exact type used by those
// fields (`Zeroizing<Vec<u8>>`) volatile-zeroes its backing bytes.  Live
// render-cache eviction zeroise (the actual mount path) is a deferred
// `/dev/fuse` manual UAT described in
// `.planning/phases/41-fuse-plaintext-in-memory/41-VALIDATION.md`.
//
// Methodology: mirrors Test 3 above (envelope payload) — invoke
// `Zeroize::zeroize` DIRECTLY on the inner `Vec<u8>` while the wrapper is
// still live (not yet dropped, not yet deallocated), then observe bytes
// immediately via `ptr::read_volatile`.  This validates the zeroise step in
// isolation from any heap-dealloc race.  The `Zeroizing<Vec<u8>>` drop chain
// fires the same `Zeroize::zeroize` call on drop, so confirming the explicit
// call confirms the drop behaviour modulo the dealloc race.
//
// The alternative `ManuallyDrop + post-drop read_volatile` approach hits the
// heap-reuse race documented in `src/crypto/hybrid.rs:644-650`: after
// `ManuallyDrop::drop` the allocator reclaims the slot immediately and test
// machinery re-allocates over the zeroed bytes before the observation runs.
// The explicit-zeroize-while-live pattern avoids this race entirely and
// produces a reliable result on all allocators.
//
// Seeded with `0xDE 0xAD 0xBE 0xEF 0xCA 0xFE 0xBA 0xBE` — a recognisable
// pattern that makes any non-zeroise failure obvious in test output.
//
// Coverage: mirrors `src/fuse/fs.rs FileHandle::cached_content` and
// `SssFS::render_cache` (Phase 41 Plan 01 REM-15 sites).
// ===========================================================================

#[test]
#[cfg(feature = "fuse")]
fn test_render_cache_plaintext_buf_zeroises_on_drop() {
    let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let len = data.len();

    // Sanity: the seed pattern must be non-zero so that a zeroisation failure
    // (bytes unchanged) would be distinguishable from a vacuous pass.
    assert!(
        data.iter().any(|&b| b != 0),
        "test seed is all-zero bytes — test is invalid"
    );

    // Wrap in Zeroizing<Vec<u8>> — the exact type used by FileHandle::cached_content
    // and SssFS::render_cache after Phase 41 Plan 01.
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(data);

    // Pre-zeroise sanity: at least one seed byte is non-zero (verified above).
    // This confirms the buffer was populated and prevents a vacuous pass.
    assert!(
        buf.iter().any(|&b| b != 0),
        "buffer before zeroize is all-zero — test is invalid"
    );

    // Capture a raw pointer into the live heap allocation BEFORE calling zeroize.
    // The Vec's backing storage stays at this address while zeroize runs (zeroize
    // operates in place; it does not reallocate).
    let raw_ptr: *const u8 = buf.as_ptr();

    // Invoke Zeroize::zeroize DIRECTLY on the inner Vec<u8> while the wrapper
    // is still live.  This is the same call that the Zeroizing<Vec<u8>> drop
    // chain would invoke on drop (Zeroize for Vec<T> writes zeros to every byte).
    // After this call the Vec is still alive on the test's stack frame; its
    // backing storage is still owned at the same address — no heap-reuse race.
    (*buf).zeroize();

    // Every byte in the (still-live) Vec must now be zero.
    for i in 0..len {
        // SAFETY: `raw_ptr` points into the still-live `buf`'s heap allocation
        // (`buf` is still owned on this stack frame); `raw_ptr.add(i)` is
        // in-bounds for `i in 0..len` because the Vec was built with exactly
        // `len` bytes and zeroize does not reallocate; `read_volatile` defeats
        // any compiler dead-store-elimination on the zeroise loop.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "MEMSAFE-05 violated: FUSE plaintext buffer Zeroizing<Vec<u8>> inner \
             Zeroize::zeroize did not zeroise byte at offset {i}. \
             Production sites `src/fuse/fs.rs FileHandle::cached_content` and \
             `SssFS::render_cache` would leak decrypted secret-file content at \
             eviction / handle-drop time (REM-15 / CON-05-001)."
        );
    }

    // Let RAII handle the final drop; Zeroizing will call zeroize again (a
    // no-op since bytes are already zero) then drop the Vec.
    drop(buf);
}
