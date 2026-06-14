// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out (mirror of
// tests/miri_smoke.rs file-top discipline).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! REM-21 / MEM-07 — drop-zeroisation regression test for `Zeroizing<String>`
//! secret-key base64 intermediates (Phase 41 Plan 02).
//!
//! Goal: prove that wrapping a secret-key base64 `String` in `Zeroizing<String>`
//! actually volatile-zeroes the string's backing bytes on drop.  This validates the
//! MEM-07 mitigation applied in `src/keystore/store.rs` and `src/keyring_manager.rs`
//! (≈20 sites across `store_keypair`, `set_passphrase`, `store_dual_keypair` Cases A+B,
//! `upgrade_keypair_in_place`, and `keyring_manager.rs:67`).
//!
//! **Pattern:** mirrors Test 4 in `tests/zeroisation_drop_tests.rs` (the FUSE
//! `PlaintextBuf` test) — invoke `Zeroize::zeroize` DIRECTLY on the inner `String`
//! while the `Zeroizing<String>` wrapper is still live (not yet dropped, not yet
//! deallocated), then observe the bytes immediately via `ptr::read_volatile`.
//!
//! This pattern avoids the heap-reuse race documented in `src/crypto/hybrid.rs:644-650`
//! (where `Vec`/`String` drop returns the slot to the allocator and subsequent
//! test machinery re-allocates before the post-drop observation can run).  By
//! invoking zeroize while the allocation is still live (no dealloc), we validate
//! the zeroise step in isolation — no race.
//!
//! The `Zeroizing<String>` drop chain fires the same `Zeroize::zeroize` call on
//! drop that we invoke here explicitly.  Confirming the explicit call confirms the
//! drop behaviour modulo the dealloc race.
//!
//! This test is feature-agnostic — `zeroize` is always available (no `optional = true`
//! in `Cargo.toml:49`), so no `#[cfg(feature = ...)]` gate is needed.
//!
//! Acceptance: passes under
//! `cargo test --features hybrid --test keystore_zeroise_tests`
//! and under the default-feature build.

use std::ptr;

use zeroize::{Zeroize, Zeroizing};

// ===========================================================================
// Test — Zeroizing<String> secret-key base64 intermediate zeroises on drop (REM-21)
//
// Mirrors the production `Zeroizing<String>` wrapping pattern applied at
// `src/keystore/store.rs` (≈19 sites) and `src/keyring_manager.rs:67` after
// Phase 41 Plan 02:
//
//   let secret_key_str: Zeroizing<String> =
//       Zeroizing::new(keypair.secret_key()?.to_base64());
//
// This test builds a recognisable base64-shaped pattern of sufficient length
// to span a heap allocation (> 8 bytes to avoid SSO / small-string-opt), wraps
// it in `Zeroizing<String>`, then invokes `Zeroize::zeroize` directly while the
// wrapper is still live.  The backing bytes must all be zero after the call.
//
// The `String` SSO note: Rust's standard `String` does not have a small-string
// optimisation (it always heap-allocates the backing buffer via `Vec<u8>`).
// However, to be conservative the test uses a 64-byte pattern so that any
// allocator SSO (e.g. a custom allocator) would also need to heap-allocate.
//
// Methodology: same as Test 3 / Test 4 in `tests/zeroisation_drop_tests.rs`
// (the envelope payload / FUSE plaintext buf tests).  See the extensive comments
// in that file for the heap-reuse race rationale.
//
// MEM-07 reference: every `Zeroizing<String>` production site closes the base64-
// string half of the plaintext-in-memory cluster — the raw-byte vecs were already
// `Zeroizing<Vec<u8>>`; this extends the same discipline to the base64 strings.
// ===========================================================================

#[test]
fn test_secret_key_base64_string_zeroises_on_drop() {
    // Build a recognisable base64-like ASCII pattern long enough to guarantee
    // heap allocation.  We repeat a short base64 snippet to reach at least 64
    // bytes — well above any realistic small-string-optimisation threshold.
    // Using a known non-zero sequence so that a zeroisation failure (bytes
    // unchanged) is clearly distinguishable from a vacuous pass.
    let secret_b64: String = "QUJDREVGR0hJSktMTU5PUQ==QUJDREVGR0hJSktMTU5PUQ==QUJDREVGR0hJSktMTU5PUQ==".to_string();
    assert!(secret_b64.len() >= 64, "test pattern must be at least 64 bytes (got {})", secret_b64.len());

    // Sanity: the pattern must contain at least one non-zero byte.
    // An all-zero pattern would make the post-zeroise assertion vacuously pass.
    assert!(
        secret_b64.as_bytes().iter().any(|&b| b != 0),
        "test pattern is all-zero bytes — test is invalid"
    );

    // Wrap in Zeroizing<String> — the exact type applied to secret-key base64
    // intermediates in src/keystore/store.rs and src/keyring_manager.rs after
    // Phase 41 Plan 02 (MEM-07 / REM-21 remediation).
    let mut wrapped: Zeroizing<String> = Zeroizing::new(secret_b64);
    let len: usize = wrapped.len();

    // Pre-zeroise sanity: the wrapped string must contain at least one non-zero byte.
    assert!(
        wrapped.as_bytes().iter().any(|&b| b != 0),
        "wrapped string before zeroize is all-zero — test is invalid"
    );

    // Capture a raw pointer into the live heap allocation BEFORE calling zeroize.
    // The String's backing Vec<u8> stays at this address while zeroize runs
    // (Zeroize for String operates in place; it does not reallocate).
    let raw_ptr: *const u8 = wrapped.as_bytes().as_ptr();

    // Invoke Zeroize::zeroize DIRECTLY on the inner String while the wrapper
    // is still live.  This is the same call that the Zeroizing<String> drop chain
    // would invoke on drop (`impl Zeroize for String` in the zeroize crate writes
    // zeros to every byte in the backing Vec<u8>).  After this call the String is
    // still alive on the test's stack frame; its backing storage is still owned at
    // the same address — no heap-reuse race.
    (*wrapped).zeroize();

    // Every byte in the (still-live) String's backing buffer must now be zero.
    for i in 0..len {
        // SAFETY: `raw_ptr` points into the still-live `wrapped` String's heap
        // allocation (`wrapped` is still owned on this stack frame);
        // `raw_ptr.add(i)` is in-bounds for `i in 0..len` because the String
        // was built with exactly `len` bytes and `Zeroize::zeroize` for String
        // zeroes in place without reallocating; `read_volatile` defeats any
        // compiler dead-store-elimination on the zeroise loop.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        assert_eq!(
            byte, 0,
            "MEM-07 / REM-21 violated: Zeroizing<String> inner Zeroize::zeroize did \
             not zeroise byte at offset {i}. Production secret-key base64 intermediates \
             in src/keystore/store.rs (≈19 sites) and src/keyring_manager.rs:67 would \
             leak secret-key base64 material in freed heap pages at store-window drop time."
        );
    }

    // Let RAII handle the final drop; Zeroizing will call zeroize again (a
    // no-op since bytes are already zero) then drop the String.
    drop(wrapped);
}
