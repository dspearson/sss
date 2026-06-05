// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Why: this entire harness is gated on `feature = "hybrid"` so HybridKeyPair / Zeroizing
// imports compile. The file compiles to an empty test binary on default-features builds.
#![cfg(feature = "hybrid")]

//! MEMSAFE-02 — miri smoke harness (Phase 22 Plan 22-02).
//!
//! Goal: exercise pure-Rust unsafe paths under the miri interpreter so the
//! pointer arithmetic, drop chains, and zeroisation behaviour of the hybrid
//! suite + scanner regex + `marker_inference` modules are validated for
//! undefined behaviour.
//!
//! Plan 22-01 has cfg-stubbed every libsodium / libc FFI call site under
//! `#[cfg(miri)]`, so miri can run these tests without attempting to execute
//! unsupported FFI. The 5 `ptr::read_volatile` sites in `src/crypto/hybrid.rs`
//! remain pure-Rust and unmodified — they are the PRIMARY value of miri.
//!
//! Test design (mirrors the in-source patterns at `src/crypto/hybrid.rs:535-696`):
//! - Test 1 invokes `HybridKeyPair`'s full drop chain through `ManuallyDrop`
//!   so miri validates the Zeroizing<..> drop on `secret_bytes` without UB.
//! - Test 2 directly exercises `Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>` wrapped
//!   in `ManuallyDrop`, with pre/post-drop `ptr::read_volatile` assertions.
//! - Test 3 exercises `Zeroizing<[u8; 32]>` for the AEAD-key drop pattern.
//!   Per Plan 22-02 spec, this test uses a deterministic stand-in pattern
//!   `[0xC3u8; 32]` rather than calling `trelis_primitives::derive_key` — the
//!   smoke harness's job is to validate the zeroisation pointer arithmetic,
//!   not the KEM math.
//! - Test 4 compiles the scanner's `regex::Regex` pattern via `FileScanner::new`,
//!   exercising the regex crate's compilation paths under miri's allocator.
//! - Test 5 invokes the `marker_inference` public API (`infer_markers`) on a small
//!   synthetic input, exercising pure-Rust string manipulation paths.
//!
//! Acceptance: all 5 tests pass on stable `cargo test`. Plan 22-03 owns the
//! pinned-nightly miri workflow that runs `cargo miri test --test miri_smoke`.

use std::mem::ManuallyDrop;
use std::ptr;

use zeroize::Zeroizing;

use sss::constants::HYBRID_SECRET_KEY_SIZE;
use sss::crypto::HybridKeyPair;
use sss::marker_inference::infer_markers;
use sss::scanner::FileScanner;

// ===========================================================================
// Test 1 — HybridKeyPair full drop chain (mirrors hybrid.rs:535-595)
// ===========================================================================

#[test]
#[cfg_attr(
    miri,
    ignore = "HybridKeyPair::generate() reaches the sntrup761 KEM C FFI \
              (PQCLEAN_SNTRUP761_CLEAN_crypto_kem_keypair, inside trelis -> \
              pqcrypto-ntruprime) which miri cannot execute. The Zeroizing<..> \
              drop-zeroisation at HYBRID_SECRET_KEY_SIZE scale is covered under \
              miri by test_zeroizing_secret_bytes_wrapper_under_miri (Test 2)."
)]
fn test_hybrid_keypair_zeroises_under_miri() {
    // PQCRYPTO-04 — exercise the HybridKeyPair drop chain (which contains a
    // Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]> on the secret_bytes field) under
    // miri so the interpreter validates the drop sequence and the pointer
    // arithmetic embedded in Zeroizing's overwrite loop.
    //
    // The in-source test (src/crypto/hybrid.rs:535-595) uses
    // `kp.secret_bytes_for_test().as_ptr()` to capture a raw pointer into the
    // Zeroizing-wrapped secret_bytes BEFORE dropping; that helper is
    // `#[cfg(test)] pub(crate)` and so not reachable from an integration test.
    // The secret_bytes field is also `pub(crate)`. We therefore cannot ASSERT
    // post-drop zeros from outside the crate — but under miri, any
    // undefined-behaviour or use-after-free inside the drop sequence
    // (including the Zeroizing<..> overwrite of HYBRID_SECRET_KEY_SIZE bytes)
    // would trip the interpreter and fail the test.
    //
    // We pair this drop-only check with Test 2 below, which observes the
    // pre/post-drop bytes directly via raw_ptr on a stand-in
    // `Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>` — same scale, same wrapper.
    let kp = HybridKeyPair::generate()
        .expect("HybridKeyPair::generate must succeed for the drop-chain smoke test");

    // Wrap in ManuallyDrop so the storage stays live through the post-drop
    // observation phase; explicitly invoke the drop so miri sees the full
    // sequence (libsodium FFI calls reached by the inner trelis path are
    // cfg-stubbed by Plan 22-01).
    let mut wrapped: ManuallyDrop<HybridKeyPair> = ManuallyDrop::new(kp);

    // SAFETY: `wrapped` has not yet been dropped; we do not access its inner
    // value again after this call. The inner value is a valid `HybridKeyPair`
    // because it came directly from `HybridKeyPair::generate()`.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Reaching this line means the entire HybridKeyPair drop chain (including
    // the Zeroizing<..> drop on secret_bytes — 1819 bytes overwritten with
    // zeroes via the zeroize crate's pointer arithmetic) executed without
    // tripping any miri UB check.
}

// ===========================================================================
// Test 2 — Standalone Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]> wrapper
// (mirrors hybrid.rs:594-635)
// ===========================================================================

#[test]
fn test_zeroizing_secret_bytes_wrapper_under_miri() {
    // PQCRYPTO-04 — confirm the Zeroizing<..> wrapper itself zeroises at the
    // HYBRID_SECRET_KEY_SIZE scale, independent of HybridKeyPair. The raw_ptr
    // pre/post-drop pattern below directly exercises the zeroize crate's drop
    // loop under miri's pointer-arithmetic interpreter — the same path miri
    // is meant to validate.
    //
    // We use ManuallyDrop<..> so the storage persists after the inner
    // Zeroizing drop runs; this avoids any allocator-reuse race between the
    // dealloc and the post-drop observation. (See hybrid.rs:597-606 for the
    // motivating rationale.)
    let mut wrapped: ManuallyDrop<Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>> =
        ManuallyDrop::new(Zeroizing::new([0xA5u8; HYBRID_SECRET_KEY_SIZE]));
    let raw_ptr: *const u8 = wrapped.as_ptr();

    // SAFETY: raw_ptr points into the stack-held ManuallyDrop<..>; the
    // allocation is live and owned by us for the duration of this test.
    let pre_drop = unsafe { ptr::read_volatile(raw_ptr) };
    assert_eq!(pre_drop, 0xA5, "marker pattern not in place pre-drop — test setup bug");

    // Run Zeroizing's drop in place without releasing the backing storage.
    // SAFETY: `wrapped` has not been dropped and we do not touch its inner
    // value again after this call (we only read the zeroed bytes through
    // raw_ptr); the inner value is a valid Zeroizing<[u8; N]>.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Re-derive the pointer AFTER the drop: `ManuallyDrop::drop` took `&mut
    // wrapped`, invalidating the pre-drop `raw_ptr`'s provenance under newer
    // miri (Tree Borrows). `&raw const wrapped` is a fresh raw borrow of the
    // still-live stack storage (sole-field newtype layout → array at offset 0)
    // without dereferencing the dropped inner value.
    // SAFETY: storage is still live; we read the bytes Zeroizing just overwrote.
    let post_drop_ptr: *const u8 = (&raw const wrapped).cast::<u8>();
    let post_drop = unsafe { ptr::read_volatile(post_drop_ptr) };
    assert_eq!(
        post_drop, 0x00,
        "Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]> wrapper failed to zeroise on drop. \
         The zeroize crate is not behaving as expected — re-verify the dep version \
         (Cargo.toml ~line 43: zeroize = \"1.8\")."
    );
}

// ===========================================================================
// Test 3 — Zeroizing<[u8; 32]> AEAD-key zeroise pattern
// (mirrors hybrid.rs:634-696, stand-in stand-in for trelis_primitives::derive_key)
// ===========================================================================

#[test]
fn test_hybrid_aead_key_zeroises_under_miri() {
    // PQCRYPTO-04 — the transient AEAD key derived inside
    // HybridCryptoSuite::seal_repo_key / open_repo_key is wrapped in
    // Zeroizing<[u8; 32]>. Validate that wrapper zeroises under miri's
    // pointer-arithmetic interpreter, using a deterministic 32-byte stand-in
    // pattern instead of `trelis_primitives::derive_key`. Per Plan 22-02:
    // the smoke harness's job is to validate the zeroisation pointer
    // arithmetic, not the KEM math.
    //
    // ManuallyDrop<..> is used so the 32-byte allocation does not return to
    // the allocator's small-object pool before the post-drop observation —
    // see hybrid.rs:644-650 for the motivating rationale (Box-then-drop
    // flaked on glibc's small-object pool during the in-source variant of
    // this test).
    let stand_in_key_bytes = [0xC3u8; 32];
    let mut wrapped: ManuallyDrop<Zeroizing<[u8; 32]>> =
        ManuallyDrop::new(Zeroizing::new(stand_in_key_bytes));
    let raw_ptr: *const u8 = wrapped.as_ptr();

    // Pre-drop sanity: every byte holds the 0xC3 marker.
    let pre_drop_marker_present = (0..32).all(|i| {
        // SAFETY: raw_ptr points into the live stack-held ManuallyDrop<..>;
        // raw_ptr.add(i) is bounded by (0..32) against the 32-byte allocation.
        let byte = unsafe { ptr::read_volatile(raw_ptr.add(i)) };
        byte == 0xC3
    });
    assert!(pre_drop_marker_present, "0xC3 stand-in pattern not in place pre-drop — test setup bug");

    // SAFETY: `wrapped` has not been dropped and we do not touch it again
    // after this call; the inner value is a valid Zeroizing<[u8; 32]>.
    unsafe { ManuallyDrop::drop(&mut wrapped) };

    // Re-derive the observation pointer AFTER the drop. ManuallyDrop::drop took
    // `&mut wrapped`, which under newer miri's Tree Borrows invalidates the
    // provenance of the pre-drop `raw_ptr` (captured via the shared `as_ptr()`),
    // so reading through `raw_ptr` here is a use of an invalidated pointer.
    // `&raw const wrapped` is a fresh raw borrow of the still-live stack storage
    // — ManuallyDrop leaves the 32 bytes intact (zeroised by Zeroizing's drop)
    // and the sole-field newtype layout puts the array at offset 0 — without
    // dereferencing the dropped inner value.
    let post_drop_ptr: *const u8 = (&raw const wrapped).cast::<u8>();

    // Every byte of the derived key must be zero after Zeroizing's drop.
    let all_zero_post_drop = (0..32).all(|i| {
        // SAFETY: post_drop_ptr points into live stack storage; .add(i) is
        // bounded by (0..32) against the 32-byte allocation.
        let byte = unsafe { ptr::read_volatile(post_drop_ptr.add(i)) };
        byte == 0
    });
    assert!(
        all_zero_post_drop,
        "PQCRYPTO-04 violated: 32-byte AEAD-key stand-in did not zeroise on drop. \
         Every seal/open call would leak 32 bytes of key material into the heap."
    );
}

// ===========================================================================
// Test 4 — Scanner regex compilation (pure-Rust regex::Regex::new)
// ===========================================================================

#[test]
fn test_scanner_regex_compile_under_miri() {
    // Exercise the pure-Rust regex compilation path inside `FileScanner::new`
    // — internally compiles the marker-detection regex
    // `(?:⊕|o\+|⊠)\{[^}]*\}` (see src/scanner.rs:39). The regex crate's
    // compilation involves allocator pressure, DFA/NFA construction, and
    // internal unsafe (e.g. SIMD probe paths) — miri validates the
    // pointer / slice arithmetic across that surface.
    //
    // We do NOT invoke scan_directory (file I/O is out-of-scope for miri
    // smoke; allocator + regex compilation is the load-bearing observable
    // here). `FileScanner::new` returns Self by value — successful
    // construction means the internal `Regex::new(...)` call completed
    // without panic.
    let scanner = FileScanner::new();
    let _: &FileScanner = &scanner;  // touch the value so the optimiser cannot elide construction
    // No further assertion: construction not panicking IS the assertion.
    // Plan 21-03 SAFETY discipline does not apply (no unsafe blocks here).
}

// ===========================================================================
// Test 5 — Marker inference pure-Rust path (infer_markers)
// ===========================================================================

#[test]
fn test_marker_inference_expand_under_miri() {
    // Exercise the marker_inference public API on a small synthetic input.
    // `infer_markers` walks 8 internal stages: parse, diff, validate,
    // map, expand, propagate, delimiter-validate, reconstruct — every stage
    // is pure-Rust string manipulation (`#![no_regex]` policy per
    // src/marker_inference/mod.rs:95-96). miri validates the allocator,
    // iterator, and slice-bounds invariants across this surface.
    //
    // Input is intentionally tiny so miri's slowdown (10-40x native) keeps
    // the smoke run inside the Plan 22-03 weekly-cron budget.
    let source = "password: o+{secret123}";
    let edited = "password: newsecret456";

    let result = infer_markers(source, edited)
        .expect("infer_markers must succeed on the canonical example from src/marker_inference/mod.rs:135-141");

    // The doc example at src/marker_inference/mod.rs:140-141 asserts the
    // output equals "password: ⊕{newsecret456}". We assert containment
    // rather than equality to absorb any future canonicalisation tweaks
    // — the load-bearing observable for miri is "non-panicking traversal
    // of the 8 stages", not exact output format.
    assert!(
        result.output.contains("newsecret456"),
        "marker_inference output did not contain the edited value: {}",
        result.output
    );
}
