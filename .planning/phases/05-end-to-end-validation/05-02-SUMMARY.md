---
phase: 05-end-to-end-validation
plan: "02"
subsystem: tests
tags:
  - property-testing
  - proptest
  - hybrid
  - TEST-01
  - AEAD
dependency_graph:
  requires:
    - "02-03: HybridCryptoSuite implementation"
    - "src/crypto/classic.rs encrypt_to_base64_deterministic"
    - "src/crypto/suite.rs CryptoSuite trait"
  provides:
    - "TEST-01: byte-identical AEAD invariant locked by property test"
  affects:
    - "tests/cross_suite_property_test.rs"
tech_stack:
  added:
    - "proptest 1.5 (already in dev-dependencies)"
  patterns:
    - "proptest property-based testing with 1000 cases"
    - "#[cfg(feature)] file-level gate for hybrid-only tests"
key_files:
  created:
    - tests/cross_suite_property_test.rs
  modified: []
decisions:
  - "Key = RepositoryKey is a direct type alias so no conversion is needed when passing to encrypt_to_base64_deterministic; k_classic and k_hybrid from open_repo_key are already &Key-compatible"
  - "any::<u8>().prop_map(|_| RepositoryKey::new()) used as key strategy since RepositoryKey has no Arbitrary impl but has a libsodium-backed ::new() constructor"
  - "Plaintext limited to printable ASCII (0x20..=0x7e, up to 512 bytes) for test performance; the invariant is character-set-agnostic so this is not a coverage compromise"
metrics:
  duration: "~10 minutes"
  completed_date: "2026-04-26"
  tasks_completed: 1
  files_created: 1
  files_modified: 0
---

# Phase 05 Plan 02: Cross-Suite Property Test Summary

**One-liner:** proptest property test locking in byte-identical AEAD ciphertext across ClassicSuite and HybridCryptoSuite for 1000 random (K, path, ts, plaintext) cases (TEST-01).

## What Was Built

A new integration test file `tests/cross_suite_property_test.rs` containing the TEST-01 property test. The test:

1. Generates a random `RepositoryKey` K via `RepositoryKey::new()`
2. Seals K for a fresh `ClassicKeyPair`, then unseals it via `ClassicSuite` → `K_classic`
3. Seals K for a fresh `HybridKeyPair`, then unseals it via `HybridCryptoSuite` → `K_hybrid`
4. Asserts `K_classic.to_base64() == K_hybrid.to_base64() == repo_key.to_base64()` (round-trip fidelity)
5. Calls `encrypt_to_base64_deterministic` with both recovered keys and asserts identical ciphertext output

The test runs 1000 cases and is gated `#![cfg(feature = "hybrid")]` at the file level so it is a no-op in default builds.

## Task Commits

| Task | Description | Commit |
|------|-------------|--------|
| T-05-02-01 | Implement byte-identical AEAD property test (TEST-01) | 8d4f905 |

## Verification

- `cargo test --features hybrid --test cross_suite_property_test` → `test result: ok. 1 passed; 0 failed` (49 seconds for 1000 cases)
- `cargo test --test cross_suite_property_test` (no feature) → `running 0 tests` — cfg gate works
- `cargo test --features hybrid` (full suite) → all `test result: ok` lines, 0 failures
- `grep '#!\[cfg(feature' tests/cross_suite_property_test.rs` → `#![cfg(feature = "hybrid")]` at line 16
- `grep 'cases: 1000' tests/cross_suite_property_test.rs` → confirmed at line 61
- `grep 'PLACEHOLDER' tests/cross_suite_property_test.rs` → no output (0 matches)

## Deviations from Plan

None — plan executed exactly as written.

The `.to_key()` placeholder in the plan template was identified before writing the file (as instructed). Reading `src/crypto/classic.rs` line 396 confirmed `pub type Key = RepositoryKey;` — so `RepositoryKey` returned by `open_repo_key` is directly usable as `&Key` with no conversion. The test uses `&k_classic` and `&k_hybrid` directly, matching the actual API.

## Known Stubs

None. All stub-like patterns (strategy functions, proptest macro) are fully wired to live crypto code.

## Threat Flags

None. The test file introduces no new network endpoints, auth paths, file access patterns, or schema changes. All test keypairs and keys are ephemeral.

## Self-Check: PASSED

- `tests/cross_suite_property_test.rs` exists: FOUND
- Commit `8d4f905` exists: FOUND
- `cargo test --features hybrid --test cross_suite_property_test` → ok. 1 passed
- No PLACEHOLDER strings in test file
- cfg gate at file level confirmed
- cases: 1000 confirmed
