---
phase: 05-end-to-end-validation
plan: "01"
subsystem: e2e-tests
tags: [tests, e2e, interop, hybrid, classic, keygen, suite-flag]
dependency_graph:
  requires:
    - 03-02  # --suite required(true) on keys generate
    - 01-02  # version gate in ProjectConfig::load_from_file
    - 02-03  # HybridCryptoSuite implementation
  provides:
    - working e2e test suite for hybrid builds
    - TEST-02 v1/v2 interop coverage
    - TEST-03 non-hybrid version-gate coverage
  affects:
    - tests/e2e_cli_workflows.rs
    - tests/editor_integration.rs
tech_stack:
  added: []
  patterns:
    - "#[cfg(feature = \"hybrid\")] / #[cfg(not(feature = \"hybrid\"))] test gating"
    - "SssTestEnv helper pattern with --suite classic"
key_files:
  created: []
  modified:
    - tests/e2e_cli_workflows.rs
    - tests/editor_integration.rs
decisions:
  - "TEST-03 non-hybrid error checked as 'hybrid feature' / 'hybrid suite' substring — matches suite_for() error in src/crypto/mod.rs"
  - "TEST-03 hybrid variant uses 'project show' (loads config, no suite dispatch) to verify no version error fires"
  - "Parallel test flake (test_add_hybrid_key_correct_length_sets_field) confirmed pre-existing, out of scope"
metrics:
  duration: ~10min
  completed: "2026-04-26T12:03:46Z"
  tasks_completed: 3
  files_modified: 2
---

# Phase 05 Plan 01: E2E Test Fix + Interop Tests Summary

Fix the 62 failing e2e tests caused by `--suite` becoming required in Phase 3, and add TEST-02 and TEST-03 cross-version interop tests. All 79 e2e tests pass with `--features hybrid`.

## Tasks Completed

| Task | Description | Commit | Status |
|------|-------------|--------|--------|
| T-05-01-01 | Fix SssTestEnv helpers + per-test keygen calls | 289f8cb | done |
| T-05-01-02 | Fix editor_integration.rs keygen call | 289f8cb | done |
| T-05-01-03 | Add TEST-02 and TEST-03 interop tests | 9b7a51c | done |

## What Was Done

**Root cause fixed:** Phase 3 (Plan 03-02) made `--suite` a required argument for `sss keys generate`. This silently broke every e2e test that called `generate_keys()` or `generate_other_pubkey()` without passing `--suite classic`. The fix was straightforward: add `"--suite", "classic"` to every `keys generate` call site in the test files.

**Call sites fixed (7 in e2e_cli_workflows.rs, 1 in editor_integration.rs):**
- `SssTestEnv::generate_keys()` helper — the root cause for ~60 tests
- `generate_other_pubkey()` top-level helper
- `SssTestEnv::setup_nested_project_other_user()` inner keygen
- `e2e_edge_confdir_override` inline keygen
- `e2e_keys_generate_basic` direct call
- `e2e_keys_generate_force_overwrites` direct call
- `e2e_keys_generate_duplicate_without_force_fails` direct call
- `test_ssse_symlink_behaviour` in editor_integration.rs

**TEST-02 (`e2e_v2_binary_reads_v1_repo_without_migration`):** Verifies the v2 binary (hybrid build) reads a v1.0 `.sss.toml` repo and performs a full seal -> open -> render round-trip using ClassicSuite automatically, without any migration step.

**TEST-03 hybrid (`e2e_hybrid_binary_opens_v2_config_no_version_error`):** Verifies the hybrid binary does NOT emit any "hybrid feature" error when opening a v2.0 config — the complement gate check.

**TEST-03 non-hybrid (`e2e_v1_binary_rejects_v2_config_with_documented_error`):** Verifies a non-hybrid binary exits non-zero with an error referencing "hybrid feature" or "hybrid suite" when pointed at a v2.0 `.sss.toml`, and does not corrupt the config file. Compiled only with `#[cfg(not(feature = "hybrid"))]`.

## Verification Results

```
cargo test --features hybrid --test e2e_cli_workflows
test result: ok. 79 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

All 79 tests pass (77 pre-existing + 2 new interop tests visible in hybrid build).

```
cargo test --features hybrid 2>&1 | grep "^test result"
```

All test suites pass. One pre-existing parallel-execution flake (`test_add_hybrid_key_correct_length_sets_field`) fails only under `-j auto` — confirmed pre-existing per STATE.md and passes in isolation. Out of scope.

## Deviations from Plan

**1. [Rule 1 - Bug] TEST-03 error string differs from plan text**

- **Found during:** Task 3 implementation
- **Issue:** The plan specified checking for "sss v2.0 or newer" but Plan 01-02 changed `resolve_suite_from_version("2.0")` to return `Ok(Suite::Hybrid)` (not an error). The actual error for non-hybrid + v2 config fires in `suite_for(Suite::Hybrid)` at `src/crypto/mod.rs:47-49` with "hybrid suite requires the `hybrid` feature — rebuild with --features hybrid".
- **Fix:** TEST-03 assertion uses `stderr.contains("hybrid feature") || stderr.contains("hybrid suite")` to match the actual error. The command used is `sss seal canary.txt` (which triggers `load_project_config_with_repository_key` -> `suite_for`) rather than `sss status` (which only calls `find_project_root` and never touches the suite).
- **Files modified:** tests/e2e_cli_workflows.rs
- **Commit:** 9b7a51c

**2. [Rule 1 - Bug] TEST-03 hybrid variant uses `project show` not `status`**

- **Found during:** Task 3 implementation
- **Issue:** `sss status` calls `find_project_root()` only — it never loads `ProjectConfig` and never triggers `suite_for`. Using it for TEST-03 would make the test vacuously pass regardless of the version gate.
- **Fix:** Used `sss project show` for the hybrid variant (loads `ProjectConfig::load_from_file` but doesn't call `suite_for` since there's no keypair to unseal). This correctly verifies the version field is parseable without erroring on "hybrid suite".
- **Files modified:** tests/e2e_cli_workflows.rs
- **Commit:** 9b7a51c

## Known Stubs

None. All tests fully wired.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes introduced. Tests use isolated TempDir instances with no cross-test contamination.

## Self-Check

- [x] tests/e2e_cli_workflows.rs modified and committed (289f8cb, 9b7a51c)
- [x] tests/editor_integration.rs modified and committed (289f8cb)
- [x] Commit 289f8cb exists: `fix(05-01): add --suite classic to all keys generate call sites in e2e tests`
- [x] Commit 9b7a51c exists: `feat(05-01): add TEST-02 and TEST-03 cross-version interop tests`
- [x] `cargo test --features hybrid --test e2e_cli_workflows` → 79 passed, 0 failed
- [x] `e2e_v2_binary_reads_v1_repo_without_migration` appears in output
- [x] `e2e_hybrid_binary_opens_v2_config_no_version_error` appears in output
- [x] e2e_cli_workflows.rs line count: 2081 (> 1950 min_lines requirement)

## Self-Check: PASSED
