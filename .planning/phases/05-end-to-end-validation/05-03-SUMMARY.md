---
phase: 05-end-to-end-validation
plan: "03"
subsystem: e2e-tests
tags: [tests, e2e, migration, hybrid, multi-user, TEST-04]
dependency_graph:
  requires:
    - 04-01  # sss users add-hybrid-key subcommand
    - 04-02  # sss migrate command (migrate_project_config)
    - 02-03  # HybridCryptoSuite implementation
    - 05-01  # e2e test infrastructure repaired
  provides:
    - TEST-04 multi-user migration end-to-end coverage
    - MIGRATE-02 byte-identical sealed file verification at e2e level
  affects:
    - tests/migrate_e2e.rs
    - src/commands/migrate.rs
    - src/project.rs
tech_stack:
  added: []
  patterns:
    - "UserEnv per-user isolated HOME pattern for multi-user e2e tests"
    - "Hybrid pubkey capture from sss keys generate --suite hybrid stdout"
    - "Byte-identical pre/post migration ciphertext assertion"
key_files:
  created:
    - tests/migrate_e2e.rs
  modified:
    - src/commands/migrate.rs
    - src/project.rs
decisions:
  - "public field in UserConfig stays as classic identity anchor after migration — not replaced by hybrid key"
  - "validate() uses PublicKey::from_base64 (classic-only) for public field, not decode_base64_for_suite"
  - "hybrid_pubkey captured from stdout of keys generate --suite hybrid, not from keys show"
metrics:
  duration: ~25min
  completed: "2026-04-26T12:27:58Z"
  tasks_completed: 1
  files_modified: 3
---

# Phase 05 Plan 03: TEST-04 Multi-User Migration E2E Test Summary

End-to-end migration test driving the real sss binary: 3-user v1 repo migrated to v2 via sss migrate, then all three users independently render sealed content with byte-identical plaintext (TEST-04, MIGRATE-02).

## Tasks Completed

| Task | Description | Commit | Status |
|------|-------------|--------|--------|
| T-05-03-01 | Write TEST-04 multi-user migration e2e test | da32810 | done |

## What Was Done

**tests/migrate_e2e.rs (324 lines, > 150 min_lines):** Full e2e test file gated `#![cfg(feature = "hybrid")]`. Defines `UserEnv` struct with isolated per-user `TempDir` HOME directories. Implements `generate_keys()` (classic then hybrid), `classic_pubkey()`, `hybrid_pubkey()` (returns captured stdout parse result). Test `e2e_migrate_three_user_repo_all_users_can_render` drives the complete pipeline for alice, bob, and charlie:

1. Classic + hybrid keygen for all three users (hybrid pubkey captured from stdout)
2. `sss init alice` — creates v1.0 `.sss.toml`
3. `sss users add bob/charlie` — registers classic users
4. `sss users add-hybrid-key alice/bob/charlie` — registers hybrid keys
5. `sss seal -x secret.txt` — seals known plaintext
6. Records `sealed_bytes_before` for MIGRATE-02 comparison
7. `sss migrate` — migrates v1 repo to v2
8. Asserts `.sss.toml` version = "2.0"
9. Asserts `sealed_bytes_after == sealed_bytes_before` (byte-identical, MIGRATE-02)
10. Each user independently renders and asserts `"db_pass=migration_test_secret"`

**src/project.rs — Rule 1 bug fix in `validate()`:** The `validate()` method was calling `PublicKey::decode_base64_for_suite(&user_config.public, suite)` for all users. For a v2 (hybrid) suite, this dispatch called the downgrade-guard code path in `decode_base64_for_suite`, which rejects any 32-byte (classic) key as a "possible downgrade attempt" in a v2 config. But `public` is the classic identity anchor that never changes during migration — it is the field that `find_user_by_public_key` uses to identify users, and it must stay as the classic key. Fixed by using `PublicKey::from_base64` (classic-only, always 32 bytes) for the `public` field validation.

**src/commands/migrate.rs — migrate_project_config step 4 comment clarified:** Reverted an earlier incorrect attempt to promote `public` to the hybrid key during migration. The correct invariant: `public` = classic identity anchor (unchanged), `sealed_key` = hybrid-wrapped K (updated), `version` = "2.0" (updated).

## Verification Results

```
cargo test --features hybrid --test migrate_e2e
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

```
cargo test --features hybrid 2>&1 | grep "^test result"
```
All test suites pass (zero failures introduced). One pre-existing failure `marker_inference::edge_cases::test_escaped_close_brace` confirmed to exist at base commit 4d16f55 before any Phase 05 work — out of scope.

```
cargo test --test migrate_e2e (no feature)
test result: ok. 0 passed; 0 failed  (cfg gate correctly excludes the test)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] validate() rejected classic-length public keys in v2 configs**

- **Found during:** Task T-05-03-01 (first test run)
- **Issue:** `ProjectConfig::validate()` in `src/project.rs` called `decode_base64_for_suite` with `Suite::Hybrid` on the `public` field. `decode_base64_for_suite` contains a downgrade-guard: it rejects 32-byte (classic-length) keys in v2 configs with "possible downgrade attempt". After `sss migrate`, the `public` field still holds the classic key (the identity anchor), so `validate()` fired on every post-migration `render` call.
- **Fix:** Changed `validate()` to use `PublicKey::from_base64` (classic-only decode, always expects 32 bytes) for the `public` field. The `suite` variable is still resolved via `self.suite()` to validate the version string — only the public-key decode dispatch was changed.
- **Files modified:** `src/project.rs`
- **Commit:** da32810

**2. [Rule 1 - Bug] Initial incorrect fix attempt (reverted) — migrate_project_config promoted public to hybrid key**

- **Found during:** First deviation fix attempt
- **Issue:** An initial approach updated `user.public = hybrid_pk` during migration. This broke `find_user_by_public_key` (which matches classic public keys) so render gave "None of your keypairs are authorized".
- **Fix:** Reverted the migrate change; fixed validate() instead (see deviation 1). `public` stays as the classic identity anchor throughout.
- **Files modified:** `src/commands/migrate.rs` (reverted to original logic)
- **Commit:** da32810

## Known Stubs

None. All assertions fully wired. All three users render post-migration content.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes beyond what the plan's threat model covers. Tests use isolated TempDir instances.

## Self-Check

- [x] tests/migrate_e2e.rs exists: 324 lines (> 150 min_lines)
- [x] `#![cfg(feature = "hybrid")]` at line 1
- [x] `e2e_migrate_three_user_repo_all_users_can_render` function present
- [x] Commit da32810 exists
- [x] `cargo test --features hybrid --test migrate_e2e` → 1 passed, 0 failed
- [x] `cargo test --test migrate_e2e` (no feature) → 0 tests (cfg gate)
- [x] No PLACEHOLDER, todo!, unimplemented! in migrate_e2e.rs
- [x] src/project.rs validate() fix present and committed
- [x] src/commands/migrate.rs: public stays as classic anchor

## Self-Check: PASSED
