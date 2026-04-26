---
phase: 04-migration-command
plan: 01
subsystem: crypto-dispatch
tags: [hybrid, userconfig, suite-dispatch, migration-prep]
dependency_graph:
  requires:
    - 03-01: StoredKeyPair hybrid fields + load_hybrid_keypair
    - 03-02: --suite CLI flag
  provides:
    - hybrid_public field in UserConfig (load-bearing for 04-02 sss migrate)
    - resolve_suite_from_version("2.0") = Ok(Suite::Hybrid) (v2 repos loadable)
    - load_project_config_internal suite-dispatched open_repo_key
    - sss users add-hybrid-key CLI + handler
  affects:
    - 04-02-PLAN.md: sss migrate can now read/write hybrid_public from .sss.toml
tech_stack:
  added: []
  patterns:
    - Option<String> hybrid_public field with serde(default, skip_serializing_if) + cfg_attr(not(hybrid), serde(skip))
    - Password hoisting: acquire once as Option<String>, pass as_deref() to every call site
    - suite_for(suite_enum)? for CryptoSuite dispatch; no hardcoded ClassicSuite in load path
key_files:
  created: []
  modified:
    - src/project.rs
    - src/config.rs
    - src/rotation.rs
    - src/commands/users.rs
    - src/main.rs
    - src/commands/keys.rs
decisions:
  - "resolve_suite_from_version(2.0) now returns Ok(Suite::Hybrid) — old SUITE-04 upgrade-prompt Err intentionally removed; v2 repos are now loadable by this binary"
  - "Password hoisted to single Option<String> in load_project_config_internal; load_keypair_with_password_retry helper removed as dead code"
  - "handle_users_add_hybrid_key gated #[cfg(feature = hybrid)] with a feature-absent stub; length check (1214 bytes) fires before any disk write (T-04-01-01)"
  - "ClassicKeyPair import in commands/keys.rs made #[cfg(feature = hybrid)]-gated to match its only use site"
metrics:
  duration: 18 minutes
  completed: "2026-04-26"
  tasks_completed: 2
  files_modified: 6
---

# Phase 4 Plan 01: Data Model + Suite Gate + add-hybrid-key Summary

Extends the data model and version-dispatch layer as prerequisite infrastructure for `sss migrate` (Plan 04-02).

## One-liner

`UserConfig` gains `hybrid_public: Option<String>`, v2 repos load as `Suite::Hybrid`, and `sss users add-hybrid-key` writes per-user hybrid public keys into `.sss.toml`.

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| Task 1 RED | Failing tests for v2 gate + hybrid_public | 21cb6dd |
| Task 1 GREEN | Add hybrid_public field; fix resolve_suite_from_version | 178f9a7 |
| Task 2 RED | Failing tests for handle_users_add_hybrid_key | c2e71ef |
| Task 2 GREEN | Suite-dispatch in load_project_config_internal + add-hybrid-key | 417892d |

## Changes by File

**src/project.rs**
- `UserConfig` gains `hybrid_public: Option<String>` with `serde(default, skip_serializing_if = "Option::is_none")` and `cfg_attr(not(feature = "hybrid"), serde(skip))`; field initialised to `None` in `ProjectConfig::new` and `add_user`
- `resolve_suite_from_version("2.0")` returns `Ok(Suite::Hybrid)` (was `Err`) — Plan 04-01 gate change
- Removed three tests that asserted the old v2-error behaviour
- Added three new tests: `test_load_from_file_accepts_v2`, `test_project_config_suite_returns_hybrid_for_v2`, `test_userconfig_hybrid_public_roundtrips`

**src/config.rs**
- `load_project_config_internal` refactored: password hoisted to `Option<String>` once; both `ClassicSuite.open_repo_key` call sites replaced with `suite_for(suite_enum)?.open_repo_key(&resolved_keypair)`; on hybrid builds v2 repos load `HybridKeyPair` via `load_hybrid_keypair`
- `load_keypair_with_password_retry` helper removed (now dead code)
- Two tests updated: `test_init_project_config_hybrid_round_trips_and_loads_as_hybrid` (was asserting error; now asserts `Suite::Hybrid`), `test_detect_config_format_accepts_v2_version` (was asserting error; now asserts `ConfigFormat::Empty`)

**src/rotation.rs**
- `updated_user_config` initialiser propagates `hybrid_public: user_config.hybrid_public.clone()` so rotation does not discard the field (Rule 1 auto-fix)

**src/commands/users.rs**
- `handle_users_add_hybrid_key` added (hybrid feature): decodes + length-checks base64, writes `hybrid_public` to user entry in `.sss.toml`
- Feature-absent stub added for non-hybrid builds
- `handle_users` dispatcher extended with `add-hybrid-key` arm; help text updated to mention it

**src/main.rs**
- `add-hybrid-key` subcommand added under `users` with `username` and `hybrid-pubkey` positional args

**src/commands/keys.rs**
- `ClassicKeyPair` import made `#[cfg(feature = "hybrid")]`-gated to match its sole use site (Rule 3 auto-fix)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Missing hybrid_public in UserConfig struct literals**
- **Found during:** Task 1 GREEN — first compile attempt after adding the field
- **Issue:** `ProjectConfig::new`, `add_user`, and `rotation.rs update_project_config` all construct `UserConfig` by name; adding a non-Option field requires updating every constructor
- **Fix:** Added `hybrid_public: None` to all three construction sites; `rotation.rs` uses `user_config.hybrid_public.clone()` to preserve the field through key rotation
- **Files modified:** `src/project.rs`, `src/rotation.rs`
- **Commit:** 178f9a7

**2. [Rule 3 - Blocking] Missing ClassicKeyPair import in commands/keys.rs**
- **Found during:** Task 1 GREEN — compile error blocked project tests from running
- **Issue:** `ClassicKeyPair` used inside `#[cfg(feature = "hybrid")]` block but not imported in any cfg-gated import
- **Fix:** Added `#[cfg(feature = "hybrid")] use crate::crypto::ClassicKeyPair;`
- **Files modified:** `src/commands/keys.rs`
- **Commit:** 178f9a7

**3. [Rule — Pre-existing] Stash pop reverted keys.rs import**
- **Observed:** A git stash pop (used to verify e2e failures were pre-existing) reverted `keys.rs` to a version where `ClassicKeyPair` is `#[cfg(feature = "hybrid")]`-gated (actually cleaner than the inline fix in Task 1)
- **Action:** Accepted the stash-pop version as correct — it compiles and the cfg-gating is semantically accurate

## Known Stubs

None — all new behaviour is fully wired.

## Threat Flags

None beyond what the plan's threat model already covers. The new `hybrid_public` field in `.sss.toml` is the only new trust boundary; it is mitigated by the 1214-byte length check in `handle_users_add_hybrid_key` (T-04-01-01).

## Verification Results

All plan verification criteria passed:

| Check | Result |
|-------|--------|
| `cargo test --features hybrid -p sss project::tests` | 19/19 passed |
| `cargo test --features hybrid -p sss config::tests` | 7/7 passed |
| `cargo test --features hybrid -p sss commands::users::tests` | 4/4 passed |
| `grep "hybrid_public" src/project.rs` | 12 hits (≥ 2 required) |
| `grep '"2.0".*Err' src/project.rs` | 0 hits (required) |
| `grep "suite_for" src/config.rs` | 2 hits (≥ 1 required) |
| `grep "add-hybrid-key" src/main.rs` | 1 hit (≥ 1 required) |
| Old test names absent from config.rs | 0 hits (required) |
| Non-hybrid build project + config tests | All pass |

## Self-Check: PASSED

- SUMMARY.md exists at `.planning/phases/04-migration-command/04-01-SUMMARY.md`
- Commit 21cb6dd (test RED Task 1): verified present
- Commit 178f9a7 (feat GREEN Task 1): verified present
- Commit c2e71ef (test RED Task 2): verified present
- Commit 417892d (feat GREEN Task 2): verified present
