---
phase: 04-migration-command
plan: 02
subsystem: crypto-migration
tags: [hybrid, migrate, sss-migrate, classic-to-hybrid, key-wrap, dry-run]

dependency_graph:
  requires:
    - 04-01: hybrid_public field in UserConfig + ClassicSuite v1 sealed_key format
    - 02-03: HybridCryptoSuite.seal_repo_key / open_repo_key implementation
  provides:
    - src/commands/migrate.rs: migrate_project_config pure function + handle_migrate CLI handler
    - sss migrate subcommand with --dry-run flag
    - MIGRATE-01: K re-sealed for every user under HybridCryptoSuite; version bumped to 2.0
    - MIGRATE-02: only .sss.toml written; in-file AEAD ciphertexts untouched
    - MIGRATE-03: early error with user list + remediation if any hybrid_public is missing
    - MIGRATE-04: --dry-run triggers validation, prints plan, exits without writing
  affects:
    - Phase 5 (validation): TEST-04 end-to-end migrate test can now be executed
    - Phase 6 (docs): sss migrate is the primary user-facing migration command

tech_stack:
  added: []
  patterns:
    - Pure core function (migrate_project_config) extracted from CLI handler for unit-testability without keystore
    - All-or-nothing in-memory mutation: re-seals computed before any config mutation; single save_to_file call
    - make_config_with_hybrid test helper accepts &RepositoryKey parameter (not internally generated) so tests assert byte-identical K recovery
    - HybridPublicKey::from_bytes(&[u8]) -> Result<Self> for length-checked construction

key-files:
  created:
    - src/commands/migrate.rs
  modified:
    - src/commands/mod.rs
    - src/main.rs

key-decisions:
  - "migrate_project_config is a pure function (no keystore, no disk I/O) so all five MIGRATE-01..04 invariants are testable as unit tests without a full CLI setup"
  - "HybridPublicKey::from_bytes takes &[u8] -> Result<Self> (not the array form stated in the plan); length check is delegated to from_bytes rather than done at the call site"
  - "ProjectConfig does not implement Clone; dry-run CLI path calls migrate_project_config with dry_run=true directly on the original config rather than cloning it (dry_run=true does not mutate)"
  - "T-04-02-01 mitigated: all re-seals computed in memory first; config mutation and save_to_file only called if all seals succeeded"
  - "T-04-02-05 mitigated: --dry-run path calls migrate_project_config with dry_run=true to trigger the missing-key validation before printing the plan"

patterns-established:
  - "Core logic extracted into pure function separate from CLI handler — enables unit testing without keystore or filesystem setup"

requirements-completed: [MIGRATE-01, MIGRATE-02, MIGRATE-03, MIGRATE-04]

duration: 15min
completed: "2026-04-26"
---

# Phase 4 Plan 02: sss migrate Command Summary

**`sss migrate` re-wraps K for all users under HybridCryptoSuite, bumps .sss.toml version to 2.0, with --dry-run validation and atomic write guarantees.**

## Performance

- **Duration:** 15 minutes
- **Started:** 2026-04-26T10:49:11Z
- **Completed:** 2026-04-26T11:04:47Z
- **Tasks:** 2
- **Files modified:** 3 (1 created, 2 modified)

## Accomplishments

- `migrate_project_config` pure function: validates all users have hybrid_public, re-seals K for every user with HybridCryptoSuite, mutates config in memory on success only, returns new sealed keys list
- `handle_migrate` CLI handler: identifies caller via classic public key, unseals K with ClassicSuite, dispatches to core function, writes atomically via `save_to_file`
- `sss migrate --dry-run` prints per-user plan and runs validation without disk writes
- Five unit tests confirm all MIGRATE-01..04 invariants including byte-identical K recovery

## Task Commits

1. **Task 1: Implement handle_migrate + migrate_project_config** — `0d3c776` (feat)
2. **Task 2: Wire sss migrate into mod.rs and main.rs** — `c7d187b` (feat)

## Files Created/Modified

- `src/commands/migrate.rs` — `migrate_project_config` core function + `handle_migrate` CLI handler + five unit tests
- `src/commands/mod.rs` — `pub mod migrate` declaration + `pub use migrate::handle_migrate` re-export + type-check in test
- `src/main.rs` — `handle_migrate` import, `migrate` subcommand definition with `--dry-run` arg, dispatch arm in `main()`, assertion in `test_create_cli_app_has_core_subcommands`

## Decisions Made

- Extracted `migrate_project_config` as a pure function separate from the CLI handler. This allows all five MIGRATE-01..04 invariants to be covered by unit tests without needing a real keystore, disk, or passphrase prompt.
- `HybridPublicKey::from_bytes` takes `&[u8] -> Result<Self>` (length-checked); the plan's interface spec described a `[u8; HYBRID_PUBLIC_KEY_SIZE] -> Self` variant that does not exist. The actual API is strictly better (returns `Result`), so this required no workaround.
- `ProjectConfig` does not implement `Clone`. The plan's dry-run path called `config.clone()` to pass to the validation step. Resolved by calling `migrate_project_config` with `dry_run=true` directly on the original config — since `dry_run=true` is contractually non-mutating, no clone is needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] HybridPublicKey::from_bytes signature mismatch**
- **Found during:** Task 1 compilation
- **Issue:** Plan interface spec listed `from_bytes(bytes: [u8; HYBRID_PUBLIC_KEY_SIZE]) -> Self` (infallible, array parameter). Actual implementation is `from_bytes(bytes: &[u8]) -> Result<Self>` (fallible, slice parameter).
- **Fix:** Used `HybridPublicKey::from_bytes(&raw)?` with `?` propagation instead of the try_into + unwrap pattern from the plan pseudocode.
- **Files modified:** `src/commands/migrate.rs`
- **Committed in:** 0d3c776

**2. [Rule 1 - Bug] ProjectConfig does not implement Clone**
- **Found during:** Task 1 compilation — `config.clone()` in the dry-run path failed to compile
- **Issue:** `ProjectConfig` derives `Debug, Serialize, Deserialize` but not `Clone`. The plan pseudocode used `.clone()` to produce an isolated copy for validation.
- **Fix:** Removed the clone; the dry-run CLI path calls `migrate_project_config(&mut config, &repository_key, true)` directly. Since `dry_run=true` is guaranteed non-mutating by the function contract (and tested as such), no copy is required.
- **Files modified:** `src/commands/migrate.rs`
- **Committed in:** 0d3c776

---

**Total deviations:** 2 auto-fixed (both Rule 1 — plan pseudocode used incorrect API signatures)
**Impact on plan:** Zero scope change. Both fixes corrected the plan's pseudocode to match the actual codebase APIs. Functionality is identical to what was specified.

## Known Stubs

None — all behaviour is fully wired.

## Threat Flags

No new trust boundaries beyond those documented in the plan's threat model. The `migrate_project_config` function operates entirely on in-memory `ProjectConfig` state; the only disk write is the single `save_to_file` call in `handle_migrate` after all re-seals succeed (T-04-02-01 mitigated). T-04-02-05 (--dry-run bypass) is mitigated: the dry-run path calls `migrate_project_config` with `dry_run=true` which still runs the full validation step.

## Issues Encountered

None beyond the two API-signature deviations documented above.

## Next Phase Readiness

- Phase 4 complete: `sss migrate` is fully functional and all MIGRATE-01..04 requirements are met.
- Phase 5 (validation) can now execute TEST-04: end-to-end `sss migrate` on a representative multi-user v1 repo.
- Phase 6 (docs): `docs/SECURITY.md`, `docs/CRYPTOGRAPHY.md`, README, and CHANGELOG need updating with the hybrid migration flow.

## Self-Check

- `src/commands/migrate.rs` created: verified
- `src/commands/mod.rs` updated: verified
- `src/main.rs` updated: verified
- Commit 0d3c776 (Task 1): verified
- Commit c7d187b (Task 2): verified

## Self-Check: PASSED

---
*Phase: 04-migration-command*
*Completed: 2026-04-26*
