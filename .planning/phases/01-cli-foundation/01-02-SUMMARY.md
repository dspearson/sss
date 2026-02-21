---
phase: 01-cli-foundation
plan: 02
subsystem: testing
tags: [rust, cargo, cli, e2e, sss, auth, non-interactive]

# Dependency graph
requires:
  - phase: 01-cli-foundation-01
    provides: "Verified baseline: 71 e2e_cli_workflows tests passing; coverage gaps identified"
provides:
  - "Phase 1 gate PASSED: all 3 roadmap success criteria gaps covered by named automated tests"
  - "e2e_cli_seal_in_place_stdout_empty: asserts stdout=='' for seal --in-place (Criterion 6)"
  - "e2e_cli_render_auth_failure_exits_nonzero: verifies non-zero exit + non-empty stderr when current keypair not authorized (Criterion 3)"
  - "e2e_cli_non_interactive_flag_render: tests --non-interactive CLI flag directly via subprocess (Criterion 7)"
  - "Confirmed CLI interface table for Phase 2 Emacs mode development"
  - "Marker byte reference: sealed ⊠{ = U+22A0 + 0x7B = \\xe2\\x8a\\xa0\\x7b"
affects: [02-emacs-mode]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Direct TOML section removal to test auth failure (avoids interactive rotation confirmation)"
    - "strip_toml_section() helper for TOML section removal without dependency on external crate"
    - "bare_cmd-style Command with no SSS_NONINTERACTIVE env var to test --non-interactive flag"

key-files:
  created:
    - ".planning/phases/01-cli-foundation/01-02-SUMMARY.md"
  modified:
    - "tests/e2e_cli_workflows.rs"

key-decisions:
  - "Auth failure test uses direct .sss.toml manipulation (strip_toml_section) instead of 'users remove' which requires interactive rotation confirmation that auto-cancels in non-interactive mode"
  - "strip_toml_section() function added as test helper to reliably revoke user auth without invoking CLI rotation flow"
  - "Phase 1 gate PASSED: all roadmap success criteria now covered by named passing tests"
  - "Confirmed: users remove requires interactive confirmation; SSS_NONINTERACTIVE does NOT bypass it (reads stdin directly)"

patterns-established:
  - "Audit-first: run existing suite before adding tests, verify baseline green"
  - "Gap-fill: add minimal tests targeting specific success criteria, not full suite rewrite"
  - "TOML direct edit for test isolation: when CLI commands have interactive side-effects, modify config files directly"

requirements-completed: [CLI-01, CLI-02]

# Metrics
duration: 5min
completed: 2026-02-21
---

# Phase 1 Plan 02: CLI Gap-Fill Tests Summary

**Three targeted regression tests closing all Phase 1 roadmap gaps: stdout-empty assertion for seal --in-place, auth failure exit-nonzero, and --non-interactive CLI flag direct test**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-21T13:56:42Z
- **Completed:** 2026-02-21T14:01:50Z
- **Tasks:** 2
- **Files modified:** 1 (tests/e2e_cli_workflows.rs) + 1 (SUMMARY.md)

## Accomplishments

- All 74 `e2e_cli_workflows` tests pass (71 pre-existing + 3 new gap-fill tests)
- Phase 1 roadmap success criteria all covered by named automated tests
- Confirmed CLI interface table for Phase 2 Emacs mode development
- Discovered and documented that `users remove` requires interactive confirmation that auto-cancels in non-interactive mode (CONCERNS.md silent-fallback confirmed)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add three targeted smoke tests for roadmap success criteria gaps** - `5e59fb1` (test)
2. **Task 1 deviation fix: Fix auth failure test to use TOML direct edit** - `531fdc1` (fix)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `tests/e2e_cli_workflows.rs` - Added 3 new test functions + strip_toml_section() helper

---

## Phase 1 Gate: PASSED

All 7 Phase 1 roadmap success criteria are now covered by passing automated tests.

| Criterion | Test Name | Status |
|-----------|-----------|--------|
| 1. `sss render FILE` writes decrypted plaintext to stdout | `e2e_workflow_render_to_stdout` | COVERED |
| 2. `sss render FILE` exits 0 on success | All render tests use `run_ok()` | COVERED |
| 3. `sss render FILE` exits non-zero + stderr on auth failure | `e2e_cli_render_auth_failure_exits_nonzero` | NEW - COVERED |
| 4. `sss seal --in-place FILE` re-encrypts in place | `e2e_workflow_full_roundtrip_seal_open_render` | COVERED |
| 5. `sss seal --in-place FILE` exits 0 on success | All seal `-x` calls use `run_ok()` | COVERED |
| 6. `sss seal --in-place FILE` stdout EMPTY (confirmation on stderr) | `e2e_cli_seal_in_place_stdout_empty` | NEW - COVERED |
| 7. `--non-interactive` flag prevents TTY blocking | `e2e_cli_non_interactive_flag_render` | NEW - COVERED |

---

## Confirmed CLI Interface for Phase 2 (Emacs Mode Development)

| Operation | Invocation | stdout | stderr | Exit |
|-----------|-----------|--------|--------|------|
| Decrypt to plaintext | `sss --non-interactive render /path/to/file.sss` | plaintext content | empty on success | 0 |
| Re-seal in-place | `sss --non-interactive seal --in-place /path/to/file.sss` | **empty** | `"File processed in-place: ..."` | 0 |
| Open (markers visible) | `sss --non-interactive open /path/to/file.sss` | content with `⊕{...}` markers | empty on success | 0 |
| Auth failure | `sss --non-interactive render /path/to/file.sss` | **empty** | "None of your keypairs are authorized..." | 1 |

**Exit codes:** 0 on success, non-zero (typically 1) on any failure.

**Alias:** `-x` is equivalent to `--in-place`.

### Non-interactive mode

- CLI flag `--non-interactive` sets env var `SSS_NONINTERACTIVE=1` internally (src/main.rs:706-708)
- Both flag and env var are equivalent at runtime
- Verified by `e2e_cli_non_interactive_flag_render`: sets no env var, passes flag explicitly, asserts exit 0 + clean stdout + empty stderr

### Sealed-file detection

- **Sealed marker byte sequence:** `⊠{` = U+22A0 + 0x7B
- **UTF-8 encoding:** `\xe2\x8a\xa0\x7b` (4 bytes)
- **Open marker byte sequence:** `⊕{` = U+2295 + 0x7B
- **UTF-8 encoding:** `\xe2\x8a\x95\x7b` (4 bytes)
- **Emacs Lisp detection predicate:** `(search-forward "⊠{" nil t)`

---

## Decisions Made

1. **Auth failure test strategy:** Direct `.sss.toml` manipulation instead of `users remove`. The `users remove` command requires interactive stdin confirmation that auto-cancels when stdin is empty (non-interactive subprocess). Directly stripping the `[testuser]` TOML section reliably revokes authorization without triggering the rotation flow.

2. **`strip_toml_section()` helper added to test file** to support direct TOML manipulation in tests. This is a test-only utility, ~15 lines.

3. **Phase 1 gate confirmed PASSED.** All roadmap success criteria are now covered by named passing tests. Phase 2 (Emacs mode) can proceed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Auth failure test used wrong removal strategy**
- **Found during:** Task 2 (running full suite)
- **Issue:** Test `e2e_cli_render_auth_failure_exits_nonzero` used `env.run_ok(&["users", "remove", "testuser"])` to remove the current user. The `users remove` handler calls `confirm_rotation()` which reads from stdin — with empty stdin, the confirmation is "N" (cancel), so the user is never removed and the subsequent render succeeds instead of failing.
- **Fix:** Replaced `users remove` with direct `.sss.toml` manipulation using a new `strip_toml_section()` helper function that removes the `[testuser]` TOML section and all its fields.
- **Files modified:** `tests/e2e_cli_workflows.rs`
- **Verification:** `cargo test --test e2e_cli_workflows e2e_cli_render_auth_failure_exits_nonzero` passes; full suite 74/74 passes.
- **Committed in:** `531fdc1`

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug)
**Impact on plan:** Fix necessary for test correctness. No scope creep. Discovered that `users remove` has an undocumented interaction with non-interactive mode — the rotation confirmation bypasses `SSS_NONINTERACTIVE`. This is a secondary finding worth noting for CONCERNS.md.

## Issues Encountered

- `users remove` does not respect `SSS_NONINTERACTIVE=1` for the rotation confirmation prompt. The prompt reads directly from stdin; when stdin is empty (subprocess), `read_line` returns empty string, which is treated as "N" (no), and the operation is cancelled. This makes it impossible to use `users remove` in non-interactive tests without piping "y\n" to stdin.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- CLI baseline fully confirmed with automated regression tests
- Phase 1 gate PASSED — all roadmap success criteria covered
- Phase 2 (Emacs mode development) can proceed with confidence:
  - CLI interface documented and regression-tested
  - Marker byte sequences confirmed
  - Auth failure behavior verified (exit non-zero, non-empty stderr)
  - `--non-interactive` flag confirmed working via direct CLI flag test
- **Known concern for Phase 2:** `users remove` rotation confirmation bypasses `SSS_NONINTERACTIVE`. Not blocking for Phase 2 (Emacs mode doesn't use `users remove`), but worth tracking.

---
*Phase: 01-cli-foundation*
*Completed: 2026-02-21*

## Self-Check: PASSED

- tests/e2e_cli_workflows.rs: FOUND
- .planning/phases/01-cli-foundation/01-02-SUMMARY.md: FOUND
- Commit 5e59fb1 (Task 1 tests): FOUND
- Commit 531fdc1 (Task 1 deviation fix): FOUND
- Phase 1 gate PASSED declaration: FOUND (5 occurrences)
- Marker byte reference \xe2\x8a\xa0\x7b: FOUND
