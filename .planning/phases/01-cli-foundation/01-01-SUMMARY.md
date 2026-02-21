---
phase: 01-cli-foundation
plan: 01
subsystem: testing
tags: [rust, cargo, cli, e2e, audit, sss]

# Dependency graph
requires: []
provides:
  - "Verified baseline: all 71 e2e_cli_workflows tests pass on current branch"
  - "Confirmed CLI invocation patterns for render, seal --in-place, and open commands"
  - "Confirmed MARKER_CIPHERTEXT byte sequence: ⊠{ = U+22A0 + 0x7B = \\xe2\\x8a\\xa0\\x7b"
  - "Identified test coverage gaps for Plan 02 to address"
affects: [02-cli-foundation, 02-emacs-mode]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Test harness uses SSS_NONINTERACTIVE=1 env var (equivalent to --non-interactive CLI flag)"
    - "All isolation via TempDir with custom prefix sss_e2e_ to avoid WalkDir hidden-dir filter"
    - "env!(CARGO_BIN_EXE_sss) used to locate binary at compile time for integration tests"

key-files:
  created:
    - ".planning/phases/01-cli-foundation/01-01-SUMMARY.md"
  modified: []

key-decisions:
  - "Confirmed: --non-interactive CLI flag sets SSS_NONINTERACTIVE=1 env var internally (src/main.rs:706-708)"
  - "Confirmed: seal --in-place uses eprintln! at src/commands/process.rs:256 — stdout stays clean"
  - "Confirmed: has_sss_markers uses literal ⊠{ string at src/commands/process.rs:564, not MARKER_CIPHERTEXT constant"
  - "Gap identified: no explicit stdout == empty assertion for seal --in-place (Criterion 6)"
  - "Gap identified: no test uses --non-interactive CLI flag directly (Criterion 7)"

patterns-established:
  - "Audit-first: run existing suite before adding tests, verify baseline green"
  - "Criterion mapping: each success criterion mapped to specific test name or flagged as gap"

requirements-completed: [CLI-01, CLI-02]

# Metrics
duration: 8min
completed: 2026-02-21
---

# Phase 1 Plan 01: CLI Audit and Baseline Verification Summary

**71 e2e_cli_workflows tests confirmed passing; CLI invocation patterns for render/seal/open documented; two coverage gaps identified for Plan 02**

## Performance

- **Duration:** 8 min
- **Started:** 2026-02-21T13:42:55Z
- **Completed:** 2026-02-21T13:50:55Z
- **Tasks:** 2
- **Files modified:** 1 (SUMMARY.md created)

## Accomplishments
- All 71 existing `e2e_cli_workflows` tests pass with zero failures
- Mapped each of the 7 Phase 1 success criteria to specific passing tests (or flagged as gap)
- Confirmed exact marker byte sequence: `⊠{` = U+22A0 + 0x7B = `\xe2\x8a\xa0\x7b`
- Documented CLI invocation patterns in a form directly usable by Phase 2 Emacs mode development

## Task Commits

Each task was committed atomically:

1. **Task 1: Run existing e2e test suite and confirm it passes** - `e2e tests verified, no files changed`
2. **Task 2: Confirm marker constants and write audit SUMMARY** - (this SUMMARY.md)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `.planning/phases/01-cli-foundation/01-01-SUMMARY.md` - This audit document

---

## Confirmed Facts (for downstream Phase 2 Emacs mode development)

### CLI Invocation Patterns

| Operation | Invocation | stdout | stderr | Exit |
|-----------|-----------|--------|--------|------|
| Decrypt to plaintext | `sss --non-interactive render /path/to/file.sss` | plaintext content | empty on success | 0 |
| Re-seal in-place | `sss --non-interactive seal --in-place /path/to/file.sss` | **empty** | `"File processed in-place: ..."` | 0 |
| Open (markers visible) | `sss --non-interactive open /path/to/file.sss` | content with `⊕{...}` markers | empty on success | 0 |

**Exit codes:** 0 on success, 1 on any failure (anyhow propagation, no custom exit code calls in source).

**Alias:** `-x` is equivalent to `--in-place`.

### Non-interactive mode

- CLI flag `--non-interactive` sets env var `SSS_NONINTERACTIVE=1` internally (src/main.rs:706-708)
- Env var `SSS_NONINTERACTIVE=1` can also be set directly — both are equivalent at runtime
- Emacs mode may use either; env var is simpler for subprocess invocation

### Sealed-file detection

- **Marker byte sequence:** `⊠{` = U+22A0 + 0x7B
- **UTF-8 encoding:** `\xe2\x8a\xa0\x7b` (4 bytes)
- **Source:** `src/constants.rs:8` defines `MARKER_CIPHERTEXT: &str = "⊠"` (U+22A0)
- **has_sss_markers:** `src/commands/process.rs:564` uses the literal `"⊠{"` string directly (not the const)
- **Emacs detection predicate:** Read first few bytes of file, check for `\xe2\x8a\xa0\x7b` prefix sequence

### Stdout contamination

Verified NONE for single-file commands:
- `seal --in-place`: uses `eprintln!` at `src/commands/process.rs:256` → stderr only
- `render` (stdout mode): uses `print!` at `src/commands/process.rs:138` → stdout with content
- `open` (stdout mode): uses `print!` at `src/commands/process.rs:258` → stdout with content
- All informational/warning messages throughout `src/commands/process.rs` use `eprintln!`

---

## Phase 1 Success Criteria — Coverage Map

### Criterion 1: `sss render FILE` writes decrypted plaintext to stdout
**Status: COVERED**
- `e2e_workflow_render_to_stdout` — asserts `assert_eq!(stdout, "key: abc")`
- `e2e_workflow_seal_then_render_recovers_plaintext` — asserts `assert_eq!(stdout, "db_pass=hunter2")`

### Criterion 2: `sss render FILE` exits 0 on success
**Status: COVERED**
- All render tests use `run_ok()` which asserts `out.status.success()`

### Criterion 3: `sss render FILE` exits non-zero with stderr on auth/config failure
**Status: PARTIALLY COVERED**
- `e2e_error_render_nonexistent_file` — covers missing-file failure (file doesn't exist error)
- **GAP:** No test exercises keystore auth failure specifically (no matching keypair for a sealed file encrypted by a different user's key). This would require: setup project with other user's key, seal file as other user, attempt to render as current user.

### Criterion 4: `sss seal --in-place FILE` re-encrypts in place
**Status: COVERED**
- `e2e_workflow_seal_in_place_message` — calls `seal -x f.txt`, then checks file
- `e2e_workflow_full_roundtrip_seal_open_render` — seals in-place and verifies ciphertext marker present

### Criterion 5: `sss seal --in-place FILE` exits 0 on success
**Status: COVERED**
- All `seal -x` calls use `run_ok()` which asserts `out.status.success()`

### Criterion 6: `sss seal --in-place FILE` keeps stdout EMPTY (confirmation on stderr only)
**Status: GAP — no explicit test**
- `e2e_workflow_seal_in_place_message` uses `let (_, stderr) = env.run_ok(&["seal", "-x", "f.txt"])` — ignores stdout via `_`
- The test asserts `stderr.contains("in-place")` but does NOT assert `stdout == ""`
- Source code at `src/commands/process.rs:256` uses `eprintln!` (correct), but this is untested at the test level

### Criterion 7: `--non-interactive` flag prevents TTY blocking
**Status: GAP — env var used, not CLI flag directly**
- All tests set `SSS_NONINTERACTIVE=1` via `.env("SSS_NONINTERACTIVE", "1")` in the `cmd()` helper
- No test explicitly passes `--non-interactive` as a CLI argument
- Functionally equivalent (src/main.rs:706-708 sets the env var from the flag), but the flag itself is not directly tested

---

## Test Coverage Gaps (Inputs to Plan 02)

Plan 02 must add tests for:

1. **Criterion 6 gap:** `seal --in-place` stdout empty — add `assert_eq!(stdout, "")` assertion
2. **Criterion 7 gap:** `--non-interactive` CLI flag — add a test that passes `["--non-interactive", "render", ...]` directly
3. **Criterion 3 gap (auth failure):** Sealed-by-other-user render attempt should fail with non-zero exit and stderr error message (not silent empty buffer — related to CONCERNS.md silent-fallback risk)

---

## What Phase 1 Does NOT Require

- No new Rust source code changes
- No new CLI flags
- No changes to `src/commands/process.rs` or `src/main.rs`
- Existing CLI implementation fully satisfies all functional requirements

## Decisions Made
- `--non-interactive` flag is confirmed as the correct flag for Emacs subprocess use
- `SSS_NONINTERACTIVE=1` env var is equally valid and simpler for subprocess wrappers
- Plan 02 scope confirmed: add 3 targeted gap-filling tests, not a full test suite rewrite

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## Next Phase Readiness
- CLI baseline confirmed: ready for Plan 02 to add gap-filling tests
- Emacs mode (Phase 2) can directly use the invocation patterns documented above
- The silent-fallback keystore concern (CONCERNS.md lines 73-81) is the highest risk for Emacs auth-failure UX

---
*Phase: 01-cli-foundation*
*Completed: 2026-02-21*
