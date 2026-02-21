---
phase: 02-sss-mode-core
plan: 01
subsystem: emacs
tags: [emacs-lisp, sss-mode, major-mode, magic-mode-alist, call-process]

# Dependency graph
requires:
  - phase: 01-cli-foundation
    provides: "Confirmed CLI interface: sss --non-interactive open/seal/render exit codes, stdout/stderr behavior, --non-interactive flag sets SSS_NONINTERACTIVE=1"
provides:
  - "emacs/sss-mode.el with package header, defgroup sss, defcustom sss-executable"
  - "sss--call-cli helper returning (exit-code stdout stderr) for any sss subcommand"
  - "sss--sealed-p detection predicate for magic-mode-alist MATCH-FUNCTION variant"
  - "magic-mode-alist registration for content-based sealed file detection"
affects:
  - 02-sss-mode-core/02-02 (open flow uses sss--call-cli and sss--sealed-p)
  - 02-sss-mode-core/02-03 (save flow uses sss--call-cli)
  - 02-sss-mode-core/02-04 (mode definition uses sss-mode-map from define-derived-mode)

# Tech tracking
tech-stack:
  added:
    - Emacs Lisp (emacs/sss-mode.el, single-file package)
    - call-process with (list stdout-buf stderr-file) destination pattern
    - magic-mode-alist MATCH-FUNCTION variant
  patterns:
    - stderr captured via make-temp-file + unwind-protect for cleanup
    - sss--call-cli always prepends --non-interactive to prevent TTY blocking
    - magic-mode-alist MATCH-FUNCTION variant (not regexp) for multibyte-safe detection
    - executable-find check at load time with warning message (never error)
    - Forward reference to sss-mode symbol acceptable in magic-mode-alist (resolved at call time)

key-files:
  created:
    - emacs/sss-mode.el
  modified: []

key-decisions:
  - "stderr-dest in call-process MUST be a file path string (not buffer object) — verified on Emacs 30.1"
  - "magic-mode-alist uses MATCH-FUNCTION variant (not regexp) for precise multibyte detection"
  - "--non-interactive always prepended to all sss CLI calls to prevent TTY blocking"
  - "sss-mode forward reference in magic-mode-alist is acceptable (Emacs resolves at call time)"
  - "docstring-width warning fixed by wrapping long line; sss-mode forward ref warning is expected/acceptable"

patterns-established:
  - "Pattern: sss--call-cli (list SUBCMD ARGS) &optional FILE — uniform CLI invocation for all plans"
  - "Pattern: (cons #'sss--sealed-p #'sss-mode) in magic-mode-alist — content-based mode detection"

requirements-completed: [EMAC-01, EMAC-05, EMAC-07]

# Metrics
duration: 5min
completed: 2026-02-21
---

# Phase 2 Plan 01: sss-mode.el Foundation Summary

**Emacs major mode foundation: package header, defgroup/defcustom, call-process CLI helper with stderr capture, and content-based detection predicate registered in magic-mode-alist**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-21T14:42:00Z
- **Completed:** 2026-02-21T14:47:00Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments
- Created `emacs/sss-mode.el` with correct package header (lexical-binding, Package-Requires emacs 27.1)
- Implemented `sss--call-cli` using `call-process` with stdout buffer + stderr temp file pattern (verified on Emacs 30.1)
- Implemented `sss--sealed-p` predicate and registered in `magic-mode-alist` as MATCH-FUNCTION variant
- File loads cleanly and byte-compiles without errors; all 5 verification checks pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Create emacs/ directory and sss-mode.el package foundation** - `b335de6` (feat)

**Plan metadata:** (pending)

## Files Created/Modified
- `emacs/sss-mode.el` - Package foundation: header, defgroup, defcustom sss-executable, sss--sealed-marker const, sss--call-cli helper, sss--sealed-p predicate, magic-mode-alist registration

## Decisions Made
- Used file path string (not buffer object) for call-process stderr destination — required for Emacs 30.1 correctness
- Used magic-mode-alist MATCH-FUNCTION variant (named predicate, not regexp) for precise multibyte-safe detection of the 4-byte ⊠{ sequence
- Fixed docstring line-width warning in sss--sealed-p to keep byte-compile output clean (Rule 1 auto-fix)
- Forward reference to sss-mode in magic-mode-alist is intentional — Emacs resolves at call time, not registration time

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed docstring wider than 80 characters in sss--sealed-p**
- **Found during:** Task 1 (byte-compile verification)
- **Issue:** Docstring line `"Checks for the exact 4-byte sequence \\xe2\\x8a\\xa0{ (\\xe2\\x8a\\xa0{) at buffer start."` was wider than 80 characters, triggering a byte-compile warning
- **Fix:** Rewrote line to `"Checks for the exact 4-byte UTF-8 sequence \\xe2\\x8a\\xa0{ at buffer start."` — same meaning, within 80 chars
- **Files modified:** emacs/sss-mode.el
- **Verification:** `emacs --batch -Q -f batch-byte-compile emacs/sss-mode.el 2>&1` — only the expected forward-reference warning remains, exits 0
- **Committed in:** b335de6 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - docstring width bug)
**Impact on plan:** Trivial formatting fix. No behavior change. Keeps byte-compile output clean.

## Issues Encountered
None — plan executed as written. The forward-reference warning (`sss-mode not known to be defined`) is documented as acceptable in the plan spec.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `sss--call-cli` is ready for use by open flow (Plan 02) and save flow (Plan 03)
- `sss--sealed-p` and magic-mode-alist registration provide content-based detection for Plan 02
- `sss-executable` defcustom satisfies EMAC-07 customization requirement
- Plan 02 (open flow) can proceed: `sss--call-cli (list "open") file` pattern is in place

## Self-Check: PASSED

- FOUND: emacs/sss-mode.el
- FOUND: .planning/phases/02-sss-mode-core/02-01-SUMMARY.md
- FOUND: commit b335de6

---
*Phase: 02-sss-mode-core*
*Completed: 2026-02-21*
