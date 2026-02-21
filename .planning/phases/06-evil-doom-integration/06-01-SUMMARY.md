---
phase: 06-evil-doom-integration
plan: 01
subsystem: emacs
tags: [evil-mode, emacs, operators, text-objects, sss-mode, doom]

# Dependency graph
requires:
  - phase: 05-core-operations-ux
    provides: sss-encrypt-region, sss-decrypt-region, sss-toggle-at-point, sss--marker-at-point, sss--any-marker-regexp
provides:
  - "Evil operators sss-evil-encrypt, sss-evil-decrypt, sss-evil-toggle bound to ge/gd/gt in sss-mode-map normal state (buffer-local)"
  - "Evil text objects sss-inner-pattern (is) and sss-outer-pattern (as) registered on evil text object maps"
  - "Single with-eval-after-load 'evil block in sss-mode.el for DOOM-03 conditional loading"
affects: [06-evil-doom-integration, 07-cleanup]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "with-eval-after-load 'evil for deferred evil integration (not featurep, not modulep!)"
    - "evil-define-key 'normal sss-mode-map for buffer-local evil normal state bindings"
    - "re-search-forward + (goto-char (match-beginning 0)) to walk markers in region operator"
    - "evil-define-text-object returns (list BEG END), not cons cell"

key-files:
  created: []
  modified:
    - emacs/sss-mode.el

key-decisions:
  - "Buffer-local evil bindings via evil-define-key 'normal sss-mode-map (not global evil-normal-state-map) — preserves ge/gd/gt in all non-sss buffers"
  - "sss-evil-toggle region walk uses re-search-forward with sss--any-marker-regexp to jump marker-to-marker, not forward-char — avoids user-error from sss-toggle-at-point on non-marker positions"
  - "sss--any-marker-regexp already defined in Phase 5 sss-mode.el — no defconst needed in evil block"
  - "All evil code (operators + bindings + text objects) in a single with-eval-after-load 'evil block — single deferred scope"

patterns-established:
  - "Pattern: evil-define-key 'normal MODE-MAP for mode-scoped evil normal state operator bindings"
  - "Pattern: re-search-forward + goto-char match-beginning + forward-char 1 for safe marker-walking loop in evil operators"

requirements-completed: [EVIL-01, EVIL-02, EVIL-03, DOOM-03]

# Metrics
duration: 2min
completed: 2026-02-23
---

# Phase 6 Plan 01: Evil & Doom Integration (Operators + Text Objects) Summary

**Evil operators ge/gd/gt and text objects is/as added to sss-mode.el inside a single with-eval-after-load 'evil block using buffer-local sss-mode-map bindings**

## Performance

- **Duration:** 2 min
- **Started:** 2026-02-23T08:41:33Z
- **Completed:** 2026-02-23T08:43:35Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Three evil operators (sss-evil-encrypt, sss-evil-decrypt, sss-evil-toggle) defined with `evil-define-operator`; bound buffer-locally to ge/gd/gt via `evil-define-key 'normal sss-mode-map`
- Two evil text objects (sss-inner-pattern for `is`, sss-outer-pattern for `as`) defined with `evil-define-text-object`; registered on `evil-inner-text-objects-map` and `evil-outer-text-objects-map`
- All code inside a single `(with-eval-after-load 'evil ...)` block; file loads without error in vanilla Emacs (DOOM-03 conditional loading scaffold)

## Task Commits

Each task was committed atomically:

1. **Task 1 + Task 2: Add evil operators, text objects, and buffer-local bindings** - `08c1e51` (feat)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified

- `emacs/sss-mode.el` - Added 66 lines: evil integration block with 3 operators, buffer-local key bindings, 2 text objects; all inside `(with-eval-after-load 'evil ...)`

## Decisions Made

- Used `evil-define-key 'normal sss-mode-map` (buffer-local) rather than `define-key evil-normal-state-map` (global). This preserves `ge` (evil-backward-word-end), `gd` (evil-goto-definition), and `gt` (evil-tab-next) in all non-sss buffers — the operators only activate when in an sss-mode buffer. The research (06-RESEARCH.md Open Question #1) recommended this approach; the plan mandated it.
- `sss-evil-toggle` region walk uses `re-search-forward sss--any-marker-regexp` to jump from marker to marker, then `(goto-char (match-beginning 0))` to position before calling `sss-toggle-at-point`. This avoids calling `sss-toggle-at-point` on inter-marker text which would signal `user-error "No SSS marker at point"` and abort the operator.
- `sss--any-marker-regexp` was already defined in Phase 5 (line 56-58 of sss-mode.el). No new `defconst` needed.
- Tasks 1 and 2 were implemented in a single edit since Task 2 is inside the same `with-eval-after-load 'evil` block as Task 1 — they are one coherent insertion.

## Deviations from Plan

None - plan executed exactly as written. The evil block consolidates both tasks (operators from Task 1, text objects from Task 2) in one contiguous `with-eval-after-load 'evil` block as specified.

## Issues Encountered

None. Byte-compiler warnings for evil symbols inside `with-eval-after-load` are expected (same pattern as `transient-define-prefix` and `auth-source-search` warnings already present in the file). Exit code 0, `.elc` created, vanilla load test passes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Evil operators and text objects complete and ready for Doom leader/localleader binding plan (06-02 if planned)
- `emacs/sss-mode.el` is the single artifact; no new files created
- `plugins/emacs/sss-doom.el` can be removed in Phase 7 cleanup — evil functionality is now in sss-mode.el

## Self-Check: PASSED

- emacs/sss-mode.el: FOUND
- 06-01-SUMMARY.md: FOUND
- commit 08c1e51: FOUND

---
*Phase: 06-evil-doom-integration*
*Completed: 2026-02-23*
