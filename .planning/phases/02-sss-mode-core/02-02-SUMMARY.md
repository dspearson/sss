---
phase: 02-sss-mode-core
plan: 02
subsystem: emacs
tags: [emacs-lisp, sss-mode, find-file-hook, auto-save, decrypt-on-open, write-contents-functions, after-revert-hook]

# Dependency graph
requires:
  - phase: 02-sss-mode-core/02-01
    provides: "sss--call-cli helper, sss--sealed-p predicate, magic-mode-alist registration"
provides:
  - "sss--find-file-hook: entry point on find-file-hook, guards with buffer-file-name + sss--sealed-p"
  - "sss--open-buffer: calls sss open FILE, disables auto-save/backup before erase-buffer, replaces content with plaintext+markers, signals error on failure"
  - "write-contents-functions registered buffer-locally for Plan 03 save flow"
  - "after-revert-hook registered buffer-locally for re-decryption on revert-buffer"
affects:
  - 02-sss-mode-core/02-03 (save flow: sss--write-contents will be defined here, registered by this plan)
  - 02-sss-mode-core/02-04 (mode definition installs sss--find-file-hook on find-file-hook)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "auto-save-mode -1 is the canonical Emacs API to disable auto-save (not setq auto-save-mode nil)"
    - "setq-local auto-save-default nil + auto-save-mode -1 + setq-local backup-inhibited t — all three needed"
    - "Disable auto-save/backup BEFORE erase-buffer/insert — timing critical to prevent partial plaintext save"
    - "pcase with backtick patterns for CLI exit-code dispatch — clean tri-tuple matching"
    - "(error ...) not (message ...) for user-visible decryption failure — signals in minibuffer, aborts find-file"
    - "add-hook with nil t (append=nil, local=t) for buffer-local hook registration"

key-files:
  created: []
  modified:
    - emacs/sss-mode.el

key-decisions:
  - "Auto-save/backup disable BEFORE erase-buffer — timing critical: auto-save timer may fire during the CLI call"
  - "sss open FILE (not sss render FILE) — open preserves ⊕{} markers; render strips them (EMAC-09 requirement)"
  - "(error ...) used for decryption failure, not (message ...) + return nil — ensures visible minibuffer signal (EMAC-06)"
  - "sss--write-contents forward reference acceptable — registered on write-contents-functions now, defined in Plan 03"
  - "Docstring width auto-fixed to <=80 chars to keep byte-compile output clean (same precedent as Plan 01)"

patterns-established:
  - "Pattern: disable auto-save before erase-buffer in any decrypt-to-buffer operation"
  - "Pattern: pcase on (exit stdout stderr) triple for CLI result dispatch in sss-mode"
  - "Pattern: add-hook 'HOOK #'FN nil t for buffer-local hook registration"

requirements-completed: [EMAC-02, EMAC-04, EMAC-06, EMAC-09]

# Metrics
duration: 4min
completed: 2026-02-21
---

# Phase 2 Plan 02: sss-mode Open Flow Summary

**Transparent decrypt-on-open via find-file-hook: sss--find-file-hook and sss--open-buffer with auto-save/backup disable before buffer replacement and after-revert re-decryption**

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-21T14:48:23Z
- **Completed:** 2026-02-21T14:52:00Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments
- Added `sss--find-file-hook` entry point (guards with `buffer-file-name` + `sss--sealed-p`, then calls `sss--open-buffer`)
- Added `sss--open-buffer` implementing the full open sequence: auto-save/backup disable first, then CLI call, then buffer replacement with plaintext+markers, then hook registration
- Registered `write-contents-functions` buffer-locally for Plan 03's save flow (`sss--write-contents` forward reference)
- Registered `after-revert-hook` buffer-locally so `revert-buffer` re-decrypts rather than leaving raw sealed bytes
- Error path uses `(error ...)` for visible minibuffer signal on decryption failure — never a silent empty buffer
- File loads cleanly and byte-compiles with only expected forward-reference warnings (no errors)

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement open flow (find-file-hook + sss--open-buffer)** - `c2312fc` (feat)

**Plan metadata:** (pending)

## Files Created/Modified
- `emacs/sss-mode.el` - Added open flow section: `sss--find-file-hook`, `sss--open-buffer` with auto-save/backup disable, write-contents-functions and after-revert-hook buffer-local registration

## Decisions Made
- `sss open FILE` (not `sss render FILE`) — `open` preserves `⊕{}` markers per EMAC-09; `render` strips them
- Auto-save/backup disabled BEFORE `erase-buffer` — timing is critical: the auto-save timer may fire during the blocking CLI call, so disabling after erase-buffer would be too late
- `(error ...)` used for decryption failures (not `(message ...)` + `nil` return) — `error` signals into the minibuffer and aborts `find-file` cleanly per EMAC-06
- `sss--write-contents` forward reference is intentional — it will be defined in Plan 03; Emacs resolves function references at call time, not at `add-hook` time

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed docstring line >80 characters in sss--open-buffer**
- **Found during:** Task 1 (byte-compile verification)
- **Issue:** Docstring line "On failure, signals a visible error (EMAC-06) — never leaves a silent empty buffer." was 85 characters, triggering a `docstring wider than 80 characters` byte-compile warning
- **Fix:** Shortened to "On failure, signals a visible error (EMAC-06) — never a silent empty buffer." (75 chars)
- **Files modified:** emacs/sss-mode.el
- **Verification:** `emacs --batch -Q -f batch-byte-compile emacs/sss-mode.el 2>&1` — only expected forward-reference warnings remain, exits 0
- **Committed in:** c2312fc (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - docstring width bug)
**Impact on plan:** Trivial formatting fix. No behavior change. Keeps byte-compile output clean. Same precedent established in Plan 01.

## Issues Encountered
None — plan executed as written. Both forward-reference warnings (`sss--write-contents not known to be defined` and `sss-mode not known to be defined`) are documented as acceptable in the plan spec.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `sss--find-file-hook` and `sss--open-buffer` are ready for use by Plan 04 (mode definition, which installs the hook on `find-file-hook`)
- `write-contents-functions` is registered buffer-locally — Plan 03 must define `sss--write-contents` to complete the save flow
- Open flow is complete and functional; sss binary needed at runtime for actual decryption
- Plan 03 (save flow) can proceed: forward reference to `sss--write-contents` is already in place

## Self-Check: PASSED

- FOUND: emacs/sss-mode.el (130 lines, meets min_lines: 120)
- FOUND: commit c2312fc
- FOUND: sss--find-file-hook (fboundp returns t)
- FOUND: sss--open-buffer (fboundp returns t)
- FOUND: uses "open" subcommand (not "render")
- FOUND: auto-save disable at lines 110-112, before erase-buffer at line 115

---
*Phase: 02-sss-mode-core*
*Completed: 2026-02-21*
