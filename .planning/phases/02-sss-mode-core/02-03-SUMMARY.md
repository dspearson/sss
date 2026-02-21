---
phase: 02-sss-mode-core
plan: 03
subsystem: emacs
tags: [emacs-lisp, sss-mode, write-contents-functions, define-derived-mode, keymap, seal-on-save]

# Dependency graph
requires:
  - phase: 02-sss-mode-core/02-01
    provides: "sss--call-cli helper, sss--sealed-p predicate, magic-mode-alist registration"
  - phase: 02-sss-mode-core/02-02
    provides: "sss--open-buffer open flow, write-contents-functions forward reference, buffer-local hook registration"
provides:
  - "sss--write-contents: two-step write-then-seal save handler for write-contents-functions"
  - "sss-mode: define-derived-mode major mode with autoload cookie"
  - "C-c s o / C-c s s keymap bindings (EMAC-08)"
  - "sss-open-buffer / sss-seal-buffer interactive wrappers"
  - "Complete emacs/sss-mode.el: loads, byte-compiles cleanly, checkdoc passes"
affects:
  - Phase 3 documentation (integration guide will reference sss-mode)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "write-contents-functions nil binding prevents infinite recursion in save handler (Pitfall 4)"
    - "set-visited-file-modtime after successful seal clears buffer-modified flag (Pitfall 5)"
    - "(error ...) in write-contents-functions handler — never nil on failure (Pitfall 1: nil falls through to plaintext write)"
    - "define-derived-mode with ;;;###autoload cookie for autoload generation"
    - "Mode-specific keymap bindings under C-c s prefix (standard Emacs convention)"
    - "checkdoc fixes: exec-path disambiguation, escaped parens in docstring, capitalized error messages"

key-files:
  created: []
  modified:
    - emacs/sss-mode.el

key-decisions:
  - "(error ...) on seal failure — never nil return — nil would fall through to default write-region writing plaintext"
  - "set-visited-file-modtime called after successful seal to clear buffer-modified flag and suppress kill-buffer save prompt"
  - "write-contents-functions nil binding is mandatory inside the handler to prevent infinite recursion"
  - "nomessage arg in write-region suppresses duplicate 'Wrote FILE' echo during save"
  - "Parent mode is text-mode (not fundamental-mode) for basic text editing features"
  - "add-hook find-file-hook in mode body (global install) — sss--find-file-hook guards with sss--sealed-p so safe on all files"
  - "checkdoc capitalization: error messages start with capital letter (Sss-mode: ...)"

patterns-established:
  - "Pattern: (let ((write-contents-functions nil)) (write-region ...)) — mandatory recursion prevention in write-contents-functions handlers"
  - "Pattern: (set-visited-file-modtime) after in-place file modification to sync Emacs modtime record"

requirements-completed: [EMAC-03, EMAC-06, EMAC-08]

# Metrics
duration: 5min
completed: 2026-02-21
---

# Phase 2 Plan 03: sss-mode Save Flow + Mode Definition Summary

**Security-critical sss--write-contents save handler (write-then-seal, recursion-safe, never-nil-on-failure) plus define-derived-mode with C-c keymap completing the full transparent edit workflow**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-21T14:57:50Z
- **Completed:** 2026-02-21T15:02:50Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- Implemented `sss--write-contents` as the write-contents-functions handler: two-step write-plaintext-then-seal-in-place, with `write-contents-functions nil` recursion guard, `set-visited-file-modtime` on success, and `(error ...)` on failure (never nil)
- Defined `sss-mode` via `define-derived-mode` with `;;;###autoload` cookie, `text-mode` parent, `"SSS"` mode-line name, and `add-hook find-file-hook` in mode body
- Added C-c s o / C-c s s keymap bindings and `sss-open-buffer` / `sss-seal-buffer` interactive wrappers
- File loads cleanly, byte-compiles with zero warnings, and checkdoc passes with zero issues

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement sss--write-contents save flow** - `84d9395` (feat)
2. **Task 2: Define sss-mode via define-derived-mode and verify complete file** - `dec9c46` (feat)

**Plan metadata:** (pending)

## Files Created/Modified
- `emacs/sss-mode.el` - Added save flow section (`sss--write-contents`) and mode definition section (`sss-mode` define-derived-mode, `sss-open-buffer`, `sss-seal-buffer`); 212 lines total, all 9 EMAC requirements satisfied

## Decisions Made
- `(error ...)` on seal failure is mandatory — `nil` return would fall through to Emacs' default `write-region`, writing plaintext to disk (the exact failure mode the whole architecture exists to prevent)
- `(let ((write-contents-functions nil)) (write-region ...))` binding prevents the save handler from calling itself recursively (Pitfall 4 from research)
- `(set-visited-file-modtime)` called after in-place seal to sync Emacs' modtime record — without this the mode-line shows `**` and `kill-buffer` prompts to save again
- `'nomessage` in write-region call suppresses duplicate "Wrote FILE" echo during save sequence
- Parent mode `text-mode` chosen over `fundamental-mode` for basic text editing infrastructure
- checkdoc error message capitalization applied: `"Sss-mode: ..."` format satisfies checkdoc's "Messages should start with a capital letter" requirement

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed docstring width warnings in define-derived-mode**
- **Found during:** Task 2 (byte-compile verification)
- **Issue:** Two docstring lines in `sss-mode` exceeded 80 characters: "Auto-save and backup are disabled for the decrypted buffer (security requirement)." (82 chars) and "Activated automatically via `magic-mode-alist' for files starting with ⊠{." (85 chars)
- **Fix:** Shortened to "Auto-save and backup are disabled for the decrypted buffer (security)." and "Activated automatically via `magic-mode-alist' for sealed files." — same meaning, within 80 chars
- **Files modified:** emacs/sss-mode.el
- **Verification:** `emacs --batch -Q -f batch-byte-compile emacs/sss-mode.el 2>&1` — exits 0 with no warnings
- **Committed in:** dec9c46 (Task 2 commit)

**2. [Rule 1 - Bug] Fixed checkdoc issues: exec-path disambiguation, paren escaping, error capitalization**
- **Found during:** Task 2 (checkdoc verification)
- **Issue:** Three checkdoc warnings: (a) `exec-path` in defcustom docstring not disambiguated, (b) open parenthesis `(1)` at column 0 in docstring not escaped, (c) error messages in `sss--open-buffer`, `sss--write-contents` not starting with capital letter
- **Fix:** (a) Changed `exec-path` to `variable \`exec-path''`; (b) rewrote "(1) write plaintext..." to "step 1 writes plaintext..."; (c) changed `"sss-mode: ..."` to `"Sss-mode: ..."` in all three `(error ...)` calls
- **Files modified:** emacs/sss-mode.el
- **Verification:** `emacs --batch -Q --eval "(checkdoc-file ...)"` — exits 0 with no output
- **Committed in:** dec9c46 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (Rule 1 - byte-compile/checkdoc correctness)
**Impact on plan:** Trivial formatting fixes. No behavior change. Same precedent as Plans 01 and 02.

## Issues Encountered
None — plan executed as specified. All verification checks pass on first attempt after auto-fixes.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `emacs/sss-mode.el` is complete: all 9 EMAC requirements satisfied (EMAC-01 through EMAC-09)
- Phase 2 success criteria are met: SC1 (plaintext shown, disk stays sealed), SC2 (save re-seals), SC3 (failures visible), SC4 (auto-save/backup disabled), SC5 (customize-group works)
- Phase 3 (documentation) can reference the complete, working `emacs/sss-mode.el` as the deliverable
- The mode is ready for end-to-end testing against a real sss binary

## Self-Check: PASSED

- FOUND: emacs/sss-mode.el (212 lines, satisfies min_lines: 180)
- FOUND: .planning/phases/02-sss-mode-core/02-03-SUMMARY.md
- FOUND: commit 84d9395 (Task 1: sss--write-contents)
- FOUND: commit dec9c46 (Task 2: define-derived-mode + keymap)
- FOUND: sss--write-contents (fboundp returns t)
- FOUND: sss-mode (fboundp returns t)
- FOUND: sss-open-buffer (fboundp returns t)
- FOUND: sss-seal-buffer (fboundp returns t)
- FOUND: write-contents-functions nil binding at line 152
- FOUND: set-visited-file-modtime at line 161
- FOUND: (provide 'sss-mode) at line 211
- FOUND: ;;;###autoload at line 173
- PASSED: byte-compile exits 0 with no warnings
- PASSED: checkdoc exits 0 with no output

---
*Phase: 02-sss-mode-core*
*Completed: 2026-02-21*
