---
phase: 06-evil-doom-integration
plan: 02
subsystem: editor-integration
tags: [emacs, doom, evil, keybindings, map!, leader, localleader]

# Dependency graph
requires:
  - phase: 06-01
    provides: evil operators (sss-evil-encrypt, sss-evil-decrypt, sss-evil-toggle), text objects (is/as), buffer-local ge/gd/gt bindings in sss-mode-map
  - phase: 05-core-ux
    provides: sss-encrypt-region, sss-decrypt-region, sss-toggle-at-point, sss-preview-at-point, sss-dispatch, sss-init, sss-process, sss-keygen, sss-keys-list
provides:
  - Doom leader SPC e prefix with 9 bindings (encrypt/decrypt/toggle/preview/dispatch + project sub-prefix + keys sub-prefix)
  - Doom localleader , e prefix with 5 buffer-local bindings scoped to sss-mode-map
  - (when (fboundp 'map!) ...) guard for graceful degradation in vanilla Emacs
  - Updated Commentary documenting evil and Doom integration
affects: [07-cleanup, any future Doom module packaging]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "eval-wrap map! calls to prevent byte-compiler from expanding Doom macro syntax outside Doom"
    - "(when (fboundp 'map!) ...) guard for optional Doom integration"
    - "(declare-function map! \"doom-core\" t t) to silence byte-compiler free-variable warning"

key-files:
  created: []
  modified:
    - emacs/sss-mode.el

key-decisions:
  - "Wrap map! calls in (eval '(...)) so byte-compiler does not attempt to parse Doom macro syntax at compile time -- exit 0 with no errors"
  - "Use (declare-function map! \"doom-core\" t t) before the when guard to suppress byte-compiler unknown-function warning without requiring doom-core"
  - "Use (when (fboundp 'map!) ...) top-level guard rather than (with-eval-after-load 'doom-core ...) -- simpler, same effect"
  - "No (require 'sss) or (require 'sss-ui) inside Doom block -- all target functions already defined earlier in sss-mode.el"

patterns-established:
  - "Doom macro eval-wrapping: use (eval '(map! ...)) when the macro is unavailable at byte-compile time"
  - "Graceful Doom degradation: (when (fboundp 'map!) ...) with declare-function is the canonical pattern for optional Doom integration"

requirements-completed: [DOOM-01, DOOM-02]

# Metrics
duration: 3min
completed: 2026-02-23
---

# Phase 6 Plan 02: Doom Leader and Localleader Bindings Summary

**Doom SPC e leader prefix (9 bindings) and , e localleader prefix (5 bindings) added to sss-mode.el, gated behind (when (fboundp 'map!) ...) for zero-cost graceful degradation in vanilla Emacs**

## Performance

- **Duration:** 3 min
- **Started:** 2026-02-23T08:47:22Z
- **Completed:** 2026-02-23T08:50:16Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Doom global leader `SPC e` prefix with encrypt/decrypt/toggle/preview/dispatch plus `SPC e p` (project) and `SPC e k` (keys) sub-prefixes — 9 total bindings (DOOM-01)
- Doom localleader `, e` prefix scoped to `sss-mode-map` — 5 buffer-local bindings for sss-mode buffers only (DOOM-02)
- `(declare-function map! "doom-core" t t)` suppresses byte-compiler warning; `(eval '(map! ...))` prevents compile-time macro expansion error — file byte-compiles exit 0 with zero errors
- Confirmed correct file tail order (evil block -> doom block -> provide -> footer) and updated Commentary to document both evil and Doom integration

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Doom leader and localleader bindings** - `f3dbfc7` (feat)
2. **Task 2: Reorder file tail structure and update Commentary section** - `296dc47` (feat)

**Plan metadata:** (to be added in final commit)

## Files Created/Modified

- `emacs/sss-mode.el` - Added `;;; Doom integration (DOOM-01, DOOM-02)` section with declare-function, when guard, eval-wrapped map! calls for leader and localleader; updated Commentary section

## Decisions Made

- **eval-wrap map! calls:** The `map!` macro uses non-standard Lisp syntax (`(:prefix-map ("e" . "encryption") ...)`) that the byte-compiler cannot parse without Doom loaded. Wrapping each call in `(eval '(...))` prevents byte-compilation from expanding the form. At runtime in Doom, `eval` executes the form normally and `map!` expands correctly.

- **declare-function placement:** `(declare-function map! "doom-core" t t)` is placed BEFORE the `(when (fboundp 'map!) ...)` guard (top-level) to ensure the declaration is visible to the byte-compiler. The `t t` arguments mark it as having `&rest` args and being a macro — suppressing "not known to be defined" warnings.

- **No (with-eval-after-load 'doom-core ...):** The plan specified `(when (fboundp 'map!) ...)` as simpler and equivalent. `map!` is defined at Doom startup before any user packages load, so the fboundp check is sufficient and avoids the complexity of deferred evaluation.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Wrapped map! calls in eval to fix byte-compiler error**
- **Found during:** Task 1 verification (byte-compile)
- **Issue:** `(byte-compile-file ...)` produced `Error: Wrong type argument: proper-list-p, ("e" . "encryption")` because the byte-compiler tried to parse `(:prefix-map ("e" . "encryption") ...)` as a normal function call
- **Fix:** Wrapped each `map!` call in `(eval '(...))` to defer parsing to runtime when `map!` macro is actually defined
- **Files modified:** emacs/sss-mode.el
- **Verification:** Byte-compile exits 0 with zero errors; vanilla Emacs load prints "loaded OK"
- **Committed in:** f3dbfc7 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - byte-compiler error in planned code)
**Impact on plan:** Required fix — without eval wrapping, byte-compiled elc would not function. No scope creep.

## Issues Encountered

None beyond the map! eval-wrapping deviation documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 6 complete: all 6 requirements satisfied (EVIL-01, EVIL-02, EVIL-03 from 06-01; DOOM-01, DOOM-02 from 06-02; DOOM-03 conditional loading verified in both plans)
- Phase 7 (Cleanup): can remove `plugins/emacs/` since all functionality is now in `emacs/sss-mode.el`
- `sss-doom.el` in `plugins/emacs/` is now superseded; Phase 7 will delete it

---
*Phase: 06-evil-doom-integration*
*Completed: 2026-02-23*

## Self-Check: PASSED

- emacs/sss-mode.el: FOUND
- .planning/phases/06-evil-doom-integration/06-02-SUMMARY.md: FOUND
- Commit f3dbfc7 (Task 1): FOUND
- Commit 296dc47 (Task 2): FOUND
