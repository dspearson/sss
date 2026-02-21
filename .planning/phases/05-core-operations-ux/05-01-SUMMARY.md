---
phase: 05-core-operations-ux
plan: 01
subsystem: emacs
tags: [emacs-lisp, auth-source, call-process-region, region-ops, encryption, sss-mode]

# Dependency graph
requires: []
provides:
  - sss--call-cli-region: stdin-based CLI invocation for region operations
  - sss-encrypt-region: interactive region encrypt with auto-wrap in ⊕{} marker
  - sss-decrypt-region: interactive region decrypt ⊠{} to ⊕{}
  - sss--get-passphrase: auth-source passphrase lookup with (require nil t) guard
  - sss-use-auth-source: defcustom for auth-source opt-in
  - sss--any-marker-regexp: regexp matching any SSS marker
  - sss--sealed-marker-regexp: regexp matching sealed SSS markers
  - SSS_PASSPHRASE injection in both sss--call-cli and sss--call-cli-region
  - keygen fix: sss-keygen now calls keys generate
affects:
  - 05-core-operations-ux (Wave 2: toggle-at-point depends on sss-encrypt-region/sss-decrypt-region)
  - 06-evil-doom (evil operators will use region encrypt/decrypt)

# Tech tracking
tech-stack:
  added: [auth-source (Emacs 27.1+ built-in, guarded with require nil t)]
  patterns:
    - call-process-region with separate stdout-buf + stderr-file pattern (mirrors sss--call-cli)
    - process-environment let-binding to inject SSS_PASSPHRASE before call-process
    - (require 'auth-source nil t) guard for optional built-in dependencies
    - auto-wrap plain text in ⊕{} before piping to sss seal -

key-files:
  created: []
  modified:
    - emacs/sss-mode.el

key-decisions:
  - "Modify sss--call-cli directly (not wrapper) so all existing callers automatically get auth-source passphrase injection"
  - "Auto-wrap plain text in ⊕{} before seal: if region does not start with ⊕{, wrap it first so arbitrary text becomes a sealed marker"
  - "Use (require 'auth-source nil t) guard: zero hard external dependencies; graceful fallback when unavailable"
  - "sss--call-cli-region mirrors sss--call-cli exactly: same (EXIT STDOUT STDERR) triple, same stderr temp file pattern"

patterns-established:
  - "stdin CLI invocation: sss--call-cli-region uses call-process-region with point-min/point-max in with-temp-buffer"
  - "passphrase injection: (let ((process-environment (cons SSS_PASSPHRASE=... process-environment))) ...) wraps call-process"
  - "region op error handling: pcase on (EXIT STDOUT STDERR) with (error ...) on non-zero exit"

requirements-completed: [CORE-01, CORE-02, CORE-04, UX-03]

# Metrics
duration: 6min
completed: 2026-02-21
---

# Phase 5 Plan 01: Core Operations & UX (Wave 1) Summary

**Region encrypt/decrypt via call-process-region stdin piping, auth-source passphrase injection in both CLI call paths, and keygen deprecation fix**

## Performance

- **Duration:** 6 min
- **Started:** 2026-02-21T19:10:22Z
- **Completed:** 2026-02-21T19:16:31Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Added `sss-encrypt-region` (C-c C-e) and `sss-decrypt-region` (C-c C-d) for in-place region operations using `sss seal -` / `sss open -` via stdin
- Added `sss--call-cli-region` as the stdin-based companion to `sss--call-cli`, following the exact same (EXIT STDOUT STDERR) triple pattern
- Added auth-source passphrase integration (`sss--get-passphrase`, `sss-use-auth-source`) injecting `SSS_PASSPHRASE` into `process-environment` for both CLI call paths
- Fixed deprecated `sss keygen` to `sss keys generate` in `sss-keygen`
- Added `sss--any-marker-regexp` and `sss--sealed-marker-regexp` constants for use by Wave 2 (toggle-at-point, overlays)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add sss--call-cli-region, region encrypt/decrypt, and keygen fix** - `26ef4ea` (feat)
2. **Task 2: Add auth-source integration and inject passphrase into sss--call-cli** - `d36cafd` (feat)

**Plan metadata:** (created in this commit)

## Files Created/Modified

- `emacs/sss-mode.el` - Added 106 lines: marker regexps, sss--get-passphrase, sss-use-auth-source defcustom, sss--call-cli-region, sss-encrypt-region, sss-decrypt-region, keygen fix, C-c C-e/C-c C-d bindings, SSS_PASSPHRASE injection in sss--call-cli

## Decisions Made

- **Auto-wrap plain text before seal:** `sss-encrypt-region` wraps the region in `⊕{...}` if it does not already start with that marker prefix. This ensures arbitrary text selected by the user becomes a sealed marker. The open question from research was resolved in the plan: wrap first, then seal.
- **Modify sss--call-cli directly:** Rather than wrapping it in `sss--call-cli-with-auth`, the passphrase injection was added directly to `sss--call-cli`'s `let*` binding. This means all existing callers (sss--open-buffer, sss--write-contents, sss-render-buffer, sss-init, sss-process, sss-keygen, sss-keys-list) automatically benefit without any changes.
- **auth-source warning in byte-compile acceptable:** The `auth-source-search` call generates a byte-compile warning "function not known to be defined" because the `(require 'auth-source nil t)` guard is checked at runtime. This is the correct pattern for optional built-ins and is not treated as an error.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Emacs batch compilation fails with exit code 255 when run from a relative path due to missing `/etc/emacs/site-start.d` on this system. Fixed by using absolute path and `-Q` flag (`emacs --batch -Q`). Not a code issue.

## User Setup Required

None - no external service configuration required. Auth-source passphrase lookup is opt-in (`sss-use-auth-source` defaults to `t` but gracefully returns `nil` if no entry found in `~/.authinfo`).

## Next Phase Readiness

- `sss-encrypt-region` and `sss-decrypt-region` are ready for Wave 2 (toggle-at-point in Plan 05-02 will dispatch to these)
- `sss--any-marker-regexp` and `sss--sealed-marker-regexp` are ready for overlay mode (Plan 05-03)
- `sss--call-cli-region` is the shared primitive for all stdin-based operations in Wave 2
- No blockers; file byte-compiles cleanly (one acceptable runtime-only warning for auth-source-search)

---
*Phase: 05-core-operations-ux*
*Completed: 2026-02-21*
