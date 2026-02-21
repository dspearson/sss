---
phase: 02-sss-mode-core
verified: 2026-02-21T16:00:00Z
status: passed
score: 5/5 success criteria verified
re_verification: false
human_verification:
  - test: "Open a real sealed .sss file in an interactive Emacs session"
    expected: "Buffer displays readable plaintext with ⊕{} markers visible; disk file stays sealed (hexdump shows ⊠{ prefix)"
    why_human: "Cannot test real keystore auto-authentication in batch mode — sss open requires live keyring access"
  - test: "Save the buffer after editing and inspect the file on disk"
    expected: "File on disk is re-sealed (⊠{ prefix bytes); Emacs does not prompt to save again; mode-line shows no ** modification indicator"
    why_human: "Two-step write-then-seal requires live sss binary with keyring access; set-visited-file-modtime behaviour verifiable only interactively"
  - test: "Force a decryption failure (e.g. by unsetting keyring) and open a sealed file"
    expected: "Minibuffer shows 'Sss-mode: decryption failed (exit N): ...' error message; buffer is not left empty or silently broken"
    why_human: "Requires live Emacs session with controlled keyring state"
  - test: "M-x customize-group RET sss RET"
    expected: "Customize buffer opens showing the 'sss' group with sss-executable path variable and its docstring"
    why_human: "customize-group only works in interactive Emacs; batch mode does not render the Customize UI"
---

# Phase 2: sss-mode Core Verification Report

**Phase Goal:** Opening a sealed file in Emacs transparently decrypts it; saving re-seals it on disk; failures are always visible
**Verified:** 2026-02-21T16:00:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (from Roadmap Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| SC1 | Opening a sealed file shows readable plaintext (⊕{} markers visible per EMAC-09); file on disk remains sealed | VERIFIED | `sss--open-buffer` calls `sss--call-cli (list "open") file` (line 105) — `open` preserves markers; `set-buffer-modified-p nil` (line 118) keeps buffer clean without disk write |
| SC2 | Saving re-seals the file on disk; plaintext never written as-is | VERIFIED | `sss--write-contents` writes plaintext then immediately calls `sss seal --in-place` (line 156); returns `t` on success to prevent default `write-region` fallthrough; signals `error` on failure (never `nil`) |
| SC3 | When decryption or sealing fails, error appears in minibuffer (not silent) | VERIFIED | `(error "Sss-mode: decryption failed (exit %d): %s" ...)` at line 126; `(error "Sss-mode: sealing failed (exit %d): %s" ...)` at line 168; `(error "Sss-mode: buffer has no associated file; cannot seal")` at line 148 |
| SC4 | Auto-save and backup disabled for decrypted buffer immediately on open | VERIFIED | Lines 110-112: `setq-local auto-save-default nil`, `auto-save-mode -1`, `setq-local backup-inhibited t` — all execute BEFORE `erase-buffer` at line 115 (timing correct) |
| SC5 | `M-x customize-group RET sss RET` shows sss-executable path variable | VERIFIED (auto) / HUMAN NEEDED (interactive) | `defgroup sss` at line 22 with `:group 'files :prefix "sss-"`; `defcustom sss-executable "sss"` at lines 27-32 with `:type 'string :group 'sss`; group wiring is correct |

**Score:** 5/5 success criteria verified (4 fully automated, 1 requires human for interactive Customize UI)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `emacs/sss-mode.el` | Complete sss-mode: foundation + open flow + save flow + mode definition | VERIFIED | 212 lines; loads in Emacs batch mode (`emacs --batch -Q -l emacs/sss-mode.el` outputs "loaded ok"); all 8 public functions defined |

**Artifact level checks:**

- **Level 1 (Exists):** `emacs/sss-mode.el` is present on disk — confirmed
- **Level 2 (Substantive):** 212 lines (exceeds min_lines: 180 from Plan 03); contains complete implementations of `sss--call-cli`, `sss--sealed-p`, `sss--find-file-hook`, `sss--open-buffer`, `sss--write-contents`, `sss-mode`, `sss-open-buffer`, `sss-seal-buffer` — not a stub
- **Level 3 (Wired):** All components connected: `magic-mode-alist` -> `sss--sealed-p` -> `sss-mode`; `find-file-hook` -> `sss--find-file-hook` -> `sss--open-buffer`; `write-contents-functions` -> `sss--write-contents`

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `magic-mode-alist` | `sss--sealed-p` | `cons #'sss--sealed-p #'sss-mode` MATCH-FUNCTION entry | WIRED | Line 79: `(add-to-list 'magic-mode-alist (cons #'sss--sealed-p #'sss-mode))` |
| `sss--call-cli` | `call-process` | stderr temp file pattern | WIRED | Line 46: `(make-temp-file "sss-stderr")`; line 51: `apply #'call-process ... (list stdout-buf stderr-file)` |
| `find-file-hook` | `sss--find-file-hook` | `add-hook` in mode body | WIRED | Line 195: `(add-hook 'find-file-hook #'sss--find-file-hook)` inside `define-derived-mode` body |
| `sss--open-buffer` | `sss--call-cli` | `"open"` subcommand | WIRED | Line 105: `(pcase (sss--call-cli (list "open") file)` |
| `sss--open-buffer` | `write-contents-functions` | buffer-local `add-hook` after successful decrypt | WIRED | Line 120: `(add-hook 'write-contents-functions #'sss--write-contents nil t)` — `nil t` = not prepended, buffer-local |
| `write-contents-functions` | `sss--write-contents` | buffer-local hook definition | WIRED | `sss--write-contents` defined at line 131; registered at line 120 |
| `sss--write-contents` | `sss--call-cli` | `seal --in-place` invocation | WIRED | Line 156: `(pcase (sss--call-cli (list "seal" "--in-place") file)` |
| `sss--write-contents` | `write-region` | recursion-safe binding | WIRED | Lines 152-153: `(let ((write-contents-functions nil)) (write-region (point-min) (point-max) file nil 'nomessage))` |
| `define-derived-mode` | `find-file-hook` | `add-hook` in mode body | WIRED | Line 195: `(add-hook 'find-file-hook #'sss--find-file-hook)` |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| EMAC-01 | 02-01 | sss-mode detects sealed files via magic bytes using `magic-mode-alist` | SATISFIED | `sss--sealed-p` predicate at lines 68-74; `magic-mode-alist` registration at line 79 with MATCH-FUNCTION variant (not regexp) |
| EMAC-02 | 02-02 | sss-mode auto-decrypts sealed files on open via `sss open` | SATISFIED | `sss--find-file-hook` at lines 89-94; `sss--open-buffer` calls `sss--call-cli (list "open") file` at line 105 |
| EMAC-03 | 02-03 | sss-mode re-seals buffer content on save using `write-contents-functions` | SATISFIED | `sss--write-contents` registered buffer-locally on `write-contents-functions` (line 120); returns `t` on success to intercept default write |
| EMAC-04 | 02-02 | sss-mode disables auto-save and backup files for decrypted buffers | SATISFIED | Lines 110-112: `auto-save-default nil`, `auto-save-mode -1`, `backup-inhibited t` — set BEFORE `erase-buffer` at line 115 (timing critical) |
| EMAC-05 | 02-01 | sss-mode uses `call-process` with exit code checking and stderr capture | SATISFIED | `sss--call-cli` uses `apply #'call-process` (line 51) with stdout buffer + stderr temp file; returns `(exit-code stdout stderr)` triple; all callers use `pcase` on the triple |
| EMAC-06 | 02-02, 02-03 | sss-mode provides clear error messages in minibuffer on failure | SATISFIED | `(error "Sss-mode: decryption failed...")` line 126; `(error "Sss-mode: sealing failed...")` line 168; `(error "Sss-mode: buffer has no associated file...")` line 148 — all use `error` not `message` |
| EMAC-07 | 02-01 | sss-mode defines a customization group with `sss-executable` path variable | SATISFIED | `defgroup sss` at line 22; `defcustom sss-executable "sss"` at lines 27-32 with `:type 'string :group 'sss` |
| EMAC-08 | 02-03 | sss-mode provides a named keymap with `C-c` prefix for commands | SATISFIED | `define-derived-mode` auto-creates `sss-mode-map`; `C-c s o` bound to `sss-open-buffer` (line 191); `C-c s s` bound to `sss-seal-buffer` (line 192) |
| EMAC-09 | 02-02 | sss-mode displays marker-visible plaintext (⊕{} markers shown, not stripped) | SATISFIED | `sss--call-cli (list "open") file` at line 105 — `open` subcommand preserves ⊕{} markers; `render` (which strips markers) is explicitly not used |

**Orphaned Requirements Check:** REQUIREMENTS.md maps EMAC-01 through EMAC-09 to Phase 2 — all 9 are claimed in the three plans (02-01: EMAC-01, EMAC-05, EMAC-07; 02-02: EMAC-02, EMAC-04, EMAC-06, EMAC-09; 02-03: EMAC-03, EMAC-06, EMAC-08). No orphaned requirements.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | — | No TODO/FIXME/placeholder/stub returns found | — | Clean |

No anti-patterns detected. Grep for `TODO`, `FIXME`, `HACK`, `PLACEHOLDER`, `return nil` (as a Lisp failure path) found no issues. The `return nil` comment at line 166 is a safety comment explaining why nil must NOT be returned — not an actual nil return.

---

### Human Verification Required

#### 1. Live Decrypt-on-Open

**Test:** In an interactive Emacs session with a working sss keyring, open a real sealed file: `M-x find-file RET /path/to/sealed.sss`
**Expected:** Buffer shows readable plaintext with ⊕{} markers visible (e.g. `⊕{key: value}`); hexdump of the file on disk still shows the `⊠{` byte sequence; mode-line shows `(SSS)` or text-mode
**Why human:** Real keystore auto-authentication cannot be tested in batch mode; requires live keyring access

#### 2. Live Re-seal-on-Save

**Test:** After opening a sealed file (test 1 above), edit a character, then save with `C-x C-s`
**Expected:** File on disk is re-sealed (hexdump shows `⊠{` prefix bytes); Emacs mode-line no longer shows `**`; no "Wrote FILE" message about plaintext; no kill-buffer prompt on next close
**Why human:** Two-step write-then-seal requires live sss binary; `set-visited-file-modtime` behaviour only observable interactively

#### 3. Failure Visibility

**Test:** With keyring unavailable (e.g. locked or removed), attempt `M-x find-file RET /path/to/sealed.sss`
**Expected:** Minibuffer shows red error: `Sss-mode: decryption failed (exit N): <stderr message>`; buffer is not left open with empty or garbled content
**Why human:** Controlled keyring failure state requires a live Emacs session

#### 4. Customize Group

**Test:** `M-x customize-group RET sss RET`
**Expected:** Customize buffer opens with heading "Sss" or "SSS", showing `Sss Executable` (or `sss-executable`) with its current value "sss" and the docstring about setting absolute path for daemon mode
**Why human:** `customize-group` only renders in interactive Emacs; batch mode does not support the Customize UI

---

### Security-Critical Correctness Notes

The following properties are verified at the code level and are security-critical:

1. **No nil return on seal failure (line 168):** `sss--write-contents` signals `(error ...)` on failure — never returns `nil`. A `nil` return would cause Emacs to fall through to the default `write-region`, writing plaintext to disk. This is correctly handled.

2. **Recursion prevention (line 152):** `(let ((write-contents-functions nil)) (write-region ...))` prevents `sss--write-contents` from calling itself when writing the temporary plaintext. This is the standard pattern from `epa-file.el`.

3. **Timing of auto-save disable (lines 110-115):** Auto-save and backup are disabled at lines 110-112, before `erase-buffer` at line 115. This prevents a window where a partially-decrypted buffer could be auto-saved. The comment confirms this is intentional.

4. **Buffer-local hook registration (line 120):** `(add-hook 'write-contents-functions #'sss--write-contents nil t)` — the trailing `t` argument makes this buffer-local. The save hook only applies to decrypted sss buffers, not globally.

---

### Gaps Summary

No gaps. All 5 roadmap success criteria are satisfied at the code level. All 9 EMAC requirements (EMAC-01 through EMAC-09) are implemented and wired. The single deliverable `emacs/sss-mode.el` is substantive (212 lines), loads in Emacs batch mode, and contains no stubs or placeholders.

Four items are flagged for human verification because they require live keyring access or an interactive Emacs session, which cannot be tested programmatically. These are expected for any Emacs mode that interfaces with external encryption tooling.

---

_Verified: 2026-02-21T16:00:00Z_
_Verifier: Claude (gsd-verifier)_
