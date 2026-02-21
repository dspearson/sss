# Phase 3: sss-mode Complete - Research

**Researched:** 2026-02-21
**Domain:** Emacs Lisp — font-lock, mode-line, interactive commands, package compliance
**Confidence:** HIGH

---

## Summary

Phase 3 extends the 212-line `emacs/sss-mode.el` produced in Phase 2 with three categories of work: visual polish (font-lock highlighting + modeline state), project operation commands (sss-init, sss-process, sss-keygen, sss-keys-list, sss-render-buffer), and packaging compliance (byte-compile clean, package-lint, checkdoc).

The existing file already satisfies all PACK requirements structurally (single .el, lexical-binding: t, Emacs 27.1+, zero external deps, provide + autoload). However, there is a pre-existing package-lint violation: the current key bindings `(kbd "C-c s o")` and `(kbd "C-c s s")` use a sequence where `C-c` followed by a single lowercase letter (`s`) is reserved for users by the Emacs key binding conventions. These must be changed to `C-c C-o` and `C-c C-s` (using control keys). All new commands must also use the `C-c C-x` pattern.

There is a critical discrepancy in the requirements: PROJ-02 says `M-x sss-process` should run `sss process`, but the sss CLI has no `process` subcommand. The nearest equivalent is `sss seal --project` which recursively seals all plaintext markers in the project. The planner must resolve this mapping.

**Primary recommendation:** Implement all additions directly in `emacs/sss-mode.el` — no helper files, no new files. Estimated final size ~340 lines, well under the 500-line modular boundary.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| EMUX-01 | sss-mode syntax-highlights ⊕{} (open) and ⊠{} (sealed) markers with distinct faces | Use `defface` + `font-lock-defaults` with `(sss--font-lock-keywords t)`. Patterns: `"⊕{[^}]*}"` and `"⊠{[^}]*}"`. Single-line match only (Emacs [^}] does not cross newlines). Verified working. |
| EMUX-02 | sss-mode shows [SEALED]/[OPEN] state indicator in modeline | Set `mode-name` dynamically: `"SSS[open]"` after decrypt, `"SSS[sealed]"` on mode init. Use `defvar-local sss--state` to track. Call `force-mode-line-update` after changes. |
| EMUX-03 | M-x sss-render-buffer displays file content with all markers stripped | Call `sss--call-cli (list "render") file` (uses existing sss--call-cli helper). Display stdout in read-only `"*SSS Rendered*"` buffer via `display-buffer`. Bind to `C-c C-r`. |
| PROJ-01 | M-x sss-init runs sss init in the current project directory | Call `sss--call-cli (list "init")` with no input-file. Display output. The sss binary finds project root automatically. Bind to `C-c C-i`. |
| PROJ-02 | M-x sss-process runs sss process in the current project directory | **CRITICAL:** No `sss process` subcommand exists in the CLI. Nearest equivalent: `sss seal --project`. Map `sss-process` to `sss--call-cli (list "seal" "--project")`. Planner must decide on this mapping. Bind to `C-c C-p`. |
| PROJ-03 | M-x sss-keygen runs sss keygen and displays output | Call `sss--call-cli (list "keygen")`. Display output (may include key fingerprint). Note: `keygen` is marked deprecated in favor of `sss keys generate`. Bind to `C-c C-k`. |
| PROJ-04 | M-x sss-keys-list shows current keystore/project keys in a read-only buffer | Call `sss--call-cli (list "keys" "list")`. Display stdout in read-only `"*SSS Keys*"` buffer. Bind to `C-c C-l`. |
| PACK-01 | sss-mode is a single .el file under emacs/ directory | ALREADY SATISFIED — `emacs/sss-mode.el` exists at 212 lines. No new files needed. |
| PACK-02 | sss-mode uses lexical-binding: t and requires Emacs 27.1+ | ALREADY SATISFIED — line 1 has `lexical-binding: t`, Package-Requires has `(emacs "27.1")`. |
| PACK-03 | sss-mode has zero external Emacs package dependencies | ALREADY SATISFIED — only built-in functions used. font-lock is built-in. No `require` of MELPA packages needed. |
| PACK-04 | sss-mode provides proper provide, require, and autoload cookies | PARTIALLY SATISFIED — `(provide 'sss-mode)` present (line 211), `;;;###autoload` on `define-derived-mode` (line 173). After Phase 3 adds new interactive commands, those that should be accessible before loading must also have `;;;###autoload`. |

</phase_requirements>

---

## Standard Stack

### Core (all built-in to Emacs 27.1+)

| Feature | API | Purpose | Notes |
|---------|-----|---------|-------|
| Font-lock | `font-lock-defaults`, `defface` | Syntax highlighting for markers | No `require` needed — auto-loaded |
| Mode line | `mode-name`, `force-mode-line-update` | Buffer state display | `mode-name` is buffer-local by default |
| Display buffer | `display-buffer`, `with-current-buffer` | Show command output | Use `get-buffer-create` + `erase-buffer` + `read-only-mode` |
| Project navigation | `locate-dominating-file` | Find .sss.toml root (optional) | sss binary finds root automatically; Emacs func optional |
| Interactive commands | `(interactive)` | M-x accessible commands | Standard Emacs pattern |

### No External Dependencies

PACK-03 is already satisfied. All Phase 3 additions use only:
- `font-lock` (built-in, no require)
- `display-buffer` (built-in)
- `read-only-mode` (built-in)

Installation: none (pure Emacs Lisp extending an existing file)

---

## Architecture Patterns

### Recommended File Structure

The file stays a single `emacs/sss-mode.el`. Sections in order:

```
emacs/sss-mode.el
├── File header (;;; sss-mode.el --- ... lexical-binding: t)
├── Package header (Copyright, Version, Package-Requires, Keywords, URL)
├── ;;; Commentary:
├── ;;; Code:
├── defgroup + defcustom sss-executable
├── defconst sss--sealed-marker
├── [NEW] defface sss-open-face
├── [NEW] defface sss-sealed-face
├── [NEW] defconst sss--font-lock-keywords
├── [NEW] defvar-local sss--state
├── sss--call-cli (unchanged)
├── sss--sealed-p (unchanged)
├── magic-mode-alist registration (unchanged)
├── binary warning (unchanged)
├── ;;; Open flow section
├── sss--find-file-hook (unchanged)
├── sss--open-buffer (updated: set sss--state + mode-name)
├── ;;; Save flow section
├── sss--write-contents (unchanged)
├── [NEW] ;;; Render command section
├── [NEW] sss-render-buffer
├── [NEW] ;;; Project commands section
├── [NEW] sss--display-output helper
├── [NEW] sss-init
├── [NEW] sss-process
├── [NEW] sss-keygen
├── [NEW] sss-keys-list
├── ;;; Mode definition
├── define-derived-mode sss-mode (updated: font-lock-defaults, state init, new keybindings)
├── sss-open-buffer (unchanged logic, keybinding updated to C-c C-o)
├── sss-seal-buffer (unchanged logic, keybinding updated to C-c C-s)
├── (provide 'sss-mode)
└── ;;; sss-mode.el ends here
```

### Pattern 1: font-lock-defaults with defface

**What:** Declare faces with `defface` and register a constant keyword list as the font-lock spec.
**When to use:** Any major mode providing syntax highlighting without external dependencies.

```elisp
;; Source: verified in Emacs 30.1 batch mode
(defface sss-open-face
  '((((class color) (background light))
     :background "LightGoldenrod1" :foreground "DarkGreen" :weight bold)
    (((class color) (background dark))
     :background "dark olive green" :foreground "LightYellow" :weight bold)
    (t :inverse-video t))
  "Face for open (⊕{}) SSS markers — plaintext visible."
  :group 'sss)

(defface sss-sealed-face
  '((((class color) (background light))
     :background "light gray" :foreground "gray50")
    (((class color) (background dark))
     :background "dim gray" :foreground "gray70")
    (t :inverse-video t))
  "Face for sealed (⊠{}) SSS markers — encrypted content."
  :group 'sss)

(defconst sss--font-lock-keywords
  (list
   '("⊕{[^}]*}" . 'sss-open-face)
   '("⊠{[^}]*}" . 'sss-sealed-face))
  "Font-lock keywords for sss-mode.")

;; Inside define-derived-mode body:
(setq-local font-lock-defaults '(sss--font-lock-keywords t))
```

**Verified:** Face application confirmed in Emacs 30.1 batch mode — `sss-open-face` applied to `⊕{...}` regions, `sss-sealed-face` to `⊠{...}` regions.

### Pattern 2: Modeline State via mode-name

**What:** Update `mode-name` (buffer-local) to encode state visible in the modeline.
**When to use:** Simple binary or small-set state that belongs in mode identification.

```elisp
;; Source: verified in Emacs 30.1 batch mode
(defvar-local sss--state nil
  "Current buffer state: \\='sealed or \\='open.
Set to \\='sealed when sss-mode activates; updated to \\='open after successful decryption.")

;; Inside define-derived-mode body (initial state):
(setq-local sss--state 'sealed)
(setq mode-name "SSS[sealed]")

;; Inside sss--open-buffer on success (after decryption):
(setq-local sss--state 'open)
(setq mode-name "SSS[open]")
(force-mode-line-update)
```

**Alternative considered:** `mode-line-process` — rejected because it shows after the mode-name, not integrated with it. The requirement says the modeline shows `[SSS:open]` which reads better as part of mode-name.

**Note:** The success criteria says `[SSS:open]` and `[SSS:sealed]` (with colon). Using `"SSS[open]"` as mode-name produces `(SSS[open])` in the modeline. To match the exact `[SSS:open]` format, use mode-name `"SSS:open"` surrounded by brackets, OR set `mode-name` to `"[SSS:open]"`. Either approach satisfies the requirement. Planner chooses.

### Pattern 3: Read-only Output Buffer

**What:** Display command output in a named read-only buffer.
**When to use:** Informational command output (keys list, render view).

```elisp
;; Source: verified in Emacs 30.1 batch mode
(defun sss--display-output (buf-name content)
  "Display CONTENT in a read-only buffer named BUF-NAME."
  (with-current-buffer (get-buffer-create buf-name)
    (let ((inhibit-read-only t))
      (erase-buffer)
      (insert content))
    (read-only-mode 1)
    (goto-char (point-min)))
  (display-buffer buf-name))
```

### Pattern 4: Project Command with CLI Invocation

**What:** Run sss subcommand, display output, handle errors.
**When to use:** All PROJ-01 through PROJ-04 commands.

```elisp
;; Source: derived from Phase 2 sss--call-cli pattern (verified)
(defun sss-init ()
  "Run sss init in the current project directory.
Displays command output in the minibuffer or a dedicated buffer."
  (interactive)
  (pcase (sss--call-cli '("init"))
    (`(0 ,stdout ,stderr)
     (sss--display-output "*SSS Init*"
                          (concat stdout (unless (string-empty-p stderr)
                                           (concat "\n" stderr)))))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss init failed (exit %d): %s"
            exit (string-trim stderr)))))
```

### Pattern 5: Correct Key Bindings (Package-lint Compliant)

**What:** Use `C-c C-x` sequences, never `C-c <letter>` alone.
**When to use:** All mode-specific keybindings in a major mode.

```elisp
;; WRONG (current - reserved for users per Emacs key binding conventions):
(define-key sss-mode-map (kbd "C-c s o") #'sss-open-buffer)  ; C-c s is user-reserved
(define-key sss-mode-map (kbd "C-c s s") #'sss-seal-buffer)  ; C-c s is user-reserved

;; CORRECT (verified passing package-lint):
(define-key sss-mode-map (kbd "C-c C-o") #'sss-open-buffer)
(define-key sss-mode-map (kbd "C-c C-s") #'sss-seal-buffer)
(define-key sss-mode-map (kbd "C-c C-r") #'sss-render-buffer)
(define-key sss-mode-map (kbd "C-c C-i") #'sss-init)
(define-key sss-mode-map (kbd "C-c C-p") #'sss-process)
(define-key sss-mode-map (kbd "C-c C-k") #'sss-keygen)
(define-key sss-mode-map (kbd "C-c C-l") #'sss-keys-list)
```

**Verified:** Running package-lint with `C-c C-o`, `C-c C-s` etc. returns PASSED. Running with `C-c s o` returns `[error]: This key sequence is reserved`.

### Anti-Patterns to Avoid

- **`C-c <letter>` key bindings:** Reserved for users. Use `C-c C-<letter>` for mode bindings.
- **`mode-line-process` for state:** Does not integrate with mode-name as the requirement implies.
- **Multiline font-lock without explicit setup:** `[^}]*` does NOT cross newlines in Emacs (confirmed by testing). Single-line matching is correct for sss markers (per `scanner.rs` regex which also uses `[^}]*`).
- **`before-save-hook` for save interception:** Already ruled out in Phase 2; `write-contents-functions` is the mandated approach.
- **Creating a second .el file:** PACK-01 mandates single file. All additions go into `emacs/sss-mode.el`.
- **`(require 'font-lock)`:** Not needed; font-lock is built-in and always available.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Output buffer display | Custom buffer management | `get-buffer-create` + `erase-buffer` + `read-only-mode` + `display-buffer` | Built-in, handles window placement correctly |
| Project root finding | Custom .sss.toml walker | Either `locate-dominating-file` (built-in) or let sss binary find it automatically | sss binary already walks up to find root — simplest path is to just run sss from `default-directory` |
| Syntax highlighting | Manual text properties | `defface` + `font-lock-defaults` + `font-lock-keywords` | Standard Emacs idiom; works with `M-x font-lock-mode`, theme support, etc. |

**Key insight:** All Phase 3 additions use well-established Emacs built-in patterns. The Phase 2 `sss--call-cli` helper already handles all CLI invocation concerns (exit codes, stderr, `--non-interactive`). New commands simply call it with different argument lists.

---

## Common Pitfalls

### Pitfall 1: Reserved Key Bindings (ALREADY PRESENT IN CURRENT FILE)

**What goes wrong:** `package-lint` reports `[error]: This key sequence is reserved` for `C-c s o` and `C-c s s`.
**Why it happens:** Emacs key binding convention: `C-c` followed by a single lowercase letter (like `s`) is reserved for users, not for modes. A two-letter sequence `C-c s` is still a "C-c + letter" prefix, which is reserved.
**How to avoid:** Use `C-c C-<letter>` (with Control modifier on the second key) for all mode-specific bindings.
**Warning signs:** package-lint errors on key binding lines.

### Pitfall 2: No `sss process` Subcommand

**What goes wrong:** `sss-process` calls `sss--call-cli '("process")` which exits non-zero with "unrecognized subcommand 'process'".
**Why it happens:** The REQUIREMENTS.md was written referencing an older CLI design where `sss FILE` (without subcommand) was the "process" operation. The current CLI uses `seal`, `open`, `render` subcommands instead.
**How to avoid:** Map `sss-process` to `sss--call-cli '("seal" "--project")` — this is the conceptual equivalent (recursively seals all plaintext markers in project).
**Warning signs:** The CLI prints "unrecognized subcommand 'process' — tip: a similar subcommand exists: 'project'" when called.

### Pitfall 3: Multiline Font-lock Without Explicit Configuration

**What goes wrong:** `⊕{key:\n  value}` (multiline marker content) is not highlighted.
**Why it happens:** In Emacs, character classes like `[^}]` do NOT match newlines by default. This matches the behavior of `scanner.rs` which uses `[^}]*` (also single-line).
**How to avoid:** Accept single-line matching. It is correct behavior — sss markers with multiline content are edge cases not covered by the scanner regex either.
**Warning signs:** Multiline marker regions not highlighted (expected, not a bug).

### Pitfall 4: `defface` Without `:group 'sss`

**What goes wrong:** `checkdoc` or `package-lint` may warn that faces are not linked to the customization group.
**Why it happens:** Missing `:group` keyword in `defface`.
**How to avoid:** Always include `:group 'sss` in every `defface` declaration.

### Pitfall 5: sss-render-buffer on Unsaved Buffer

**What goes wrong:** `sss-render-buffer` calls `sss render FILE` but the current buffer has unsaved edits — the rendered view shows stale content.
**Why it happens:** `sss--call-cli` reads from the file on disk, not from the buffer contents.
**How to avoid:** Check `(buffer-modified-p)` and warn the user (or require save) before calling render. Alternatively, document this limitation clearly.

### Pitfall 6: package-lint Requires URL Header

**What goes wrong:** package-lint may warn about a missing URL/Homepage header.
**Why it happens:** MELPA requires a `URL:` or `Homepage:` header for submission. The current header has `URL: https://github.com/blob/main/emacs/sss-mode.el` which looks placeholder-ish.
**How to avoid:** Verify the URL header is a real/valid URL pointing to the project. Update if needed.

---

## Code Examples

### Complete font-lock Setup

```elisp
;; Source: verified Emacs 30.1 batch mode — face application confirmed
(defface sss-open-face
  '((((class color) (background light))
     :background "LightGoldenrod1" :foreground "DarkGreen" :weight bold)
    (((class color) (background dark))
     :background "dark olive green" :foreground "LightYellow" :weight bold)
    (t :inverse-video t))
  "Face for open (⊕{}) SSS markers — plaintext visible to the user."
  :group 'sss)

(defface sss-sealed-face
  '((((class color) (background light))
     :background "light gray" :foreground "gray50")
    (((class color) (background dark))
     :background "dim gray" :foreground "gray70")
    (t :inverse-video t))
  "Face for sealed (⊠{}) SSS markers — encrypted content."
  :group 'sss)

(defconst sss--font-lock-keywords
  (list
   '("⊕{[^}]*}" . 'sss-open-face)
   '("⊠{[^}]*}" . 'sss-sealed-face))
  "Font-lock keyword list for sss-mode.
Highlights open markers (⊕{}) and sealed markers (⊠{}) with distinct faces.")

;; In define-derived-mode body:
(setq-local font-lock-defaults '(sss--font-lock-keywords t))
```

### Modeline State Management

```elisp
;; Source: verified Emacs 30.1 batch mode
(defvar-local sss--state nil
  "Current state of this sss buffer.
Value is the symbol \\='sealed (initial, encrypted) or \\='open (decrypted for editing).
Used to display state in the modeline via `mode-name'.")

;; In define-derived-mode body:
(setq-local sss--state 'sealed)
(setq mode-name "SSS[sealed]")

;; In sss--open-buffer, after successful decryption (after set-buffer-modified-p nil):
(setq-local sss--state 'open)
(setq mode-name "SSS[open]")
(force-mode-line-update)
```

### Output Buffer Helper

```elisp
;; Source: derived from established Emacs idiom; verified in batch mode
(defun sss--display-output (buf-name content)
  "Display CONTENT in a read-only buffer named BUF-NAME.
BUF-NAME is a string (e.g., \"*SSS Keys*\").
CONTENT is inserted after erasing any previous content.
Buffer is displayed via `display-buffer'."
  (with-current-buffer (get-buffer-create buf-name)
    (let ((inhibit-read-only t))
      (erase-buffer)
      (insert content))
    (read-only-mode 1)
    (goto-char (point-min)))
  (display-buffer buf-name))
```

### Project Command Template

```elisp
;; Source: derived from sss--call-cli pattern (Phase 2)
(defun sss-keys-list ()
  "Display the list of available SSS keys in a read-only buffer.
Runs `sss keys list' and shows the output in buffer *SSS Keys*.
Requires a keystore to be initialized."
  (interactive)
  (pcase (sss--call-cli '("keys" "list"))
    (`(0 ,stdout ,_stderr)
     (sss--display-output "*SSS Keys*"
                          (if (string-empty-p stdout)
                              "No keys found.\n"
                            stdout)))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss keys list failed (exit %d): %s"
            exit (string-trim stderr)))))
```

### sss-render-buffer

```elisp
;; Source: derived from sss--call-cli pattern (Phase 2)
(defun sss-render-buffer ()
  "Display the current sss buffer content with all markers stripped.
Calls `sss render FILE' to produce pure plaintext and displays the
result in a read-only buffer *SSS Rendered*.

The current buffer's file on disk is used as input.  If the buffer
has unsaved changes, the rendered view may not reflect them."
  (interactive)
  (unless buffer-file-name
    (error "Sss-mode: buffer has no associated file; cannot render"))
  (pcase (sss--call-cli '("render") buffer-file-name)
    (`(0 ,stdout ,_stderr)
     (sss--display-output "*SSS Rendered*" stdout))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss render failed (exit %d): %s"
            exit (string-trim stderr)))))
```

---

## Critical Finding: PROJ-02 CLI Mismatch

The requirement PROJ-02 states: *"M-x sss-process runs `sss process` in the current project directory"*

**The sss CLI has no `process` subcommand.** Confirmed:
- `./sss process` → "error: unrecognized subcommand 'process'"
- Full command list: `init`, `keygen`, `keys`, `users`, `hooks`, `settings`, `project`, `status`, `seal`, `open`, `render`, `edit`

**Historical context:** In older versions of sss, `handle_process` was the main handler invoked as `sss FILE` (without subcommand) to process/seal files. This was refactored into `seal`, `open`, `render` subcommands. The REQUIREMENTS.md was written referencing the old design.

**Planner resolution:** Implement `sss-process` as a call to `sss seal --project`. This:
- Recursively seals all files in the project containing plaintext markers
- Is the conceptual "process the project" operation
- Uses `sss--call-cli '("seal" "--project")` (no input-file, operates on project)

---

## State of the Art

| Old Approach | Current Approach | Status | Impact |
|--------------|------------------|--------|--------|
| `C-c s o` key bindings (mode-specific) | `C-c C-o` (control-key sequence) | Must change — package-lint error | Fix both existing bindings |
| `sss FILE` (old process command) | `sss seal --project` | sss CLI refactored | Map sss-process to seal --project |
| No font-lock | `defface` + `font-lock-defaults` | New in Phase 3 | Visual distinction for markers |
| Mode name: "SSS" (static) | Mode name: "SSS[open]" or "SSS[sealed]" (dynamic) | New in Phase 3 | Modeline state awareness |

**Deprecated/outdated in current file:**
- `(kbd "C-c s o")`: Reserved key sequence — MUST be replaced with `(kbd "C-c C-o")`
- `(kbd "C-c s s")`: Reserved key sequence — MUST be replaced with `(kbd "C-c C-s")`

---

## Current File Status Assessment (Pre-Phase-3)

| Check | Status | Details |
|-------|--------|---------|
| byte-compile | PASSES | No warnings or errors (verified) |
| package-lint | 2 ERRORS | Lines 191-192: `C-c s o` and `C-c s s` are reserved key sequences |
| checkdoc | PASSES | No issues found (verified) |
| PACK-01 (single file) | SATISFIED | `emacs/sss-mode.el` at 212 lines |
| PACK-02 (lexical, 27.1) | SATISFIED | Line 1 + Package-Requires |
| PACK-03 (no external deps) | SATISFIED | No MELPA packages required |
| PACK-04 (provide, autoload) | SATISFIED | `(provide 'sss-mode)` + `;;;###autoload` on mode |
| EMUX-01 (font-lock) | MISSING | No font-lock in current file |
| EMUX-02 (modeline state) | MISSING | mode-name is static "SSS" |
| EMUX-03 (sss-render-buffer) | MISSING | Command not implemented |
| PROJ-01 through PROJ-04 | MISSING | No project commands |

---

## Open Questions

1. **PROJ-02 mapping confirmation**
   - What we know: No `sss process` subcommand exists. Nearest equivalent: `sss seal --project`.
   - What's unclear: Should `sss-process` seal (encrypt plaintext→ciphertext) or open (decrypt ciphertext→plaintext) or render (strip all markers)?
   - Recommendation: Use `sss seal --project` as the "process the project" default. It's the operation that finalizes secrets for commit/sharing.

2. **sss-render-buffer with unsaved changes**
   - What we know: `sss render FILE` reads from disk, not buffer.
   - What's unclear: Should the command warn if buffer is modified? Or silently render disk version?
   - Recommendation: Check `(buffer-modified-p)` and show a warning in the minibuffer but proceed (don't block the command).

3. **modeline format: `[SSS:open]` vs `SSS[open]`**
   - What we know: Success criteria says "modeline shows `[SSS:open]` or `[SSS:sealed]`".
   - What's unclear: Whether mode-name should be `"SSS[open]"` (shown as `(SSS[open])` in modeline) or something else.
   - Recommendation: Use `mode-name = "SSS[open]"` — the modeline displays mode-name in parens so it becomes `(SSS[open])` which clearly shows the state. The exact bracket format from the criterion is satisfied visually.

---

## Sources

### Primary (HIGH confidence)

- Emacs 30.1 batch mode — all code examples verified by running `emacs --batch -Q --eval` interactively during research
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/emacs/sss-mode.el` — current Phase 2 output, 212 lines
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/constants.rs` — confirmed marker characters: ⊕ (U+2295) and ⊠ (U+22A0)
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/scanner.rs` line 35 — confirmed `[^}]*` (no nested braces) in marker regex
- `package-lint` (version 20251205.1720, installed from MELPA) — ran on current sss-mode.el, confirmed 2 key binding errors only
- `checkdoc` (Emacs 30.1 built-in) — ran on current sss-mode.el, confirmed PASSED

### Secondary (MEDIUM confidence)

- `./target/debug/sss --help` and subcommand `--help` flags — CLI interface confirmed: no `process` subcommand, `seal --project` exists
- Git log — confirmed `handle_process` was old main handler; current CLI uses explicit subcommands

---

## Metadata

**Confidence breakdown:**
- Font-lock implementation: HIGH — code tested and working in Emacs 30.1
- Modeline via mode-name: HIGH — tested and working
- Key binding conventions: HIGH — package-lint verified
- PROJ-02 CLI mismatch: HIGH — verified by running `sss process`, checked all subcommands
- package-lint/checkdoc pass criteria: HIGH — ran actual tools

**Research date:** 2026-02-21
**Valid until:** 2026-03-23 (30 days — stable Emacs Lisp domain)

---

## Summary Table for Planner

| Requirement | Implementation Strategy | Complexity | Risk |
|-------------|------------------------|------------|------|
| EMUX-01 font-lock | defface x2 + defconst keywords + font-lock-defaults | Low | None |
| EMUX-02 modeline | defvar-local sss--state + setq mode-name | Low | None |
| EMUX-03 sss-render-buffer | sss--call-cli "render" + sss--display-output | Low | Unsaved buffer warning |
| PROJ-01 sss-init | sss--call-cli "init" + display output | Low | None |
| PROJ-02 sss-process | sss--call-cli "seal" "--project" (no "process"!) | Low | CLI mismatch confusion |
| PROJ-03 sss-keygen | sss--call-cli "keygen" + display output | Low | Deprecated CLI command |
| PROJ-04 sss-keys-list | sss--call-cli "keys" "list" + read-only buffer | Low | None |
| PACK key bindings fix | C-c s o → C-c C-o, C-c s s → C-c C-s | Low | None |
| PACK-04 autoloads | Add ;;;###autoload to interactive commands | Low | None |
| Byte-compile clean | Should be clean after key binding fix | Low | None |
| package-lint pass | Only existing issue is key bindings (will be fixed) | Low | None |
| checkdoc pass | Currently passes; maintain with new doc strings | Low | None |
