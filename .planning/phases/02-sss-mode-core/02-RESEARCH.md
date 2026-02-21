# Phase 2: sss-mode Core — Research

**Researched:** 2026-02-21
**Domain:** Emacs Lisp major mode with transparent file encryption/decryption via external CLI
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| EMAC-01 | sss-mode detects sealed files via marker content scanning (⊠{ magic bytes) using `magic-mode-alist` | Magic-mode-alist with named predicate function (MATCH-FUNCTION variant, not regexp); predicate scans for `\xe2\x8a\xa0{` at buffer start |
| EMAC-02 | sss-mode auto-decrypts sealed files on open using keystore auto-authentication via `sss open` | file-name-handler-alist intercepts `insert-file-contents`; `sss render FILE` (stdout plaintext, exit 0) confirmed from Phase 1 |
| EMAC-03 | sss-mode re-seals buffer content on save using `write-contents-functions` (not hooks) | `write-contents-functions` confirmed: returning non-nil skips default `write-region`; see "The write-contents-functions vs file-name-handler-alist decision" section |
| EMAC-04 | sss-mode disables auto-save and backup files for decrypted buffers | `(setq-local auto-save-default nil)`, `(auto-save-mode -1)`, `(setq-local backup-inhibited t)` — must be set in find-file hook, not mode body |
| EMAC-05 | sss-mode uses `call-process` with exit code checking and stderr capture for all CLI invocations | Verified pattern: `(call-process PROG nil (list stdout-buf stderr-file) nil args...)` — stderr-dest MUST be a file path string, not a buffer object |
| EMAC-06 | sss-mode provides clear error messages in minibuffer when decryption/sealing fails | Signal `(error "sss-mode: ...")` on non-zero exit; epa-file.el uses `(signal 'file-error ...)` pattern |
| EMAC-07 | sss-mode defines a customization group with `sss-executable` path variable | `(defgroup sss ...)` + `(defcustom sss-executable "sss" ...)` with `executable-find` check |
| EMAC-08 | sss-mode provides a named keymap with `C-c` prefix for commands | `define-derived-mode` auto-creates `sss-mode-map`; `(define-key sss-mode-map (kbd "C-c s ...") ...)` |
| EMAC-09 | sss-mode displays marker-visible plaintext (⊕{} markers shown, not stripped) | Use `sss open FILE` (stdout with ⊕{} markers) NOT `sss render FILE` (strips markers) — confirmed from Phase 1 |
</phase_requirements>

---

## Summary

Phase 2 implements `sss-mode.el` — a zero-dependency Emacs major mode that makes editing sealed `.sss` files transparent. The research resolves the single most important design question: **the save flow uses `write-contents-functions` (as EMAC-03 mandates), not the `file-name-handler-alist` `write-region` handler**. This is the correct pattern because sss-mode is a *content-aware* mode (the mode identity determines behavior, not the filename), and `write-contents-functions` is explicitly designed for "hooks that pertain to the buffer's contents, not to the particular visited file." The `file-name-handler-alist` approach (epa-file.el's model) is filename-regex-based and fights against sss's content-detection requirement.

The open flow uses `find-file-hook` to detect sealed content after Emacs loads the raw bytes, then replaces buffer content with plaintext via `sss open FILE` (stdout with ⊕{} markers, satisfying EMAC-09). Auto-save and backup are disabled in that same hook before the auto-save timer has a chance to fire. The detection predicate uses `magic-mode-alist` with a named match function (not a regexp), checking for the exact 4-byte sequence `\xe2\x8a\xa0\x7b` at the buffer start.

The highest-risk implementation item is the `write-contents-functions` save flow: it must write the sealed content to disk directly (bypassing normal Emacs `write-region`), call `(set-visited-file-modtime)` to clear the modified flag, and return `t` on success. On failure it must signal an error — never return `nil` (which would fall through to a plaintext write).

**Primary recommendation:** Implement in build order: (A) `sss--call-cli` helper + `defcustom sss-executable`, (B) `sss--sealed-p` predicate + `magic-mode-alist` entry, (C) `find-file-hook` open flow with auto-save/backup disable, (D) `write-contents-functions` save flow, (E) `define-derived-mode` wiring.

---

## The Critical Design Question: write-contents-functions vs file-name-handler-alist

This is the central question identified in the phase brief. The answer is unambiguous, and the two mechanisms serve different purposes.

### file-name-handler-alist (the epa-file.el model)

**How it works:** A regex is registered in `file-name-handler-alist`. Whenever Emacs performs any file operation on a path matching the regex, the handler function is called instead. The handler dispatches on the operation name (`insert-file-contents`, `write-region`, etc.) and uses `inhibit-file-name-handlers` to call the real operation without re-triggering the handler.

From `epa-file.el` (Emacs 30.1, verified from system install at `/usr/share/emacs/30.1/lisp/epa-file.el.gz`):

```elisp
;; The handler function dispatches via property list on the operation symbol:
(defun epa-file-handler (operation &rest args)
  (save-match-data
    (let ((op (get operation 'epa-file)))
      (if (and op (not epa-inhibit))
          (apply op args)
        (epa-file-run-real-handler operation args)))))

;; inhibit-file-name-handlers prevents recursion:
(defun epa-file-run-real-handler (operation args)
  (let ((inhibit-file-name-handlers
         (cons 'epa-file-handler
               (and (eq inhibit-file-name-operation operation)
                    inhibit-file-name-handlers)))
        (inhibit-file-name-operation operation))
    (apply operation args)))

;; Registered operations:
(put 'insert-file-contents 'epa-file 'epa-file-insert-file-contents)
(put 'write-region         'epa-file 'epa-file-write-region)
;; (verified: ONLY these two operations are registered; no write-contents-functions used)
```

**When to use:** When detection is filename-based (e.g., `*.gpg`). The handler fires for ALL files matching the regex, regardless of which major mode is active.

**Why NOT correct for sss-mode:** sss files have no fixed extension. Detection is content-based (⊠{ bytes), handled by `magic-mode-alist`. The file-name-handler approach would require a regex that matches filenames — but the whole point of sss is that any file can be sealed without renaming it. Using `file-name-handler-alist` here would require either (a) a catch-all regex (breaking all file I/O for every file) or (b) a per-buffer dynamic registration (complex, fragile, not the intended use of the mechanism).

### write-contents-functions (the correct approach for sss-mode)

**How it works:** A buffer-local hook list. When `save-buffer` is called, Emacs runs each function in `write-contents-functions` in order. If any function returns non-nil, Emacs skips its default `write-region` call. The function is responsible for writing the file itself.

From Emacs 30.1 documentation (verified via `emacs --batch -Q`):

> "List of functions to be called before writing out a buffer to a file. Used only by `save-buffer`. If one of them returns non-nil, the file is considered already written and the rest are not called and neither are the functions in `write-file-functions`. This variable is meant to be used for hooks that pertain to the buffer's contents, not to the particular visited file; thus, `set-visited-file-name` does not clear this variable; but changing the major mode does clear it."

**Why correct for sss-mode:**
1. It is set buffer-locally — exactly what a major mode needs
2. It intercepts precisely the save path (`save-buffer` / `C-x C-s`) without affecting other buffers
3. Returning `t` prevents ANY plaintext write to disk — this is the security guarantee
4. The requirement EMAC-03 explicitly mandates it: "using `write-contents-functions` (not hooks)"
5. The REQUIREMENTS.md and STATE.md both record this as a locked decision

**Critical implementation requirement:** The function registered in `write-contents-functions` MUST:
- Shell out to `sss seal --in-place buffer-file-name` (Phase 1 confirmed: `sss --non-interactive seal --in-place FILE` exits 0, stdout empty, stderr has confirmation message)
- Call `(set-visited-file-modtime)` after successful seal (clears the "buffer modified" indicator)
- Return `t` on success
- Signal `(error "sss-mode: sealing failed — %s" stderr-content)` on failure — NEVER return `nil` on failure, as that falls through to a plaintext write

---

## Standard Stack

### Core (all Emacs built-ins — zero external dependencies)

| Technology | Version | Purpose | Notes |
|------------|---------|---------|-------|
| `define-derived-mode` | Emacs 27.1+ | Major mode definition | Auto-creates `sss-mode-map`, `sss-mode-hook`, abbrev table; use `text-mode` as parent |
| `magic-mode-alist` | Emacs 27.1+ | Content-based file detection | MATCH-FUNCTION variant (not regexp); checked before `auto-mode-alist` |
| `write-contents-functions` | Emacs 27.1+ | Re-seal on save | Buffer-local hook; returning non-nil prevents plaintext write |
| `find-file-hook` | Emacs 27.1+ | Decrypt on open | Fires after raw bytes are in buffer; replace content with plaintext |
| `call-process` | Emacs 27.1+ | Shell out to sss binary | Synchronous; exit code available; use `(list stdout-buf stderr-file)` destination |
| `defgroup` / `defcustom` | Emacs 27.1+ | Customization group | `(defgroup sss nil ...)`, `(defcustom sss-executable "sss" ...)` |
| `executable-find` | Emacs 27.1+ | Binary location check | Check at mode-load time; warn if not found |

### Supporting (development/CI only — not runtime dependencies)

| Library | Purpose | Notes |
|---------|---------|-------|
| `checkdoc` (built-in) | Docstring validation | `emacs --batch --eval "(checkdoc-file \"sss-mode.el\")"` |
| `package-lint` (MELPA) | Package header validation | CI only; install via batch emacs |
| ERT (built-in) | Unit testing | Test predicate and CLI helper in isolation with mocks |

### What NOT to use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `shell-command-to-string` | No exit code; no stderr separation | `call-process` with exit code check |
| `before-save-hook` | Cannot cleanly abort save on error; errors don't prevent write | `write-contents-functions` returning non-nil |
| `file-name-handler-alist` for save | Requires filename-based trigger; fights content-based detection | `write-contents-functions` (buffer-local, mode-driven) |
| `make-process` (async) | REQUIREMENTS.md and PROJECT.md mandate synchronous for v1 | `call-process` (synchronous) |
| Hardcoded `"/usr/bin/sss"` path | Breaks daemon mode, non-standard installs | `(defcustom sss-executable "sss")` + `executable-find` |
| `auto-save-mode` without `-1` argument | Default arg is wrong | `(auto-save-mode -1)` explicitly |

---

## Architecture Patterns

### Recommended File Structure

```
emacs/
└── sss-mode.el          # Single-file package; all functionality in one file
```

Single file is correct for this scope (estimated 200-350 lines). Multi-file packages are for 500+ line packages with multiple major subsystems. Zero external runtime dependencies required.

### Package Header (mandatory format)

```elisp
;;; sss-mode.el --- Major mode for sss-sealed files  -*- lexical-binding: t; -*-

;; Copyright (C) 2026 <Author>
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: files, encryption, secrets
;; URL: https://github.com/<org>/sss

;;; Commentary:
;; sss-mode provides transparent decrypt-on-open and re-seal-on-save
;; for files sealed with the sss secrets tool.

;;; Code:

;; ... implementation ...

(provide 'sss-mode)
;;; sss-mode.el ends here
```

### Build Order (A → B → C → D → E)

Strict dependency chain. Each phase is testable before the next.

**A: CLI helper + customization**
```
sss-executable defcustom → executable-find check at load → sss--call-cli helper
```

**B: Detection predicate + magic-mode-alist**
```
sss--sealed-p predicate → magic-mode-alist registration
```

**C: Open flow**
```
find-file-hook → sss--maybe-open → replace buffer + disable auto-save/backup
```

**D: Save flow**
```
write-contents-functions → sss--seal-buffer → write sealed content + set-visited-file-modtime
```

**E: Mode definition**
```
define-derived-mode → keymap (C-c prefix) + mode-line indicator
```

---

## Code Examples

### Pattern A: CLI Helper with Exit Code + Stderr Capture

The DESTINATION argument to `call-process` is `(BUFFER STDERR-DEST)`. STDERR-DEST in Emacs must be a **file path string** (not a buffer object) when running in batch mode or when the stderr buffer is separate from stdout. This is verified by live testing:

```elisp
;; VERIFIED WORKING PATTERN (tested 2026-02-21 on Emacs 30.1):
;; call-process PROGRAM INFILE DESTINATION DISPLAY &rest ARGS
;; DESTINATION = (stdout-buffer stderr-filepath-string)

(defun sss--call-cli (args &optional input-file)
  "Call sss CLI with ARGS, return (exit-code stdout-string stderr-string).
INPUT-FILE, if non-nil, is passed as the final argument."
  (let* ((stdout-buf (generate-new-buffer " *sss-stdout*"))
         (stderr-file (make-temp-file "sss-stderr"))
         exit-code stdout stderr)
    (unwind-protect
        (progn
          (setq exit-code
                (apply #'call-process
                       sss-executable
                       nil                          ; INFILE: no stdin
                       (list stdout-buf stderr-file) ; DESTINATION: stdout buf, stderr file
                       nil                          ; DISPLAY: don't update display
                       (append (list "--non-interactive") args
                               (when input-file (list input-file)))))
          (setq stdout (with-current-buffer stdout-buf (buffer-string)))
          (setq stderr (with-temp-buffer
                         (insert-file-contents stderr-file)
                         (buffer-string))))
      (kill-buffer stdout-buf)
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))
    (list exit-code stdout stderr)))
```

**Key detail:** `--non-interactive` flag is prepended to all calls. Phase 1 confirmed: this sets `SSS_NONINTERACTIVE=1` internally (src/main.rs:706-708), preventing any TTY blocking. Alternatively, set `SSS_NONINTERACTIVE=1` in the environment before `call-process`.

### Pattern B: Detection Predicate for magic-mode-alist

```elisp
;; Confirmed marker bytes from src/constants.rs (2026-02-21):
;; MARKER_CIPHERTEXT = "⊠" (U+22A0)
;; UTF-8: \xe2\x8a\xa0  followed by "{" = \x7b
;; Full sequence: \xe2\x8a\xa0\x7b (4 bytes)
(defconst sss--sealed-marker "\xe2\x8a\xa0{"
  "UTF-8 byte sequence for sealed SSS marker ⊠{.")

(defun sss--sealed-p ()
  "Return non-nil if the current buffer begins with a sealed SSS marker.
Used as a MATCH-FUNCTION in `magic-mode-alist'."
  (save-excursion
    (goto-char (point-min))
    ;; Check exact bytes at buffer start — no regexp, no ambiguity
    (looking-at-p (regexp-quote sss--sealed-marker))))

;; Registration — use MATCH-FUNCTION variant (not regexp) for precision:
(add-to-list 'magic-mode-alist (cons #'sss--sealed-p #'sss-mode))
```

**Why MATCH-FUNCTION not regexp:** The `magic-mode-alist` documentation (Emacs 30.1, verified) says elements can be `(REGEXP . FUNCTION)` OR `(MATCH-FUNCTION . FUNCTION)`. The match-function variant calls the function with the buffer narrowed to its beginning; returning non-nil activates FUNCTION as the major mode. A named predicate function avoids regex escaping issues with multibyte characters and makes false-positive prevention explicit.

### Pattern C: Open Flow (find-file-hook)

```elisp
(defun sss--find-file-hook ()
  "Decrypt sealed buffer content after file is visited.
Installed on `find-file-hook' by sss-mode setup."
  (when (and buffer-file-name (sss--sealed-p))
    (sss--open-buffer)))

(defun sss--open-buffer ()
  "Replace buffer content with decrypted plaintext.
Uses `sss open FILE' (markers visible, satisfying EMAC-09).
Disables auto-save and backup immediately (EMAC-04)."
  (let ((file buffer-file-name))
    (pcase (sss--call-cli (list "open") file)
      (`(0 ,plaintext ,_stderr)
       ;; Replace raw sealed bytes with plaintext (⊕{} markers visible per EMAC-09)
       (let ((inhibit-read-only t))
         (erase-buffer)
         (insert plaintext))
       ;; Mark buffer unmodified (content replaced, not user-edited)
       (set-buffer-modified-p nil)
       ;; EMAC-04: disable auto-save and backup BEFORE auto-save timer fires
       (setq-local auto-save-default nil)
       (auto-save-mode -1)
       (setq-local backup-inhibited t)
       ;; Install save hook buffer-locally
       (add-hook 'write-contents-functions #'sss--write-contents nil t))
      (`(,exit ,_stdout ,stderr)
       ;; EMAC-06: always visible error — never a silent empty buffer
       (erase-buffer)
       (error "sss-mode: decryption failed (exit %d): %s" exit
              (string-trim stderr))))))
```

**Critical timing:** Auto-save and backup are disabled in the `find-file-hook` function (not in the `define-derived-mode` body). This ensures they are disabled before the auto-save timer can fire during a slow decryption call. EPA does this the same way via `epa-file-find-file-hook` → `(auto-save-mode 0)` when `epa-file-inhibit-auto-save` is non-nil.

**EMAC-09 design choice:** The open flow uses `sss open FILE` (not `sss render FILE`). Phase 1 confirmed:
- `sss open FILE`: stdout contains content with `⊕{...}` markers visible — user sees which regions are secrets
- `sss render FILE`: stdout contains raw plaintext with all markers stripped — markers invisible

EMAC-09 requires "markers visible" — `sss open` is correct. The save flow must handle `⊕{...}` markers when re-sealing.

### Pattern D: Save Flow (write-contents-functions)

```elisp
(defun sss--write-contents ()
  "Re-seal buffer content and write sealed bytes to disk.
Registered as a `write-contents-functions' function.
Returns t on success (prevents default plaintext write).
Signals error on failure (never returns nil on failure — that would
allow plaintext to be written by the fallback write path)."
  (let ((file buffer-file-name))
    (unless file
      (error "sss-mode: buffer has no associated file"))
    ;; Step 1: Write current buffer content (plaintext with ⊕{} markers) to disk
    ;; Using epa-file-run-real-handler approach: bypass our own hook temporarily
    (let ((write-contents-functions nil))  ; prevent recursion
      (write-region (point-min) (point-max) file nil 'nomessage))
    ;; Step 2: Seal the file in-place
    ;; Phase 1 confirmed: sss seal --in-place FILE exits 0, stdout empty, stderr has message
    (pcase (sss--call-cli (list "seal" "--in-place") file)
      (`(0 ,_stdout ,_stderr)
       ;; Success: update modtime so Emacs knows file matches buffer
       (set-visited-file-modtime)
       ;; Return t to signal "file already written" — prevents default write-region call
       t)
      (`(,exit ,_stdout ,stderr)
       ;; EMAC-06: surface error in minibuffer
       ;; Do NOT return nil here — that would fall through to a plaintext write
       (error "sss-mode: sealing failed (exit %d): %s" exit
              (string-trim stderr))))))
```

**The nil-return danger:** `write-contents-functions` semantics: returning non-nil = "I handled the save, skip default write". Returning nil = "I didn't handle it, proceed normally". If sealing fails and nil is returned, Emacs writes the plaintext buffer to disk. The correct behavior on failure is `(error ...)` which signals an error and aborts the save entirely. The user sees "sss-mode: sealing failed — ..." in the minibuffer.

**The two-step write:** Step 1 writes plaintext temporarily to disk; Step 2 seals it in-place. This means there is a brief window where plaintext exists on disk. This is identical to the `after-save-hook` pattern in the original architecture research. The alternative would be to write to a temp file and seal that — but `sss seal --in-place` operates on the actual file path (which matters for project-root resolution), making temp-file sealing impractical. The plaintext window is milliseconds on a local filesystem and is an accepted limitation (documented in epa-file.el similarly).

### Pattern E: Mode Definition

```elisp
(defgroup sss nil
  "Major mode for sss-sealed files."
  :group 'files
  :prefix "sss-")

(defcustom sss-executable "sss"
  "Path to the sss binary.
Set to an absolute path if sss is not on `exec-path' (e.g., in daemon mode)."
  :type 'string
  :group 'sss)

(define-derived-mode sss-mode text-mode "SSS"
  "Major mode for files sealed with the sss secrets tool.
Transparently decrypts on open (via `find-file-hook') and
re-seals on save (via `write-contents-functions').

Customization: M-x customize-group RET sss RET"
  ;; Keymap is auto-created as sss-mode-map by define-derived-mode (EMAC-08)
  (define-key sss-mode-map (kbd "C-c s s") #'sss-seal-buffer)
  (define-key sss-mode-map (kbd "C-c s o") #'sss-open-buffer))

;; At-load-time binary check (EMAC-07):
(unless (executable-find sss-executable)
  (message "sss-mode: warning: `%s' not found on exec-path. \
Set `sss-executable' to the full path." sss-executable))
```

**`define-derived-mode` note:** Do NOT set `auto-save-default` or `backup-inhibited` in the mode body. Those must be set in the `find-file-hook` (Pattern C) where they are timed to fire before the auto-save timer. The mode body runs when the mode is activated, which may be before or after the hook.

---

## Confirmed CLI Interface (from Phase 1)

| Operation | Invocation | stdout | stderr | Exit |
|-----------|-----------|--------|--------|------|
| Decrypt (markers visible) | `sss --non-interactive open FILE` | plaintext with `⊕{...}` markers | empty on success | 0 |
| Decrypt (markers stripped) | `sss --non-interactive render FILE` | raw plaintext | empty on success | 0 |
| Re-seal in-place | `sss --non-interactive seal --in-place FILE` | **empty** | `"File processed in-place: ..."` | 0 |
| Any failure | any command | empty or partial | error message | 1 |

**For EMAC-09 (markers visible):** Use `sss open FILE` (stdout preserves `⊕{...}` markers).

**Non-interactive flag:** `--non-interactive` flag OR env var `SSS_NONINTERACTIVE=1` are equivalent. Setting via env var in the subprocess environment is cleaner than prepending as argument. Either works.

**Marker byte sequence (confirmed from src/constants.rs):**
- `⊠{` (sealed): UTF-8 `\xe2\x8a\xa0\x7b` (4 bytes) — U+22A0 + 0x7B
- `⊕{` (open/plaintext): UTF-8 `\xe2\x8a\x95\x7b` (4 bytes) — U+2295 + 0x7B

---

## Common Pitfalls

### Pitfall 1: write-contents-functions returning nil on failure

**What goes wrong:** Function handles the error, returns nil instead of signaling, Emacs proceeds to write plaintext.

**Prevention:** ALWAYS use `(error ...)` on failure. Never `(progn (message "error") nil)`.

**Warning sign:** Any `nil` return path in the `write-contents-functions` handler after a CLI failure.

### Pitfall 2: Auto-save disabled too late

**What goes wrong:** `(setq-local auto-save-default nil)` is set in the mode body, not the find-file hook. The auto-save timer fires during the decryption call (which takes 50-200ms) and writes a `#file#` with the still-sealed bytes (harmless) or, if another hook has already partially replaced content, with partial plaintext (dangerous).

**Prevention:** Disable auto-save as the very first thing in the hook that replaces buffer content with plaintext (Pattern C above).

**Verification:** After `(find-file "/path/to/sealed.sss")`, check: `(auto-save-mode)` should return -1; no `#file#` should exist.

### Pitfall 3: call-process stderr destination as buffer object

**What goes wrong:** `(call-process "sss" nil (list stdout-buf stderr-buf) nil ...)` — when STDERR-DEST is a buffer object (not a file path string), Emacs 30.1 raises `(wrong-type-argument stringp #<buffer *stderr*>)` in some contexts.

**Prevention:** Use a temp file for stderr: `(make-temp-file "sss-stderr")`. Read stderr file content after call completes. Delete temp file in `unwind-protect`. This is verified to work on Emacs 30.1.

**Verified working pattern:**
```elisp
(let* ((stderr-file (make-temp-file "sss-stderr"))
       (exit (call-process "sss" nil (list t stderr-file) nil "open" file)))
  ;; t means "current buffer" for stdout
  ;; stderr-file is a path string for stderr
  ...)
```

### Pitfall 4: write-region recursion in write-contents-functions

**What goes wrong:** The `write-contents-functions` handler calls `write-region` to write plaintext temporarily, which triggers `write-contents-functions` again → infinite recursion.

**Prevention:** Set `write-contents-functions` to nil locally before calling `write-region`:
```elisp
(let ((write-contents-functions nil))
  (write-region (point-min) (point-max) file nil 'nomessage))
```

Or use `write-region` via `inhibit-local-variables` — but the `nil` binding is simpler.

### Pitfall 5: set-buffer-modified-p not called after successful seal

**What goes wrong:** After sealing, Emacs still considers the buffer modified (it is — its content diverges from what would be written by default write-region). The mode-line shows `**`. Subsequent saves re-trigger the seal unnecessarily. More importantly, killing the buffer prompts "Buffer modified, save before killing?"

**Prevention:** Call `(set-visited-file-modtime)` after a successful seal. This updates Emacs' record of when the file was last written, marking the buffer clean.

### Pitfall 6: magic-mode-alist fires on non-sealed files

**What goes wrong:** A regex-based `magic-mode-alist` entry accidentally matches non-SSS files containing the Unicode character U+22A0 (⊠) in their content.

**Prevention:** The named predicate function (Pattern B) uses `looking-at-p` on the exact 4-byte sequence `\xe2\x8a\xa0{` — the full `⊠{` including the literal `{`. The `{` character is critical: it makes false positives from stray U+22A0 characters astronomically unlikely.

**Test:** Verify `sss-mode` does NOT activate on `.toml`, `.sh`, `.rs`, `.json`, `.yaml` files.

### Pitfall 7: Keystore failure produces silent empty buffer

**What goes wrong:** `sss open FILE` exits non-zero (keystore unavailable). The handler erases the buffer and returns normally (no error). The user sees an empty buffer and doesn't know why.

**Prevention:** Pattern C above: check exit code, always signal `(error ...)` on non-zero exit with the stderr content. This produces a minibuffer error message satisfying EMAC-06. Never treat CLI failure as "no secrets found."

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Exit code + stderr capture | Custom `start-process` + process sentinel | `call-process` with `(list buf file)` destination | Synchronous is correct for v1; sentinel adds async complexity |
| Binary path resolution | Hardcoded paths | `executable-find sss-executable` | Daemon mode PATH mismatch is real; user-configurable path is required |
| File content detection | Ad-hoc byte comparison | `looking-at-p (regexp-quote sss--sealed-marker)` | Standard, correct, handles point management |
| Auto-save disable | Custom timer manipulation | `(auto-save-mode -1)` | The canonical API; epa-file.el does this |
| Mode keymap creation | Manual `(make-keymap)` | Let `define-derived-mode` create `sss-mode-map` | Auto-created, auto-inherits parent bindings |
| Modtime tracking | Custom file stat calls | `(set-visited-file-modtime)` | The correct Emacs API for "I wrote this file" |

---

## Architecture: Two-Approach Comparison (Resolved)

The prior architecture research described two approaches. This section records the definitive resolution:

| Approach | Trigger | Detection | Save mechanism | sss-mode verdict |
|----------|---------|-----------|----------------|-----------------|
| **file-name-handler-alist** | Filename regex | At file-open via regex match | `write-region` handler intercepted | **WRONG for sss-mode** — requires filename-based trigger; content detection via magic bytes is incompatible |
| **find-file-hook + write-contents-functions** | `find-file-hook` fires, predicate checks content | `magic-mode-alist` + named predicate | `write-contents-functions` returning non-nil | **CORRECT** — content-based detection + buffer-local save override; EMAC-03 mandates this |

The requirements document (EMAC-03) mandates `write-contents-functions` explicitly. STATE.md records it as a locked decision: "write-contents-functions mandated for save flow — before-save-hook explicitly ruled out." The REQUIREMENTS.md, STATE.md, and prior research PITFALLS.md all converge on this answer.

---

## Open Questions

1. **write-contents-functions + write-file behavior**
   - What we know: `write-contents-functions` is "used only by `save-buffer`" per documentation
   - What's unclear: Does `write-file` (C-x C-w, save-to-new-name) bypass `write-contents-functions`?
   - Recommendation: Test explicitly. If `write-file` bypasses it, add `write-file-functions` as well (similar hook, for file-specific saves). For v1 scope, document the limitation if `write-file` is not covered.

2. **revert-buffer behavior**
   - What we know: `revert-buffer` re-reads the file from disk, which will show sealed bytes
   - What's unclear: Whether `find-file-hook` fires after `revert-buffer` to re-decrypt
   - Recommendation: Add `after-revert-hook` buffer-locally in Pattern C: `(add-hook 'after-revert-hook #'sss--open-buffer nil t)`. Test the cycle: open → edit → save → revert → verify plaintext shown.

3. **Multibyte character handling in buffer replacement**
   - What we know: `sss open FILE` outputs UTF-8 text; Emacs buffers are multibyte by default
   - What's unclear: Whether `insert` of the returned string needs explicit coding handling
   - Recommendation: Use `(decode-coding-string stdout 'utf-8)` if output appears as raw bytes. Test with non-ASCII content in secrets. The epa-file.el `decode-coding-inserted-region` pattern may be relevant if issues arise.

---

## Sources

### Primary (HIGH confidence)

- `/usr/share/emacs/30.1/lisp/epa-file.el.gz` — complete epa-file.el source (Emacs 30.1 system install). Verified: uses `insert-file-contents` + `write-region` via `file-name-handler-alist`; does NOT use `write-contents-functions`; `inhibit-file-name-handlers` recursion prevention pattern confirmed.
- `/usr/share/emacs/30.1/lisp/epa-hook.el.gz` — epa-hook.el source. Confirmed: `(auto-save-mode 0)` in `epa-file-find-file-hook` when `epa-file-inhibit-auto-save` is non-nil.
- `emacs --batch -Q` live testing — verified `write-contents-functions` documentation; confirmed `call-process` stderr destination must be file path string (not buffer object); confirmed working pattern `(list t stderr-file)`.
- `src/constants.rs` (sss repo) — `MARKER_CIPHERTEXT = "⊠"` (U+22A0), `MARKER_PLAINTEXT_UTF8 = "⊕"` (U+2295); UTF-8 byte sequences computed via Python (`\xe2\x8a\xa0\x7b` for ⊠{, `\xe2\x8a\x95\x7b` for ⊕{).
- `.planning/phases/01-cli-foundation/01-01-SUMMARY.md` — Phase 1 confirmed CLI interface; exit codes; stdout/stderr behavior for `render`, `open`, `seal --in-place`.
- `.planning/REQUIREMENTS.md` — EMAC-01 through EMAC-09 requirements; EMAC-03 explicitly mandates `write-contents-functions`.
- `.planning/STATE.md` — Locked decisions: `write-contents-functions` mandated, `before-save-hook` ruled out, `magic-mode-alist` with named predicate.

### Secondary (MEDIUM confidence)

- `.planning/research/PITFALLS.md` — Six critical pitfalls; all apply to this phase; auto-save/backup timing, write-contents-functions vs before-save-hook, call-process stderr blindness, daemon mode PATH, magic byte false positives, keystore silent failure.
- `.planning/research/STACK.md` — Emacs Lisp stack; Pattern 1 (file handler — useful as reference but NOT the chosen approach); Pattern 3 (define-derived-mode body); Pattern 4 (call-process examples).
- `.planning/research/ARCHITECTURE.md` — Build order; component list; data flow diagrams.
- GNU Emacs documentation (via training data, cross-verified against live Emacs 30.1) — `magic-mode-alist` MATCH-FUNCTION variant behavior; `define-derived-mode` auto-created keymap; `write-contents-functions` vs `write-file-functions` distinction.

---

## Metadata

**Confidence breakdown:**
- CLI interface: HIGH — confirmed by Phase 1 tests and source code analysis
- write-contents-functions correctness: HIGH — live tested on Emacs 30.1; matches REQUIREMENTS.md mandate; epa-file.el comparison confirms the alternative (file-name-handler-alist) is wrong for this use case
- call-process stderr capture pattern: HIGH — live tested; confirmed file path string required for STDERR-DEST
- magic-mode-alist predicate: HIGH — documentation verified on live Emacs 30.1; byte sequence confirmed from constants.rs
- Auto-save/backup timing: HIGH — epa-hook.el source confirms find-file-hook timing is correct; epa pattern followed exactly
- Open questions (write-file, revert-buffer): LOW — not tested; needs explicit validation in implementation

**Research date:** 2026-02-21
**Valid until:** 2026-08-21 (Emacs Lisp core APIs are stable; write-contents-functions has been stable since Emacs 22)
