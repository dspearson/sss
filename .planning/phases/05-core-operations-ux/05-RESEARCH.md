# Phase 5: Core Operations & UX - Research

**Researched:** 2026-02-21
**Domain:** Emacs Lisp — region encrypt/decrypt, overlay mode, auth-source, transient menus
**Confidence:** HIGH

## Summary

Phase 5 ports features from `plugins/emacs/` into `emacs/sss-mode.el`. All required features
already exist in the plugins source — this is an adaptation task, not a greenfield task. The
critical implementation decisions are: (1) how to invoke the CLI for region operations (stdin
vs temp file), (2) which unsafe patterns from plugins/ must be fixed, and (3) how to guard
optional dependencies (transient, auth-source) so the package remains zero-dependency.

The CLI fully supports stdin via `-` as the file argument for `seal`, `open`, and `render`.
Verified: `printf '⊕{mysecret}' | sss seal -` produces `⊠{...}` on stdout, and
`echo '⊠{...}' | sss open -` produces `⊕{mysecret}` on stdout. This means region operations
can use `call-process-region` (stdin in, stdout out) without temp files.

Both `transient` and `auth-source` are bundled with Emacs 30.1 (confirmed at
`/usr/share/emacs/30.1/lisp/`). They are available without any external package install. The
`sss-mode.el` target requires Emacs 27.1+, so both need `(require 'X nil t)` guards with
graceful fallback for older Emacs.

**Primary recommendation:** Port `sss--run-command`/`call-process-region` for region ops;
use `sss--call-cli` for file ops (already in sss-mode.el). Keep everything in one file.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| CORE-01 | Region encrypt -- encrypt selected region in-place, wrapping in sealed marker | CLI `sss seal -` (stdin) confirmed working; adapt `sss-encrypt-region` from plugins/emacs/sss.el |
| CORE-02 | Region decrypt -- decrypt selected sealed region in-place to plaintext marker | CLI `sss open -` (stdin) confirmed working; adapt `sss-decrypt-region` from plugins/emacs/sss.el |
| CORE-03 | Toggle at point -- detect marker type at point and toggle encrypt/decrypt | Adapt `sss-toggle-at-point` + `sss-pattern-at-point` from plugins/emacs/sss.el; needs CORE-01/02 |
| CORE-04 | Fix deprecated keygen -- update `sss-keygen` to call `sss keys generate` not `sss keygen` | Trivial: change `'("keygen")` to `'("keys" "generate")` in existing sss-keygen function |
| UX-01 | Fancy overlay mode -- inline decrypt previews using overlays on sealed markers | Adapt `sss--apply-fancy-overlays` from plugins/emacs/sss.el; needs simplification for v1.0 security model |
| UX-02 | Preview secret at point -- show decrypted value of marker at point without modifying buffer | Adapt `sss-preview-secret-at-point` from plugins/emacs/sss.el; use overlay popup fallback only |
| UX-03 | Auth-source integration -- password caching via Emacs auth-source for keystore passphrase | Adapt auth-source search pattern; `(require 'auth-source nil t)` guard; store under host "sss" |
| UX-04 | Transient menu -- `sss-dispatch` opens transient listing all commands | Adapt `sss-menu` from plugins/emacs/sss-ui.el; `(require 'transient nil t)` guard with fallback |

</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| emacs/sss-mode.el | 0.1.0 | Target file — all additions go here | v1.0 foundation with correct security patterns |
| `call-process` | Emacs built-in | File-based CLI invocation (open/seal/render whole files) | Already used; exit-code + stderr capture pattern established |
| `call-process-region` | Emacs built-in | Stdin-based CLI invocation for region ops | Sends buffer region as stdin; `-` file arg confirmed working |
| `auth-source` | Emacs 27.1+ built-in | Keystore passphrase caching | Built into Emacs, no external dependency |
| `transient` | Emacs 28+ built-in | Transient menus | Bundled with Emacs 30.1 at `/usr/share/emacs/30.1/lisp/transient.elc` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `overlay` | Emacs built-in | Visual previews on markers without modifying buffer | UX-01, UX-02 |
| `font-lock` | Emacs built-in | Already used for highlighting | Existing patterns reused |
| `make-overlay` / `overlay-put` | Emacs built-in | Creating inline previews | UX-01 fancy overlays, UX-02 popup preview |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `call-process-region` (stdin) | Temp file + `call-process` | Temp file creates a brief plaintext-on-disk window; stdin approach is cleaner for regions |
| auth-source | Custom hash table cache (already in plugins/) | auth-source integrates with user's existing credential stores (.authinfo, macOS Keychain, etc.) |
| transient | completing-read / which-key | transient provides discoverable, grouped menus with hints; completing-read is fallback if transient unavailable |

## Architecture Patterns

### Region Operations Pattern (CORE-01, CORE-02)

The v1.0 `sss--call-cli` function uses `call-process` with a file argument. Region operations
need stdin. Add a companion `sss--call-cli-region` function:

```elisp
;; Source: Verified by stdin test (sss seal - and sss open - both accept stdin)
(defun sss--call-cli-region (args text)
  "Call the sss binary with ARGS, sending TEXT as stdin.
Returns (EXIT-CODE STDOUT STDERR).
ARGS should NOT include the final '-' (stdin) argument -- it is appended.
The --non-interactive flag is always prepended."
  (let* ((stdout-buf (generate-new-buffer " *sss-stdout*"))
         (stderr-file (make-temp-file "sss-stderr"))
         exit-code stdout stderr)
    (unwind-protect
        (with-temp-buffer
          (insert text)
          (setq exit-code
                (apply #'call-process-region
                       (point-min) (point-max)
                       sss-executable
                       nil                           ; do not delete region
                       (list stdout-buf stderr-file) ; stdout buf + stderr file
                       nil                           ; DISPLAY
                       (append (list "--non-interactive") args (list "-"))))
          (setq stdout (with-current-buffer stdout-buf (buffer-string)))
          (setq stderr (with-temp-buffer
                         (insert-file-contents stderr-file)
                         (buffer-string))))
      (kill-buffer stdout-buf)
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))
    (list exit-code stdout stderr)))
```

### Region Encrypt/Decrypt (CORE-01, CORE-02)

The `sss-encrypt-region` / `sss-decrypt-region` pattern from `plugins/emacs/sss.el` lines
225-252 is the reference. Adapt it to use `sss--call-cli-region` instead of
`sss--run-command` / `call-process-region`:

```elisp
;;;###autoload
(defun sss-encrypt-region (start end)
  "Encrypt the region between START and END in-place.
The selected text is replaced with a sealed ⊠{} marker.
Uses `sss seal -' with the region text sent as stdin."
  (interactive "r")
  (let ((text (buffer-substring-no-properties start end)))
    (pcase (sss--call-cli-region (list "seal") text)
      (`(0 ,sealed ,_stderr)
       (delete-region start end)
       (insert (string-trim-right sealed)))
      (`(,exit ,_stdout ,stderr)
       (error "Sss-mode: encrypt failed (exit %d): %s"
              exit (string-trim stderr))))))

;;;###autoload
(defun sss-decrypt-region (start end)
  "Decrypt the sealed region between START and END in-place.
The ⊠{} marker is replaced with the plaintext ⊕{} marker.
Uses `sss open -' with the region text sent as stdin."
  (interactive "r")
  (let ((text (buffer-substring-no-properties start end)))
    (pcase (sss--call-cli-region (list "open") text)
      (`(0 ,opened ,_stderr)
       (delete-region start end)
       (insert (string-trim-right opened)))
      (`(,exit ,_stdout ,stderr)
       (error "Sss-mode: decrypt failed (exit %d): %s"
              exit (string-trim stderr))))))
```

### Pattern Detection at Point (CORE-03)

The plugins' `sss-pattern-at-point` in `plugins/emacs/sss-utils.el` lines 29-45 is cleaner
than the version in `plugins/emacs/sss.el` lines 518-530. Use the utils version — it properly
verifies the original point was within the pattern bounds:

```elisp
;; Source: plugins/emacs/sss-utils.el lines 20-55
(defconst sss--any-marker-regexp
  "\\(?:⊕\\|⊠\\){[^}]*}"
  "Regexp matching any SSS marker (open or sealed).")

(defconst sss--sealed-marker-regexp
  "⊠{[^}]*}"
  "Regexp matching a sealed SSS marker.")

(defun sss--marker-at-point ()
  "Return (START . END) of SSS marker at point, or nil.
Scans backward from point to find the marker start, then verifies
that the original point position falls within the match."
  (save-excursion
    (let ((original-point (point)))
      (while (and (not (bobp))
                  (not (looking-at sss--any-marker-regexp)))
        (backward-char))
      (when (and (looking-at sss--any-marker-regexp)
                 (<= (point) original-point)
                 (>= (match-end 0) original-point))
        (cons (point) (match-end 0))))))
```

Toggle at point uses `sss--marker-at-point` to get bounds, reads the marker prefix char to
determine whether to call `sss-encrypt-region` or `sss-decrypt-region`:

```elisp
;;;###autoload
(defun sss-toggle-at-point ()
  "Toggle the encryption state of the SSS marker at point.
If point is on a ⊕{} marker, encrypts it.
If point is on a ⊠{} marker, decrypts it."
  (interactive)
  (let ((bounds (sss--marker-at-point)))
    (unless bounds
      (error "Sss-mode: no SSS marker at point"))
    (let ((start (car bounds))
          (end (cdr bounds)))
      (save-excursion
        (goto-char start)
        (if (looking-at "⊠{")
            (sss-decrypt-region start end)
          (sss-encrypt-region start end))))))
```

### Keygen Fix (CORE-04)

Current `emacs/sss-mode.el` line 278 uses `'("keygen")`. CLI confirms `keygen` is deprecated
(help says "deprecated, use 'keys generate'"). Fix is a one-line change:

```elisp
;; Before (line 279):
(pcase (sss--call-cli '("keygen"))
;; After:
(pcase (sss--call-cli '("keys" "generate"))
```

Also update the docstring to match.

### Overlay Mode (UX-01)

The plugins' `sss--apply-fancy-overlays` in `plugins/emacs/sss.el` lines 682-722 is the
reference. The v1.0 adaptation must be simpler and must NOT modify buffer content (no inline
edit scaffolding). Key differences to make:

1. Remove the `sss--start-inline-edit` keymap entries — that modifies buffer content.
2. Remove the `after-change-functions` hook — triggers on every keystroke; use `post-command-hook` or explicit toggle instead.
3. The overlay shows `⊠{...}` markers with the sealed face; no need to call the CLI for
   the overlay display itself — the overlay just changes visual appearance without decrypting.
4. `sss-overlay-mode` should be a buffer-local minor mode that can be toggled.

```elisp
;; Defcustom for overlay mode
(defcustom sss-overlay-mode nil
  "When non-nil, show sealed markers with visual overlay styling.
Overlays do not modify buffer content -- they are purely visual."
  :type 'boolean
  :group 'sss)

(defvar-local sss--overlays nil
  "List of SSS overlays in the current buffer.")

(defun sss--make-overlays ()
  "Create visual overlays for all SSS markers in the current buffer."
  (sss--remove-overlays)
  (save-excursion
    (goto-char (point-min))
    (while (re-search-forward sss--any-marker-regexp nil t)
      (let* ((start (match-beginning 0))
             (end (match-end 0))
             (sealed-p (eq (char-after start) ?⊠)) ; U+22A0
             (ov (make-overlay start end)))
        (overlay-put ov 'face (if sealed-p 'sss-sealed-face 'sss-open-face))
        (overlay-put ov 'help-echo
                     (if sealed-p "Sealed secret (M-x sss-decrypt-region)"
                       "Open secret (M-x sss-encrypt-region)"))
        (overlay-put ov 'sss t)
        (push ov sss--overlays)))))

(defun sss--remove-overlays ()
  "Remove all SSS overlays from the current buffer."
  (mapc #'delete-overlay sss--overlays)
  (setq sss--overlays nil))
```

Note: `?⊠` in Emacs Lisp is the character literal for U+22A0. Alternatively use
`(string= (buffer-substring start (1+ start)) "⊠")`.

### Preview at Point (UX-02)

Adapt `sss-preview-secret-at-point` from `plugins/emacs/sss.el` lines 551-568. The plugins
version tries posframe, then popup.el, then a plain overlay. For v1.0 (zero external deps),
use only the plain overlay fallback. Use `sss--call-cli-region` for the actual decryption:

```elisp
;;;###autoload
(defun sss-preview-at-point ()
  "Show a transient overlay preview of the decrypted secret at point.
Does not modify buffer content. Dismisses on next command."
  (interactive)
  (let ((bounds (sss--marker-at-point)))
    (unless bounds
      (user-error "No SSS marker at point"))
    (let ((text (buffer-substring-no-properties (car bounds) (cdr bounds))))
      (unless (string-match-p "^⊠{" text)
        (user-error "Marker at point is not sealed"))
      (pcase (sss--call-cli-region (list "open") text)
        (`(0 ,plaintext ,_)
         (sss--show-transient-overlay (string-trim-right plaintext) (car bounds)))
        (`(,exit ,_ ,stderr)
         (error "Sss-mode: preview failed (exit %d): %s" exit (string-trim stderr)))))))

(defun sss--show-transient-overlay (content pos)
  "Show CONTENT in a transient overlay at POS. Dismisses on next command."
  (let* ((ov (make-overlay pos pos))
         (text (propertize (concat " [" content "]")
                           'face 'tooltip)))
    (overlay-put ov 'after-string text)
    (overlay-put ov 'sss-preview t)
    (let ((cleanup (lambda ()
                     (when (overlay-buffer ov) (delete-overlay ov))
                     (remove-hook 'pre-command-hook cleanup))))
      (add-hook 'pre-command-hook cleanup))))
```

### Auth-Source Integration (UX-03)

The current v1.0 `sss--call-cli` always passes `--non-interactive`, meaning the CLI will fail
if no passphrase is in the environment. Auth-source integration means: before calling the CLI,
check auth-source for a stored passphrase and set `SSS_PASSPHRASE` in the environment.

The sss CLI reads the passphrase from `SSS_PASSPHRASE` env var when `--non-interactive` is
set (confirmed in `sss --help` description of `--non-interactive`).

```elisp
;; Source: auth-source.el is bundled with Emacs 27.1+
(defcustom sss-use-auth-source t
  "When non-nil, use auth-source for keystore passphrase lookup.
Stores passphrases under host \"sss\" in `auth-sources'."
  :type 'boolean
  :group 'sss)

(defun sss--get-passphrase ()
  "Return passphrase for SSS keystore, or nil if unavailable.
Checks auth-source when `sss-use-auth-source' is non-nil.
The passphrase is cached in auth-source (e.g. ~/.authinfo or system keychain)."
  (when (and sss-use-auth-source (require 'auth-source nil t))
    (let ((result (auth-source-search :host "sss"
                                      :require '(:secret)
                                      :max 1)))
      (when result
        (let ((secret (plist-get (car result) :secret)))
          (if (functionp secret) (funcall secret) secret))))))
```

The `sss--call-cli` function is then wrapped to set `SSS_PASSPHRASE` when available:

```elisp
;; Wrap existing sss--call-cli to inject passphrase
(defun sss--call-cli-with-auth (args &optional input-file)
  "Like `sss--call-cli' but injects passphrase from auth-source when available."
  (let* ((passphrase (sss--get-passphrase))
         (process-environment
          (if passphrase
              (cons (concat "SSS_PASSPHRASE=" passphrase) process-environment)
            process-environment)))
    (sss--call-cli args input-file)))
```

The simplest approach for Phase 5 is to modify `sss--call-cli` directly (not wrap it) to
check auth-source as part of its implementation. This avoids a split function naming scheme.

### Transient Menu (UX-04)

The `plugins/emacs/sss-ui.el` `sss-menu` transient at lines 35-61 is the reference. For the
v1.0 port, adapt to only list commands that exist in `emacs/sss-mode.el`. The menu must be
guarded by `(require 'transient nil t)` with a fallback.

`transient` is confirmed bundled with Emacs 30.1. For Emacs 27.1 compatibility (the package
minimum), guard with `(when (require 'transient nil t) ...)`.

```elisp
;; Source: plugins/emacs/sss-ui.el lines 32-61 (adapted)
(defun sss-dispatch ()
  "Open the SSS command menu.
Uses transient if available; falls back to `completing-read'."
  (interactive)
  (if (require 'transient nil t)
      (sss--transient-dispatch)
    (sss--completing-read-dispatch)))

(when (require 'transient nil t)
  (transient-define-prefix sss--transient-dispatch ()
    "SSS command dispatch."
    ["Region Operations"
     ("e" "Encrypt region"  sss-encrypt-region)
     ("d" "Decrypt region"  sss-decrypt-region)
     ("t" "Toggle at point" sss-toggle-at-point)]
    ["Buffer / File"
     ("o" "Open (decrypt) buffer"  sss-open-buffer)
     ("s" "Seal (encrypt) buffer"  sss-seal-buffer)
     ("r" "Render (strip markers)" sss-render-buffer)
     ("P" "Preview at point"       sss-preview-at-point)]
    ["Project"
     ("i" "Init project"  sss-init)
     ("p" "Process project" sss-process)
     ("k" "Generate keys" sss-keygen)
     ("l" "List keys"     sss-keys-list)]
    ["Settings"
     ("O" "Toggle overlay mode" sss-toggle-overlay-mode)]))

(defun sss--completing-read-dispatch ()
  "Fallback dispatch via completing-read when transient is unavailable."
  (let* ((cmds '(("Encrypt region"  . sss-encrypt-region)
                 ("Decrypt region"  . sss-decrypt-region)
                 ("Toggle at point" . sss-toggle-at-point)
                 ("Open buffer"     . sss-open-buffer)
                 ("Seal buffer"     . sss-seal-buffer)
                 ("Render buffer"   . sss-render-buffer)
                 ("Preview at point". sss-preview-at-point)
                 ("Init project"    . sss-init)
                 ("Process project" . sss-process)
                 ("Generate keys"   . sss-keygen)
                 ("List keys"       . sss-keys-list)))
         (choice (completing-read "SSS command: " (mapcar #'car cmds) nil t))
         (fn (cdr (assoc choice cmds))))
    (when fn (call-interactively fn))))
```

### Anti-Patterns to Avoid

- **`before-save-hook` for re-sealing:** The v1.0 design correctly uses `write-contents-functions`. Never switch to `before-save-hook` -- it cannot prevent the default write path.
- **`after-change-functions` for overlay refresh:** Triggers on every keystroke. Use `post-command-hook` with an idle timer, or explicit refresh after encrypt/decrypt/toggle.
- **Modifying buffer content in overlay mode:** Overlays must be purely visual. The `sss--start-inline-edit` pattern from plugins/ modifies buffer content -- do not port this.
- **`call-process-region` with nil INFILE for stdin:** `call-process-region` uses `START`/`END` args (buffer positions) as stdin -- this is correct. Don't pass `nil` for those args when you want stdin.
- **`sss--run-command` from plugins/:** Uses `call-process-region` with a single combined stdout+stderr buffer; no separate exit code + stderr capture. The v1.0 `sss--call-cli` pattern (separate stdout buffer + stderr temp file + exit code) is correct and must be followed.
- **External package requirements:** plugins/ `sss.el` requires `(require 'auth-source)` (hard), `sss-mode.el` hard-requires Emacs 30.1. The v1.0 target requires Emacs 27.1 with zero hard external deps. All optional features must use `(require 'X nil t)`.
- **`customize-set-variable` for transient settings:** plugins/ uses this in toggle functions. For sss-mode.el, use `setq-local` or `setq` directly. `customize-set-variable` requires `cus-edit` to be loaded.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Passphrase caching | Custom hash table (plugins/ pattern) | auth-source with `(require 'auth-source nil t)` | Integrates with user's existing .authinfo, macOS Keychain, GNOME Keyring; handles cache lifetime |
| Popup/tooltip display | New buffer display code | `overlay-put` with `after-string` | Simpler, dismisses automatically via `pre-command-hook`, zero dependencies |
| Menu discovery | Custom completing-read wrapper | `transient-define-prefix` (when available) | transient provides grouping, hints, persistence, and is bundled with Emacs 28+ |
| Marker regex | Writing new patterns | Reuse `sss--sealed-marker` const from v1.0 sss-mode.el + extend | Already defined, tested. Extend to add the open-marker regexp constant |

## Common Pitfalls

### Pitfall 1: `call-process-region` INFILE Argument
**What goes wrong:** Passing `nil` for INFILE to `call-process-region` means "use the region as stdin", but the signature is `(call-process-region START END PROGRAM &optional DELETE BUFFER DISPLAY &rest ARGS)`. If `DELETE` is `nil`, the region is NOT deleted. The `BUFFER` argument (5th position) is the output destination, not the input.
**Why it happens:** Confusing `call-process` (takes INFILE) with `call-process-region` (uses buffer region as stdin directly).
**How to avoid:** `call-process-region START END program nil output-spec nil args...` -- the region content between START and END is sent as stdin; output goes to `output-spec`.
**Warning signs:** Function appears to run but CLI receives empty stdin.

### Pitfall 2: Overlay Not Cleaned Up
**What goes wrong:** Creating overlays in `sss--make-overlays` but not cleaning them up when overlay mode is toggled off or buffer is killed.
**Why it happens:** Overlays persist across mode changes unless explicitly deleted.
**How to avoid:** Always pair overlay creation with a cleanup path. Use `(add-hook 'kill-buffer-hook #'sss--remove-overlays nil t)` when enabling overlay mode.

### Pitfall 3: Transient `when` Guard Ordering
**What goes wrong:** `(when (require 'transient nil t) (transient-define-prefix ...))` at load time fails silently if transient is not available, but `sss-dispatch` then calls `sss--transient-dispatch` which is undefined.
**Why it happens:** `transient-define-prefix` creates the function but only inside the `when` block.
**How to avoid:** `sss-dispatch` checks `(featurep 'transient)` at call time (not at load time) and branches to the fallback. The `when (require ...)` block defines the transient -- it runs once at load; if transient becomes available later, the transient is not defined.
**Better pattern:** `(when (require 'transient nil t) (transient-define-prefix ...))` at top level; `sss-dispatch` uses `(if (fboundp 'sss--transient-dispatch) (sss--transient-dispatch) (sss--completing-read-dispatch))`.

### Pitfall 4: Region Operations on Active Region vs. Saved Positions
**What goes wrong:** Using `(interactive "r")` captures start/end at activation time, but if the function calls `sss--call-cli-region` which creates a temp buffer, point/mark may be invalidated.
**Why it happens:** `(interactive "r")` is correct and safe -- it captures positions as integers before the function body runs. The issue is using `(region-beginning)` / `(region-end)` in the body directly.
**How to avoid:** Always use `(interactive "r")` for region operations; use the bound `start`/`end` parameters directly, not `region-beginning`/`region-end` in the function body.

### Pitfall 5: Auth-Source `SSS_PASSPHRASE` Env Injection
**What goes wrong:** Setting `process-environment` inside a `let` binding works for `call-process` but must wrap the entire `call-process` call. If `sss--call-cli` is called as a sub-function, the `let` binding must encompass that call.
**Why it happens:** `process-environment` is a global-ish dynamic variable; modifying it in the wrong scope doesn't affect the spawned process.
**How to avoid:** Modify `sss--call-cli` itself (not a wrapper) to check `sss--get-passphrase` internally, binding `process-environment` around the `apply #'call-process` call.

### Pitfall 6: Sealed Marker `string-trim-right` vs. Exact Output
**What goes wrong:** `sss seal -` output may include a trailing newline. If `insert` is called without trimming, the buffer gets an extra blank line after each region encrypt.
**Why it happens:** CLI adds `\n` at end of output.
**How to avoid:** Use `(string-trim-right sealed)` before inserting the output. Verified in test: `printf '⊕{mysecret}' | sss seal -` outputs `⊠{...}\n`.

## Code Examples

### Full stdin invocation (verified working)

```elisp
;; Source: Verified by direct CLI test 2026-02-21
;; printf '⊕{mysecret}' | sss seal -  => ⊠{CtNeSAe...}
;; echo '⊠{...}' | sss open -         => ⊕{mysecret}
(defun sss--call-cli-region (args text)
  "Call sss CLI with TEXT as stdin and ARGS. Returns (EXIT STDOUT STDERR).
Appends '-' to ARGS to signal stdin input. Always prepends --non-interactive."
  (let* ((stdout-buf (generate-new-buffer " *sss-stdout*"))
         (stderr-file (make-temp-file "sss-stderr"))
         exit-code stdout stderr)
    (unwind-protect
        (with-temp-buffer
          (insert text)
          (setq exit-code
                (apply #'call-process-region
                       (point-min) (point-max)
                       sss-executable
                       nil                           ; don't delete region
                       (list stdout-buf stderr-file)
                       nil                           ; no display update
                       (append (list "--non-interactive") args (list "-"))))
          (setq stdout (with-current-buffer stdout-buf (buffer-string)))
          (setq stderr (with-temp-buffer
                         (insert-file-contents stderr-file)
                         (buffer-string))))
      (kill-buffer stdout-buf)
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))
    (list exit-code stdout stderr)))
```

### Auth-source passphrase lookup

```elisp
;; Source: auth-source.el bundled API (Emacs 27.1+)
;; Entries stored as: machine sss login default password PASSPHRASE
(defun sss--get-passphrase ()
  "Return SSS keystore passphrase from auth-source, or nil."
  (when (and sss-use-auth-source (require 'auth-source nil t))
    (when-let* ((matches (auth-source-search :host "sss" :require '(:secret) :max 1))
                (entry (car matches))
                (secret (plist-get entry :secret)))
      (if (functionp secret) (funcall secret) secret))))
```

### Transient menu guard pattern

```elisp
;; Source: transient.el bundled API (Emacs 28+, confirmed Emacs 30.1)
;; Pattern: define at load time when available; dispatch checks fboundp
(when (require 'transient nil t)
  (transient-define-prefix sss--transient-dispatch ()
    "SSS command dispatch."
    ["Region" ("e" "Encrypt" sss-encrypt-region) ("d" "Decrypt" sss-decrypt-region)]
    ["Buffer" ("o" "Open"    sss-open-buffer)    ("s" "Seal"    sss-seal-buffer)]))

(defun sss-dispatch ()
  "Open SSS command menu (transient if available, completing-read fallback)."
  (interactive)
  (if (fboundp 'sss--transient-dispatch)
      (sss--transient-dispatch)
    (sss--completing-read-dispatch)))
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `sss keygen` | `sss keys generate` | Present (keygen is deprecated) | CORE-04: must update sss-keygen |
| Custom password hash table | auth-source | UX-03 target | auth-source integrates with system keystores |
| Multi-file plugin (sss.el + sss-mode.el + sss-ui.el) | Single file emacs/sss-mode.el | v1.1 consolidation | Simpler load path; zero external deps |
| `call-process-region` (plugins/ sss--run-command) | `call-process` + `call-process-region` as needed | Phase 5 | `call-process` for file ops, `call-process-region` for region ops |

**Deprecated/outdated:**
- `sss keygen`: CLI marks this deprecated, use `sss keys generate` (same options: `--force`, `--no-password`)
- plugins/emacs/sss.el `sss--run-command`: Uses merged stdout+stderr in one buffer, no separate exit code for stderr. The v1.0 `sss--call-cli` pattern is strictly better.
- plugins/emacs/sss.el `sss-fancy-mode` with `after-change-functions`: Triggers on every keystroke causing performance problems. Use explicit refresh or `post-command-hook` with idle timer.

## Per-Requirement Analysis

### CORE-01: Region Encrypt

**Source in plugins/:** `plugins/emacs/sss.el` lines 224-238 (`sss-encrypt-region`)
**Unsafe pattern to fix:** Uses `sss--run-command` with `call-process-region` that pipes stdout+stderr to a single buffer without separate exit code. Must use `sss--call-cli-region` instead.
**Username argument:** plugins/ version takes `&optional username` and calls `sss--process-text`. v1.0 does not have a username concept (keystore handles auth). **Drop the username argument entirely.**
**CLI invocation:** `sss seal -` (stdin → stdout). Text is the raw region content (may contain `⊕{...}` markers or plain text). CLI will seal all plaintext markers found.
**Output handling:** Trim trailing newline from stdout before inserting.
**Key bindings to add:** `C-c C-e` for encrypt-region in sss-mode-map.

### CORE-02: Region Decrypt

**Source in plugins/:** `plugins/emacs/sss.el` lines 239-252 (`sss-decrypt-region`)
**Unsafe pattern to fix:** Same as CORE-01 — uses unsafe `sss--run-command`.
**CLI invocation:** `sss open -` (stdin → stdout). Text is the sealed region containing `⊠{...}`.
**Key bindings to add:** `C-c C-d` for decrypt-region in sss-mode-map.

### CORE-03: Toggle at Point

**Source in plugins/:** `plugins/emacs/sss.el` lines 254-281 (`sss-toggle-at-point`)
**Better pattern detection:** Use `sss-pattern-at-point` from `plugins/emacs/sss-utils.el` lines 29-45 (verifies original-point is within match bounds).
**Unsafe pattern to fix:** plugins/ version uses `save-excursion` + `backward-char` loop + calls `sss--process-text` (which uses `--render` flag via a custom `--render` arg -- this is not the v1.0 CLI interface). Must call `sss-encrypt-region` or `sss-decrypt-region` instead after detecting marker type.
**Depends on:** CORE-01 and CORE-02 (toggle dispatches to them).
**Key bindings to add:** `C-c C-t` for toggle-at-point in sss-mode-map.

### CORE-04: Keygen Fix

**Source in plugins/:** `plugins/emacs/sss.el` lines 460-471 (`sss-generate-keypair`) — uses `(list "keys" "generate")` correctly.
**Current sss-mode.el:** Line 279 calls `'("keygen")` -- deprecated.
**Fix:** Change one line in `sss-keygen` body: `'("keygen")` → `'("keys" "generate")`.
**CLI compatibility:** Confirmed: `sss keys generate` accepts `--force`, `--no-password`, `--non-interactive`. Same options as `sss keygen`. No breaking change.

### UX-01: Overlay Mode

**Source in plugins/:** `plugins/emacs/sss.el` lines 677-741 (`sss--apply-fancy-overlays`, `sss--remove-fancy-overlays`, `sss--refresh-fancy-mode`)
**What to port:** Visual overlay creation/removal. Add `sss-toggle-overlay-mode` command.
**What NOT to port:** `sss--start-inline-edit` (modifies buffer content), `after-change-functions` hook (too aggressive), `sss--inline-edit-overlay` (complex stateful editing).
**New faces:** Can reuse existing `sss-sealed-face` and `sss-open-face` already in sss-mode.el. No new faces needed.
**Overlay mode as minor mode or defcustom:** plugins/ uses `sss-fancy-mode` as a defcustom with a `:set` hook. For v1.0 port, a simpler buffer-local toggle function (`sss-toggle-overlay-mode`) is sufficient without a full minor mode definition.

### UX-02: Preview at Point

**Source in plugins/:** `plugins/emacs/sss.el` lines 551-606 (`sss-preview-secret-at-point`, `sss--show-preview-popup`, `sss--show-overlay-popup`)
**What to port:** The overlay popup fallback (`sss--show-overlay-popup` lines 592-606). Drop posframe and popup.el branches entirely.
**Security note:** This calls the CLI to decrypt the marker content -- this is acceptable because it's an explicit user action and the plaintext is displayed transiently (not written to disk or buffer).
**Key binding to add:** `C-c C-v` for preview-at-point in sss-mode-map.

### UX-03: Auth-Source

**Source in plugins/:** None -- plugins/ uses a custom hash table cache (lines 96-194 of sss.el). Auth-source integration is new code, not a port.
**Pattern:** `auth-source-search :host "sss" :require '(:secret) :max 1`. Returns a list of plists; `:secret` may be a string or a function (call it to get the string).
**Where to inject:** Modify `sss--call-cli` to check `sss--get-passphrase` and prepend `SSS_PASSPHRASE=<pass>` to `process-environment` when a passphrase is found.
**Storage:** Users add entries manually to `~/.authinfo` or via `M-x auth-source-store-login-data`. Example `~/.authinfo` entry: `machine sss login default password PASSPHRASE`.
**Fallback:** If auth-source finds nothing, behavior is unchanged (CLI uses `--non-interactive`, which will fail if `SSS_PASSPHRASE` is not in the environment -- this is the current behavior).

### UX-04: Transient Menu

**Source in plugins/:** `plugins/emacs/sss-ui.el` lines 35-128 (`sss-menu` and sub-menus)
**What to port:** `sss-menu` (top-level, renamed `sss--transient-dispatch`). Drop sub-menus for project/user/key management (those commands exist but the sub-menu complexity is out of scope).
**What's new:** `sss-dispatch` as the user-facing entry point with `(fboundp ...)` guard for fallback.
**transient availability:** Confirmed bundled with Emacs 30.1. For Emacs 27.1 compat, `(require 'transient nil t)` returns nil on older installs; `sss-dispatch` uses completing-read fallback.
**Key binding to add:** `C-c C-m` for `sss-dispatch` in sss-mode-map (mnemonic: menu).

## Open Questions

1. **Partial region content behavior**
   - What we know: `sss seal -` processes whatever is sent on stdin. If a region contains text with NO `⊕{}` markers, `sss seal -` will output it unchanged (no markers to process).
   - What's unclear: Should `sss-encrypt-region` first wrap the region in `⊕{...}` before piping to `sss seal -`? Or should it wrap the region in a marker and then seal? The requirement says "selected text is replaced with a sealed marker" -- this implies the text becomes `⊠{...}`.
   - Recommendation: If the region text does NOT already start with `⊕{`, wrap it in `⊕{...}` before piping to `sss seal -`. This matches the expected UX: user selects arbitrary text, it becomes `⊠{encrypted}`.
   - **Needs decision in plan/implementation.** See plan note.

2. **Auth-source: does `sss --non-interactive` use `SSS_PASSPHRASE`?**
   - What we know: `sss --help` says `--non-interactive: fail if passphrase not in SSS_PASSPHRASE environment variable`.
   - What's confirmed: The env var is named `SSS_PASSPHRASE`.
   - What's unclear: Whether `SSS_PASSPHRASE` is checked for keystore passphrase (key decryption) or project passphrase (if any). For passwordless keys (`--no-password`), the env var is irrelevant.
   - Recommendation: Implement auth-source lookup; store under `machine sss login default`. If the env var approach breaks for some key types, it's a configuration issue, not a code issue.

3. **Overlay mode refresh strategy**
   - What we know: plugins/ uses `after-change-functions` which fires on every keystroke (too aggressive).
   - What's unclear: Best refresh trigger for v1.0. Options: (a) refresh only after encrypt/decrypt/toggle, (b) `post-command-hook` with idle timer, (c) explicit `M-x sss-refresh-overlays`.
   - Recommendation: Refresh explicitly after each encrypt/decrypt/toggle. Add `sss-refresh-overlays` as an interactive command. This is the simplest approach that satisfies the requirement.

## Sources

### Primary (HIGH confidence)
- `emacs/sss-mode.el` (354 lines) — v1.0 foundation code, directly read
- `plugins/emacs/sss.el` (912 lines) — feature source for CORE-01, CORE-02, CORE-03, UX-01, UX-02, directly read
- `plugins/emacs/sss-mode.el` (241 lines) — overlay and keymap reference, directly read
- `plugins/emacs/sss-ui.el` (359 lines) — transient menu reference for UX-04, directly read
- `plugins/emacs/sss-utils.el` (333 lines) — pattern detection utilities, directly read
- CLI `sss --help`, `sss seal --help`, `sss open --help`, `sss keys --help`, `sss keygen --help` — directly run
- CLI stdin test: `printf '⊕{mysecret}' | sss seal -` and `echo '⊠{...}' | sss open -` — confirmed working 2026-02-21
- `/usr/share/emacs/30.1/lisp/transient.elc` — confirmed bundled with Emacs 30.1
- `/usr/share/emacs/30.1/lisp/auth-source.elc` — confirmed bundled with Emacs 30.1

### Secondary (MEDIUM confidence)
- `auth-source` API patterns: standard Emacs auth-source-search usage; well-established pattern in epa.el, gnutls.el, etc.
- `transient-define-prefix` patterns: standard transient usage; patterns verified from bundled transient.el

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- CLI behavior (stdin support, keygen deprecation): HIGH — directly tested
- Standard stack (transient/auth-source bundled): HIGH — files confirmed on disk
- Architecture patterns (sss--call-cli-region, overlay approach): HIGH — derived from reading actual source
- Port correctness (unsafe patterns identified): HIGH — direct code analysis
- auth-source `SSS_PASSPHRASE` env injection: MEDIUM — env var name confirmed from --help, injection pattern is standard Emacs process-environment usage but not tested end-to-end
- Open question 1 (wrap-then-seal for plain text regions): LOW — behavior needs empirical verification in implementation

**Research date:** 2026-02-21
**Valid until:** 2026-08-21 (stable Emacs built-in APIs, unlikely to change; CLI confirmed today)
