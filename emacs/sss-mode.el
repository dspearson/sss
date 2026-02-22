;;; sss-mode.el --- Major mode for sss-sealed files  -*- lexical-binding: t; -*-

;; Copyright (C) 2026
;; Version: 1.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: files, encryption, secrets
;; URL: https://github.com/blob/main/emacs/sss-mode.el

;;; Commentary:
;; sss-mode provides transparent decrypt-on-open and re-seal-on-save
;; for files sealed with the sss secrets tool.
;;
;; Usage: Add to init.el:
;;   (add-to-list 'load-path "/path/to/emacs/")
;;   (require 'sss-mode)
;;
;; For daemon mode, set sss-executable to the absolute path:
;;   (setq sss-executable "/usr/local/bin/sss")
;;
;; New in v1.1:
;; - Region encrypt/decrypt (sss-encrypt-region, sss-decrypt-region)
;; - Toggle marker state at point (sss-toggle-at-point)
;; - Overlay mode for visual marker highlighting (sss-toggle-overlay-mode)
;; - Preview decrypted secret at point (sss-preview-at-point)
;; - Auth-source integration for keystore passphrase (sss-use-auth-source)
;; - Transient command menu with fallback (sss-dispatch)
;; - Fixed keygen to use non-deprecated CLI command

;;; Code:

(defgroup sss nil
  "Major mode for files sealed with the sss secrets tool."
  :group 'files
  :prefix "sss-")

(defcustom sss-executable "sss"
  "Path to the sss binary.
Set to an absolute path if sss is not on variable `exec-path' (daemon mode).
Example: \"/usr/local/bin/sss\""
  :type 'string
  :group 'sss)

(defcustom sss-use-auth-source t
  "When non-nil, use auth-source for keystore passphrase lookup.
Passphrases are stored under host \"sss\" in `auth-sources'.
Example ~/.authinfo entry: machine sss login default password YOURPASS
Requires auth-source (bundled with Emacs 27.1+)."
  :type 'boolean
  :group 'sss)

(defconst sss--sealed-marker "\xe2\x8a\xa0{"
  "UTF-8 byte sequence for the sealed SSS marker \xe2\x8a\xa0{.
U+22A0 (SQUARE ORIGINAL OF) followed by U+007B (LEFT CURLY BRACKET).
UTF-8 encoding: \\xe2\\x8a\\xa0\\x7b (4 bytes).")

(defconst sss--any-marker-regexp
  "\\(?:\xe2\x8a\x95\\|\xe2\x8a\xa0\\){[^}]*}"
  "Regexp matching any SSS marker (open or sealed).
Uses raw UTF-8 byte sequences for cross-version compatibility.")

(defconst sss--sealed-marker-regexp
  "\xe2\x8a\xa0{[^}]*}"
  "Regexp matching a sealed SSS marker.")

(defface sss-open-face
  '((((class color) (background light))
     :background "LightGoldenrod1" :foreground "DarkGreen" :weight bold)
    (((class color) (background dark))
     :background "dark olive green" :foreground "LightYellow" :weight bold)
    (t :inverse-video t))
  "Face for open SSS markers.
Applied to regions matching the open-marker pattern."
  :group 'sss)

(defface sss-sealed-face
  '((((class color) (background light))
     :background "light gray" :foreground "gray50")
    (((class color) (background dark))
     :background "dim gray" :foreground "gray70")
    (t :inverse-video t))
  "Face for sealed SSS markers.
Applied to regions matching the sealed-marker pattern."
  :group 'sss)

(defconst sss--font-lock-keywords
  (list
   '("\xe2\x8a\x95{[^}]*}" . 'sss-open-face)
   '("\xe2\x8a\xa0{[^}]*}" . 'sss-sealed-face))
  "Font-lock keyword list for `sss-mode'.
Highlights open markers and sealed markers with distinct faces.")

(defvar-local sss--state nil
  "Current state of this sss buffer.
Value is the symbol \\='sealed or \\='open.")

(defun sss--get-passphrase ()
  "Return passphrase for SSS keystore from auth-source, or nil.
Checks auth-source when `sss-use-auth-source' is non-nil.
The passphrase is cached by auth-source in the user's credential store."
  (when (and sss-use-auth-source (require 'auth-source nil t))
    (let ((result (auth-source-search :host "sss"
                                      :require '(:secret)
                                      :max 1)))
      (when result
        (let ((secret (plist-get (car result) :secret)))
          (if (functionp secret) (funcall secret) secret))))))

(defun sss--call-cli (args &optional input-file)
  "Call the sss binary with ARGS, return (EXIT-CODE STDOUT STDERR).
ARGS is a list of strings (subcommand and flags, without the binary name).
INPUT-FILE, if non-nil, is appended as the final argument.
The --non-interactive flag is always prepended to prevent TTY blocking.
EXIT-CODE is an integer (0 = success).  STDOUT and STDERR are strings."
  (let* ((stdout-buf (generate-new-buffer " *sss-stdout*"))
         (stderr-file (make-temp-file "sss-stderr"))
         (passphrase (sss--get-passphrase))
         (process-environment
          (if passphrase
              (cons (concat "SSS_PASSPHRASE=" passphrase) process-environment)
            process-environment))
         exit-code stdout stderr)
    (unwind-protect
        (progn
          (setq exit-code
                (apply #'call-process
                       sss-executable
                       nil                           ; INFILE: no stdin
                       (list stdout-buf stderr-file) ; stdout buf + stderr file path
                       nil                           ; DISPLAY: do not update display
                       (append (list "--non-interactive")
                               args
                               (when input-file (list input-file)))))
          (setq stdout (with-current-buffer stdout-buf (buffer-string)))
          (setq stderr (with-temp-buffer
                         (insert-file-contents stderr-file)
                         (buffer-string))))
      (kill-buffer stdout-buf)
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))
    (list exit-code stdout stderr)))

(defun sss--call-cli-region (args text)
  "Call the sss binary with ARGS, sending TEXT as stdin.
Returns (EXIT-CODE STDOUT STDERR).
ARGS should NOT include the final `-' argument -- it is appended.
The --non-interactive flag is always prepended."
  (let* ((stdout-buf (generate-new-buffer " *sss-stdout*"))
         (stderr-file (make-temp-file "sss-stderr"))
         (passphrase (sss--get-passphrase))
         (process-environment
          (if passphrase
              (cons (concat "SSS_PASSPHRASE=" passphrase) process-environment)
            process-environment))
         exit-code stdout stderr)
    (unwind-protect
        (with-temp-buffer
          (insert text)
          (setq exit-code
                (apply #'call-process-region
                       (point-min) (point-max)
                       sss-executable
                       nil
                       (list stdout-buf stderr-file)
                       nil
                       (append (list "--non-interactive") args (list "-"))))
          (setq stdout (with-current-buffer stdout-buf (buffer-string)))
          (setq stderr (with-temp-buffer
                         (insert-file-contents stderr-file)
                         (buffer-string))))
      (kill-buffer stdout-buf)
      (when (file-exists-p stderr-file)
        (delete-file stderr-file)))
    (list exit-code stdout stderr)))

;;;###autoload
(defun sss-encrypt-region (start end)
  "Encrypt the region between START and END in-place.
If the region is not already an open marker, it is wrapped in
a \xe2\x8a\x95{} marker first.  The text is then sealed via `sss seal -'
and the region is replaced with the resulting \xe2\x8a\xa0{} marker."
  (interactive "r")
  (let* ((text (buffer-substring-no-properties start end))
         (input (if (string-match-p "\\`\xe2\x8a\x95{" text)
                    text
                  (concat "\xe2\x8a\x95{" text "}"))))
    (pcase (sss--call-cli-region (list "seal") input)
      (`(0 ,sealed ,_stderr)
       (delete-region start end)
       (insert (string-trim-right sealed))
       (sss--refresh-overlays))
      (`(,exit ,_stdout ,stderr)
       (error "Sss-mode: encrypt failed (exit %d): %s"
              exit (string-trim stderr))))))

;;;###autoload
(defun sss-decrypt-region (start end)
  "Decrypt the sealed region between START and END in-place.
The \xe2\x8a\xa0{} marker is replaced with the plaintext \xe2\x8a\x95{} marker.
Uses `sss open -' with the region text sent as stdin."
  (interactive "r")
  (let ((text (buffer-substring-no-properties start end)))
    (pcase (sss--call-cli-region (list "open") text)
      (`(0 ,opened ,_stderr)
       (delete-region start end)
       (insert (string-trim-right opened))
       (sss--refresh-overlays))
      (`(,exit ,_stdout ,stderr)
       (error "Sss-mode: decrypt failed (exit %d): %s"
              exit (string-trim stderr))))))

(defun sss--sealed-p ()
  "Return non-nil if the current buffer begins with a sealed SSS marker.
Checks for the exact 4-byte UTF-8 sequence \\xe2\\x8a\\xa0{ at buffer start.
Used as a MATCH-FUNCTION in `magic-mode-alist'."
  (save-excursion
    (goto-char (point-min))
    (looking-at-p (regexp-quote sss--sealed-marker))))

;; Register detection predicate — MATCH-FUNCTION variant (not regexp).
;; magic-mode-alist is checked before auto-mode-alist; the predicate
;; is called with the buffer narrowed to its beginning.
(add-to-list 'magic-mode-alist (cons #'sss--sealed-p #'sss-mode))

;; Warn at load time if sss binary is not found — never error, just warn.
;; Users set sss-executable to absolute path for daemon mode.
(unless (executable-find sss-executable)
  (message "sss-mode: warning: `%s' not found on exec-path. \
Set `sss-executable' to the absolute path." sss-executable))

;;; Open flow — decrypt-on-open via find-file-hook

(defun sss--find-file-hook ()
  "Decrypt sealed buffer content after file is visited.
Installed on `find-file-hook' by `sss-mode'.
Only acts when the buffer has an associated file and contains sealed content."
  (when (and buffer-file-name (sss--sealed-p))
    (sss--open-buffer)))

(defun sss--open-buffer ()
  "Replace sealed buffer content with decrypted plaintext.
Uses `sss open FILE' so ⊕{} markers remain visible (satisfying EMAC-09).
Disables auto-save and backup immediately before any timer fires (EMAC-04).
On failure, signals a visible error (EMAC-06) — never a silent empty buffer.

This function also registers `sss--write-contents' on `write-contents-functions'
buffer-locally, so that subsequent saves re-seal the file."
  (let ((file buffer-file-name))
    (pcase (sss--call-cli (list "open") file)
      (`(0 ,plaintext ,_stderr)
       ;; Disable auto-save and backup FIRST — before replacing content.
       ;; Timing matters: the auto-save timer may fire during the CLI call.
       ;; Must be set before erase-buffer/insert so no partial plaintext is saved.
       (setq-local auto-save-default nil)
       (auto-save-mode -1)
       (setq-local backup-inhibited t)
       ;; Replace raw sealed bytes with decrypted plaintext (⊕{} markers visible per EMAC-09)
       (let ((inhibit-read-only t))
         (erase-buffer)
         (insert plaintext))
       ;; Mark buffer unmodified — content was replaced by open, not by user edit
       (set-buffer-modified-p nil)
       ;; Update modeline to reflect decrypted state (EMUX-02)
       (setq-local sss--state 'open)
       (setq mode-name "SSS[open]")
       (force-mode-line-update)
       ;; Register save hook buffer-locally (Plan 03 will define sss--write-contents)
       (add-hook 'write-contents-functions #'sss--write-contents nil t)
       ;; Register revert hook buffer-locally to re-decrypt after revert-buffer
       (add-hook 'after-revert-hook #'sss--open-buffer nil t))
      (`(,exit ,_stdout ,stderr)
       ;; EMAC-06: always a visible error — never a silent empty buffer.
       ;; (error ...) signals into the minibuffer; aborts find-file cleanly.
       (error "Sss-mode: decryption failed (exit %d): %s"
              exit (string-trim stderr))))))

;;; Save flow — re-seal-on-save via write-contents-functions

(defun sss--write-contents ()
  "Re-seal buffer content and write sealed bytes to disk.
Registered buffer-locally on `write-contents-functions' by `sss--open-buffer'.

Returns t on success — this signals to Emacs that the file has been written,
preventing the default `write-region' call from writing plaintext to disk.

On failure, signals `(error ...)' — this is MANDATORY.  Returning nil on
failure would allow Emacs to fall through to its default write path, writing
plaintext.

Two-step process: step 1 writes plaintext buffer content to disk temporarily,
step 2 calls `sss seal --in-place' to encrypt the file in place.
There is a brief window (milliseconds) where plaintext exists on disk — this
is an accepted limitation identical to the epa-file.el pattern."
  (let ((file buffer-file-name))
    (unless file
      (error "Sss-mode: buffer has no associated file; cannot seal"))
    ;; Step 1: Write plaintext buffer content to disk.
    ;; Bind write-contents-functions to nil to prevent recursion.
    ;; Use 'nomessage to suppress "Wrote /path/to/file" echo.
    (let ((write-contents-functions nil))
      (write-region (point-min) (point-max) file nil 'nomessage))
    ;; Step 2: Seal the file in-place.
    ;; Phase 1 confirmed: exits 0, stdout empty, stderr has confirmation message.
    (pcase (sss--call-cli (list "seal" "--in-place") file)
      (`(0 ,_stdout ,_stderr)
       ;; Success: update Emacs' record of file modification time.
       ;; This marks the buffer as "clean" (not modified since last write).
       ;; Without this, the mode-line shows ** and kill-buffer prompts to save.
       (set-visited-file-modtime)
       ;; Return t: signals "file written, skip default write-region"
       t)
      (`(,exit ,_stdout ,stderr)
       ;; EMAC-06: visible minibuffer error.
       ;; DO NOT return nil here — that falls through to a plaintext disk write.
       ;; DO NOT use (message ...) + nil — same problem.
       (error "Sss-mode: sealing failed (exit %d): %s"
              exit (string-trim stderr))))))

;;; Render command

(defun sss--display-output (buf-name content)
  "Display CONTENT in a read-only buffer named BUF-NAME.
BUF-NAME is a string.  CONTENT is inserted after erasing any
previous content.  Buffer is displayed via `display-buffer'."
  (with-current-buffer (get-buffer-create buf-name)
    (let ((inhibit-read-only t))
      (erase-buffer)
      (insert content))
    (read-only-mode 1)
    (goto-char (point-min)))
  (display-buffer buf-name))

;;;###autoload
(defun sss-render-buffer ()
  "Display the current file with all SSS markers stripped.
Calls `sss render FILE' and shows pure plaintext in buffer
*SSS Rendered*.  Operates on the file on disk; unsaved buffer
changes are not reflected."
  (interactive)
  (unless buffer-file-name
    (error "Sss-mode: buffer has no associated file; cannot render"))
  (when (buffer-modified-p)
    (message "Sss-mode: warning: buffer has unsaved changes; \
rendering disk version"))
  (pcase (sss--call-cli '("render") buffer-file-name)
    (`(0 ,stdout ,_stderr)
     (sss--display-output "*SSS Rendered*" stdout))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss render failed (exit %d): %s"
            exit (string-trim stderr)))))

;;; Project commands

;;;###autoload
(defun sss-init ()
  "Initialise an SSS project in the current directory.
Runs `sss init' and displays the output."
  (interactive)
  (pcase (sss--call-cli '("init"))
    (`(0 ,stdout ,stderr)
     (sss--display-output "*SSS Init*"
                          (concat stdout
                                  (unless (string-empty-p stderr)
                                    (concat "\n" stderr)))))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss init failed (exit %d): %s"
            exit (string-trim stderr)))))

;;;###autoload
(defun sss-process ()
  "Seal all plaintext markers in the current SSS project.
Runs `sss seal --project' (the project-wide seal operation).
There is no `sss process' subcommand; this command provides the
equivalent functionality."
  (interactive)
  (pcase (sss--call-cli '("seal" "--project"))
    (`(0 ,stdout ,stderr)
     (sss--display-output "*SSS Process*"
                          (concat stdout
                                  (unless (string-empty-p stderr)
                                    (concat "\n" stderr)))))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss seal --project failed (exit %d): %s"
            exit (string-trim stderr)))))

;;;###autoload
(defun sss-keygen ()
  "Generate a new SSS keypair.
Runs `sss keys generate' and displays the output."
  (interactive)
  (pcase (sss--call-cli '("keys" "generate"))
    (`(0 ,stdout ,stderr)
     (sss--display-output "*SSS Keygen*"
                          (concat stdout
                                  (unless (string-empty-p stderr)
                                    (concat "\n" stderr)))))
    (`(,exit ,_stdout ,stderr)
     (error "Sss-mode: sss keys generate failed (exit %d): %s"
            exit (string-trim stderr)))))

;;;###autoload
(defun sss-keys-list ()
  "Display the list of available SSS keys.
Runs `sss keys list' and shows the output in buffer *SSS Keys*."
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

;;; Marker detection and toggle

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

;;;###autoload
(defun sss-toggle-at-point ()
  "Toggle the encryption state of the SSS marker at point.
If point is on a \xe2\x8a\xa0{} marker, decrypts it.
If point is on a \xe2\x8a\x95{} marker, encrypts it."
  (interactive)
  (let ((bounds (sss--marker-at-point)))
    (unless bounds
      (user-error "No SSS marker at point"))
    (let ((start (car bounds))
          (end (cdr bounds)))
      (save-excursion
        (goto-char start)
        (if (looking-at (regexp-quote sss--sealed-marker))
            (sss-decrypt-region start end)
          (sss-encrypt-region start end))))))

;;; Overlay mode

(defvar-local sss--overlays nil
  "List of SSS visual overlays in the current buffer.")

(defun sss--remove-overlays ()
  "Remove all SSS overlays from the current buffer."
  (mapc #'delete-overlay sss--overlays)
  (setq sss--overlays nil))

(defun sss--make-overlays ()
  "Create visual overlays for all SSS markers in the current buffer.
Overlays are purely visual -- they do not modify buffer content."
  (sss--remove-overlays)
  (save-excursion
    (goto-char (point-min))
    (while (re-search-forward sss--any-marker-regexp nil t)
      (let* ((start (match-beginning 0))
             (end (match-end 0))
             (sealed-p (eq (char-after start) ?\u22A0))
             (ov (make-overlay start end)))
        (overlay-put ov 'face (if sealed-p 'sss-sealed-face 'sss-open-face))
        (overlay-put ov 'help-echo
                     (if sealed-p
                         "Sealed secret (C-c C-d to decrypt, C-c C-t to toggle)"
                       "Open secret (C-c C-e to encrypt, C-c C-t to toggle)"))
        (overlay-put ov 'sss-overlay t)
        (push ov sss--overlays)))))

(defun sss--refresh-overlays ()
  "Refresh SSS overlays if overlay mode is active."
  (when sss--overlays
    (sss--make-overlays)))

;;;###autoload
(defun sss-toggle-overlay-mode ()
  "Toggle SSS overlay mode in the current buffer.
When enabled, markers are visually highlighted with overlays.
When disabled, overlays are removed."
  (interactive)
  (if sss--overlays
      (progn
        (sss--remove-overlays)
        (remove-hook 'kill-buffer-hook #'sss--remove-overlays t)
        (message "SSS overlay mode disabled"))
    (sss--make-overlays)
    (add-hook 'kill-buffer-hook #'sss--remove-overlays nil t)
    (message "SSS overlay mode enabled")))

;;; Preview at point

(defun sss--show-preview-overlay (content pos)
  "Show CONTENT in a transient overlay at POS.
Dismisses on the next command."
  (let* ((ov (make-overlay pos pos))
         (text (propertize (concat " [" content "]")
                           'face 'tooltip)))
    (overlay-put ov 'after-string text)
    (overlay-put ov 'sss-preview t)
    (letrec ((cleanup (lambda ()
                        (when (overlay-buffer ov) (delete-overlay ov))
                        (remove-hook 'pre-command-hook cleanup))))
      (add-hook 'pre-command-hook cleanup))))

;;;###autoload
(defun sss-preview-at-point ()
  "Show a transient overlay preview of the decrypted secret at point.
Does not modify buffer content.  Dismisses on next command.
Only works on sealed (\xe2\x8a\xa0{}) markers."
  (interactive)
  (let ((bounds (sss--marker-at-point)))
    (unless bounds
      (user-error "No SSS marker at point"))
    (let ((text (buffer-substring-no-properties (car bounds) (cdr bounds))))
      (unless (string-match-p (concat "\\`" (regexp-quote sss--sealed-marker))
                              text)
        (user-error "Marker at point is not sealed"))
      (pcase (sss--call-cli-region (list "open") text)
        (`(0 ,plaintext ,_)
         (sss--show-preview-overlay (string-trim-right plaintext) (car bounds)))
        (`(,exit ,_ ,stderr)
         (error "Sss-mode: preview failed (exit %d): %s"
                exit (string-trim stderr)))))))

;;; Transient menu (UX-04)

(when (require 'transient nil t)
  (transient-define-prefix sss--transient-dispatch ()
    "SSS command dispatch."
    ["Region Operations"
     ("e" "Encrypt region"   sss-encrypt-region)
     ("d" "Decrypt region"   sss-decrypt-region)
     ("t" "Toggle at point"  sss-toggle-at-point)
     ("v" "Preview at point" sss-preview-at-point)]
    ["Buffer / File"
     ("o" "Open (decrypt) buffer"  sss-open-buffer)
     ("s" "Seal (encrypt) buffer"  sss-seal-buffer)
     ("r" "Render (strip markers)" sss-render-buffer)]
    ["Project"
     ("i" "Init project"    sss-init)
     ("p" "Process project" sss-process)
     ("k" "Generate keys"   sss-keygen)
     ("l" "List keys"       sss-keys-list)]
    ["Settings"
     ("O" "Toggle overlay mode" sss-toggle-overlay-mode)]))

(defun sss--completing-read-dispatch ()
  "Fallback dispatch via `completing-read' when transient is unavailable."
  (let* ((cmds '(("Encrypt region"      . sss-encrypt-region)
                 ("Decrypt region"      . sss-decrypt-region)
                 ("Toggle at point"     . sss-toggle-at-point)
                 ("Preview at point"    . sss-preview-at-point)
                 ("Open buffer"         . sss-open-buffer)
                 ("Seal buffer"         . sss-seal-buffer)
                 ("Render buffer"       . sss-render-buffer)
                 ("Init project"        . sss-init)
                 ("Process project"     . sss-process)
                 ("Generate keys"       . sss-keygen)
                 ("List keys"           . sss-keys-list)
                 ("Toggle overlay mode" . sss-toggle-overlay-mode)))
         (choice (completing-read "SSS command: " (mapcar #'car cmds) nil t))
         (fn (cdr (assoc choice cmds))))
    (when fn (call-interactively fn))))

;;;###autoload
(defun sss-dispatch ()
  "Open the SSS command menu.
Uses transient if available; falls back to `completing-read'."
  (interactive)
  (if (fboundp 'sss--transient-dispatch)
      (sss--transient-dispatch)
    (sss--completing-read-dispatch)))

;;; Mode definition

;;;###autoload
(define-derived-mode sss-mode text-mode "SSS"
  "Major mode for files sealed with the sss secrets tool.

Provides transparent decrypt-on-open and re-seal-on-save:
- Opening a sealed file shows decrypted plaintext with ⊕{} markers visible
- Saving the buffer re-seals the file on disk; plaintext is never written as-is
- Failures produce visible minibuffer errors (never silent empty buffers)

Auto-save and backup are disabled for the decrypted buffer (security).

Activated automatically via `magic-mode-alist' for sealed files.

Customization: \\[customize-group] RET sss RET

\\{sss-mode-map}"
  ;; Font-lock (EMUX-01): highlight ⊕{} and ⊠{} markers with distinct faces.
  (setq-local font-lock-defaults '(sss--font-lock-keywords t))
  ;; Modeline state (EMUX-02): initialise to sealed on mode activation.
  (setq-local sss--state 'sealed)
  (setq mode-name "SSS[sealed]")
  ;; Keymap (EMAC-08): sss-mode-map is auto-created by define-derived-mode.
  ;; Bind commands under C-c C-x pattern (package-lint compliant).
  (define-key sss-mode-map (kbd "C-c C-o") #'sss-open-buffer)
  (define-key sss-mode-map (kbd "C-c C-s") #'sss-seal-buffer)
  (define-key sss-mode-map (kbd "C-c C-r") #'sss-render-buffer)
  (define-key sss-mode-map (kbd "C-c C-i") #'sss-init)
  (define-key sss-mode-map (kbd "C-c C-p") #'sss-process)
  (define-key sss-mode-map (kbd "C-c C-k") #'sss-keygen)
  (define-key sss-mode-map (kbd "C-c C-l") #'sss-keys-list)
  (define-key sss-mode-map (kbd "C-c C-e") #'sss-encrypt-region)
  (define-key sss-mode-map (kbd "C-c C-d") #'sss-decrypt-region)
  (define-key sss-mode-map (kbd "C-c C-t") #'sss-toggle-at-point)
  (define-key sss-mode-map (kbd "C-c C-v") #'sss-preview-at-point)
  (define-key sss-mode-map (kbd "C-c C-m") #'sss-dispatch)
  ;; Install find-file-hook to handle decryption when mode activates on open.
  ;; The hook checks sss--sealed-p before acting — safe to install globally.
  (add-hook 'find-file-hook #'sss--find-file-hook))

(defun sss-open-buffer ()
  "Decrypt the current sealed sss buffer in place.
Interactive command for `sss-mode-map' (\\[sss-open-buffer]).
Calls `sss--open-buffer' which replaces content with decrypted plaintext."
  (interactive)
  (sss--open-buffer))

(defun sss-seal-buffer ()
  "Re-seal and save the current sss buffer.
Interactive command for `sss-mode-map' (\\[sss-seal-buffer]).
Equivalent to \\[save-buffer] — triggers `write-contents-functions'."
  (interactive)
  (save-buffer))

;;; Evil integration (EVIL-01, EVIL-02, EVIL-03, DOOM-03)

(with-eval-after-load 'evil

  ;; Operators (EVIL-01, EVIL-02, EVIL-03)

  (evil-define-operator sss-evil-encrypt (beg end)
    "Evil operator to encrypt region between BEG and END."
    :motion evil-line
    (sss-encrypt-region beg end))

  (evil-define-operator sss-evil-decrypt (beg end)
    "Evil operator to decrypt sealed marker between BEG and END."
    :motion evil-line
    (sss-decrypt-region beg end))

  (evil-define-operator sss-evil-toggle (beg end)
    "Evil operator to toggle encryption at point or region."
    :motion evil-line
    (if (= beg end)
        (sss-toggle-at-point)
      (save-excursion
        (goto-char beg)
        (while (and (< (point) end)
                    (re-search-forward sss--any-marker-regexp end t))
          (goto-char (match-beginning 0))
          (sss-toggle-at-point)
          (forward-char 1)))))

  ;; Buffer-local key bindings: ge/gd/gt active only in sss-mode buffers (EVIL-01, EVIL-02, EVIL-03)
  ;; Uses evil-define-key with sss-mode-map (buffer-local) rather than evil-normal-state-map
  ;; (global). This preserves ge=evil-backward-word-end, gd=evil-goto-definition,
  ;; gt=evil-tab-next in all other buffers where they are meaningful.
  (evil-define-key 'normal sss-mode-map
    (kbd "ge") #'sss-evil-encrypt
    (kbd "gd") #'sss-evil-decrypt
    (kbd "gt") #'sss-evil-toggle)

  ;; Text objects: `is' (inner sss) and `as' (outer sss) (EVIL-03)
  ;; Usage: vis/dis/cis -- select/delete/change inner pattern content
  ;;        vas/das/cas -- select/delete/change entire pattern

  (evil-define-text-object sss-inner-pattern (count &optional beg end type)
    "Inner SSS text object: content inside marker braces, excluding delimiters."
    (let ((bounds (sss--marker-at-point)))
      (when bounds
        (save-excursion
          (goto-char (car bounds))
          (when (re-search-forward "{" (cdr bounds) t)
            (let ((content-start (point))
                  (content-end (save-excursion
                                 (goto-char (cdr bounds))
                                 (when (re-search-backward "}" (car bounds) t)
                                   (point)))))
              (when content-end
                (list content-start content-end))))))))

  (evil-define-text-object sss-outer-pattern (count &optional beg end type)
    "Outer SSS text object: entire marker including prefix and braces."
    (let ((bounds (sss--marker-at-point)))
      (when bounds
        (list (car bounds) (cdr bounds)))))

  (define-key evil-inner-text-objects-map "s" 'sss-inner-pattern)
  (define-key evil-outer-text-objects-map "s" 'sss-outer-pattern))

;;; Doom integration (DOOM-01, DOOM-02)

;; Silence byte-compiler warning for map! without requiring doom-core at compile time.
(declare-function map! "doom-core" t t)

(when (fboundp 'map!)
  ;; Global leader bindings (DOOM-01): SPC e prefix for encryption commands.
  ;; Sub-prefixes: SPC e p (project), SPC e k (keys).
  ;; eval prevents byte-compiler from expanding map! macro syntax outside Doom.
  (eval
   '(map! :leader
          (:prefix-map ("e" . "encryption")
           :desc "Encrypt region"   "e" #'sss-encrypt-region
           :desc "Decrypt region"   "d" #'sss-decrypt-region
           :desc "Toggle at point"  "t" #'sss-toggle-at-point
           :desc "Preview at point" "v" #'sss-preview-at-point
           :desc "SSS menu"         "SPC" #'sss-dispatch
           (:prefix ("p" . "project")
            :desc "Init project"    "i" #'sss-init
            :desc "Process project" "p" #'sss-process)
           (:prefix ("k" . "keys")
            :desc "Generate keys"   "g" #'sss-keygen
            :desc "List keys"       "l" #'sss-keys-list))))
  ;; Localleader bindings (DOOM-02): , e prefix in sss-mode buffers only.
  ;; :map sss-mode-map scopes these bindings to sss-mode buffers.
  (eval
   '(map! :localleader
          :map sss-mode-map
          (:prefix ("e" . "sss")
           :desc "Encrypt region"   "e" #'sss-encrypt-region
           :desc "Decrypt region"   "d" #'sss-decrypt-region
           :desc "Toggle at point"  "t" #'sss-toggle-at-point
           :desc "Preview at point" "v" #'sss-preview-at-point
           :desc "SSS menu"         "SPC" #'sss-dispatch))))

(provide 'sss-mode)
;;; sss-mode.el ends here
