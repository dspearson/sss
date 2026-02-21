;;; sss-mode.el --- Major mode for sss-sealed files  -*- lexical-binding: t; -*-

;; Copyright (C) 2026
;; Version: 0.1.0
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

;;; Code:

(defgroup sss nil
  "Major mode for files sealed with the sss secrets tool."
  :group 'files
  :prefix "sss-")

(defcustom sss-executable "sss"
  "Path to the sss binary.
Set to an absolute path if sss is not on `exec-path' (e.g., in daemon mode).
Example: \"/usr/local/bin/sss\""
  :type 'string
  :group 'sss)

(defconst sss--sealed-marker "\xe2\x8a\xa0{"
  "UTF-8 byte sequence for the sealed SSS marker \xe2\x8a\xa0{.
U+22A0 (SQUARE ORIGINAL OF) followed by U+007B (LEFT CURLY BRACKET).
UTF-8 encoding: \\xe2\\x8a\\xa0\\x7b (4 bytes).")

(defun sss--call-cli (args &optional input-file)
  "Call the sss binary with ARGS, return (EXIT-CODE STDOUT STDERR).
ARGS is a list of strings (subcommand and flags, without the binary name).
INPUT-FILE, if non-nil, is appended as the final argument.
The --non-interactive flag is always prepended to prevent TTY blocking.
EXIT-CODE is an integer (0 = success).  STDOUT and STDERR are strings."
  (let* ((stdout-buf (generate-new-buffer " *sss-stdout*"))
         (stderr-file (make-temp-file "sss-stderr"))
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
       ;; Register save hook buffer-locally (Plan 03 will define sss--write-contents)
       (add-hook 'write-contents-functions #'sss--write-contents nil t)
       ;; Register revert hook buffer-locally to re-decrypt after revert-buffer
       (add-hook 'after-revert-hook #'sss--open-buffer nil t))
      (`(,exit ,_stdout ,stderr)
       ;; EMAC-06: always a visible error — never a silent empty buffer.
       ;; (error ...) signals into the minibuffer; aborts find-file cleanly.
       (error "sss-mode: decryption failed (exit %d): %s"
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

The two-step process: (1) write plaintext buffer content to disk temporarily,
(2) call `sss seal --in-place' to encrypt the file in place.
There is a brief window (milliseconds) where plaintext exists on disk — this
is an accepted limitation identical to the epa-file.el pattern."
  (let ((file buffer-file-name))
    (unless file
      (error "sss-mode: buffer has no associated file; cannot seal"))
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
       (error "sss-mode: sealing failed (exit %d): %s"
              exit (string-trim stderr))))))

(provide 'sss-mode)
;;; sss-mode.el ends here
