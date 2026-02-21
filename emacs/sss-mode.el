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

(provide 'sss-mode)
;;; sss-mode.el ends here
