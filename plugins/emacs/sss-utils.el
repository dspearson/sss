;;; sss-utils.el --- SSS utility functions and helpers -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; This file provides utility functions and helpers for the SSS
;; Emacs interface, including pattern detection, file handling,
;; and various convenience functions.

;;; Code:

(require 'cl-lib)

;;; Pattern detection and manipulation

(defconst sss-plaintext-pattern "\\(?:⊕\\|o\\+\\){"
  "Regex pattern for SSS plaintext markers.")

(defconst sss-ciphertext-pattern "⊠{"
  "Regex pattern for SSS ciphertext markers.")

(defconst sss-any-pattern "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}"
  "Regex pattern for any SSS marker.")

(defun sss-pattern-at-point ()
  "Return SSS pattern at point, or nil if none found.
Returns (start . end) positions of the pattern."
  (save-excursion
    (let ((original-point (point)))
      ;; Move to start of pattern if we're inside one
      (while (and (not (bobp))
                  (not (looking-at sss-any-pattern))
                  (> (point) (line-beginning-position)))
        (backward-char))

      (when (looking-at sss-any-pattern)
        (let ((start (point))
              (end (match-end 0)))
          ;; Verify original point was within the pattern
          (when (<= start original-point end)
            (cons start end)))))))

(defun sss-pattern-type-at-point ()
  "Return type of SSS pattern at point: 'plaintext, 'ciphertext, or nil."
  (when-let ((pattern-bounds (sss-pattern-at-point)))
    (save-excursion
      (goto-char (car pattern-bounds))
      (cond
       ((looking-at sss-plaintext-pattern) 'plaintext)
       ((looking-at sss-ciphertext-pattern) 'ciphertext)
       (t nil)))))

(defun sss-extract-pattern-content (text)
  "Extract content from SSS pattern TEXT.
Returns the content between braces, or nil if invalid pattern."
  (when (string-match "\\(?:⊕\\|o\\+\\|⊠\\){\\([^}]*\\)}" text)
    (match-string 1 text)))

(defun sss-wrap-content (content type)
  "Wrap CONTENT in SSS pattern of TYPE ('plaintext or 'ciphertext).
For plaintext, uses UTF-8 marker (⊕) by default."
  (pcase type
    ('plaintext (format "⊕{%s}" content))
    ('ciphertext (format "⊠{%s}" content))
    (_ (error "Invalid pattern type: %s" type))))

;;; Buffer analysis

(defun sss-count-patterns (&optional buffer)
  "Count SSS patterns in BUFFER (or current buffer).
Returns alist: ((plaintext . count) (ciphertext . count) (total . count))"
  (with-current-buffer (or buffer (current-buffer))
    (save-excursion
      (goto-char (point-min))
      (let ((plaintext-count 0)
            (ciphertext-count 0))

        ;; Count plaintext patterns
        (goto-char (point-min))
        (while (re-search-forward sss-plaintext-pattern nil t)
          (cl-incf plaintext-count))

        ;; Count ciphertext patterns
        (goto-char (point-min))
        (while (re-search-forward sss-ciphertext-pattern nil t)
          (cl-incf ciphertext-count))

        `((plaintext . ,plaintext-count)
          (ciphertext . ,ciphertext-count)
          (total . ,(+ plaintext-count ciphertext-count)))))))

(defun sss-buffer-has-patterns-p (&optional buffer)
  "Check if BUFFER (or current buffer) contains any SSS patterns."
  (> (cdr (assoc 'total (sss-count-patterns buffer))) 0))

(defun sss-find-all-patterns (&optional buffer)
  "Find all SSS patterns in BUFFER (or current buffer).
Returns list of (start end type content) for each pattern."
  (with-current-buffer (or buffer (current-buffer))
    (save-excursion
      (goto-char (point-min))
      (let ((patterns '()))
        (while (re-search-forward sss-any-pattern nil t)
          (let* ((start (match-beginning 0))
                 (end (match-end 0))
                 (text (match-string 0))
                 (content (sss-extract-pattern-content text))
                 (type (save-excursion
                         (goto-char start)
                         (sss-pattern-type-at-point))))
            (push (list start end type content) patterns)))
        (nreverse patterns)))))

;;; File utilities

(defun sss-file-has-patterns-p (filename)
  "Check if FILENAME contains SSS patterns."
  (when (file-readable-p filename)
    (with-temp-buffer
      (insert-file-contents filename)
      (sss-buffer-has-patterns-p))))

(defun sss-safe-file-name (filename)
  "Generate safe backup filename for FILENAME."
  (let ((dir (file-name-directory filename))
        (base (file-name-nondirectory filename)))
    (expand-file-name (format ".sss-backup-%s-%s"
                              (format-time-string "%Y%m%d-%H%M%S")
                              base)
                      dir)))

(defun sss-create-backup (filename)
  "Create backup of FILENAME before SSS processing.
Returns backup filename."
  (when (file-exists-p filename)
    (let ((backup-file (sss-safe-file-name filename)))
      (copy-file filename backup-file)
      backup-file)))

;;; Text processing utilities

(defun sss-normalise-line-endings (text)
  "Normalise line endings in TEXT to Unix format."
  (replace-regexp-in-string "\r\n\\|\r" "\n" text))

(defun sss-sanitize-content (content)
  "Sanitize CONTENT for use in SSS patterns.
Removes problematic characters and normalises whitespace."
  (let ((sanitized (string-trim content)))
    ;; Remove or escape problematic characters
    (setq sanitized (replace-regexp-in-string "[{}]" "" sanitized))
    ;; Normalise whitespace
    (setq sanitized (replace-regexp-in-string "\\s-+" " " sanitized))
    sanitized))

;;; Validation utilities

(defun sss-valid-username-p (username)
  "Check if USERNAME is valid for SSS operations."
  (and (stringp username)
       (> (length username) 0)
       (< (length username) 256)
       (string-match "^[a-zA-Z0-9_.-]+$" username)))

(defun sss-valid-pattern-p (text)
  "Check if TEXT is a valid SSS pattern."
  (and (stringp text)
       (string-match sss-any-pattern text)
       (= (match-beginning 0) 0)
       (= (match-end 0) (length text))))

;;; Formatting utilities

(defun sss-format-file-size (size)
  "Format file SIZE in bytes to human-readable format."
  (cond
   ((< size 1024) (format "%d B" size))
   ((< size (* 1024 1024)) (format "%.1f KB" (/ size 1024.0)))
   ((< size (* 1024 1024 1024)) (format "%.1f MB" (/ size (* 1024.0 1024))))
   (t (format "%.1f GB" (/ size (* 1024.0 1024 1024))))))

(defun sss-format-duration (seconds)
  "Format SECONDS into human-readable duration."
  (cond
   ((< seconds 60) (format "%.1fs" seconds))
   ((< seconds 3600) (format "%dm %.1fs" (/ seconds 60) (mod seconds 60)))
   (t (format "%dh %dm" (/ seconds 3600) (/ (mod seconds 3600) 60)))))

;;; Interactive utilities

;;;###autoload
(defun sss-count-patterns-interactive ()
  "Count and display SSS patterns in current buffer."
  (interactive)
  (let ((counts (sss-count-patterns)))
    (message "SSS patterns: %d plaintext, %d ciphertext, %d total"
             (cdr (assoc 'plaintext counts))
             (cdr (assoc 'ciphertext counts))
             (cdr (assoc 'total counts)))))

;;;###autoload
(defun sss-show-pattern-at-point ()
  "Show information about SSS pattern at point."
  (interactive)
  (if-let ((bounds (sss-pattern-at-point)))
      (let* ((text (buffer-substring (car bounds) (cdr bounds)))
             (type (sss-pattern-type-at-point))
             (content (sss-extract-pattern-content text)))
        (message "SSS pattern: %s, type: %s, content: %s"
                 text type (or content "invalid")))
    (message "No SSS pattern at point")))

;;;###autoload
(defun sss-goto-next-pattern ()
  "Go to next SSS pattern in buffer."
  (interactive)
  (if (re-search-forward sss-any-pattern nil t)
      (goto-char (match-beginning 0))
    (message "No more SSS patterns found")))

;;;###autoload
(defun sss-goto-previous-pattern ()
  "Go to previous SSS pattern in buffer."
  (interactive)
  (if (re-search-backward sss-any-pattern nil t)
      (goto-char (match-beginning 0))
    (message "No previous SSS patterns found")))

;;;###autoload
(defun sss-list-patterns-in-buffer ()
  "List all SSS patterns in current buffer."
  (interactive)
  (let ((patterns (sss-find-all-patterns)))
    (if patterns
        (with-current-buffer (get-buffer-create "*SSS Patterns*")
          (erase-buffer)
          (insert (format "SSS Patterns in %s\n" (buffer-name)))
          (insert (format "===========================\n\n"))
          (insert (format "Found %d patterns:\n\n" (length patterns)))

          (dolist (pattern patterns)
            (let ((start (nth 0 pattern))
                  (end (nth 1 pattern))
                  (type (nth 2 pattern))
                  (content (nth 3 pattern)))
              (insert (format "Line %d: %s pattern\n"
                              (line-number-at-pos start)
                              type))
              (insert (format "  Content: %s\n"
                              (if (> (length content) 50)
                                  (concat (substring content 0 47) "...")
                                content)))
              (insert "\n")))

          (display-buffer (current-buffer)))
      (message "No SSS patterns found in buffer"))))

;;; Clipboard utilities

;;;###autoload
(defun sss-copy-pattern-content ()
  "Copy content of SSS pattern at point to clipboard."
  (interactive)
  (if-let ((bounds (sss-pattern-at-point)))
      (let* ((text (buffer-substring (car bounds) (cdr bounds)))
             (content (sss-extract-pattern-content text)))
        (if content
            (progn
              (kill-new content)
              (message "Copied pattern content: %s" content))
          (message "Invalid SSS pattern at point")))
    (message "No SSS pattern at point")))

;;;###autoload
(defun sss-paste-as-pattern (type)
  "Paste clipboard content as SSS pattern of TYPE."
  (interactive (list (intern (completing-read "Pattern type: "
                                              '("plaintext" "ciphertext")
                                              nil t))))
  (let ((content (current-kill 0)))
    (when content
      (insert (sss-wrap-content (sss-sanitize-content content) type)))))

;;; Debug utilities

(defvar sss-debug nil
  "Enable SSS debug mode.")

(defun sss-debug-message (format-string &rest args)
  "Print debug message if `sss-debug' is enabled."
  (when sss-debug
    (apply #'message (concat "SSS DEBUG: " format-string) args)))

;;;###autoload
(defun sss-toggle-debug ()
  "Toggle SSS debug mode."
  (interactive)
  (setq sss-debug (not sss-debug))
  (message "SSS debug mode: %s" (if sss-debug "enabled" "disabled")))

;;; Performance utilities

(defmacro sss-with-timing (description &rest body)
  "Execute BODY and report timing with DESCRIPTION."
  (declare (indent 1))
  `(let ((start-time (current-time)))
     (prog1 (progn ,@body)
       (let ((elapsed (float-time (time-subtract (current-time) start-time))))
         (sss-debug-message "%s took %s" ,description (sss-format-duration elapsed))))))

;;; Export functions

(defun sss-export-patterns-to-csv (filename)
  "Export SSS patterns in current buffer to CSV FILENAME."
  (interactive "FSave patterns to CSV file: ")
  (let ((patterns (sss-find-all-patterns)))
    (with-temp-file filename
      (insert "Line,Type,Content\n")
      (dolist (pattern patterns)
        (let ((line (line-number-at-pos (nth 0 pattern)))
              (type (nth 2 pattern))
              (content (nth 3 pattern)))
          (insert (format "%d,%s,\"%s\"\n"
                          line
                          type
                          (replace-regexp-in-string "\"" "\"\"" content))))))
    (message "Exported %d patterns to %s" (length patterns) filename)))

(provide 'sss-utils)

;;; sss-utils.el ends here