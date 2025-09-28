;;; sss-mode.el --- SSS minor mode with syntax highlighting -*- lexical-binding: t; -*-

;; Copyright (C) 2024

;; Author: SSS Contributors
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "26.1"))

;;; Commentary:

;; This file provides the SSS minor mode with syntax highlighting,
;; keybindings, and automatic file processing hooks.

;;; Code:

(require 'sss)

;;; Font-lock support

(defface sss-plaintext-face
  '((t :foreground "green" :weight bold))
  "Face for SSS plaintext markers (⊕{} and o+{})."
  :group 'sss)

(defface sss-ciphertext-face
  '((t :foreground "red" :weight bold))
  "Face for SSS ciphertext markers (⊠{})."
  :group 'sss)

(defface sss-content-face
  '((t :background "grey90"))
  "Face for content inside SSS markers."
  :group 'sss)

(defvar sss-font-lock-keywords
  `(
    ;; Plaintext markers: ⊕{content} and o+{content}
    ("\\(⊕\\|o\\+\\)\\({\\)\\([^}]*\\)\\(}\\)"
     (1 'sss-plaintext-face)
     (2 'sss-plaintext-face)
     (3 'sss-content-face)
     (4 'sss-plaintext-face))

    ;; Ciphertext markers: ⊠{content}
    ("\\(⊠\\)\\({\\)\\([^}]*\\)\\(}\\)"
     (1 'sss-ciphertext-face)
     (2 'sss-ciphertext-face)
     (3 'sss-content-face)
     (4 'sss-ciphertext-face)))
  "Font-lock keywords for SSS patterns.")

;;; Mode line

(defvar sss-mode-line-format
  '(:eval (when sss-mode
            (format " SSS[%s]" (or sss--current-username "auto"))))
  "Mode line format for SSS mode.")

;;; Keymap

(defvar sss-mode-map
  (let ((map (make-sparse-keymap)))
    ;; Parse the prefix key string
    (let ((prefix-key (kbd sss-keybinding-prefix)))
      (define-key map (vconcat prefix-key (kbd "e")) #'sss-encrypt-region)
      (define-key map (vconcat prefix-key (kbd "d")) #'sss-decrypt-region)
      (define-key map (vconcat prefix-key (kbd "t")) #'sss-toggle-at-point)
      (define-key map (vconcat prefix-key (kbd "b")) #'sss-process-buffer)
      (define-key map (vconcat prefix-key (kbd "r")) #'sss-render-buffer)
      (define-key map (vconcat prefix-key (kbd "f")) #'sss-process-file)
      (define-key map (vconcat prefix-key (kbd "R")) #'sss-render-file)
      (define-key map (vconcat prefix-key (kbd "E")) #'sss-edit-file)
      (define-key map (vconcat prefix-key (kbd "u")) #'sss-select-user)
      (define-key map (vconcat prefix-key (kbd "i")) #'sss-init-project)
      (define-key map (vconcat prefix-key (kbd "k")) #'sss-list-keys)
      (define-key map (vconcat prefix-key (kbd "p")) #'sss-show-pubkey)
      (define-key map (vconcat prefix-key (kbd "U")) #'sss-list-users)
      (define-key map (vconcat prefix-key (kbd "c")) #'sss-clear-cache)
      (define-key map (vconcat prefix-key (kbd "v")) #'sss-show-version)
      (define-key map (vconcat prefix-key (kbd "h")) #'sss-help))
    map)
  "Keymap for SSS mode.")

;;; Auto-mode patterns

(defcustom sss-auto-mode-patterns
  '("\\.sss\\'" "\\.secret\\'" "\\.enc\\'")
  "File patterns that should automatically enable SSS mode."
  :type '(repeat regexp)
  :group 'sss)

;;; File hooks

(defun sss--auto-decrypt-file ()
  "Automatically decrypt file if it contains SSS patterns."
  (when (and sss-auto-decrypt-on-open
             (sss--buffer-has-sss-patterns-p))
    (condition-case err
        (let ((username (sss--get-username)))
          (sss-process-buffer username)
          (message "Auto-decrypted file with user: %s" username))
      (error
       (message "Failed to auto-decrypt: %s" (error-message-string err))))))

(defun sss--auto-encrypt-file ()
  "Automatically encrypt file if SSS mode is enabled."
  (when (and sss-auto-encrypt-on-save
             sss-mode
             (sss--buffer-has-sss-patterns-p))
    (condition-case err
        (let ((username (sss--get-username)))
          (sss-process-buffer username)
          (message "Auto-encrypted file with user: %s" username))
      (error
       (message "Failed to auto-encrypt: %s" (error-message-string err))))))

(defun sss--buffer-has-sss-patterns-p ()
  "Check if current buffer contains SSS patterns."
  (save-excursion
    (goto-char (point-min))
    (re-search-forward "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}" nil t)))

;;; Mode definition

;;;###autoload
(define-minor-mode sss-mode
  "Minor mode for Secret String Substitution.

This mode provides syntax highlighting for SSS patterns, keybindings
for common operations, and automatic file processing hooks.

Key bindings:
\\{sss-mode-map}"
  :init-value nil
  :lighter sss-mode-line-format
  :keymap sss-mode-map
  :group 'sss

  (if sss-mode
      (progn
        ;; Enable syntax highlighting
        (when sss-highlight-patterns
          (font-lock-add-keywords nil sss-font-lock-keywords)
          (font-lock-refresh-defaults))

        ;; Add file hooks
        (add-hook 'find-file-hook #'sss--auto-decrypt-file nil t)
        (add-hook 'before-save-hook #'sss--auto-encrypt-file nil t)

        (message "SSS mode enabled"))

    (progn
      ;; Disable syntax highlighting
      (when sss-highlight-patterns
        (font-lock-remove-keywords nil sss-font-lock-keywords)
        (font-lock-refresh-defaults))

      ;; Remove file hooks
      (remove-hook 'find-file-hook #'sss--auto-decrypt-file t)
      (remove-hook 'before-save-hook #'sss--auto-encrypt-file t)

      (message "SSS mode disabled"))))

;;; Auto-mode setup

;;;###autoload
(defun sss-setup-auto-mode ()
  "Set up automatic SSS mode for configured file patterns."
  (dolist (pattern sss-auto-mode-patterns)
    (add-to-list 'auto-mode-alist (cons pattern #'sss-mode))))

;;; Help function

;;;###autoload
(defun sss-help ()
  "Show SSS mode help."
  (interactive)
  (with-help-window "*SSS Help*"
    (princ "SSS Mode - Secret String Substitution\n")
    (princ "======================================\n\n")
    (princ "Key Bindings (prefix: ")
    (princ sss-keybinding-prefix)
    (princ "):\n\n")
    (princ "Text Operations:\n")
    (princ "  e  - Encrypt region\n")
    (princ "  d  - Decrypt region\n")
    (princ "  t  - Toggle encryption at point\n")
    (princ "  b  - Process entire buffer\n")
    (princ "  r  - Render buffer (decrypt all)\n\n")
    (princ "File Operations:\n")
    (princ "  f  - Process file\n")
    (princ "  R  - Render file (decrypt all)\n")
    (princ "  E  - Edit file with SSS\n\n")
    (princ "Project Management:\n")
    (princ "  i  - Initialize project\n")
    (princ "  u  - Select user\n")
    (princ "  U  - List users\n\n")
    (princ "Key Management:\n")
    (princ "  k  - List keys\n")
    (princ "  p  - Show public key\n\n")
    (princ "Utilities:\n")
    (princ "  c  - Clear password cache\n")
    (princ "  v  - Show version\n")
    (princ "  h  - Show this help\n\n")
    (princ "SSS Patterns:\n")
    (princ "  ⊕{text}  - Plaintext (UTF-8)\n")
    (princ "  o+{text} - Plaintext (ASCII)\n")
    (princ "  ⊠{text}  - Ciphertext\n\n")
    (princ "Configuration:\n")
    (princ "  M-x customise-group RET sss RET\n")))

(provide 'sss-mode)

;;; sss-mode.el ends here