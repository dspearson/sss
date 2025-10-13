;;; sss-mode.el --- SSS minor mode with syntax highlighting -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; This file provides the SSS minor mode with syntax highlighting,
;; keybindings, and automatic file processing hooks.

;;; Code:

;; Forward declarations to avoid circular dependencies
(defvar sss-keybinding-prefix)
(defvar sss--current-username)
(defvar sss-highlight-patterns)
(defvar sss-fancy-mode)
(defvar sss-auto-decrypt-on-open)
(defvar sss-auto-encrypt-on-save)
(defvar sss-executable)

(declare-function sss-encrypt-region "sss")
(declare-function sss-decrypt-region "sss")
(declare-function sss-toggle-at-point "sss")
(declare-function sss-process-buffer "sss")
(declare-function sss-render-buffer "sss")
(declare-function sss-process-file "sss")
(declare-function sss-render-file "sss")
(declare-function sss-edit-file "sss")
(declare-function sss-select-user "sss")
(declare-function sss-init-project "sss")
(declare-function sss-list-keys "sss")
(declare-function sss-show-pubkey "sss")
(declare-function sss-list-users "sss")
(declare-function sss-clear-cache "sss")
(declare-function sss-show-version "sss")
(declare-function sss-preview-secret-at-point "sss")
(declare-function sss-goto-next-pattern "sss")
(declare-function sss-goto-previous-pattern "sss")
(declare-function sss-copy-pattern-content "sss")
(declare-function sss-toggle-fancy-mode "sss")
(declare-function sss-help "sss")
(declare-function sss--get-username "sss")
(declare-function sss--executable-available-p "sss")
(declare-function sss--apply-fancy-overlays "sss")
(declare-function sss--remove-fancy-overlays "sss")
(declare-function sss--after-change-function "sss")

;;; Font-lock support

(defface sss-plaintext-face
  '((t :foreground "#98C379" :weight bold))
  "Face for SSS plaintext markers (⊕{} and o+{})."
  :group 'sss)

(defface sss-ciphertext-face
  '((t :foreground "#E06C75" :weight bold))
  "Face for SSS ciphertext markers (⊠{})."
  :group 'sss)

(defface sss-content-face
  '((t :foreground "#ABB2BF" :slant italic))
  "Face for plaintext content inside SSS markers."
  :group 'sss)

(defface sss-encrypted-content-face
  '((t :foreground "#61AFEF" :background "#2C323C" :slant italic))
  "Face for encrypted content inside ciphertext markers."
  :group 'sss)

(defface sss-braces-face
  '((t :foreground "#C678DD" :weight bold))
  "Face for braces in SSS patterns."
  :group 'sss)

(defvar sss-font-lock-keywords
  `(
    ;; Plaintext markers: ⊕{content} and o+{content}
    ("\\(⊕\\|o\\+\\)\\({\\)\\([^}]*\\)\\(}\\)"
     (1 'sss-plaintext-face)
     (2 'sss-braces-face)
     (3 'sss-content-face)
     (4 'sss-braces-face))

    ;; Ciphertext markers: ⊠{content}
    ("\\(⊠\\)\\({\\)\\([^}]*\\)\\(}\\)"
     (1 'sss-ciphertext-face)
     (2 'sss-braces-face)
     (3 'sss-encrypted-content-face)
     (4 'sss-braces-face)))
  "Font-lock keywords for SSS patterns.")

;;; Mode line

;; Disabled for now to avoid mode-line errors
;; (defvar sss-mode-line-format
;;   '(:eval (when sss-mode
;;             (let ((username (cond
;;                              ((stringp sss--current-username) sss--current-username)
;;                              ((null sss--current-username) "auto")
;;                              (t "auto"))))
;;               (format " SSS[%s]" username))))
;;   "Mode line format for SSS mode.")

;;; Keymap

(defvar sss-mode-map (make-sparse-keymap)
  "Keymap for SSS mode.")

(defun sss--setup-keymap ()
  "Set up the SSS mode keymap with proper prefix keys."
  ;; Clear any existing bindings first
  (setq sss-mode-map (make-sparse-keymap))
  ;; Parse the prefix key string
  (let ((prefix-key (kbd (or sss-keybinding-prefix "C-c s"))))
    (define-key sss-mode-map (vconcat prefix-key (kbd "e")) #'sss-encrypt-region)
    (define-key sss-mode-map (vconcat prefix-key (kbd "d")) #'sss-decrypt-region)
    (define-key sss-mode-map (vconcat prefix-key (kbd "t")) #'sss-toggle-at-point)
    (define-key sss-mode-map (vconcat prefix-key (kbd "b")) #'sss-process-buffer)
    (define-key sss-mode-map (vconcat prefix-key (kbd "r")) #'sss-render-buffer)
    (define-key sss-mode-map (vconcat prefix-key (kbd "f")) #'sss-process-file)
    (define-key sss-mode-map (vconcat prefix-key (kbd "R")) #'sss-render-file)
    (define-key sss-mode-map (vconcat prefix-key (kbd "E")) #'sss-edit-file)
    (define-key sss-mode-map (vconcat prefix-key (kbd "u")) #'sss-select-user)
    (define-key sss-mode-map (vconcat prefix-key (kbd "i")) #'sss-init-project)
    (define-key sss-mode-map (vconcat prefix-key (kbd "k")) #'sss-list-keys)
    (define-key sss-mode-map (vconcat prefix-key (kbd "p")) #'sss-show-pubkey)
    (define-key sss-mode-map (vconcat prefix-key (kbd "U")) #'sss-list-users)
    (define-key sss-mode-map (vconcat prefix-key (kbd "c")) #'sss-clear-cache)
    (define-key sss-mode-map (vconcat prefix-key (kbd "v")) #'sss-show-version)
    (define-key sss-mode-map (vconcat prefix-key (kbd "s")) #'sss-preview-secret-at-point)
    (define-key sss-mode-map (vconcat prefix-key (kbd "n")) #'sss-goto-next-pattern)
    (define-key sss-mode-map (vconcat prefix-key (kbd "N")) #'sss-goto-previous-pattern)
    (define-key sss-mode-map (vconcat prefix-key (kbd "y")) #'sss-copy-pattern-content)
    (define-key sss-mode-map (vconcat prefix-key (kbd "F")) #'sss-toggle-fancy-mode)
    (define-key sss-mode-map (vconcat prefix-key (kbd "h")) #'sss-help)))



;;; Mode definition

;;;###autoload
(define-minor-mode sss-mode
  "Minor mode for Secret String Substitution.

This mode provides syntax highlighting for SSS patterns, keybindings
for common operations, and automatic file processing hooks.

Key bindings:
\\{sss-mode-map}"
  :init-value nil
  :keymap sss-mode-map
  :group 'sss

  ;; Set up keymap if not already done
  (sss--setup-keymap)

  (if sss-mode
      (progn
        ;; Enable syntax highlighting
        (when sss-highlight-patterns
          (font-lock-add-keywords nil sss-font-lock-keywords 'append)
          (font-lock-flush))

        ;; Set up fancy mode if enabled
        (when sss-fancy-mode
          (sss--apply-fancy-overlays))

        ;; Add change detection for fancy mode
        (add-hook 'after-change-functions #'sss--after-change-function nil t)

        (message "SSS mode enabled"))

    (progn
      ;; Disable syntax highlighting
      (when sss-highlight-patterns
        (font-lock-remove-keywords nil sss-font-lock-keywords)
        (font-lock-flush))

      ;; Remove change detection hook
      (remove-hook 'after-change-functions #'sss--after-change-function t)

      ;; Clean up fancy mode
      (sss--remove-fancy-overlays)

      (message "SSS mode disabled"))))

;;; Project detection

(defun sss-in-project-p ()
  "Check if current buffer is in an SSS project using SSS CLI."
  (when (sss--executable-available-p)
    (let ((default-directory (or (when (buffer-file-name)
                                   (file-name-directory (buffer-file-name)))
                                 default-directory)))
      (= 0 (call-process sss-executable nil nil nil "status")))))

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
    (princ "  M-x customize-group RET sss RET\n")))


(provide 'sss-mode)

;;; sss-mode.el ends here