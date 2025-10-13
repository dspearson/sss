;;; sss-doom.el --- Doom Emacs integration for SSS -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files, doom
;; Version: 1.0
;; Package-Requires: ((emacs "30.1") (doom-core "3.0.0"))

;;; Commentary:

;; This file provides Doom Emacs integration for SSS, including
;; leader key bindings, evil integration, and Doom-style configuration.
;;
;; To use this integration, add to your Doom config:
;;   (use-package! sss-doom
;;     :after sss)

;;; Code:

;;; Doom detection and requirements

(defvar doom-leader-key)
(defvar doom-localleader-key)

(declare-function map! "doom-core")
(declare-function after! "doom-core")
(declare-function use-package! "doom-core")

;;; Evil integration

(when (featurep 'evil)
  (evil-define-operator sss-evil-encrypt (beg end)
    "Evil operator to encrypt region."
    :motion evil-line
    (sss-encrypt-region beg end))

  (evil-define-operator sss-evil-decrypt (beg end)
    "Evil operator to decrypt region."
    :motion evil-line
    (sss-decrypt-region beg end))

  (evil-define-operator sss-evil-toggle (beg end)
    "Evil operator to toggle encryption at point or region."
    :motion evil-line
    (if (= beg end)
        (sss-toggle-at-point)
      (sss-encrypt-region beg end))))

;;; Doom keybindings

(defun sss--setup-doom-keybindings ()
  "Set up Doom-style keybindings for SSS."
  (when (fboundp 'map!)
    ;; Ensure functions are available
    (require 'sss)
    (require 'sss-ui)

    ;; Global leader bindings - only for project setup and key management
    (map! :leader
          (:prefix-map ("e" . "encryption")
           (:prefix-map ("p" . "project")
            :desc "Initialize project" "i" #'sss-init-project)

           (:prefix-map ("k" . "keys")
            :desc "Generate keypair" "g" #'sss-generate-keypair
            :desc "List keys" "l" #'sss-list-keys
            :desc "Show public key" "p" #'sss-show-pubkey)

           :desc "Help" "h" #'sss-help
           :desc "Version" "v" #'sss-show-version))

    ;; Local leader bindings for sss-mode
    (map! :localleader
          :map sss-mode-map
          :desc "SSS menu" "SPC" #'sss-menu
          :desc "Encrypt region" "e" #'sss-encrypt-region
          :desc "Decrypt region" "d" #'sss-decrypt-region
          :desc "Toggle at point" "t" #'sss-toggle-at-point
          :desc "Preview secret" "s" #'sss-preview-secret-at-point
          :desc "Process buffer" "b" #'sss-process-buffer
          :desc "Preview buffer" "v" #'sss-preview-buffer
          :desc "Render buffer" "r" #'sss-render-buffer
          :desc "Select user" "u" #'sss-select-user
          :desc "Next pattern" "n" #'sss-goto-next-pattern
          :desc "Previous pattern" "N" #'sss-goto-previous-pattern
          :desc "Copy pattern content" "y" #'sss-copy-pattern-content
          :desc "Help" "h" #'sss-help)

    ;; Evil operator bindings
    (when (featurep 'evil)
      (map! :map evil-normal-state-map
            :desc "SSS encrypt operator" "ge" #'sss-evil-encrypt
            :desc "SSS decrypt operator" "gd" #'sss-evil-decrypt
            :desc "SSS toggle operator" "gt" #'sss-evil-toggle)

      (map! :map evil-visual-state-map
            :desc "Encrypt selection" "E" #'sss-encrypt-region
            :desc "Decrypt selection" "D" #'sss-decrypt-region))))






;;; Auto-setup for Doom

(defun sss-doom-setup ()
  "Set up SSS for Doom Emacs."
  (interactive)
  (sss--setup-doom-keybindings)
  (message "SSS Doom integration configured (keybindings)"))

;; Note: Auto-setup disabled to prevent conflicts
;; Call (sss-doom-setup) manually in your config

;;; Configuration helpers for Doom users

;;;###autoload
(defun sss-doom-config-template ()
  "Insert Doom configuration template for SSS."
  (interactive)
  (let ((config "
;; SSS (Secret String Substitution) configuration for Doom Emacs
(use-package! sss
  :commands (sss-mode sss-init-project)
  :init
  ;; Set default username
  (setq sss-default-username \"your-username\")

  ;; SSS mode should be enabled manually or via sss status check

  :config
  ;; Load Doom integration
  (require 'sss-doom)

  ;; Customize settings
  (setq sss-auto-decrypt-on-open t
        sss-auto-encrypt-on-save t
        sss-highlight-patterns t
        sss-password-cache-timeout 300)

  ;; Optional: Custom file patterns
  (setq sss-auto-mode-patterns '(\"\\.sss\\'\" \"\\.secret\\'\" \"\\.enc\\'\"))

  ;; Optional: Enable for specific major modes
  (add-hook 'conf-mode-hook #'sss-mode)
  (add-hook 'yaml-mode-hook #'sss-mode))

;; Optional: Transient menus (requires transient package)
(use-package! sss-ui
  :after sss
  :config
  (map! :leader :desc \"SSS Menu\" \"e SPC\" #'sss-menu))"))

    (if (called-interactively-p 'interactive)
        (with-current-buffer (get-buffer-create "*SSS Doom Config*")
          (erase-buffer)
          (insert config)
          (emacs-lisp-mode)
          (display-buffer (current-buffer)))
      config)))

;;; Evil text objects for SSS patterns

(when (featurep 'evil)
  (evil-define-text-object sss-inner-pattern (count &optional beg end type)
    "Inner text object for SSS patterns."
    (when-let ((bounds (sss-pattern-at-point)))
      (let* ((start (car bounds))
             (end (cdr bounds))
             (text (buffer-substring start end))
             (content (sss-extract-pattern-content text)))
        (when content
          ;; Find the content boundaries within the pattern
          (save-excursion
            (goto-char start)
            (when (re-search-forward "{" end t)
              (let ((content-start (point))
                    (content-end (save-excursion
                                   (goto-char end)
                                   (when (re-search-backward "}" start t)
                                     (point)))))
                (when content-end
                  (list content-start content-end)))))))))

  (evil-define-text-object sss-outer-pattern (count &optional beg end type)
    "Outer text object for SSS patterns."
    (when-let ((bounds (sss-pattern-at-point)))
      (list (car bounds) (cdr bounds))))

  ;; Register text objects
  (define-key evil-inner-text-objects-map "s" 'sss-inner-pattern)
  (define-key evil-outer-text-objects-map "s" 'sss-outer-pattern))

(provide 'sss-doom)

;;; sss-doom.el ends here
