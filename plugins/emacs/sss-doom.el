;;; sss-doom.el --- Doom Emacs integration for SSS -*- lexical-binding: t; -*-

;; Copyright (C) 2024

;; Author: SSS Contributors
;; Keywords: encryption, security, files, doom
;; Version: 1.0
;; Package-Requires: ((emacs "26.1") (doom-core "3.0.0"))

;;; Commentary:

;; This file provides Doom Emacs integration for SSS, including
;; leader key bindings, evil integration, and Doom-style configuration.
;;
;; To use this integration, add to your Doom config:
;;   (use-package! sss-doom
;;     :after sss)

;;; Code:

(require 'sss)
(require 'sss-mode)

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
    ;; Global leader bindings under 'e' for encryption
    (map! :leader
          (:prefix-map ("e" . "encryption")
           :desc "SSS menu" "SPC" #'sss-menu
           :desc "Encrypt region" "e" #'sss-encrypt-region
           :desc "Decrypt region" "d" #'sss-decrypt-region
           :desc "Toggle at point" "t" #'sss-toggle-at-point
           :desc "Process buffer" "b" #'sss-process-buffer
           :desc "Render buffer" "r" #'sss-render-buffer
           :desc "Process file" "f" #'sss-process-file
           :desc "Render file" "R" #'sss-render-file
           :desc "Edit file" "E" #'sss-edit-file

           (:prefix-map ("p" . "project")
            :desc "Initialize project" "i" #'sss-init-project
            :desc "Project info" "I" #'sss-show-project-info
            :desc "Project status" "s" #'sss-project-status
            :desc "List users" "l" #'sss-list-users
            :desc "Add user" "a" #'sss-add-user
            :desc "Remove user" "r" #'sss-remove-user
            :desc "Select user" "u" #'sss-select-user
            :desc "Open config" "c" #'sss-open-project-config
            :desc "Goto root" "g" #'sss-goto-project-root
            :desc "Find encrypted files" "f" #'sss-find-encrypted-files-interactive)

           (:prefix-map ("k" . "keys")
            :desc "Generate keypair" "g" #'sss-generate-keypair
            :desc "List keys" "l" #'sss-list-keys
            :desc "Show public key" "p" #'sss-show-pubkey
            :desc "Show fingerprint" "f" #'sss-show-fingerprint
            :desc "Set current key" "c" #'sss-set-current-key
            :desc "Delete key" "d" #'sss-delete-key)

           (:prefix-map ("s" . "settings")
            :desc "Show settings" "s" #'sss-show-settings
            :desc "Set username" "u" #'sss-set-default-username
            :desc "Set editor" "e" #'sss-set-editor
            :desc "Toggle auto-decrypt" "d" #'sss-toggle-auto-decrypt
            :desc "Toggle auto-encrypt" "E" #'sss-toggle-auto-encrypt
            :desc "Toggle highlighting" "h" #'sss-toggle-highlighting
            :desc "Clear cache" "c" #'sss-clear-cache
            :desc "Reset settings" "r" #'sss-reset-settings)

           :desc "Help" "h" #'sss-help
           :desc "Version" "v" #'sss-show-version))

    ;; Local leader bindings for sss-mode
    (map! :localleader
          :map sss-mode-map
          :desc "SSS menu" "SPC" #'sss-menu
          :desc "Encrypt region" "e" #'sss-encrypt-region
          :desc "Decrypt region" "d" #'sss-decrypt-region
          :desc "Toggle at point" "t" #'sss-toggle-at-point
          :desc "Process buffer" "b" #'sss-process-buffer
          :desc "Render buffer" "r" #'sss-render-buffer
          :desc "Select user" "u" #'sss-select-user
          :desc "List patterns" "l" #'sss-list-patterns-in-buffer
          :desc "Count patterns" "c" #'sss-count-patterns-interactive
          :desc "Show pattern at point" "p" #'sss-show-pattern-at-point
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

;;; Doom modeline integration

(defun sss--doom-modeline-segment ()
  "Doom modeline segment for SSS."
  (when sss-mode
    (concat " "
            (propertize "SSS" 'face 'doom-modeline-info)
            (when sss--current-username
              (propertize (format "[%s]" sss--current-username)
                         'face 'doom-modeline-buffer-minor-mode)))))

;; Add to doom modeline if available
(with-eval-after-load 'doom-modeline
  (doom-modeline-def-segment sss
    (sss--doom-modeline-segment))

  ;; Add to default segments (users can customise this)
  (doom-modeline-def-modeline 'sss-modeline
    '(bar workspace-name window-number modals matches follow buffer-info remote-host buffer-position word-count parrot selection-info)
    '(misc-info persp-name battery grip irc mu4e gnus github debug repl lsp minor-modes sss input-method indent-info buffer-encoding major-mode process vcs checker)))

;;; Doom snippets integration

(defvar sss-doom-snippets-dir
  (expand-file-name "snippets" (file-name-directory (or load-file-name buffer-file-name)))
  "Directory for SSS yasnippet snippets.")

(defun sss--setup-doom-snippets ()
  "Set up SSS snippets for Doom."
  (when (and (featurep 'yasnippet) (bound-and-true-p yas-global-mode))
    (when (file-exists-p sss-doom-snippets-dir)
      (add-to-list 'yas-snippet-dirs sss-doom-snippets-dir t)
      (yas-reload-all))))

;;; Which-key integration for Doom

(defun sss--setup-doom-which-key ()
  "Set up which-key integration for Doom."
  (when (featurep 'which-key)
    (which-key-add-key-based-replacements
      (concat doom-leader-key " e") "encryption"
      (concat doom-leader-key " e p") "project"
      (concat doom-leader-key " e k") "keys"
      (concat doom-leader-key " e s") "settings"
      (concat doom-localleader-key " SPC") "sss-menu")

    ;; Add descriptions for evil operators
    (when (featurep 'evil)
      (which-key-add-key-based-replacements
        "g e" "sss-encrypt"
        "g d" "sss-decrypt"
        "g t" "sss-toggle"))))

;;; Doom project integration

(with-eval-after-load 'projectile
  (defun sss--projectile-project-p (project-root)
    "Check if PROJECT-ROOT is an SSS project."
    (file-exists-p (expand-file-name ".sss.toml" project-root)))

  (add-to-list 'projectile-project-root-functions #'sss--projectile-project-p))

;;; Doom popup integration

(when (featurep 'doom-popup)
  (set-popup-rule! "^\\*SSS" :side 'bottom :height 0.3 :select t :quit t)
  (set-popup-rule! "^\\*SSS Menu\\*" :side 'bottom :height 0.4 :select t :quit t)
  (set-popup-rule! "^\\*SSS Project Info\\*" :side 'right :width 0.4 :select t :quit t)
  (set-popup-rule! "^\\*SSS Keys\\*" :side 'bottom :height 0.3 :select t :quit t)
  (set-popup-rule! "^\\*SSS Help\\*" :side 'right :width 0.5 :select t :quit t))

;;; Doom treemacs integration

(with-eval-after-load 'treemacs
  (defun sss--treemacs-icon-for-sss-file (file)
    "Return icon for SSS FILE."
    (when (sss-file-has-patterns-p file)
      "🔒"))

  (when (fboundp 'treemacs-define-custom-icon)
    (treemacs-define-custom-icon sss--treemacs-icon-for-sss-file "sss")))

;;; Doom workspace integration

(with-eval-after-load '+workspace
  (defun sss--workspace-contains-sss-files ()
    "Check if current workspace contains SSS files."
    (when-let ((files (sss-find-encrypted-files)))
      (> (length files) 0)))

  ;; Add to workspace buffer display rules
  (when (fboundp '+workspace-buffer-predicate-add)
    (+workspace-buffer-predicate-add #'sss--workspace-contains-sss-files)))

;;; Auto-setup for Doom

(defun sss-doom-setup ()
  "Set up SSS for Doom Emacs."
  (interactive)
  (sss--setup-doom-keybindings)
  (sss--setup-doom-which-key)
  (sss--setup-doom-snippets)
  (message "SSS Doom integration configured"))

;; Auto-setup when this file is loaded in Doom
(when (featurep 'doom-core)
  (add-hook 'doom-init-ui-hook #'sss-doom-setup))

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

  ;; Enable auto-modes
  (add-hook 'doom-first-file-hook #'sss-setup-auto-mode)

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