;;; sss-ui.el --- SSS UI components and transient menus -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; This file provides enhanced UI components for the SSS Emacs interface.
;; Includes transient menus (if transient package is available) and
;; various interactive settings functions.

;;; Code:

(require 'sss)

;; Transient is optional - gracefully handle if not available
(when (or (featurep 'transient)
          (require 'transient nil t))
  (message "SSS: Transient menus available"))

;; If transient is not available, provide fallback message
(unless (featurep 'transient)
  (defun sss--transient-not-available ()
    "Show message when transient is not available."
    (interactive)
    (message "Transient package not available. Install with: M-x package-install RET transient RET")))

;;; Transient menus

(when (featurep 'transient)

;;;###autoload (autoload 'sss-menu "sss-ui" nil t)
(transient-define-prefix sss-menu ()
  "Main SSS menu."
  :man-page "sss"
  ["Text Operations"
   ("e" "Encrypt region" sss-encrypt-region :if-not region-active-p)
   ("d" "Decrypt region" sss-decrypt-region :if-not region-active-p)
   ("E" "Encrypt region" sss-encrypt-region :if region-active-p)
   ("D" "Decrypt region" sss-decrypt-region :if region-active-p)
   ("t" "Toggle at point" sss-toggle-at-point)
   ("b" "Process buffer" sss-process-buffer)
   ("r" "Render buffer" sss-render-buffer)]

  ["File Operations"
   ("f" "Process file..." sss-process-file)
   ("R" "Render file..." sss-render-file)
   ("F" "Edit file..." sss-edit-file)]

  ["Project & Users"
   ("p" "Project menu..." sss-project-menu)
   ("u" "User menu..." sss-user-menu)
   ("k" "Key menu..." sss-key-menu)]

  ["Utilities"
   ("c" "Clear cache" sss-clear-cache)
   ("v" "Show version" sss-show-version)
   ("s" "Settings..." sss-settings-menu)
   ("h" "Help" sss-help)])

;;;###autoload (autoload 'sss-project-menu "sss-ui" nil t)
(transient-define-prefix sss-project-menu ()
  "SSS project management menu."
  ["Project Management"
   ("i" "Initialize project" sss-init-project)
   ("l" "List users" sss-list-users)
   ("a" "Add user..." sss-add-user)
   ("r" "Remove user..." sss-remove-user)
   ("s" "Select user..." sss-select-user)]

  ["Current Selection"
   ("u" sss--show-current-user :description (lambda ()
                                               (format "Current user: %s"
                                                       (or sss--current-username "auto"))))])

;;;###autoload (autoload 'sss-user-menu "sss-ui" nil t)
(transient-define-prefix sss-user-menu ()
  "SSS user management menu."
  ["User Operations"
   ("s" "Select user..." sss-select-user)
   ("l" "List users" sss-list-users)
   ("a" "Add user..." sss-add-user)
   ("r" "Remove user..." sss-remove-user)
   ("i" "User info..." sss-user-info)]

  ["Current Selection"
   ("u" sss--show-current-user :description (lambda ()
                                               (format "Current: %s"
                                                       (or sss--current-username "auto"))))])

;;;###autoload (autoload 'sss-key-menu "sss-ui" nil t)
(transient-define-prefix sss-key-menu ()
  "SSS key management menu."
  ["Key Operations"
   ("g" "Generate keypair" sss-generate-keypair)
   ("l" "List keys" sss-list-keys)
   ("p" "Show public key" sss-show-pubkey)
   ("f" "Show fingerprint" sss-show-fingerprint)
   ("c" "Set current key..." sss-set-current-key)
   ("d" "Delete key..." sss-delete-key)]

  ["Key Generation Options"
   ("G" "Generate (force)" sss-generate-keypair-force)
   ("N" "Generate (no password)" sss-generate-keypair-no-password)])

;;;###autoload (autoload 'sss-settings-menu "sss-ui" nil t)
(transient-define-prefix sss-settings-menu ()
  "SSS settings menu."
  ["Settings"
   ("u" "Set default username..." sss-set-default-username)
   ("e" "Set editor..." sss-set-editor)
   ("c" "Toggle coloured output" sss-toggle-coloured-output)
   ("a" "Toggle auto-decrypt" sss-toggle-auto-decrypt)
   ("s" "Toggle auto-encrypt" sss-toggle-auto-encrypt)
   ("h" "Toggle highlighting" sss-toggle-highlighting)
   ("f" "Toggle fancy mode" sss-toggle-fancy-mode)]

  ["Cache & Cleanup"
   ("C" "Clear password cache" sss-clear-cache)
   ("t" "Set cache timeout..." sss-set-cache-timeout)]

  ["Configuration"
   ("S" "Show settings" sss-show-settings)
   ("r" "Reset settings" sss-reset-settings)
   ("l" "Show config locations" sss-show-config-locations)])

) ; End of (when (featurep 'transient))

;; Fallback functions when transient is not available
(unless (featurep 'transient)
  (defun sss-menu ()
    "Fallback menu when transient is not available."
    (interactive)
    (sss--transient-not-available))

  (defun sss-project-menu ()
    "Fallback project menu when transient is not available."
    (interactive)
    (sss--transient-not-available))

  (defun sss-user-menu ()
    "Fallback user menu when transient is not available."
    (interactive)
    (sss--transient-not-available))

  (defun sss-key-menu ()
    "Fallback key menu when transient is not available."
    (interactive)
    (sss--transient-not-available))

  (defun sss-settings-menu ()
    "Fallback settings menu when transient is not available."
    (interactive)
    (sss--transient-not-available)))

;;; Enhanced interactive functions

;;;###autoload
(defun sss-show-fingerprint ()
  "Show public key fingerprint."
  (interactive)
  (sss-show-pubkey t))

;;;###autoload
(defun sss-generate-keypair-force ()
  "Generate keypair with force option."
  (interactive)
  (sss-generate-keypair t))

;;;###autoload
(defun sss-generate-keypair-no-password ()
  "Generate keypair without password protection."
  (interactive)
  (sss-generate-keypair nil t))

;;;###autoload
(defun sss-user-info (username)
  "Show information about USERNAME."
  (interactive (list (completing-read "Username: " (sss--list-project-users))))
  (let ((output (sss--run-command-success (list "users" "info" username))))
    (with-current-buffer (get-buffer-create "*SSS User Info*")
      (erase-buffer)
      (insert output)
      (display-buffer (current-buffer)))))

(defun sss--show-current-user ()
  "Show current user selection."
  (interactive)
  (message "Current user: %s" (or sss--current-username "auto")))

;;; Settings functions

;;;###autoload
(defun sss-set-default-username (username)
  "Set default USERNAME for SSS operations."
  (interactive "sDefault username (empty to clear): ")
  (setq sss-default-username (if (string-empty-p username) nil username))
  (customize-save-variable 'sss-default-username sss-default-username)
  (message "Default username set to: %s" (or sss-default-username "auto")))

;;;###autoload
(defun sss-set-editor (editor)
  "Set preferred EDITOR for SSS operations."
  (interactive "sEditor command (empty for default): ")
  (let ((editor-val (if (string-empty-p editor) nil editor)))
    (setenv "EDITOR" editor-val)
    (message "Editor set to: %s" (or editor-val "default"))))

;;;###autoload
(defun sss-toggle-coloured-output ()
  "Toggle coloured output preference."
  (interactive)
  (let ((current (getenv "SSS_COLORED")))
    (setenv "SSS_COLORED" (if (equal current "true") "false" "true"))
    (message "Coloured output: %s" (getenv "SSS_COLORED"))))

;;;###autoload
(defun sss-toggle-auto-decrypt ()
  "Toggle auto-decrypt on file open."
  (interactive)
  (setq sss-auto-decrypt-on-open (not sss-auto-decrypt-on-open))
  (customize-save-variable 'sss-auto-decrypt-on-open sss-auto-decrypt-on-open)
  (message "Auto-decrypt on open: %s" sss-auto-decrypt-on-open))

;;;###autoload
(defun sss-toggle-auto-encrypt ()
  "Toggle auto-encrypt on file save."
  (interactive)
  (setq sss-auto-encrypt-on-save (not sss-auto-encrypt-on-save))
  (customize-save-variable 'sss-auto-encrypt-on-save sss-auto-encrypt-on-save)
  (message "Auto-encrypt on save: %s" sss-auto-encrypt-on-save))

;;;###autoload
(defun sss-toggle-highlighting ()
  "Toggle SSS pattern highlighting."
  (interactive)
  (setq sss-highlight-patterns (not sss-highlight-patterns))
  (customize-save-variable 'sss-highlight-patterns sss-highlight-patterns)
  (message "SSS highlighting: %s" sss-highlight-patterns)

  ;; Refresh highlighting in current buffer if SSS mode is active
  (when sss-mode
    (if sss-highlight-patterns
        (font-lock-add-keywords nil sss-font-lock-keywords 'append)
      (font-lock-remove-keywords nil sss-font-lock-keywords))
    (font-lock-flush)))

;;;###autoload
(defun sss-set-cache-timeout (timeout)
  "Set password cache TIMEOUT in seconds."
  (interactive "nCache timeout (seconds, 0 to disable): ")
  (setq sss-password-cache-timeout timeout)
  (customize-save-variable 'sss-password-cache-timeout timeout)
  (message "Password cache timeout: %d seconds" timeout))

;;;###autoload
(defun sss-show-settings ()
  "Display current SSS settings."
  (interactive)
  (with-current-buffer (get-buffer-create "*SSS Settings*")
    (erase-buffer)
    (insert "SSS Emacs Settings\n")
    (insert "==================\n\n")
    (insert (format "Executable: %s\n" sss-executable))
    (insert (format "Default username: %s\n" (or sss-default-username "auto")))
    (insert (format "Config directory: %s\n" (or sss-config-directory "default")))
    (insert (format "Password cache timeout: %d seconds\n" sss-password-cache-timeout))
    (insert (format "Auto-decrypt on open: %s\n" sss-auto-decrypt-on-open))
    (insert (format "Auto-encrypt on save: %s\n" sss-auto-encrypt-on-save))
    (insert (format "Syntax highlighting: %s\n" sss-highlight-patterns))
    (insert (format "Keybinding prefix: %s\n" sss-keybinding-prefix))
    (insert (format "Current user: %s\n" (or sss--current-username "auto")))
    (insert (format "Editor: %s\n" (or (getenv "EDITOR") "default")))
    (insert (format "Colored output: %s\n" (or (getenv "SSS_COLORED") "auto")))
    (display-buffer (current-buffer))))

;;;###autoload
(defun sss-reset-settings ()
  "Reset all SSS settings to defaults."
  (interactive)
  (when (yes-or-no-p "Reset all SSS settings to defaults? ")
    (setq sss-default-username nil
          sss-config-directory nil
          sss-password-cache-timeout 300
          sss-auto-decrypt-on-open t
          sss-auto-encrypt-on-save t
          sss-highlight-patterns t
          sss--current-username nil)
    (setenv "EDITOR" nil)
    (setenv "SSS_COLORED" nil)
    (sss--clear-password-cache)
    (message "SSS settings reset to defaults")))

;;;###autoload
(defun sss-show-config-locations ()
  "Show SSS configuration file locations."
  (interactive)
  (let ((output (sss--run-command-success (list "settings" "location"))))
    (with-current-buffer (get-buffer-create "*SSS Config Locations*")
      (erase-buffer)
      (insert output)
      (display-buffer (current-buffer)))))

;;; Integration with which-key

(defun sss--setup-which-key ()
  "Set up which-key descriptions for SSS commands."
  (when (featurep 'which-key)
    (which-key-add-key-based-replacements
      (concat sss-keybinding-prefix " e") "encrypt-region"
      (concat sss-keybinding-prefix " d") "decrypt-region"
      (concat sss-keybinding-prefix " t") "toggle-at-point"
      (concat sss-keybinding-prefix " b") "process-buffer"
      (concat sss-keybinding-prefix " r") "render-buffer"
      (concat sss-keybinding-prefix " f") "process-file"
      (concat sss-keybinding-prefix " R") "render-file"
      (concat sss-keybinding-prefix " E") "edit-file"
      (concat sss-keybinding-prefix " u") "select-user"
      (concat sss-keybinding-prefix " i") "init-project"
      (concat sss-keybinding-prefix " k") "list-keys"
      (concat sss-keybinding-prefix " p") "show-pubkey"
      (concat sss-keybinding-prefix " U") "list-users"
      (concat sss-keybinding-prefix " c") "clear-cache"
      (concat sss-keybinding-prefix " v") "show-version"
      (concat sss-keybinding-prefix " h") "help")))

;; Set up which-key when this file is loaded
(eval-after-load 'which-key
  '(sss--setup-which-key))

;;; Completion helpers

(defun sss--completing-read-user (prompt)
  "Completing read for usernames with PROMPT."
  (let ((users (or (sss--list-project-users)
                   (list (sss--get-username)))))
    (completing-read prompt users nil nil nil nil (car users))))

(defun sss--completing-read-file (prompt)
  "Completing read for files with PROMPT."
  (read-file-name prompt nil nil t))

;;; Progress indicators

(defvar sss--progress-reporter nil
  "Progress reporter for long-running operations.")

(defun sss--with-progress (message &rest body)
  "Execute BODY with progress MESSAGE."
  (let ((sss--progress-reporter (make-progress-reporter message)))
    (unwind-protect
        (progn ,@body)
      (when sss--progress-reporter
        (progress-reporter-done sss--progress-reporter)
        (setq sss--progress-reporter nil)))))

(provide 'sss-ui)

;;; sss-ui.el ends here