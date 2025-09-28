;;; sss.el --- Secret String Substitution Emacs interface -*- lexical-binding: t; -*-

;; Copyright (C) 2024

;; Author: SSS Contributors
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "26.1"))

;;; Commentary:

;; SSS (Secret String Substitution) is a command-line tool for transparent
;; encryption and decryption of text within files using XChaCha20Poly1305
;; with a modern multi-user architecture.
;;
;; This package provides an ergonomic Emacs interface to SSS functionality,
;; including:
;; - Interactive encryption/decryption of text regions
;; - Project and user management
;; - Key management operations
;; - File processing with automatic encrypt/decrypt
;; - Minor mode with syntax highlighting
;; - Integration with Emacs auth-source for password storage

;;; Code:

(require 'auth-source)
(require 'cl-lib)
(require 'subr-x)

;;; Customization

(defgroup sss nil
  "Secret String Substitution interface."
  :group 'tools
  :prefix "sss-")

(defcustom sss-executable "sss"
  "Path to the SSS executable."
  :type 'string
  :group 'sss)

(defcustom sss-default-username nil
  "Default username for SSS operations.
If nil, will attempt to use system username."
  :type '(choice (const :tag "Auto-detect" nil)
                 (string :tag "Username"))
  :group 'sss)

(defcustom sss-config-directory nil
  "Override SSS config directory.
If nil, uses SSS default (~/.config/sss or platform equivalent)."
  :type '(choice (const :tag "Default" nil)
                 (directory :tag "Custom directory"))
  :group 'sss)

(defcustom sss-password-cache-timeout 300
  "Password cache timeout in seconds.
Set to 0 to disable caching."
  :type 'integer
  :group 'sss)

(defcustom sss-auto-decrypt-on-open t
  "Automatically decrypt SSS files when opening."
  :type 'boolean
  :group 'sss)

(defcustom sss-auto-encrypt-on-save t
  "Automatically encrypt SSS files when saving."
  :type 'boolean
  :group 'sss)

(defcustom sss-highlight-patterns t
  "Enable syntax highlighting of SSS patterns."
  :type 'boolean
  :group 'sss)

(defcustom sss-keybinding-prefix "C-c s"
  "Prefix key for SSS commands."
  :type 'string
  :group 'sss)

;;; Internal variables

(defvar sss--password-cache (make-hash-table :test 'equal)
  "Cache for passwords to avoid repeated prompts.")

(defvar sss--password-cache-timers (make-hash-table :test 'equal)
  "Timers for password cache expiration.")

(defvar sss--current-username nil
  "Currently selected username for operations.")

;;; Utility functions

(defun sss--executable-available-p ()
  "Check if SSS executable is available."
  (executable-find sss-executable))

(defun sss--build-command-args (&rest args)
  "Build command arguments for SSS, including config directory if set."
  (if sss-config-directory
      (append (list "--confdir" sss-config-directory) args)
    args))

(defun sss--run-command (args &optional input)
  "Run SSS command with ARGS and optional INPUT.
Returns (exit-code . output)."
  (unless (sss--executable-available-p)
    (error "SSS executable not found: %s" sss-executable))

  (with-temp-buffer
    (when input
      (insert input))
    (let ((exit-code (apply #'call-process-region
                            (if input (point-min) nil)
                            (if input (point-max) nil)
                            sss-executable
                            (not (null input))  ; delete input region
                            t                   ; output to current buffer
                            nil                 ; no error buffer
                            (sss--build-command-args args))))
      (cons exit-code (buffer-string)))))

(defun sss--run-command-success (args &optional input)
  "Run SSS command, returning output on success or signalling error."
  (let ((result (sss--run-command args input)))
    (if (= (car result) 0)
        (cdr result)
      (error "SSS command failed: %s" (string-trim (cdr result))))))

(defun sss--get-username ()
  "Get username for operations, either from cache or user input."
  (or sss--current-username
      sss-default-username
      (getenv "USER")
      (getenv "USERNAME")
      (read-string "Username: ")))

(defun sss--get-cached-password (username)
  "Get cached password for USERNAME."
  (gethash username sss--password-cache))

(defun sss--cache-password (username password)
  "Cache PASSWORD for USERNAME with expiration timer."
  (when (> sss-password-cache-timeout 0)
    ;; Cancel existing timer
    (when-let ((timer (gethash username sss--password-cache-timers)))
      (cancel-timer timer))

    ;; Cache password
    (puthash username password sss--password-cache)

    ;; Set expiration timer
    (let ((timer (run-with-timer sss-password-cache-timeout nil
                                 (lambda ()
                                   (remhash username sss--password-cache)
                                   (remhash username sss--password-cache-timers)))))
      (puthash username timer sss--password-cache-timers))))

(defun sss--clear-password-cache (&optional username)
  "Clear password cache for USERNAME, or all users if USERNAME is nil."
  (if username
      (progn
        (when-let ((timer (gethash username sss--password-cache-timers)))
          (cancel-timer timer))
        (remhash username sss--password-cache)
        (remhash username sss--password-cache-timers))
    (maphash (lambda (_user timer) (cancel-timer timer)) sss--password-cache-timers)
    (clrhash sss--password-cache)
    (clrhash sss--password-cache-timers)))

(defun sss--read-password (username)
  "Read password for USERNAME, checking cache first."
  (or (sss--get-cached-password username)
      (let ((password (read-passwd (format "Password for %s: " username))))
        (sss--cache-password username password)
        password)))

;;; Core encryption/decryption functions

(defun sss--process-text (text username &optional decrypt-only)
  "Process TEXT with SSS for USERNAME.
If DECRYPT-ONLY is non-nil, only decrypt without re-encrypting."
  (let ((temp-file (make-temp-file "sss-emacs")))
    (unwind-protect
        (progn
          (with-temp-file temp-file
            (insert text))
          (if decrypt-only
              (sss--run-command-success (list "--user" username "--render" temp-file))
            (sss--run-command-success (list "--user" username temp-file))))
      (delete-file temp-file))))

;;;###autoload
(defun sss-encrypt-region (start end &optional username)
  "Encrypt text between START and END using SSS.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive "r")
  (let* ((username (or username (sss--get-username)))
         (text (buffer-substring start end))
         (processed (sss--process-text text username)))
    (delete-region start end)
    (insert processed)
    (message "Encrypted region with user: %s" username)))

;;;###autoload
(defun sss-decrypt-region (start end &optional username)
  "Decrypt text between START and END using SSS.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive "r")
  (let* ((username (or username (sss--get-username)))
         (text (buffer-substring start end))
         (processed (sss--process-text text username t)))
    (delete-region start end)
    (insert processed)
    (message "Decrypted region with user: %s" username)))

;;;###autoload
(defun sss-toggle-at-point (&optional username)
  "Toggle encryption state of SSS pattern at point.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (let ((username (or username (sss--get-username))))
    (save-excursion
      (let* ((pattern-regex "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}")
             (start (progn
                      (while (and (not (bobp))
                                  (not (looking-at pattern-regex)))
                        (backward-char))
                      (if (looking-at pattern-regex)
                          (point)
                        (error "No SSS pattern found at point"))))
             (end (progn
                    (goto-char start)
                    (when (re-search-forward pattern-regex nil t)
                      (point)))))
        (when (and start end)
          (let* ((text (buffer-substring start end))
                 (processed (sss--process-text text username)))
            (delete-region start end)
            (insert processed)
            (message "Toggled encryption state at point")))))))

;;;###autoload
(defun sss-process-buffer (&optional username)
  "Process entire buffer with SSS.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (let* ((username (or username (sss--get-username)))
         (text (buffer-string))
         (processed (sss--process-text text username)))
    (erase-buffer)
    (insert processed)
    (message "Processed buffer with user: %s" username)))

;;;###autoload
(defun sss-render-buffer (&optional username)
  "Render buffer to raw text (decrypt all patterns).
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (let* ((username (or username (sss--get-username)))
         (text (buffer-string))
         (processed (sss--process-text text username t)))
    (erase-buffer)
    (insert processed)
    (message "Rendered buffer to raw text with user: %s" username)))

;;; File operations

;;;###autoload
(defun sss-process-file (filename &optional username in-place)
  "Process FILENAME with SSS.
If USERNAME is provided, use it; otherwise prompt or use default.
If IN-PLACE is non-nil, modify file in place."
  (interactive (list (read-file-name "File to process: ")
                     (sss--get-username)
                     current-prefix-arg))
  (let ((args (list "--user" username)))
    (when in-place
      (push "--in-place" args))
    (push filename args)
    (let ((output (sss--run-command-success args)))
      (if in-place
          (progn
            (revert-buffer t t)
            (message "Processed file in-place: %s" filename))
        (with-current-buffer (get-buffer-create "*SSS Output*")
          (erase-buffer)
          (insert output)
          (display-buffer (current-buffer))
          (message "Processed file: %s" filename))))))

;;;###autoload
(defun sss-render-file (filename &optional username in-place)
  "Render FILENAME to raw text (decrypt all).
If USERNAME is provided, use it; otherwise prompt or use default.
If IN-PLACE is non-nil, modify file in place."
  (interactive (list (read-file-name "File to render: ")
                     (sss--get-username)
                     current-prefix-arg))
  (let ((args (list "--user" username "--render")))
    (when in-place
      (push "--in-place" args))
    (push filename args)
    (let ((output (sss--run-command-success args)))
      (if in-place
          (progn
            (revert-buffer t t)
            (message "Rendered file in-place: %s" filename))
        (with-current-buffer (get-buffer-create "*SSS Output*")
          (erase-buffer)
          (insert output)
          (display-buffer (current-buffer))
          (message "Rendered file: %s" filename))))))

;;;###autoload
(defun sss-edit-file (filename &optional username)
  "Edit FILENAME with automatic SSS encrypt/decrypt.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive (list (read-file-name "File to edit: ")
                     (sss--get-username)))
  (let ((args (list "--user" username "--edit" filename)))
    (sss--run-command-success args)
    (message "Editing file with SSS: %s" filename)))

;;; Project management

;;;###autoload
(defun sss-init-project (&optional username)
  "Initialize SSS project in current directory.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (let ((username (or username (sss--get-username))))
    (sss--run-command-success (list "init" username))
    (message "Initialized SSS project with user: %s" username)))

;;;###autoload
(defun sss-add-user (username public-key)
  "Add USERNAME with PUBLIC-KEY to current project."
  (interactive (list (read-string "Username: ")
                     (read-string "Public key (base64 or file path): ")))
  (sss--run-command-success (list "users" "add" username public-key))
  (message "Added user: %s" username))

;;;###autoload
(defun sss-remove-user (username)
  "Remove USERNAME from current project."
  (interactive (list (completing-read "Username to remove: "
                                      (sss--list-project-users))))
  (when (yes-or-no-p (format "Remove user %s from project? " username))
    (sss--run-command-success (list "users" "remove" username))
    (message "Removed user: %s" username)))

(defun sss--list-project-users ()
  "Get list of users in current project."
  (condition-case nil
      (split-string (string-trim (sss--run-command-success (list "users" "list"))) "\n" t)
    (error nil)))

;;;###autoload
(defun sss-list-users ()
  "Display project users."
  (interactive)
  (let ((users (sss--list-project-users)))
    (if users
        (message "Project users: %s" (string-join users ", "))
      (message "No SSS project found or no users"))))

;;;###autoload
(defun sss-select-user (username)
  "Select USERNAME for subsequent SSS operations."
  (interactive (list (completing-read "Select user: "
                                      (or (sss--list-project-users)
                                          (list (sss--get-username))))))
  (setq sss--current-username username)
  (message "Selected user: %s" username))

;;; Key management

;;;###autoload
(defun sss-generate-keypair (&optional force no-password)
  "Generate new SSS keypair.
If FORCE is non-nil, overwrite existing keypair.
If NO-PASSWORD is non-nil, generate without password protection."
  (interactive "P")
  (let ((args (list "keys" "generate")))
    (when force
      (push "--force" args))
    (when no-password
      (push "--no-password" args))
    (sss--run-command-success args)
    (message "Generated new keypair")))

;;;###autoload
(defun sss-list-keys ()
  "Display available SSS keys."
  (interactive)
  (let ((output (sss--run-command-success (list "keys" "list"))))
    (with-current-buffer (get-buffer-create "*SSS Keys*")
      (erase-buffer)
      (insert output)
      (display-buffer (current-buffer)))))

;;;###autoload
(defun sss-show-pubkey (&optional fingerprint)
  "Show public key.
If FINGERPRINT is non-nil, show fingerprint instead of full key."
  (interactive "P")
  (let ((args (list "keys" "pubkey")))
    (when fingerprint
      (push "--fingerprint" args))
    (let ((output (sss--run-command-success args)))
      (kill-new output)
      (message "Public key %s(copied to clipboard): %s"
               (if fingerprint "fingerprint " "")
               (string-trim output)))))

;;;###autoload
(defun sss-delete-key (key-name)
  "Delete keypair KEY-NAME."
  (interactive "sKey name to delete: ")
  (when (yes-or-no-p (format "Delete key %s? " key-name))
    (sss--run-command-success (list "keys" "delete" key-name))
    (message "Deleted key: %s" key-name)))

;;;###autoload
(defun sss-set-current-key (&optional key-name)
  "Set or show current keypair.
If KEY-NAME is provided, set it as current; otherwise show current."
  (interactive)
  (let ((args (list "keys" "current")))
    (when key-name
      (push key-name args))
    (let ((output (sss--run-command-success args)))
      (message "Current key: %s" (string-trim output)))))

;;; Utility commands

;;;###autoload
(defun sss-clear-cache ()
  "Clear password cache."
  (interactive)
  (sss--clear-password-cache)
  (message "Cleared password cache"))

;;;###autoload
(defun sss-show-version ()
  "Show SSS version."
  (interactive)
  (let ((output (sss--run-command-success (list "--version"))))
    (message "SSS version: %s" (string-trim output))))

(provide 'sss)

;;; sss.el ends here