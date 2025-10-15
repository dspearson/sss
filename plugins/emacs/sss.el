;;; sss.el --- Secret String Substitution Emacs interface -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; SSS (Secret String Substitution) is a command-line tool for transparent
;; encryption and decryption of text within files using XChaCha20-Poly1305
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
(require 'sss-mode)

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

(defcustom sss-fancy-mode nil
  "Enable fancy visual mode for SSS patterns.
When enabled, encrypted content is shown as solid black bars,
and decrypted content is highlighted with danger colors."
  :type 'boolean
  :group 'sss
  :set (lambda (symbol value)
         (set-default symbol value)
         ;; Apply to all SSS buffers when changed
         (when (featurep 'sss)
           (sss--refresh-fancy-mode-all-buffers))))


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

(defun sss--build-command-args (args)
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
    (let* ((command-args (sss--build-command-args args))
           (exit-code (apply #'call-process-region
                             (if input (point-min) nil)
                             (if input (point-max) nil)
                             sss-executable
                             (not (null input))  ; delete input region
                             t                   ; output to current buffer
                             nil                 ; no error buffer
                             command-args)))
      (cons exit-code (buffer-string)))))

(defun sss--run-command-success (args &optional input)
  "Run SSS command, returning output on success or signalling error."
  (let ((result (sss--run-command args input)))
    (if (= (car result) 0)
        (cdr result)
      (error "SSS command failed: %s" (string-trim (cdr result))))))

(defun sss--get-username ()
  "Get username for operations, either from cache or user input."
  (let ((username (or sss--current-username
                      sss-default-username
                      (getenv "USER")
                      (getenv "USERNAME")
                      (read-string "Username: "))))
    (if (and username (stringp username) (not (string-empty-p username)))
        username
      (read-string "Username: "))))

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

(defun sss--find-sss-project-root ()
  "Find the SSS project root by looking for .sss.toml file."
  (let ((dir (or (when (buffer-file-name)
                   (file-name-directory (buffer-file-name)))
                 default-directory)))
    (while (and dir
                (not (file-exists-p (expand-file-name ".sss.toml" dir)))
                (not (string= dir (file-name-directory (directory-file-name dir)))))
      (setq dir (file-name-directory (directory-file-name dir))))
    (when (and dir (file-exists-p (expand-file-name ".sss.toml" dir)))
      dir)))

(defun sss--process-text (text username &optional decrypt-only)
  "Process TEXT with SSS for USERNAME.
If DECRYPT-ONLY is non-nil, only decrypt without re-encrypting."
  (let* ((project-root (or (sss--find-sss-project-root)
                           (when (fboundp 'projectile-project-root)
                             (projectile-project-root))
                           default-directory))
         (default-directory project-root)  ; Ensure we're in project root
         (args (list "--user" username)))
    (when decrypt-only
      (push "--render" args))
    (push "-" args)  ; Use stdin
    (sss--run-command-success args text)))

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
    ;; Refresh fancy mode overlays if fancy mode is enabled
    (when sss-fancy-mode
      (sss--refresh-fancy-mode))
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
    ;; Refresh fancy mode overlays if fancy mode is enabled
    (when sss-fancy-mode
      (sss--refresh-fancy-mode))
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
            ;; Refresh fancy mode overlays if fancy mode is enabled
            (when sss-fancy-mode
              (sss--refresh-fancy-mode))
            (message "Toggled encryption state at point")))))))

;;;###autoload
(defun sss-process-buffer (&optional username)
  "Process the file backing the current buffer with SSS.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (unless (buffer-file-name)
    (error "Buffer is not visiting a file"))
  (unless (stringp username)
    (setq username (sss--get-username)))
  (when (buffer-modified-p)
    (if (y-or-n-p "Buffer has unsaved changes. Save first? ")
        (save-buffer)
      (error "Cannot process buffer with unsaved changes")))
  (let ((filename (buffer-file-name))
        (sss-was-enabled (bound-and-true-p sss-mode)))
    (sss-process-file filename username t)  ; t for in-place
    (revert-buffer t t t)
    ;; Re-enable SSS mode if it was enabled before revert
    (when sss-was-enabled
      (sss-mode 1))
    ;; Refresh fancy mode overlays if fancy mode is enabled
    (when sss-fancy-mode
      (sss--refresh-fancy-mode))
    (message "Processed file %s with user: %s" filename username)))

;;;###autoload
(defun sss-render-buffer (&optional username)
  "Render buffer to raw text (decrypt all patterns) in a preview buffer.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (unless (stringp username)
    (setq username (sss--get-username)))
  (let* ((text (buffer-string))
         (rendered (sss--process-text text username t)))  ; t for decrypt-only
    (with-current-buffer (get-buffer-create "*SSS Rendered*")
      (setq buffer-read-only nil)
      (erase-buffer)
      (insert rendered)
      (setq buffer-read-only t)
      (goto-char (point-min))
      (display-buffer (current-buffer)))
    (message "Rendered buffer content for user: %s" username)))

;;;###autoload
(defun sss-preview-buffer (&optional username)
  "Preview how the buffer would look after SSS processing (encrypt/decrypt).
Shows result in a separate buffer without modifying the original.
If USERNAME is provided, use it; otherwise prompt or use default."
  (interactive)
  (unless (stringp username)
    (setq username (sss--get-username)))
  (let* ((text (buffer-string))
         (processed (sss--process-text text username)))  ; Full processing
    (with-current-buffer (get-buffer-create "*SSS Preview*")
      (setq buffer-read-only nil)
      (erase-buffer)
      (insert processed)
      (when (fboundp 'sss-mode)
        (sss-mode 1))  ; Enable SSS mode for syntax highlighting
      (setq buffer-read-only t)
      (goto-char (point-min))
      (display-buffer (current-buffer)))
    (message "Preview of processed buffer for user: %s" username)))

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

;;; Pattern detection and utility functions

(defun sss-pattern-at-point ()
  "Get SSS pattern bounds at point.
Returns cons cell (start . end) or nil if no pattern found."
  (save-excursion
    (let ((pattern-regex "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}")
          (original-point (point)))
      ;; Find pattern start
      (when (or (looking-at pattern-regex)
                (and (re-search-backward "[⊕o⊠]" nil t)
                     (looking-at pattern-regex)
                     (<= (point) original-point)
                     (>= (match-end 0) original-point)))
        (cons (match-beginning 0) (match-end 0))))))

(defun sss-extract-pattern-content (pattern-text)
  "Extract content from PATTERN-TEXT.
Returns the content between braces or nil if invalid pattern."
  (when (string-match "\\(?:⊕\\|o\\+\\|⊠\\){\\([^}]*\\)}" pattern-text)
    (match-string 1 pattern-text)))

(defun sss-count-patterns-in-buffer ()
  "Count SSS patterns in current buffer.
Returns cons cell (encrypted . decrypted)."
  (save-excursion
    (goto-char (point-min))
    (let ((encrypted 0)
          (decrypted 0))
      (while (re-search-forward "\\(?:\\(⊠\\)\\|\\(⊕\\|o\\+\\)\\){[^}]*}" nil t)
        (if (match-string 1)
            (setq encrypted (1+ encrypted))
          (setq decrypted (1+ decrypted))))
      (cons encrypted decrypted))))

;;;###autoload
(defun sss-preview-secret-at-point ()
  "Show a popup preview of the decrypted secret at point.
Uses posframe or popup to display content without modifying buffer."
  (interactive)
  (if-let ((bounds (sss-pattern-at-point)))
      (let* ((pattern-text (buffer-substring (car bounds) (cdr bounds)))
             (username (sss--get-username)))
        ;; Only preview if it's encrypted (starts with ⊠)
        (if (string-match "^⊠{" pattern-text)
            (condition-case err
                (let ((decrypted (sss--process-text pattern-text username t)))
                  (sss--show-preview-popup
                   (format "Secret (user: %s):\n%s" username (string-trim decrypted))
                   (car bounds)))
              (error (message "Failed to decrypt: %s" (error-message-string err))))
          (message "Pattern at point is not encrypted")))
    (message "No SSS pattern found at point")))

(defun sss--show-preview-popup (content pos)
  "Show CONTENT in a popup at position POS."
  (cond
   ;; Try posframe first (modern, nice looking)
   ((fboundp 'posframe-show)
    (posframe-show " *sss-preview*"
                   :string content
                   :position pos
                   :border-width 2
                   :border-color "#666666"
                   :background-color (face-background 'tooltip nil t)
                   :foreground-color (face-foreground 'tooltip nil t)
                   :timeout 10
                   :hidehandler 'posframe-hide-when-buffer-switch))

   ;; Fall back to popup.el if available
   ((fboundp 'popup-tip)
    (popup-tip content :point pos :timeout 10 :margin t))

   ;; Final fallback: simple overlay
   (t (sss--show-overlay-popup content pos))))

(defun sss--show-overlay-popup (content pos)
  "Show CONTENT using an overlay at POS."
  (let* ((overlay (make-overlay pos pos))
         (text (propertize (concat "\n" content "\n")
                          'face 'tooltip)))
    (overlay-put overlay 'after-string text)
    (overlay-put overlay 'sss-preview t)
    ;; Auto-remove after 10 seconds or on next command
    (run-with-timer 10 nil (lambda () (when (overlay-buffer overlay)
                                        (delete-overlay overlay))))
    (let ((cleanup-fn (lambda ()
                        (when (overlay-buffer overlay)
                          (delete-overlay overlay)
                          (remove-hook 'pre-command-hook cleanup-fn)))))
      (add-hook 'pre-command-hook cleanup-fn))))

;;;###autoload
(defun sss-goto-next-pattern ()
  "Move to the next SSS pattern in buffer."
  (interactive)
  (let ((pos (save-excursion
               (when (looking-at "\\(?:⊕\\|o\\+\\|⊠\\)")
                 (forward-char))
               (re-search-forward "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}" nil t))))
    (if pos
        (progn
          (goto-char (match-beginning 0))
          (message "Found pattern at position %d" (point)))
      (message "No more patterns found"))))

;;;###autoload
(defun sss-goto-previous-pattern ()
  "Move to the previous SSS pattern in buffer."
  (interactive)
  (let ((pos (save-excursion
               (re-search-backward "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}" nil t))))
    (if pos
        (progn
          (goto-char pos)
          (message "Found pattern at position %d" (point)))
      (message "No previous patterns found"))))

;;;###autoload
(defun sss-copy-pattern-content ()
  "Copy the content of SSS pattern at point to kill ring."
  (interactive)
  (if-let ((bounds (sss-pattern-at-point)))
      (let* ((pattern-text (buffer-substring (car bounds) (cdr bounds)))
             (content (sss-extract-pattern-content pattern-text)))
        (if content
            (progn
              (kill-new content)
              (message "Copied pattern content: %s" content))
          (message "Failed to extract pattern content")))
    (message "No SSS pattern found at point")))

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

;;; Fancy mode implementation

(defface sss-redacted-face
  '((t :background "#000000" :foreground "#000000"))
  "Face for redacted (encrypted) content - solid black like a marker."
  :group 'sss)

(defface sss-danger-face
  '((t :background "#FF0000" :foreground "#FFFFFF" :weight bold))
  "Face for unlocked (dangerous) content in fancy mode."
  :group 'sss)


(defvar sss--fancy-overlays nil
  "List of overlays created by fancy mode.")



(defun sss--apply-fancy-overlays ()
  "Apply fancy mode overlays to SSS patterns in current buffer."
  (when sss-fancy-mode
    (sss--remove-fancy-overlays)
    (save-excursion
      (goto-char (point-min))
      (while (re-search-forward "\\(?:\\(⊠\\)\\|\\(⊕\\|o\\+\\)\\){\\([^}]*\\)}" nil t)
        (let* ((start (match-beginning 0))
               (end (match-end 0))
               (is-encrypted (match-string 1))
               (content (match-string 3))
               (overlay (make-overlay start end)))

          (if is-encrypted
              ;; Encrypted content: solid black overlay like a marker
              (progn
                (overlay-put overlay 'face 'sss-redacted-face)
                (overlay-put overlay 'help-echo "🔒 ENCRYPTED CONTENT\nPress RET to edit inline")
                (overlay-put overlay 'keymap
                             (let ((map (make-sparse-keymap)))
                               (define-key map [mouse-1]
                                 (lambda () (interactive) (sss--start-inline-edit)))
                               (define-key map (kbd "RET")
                                 (lambda () (interactive) (sss--start-inline-edit)))
                               map)))
            ;; Decrypted content: show with danger styling but keep text visible
            (progn
              (overlay-put overlay 'face 'sss-danger-face)
              (overlay-put overlay 'help-echo "⚠ EXPOSED SECRET\nPress RET to edit inline")
              (overlay-put overlay 'keymap
                           (let ((map (make-sparse-keymap)))
                             (define-key map [mouse-1]
                               (lambda () (interactive) (sss--start-inline-edit)))
                             (define-key map (kbd "RET")
                               (lambda () (interactive) (sss--start-inline-edit)))
                             map))))

          (overlay-put overlay 'sss-fancy t)
          (overlay-put overlay 'sss-original-content content)
          (overlay-put overlay 'sss-is-encrypted is-encrypted)
          (push overlay sss--fancy-overlays))))))

(defun sss--remove-fancy-overlays ()
  "Remove all fancy mode overlays."
  (mapc #'delete-overlay sss--fancy-overlays)
  (setq sss--fancy-overlays nil))

(defun sss--refresh-fancy-mode ()
  "Refresh fancy mode overlays."
  (when (bound-and-true-p sss-mode)
    (if sss-fancy-mode
        (sss--apply-fancy-overlays)
      (sss--remove-fancy-overlays))))

(defun sss--refresh-fancy-mode-all-buffers ()
  "Refresh fancy mode overlays in all SSS buffers."
  (dolist (buffer (buffer-list))
    (with-current-buffer buffer
      (when (bound-and-true-p sss-mode)
        (sss--refresh-fancy-mode)))))

;;;###autoload
(defun sss-toggle-fancy-mode ()
  "Toggle fancy visual mode for SSS patterns."
  (interactive)
  (customize-set-variable 'sss-fancy-mode (not sss-fancy-mode))
  (message "SSS fancy mode: %s" (if sss-fancy-mode "enabled" "disabled")))

;;;###autoload
(defun sss-enable-fancy-mode ()
  "Enable fancy visual mode for SSS patterns and save the setting."
  (interactive)
  (customize-set-variable 'sss-fancy-mode t)
  (customize-save-variable 'sss-fancy-mode t)
  (message "SSS fancy mode enabled and saved"))

;;;###autoload
(defun sss-disable-fancy-mode ()
  "Disable fancy visual mode for SSS patterns and save the setting."
  (interactive)
  (customize-set-variable 'sss-fancy-mode nil)
  (customize-save-variable 'sss-fancy-mode nil)
  (message "SSS fancy mode disabled and saved"))

;; Hook to refresh fancy mode after buffer changes
(defun sss--after-change-function (beg end len)
  "Refresh fancy overlays after buffer changes."
  (when (and sss-fancy-mode (bound-and-true-p sss-mode))
    (run-with-idle-timer 0.1 nil #'sss--refresh-fancy-mode)))

;;; Inline editing for fancy mode

(defvar sss--inline-edit-overlay nil
  "Overlay used for inline editing.")

(defvar sss--inline-edit-keymap
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "<escape> <escape>") #'sss--finish-inline-edit)
    (define-key map (kbd "C-c C-c") #'sss--finish-inline-edit)
    (define-key map (kbd "C-c C-k") #'sss--cancel-inline-edit)
    map)
  "Keymap for inline editing mode.")

(defun sss--start-inline-edit ()
  "Start inline editing of SSS pattern at point."
  (interactive)
  (when-let ((bounds (sss-pattern-at-point)))
    (let* ((start (car bounds))
           (end (cdr bounds))
           (pattern-text (buffer-substring start end))
           (content (sss-extract-pattern-content pattern-text)))
      (when content
        ;; Remove fancy overlay temporarily
        (sss--remove-fancy-overlays)

        ;; Create inline edit overlay
        (setq sss--inline-edit-overlay (make-overlay start end))
        (overlay-put sss--inline-edit-overlay 'face '(:background "#2B2B2B" :box (:line-width 2 :color "#00FF00")))
        (overlay-put sss--inline-edit-overlay 'keymap sss--inline-edit-keymap)
        (overlay-put sss--inline-edit-overlay 'sss-original-pattern pattern-text)

        ;; Show the actual content for editing
        (save-excursion
          (goto-char start)
          (delete-region start end)
          (insert content))

        (message "Inline edit mode. Press ESC ESC or C-c C-c to encrypt and finish, C-c C-k to cancel")))))

(defun sss--finish-inline-edit ()
  "Finish inline editing and encrypt the content."
  (interactive)
  (when sss--inline-edit-overlay
    (let* ((start (overlay-start sss--inline-edit-overlay))
           (end (overlay-end sss--inline-edit-overlay))
           (new-content (buffer-substring start end))
           (username (sss--get-username)))

      ;; Replace with encrypted version
      (save-excursion
        (goto-char start)
        (delete-region start end)
        (insert (format "⊕{%s}" new-content))
        ;; Process to encrypt
        (let ((pattern-start (point)))
          (goto-char start)
          (when (re-search-forward "⊕{[^}]*}" pattern-start t)
            (let ((pattern-text (buffer-substring (match-beginning 0) (match-end 0))))
              (delete-region (match-beginning 0) (match-end 0))
              (insert (sss--process-text pattern-text username))))))

      ;; Clean up
      (delete-overlay sss--inline-edit-overlay)
      (setq sss--inline-edit-overlay nil)

      ;; Restore fancy mode
      (when sss-fancy-mode
        (sss--refresh-fancy-mode))

      (message "Content encrypted and sealed"))))

(defun sss--cancel-inline-edit ()
  "Cancel inline editing and restore original content."
  (interactive)
  (when sss--inline-edit-overlay
    (let* ((start (overlay-start sss--inline-edit-overlay))
           (end (overlay-end sss--inline-edit-overlay))
           (original-pattern (overlay-get sss--inline-edit-overlay 'sss-original-pattern)))

      ;; Restore original pattern
      (save-excursion
        (goto-char start)
        (delete-region start end)
        (insert original-pattern))

      ;; Clean up
      (delete-overlay sss--inline-edit-overlay)
      (setq sss--inline-edit-overlay nil)

      ;; Restore fancy mode
      (when sss-fancy-mode
        (sss--refresh-fancy-mode))

      (message "Inline edit cancelled"))))

;;; Company-mode integration

(defun sss--company-backend (command &optional arg &rest ignored)
  "Company backend for SSS patterns."
  (interactive (list 'interactive))
  (pcase command
    ('interactive (company-begin-backend 'sss--company-backend))
    ('prefix (and (bound-and-true-p sss-mode)
                  (looking-back "\\(?:⊕\\|o\\+\\|⊠\\){\\([^}]*\\)" (line-beginning-position))
                  (match-string 1)))
    ('candidates
     (let ((prefix arg))
       (list (concat prefix " (plaintext)")
             (concat prefix " (encrypted)")
             "new-secret"
             "password"
             "api-key"
             "token"
             "database-url"
             "private-key")))
    ('annotation
     (cond
      ((string-suffix-p " (plaintext)" arg) " ⊕")
      ((string-suffix-p " (encrypted)" arg) " ⊠")
      (t " SSS")))
    ('post-completion
     ;; Remove annotation from inserted text
     (when (string-match " (\\(plaintext\\|encrypted\\))$" arg)
       (delete-region (match-beginning 0) (match-end 0))))
    ('doc-buffer
     (company-doc-buffer
      (format "SSS Pattern: %s\n\nThis will create an SSS encryption pattern.\n⊕{} for plaintext\n⊠{} for encrypted content"
              arg)))))

;;;###autoload
(defun sss-setup-company ()
  "Set up company-mode integration for SSS."
  (when (featurep 'company)
    (add-to-list 'company-backends 'sss--company-backend)))

;; Auto-setup company integration
(eval-after-load 'company
  '(sss-setup-company))

(provide 'sss)

;;; sss.el ends here