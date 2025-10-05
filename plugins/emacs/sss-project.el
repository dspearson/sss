;;; sss-project.el --- SSS project management utilities -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; This file provides project management utilities for SSS,
;; including project detection, configuration handling,
;; and user management helpers.

;;; Code:

(require 'sss)

;;; Project detection

(defun sss-project-root (&optional dir)
  "Find SSS project root starting from DIR (or current directory).
Returns the directory containing .sss.toml or nil if not found."
  (let ((dir (or dir default-directory)))
    (locate-dominating-file dir ".sss.toml")))

(defun sss-in-project-p (&optional dir)
  "Check if DIR (or current directory) is within an SSS project."
  (not (null (sss-project-root dir))))

(defun sss-ensure-project ()
  "Ensure we're in an SSS project, signal error if not."
  (unless (sss-in-project-p)
    (error "Not in an SSS project (no .sss.toml found)")))

;;; Project configuration

(defun sss-project-config-file (&optional dir)
  "Get path to .sss.toml file for project containing DIR."
  (when-let ((root (sss-project-root dir)))
    (expand-file-name ".sss.toml" root)))

(defun sss-read-project-config (&optional dir)
  "Read and parse .sss.toml configuration file.
Returns parsed configuration or nil if not found."
  (when-let ((config-file (sss-project-config-file dir)))
    (when (file-exists-p config-file)
      (with-temp-buffer
        (insert-file-contents config-file)
        (let ((config-text (buffer-string)))
          ;; Simple TOML parsing for user sections
          (sss--parse-simple-toml config-text))))))

(defun sss--parse-simple-toml (text)
  "Simple TOML parser for SSS project configuration.
Returns alist of (username . properties)."
  (let ((result '())
        (current-section nil))
    (dolist (line (split-string text "\n"))
      (let ((line (string-trim line)))
        (cond
         ;; Section headers [username]
         ((string-match "^\\[\\([^]]+\\)\\]$" line)
          (setq current-section (match-string 1 line))
          (unless (assoc current-section result)
            (push (cons current-section '()) result)))
         ;; Key-value pairs
         ((and current-section
               (string-match "^\\([^=]+\\)\\s-*=\\s-*\"\\([^\"]*\\)\"" line))
          (let ((key (string-trim (match-string 1 line)))
                (value (match-string 2 line)))
            (let ((section-data (assoc current-section result)))
              (setcdr section-data (cons (cons key value) (cdr section-data)))))))))
    result))

;;; User management helpers

(defun sss-project-users (&optional dir)
  "Get list of users in SSS project containing DIR."
  (when-let ((config (sss-read-project-config dir)))
    (mapcar #'car config)))

(defun sss-project-user-info (username &optional dir)
  "Get information about USERNAME in project containing DIR."
  (when-let ((config (sss-read-project-config dir)))
    (cdr (assoc username config))))

(defun sss-project-user-public-key (username &optional dir)
  "Get public key for USERNAME in project containing DIR."
  (when-let ((user-info (sss-project-user-info username dir)))
    (cdr (assoc "public" user-info))))

;;; Interactive project functions

;;;###autoload
(defun sss-show-project-info ()
  "Display information about current SSS project."
  (interactive)
  (if-let ((root (sss-project-root)))
      (let ((config (sss-read-project-config))
            (config-file (sss-project-config-file)))
        (with-current-buffer (get-buffer-create "*SSS Project Info*")
          (erase-buffer)
          (insert (format "SSS Project Information\n"))
          (insert (format "=======================\n\n"))
          (insert (format "Project root: %s\n" root))
          (insert (format "Config file: %s\n" config-file))
          (insert (format "Users: %d\n\n" (length config)))

          (when config
            (insert "Project Users:\n")
            (insert "--------------\n")
            (dolist (user-entry config)
              (let ((username (car user-entry))
                    (user-data (cdr user-entry)))
                (insert (format "• %s\n" username))
                (when-let ((pubkey (cdr (assoc "public" user-data))))
                  (insert (format "  Public key: %s...\n"
                                  (substring pubkey 0 (min 40 (length pubkey))))))
                (insert "\n"))))

          (display-buffer (current-buffer))))
    (message "Not in an SSS project")))

;;;###autoload
(defun sss-project-status ()
  "Show brief project status in minibuffer."
  (interactive)
  (if-let ((root (sss-project-root)))
      (let ((users (sss-project-users)))
        (message "SSS project: %s (%d users: %s)"
                 (file-name-nondirectory (directory-file-name root))
                 (length users)
                 (string-join users ", ")))
    (message "Not in an SSS project")))

;;;###autoload
(defun sss-goto-project-root ()
  "Navigate to SSS project root directory."
  (interactive)
  (if-let ((root (sss-project-root)))
      (dired root)
    (message "Not in an SSS project")))

;;;###autoload
(defun sss-open-project-config ()
  "Open the .sss.toml configuration file."
  (interactive)
  (if-let ((config-file (sss-project-config-file)))
      (find-file config-file)
    (message "Not in an SSS project")))

;;; User selection helpers

(defun sss-select-project-user (&optional prompt)
  "Select a user from the current project.
Returns selected username or nil if cancelled."
  (sss-ensure-project)
  (let ((users (sss-project-users)))
    (if users
        (completing-read (or prompt "Select user: ") users nil t)
      (error "No users found in project"))))

;;;###autoload
(defun sss-set-project-user ()
  "Set current user from project users."
  (interactive)
  (when-let ((username (sss-select-project-user "Set current user: ")))
    (setq sss--current-username username)
    (message "Current user set to: %s" username)))

;;; File discovery

(defun sss-find-encrypted-files (&optional dir)
  "Find files containing SSS patterns in DIR (or project root)."
  (let ((search-dir (or dir (sss-project-root) default-directory))
        (pattern "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}")
        (files '()))

    (dolist (file (directory-files-recursively search-dir "\\..*"))
      (when (and (file-regular-p file)
                 (not (string-match "\\.git/" file))
                 (not (string-match "/\\." (file-name-nondirectory file))))
        (with-temp-buffer
          (condition-case nil
              (progn
                (insert-file-contents file nil 0 4096) ; Check first 4KB
                (when (re-search-forward pattern nil t)
                  (push file files)))
            (error nil))))) ; Ignore files we can't read

    (nreverse files)))

;;;###autoload
(defun sss-find-encrypted-files-interactive ()
  "Interactively find and display files with SSS patterns."
  (interactive)
  (let ((files (sss-find-encrypted-files)))
    (if files
        (with-current-buffer (get-buffer-create "*SSS Encrypted Files*")
          (erase-buffer)
          (insert "Files with SSS patterns:\n")
          (insert "========================\n\n")
          (dolist (file files)
            (insert (format "%s\n" file)))
          (insert (format "\nTotal: %d files\n" (length files)))
          (display-buffer (current-buffer)))
      (message "No files with SSS patterns found"))))

;;; Project templates

(defcustom sss-project-templates
  '(("basic" . "Basic SSS project")
    ("config" . "Configuration files project")
    ("secrets" . "Secrets management project"))
  "Available SSS project templates."
  :type '(alist :key-type string :value-type string)
  :group 'sss)

;;;###autoload
(defun sss-init-project-with-template (&optional template)
  "Initialize SSS project with TEMPLATE."
  (interactive
   (list (completing-read "Project template: "
                          sss-project-templates
                          nil t nil nil "basic")))

  (let ((username (sss--get-username)))
    (sss--run-command-success (list "init" username))

    ;; Add template-specific setup
    (pcase template
      ("config"
       (message "Initialized config project. Consider adding *.conf, *.ini patterns to .gitignore"))
      ("secrets"
       (message "Initialized secrets project. Consider adding .env, *.key patterns to .gitignore"))
      (_
       (message "Initialized basic SSS project")))

    (when (y-or-n-p "Create sample encrypted file? ")
      (sss--create-sample-file template))))

(defun sss--create-sample-file (template)
  "Create a sample file for TEMPLATE."
  (let ((filename (pcase template
                    ("config" "sample.conf")
                    ("secrets" ".env.sample")
                    (_ "README.sss")))
        (content (pcase template
                   ("config"
                    "# Sample configuration file\nserver_host=example.com\napi_key=⊕{your-api-key-here}\n")
                   ("secrets"
                    "# Environment variables\nDATABASE_URL=⊕{postgresql://user:pass@localhost/db}\nAPI_SECRET=⊕{your-secret-here}\n")
                   (_
                    "# SSS Sample File\n\nThis is a sample file with encrypted content: ⊕{secret data}\n\nYou can encrypt text by selecting it and using C-c s e\n"))))

    (with-temp-file filename
      (insert content))

    (find-file filename)
    (message "Created sample file: %s" filename)))

;;; Integration with project.el

(defun sss-project-try-sss (dir)
  "Try to find SSS project root from DIR for project.el integration."
  (when-let ((root (sss-project-root dir)))
    (cons 'sss root)))

;; Register with project.el if available
(with-eval-after-load 'project
  (add-to-list 'project-find-functions #'sss-project-try-sss))

(provide 'sss-project)

;;; sss-project.el ends here