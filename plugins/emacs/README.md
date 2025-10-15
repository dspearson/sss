# SSS Emacs Package

A comprehensive Emacs interface for [SSS (Secret String Substitution)](../../README.md), providing seamless encryption and decryption of text within files using XChaCha20-Poly1305 with a modern multi-user architecture.

## ✨ Features

### 🔐 **Core Operations**
- **Text Processing**: Encrypt/decrypt regions, toggle patterns at point, process entire buffers
- **File Operations**: Process files with automatic encrypt/decrypt, render to raw text
- **Pattern Recognition**: Automatic detection of `⊕{}`, `o+{}`, and `⊠{}` patterns

### 👥 **Multi-User Support**
- **Project Management**: Initialize projects, manage users, handle multi-user workflows
- **Key Management**: Generate keypairs, manage keys, show public keys and fingerprints
- **User Selection**: Easy switching between project users

### 🎨 **User Experience**
- **Minor Mode**: Syntax highlighting, automatic file processing, context-aware keybindings
- **Doom Integration**: Full Evil/leader key support with operators and text objects
- **UI Enhancements**: Transient menus, completion support, visual feedback
- **Security**: Password caching with timeout, auth-source integration

## 📦 Installation

### Prerequisites

- **SSS CLI**: Ensure the `sss` command-line tool is installed and available in your PATH
- **Emacs**: Version 26.1 or later
- **Optional**: `transient` package for enhanced UI menus

### 🚀 Quick Setup

Choose your preferred installation method:

#### Standard Emacs

```elisp
;; Add to your init.el
(add-to-list 'load-path "/path/to/sss/plugins/emacs")
(require 'sss)
(require 'sss-mode)
(sss-setup-auto-mode)  ; Enable auto-mode for encrypted files
```

#### Doom Emacs (Recommended)

**packages.el:**
```elisp
(package! sss :recipe (:local-repo "/path/to/sss/plugins/emacs"))
```

**config.el:**
```elisp
(use-package! sss
  :commands (sss-mode sss-init-project)
  :hook (doom-first-file . sss-setup-auto-mode)
  :init
  (setq sss-default-username "your-username")
  :config
  (require 'sss-doom))  ; Enables all Doom features automatically
```

#### Package.el

```elisp
(package-install-file "/path/to/sss/plugins/emacs/sss.el")
```

### 📁 Package Components

| File | Purpose | Lines |
|------|---------|-------|
| `sss.el` | Core functionality | 455 |
| `sss-mode.el` | Minor mode & highlighting | 214 |
| `sss-ui.el` | Transient menus & UI | 318 |
| `sss-project.el` | Project management | 276 |
| `sss-utils.el` | Utilities & helpers | 336 |
| `sss-doom.el` | Doom Emacs integration | 322 |

**Total: 1,921 lines of comprehensive SSS integration**

### Optional Components

Load additional features as needed:

```elisp
(require 'sss-ui)      ; Transient menus and enhanced UI
(require 'sss-project) ; Project management utilities
(require 'sss-utils)   ; Pattern analysis and utilities
(require 'sss-doom)    ; Doom Emacs integration
```

## ⚡ Quick Start

### 1️⃣ Initialize Project
```elisp
M-x sss-init-project  ; Creates .sss.toml with your user
```

### 2️⃣ Enable SSS Mode
```elisp
M-x sss-mode          ; Enable syntax highlighting and keybindings
```

### 3️⃣ Encrypt Text
**Standard Emacs:**
- Select text → `C-c s e`

**Doom Emacs:**
- Select text → `SPC e e`
- Evil: `V` (select line) → `E`
- Evil operator: `g e i w` (encrypt inner word)

### 4️⃣ Decrypt Text
- Select encrypted pattern → `C-c s d` (Standard) or `SPC e d` (Doom)
- Toggle at point: `C-c s t` / `SPC e t`

## Configuration

### Basic Configuration

Add to your Emacs configuration:

```elisp
;; Load SSS packages
(require 'sss)
(require 'sss-mode)

;; Set up automatic mode activation
(sss-setup-auto-mode)

;; Customize settings
(setq sss-default-username "your-username"
      sss-auto-decrypt-on-open t
      sss-auto-encrypt-on-save t
      sss-highlight-patterns t
      sss-password-cache-timeout 300)

;; Optional: Set custom keybinding prefix
(setq sss-keybinding-prefix "C-c e")
```

### Advanced Configuration

```elisp
;; Custom config directory
(setq sss-config-directory "~/.config/sss")

;; Custom file patterns for auto-mode
(setq sss-auto-mode-patterns '("\\.sss\\'" "\\.secret\\'" "\\.enc\\'"))

;; Disable password caching
(setq sss-password-cache-timeout 0)

;; Custom faces for syntax highlighting
(custom-set-faces
 '(sss-plaintext-face ((t (:foreground "green" :weight bold))))
 '(sss-ciphertext-face ((t (:foreground "red" :weight bold))))
 '(sss-content-face ((t (:background "grey90")))))
```

## Usage

## ⌨️ Keybindings

SSS provides **dual binding systems** that work together - use whichever feels natural!

### 🎯 **Standard Emacs** (Prefix: `C-c s`)

| Key | Action | Description |
|-----|--------|-------------|
| `C-c s e` | Encrypt | Encrypt selected region |
| `C-c s d` | Decrypt | Decrypt selected region |
| `C-c s t` | Toggle | Toggle encryption at point |
| `C-c s b` | Buffer | Process entire buffer |
| `C-c s r` | Render | Decrypt all to raw text |
| `C-c s f` | File | Process file |
| `C-c s i` | Init | Initialize project |
| `C-c s u` | User | Select user |
| `C-c s k` | Keys | List keys |
| `C-c s h` | Help | Show help |

### 🔥 **Doom Emacs** (Leader: `SPC e`)

#### Global Operations
| Key | Action | Description |
|-----|--------|-------------|
| `SPC e SPC` | **Menu** | **Open SSS transient menu** |
| `SPC e e` | Encrypt | Encrypt region |
| `SPC e d` | Decrypt | Decrypt region |
| `SPC e t` | Toggle | Toggle at point |
| `SPC e b` | Buffer | Process buffer |
| `SPC e r` | Render | Decrypt all |

#### Project & Users (`SPC e p`)
| Key | Action | Description |
|-----|--------|-------------|
| `SPC e p i` | Init | Initialize project |
| `SPC e p s` | Status | Show project status |
| `SPC e p u` | User | Select user |
| `SPC e p l` | List | List all users |

#### Keys (`SPC e k`)
| Key | Action | Description |
|-----|--------|-------------|
| `SPC e k g` | Generate | Generate keypair |
| `SPC e k l` | List | List keys |
| `SPC e k p` | Pubkey | Show public key |

#### Evil Integration
| Key | Mode | Action |
|-----|------|--------|
| `g e` | Normal | Encrypt operator |
| `g d` | Normal | Decrypt operator |
| `g t` | Normal | Toggle operator |
| `E` | Visual | Encrypt selection |
| `D` | Visual | Decrypt selection |
| `i s` | Any | Inner SSS pattern |
| `a s` | Any | Outer SSS pattern |

#### Local Leader (`,` in sss-mode)
| Key | Action |
|-----|--------|
| `, e/d/t` | Quick encrypt/decrypt/toggle |
| `, n/N` | Next/previous pattern |
| `, l` | List patterns in buffer |

### 🎪 **Examples**

**Doom Evil Operators:**
- `g e i w` - Encrypt inner word
- `g e i p` - Encrypt inner paragraph
- `g d a s` - Decrypt outer SSS pattern
- `c i s` - Change inner SSS pattern content

### Interactive Commands

#### Core Functions

- `sss-encrypt-region` - Encrypt selected text
- `sss-decrypt-region` - Decrypt selected text
- `sss-toggle-at-point` - Toggle encryption state of pattern at cursor
- `sss-process-buffer` - Process entire buffer (encrypt/decrypt as needed)
- `sss-render-buffer` - Decrypt all patterns to raw text

#### File Operations

- `sss-process-file` - Process a file with SSS
- `sss-render-file` - Render file to raw text
- `sss-edit-file` - Edit file with automatic encrypt/decrypt

#### Project Management

- `sss-init-project` - Initialize SSS project
- `sss-add-user` - Add user to project
- `sss-remove-user` - Remove user from project
- `sss-list-users` - List project users
- `sss-select-user` - Select user for operations

#### Key Management

- `sss-generate-keypair` - Generate new keypair
- `sss-list-keys` - Show available keys
- `sss-show-pubkey` - Show public key
- `sss-delete-key` - Delete keypair
- `sss-set-current-key` - Set current keypair

#### Utilities

- `sss-clear-cache` - Clear password cache
- `sss-show-version` - Show SSS version
- `sss-help` - Show help information

### Transient Menus

If you have the `transient` package installed, you can use the enhanced UI menus:

- `M-x sss-menu` - Main SSS menu
- `M-x sss-project-menu` - Project management menu
- `M-x sss-user-menu` - User management menu
- `M-x sss-key-menu` - Key management menu
- `M-x sss-settings-menu` - Settings and configuration menu

### SSS Patterns

The package recognises and highlights three types of SSS patterns:

- `⊕{content}` - Plaintext (UTF-8 marker)
- `o+{content}` - Plaintext (ASCII alternative)
- `⊠{content}` - Ciphertext

When `sss-mode` is enabled, these patterns are highlighted with distinct colours.

### Auto-mode Features

When `sss-mode` is enabled:

- **Auto-decrypt**: Files are automatically decrypted when opened
- **Auto-encrypt**: Files are automatically encrypted when saved
- **Syntax highlighting**: SSS patterns are visually distinguished
- **Context-aware**: Operations adapt based on pattern type at point

## Project Integration

### Project Detection

The package automatically detects SSS projects by looking for `.sss.toml` files. It integrates with:

- **project.el**: SSS projects are recognised as project roots
- **dired**: Navigate to project root with `sss-goto-project-root`
- **completion**: User lists are populated from project configuration

### Project Commands

- `sss-show-project-info` - Display detailed project information
- `sss-project-status` - Show brief project status
- `sss-goto-project-root` - Navigate to project root
- `sss-open-project-config` - Open `.sss.toml` file
- `sss-find-encrypted-files-interactive` - Find files with SSS patterns

## Customization

### Customization Groups

Use `M-x customize-group RET sss RET` to access all customization options:

- **sss-executable**: Path to SSS command
- **sss-default-username**: Default username for operations
- **sss-config-directory**: Override config directory
- **sss-password-cache-timeout**: Password cache timeout (seconds)
- **sss-auto-decrypt-on-open**: Auto-decrypt files when opening
- **sss-auto-encrypt-on-save**: Auto-encrypt files when saving
- **sss-highlight-patterns**: Enable syntax highlighting
- **sss-keybinding-prefix**: Key binding prefix
- **sss-auto-mode-patterns**: File patterns for auto-mode activation

### Faces

Customize the appearance of SSS patterns:

- `sss-plaintext-face` - Face for plaintext markers
- `sss-ciphertext-face` - Face for ciphertext markers
- `sss-content-face` - Face for content inside markers

## Security Considerations

### Password Handling

- Passwords are cached securely with configurable timeout
- Integration with Emacs auth-source for credential storage
- Passwords are cleared from memory when cache expires
- Use `sss-clear-cache` to manually clear cached passwords

### File Security

- Temporary files are created with restrictive permissions
- Backup files are created before in-place modifications
- File paths are validated to prevent directory traversal

### Best Practices

1. Use strong passphrases for keypairs
2. Regularly rotate keys in multi-user projects
3. Keep `.sss.toml` files in version control but never commit private keys
4. Use `sss-render-file` for creating plaintext copies when needed
5. Clear password cache when leaving workstation unattended

## Troubleshooting

### Common Issues

**SSS executable not found**
- Ensure `sss` is installed and in your PATH
- Set `sss-executable` to the full path if needed

**Permission denied errors**
- Check file permissions
- Ensure you have write access to the directory
- Verify SSS config directory permissions

**Decryption failures**
- Verify you have the correct keypair
- Check that you're using the right username
- Ensure the project is properly initialised

**Emacs hangs during operations**
- Check if SSS is prompting for password in terminal
- Use `C-g` to cancel operation
- Clear password cache and retry

### Debug Mode

Enable debug mode for troubleshooting:

```elisp
M-x sss-toggle-debug
```

This will show detailed information about SSS operations in the message buffer.

### Getting Help

- `M-x sss-help` - Show built-in help
- `M-x sss-show-version` - Show SSS version
- `M-x sss-show-settings` - Display current configuration
- Check the main SSS documentation for CLI-specific issues

## 🔥 Doom Emacs Integration

### What You Get

The `sss-doom.el` module provides **complete Doom integration**:

| Feature | Description |
|---------|-------------|
| 🎯 **Leader Keys** | `SPC e` namespace for all SSS operations |
| ⚔️ **Evil Operators** | `ge`/`gd`/`gt` encrypt/decrypt/toggle operators |
| 🎪 **Text Objects** | `is`/`as` for inner/outer SSS patterns |
| 🎨 **UI Integration** | Popups, modeline, which-key, treemacs icons |
| 🚀 **Project Integration** | Works with projectile and workspace system |

### 🚀 Setup Examples

#### Minimal Setup
```elisp
(use-package! sss
  :config (require 'sss-doom))
```

#### Recommended Setup
```elisp
(use-package! sss
  :hook ((conf-mode yaml-mode) . sss-mode)
  :init
  (setq sss-default-username "myuser")
  :config
  (require 'sss-doom)

  ;; Auto-enable for encrypted files
  (add-to-list 'auto-mode-alist '("\\.env\\." . sss-mode))
  (add-to-list 'auto-mode-alist '("secrets\\." . sss-mode)))
```

#### Generate Full Config
```elisp
M-x sss-doom-config-template  ; Generates complete configuration
```

## Contributing

Contributions are welcome! Please:

1. Follow Emacs Lisp coding conventions
2. Add docstrings to all functions
3. Include interactive commands in the autoload section
4. Test with different Emacs versions (including Doom)
5. Update documentation for new features

## Licence

This package is part of the SSS project. See the main project LICENCE file for details.

## See Also

- [SSS Main Documentation](../../README.md)
- [Emacs Manual on Minor Modes](https://www.gnu.org/software/emacs/manual/html_node/emacs/Minor-Modes.html)
- [Transient Package Documentation](https://magit.vc/manual/transient/)
