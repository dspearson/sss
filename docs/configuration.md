# sss Configuration Reference

This document is the complete reference for all configuration surfaces in sss:
project-level `.sss.toml`, user-level `settings.toml`, environment variables, and global
CLI options. For workflow instructions, see [usage-guide.md](usage-guide.md).

---

## Contents

1. [Configuration Layers](#configuration-layers)
2. [Project Configuration (.sss.toml)](#project-configuration-ssstoml)
3. [User Settings (settings.toml)](#user-settings-settingstoml)
4. [Private Key Storage](#private-key-storage)
5. [Environment Variables](#environment-variables)
6. [Global CLI Options](#global-cli-options)
7. [Ignore Patterns](#ignore-patterns)
8. [Secrets File Configuration](#secrets-file-configuration)

---

## Configuration Layers

sss resolves configuration from multiple sources. When the same setting appears in more
than one place, the highest-priority source wins:

```
CLI arguments       (highest priority)
     ↓
Environment variables
     ↓
User settings (~/.config/sss/settings.toml)
     ↓
Project config (.sss.toml)
     ↓
Built-in defaults   (lowest priority)
```

---

## Project Configuration (.sss.toml)

`.sss.toml` is created in the project root by `sss init`. It records each authorised
user's public key and a copy of the project repository key sealed for that user. The file
is safe to commit to git — all values in it are either public-key material or
ciphertext.

### Annotated Example

```toml
# Schema version — currently always "1.0"
version = "1.0"

# Timestamp when the project was initialised (RFC 3339)
created = "2026-02-21T12:00:00Z"

# One section per authorised user (flattened into the top level)
[alice]
# Alice's Ed25519 public key, base64-encoded (44 characters)
public = "KkgbqNe8lYfzJgC9yDc7H3LwNp4QmVxKoTbOuUeRsBA="

# The project's repository symmetric key, sealed (X25519 crypto_box_seal)
# for Alice's public key. Base64-encoded.
sealed_key = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlYWxlZCBrZXk="

# Timestamp when Alice was added (RFC 3339)
added = "2026-02-21T12:00:00Z"

[bob]
public = "XzYbpOv9mAfzLhD8zEc8I4MxOq5RnWyLpUcPvVfStCB="
sealed_key = "Ym9iIHNlYWxlZCBrZXkgZXhhbXBsZSBiYXNlNjQ="
added = "2026-02-21T13:00:00Z"

# --- Optional project settings ---

# Custom filename for secrets files (default: "secrets")
# Affects which files sss looks for as secrets sources for ⊲{} interpolation
secrets_filename = "secrets"

# Custom suffix for secrets files (default: ".secrets")
# A file named "app.secrets" or "config.secrets" will be treated as a secrets file
secrets_suffix = ".secrets"

# Gitignore-style patterns for files to exclude from project-wide operations
# (sss seal --project, sss open --project, sss render --project)
# Patterns are space- or comma-separated. Prefix with ! to negate (un-exclude).
ignore = "*.log build/ dist/ node_modules/ !important.log"
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | string | `"1.0"` | Configuration schema version |
| `created` | string (RFC 3339) | current time | Project creation timestamp |
| `[username]` | section | — | Per-user section; one per authorised user |
| `[username].public` | string | required | User's Ed25519 public key (base64) |
| `[username].sealed_key` | string | required | Repository key sealed for this user (base64) |
| `[username].added` | string (RFC 3339) | current time | When user was added |
| `secrets_filename` | string | `"secrets"` | Basename for secrets lookup files |
| `secrets_suffix` | string | `".secrets"` | Suffix for secrets lookup files |
| `ignore` | string | none | Space/comma-separated gitignore-style patterns |

### Committing `.sss.toml`

`.sss.toml` should be committed to git. It contains only:
- Public keys (not secret)
- Repository keys encrypted for each user (safe without the corresponding private keys)
- Project metadata

Do **not** add `.sss.toml` to `.gitignore`.

---

## User Settings (settings.toml)

User settings live in your platform's standard configuration directory:

| Platform | Path |
|----------|------|
| Linux / BSD | `~/.config/sss/settings.toml` |
| macOS | `~/Library/Application Support/sss/settings.toml` |
| Windows | `%APPDATA%\sss\settings.toml` |

To find the exact path on your system:

```bash
sss settings location
```

### Viewing and Editing Settings

Show current settings:

```bash
sss settings show
```

Set individual values from the command line:

```bash
sss settings set --username alice
sss settings set --editor vim
sss settings set --coloured true
sss settings set --kdf-level moderate
sss settings set --use-keyring true
```

Reset all settings to defaults:

```bash
sss settings reset --confirm
```

### Annotated Example

```toml
# Default username used when --user is not specified and SSS_USER is not set
default_username = "alice"

# Preferred editor for `sss edit` (overrides $EDITOR / $VISUAL)
editor = "vim"

# Default secrets file basename (can be overridden per-project in .sss.toml)
# secrets_filename = "secrets"

# Default secrets file suffix
# secrets_suffix = ".secrets"

[ui]
# Enable coloured terminal output (default: true when stdout is a TTY)
coloured_output = true

# Show progress bars for long operations (default: true)
# show_progress = true

# Verbosity level 0–3 (default: 1)
# verbosity = 1

# Prompt before destructive operations such as key deletion (default: true)
# confirm_destructive = true

[keystore]
# Argon2id security level for new key generation
# "sensitive"   — ~256 MiB RAM, highest security (default)
# "moderate"    — ~128 MiB RAM, balanced
# "interactive" — ~64 MiB RAM, fastest (suitable for development keys)
kdf_level = "sensitive"

# Store key passphrases in the system keyring
# (macOS Keychain, Windows Credential Manager, Linux Secret Service)
# Default: false
use_system_keyring = false

# Auto-lock private keys after this many minutes of inactivity (optional)
# auto_lock_minutes = 30

# Maximum number of keys to retain (optional)
# max_keys = 10
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_username` | string | none | Username used when not specified elsewhere |
| `editor` | string | none | Editor for `sss edit` |
| `secrets_filename` | string | `"secrets"` | Default secrets file basename |
| `secrets_suffix` | string | `".secrets"` | Default secrets file suffix |
| `ui.coloured_output` | bool | `true` (TTY) | Enable colour in terminal output |
| `ui.show_progress` | bool | `true` | Show progress indicators |
| `ui.verbosity` | integer 0–3 | `1` | Verbosity level |
| `ui.confirm_destructive` | bool | `true` | Prompt before destructive operations |
| `keystore.kdf_level` | string | `"sensitive"` | Argon2id security level |
| `keystore.use_system_keyring` | bool | `false` | Use OS keyring for passphrase |
| `keystore.auto_lock_minutes` | integer | `30` | Idle minutes before auto-locking keys |
| `keystore.max_keys` | integer | none | Maximum keys to keep |

---

## Private Key Storage

Private keys are stored in the `keys/` subdirectory of your sss configuration directory:

| Platform | Keys directory |
|----------|---------------|
| Linux / BSD | `~/.config/sss/keys/` |
| macOS | `~/Library/Application Support/sss/keys/` |
| Windows | `%APPDATA%\sss\keys\` |

On Unix systems, the `keys/` directory has mode `0700` (readable only by the owner).

Each key file is encrypted using Argon2id key derivation from your passphrase:

- Algorithm: Argon2id (via libsodium `crypto_pwhash` with `ALG_ARGON2ID13`)
- Security level determined by `keystore.kdf_level` setting (default: `sensitive`)
  - `sensitive`: ~256 MiB RAM, highest security
  - `moderate`: ~128 MiB RAM, balanced
  - `interactive`: ~64 MiB RAM, fastest

Alternatively, passphrase protection can be delegated to the system keyring with
`keystore.use_system_keyring = true`, in which case the key file is stored
without passphrase protection and the passphrase is retrieved from the OS credential
store on demand.

---

## Environment Variables

These variables override configuration file settings for the duration of a command:

| Variable | Purpose | Example value |
|----------|---------|---------------|
| `SSS_USER` | Override the username | `alice` |
| `SSS_PASSPHRASE` | Provide key passphrase without a prompt | `mypassphrase` |
| `SSS_PROJECT_OPEN` | Allow `sss open --project` without per-project permission | `true` or `1` |
| `SSS_PROJECT_RENDER` | Allow `sss render --project` without per-project permission | `true` or `1` |
| `SSS_USE_KEYRING` | Enable system keyring for this invocation | `true` or `1` |
| `SSS_KDF_LEVEL` | Override KDF security level | `interactive` |
| `SSS_DEVEL_MODE` | Enable experimental agent commands | `1` |
| `SSS_NONINTERACTIVE` | Fail if passphrase is not in `SSS_PASSPHRASE` (set internally by `--non-interactive`) | `1` |
| `EDITOR` | Editor for `sss edit` (standard Unix variable) | `vim` |
| `VISUAL` | Alternative editor variable (lower priority than `EDITOR`) | `emacsclient` |

### Notes

- `SSS_PASSPHRASE` is convenient in CI/CD pipelines and in Emacs daemon mode where
  no TTY is available. Keep it out of shell history (`export SSS_PASSPHRASE=$(cat secret-file)` or use the system keyring).
- `SSS_PROJECT_OPEN` and `SSS_PROJECT_RENDER` bypass the per-project safety gate that
  prevents accidental mass-decryption. Use them deliberately and temporarily.
- `SSS_KDF_LEVEL` accepts the same values as the `--kdf-level` CLI option:
  `sensitive`, `moderate`, `interactive` (and aliases `high`, `medium`, `low`,
  `fast`, `balanced`).
- `SSS_NONINTERACTIVE` is set automatically by `--non-interactive`; you do not normally
  need to set it yourself.

---

## Global CLI Options

These options can be passed before any subcommand and apply globally:

```
sss [GLOBAL OPTIONS] <subcommand> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--confdir <DIR>` | Override the configuration directory location |
| `--non-interactive` | Fail if a passphrase is required and `SSS_PASSPHRASE` is not set |
| `--kdf-level <LEVEL>` | Override the KDF security level for this invocation |
| `--user <USERNAME>` | Override the username for this invocation (equivalent to `SSS_USER`) |

### Examples

```bash
# Use a custom configuration directory
sss --confdir /tmp/test-config keys list

# CI pipeline: fail fast if passphrase not available
sss --non-interactive seal -x config.txt

# Use a faster KDF for development (not production)
sss --kdf-level interactive keys generate

# Specify username inline
sss --user bob open config.txt
```

---

## Ignore Patterns

Ignore patterns prevent specific files from being processed by project-wide operations
(`sss seal --project`, `sss open --project`, `sss render --project`).

### Syntax

Patterns use gitignore-style glob syntax:

```
*.log           # match all .log files anywhere in the project
build/          # match the build/ directory and its contents
dist/**         # match everything under dist/
!important.log  # negate: do not ignore this specific file
temp*.txt       # match temp followed by anything, then .txt
```

- A trailing `/` means "directory"; it expands to `dir/**` internally.
- Patterns match against both the full relative path and the filename alone.
- Negation patterns (`!`) override positive patterns for files that match both.

### Managing Patterns

Manage ignore patterns from the command line:

```bash
sss project ignore add "*.log"
sss project ignore add "build/"
sss project ignore remove "*.log"
sss project ignore list
```

These commands update the `ignore` field in `.sss.toml` and commit the change.

### Setting Patterns Directly in `.sss.toml`

You can also edit the `ignore` field directly. Patterns are space- or comma-separated on
a single line:

```toml
ignore = "*.log build/ dist/ node_modules/"
```

---

## Secrets File Configuration

Secrets files provide named values for `⊲{name}` interpolation (see
[Secrets Files](usage-guide.md#secrets-files) in the usage guide).

### Filename Resolution

sss looks for secrets files using the project's `secrets_filename` and `secrets_suffix`
settings. The defaults result in files named `secrets` or `*.secrets`.

### Managing the Filename per Project

```bash
sss project secrets-file set passwords     # use "passwords" as the filename
sss project secrets-file show              # show current setting
sss project secrets-file clear            # revert to default "secrets"
```

These commands update `secrets_filename` in `.sss.toml`.

### User-Wide Defaults

Set a default for all projects in your user settings:

```bash
sss settings set --secrets-filename .env.secrets
sss settings set --secrets-suffix .sealed
```

### Precedence

```
Project .sss.toml (secrets_filename / secrets_suffix)
     overrides
User settings.toml (secrets_filename / secrets_suffix)
     overrides
Built-in default ("secrets" / ".secrets")
```

---

*See also:*
- [usage-guide.md](usage-guide.md) — workflow guide for daily use
- [docs/SECRETS_FILE_FORMAT.md](SECRETS_FILE_FORMAT.md) — detailed secrets file format reference
