# Project Configuration

This tutorial covers configuring sss projects, including ignore
patterns, secrets files, user settings, and per-project features.

## User settings

Global settings that apply across all your projects.

### View settings

```console
$ sss settings show
username: alice
editor: vim
coloured: true
kdf_level: sensitive
use_keyring: false
secrets_filename: (default)
secrets_suffix: (default)
```

### Set preferences

```console
$ sss settings set --username alice
$ sss settings set --editor vim
$ sss settings set --coloured true
$ sss settings set --kdf-level moderate
$ sss settings set --use-keyring true
```

Use `none` to clear a value back to its default:

```console
$ sss settings set --editor none
```

### Reset everything

```console
$ sss settings reset --confirm
```

### Find config files

```console
$ sss settings location
User config:    ~/.config/sss/config.toml
Key directory:  ~/.config/sss/keys/
```

## System keyring

sss can store key passphrases in your OS keyring to avoid repeated
prompts:

- **macOS**: Keychain
- **Linux**: Secret Service (GNOME Keyring, KDE Wallet)
- **Windows**: Credential Manager

```console
$ sss settings set --use-keyring true
```

Once enabled, your passphrase is stored after the first successful
entry and retrieved automatically thereafter.

## Project settings

Per-project settings live in `.sss.toml` at the project root.

### View project status

```console
$ sss project show
Project: /home/alice/my-project
Version: 1.0
Created: 2024-01-15T10:30:00Z
Users: 2
Render: disabled
Open: disabled
```

### List all known projects

```console
$ sss project list
/home/alice/my-project    2 users
/home/alice/other-project 1 user
```

### Enable/disable features

Auto-render or auto-open modes control whether project-wide operations
happen automatically:

```console
$ sss project enable render    # auto-render on open
$ sss project disable render
$ sss project enable open      # auto-open on checkout
$ sss project disable open
```

Shortcut for enabling render:

```console
$ sss project --render
```

### Remove a project

Remove a project from your settings (does not delete files):

```console
$ sss project remove
$ sss project remove /path/to/other/project
```

## Ignore patterns

Control which files are skipped during project-wide `seal`, `open`, and
`render` operations.

### Add patterns

```console
$ sss project ignore add "*.log"
$ sss project ignore add "build/**"
$ sss project ignore add "node_modules/**"
$ sss project ignore add "*.test.js"
```

Patterns use glob syntax, similar to `.gitignore`.

### List patterns

```console
$ sss project ignore list
*.log
build/**
node_modules/**
*.test.js
```

### Remove patterns

```console
$ sss project ignore remove "*.test.js"
```

### Negation

Prefix a pattern with `!` to un-ignore a file that would otherwise
match:

```console
$ sss project ignore add "*.log"
$ sss project ignore add "!important.log"
```

This ignores all `.log` files except `important.log`.

### Nested project boundaries

If a subdirectory contains its own `.sss.toml`, it is treated as a
separate project. Parent project operations will not descend into it.

## Secrets files

sss supports a separate **secrets file** for storing key-value pairs
that are interpolated into source files using `⊲{name}` markers.

### How it works

1. Create a source file with interpolation markers:

```yaml
# config.yaml
database:
  password: ⊲{db_password}
api:
  key: ⊲{api_key}
```

2. Create a secrets file alongside it:

```
# secrets (or config.yaml.secrets)
db_password: s3cret-passw0rd
api_key: sk_live_abc123def456
```

3. Seal the secrets file:

```console
$ sss seal secrets -x
```

4. Render the source file -- `⊲{...}` markers are replaced with values
   from the decrypted secrets file:

```console
$ sss render config.yaml
database:
  password: s3cret-passw0rd
api:
  key: sk_live_abc123def456
```

### Custom secrets filename

By default, sss looks for files named `secrets` and files with a
`.secrets` suffix. You can change this:

```console
$ sss project secrets-file set .env
$ sss project secrets-file show
.env
$ sss project secrets-file clear    # back to default
```

Or set it globally:

```console
$ sss settings set --secrets-filename env
$ sss settings set --secrets-suffix .sealed
```

### Best practices for secrets files

- **Seal the secrets file** before committing -- the entire file
  becomes one `⊠{...}` block
- **Add plaintext secrets files to `.gitignore`** as a safety net
- Use `⊲{...}` interpolation for values that multiple files reference
- Use inline `⊕{...}` markers for one-off secrets

## Project users (via project subcommand)

You can also manage users through the project subcommand:

```console
$ sss project users list
$ sss project users add bob "X25519:..."
$ sss project users remove bob
$ sss project users info bob
```

These are equivalent to `sss users list`, `sss users add`, etc.

## KDF security levels

The key derivation function (KDF) level controls how much work is
required to derive an encryption key from your passphrase. This can be
set globally or per-operation:

| Level         | Security   | Speed       | Use case              |
|---------------|------------|-------------|-----------------------|
| sensitive     | Highest    | ~2 seconds  | Production, shared    |
| moderate      | Balanced   | ~1 second   | Interactive use       |
| interactive   | Standard   | ~0.3 second | Development, testing  |

Set globally:

```console
$ sss settings set --kdf-level moderate
```

Or per-command:

```console
$ sss --kdf-level interactive seal config.yaml
```

## Non-interactive mode

For scripts and CI/CD, pass `--non-interactive` to prevent passphrase
prompts. Supply the passphrase via environment variable:

```console
$ export SSS_PASSPHRASE="mypass"
$ sss --non-interactive seal --project
```

sss will fail with an error rather than block waiting for input.

## Configuration file locations

```
~/.config/sss/
├── config.toml        # global user settings
├── keys/              # private keypairs
│   └── a1b2c3d4-...
└── hooks/             # exported hook scripts

~/my-project/
└── .sss.toml          # project config (commit this)
```

## Summary

| What                  | Command                                     |
|-----------------------|---------------------------------------------|
| View settings         | `sss settings show`                         |
| Set editor            | `sss settings set --editor vim`             |
| Enable keyring        | `sss settings set --use-keyring true`       |
| View project          | `sss project show`                          |
| Add ignore pattern    | `sss project ignore add "*.log"`            |
| Set secrets filename  | `sss project secrets-file set .env`         |
| Non-interactive mode  | `sss --non-interactive seal --project`      |

## Previous tutorials

- [Getting Started](01-getting-started.md)
- [Team Collaboration](02-team-collaboration.md)
- [Git Integration](03-git-integration.md)
- [Editor Workflow](04-editor-workflow.md)
- [FUSE Mounting](05-fuse-mounting.md)
