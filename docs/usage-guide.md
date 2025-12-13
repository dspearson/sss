# sss Usage Guide

This guide covers the complete sss workflow from initial setup through daily use, team
collaboration, and git integration. For configuration reference, see
[configuration.md](configuration.md).

---

## Contents

1. [Overview](#overview)
2. [Initial Setup](#initial-setup)
3. [Marking Secrets](#marking-secrets)
4. [Sealing Files](#sealing-files)
5. [Opening Files](#opening-files)
6. [Editing Files](#editing-files)
7. [Rendering](#rendering)
8. [Key Management](#key-management)
9. [Team Collaboration](#team-collaboration)
10. [Git Integration](#git-integration)
11. [Secrets Files](#secrets-files)
12. [Stdin Support](#stdin-support)

---

## Overview

sss (Secret String Substitution) uses a marker-based approach to encrypt selected text
within files. You annotate the sensitive parts of a file with `⊕{...}` markers; sss
encrypts those segments in place, leaving the surrounding text unchanged. The sealed file
is ordinary text and commits cleanly to git.

Two marker characters are in use:

| Character | Unicode | Meaning |
|-----------|---------|---------|
| `⊕` | U+2295 CIRCLED PLUS | Plaintext / open marker — what you write |
| `⊠` | U+22A0 SQUARED ASTERISK | Ciphertext / sealed marker — what appears after sealing |

Encryption is XChaCha20-Poly1305 (via libsodium). Key derivation uses Argon2id.

---

## Initial Setup

### Generate a Keypair

Before using sss in any project, generate an asymmetric keypair:

```bash
sss keys generate
```

You will be prompted for a passphrase to protect the private key. The key is stored in
your configuration directory under `keys/` (see [Private Key Storage](configuration.md#private-key-storage)).

To generate a keypair without passphrase protection (useful for CI/CD environments):

```bash
sss keys generate --no-password
```

To store the passphrase in the system keyring instead of being prompted each time:

```bash
sss settings set --use-keyring true
sss keys generate
```

### Initialise a Project

From the root of your project directory, initialise sss:

```bash
sss init alice
```

Replace `alice` with your username. This creates `.sss.toml` in the current directory,
which holds your public key and a copy of the project repository key encrypted for you.
This file is safe to commit to git — it contains only public-key material and encrypted
keys.

If you have a default username configured in your settings, you can omit the argument:

```bash
sss settings set --username alice
sss init
```

---

## Marking Secrets

Mark the parts of a file that should be encrypted by wrapping them in `⊕{...}`:

```
database_url=postgres://admin:⊕{my-secret-password}@localhost/app
api_key=⊕{sk-1234567890abcdef}
```

The ASCII alternative `o+{...}` is accepted wherever `⊕{...}` is:

```
api_key=o+{sk-1234567890abcdef}
```

After sealing, `⊕` markers become `⊠` markers containing base64-encoded ciphertext.
After opening, they become `⊕` markers again (always the UTF-8 form, even if you wrote
`o+{...}`).

### Nested Braces

The parser uses balanced brace counting, so JSON and similar structured content is valid
inside a marker:

```
config=⊕{{"host":"db.example.com","port":5432,"password":"secret"}}
```

The closing `}}` is two closing braces: one closing the JSON object and one closing the
`⊕{...}` marker. This works correctly because the parser tracks brace depth.

---

## Sealing Files

Sealing encrypts every `⊕{...}` (or `o+{...}`) marker in a file, replacing each with
`⊠{base64ciphertext}`. Existing `⊠{...}` markers are passed through unchanged.

**Output to stdout** (non-destructive preview):

```bash
sss seal config.txt
```

**Seal in-place** (overwrites the file):

```bash
sss seal -x config.txt
```

**Seal all files in the project** (project-wide):

```bash
sss seal --project
```

The `--project` form recursively processes all files in the project directory, respecting
ignore patterns from `.sss.toml` and your project settings. See
[Ignore Patterns](configuration.md#ignore-patterns) for details.

---

## Opening Files

Opening decrypts every `⊠{...}` marker, replacing it with `⊕{decrypted_plaintext}`. The
plaintext marker form (`⊕{...}`) is preserved — use `sss render` if you want markers
removed entirely.

**Output to stdout**:

```bash
sss open config.txt
```

**Open in-place** (overwrites the file):

```bash
sss open -x config.txt
```

**Open all files in the project**:

```bash
sss open --project
```

Project-wide opening requires explicit permission per project to prevent accidental
mass-decryption. Grant permission with:

```bash
sss project enable open
```

Or set the environment variable for a single invocation:

```bash
SSS_PROJECT_OPEN=true sss open --project
```

---

## Editing Files

The `edit` command provides a single-command workflow: decrypt to a temporary form, open
your editor, and re-encrypt on save.

```bash
sss edit config.txt
```

sss will:

1. Open the file and decrypt all `⊠{...}` markers to `⊕{...}` form.
2. Launch your editor (`$EDITOR`, or the editor configured in your settings).
3. When you save and quit, re-seal any `⊕{...}` markers and write the result back.

The editor is determined in this order: `EDITOR` environment variable, `VISUAL`
environment variable, the `editor` field in your settings, then a platform default.

---

## Rendering

Rendering decrypts all `⊠{...}` markers and removes all markers entirely, producing pure
plaintext with no sss annotations. This is useful for passing files to tools that do not
understand sss markers.

```bash
sss render config.txt
```

Render in-place:

```bash
sss render -x config.txt
```

Render all files in the project:

```bash
sss render --project
```

Project-wide rendering requires explicit permission:

```bash
sss project enable render
# or
SSS_PROJECT_RENDER=true sss render --project
```

**Caution:** rendered files contain plaintext secrets. Do not commit them to git.

---

## Key Management

### List Keys

```bash
sss keys list
```

Displays the key ID, creation date, and whether a passphrase is set for each stored key.

### Show Your Public Key

```bash
sss keys pubkey
```

Export to a file for sharing with teammates:

```bash
sss keys pubkey > my-public-key.txt
```

Show only the fingerprint:

```bash
sss keys pubkey --fingerprint
```

Show the public key for another user registered in the project:

```bash
sss keys pubkey --user bob
```

### Show or Set the Current Keypair

```bash
sss keys current          # show which key is active
sss keys current <key-id> # set active key by ID or partial ID
```

### Change Passphrase

To set or change the passphrase on an existing key:

```bash
sss keys set-passphrase <key-id>
```

To remove passphrase protection (useful for unattended environments):

```bash
sss keys remove-passphrase <key-id>
```

### Rotate the Project Key

Key rotation generates a new repository symmetric key and re-encrypts all sealed files in
the project. This is automatically triggered when a user is removed, but can also be
performed manually.

```bash
sss keys rotate
```

Options:

```bash
sss keys rotate --force     # skip confirmation prompt
sss keys rotate --dry-run   # show what would be changed without making changes
sss keys rotate --no-backup # skip creating backup copies before rotation
```

Key rotation requires all sealed files to be accessible and re-encrypts them for all
remaining users in `.sss.toml`.

---

## Team Collaboration

### Adding a User

**Step 1: Bob generates a keypair and exports his public key.**

```bash
# On Bob's machine
sss keys generate
sss keys pubkey > bob-public-key.txt
```

Bob sends `bob-public-key.txt` to Alice (or posts it somewhere she can access it).

**Step 2: Alice adds Bob to the project.**

```bash
# On Alice's machine, in the project directory
sss project users add bob bob-public-key.txt
```

This unseals the project repository key (using Alice's private key), re-seals it for Bob
using his public key, and adds a `[bob]` section to `.sss.toml`. Alice commits and pushes
the updated `.sss.toml`.

**Step 3: Bob pulls and can now seal and open project files.**

```bash
# On Bob's machine
git pull
sss open config.txt  # works — Bob's key is in .sss.toml
```

### Listing Project Users

```bash
sss project users list
```

### Removing a User

```bash
sss project users remove bob
```

Removing a user automatically triggers key rotation: a new repository key is generated
and all sealed files are re-encrypted. Bob's entry is removed from `.sss.toml`. After the
rotation, Bob can no longer decrypt project files, even with the old ciphertext.

Commit and push the updated `.sss.toml` and all re-encrypted files after removal.

---

## Git Integration

### Installing Hooks

sss can install git hooks that automatically seal files before commits and open/render
files after checkout or merge.

```bash
sss hooks install
```

This installs the following hooks in `.git/hooks/`:

| Hook | Behaviour |
|------|-----------|
| `pre-commit` | Seals any files with open `⊕{...}` markers before they are committed |
| `post-merge` | Opens or renders files after a merge (if permitted) |
| `post-checkout` | Opens or renders files after checkout (if permitted) |

### Multiplexed Hooks

If your project already has custom hooks, use the multiplexed structure to avoid
overwriting them:

```bash
sss hooks install --multiplex
```

This creates `.git/hooks/<hookname>.d/` directories and adds sss scripts there, leaving
existing hook scripts undisturbed.

### Listing and Inspecting Hooks

```bash
sss hooks list        # list available hooks
sss hooks show <hook> # show the content of a specific hook
```

### Template Hooks

To install hooks in a git template directory (affecting all future clones on this
machine):

```bash
sss hooks install --template
```

---

## Secrets Files

Secrets files hold named secret values that can be interpolated into your sealed files
using the `⊲{name}` syntax (U+22B2 NORMAL SUBGROUP OF).

### Creating a Secrets File

The default secrets filename is `secrets` (without extension). Create a `.secrets`-style
file alongside your project:

```
# Project secrets
database_password: hunter2
api_token: sk-abcdef1234567890

# Multi-line value (YAML-style pipe)
ssh_private_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAA...
  -----END OPENSSH PRIVATE KEY-----
```

### Using Interpolation

Reference a secret by name:

```
DATABASE_URL=postgres://admin:⊲{database_password}@localhost/app
```

When the file is sealed, `⊲{database_password}` is looked up in the secrets file and the
value is substituted before encryption. The sealed file contains `⊠{...}` (ciphertext)
at the interpolation site.

### Custom Secrets Filename

Configure a different filename for the project:

```bash
sss project secrets-file set .env.secrets
sss project secrets-file show
sss project secrets-file clear  # revert to default "secrets"
```

Or set it directly in `.sss.toml` or via your user settings. See
[Secrets File Configuration](configuration.md#secrets-file-configuration) for details.

---

## Stdin Support

All file-processing commands accept `-` as the filename to read from standard input:

```bash
echo "password=⊕{secret}" | sss seal -
cat config.txt | sss open -
cat config.txt | sss render -
```

This is useful in pipelines and shell scripts where you want to process text without
writing intermediate files.

---

*See also:*
- [configuration.md](configuration.md) — complete reference for `.sss.toml`, `settings.toml`, and environment variables
- [docs/SECRETS_FILE_FORMAT.md](SECRETS_FILE_FORMAT.md) — detailed secrets file format reference
