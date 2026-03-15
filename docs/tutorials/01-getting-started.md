# Getting Started with sss

This tutorial walks you through initialising your first sss project and
encrypting secrets in your files.

## Prerequisites

- sss installed and available on your `$PATH`
- A directory you'd like to protect secrets in

## Concepts

sss works by embedding encrypted markers directly in your source files.
A secret passes through three states:

| State     | Marker   | Example                        | Meaning                    |
|-----------|----------|--------------------------------|----------------------------|
| Plaintext | `⊕{...}` | `⊕{hunter2}`                   | Human-readable, unencrypted |
| Sealed    | `⊠{...}` | `⊠{z4NqW...base64...==}`      | Encrypted, safe to commit  |
| Rendered  | *(none)* | `hunter2`                      | Raw value, no markers      |

There is also a secrets-interpolation marker `⊲{name}` for referencing
values stored in a separate secrets file (covered in a later tutorial).

## Step 1: Generate a keypair

Before creating a project you need a personal keypair. This is stored in
`~/.config/sss/keys/` and never leaves your machine.

```console
$ sss keys generate
Enter passphrase (leave blank for no passphrase):
Confirm passphrase:
Keypair generated: a1b2c3d4-5678-...
```

The passphrase protects your private key at rest using Argon2id key
derivation. You can choose from three KDF security levels:

- **sensitive** (default) -- strongest, ~2 seconds to derive
- **moderate** -- balanced for interactive use
- **interactive** -- fastest, suitable for development

```console
$ sss keys generate --kdf-level interactive
```

Use `--no-password` if you prefer no passphrase at all (not recommended
for shared machines).

## Step 2: Initialise a project

Navigate to the directory you want to protect and run `init` with your
username:

```console
$ cd ~/my-project
$ sss init alice
Enter passphrase for key a1b2c3d4:
Project initialised: ~/my-project/.sss.toml
```

This creates `.sss.toml` in the project root. It contains:

- Project metadata (version, creation timestamp)
- Your public key
- A sealed copy of the shared repository encryption key

The `.sss.toml` file is safe to commit -- it contains no secrets.

## Step 3: Mark secrets in your files

Edit any text file and wrap sensitive values with `⊕{...}`:

```yaml
# config.yaml
database:
  host: localhost
  port: 5432
  username: myapp
  password: ⊕{s3cret-passw0rd}

api:
  key: ⊕{sk_live_abc123def456}
```

The `⊕` marker tells sss "this value is a plaintext secret."

## Step 4: Seal (encrypt)

Encrypt all plaintext markers in a file:

```console
$ sss seal config.yaml
```

This outputs the sealed version to stdout. To modify the file in place:

```console
$ sss seal config.yaml -x
```

The file now looks like:

```yaml
# config.yaml
database:
  host: localhost
  port: 5432
  username: myapp
  password: ⊠{z4NqW3Bx...long-base64...==}

api:
  key: ⊠{hR7mKp2...long-base64...==}
```

The `⊠` markers contain XChaCha20-Poly1305 authenticated ciphertext.
This is safe to commit to version control.

To seal every file in the project at once:

```console
$ sss seal --project
```

## Step 5: Open (decrypt to editable form)

To get back to the editable plaintext-marker form:

```console
$ sss open config.yaml
```

Or in place:

```console
$ sss open config.yaml -x
```

This restores the `⊕{...}` markers so you can see and edit secret values.

To open all files in the project:

```console
$ sss open --project
```

## Step 6: Render (decrypt to raw values)

When you need the completely decrypted output with no markers at all:

```console
$ sss render config.yaml
```

Output:

```yaml
database:
  host: localhost
  port: 5432
  username: myapp
  password: s3cret-passw0rd

api:
  key: sk_live_abc123def456
```

This is what your application would consume. You would typically pipe
this to a file or process rather than writing it back in place.

## Step 7: Check project status

```console
$ sss status
/home/alice/my-project
```

Returns the project root path and exits 0 if you're inside an sss
project, or exits 1 if not.

## Typical workflow

```
  Edit files           Seal              Commit
  (⊕ markers)  ──────► (⊠ markers) ──────► git
       ▲                                     │
       │                                     │
       └──── Open ◄──── Pull/Checkout ◄──────┘
```

1. **Work**: edit files with `⊕{...}` plaintext markers
2. **Seal**: encrypt before committing (`sss seal --project`)
3. **Commit**: push `⊠{...}` ciphertext to the repository
4. **Open**: after pulling, decrypt back to `⊕{...}` for editing

## Deterministic encryption

sss uses deterministic nonces derived from the project timestamp, file
path, and plaintext content. This means identical secrets in the same
file always produce identical ciphertext -- keeping your git diffs clean.

## Next steps

- [Team Collaboration](02-team-collaboration.md) -- adding other users
- [Git Integration](03-git-integration.md) -- automating seal/open with hooks
- [Editor Workflow](04-editor-workflow.md) -- using `sss edit`
