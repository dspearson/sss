# Team Collaboration

This tutorial covers adding collaborators to an sss project so that
multiple people can encrypt and decrypt the same files.

## How multi-user encryption works

Every sss project has a single **repository key** -- a symmetric
XChaCha20-Poly1305 key that encrypts and decrypts all secrets. Each user
holds a copy of this repository key, sealed (wrapped) with their own
X25519 public key.

```
                  ┌─────────────┐
                  │ Repo Key    │  (symmetric, never stored in plaintext)
                  └──────┬──────┘
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
     ┌────────────┐ ┌────────────┐ ┌────────────┐
     │ Sealed for │ │ Sealed for │ │ Sealed for │
     │   Alice    │ │    Bob     │ │  Charlie   │
     └────────────┘ └────────────┘ └────────────┘
```

All three sealed copies live in `.sss.toml`. Anyone with the matching
private key can unwrap their copy and use the repo key.

## Step 1: New user generates a keypair

The new collaborator generates their own keypair on their machine:

```console
bob$ sss keys generate
Enter passphrase:
Confirm passphrase:
Keypair generated: f9e8d7c6-...
```

## Step 2: New user shares their public key

```console
bob$ sss keys pubkey
X25519:b4se64EncodedPublicKey...==
```

Bob sends this public key string to Alice (the project owner) through a
trusted channel -- email, chat, in person, etc.

To show the key fingerprint instead (useful for verification):

```console
bob$ sss keys pubkey --fingerprint
SHA256:xYz123...
```

## Step 3: Project owner adds the user

Alice adds Bob using his username and public key:

```console
alice$ sss users add bob "X25519:b4se64EncodedPublicKey...=="
Enter passphrase for key a1b2c3d4:
User 'bob' added to project.
```

Behind the scenes, sss:

1. Decrypts Alice's sealed copy of the repository key
2. Re-seals the repository key with Bob's public key
3. Stores both sealed copies in `.sss.toml`

Alice commits and pushes the updated `.sss.toml`.

## Step 4: New user clones and works

Bob clones the repository and can immediately seal and open files:

```console
bob$ git clone git@github.com:team/project.git
bob$ cd project
bob$ sss open config.yaml
```

sss finds Bob's entry in `.sss.toml`, unwraps the repository key using
his private key, and decrypts the file.

## Managing users

### List all users

```console
$ sss users list
alice   added 2024-01-15  fingerprint: SHA256:abc...
bob     added 2024-02-01  fingerprint: SHA256:def...
```

### Show user details

```console
$ sss users info bob
Username: bob
Public key: X25519:b4se64...==
Fingerprint: SHA256:def...
Added: 2024-02-01T10:30:00Z
```

### Remove a user

```console
$ sss users remove bob
User 'bob' removed from project.
```

**Important**: removing a user deletes their sealed copy of the
repository key from `.sss.toml`, but they may still have a cached copy
of the key. For full revocation, you should also rotate the repository
key:

```console
$ sss keys rotate
```

This generates a new repository key, re-encrypts all files, and
re-seals the key for all remaining users.

## Key rotation

Rotate the repository key periodically or after removing a user:

```console
$ sss keys rotate
This will:
  - Generate a new repository key
  - Re-encrypt all sealed markers in the project
  - Re-seal the key for all current users
  - Create backup files (.bak)

Proceed? [y/N] y
Enter passphrase for key a1b2c3d4:
Rotating... done.
  Files re-encrypted: 47
  Users re-keyed: 2
  Backups created: 47
```

Options:

- `--dry-run` -- show what would change without modifying anything
- `--no-backup` -- skip creating `.bak` files
- `--force` -- skip confirmation prompt

## Viewing your own public key for a project user

If you want to see the public key stored for a specific user in the
current project:

```console
$ sss keys pubkey --user bob
X25519:b4se64EncodedPublicKey...==
```

## Best practices

1. **Verify fingerprints** -- when receiving a public key, confirm the
   fingerprint through a separate channel
2. **Rotate after removal** -- always run `sss keys rotate` after
   removing a user
3. **One keypair per person** -- avoid sharing private keys between
   people
4. **Passphrase-protect keys** -- especially on shared or work machines
5. **Commit `.sss.toml`** -- it's the source of truth for who has access

## Next steps

- [Git Integration](03-git-integration.md) -- automate seal/open with hooks
- [Project Configuration](06-project-configuration.md) -- per-project settings
