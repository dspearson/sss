# Editor Workflow

This tutorial covers `sss edit` and the `ssse` editor-mode binary for
seamlessly editing encrypted files.

## The problem

Manually running open/edit/seal for every file change is tedious:

```console
$ sss open config.yaml -x    # decrypt
$ vim config.yaml             # edit
$ sss seal config.yaml -x    # re-encrypt
```

`sss edit` wraps this into a single command.

## Using sss edit

```console
$ sss edit config.yaml
```

This:

1. **Opens** the file -- decrypts `⊠{...}` to `⊕{...}` in a temporary
   copy with restricted permissions (0600)
2. **Launches your editor** -- opens the temporary file
3. **Seals** the file -- when you save and quit, re-encrypts `⊕{...}`
   back to `⊠{...}` and writes the result back to the original file
4. **Cleans up** -- removes the temporary file

Your editor sees plaintext markers that you can read and modify. New
secrets can be added by typing `⊕{new-secret-value}`.

## Editor selection

sss picks your editor in this order:

1. `$EDITOR` environment variable
2. `editor` setting in sss config (`sss settings set --editor vim`)
3. Fallback: tries `nano`, `vim`, `emacs`, `vi` in order

Set your preferred editor:

```console
$ export EDITOR=vim
```

Or persistently via sss settings:

```console
$ sss settings set --editor vim
```

## Security features

sss launches editors with flags to prevent secret leakage:

**vim/nvim:**
- `-n` -- no swap file
- `-i NONE` -- no viminfo file
- `+set nobackup nowritebackup noundofile` -- no backup or undo files

**emacs:**
- `--no-init-file` -- skip user config that might enable logging
- `--eval (setq make-backup-files nil)` -- no backup files

The temporary file is created with 0600 permissions (owner read/write
only) and is deleted immediately after editing completes.

## The ssse symlink

sss ships a companion binary `ssse` (note the extra 'e') that acts as
an editor-mode entry point:

```console
$ ssse config.yaml
```

This is equivalent to `sss edit config.yaml` but is useful as a
`$EDITOR` replacement in other tools. For example, you could set it as
your git editor for commit messages in encrypted repositories.

`ssse` determines the username via:
1. `$SSS_USER` environment variable
2. Default username from sss config
3. `$USER` / `$USERNAME` environment variable

## Adding new secrets during editing

While editing a file, simply type new `⊕{...}` markers:

```yaml
# Before (in editor):
database:
  password: ⊕{old-password}
  api_token: ⊕{new-token-here}

# After save+quit (on disk):
database:
  password: ⊠{...sealed...}
  api_token: ⊠{...sealed...}
```

Both old and new secrets are sealed when you close the editor.

## Modifying existing secrets

To change a secret's value, simply edit the content inside the `⊕{...}`
marker:

```yaml
# Change password:
password: ⊕{new-better-password}
```

The old ciphertext is replaced with a new sealed marker for the updated
value.

## Removing secrets

Delete the entire marker to remove a secret:

```yaml
# Before:
debug_key: ⊕{temporary-key}

# After (just delete the line or the marker):
# (line removed)
```

## Tips

- **Don't edit sealed markers directly** -- always use `sss edit` or
  `sss open` first. Modifying `⊠{...}` content will corrupt the
  ciphertext.
- **Use `sss edit` for single files** and git hooks for batch operations.
- **Check your editor** isn't creating hidden backup files (`.swp`,
  `~`, `#`) that might contain decrypted content. sss mitigates this
  for vim and emacs, but check other editors manually.

## Next steps

- [FUSE Mounting](05-fuse-mounting.md) -- transparent decrypted filesystem view
- [Git Integration](03-git-integration.md) -- automatic seal/open on commit
