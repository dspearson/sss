# Git Integration

This tutorial covers using sss with git, including automatic hooks that
seal and open files as you commit, pull, and checkout.

## The problem

Without automation, you must remember to:

1. Seal files before every commit (so plaintext never enters the repo)
2. Open files after every pull or checkout (so you can read them)

sss provides git hooks that handle this automatically.

## Installing hooks

From your project root:

```console
$ sss hooks install
Installed hooks:
  .git/hooks/pre-commit
  .git/hooks/post-merge
  .git/hooks/post-checkout
```

### Multiplexed hooks

If you already have git hooks and don't want sss to overwrite them, use
the multiplexed layout:

```console
$ sss hooks install --multiplex
Installed hooks:
  .git/hooks/pre-commit.d/sss
  .git/hooks/post-merge.d/sss
  .git/hooks/post-checkout.d/sss
```

This places sss hooks alongside your existing ones in `.d/` directories.

### Template installation

To apply hooks to all future clones automatically:

```console
$ sss hooks install --template
Installed to git template directory.
```

## How the hooks work

### pre-commit

Runs before `git commit`. It seals all files in the project that contain
`⊕{...}` plaintext markers, converting them to `⊠{...}` ciphertext.
This prevents you from accidentally committing plaintext secrets.

```
  You run: git commit
  ┌─────────────────────────────┐
  │ pre-commit hook fires       │
  │  └─ sss seal --project      │
  │     ⊕{secret} → ⊠{cipher}  │
  └─────────────────────────────┘
  Commit proceeds with sealed files.
```

### post-merge

Runs after `git pull` or `git merge`. It opens all sealed files in the
project, converting `⊠{...}` back to `⊕{...}` so you can read and edit
them.

```
  You run: git pull
  ┌─────────────────────────────┐
  │ post-merge hook fires       │
  │  └─ sss open --project      │
  │     ⊠{cipher} → ⊕{secret}  │
  └─────────────────────────────┘
  Working tree has readable secrets.
```

### post-checkout

Runs after `git checkout`. Same as post-merge -- opens sealed files so
the branch you've switched to is immediately readable.

## Viewing installed hooks

```console
$ sss hooks list
pre-commit     installed
post-merge     installed
post-checkout  installed
```

To see the contents of a specific hook:

```console
$ sss hooks show pre-commit
#!/bin/sh
# sss pre-commit hook
...
```

## Exporting hooks

To save hook scripts to your config directory for backup or sharing:

```console
$ sss hooks export
Exported hooks to ~/.config/sss/hooks/
```

## FUSE git passthrough

When working with a FUSE-mounted sss project (see the
[FUSE tutorial](05-fuse-mounting.md)), git commands would normally see
the rendered (decrypted) view rather than the sealed files. The
`sss git` command solves this:

```console
$ sss git status
$ sss git add config.yaml
$ sss git commit -m "Update secrets"
$ sss git push
```

`sss git` routes git operations to the underlying (sealed) directory,
so git always works with the encrypted markers. Use this whenever you're
inside a FUSE mount.

## Workflow with hooks

Once hooks are installed, your daily workflow simplifies to:

```console
$ vim config.yaml          # edit with ⊕{...} markers
$ git add config.yaml
$ git commit -m "Update"   # pre-commit auto-seals
$ git push                 # only ciphertext is pushed
```

And when pulling:

```console
$ git pull                  # post-merge auto-opens
$ cat config.yaml           # ⊕{...} markers visible
```

## Working without hooks

If you prefer manual control, you can skip hook installation and run
seal/open yourself:

```console
$ sss seal --project && git add -A && git commit -m "Update"
$ git pull && sss open --project
```

## Non-interactive mode

In CI/CD pipelines or scripts where no TTY is available, use
`--non-interactive` to fail rather than prompt for a passphrase:

```console
$ SSS_PASSPHRASE="mypass" sss seal --project --non-interactive
```

The `SSS_PASSPHRASE` environment variable supplies the passphrase.

## Tips

- **Always commit `.sss.toml`** -- it contains the user/key mappings
- **Add `.secrets` to `.gitignore`** if you have plaintext secrets files
- **Check `sss status`** in CI to verify you're in a project
- Hooks respect [ignore patterns](06-project-configuration.md) --
  files matching ignore rules are skipped during project-wide operations

## Next steps

- [Editor Workflow](04-editor-workflow.md) -- using `sss edit`
- [FUSE Mounting](05-fuse-mounting.md) -- transparent decrypted views
