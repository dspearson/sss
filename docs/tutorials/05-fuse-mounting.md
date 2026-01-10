# FUSE Mounting

This tutorial covers mounting an sss project as a transparent filesystem
where encrypted files appear decrypted in real time.

## Prerequisites

- sss built with the `fuse` feature: `cargo build --features fuse`
- Linux with FUSE3, or macOS with macFUSE installed

## What FUSE mounting does

Instead of manually running `sss open` and `sss seal`, you mount the
project and get a live decrypted view:

```
  Disk (sealed)              Mount (rendered)
  ┌──────────────────┐       ┌──────────────────┐
  │ config.yaml      │       │ config.yaml      │
  │ pw: ⊠{cipher..}  │ ────► │ pw: s3cret       │
  └──────────────────┘       └──────────────────┘
```

Reading files through the mount returns fully decrypted content.
Writing through the mount automatically encrypts secrets back.

## Basic mount

Mount a project directory to a separate mountpoint:

```console
$ mkdir /tmp/decrypted
$ sss mount ~/my-project /tmp/decrypted
Enter passphrase for key a1b2c3d4:
Mounted ~/my-project at /tmp/decrypted
```

Now browse `/tmp/decrypted` -- all files appear with secrets decrypted.

## In-place (overlay) mount

Mount the project over itself, so your existing paths still work:

```console
$ cd ~/my-project
$ sss mount --in-place
Enter passphrase for key a1b2c3d4:
Mounted in-place at ~/my-project
```

Your editors, IDEs, and tools see decrypted content at the same paths
they always use. The underlying sealed files are still accessible
through `/proc/self/fd/` on Linux.

## Foreground mode

By default, sss daemonises the FUSE process. To keep it in the
foreground (useful for debugging):

```console
$ sss mount --in-place --foreground
```

Press Ctrl+C to unmount.

## Read-only mount

If you only need to view files without modifying them:

```console
$ sss mount ~/my-project /tmp/decrypted --read-only
```

## Virtual file suffixes

The FUSE mount provides three views of each file:

| Access               | Content                          |
|----------------------|----------------------------------|
| `file`               | Rendered -- raw decrypted values |
| `file.sss-opened`    | Opened -- `⊕{...}` markers      |
| `file.sss-sealed`    | Sealed -- `⊠{...}` markers      |

For example:

```console
$ cat /tmp/decrypted/config.yaml
password: s3cret

$ cat /tmp/decrypted/config.yaml.sss-opened
password: ⊕{s3cret}

$ cat /tmp/decrypted/config.yaml.sss-sealed
password: ⊠{z4NqW3...==}
```

This is useful when you need different views for different tools.

## Using git inside a FUSE mount

Git should see the sealed (encrypted) files, not the rendered view.
Use the `sss git` passthrough:

```console
$ cd /tmp/decrypted    # or ~/my-project with --in-place
$ sss git status
$ sss git add config.yaml
$ sss git commit -m "Update secrets"
$ sss git push
```

`sss git` routes commands to the underlying sealed directory so that
git commits contain ciphertext, not plaintext.

## Unmounting

```console
$ fusermount -u /tmp/decrypted       # Linux
$ umount /tmp/decrypted              # macOS
```

Or if running in foreground, simply press Ctrl+C.

## Debugging

Enable debug logging with the `SSS_FUSE_DEBUG` environment variable:

```console
$ SSS_FUSE_DEBUG=1 sss mount --in-place --foreground
```

This logs all filesystem operations to stderr, which is helpful for
diagnosing issues.

## Performance

The FUSE layer includes:

- **Content caching** with a 1-second TTL per file
- **Dirty tracking** for modified files
- **Thread-safe access** via read-write locks

For most workloads (config files, env files, small secrets), the
overhead is negligible. Very large files (>10 MB) with many markers
will be slower due to the encryption/decryption pass on every read.

## Tips

- **IDE integration** -- in-place mounts work seamlessly with VS Code,
  IntelliJ, and other editors that watch the filesystem
- **CI/CD** -- mount in a container to render secrets at deploy time
  without writing decrypted files to disk permanently
- **Don't commit from the rendered view** -- always use `sss git` or
  unmount before running plain `git` commands

## Next steps

- [Project Configuration](06-project-configuration.md) -- ignore patterns and settings
- [Git Integration](03-git-integration.md) -- hooks for non-FUSE workflows
