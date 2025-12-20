# sss-mode: Emacs Integration Guide

sss-mode is an Emacs major mode that provides **transparent decrypt-on-open and re-seal-on-save** for files sealed with the sss secrets tool. It is a single `.el` file with zero external dependencies.

For CLI workflow context, see [usage-guide.md](usage-guide.md).

---

## 1. Overview

When you open a sealed file (one beginning with `⊠{`) in Emacs, sss-mode:

1. Detects the sealed-file signature automatically via `magic-mode-alist`.
2. Calls `sss open FILE` to decrypt the content.
3. Displays the decrypted plaintext with `⊕{}` markers visible in the buffer.
4. Registers a save handler that calls `sss seal --in-place FILE` whenever you save.

The result is transparent editing: you see and edit plaintext, but the on-disk file always remains sealed. Failures surface as visible minibuffer errors — sss-mode never silently produces an empty buffer.

---

## 2. Prerequisites

Before loading sss-mode, ensure all of the following are in place:

| Requirement | How to satisfy |
|-------------|----------------|
| Emacs 27.1 or later | Install via your package manager or from https://www.gnu.org/software/emacs/ |
| `sss` binary on PATH | Install sss; verify with `which sss` in a terminal |
| Working keystore | Run `sss keys generate` at least once |
| Initialised project | Run `sss init <username>` in the project directory |
| Passphrase without TTY | Store in system keyring, `SSS_PASSPHRASE` env var, or `~/.authinfo` (see Section 10) |

The last requirement is critical. sss-mode always passes `--non-interactive` to every CLI call, which prevents sss from prompting for a passphrase on a TTY. If the passphrase is not available through the keyring, auth-source, or the environment variable, all operations will fail with "Decryption failed".

---

## 3. Installation

**Step 1.** Obtain `sss-mode.el`. Either clone the sss repository or copy the single file:

```
emacs/sss-mode.el
```

**Step 2.** Add to your Emacs `init.el`:

```elisp
(add-to-list 'load-path "/path/to/sss/emacs/")
(require 'sss-mode)
```

Replace `/path/to/sss/emacs/` with the actual directory containing `sss-mode.el`.

That is all. sss-mode registers itself in `magic-mode-alist` at load time. The next time you open a sealed file (one that begins with the sealed marker `⊠{`), Emacs will automatically activate sss-mode.

---

## 4. Daemon-Mode / GUI Emacs Configuration

When Emacs is launched from a GUI launcher (e.g. a `.desktop` file, macOS Dock, or as a systemd user service), it may not inherit the shell `PATH` that your terminal session has. This means `sss` may not be found even though `which sss` works in a terminal.

### Solution A: Set `sss-executable` to an Absolute Path

```elisp
(setq sss-executable "/usr/local/bin/sss")
```

Add this to `init.el` **before** or **after** `(require 'sss-mode)`. The variable is read at call time, not at load time.

To find the correct absolute path:

```bash
which sss
```

Common locations: `/usr/local/bin/sss`, `/usr/bin/sss`, `~/.cargo/bin/sss`.

### Solution B: Use `exec-path-from-shell`

The `exec-path-from-shell` package copies PATH from the user's shell profile into Emacs:

```elisp
(use-package exec-path-from-shell
  :config
  (exec-path-from-shell-initialize))
```

Available on MELPA. This fixes PATH for all external tools, not just sss.

### Solution C: Set the Environment via systemd

If running Emacs as a systemd user daemon:

```bash
systemctl --user set-environment SSS_PASSPHRASE="your-passphrase"
systemctl --user set-environment PATH="/usr/local/bin:$PATH"
```

This injects the variables into the systemd user session, where Emacs will inherit them.

---

## 5. Keyring Prerequisites for Daemon Mode

sss-mode passes `--non-interactive` to all CLI calls, so sss will never show a TTY passphrase prompt. The passphrase must be available through one of:

### Linux (GNOME Keyring / KWallet)

The keyring session must be available to the Emacs process. For GUI Emacs launched from a display manager, this is typically automatic. For daemon mode:

- **GNOME Keyring**: ensure `gnome-keyring-daemon --start` has been called in the user session before Emacs starts. Typically handled by PAM.
- **KWallet**: similar — ensure `kwallet-query` can succeed without a terminal.

To test whether the keyring is accessible to Emacs, run in the `*scratch*` buffer:

```elisp
(shell-command-to-string "sss --non-interactive keys list")
```

### macOS (Keychain)

macOS Keychain is typically available to GUI applications, including GUI Emacs. No special configuration is needed in most cases.

### Alternative: `SSS_PASSPHRASE` Environment Variable

If keyring integration is not available or not desired, set the passphrase as an environment variable:

```bash
# For the current shell session:
export SSS_PASSPHRASE="your-passphrase"

# For systemd daemon mode:
systemctl --user set-environment SSS_PASSPHRASE="your-passphrase"

# For launchd (macOS):
launchctl setenv SSS_PASSPHRASE "your-passphrase"
```

**Security note:** environment variables are visible to other processes owned by the same user. Prefer keyring integration or auth-source (Section 10) where possible.

---

## 6. How It Works

### 6.1 Automatic File Detection

sss-mode registers a named predicate function `sss--sealed-p` in `magic-mode-alist`:

```elisp
(add-to-list 'magic-mode-alist (cons #'sss--sealed-p #'sss-mode))
```

The predicate checks whether the buffer begins with the 4-byte UTF-8 sequence for `⊠{`. This check is multibyte-safe and fires before `auto-mode-alist`, so sss-mode takes precedence over any extension-based mode.

### 6.2 Decrypt-on-Open

When a sealed file is opened (`find-file`), the mode's `find-file-hook` calls `sss--open-buffer`, which:

1. **Disables auto-save** (`auto-save-mode -1`) before touching the buffer content. This prevents the auto-save timer from writing partial plaintext to `#file#` during the CLI call.
2. **Disables backup** (`backup-inhibited t`) for the same reason.
3. Calls `sss --non-interactive open FILE` via `call-process`.
4. Replaces the buffer content with the decrypted output (`⊕{}` markers are preserved so you can see what is and is not encrypted).
5. Marks the buffer unmodified.
6. Updates the modeline to `SSS[open]`.
7. Registers `sss--write-contents` on `write-contents-functions` (buffer-local).

### 6.3 Re-Seal-on-Save

When you save the buffer (`C-x C-s` or `save-buffer`), the `write-contents-functions` handler `sss--write-contents` runs:

1. Writes the plaintext buffer content to disk (using `write-region` with `write-contents-functions` temporarily disabled to prevent recursion).
2. Calls `sss --non-interactive seal --in-place FILE`.
3. If sealing succeeds, calls `set-visited-file-modtime` so Emacs considers the buffer clean.
4. Returns `t` to signal that the file has been written — preventing Emacs from writing plaintext via its default path.

If sealing fails at step 2, `sss--write-contents` signals `(error ...)`. This is mandatory: returning `nil` would cause Emacs to fall through to its default `write-region` and write plaintext to disk.

**Brief plaintext window:** Between step 1 (write plaintext) and step 2 (seal), the file exists on disk in plaintext for a few milliseconds. This is the same limitation as `epa-file.el` (Emacs' built-in GnuPG integration) and is considered an accepted trade-off.

### 6.4 Modeline Indicator

The modeline shows the current buffer state:

| Modeline text | Meaning |
|--------------|---------|
| `SSS[sealed]` | File was just opened; decryption has not run yet, or the buffer holds sealed content |
| `SSS[open]` | Decryption succeeded; buffer shows plaintext with `⊕{}` markers |

---

## 7. Key Bindings

All sss-mode bindings use the `C-c C-x` pattern (package-lint compliant — minor-mode-style bindings for major modes).

| Key | Command | Description |
|-----|---------|-------------|
| `C-c C-o` | `sss-open-buffer` | Decrypt the sealed buffer in place |
| `C-c C-s` | `sss-seal-buffer` | Re-seal and save (equivalent to `C-x C-s`) |
| `C-c C-r` | `sss-render-buffer` | View pure plaintext (markers stripped) in a separate buffer |
| `C-c C-i` | `sss-init` | Run `sss init` in the project directory |
| `C-c C-p` | `sss-process` | Run `sss seal --project` (seal all files in project) |
| `C-c C-k` | `sss-keygen` | Run `sss keys generate` (generate a new keypair) |
| `C-c C-l` | `sss-keys-list` | Display available keys (project and keystore) |
| `C-c C-e` | `sss-encrypt-region` | Encrypt selected region in-place |
| `C-c C-d` | `sss-decrypt-region` | Decrypt sealed region in-place |
| `C-c C-t` | `sss-toggle-at-point` | Toggle encrypt/decrypt at point |
| `C-c C-v` | `sss-preview-at-point` | Preview decrypted secret (transient overlay) |
| `C-c C-m` | `sss-dispatch` | Open SSS command menu (transient or completing-read) |

**Note:** `sss-process` calls `sss seal --project` — there is no `sss process` subcommand in the CLI. This command seals all files with plaintext markers across the whole project.

---

## 8. Region Operations

v1.1 adds four commands for operating on individual markers within a buffer. These complement the whole-buffer open/seal commands and allow fine-grained control over which secrets are encrypted at any given time.

### `sss-encrypt-region` (`C-c C-e`)

Select any text and press `C-c C-e` to encrypt it in-place.

- If the selected text is already an open marker (`⊕{...}`), it is passed directly to `sss seal -`.
- If the selected text is plain text (not wrapped in a marker), sss-mode automatically wraps it in `⊕{...}` before sealing.
- The region is replaced with the resulting sealed marker (`⊠{...}`).

```
Before: my-secret-password
        ^----- select this -----^

After:  ⊠{a3f8c2...}
```

### `sss-decrypt-region` (`C-c C-d`)

Select a sealed marker and press `C-c C-d` to decrypt it in-place.

- The selected `⊠{...}` marker is passed to `sss open -`.
- The region is replaced with the open marker (`⊕{...}`), revealing the plaintext content.

### `sss-toggle-at-point` (`C-c C-t`)

Place point anywhere inside a marker and press `C-c C-t` to toggle its encryption state.

- If point is on a sealed marker (`⊠{...}`), it is decrypted to an open marker.
- If point is on an open marker (`⊕{...}`), it is encrypted to a sealed marker.
- No selection required — sss-mode detects the marker boundaries automatically by scanning backward from point.

### Example Workflow

1. Type a secret value in the buffer: `api_key=abc123xyz`
2. Select the value: `C-SPC` then move to end of line.
3. Press `C-c C-e` to encrypt: buffer now shows `api_key=⊠{3f8a...}`.
4. To inspect the value temporarily, place point inside the sealed marker.
5. Press `C-c C-t` to toggle: marker becomes `⊕{abc123xyz}` (plaintext visible).
6. Press `C-c C-t` again to re-seal: marker returns to `⊠{3f8a...}`.

---

## 9. Preview and Overlays

### Preview at Point (`C-c C-v`)

`sss-preview-at-point` decrypts a sealed marker and shows the result as a **transient overlay** next to the marker in the buffer. The buffer content is **not modified**.

- Place point anywhere inside a `⊠{...}` marker.
- Press `C-c C-v`.
- The decrypted value appears in a tooltip-style overlay immediately after the marker: `⊠{3f8a...} [abc123xyz]`.
- Press any key to dismiss the overlay.

This is useful for quickly checking a secret's value without leaving an open marker in the buffer.

### Overlay Mode (`sss-toggle-overlay-mode`)

`sss-toggle-overlay-mode` enables or disables persistent visual overlays on all SSS markers in the buffer.

When overlay mode is **enabled**:

- Every `⊕{...}` marker receives the `sss-open-face` highlight (gold/green by default).
- Every `⊠{...}` marker receives the `sss-sealed-face` highlight (grey by default).
- Overlays include `help-echo` tooltips listing available commands:
  - On a sealed marker: "Sealed secret (C-c C-d to decrypt, C-c C-t to toggle)"
  - On an open marker: "Open secret (C-c C-e to encrypt, C-c C-t to toggle)"
- Overlays update automatically after any encrypt/decrypt operation.

When overlay mode is **disabled**, all overlays are removed. Font-lock highlighting (Section 15) remains active regardless of overlay mode.

To enable overlay mode on startup, add to `init.el`:

```elisp
(add-hook 'sss-mode-hook #'sss-toggle-overlay-mode)
```

`sss-toggle-overlay-mode` has no default key binding in the base mode-map; use `C-c C-m` (`sss-dispatch`) to access it from the command menu.

---

## 10. Auth-Source Integration

sss-mode v1.1 integrates with Emacs' built-in `auth-source` library, providing a third passphrase mechanism alongside the system keyring and `SSS_PASSPHRASE` environment variable.

### How It Works

The custom variable `sss-use-auth-source` (default: `t`) controls this behaviour. When non-nil, sss-mode calls `auth-source-search` with `:host "sss"` before each CLI invocation. If a matching entry is found, the secret is injected as `SSS_PASSPHRASE` in the subprocess environment — without ever writing it to disk or exposing it in process listings beyond the child process.

This uses `(require 'auth-source nil t)` — a soft require that adds no hard dependency. If auth-source is not available, the feature silently does nothing.

### Setting Up `~/.authinfo`

Add a single line to `~/.authinfo`:

```
machine sss login default password YOURPASSPHRASE
```

Replace `YOURPASSPHRASE` with your actual keystore passphrase.

For a GPG-encrypted authinfo file (`~/.authinfo.gpg`), use the same format — Emacs decrypts it transparently via EasyPG.

### Auth-Source Backends

`auth-source` supports multiple backends. Any of the following work:

| Backend | Configuration |
|---------|--------------|
| Plain text file | `(setq auth-sources '("~/.authinfo"))` |
| GPG-encrypted file | `(setq auth-sources '("~/.authinfo.gpg"))` |
| Secrets Service (GNOME Keyring, KWallet) | `(setq auth-sources '(default))` |
| macOS Keychain | `(setq auth-sources '(macos-keychain-internet))` |

The default `auth-sources` value on most Emacs installations already includes `~/.authinfo.gpg` and `~/.authinfo`.

### Disabling Auth-Source

To disable auth-source lookup and fall back to system keyring or environment variable:

```elisp
(setq sss-use-auth-source nil)
```

---

## 11. Command Menu (`sss-dispatch`)

`sss-dispatch` (`C-c C-m`) opens a unified command menu listing all SSS operations. It is the primary discoverability entry point: new users can press `C-c C-m` to see what sss-mode can do.

### Transient Menu (Emacs 28+ or MELPA)

When the `transient` package is available (bundled with Emacs 28+, available on MELPA for Emacs 27.1), `sss-dispatch` opens a categorised transient popup:

```
SSS command dispatch.

Region Operations
  e  Encrypt region        d  Decrypt region
  t  Toggle at point       v  Preview at point

Buffer / File
  o  Open (decrypt) buffer     s  Seal (encrypt) buffer
  r  Render (strip markers)

Project
  i  Init project    p  Process project
  k  Generate keys   l  List keys

Settings
  O  Toggle overlay mode
```

### Completing-Read Fallback

When `transient` is not installed, `sss-dispatch` falls back to `completing-read`, presenting the same command list in the minibuffer with completion. All commands are accessible — only the presentation differs.

### Usage

Press `C-c C-m` from any sss-mode buffer. The menu is always available regardless of whether transient is installed.

---

## 12. Evil Integration

sss-mode includes evil-mode integration that is **conditionally loaded**: the evil code only runs when `evil` has been loaded (`with-eval-after-load 'evil`). In vanilla Emacs without evil, no evil code is evaluated.

### Operators

Three evil operators are defined for sss-mode buffers:

| Key | Operator | Description |
|-----|----------|-------------|
| `ge` | `sss-evil-encrypt` | Encrypt text covered by motion |
| `gd` | `sss-evil-decrypt` | Decrypt text covered by motion |
| `gt` | `sss-evil-toggle` | Toggle encryption state of markers in motion range |

**Usage with motions:**

- `geiw` — Encrypt the current word (inner word motion)
- `ge$` — Encrypt from point to end of line
- `gd` (on a sealed marker line) — Decrypt the line's marker
- `gtiw` — Toggle the marker under the cursor

**Scope:** These bindings are set via `evil-define-key 'normal sss-mode-map`, making them **buffer-local** to sss-mode buffers. The default evil bindings (`ge` = `evil-backward-word-end`, `gd` = `evil-goto-definition`, `gt` = `evil-tab-next`) remain in effect in all non-sss buffers.

### Text Objects

Two text objects are defined for selecting SSS marker content:

| Key | Object | Selects |
|-----|--------|---------|
| `is` | `sss-inner-pattern` | Content inside marker braces, excluding `⊕{` / `⊠{` prefix and closing `}` |
| `as` | `sss-outer-pattern` | Entire marker including prefix and braces |

**Usage examples:**

- `vis` — Visually select the secret value inside a marker (inner)
- `das` — Delete the entire marker including delimiters (outer)
- `cis` — Change the inner content of a marker (replace the secret value)
- `yis` — Yank (copy) the inner content to the kill ring

Text objects work in both visual state and as arguments to operators: `geis` encrypts the inner content of the marker at point.

---

## 13. Doom Emacs Integration

sss-mode includes Doom Emacs bindings that are **conditionally loaded**: the `map!` calls only execute when the `map!` macro is available (`(fboundp 'map!)`). The code is safe to load in vanilla Emacs — the `when` guard prevents `map!` from being called.

### Installation for Doom

1. Copy `emacs/sss-mode.el` to `~/.config/doom/lisp/sss-mode.el`
2. Add to `~/.config/doom/config.el`:
   ```elisp
   (load! "lisp/sss-mode")
   ```
3. Run `doom sync`

That is all. sss-mode activates automatically for sealed files via `magic-mode-alist`.

### Leader Bindings (`SPC e` prefix)

The `SPC e` prefix provides global access to encryption commands from any buffer:

| Key | Command | Description |
|-----|---------|-------------|
| `SPC e e` | `sss-encrypt-region` | Encrypt region |
| `SPC e d` | `sss-decrypt-region` | Decrypt region |
| `SPC e t` | `sss-toggle-at-point` | Toggle at point |
| `SPC e v` | `sss-preview-at-point` | Preview at point |
| `SPC e SPC` | `sss-dispatch` | SSS command menu |
| `SPC e p i` | `sss-init` | Init project |
| `SPC e p p` | `sss-process` | Process project |
| `SPC e k g` | `sss-keygen` | Generate keys |
| `SPC e k l` | `sss-keys-list` | List keys |

Sub-prefixes: `SPC e p` for project commands, `SPC e k` for key management.

### Localleader Bindings (`, e` prefix)

The `, e` prefix provides buffer-local access in sss-mode buffers (`:map sss-mode-map`). In Doom, the localleader is typically `,` (comma):

| Key | Command | Description |
|-----|---------|-------------|
| `, e e` | `sss-encrypt-region` | Encrypt region |
| `, e d` | `sss-decrypt-region` | Decrypt region |
| `, e t` | `sss-toggle-at-point` | Toggle at point |
| `, e v` | `sss-preview-at-point` | Preview at point |
| `, e SPC` | `sss-dispatch` | SSS command menu |

---

## 14. Customisation

Open the customisation interface:

```
M-x customize-group RET sss RET
```

### Variables

**`sss-executable`** (default: `"sss"`)

Path to the sss binary. sss-mode searches `exec-path` (Emacs' equivalent of `PATH`) for this name. Set to an absolute path for daemon-mode or GUI-launcher environments where `exec-path` may not include your install location:

```elisp
(setq sss-executable "/usr/local/bin/sss")
```

**`sss-use-auth-source`** (default: `t`)

When non-nil, sss-mode looks up the keystore passphrase from `auth-source` before each CLI call. See Section 10 for setup instructions. To disable:

```elisp
(setq sss-use-auth-source nil)
```

---

## 15. Font-Lock Highlighting

sss-mode highlights marker syntax with distinct colours:

| Marker | Face | Default appearance |
|--------|------|--------------------|
| `⊕{...}` | `sss-open-face` | Light background: LightGoldenrod1 on DarkGreen; dark background: dark olive green on LightYellow |
| `⊠{...}` | `sss-sealed-face` | Light background: light gray on gray50; dark background: dim gray on gray70 |

This lets you visually distinguish open (plaintext) regions from sealed (encrypted) regions within the same file. Both faces can be customised via `M-x customize-face`.

---

## 16. Troubleshooting

### "sss: command not found" or binary not on exec-path

Set `sss-executable` to the absolute path:

```elisp
(setq sss-executable "/usr/local/bin/sss")
```

Verify the path in a terminal: `which sss`.

### "Decryption failed" on file open

sss-mode passes `--non-interactive` to all calls, so the passphrase must be in the system keyring, auth-source, or `SSS_PASSPHRASE`. Test from a terminal:

```bash
sss --non-interactive open /path/to/sealed-file.txt
```

If this fails, the issue is with the keystore or passphrase, not with sss-mode. Common causes:

- Keyring not unlocked for the Emacs process (daemon mode issue — see Section 5).
- `SSS_PASSPHRASE` not set in the environment Emacs inherited.
- `~/.authinfo` entry missing or misspelt (see Section 10).
- Wrong user: the project was initialised with a different username. Check `.sss.toml`.

### Blank or empty buffer after open

Check the `*Messages*` buffer (`C-h e`) for error output. sss-mode should have raised a visible error — if the buffer is blank without an error, this is a bug.

### "File modified" prompts when killing the buffer

Expected if the buffer was opened (decrypted) but you have not saved since. sss-mode leaves the buffer marked clean after a successful seal, so this prompt indicates an unsaved edit or a failed seal.

### Daemon mode hangs or pauses on open

sss is waiting for a passphrase on a non-existent TTY. The `--non-interactive` flag should prevent this, but if your sss binary predates this flag, upgrade. For current versions, ensure `SSS_PASSPHRASE` is set:

```bash
systemctl --user set-environment SSS_PASSPHRASE="your-passphrase"
```

### Auto-save files appearing (`#file#`)

This should not happen — sss-mode disables auto-save immediately when opening a sealed file. If you see `#file#` containing plaintext, check whether the auto-save disable code ran before the auto-save timer fired. This can happen if Emacs is under heavy load. Upgrade to a current sss-mode version which disables auto-save before calling the CLI.

---

## 17. Security Considerations

### Protections Provided by sss-mode

- **Auto-save disabled:** Emacs will not write `#file#` auto-save files containing plaintext.
- **Backup disabled:** Emacs will not write `file~` backup files containing plaintext.
- **`write-contents-functions` return value:** Returning `t` on success prevents Emacs' default `write-region` from writing plaintext.
- **Error on seal failure:** `(error ...)` on a failed seal prevents the plaintext write that would otherwise occur if `nil` were returned.
- **Auth-source passphrase injection:** When `sss-use-auth-source` is enabled, the passphrase is retrieved from the user's credential store and injected into the subprocess environment rather than being stored in Emacs variables or written to any file.

### Accepted Limitations

- **Brief plaintext window on save:** Between the write-plaintext and seal-in-place steps, the file exists on disk in plaintext for a few milliseconds. Identical to `epa-file.el`'s behaviour.
- **Buffer is plaintext in Emacs memory:** While the buffer is open, the decrypted content lives in Emacs process memory. This is unavoidable for interactive editing. Emacs memory is not swapped to disk on modern systems with sufficient RAM, but this is not guaranteed.
- **No protection against Emacs crashes:** If Emacs crashes after writing plaintext but before sealing, the plaintext file may remain on disk. Consider enabling full-disk encryption on systems where this is a concern.
- **Preview overlay decrypts to memory:** `sss-preview-at-point` calls the CLI to decrypt the marker; the decrypted value passes through Emacs process memory momentarily. The overlay is dismissed on the next keystroke, but the value may linger in the process address space until garbage collected.
