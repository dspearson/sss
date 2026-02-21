# Pitfalls Research

**Domain:** Emacs major mode with transparent encryption + CLI secrets tool documentation
**Researched:** 2026-02-21
**Confidence:** MEDIUM — Emacs EPA/age.el issues verified via official docs and multiple credible community sources. SSS-specific behavior extrapolated from codebase analysis (CONCERNS.md) and general CLI documentation research.

---

## Critical Pitfalls

### Pitfall 1: Auto-Save and Backup Files Write Plaintext to Disk

**What goes wrong:**
Emacs auto-save (`#file#`) and backup (`file~`) mechanisms fire independently of `before-save-hook`. When a sealed file is opened and decrypted into the buffer, Emacs will happily write the plaintext to `#.sss_secrets#` or `.sss_secrets~` without triggering any encryption logic. The sealed original stays intact, but the plaintext leaks to the filesystem.

**Why it happens:**
Auto-save is a background timer that calls `do-auto-save`, not `save-buffer`. Backup files are created by `make-backup-file` during the first `save-buffer` call, before `before-save-hook` runs. Neither pathway routes through the custom save logic. EasyPG avoids this by disabling both for `.gpg` buffers — sss-mode must do the same explicitly.

**How to avoid:**
In the major mode setup, set buffer-local variables immediately after decryption into the buffer:
```elisp
(setq-local backup-inhibited t)
(setq-local auto-save-default nil)
(auto-save-mode -1)
```
Do this inside the find-file hook that triggers decryption, not in the mode body, so it applies before auto-save has a chance to fire on a slow open.

**Warning signs:**
- `#sss-sealed-file#` appearing in the same directory as sealed files after opening them
- Backup files (`~`) with readable plaintext content after a first save
- Missing `backup-inhibited` and `auto-save-mode -1` in the mode initialization code

**Phase to address:** Emacs major mode implementation — auto-save/backup must be disabled before the first opportunity for a leak, which is during find-file, not at mode load time.

---

### Pitfall 2: The Before-Save-Hook Can Silently Fail and Leave Plaintext on Disk

**What goes wrong:**
If the `before-save-hook` function errors out (CLI exits non-zero, keystore unavailable, network timeout), Emacs may still proceed to write the buffer to disk with `write-region` in its plaintext decrypted state. The user sees an error message but the file is saved unencrypted. Next `git add` commits the secret in the clear.

**Why it happens:**
`before-save-hook` errors do not abort the save by default. Emacs' hook runner catches errors and logs them but continues. Only `write-contents-functions` (returning non-nil) or explicitly signaling an error from inside the hook with `(error ...)` will interrupt the save. Raising an error from a hook causes Emacs to ask "Save anyway?", which is better than silent plaintext write, but still not atomic.

**How to avoid:**
Use `write-contents-functions` rather than `before-save-hook` for the re-seal operation. `write-contents-functions` is specifically designed to replace the default save: if the function returns non-nil, Emacs skips `write-region` entirely. The function should: shell out to `sss seal`, verify the sealed output exists, write the sealed bytes to the file directly, and return `t`. If any step fails, signal a user-visible error and return nil (which will fall through to normal save — so also consider never returning nil on failure).

Alternatively, if `before-save-hook` is used: explicitly call `(signal 'error ...)` on CLI failure, which forces Emacs to prompt "Error in before-save-hook. Abort save?" rather than writing plaintext silently.

**Warning signs:**
- The mode uses `before-save-hook` without explicit `(error ...)` on CLI failure
- `sss seal` exit code is not checked before returning from the hook function
- No test for the scenario where `sss` is not on PATH during a save

**Phase to address:** Emacs major mode implementation — this is the single most dangerous data safety issue and must be addressed before any public release.

---

### Pitfall 3: Plaintext Left in Buffer After Save (Buffer State Mismatch)

**What goes wrong:**
After re-sealing on save, the buffer still contains the decrypted plaintext. If the user then uses `C-x C-w` (write-file to new name), kills the buffer and restores it from a session manager, or does `revert-buffer`, they can end up with plaintext written somewhere unexpected, or with the sealed bytes displayed in the buffer as garbage characters.

**Why it happens:**
The re-seal hook writes encrypted bytes to the file but leaves the buffer state unchanged. The buffer's content (plaintext) and the file's content (sealed bytes) diverge. Emacs tracks modification state with `buffer-modified-p` — after a successful sealed write, this should be set to nil, but if the buffer still contains plaintext, a subsequent `revert-buffer` will re-read the sealed file and display garbage unless re-decryption is triggered.

**How to avoid:**
After a successful seal-on-save: call `(set-buffer-modified-p nil)` to mark the buffer clean. Register an `after-revert-hook` (buffer-local) that re-triggers decryption when the buffer is reverted. Ensure that `find-file-hook` detection fires again after revert. Test the cycle: open → edit → save → revert → verify plaintext is shown correctly again.

**Warning signs:**
- Buffer shows `⊠{...}` marker syntax after a save followed by revert
- `(buffer-modified-p)` returns t after a successful seal
- No `after-revert-hook` handler in the mode

**Phase to address:** Emacs major mode implementation — buffer lifecycle testing.

---

### Pitfall 4: exec-path / PATH Mismatch Breaks sss Shell-Out in Daemon Mode

**What goes wrong:**
When Emacs is started as a daemon (via `systemd --user` or `launchd`), it does not inherit the user's shell `PATH`. The `sss` binary installed to `~/.cargo/bin/` or `/usr/local/bin/` is not on `exec-path`. Every call to `(call-process "sss" ...)` returns `"Searching for program: no such file or directory, sss"`. The mode appears broken with no useful error message pointing to the root cause.

**Why it happens:**
Emacs daemon mode starts from the init system with a minimal environment. `exec-path` defaults to a short list that does not include Rust cargo installs or local bin directories. This is one of the most commonly reported Emacs packaging bugs, affecting nearly every mode that shells out to external tools (magit, lsp-mode, etc.). The popular fix is `exec-path-from-shell`, but that is a user-config dependency the mode cannot mandate.

**How to avoid:**
In the sss-mode implementation: provide a customizable variable `sss-executable` that defaults to `"sss"` but can be set to an absolute path. Document this prominently. At mode load time, call `(executable-find sss-executable)` and warn loudly (not silently fail) if the binary is not found. Do not error on load — error at first use with a clear message like: `"sss not found on exec-path. Set sss-executable to the full path."`. Do not hardcode a path.

**Warning signs:**
- Mode uses `(shell-command-to-string "sss ...")` or `(call-process "sss" ...)` with a bare `"sss"` string and no fallback
- No user-configurable `sss-executable` variable
- No at-load-time check for binary presence
- No documentation for daemon mode setup

**Phase to address:** Emacs major mode implementation — first-use error messages and configuration.

---

### Pitfall 5: Magic Bytes Detection Conflicts with Other Modes or Fails on Large Files

**What goes wrong:**
Using `magic-mode-alist` to detect SSS-sealed files by header bytes can conflict with other modes examining the same bytes. If the magic bytes happen to look like another format (XML preamble, UTF-8 BOM, shebang line), the wrong mode fires. Alternatively, if the sealed file header is large (>4KB), Emacs' buffer scanning for magic-mode-alist may not reach the distinctive bytes and fall through to `fundamental-mode`.

**Why it happens:**
`magic-mode-alist` uses regexp matching against the beginning of the buffer. The match function is called with the buffer narrowed to the first chunk of the file. If the SSS sealed format wraps its magic bytes after a variable-length header, the fixed-position assumption breaks. Additionally, `magic-mode-alist` is checked before `auto-mode-alist`, so a poorly anchored regexp can shadow legitimate modes for non-SSS files that happen to share initial bytes.

**How to avoid:**
Use a custom match function (not a regexp) in `magic-mode-alist` that checks for SSS-specific marker bytes at known offsets. Keep the function defensive: return nil immediately for files over a threshold size before full parsing, return nil if the first bytes don't match the exact SSS prefix. Test against common file types (shell scripts, TOML, JSON, Rust source) to verify no false positives. As a belt-and-suspenders approach, also provide `auto-mode-alist` entries for any file extensions SSS conventionally uses.

**Warning signs:**
- The magic detection uses a simple regexp without anchoring to byte offsets
- No test for false-positive activation on non-SSS files
- No test for large files or files with variable-length preambles
- `auto-mode-alist` entry is the only detection mechanism (will miss extension-less sealed files)

**Phase to address:** Emacs major mode implementation — file detection strategy must be validated before hook logic is built on top of it.

---

### Pitfall 6: Keystore Authentication Failure Causes Silent No-Op Decrypt

**What goes wrong:**
The design relies on keystore auto-authentication. If the keystore is unavailable (locked, missing, wrong session keyring), the `sss open` call fails with a non-zero exit code. If the mode does not check this and treats empty stdout as "file has no secrets," the user opens what looks like a blank or garbled buffer without understanding why decryption did not occur. They edit the garbled content and save — overwriting the sealed file with garbage.

**Why it happens:**
Shell-out functions like `shell-command-to-string` return stdout only. If the CLI exits with an error and writes the error to stderr, the Emacs caller sees an empty string and no indication of failure. This is a classic stderr-blindness bug in Emacs CLI integration.

The existing codebase already has a known fragile area here: CONCERNS.md notes that keyring fallback silently degrades and the error context is lost (src/keystore.rs lines 73-81).

**How to avoid:**
Use `call-process` (not `shell-command-to-string`) so the exit code is available. Capture stderr to a dedicated buffer using the `(list t stderr-buffer)` destination argument. Check the return value: non-zero exit means decryption failed. Display a clear error to the user: `"sss open failed: <stderr message>"`. Never treat CLI failure as "no secrets found."

**Warning signs:**
- Mode uses `shell-command-to-string` for decryption calls
- No exit code check after `sss open`
- Stderr is discarded or merged with stdout without being surfaced to the user
- No test for keystore-unavailable scenario

**Phase to address:** Emacs major mode implementation — CLI integration layer.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Use `shell-command-to-string` instead of `call-process` | Simpler one-liner | No exit code, no stderr separation; silent failures | Never for encryption operations |
| Hardcode `sss` binary path | Works immediately | Breaks on any non-standard install, daemon mode | Never |
| Use `before-save-hook` instead of `write-contents-functions` | Familiar pattern | Cannot cleanly abort save on error | Never for seal-on-save |
| Skip disabling auto-save for decrypted buffers | Less setup code | Plaintext leak to `#file#` auto-save files | Never |
| Single `find-file-hook` for detection | Simple | Misses `revert-buffer` and `after-change-major-mode-hook` cycles | MVP only if documented as known gap |
| Documentation with command reference only, no tutorial | Faster to write | New users cannot orient themselves; conceptual model of seal/open/render is non-obvious | Never as the sole entry point |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| `sss` CLI from Emacs Lisp | Use `shell-command-to-string`; miss stderr and exit code | Use `call-process` with exit code check; route stderr to named buffer |
| Keystore on daemon-launched Emacs | Assume keyring session is available; it's not in daemon context | Detect keyring failure explicitly; surface error with recovery instructions |
| `magic-mode-alist` detection | Use a simple string regexp that matches SSS bytes but also matches other formats | Use a named predicate function that validates the full SSS header structure |
| `before-save-hook` for re-seal | Return nil on error, allowing Emacs to proceed with plaintext write | Use `write-contents-functions` or signal `(error ...)` explicitly on failure |
| Auto-save on decrypted buffer | Rely on default Emacs behavior | Explicitly disable auto-save and backups in buffer-local vars immediately on decrypt |
| CLI error messages in Emacs | Swallow stderr; show generic "error" | Capture stderr; display verbatim in `*sss-errors*` buffer |
| `sss` on macOS vs Linux | Assume same binary behavior | Test on both; macOS keychain integration differs from Linux Secret Service |

---

## Security Mistakes

Domain-specific security issues for this milestone.

| Mistake | Risk | Prevention |
|---------|------|------------|
| Auto-save writes decrypted buffer to `#file#` on disk | Plaintext secret leaks to filesystem without user awareness | `(setq-local auto-save-default nil)` + `(auto-save-mode -1)` immediately on decrypt |
| Backup file (`file~`) created from plaintext buffer | Same as above; persists after session ends | `(setq-local backup-inhibited t)` immediately on decrypt |
| Passing secrets via Emacs `(shell-command "sss ... secret-value")` | Secret value appears in `ps aux` output and shell history | Pass content via stdin (`process-send-string`) or temp file with secure permissions |
| CLI documentation shows `sss seal --key <actual-key-value>` in examples | Example commands in docs become copy-paste vectors for insecure usage | Use placeholder values `<your-key-id>` in all examples; never real keys |
| `(message "Decrypted: %s" plaintext)` debugging left in released mode | Plaintext appears in `*Messages*` buffer, accessible to other users and plugins | Audit all `message` calls before release; use `(when sss-debug ...)` guard |
| No POSIX mlock equivalent for decrypted buffer contents | Decrypted secrets can be paged to swap on memory pressure | Document this limitation explicitly; recommend encrypted swap or tmpfs for sensitive workloads |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| No visual indicator that buffer is decrypted/live | User does not know if they are editing plaintext or sealed bytes; confusion about what is saved | Show mode-line indicator: `[SSS:open]` when decrypted, `[SSS:sealed]` after seal |
| Seal failure produces Emacs backtrace instead of human error | User sees `(wrong-type-argument stringp nil)` and does not know the CLI failed | Catch all errors in hook; show `"sss-mode: seal failed — <reason>"` in minibuffer |
| "Keystore unavailable" looks the same as "file has no secrets" | User thinks empty buffer means empty file; edits and saves blank content | Distinguish these states; never show empty buffer without explicit error on keystore failure |
| Documentation tutorial starts with architecture, not workflow | New user cannot figure out the first command to run | Documentation must open with a 3-command quickstart: init → seal → open |
| `sss render` vs `sss open` vs `sss process` distinction not explained | Users pick the wrong subcommand for their use case; sealed files stay sealed when they expected plaintext | Tutorial must show each subcommand with a concrete before/after file example |
| Emacs mode requires manual `(require 'sss-mode)` with no autoload | Mode is not activated automatically; users install it and see nothing happen | Provide `autoload` cookie on `sss-mode` and add `magic-mode-alist` entry at package load time |

---

## "Looks Done But Isn't" Checklist

- [ ] **Auto-save disabled:** Verify `(auto-save-mode)` returns -1 in an sss-mode buffer after opening a sealed file — not just that the variable is set
- [ ] **Backup disabled:** Verify no `file~` appears in the directory after first save of a decrypted buffer
- [ ] **Seal-on-save atomic:** Verify that if `sss seal` exits non-zero, the original sealed file is unchanged and Emacs does NOT write plaintext
- [ ] **Buffer state after save:** Verify `(buffer-modified-p)` is nil after a successful seal, and `revert-buffer` re-decrypts correctly
- [ ] **Daemon mode PATH:** Verify sss-mode works when Emacs started via `emacs --daemon` with a stripped PATH (no `~/.cargo/bin`)
- [ ] **Error surfaces to user:** Verify that keystore authentication failure produces a visible error message, not a silent empty buffer
- [ ] **Magic byte detection no false positives:** Verify `sss-mode` does NOT activate on a normal `.toml`, `.sh`, or `.rs` file
- [ ] **Documentation quickstart:** Verify a new user can complete the full seal→edit→save cycle from the README alone, without reading architecture docs first
- [ ] **No plaintext in \*Messages\*:** Verify no decrypted secret content appears in the Emacs `*Messages*` buffer after open/save cycles

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Auto-save leaked plaintext | MEDIUM | Locate and shred `#file#` auto-save files; rotate any exposed secrets; add `backup-inhibited` fix |
| Save-hook failure wrote plaintext to sealed file path | HIGH | Restore from git history or backup; rotate exposed secrets; fix `write-contents-functions` usage |
| Daemon mode `exec-path` broken | LOW | Add `(setq sss-executable "/absolute/path/to/sss")` to user config; document the fix prominently |
| Magic mode false positive activated on non-SSS file | LOW | Add exclusion condition to detection function; user can `M-x fundamental-mode` as immediate workaround |
| Buffer state mismatch after revert | LOW | `M-x revert-buffer`; if still garbled, `M-x sss-open-buffer` manual command |
| Documentation lacking quickstart | MEDIUM | Write tutorial-first section; add "30-second quickstart" block at top of README |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Auto-save/backup plaintext leak | Emacs mode: buffer initialization | Test: check filesystem after opening sealed file; assert no `#file#` exists |
| `before-save-hook` silent plaintext write | Emacs mode: save hook implementation | Test: make `sss seal` fail; verify original sealed file unchanged |
| Buffer state mismatch after save | Emacs mode: buffer lifecycle | Test: open → edit → save → revert; verify plaintext shown, not garbage |
| exec-path broken in daemon mode | Emacs mode: CLI integration config | Test: start `emacs --daemon` with minimal PATH; verify `sss-mode` gives clear error |
| Magic bytes false positive | Emacs mode: file detection | Test: open `.toml`, `.sh`, `.rs` files; verify sss-mode not activated |
| Keystore failure silent no-op | Emacs mode: CLI integration error handling | Test: run with locked keystore; verify explicit error message shown |
| Documentation missing quickstart | Docs: README and usage guide | Review: new-user walkthrough from zero; time to first successful seal should be under 5 minutes |
| CLI docs show insecure example usage | Docs: all command reference pages | Review: audit every example for secret values in flags/args; use placeholder tokens only |

---

## Sources

- [EasyPG Assistant User's Manual — GNU Emacs](https://www.gnu.org/software/emacs/manual/html_mono/epa.html) — official documentation on EPA security considerations, auto-save behavior, temp file leaks (HIGH confidence)
- [Editing encrypted files in Emacs — akuszyk.com, 2024](https://akuszyk.com/2024-08-29-editing-encrypted-files-in-emacs.html) — key portability, passphrase fatigue pitfalls (MEDIUM confidence)
- [age.el issues — GitHub anticomputer/age.el](https://github.com/anticomputer/age.el/issues) — passphrase-protected identity key failure, memory residency gap (MEDIUM confidence)
- [age.el README — GitHub anticomputer/age.el](https://github.com/anticomputer/age.el) — recipient metadata challenge: files cannot auto-re-encrypt without buffer-local recipient variable (MEDIUM confidence)
- [exec-path-from-shell — GitHub purcell](https://github.com/purcell/exec-path-from-shell) — exec-path/PATH mismatch in daemon mode (HIGH confidence — widely reported, multiple sources)
- [Major Mode Conventions — GNU Emacs Lisp Reference Manual](https://www.gnu.org/software/emacs/manual/html_node/elisp/Major-Mode-Conventions.html) — `make-local-variable` vs `make-variable-buffer-local` distinction (HIGH confidence)
- [EasyPG save bug — bug#63293, GNU mailing list 2023](https://lists.gnu.org/archive/html/bug-gnu-emacs/2023-05/msg00225.html) — buffer modified flag not cleared after encrypted save (MEDIUM confidence)
- [before-save-hook error blocking save — Doom Emacs issue #893](https://github.com/hlissner/doom-emacs/issues/893) — hook errors blocking other hooks; abort-save pattern (MEDIUM confidence)
- [Org-encrypt before-save-hook failure — Doom Emacs Discourse](https://discourse.doomemacs.org/t/org-encrypt-entries-before-save-hook-wont-let-me-save-my-org-file/3349) — hook errors, save abort behavior (MEDIUM confidence)
- [Auto Major Mode — GNU Emacs Lisp Reference Manual](https://www.gnu.org/software/emacs/manual/html_node/elisp/Auto-Major-Mode.html) — `magic-mode-alist` precedence and custom match functions (HIGH confidence)
- [How to Handle Secrets on the Command Line — smallstep.com](https://smallstep.com/blog/command-line-secrets/) — CLI documentation antipatterns: secrets in flags, ps visibility (MEDIUM confidence)
- [New Users' Experiences with Secret Management Tools — arxiv.org 2025](https://arxiv.org/abs/2509.09036) — user confusion from poor CLI documentation; flags without explanation (MEDIUM confidence)
- [Codebase CONCERNS.md — sss repo](../codebase/CONCERNS.md) — keyring silent fallback (src/keystore.rs 73-81), existing fragile areas relevant to Emacs integration (HIGH confidence — direct codebase analysis)

---
*Pitfalls research for: Emacs sss-mode transparent encryption + CLI documentation*
*Researched: 2026-02-21*
