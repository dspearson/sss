# Feature Research

**Domain:** Emacs encryption/secrets major mode + CLI tool documentation
**Researched:** 2026-02-21
**Confidence:** MEDIUM (Emacs mode conventions: HIGH from official docs; encryption mode feature patterns: MEDIUM from multiple ecosystem examples; documentation table stakes: MEDIUM from community consensus)

---

## Feature Landscape

This milestone has two parallel, independent tracks: (1) an Emacs major mode for transparent sss-encrypted file editing, and (2) user-facing documentation. Features are catalogued for each track separately.

---

## Track 1: Emacs Major Mode (sss-mode)

### Table Stakes (Users Expect These)

Features that every Emacs encryption mode provides. Missing any of these makes the mode feel half-finished.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Auto-detect sealed files on open | EPA, age.el, sops-mode all do this. Users expect a sealed file just opens. | LOW | Detect via sss marker bytes (⊠{) at buffer load time. Use `magic-mode-alist` or `find-file-hook`. |
| Auto-decrypt to plaintext on open | After detection, the buffer must display cleartext — the whole point of the mode. | LOW | Shell out to `sss render` or `sss open`. Display result in buffer, not the raw sealed content. |
| Auto-re-seal on save | Save must write sealed content back to disk. No user action. | MEDIUM | `before-save-hook` or `write-file-functions`. Pipe buffer through `sss seal`. |
| Disable auto-save for the buffer | EPA does this by default; every encryption mode must. Auto-save writes plaintext to disk. | LOW | `(auto-save-mode -1)` and `(setq-local backup-inhibited t)` in mode setup. Security-critical. |
| Named keymap with prefix | All major modes define `sss-mode-map` with a `C-c` prefix. Without this users have no discoverable commands. | LOW | Standard Emacs convention. |
| Modeline indicator | Users need to know the file is being managed by sss-mode. Shows sealed/unsealed state. | LOW | Set `mode-name` in the major mode definition. Consider showing lock state. |
| Error feedback in minibuffer/buffer | When decryption fails (missing key, corrupt file), user must see a clear message — not a raw Lisp backtrace. | MEDIUM | Wrap all subprocess calls with error handling. Display output in `*sss-mode*` buffer on failure. |
| `provide` / `require` / autoload compliance | Required for any distributable Emacs package. Without it the package can't be loaded or installed correctly. | LOW | Standard elisp package conventions. Lexical binding required for modern Emacs. |
| Customization group | Users configure via `M-x customize-group RET sss RET`. Expected by experienced users. | LOW | `defgroup sss ...` with `defcustom` for all user-facing variables. |
| Configurable sss executable path | Users may have sss installed in a non-standard location. | LOW | `(defcustom sss-executable "sss" ...)`. |

### Differentiators (Competitive Advantage)

Features that go beyond what EPA/age.el/sops-mode provide. These are where sss-mode can shine given sss's unique semantics.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Marker-aware display (syntax highlighting) | sss files have plaintext sections and sealed sections interleaved (⊕{} and ⊠{} markers). Highlighting them visually distinguishes encrypted vs plaintext regions at a glance — no other mode does this because GPG/age are whole-file. | MEDIUM | `font-lock-defaults`. Highlight ⊕{}, ⊠{}, marker delimiters in distinct faces. Requires understanding marker format. |
| Selective seal/unseal commands | Because sss operates on markers (not whole files), users can unseal the full file or work with `sss open` (preserve markers) vs `sss render` (strip markers). Two distinct commands lets users choose. | MEDIUM | `sss-open-buffer` (marker-preserving) vs `sss-render-buffer` (plaintext). Maps to existing CLI. |
| Project operation commands | `M-x sss-init`, `M-x sss-process`, `M-x sss-keygen` etc. sss is project-aware via .sss.toml — surface this in Emacs. No comparable mode does project operations. | MEDIUM | Each command shells out to corresponding `sss` subcommand. Use `project.el` or `vc-root` to find project root. |
| Sealed file indicator in modeline | Show a lock icon or [SEALED]/[OPEN] state so users always know what's on disk vs what's in the buffer. EPA doesn't show this. | LOW | Extend `mode-name` dynamically: `"SSS[sealed]"` vs `"SSS[open]"`. Set buffer-local variable tracking state. |
| Audit log command | `M-x sss-audit` to run `sss audit` and show results in a read-only buffer. Useful for security-conscious users. | LOW | Trivial wrapper. High value: surfaces a unique sss capability from inside Emacs. |
| Keystore management commands | `M-x sss-keys-list`, `M-x sss-keys-rotate` etc. Reduce need to drop to terminal for key ops. | MEDIUM | Shell out to `sss keys` subcommands. Output in dedicated buffer. |

### Anti-Features (Things to Deliberately NOT Build)

| Anti-Feature | Why Requested | Why Problematic | Alternative |
|--------------|---------------|-----------------|-------------|
| Interactive passphrase prompts | Users imagine they want to enter passphrases in Emacs minibuffer for "security theater" feeling. | sss uses keystore auto-auth. Adding passphrase prompts contradicts the design, adds complexity, and creates friction. PROJECT.md explicitly forbids this. | Rely on keystore. If keystore fails, error clearly: "No key in keystore. Run `sss keys` to set up authentication." |
| FUSE mount/unmount from Emacs | Seems useful — manage the whole filesystem from Emacs. | FUSE management is stateful, platform-specific (Linux/macOS only), adds daemon lifecycle complexity. Out of scope per PROJECT.md. | Document how to use `sss mount` from terminal. sss-mode handles the edit workflow; FUSE is for directory-level access. |
| Async/background decryption | Users might request non-blocking decryption for large files. | For v1, async adds significant complexity (process sentinels, buffer management, race conditions). PROJECT.md says keep synchronous. | Synchronous shell-out is fast enough for secrets files (small by nature). |
| Auto-revert encrypted files | Automatically re-reading sealed content from disk when it changes externally. | Creates a loop: external seal → Emacs reads sealed bytes → tries to decrypt already-decrypted buffer state. Logic is fragile. | Document: close and reopen the file if external changes occur. |
| MELPA packaging in this milestone | Users will ask for it immediately. | Requires a separate MELPA PR, recipe, maintainer approval — entirely outside the repo. Out of scope per PROJECT.md. | Bundle in `emacs/` directory. Document manual installation and `straight.el` / `use-package` loading from local path. |
| Org-mode integration (org-crypt style) | Power users want to encrypt individual Org headings. | Org-crypt has its own marker system that conflicts with sss markers. Integration is a research project, not v1 work. | Out of scope. Document that whole org files can be sealed at the file level. |

---

## Track 2: CLI Documentation

### Table Stakes (Users Expect These)

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Installation section | Every CLI tool starts here. Without it, users leave immediately. | LOW | Cover: Cargo install, pre-built binaries, RPM/DEB packages. Include one-liner for each path. |
| Quickstart / getting-started guide | Users need to succeed in 5 minutes or they disengage. Walkthrough: init → seal → open → edit. | LOW | Tutorial-style, copy-paste commands, expected output shown. |
| Subcommand reference | `--help` output is not enough for complex CLIs. Users expect a doc page per subcommand. | MEDIUM | Cover all 11 subcommands (init, keys, seal, open, render, edit, process, mount, serve9p, audit, settings). |
| Common workflows / recipes | "How do I...?" is the most-asked question type. Users need worked examples. | LOW | Seal a file, rotate keys, add a team member, use with git, use the FUSE mount. |
| Configuration reference | .sss.toml and ~/.config/sss/settings.toml have fields users need to know about. | MEDIUM | Document every key with type, default, and effect. |
| Security model explanation | For a secrets tool, users need to trust it. Explain what is encrypted, with what algorithm, and what the threat model is. | MEDIUM | Cover: XChaCha20-Poly1305, Argon2id KDF, what's stored where, what is NOT protected (e.g., plaintext temp files during edit). |
| README overhaul | The GitHub README is the front door. If it's stale, users assume the project is dead. | LOW | Install, quickstart, links to full docs. |
| Marker format documentation | Users need to know what ⊕{} and ⊠{} mean to understand why their files look the way they do. | LOW | Single reference page. Explain open marker, sealed marker, rendering behavior. |

### Differentiators (Competitive Advantage)

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Architecture guide for contributors | sss has a non-trivial internal design (marker inference, 8-step algorithm, FUSE/9P). Contributors need this to onboard. Rare for CLI tools to document this well. | MEDIUM | Target: contributor who has read the code once and is confused. Cover: marker inference algorithm, processor pipeline, key loading flow. |
| Threat model and what-is-not-protected section | Most secrets tools don't document their threat model clearly. Doing so builds trust and sets correct expectations. | LOW | What sss protects against (file at rest, repo access). What it doesn't (compromised machine, temp files during edit, markers leaking field names). |
| Ignore patterns guide | The .gitignore-style ignore system is non-obvious. A dedicated doc prevents support questions. | LOW | Exists as IGNORE_PATTERNS.md in docs/ already — needs surfacing/linking from main docs. |
| Multi-user / team workflows | Shamir's Secret Sharing and multi-user key enrollment are unique features. Document the team onboarding workflow explicitly. | MEDIUM | Cover: `sss users add`, key rotation with multiple users, what happens when a user leaves. |
| Platform-specific notes | FUSE on Linux vs macOS, 9P for Windows, RPM/DEB packaging. Cross-platform notes are rare and valued. | LOW | Short notes per platform. Flag Linux FUSE kernel module requirement. |

### Anti-Features (Things to Deliberately NOT Build)

| Anti-Feature | Why Requested | Why Problematic | Alternative |
|--------------|---------------|-----------------|-------------|
| Man pages | Man pages are traditional for CLI tools, users will ask. | Lower priority than tutorial docs for this milestone. Requires separate build tooling and packaging integration. Out of scope per PROJECT.md. | `--help` output and web docs cover v1. Add man pages in a subsequent milestone. |
| API / library documentation | If sss is a Rust crate, some users will want Rustdoc. | sss is a CLI tool, not a library crate. The processor internals are not a stable API. | Architecture guide covers the concepts. Rustdoc is auto-generated and already available via `cargo doc`. |
| Video tutorials | Modern documentation sometimes includes screencasts. | High production cost, go stale quickly, no-code maintainability. | Animated terminal demos (asciinema) if warranted, but not in scope for this milestone. |
| Translated documentation | Some projects translate docs to multiple languages. | Maintenance burden far exceeds v1 value. | English only for v1. |

---

## Feature Dependencies

```
[Auto-detect sealed files]
    └──requires──> [Magic byte / marker detection logic]
                       └──requires──> [sss executable configured and on PATH]

[Auto-decrypt on open]
    └──requires──> [Auto-detect sealed files]
    └──requires──> [sss executable configured]
    └──requires──> [Keystore authentication (via sss CLI)]

[Auto-re-seal on save]
    └──requires──> [Auto-decrypt on open] (must know file is managed by mode)
    └──requires──> [Disable auto-save] (security precondition)
    └──requires──> [sss executable configured]

[Selective seal/unseal commands]
    └──requires──> [Auto-decrypt on open] (basic open/seal flow must work first)

[Marker syntax highlighting]
    └──enhances──> [Auto-detect sealed files] (only useful when mode is active)
    └──requires──> [Understanding of marker format ⊕{} ⊠{}]

[Project operation commands]
    └──requires──> [sss executable configured]
    └──enhances──> [CLI documentation] (commands need to be documented)

[Audit log command]
    └──requires──> [sss executable configured]
    └──requires──> [Project operation commands] (same infrastructure)

[CLI documentation: quickstart]
    └──requires──> [CLI documentation: installation] (user needs sss installed first)

[CLI documentation: subcommand reference]
    └──requires──> [CLI documentation: quickstart] (reader needs orientation first)

[CLI documentation: architecture guide]
    └──requires──> [CLI documentation: subcommand reference] (readers need CLI fluency first)

[Disable auto-save] ──conflicts──> [auto-save-mode] (must be disabled for security)

[Marker-aware display] ──conflicts with──> [render-based display] (if rendering strips markers,
    there is nothing to highlight; display mode choice determines highlighting feasibility)
```

### Dependency Notes

- **Auto-re-seal requires auto-save disabled**: If auto-save fires before the `before-save-hook`, it writes plaintext to `#filename#`. Auto-save must be disabled at buffer load time, before decryption, not after.
- **Render vs open display mode**: sss-mode must decide whether to display `sss render` output (no markers, pure plaintext) or `sss open` output (plaintext markers ⊕{} visible). Render output is simpler UX but makes marker highlighting impossible. Open output preserves markers and enables highlighting, but users see marker syntax. Recommendation: render output for the default display; provide `sss-open-buffer` as an explicit command for marker-visible mode.
- **Project commands depend on .sss.toml discovery**: `sss-init`, `sss-process` etc. need to know the project root. Tie this to `vc-root-dir` or `locate-dominating-file` for .sss.toml. This is shared infrastructure across all project commands.

---

## MVP Definition

### Launch With (v1 — sss-mode)

Minimum viable Emacs mode. Everything here must work before shipping.

- [ ] Auto-detect sealed files via magic bytes (⊠{ marker) in `find-file-hook`
- [ ] Auto-decrypt to plaintext on open via `sss render` — buffer shows cleartext
- [ ] Auto-re-seal on save via `before-save-hook` — file on disk stays encrypted
- [ ] Disable auto-save and backup for the buffer (security non-negotiable)
- [ ] Error display in `*sss-errors*` buffer on subprocess failure
- [ ] Named keymap `sss-mode-map` with documented prefix `C-c s`
- [ ] Modeline indicator showing mode is active
- [ ] `defcustom sss-executable` for configurable binary path
- [ ] `defgroup sss` customization group
- [ ] `provide 'sss-mode`, lexical binding, proper `;;;###autoload` comments
- [ ] Installation instructions in README (manual `load-file` + `use-package` from local path)

### Launch With (v1 — documentation)

- [ ] README overhaul: installation, 60-second quickstart, links to full docs
- [ ] Usage guide: tutorial walkthrough (init → seal → open → edit → team workflow)
- [ ] Subcommand reference: one section per subcommand with options and examples
- [ ] Security model page: what is protected, what is not, memory/disk guarantees
- [ ] Marker format reference: what ⊕{} and ⊠{} mean, how rendering works

### Add After Validation (v1.x)

- [ ] Marker syntax highlighting (font-lock) — add after basic mode is stable
- [ ] `sss-open-buffer` / `sss-render-buffer` explicit commands — after default flow is trusted
- [ ] Project operation commands (init, process, keygen) — after edit flow works
- [ ] Audit log command — low effort, add when project commands exist
- [ ] Architecture documentation for contributors — after user docs are complete

### Future Consideration (v2+)

- [ ] MELPA packaging — separate milestone, requires external MELPA PR
- [ ] Man pages — separate milestone, requires packaging integration
- [ ] Org-mode integration — research project, not v1 work
- [ ] Keystore management commands — after project commands exist and are stable
- [ ] Translated documentation — only if community demand exists

---

## Feature Prioritization Matrix

### sss-mode

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Auto-detect + auto-decrypt on open | HIGH | LOW | P1 |
| Auto-re-seal on save | HIGH | MEDIUM | P1 |
| Disable auto-save (security) | HIGH | LOW | P1 |
| Error feedback | HIGH | MEDIUM | P1 |
| Named keymap + modeline | MEDIUM | LOW | P1 |
| `defcustom`/`defgroup` customization | MEDIUM | LOW | P1 |
| Marker syntax highlighting | MEDIUM | MEDIUM | P2 |
| Selective open vs render commands | MEDIUM | MEDIUM | P2 |
| Project operation commands | MEDIUM | MEDIUM | P2 |
| Audit log command | LOW | LOW | P2 |
| Keystore management commands | LOW | MEDIUM | P3 |

### Documentation

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| README overhaul | HIGH | LOW | P1 |
| Quickstart / usage guide | HIGH | LOW | P1 |
| Security model | HIGH | MEDIUM | P1 |
| Marker format reference | HIGH | LOW | P1 |
| Subcommand reference | MEDIUM | MEDIUM | P1 |
| Common workflows / recipes | MEDIUM | LOW | P1 |
| Configuration reference | MEDIUM | MEDIUM | P2 |
| Architecture guide for contributors | LOW | MEDIUM | P2 |
| Multi-user / team workflows | MEDIUM | LOW | P2 |
| Threat model section | MEDIUM | LOW | P2 |
| Man pages | LOW | HIGH | P3 |

---

## Competitor Feature Analysis

| Feature | EPA (epa-file) | age.el (anticomputer) | sops-mode (djgoku) | sss-mode (ours) |
|---------|---------------|----------------------|-------------------|-----------------|
| Auto-detect encrypted files | Yes (*.gpg extension) | Yes (*.age extension) | Yes (SOPS header detection) | Yes (⊠{ magic bytes in file body) |
| Auto-decrypt on open | Yes (transparent) | Yes (transparent) | Yes (on-demand via C-c C-d) | Yes (transparent, render mode) |
| Auto-re-seal on save | Yes (transparent) | Yes (transparent) | Yes (via sops-save-file) | Yes (transparent, before-save-hook) |
| Disable auto-save | Yes (default) | Partial | No (user must configure) | Yes (must be explicit) |
| Modeline indicator | Via mode name only | No | No | Yes (planned: [sealed]/[open]) |
| Marker-aware display/highlighting | N/A (whole-file encryption) | N/A (whole-file encryption) | N/A (whole-file) | Yes (unique: partial-file encryption) |
| Project/team commands | No | No | No | Yes (init, process, keygen, audit) |
| Keymap with prefix | Minimal | No | Yes (C-c prefix) | Yes (C-c s prefix) |
| Error feedback | Via minibuffer | Minimal | Partial | Dedicated *sss-errors* buffer |
| TRAMP support | Yes | Partial | No | No (v1 out of scope) |
| MELPA distributed | Yes (built-in) | Yes | Yes | No (bundled in repo) |

---

## Sources

- [EasyPG Assistant User's Manual](https://www.gnu.org/software/emacs/manual/html_mono/epa.html) — HIGH confidence, official GNU docs
- [age.el GitHub (anticomputer)](https://github.com/anticomputer/age.el) — HIGH confidence, primary source
- [age-mode on Codeberg (sochotnicky)](https://codeberg.org/sochotnicky/age-mode) — MEDIUM confidence, deprecated but informative on failure modes
- [sops-mode GitHub (djgoku)](https://github.com/djgoku/sops) — HIGH confidence, primary source
- [EmacsConf 2024: Committing secrets with sops-mode](https://emacsconf.org/2024/talks/secrets/) — MEDIUM confidence, author's own talk
- [Major Mode Conventions — GNU Emacs Lisp Reference Manual](https://www.gnu.org/software/emacs/manual/html_node/elisp/Major-Mode-Conventions.html) — HIGH confidence, official spec
- [Editing encrypted files in Emacs (akuszyk, 2024)](https://akuszyk.com/2024-08-29-editing-encrypted-files-in-emacs.html) — MEDIUM confidence, practitioner experience
- [Keeping Secrets in Emacs — Mastering Emacs](https://www.masteringemacs.org/article/keeping-secrets-in-emacs-gnupg-auth-sources) — MEDIUM confidence, community expert
- [Make a README](https://www.makeareadme.com/) — MEDIUM confidence, community consensus on documentation structure
- [Rust CLI book — Rendering docs](https://rust-cli.github.io/book/in-depth/docs.html) — MEDIUM confidence, official Rust CLI guidance

---

*Feature research for: Emacs integration and documentation for sss (Shamir's Secret Sharing CLI)*
*Researched: 2026-02-21*
