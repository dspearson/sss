# SSS — Secrets Management CLI + Emacs Integration

## What This Is

SSS is a Rust CLI tool for encrypting secrets in-place using Shamir's Secret Sharing, with transparent filesystem access via FUSE/9P. The Emacs integration (`emacs/sss-mode.el`, v1.1) provides a single-file package with transparent decrypt-on-open, re-seal-on-save, region operations, evil operators, Doom Emacs bindings, overlay previews, auth-source integration, and a transient command menu.

## Core Value

Secrets management should be invisible — open a sealed file, edit it, save it, and it's sealed again.

## Current State

Shipped v1.1 on 2026-02-23. Two milestones complete:
- **v1.0** (2026-02-21): CLI foundation, sss-mode.el core (354 lines), 6 documentation files, README overhaul
- **v1.1** (2026-02-23): Consolidated two Emacs implementations into one package (746 lines), removed legacy `plugins/emacs/`

Tech stack: Rust CLI, Emacs Lisp (single .el file), libsodium (XChaCha20-Poly1305, BLAKE2b, Argon2id).

## Requirements

### Validated

- ✓ CLI with subcommands: init, keys, seal, open, render, edit, process, mount, serve9p, audit, settings — existing
- ✓ Asymmetric encryption using libsodium (XChaCha20-Poly1305, BLAKE2b, Argon2id) — existing
- ✓ Marker inference system for preserving encryption markers during edits — existing
- ✓ FUSE filesystem for transparent decryption on Linux/macOS — existing
- ✓ 9P network filesystem protocol support — existing
- ✓ Project-based configuration with .sss.toml — existing
- ✓ Keystore/keyring integration for key management — existing
- ✓ Ignore patterns (.gitignore-style) for selective processing — existing
- ✓ Multi-user key sharing and project collaboration — existing
- ✓ Cross-platform builds (Linux, macOS, Windows) with RPM/DEB packaging — existing
- ✓ Usage guide covering complete edit workflow — v1.0
- ✓ README overhaul with quickstart and installation — v1.0
- ✓ Architecture documentation for contributors — v1.0
- ✓ Emacs major mode (sss-mode) transparent editing — v1.0
- ✓ Emacs auto-decrypt on open via magic-mode-alist — v1.0
- ✓ Emacs re-seal on save via write-contents-functions — v1.0
- ✓ Emacs project commands (init, process, keygen, keys-list, render-buffer) — v1.0
- ✓ Emacs package bundled in repo under emacs/ — v1.0
- ✓ Region encrypt/decrypt in-place — v1.1
- ✓ Toggle encryption at point — v1.1
- ✓ Evil operators (ge/gd/gt) and text objects (is/as) — v1.1
- ✓ Doom leader (SPC e) and localleader (, e) bindings — v1.1
- ✓ Auth-source passphrase caching — v1.1
- ✓ Overlay mode for inline visual previews — v1.1
- ✓ Preview secret at point — v1.1
- ✓ Transient dispatch menu with completing-read fallback — v1.1
- ✓ Consolidated single-file Emacs package (plugins/emacs/ removed) — v1.1
- ✓ Updated documentation (sss-mode-guide 17 sections, README v1.1) — v1.1

### Active

(None — next milestone not yet defined)

### Out of Scope

- Man pages — useful but lower priority than tutorial docs
- MELPA packaging — bundle in-repo first, MELPA later
- Mount/unmount from Emacs — FUSE management adds complexity, not core to edit workflow
- Emacs async/background operations — keep it synchronous; secrets files are small
- GUI/web interface — CLI and Emacs only
- Org-crypt integration — marker system conflicts; research project

## Constraints

- **Language**: Emacs Lisp for the Emacs package, Rust for any CLI changes
- **Auth model**: Keystore auto-authentication only — no interactive passphrase prompts
- **Detection**: Use existing SSS markers/magic bytes for sealed file recognition
- **Bundling**: Ship Emacs package in-repo under emacs/ directory

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keystore auto-auth for Emacs | Seamless editing UX — no prompts breaking flow | ✓ Good |
| Magic bytes for file detection | Reuse existing marker system (magic-mode-alist with named predicate) | ✓ Good |
| Bundle in-repo (emacs/) | Simplest distribution, ships with sss itself | ✓ Good |
| write-contents-functions for save | Correct Emacs pattern — before-save-hook ruled out (EPA bug#63293) | ✓ Good |
| (error ...) on seal failure | Prevents nil return falling through to plaintext disk write | ✓ Good |
| C-c C-x key pattern | Package-lint compliance (C-c + letter reserved for users) | ✓ Good |
| XChaCha20 + Argon2id in docs | Corrected from inaccurate age/scrypt claims in old README | ✓ Good |
| Consolidate into single package | Two implementations was tech debt; one correct + feature-rich package | ✓ Good |
| emacs/sss-mode.el as foundation | Has the correct security patterns (write-contents-functions, error-on-fail) | ✓ Good |
| Port features from plugins/emacs/ | Don't rewrite what exists — adapt and integrate | ✓ Good |
| Buffer-local evil bindings | evil-define-key 'normal sss-mode-map preserves ge/gd/gt in non-sss buffers | ✓ Good |
| with-eval-after-load 'evil | Works for all evil users, not just Doom; avoids modulep! dependency | ✓ Good |
| (eval '(map! ...)) for Doom | Prevents byte-compiler from expanding Doom macro syntax at compile time | ✓ Good |
| Auth-source opt-in with guard | (require 'auth-source nil t) — zero hard dependencies, graceful fallback | ✓ Good |
| Transient with completing-read fallback | Graceful degradation on Emacs 27.1 without transient package | ✓ Good |
| re-search-forward marker walk | Safe marker-to-marker jumping in evil toggle — avoids user-error on inter-marker text | ✓ Good |

---
*Last updated: 2026-02-23 after v1.1 milestone*
