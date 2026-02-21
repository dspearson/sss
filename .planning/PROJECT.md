# SSS — Documentation & Emacs Integration

## What This Is

SSS is a Rust CLI tool for encrypting secrets in-place using Shamir's Secret Sharing, with transparent filesystem access via FUSE/9P. This milestone adds user-facing documentation and an Emacs major mode that enables transparent edit-on-open/seal-on-save workflows and project management from within Emacs.

## Core Value

Secrets management should be invisible — open a sealed file, edit it, save it, and it's sealed again. The Emacs integration makes this native to the editor, and the documentation makes it accessible to new users.

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

### Active

- [ ] Usage guide — tutorial-style walkthrough of common workflows
- [ ] README overhaul — installation, quickstart, examples
- [ ] Architecture documentation — how sss works internally, for contributors
- [ ] Emacs major mode (sss-mode) — transparent sealed file editing
- [ ] Emacs auto-decrypt on open — detect sealed files via existing markers, decrypt using keystore
- [ ] Emacs re-seal on save — automatically re-encrypt on buffer save
- [ ] Emacs project commands — init, process, keygen, keystore operations from Emacs
- [ ] Emacs package bundled in repo — ship under emacs/ directory

### Out of Scope

- Man pages — useful but lower priority than tutorial docs for this milestone
- MELPA packaging — bundle in-repo first, MELPA later
- Mount/unmount from Emacs — FUSE management adds complexity, not core to edit workflow
- Emacs async/background operations — keep it synchronous for v1
- GUI/web interface — CLI and Emacs only

## Context

- SSS already has a well-defined marker system for identifying encrypted content — the Emacs mode will detect these markers via magic bytes to trigger auto-decrypt
- The keystore auto-authentication means no passphrase prompts during editing — seamless UX
- Existing `processor/core.rs` handles the encrypt/decrypt pipeline that the Emacs mode will shell out to
- The codebase has extensive tests (30+ test files) but no user-facing documentation
- Documentation and Emacs work are independent tracks that can progress in parallel

## Constraints

- **Language**: Emacs Lisp for the Emacs package, Rust for any CLI changes needed to support it
- **Auth model**: Keystore auto-authentication only — no interactive passphrase prompts in Emacs mode
- **Detection**: Use existing SSS markers/magic bytes for sealed file recognition — no new extensions
- **Bundling**: Ship Emacs package in-repo under emacs/ directory

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keystore auto-auth for Emacs | Seamless editing UX — no prompts breaking flow | — Pending |
| Magic bytes for file detection | Reuse existing marker system rather than inventing new extensions | — Pending |
| Bundle in-repo (emacs/) | Simplest distribution, ships with sss itself | — Pending |
| Parallel docs + Emacs work | Independent tracks, no blocking dependencies | — Pending |
| No FUSE management from Emacs | Reduces scope, edit workflow doesn't need mount/unmount | — Pending |

---
*Last updated: 2026-02-21 after initialization*
