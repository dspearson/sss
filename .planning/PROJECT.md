# SSS — Documentation & Emacs Integration

## What This Is

SSS is a Rust CLI tool for encrypting secrets in-place using Shamir's Secret Sharing, with transparent filesystem access via FUSE/9P. The v1.0 milestone delivered an Emacs major mode (sss-mode) for transparent decrypt-on-open and re-seal-on-save workflows, plus comprehensive user-facing documentation covering security model, architecture, and usage.

## Core Value

Secrets management should be invisible — open a sealed file, edit it, save it, and it's sealed again.

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
- ✓ Usage guide covering complete edit workflow — v1.0 (docs/usage-guide.md, 493 lines)
- ✓ README overhaul with quickstart and installation — v1.0 (272 lines, correct crypto claims)
- ✓ Architecture documentation for contributors — v1.0 (docs/architecture.md, 430 lines)
- ✓ Emacs major mode (sss-mode) transparent editing — v1.0 (emacs/sss-mode.el, 354 lines)
- ✓ Emacs auto-decrypt on open via magic-mode-alist — v1.0
- ✓ Emacs re-seal on save via write-contents-functions — v1.0
- ✓ Emacs project commands (init, process, keygen, keys-list, render-buffer) — v1.0
- ✓ Emacs package bundled in repo under emacs/ — v1.0

### Active

(None — next milestone requirements to be defined via `/gsd:new-milestone`)

### Out of Scope

- Man pages — useful but lower priority than tutorial docs
- MELPA packaging — bundle in-repo first, MELPA later
- Mount/unmount from Emacs — FUSE management adds complexity, not core to edit workflow
- Emacs async/background operations — keep it synchronous; secrets files are small
- GUI/web interface — CLI and Emacs only
- Selective seal/unseal of individual marker regions — v2 enhancement

## Context

Shipped v1.0 with 2,712 lines of new content across 8 files.

- **emacs/sss-mode.el** (354 lines): Full Emacs integration — detect sealed files via magic bytes, decrypt on open, re-seal on save, 7 key bindings, font-lock highlighting, modeline state indicator. Byte-compiles cleanly, passes package-lint and checkdoc.
- **docs/** (6 files, 2,086 lines): Usage guide, security model (XChaCha20-Poly1305, Argon2id, BLAKE2b), marker format with BNF grammar, architecture overview, configuration reference, sss-mode guide.
- **README.md** (272 lines): Overhauled with working quickstart, correct cryptographic claims, cross-links to all docs.
- **tests/e2e_cli_workflows.rs**: 3 new smoke tests added (74 total) verifying CLI interface for Emacs mode.
- Known issue: `sss keygen` deprecated in favour of `sss keys generate`; sss-mode still calls the deprecated form.

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
| Parallel docs + Emacs work | Independent tracks, no blocking dependencies | ✓ Good |
| No FUSE management from Emacs | Reduces scope, edit workflow doesn't need mount/unmount | ✓ Good |
| write-contents-functions for save | Correct Emacs pattern — before-save-hook ruled out (EPA bug#63293) | ✓ Good |
| magic-mode-alist named predicate | Multibyte-safe ⊠{ detection vs bare regexp | ✓ Good |
| sss open (not render) for buffer | Preserves ⊕{} markers per EMAC-09 requirement | ✓ Good |
| (error ...) on seal failure | Prevents nil return falling through to plaintext disk write | ✓ Good |
| sss-process maps to seal --project | No `sss process` subcommand exists in CLI | ✓ Good |
| C-c C-x key pattern | Package-lint compliance (C-c + letter reserved for users) | ✓ Good |
| Markdown docs not mdBook | Simpler for v1, mdBook deferred to v2 | ✓ Good |
| XChaCha20 + Argon2id in docs | Corrected from inaccurate age/scrypt claims in old README | ✓ Good |

---
*Last updated: 2026-02-21 after v1.0 milestone*
