# SSS — Emacs Integration Consolidation

## What This Is

SSS is a Rust CLI tool for encrypting secrets in-place using Shamir's Secret Sharing, with transparent filesystem access via FUSE/9P. v1.0 delivered documentation and a minimal Emacs mode. v1.1 consolidates two existing Emacs implementations into a single, feature-complete package: the correct save/open patterns from `emacs/sss-mode.el` merged with the rich feature set from `plugins/emacs/` (evil operators, Doom integration, region encrypt/decrypt, fancy overlays, auth-source integration).

## Current Milestone: v1.1 Emacs Integration Consolidation

**Goal:** Unify the two Emacs implementations into a single package that has both correct security patterns and full feature coverage.

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

- [ ] Merge plugins/emacs/ feature set into emacs/sss-mode.el with correct save/open patterns
- [ ] Evil operator integration (encrypt/decrypt/toggle as evil motions)
- [ ] Doom Emacs integration (leader bindings, localleader, which-key descriptions)
- [ ] Region-based encrypt/decrypt (not just whole-file operations)
- [ ] Toggle encryption at point
- [ ] Fancy overlay mode (visual inline decrypt previews)
- [ ] Auth-source integration for password caching
- [ ] Preview secret at point without full file decrypt
- [ ] UI components (transient menu, progress reporting)
- [ ] Remove plugins/emacs/ directory after consolidation
- [ ] Update Doom config and documentation to point at unified package

### Out of Scope

- Man pages — useful but lower priority than tutorial docs
- MELPA packaging — bundle in-repo first, MELPA later
- Mount/unmount from Emacs — FUSE management adds complexity, not core to edit workflow
- Emacs async/background operations — keep it synchronous; secrets files are small
- GUI/web interface — CLI and Emacs only
- Selective seal/unseal of individual marker regions — v2 enhancement
- MELPA packaging — revisit after consolidation is stable

## Context

Two Emacs implementations exist that must be consolidated:

- **emacs/sss-mode.el** (354 lines, v1.0): Correct patterns — `write-contents-functions` save flow, `magic-mode-alist` detection, auto-save/backup disable, `(error ...)` on seal failure. But limited to whole-file operations only, no evil integration, no Doom bindings.
- **plugins/emacs/** (7 files, ~97k, pre-v1.0): Feature-rich — evil operators, Doom leader/localleader bindings, region encrypt/decrypt, toggle-at-point, fancy overlay mode, auth-source password caching, preview-secret-at-point, transient UI menus, project detection. But uses different save/open patterns that may have the security issues research identified (before-save-hook, no auto-save disable).

The consolidation strategy: take `emacs/sss-mode.el` as the foundation (correct security patterns), port features from `plugins/emacs/` into it, then remove `plugins/emacs/`.

Additionally shipped in v1.0:
- **docs/** (6 files, 2,086 lines): Usage guide, security model, marker format, architecture, config ref, sss-mode guide.
- **README.md** (272 lines): Overhauled with correct crypto claims.
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

| Consolidate into single package | Two implementations is tech debt; one correct + feature-rich package | — Pending |
| emacs/sss-mode.el as foundation | Has the correct security patterns (write-contents-functions, error-on-fail) | — Pending |
| Port features from plugins/emacs/ | Don't rewrite what exists — adapt and integrate | — Pending |

---
*Last updated: 2026-02-21 after v1.1 milestone start*
