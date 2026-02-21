# Requirements: SSS — Documentation & Emacs Integration

**Defined:** 2026-02-21
**Core Value:** Secrets management should be invisible — open, edit, save, sealed.

## v1 Requirements

Requirements for this milestone. Each maps to roadmap phases.

### CLI Foundation

- [x] **CLI-01**: `sss render` and `sss open` support stdout output for piping to Emacs
- [x] **CLI-02**: `sss seal --in-place` works for re-sealing an opened file after editing

### Emacs Core

- [x] **EMAC-01**: sss-mode detects sealed files via marker content scanning (⊠{ magic bytes) using `magic-mode-alist`
- [x] **EMAC-02**: sss-mode auto-decrypts sealed files on open using keystore auto-authentication via `sss open`
- [x] **EMAC-03**: sss-mode re-seals buffer content on save using `write-contents-functions` (not hooks)
- [x] **EMAC-04**: sss-mode disables auto-save and backup files for decrypted buffers
- [x] **EMAC-05**: sss-mode uses `call-process` with exit code checking and stderr capture for all CLI invocations
- [x] **EMAC-06**: sss-mode provides clear error messages in minibuffer when decryption/sealing fails
- [x] **EMAC-07**: sss-mode defines a customization group with `sss-executable` path variable
- [x] **EMAC-08**: sss-mode provides a named keymap with `C-c` prefix for commands
- [x] **EMAC-09**: sss-mode displays marker-visible plaintext (⊕{} markers shown, not stripped)

### Emacs UX

- [x] **EMUX-01**: sss-mode syntax-highlights ⊕{} (open) and ⊠{} (sealed) markers with distinct faces
- [x] **EMUX-02**: sss-mode shows [SEALED]/[OPEN] state indicator in modeline
- [x] **EMUX-03**: sss-mode provides `M-x sss-render-buffer` for pure plaintext view (markers stripped)

### Emacs Project Commands

- [x] **PROJ-01**: `M-x sss-init` runs `sss init` in the current project directory
- [x] **PROJ-02**: `M-x sss-process` runs `sss process` in the current project directory
- [x] **PROJ-03**: `M-x sss-keygen` runs `sss keygen` and displays output
- [x] **PROJ-04**: `M-x sss-keys-list` shows current keystore/project keys in a read-only buffer

### Emacs Packaging

- [x] **PACK-01**: sss-mode is a single .el file under `emacs/` directory in the repo
- [x] **PACK-02**: sss-mode uses `lexical-binding: t` and requires Emacs 27.1+
- [x] **PACK-03**: sss-mode has zero external Emacs package dependencies
- [x] **PACK-04**: sss-mode provides proper `provide`, `require`, and autoload cookies

### Documentation

- [x] **DOC-01**: README overhaul with installation (cargo, pre-built, RPM/DEB), quickstart, feature overview
- [x] **DOC-02**: Usage guide covering common workflows: seal, open, edit, process, key management, team collaboration
- [x] **DOC-03**: Architecture documentation explaining marker inference, processor pipeline, key loading, FUSE/9P
- [x] **DOC-04**: Security model documentation: what is encrypted, algorithms, threat model, what is NOT protected
- [x] **DOC-05**: Marker format reference: ⊕{} and ⊠{} semantics, rendering behaviour
- [x] **DOC-06**: Configuration reference for .sss.toml and settings.toml
- [x] **DOC-07**: sss-mode installation and usage guide (Emacs setup, keyring prerequisites)

## v2 Requirements

Deferred to future milestone. Tracked but not in current roadmap.

### Emacs Enhancements

- **EMAC-V2-01**: `M-x sss-audit` for viewing audit results in a buffer
- **EMAC-V2-02**: Selective seal/unseal of individual marker regions
- **EMAC-V2-03**: MELPA package submission
- **EMAC-V2-04**: Async/background decryption for large files

### Documentation Enhancements

- **DOC-V2-01**: Man page generation via `clap_mangen`
- **DOC-V2-02**: Auto-generated CLI reference via `clap-markdown`
- **DOC-V2-03**: mdBook documentation site with search

## Out of Scope

| Feature | Reason |
|---------|--------|
| Interactive passphrase prompts in Emacs | Contradicts keystore auto-auth design; adds friction |
| FUSE mount/unmount from Emacs | Stateful, platform-specific, not core to edit workflow |
| Auto-revert encrypted files | Creates decrypt/seal loop; fragile |
| Org-crypt integration | Marker system conflicts; research project, not v1 |
| Emacs async operations | Adds process sentinel complexity; secrets files are small |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLI-01 | Phase 1 | Complete |
| CLI-02 | Phase 1 | Complete |
| EMAC-01 | Phase 2 | Complete |
| EMAC-02 | Phase 2 | Complete |
| EMAC-03 | Phase 2 | Complete |
| EMAC-04 | Phase 2 | Complete |
| EMAC-05 | Phase 2 | Complete |
| EMAC-06 | Phase 2 | Complete |
| EMAC-07 | Phase 2 | Complete |
| EMAC-08 | Phase 2 | Complete |
| EMAC-09 | Phase 2 | Complete |
| EMUX-01 | Phase 3 | Complete |
| EMUX-02 | Phase 3 | Complete |
| EMUX-03 | Phase 3 | Complete |
| PROJ-01 | Phase 3 | Complete |
| PROJ-02 | Phase 3 | Complete |
| PROJ-03 | Phase 3 | Complete |
| PROJ-04 | Phase 3 | Complete |
| PACK-01 | Phase 3 | Complete |
| PACK-02 | Phase 3 | Complete |
| PACK-03 | Phase 3 | Complete |
| PACK-04 | Phase 3 | Complete |
| DOC-01 | Phase 4 | Complete |
| DOC-02 | Phase 4 | Complete |
| DOC-03 | Phase 4 | Complete |
| DOC-04 | Phase 4 | Complete |
| DOC-05 | Phase 4 | Complete |
| DOC-06 | Phase 4 | Complete |
| DOC-07 | Phase 4 | Complete |

**Coverage:**
- v1 requirements: 29 total
- Mapped to phases: 29
- Unmapped: 0 ✓

---
*Requirements defined: 2026-02-21*
*Last updated: 2026-02-21 — DOC-03, DOC-07 marked complete (Phase 4 Plan 03)*
