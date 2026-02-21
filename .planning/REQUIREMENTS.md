# Requirements: SSS — Emacs Integration Consolidation

**Defined:** 2026-02-21
**Core Value:** Secrets management should be invisible -- open, edit, save, sealed.

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

## v1.1 Requirements

Requirements for the Emacs Integration Consolidation milestone. Merges `plugins/emacs/` feature set into `emacs/sss-mode.el` with correct security patterns.

### Core Operations

- [x] **CORE-01**: Region encrypt -- encrypt selected region in-place, wrapping in sealed marker
- [x] **CORE-02**: Region decrypt -- decrypt selected sealed region in-place to plaintext marker
- [x] **CORE-03**: Toggle at point -- detect marker type at point and toggle encrypt/decrypt
- [x] **CORE-04**: Fix deprecated keygen -- update `sss-keygen` to call `sss keys generate` instead of `sss keygen`

### Evil Integration

- [ ] **EVIL-01**: Evil encrypt operator -- `sss-evil-encrypt` motion-based operator for encrypting text objects
- [ ] **EVIL-02**: Evil decrypt operator -- `sss-evil-decrypt` motion-based operator for decrypting text objects
- [ ] **EVIL-03**: Evil toggle operator -- `sss-evil-toggle` motion-based operator for toggling encryption

### Doom Integration

- [ ] **DOOM-01**: Leader bindings -- `SPC e` prefix with encrypt/decrypt/toggle/process commands via `map!`
- [ ] **DOOM-02**: Localleader bindings -- `, e` prefix for buffer-local sss operations via `map!`
- [ ] **DOOM-03**: Conditional loading -- Doom integration loads only when `(modulep! :editor evil)` is available

### UX Enhancements

- [x] **UX-01**: Fancy overlay mode -- inline decrypt previews using overlays on sealed markers
- [x] **UX-02**: Preview secret at point -- show decrypted value of marker at point without modifying buffer
- [x] **UX-03**: Auth-source integration -- password caching via Emacs auth-source for keystore passphrase
- [x] **UX-04**: Transient menu -- `sss-dispatch` (or equivalent) for discoverability of all commands

### Cleanup

- [ ] **CLEAN-01**: Remove `plugins/emacs/` directory after all features are ported
- [ ] **CLEAN-02**: Update `docs/sss-mode-guide.md` to document new features (evil, doom, overlays, region ops)
- [ ] **CLEAN-03**: Update README.md Emacs section to reflect consolidated package

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
| CORE-01 | Phase 5 | Complete |
| CORE-02 | Phase 5 | Complete |
| CORE-03 | Phase 5 | Complete |
| CORE-04 | Phase 5 | Complete |
| UX-01 | Phase 5 | Complete |
| UX-02 | Phase 5 | Complete |
| UX-03 | Phase 5 | Complete |
| UX-04 | Phase 5 | Complete |
| EVIL-01 | Phase 6 | Pending |
| EVIL-02 | Phase 6 | Pending |
| EVIL-03 | Phase 6 | Pending |
| DOOM-01 | Phase 6 | Pending |
| DOOM-02 | Phase 6 | Pending |
| DOOM-03 | Phase 6 | Pending |
| CLEAN-01 | Phase 7 | Pending |
| CLEAN-02 | Phase 7 | Pending |
| CLEAN-03 | Phase 7 | Pending |

**v1.0 Coverage:**
- v1.0 requirements: 29 total
- Mapped to phases: 29
- Unmapped: 0

**v1.1 Coverage:**
- v1.1 requirements: 17 total
- Mapped to phases: 17
- Unmapped: 0

---
*Requirements defined: 2026-02-21*
*Last updated: 2026-02-21 -- v1.1 traceability updated after roadmap creation*
