# Roadmap: SSS — Documentation & Emacs Integration

## Overview

This milestone adds two deliverables on top of the existing sss binary: an Emacs major mode (sss-mode) that provides transparent decrypt-on-open and re-seal-on-save for sealed files, and user-facing documentation. The CLI foundation must be confirmed first because the Emacs mode shells out to it. Once that gate clears, the Emacs core is built from primitives up (detection and CLI helper, then open/save flows, then mode assembly and project commands). Documentation runs as the final phase, after the CLI interface is stable.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: CLI Foundation** - Verify and extend sss CLI flags needed by the Emacs mode
- [ ] **Phase 2: sss-mode Core** - Detection predicate, CLI helper, open flow, save flow
- [ ] **Phase 3: sss-mode Complete** - UX polish, project commands, packaging structure
- [ ] **Phase 4: Documentation** - README overhaul, usage guide, architecture, security, reference docs

## Phase Details

### Phase 1: CLI Foundation
**Goal**: The sss CLI supports the exact interface that sss-mode requires, with stable exit codes and clean stderr
**Depends on**: Nothing (first phase)
**Requirements**: CLI-01, CLI-02
**Success Criteria** (what must be TRUE):
  1. `sss render FILE` writes decrypted plaintext to stdout and exits 0; exits non-zero with a stderr message when keystore auth fails
  2. `sss seal --in-place FILE` re-encrypts the named file in place and exits 0; exits non-zero with a stderr message on failure
  3. The exact byte sequence for the sealed-file marker (`⊠{`) is confirmed from `src/constants.rs` and matches what a real sealed file produces
**Plans**: TBD

### Phase 2: sss-mode Core
**Goal**: Opening a sealed file in Emacs transparently decrypts it; saving re-seals it on disk; failures are always visible
**Depends on**: Phase 1
**Requirements**: EMAC-01, EMAC-02, EMAC-03, EMAC-04, EMAC-05, EMAC-06, EMAC-07, EMAC-08, EMAC-09
**Success Criteria** (what must be TRUE):
  1. Opening a sealed `.sss`-marked file in Emacs shows readable plaintext (markers visible per EMAC-09); the file on disk remains sealed
  2. Saving the buffer re-seals the file on disk; the plaintext is never written as-is to disk
  3. When decryption or sealing fails, an error message appears in the minibuffer (not a silent empty buffer or silent no-op)
  4. Auto-save and backup files are disabled for the decrypted buffer immediately on open
  5. `M-x customize-group RET sss RET` shows the sss-executable path variable
**Plans**: TBD

### Phase 3: sss-mode Complete
**Goal**: sss-mode is visually polished, provides project operation commands, and is a correct single-file Emacs package
**Depends on**: Phase 2
**Requirements**: EMUX-01, EMUX-02, EMUX-03, PROJ-01, PROJ-02, PROJ-03, PROJ-04, PACK-01, PACK-02, PACK-03, PACK-04
**Success Criteria** (what must be TRUE):
  1. Sealed-marker (`⊠{}`) and open-marker (`⊕{}`) regions are visually distinct via font-lock; modeline shows `[SSS:open]` or `[SSS:sealed]`
  2. `M-x sss-render-buffer` displays the file content with all markers stripped (pure plaintext view)
  3. `M-x sss-init`, `M-x sss-process`, `M-x sss-keygen`, and `M-x sss-keys-list` each run the corresponding sss subcommand and display output
  4. `emacs/sss-mode.el` byte-compiles without warnings, passes package-lint and checkdoc, requires no external MELPA packages
**Plans**: TBD

### Phase 4: Documentation
**Goal**: A new user can install sss, understand the security model, and complete common workflows using the documentation alone
**Depends on**: Phase 1 (stable CLI interface required for accuracy)
**Requirements**: DOC-01, DOC-02, DOC-03, DOC-04, DOC-05, DOC-06, DOC-07
**Success Criteria** (what must be TRUE):
  1. README contains a working quickstart (install via cargo, seal a file, open it, edit it) that a new user can follow without consulting source code
  2. The usage guide covers the complete edit workflow: init → seal → open → edit → re-seal, plus key management and team collaboration
  3. The security model document states explicitly what is encrypted, what is not, and which algorithms are used
  4. The marker format reference describes `⊕{}` and `⊠{}` semantics and rendering behaviour accurately enough to implement a compatible parser
  5. The sss-mode installation guide covers Emacs setup, keyring prerequisites, and daemon-mode PATH configuration
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. CLI Foundation | 0/? | Not started | - |
| 2. sss-mode Core | 0/? | Not started | - |
| 3. sss-mode Complete | 0/? | Not started | - |
| 4. Documentation | 0/? | Not started | - |
