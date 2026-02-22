# Roadmap: SSS — Documentation & Emacs Integration

## Milestones

- ✅ **v1.0 Documentation & Emacs Integration** — Phases 1-4 (shipped 2026-02-21)
- [ ] **v1.1 Emacs Integration Consolidation** — Phases 5-7

## Phases

<details>
<summary>v1.0 Documentation & Emacs Integration (Phases 1-4) — SHIPPED 2026-02-21</summary>

- [x] Phase 1: CLI Foundation (2/2 plans) — completed 2026-02-21
- [x] Phase 2: sss-mode Core (3/3 plans) — completed 2026-02-21
- [x] Phase 3: sss-mode Complete (2/2 plans) — completed 2026-02-21
- [x] Phase 4: Documentation (4/4 plans) — completed 2026-02-21

See: `.planning/milestones/v1.0-ROADMAP.md` for full phase details.

</details>

### v1.1 Emacs Integration Consolidation

- [x] **Phase 5: Core Operations & UX** - Region encrypt/decrypt, toggle-at-point, keygen fix, overlays, preview, auth-source, transient menu (completed 2026-02-21)
- [x] **Phase 6: Evil & Doom Integration** - Evil operators, Doom leader/localleader bindings, conditional loading (completed 2026-02-23)
- [ ] **Phase 7: Cleanup & Documentation** - Remove plugins/emacs/, update guides and README

## Phase Details

### Phase 5: Core Operations & UX
**Goal**: Users can encrypt and decrypt individual regions within a buffer, preview secrets inline, and discover all commands through a menu -- without leaving the v1.0 security model
**Depends on**: Phase 4 (v1.0 complete)
**Requirements**: CORE-01, CORE-02, CORE-03, CORE-04, UX-01, UX-02, UX-03, UX-04
**Success Criteria** (what must be TRUE):
  1. User can select a text region, run `M-x sss-encrypt-region`, and the selected text is replaced with a sealed marker in the buffer
  2. User can place point inside a sealed marker, run `M-x sss-decrypt-region`, and the marker is replaced with plaintext
  3. User can place point on any marker and run `M-x sss-toggle-at-point` to flip between encrypted and decrypted state
  4. `M-x sss-keygen` calls `sss keys generate` (not the deprecated `sss keygen`)
  5. User can enable overlay mode and see inline visual previews on sealed markers without modifying the buffer
  6. `M-x sss-dispatch` (or equivalent) opens a transient menu listing all available sss commands
**Plans:** 3/3 plans complete

Plans:
- [ ] 05-01-PLAN.md -- Region encrypt/decrypt, keygen fix, auth-source integration (Wave 1)
- [ ] 05-02-PLAN.md -- Toggle at point, overlay mode, preview at point (Wave 2)
- [ ] 05-03-PLAN.md -- Transient menu with completing-read fallback (Wave 3)

Wave structure:
- **Wave 1**: 05-01 (CORE-01 + CORE-02 + CORE-04 + UX-03)
- **Wave 2**: 05-02 (CORE-03 + UX-01 + UX-02) -- depends on 05-01
- **Wave 3**: 05-03 (UX-04) -- depends on 05-02

### Phase 6: Evil & Doom Integration
**Goal**: Evil users can encrypt/decrypt via motions and text objects; Doom users get idiomatic leader bindings -- with graceful degradation when evil or Doom are absent
**Depends on**: Phase 5 (evil operators call region encrypt/decrypt from Phase 5)
**Requirements**: EVIL-01, EVIL-02, EVIL-03, DOOM-01, DOOM-02, DOOM-03
**Success Criteria** (what must be TRUE):
  1. In evil normal state, `ge{motion}` encrypts the text covered by the motion; `gd{motion}` decrypts it; `gt{motion}` toggles it
  2. `SPC e` opens an encryption prefix with project/key/help commands; `, e` in sss-mode buffers provides buffer-local encrypt/decrypt/toggle
  3. Loading sss-mode in vanilla Emacs (no evil, no Doom) produces no errors or warnings -- evil and Doom features are conditionally defined
  4. Evil text objects `is` (inner sss pattern) and `as` (outer sss pattern) select pattern content and full pattern respectively
**Plans:** 2/2 plans complete

Plans:
- [x] 06-01-PLAN.md -- Evil operators, text objects, conditional loading scaffold (Wave 1) -- completed 2026-02-23
- [ ] 06-02-PLAN.md -- Doom leader and localleader bindings (Wave 2)

Wave structure:
- **Wave 1**: 06-01 (EVIL-01 + EVIL-02 + EVIL-03 + DOOM-03)
- **Wave 2**: 06-02 (DOOM-01 + DOOM-02) -- depends on 06-01

### Phase 7: Cleanup & Documentation
**Goal**: The `plugins/emacs/` directory is removed, documentation reflects the consolidated package, and the repo has a single authoritative Emacs integration
**Depends on**: Phase 6 (all features must be ported before removal)
**Requirements**: CLEAN-01, CLEAN-02, CLEAN-03
**Success Criteria** (what must be TRUE):
  1. The `plugins/emacs/` directory does not exist in the repo; no file in the codebase references it
  2. `docs/sss-mode-guide.md` documents region encrypt/decrypt, toggle-at-point, evil operators, Doom bindings, overlay mode, and transient menu
  3. The README.md Emacs section describes the consolidated package and its capabilities (not the old two-package split)
**Plans**: 2 plans (suggested)

Wave structure:
- **Wave 1** (parallel): CLEAN-01 (remove plugins/emacs/) | CLEAN-02 (update guide) | CLEAN-03 (update README)
- All three are independent and can execute in parallel once Phase 6 is complete

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. CLI Foundation | v1.0 | 2/2 | Complete | 2026-02-21 |
| 2. sss-mode Core | v1.0 | 3/3 | Complete | 2026-02-21 |
| 3. sss-mode Complete | v1.0 | 2/2 | Complete | 2026-02-21 |
| 4. Documentation | v1.0 | 4/4 | Complete | 2026-02-21 |
| 5. Core Operations & UX | 3/3 | Complete    | 2026-02-21 | - |
| 6. Evil & Doom Integration | 2/2 | Complete    | 2026-02-23 | - |
| 7. Cleanup & Documentation | v1.1 | 0/2 | Not started | - |
