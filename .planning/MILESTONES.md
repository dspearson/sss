# Milestones

## v1.0 Documentation & Emacs Integration (Shipped: 2026-02-21)

**Phases completed:** 4 phases, 11 plans, 0 tasks

**Key accomplishments:**
- sss-mode.el Emacs major mode (354 lines) — transparent decrypt-on-open, re-seal-on-save for sealed files
- Font-lock marker highlighting with distinct faces for ⊕{} and ⊠{} regions; modeline shows SSS[open]/SSS[sealed]
- Five project commands (init, process, keygen, keys-list, render-buffer) accessible via C-c C- bindings
- Six documentation files: usage guide, security model (XChaCha20-Poly1305 + Argon2id), marker format with BNF grammar, architecture, configuration reference, sss-mode guide
- README overhaul (628→272 lines) with working quickstart, correct cryptographic claims, 15 verified cross-links
- CLI foundation verified with 74 passing e2e tests including 3 new Emacs-interface smoke tests

**Deliverables:** 2,712 lines across 8 files (emacs/sss-mode.el + 6 docs/ + README.md)
**Timeline:** 2026-02-21 (4 phases, 11 plans, 37 commits)

---


## v1.1 Emacs Integration Consolidation (Shipped: 2026-02-23)

**Phases completed:** 3 phases (5-7), 7 plans, 12 tasks

**Key accomplishments:**
- Consolidated two Emacs implementations into one: `emacs/sss-mode.el` grew from 354 to 746 lines with correct security patterns and full feature coverage
- Region encrypt/decrypt (`C-c C-e`/`C-c C-d`), toggle-at-point (`C-c C-t`), and preview-at-point (`C-c C-v`) via `call-process-region` stdin piping
- Evil operators `ge`/`gd`/`gt` (buffer-local to sss-mode) and text objects `is`/`as` for marker selection, inside `with-eval-after-load 'evil`
- Doom Emacs `SPC e` leader (9 bindings) and `, e` localleader (5 bindings) with `(eval '(map! ...))` byte-compiler safety
- Auth-source passphrase caching, overlay mode for inline visual previews, and transient dispatch menu (`C-c C-m`) with completing-read fallback
- Removed legacy `plugins/emacs/` (7 files, 2,790 lines); updated README and docs/sss-mode-guide.md (11 to 17 sections)

**Deliverables:** 716 insertions, 2,809 deletions across 10 files (net reduction: single package replaces 8 files)
**Timeline:** 2026-02-21 to 2026-02-23 (3 phases, 7 plans, 33 commits)

---

