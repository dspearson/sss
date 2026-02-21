# Project Research Summary

**Project:** sss — Emacs Major Mode + CLI Documentation Milestone
**Domain:** Emacs Lisp package development + Rust CLI user documentation
**Researched:** 2026-02-21
**Confidence:** MEDIUM (stack: MEDIUM; features: MEDIUM; architecture: HIGH; pitfalls: MEDIUM)

## Executive Summary

This milestone adds two independent deliverables to an existing Rust CLI secrets tool (sss): (1) an Emacs major mode (`sss-mode`) that provides transparent decrypt-on-open and re-seal-on-save behaviour for sss-sealed files, and (2) user-facing documentation via mdBook. The existing Rust/crypto stack (clap 4.5, libsodium-sys, XChaCha20-Poly1305, Argon2id) is established and not revisited here. Both deliverables sit on top of the existing binary — neither requires changes to core cryptographic logic, only CLI interface additions and new wrapping infrastructure.

The recommended approach for `sss-mode` is the `file-name-handler-alist` mechanism modelled directly on Emacs' own `epa-file.el` (GPG support). This intercepts file I/O at the C layer, making encryption transparent to all Emacs operations including revert-buffer, which hook-based approaches miss. The mode must be zero-dependency (no external MELPA packages), target Emacs 27.1+, use lexical binding, and disable auto-save and backup creation immediately on file open — these are non-negotiable security requirements. For documentation, mdBook is the unambiguous choice for the Rust ecosystem; `clap-markdown` eliminates drift between help text and docs by generating the CLI reference directly from clap definitions.

The dominant risks in this milestone are data-safety failures in the Emacs integration: silent plaintext writes to disk when sealing fails, auto-save files capturing plaintext, and keystore authentication failures that look like empty files. Every one of these has an established prevention pattern (use `write-contents-functions` over `before-save-hook`, disable auto-save buffer-locally on open, check exit codes with `call-process`). Addressing these correctly in the implementation phase is the highest-priority concern — the patterns are well-understood but must be applied without shortcuts.

## Key Findings

### Recommended Stack

The Emacs side of this milestone uses only Emacs built-ins: `define-derived-mode`, `file-name-handler-alist`, `magic-mode-alist`, and `call-process` / `call-process-region`. No external runtime MELPA dependencies are acceptable — `sss-mode.el` ships as a zero-dependency single-file package bundled in `emacs/` within the sss repository. Development tooling (for CI/linting only) includes `buttercup` for BDD testing, `package-lint` for header validation, `checkdoc` for docstring quality, and `makem.sh` as a unified Makefile driver. For documentation, mdBook 0.5.2 serves as the static site generator, and `clap-markdown` 0.1.5 auto-generates the CLI reference page from clap definitions. See `.planning/research/STACK.md` for full rationale.

**Core technologies:**
- `file-name-handler-alist` (Emacs built-in): transparent I/O interception for decrypt/encrypt — the epa-file.el model; the only correct mechanism
- `define-derived-mode` (Emacs built-in): major mode definition with auto-created keymap, hooks, and abbrev table
- `magic-mode-alist` (Emacs built-in): content-based file detection on the `⊠{` marker bytes — works without file extensions
- `call-process` / `call-process-region` (Emacs built-in): synchronous shell-out to the `sss` binary; provides exit code and stderr capture
- `mdBook` 0.5.2: documentation site generator, standard for Rust projects
- `clap-markdown` 0.1.5: auto-generated CLI reference from clap definitions; eliminates drift

**Critical version floor:** Emacs 27.1 (`Package-Requires: ((emacs "27.1"))`). Do not target lower.

### Expected Features

The Emacs mode has clear table stakes established by comparison with EPA, age.el, and sops-mode. The feature set is compact and well-scoped. See `.planning/research/FEATURES.md` for full matrix.

**Must have (table stakes — all P1, launch-blocking):**
- Auto-detect sealed files via `⊠{` magic bytes on open
- Auto-decrypt to plaintext buffer on open (using `sss render` — strips markers for clean display)
- Auto-re-seal on save — file on disk stays encrypted, buffer shows plaintext
- Disable auto-save (`auto-save-mode -1`) and backup (`backup-inhibited t`) immediately on decrypt — security non-negotiable
- Error feedback in dedicated `*sss-errors*` buffer when subprocess fails
- Named keymap `sss-mode-map` with `C-c s` prefix
- Modeline indicator showing mode active and sealed/open state
- `defcustom sss-executable` for configurable binary path
- `defgroup sss` customization group
- Standard package structure: `provide`, `autoload` cookies, lexical binding

**Documentation must-haves:**
- README overhaul with 60-second quickstart
- Usage guide (init → seal → open → edit workflow)
- Subcommand reference (all 11 subcommands)
- Security model page (what is and is not protected)
- Marker format reference (`⊕{}`, `⊠{}`, rendering behaviour)

**Should have (differentiators — P2, add after v1 core is stable):**
- Marker-aware syntax highlighting (font-lock for `⊕{}` / `⊠{}` — unique; GPG/age are whole-file)
- Selective open vs render commands (`sss-open-buffer` / `sss-render-buffer`)
- Project operation commands (`M-x sss-init`, `M-x sss-process`, `M-x sss-audit`)
- Sealed file state indicator in modeline: `[SSS:open]` vs `[SSS:sealed]`
- Architecture guide for contributors
- Multi-user / team workflow documentation

**Defer (v2+):**
- MELPA packaging — requires separate external MELPA PR
- Man pages — requires packaging integration
- Org-mode integration — research project, known marker format conflicts
- Keystore management commands — after project commands are stable
- Translated documentation

**Anti-features (explicitly out of scope):**
- Interactive passphrase prompts in Emacs — contradicts keystore auto-auth design
- FUSE mount/unmount from Emacs — stateful, platform-specific, out of scope
- Async/background decryption — PROJECT.md mandates synchronous for v1

### Architecture Approach

The architecture is a thin Emacs Lisp wrapper that delegates all cryptography to the existing `sss` binary via synchronous subprocess calls. There is no cryptographic logic in the Emacs Lisp code. The mode intercepts Emacs file I/O via `file-name-handler-alist` (for the core read/write path) supplemented by `find-file-hook` for buffer-state tracking. The critical keystore constraint — auto-authentication only, no TTY prompts — is already enforced by the CLI; the Emacs mode just needs to surface CLI errors clearly when authentication fails. The project structure is `emacs/sss-mode.el` (single-file package) with tests in `emacs/test/sss-mode-test.el`. See `.planning/research/ARCHITECTURE.md` for the full data-flow diagrams.

**Major components:**
1. `sss--file-handler` (file-name-handler-alist entry) — intercepts `insert-file-contents` (decrypt) and `write-region` (re-seal) at the C layer; uses `inhibit-file-name-handlers` pattern to prevent recursion
2. `sss--sealed-file-p` predicate — scans buffer for `⊠{` (UTF-8: `\xe2\x8a\xa0{`) at known offsets; no CLI invocation required for detection
3. `sss--call-cli` helper — wraps `call-process` with exit-code checking, stderr capture, and user-visible error display; used by all file operations and interactive commands
4. `sss-mode` major mode (`define-derived-mode`) — wires detection, disables auto-save/backup, sets up keymap and modeline
5. Interactive commands module — `M-x sss-init`, `sss-process`, `sss-audit`; fire-and-forget to `*sss-output*` buffer

**Build order within the mode:**
Phase A (foundation): `sss--sealed-file-p` + `sss--call-cli` (testable in isolation with ERT mocks)
Phase B (open flow): `file-name-handler-alist` decrypt integration + `find-file-hook`
Phase C (save flow): `write-region` handler + buffer state management (trickiest part)
Phase D (mode definition): `sss-mode` with magic-mode-alist, auto-save disable
Phase E (interactive commands): project ops commands

### Critical Pitfalls

All six critical pitfalls from research map to the Emacs integration implementation phase. There are no architecture-level unknowns — the patterns are established from EPA and age.el prior art. See `.planning/research/PITFALLS.md` for full detail including warning signs and recovery strategies.

1. **Auto-save and backup write plaintext to disk** — Prevent by setting `(setq-local backup-inhibited t)`, `(setq-local auto-save-default nil)`, `(auto-save-mode -1)` inside the `find-file-hook` that triggers decryption, not in the mode body. Timing matters: must execute before the first auto-save timer fires on a slow open.

2. **`before-save-hook` fails silently, writes plaintext** — Never use `before-save-hook` as the primary re-seal mechanism. Use `write-contents-functions` instead: returning non-nil skips Emacs' default `write-region` call entirely. If sealing fails, surface explicit error and return nil only after confirming the sealed file on disk is intact. Alternatively, signal `(error ...)` explicitly on CLI failure.

3. **`shell-command-to-string` discards exit code and stderr** — Use `call-process` for all CLI invocations. Capture stderr to a named buffer using the `(list t stderr-buffer)` destination argument. Never treat empty stdout as "no secrets"; check exit code. Silent decryption failure that looks like an empty file is the most dangerous UX pitfall.

4. **exec-path / PATH broken in Emacs daemon mode** — Provide `(defcustom sss-executable "sss" ...)` and call `(executable-find sss-executable)` at mode load time with a loud warning (not error) if not found. Document daemon-mode PATH setup. Never hardcode binary path.

5. **`magic-mode-alist` false positives on non-SSS files** — Use a named predicate function, not a bare regexp. Validate the full SSS header structure (exact byte offsets, not just presence of UTF-8 characters that may appear in other contexts). Test against `.toml`, `.sh`, `.rs`, `.json` files.

6. **Keystore auth failure produces silent no-op (empty buffer)** — Non-zero exit from `sss render` must produce a visible user error, never a blank buffer. The existing `src/keystore.rs` already has a known silent-fallback issue (CONCERNS.md lines 73-81); the Emacs integration must not compound this with its own error suppression.

## Implications for Roadmap

Based on research, the milestone divides naturally into five sequential phases. The two tracks (Emacs mode and documentation) are largely independent but the documentation phase benefits from a working mode to document. Phase ordering within the Emacs track follows strict dependency chains: the predicate and CLI helper must exist before any hook can be built; the open flow must work before the save flow can be safely tested; the mode definition is the final assembly.

### Phase 1: CLI Foundation for Emacs Integration
**Rationale:** The Emacs mode shells out to `sss render FILE` and `sss seal --in-place FILE`. If the CLI does not already support `--render` / `--in-place` flags with stable exit codes and clean stderr, the Emacs mode cannot be built or tested. This must be validated and any missing flags added before Emacs work begins.
**Delivers:** Confirmed or extended CLI interface — `sss render FILE` (stdout plaintext), `sss seal --in-place FILE`, clean non-zero exit on auth failure with stderr message. Also: confirmation of the exact `⊠{` marker byte sequence from `src/constants.rs`.
**Addresses:** Architecture integration boundary (ARCHITECTURE.md: "CLI Subcommands Used by sss-mode"), STACK.md note "Verify against `src/commands/` before finalising."
**Avoids:** Discovering mid-Emacs-implementation that the CLI interface needs changes (would require a re-plan).

### Phase 2: sss-mode Foundation (Detection + CLI Helper)
**Rationale:** `sss--sealed-file-p` and `sss--call-cli` are the shared primitives on which all hooks and interactive commands depend. Building and testing them in isolation (with ERT/buttercup mocks, no real `sss` install needed) de-risks all downstream phases.
**Delivers:** `sss--sealed-file-p` predicate validated against real SSS marker bytes and confirmed non-false-positive on common file types; `sss--call-cli` helper with exit-code checking, stderr capture, and user-visible error formatting; `defcustom sss-executable` with `executable-find` check at load time.
**Uses:** `call-process`, `executable-find`, `buttercup` BDD test framework (STACK.md)
**Avoids:** Pitfall 3 (stderr blindness), Pitfall 4 (daemon mode PATH), Pitfall 5 (magic byte false positives)

### Phase 3: sss-mode Core — Open and Save Flows
**Rationale:** This is the highest-risk implementation work. The open flow (decrypt on `insert-file-contents`) and save flow (re-seal on `write-region`) must both work correctly before any other mode behaviour is meaningful. The `file-name-handler-alist` + `inhibit-file-name-handlers` recursion prevention pattern is non-obvious and must be implemented exactly as in `epa-file.el`.
**Delivers:** `sss-file-handler` registered in `file-name-handler-alist`; transparent decrypt on open; auto-save and backup disabled immediately on decrypt; re-seal on save via `write-contents-functions` (not `before-save-hook`); buffer-modified-p managed correctly; `after-revert-hook` re-triggers decryption.
**Implements:** Architecture components 1, 2 (ARCHITECTURE.md)
**Avoids:** Pitfall 1 (auto-save/backup plaintext leak), Pitfall 2 (before-save-hook silent failure), Pitfall 3 (buffer state mismatch after save/revert), Pitfall 6 (keystore failure silent no-op)

### Phase 4: sss-mode Mode Definition and UX
**Rationale:** With open/save flows tested and working, the `define-derived-mode` body and auto-detection wiring are assembly work. This phase also adds the user-visible polish (modeline, keymap, customization group) that makes the mode feel complete.
**Delivers:** `sss-mode` defined via `define-derived-mode text-mode`; `magic-mode-alist` entry with predicate function; `sss-mode-map` with `C-c s` prefix; modeline indicator `[SSS:open]` / `[SSS:sealed]`; `defgroup sss` with all `defcustom` variables; proper package header (`Package-Requires: ((emacs "27.1"))`), `provide 'sss-mode`, `autoload` cookies, lexical binding; `makem.sh` CI with byte-compile, checkdoc, package-lint, buttercup.
**Uses:** `define-derived-mode`, `magic-mode-alist`, `makem.sh`, `package-lint`, `checkdoc` (STACK.md)
**Avoids:** Pitfall 5 (magic byte false positives — predicate function, not bare regexp)

### Phase 5: Interactive Project Commands (P2 — after v1 core validated)
**Rationale:** The core transparency (open/save) is the v1 value. Project operation commands (`M-x sss-init`, `sss-process`, `sss-audit`) add convenience but are not launch-blocking. Implementing them after v1 core is validated reduces scope risk.
**Delivers:** `M-x sss-init`, `M-x sss-process`, `M-x sss-audit`, `M-x sss-keys-list` — each shells out to the corresponding `sss` subcommand, outputs to `*sss-output*` buffer; project root discovery via `locate-dominating-file` for `.sss.toml`.
**Implements:** Architecture component 5 (interactive commands module)

### Phase 6: Documentation (mdBook Site)
**Rationale:** Documentation can proceed largely in parallel with Phases 3-5 once Phase 1 confirms the CLI interface is stable. The subcommand reference generated by `clap-markdown` requires a stable CLI. Documentation is not gated on the Emacs mode being complete, but benefits from it being tested.
**Delivers:** `docs/` mdBook site structure; `book.toml`; README overhaul; usage guide (init → seal → open → edit); subcommand reference auto-generated by `clap-markdown`; security model page; marker format reference; `mdbook-linkcheck` in CI.
**Uses:** mdBook 0.5.2, `clap-markdown` 0.1.5, `mdbook-linkcheck` (STACK.md)
**Avoids:** Documentation anti-pattern: starting with architecture, not quickstart (PITFALLS.md: UX pitfalls); CLI reference drift (generated, not hand-authored)

### Phase Ordering Rationale

- **Phase 1 must come first** because the Emacs mode cannot be implemented or tested without knowing the exact CLI interface. Discovering flag incompatibilities mid-implementation is expensive.
- **Phases 2 then 3** follow the architecture's own declared build order (predicate/helper → open hook → save hook). The dependency chain is strict: no hook can be implemented without the underlying helpers.
- **Phase 4 is assembly** — it depends on Phase 3 being working and tested. Attempting to wire the mode definition before the I/O handler works leads to false confidence from the mode activating but not functioning.
- **Phase 5 is explicitly deferred** to avoid scope creep on the higher-risk core. All six critical pitfalls are in Phases 2-4; Phase 5 has no novel technical risk.
- **Phase 6 is parallelisable** with Phases 3-5 for experienced contributors, but should not block on mode completion. The documentation quickstart should be validated against the actual working mode before publishing.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 1:** The exact CLI flags (`--in-place`, `--render`, `--stdout`, `--stdin`) must be confirmed against current `src/commands/` before implementation begins. STACK.md explicitly flags this: "If the current CLI does not support these flags, they must be added as part of this milestone."
- **Phase 3:** The `write-contents-functions` vs `before-save-hook` interaction with Emacs' internal save machinery warrants a focused spike. The EPA save bug (bug#63293) shows this area has historically caused subtle regressions even in Emacs core code.

Phases with standard patterns (skip additional research):
- **Phase 2:** `call-process` usage, `executable-find`, `defcustom` — all well-documented stable Emacs APIs.
- **Phase 4:** `define-derived-mode`, `magic-mode-alist`, `package-lint` — standard, extensively documented in GNU Emacs Lisp Reference Manual and epa-file.el source.
- **Phase 6:** mdBook and `clap-markdown` are straightforward; official docs are complete and high-confidence.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Emacs Lisp patterns confirmed from official GNU docs and epa-file.el source. Some version specifics (makem.sh, package-lint) from WebSearch only. mdBook and clap-markdown verified from official docs. |
| Features | MEDIUM | Emacs mode conventions HIGH from official docs and competitor analysis. Documentation table stakes MEDIUM from community consensus. Feature priorities aligned with PROJECT.md constraints. |
| Architecture | HIGH | Based on direct codebase analysis of `src/constants.rs`, `src/keystore.rs`, `src/processor/core.rs`, and explicit PROJECT.md constraints. Data flow diagrams verified against actual code. |
| Pitfalls | MEDIUM | EPA and age.el issues verified via official docs and multiple credible community sources. SSS-specific behaviour extrapolated from CONCERNS.md codebase analysis. Before-save-hook failure modes confirmed from Doom Emacs bug reports. |

**Overall confidence:** MEDIUM

### Gaps to Address

- **CLI interface verification (Phase 1 gate):** STACK.md and ARCHITECTURE.md both flag that `sss render FILE` (stdout mode), `sss seal --in-place FILE`, and `sss open FILE` must be verified against actual `src/commands/` before Emacs implementation. If any flag is missing, CLI work is required before Emacs work. This is the single most important gap to close before roadmap execution begins.
- **Magic marker exact byte sequence:** The Emacs detection predicate needs the exact byte sequence for `⊠{` confirmed from `src/constants.rs`. Architecture research provides the Unicode codepoint (`U+2220`, UTF-8: `\xe2\x8a\xa0`) but the implementation should validate this against actual sealed file output before committing to the regexp.
- **Keyring availability in CI environment:** Phase 3 testing of keystore-failure paths requires a test environment where the system keyring is either absent or deliberately locked. This is non-trivial in headless CI (no D-Bus session, no macOS Keychain). Test strategy for this scenario needs planning.
- **`sss-mode` display mode decision:** FEATURES.md notes a render-vs-open display choice: `sss render` (no markers, simpler UX) vs `sss open` (markers visible, enables syntax highlighting). Research recommends `render` as default. This must be confirmed as a hard decision before Phase 3 implementation begins, because it determines whether font-lock highlighting is feasible in the default mode.

## Sources

### Primary (HIGH confidence)
- GNU Emacs Lisp Reference Manual, "Magic File Names" — `file-name-handler-alist`, `inhibit-file-name-handlers` pattern
- GNU Emacs Lisp Reference Manual, "Derived Modes" — `define-derived-mode` syntax and conventions
- GNU Emacs Lisp Reference Manual, "Auto Major Mode" — `magic-mode-alist` ordering and precedence
- emacs-mirror/emacs `lisp/epa-file.el` — complete file handler implementation pattern (primary reference)
- mdBook official docs (rust-lang.github.io/mdBook) — version 0.5.2, book.toml format
- docs.rs/clap-markdown — API surface, version 0.1.5
- `src/constants.rs` — marker format definitions (`MARKER_CIPHERTEXT`, `MARKER_PLAINTEXT_UTF8`, `MARKER_PLAINTEXT_ASCII`)
- `src/config.rs` — `find_project_root_from()` — project root discovery
- `src/keystore.rs` — `StoredKeyPair`, `in_keyring` field — system keyring auto-auth
- `src/processor/core.rs` — `find_balanced_markers()` — marker detection algorithm
- `.planning/PROJECT.md` — authoritative constraints (no async, no new extensions, keystore auto-auth only, bundle under `emacs/`)
- `.planning/codebase/CONCERNS.md` — known keyring silent-fallback issue (lines 73-81)

### Secondary (MEDIUM confidence)
- EasyPG Assistant User's Manual (GNU Emacs) — auto-save security considerations
- age.el GitHub (anticomputer) — competitor feature analysis, passphrase-protected identity failure patterns
- sops-mode GitHub (djgoku) — competitor keymap and save-hook patterns
- exec-path-from-shell GitHub (purcell) — daemon mode PATH mismatch patterns
- alphapapa/emacs-package-dev-handbook — makem.sh, package development workflow
- akuszyk.com 2024 — practitioner experience with Emacs encryption modes
- Doom Emacs issue #893 — `before-save-hook` error blocking behaviour
- EasyPG save bug#63293 (GNU mailing list 2023) — buffer-modified-p not cleared after encrypted save
- smallstep.com — CLI documentation antipatterns for secrets tools
- arxiv.org 2025 — new user confusion from poor secrets tool documentation

### Tertiary (LOW confidence)
- mdBook-linkcheck — current version; verify on install
- clap_mangen 0.2.x — WebSearch only; out of scope for this milestone but noted for future

---
*Research completed: 2026-02-21*
*Ready for roadmap: yes*
