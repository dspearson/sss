# Stack Research

**Domain:** Emacs major mode + Rust CLI user documentation
**Researched:** 2026-02-21
**Confidence:** MEDIUM — Emacs Lisp patterns verified against official GNU docs and emacs-mirror source; documentation tooling verified against crates.io and official mdBook docs. Some version specifics from WebSearch only (flagged).

---

## Context

The existing Rust/crypto stack (Cargo, clap 4.5, libsodium-sys, etc.) is documented in `.planning/codebase/STACK.md` and is not revisited here. This document covers only the two new technology domains this milestone introduces:

1. **Emacs Lisp** — building `sss-mode`, a major mode with transparent decrypt-on-open and re-seal-on-save behaviour
2. **Documentation tooling** — generating user-facing docs (README, usage guide, architecture docs) for the existing Rust CLI

---

## Part 1: Emacs Major Mode Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Emacs Lisp (built-in) | Emacs 27+ | Implementation language for sss-mode | Only language for Emacs packages; no alternative. Emacs 27 introduced `define-derived-mode` improvements and `use-package` built-in (28+). Target 27+ for widest compatibility. |
| `define-derived-mode` (built-in macro) | Emacs 27+ | Define sss-mode as a derived mode | Standard since Emacs 21. Automatically handles keymap, syntax table, mode hook, abbrev table, and `run-mode-hooks`. DO NOT use bare `defun` for a major mode. |
| `file-name-handler-alist` (built-in) | Emacs 27+ | Intercept file I/O for transparent decrypt/encrypt | The canonical mechanism, used by `epa-file.el` (GPG), `jka-compr.el` (gzip), and `tramp`. It hooks into all file primitives (`insert-file-contents`, `write-region`, etc.) at the C layer, making it truly transparent — the buffer sees plaintext while the file stays sealed. |
| `magic-mode-alist` (built-in) | Emacs 27+ | Detect sealed files by content, not filename | SSS files have no fixed extension. `magic-mode-alist` matches a regexp against the first bytes of the buffer, which is exactly where SSS stores its marker. Takes precedence over `auto-mode-alist`. |
| `call-process` / `call-process-region` (built-in) | Emacs 27+ | Shell out to `sss` binary for decrypt/encrypt | Synchronous shell-out is correct for v1 (PROJECT.md explicitly rules out async). `call-process-region` passes buffer region as stdin and captures stdout, which maps cleanly to `sss open` / `sss seal` operating on content. |

### Supporting Libraries (Emacs Packages)

These are development-time tools, not runtime dependencies of sss-mode itself. sss-mode must have zero external Emacs package dependencies — it ships with the sss binary and cannot require users to install MELPA packages.

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `package-lint` | current (MELPA) | Validates package metadata (Package-Version, Package-Requires headers, copyright) | During development/CI; enforces MELPA standards even though we're not on MELPA yet. Catches header errors early. |
| `checkdoc` (built-in) | Emacs 27+ | Validates docstring conventions | Run during CI (`emacs --batch --eval "(checkdoc-file ...)"`) to enforce documentation quality. Required for any eventual MELPA submission. |
| `buttercup` | current (MELPA) | BDD-style test framework for Emacs Lisp | Better than ERT for testing mode behaviour (hooks firing, buffer state, process integration). `describe`/`it` DSL is readable. |
| `makem.sh` | current (GitHub) | Makefile-driven lint + test runner for Emacs packages | Single shell script, no dependencies. Handles byte-compile, checkdoc, package-lint, and buttercup in one `make test`. Eliminates boilerplate CI configuration. |

### Key Emacs Lisp Patterns for sss-mode

#### Pattern 1: File Handler for Transparent I/O (the epa-file.el model)

This is the correct architecture for transparent decrypt-on-open and re-seal-on-save. Do NOT use `before-save-hook` + `find-file-hook` as the primary mechanism — that approach is fragile (hooks can be removed, revert-buffer bypasses them, backup files get plaintext). The file-name-handler approach intercepts at the C layer.

```lisp
;; Register handler: regexp matches SSS marker bytes at start of file
(defconst sss--file-handler-entry
  (cons (concat "\\`" (regexp-quote sss--magic-marker)) 'sss-file-handler))

(defun sss-file-enable ()
  "Enable transparent sss file handling."
  (add-to-list 'file-name-handler-alist sss--file-handler-entry)
  (add-hook 'find-file-hook #'sss--find-file-hook))

(defun sss-file-handler (operation &rest args)
  "Dispatch file OPERATION for sss-sealed files."
  (cond
   ((eq operation 'insert-file-contents) (apply #'sss--insert-file-contents args))
   ((eq operation 'write-region)         (apply #'sss--write-region args))
   (t (let ((inhibit-file-name-handlers
             (cons 'sss-file-handler
                   (and (eq inhibit-file-name-operation operation)
                        inhibit-file-name-handlers)))
            (inhibit-file-name-operation operation))
        (apply operation args)))))

;; Decrypt on read
(defun sss--insert-file-contents (file &optional visit beg end replace)
  (let ((plaintext (sss--run-decrypt file)))
    (insert plaintext)
    (list file (length plaintext))))

;; Re-seal on write
(defun sss--write-region (start end file &optional append visit lockname mustbenew)
  (let ((sealed (sss--run-seal start end)))
    (let ((inhibit-file-name-handlers
           (cons 'sss-file-handler
                 (and (eq inhibit-file-name-operation 'write-region)
                      inhibit-file-name-handlers)))
          (inhibit-file-name-operation 'write-region))
      (write-region sealed nil file nil visit lockname mustbenew))))
```

The `inhibit-file-name-handlers` pattern is mandatory to prevent infinite recursion. This is identical to what `epa-file.el` and `jka-compr.el` do. (Source: GNU Emacs Lisp Reference Manual, "Magic File Names"; verified against emacs-mirror/emacs source.)

#### Pattern 2: Magic Byte Detection

```lisp
;; SSS sealed files begin with a known marker string (e.g. "SSS:")
;; Add to magic-mode-alist so Emacs triggers sss-mode on content, not extension
(add-to-list 'magic-mode-alist
             (cons (concat "\\`" (regexp-quote sss--magic-marker))
                   #'sss-mode))
```

`magic-mode-alist` is checked before `auto-mode-alist`, so this takes priority. The marker must be a fixed string that appears at byte offset 0. Confirm the exact marker from `src/processor/core.rs` before finalising the regexp.

#### Pattern 3: define-derived-mode Body

```lisp
(define-derived-mode sss-mode text-mode "SSS"
  "Major mode for sss-sealed files.
Transparently decrypts on open and re-seals on save."
  ;; Buffer-local: disable auto-save (plaintext must not touch disk)
  (setq-local auto-save-default nil)
  ;; Buffer-local: disable backup files (same reason)
  (setq-local make-backup-files nil)
  ;; Mode-local keymap entries set via `sss-mode-map` (auto-created by define-derived-mode)
  )
```

Use `setq-local` (not `make-local-variable` + `setq`) — it is the modern idiom since Emacs 24.3 and more readable.

#### Pattern 4: CLI Integration via call-process-region

```lisp
(defun sss--run-decrypt (file)
  "Return decrypted plaintext string for FILE."
  (with-temp-buffer
    (let ((exit-code (call-process "sss" nil t nil "open" "--stdout" file)))
      (unless (= exit-code 0)
        (error "sss-mode: decryption failed (exit %d)" exit-code))
      (buffer-string))))

(defun sss--run-seal (start end)
  "Return sealed content string from buffer region START to END."
  (with-temp-buffer
    (let ((exit-code (call-process-region start end "sss" nil t nil "seal" "--stdin")))
      (unless (= exit-code 0)
        (error "sss-mode: sealing failed (exit %d)" exit-code))
      (buffer-string))))
```

This requires sss to support `--stdout` for decryption and `--stdin` for sealing. If the current CLI does not support these flags, they must be added as part of this milestone. Verify against `src/commands/` before finalising.

### Emacs Lisp Package File Structure

```
emacs/
  sss-mode.el          # Single-file package (preferred for simplicity)
  test/
    sss-mode-test.el   # buttercup tests
  Makefile             # makem.sh wrapper
```

A single `.el` file is the correct choice for an in-repo bundle with no external dependencies. The file header must follow MELPA conventions even now:

```lisp
;;; sss-mode.el --- Major mode for sss-sealed files  -*- lexical-binding: t; -*-

;; Copyright (C) 2026 <Author>
;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: files, encryption, secrets
;; URL: https://github.com/<org>/sss

;;; Commentary:
;; ...

;;; Code:

;; ...

(provide 'sss-mode)
;;; sss-mode.el ends here
```

The `Package-Requires: ((emacs "27.1"))` floor should be 27.1 (released 2020), which is the oldest version with `define-derived-mode` improvements worth targeting. Do not go lower.

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `emacs --batch` | Headless testing and linting | Standard CI approach; no graphical display needed |
| `makem.sh` | Unified lint + test Makefile | Single script from GitHub (nicferrier/makem.sh); covers byte-compile, checkdoc, package-lint, buttercup |
| `package-lint` | Package metadata validation | Install via `emacs --batch -f package-initialize --eval "(package-install 'package-lint)"` in CI |
| `buttercup` | BDD test runner | `emacs --batch -f package-initialize -f buttercup-run-discover` |
| `flycheck-package` | Editor-time package linting | Local dev only; not needed in CI |

---

## Part 2: Documentation Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| mdBook | 0.5.2 | User-facing documentation (usage guide, architecture docs) | The de-facto standard for Rust project documentation. Used by the Rust language itself (The Book, The Reference, The Nomicon). Markdown-native, zero Python dependency, ships a binary, integrates cleanly with CI. All major Rust CLI projects (ripgrep, bat, fd) use mdBook or simple Markdown. |
| `clap-markdown` | 0.1.5 | Auto-generate Markdown CLI reference from clap definitions | Derives documentation directly from clap `Command` definitions, eliminating drift between CLI help and docs. One function call: `clap_markdown::print_help_markdown(&mut app)`. The generated file (e.g. `docs/CommandLineHelp.md`) is committed to git so changes are visible in PR diffs. |
| `clap_mangen` | 0.2.x | Man page generation (roff format) | Part of the official clap-rs org. Generates from the same clap `Command` definitions used everywhere else. Run from `build.rs` to produce man pages at compile time. Correct choice if man pages are in scope for a future milestone. Out of scope for this milestone per PROJECT.md but worth noting for future. |

### Supporting Tools

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `mdbook-linkcheck` | current | Validate all links in mdBook source | Use in CI to catch dead links before they ship. A forgotten link is the most common doc regression. |
| `cargo doc` | built-in | Generate rustdoc HTML for internal API docs | Use for contributor-facing architecture documentation (the internal rustdoc). Link from the mdBook "Architecture" chapter using `--no-deps`. |
| GitHub Actions / CI | — | Auto-publish mdBook to GitHub Pages | Standard practice; `peaceiris/actions-mdbook` action is the most-used. Out of scope for this milestone but the mdBook structure should anticipate it. |

### Documentation Structure

```
docs/                         # mdBook source root
  book.toml                   # mdBook configuration
  src/
    SUMMARY.md                # Table of contents (mdBook requires this)
    README.md                 # Introduction / landing page
    guide/
      installation.md
      quickstart.md
      workflows.md            # Common workflows: seal, open, edit, render
      configuration.md        # .sss.toml reference
      emacs.md               # Emacs mode usage
    reference/
      CommandLineHelp.md      # AUTO-GENERATED by clap-markdown (do not hand-edit)
      encryption.md           # Marker format, crypto primitives
    architecture/
      overview.md
      processor.md
      keystore.md
```

**Do not hand-author `CommandLineHelp.md`**. It is generated by a `cargo run -- --markdown-help > docs/src/reference/CommandLineHelp.md` step (or equivalent) in CI. Treat it as a build artifact that happens to be committed.

### mdBook Configuration (book.toml)

```toml
[book]
title = "sss — Secrets Sharing System"
authors = ["sss contributors"]
language = "en"
src = "src"

[output.html]
git-repository-url = "https://github.com/<org>/sss"
edit-url-template = "https://github.com/<org>/sss/edit/main/docs/src/{path}"

[preprocessor.links]
# built-in; enables {{#include}} for embedding code samples from src/
```

---

## Alternatives Considered

| Recommended | Alternative | Why Not |
|-------------|-------------|---------|
| `file-name-handler-alist` for transparent I/O | `before-save-hook` + `find-file-hook` | Hook-based approach is fragile: hooks can be removed by other modes, `revert-buffer` bypasses `find-file-hook`, and backup files may capture plaintext. The handler approach is what Emacs itself uses for GPG and gzip — it is the correct level of abstraction. |
| `magic-mode-alist` for file detection | `auto-mode-alist` with extension | SSS files have no dedicated extension — they look like `.yaml`, `.env`, etc., with encrypted content. Content-based detection via the marker is the only reliable mechanism. |
| `call-process` / `call-process-region` (synchronous) | `make-process` (async) | PROJECT.md explicitly states "No async/background operations for v1". Synchronous is simpler, easier to test, and correct for the keystore-authenticated workflow where decrypt completes in milliseconds. |
| Single `.el` file | Multi-file package | No external dependencies, no autoload infrastructure needed, simpler for in-repo distribution. Multi-file packages are for large packages (>500 lines, multiple major features). |
| mdBook | Sphinx | Sphinx requires Python. mdBook is a single Rust binary with no runtime dependencies. For a Rust project, mdBook is the convention and Sphinx adds operational complexity for no benefit. |
| mdBook | GitBook | GitBook is a commercial SaaS product. mdBook is open source, self-hosted, and the Rust ecosystem standard. |
| `clap-markdown` | Hand-written CLI reference | Hand-written docs drift. `clap-markdown` generates from the same source-of-truth as `--help`, so it is always correct by construction. |
| `clap-markdown` | `clap_mangen` for reference docs | `clap_mangen` generates roff (man pages), not Markdown. Markdown integrates into the mdBook site. Both can coexist, but for the primary reference page use `clap-markdown`. |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| MELPA `epa` or `gnupg` Emacs packages | Creates an external dependency on packages that users must install separately. sss-mode must be zero-dependency. | Use `call-process` to shell out to the `sss` binary directly. |
| `before-save-hook` as the sole re-seal mechanism | Hooks are buffer-local but can be cleared, other modes can interfere, and they do not intercept all write paths (e.g. `write-file`, backup writes). | Use `file-name-handler-alist` (intercepts at the C layer). A `before-save-hook` may be added as a belt-and-suspenders secondary check, but must not be the primary mechanism. |
| Auto-save for sss buffers | Auto-save writes plaintext to `#file#` on disk, defeating encryption. | `(setq-local auto-save-default nil)` in `define-derived-mode` body. This is what `epa-file.el` does. |
| MakeBackupFiles for sss buffers | Backup files (`file~`) capture plaintext. | `(setq-local make-backup-files nil)` in `define-derived-mode` body. |
| Sphinx for user docs | Python runtime dependency, reStructuredText markup, unfamiliar to most Rust contributors. | mdBook. |
| Hand-authoring the CLI reference | Guaranteed to drift from the actual `--help` output within weeks. | `clap-markdown` generating `CommandLineHelp.md` in CI. |
| `lexical-binding: nil` (omitting the cookie) | Dynamic binding is the Emacs Lisp default but produces slower, harder-to-reason-about code. All modern Emacs packages use lexical binding. | Add `-*- lexical-binding: t; -*-` to the first line of every `.el` file. |

---

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| `sss-mode.el` (`Package-Requires: ((emacs "27.1"))`) | Emacs 27.1 – 30.x | 27.1 is the safe floor: `define-derived-mode`, `setq-local`, `lexical-binding` are all stable since then. `use-package` became built-in at 29.1 but is not required by sss-mode. |
| `clap-markdown` 0.1.5 | clap 4.x | Derives from `clap::Command`; the existing project uses clap 4.5.47. Compatible. |
| `clap_mangen` 0.2.x | clap 4.x | Same. Future milestone only. |
| mdBook 0.5.2 | mdBook 0.4.x | Minor version bump; SUMMARY.md format is stable across 0.4/0.5. Use 0.5.2 for new installs. |

---

## Installation

### Emacs Package Development Tools (CI)

```bash
# In CI, install via batch Emacs
emacs --batch \
  --eval "(require 'package)" \
  --eval "(add-to-list 'package-archives '(\"melpa\" . \"https://melpa.org/packages/\") t)" \
  --eval "(package-initialize)" \
  --eval "(package-install 'package-lint)" \
  --eval "(package-install 'buttercup)"

# Download makem.sh
curl -O https://raw.githubusercontent.com/alphapapa/makem.sh/master/makem.sh
chmod +x makem.sh
```

### mdBook

```bash
# Install mdBook binary
cargo install mdbook --version "0.5.2"

# Optional: link checker
cargo install mdbook-linkcheck
```

### clap-markdown (add to Cargo.toml)

```toml
[dependencies]
clap-markdown = "0.1.5"
```

Add a hidden `--markdown-help` flag to the CLI:

```rust
// In main.rs or cli.rs
if args.markdown_help {
    clap_markdown::print_help_markdown::<Cli>();
    return Ok(());
}
```

Then in CI:

```bash
cargo run -- --markdown-help > docs/src/reference/CommandLineHelp.md
```

---

## Sources

- GNU Emacs Lisp Reference Manual, "Magic File Names" — file-name-handler-alist API, inhibit-file-name-handlers pattern — MEDIUM confidence (official docs, rate-limited during fetch but pattern confirmed from cached content and WebSearch results)
- GNU Emacs Lisp Reference Manual, "Derived Modes" — define-derived-mode syntax — MEDIUM confidence
- GNU Emacs Lisp Reference Manual, "Auto Major Mode" — magic-mode-alist and auto-mode-alist ordering — HIGH confidence (multiple official sources agree)
- emacs-mirror/emacs, `lisp/epa-file.el` — complete file handler implementation pattern — HIGH confidence (primary source, fetched directly)
- emacs-mirror/emacs, `lisp/epa-hook.el` — find-file-hook integration — HIGH confidence
- mdBook official docs (rust-lang.github.io/mdBook) — version 0.5.2, SUMMARY.md format, preprocessors — HIGH confidence (fetched directly)
- docs.rs/clap-markdown — API surface, version 0.1.5 — HIGH confidence (fetched directly)
- crates.io/clap_mangen — version 0.2.x, roff generation — MEDIUM confidence (WebSearch, consistent with official clap-rs repository)
- alphapapa/emacs-package-dev-handbook — makem.sh, package development workflow — MEDIUM confidence (WebSearch, GitHub source)
- purcell/package-lint — package metadata linting — MEDIUM confidence (WebSearch, consistent with MELPA tooling documentation)

---

*Stack research for: sss Emacs major mode + Rust CLI documentation*
*Researched: 2026-02-21*
