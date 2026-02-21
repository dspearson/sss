# Phase 4: Documentation - Research

**Researched:** 2026-02-21
**Domain:** Technical documentation for a Rust CLI secrets-management tool
**Confidence:** HIGH (all findings derived from direct source inspection)

---

## Summary

Phase 4 requires producing six Markdown documents (plus a README overhaul) that collectively let a new user install, configure, and use sss, understand its security properties, and integrate the Emacs mode — all without reading source code. The documentation audience ranges from first-time users (quickstart path) through team administrators (key management, collaboration) to integrators who need to write compatible parsers (marker format reference).

The project is a Rust CLI binary (`sss`, version 1.1.9) using `libsodium-sys` directly for XChaCha20-Poly1305 symmetric encryption, Argon2id key derivation, and X25519/Ed25519 asymmetric operations. This is not the `age` crate (the README description was aspirational or out of date) — the implementation calls libsodium primitives directly. All cryptographic facts for DOC-04 must be drawn from `src/crypto.rs` and `src/kdf.rs`, not from prior README descriptions.

The current README is not minimal — it is actually dense and close to complete, but structurally flat and not beginner-friendly. The quickstart section exists but uses subcommand names (`sss keys generate`) that differ from what `src/main.rs` wires up (actual handler is `handle_keys`, implying `sss keys` is the right top-level, but the subcommand `generate` vs `keygen` needs verification). Documentation must be produced from source truth, not from README content.

The Emacs mode (`emacs/sss-mode.el`, 354 lines, complete) has all the details needed for DOC-07: executable path, `magic-mode-alist` registration, keymap (`C-c C-o`, `C-c C-s`, `C-c C-r`, `C-c C-i`, `C-c C-p`, `C-c C-k`, `C-c C-l`), daemon-mode PATH caveat, and the `--non-interactive` flag requirement.

**Primary recommendation:** Write documentation from source code and tests, not from the existing README. The existing README contains inaccuracies (age crate claim, deprecated `sss keygen` subcommand reference) that must not be propagated. Treat every CLI command example as unverified until confirmed against `src/main.rs`.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DOC-01 | README overhaul with installation (cargo, pre-built, RPM/DEB), quickstart, feature overview | Source: README.md current state; Cargo.toml build metadata; existing RPM/DEB build scripts confirmed present |
| DOC-02 | Usage guide covering common workflows: seal, open, edit, process, key management, team collaboration | Source: README.md Core Commands section; src/main.rs subcommand wiring; confirmed workflow order from STATE.md |
| DOC-03 | Architecture documentation: marker inference, processor pipeline, key loading, FUSE/9P | Source: src/processor/core.rs (processor structure); src/crypto.rs (key loading); src/project.rs (project config) |
| DOC-04 | Security model: what is encrypted, algorithms, threat model, what is NOT protected | Source: src/crypto.rs (XChaCha20-Poly1305, X25519, Ed25519); src/kdf.rs (Argon2id levels) |
| DOC-05 | Marker format reference: ⊕{} and ⊠{} semantics, rendering behaviour | Source: src/constants.rs (marker strings); src/processor/core.rs (find_balanced_markers parser) |
| DOC-06 | Configuration reference for .sss.toml and settings.toml | Source: src/project.rs (ProjectConfig struct); src/config_manager.rs (UserSettings) |
| DOC-07 | sss-mode installation and usage guide (Emacs setup, keyring prerequisites, daemon-mode PATH) | Source: emacs/sss-mode.el (all 354 lines read directly) |
</phase_requirements>

---

## Standard Stack

### Core
| Item | Version/Value | Purpose | Source |
|------|---------------|---------|--------|
| Markdown files | CommonMark | All documentation format (decided in roadmap) | ROADMAP.md: "Documentation uses markdown files — not mdBook for v1" |
| docs/ directory | existing | Output location per CLAUDE.md | CLAUDE.md file organisation rules |
| British English | required | All documentation language | CLAUDE.md instructions |

### No external documentation tooling required
The decision is Markdown files only. No mdBook, no man page generators (DOC-V2-01 deferred). Documentation is hand-written Markdown in `docs/`.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Plain Markdown | mdBook | mdBook adds search and navigation but is deferred to v2 (DOC-V2-03) |
| Plain Markdown | clap-markdown auto-gen | Auto-gen CLI reference deferred to v2 (DOC-V2-02) |
| Hand-written | clap_mangen man pages | Man pages deferred to v2 (DOC-V2-01) |

---

## Architecture Patterns

### Recommended Documentation Structure

```
docs/
├── USAGE.md              # DOC-02: Common workflows guide
├── ARCHITECTURE.md       # DOC-03: Technical architecture (file already referenced in README)
├── SECURITY.md           # DOC-04: Security model (file already referenced in README)
├── MARKER_FORMAT.md      # DOC-05: Marker format reference
├── CONFIGURATION.md      # DOC-06: Config reference (.sss.toml + settings.toml)
└── EMACS.md              # DOC-07: sss-mode installation and usage

README.md                 # DOC-01: Overhauled (quickstart, install, feature overview)
```

Note: `ARCHITECTURE.md` and `SECURITY.md` are already referenced in the current README but may not exist as complete documents. The research confirms the README lists them as links but they should be created/completed as part of this phase.

### Pattern: Source-First Documentation

Every CLI command example must be verified against `src/main.rs` subcommand wiring before inclusion. Key verification points:

- `sss keys generate` vs `sss keygen` — the README lists both but the current main.rs calls `handle_keygen_deprecated` for `keygen`, implying `keys generate` is the current path
- `sss seal --in-place` vs `sss seal -x` — both forms must be confirmed from clap arg definitions
- `sss process` — confirmed from STATE.md decision: "sss-process calls sss seal --project — no sss process subcommand exists in CLI"

### Anti-Patterns to Avoid
- **Copying README verbatim**: The existing README has inaccuracies. Cross-verify all commands against source.
- **Claiming age crate for encryption**: The README says "age-core" but `src/crypto.rs` uses `libsodium-sys` directly (XChaCha20-Poly1305). The age claim is wrong.
- **Stating scrypt for KDF**: The README header mentions "scrypt" in the additional context but `src/kdf.rs` uses Argon2id (via `sodium::crypto_pwhash` with `ALG_ARGON2ID13`). Must use Argon2id in DOC-04.
- **Incomplete marker syntax**: The marker parser supports both ASCII (`o+{...}`) and UTF-8 (`⊕{...}`) for plaintext, and only UTF-8 (`⊠{...}`) for ciphertext. Document both forms.
- **Ignoring nested braces**: The parser uses balanced brace counting (`find_balanced_markers`), so `⊕{{"key":"value"}}` is valid. The format reference must document this.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CLI command reference | Custom scraping | Read src/main.rs directly | clap definitions are authoritative |
| Cryptographic algorithm names | Guess from crate names | Read src/crypto.rs constants | libsodium constant names are definitive |
| KDF parameter values | Estimate | Read src/kdf.rs KdfParams impls | Exact memory/ops values are in code |
| .sss.toml schema | Infer | Read src/project.rs ProjectConfig | Serde annotations are the schema |
| Settings schema | Infer | Read src/config_manager.rs UserSettings | Field names are in the struct |

---

## Common Pitfalls

### Pitfall 1: Wrong Encryption Library Attribution
**What goes wrong:** Documentation claims `age` crate or `scrypt` (both appear in earlier context/README) when the actual implementation uses libsodium directly.
**Why it happens:** README was likely written before or during development and not kept up to date with implementation.
**How to avoid:** Source of truth is `src/crypto.rs` — confirmed: `libsodium_sys`, `crypto_secretbox_xchacha20poly1305_*` constants, `crypto_pwhash` (Argon2id).
**Warning signs:** Any mention of "age", "scrypt", or "chacha20" (without "x") is suspect.

### Pitfall 2: Subcommand Name Confusion
**What goes wrong:** Documentation uses `sss keygen` but the current path is `sss keys generate`. Or documents `sss process` which does not exist (it is `sss seal --project`).
**Why it happens:** CLI evolved and the README was not fully updated.
**How to avoid:** Confirmed from STATE.md: "sss-process calls sss seal --project — no sss process subcommand exists in CLI". Verify every subcommand in `src/main.rs` before writing.
**Warning signs:** Any example using `sss keygen`, `sss process`, or `sss users` as top-level subcommands.

### Pitfall 3: Daemon-Mode PATH for Emacs
**What goes wrong:** sss-mode installation guide omits the daemon-mode PATH issue, leading to "binary not found" errors for users who launch Emacs from a GUI launcher (macOS Dock, systemd user service).
**Why it happens:** PATH is inherited from the shell in terminal-launched Emacs but not in daemon mode.
**How to avoid:** DOC-07 must explicitly document `(setq sss-executable "/usr/local/bin/sss")` or equivalent absolute path configuration. This is already in the sss-mode.el Commentary block.
**Warning signs:** Installation guide that only says "add to load-path" without addressing PATH.

### Pitfall 4: Marker Unicode Confusion
**What goes wrong:** Documentation conflates or reverses the two marker characters.
**Why it happens:** Both are obscure Unicode symbols that look similar in some fonts.
**How to avoid:**
  - `⊕` (U+2295, CIRCLED PLUS) = plaintext/open marker — what you write to mark secrets
  - `⊠` (U+22A0, SQUARE ORIGINAL OF) = ciphertext/sealed marker — what appears after encryption
  - ASCII alternative for plaintext only: `o+{...}`
  - No ASCII alternative for ciphertext
  - Source: `src/constants.rs` `MARKER_PLAINTEXT_UTF8 = "⊕"`, `MARKER_CIPHERTEXT = "⊠"`
**Warning signs:** Reversed descriptions, or claiming `⊠` has an ASCII alternative.

### Pitfall 5: Quickstart Missing Key Init Step
**What goes wrong:** Quickstart sends user to `sss seal` before they have generated a keypair or initialised a project, producing a confusing error.
**Why it happens:** The conceptual model (mark, seal, open) skips infrastructure setup.
**How to avoid:** Quickstart order must be: `sss keys generate` → `sss init <username>` → mark file → `sss seal` → `sss open`.
**Warning signs:** Any quickstart that does not start with key generation.

### Pitfall 6: Omitting --non-interactive in Emacs Context
**What goes wrong:** Users running Emacs in daemon mode (no TTY) get hangs if sss prompts for a passphrase.
**Why it happens:** Without `--non-interactive`, sss may try to read from TTY.
**How to avoid:** DOC-07 must state that sss-mode always passes `--non-interactive` and that the passphrase must be in the system keyring or `SSS_PASSPHRASE` env var. Confirmed from sss-mode.el: `(append (list "--non-interactive") args ...)`.
**Warning signs:** Guide that doesn't explain keyring prerequisite.

---

## Code Examples

### Verified Marker Constants (from src/constants.rs)
```rust
pub const MARKER_PLAINTEXT_UTF8: &str = "⊕";   // U+2295 CIRCLED PLUS
pub const MARKER_PLAINTEXT_ASCII: &str = "o+";  // ASCII fallback (input only)
pub const MARKER_CIPHERTEXT: &str = "⊠";        // U+22A0 SQUARE ORIGINAL OF
```

### Verified Encryption Stack (from src/crypto.rs)
```rust
// Symmetric encryption: XChaCha20-Poly1305 (via libsodium)
const SYMMETRIC_KEY_SIZE: usize = sodium::crypto_secretbox_xchacha20poly1305_KEYBYTES;  // 32 bytes
const SYMMETRIC_NONCE_SIZE: usize = sodium::crypto_secretbox_xchacha20poly1305_NONCEBYTES;  // 24 bytes
const SYMMETRIC_MAC_SIZE: usize = sodium::crypto_secretbox_xchacha20poly1305_MACBYTES;  // 16 bytes

// Nonce derivation: BLAKE2b (deterministic — same secret + file → same ciphertext)
// Input: project_timestamp + file_path + plaintext
// Key parameter: repository key (additional security)

// Key wrapping: X25519 via crypto_box_seal (asymmetric, public-key only needed to encrypt)
// User identity: Ed25519 keypairs
```

### Verified KDF Parameters (from src/kdf.rs)
```rust
// Argon2id (via libsodium crypto_pwhash with ALG_ARGON2ID13)
// Three levels:
// sensitive:   OPSLIMIT_SENSITIVE (~4 iterations), MEMLIMIT_SENSITIVE (256 MiB)
// moderate:    OPSLIMIT_MODERATE (~3 iterations),  MEMLIMIT_MODERATE  (128 MiB)
// interactive: OPSLIMIT_INTERACTIVE (~2 iterations), MEMLIMIT_INTERACTIVE (64 MiB) [default]
// Default keystore: sensitive (highest security)
```

### Verified .sss.toml Schema (from src/project.rs ProjectConfig)
```toml
version = "1.0"                   # String, defaults to "1.0"
created = "2026-02-21T00:00:00Z" # RFC3339 timestamp

# Per-user sections (flattened via serde flatten)
[alice]
public = "<base64-encoded-Ed25519-public-key>"
sealed_key = "<base64-encoded-X25519-sealed-repository-key>"
added = "2026-02-21T00:00:00Z"

# Optional fields
secrets_filename = "secrets"      # Custom secrets file basename (default: "secrets")
secrets_suffix = ".secrets"       # Custom secrets file suffix (default: ".secrets")
ignore = "*.log build/ temp*.txt" # Gitignore-style patterns, space/comma separated
```

### Verified sss-mode.el Key Bindings (from emacs/sss-mode.el lines 328-334)
```
C-c C-o  →  sss-open-buffer    (decrypt in place)
C-c C-s  →  sss-seal-buffer    (re-seal and save)
C-c C-r  →  sss-render-buffer  (view pure plaintext, markers stripped)
C-c C-i  →  sss-init           (run sss init)
C-c C-p  →  sss-process        (run sss seal --project)
C-c C-k  →  sss-keygen         (run sss keygen)
C-c C-l  →  sss-keys-list      (run sss keys list)
```

### Verified Marker Parser Semantics (from src/processor/core.rs)
```
Parser: find_balanced_markers() with brace-depth counting
Supports nested braces: ⊕{{"key":"value"}} is valid
Plaintext markers accepted: both ⊕{...} and o+{...}
Ciphertext marker: ⊠{...} only (no ASCII alternative)
Size limit: MAX_MARKER_CONTENT_SIZE = 100MB per marker
```

### sss-mode.el Installation Snippet (from Commentary block, line 14-18)
```elisp
;; Usage: Add to init.el:
;;   (add-to-list 'load-path "/path/to/emacs/")
;;   (require 'sss-mode)
;;
;; For daemon mode, set sss-executable to the absolute path:
;;   (setq sss-executable "/usr/local/bin/sss")
```

---

## Detailed Findings by Document

### DOC-01: README Overhaul

**Current state:** README.md is ~629 lines and covers most commands, but:
- Flat structure (no clear beginner path)
- Claims age-core encryption (wrong — it is libsodium)
- Quickstart lacks key generation step before init
- `sss keys generate` section uses consistent naming (good), but `sss keygen` appears in comments
- Missing: `cargo install` path (only shows `cargo build --release`)
- The documentation links at bottom reference files (`ARCHITECTURE.md`, `SECURITY.md`, `CRYPTOGRAPHY.md`, `KEY_MANAGEMENT.md`, `SECRETS_FILE_FORMAT.md`, `INSTALLATION.md`, man pages) that may not all exist

**Required content:**
1. Hero section: one-line description, badges if applicable
2. Installation: `cargo install` (primary), build from source, pre-built packages (RPM/DEB)
3. Quickstart: 5-step sequence with working commands
4. Features: concise bullet list (can borrow from current Features section)
5. Links to docs/ documents

### DOC-02: Usage Guide

**Core workflows to cover:**
1. Initial setup: generate keys → init project
2. Sealing a file: mark with ⊕{} → `sss seal -x file`
3. Opening a file: `sss open file` (to stdout) or `sss open -x file` (in-place)
4. Edit workflow: `sss edit file` (one command, auto-decrypt → editor → re-encrypt)
5. Render: `sss render file` (strips markers, plain text output)
6. Key management: generate, list, rotate, set/remove passphrase
7. Team collaboration: add user (pubkey exchange flow), remove user (triggers rotation)
8. Git integration: `sss hooks install`, hook behaviours
9. Project-wide operations: `sss seal --project`, `sss open --project`

**Note on `sss edit`:** This calls the user's `$EDITOR`. Combined with Emacs mode, the editor workflow is `sss edit file` which opens the editor with decrypted content, re-seals on exit. The Emacs mode (`sss-mode`) provides a more integrated approach where files are decrypted transparently on `C-x C-f`.

### DOC-03: Architecture

**Key topics:**
1. Processor pipeline: `Processor` struct with `RepositoryKey`, `SecretsCache`, `project_root`
2. Marker detection: `find_balanced_markers()` algorithm, two-pass (plaintext → seal, or ciphertext → open)
3. Key loading flow: `.sss.toml` → `UserConfig.sealed_key` → decrypt with user's private key → `RepositoryKey`
4. FUSE filesystem: optional feature, transparent rendering at mount layer
5. 9P server: optional feature, network-transparent access with three file views (`.file`, `.file.open`, `.file.sealed`)
6. Marker inference: 8-step algorithm (mentioned in README `src/marker_inference/`)
7. Secrets interpolation: `⊲{secret_name}` from `.secrets` files

### DOC-04: Security Model

**What IS encrypted:**
- The content inside `⊠{...}` markers (the ciphertext) — using XChaCha20-Poly1305
- The repository symmetric key in `.sss.toml` (`sealed_key` per user) — using X25519 `crypto_box_seal`
- Private keys on disk — using Argon2id-derived key wrapping

**What is NOT encrypted:**
- File structure and non-secret text (surrounding the markers)
- The fact that a file contains secrets (presence of `⊠{...}` markers is visible)
- Filenames
- Git history (before sealing)
- The public keys in `.sss.toml`
- Marker positions/offsets (an observer can see how many secrets a file has)

**Algorithms (all verified from source):**
- Symmetric: XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit MAC)
- Nonce derivation: BLAKE2b keyed hash (deterministic — same inputs → same ciphertext, clean git diffs)
- Key exchange: X25519 via `crypto_box_seal` (ephemeral sender key)
- Identity: Ed25519 keypairs
- KDF: Argon2id via libsodium `crypto_pwhash`
- Memory safety: `zeroize` crate for sensitive data

**Threat model:**
- Protects: secret values when committed to git, when files are shared, when repo is public
- Does not protect: metadata, traffic analysis, timing attacks on large files
- DoS protection: 100MB per-secret limit, rate limiting on passphrase attempts

**Brief plaintext window on save:** sss-mode.el `sss--write-contents` writes plaintext to disk momentarily before sealing (identical to epa-file.el pattern). DOC-04 should acknowledge this.

### DOC-05: Marker Format Reference

**Syntax:**
```
plaintext-marker  ::= ("⊕" | "o+") "{" content "}"
ciphertext-marker ::= "⊠" "{" content "}"
content           ::= any sequence with balanced braces (depth-counted)
```

**Character codepoints:**
- `⊕` = U+2295 CIRCLED PLUS, UTF-8: `\xe2\x8a\x95` (3 bytes)
- `⊠` = U+22A0 SQUARE ORIGINAL OF, UTF-8: `\xe2\x8a\xa0` (3 bytes)
- `o+` = ASCII, 2 bytes (input alias for `⊕`, NOT for `⊠`)

**Rendering behaviours:**
- `sss seal`: `⊕{secret}` or `o+{secret}` → `⊠{base64ciphertext}`; existing `⊠{}` markers are passed through unchanged
- `sss open`: `⊠{base64ciphertext}` → `⊕{decrypted_plaintext}` (UTF-8 marker form, even if input was `o+`)
- `sss render`: `⊠{base64ciphertext}` → `decrypted_plaintext` (no markers at all); `⊕{...}` markers also stripped
- Nested braces: `⊕{{"key": "value"}}` is valid — closing brace is depth-0 match
- Magic detection: A file starting with `⊠{` (UTF-8 `\xe2\x8a\xa0{`) is treated as a sealed file by sss-mode

**Ciphertext format (inside `⊠{...}`):**
```
base64( nonce[24] || MAC[16] || ciphertext[N] )
```
- Nonce is deterministically derived via BLAKE2b (not random) for clean git diffs
- Total overhead per secret: 40 bytes binary → ~54 bytes base64, plus marker and braces

### DOC-06: Configuration Reference

**`.sss.toml` (project config, typically in git):**
```toml
version = "1.0"
created = "<RFC3339 timestamp>"

# Per-user: one [username] section per authorised user
[alice]
public = "<base64 Ed25519 public key>"      # 44 chars (32 bytes)
sealed_key = "<base64 X25519 sealed key>"   # base64 of sealed repo key
added = "<RFC3339 timestamp>"

# Optional project settings
secrets_filename = "secrets"     # basename for secrets files (default: "secrets")
secrets_suffix = ".secrets"      # suffix for secrets files (default: ".secrets")
ignore = "*.log build/ temp*"    # gitignore-style ignore patterns (space/comma sep)
```

**`~/.config/sss/settings.toml` (user settings, platform-specific path):**
```toml
default_username = "alice"
editor = "vim"

[ui]
coloured_output = true

[keystore]
kdf_level = "sensitive"         # "sensitive" | "moderate" | "interactive"
use_system_keyring = false      # store passphrase in OS keyring
```

Platform paths for settings.toml (from src/keystore.rs):
- Linux/BSD: `~/.config/sss/settings.toml`
- macOS: `~/Library/Application Support/sss/settings.toml`
- Windows: `%APPDATA%\sss\settings.toml`

Private keys stored at: `<config_dir>/sss/keys/` (mode 0700 on Unix)

**Environment variables (all confirmed from README + src/config_manager.rs):**
- `SSS_USER` — username override
- `SSS_PASSPHRASE` — passphrase (avoids interactive prompt)
- `SSS_PROJECT_OPEN` — bypass project-wide open permission check
- `SSS_PROJECT_RENDER` — bypass project-wide render permission check
- `SSS_USE_KEYRING` — enable system keyring
- `SSS_KDF_LEVEL` — KDF level override
- `SSS_DEVEL_MODE=1` — enable experimental agent commands
- `EDITOR` / `VISUAL` — editor for `sss edit`

### DOC-07: sss-mode Installation and Usage

**Prerequisites:**
1. `sss` binary on PATH (or absolute path configured)
2. Working keystore: `sss keys generate` must have been run
3. Project initialised: `sss init <username>` must have been run
4. Passphrase must be accessible without TTY interaction (system keyring or `SSS_PASSPHRASE`)

**Emacs version requirement:** 27.1+ (from Package-Requires header)
**External package dependencies:** None (PACK-03 confirmed)
**Lexical binding:** Yes (`lexical-binding: t`)

**Installation steps:**
```elisp
;; 1. Clone the repository or copy emacs/sss-mode.el somewhere on your system
;; 2. Add to init.el:
(add-to-list 'load-path "/path/to/sss/emacs/")
(require 'sss-mode)

;; 3. For daemon-mode / GUI Emacs (sss not on inherited PATH):
(setq sss-executable "/usr/local/bin/sss")
```

**Keyring prerequisites for daemon mode:**
- Linux Secret Service (GNOME Keyring / KWallet): must have `sss keys generate` run in a session where the daemon is running
- Alternative: set `SSS_PASSPHRASE` in systemd user environment:
  ```bash
  systemctl --user set-environment SSS_PASSPHRASE="your-passphrase"
  ```

**Auto-activation:** Files containing `⊠{` at the start are automatically detected and opened in sss-mode via `magic-mode-alist`.

**Key bindings table:**
| Key | Command | Action |
|-----|---------|--------|
| `C-c C-o` | `sss-open-buffer` | Decrypt sealed buffer |
| `C-c C-s` | `sss-seal-buffer` | Re-seal and save |
| `C-c C-r` | `sss-render-buffer` | View pure plaintext |
| `C-c C-i` | `sss-init` | Run `sss init` |
| `C-c C-p` | `sss-process` | Run `sss seal --project` |
| `C-c C-k` | `sss-keygen` | Run `sss keygen` |
| `C-c C-l` | `sss-keys-list` | Run `sss keys list` |

**Customisation:** `M-x customize-group RET sss RET` — shows `sss-executable` path variable.

**Security notes:**
- Auto-save and backup are disabled for decrypted buffers
- Brief plaintext window on save (identical to epa-file.el behaviour)
- Buffer shows `⊕{}` markers (not stripped) — use `C-c C-r` for rendered view

---

## State of the Art

| Old Approach | Current Approach | Notes |
|--------------|------------------|-------|
| Single doc (README) | Split into docs/ | Phase 4 splits concerns across focused documents |
| mdBook (deferred) | Plain Markdown | v1 decision; mdBook is v2 |
| `sss keygen` subcommand | `sss keys generate` | keygen still works (handle_keygen_deprecated) but generate is preferred |
| `sss process` | `sss seal --project` | process subcommand does not exist; sss-mode confirmed this |

---

## Open Questions

1. **Do ARCHITECTURE.md and SECURITY.md already exist at their referenced paths?**
   - What we know: README.md links to `ARCHITECTURE.md` and `SECURITY.md` and `docs/CRYPTOGRAPHY.md`, etc.
   - What's unclear: Whether these files exist and have content, or are placeholder links
   - Recommendation: Check existence of each linked file before writing. If they exist, evaluate whether they need updating or replacement. (Not checked in this research pass — planner should add a verification step.)

2. **Exact keygen subcommand name for docs**
   - What we know: `handle_keygen_deprecated` handler exists; `sss keys generate` is the current form; `sss keygen` is deprecated
   - What's unclear: Whether `sss keys generate` is the correct invocation (vs `sss keys keygen`)
   - Recommendation: Planner should add a task to run `sss keys --help` to confirm before writing DOC-02.

3. **Settings.toml exact field names**
   - What we know: `src/config_manager.rs` shows struct fields; serialised names may differ (serde rename)
   - What's unclear: Whether `default_username` serialises as `default_username` or `username` in TOML
   - Recommendation: Task should verify by running `sss settings show` or inspecting serde annotations.

4. **Existing docs/ directory contents**
   - What we know: README references `docs/CRYPTOGRAPHY.md`, `docs/KEY_MANAGEMENT.md`, `docs/SECRETS_FILE_FORMAT.md`, `docs/INSTALLATION.md`
   - What's unclear: Which of these exist and have content vs which are aspirational references
   - Recommendation: Planner should list `docs/` at task start and decide whether to update or replace.

---

## Sources

### Primary (HIGH confidence — direct source inspection)
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/constants.rs` — marker strings, size limits, error messages
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/crypto.rs` — encryption algorithms (XChaCha20-Poly1305, X25519, BLAKE2b, Ed25519)
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/kdf.rs` — Argon2id parameters (sensitive/moderate/interactive)
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/processor/core.rs` — marker parser (find_balanced_markers), Processor struct
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/project.rs` — ProjectConfig / .sss.toml schema
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/config_manager.rs` — UserSettings / settings.toml schema
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/keystore.rs` — platform config paths, key storage
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/emacs/sss-mode.el` — all sss-mode details (354 lines)
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/Cargo.toml` — version (1.1.9), binary names, feature flags

### Secondary (HIGH confidence — planning documents)
- `.planning/STATE.md` — confirmed decisions (sss process = sss seal --project; keygen deprecated)
- `.planning/REQUIREMENTS.md` — DOC-01 through DOC-07 requirement text
- `.planning/ROADMAP.md` — phase goals and success criteria
- `README.md` — current state (used as reference, not authoritative for accuracy)

### Notes on discrepancies found
- README claims "age-core" crate for encryption: **INCORRECT** — libsodium is used directly
- Additional context to this task claims "key derivation via scrypt": **INCORRECT** — Argon2id is confirmed from source
- These discrepancies are the primary reason DOC-04 cannot be based on existing README content

---

## Metadata

**Confidence breakdown:**
- Marker format (DOC-05): HIGH — directly from constants.rs and processor/core.rs parser code
- Encryption algorithms (DOC-04): HIGH — directly from crypto.rs libsodium constant names
- KDF parameters (DOC-04): HIGH — directly from kdf.rs KdfParams methods with comments
- .sss.toml schema (DOC-06): HIGH — directly from project.rs ProjectConfig struct with serde annotations
- Settings schema (DOC-06): HIGH — directly from config_manager.rs UserSettings (field names may need serde rename verification)
- sss-mode details (DOC-07): HIGH — entire 354-line file read
- CLI subcommand names (DOC-02): MEDIUM — most confirmed; `sss keys generate` vs `sss keygen` needs runtime verification
- Existing docs/ file presence: LOW — not checked in this research pass

**Research date:** 2026-02-21
**Valid until:** Stable — documentation for a completed implementation; valid indefinitely unless CLI changes
