# sss Architecture

This document explains how sss works internally. It is aimed at contributors and advanced users who want to understand the system rather than just use it. For the protocol specification (marker wire format, cryptographic primitives), see the root-level [ARCHITECTURE.md](../ARCHITECTURE.md). For marker syntax details, see [marker-format.md](marker-format.md) (if present) or [marker-design.md](marker-design.md).

---

## 1. Overview

sss is structured as a processing pipeline. The fundamental operation is:

```
Input file  →  Marker detection  →  Transformation (seal / open / render)  →  Output
     ^                |
     |         Scanner (--project)
     |                |
     +--- Project directory tree
```

The core of the pipeline is the **Processor**, which holds the decrypted repository key and performs marker-by-marker transformations on file content. Everything else — the CLI, FUSE filesystem, and 9P server — feeds files into the Processor and writes the output back.

The three transformation modes are:

| Mode | Input markers | Output |
|------|--------------|--------|
| **seal** | `⊕{plaintext}` or `o+{plaintext}` | `⊠{base64ciphertext}` |
| **open** | `⊠{base64ciphertext}` | `⊕{plaintext}` |
| **render** | `⊠{base64ciphertext}` | bare plaintext (markers stripped) |

---

## 2. Processor Pipeline

### 2.1 The Processor Struct

```
src/processor/core.rs — Processor
```

```
pub struct Processor {
    repository_key: RepositoryKey,   // Symmetric XChaCha20-Poly1305 key
    secrets_cache: CacheWrapper<SecretsCache>,  // Cached .secrets file data
    project_root: Option<PathBuf>,   // Root dir for relative path computation
    project_created: String,         // ISO-8601 timestamp (for deterministic nonces)
}
```

The Processor is constructed after key loading (see Section 4). It does not read `.sss.toml` itself — that is handled by the command layer.

### 2.2 Per-file Operation

```
File path
    │
    ▼
 fs::metadata (size check — reject if > MAX_FILE_SIZE = 100 MB)
    │
    ▼
 fs::read_to_string (buffered I/O)
    │
    ▼
 make_relative_path (compute ./rel/path for deterministic nonce)
    │
    ▼
 process_content_with_path
    │
    ├── [.secrets file?] ──→ process_secrets_file_content (whole-file encrypt/decrypt)
    │
    └── [regular file]
         │
         ├── find_plaintext_markers  → encrypt_content_with_path  (seal)
         ├── find_ciphertext_markers → decrypt_content             (open)
         └── [neither]               → pass through unchanged
```

### 2.3 Output Reassembly

The Processor never works on a file as a whole string replacement. Instead it:

1. Collects all `MarkerMatch` positions (start byte, end byte, content string).
2. Iterates through markers in order, copying unchanged text between markers verbatim.
3. Replaces each marker with its transformed version.
4. Appends any trailing content after the last marker.

This approach preserves every byte outside marker boundaries exactly, including mixed line endings, trailing newlines, and binary-safe content adjacent to markers.

---

## 3. Marker Detection (`find_balanced_markers`)

```
src/processor/core.rs — find_balanced_markers
```

The marker parser is a **single-pass brace-depth counter**. It handles nested braces correctly — for example, `⊕{{"key":"value"}}` or `o+{a:{b:{}}}`.

### 3.1 Recognised Prefixes

| Prefix | Meaning |
|--------|---------|
| `⊕` (U+2295) | Plaintext open marker (canonical) |
| `o+` | Plaintext open marker (ASCII alias) |
| `⊠` (U+22A0) | Ciphertext sealed marker |

The secrets interpolation marker `⊲` (U+22B2) / `<` alias is handled separately by `normalize_secrets_markers` and `interpolate_secrets`, not by this parser.

### 3.2 Algorithm

```
byte_pos = 0
while byte_pos < len(file):
    for each prefix in [checked prefixes]:
        if file[byte_pos..] starts with prefix and next char is '{':
            record marker_start = byte_pos
            advance past prefix and '{'
            depth = 1
            for each char from current position:
                if char == '{': depth += 1
                if char == '}': depth -= 1
                if depth == 0:
                    record marker_end = current position + 1
                    emit MarkerMatch { start, end, content }
                    advance byte_pos to marker_end
                    break
    else:
        advance byte_pos by one UTF-8 character
```

### 3.3 Size Limit

Marker content exceeding `MAX_MARKER_CONTENT_SIZE` (100 MB) is skipped with a warning — the original marker bytes are emitted unchanged. This prevents DoS via crafted input.

---

## 4. Key Loading Flow

Before any Processor can be constructed, the user's private key must be loaded and used to unseal the repository key from `.sss.toml`.

```
.sss.toml                ~/.config/sss/keys/
(project config)         (user keystore)
     │                         │
     │  sealed_key (per user)  │  encrypted_secret_key (per user)
     │                         │
     ▼                         ▼
  parse TOML              load StoredKeyPair
  find user section       derive passphrase (KDF / keyring)
       │                  decrypt secret key
       │                         │
       └──────── X25519 ─────────┘
                 crypto_box_seal_open
                         │
                         ▼
                   RepositoryKey
                         │
                         ▼
                     Processor
```

**Step-by-step:**

1. **Read `.sss.toml`** — upward search from `cwd` via `find_project_root()`.
2. **Identify the current user** — from `--user` flag, then `SSS_USER` environment variable, then `default_username` in `~/.config/sss/settings.toml`.
3. **Load the user's keystore entry** — `~/.config/sss/keys/<uuid>.json` (a `StoredKeyPair` in JSON).
4. **Obtain the private key** — decrypt `encrypted_secret_key` using a passphrase. The passphrase is retrieved from:
   - System keyring (GNOME Keyring on Linux, macOS Keychain)
   - `SSS_PASSPHRASE` environment variable
   - Interactive TTY prompt (unless `--non-interactive` is active)
5. **Unseal the repository key** — `crypto_box_seal_open(sealed_key, public_key, secret_key)` using libsodium's X25519 anonymous box. This yields the 32-byte `RepositoryKey`.
6. **Construct Processor** — `Processor::new_with_context(repository_key, project_root, project_created)`.

The `RepositoryKey` is a `[u8; 32]` wrapped in a zeroize-on-drop struct. It is never written to disk after derivation.

---

## 5. Marker Inference (8-Step Algorithm)

```
src/marker_inference/
```

Marker inference solves the problem of **round-trip editing** via the FUSE or 9P filesystems. When a user opens a file through the virtual filesystem, they see rendered plaintext (no markers). When they save, sss must reconstruct which regions should be encrypted.

The `infer_markers(source, edited)` function:

```
source: original file with ⊕{} markers
edited: user's modified rendered text (no markers)
```

### 8 Steps

| Step | Module | Description |
|------|--------|-------------|
| 1 | `parser.rs` | Parse markers from source; extract rendered form |
| 2 | `diff.rs` | Compute Myers diff between rendered source and edited text |
| 3 | `validator.rs` | Validate any user-inserted markers in edited text |
| 4 | `mapper.rs` | Map change positions back to source coordinates |
| 5 | `expander.rs` | Apply 5 expansion rules to determine new marker boundaries |
| 6 | `propagator.rs` | Mark all duplicate instances of sensitive content (Aho-Corasick) |
| 7 | `delimiter.rs` | Ensure paired delimiters (quotes, brackets) remain consistently marked |
| 8 | `reconstructor.rs` | Build output string with canonical `⊕{}` markers |

### 5 Expansion Rules (Step 5)

| Rule | Trigger | Effect |
|------|---------|--------|
| 1 | Change spans multiple markers | Mark entire span as one region |
| 2 | Change adjacent to one marker | Expand that marker to cover the change |
| 3 | Change adjacent to multiple markers | Merge with left marker (left-bias) |
| 4 | Change affects only one of separate markers | Preserve separation |
| 5 | Change not adjacent to any marker | Leave to propagation (Rule 6) |

The algorithm is **security-first**: when uncertain, it over-marks rather than risking leakage. See `src/marker_inference/README.md` for the full specification.

---

## 6. Secrets Interpolation

```
src/secrets.rs
```

The `⊲{secret_name}` marker (Unicode U+22B2; also written `<{secret_name}` in ASCII) is a **lookup marker**. It is resolved to a value from a `.secrets` file during `render` operations only — not during `seal` or `open`.

### Resolution Order

1. Check for a file-specific secrets file: `<filename>.secrets` in the project root.
2. Fall back to the generic `secrets` file in the project root.

### File Format

```
api_key: my-secret-value
database_url: postgresql://user:pass@host/db

# Multi-line value (pipe syntax):
private_key: |
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA...
  -----END RSA PRIVATE KEY-----
```

### Interpolation Timing

```
seal:   ⊲{secret} → unchanged  (stored as reference, not resolved value)
open:   ⊲{secret} → unchanged  (stored as reference)
render: ⊲{secret} → resolved value
```

This means secrets references are never encrypted — only the `.secrets` file itself can be sealed.

### Secrets Files

Files ending in `.secrets` or named exactly `secrets` receive special treatment: the Processor encrypts or decrypts the **entire file content** as a single ciphertext blob, rather than scanning for markers inside. This prevents accidental exposure of the key–value structure.

---

## 7. Project Scanner

```
src/scanner.rs — FileScanner
```

The `--project` flag on `sss seal`, `sss open`, and `sss render` invokes the project scanner to walk the directory tree.

```
FileScanner {
    pattern_regex: Regex,             // Detect ⊕, o+, ⊠ patterns
    ignored_dirs: HashSet<String>,    // .git, .svn, node_modules, target, .cargo
    allowed_extensions: Option,       // Optional extension filter
    ignore_patterns: Option<GlobSet>, // From .sss.toml ignore field
    negation_patterns: Option<GlobSet>, // ! prefixed patterns
    respect_project_boundaries: bool, // Stop at nested .sss.toml
}
```

### Ignore Pattern Syntax

The `ignore` field in `.sss.toml` accepts gitignore-style glob patterns:

```toml
[project]
ignore = "*.log !important.log dist/ build/"
```

Patterns separated by whitespace. Prefix `!` negates a pattern (always include, even if an earlier pattern would exclude).

---

## 8. FUSE Filesystem (Optional)

```
src/fuse_fs.rs
Feature gate: --features fuse (build-time)
CLI: sss mount <mountpoint>
```

The FUSE filesystem mounts a project directory and presents files in **rendered form** (all `⊠{}` markers decrypted, markers stripped). The underlying directory is never modified.

### File Views

Files are presented at the mountpoint as if they were decrypted. Applications read and write through the FUSE layer; encryption and decryption happen transparently.

The filesystem also exposes an overlay directory for direct access to the underlying sealed files (for tools such as `git`).

### `sss git` Command

`sss git` is a passthrough that runs git against the **underlying sealed files**, not the FUSE-rendered view. This ensures git tracks the encrypted state and avoids committing plaintext.

### Read-Write Operation

On **write** to the FUSE mountpoint, the filesystem:

1. Receives the user's edited plaintext.
2. Calls `marker_inference::infer_markers(original_sealed, rendered_edit)` to reconstruct marker positions.
3. Encrypts the result via the Processor.
4. Writes the sealed content back to the underlying file.

### Debug Logging

Set `SSS_FUSE_DEBUG=1` to enable verbose per-operation logging including thread IDs and PIDs — useful for diagnosing concurrency issues.

---

## 9. 9P Server (Optional)

```
src/ninep_fs.rs
Feature gate: --features ninep (build-time)
CLI: sss serve9p <address>
```

The 9P server provides network-transparent access via the Plan 9 filesystem protocol (9P2000.L). It is implemented as an async tokio server using the `rs9p` library.

### File Views

Different views of each encrypted file are exposed through naming conventions:

| Filename | Content |
|----------|---------|
| `file` | Rendered view — fully decrypted, no markers |
| `file.open` | Opened form — decrypted with `⊕{}` markers visible |
| `file.sealed` | Sealed form — raw `⊠{}` content as stored on disk |

### Mounting

```bash
# Start server
sss serve9p tcp:0.0.0.0:564

# Mount on Linux (v9fs kernel module)
mount -t 9p -o trans=tcp,port=564 127.0.0.1 /mnt/project

# Mount on Plan 9 / 9front
9fs tcp!server!564
```

### TCP and Unix Socket Support

The server accepts both TCP addresses (`tcp:host:port`) and Unix domain sockets (`unix:/path/to/socket`).

---

## 10. Module Map

```
sss/src/
├── main.rs                — CLI entry point, argument parsing (clap)
├── commands/              — Subcommand implementations
│   ├── process.rs         — seal, open, render operations
│   ├── project.rs         — project init, project-wide operations
│   ├── mount.rs           — FUSE mount command
│   ├── ninep.rs           — 9P server command
│   └── utils.rs           — Shared CLI utilities
│
├── processor/             — Core transformation engine
│   └── core.rs            — Processor struct, find_balanced_markers, seal/open/render
│
├── marker_inference/      — Intelligent marker preservation for FUSE/9P writes
│   ├── mod.rs             — infer_markers() entry point
│   ├── parser.rs          — Step 1: parse markers from source
│   ├── diff.rs            — Step 2: Myers diff (similar crate)
│   ├── validator.rs       — Step 3: validate user-inserted markers
│   ├── mapper.rs          — Step 4: map changes to source positions
│   ├── expander.rs        — Step 5: 5 expansion rules
│   ├── propagator.rs      — Step 6: Aho-Corasick content propagation
│   ├── delimiter.rs       — Step 7: paired delimiter validation
│   └── reconstructor.rs   — Step 8: output reconstruction
│
├── crypto.rs              — RepositoryKey, KeyPair, XChaCha20-Poly1305 encrypt/decrypt
├── kdf.rs                 — Argon2id key derivation (passphrase → decryption key)
├── keystore.rs            — StoredKeyPair, ~/.config/sss/keys/ management
├── keyring_support.rs     — System keyring integration (libsecret / macOS Keychain)
├── keyring_manager.rs     — Keyring abstraction layer
├── config.rs              — find_project_root(), load_project_config()
├── config_manager.rs      — Settings file (~/.config/sss/settings.toml)
├── project.rs             — ProjectConfig (.sss.toml parsing)
├── scanner.rs             — FileScanner (project-wide file discovery)
├── secrets.rs             — Secrets interpolation, SecretsCache, .secrets file parsing
│
├── fuse_fs.rs             — FUSE filesystem implementation (feature = "fuse")
├── fuse/                  — FUSE helper modules
├── ninep_fs.rs            — 9P server implementation (feature = "ninep")
│
├── audit_log.rs           — Audit trail for key operations
├── rotation.rs            — Key rotation logic
├── merge.rs               — Smart content merging utilities
├── validation.rs          — Input validation helpers
├── secure_memory.rs       — Zeroize-on-drop memory wrappers
├── error.rs               — Error types
├── error_helpers.rs       — Base64 decode, error formatting
├── constants.rs           — MAX_FILE_SIZE, MAX_MARKER_CONTENT_SIZE, etc.
└── lib.rs                 — Library crate root (re-exports public API)
```

### Grouping by Layer

| Layer | Modules |
|-------|---------|
| CLI | `main.rs`, `commands/` |
| Core pipeline | `processor/core.rs`, `crypto.rs`, `kdf.rs` |
| Marker inference | `marker_inference/` |
| Key management | `keystore.rs`, `keyring_support.rs`, `keyring_manager.rs` |
| Project/config | `config.rs`, `config_manager.rs`, `project.rs`, `scanner.rs` |
| Secrets | `secrets.rs` |
| Optional (FUSE) | `fuse_fs.rs`, `fuse/` |
| Optional (9P) | `ninep_fs.rs` |
| Utilities | `audit_log.rs`, `rotation.rs`, `merge.rs`, `validation.rs`, `secure_memory.rs`, `error.rs`, `constants.rs` |
