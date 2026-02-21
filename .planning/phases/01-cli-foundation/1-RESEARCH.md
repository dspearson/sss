# Phase 1: CLI Foundation - Research

**Researched:** 2026-02-21
**Domain:** Rust CLI (clap 4.5, anyhow 1.0), existing sss command handlers
**Confidence:** HIGH — all findings are from direct source code inspection

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| CLI-01 | `sss render` and `sss open` support stdout output for piping to Emacs | ALREADY SATISFIED: both commands default to stdout when `--in-place` is absent. See `process_file_or_stdin` in `src/commands/process.rs`. |
| CLI-02 | `sss seal --in-place` works for re-sealing an opened file after editing | ALREADY SATISFIED: `sss seal` has `--in-place` / `-x` flag, wired through `process_file_or_stdin`. |

</phase_requirements>

---

## Summary

Phase 1 is almost entirely an audit and validation phase, not a development phase. The source code shows that both required CLI interfaces are already implemented and wired into the binary.

`sss render FILE` (without `--in-place`) calls `process_file_or_stdin(sub_matches, "render")` in `src/commands/process.rs`. When `in_place` is false, it does `print!("{}", output)` followed by `io::stdout().flush()` — decrypted plaintext goes to stdout with no other content mixed in. The same is true for `sss open FILE`.

`sss seal --in-place FILE` calls `process_file_or_stdin(sub_matches, "seal")`. When `in_place` is true, it does `fs::write(&file_path, &output)` then `eprintln!("File processed in-place: {:?}", file_path)` — the file is rewritten in place and the confirmation message goes to stderr, not stdout.

Exit codes are correct by construction: `main()` returns `Result<()>`. When any command handler returns `Err`, Rust's `Termination` trait prints the error to stderr via anyhow's Debug output and exits with code 1. There is no `std::process::exit()` call in `src/main.rs`. All authentication failures in `src/config.rs` (keypair not found, not authorized, config missing) propagate as `anyhow::Error` through the `?` operator up to `main`, which writes them to stderr and exits 1.

The only real work in Phase 1 is:
1. Confirm the marker byte sequence from `src/constants.rs` (done here — see below).
2. Confirm the --non-interactive flag behavior for Emacs use.
3. Write and run smoke tests to validate all three success criteria from the roadmap.
4. Confirm that the in-place confirmation message (`eprintln!`) goes to stderr (not stdout), so piping is clean.

**Primary recommendation:** Phase 1 execution is smoke testing + documentation of what's verified, not new feature development. There is a small risk around the interactive passphrase prompt: if a user's key is password-protected and `--non-interactive` is not passed, `sss render` will block on a TTY prompt. Emacs must invoke sss with `--non-interactive` to prevent that.

---

## Standard Stack

### Core (already in use — no changes)

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| clap | 4.5.47 | CLI argument parsing | `render`, `seal`, `open` subcommands with `--in-place` / `-x` already defined |
| anyhow | 1.0.99 | Error propagation | `fn main() -> Result<()>` — errors go to stderr, exit 1 automatically |
| libsodium-sys | 0.2 | Cryptography | XChaCha20-Poly1305 for all encryption |
| keyring | 3.2 | System keyring access | Used for `in_keyring` key storage path |

### No new dependencies needed for Phase 1

Phase 1 is verification and smoke testing. No new Cargo dependencies are required. If integration tests are added, they use the existing `tempfile` (3.21.0) and `serial_test` patterns already in the codebase.

---

## Architecture Patterns

### Existing Command Handler Structure

All three relevant commands share a single implementation path:

```
main.rs:
  Some(("render", sub_matches)) => handle_render(&matches, sub_matches)
  Some(("seal",   sub_matches)) => handle_seal(&matches, sub_matches)
  Some(("open",   sub_matches)) => handle_open(&matches, sub_matches)

src/commands/process.rs:
  handle_render -> process_file_or_stdin(sub_matches, "render")
  handle_seal   -> process_file_or_stdin(sub_matches, "seal")
  handle_open   -> process_file_or_stdin(sub_matches, "open")
```

`process_file_or_stdin` is the unified implementation at lines 211–263 of `src/commands/process.rs`. Key behavior:

```rust
// src/commands/process.rs lines 247-262
let output = match operation {
    "seal"   => processor.seal_content_with_path(&content, &file_path)?,
    "open"   => processor.open_content_with_path(&content, &file_path)?,
    "render" => processor.decrypt_to_raw_with_path(&content, &file_path)?,
    _ => unreachable!(),
};

if in_place {
    fs::write(&file_path, &output)?;
    eprintln!("File processed in-place: {:?}", file_path);  // <-- stderr
} else {
    print!("{}", output);          // <-- stdout
    io::stdout().flush()?;
}
```

This is exactly what Emacs needs: stdout output for piping, clean stderr for diagnostics.

### CLI Flag Definitions (confirmed from main.rs)

`sss render` subcommand (lines 633–655 of `src/main.rs`):
- `file` positional arg: required unless `--project`; accepts `-` for stdin
- `--in-place` / `-x`: bool flag; when absent, output goes to stdout
- `--project`: recursively process all files

`sss seal` subcommand (lines 587–609 of `src/main.rs`):
- `file` positional arg: required unless `--project`; accepts `-` for stdin
- `--in-place` / `-x`: bool flag; when set, rewrites file in place

`sss open` subcommand (lines 610–632 of `src/main.rs`):
- Same structure as `render` and `seal`

### Error Propagation (exit codes)

`main()` signature: `fn main() -> Result<()>` (line 671 of `src/main.rs`, using `anyhow::Result`).

There is NO `std::process::exit()` call in `src/main.rs`. All command handlers return `anyhow::Result<()>`. When a handler returns `Err(e)`:

- Rust's `Termination` trait for `Result<(), E>` prints `"Error: {e:?}"` to stderr
- Exits with code 1

anyhow's `Debug` output includes the full error chain separated by "Caused by:".

Authentication failure path (tracked through source):
1. `handle_render` → `process_file_or_stdin` → `create_processor_from_project_config()`
2. → `config::load_project_config_with_repository_key()`
3. → `load_project_config_internal()` → `load_keypair_with_password_retry()`
4. If no keypair matches project: returns `Err(anyhow!("None of your keypairs are authorized for this project..."))`
5. Propagates via `?` to `main()` → stderr + exit 1

Specific error message for auth failure (from `src/config.rs` line 277–286):
```
None of your keypairs are authorized for this project.
Available users: <list>
Your current key: <pubkey>

Tip: You may need to:
  1. Ask a project admin to add your key: sss user add <username> <your-pubkey>
  2. Or switch to a different keypair: sss keys current <key-id>
```

This message goes to stderr via anyhow's Termination output (prefixed with "Error: ").

---

## Confirmed Marker Constants

From `src/constants.rs` (lines 6–8):

```rust
pub const MARKER_PLAINTEXT_UTF8: &str = "⊕";   // U+2295, UTF-8: e2 8a 95
pub const MARKER_CIPHERTEXT: &str     = "⊠";   // U+2220, UTF-8: e2 8a a0
pub const MARKER_PLAINTEXT_ASCII: &str = "o+";  // ASCII fallback
```

A sealed file marker begins with `⊠{` — the MARKER_CIPHERTEXT character immediately followed by `{`.

**Exact UTF-8 byte sequence for sealed-file detection:**
- `⊠` = `\xe2\x8a\xa0` (3 bytes)
- `{` = `\x7b` (1 byte)
- Full marker start: `\xe2\x8a\xa0\x7b` (4 bytes)

This is verified from `src/commands/process.rs` line 564:
```rust
fn has_sss_markers(content: &str) -> bool {
    content.contains("⊠{") || content.contains("⊕{") || ...
}
```

The Emacs detection predicate should scan for `⊠{` (the string, not a char-by-char sequence) since the file is UTF-8 text. In Emacs Lisp, the literal string `"⊠{"` or the regexp `"\xe2\x8aa0{"`  works. The prior research codebase analysis has a minor error: U+2295 is `⊕` (CIRCLED PLUS), not U+2220. U+2220 is `∠` (ANGLE). The MARKER_CIPHERTEXT `⊠` is actually U+22A0 (SQUARED TIMES). The exact bytes are what matters for Emacs detection: `\xe2\x8a\xa0`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Stdout vs file output | Custom output routing | Existing `process_file_or_stdin` | Already handles both paths correctly |
| Exit code on error | Manual `process::exit` calls | anyhow + `fn main() -> Result<()>` | Already in place; Rust Termination trait handles it |
| Marker constants | Hardcoded strings | `constants::MARKER_CIPHERTEXT` | Single source of truth already defined |

---

## Common Pitfalls

### Pitfall 1: Interactive Passphrase Prompt Blocking Emacs

**What goes wrong:** If the user's key is password-protected and `--non-interactive` is not used, `sss render` will block waiting for a TTY passphrase prompt. Emacs using `call-process` will hang.

**Why it happens:** `load_keypair_with_password_retry()` in `src/config.rs` calls `get_passphrase_or_prompt()`. Without `SSS_NONINTERACTIVE=1` or `--non-interactive`, this calls `rpassword::prompt_password()` which blocks on stdin.

**How to avoid:** Emacs must invoke sss with `--non-interactive`. This causes `get_passphrase_or_prompt` to return `Err("Non-interactive mode enabled but SSS_PASSPHRASE environment variable is not set")` if no keyring or passwordless key is available. That Err propagates to stderr + exit 1 — a visible failure, not a hang.

**Warning signs:** `sss render FILE` hangs indefinitely when run from a subprocess without a TTY.

### Pitfall 2: stdout Contamination from Informational Messages

**What goes wrong:** A message printed via `println!` (stdout) instead of `eprintln!` (stderr) during processing would corrupt the piped plaintext that Emacs reads.

**Current state (VERIFIED CLEAN):** All informational messages in `process_file_or_stdin` use `eprintln!`. The only `print!` call is `print!("{}", output)` — the actual decrypted content. This is safe. However, upstream in `config.rs` line 251, there is an `eprintln!("Current keypair not found in project, trying other available keys...")` — this is also stderr (eprintln), so safe.

**Warning signs:** Any future change that adds `println!` to a code path called from `handle_render` or `handle_seal`.

### Pitfall 3: The `--in-place` Confirmation Message Goes to Stderr

**What goes wrong:** Someone might expect the in-place confirmation to be suppressible or wonder why it shows up in terminal output.

**Current state:** `eprintln!("File processed in-place: {:?}", file_path)` — correctly on stderr. Not a problem; just worth documenting so Emacs integration knows not to capture or check it.

### Pitfall 4: Missing Project Config

**What goes wrong:** Running `sss render FILE` or `sss seal --in-place FILE` outside an sss project directory (no `.sss.toml` in path ancestors) returns a non-zero exit with an error message. Emacs integration must be tested with a real project setup.

**Error message:** `"No project configuration found at ... Run 'sss init' to create one."` — goes to stderr, exit 1.

### Pitfall 5: Marker Unicode Codepoint Error in Prior Research

**What:** The prior SUMMARY.md states MARKER_CIPHERTEXT is `U+2220`. This is incorrect. U+2220 is `∠` (ANGLE). The actual codepoint is U+22A0 (SQUARED TIMES, `⊠`). The UTF-8 encoding `\xe2\x8a\xa0` is correct in both cases as U+22A0 encodes to `e2 8a a0`.

**Impact:** Zero impact on implementation — the literal string `"⊠{"` is the right thing to use in Emacs Lisp detection. Do not use the codepoint number directly.

---

## Code Examples

### Correct invocation pattern for Emacs (verified against source)

For reading decrypted content from a sealed file:
```
sss --non-interactive render /path/to/file.sss
```
- stdout: decrypted plaintext (no markers)
- stderr: empty on success; error message on failure
- exit 0: success
- exit 1: failure (auth, no project, file not found, etc.)

For re-sealing after edit:
```
sss --non-interactive seal --in-place /path/to/file.sss
```
- stdout: empty
- stderr: `"File processed in-place: ..."` on success; error on failure
- exit 0: success
- exit 1: failure

For opening with markers preserved (sss-mode "open" display mode):
```
sss --non-interactive open /path/to/file.sss
```
- stdout: decrypted plaintext WITH `⊕{...}` markers visible
- stderr: empty on success; error message on failure
- exit 0: success
- exit 1: failure

### Confirmed marker detection (from src/commands/process.rs has_sss_markers)

```rust
content.contains("⊠{")  // sealed file has this
content.contains("⊕{")  // open file has this
```

In Emacs Lisp for `magic-mode-alist` predicate:
```elisp
(defun sss--sealed-file-p ()
  "Return non-nil if the current buffer contains a sealed SSS file."
  (save-excursion
    (goto-char (point-min))
    (search-forward "⊠{" nil t)))
```

---

## State of the Art

| Claim | Status | Evidence |
|-------|--------|---------|
| `sss render FILE` outputs to stdout | CONFIRMED | `process_file_or_stdin` line 258: `print!("{}", output)` |
| `sss render FILE` exits 0 on success | CONFIRMED | `fn main() -> Result<()>` — Ok(()) → exit 0 |
| `sss render FILE` exits non-zero on auth failure | CONFIRMED | Auth errors propagate as anyhow::Err → stderr + exit 1 |
| `sss seal --in-place FILE` rewrites file | CONFIRMED | `process_file_or_stdin` line 254–255: `fs::write` |
| `sss seal --in-place FILE` exits 0 on success | CONFIRMED | Same mechanism |
| `sss seal --in-place FILE` keeps stdout clean | CONFIRMED | In-place confirmation uses `eprintln!` (stderr) |
| Sealed marker: `⊠{` (U+22A0 + `{`) | CONFIRMED | `src/constants.rs` line 8: `pub const MARKER_CIPHERTEXT: &str = "⊠"` |
| UTF-8 bytes for sealed marker | CONFIRMED | `⊠` = `\xe2\x8a\xa0`, `{` = `\x7b` |
| `--non-interactive` prevents TTY prompt | CONFIRMED | `get_passphrase_or_prompt` checks `SSS_NONINTERACTIVE` env var |

---

## Open Questions

1. **Should Phase 1 add integration tests?**
   - What we know: no integration test for `sss render FILE` stdout behavior currently exists in the test files listed in git status.
   - What's unclear: whether the roadmap intends Phase 1 to only verify (manual smoke test) or also codify verification as automated tests.
   - Recommendation: Add at least one integration test that invokes the binary and checks stdout/stderr/exit code. This is the correct artifact to prove the success criteria.

2. **Should `--non-interactive` be documented as required for Emacs?**
   - What we know: without it, password-protected keys cause a blocking TTY prompt.
   - What's unclear: whether the existing documentation says anything about this.
   - Recommendation: Phase 1 should confirm this is documented in the sss-mode guide (or flag it for Phase 4 documentation).

3. **Does `sss open` also support stdout (for Emacs "open" display mode)?**
   - Status: CONFIRMED. Same `process_file_or_stdin` path with operation `"open"`. Output is `print!("{}", output)` when `in_place` is false.

---

## Sources

### Primary (HIGH confidence — direct source code inspection)

- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/constants.rs` — marker constants verified
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/main.rs` — CLI subcommand definitions, error propagation
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/commands/process.rs` — `process_file_or_stdin`, stdout/stderr behavior
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/config.rs` — auth failure error messages, passphrase prompt logic
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/src/keystore.rs` — `get_passphrase_or_prompt`, `SSS_NONINTERACTIVE` check
- `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/Cargo.toml` — dependency versions confirmed

### Secondary (MEDIUM confidence)

- Rust standard library documentation: `fn main() -> Result<()>` exit code behavior via `std::process::Termination` trait — anyhow 1.x Debug output and exit code 1 on Err.

---

## Metadata

**Confidence breakdown:**
- CLI interface (render/seal/open): HIGH — read from source, confirmed with grep
- Exit code behavior: HIGH — standard Rust Termination + no custom exit() in main
- Marker byte sequence: HIGH — read directly from constants.rs, verified with Python
- Non-interactive behavior: HIGH — read from keystore.rs get_passphrase_or_prompt
- Auth error messages: HIGH — read from config.rs load_project_config_internal

**Research date:** 2026-02-21
**Valid until:** Until any of the following files change: `src/main.rs`, `src/commands/process.rs`, `src/constants.rs`, `src/config.rs`, `src/keystore.rs`

---

## Key Insight for Planner

**Phase 1 requires zero new Rust code.** Both CLI interfaces (CLI-01 and CLI-02) are fully implemented. The phase is a verification and testing exercise:

1. Run smoke tests to confirm `sss render FILE` stdout behavior
2. Run smoke tests to confirm `sss seal --in-place FILE` behavior
3. Run smoke tests to confirm non-zero exit + stderr message on auth failure
4. Document the confirmed marker byte sequence
5. Optionally: add integration tests that permanently codify these behaviors as regression guards

The planner should scope Phase 1 as: **audit → smoke test → (optional: automated test) → document findings**. No feature development is required unless smoke testing reveals a discrepancy with the success criteria.
