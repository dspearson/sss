# Marker Format Reference

This document is the authoritative reference for the sss marker syntax. It covers both marker types, their Unicode and byte representations, parser semantics, the ciphertext payload format, and enough detail for a third party to implement a compatible parser.

---

## Overview

sss uses inline markers to identify secret content within files. Three marker families exist:

- **Plaintext markers** (`⊕{...}` or `o+{...}`) — written by the user to identify secret content before sealing.
- **Ciphertext markers** (`⊠{...}`) — produced by `sss seal`; contain the encrypted secret.
- **Vault reference markers** (`⊳{...}` or `>{...}`) — render-time references to an external secret store (HashiCorp Vault). Vault references are **not encrypted** and are preserved byte-for-byte by both `sss seal` and `sss open`. Resolution only occurs at render time (`sss render`, FUSE, 9P).

Files may contain any mix of plaintext text and markers. Everything outside a marker is treated as opaque content and is preserved unchanged by all sss operations.

---

## Marker Syntax

```
plaintext-marker  ::= ("⊕" | "o+") "{" content "}"
ciphertext-marker ::= "⊠" "{" content "}"
content           ::= any byte sequence with balanced braces (depth-counted)
```

Examples:

```
⊕{my_secret_password}
o+{my_secret_password}
⊠{base64encodedciphertext}
⊕{{"db": {"host": "localhost", "password": "secret"}}}
```

The `o+` prefix is accepted as input only for plaintext markers. There is no ASCII alternative for the ciphertext marker.

---

## Character Reference

| Symbol | Unicode Name | Codepoint | UTF-8 Bytes | Purpose |
|--------|-------------|-----------|-------------|---------|
| `⊕` | CIRCLED PLUS | U+2295 | `\xe2\x8a\x95` (3 bytes) | Plaintext / open marker prefix |
| `⊠` | SQUARED TIMES | U+22A0 | `\xe2\x8a\xa0` (3 bytes) | Ciphertext / sealed marker prefix |
| `o+` | ASCII (two characters) | U+006F U+002B | `\x6f\x2b` (2 bytes) | Input alias for `⊕` (plaintext only) |
| `⊳` | CONTAINS AS NORMAL SUBGROUP | U+22B3 | `\xe2\x8a\xb3` (3 bytes) | Vault reference marker prefix (render-time) |
| `>` | GREATER-THAN SIGN (ASCII) | U+003E | `\x3e` (1 byte) | Input alias for `⊳` (vault references only; output always uses `⊳{}` form) |

**Important:** `⊕` (U+2295), `⊠` (U+22A0), `⊲` (U+22B2, secrets interpolation), and `⊳` (U+22B3, vault reference) are distinct characters. They may look superficially similar in some fonts but have different codepoints and different UTF-8 encodings. In particular, `⊲` (U+22B2, NORMAL SUBGROUP OF) and `⊳` (U+22B3, CONTAINS AS NORMAL SUBGROUP) are mirrors of each other and must not be confused.

Source reference (from `src/constants.rs`):

```rust
pub const MARKER_PLAINTEXT_UTF8:  &str = "⊕";  // U+2295
pub const MARKER_PLAINTEXT_ASCII: &str = "o+";  // ASCII fallback (input only)
pub const MARKER_CIPHERTEXT:      &str = "⊠";  // U+22A0
pub const MARKER_VAULT_UTF8:      &str = "⊳";  // U+22B3
pub const MARKER_VAULT_ASCII:     &str = ">";   // single char '>' (input only)
```

---

## Balanced Brace Parsing

The parser uses brace depth-counting to find the end of a marker's content. This allows marker content to contain nested braces.

**Algorithm:**

1. Match the marker prefix (`⊕`, `o+`, or `⊠`) at the current position.
2. Confirm the next character is `{`.
3. Increment a depth counter to 1.
4. Scan forward through the content:
   - `{` increments depth.
   - `}` decrements depth.
   - When depth reaches 0, the marker content ends at the preceding character and the marker is complete.
5. Everything from after the opening `{` to the character before the depth-0 closing `}` is the marker content.

**Examples:**

| Input | Marker content | Notes |
|-------|---------------|-------|
| `⊕{hello}` | `hello` | Simple case |
| `⊕{}` | `` (empty) | Empty marker — valid |
| `⊕{{"key":"value"}}` | `{"key":"value"}` | Nested braces — the outer `{` opens the marker, the inner `{}` pair is content |
| `⊕{{"db": {"host": "localhost", "port": 5432}}}` | `{"db": {"host": "localhost", "port": 5432}}` | Deeply nested JSON |

**Size limit:** Marker content is capped at `MAX_MARKER_CONTENT_SIZE = 100 MB`. Markers exceeding this limit are skipped with a warning on stderr.

**Unmatched braces:** If the parser reaches end-of-input without finding a depth-0 closing brace, the marker prefix is treated as literal text and the parser moves on. No error is raised.

---

## Transformation Behaviours

### `sss seal`

Seals plaintext markers; normalises vault ASCII aliases; leaves ciphertext markers and vault references unchanged.

| Input | Output | Notes |
|-------|--------|-------|
| `⊕{secret}` | `⊠{base64ciphertext}` | UTF-8 plaintext marker sealed |
| `o+{secret}` | `⊠{base64ciphertext}` | ASCII alias sealed; output is always `⊠{}` form |
| `⊠{existingciphertext}` | `⊠{existingciphertext}` | Already sealed — passed through unchanged |
| `⊳{path#field}` | `⊳{path#field}` | Vault reference — preserved verbatim; never encrypted |
| `>{path#field}` | `⊳{path#field}` | ASCII vault alias normalised to UTF-8 `⊳{}` form on the seal path |

### `sss open`

Decrypts ciphertext markers; leaves plaintext markers and vault references unchanged.

| Input | Output | Notes |
|-------|--------|-------|
| `⊠{base64ciphertext}` | `⊕{decryptedplaintext}` | Always produces UTF-8 `⊕{}` form, even if the original was `o+` |
| `⊕{existing}` | `⊕{existing}` | Already open — passed through unchanged |
| `⊳{path#field}` | `⊳{path#field}` | Vault reference — preserved verbatim; never decrypted |

### `sss render`

Decrypts sealed markers and strips all plaintext markers, producing plain text output. Vault references (`⊳{}`) are resolved at this stage (Phase 47 — see "Vault Reference Markers" section below).

| Input | Output | Notes |
|-------|--------|-------|
| `⊠{base64ciphertext}` | `decryptedplaintext` | Markers removed; only the content remains |
| `⊕{plaintext}` | `plaintext` | Markers removed; content preserved |
| `⊳{path#field}` | `<resolved value>` | Vault reference resolved at render time (Phase 47) |

**Idempotency:** All three operations are idempotent on already-transformed markers. Running `sss seal` twice on an already-sealed file produces the same output (same ciphertext, same nonce derivation). Running `sss open` on an already-open file leaves it unchanged.

**Surrounding text:** Content outside markers is always preserved byte-for-byte.

---

## Ciphertext Payload Format

Inside a `⊠{...}` marker, the content is a base64-encoded binary blob with the following layout:

```
base64( nonce[24 bytes] || MAC[16 bytes] || ciphertext[N bytes] )
```

| Field | Size | Description |
|-------|------|-------------|
| `nonce` | 24 bytes | Deterministically derived via BLAKE2b keyed hash — not random |
| `MAC` | 16 bytes | Poly1305 authentication tag |
| `ciphertext` | N bytes | XChaCha20-encrypted content — same length as plaintext |

Total binary overhead per secret: **40 bytes** (nonce + MAC).

The base64 encoding uses the standard alphabet (`A–Z`, `a–z`, `0–9`, `+`, `/`, with `=` padding). The base64 character set deliberately avoids `{` and `}`, which means the ciphertext payload can never prematurely close the marker brace.

**Binary overhead example:** A 32-byte secret produces `24 + 16 + 32 = 72` bytes of binary, which encodes to 96 characters of base64. The total marker is `⊠{` + 96 chars + `}` = 101 bytes in the file.

For algorithm details (XChaCha20-Poly1305 parameters, BLAKE2b nonce derivation inputs), see [security-model.md](./security-model.md).

---

## Secrets Interpolation Marker

In addition to the two primary marker types, sss supports a **secrets interpolation marker**:

```
⊲{secret_name}
```

Unicode: `⊲` = U+22B2 (NORMAL SUBGROUP OF), UTF-8: `\xe2\x8a\xb2` (3 bytes).

ASCII alias accepted on input: `<{secret_name}`.

This marker is not an encryption marker. It references a named value from a `.secrets` file in the project. During seal and open operations, sss resolves `⊲{name}` to the corresponding value from `.secrets`, and the resolved value can then be encrypted via a surrounding `⊕{}` marker.

Example:

```
⊕{⊲{database_password}}
```

After interpolation: `⊕{the_actual_password}`, then sealed to `⊠{base64ciphertext}`.

The `.secrets` file is plaintext, local-only, and should not be committed to version control.

---

## Vault Reference Markers (`⊳{}`)

Vault reference markers reference secrets stored in an external secret store (HashiCorp Vault) and are resolved at render time. They are distinct from the `⊲{}` secrets interpolation marker, which references the local `.secrets` file.

**Character:** `⊳` = U+22B3 (CONTAINS AS NORMAL SUBGROUP), UTF-8: `\xe2\x8a\xb3` (3 bytes).

**ASCII alias accepted on input:** `>` (single char, U+003E). On the seal path, `>{...}` is normalised to `⊳{...}`. Output always uses the UTF-8 `⊳{}` form.

### Grammar

```
vault-marker  ::= ("⊳" | ">") "{" vault-ref "}"
vault-ref     ::= [binding ":"] path ["#" field] ["@" version]
binding       ::= [A-Za-z0-9_-]+
path          ::= non-empty string (the Vault secret path)
field         ::= non-empty string (the key within the secret)
version       ::= non-empty string (the Vault secret version)
```

All four components are optional except `path`. In full form:

```
⊳{mystore:secret/database#password@2}
```

This references binding `mystore`, Vault path `secret/database`, field `password`, version `2`.

**Partial forms (all valid):**

| Marker | Meaning |
|--------|---------|
| `⊳{secret/database#password}` | No binding (uses default), no version |
| `⊳{secret/database}` | No binding, no field, no version (resolves to `default_field`) |
| `⊳{mystore:secret/database}` | Binding, path; no field or version |
| `⊳{secret/database@3}` | No binding or field; version 3 |
| `⊳{mystore:secret/database#password@2}` | Full form |

**Binding selector rule:** A `binding:` prefix is recognised as a binding selector when the text before the first `:` matches a configured binding name (`[A-Za-z0-9_-]+`). If no binding by that name exists in the configuration, the entire string including the colon is treated as the path.

**Field omitted:** When `#field` is absent, the binding's `default_field` is used. If the binding has no `default_field` and the secret contains multiple fields, the reference is ambiguous — sss reports an error. A missing field is never silently resolved to an empty string or a random pick.

### Resolution Semantics

Vault references are **render-time only**. They are resolved by `sss render`, the FUSE virtual filesystem, and the 9P server. Resolution is not yet implemented and will land in Phase 47.

**Seal and open preserve vault references byte-for-byte.** A `⊳{}` marker is never encrypted, never modified, and never stripped by `sss seal` or `sss open`.

**Malformed references:** If a `⊳{}` marker is syntactically invalid (e.g., empty content, invalid characters), sss reports a warning and leaves the marker as literal text in the output. Malformed references are never silently dropped or resolved to an empty string.

### Example: Mixing Native and Vault References

```
⊕{⊲{local_api_key}}
db_host: ⊳{infra:secret/db#host}
db_pass: ⊳{infra:secret/db#password}
```

After `sss seal`, the `⊕{}` marker is encrypted to `⊠{...}`; the vault markers are preserved verbatim. After `sss render` (Phase 47), the sealed marker is decrypted, the vault markers are resolved against Vault, and all markers are stripped from the output.

### Adoption: `[vault]` Requires a Signed Envelope

To use a `[vault]` configuration table in `.sss.toml`, the repo envelope must be signed at `format_version = 3`. Repos without a `[vault]` table do not require a v3 signature.

**Opt-in path:** Run once after adding a `[vault]` section:

```sh
sss envelope upgrade-sig
```

This re-signs the envelope at `format_version = 3` if `[vault]` is present, or `format_version = 2` if not. The command is idempotent — running it again on an already-upgraded repo prints "already signed" and exits without touching the file.

**Existing signed v2 repos are unaffected** until they choose to adopt `[vault]`. The v2 signature verify arm is retained. There is no requirement for all repos to re-sign.

**Unsigned repos (v1):** A `[vault]` section on an unsigned (v1) repo is a hard error unless `--allow-unsigned-vault-config` is passed, in which case `tls_ca_secret` is mandatory.

For the envelope signature rationale and the v3 payload format, see [security-model.md](./security-model.md) (updated in Phase 48).

---

## Magic Detection

sss-mode (the Emacs integration) detects sealed files by checking whether the file content begins with the byte sequence for `⊠{`:

```
\xe2\x8a\xa0\x7b
```

(That is, the UTF-8 encoding of `⊠` followed by `{`.)

Files starting with this sequence are automatically opened in `sss-mode` via Emacs's `magic-mode-alist`.

---

## Implementing a Compatible Parser

The following pseudocode describes a minimal balanced-brace marker scanner compatible with sss's `find_balanced_markers` implementation:

```
function find_markers(input: bytes, prefixes: list[str]) -> list[Match]:
    matches = []
    pos = 0

    while pos < len(input):
        found_prefix = None
        for prefix in prefixes:
            if input[pos:].starts_with(prefix):
                after_prefix = input[pos + len(prefix):]
                if after_prefix starts with '{':
                    found_prefix = prefix
                    break

        if found_prefix is not None:
            marker_start = pos
            pos += len(found_prefix)   // skip prefix
            pos += 1                   // skip opening '{'
            content_start = pos
            depth = 1

            while pos < len(input) and depth > 0:
                ch = next UTF-8 character at pos
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        content = input[content_start : pos]
                        matches.append(Match(
                            start   = marker_start,
                            end     = pos + 1,   // include closing '}'
                            content = content,
                        ))
                        pos += 1
                        break
                pos += len(UTF8(ch))

            if depth != 0:
                // Unmatched — skip; pos already past prefix
                pass
        else:
            pos += len(next UTF-8 character at pos)

    return matches
```

**Plaintext markers:** call `find_markers(input, ["⊕", "o+"])`

**Ciphertext markers:** call `find_markers(input, ["⊠"])`

**Edge cases to handle:**

| Case | Behaviour |
|------|-----------|
| Empty marker `⊕{}` | Valid; content is empty string |
| Whitespace-only `⊕{   }` | Valid; content is the whitespace string |
| Marker at end of file with no trailing newline | Valid; closing `}` may be the last byte |
| Unmatched `⊕{unclosed` | Skipped; prefix treated as literal text |
| Overlapping prefixes | Scan is greedy; the first matching prefix at each position wins |
| Multi-byte UTF-8 inside content | Scanner advances by character (not byte) to avoid misidentifying UTF-8 continuation bytes as `{` or `}` |

---

## Security: Byte-Exact Matching and Homoglyphs

**Marker-prefix detection is byte-exact UTF-8.** The scanner, marker processor, and
marker inference engine all match the literal UTF-8 byte sequences for `⊕` (3 bytes:
`\xe2\x8a\x95`), `⊠` (3 bytes: `\xe2\x8a\xa0`), `⊲` (3 bytes: `\xe2\x8a\xb2`),
`⊳` (3 bytes: `\xe2\x8a\xb3`), and the ASCII aliases `o+` (2 bytes: `\x6f\x2b`) and
`>` (1 byte: `\x3e`) with no Unicode normalisation applied to the input file.

**Consequence:** a visually identical look-alike character (a *homoglyph*) is silently
**not** detected as a marker.

For example:

| Written in the file | Codepoint | Detected? | Risk |
|---------------------|-----------|-----------|------|
| `o+{secret}` | U+006F U+002B (ASCII `o`, `+`) | Yes | — |
| `ο+{secret}` | U+03BF U+002B (Greek lowercase **omicron** + ASCII `+`) | **No** | Plaintext committed unsealed |
| `⊕{secret}` | U+2295 (CIRCLED PLUS) | Yes | — |
| Visually similar `⊕`-lookalike | e.g. U+2A01 (N-ARY CIRCLED PLUS) | **No** | Plaintext committed unsealed |

The Greek omicron (U+03BF) is the most likely source of confusion for the `o+` prefix:
it is visually indistinguishable from the ASCII letter `o` in most fonts. A file containing
`ο+{API_KEY}` (with U+03BF) would pass through `sss seal` with the plaintext value
unchanged and would be committed to version control in the clear.

**This is intentional design.** Applying Unicode normalisation (e.g. NFKC) to input
file content before scanning would change the bytes of non-secret content, which is
unacceptable for a tool that guarantees byte-for-byte preservation of surrounding text.
The correctness trade-offs of normalisation are why this alternative was explicitly
deferred.

**What this means for reviewers and authors:**

- Always use the exact documented codepoints (U+2295, U+22A0, U+22B2, U+22B3, or the
  ASCII aliases `o+` and `>`). Copy marker syntax from this document or use the git
  pre-commit hook, which scans for the exact byte sequences.
- A homoglyph-substituted marker does **not** bypass encryption of already-sealed
  content — it is only a review-trust risk for content that has not yet been sealed.
  An attacker who can substitute a homoglyph could cause a secret to go unsealed on
  the next `sss seal` run, but cannot decrypt existing `⊠{...}` ciphertext.
- The pre-commit hook (`githooks/pre-commit`) also matches byte-exact and will not
  catch a homoglyph marker.

---

## Summary Table

| Marker | Prefix | Type | Seal input? | Seal output? | Open output? | Render output? |
|--------|--------|------|-------------|--------------|--------------|----------------|
| `⊕{...}` | U+2295 | Plaintext | Yes | `⊠{...}` | Unchanged | stripped (content only) |
| `o+{...}` | ASCII | Plaintext alias | Yes | `⊠{...}` | — | stripped (content only) |
| `⊠{...}` | U+22A0 | Ciphertext | Unchanged | — | `⊕{...}` | decrypted + stripped |
| `⊲{...}` | U+22B2 | Secrets interpolation | Resolved first | — | Resolved first | resolved from `.secrets` |
| `⊳{...}` | U+22B3 | Vault reference | Preserved verbatim | `⊳{...}` | Preserved verbatim | resolved from Vault (Phase 47) |
| `>{...}` | ASCII | Vault alias | Normalised → `⊳{...}` | `⊳{...}` | — | — |
