# Marker Format Reference

This document is the authoritative reference for the sss marker syntax. It covers both marker types, their Unicode and byte representations, parser semantics, the ciphertext payload format, and enough detail for a third party to implement a compatible parser.

---

## Overview

sss uses inline markers to identify secret content within files. Two marker types exist:

- **Plaintext markers** (`⊕{...}` or `o+{...}`) — written by the user to identify secret content before sealing.
- **Ciphertext markers** (`⊠{...}`) — produced by `sss seal`; contain the encrypted secret.

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

**Important:** `⊕` (U+2295) and `⊠` (U+22A0) are distinct characters. They look superficially similar in some fonts but have different codepoints and different UTF-8 encodings.

Source reference (from `src/constants.rs`):

```rust
pub const MARKER_PLAINTEXT_UTF8:  &str = "⊕";  // U+2295
pub const MARKER_PLAINTEXT_ASCII: &str = "o+";  // ASCII fallback (input only)
pub const MARKER_CIPHERTEXT:      &str = "⊠";  // U+22A0
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

Seals plaintext markers; leaves ciphertext markers unchanged.

| Input | Output | Notes |
|-------|--------|-------|
| `⊕{secret}` | `⊠{base64ciphertext}` | UTF-8 plaintext marker sealed |
| `o+{secret}` | `⊠{base64ciphertext}` | ASCII alias sealed; output is always `⊠{}` form |
| `⊠{existingciphertext}` | `⊠{existingciphertext}` | Already sealed — passed through unchanged |

### `sss open`

Decrypts ciphertext markers; leaves plaintext markers unchanged.

| Input | Output | Notes |
|-------|--------|-------|
| `⊠{base64ciphertext}` | `⊕{decryptedplaintext}` | Always produces UTF-8 `⊕{}` form, even if the original was `o+` |
| `⊕{existing}` | `⊕{existing}` | Already open — passed through unchanged |

### `sss render`

Decrypts and strips all markers, producing plain text output with no marker characters.

| Input | Output | Notes |
|-------|--------|-------|
| `⊠{base64ciphertext}` | `decryptedplaintext` | Markers removed; only the content remains |
| `⊕{plaintext}` | `plaintext` | Markers removed; content preserved |

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

## Summary Table

| Marker | Prefix | Type | Seal input? | Seal output? | Open output? |
|--------|--------|------|-------------|--------------|--------------|
| `⊕{...}` | U+2295 | Plaintext | Yes | `⊠{...}` | Unchanged |
| `o+{...}` | ASCII | Plaintext alias | Yes | `⊠{...}` | — |
| `⊠{...}` | U+22A0 | Ciphertext | Unchanged | — | `⊕{...}` |
| `⊲{...}` | U+22B2 | Secrets interpolation | Resolved first | — | Resolved first |
