# Security Model

This document describes the security model of **sss** (Secrets in Source): what it protects, how the cryptography works, and what it does not protect.

---

## Overview

sss uses marker-based encryption to protect individual secret values within source files. Rather than encrypting entire files, sss replaces `⊕{secret}` markers with `⊠{ciphertext}` markers in place, leaving surrounding text readable. This approach is designed to be transparent in a version-controlled workflow: sealed files can be committed to git, reviewed structurally, and diffed without exposing secret content.

The cryptographic implementation is built directly on [libsodium](https://doc.libsodium.org/), the widely-audited C cryptography library, via the `libsodium-sys` Rust crate. sss does not use any higher-level cryptographic abstraction crates — all calls go directly to libsodium primitives via the `libsodium-sys` bindings.

---

## Cryptographic Algorithms

| Algorithm | Purpose | Key Size | Nonce/Salt | MAC |
|-----------|---------|----------|------------|-----|
| XChaCha20-Poly1305 | Symmetric encryption of secret content | 256 bits (32 bytes) | 192 bits (24 bytes) | 128 bits (16 bytes) |
| BLAKE2b (keyed) | Deterministic nonce derivation | 256-bit BLAKE2b key (repository key) | — | — |
| X25519 (`crypto_box_seal`) | Asymmetric key wrapping per user — **classic suite (v1.0 default)** | 256 bits (32 bytes) | Ephemeral sender key | XSalsa20-Poly1305 |
| X448 + sntrup761 (`trelis HybridKemKeypair`) | Asymmetric key wrapping per user — **hybrid suite (opt-in, v2.0)** | 1214 bytes (combined public key) | Random 24-byte nonce | XChaCha20-Poly1305 |
| Argon2id v1.3 | Key derivation from passphrase | 256-bit output | 128-bit random salt | — |

> **NOTE (v2.0): The hybrid suite (trelis, X448 + sntrup761) is an opt-in alternative to the
> classic X25519 suite. trelis is experimental and unaudited. Classic (libsodium) remains the
> recommended default. See the "Cryptographic Suite Selection" section below.**

All constants are drawn from the libsodium header values exposed via `libsodium-sys`:

```
crypto_secretbox_xchacha20poly1305_KEYBYTES  = 32
crypto_secretbox_xchacha20poly1305_NONCEBYTES = 24
crypto_secretbox_xchacha20poly1305_MACBYTES  = 16
```

---

## Cryptographic Suite Selection

sss supports two cryptographic suites for per-user repository-key wrapping:

| Suite | `.sss.toml` version | Recommendation |
|-------|---------------------|----------------|
| Classic (libsodium X25519) | `"1.0"` | **Recommended default** — extensively audited via libsodium |
| Hybrid (trelis X448 + sntrup761) | `"2.0"` | Opt-in — experimental, unaudited, post-quantum capable |

The suite is selected by the `version` field in `.sss.toml`. New projects default to `"1.0"`
(classic). Use `sss init --crypto hybrid` to create a v2.0 project or `sss migrate` to upgrade
an existing project.

**The in-file AEAD ciphertext (the `⊠{...}` markers in your files) is byte-identical regardless
of which suite is in use.** Only the per-user `sealed_key` entries in `.sss.toml` differ.
Migration never touches file content.

---

## Key Derivation (Argon2id)

When a user generates a key pair with a passphrase, the passphrase is not used directly. Instead, sss derives a 256-bit wrapping key using Argon2id (variant `ALG_ARGON2ID13` from libsodium `crypto_pwhash`). This wrapping key encrypts the user's private key on disk.

Three parameter levels are supported, selectable via `--kdf-level` or the `SSS_KDF_LEVEL` environment variable:

| Level | Operations Limit | Memory Limit | Approximate Time | Use Case |
|-------|-----------------|--------------|-----------------|----------|
| `sensitive` | `OPSLIMIT_SENSITIVE` (~4 passes) | `MEMLIMIT_SENSITIVE` (256 MiB) | ~2 seconds | Default for keystore — recommended for all production use |
| `moderate` | `OPSLIMIT_MODERATE` (~3 passes) | `MEMLIMIT_MODERATE` (128 MiB) | ~1 second | Balanced performance/security |
| `interactive` | `OPSLIMIT_INTERACTIVE` (~2 passes) | `MEMLIMIT_INTERACTIVE` (64 MiB) | ~0.5 seconds | Not recommended for production |

The default for keystore operations is `sensitive`. A random 128-bit (16-byte) salt (`crypto_pwhash_SALTBYTES`) is generated per key and stored alongside the encrypted private key. The salt is not secret.

---

## What IS Encrypted

The following data is encrypted at rest:

1. **Secret content inside `⊠{...}` markers** — The ciphertext payload. Encrypted with XChaCha20-Poly1305 using the repository key and a deterministically derived nonce. See [marker-format.md](./marker-format.md) for the precise binary layout.

2. **The repository symmetric key in `.sss.toml`** — Each authorised user's entry has a `sealed_key` field. This contains the repository key encrypted with that user's public key via `crypto_box_seal` (X25519 key exchange + XSalsa20-Poly1305). Only the holder of the corresponding private key can recover the repository key.

3. **User private keys on disk** — When a passphrase is provided during key generation, the private key is wrapped with an Argon2id-derived key before being written to `~/.config/sss/keys/<uuid>.toml`. The private key file is stored with mode `0600` (owner-read/write only on Unix).

---

## What is NOT Encrypted

The following data is visible to anyone with access to the repository or file system:

- **File structure and surrounding text** — All content outside `⊠{...}` markers is stored in plaintext. Only the marker content is encrypted.
- **The presence of secrets** — `⊠{...}` markers are visible. An observer can see that a file contains secrets, how many secrets it contains, and where they are positioned within the file.
- **Filenames** — sss does not encrypt file names or directory structures.
- **Git history prior to sealing** — If a secret was committed in plaintext before `sss seal` was run, that plaintext remains in git history. sss protects forward, not backward.
- **Public keys in `.sss.toml`** — The `[username]` sections in `.sss.toml` list each user's public key in plaintext. These are not secret.
- **Marker positions and count** — An observer can determine how many `⊠{}` markers a file contains and at what byte offsets, without being able to read their content.
- **`.secrets` file contents** — The `.secrets` file (used for secrets interpolation with `⊲{name}` markers) is stored in plaintext. It is intended for local use only and should be added to `.gitignore`.

---

## Threat Model

### Protects Against

| Threat | Mitigation |
|--------|-----------|
| Secret values committed to a git repository | XChaCha20-Poly1305 encryption; only users with `sealed_key` entries in `.sss.toml` can decrypt |
| Repository made public after sealing | Repository key is sealed per-user; no global shared secret |
| Files shared with untrusted third parties | Sealed markers cannot be decrypted without the repository key |
| Offline brute-force attack on private key passphrase | Argon2id with `sensitive` parameters (~4 passes, 256 MiB RAM) |
| Ciphertext tampering | Poly1305 MAC authentication; tampered ciphertexts are rejected |
| Sensitive data in memory after use | `zeroize` crate: keys and plaintext are overwritten when they go out of scope |
| Harvest-now-decrypt-later attack by a quantum-capable adversary | Hybrid suite (opt-in): sntrup761 lattice KEM provides post-quantum security for repo-key wrapping; classic suite does not protect against quantum adversaries |

### Does Not Protect Against

| Threat | Notes |
|--------|-------|
| Metadata analysis | The number, positions, and sizes of secrets in a file are visible |
| Observation of whether a secret changed between commits | Same plaintext → same ciphertext (deterministic nonce). An observer can detect that a secret changed without learning its value |
| Compromise of a user's private key or passphrase | If the private key is stolen, the attacker can decrypt all secrets the user is authorised for |
| Plaintext secrets committed to git before sealing | sss does not rewrite git history |
| Malware or other code with access to the decrypted process | Once a file is opened with `sss open`, the plaintext is in memory |
| Supply chain attacks or compromised libsodium | sss trusts its cryptographic dependencies |
| trelis library vulnerabilities or supply-chain compromise | The hybrid suite depends on trelis (unaudited). A vulnerability in trelis could compromise repo-key wrapping for v2.0 projects. Classic suite is not affected. |

### DoS Protection

- Maximum marker content size: `MAX_MARKER_CONTENT_SIZE = 100 MB` — markers exceeding this limit are skipped with a warning.
- Maximum file size: `MAX_FILE_SIZE = 100 MB` — files exceeding this are rejected.
- Passphrase input: Argon2id naturally rate-limits passphrase verification attempts due to its memory-hard design.

---

## Deterministic Nonces

sss uses deterministic nonce derivation rather than random nonces. This is a deliberate design choice to produce clean git diffs.

**How it works:** The 24-byte nonce is derived via BLAKE2b in keyed mode, using the repository key as the BLAKE2b key and the following input:

```
project_timestamp || NUL || file_path || NUL || plaintext
```

With the personalisation string `"sss_autononce_v1"` for domain separation.

**Consequence:** Given the same project, the same file path, and the same plaintext, `sss seal` will always produce the same ciphertext. This means:

- `git diff` on a sealed file shows changes only when the actual secret value changes — not on every seal operation.
- An observer with access to two versions of a sealed file can determine whether a specific secret changed between versions, but cannot learn the secret value without the repository key.

**Nonce collision safety:** A nonce collision (two different plaintexts producing the same nonce) would break confidentiality. The inputs to the hash include the full plaintext, the file path, and the project timestamp. A collision requires finding a BLAKE2b hash collision — this is computationally infeasible with a 192-bit output in keyed mode.

---

## Memory Protection

sss uses the `zeroize` crate to ensure that sensitive values are overwritten with zeroes when they are no longer needed. The following types implement `ZeroizeOnDrop`:

- `RepositoryKey` (32-byte symmetric key)
- `SecretKey` (32-byte user private key)
- `DerivedKey` (32-byte Argon2id output)
- `Salt` (16-byte Argon2id salt)

This prevents secrets from persisting in memory after use and reduces exposure from memory dumps, swap files, and cold-boot attacks.

No plaintext secret value is cached in process memory beyond the immediate operation that requires it.

---

## Brief Plaintext Window

When using `sss edit` or the `sss-mode` Emacs integration, there is a brief period during which plaintext content exists on disk:

1. The sealed file is opened (decrypted), and the plaintext is written to disk temporarily.
2. The editor operates on the plaintext file.
3. On save, sss seals the file before the final write completes.

This pattern is identical to the `epa-file.el` approach used by Emacs for GPG-encrypted files. The plaintext file is written to the same directory as the sealed file.

**Mitigation in sss-mode:** Auto-save and backup file creation are disabled for decrypted buffers in `sss-mode`, reducing the window in which plaintext could be written to unintended locations.

Users running `sss edit` directly should be aware that the editor may create swap or backup files (e.g., Vim's `.swp` files). These may contain plaintext. Adding editor-specific temporary file patterns to `.gitignore` is recommended.

---

## Key Hierarchy

**Classic path (version "1.0" — recommended default):**

```
User Passphrase
     |
     | Argon2id (sensitive: ~4 passes, 256 MiB)
     v
Derived Key (256-bit)
     |
     | XChaCha20-Poly1305 (encrypt)
     v
Encrypted Private Key  -->  stored in ~/.config/sss/keys/<uuid>.toml
     |
     | (decrypt with derived key)
     v
User Private Key (X25519, 256-bit)
     |
     | crypto_box_seal_open (X25519)
     v
Repository Key K (256-bit)
     |
     | XChaCha20-Poly1305 + deterministic BLAKE2b nonce
     v
Encrypted Secrets  -->  ⊠{base64(nonce[24]||MAC[16]||ciphertext[N])}
```

**Hybrid path (version "2.0" — opt-in, experimental):**

```
User Passphrase
     |
     | Argon2id (same path as classic — shared KDF)
     v
Derived Key (256-bit)
     |
     | XChaCha20-Poly1305 (encrypt hybrid secret key)
     v
Encrypted Hybrid Private Key (1819 bytes)  -->  stored in ~/.config/sss/keys/<uuid>.toml
     |
     | (decrypt with derived key)
     v
Hybrid Private Key (X448 || sntrup761, 1819 bytes)
     |
     | trelis decapsulate + BLAKE3 KDF
     v
Repository Key K (256-bit)  [same K as classic path]
     |
     | XChaCha20-Poly1305 + deterministic BLAKE2b nonce  [identical to classic]
     v
Encrypted Secrets  -->  ⊠{base64(nonce[24]||MAC[16]||ciphertext[N])}
```

---

## References

- [libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [libsodium Sealed Boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
- [libsodium Password Hashing (Argon2id)](https://doc.libsodium.org/password_hashing/default_phc)
- [libsodium BLAKE2b](https://doc.libsodium.org/hashing/generic_hashing)
- [RFC 9106 – Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [Marker format details](./marker-format.md)
- [trelis (experimental KEM library)](https://github.com/dspearson/trelis)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)
