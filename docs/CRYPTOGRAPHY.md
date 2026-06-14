# Cryptographic Implementation - SSS (Secrets in Source)

## Overview

This document provides a detailed technical specification of the cryptographic primitives, algorithms, and implementation patterns used in SSS. It is intended for security auditors, cryptographers, and developers who need to understand the low-level cryptographic details.

For the project's threat model — what each primitive in this spec is required to defend against, the trust boundaries it crosses, and the per-suite assumption breakdown — see [`docs/security-model.md`](./security-model.md). This file owns the algorithmic spec; `security-model.md` owns the threat-model coverage.

> **UNAUDITED POST-QUANTUM COMPONENT:** The hybrid suite (v2.0) relies on the
> [`trelis`](https://github.com/dspearson/trelis) library (X448 + sntrup761 KEM,
> Ed448 + ML-DSA-65 signatures, BLAKE3 KDF), which is **in-house and has not
> undergone a formal third-party security audit** (backlog item AUDIT-01). Classic
> (libsodium) remains the recommended default for production deployments. See
> [trelis Cryptographic Library (UNAUDITED)](#trelis-cryptographic-library-unaudited)
> for the full audit-gap scope, interim mitigations, and resolution path.

## Table of Contents

1. [Cryptographic Dependencies](#cryptographic-dependencies)
2. [trelis Cryptographic Library (UNAUDITED)](#trelis-cryptographic-library-unaudited)
3. [Symmetric Encryption](#symmetric-encryption)
4. [Asymmetric Encryption](#asymmetric-encryption)
5. [Hybrid Suite (v2.0)](#hybrid-suite-v20)
6. [Key Derivation](#key-derivation)
7. [Hash Functions](#hash-functions)
8. [Nonce Derivation](#nonce-derivation)
9. [Vault Lockfile Digest (keyed BLAKE2b MAC)](#vault-lockfile-digest-keyed-blake2b-mac)
10. [Memory Safety](#memory-safety)
11. [Implementation Patterns](#implementation-patterns)
12. [Security Properties](#security-properties)
13. [Code Examples](#code-examples)

## Cryptographic Dependencies

SSS relies on battle-tested cryptographic libraries:

### libsodium (via libsodium-sys)

**Version**: Latest stable via `libsodium-sys-stable` crate
**Rationale**: Industry-standard cryptographic library with extensive auditing

**Functions Used**:
- `crypto_secretbox_easy` / `crypto_secretbox_open_easy` - XChaCha20-Poly1305 AEAD
- `crypto_box_seal` / `crypto_box_seal_open` - X25519 sealed boxes
- `crypto_pwhash` - Argon2id key derivation
- `crypto_generichash` - BLAKE2b hashing
- `randombytes_buf` - CSPRNG for key/salt generation

### Supporting Crates

- **zeroize** (`^1.8`): Secure memory zeroing on drop
- **subtle** (`^2.6`): Constant-time operations
- **base64** (`^0.22`): Base64 encoding/decoding
- **keyring** (`^3.6`): OS keyring integration

## Symmetric Encryption

XChaCha20-Poly1305 is the AEAD used both for in-file `⊠{...}` ciphertexts (both suites; see [`docs/security-model.md#protects-against`](./security-model.md#protects-against) for the threat-model rationale) and for the repository-key sealing layer in the hybrid suite.

### Algorithm: XChaCha20-Poly1305

**Specification**: [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)

#### Parameters

```rust
pub const XCHACHA20_POLY1305_NONCEBYTES: usize = 24;  // 192 bits
pub const XCHACHA20_POLY1305_KEYBYTES: usize = 32;    // 256 bits
pub const XCHACHA20_POLY1305_MACBYTES: usize = 16;    // 128 bits
```

#### Why XChaCha20-Poly1305?

1. **Extended Nonce**: 192-bit nonce (vs 96-bit in ChaCha20) eliminates nonce reuse concerns
2. **Performance**: ~2-3x faster than AES-GCM on non-hardware-accelerated platforms
3. **Side-Channel Resistance**: No timing attacks (unlike AES without AES-NI)
4. **AEAD**: Provides both confidentiality and authenticity in one operation
5. **Constant-Time**: Implementation is constant-time by design

#### Encryption Process

```rust
pub fn encrypt(plaintext: &[u8], key: &RepositoryKey, timestamp: &str, file_path: &str) -> Result<Vec<u8>> {
    // 1. Derive deterministic nonce
    let nonce = derive_nonce(plaintext, key, timestamp, file_path)?;

    // 2. Prepare output buffer: nonce || ciphertext || mac
    let mut output = vec![0u8; NONCEBYTES + plaintext.len() + MACBYTES];

    // 3. Copy nonce to output
    output[..NONCEBYTES].copy_from_slice(&nonce);

    // 4. Encrypt using libsodium
    unsafe {
        crypto_secretbox_easy(
            output.as_mut_ptr().add(NONCEBYTES),  // ciphertext destination
            plaintext.as_ptr(),                    // plaintext source
            plaintext.len() as u64,                // plaintext length
            nonce.as_ptr(),                        // nonce
            key.as_bytes().as_ptr(),               // key
        );
    }

    Ok(output)
}
```

#### Decryption Process

```rust
pub fn decrypt(ciphertext: &[u8], key: &RepositoryKey) -> Result<Vec<u8>> {
    // 1. Validate minimum size: nonce + mac
    if ciphertext.len() < NONCEBYTES + MACBYTES {
        return Err(anyhow!("Ciphertext too short"));
    }

    // 2. Extract nonce
    let nonce = &ciphertext[..NONCEBYTES];

    // 3. Extract encrypted portion (ciphertext + mac)
    let encrypted = &ciphertext[NONCEBYTES..];

    // 4. Prepare plaintext buffer
    let plaintext_len = encrypted.len() - MACBYTES;
    let mut plaintext = vec![0u8; plaintext_len];

    // 5. Decrypt and verify MAC using libsodium
    let result = unsafe {
        crypto_secretbox_open_easy(
            plaintext.as_mut_ptr(),              // plaintext destination
            encrypted.as_ptr(),                  // ciphertext + mac source
            encrypted.len() as u64,              // encrypted length
            nonce.as_ptr(),                      // nonce
            key.as_bytes().as_ptr(),             // key
        )
    };

    // 6. Check authentication
    if result != 0 {
        return Err(anyhow!("Decryption failed: authentication error"));
    }

    Ok(plaintext)
}
```

#### Security Properties

- **IND-CCA2**: Indistinguishable under adaptive chosen-ciphertext attack
- **INT-CTXT**: Integrity of ciphertext (unforgeable)
- **Nonce Misuse Resistance**: Large 192-bit nonce space
- **Key Commitment**: Poly1305 MAC provides key commitment

## Asymmetric Encryption

X25519 sealed boxes wrap the per-user repository key in classic-suite (`version = "1.0"`) projects; see [`docs/security-model.md#per-suite-threat-tables`](./security-model.md#per-suite-threat-tables) for the threat-model coverage and the divergent-assumptions table that names the X25519 DLP hardness assumption explicitly.

### Algorithm: X25519 Sealed Boxes

**Specification**: [Curve25519](https://cr.yp.to/ecdh.html), [NaCl crypto_box_seal](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)

#### Parameters

```rust
pub const X25519_PUBLICKEYBYTES: usize = 32;   // 256 bits
pub const X25519_SECRETKEYBYTES: usize = 32;   // 256 bits
pub const SEALBYTES: usize = 48;                // Ephemeral PK (32) + MAC (16)
```

#### Sealed Box Construction

A sealed box is an **anonymous** public-key encryption:

```
SealedBox = EphemeralPublicKey || Encrypt(Message, SharedSecret)
```

Where:
- `EphemeralPublicKey` = 32-byte ephemeral public key (one-time use)
- `SharedSecret` = X25519(EphemeralSecretKey, RecipientPublicKey)
- `Encrypt` = XSalsa20-Poly1305 AEAD

#### Key Generation

```rust
pub fn generate() -> Result<KeyPair> {
    let mut public_key = [0u8; crypto_box_PUBLICKEYBYTES as usize];
    let mut secret_key = [0u8; crypto_box_SECRETKEYBYTES as usize];

    unsafe {
        crypto_box_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr());
    }

    Ok(KeyPair {
        public_key: PublicKey(public_key),
        secret_key: SecretKey(secret_key),
    })
}
```

#### Repository Key Wrapping

```rust
pub fn wrap_repository_key(repo_key: &RepositoryKey, public_key: &PublicKey) -> Result<Vec<u8>> {
    let plaintext = repo_key.as_bytes();
    let mut sealed = vec![0u8; plaintext.len() + crypto_box_SEALBYTES as usize];

    unsafe {
        crypto_box_seal(
            sealed.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u64,
            public_key.0.as_ptr(),
        );
    }

    Ok(sealed)
}
```

#### Repository Key Unwrapping

```rust
pub fn unwrap_repository_key(sealed: &[u8], keypair: &KeyPair) -> Result<RepositoryKey> {
    let plaintext_len = sealed.len() - crypto_box_SEALBYTES as usize;
    let mut plaintext = vec![0u8; plaintext_len];

    let result = unsafe {
        crypto_box_seal_open(
            plaintext.as_mut_ptr(),
            sealed.as_ptr(),
            sealed.len() as u64,
            keypair.public_key.0.as_ptr(),
            keypair.secret_key.0.as_ptr(),
        )
    };

    if result != 0 {
        return Err(anyhow!("Failed to unwrap repository key"));
    }

    RepositoryKey::from_bytes(&plaintext)
}
```

#### Security Properties

- **Forward Secrecy**: Ephemeral keys provide forward secrecy per message
- **Anonymous**: No sender identification (sealed box property)
- **Authenticated**: Poly1305 MAC prevents tampering
- **Post-Quantum Security**: ~128-bit security against Grover's algorithm

## trelis Cryptographic Library (UNAUDITED)

> **SECURITY NOTICE: The hybrid-feature arm of sss uses the [trelis](https://github.com/dspearson/trelis)
> library, which is IN-HOUSE and UNAUDITED. An independent third-party security audit of trelis
> is tracked as backlog item AUDIT-01 and has NOT been performed. Until AUDIT-01 is complete,
> treat the hybrid suite as EXPERIMENTAL for production deployments with a high assurance
> requirement. Classic (libsodium) remains the recommended default.**

**What trelis provides:**

- **X448 + sntrup761 KEM** (`HybridKemKeypair`) — post-quantum key encapsulation for per-user
  repository-key wrapping in all v2.0 projects
- **Ed448 + ML-DSA-65 signature primitives** — keystore entry and envelope signing (Phases 18, 19)
- **BLAKE3 KDF** (`trelis_primitives::derive_key`) — domain-separated key derivation from the
  shared secret (`HYBRID_KEM_CONTEXT = "sss-hybrid-kem-v1"`)

**Pinned commit:** `5374dff482ba94a94695794b5e4554f908eb0d4d` (2026-04-24, `github.com/dspearson/trelis`)
— updates require an explicit `Cargo.toml` change; the project does not consume floating versions.

**Scope of the audit gap:** Every v2.0 (hybrid-default) repository relies on trelis for its
post-quantum security claim. The classical X25519 AEAD layer (XChaCha20-Poly1305 on `⊠{...}`
markers) is libsodium and is unaffected — the trelis exposure is bounded to the per-user
`sealed_key` wrapping in `.sss.toml` and to keystore/envelope signatures. A defect in trelis's
sntrup761 KEM, ML-DSA-65, or BLAKE3 KDF binding would eliminate the PQ guarantee while
classical security remains intact.

**In-house interim mitigations (Phase 42, pending AUDIT-01):**

| Mitigation | Description |
|------------|-------------|
| REM-30 (MEM-16) | `ZeroizeOnDrop` regression tests for `HybridKemKeypair`, `Ed448SigningKey`, `MlDsa65SigningKey` — detects a defective upstream `ZeroizeOnDrop` derive |
| REM-27 (CRY-17) | KAT pinning `HYBRID_KEM_CONTEXT` bytes and `derive_key` output against the pinned SHA — detects silent context-string or output-length drift on any trelis bump |

**Resolution path:** AUDIT-01 — commission / track a third-party audit of trelis at pinned rev
`5374dff482ba94a94695794b5e4554f908eb0d4d`. See `.planning/REQUIREMENTS.md` (Future
Requirements / External Engagement). Teams that cannot accept this supply-chain risk should
use the classic suite (`sss init --crypto classic`).

See [`docs/security-model.md#trelis-attack-surface`](./security-model.md#trelis-attack-surface)
for the full attack-surface picture, mitigation options for teams, and per-suite threat tables.

---

## Hybrid Suite (v2.0)

### WARNING: trelis is Unaudited and Experimental

> **WARNING: The hybrid suite depends on the `trelis` library (X448 + sntrup761), which is
> experimental and has not undergone a formal third-party security audit. The hybrid suite is
> opt-in and disabled by default. Classic (libsodium) remains the recommended default for all
> production deployments until a trelis audit is completed. Do not rely on the hybrid suite
> for production security without understanding this limitation.**

For the threat-model framing of this surface — what the hybrid suite is required to defend against, what dual-keystore compromise looks like, and how `sss migrate` is constrained — see [`docs/security-model.md#hybrid-trust-boundaries-v20`](./security-model.md#hybrid-trust-boundaries-v20). For the consolidated trelis attack-surface picture (pinned commit, audit posture, mitigation guidance for teams), see [`docs/security-model.md#trelis-attack-surface`](./security-model.md#trelis-attack-surface).

### Algorithm Overview

The hybrid suite uses **trelis** (X448 + sntrup761) for key-encapsulation, **BLAKE3** for key
derivation, and **libsodium XChaCha20-Poly1305** for AEAD. The in-file ciphertext layer is
identical to the classic suite; only per-user `.sss.toml` `sealed_key` entries differ between
suites. Hybrid is selected when the `.sss.toml` `version` field is `"2.0"`.

### Public Key Sizes

| Component | Size (bytes) | Description |
|-----------|-------------|-------------|
| X448 public scalar | 56 | DH component |
| sntrup761 public key | 1158 | KEM component |
| Combined (`HYBRID_PUBLIC_KEY_SIZE`) | 1214 | Concatenated |
| X448 secret scalar | 56 | DH component |
| sntrup761 secret key | 1763 | KEM component |
| Combined (`HYBRID_SECRET_KEY_SIZE`) | 1819 | Concatenated |

### KEM and Key-Derivation

The hybrid suite seals the 32-byte repository key `K` via a three-step process:

1. **trelis KEM** — `HybridKemKeypair::encapsulate(recipient_public_key)` produces
   `(encapsulation[1095], shared_bytes[64])`. The encapsulation contains the X448 ephemeral
   public key concatenated with the sntrup761 ciphertext.
2. **BLAKE3 KDF** — `blake3::derive_key("sss-hybrid-kem-v1", shared_bytes)` reduces the
   64-byte shared secret to a 32-byte AEAD key.
3. **libsodium XChaCha20-Poly1305** — the derived 32-byte key seals the repository key `K`
   with a random 24-byte nonce.

### Sealed Key Wire Format

```
Hybrid sealed key (1167 bytes total):
  [0..1095)    encapsulation  — X448 ephemeral || sntrup761 ciphertext
  [1095..1119) nonce          — 24-byte random XChaCha20 nonce
  [1119..1167) ciphertext     — 32-byte K encrypted + 16-byte Poly1305 tag

Classic sealed key (80 bytes total, for comparison):
  [0..32)  ephemeral_pubkey   — X25519 ephemeral sender public key
  [32..80) ciphertext+mac     — 32-byte K encrypted + 16-byte XSalsa20-Poly1305 mac
```

Per-user `.sss.toml` `sealed_key` field grows by approximately **1448 base64 characters** per
user entry (1167 bytes vs 80 bytes raw; `ceil(1167/3)*4 − ceil(80/3)*4 = 1556 − 108 ≈ 1448`).

### Byte-Identical Ciphertexts Invariant

A core invariant of the sss v2.0 design is that **in-file ciphertexts are byte-for-byte
identical regardless of which suite wrapped the repository key**:

- The 32-byte repository key `K` is **identical** regardless of which suite wrapped it — both
  suites seal the same `K`.
- Nonce derivation uses `BLAKE2b-192(key=K, input=timestamp||NUL||file_path||NUL||plaintext)`
  with personalisation `"sss_autononce_v1"`. This uses the **same `K`** for both suites.
- Therefore the XChaCha20-Poly1305 AEAD ciphertext embedded in each `⊠{...}` marker is
  byte-identical whether `K` was wrapped via classic or hybrid.
- `sss migrate` re-wraps the per-user entries in `.sss.toml` only; **no file content is
  touched**.

The threat-model significance of this invariant — and the safety properties of `sss migrate` that depend on it — are documented in [`docs/security-model.md#sss-migrate-safety-properties`](./security-model.md#sss-migrate-safety-properties).

### Feature Gate

The hybrid suite is compiled only when the `hybrid` Cargo feature is enabled. The default
build links only libsodium and contains no trelis code.

```bash
# Default build: classic suite only
cargo build

# Hybrid suite included (adds trelis dependency)
cargo build --features hybrid
```

### Classic vs Hybrid Comparison

| Property | Classic (v1.0) | Hybrid (v2.0) |
|----------|----------------|----------------|
| KEM | X25519 (`crypto_box_seal`) | X448 + sntrup761 (trelis) |
| KDF | XSalsa20-Poly1305 nonce derivation (implicit in NaCl) | BLAKE3 `derive_key` |
| AEAD for sealed key | XSalsa20-Poly1305 | XChaCha20-Poly1305 |
| AEAD for file content | XChaCha20-Poly1305 (unchanged) | XChaCha20-Poly1305 (unchanged) |
| Post-quantum security | No | Yes (sntrup761 lattice KEM) |
| Audit status | libsodium (extensively audited) | trelis (unaudited, experimental) |
| Sealed key size (bytes) | 80 | 1167 |
| `.sss.toml` size delta/user | — | +~1448 base64 chars |
| Default | Yes | No (opt-in) |

**Classic (libsodium) is the recommended default for all production deployments.** The hybrid
suite is opt-in and should only be used when post-quantum key-wrapping is required and the
experimental status of trelis is understood and accepted.

For the per-suite threat-model breakdown (divergent assumptions, shared assumptions, audit pedigree row by row), see [`docs/security-model.md#per-suite-threat-tables`](./security-model.md#per-suite-threat-tables).

---

## Key Derivation

Argon2id derives the symmetric wrapping key used to encrypt user private keys on disk; see [`docs/security-model.md#key-derivation-argon2id`](./security-model.md#key-derivation-argon2id) for the threat-model framing (offline brute-force-attack resistance, parameter-level rationale, DoS-protection consequences).

### Algorithm: Argon2id v1.3

**Specification**: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
**Winner**: Password Hashing Competition (2015)

#### Why Argon2id?

1. **Hybrid Mode**: Combines data-dependent (Argon2d) and data-independent (Argon2i) modes
2. **Memory-Hard**: Resistant to GPU/ASIC/FPGA attacks
3. **Configurable**: Adjustable time/memory trade-offs
4. **Side-Channel Resistant**: Timing-attack resistant
5. **Widely Adopted**: OWASP recommended, used by 1Password, Bitwarden, etc.

#### Security Levels

```rust
pub struct KdfParams {
    pub ops_limit: u64,    // Time cost (iterations)
    pub mem_limit: usize,  // Memory cost (bytes)
}

impl KdfParams {
    /// SENSITIVE (DEFAULT) - Maximum security
    /// ~2 seconds on modern CPU, 256 MiB RAM
    pub fn sensitive() -> Self {
        Self {
            ops_limit: crypto_pwhash_OPSLIMIT_SENSITIVE as u64,  // 4 iterations
            mem_limit: crypto_pwhash_MEMLIMIT_SENSITIVE as usize, // 256 MiB
        }
    }

    /// MODERATE - Balanced security/performance
    /// ~1 second on modern CPU, 128 MiB RAM
    pub fn moderate() -> Self {
        Self {
            ops_limit: crypto_pwhash_OPSLIMIT_MODERATE as u64,    // 3 iterations
            mem_limit: crypto_pwhash_MEMLIMIT_MODERATE as usize,  // 128 MiB
        }
    }

    /// INTERACTIVE - Fast but less secure
    /// ~0.5 seconds on modern CPU, 64 MiB RAM
    /// WARNING: Not recommended for production
    pub fn interactive() -> Self {
        Self {
            ops_limit: crypto_pwhash_OPSLIMIT_INTERACTIVE as u64, // 2 iterations
            mem_limit: crypto_pwhash_MEMLIMIT_INTERACTIVE as usize, // 64 MiB
        }
    }
}
```

#### Cost Estimates

| Level | Ops | Memory | Time (CPU) | GPU Speedup | ASIC Cost |
|-------|-----|--------|------------|-------------|-----------|
| Sensitive | 4 | 256 MiB | ~2.0s | ~2-4x | Very High |
| Moderate | 3 | 128 MiB | ~1.0s | ~4-8x | High |
| Interactive | 2 | 64 MiB | ~0.5s | ~8-16x | Moderate |

**Rationale for Default (Sensitive)**:
- Keys are generated once and reused
- 2-second delay is acceptable for key generation
- Maximum protection against offline brute-force attacks

#### Key Derivation Implementation

```rust
pub fn derive_with_params(passphrase: &str, salt: &Salt, params: &KdfParams) -> Result<Self> {
    let mut key = [0u8; 32];  // 256-bit output

    let result = unsafe {
        crypto_pwhash(
            key.as_mut_ptr(),                    // Output key
            32,                                  // Key length
            passphrase.as_ptr() as *const i8,   // Password
            passphrase.len() as u64,            // Password length
            salt.as_bytes().as_ptr(),           // Salt
            params.ops_limit,                    // Time cost
            params.mem_limit,                    // Memory cost
            crypto_pwhash_ALG_ARGON2ID13,       // Argon2id v1.3
        )
    };

    if result != 0 {
        return Err(anyhow!("Key derivation failed"));
    }

    Ok(DerivedKey(key))
}
```

#### Salt Generation

```rust
pub fn new() -> Self {
    let mut salt = [0u8; crypto_pwhash_SALTBYTES as usize];  // 16 bytes
    unsafe {
        randombytes_buf(salt.as_mut_ptr() as *mut c_void, salt.len());
    }
    Salt(salt)
}
```

**Properties**:
- **Unique**: Cryptographically random per key
- **Size**: 128 bits (16 bytes)
- **Storage**: Stored alongside encrypted key
- **CSPRNG**: Uses OS-provided random source

## Hash Functions

BLAKE2b is used exclusively for deterministic nonce derivation in sss; see [`docs/security-model.md#deterministic-nonces`](./security-model.md#deterministic-nonces) for the threat-model rationale (clean git diffs, controlled information leakage, nonce-collision-safety analysis).

### Algorithm: BLAKE2b

**Specification**: [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)

#### Parameters

```rust
pub const BLAKE2B_OUTBYTES: usize = 24;   // 192 bits (for nonce)
pub const BLAKE2B_KEYBYTES: usize = 32;   // 256 bits (repository key)
```

#### Why BLAKE2b?

1. **Faster than MD5**: While being cryptographically secure
2. **Keyed Mode**: Built-in MAC functionality
3. **Configurable Output**: Variable-length output (we use 24 bytes)
4. **Personalization**: Domain separation via personalization string
5. **No Length Extension**: Resistant to length extension attacks

#### Usage in SSS

BLAKE2b is used **exclusively** for deterministic nonce derivation, not for general hashing.

```rust
fn derive_nonce(
    plaintext: &[u8],
    key: &RepositoryKey,
    timestamp: &str,
    file_path: &str,
) -> Result<[u8; NONCEBYTES]> {
    // Concatenate inputs: timestamp || file_path || plaintext
    let mut input = Vec::new();
    input.extend_from_slice(timestamp.as_bytes());
    input.extend_from_slice(file_path.as_bytes());
    input.extend_from_slice(plaintext);

    // Hash with BLAKE2b in keyed mode
    let mut nonce = [0u8; NONCEBYTES];
    let mut state = Blake2bState::new(NONCEBYTES, key.as_bytes())?;
    state.update(&input)?;
    state.finalize(&mut nonce)?;

    Ok(nonce)
}
```

**Personalization String**: `"sss_autononce_v1"`

This provides domain separation, ensuring nonces derived for SSS cannot be confused with other uses of BLAKE2b.

## Nonce Derivation

### Deterministic Nonce Strategy

SSS uses **deterministic nonce derivation** instead of random nonces. This design choice enables git-friendly diffs.

#### Nonce Derivation Formula

```
Nonce = BLAKE2b-192(Key, Timestamp || FilePath || Plaintext)
       with personalization "sss_autononce_v1"
```

#### Inputs

1. **Timestamp** - Project initialization timestamp (ISO 8601)
2. **FilePath** - Relative path from project root
3. **Plaintext** - The secret value being encrypted
4. **Key** - Repository key (used as BLAKE2b key)

#### Properties

**Uniqueness Guarantees**:
- Different plaintexts → Different nonces (hash collision resistance)
- Different files → Different nonces (path included in hash)
- Different projects → Different nonces (unique timestamp per project)
- Different keys → Different nonces (key used as BLAKE2b key)

**Determinism**:
- Same inputs → Same nonce
- Enables git diff to only show actual secret changes
- No spurious diffs from random nonce changes

#### Security Analysis

**Nonce Reuse Risk**: ELIMINATED

The only way to get nonce reuse is:
```
Same Key AND Same Timestamp AND Same FilePath AND Same Plaintext
```

If all four are identical, **we want the same nonce** (deterministic encryption).

**Information Leakage**: MINIMAL

Deterministic encryption reveals:
- ✅ When a secret **changes** (different ciphertext)
- ✅ When a secret **doesn't change** (same ciphertext)
- ❌ What the secret **is** (still requires key to decrypt)

This is an acceptable trade-off for git-friendly operation.

#### Implementation

```rust
pub(crate) struct Blake2bState {
    state: crypto_generichash_state,
}

impl Blake2bState {
    pub fn new(outlen: usize, key: &[u8]) -> Result<Self> {
        let mut state = MaybeUninit::uninit();
        let result = unsafe {
            crypto_generichash_init(
                state.as_mut_ptr(),
                key.as_ptr(),
                key.len(),
                outlen,
            )
        };
        if result != 0 {
            return Err(anyhow!("BLAKE2b init failed"));
        }
        Ok(Self { state: unsafe { state.assume_init() } })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let result = unsafe {
            crypto_generichash_update(
                &mut self.state,
                data.as_ptr(),
                data.len() as u64,
            )
        };
        if result != 0 {
            return Err(anyhow!("BLAKE2b update failed"));
        }
        Ok(())
    }

    pub fn finalize(&mut self, output: &mut [u8]) -> Result<()> {
        let result = unsafe {
            crypto_generichash_final(
                &mut self.state,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        if result != 0 {
            return Err(anyhow!("BLAKE2b finalize failed"));
        }
        Ok(())
    }
}
```

## Vault Lockfile Digest (keyed BLAKE2b MAC)

This subsection documents the cryptographic construction used for `.sss.vault.lock`
entry digests (Phase 48, Plan 01). It uses the **same libsodium primitive** as nonce
derivation ([§ Nonce Derivation](#nonce-derivation)) — `crypto_generichash_blake2b_salt_personal`
via `libsodium-sys` — but with distinct parameters that make it a **keyed MAC** rather
than a nonce-derivation call. The two usages are domain-separated by different
`personal` tag bytes and by different output widths; they are completely independent.

For the threat-model rationale (what offline oracle this closes and why the key is
required), see [§ Vault Lockfile Integrity](./security-model.md#vault-lockfile-integrity)
in `docs/security-model.md`. For the surrounding vault bootstrap-trust-chain
(AppRole auth, CA-pinning, classic-v1 gate, envelope-sig v3 context), see
[§ Envelope Signatures (v2)](#envelope-signatures-v2) and the vault section of
`docs/security-model.md`.

### Primitive

```
crypto_generichash_blake2b_salt_personal(
    out      = [u8; 32],          // 32-byte output (LOCKFILE_DIGEST_LEN)
    in       = resolved_value_bytes,
    key      = repo_key.to_bytes(),  // 32-byte RepositoryKey — never committed
    salt     = NULL,              // unused; libsodium requires NULL or zeroed
    personal = LOCKFILE_EFFECTIVE_PERSONAL,  // b"sss-vault-lock-v" (16 bytes)
)
```

**Library:** `libsodium-sys` — no new crypto dependency (VNET-05 zero-new-crypto-deps).
The `#[cfg(miri)]` test stub replaces the FFI call with a deterministic zero array for
Miri-compatible test runs; production builds always use the FFI path.

### Constants (frozen for the lockfile format)

```rust
/// Human-readable label stored in the TOML `personal` field.
/// 17 bytes — the trailing `'1'` is stripped by BLAKE2B_PERSONALBYTES truncation.
pub const LOCKFILE_PERSONAL: &[u8] = b"sss-vault-lock-v1";

/// The 16 bytes that libsodium actually sees as the `personal` parameter.
/// FROZEN FOREVER: changing these bytes silently invalidates every existing
/// `.sss.vault.lock` entry. Any future lockfile format version MUST use a
/// different effective personal value and a new schema `version` field.
pub const LOCKFILE_EFFECTIVE_PERSONAL: &[u8; 16] = b"sss-vault-lock-v";

/// Output width in bytes; stored as 64 lowercase hex characters.
/// FROZEN: widening or narrowing silently invalidates existing lockfiles.
pub const LOCKFILE_DIGEST_LEN: usize = 32;
```

The 17-byte source string `"sss-vault-lock-v1"` is truncated to 16 bytes because
`BLAKE2B_PERSONALBYTES` = 16 (defined in `libsodium-sys`). The effective 16-byte value
is stored in `LOCKFILE_EFFECTIVE_PERSONAL` as an explicitly named, documented constant
(a named-constant-freeze pattern: see `48-01-SUMMARY.md` decision 1). The trailing
`'1'` is not part of the effective domain-separation tag.

### Distinguished from Nonce-Derivation BLAKE2b

| Property | Nonce derivation | Lockfile MAC |
|----------|-----------------|--------------|
| Output width | 24 bytes | 32 bytes |
| `personal` tag | `b"sss_autononce_v1"` (16 bytes) | `b"sss-vault-lock-v"` (16 bytes, from 17-byte source) |
| Key | `RepositoryKey` (32 bytes) | `RepositoryKey` (32 bytes) |
| Purpose | Deterministic XChaCha20 nonce | Keyed MAC for lockfile integrity check |
| Where stored | Embedded in `⊠{...}` ciphertext markers | `.sss.vault.lock` `digest` field as 64 hex chars |

The distinct `personal` tags and output widths ensure that a lockfile digest cannot be
confused with a nonce, even though both are computed with the same key. A BLAKE2b output
computed under `personal = b"sss_autononce_v1"` with 24-byte width is cryptographically
unrelated to one computed under `personal = b"sss-vault-lock-v"` with 32-byte width.

### Frozen-Parameter Invariant

The effective 16-byte personal tag **and** the 32-byte output width are frozen for
`version = 1` lockfiles. Changing either silently invalidates every existing
`.sss.vault.lock` entry: `vault verify` would recompute a different digest and report
drift against all previously locked references, even when the Vault values have not
changed. Any lockfile format change must increment the TOML `version` field and
introduce a new frozen `LOCKFILE_EFFECTIVE_PERSONAL` constant.

### Security Property

The keyed digest is a commitment to the secret value that is safe to commit alongside
source code because it cannot be reversed or used for offline dictionary confirmation
without the `RepositoryKey`. Two repositories with different `RepositoryKey` values
produce different digests for identical secret values, preventing cross-repository
comparison (test: `different_keys_different_digest`, VLOCK-03).

For the full oracle-closure argument and the no-plaintext guarantee, see
[§ Vault Lockfile Integrity](./security-model.md#vault-lockfile-integrity).

---

## Memory Safety

### Zeroization

All sensitive data is zeroized on drop using the `zeroize` crate.

#### Wrapped Types

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RepositoryKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Salt([u8; 16]);
```

#### Behavior

When a value goes out of scope:
1. `Zeroize::zeroize()` is called automatically
2. Memory is overwritten with zeros
3. Compiler optimizations cannot remove the zeroing (via `volatile_set_memory`)

#### Protection Against

- Memory dumps (core dumps, swap)
- Use-after-free vulnerabilities
- Heap/stack inspection attacks
- Cold boot attacks (partial mitigation)

### Constant-Time Operations

Critical operations use constant-time implementations to prevent timing side-channels.

```rust
use subtle::ConstantTimeEq;

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
```

**Why This Matters**:
- Prevents timing attacks that could leak key bits
- Ensures comparison time doesn't depend on input values
- Required for cryptographic key equality checks

### Memory Limits

```rust
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;           // 100 MB
pub const MAX_MARKER_CONTENT_SIZE: usize = 100 * 1024 * 1024; // 100 MB
```

**Rationale**:
- Prevents memory exhaustion attacks
- Limits Argon2id work (memory cost is per-operation)
- Reasonable limit for source code files

## Implementation Patterns

### Type Safety

All cryptographic types are wrapped in newtype structs:

```rust
pub struct PublicKey([u8; 32]);
pub struct SecretKey([u8; 32]);
pub struct RepositoryKey([u8; 32]);
pub struct DerivedKey([u8; 32]);
pub struct Salt([u8; 16]);
```

**Benefits**:
- Type safety prevents key confusion
- Cannot accidentally use public key as secret key
- Compiler enforces correct usage

### Error Handling

All cryptographic operations return `Result<T, anyhow::Error>`:

```rust
pub fn encrypt(plaintext: &[u8], key: &RepositoryKey, ...) -> Result<Vec<u8>> {
    // ...
}

pub fn decrypt(ciphertext: &[u8], key: &RepositoryKey) -> Result<Vec<u8>> {
    // ...
}
```

**Benefits**:
- Forces error handling (no silent failures)
- Provides context via `anyhow::Error`
- Allows `?` operator for clean code

### Serialization

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct StoredKeyPair {
    pub uuid: String,
    pub public_key: String,          // Base64
    pub encrypted_secret_key: String, // Base64
    pub salt: Option<String>,        // Base64 (if password-protected)
    pub kdf_ops_limit: Option<u64>,
    pub kdf_mem_limit: Option<usize>,
    pub in_keyring: bool,
}
```

**Security Notes**:
- Only encrypted keys are serialized
- Plaintext keys never touch disk
- Base64 encoding for safe TOML storage

## Security Properties

### Authenticated Encryption

**All encryption uses AEAD** (Authenticated Encryption with Associated Data):

| Primitive | Cipher | MAC | Tag Size |
|-----------|--------|-----|----------|
| XChaCha20-Poly1305 | XChaCha20 | Poly1305 | 128 bits |
| XSalsa20-Poly1305 | XSalsa20 | Poly1305 | 128 bits |

**Properties**:
- **Confidentiality**: Ciphertext doesn't reveal plaintext
- **Authenticity**: Tampered ciphertexts are rejected
- **Integrity**: Any modification is detected

### Key Derivation Properties

**Argon2id provides**:
- **Preimage Resistance**: Cannot reverse password from derived key
- **Collision Resistance**: Different passwords → Different keys
- **Brute-Force Resistance**: Memory-hard function resists GPU/ASIC attacks

**Cost to brute-force** (with Sensitive parameters):
- **Time**: ~2 seconds per guess per core
- **Memory**: 256 MiB per concurrent guess
- **GPU**: Limited speedup (~2-4x) due to memory bottleneck

### Nonce Security

**With 192-bit nonces**:
- **Birthday Bound**: 2^96 encryptions before 50% collision probability
- **Safety Margin**: Effectively unlimited for reasonable usage

**Deterministic nonce derivation** ensures:
- No accidental nonce reuse
- Git-friendly diffs
- Controlled information leakage

## Code Examples

### Complete Encryption Flow

```rust
use sss::crypto::{RepositoryKey, encrypt, decrypt};

fn example_encryption() -> Result<()> {
    // 1. Generate repository key
    let key = RepositoryKey::new();

    // 2. Prepare context
    let timestamp = "2025-01-01T00:00:00Z";
    let file_path = "config/secrets.txt";
    let plaintext = b"my_secret_password";

    // 3. Encrypt
    let ciphertext = encrypt(plaintext, &key, timestamp, file_path)?;

    // 4. Ciphertext format: [nonce || encrypted || mac]
    assert_eq!(ciphertext.len(), 24 + plaintext.len() + 16);

    // 5. Decrypt
    let recovered = decrypt(&ciphertext, &key)?;
    assert_eq!(recovered, plaintext);

    Ok(())
}
```

### Complete Key Management Flow

```rust
use sss::crypto::KeyPair;
use sss::kdf::{KdfParams, DerivedKey, Salt};

fn example_key_management() -> Result<()> {
    // 1. Generate user keypair
    let keypair = KeyPair::generate()?;

    // 2. Get user password
    let password = "user_strong_password";

    // 3. Generate random salt
    let salt = Salt::new();

    // 4. Derive key from password (using sensitive parameters)
    let params = KdfParams::sensitive();
    let derived_key = DerivedKey::derive_with_params(password, &salt, &params)?;

    // 5. Encrypt secret key with derived key
    let encrypted_secret = encrypt(
        keypair.secret_key.as_bytes(),
        &RepositoryKey::from_bytes(derived_key.as_bytes())?,
        "key_storage",
        "user_key",
    )?;

    // 6. Store: uuid, public_key (plain), encrypted_secret, salt, kdf_params
    // (Implementation details in keystore module)

    Ok(())
}
```

### Repository Key Wrapping

```rust
use sss::crypto::{KeyPair, RepositoryKey, wrap_repository_key, unwrap_repository_key};

fn example_key_wrapping() -> Result<()> {
    // 1. Generate repository key
    let repo_key = RepositoryKey::new();

    // 2. Generate user keypair
    let keypair = KeyPair::generate()?;

    // 3. Wrap repository key with user's public key
    let wrapped = wrap_repository_key(&repo_key, &keypair.public_key)?;

    // 4. Later: unwrap with user's keypair
    let unwrapped = unwrap_repository_key(&wrapped, &keypair)?;

    // 5. Keys should match
    assert_eq!(repo_key.to_base64(), unwrapped.to_base64());

    Ok(())
}
```

## Keystore Entry Signatures (v3)

Phase 18 introduces hybrid AND-composition signatures over keystore entries. Every `~/.config/sss/keys/<uuid>.toml` entry written by an `sss` v2.2-or-later client carries a `[signature]` sub-table whose Ed448 + ML-DSA-65 components both verify before the entry is accepted on read.

Phase 38 (REM-04) extends the signed payload from 6 to 8 fields by adding `kdf_ops_limit` and `kdf_mem_limit` as fields 7–8 (decimal-ASCII encoded), bumps the domain-separation context from `v1` to `v2`, and introduces `format_version=3` for entries with KDF params authenticated. Existing `format_version=2` entries remain loadable but must be re-signed via `sss keys upgrade <uuid>` to reach v3.

### Format-Version Dispatch

Each on-disk entry carries a `format_version` field:

| format_version | Meaning | Read behaviour |
|----------------|---------|----------------|
| (absent) or `1` | Legacy unsigned (pre-Phase 18) | Rejected unless caller passes `--allow-unsigned` |
| `2`             | Hybrid signed (Phase 18+) | Hard verify under v1 context; re-sign to v3 recommended |
| `3`             | Hybrid signed incl. KDF params (Phase 38+) | Hard verify under v2 context; reject on mismatch |
| `>= 4`          | Future schema | Hard reject with "upgrade sss" error |

> **Note (format\_version=1 / unsigned legacy):** A `format_version=1` entry carries
> **zero signature coverage** — no signed payload exists. As a consequence, the Phase 38
> KDF anti-downgrade protection (REM-04), which relies on the numeric `kdf_ops_limit` and
> `kdf_mem_limit` values being pinned inside a verified v3 signed payload, is **orthogonal
> to v1 entries and does not apply to them**. Upgrading to `format_version=3` via
> `sss keys upgrade <uuid>` is strongly recommended for all production keystores.

Mixed keystores (some `format_version=1`, some `=2`, some `=3`) are supported — each `*.toml` file is dispatched independently. `sss keys list` displays a trailing ` (unsigned-legacy)` tag for `format_version=1` entries; the tag is omitted (silent good case) for signed entries (v2 or v3).

The transition path is `sss keys upgrade <uuid>`, which re-signs a legacy entry in place using the existing passphrase (atomic via `tempfile::NamedTempFile::persist`). v1 entries generate fresh per-entry sig keypairs; v2 entries reuse the existing sig keypairs (no rotation — only the signed payload and context change).

### Per-Entry Signing Keypair Model

Each `format_version=2` or `format_version=3` `StoredKeyPair` carries its own dedicated Ed448 + ML-DSA-65 signing keypair, generated alongside the existing X448 + sntrup761 encryption keypair. All three keypairs share a single KDF-derived KEK (Argon2id over `passphrase + salt`), so one passphrase prompt unlocks all three secret keys.

For passwordless entries (`is_password_protected = false`), no KEK is applied; sig secret keys are stored as plain base64 of raw bytes. At signing / verification time, such entries use the **0/0 sentinel** for KDF params (see below).

The canonical fields added in v2/v3:

```rust
pub struct StoredKeyPair {
    // ... existing v1 fields ...
    pub format_version: u32,                          // 1 = legacy, 2 = signed, 3 = signed incl. KDF params
    pub sig_ed448_public_key: Option<String>,         // Ed448 verifying key, base64 (57B)
    pub sig_ed448_encrypted_secret_key: Option<String>,
    pub sig_mldsa65_public_key: Option<String>,       // ML-DSA-65 verifying key, base64 (1952B)
    pub sig_mldsa65_encrypted_secret_key: Option<String>,
    pub signature: Option<KeystoreEntrySig>,
}

pub struct KeystoreEntrySig {
    pub ed448: String,    // base64 of 114-byte Ed448 sig
    pub mldsa65: String,  // base64 of 3309-byte ML-DSA-65 sig
}
```

### Canonical Encoding (Signed Payload)

The signed payload is a length-prefixed concatenation of the entry's identity-bearing fields. All integers are big-endian; lengths are 4-byte unsigned (count bytes that follow):

| # | Field | Length | Value |
|---|-------|--------|-------|
| 1 | `uuid_len` + `uuid_bytes` | 4B u32-BE + `uuid_len` | UTF-8 of `uuid` |
| 2 | `pk_len` + `pk_b64_bytes` | 4B u32-BE + `pk_len` | UTF-8 of base64-encoded `public_key` |
| 3 | `hybrid_pk_len` + `hybrid_pk_b64_bytes` | 4B u32-BE + `hybrid_pk_len` | UTF-8 (0-length if absent) |
| 4 | `sig_ed448_pk_len` + `sig_ed448_pk_b64_bytes` | 4B u32-BE + `sig_ed448_pk_len` | UTF-8 of base64-encoded `sig_ed448_public_key` |
| 5 | `sig_mldsa65_pk_len` + `sig_mldsa65_pk_b64_bytes` | 4B u32-BE + `sig_mldsa65_pk_len` | UTF-8 of base64-encoded `sig_mldsa65_public_key` |
| 6 | `created_at_len` + `created_at_bytes` | 4B u32-BE + `created_at_len` | UTF-8 of `created_at.to_rfc3339()` |
| 7 | `kdf_ops_len` + `kdf_ops_bytes` | 4B u32-BE + `kdf_ops_len` | Decimal ASCII of `kdf_ops_limit` (e.g. `"3"`) |
| 8 | `kdf_mem_len` + `kdf_mem_bytes` | 4B u32-BE + `kdf_mem_len` | Decimal ASCII of `kdf_mem_limit` (e.g. `"268435456"`) |

Fields 7–8 were added in Phase 38 (REM-04, `format_version=3`). Absent `hybrid_public_key` encodes as a 4-byte zero-length prefix followed by zero bytes (the slot is preserved for future schema growth). KDF params are decimal-ASCII (not binary) for human-legibility in debug logs and consistency with the `created_at` timestamp encoding.

**Passwordless 0/0 sentinel:** Entries with `is_password_protected = false` do not apply Argon2id — there are no KDF cost params to sign. Both legs sign `kdf_ops_limit = 0, kdf_mem_limit = 0`. The signer and verifier both key off `stored.is_password_protected` identically, eliminating any order-dependent ambiguity (T-38-13).

Encrypted-secret fields (`encrypted_secret_key`, `hybrid_encrypted_secret_key`, `sig_*_encrypted_secret_key`) are NOT in the signed payload — the signature covers identity (public keys + uuid + timestamp + KDF cost), not storage detail. The encrypted-secret bytes are independently authenticated by the AEAD tag of XChaCha20-Poly1305 at decrypt time.

### Signature Scheme

Two signatures are computed over the same canonical payload, both required:

| Component | Algorithm | Trelis API | Sig size | Pubkey size |
|-----------|-----------|------------|----------|-------------|
| Classic | Ed448 (RFC 8032 SHAKE256) | `Ed448Standard` | 114 B | 57 B |
| Post-quantum | ML-DSA-65 (FIPS 204) | `MlDsa65Fips204` | 3309 B | 1952 B |

Both use the trelis `sign_with_context` / `verify_with_context` APIs (NOT plain `sign` / `verify`) to invoke each algorithm's native domain-separation path. The context bytes are constant across both schemes:

```rust
pub const KEYSTORE_SIG_CONTEXT: &[u8] = b"sss-keystore-entry-sig-v2";
```

Phase 38 (REM-04) bumped the context from `v1` to `v2` to reflect the extended 8-field payload. Any entry signed under the old `v1` context fails verification with the new binary, prompting `sss keys upgrade <uuid>` — the intended fail-closed migration path.

The trelis API folds the context into Ed448's RFC 8032 §8.1 with-context branch and into ML-DSA-65's FIPS 204 §5.1 ctx parameter — no application-layer concatenation needed. This prevents cross-protocol confusion attacks (e.g. a Phase 19 envelope signature being valid as a keystore signature).

### On-Disk Schema (TOML)

A `format_version=3` entry on disk (Phase 38+):

```toml
uuid = "abc12345-6789-..."
public_key = "<b64-classic-pk>"
encrypted_secret_key = "<b64-classic-sk-encrypted>"
salt = "<b64-salt>"
created_at = "2026-05-09T12:00:00Z"
is_password_protected = true
in_keyring = false
hybrid_public_key = "<b64-x448-sntrup-pk>"
hybrid_encrypted_secret_key = "<b64-hybrid-sk-encrypted>"
format_version = 3
sig_ed448_public_key = "<b64-ed448-pk-57b>"
sig_ed448_encrypted_secret_key = "<b64-ed448-sk-encrypted>"
sig_mldsa65_public_key = "<b64-mldsa-pk-1952b>"
sig_mldsa65_encrypted_secret_key = "<b64-mldsa-sk-encrypted>"

[signature]
ed448 = "<b64-114b>"
mldsa65 = "<b64-3309b>"
```

The `[signature]` blob authenticates all 8 payload fields (uuid, public_key, hybrid_public_key, sig_ed448_public_key, sig_mldsa65_public_key, created_at, kdf_ops_limit, kdf_mem_limit) under the `v2` context. Substituting weaker KDF params on disk will cause verification to fail, detecting a KDF parameter substitution (downgrade) attack (T-38-10, CRY-05).

### Verification Algorithm

Pseudocode for verifying an entry on read:

```text
1. Deserialise TOML → StoredKeyPair { format_version, ..., signature: Option<KeystoreEntrySig>, ... }.
2. If format_version is absent or 1:
    - If caller passed --allow-unsigned: accept; skip steps 3-8.
    - Else: hard-reject with "unsigned legacy format" error.
3. If format_version >= 4: hard-reject with "unsupported format_version" error.
4. Assert format_version == 2 or 3 implies signature is Some(...) AND all four sig pubkey fields are Some(...).
   If any are None: hard-reject with "missing signature" or "missing sig pubkey" error.
5. Determine KDF params for payload:
    - If is_password_protected == true: use keystore's kdf_params (ops_limit, mem_limit).
    - If is_password_protected == false (passwordless): use 0/0 sentinel.
6. Build canonical 8-field payload over (uuid, public_key, hybrid_public_key, sig_ed448_public_key,
   sig_mldsa65_public_key, created_at, kdf_ops_limit, kdf_mem_limit).
7. Decode base64 of signature.ed448 (114B) and signature.mldsa65 (3309B).
8. Run BOTH:
    - Ed448Standard::verify_with_context(&ed448_pk, &payload, KEYSTORE_SIG_CONTEXT, &ed448_sig)
        → must return true.
    - MlDsa65Fips204::verify_with_context(&mldsa_pk, &payload, KEYSTORE_SIG_CONTEXT, &mldsa_sig)
        → must return Ok(()).
   If either fails: hard-reject with the failure-mode error below.
```

AND-composition: BOTH legs must verify. If only Ed448 verifies, the entry is rejected. If only ML-DSA-65 verifies, the entry is rejected. The composition is OR-secure under the union of Ed448 + ML-DSA-65 security assumptions; AND-broken means both algorithms broken.

### Failure Modes

The canonical hard-error message for verify-on-read failure:

```text
keystore: signature verification failed for <uuid> (file: <path>) — entry rejected; if this is expected after a format upgrade run `sss keys upgrade <uuid>`
```

Sub-causes (tampered public key, tampered Ed448 sig, tampered ML-DSA-65 sig, mutated timestamp, etc.) all produce the same message — sub-cause information is intentionally NOT leaked, since an attacker who can mutate one field can typically mutate any field.

There is no soft-fail mode, no warning-only mode, and no `--ignore-signature-errors` flag. ROADMAP §Phase 18 success-criterion 4 mandates hard-error on verification failure.

### Cross-References

- Canonical implementation: `src/keystore/sig.rs` (struct, canonical-encoding builder, sign/verify primitives).
- Wired into command paths: `src/commands/keys.rs` (`generate`, `import`, `export`, `upgrade`, `list`).
- Executable spec (regression tests): `tests/keystore_signature_negative_paths.rs` (NEG-01..NEG-07 mandatory + bonus tests).
- Trelis upstream: pinned commit `5374dff482ba94a94695794b5e4554f908eb0d4d`, crates `trelis-primitives::Ed448Standard` (`crates/trelis-primitives/src/ed448_scheme.rs`) + `trelis-primitives::MlDsa65Fips204` (`crates/trelis-primitives/src/mldsa.rs`).
- Test vectors: `vectors/hybrid-sig.json` in trelis upstream (sanity-check reference).

**Final state (v2.5 / Phase 38):** Phase 18 (PQSIG-01..03) closed with AND-composition
Ed448 + ML-DSA-65, payload-first canonical encoding, and domain-separation
context bytes `b"sss-keystore-entry-sig-v1"`. Phase 38 (REM-04) extended the
signed payload to 8 fields (adding `kdf_ops_limit` and `kdf_mem_limit`) and
bumped the context to `b"sss-keystore-entry-sig-v2"`, closing CRY-05 (KDF
parameter substitution downgrade attack). New entries are written as
`format_version=3`; existing v1/v2 entries are upgraded in-place via
`sss keys upgrade <uuid>`. Each leg verifies independently and both must succeed;
verification errors report which leg failed (Ed448 / ML-DSA-65 / both) for
operator triage. Negative-path coverage in
`tests/keystore_signature_negative_paths.rs` exercises tampered ciphertext,
context-byte mismatch, and downgrade attempts.

## Envelope Signatures (v2)

Phase 19 introduces hybrid AND-composition signatures over the entire `.sss.toml`
project envelope. The signed payload covers `version`, `created`, and the canonical
(sorted-by-username) `users` table including each user's `public`, `sealed_key`,
`added`, `hybrid_public`, `sig_ed448_public`, and `sig_mldsa65_public`.
Verification at load time is non-negotiable for `format_version >= 2`; the legacy v1
schema remains readable but is rejected for any mutating verb (see PQSIG-06 below).

### Cryptographic Primitives

- **Ed448** (RFC 8032 EdDSA): classical signature leg.
- **ML-DSA-65** (FIPS 204): post-quantum signature leg.
- Both legs MUST verify (AND-composition); single-leg success is rejected
  (T-19-06 mitigation).

### Domain-Separation Context

The signed payload is prefixed with the byte-exact ASCII string used as the signing
context (D-02):

```rust
pub const ENVELOPE_SIG_CONTEXT: &[u8] = b"sss-toml-envelope-sig-v2";
```

Phase 38 (REM-01) bumped the envelope context from `v1` to `v2`. This MUST differ
from the keystore entry signature context (`b"sss-keystore-entry-sig-v2"`) to prevent
cross-context replay (T-19-01). Any change to either context requires a
`format_version` bump and must update both this section and the corresponding
drift-detector unit test.

### Canonical Signed Payload (D-03)

Field order is fixed; each variable-length field is preceded by a `u32`-BE length
prefix to prevent length-extension / boundary-shift attacks (T-19-02).

**Updated Phase 38 (REM-01/02):** fields 3-8 were added to close CRY-06 (configuration
fields outside the signed payload). An independent implementer MUST include all 8 fixed
fields before the per-user loop, in the exact order shown:

| # | Field | Encoding | Notes |
|---|-------|----------|-------|
| 1 | `version` | u32-BE length + UTF-8 bytes | e.g. `"2.0"` |
| 2 | `created` | u32-BE length + UTF-8 bytes | RFC 3339 envelope creation timestamp |
| 3 | `format_version` | u32-BE length + UTF-8 decimal string | e.g. `"2"` |
| 4 | `secrets_filename` | u32-BE length + UTF-8 bytes; zero-length if `None` | e.g. `"secrets.env"` |
| 5 | `secrets_suffix` | u32-BE length + UTF-8 bytes; zero-length if `None` | e.g. `".enc"` |
| 6 | `ignore` | u32-BE length + UTF-8 bytes; zero-length if `None` | gitignore-style pattern |
| 7 | `hooks.git_pre_commit` | u32-BE length + UTF-8 bytes; `"true"` / `"false"` / `""` if `None` | Phase 38 REM-02 |
| 8 | `hooks.git_post_checkout` | u32-BE length + UTF-8 bytes; `"true"` / `"false"` / `""` if `None` | Phase 38 REM-02 |
| 9..N | Per-user entries, sorted by username | — | See sub-table below |

Per-user fields (each prefixed with u32-BE length), within a user block sorted alphabetically by username:

| Sub-field | Notes |
|-----------|-------|
| username | UTF-8 bytes |
| `public` | base64 X25519 KEM pubkey (classic identity anchor) |
| `sealed_key` | base64 sealed repository key (per-user) |
| `added` | RFC 3339 timestamp |
| `hybrid_public` | base64; zero-length prefix if `None` |
| `sig_ed448_public` | base64 Ed448 verifying key; zero-length prefix if `None` |
| `sig_mldsa65_public` | base64 ML-DSA-65 verifying key; zero-length prefix if `None` |

The exact field list and order is defined by `src/envelope_sig.rs::build_envelope_payload`.
Any change to this list requires a `format_version` bump and must update both this table
and the drift-detector unit test.

### Real `.sss.toml` Schema (Post-Phase-38, Abridged)

```toml
version = "2.0"
created = "2026-05-09T12:34:56Z"
format_version = 2
secrets_filename = "secrets.env"  # field 4 in signed payload (Phase 38 REM-01)
secrets_suffix = ".enc"           # field 5 in signed payload (Phase 38 REM-01)
ignore = "node_modules"           # field 6 in signed payload (Phase 38 REM-01)

[hooks]
git_pre_commit = true             # field 7 in signed payload (Phase 38 REM-02)
git_post_checkout = false         # field 8 in signed payload (Phase 38 REM-02)

[users.alice]
public = "..."              # base64 X25519 KEM pubkey (classic identity anchor)
sealed_key = "..."          # base64 sealed repository key (per user)
added = "2026-05-09T12:34:56Z"
hybrid_public = "..."       # base64 hybrid KEM pubkey (Phase 18; Some in v2)
sig_ed448_public = "..."    # base64 Ed448 verifying key (Phase 19; Some in v2)
sig_mldsa65_public = "..."  # base64 ML-DSA-65 verifying key (Phase 19; Some in v2)

[envelope.sig]
ed448 = "..."     # base64 Ed448 signature over canonical payload (114 bytes)
mldsa65 = "..."   # base64 ML-DSA-65 signature over canonical payload (3309 bytes)
```

Fields `salt`, `recovery_share`, per-user `encrypted_share`, and `public_key` do NOT
exist in `ProjectConfig` / `UserConfig` and MUST NOT appear in the schema.

### Verification Algorithm (D-05 Try-All-Users)

1. Build the canonical payload from the in-memory config using
   `src/envelope_sig.rs::build_envelope_payload`.
2. Extract `[envelope.sig]` — fail with "missing sig table" if absent.
3. Iterate `users` in sorted-by-username order (BTreeMap-style determinism).
4. For each user that has BOTH `sig_ed448_public` and `sig_mldsa65_public`:
   base64-decode both, then attempt `verify_envelope(ed448_pk, mldsa_pk, payload, sig)`.
5. The first successful verification wins; return `Ok(())`.
6. If all users fail, return a hard error listing every attempted username and
   the per-user failure reason (including which leg failed).

### Sign-on-Write Call Sites (D-17)

The envelope is re-signed on disk after every mutation:

| Command | Writer |
|---------|--------|
| `sss init --crypto hybrid` | First user (the initialising user) |
| `sss users add` | Invoking user |
| `sss users remove` | Invoking user (sign AFTER `RotationManager` completes) |
| `sss migrate` | Invoking user |
| `sss envelope upgrade-sig` | First keystore-resolvable user |

Atomic writes go through `tempfile::NamedTempFile::new_in(parent).persist(target)`
to prevent torn files (D-13).

### `format_version` Dispatch (D-09)

| Version | Behaviour |
|---------|-----------|
| 1 (legacy / absent) | Read-only verbs allowed (classic envelopes); hybrid v1 envelopes are rejected for any mutating verb with the PQSIG-06 actionable error |
| 2 (signed) | Verify-on-read; reject if any leg fails |
| ≥ 3 (future) | Hard-rejected as forward-incompatible with "upgrade sss" message |

### PQSIG-06 Actionable Error (D-10)

Mutating verbs invoked against a v1 envelope return the byte-exact text:

```
<PATH>: unsigned envelope (format_version=1); run `sss envelope upgrade-sig` to sign in place
```

Where `<PATH>` is the resolved path passed to `require_signed` (typically the
absolute path to `.sss.toml` discovered by `get_project_config_path()`).

This string is asserted byte-exact by `neg_04_unsigned_v2_exact_string` in
`tests/envelope_signature_negative_paths.rs`.

### Threat Model

| Threat ID | Description | Mitigation |
|-----------|-------------|-----------|
| T-19-01 | Cross-context replay (envelope ↔ keystore) | Distinct context bytes (`b"sss-toml-envelope-sig-v2"` ≠ `b"sss-keystore-entry-sig-v2"`); assert_ne unit test |
| T-19-02 | Canonicalisation drift | u32-BE length-prefixed payload; determinism test |
| T-19-03 | sign↔verify drift | proptest round-trip across 50 arbitrary envelopes |
| T-19-04 | Unsigned write reaches disk | Sign-on-write at all 5 mutating sites + NEG-04 integration test |
| T-19-05 | Verify-bypass on load | Single dispatch loader + verify-passes-round-trip test |
| T-19-06 | Single-leg accept | AND-composition verifier + NEG-01/NEG-02 (each leg tamper is detected independently) |
| T-19-07 | Canonicalisation bypass (payload tamper) | Length-prefixed payload + NEG-03 (per-user `sealed_key` tamper detected) |
| T-19-08 | Vendor drift (Trelis dependency) | SHA pinned in `Cargo.toml` (`5374dff482ba94a94695794b5e4554f908eb0d4d`); CI grep invariant (count = 3) |

### Cross-References

- Canonical implementation: `src/envelope_sig.rs` (`ENVELOPE_SIG_CONTEXT`, `build_envelope_payload`, `sign_envelope`, `verify_envelope`, `verify_envelope_signature`).
- Schema: `src/project.rs` (`ProjectConfig`, `UserConfig`, `EnvelopeMeta`, `EnvelopeSig`, `require_signed`).
- Sign-on-write wiring: `src/commands/init.rs`, `src/commands/users.rs`, `src/commands/migrate.rs`, `src/commands/envelope.rs`.
- Executable spec (regression tests): `tests/envelope_signature_negative_paths.rs` (7 sign-on-write + round-trip + upgrade-sig + 4 NEG tests).
- Trelis upstream: pinned commit `5374dff482ba94a94695794b5e4554f908eb0d4d`.

**Final state (v2.5 / Phase 38):** Phase 19 (PQSIG-04..06) closed with sign-on-write at
`init` / `users add` / `users remove` / `migrate` and verify-on-read on every
envelope load. Phase 38 (REM-01) bumped the context from `b"sss-toml-envelope-sig-v1"`
to `b"sss-toml-envelope-sig-v2"`. Distinct context bytes distinguish envelope sigs
from keystore-entry sigs (`b"sss-keystore-entry-sig-v2"`). Per-leg error reporting
matches the keystore pattern. Negative-path coverage in
`tests/envelope_signature_negative_paths.rs` exercises tampered envelope body,
swapped sig bytes, missing signature, and context-byte mismatch.

## References

- **XChaCha20-Poly1305**: [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
- **Curve25519**: [Bernstein, D.J. "Curve25519"](https://cr.yp.to/ecdh.html)
- **Argon2**: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- **BLAKE2**: [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)
- **libsodium**: [Documentation](https://doc.libsodium.org/)
- **NaCl**: [Networking and Cryptography library](https://nacl.cr.yp.to/)

---

**Last Updated**: 2026-04-26
**Version**: 2.0.0
**Security Review**: See [security-model.md](./security-model.md)
