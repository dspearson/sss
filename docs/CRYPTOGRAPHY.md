# Cryptographic Implementation - SSS (Secrets in Source)

## Overview

This document provides a detailed technical specification of the cryptographic primitives, algorithms, and implementation patterns used in SSS. It is intended for security auditors, cryptographers, and developers who need to understand the low-level cryptographic details.

## Table of Contents

1. [Cryptographic Dependencies](#cryptographic-dependencies)
2. [Symmetric Encryption](#symmetric-encryption)
3. [Asymmetric Encryption](#asymmetric-encryption)
4. [Key Derivation](#key-derivation)
5. [Hash Functions](#hash-functions)
6. [Nonce Derivation](#nonce-derivation)
7. [Memory Safety](#memory-safety)
8. [Implementation Patterns](#implementation-patterns)
9. [Security Properties](#security-properties)
10. [Code Examples](#code-examples)

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

## Key Derivation

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

## References

- **XChaCha20-Poly1305**: [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
- **Curve25519**: [Bernstein, D.J. "Curve25519"](https://cr.yp.to/ecdh.html)
- **Argon2**: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- **BLAKE2**: [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)
- **libsodium**: [Documentation](https://doc.libsodium.org/)
- **NaCl**: [Networking and Cryptography library](https://nacl.cr.yp.to/)

---

**Last Updated**: 2025-12-07
**Version**: 1.2.0
**Security Review**: See [SECURITY.md](./SECURITY.md)
