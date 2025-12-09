# Security Documentation - SSS (Secrets in Source)

## Overview

This document describes the security architecture, threat model, and security practices for the SSS (Secrets in Source) project. SSS is designed to protect sensitive secrets in source code using strong cryptography.

## Table of Contents

1. [Threat Model](#threat-model)
2. [Cryptographic Architecture](#cryptographic-architecture)
3. [Key Management](#key-management)
4. [Security Features](#security-features)
5. [Security Best Practices](#security-best-practices)
6. [Known Limitations](#known-limitations)
7. [Security Audit History](#security-audit-history)
8. [Reporting Security Issues](#reporting-security-issues)

## Threat Model

### Assumptions

**Trusted**:
- The user's local machine and filesystem
- The libsodium cryptographic library
- The Rust compiler and standard library
- OS-provided CSPRNG (cryptographically secure pseudorandom number generator)

**Untrusted**:
- Git repositories (public or private)
- Network transmission
- Cloud storage providers
- Backup systems
- Other users on multi-user systems

### Assets to Protect

1. **Secret Values**: Passwords, API keys, tokens, credentials
2. **Private Keys**: User private keys used for decryption
3. **Repository Keys**: Symmetric keys used for project-wide encryption

### Threats

#### IN SCOPE

1. **T1: Unauthorized Access to Source Code** ✅ MITIGATED
   - **Attack**: Attacker gains read access to git repository
   - **Mitigation**: All secrets are encrypted with AES-256-GCM or XChaCha20-Poly1305

2. **T2: Man-in-the-Middle Attacks** ✅ MITIGATED
   - **Attack**: Attacker intercepts encrypted secrets during transmission
   - **Mitigation**: AEAD encryption provides authentication; tampered ciphertexts are rejected

3. **T3: Brute-Force Password Attacks** ✅ MITIGATED
   - **Attack**: Attacker attempts to guess password-protected keys
   - **Mitigation**: Argon2id with sensitive parameters (4 iterations, 256 MiB RAM) resists GPU/ASIC attacks

4. **T4: Key Confusion Attacks** ✅ MITIGATED
   - **Attack**: Attacker tricks system into using wrong key type
   - **Mitigation**: Keys are type-safe, domain-separated, and authenticated

5. **T5: Timing Attacks** ✅ PARTIALLY MITIGATED
   - **Attack**: Attacker infers secret information from timing differences
   - **Mitigation**: Constant-time comparisons for critical operations; Argon2id is timing-resistant

6. **T6: Side-Channel Attacks (Memory)** ✅ MITIGATED
   - **Attack**: Attacker reads secrets from memory dumps or swap
   - **Mitigation**: Secrets are zeroized on drop using `zeroize` crate

#### OUT OF SCOPE

1. **Malware on User's Machine**: If attacker has code execution on user's machine, game over
2. **Compromised libsodium**: We trust the cryptographic library
3. **Social Engineering**: Users can be tricked into revealing passwords
4. **Physical Access**: Physical access to unlocked machine allows key theft
5. **Supply Chain Attacks**: Compromised dependencies are out of scope

## Cryptographic Architecture

### Symmetric Encryption (Data Protection)

**Algorithm**: XChaCha20-Poly1305 (AEAD)
- **Cipher**: XChaCha20 stream cipher (extended nonce variant)
- **Authentication**: Poly1305 MAC (128-bit tag)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 192 bits (24 bytes) - prevents nonce reuse
- **Security Level**: 256-bit security

**Nonce Strategy**: Deterministic derivation using BLAKE2b
- Inputs: project timestamp, file path, plaintext content, repository key
- Prevents nonce reuse while enabling git-friendly diffs

### Asymmetric Encryption (Key Wrapping)

**Algorithm**: X25519 Sealed Boxes (Curve25519 + XSalsa20-Poly1305)
- **Key Exchange**: X25519 (ECDH over Curve25519)
- **Encryption**: XSalsa20-Poly1305 AEAD
- **Public Key Size**: 256 bits (32 bytes)
- **Private Key Size**: 256 bits (32 bytes)
- **Security Level**: 128-bit post-quantum security (Grover's algorithm reduces to ~128 bits)

### Key Derivation

**Algorithm**: Argon2id v1.3 (winner of Password Hashing Competition)
- **Mode**: Hybrid (combines Argon2i and Argon2d)
- **Output**: 256 bits (32 bytes)
- **Salt**: 128 bits (16 bytes), cryptographically random

**Security Levels**:
- **Sensitive** (default): 4 iterations, 256 MiB RAM (~2 sec on modern CPU)
- **Moderate**: 3 iterations, 128 MiB RAM (~1 sec)
- **Interactive**: 2 iterations, 64 MiB RAM (~0.5 sec) - NOT RECOMMENDED for production

### Hash Function

**Algorithm**: BLAKE2b (keyed mode)
- **Output Size**: 192 bits (24 bytes) for nonce derivation
- **Key**: Repository key used as BLAKE2b key
- **Personalization**: "sss_autononce_v1" for domain separation

## Key Management

### Key Hierarchy

```
User Passphrase
    ↓ (Argon2id)
Derived Key (256-bit)
    ↓ (encrypt)
User Private Key (256-bit)
    ↓ (X25519 decrypt)
Repository Key (256-bit)
    ↓ (XChaCha20-Poly1305)
Encrypted Secrets
```

### Key Storage Options

#### 1. Password-Protected Keys (RECOMMENDED)

**Storage**: `~/.config/sss/keys/{uuid}.toml`
- Private key encrypted with Argon2id-derived key
- Salt stored alongside encrypted key
- Permissions: `0600` (owner read/write only)

**Security Properties**:
- ✅ Resistant to offline brute-force (Argon2id)
- ✅ Requires user interaction for each use
- ✅ Can be backed up safely (encrypted)

#### 2. System Keyring (OPTIONAL)

**Storage**: OS-provided secure storage
- macOS: Keychain
- Windows: Credential Manager
- Linux: Secret Service (gnome-keyring, kwallet)

**Security Properties**:
- ✅ No plaintext keys on disk
- ✅ OS-level protection (ACLs, encryption)
- ✅ Survives system reboots
- ⚠️ Requires keyring availability (not available on all systems)

**Enable**: `export SSS_USE_KEYRING=true` or `sss settings set --use-keyring true`

#### 3. Unencrypted Keys (NOT RECOMMENDED)

**Storage**: `~/.config/sss/keys/{uuid}.toml` (base64 encoded, not encrypted)

⚠️ **SECURITY WARNING**: This mode provides **NO cryptographic protection**!

**Risks**:
- Anyone with filesystem access can steal your private key
- Backups, cloud sync, and disk images expose the key
- No protection against accidental sharing

**When to use**: Never in production; only for testing

## Security Features

### 1. Authenticated Encryption (AEAD)

All encryption uses AEAD modes (XChaCha20-Poly1305, XSalsa20-Poly1305) which provide:
- **Confidentiality**: Ciphertext doesn't reveal plaintext
- **Authenticity**: Tampered ciphertexts are rejected
- **Integrity**: Any modification is detected

### 2. Memory Safety

All sensitive data is zeroized on drop:
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; 32]);
```

This prevents:
- Memory dumps from revealing secrets
- Swap file exposure
- Use-after-free vulnerabilities

### 3. Constant-Time Operations

Critical operations use constant-time implementations:
- `subtle::ConstantTimeEq` for secret comparisons
- Argon2id for password hashing (timing-attack resistant)

### 4. Domain Separation

Different contexts use different personalization:
- Nonce derivation: `"sss_autononce_v1"`
- Prevents key/nonce reuse across contexts

### 5. Size Limits (DoS Protection)

```rust
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;           // 100 MB
pub const MAX_MARKER_CONTENT_SIZE: usize = 100 * 1024 * 1024; // 100 MB
```

Prevents:
- Memory exhaustion attacks
- CPU exhaustion (e.g., via Argon2id)

## Security Best Practices

### For Users

1. **Use Strong Passwords** ✅
   - Minimum 12 characters
   - Mix of uppercase, lowercase, numbers, symbols
   - Use a password manager

2. **Enable Password Protection** ✅
   - Always use `sss keys generate` (with password prompt)
   - Never use `--no-password` in production

3. **Use Sensitive KDF Level** ✅
   - Default is now `sensitive` (most secure)
   - Override only if you understand the trade-offs: `--kdf-level moderate`

4. **Rotate Keys Regularly** ✅
   - Rotate repository keys annually or after team changes
   - Use `sss rotate` command

5. **Protect `~/.config/sss/keys/`** ✅
   - Never commit this directory to git
   - Ensure permissions are `0700`
   - Backup encrypted keys separately

6. **Use System Keyring for Headless Systems** ✅
   - SSH-only servers: `export SSS_USE_KEYRING=true`
   - Requires keyring availability

### For Developers

1. **Never Log Secrets** ✅
   - Use `SecureString` and `SecureBuffer` types
   - Secrets are redacted in debug output

2. **Validate All Inputs** ✅
   - Size limits enforced
   - Base64 validation
   - File path validation

3. **Follow Cryptographic Best Practices** ✅
   - Use libsodium (don't roll your own crypto)
   - Validate all cryptographic operations
   - Check return codes

## Known Limitations

### 1. Deterministic Encryption (Design Choice)

**Limitation**: Same plaintext in same file produces same ciphertext

**Rationale**: Enables git-friendly diffs (secrets don't change unless content changes)

**Security Impact**: ⚠️ Information leakage
- Reveals when secrets are identical
- Reveals when secrets change vs remain unchanged
- Does NOT reveal plaintext content

**Mitigation**: Nonce is derived from (timestamp + file path + plaintext + key)
- Different files: different ciphertexts
- Different projects: different ciphertexts
- Different plaintexts: different ciphertexts

### 2. No Forward Secrecy

**Limitation**: Compromised repository key can decrypt all past commits

**Mitigation**: Regular key rotation with `sss rotate`

### 3. Requires User Interaction

**Limitation**: Password-protected keys require password entry

**Workarounds**:
- Use system keyring: `SSS_USE_KEYRING=true`
- Use `SSS_PASSPHRASE` environment variable (less secure)

## Security Audit History

| Date | Auditor | Scope | Result |
|------|---------|-------|--------|
| 2025-12-07 | Internal | Cryptographic implementation review | Passed with minor recommendations |

**Findings**: See [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) for detailed security analysis

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

**Instead, email**: security@example.com (replace with actual contact)

Include:
- Vulnerability description
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We follow responsible disclosure:
1. Acknowledge report within 48 hours
2. Confirm vulnerability within 7 days
3. Release fix within 30 days (for high-severity issues)
4. Public disclosure after fix is released

## References

- [NIST SP 800-175B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf): Key Derivation Functions
- [RFC 7539](https://tools.ietf.org/html/rfc7539): ChaCha20 and Poly1305
- [libsodium Documentation](https://doc.libsodium.org/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

**Last Updated**: 2025-12-07
**Version**: 1.2.0
