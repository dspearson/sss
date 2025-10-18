# Security Policy

## Supported Versions

We take security seriously. The following versions of sss are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by email to:

**dsp@technoanimal.net**

Include the following information in your report:

- Type of issue (e.g., buffer overflow, authentication bypass, injection, information disclosure)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to Expect

- We will acknowledge your email within 48 hours
- We will provide a more detailed response within 7 days indicating the next steps in handling your report
- We will keep you informed about the progress toward a fix and announcement
- We may ask for additional information or guidance

### Responsible Disclosure Guidelines

We request that you:

- Give us reasonable time to address the issue before public disclosure
- Make a good faith effort to avoid privacy violations, data destruction, and service interruption
- Do not access or modify data that doesn't belong to you
- Do not perform testing on production systems

## Security Features

### Cryptographic Design

sss uses industry-standard cryptography:

- **Encryption**: XChaCha20-Poly1305 (authenticated encryption)
- **Key Derivation**: Argon2id (memory-hard, resistant to GPU attacks)
- **Key Exchange**: X25519 (elliptic curve Diffie-Hellman)
- **Signatures**: Ed25519 (elliptic curve signatures)
- **Hashing**: BLAKE2b (for deterministic nonce derivation)
- **Library**: libsodium (audited, battle-tested cryptographic library)

### Security Properties

1. **Authenticated Encryption**: All encrypted data includes a MAC for integrity verification
2. **Deterministic Nonces**: BLAKE2b-derived nonces prevent nonce reuse while enabling clean git diffs
3. **Forward Security**: Key rotation updates both keys and timestamps
4. **Memory Protection**: Cryptographic material is zeroized after use
5. **Input Validation**: Comprehensive validation with DoS protection
6. **No Information Leakage**: Error messages don't reveal sensitive information

### Deterministic Encryption Trade-offs

sss uses deterministic nonce generation for file secrets to achieve clean git diffs. This has the following security properties:

**Secure:**
- Different plaintexts always get different nonces (plaintext in derivation)
- Different files get different nonces (file path in derivation)
- Different projects get different nonces (unique timestamps)
- No nonce reuse catastrophe (the critical vulnerability is prevented)

**Acceptable Trade-off:**
- An observer with git access can determine if a specific secret hasn't changed within the same file across commits
- This trade-off is intentional and enables better workflow and code review

**Mitigations:**
- Key rotation changes all ciphertexts (new timestamp + new key)
- Cross-file secrets have different ciphertexts (path in derivation)
- Cross-project secrets have different ciphertexts (unique timestamps)

### Known Limitations

1. **Metadata Leakage**: File sizes and modification times are not hidden
2. **Project Detection**: The presence of `.sss.toml` identifies an sss project
3. **User Enumeration**: Project configuration reveals authorized usernames
4. **Git History**: Encrypted content history is visible in git (use git filter-branch or BFG for removal)

## Security Best Practices

### For Users

1. **Use Strong Passphrases**: Protect your private keys with strong, unique passphrases
2. **Key Rotation**: Rotate project keys periodically, especially after user removal
3. **Secure Key Storage**: Keep your keystore directory (`~/.config/sss/`) secure
4. **Rate Limiting**: Don't disable password attempt rate limiting
5. **Review Changes**: Always review git diffs before committing encrypted changes
6. **Access Control**: Limit git repository access to authorized users only
7. **Backup Keys**: Securely backup your private keys (encrypted, offline storage)

### For Developers

1. **Review Unsafe Code**: All unsafe blocks are documented and necessary for FFI
2. **Error Handling**: Never log or display decrypted content in errors
3. **Zeroization**: All sensitive data must be zeroized after use
4. **Testing**: Run `cargo test` before committing changes
5. **Clippy**: Run `cargo clippy --all-features` and fix all warnings
6. **Audit Dependencies**: Regularly review and update dependencies
7. **Code Review**: All crypto-related changes require thorough review

## Security Audit History

No formal third-party security audits have been conducted yet.

If you are interested in conducting or sponsoring a security audit, please contact: dsp@technoanimal.net

## Security-Related Configuration

### Environment Variables

- `SSS_DEVEL_MODE`: Enables experimental features (DO NOT use in production)
- `SSS_AUTH_SOCK`: Agent socket path (experimental feature, not recommended for production)

### Files and Permissions

Sensitive files that should have restricted permissions:

- `~/.config/sss/keystore.toml` (should be 0600 or 0400)
- `~/.config/sss/keys/*` (should be 0600 or 0400)
- `.sss.toml` (project config - world readable, but keys are sealed)

Verify permissions:
```bash
# Check keystore permissions
ls -la ~/.config/sss/

# Verify no secrets are in plaintext
sss status
```

## Cryptographic Algorithm Recommendations

### Current Recommendations (2025)

✅ **Recommended** (currently used):
- XChaCha20-Poly1305 (authenticated encryption)
- Argon2id (key derivation)
- Ed25519 (signatures)
- X25519 (key exchange)
- BLAKE2b (hashing)

⚠️ **Deprecated** (not used):
- AES-GCM with random nonces < 96 bits
- PBKDF2 (use Argon2id instead)
- SHA-1 (use SHA-256 or BLAKE2b instead)
- RSA < 2048 bits (use Ed25519 instead)

## Update and Patching

Security updates are released as soon as possible after discovery. To update:

```bash
# Via cargo
cargo install sss --force

# Via package manager (if available)
# Debian/Ubuntu
sudo apt update && sudo apt upgrade sss

# RHEL/Fedora
sudo dnf update sss

# macOS (Homebrew)
brew upgrade sss
```

## Contact

For security-related questions or concerns:

**Email**: dsp@technoanimal.net

For general questions or support:

**Issues**: https://github.com/[YOUR_ORG]/sss/issues (for non-security issues only)

---

Last Updated: 2025-01-19
