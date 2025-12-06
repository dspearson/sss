# Key Management Guide - SSS (Secrets in Source)

## Overview

This document provides practical guidance for managing cryptographic keys in SSS. It covers key generation, storage, protection, rotation, backup, and recovery procedures for both individual users and teams.

## Table of Contents

1. [Key Lifecycle](#key-lifecycle)
2. [Generating Keys](#generating-keys)
3. [Storing Keys](#storing-keys)
4. [Password Management](#password-management)
5. [Key Rotation](#key-rotation)
6. [Team Key Management](#team-key-management)
7. [Backup and Recovery](#backup-and-recovery)
8. [Security Best Practices](#security-best-practices)
9. [Troubleshooting](#troubleshooting)
10. [Advanced Topics](#advanced-topics)

## Key Lifecycle

### Three Types of Keys

1. **User Keypairs** (X25519)
   - Generated per user
   - Stored in `~/.config/sss/keys/`
   - Protected by password (recommended) or stored in system keyring
   - Used to decrypt repository keys

2. **Repository Keys** (XChaCha20-Poly1305)
   - Generated per project
   - Stored encrypted in `.sss.toml`
   - Wrapped with user public keys
   - Used to encrypt/decrypt secrets

3. **Derived Keys** (Argon2id)
   - Derived from user password + salt
   - Never stored on disk
   - Used to encrypt user secret keys
   - Ephemeral (exists only during password entry)

### Key Flow Diagram

```
User Password
    ↓ (Argon2id + Salt)
Derived Key (ephemeral)
    ↓ (decrypts)
User Secret Key
    ↓ (X25519 decrypt)
Repository Key
    ↓ (XChaCha20-Poly1305)
Encrypted/Decrypted Secrets
```

## Generating Keys

### First-Time Setup

```bash
# Initialize SSS in your project
cd /path/to/your/project
sss init

# Generate your user keypair (with password protection - RECOMMENDED)
sss keys generate

# Enter a strong password when prompted
# This will create ~/.config/sss/keys/<uuid>.toml
```

### With Custom Security Level

```bash
# Use sensitive KDF (default, most secure, ~2 sec)
sss keys generate --kdf-level sensitive

# Use moderate KDF (balanced, ~1 sec)
sss keys generate --kdf-level moderate

# Use interactive KDF (fastest, ~0.5 sec, less secure)
sss keys generate --kdf-level interactive
```

### Without Password (NOT RECOMMENDED)

```bash
# WARNING: Insecure! Only for testing.
sss keys generate --no-password
```

This will display a prominent warning:

```
⚠️  WARNING: Storing keypair WITHOUT password protection!
   Your private key will be accessible to anyone who can read:
   ~/.config/sss/keys/

   Consider using:
   - Password protection (recommended)
   - System keyring (SSS_USE_KEYRING=true)
```

### Using System Keyring

```bash
# Enable keyring support (environment variable)
export SSS_USE_KEYRING=true
sss keys generate --no-password

# Or via configuration
sss settings set --use-keyring true
sss keys generate --no-password
```

This stores your private key in:
- **macOS**: Keychain
- **Windows**: Credential Manager
- **Linux**: Secret Service (gnome-keyring, kwallet)

## Storing Keys

### Storage Locations

#### User Keys: `~/.config/sss/keys/<uuid>.toml`

**With Password Protection**:
```toml
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
public_key = "base64_encoded_public_key"
encrypted_secret_key = "base64_encrypted_secret_key"
salt = "base64_encoded_salt"
kdf_ops_limit = 4
kdf_mem_limit = 268435456  # 256 MiB
in_keyring = false
```

**Without Password** (NOT RECOMMENDED):
```toml
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
public_key = "base64_encoded_public_key"
encrypted_secret_key = "base64_encoded_secret_key"  # Not actually encrypted!
in_keyring = false
```

**In System Keyring**:
```toml
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
public_key = "base64_encoded_public_key"
encrypted_secret_key = "STORED_IN_KEYRING"
in_keyring = true
```

#### Repository Keys: `.sss.toml` (in project root)

```toml
timestamp = "2025-01-01T12:00:00Z"

[users.alice]
public_key = "alice_public_key_base64"
wrapped_key = "repository_key_wrapped_for_alice"

[users.bob]
public_key = "bob_public_key_base64"
wrapped_key = "repository_key_wrapped_for_bob"
```

### File Permissions

SSS automatically sets secure permissions:

```bash
~/.config/sss/                # 0700 (drwx------)
~/.config/sss/keys/           # 0700 (drwx------)
~/.config/sss/keys/*.toml     # 0600 (-rw-------)
```

**Verify permissions**:
```bash
ls -la ~/.config/sss/keys/
```

If permissions are wrong, fix them:
```bash
chmod 700 ~/.config/sss ~/.config/sss/keys
chmod 600 ~/.config/sss/keys/*.toml
```

## Password Management

### Choosing a Strong Password

**Minimum Requirements**:
- 12+ characters
- Mix of uppercase, lowercase, numbers, symbols
- Not based on dictionary words
- Unique (not reused from other services)

**Recommended**:
- Use a password manager (1Password, Bitwarden, KeePassXC)
- Generate random passwords (20+ characters)
- Enable password manager autofill for SSS operations

### Password Entry Methods

**1. Interactive Prompt** (RECOMMENDED):
```bash
sss decrypt file.txt
# Enter passphrase:
```

**2. Environment Variable** (Less Secure):
```bash
export SSS_PASSPHRASE="your_password"
sss decrypt file.txt
```

⚠️ **WARNING**: Environment variables can be:
- Logged in shell history
- Visible in process listings (`ps aux | grep SSS_PASSPHRASE`)
- Inherited by child processes
- Leaked in error reports

**Use only in**:
- Automated CI/CD pipelines (with encrypted secrets)
- Containerized environments (with secure secret injection)

**3. System Keyring** (Recommended for Headless Systems):
```bash
export SSS_USE_KEYRING=true
sss keys generate --no-password
# Key stored in OS keyring, unlocked via system authentication
```

### Changing Your Password

```bash
# Change password for current key
sss keys set-passphrase

# Or specify key UUID
sss keys set-passphrase --key <uuid>
```

This will:
1. Prompt for old password
2. Prompt for new password
3. Decrypt secret key with old password
4. Re-encrypt with new password (using same KDF parameters)
5. Update `~/.config/sss/keys/<uuid>.toml`

### Adding Password to Unprotected Key

```bash
sss keys set-passphrase --key <uuid>
# Old passphrase: (leave empty)
# New passphrase: your_new_password
```

### Removing Password (NOT RECOMMENDED)

```bash
sss keys remove-passphrase --key <uuid>
```

This will display a warning and require confirmation.

## Key Rotation

### When to Rotate Keys

**Rotate repository keys when**:
- A team member leaves the organization
- A key is suspected to be compromised
- Required by security policy (e.g., annually)
- Migrating to stronger cryptographic parameters

**Rotate user keys when**:
- Password is compromised
- Moving to a new machine (generate new key, don't copy)
- Required by security policy

### Repository Key Rotation

```bash
cd /path/to/your/project

# Rotate repository key
sss rotate

# This will:
# 1. Generate new repository key
# 2. Re-encrypt all secrets with new key
# 3. Wrap new key for all current users
# 4. Update .sss.toml
# 5. Commit changes (if git repo)
```

**Process**:
1. ✅ Decrypt all secrets with old key
2. ✅ Generate new repository key
3. ✅ Encrypt all secrets with new key
4. ✅ Wrap new key for all users in `.sss.toml`
5. ✅ Update files with new ciphertexts
6. ✅ Commit to git

**Important Notes**:
- All team members must pull the changes
- Old commits still use old key (git history)
- Consider rewriting git history for complete rotation (advanced)

### User Key Rotation

```bash
# Generate new user key
sss keys generate

# Get new key UUID
sss keys list

# Update project to use new key
cd /path/to/your/project
sss config add-user --key <new_uuid>

# Remove old key from project
sss config remove-user --key <old_uuid>

# Delete old keypair
sss keys delete --key <old_uuid>
```

## Team Key Management

### Adding a New Team Member

**1. New user generates their keypair**:
```bash
# User: alice
sss keys generate
sss keys list  # Get UUID and public key
```

**2. Alice shares her public key** (safe to share):
```bash
cat ~/.config/sss/keys/<uuid>.toml | grep public_key
```

**3. Existing team member adds Alice**:
```bash
cd /path/to/project
sss config add-user alice <alice_public_key>
# This wraps repository key for Alice and updates .sss.toml
```

**4. Commit and push**:
```bash
git add .sss.toml
git commit -m "Add Alice to SSS users"
git push
```

**5. Alice pulls and can now decrypt**:
```bash
git pull
sss decrypt file.txt
```

### Removing a Team Member

**1. Remove user from configuration**:
```bash
cd /path/to/project
sss config remove-user bob
```

**2. Rotate repository key** (IMPORTANT):
```bash
sss rotate
```

This ensures Bob can no longer decrypt **new** secrets, even though he can still decrypt old commits.

**3. Commit and push**:
```bash
git add .
git commit -m "Remove Bob from SSS users and rotate key"
git push
```

**4. (Optional) Rewrite git history**:
```bash
# Advanced: Remove Bob's access to historical secrets
# WARNING: Destructive operation!
git filter-branch --tree-filter 'sss rotate --force' HEAD
```

### Managing Multiple Projects

```bash
# List all your keys
sss keys list

# Different keys for different projects
~/work-project/.sss.toml     # Uses work key
~/personal-project/.sss.toml  # Uses personal key

# Set current key for a project
cd ~/work-project
sss config set-current-key <work_key_uuid>
```

## Backup and Recovery

### Backing Up Keys

#### User Keys (CRITICAL)

**Password-Protected Keys** (Safe to Back Up):
```bash
# Backup entire keys directory
tar -czf sss-keys-backup.tar.gz ~/.config/sss/keys/

# Store backup:
# ✅ Encrypted USB drive
# ✅ Password manager (1Password Secure Notes)
# ✅ Encrypted cloud storage (with separate password)
# ❌ Unencrypted cloud storage
# ❌ Email
```

**Unprotected Keys** (DANGEROUS):
```bash
# NEVER back up unprotected keys to cloud
# If you must back up, encrypt first:
gpg -c ~/.config/sss/keys/<uuid>.toml
```

#### Repository Keys (In .sss.toml)

Repository keys are already encrypted (wrapped with user public keys):
```bash
# Safe to commit to git (encrypted)
git add .sss.toml
git commit -m "Update SSS configuration"
git push
```

### Recovery Scenarios

#### Lost Password

**If you forgot your password**:
- ❌ Cannot recover (by design - security feature)
- ✅ Generate new keypair
- ✅ Ask team member to add you back to projects
- ❌ Old encrypted keys are permanently inaccessible

**Prevention**:
- Store password in password manager
- Write down password and store in safe
- Use password hints (but not obvious ones)

#### Lost Key File

**If you deleted ~/.config/sss/keys**:
- ❌ Cannot recover unless you have backup
- ✅ Restore from backup
- ✅ Or generate new keypair and re-add to projects

**Prevention**:
- Regular backups (see above)
- Store backup in multiple secure locations
- Test recovery procedure periodically

#### Compromised Key

**If your private key is compromised**:
```bash
# 1. Generate new keypair immediately
sss keys generate

# 2. For each project:
cd /path/to/project
sss config add-user <username> <new_public_key>
sss config remove-user <username> --key <old_key_uuid>
sss rotate  # Rotate repository key

# 3. Delete compromised keypair
sss keys delete --key <compromised_uuid>

# 4. Change password on all services (if password was reused)
```

#### Corrupted .sss.toml

**If .sss.toml is corrupted**:
```bash
# Restore from git history
git checkout HEAD~1 .sss.toml

# Or restore from backup
cp .sss.toml.backup .sss.toml

# If completely lost, reinitialize (loses access to old secrets):
sss init
# WARNING: Old encrypted secrets cannot be decrypted!
```

## Security Best Practices

### For Individual Users

1. ✅ **Use password protection** (always)
2. ✅ **Use sensitive KDF level** (default)
3. ✅ **Choose strong passwords** (20+ characters)
4. ✅ **Store password in password manager**
5. ✅ **Backup encrypted keys** (to multiple secure locations)
6. ✅ **Use system keyring** (on headless systems)
7. ✅ **Set proper file permissions** (automatic, but verify)
8. ❌ **Never share your private key**
9. ❌ **Never commit unencrypted keys to git**
10. ❌ **Never store passwords in shell history**

### For Teams

1. ✅ **Rotate repository keys** when members leave
2. ✅ **Use different keys** for different projects
3. ✅ **Document team key management procedures**
4. ✅ **Regular key rotation** (annually or per policy)
5. ✅ **Onboarding process** for new members
6. ✅ **Offboarding process** for departing members
7. ✅ **Monitor .sss.toml changes** (via git review)
8. ❌ **Don't reuse repository keys** across projects
9. ❌ **Don't skip rotation** after member departures

### For CI/CD Systems

1. ✅ **Use environment variables** (SSS_PASSPHRASE)
2. ✅ **Store password in CI secrets** (encrypted)
3. ✅ **Use system keyring** (if supported)
4. ✅ **Generate dedicated CI keys** (don't use personal keys)
5. ✅ **Rotate CI keys regularly**
6. ✅ **Audit CI key usage** (logging)
7. ❌ **Don't log passwords**
8. ❌ **Don't expose keys in build artifacts**

## Troubleshooting

### "Decryption failed: authentication error"

**Causes**:
- Wrong password
- Wrong key
- Corrupted ciphertext
- Key mismatch

**Solutions**:
```bash
# Verify you're using the correct key
sss keys list

# Try with correct key explicitly
sss decrypt file.txt --key <uuid>

# Check .sss.toml for your username
cat .sss.toml | grep -A2 "\[users.<username>\]"
```

### "Keyring not available"

**Causes**:
- No keyring service running (Linux)
- SSH-only session (no GUI)

**Solutions**:
```bash
# Check keyring availability
sss settings check-keyring

# Fallback to file-based storage
export SSS_USE_KEYRING=false

# Or install keyring service (Linux)
sudo apt-get install gnome-keyring  # Ubuntu/Debian
sudo yum install gnome-keyring      # RHEL/CentOS
```

### "Key file not found"

**Causes**:
- Key deleted or moved
- Wrong `--confdir` specified

**Solutions**:
```bash
# List existing keys
ls -la ~/.config/sss/keys/

# List keys via SSS
sss keys list

# Restore from backup
cp /backup/sss-keys/*.toml ~/.config/sss/keys/
```

### "Wrong number of secrets after rotation"

**Causes**:
- Some secrets couldn't be decrypted
- Concurrent modifications during rotation

**Solutions**:
```bash
# Verify all secrets decrypt before rotation
sss verify

# Retry rotation
sss rotate --force

# Check for errors in specific files
sss decrypt file.txt --verbose
```

## Advanced Topics

### Custom KDF Parameters

```bash
# Generate key with custom parameters
sss keys generate \
    --kdf-ops-limit 5 \
    --kdf-mem-limit 536870912  # 512 MiB

# This creates a stronger (slower) KDF
```

### Multiple Identities

```bash
# Work identity
export SSS_CONFDIR=~/.config/sss-work
sss keys generate

# Personal identity
export SSS_CONFDIR=~/.config/sss-personal
sss keys generate

# Switch between them
export SSS_CONFDIR=~/.config/sss-work
cd ~/work-project
sss decrypt file.txt
```

### Key Migration

```bash
# Migrate from old SSS installation
# 1. Export old keys
tar -czf old-keys.tar.gz ~/.sss/

# 2. Convert format (if needed)
# ... migration script ...

# 3. Import to new location
tar -xzf old-keys.tar.gz -C ~/.config/sss/
```

### Auditing Key Usage

```bash
# Check which keys are used in current project
sss config list-users

# Check which projects use a specific key
grep -r "<public_key>" ~/projects/*/.sss.toml

# Find unused keys
sss keys list --show-usage
```

### Emergency Key Access

**If primary key holder is unavailable**:

1. **Escrow Setup** (Recommended for Teams):
   ```bash
   # Generate shared escrow key
   sss keys generate

   # Add to all projects
   sss config add-user emergency <escrow_public_key>

   # Store escrow password in corporate safe
   ```

2. **Multi-Signature** (Future Feature):
   ```bash
   # Require 2-of-3 keys to decrypt
   sss config set-threshold 2
   sss config add-key-holder alice
   sss config add-key-holder bob
   sss config add-key-holder charlie
   ```

## See Also

- [SECURITY.md](./SECURITY.md) - Security architecture and threat model
- [CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md) - Cryptographic implementation details
- [README.md](../README.md) - General usage documentation

---

**Last Updated**: 2025-12-07
**Version**: 1.2.0
**Maintainer**: SSS Security Team
