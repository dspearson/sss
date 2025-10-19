# Contributing to sss

Thank you for your interest in contributing to sss! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Security](#security)

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Focus on what is best for the project and community
- Show empathy towards other contributors
- Accept constructive criticism gracefully
- Use welcoming and inclusive language

### Unacceptable Behavior

- Harassment, discriminatory language, or personal attacks
- Trolling, insulting/derogatory comments
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

## Getting Started

### Prerequisites

- Rust 1.70 or later
- libsodium (via libsodium-sys)
- Git
- (Optional) libfuse3-dev for FUSE support
- (Optional) Rust 9P dependencies for 9P server support

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/sss.git
   cd sss
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/sss.git
   ```

4. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Basic Build

```bash
# Standard build (no optional features)
cargo build

# Build with all features
cargo build --all-features

# Build with specific features
cargo build --features fuse
cargo build --features ninep
cargo build --features fuse,ninep
```

### Development Dependencies

The project uses several development tools:

```bash
# Install development tools
cargo install cargo-watch    # Auto-rebuild on changes
cargo install cargo-tarpaulin # Code coverage
cargo install cargo-audit     # Security audit
cargo install cargo-outdated  # Check dependency versions
```

## Making Changes

### Finding Work

- Check the [Issues](https://github.com/OWNER/sss/issues) page for open issues
- Look for issues labeled `good first issue` or `help wanted`
- If you have a new feature idea, open an issue first to discuss it

### Creating a Branch

Use descriptive branch names:

```bash
# Features
git checkout -b feature/add-new-cipher

# Bug fixes
git checkout -b fix/keystore-corruption

# Documentation
git checkout -b docs/update-readme

# Refactoring
git checkout -b refactor/simplify-processor
```

### Commit Messages

Follow these conventions:

```
type(scope): Short description (max 72 chars)

Longer explanation if needed. Wrap at 72 characters.

- Bullet points are okay
- Use imperative mood: "Add feature" not "Added feature"
- Reference issues: "Fixes #123"
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring without behavior changes
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependency updates

**Examples:**
```
feat(crypto): Add support for alternative cipher algorithms

Implements support for additional authenticated encryption
algorithms while maintaining backward compatibility.

Fixes #456
```

```
fix(keystore): Prevent corruption on concurrent access

Add proper file locking to prevent race conditions when
multiple processes access the keystore simultaneously.
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific module
cargo test crypto

# Run tests with output
cargo test -- --nocapture

# Run ignored tests (integration tests requiring interaction)
cargo test -- --include-ignored

# Run with all features
cargo test --all-features
```

### Writing Tests

- Add unit tests in the same file as the code (in a `#[cfg(test)]` module)
- Add integration tests in `tests/` directory
- Use property-based testing (proptest) for crypto functions
- Test both success and failure cases
- Test edge cases and boundary conditions

**Example:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = Key::new();
        let plaintext = "secret data";
        let encrypted = encrypt(plaintext.as_bytes(), &key, "2025-01-01", "./test.txt").unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn test_invalid_key_rejected() {
        let result = Key::from_base64("invalid");
        assert!(result.is_err());
    }
}
```

### Code Coverage

Check code coverage with:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html

# View report
open tarpaulin-report.html
```

## Code Style

### Rust Style Guide

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `rustfmt` for automatic formatting
- Use `clippy` for linting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy --all-features

# Fix clippy warnings automatically
cargo clippy --fix --all-features
```

### Code Quality Standards

- **No Warnings**: Code must compile without warnings
- **No Clippy Issues**: Fix all clippy warnings before submitting
- **Documentation**: Public APIs must have rustdoc comments
- **Error Handling**: Use `Result` types, avoid `.unwrap()` in library code
- **Safety**: Document all `unsafe` blocks with safety comments
- **Testing**: Maintain or improve test coverage

### Documentation

- Add rustdoc comments for all public items
- Include examples in documentation
- Update ARCHITECTURE.md for significant features
- Keep README.md up to date

**Example:**

```rust
/// Encrypts plaintext using XChaCha20-Poly1305 with deterministic nonce.
///
/// The nonce is derived from the project timestamp, file path, and plaintext
/// to enable clean git diffs while preventing nonce reuse.
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - The encryption key
/// * `project_timestamp` - ISO 8601 timestamp from .sss.toml
/// * `file_path` - Relative path from project root
///
/// # Returns
///
/// Returns the encrypted data (nonce || ciphertext || MAC)
///
/// # Example
///
/// ```
/// let key = Key::new();
/// let encrypted = encrypt(b"secret", &key, "2025-01-01T00:00:00Z", "./config.yml")?;
/// ```
pub fn encrypt(
    plaintext: &[u8],
    key: &Key,
    project_timestamp: &str,
    file_path: &str,
) -> Result<Vec<u8>> {
    // ...
}
```

## Submitting Changes

### Before Submitting

Checklist before creating a pull request:

- [ ] Code compiles without warnings: `cargo build --all-features`
- [ ] All tests pass: `cargo test --all-features`
- [ ] Code is formatted: `cargo fmt`
- [ ] No clippy warnings: `cargo clippy --all-features`
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (for significant changes)
- [ ] Commit messages follow conventions
- [ ] Branch is up to date with upstream main

### Creating a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a pull request on GitHub

3. Fill out the PR template with:
   - Clear description of changes
   - Related issue numbers
   - Testing performed
   - Breaking changes (if any)

4. Wait for review and address feedback

### PR Review Process

- Maintainers will review your PR
- Automated checks must pass (CI/CD)
- At least one maintainer approval required
- Address review comments promptly
- Keep PR focused and reasonably sized

### After Merge

- Delete your feature branch
- Pull the latest changes from upstream:
  ```bash
  git checkout main
  git pull upstream main
  ```

## Security

### Reporting Security Issues

**DO NOT** report security vulnerabilities in public issues.

Report security vulnerabilities to: **dsp@technoanimal.net**

See [SECURITY.md](SECURITY.md) for details.

### Security Review

Changes affecting cryptography or security require:

- Detailed explanation of security implications
- Additional scrutiny during code review
- Testing with security-focused test cases
- Documentation of threat model changes

### Cryptographic Code

Special requirements for crypto-related changes:

- Use well-established libraries (libsodium)
- No custom cryptographic primitives without extensive review
- Follow current best practices (see SECURITY.md)
- Include comprehensive tests
- Document security properties

## Development Guidelines

### Architecture

Familiarize yourself with:

- **Hybrid Encryption**: Asymmetric (user keys) + Symmetric (project key)
- **Deterministic Nonces**: BLAKE2b derivation for clean git diffs
- **Multi-User**: Sealed keys for each authorized user
- **File Processing**: Regex-based marker detection and processing

See ARCHITECTURE.md for detailed architecture documentation.

### Adding Features

When adding new features:

1. Discuss in an issue first
2. Ensure backward compatibility (or document breaking changes)
3. Add comprehensive tests
4. Update documentation
5. Consider security implications
6. Add to CHANGELOG.md

### Performance

- Profile before optimizing
- Use `cargo bench` for benchmarks
- Avoid premature optimization
- Document performance characteristics
- Consider memory usage

### Dependencies

When adding dependencies:

- Use minimal, well-maintained crates
- Check security advisories: `cargo audit`
- Prefer dependencies with:
  - Active maintenance
  - Good documentation
  - Minimal transitive dependencies
  - Compatible licenses (ISC, MIT, Apache-2.0, BSD)

## Getting Help

### Resources

- **Documentation**: See ARCHITECTURE.md for implementation details
- **Examples**: Check `examples/` directory
- **Tests**: Look at existing tests for patterns

### Contact

- **Issues**: [GitHub Issues](https://github.com/OWNER/sss/issues)
- **Email**: dsp@technoanimal.net

## Recognition

Contributors will be recognized in:

- Git commit history
- GitHub contributors page
- CHANGELOG.md (for significant contributions)

## License

By contributing to sss, you agree that your contributions will be licensed under the ISC License.

---

Thank you for contributing to sss!
