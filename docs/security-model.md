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

**v2.2 update:** Hybrid is the default for new repositories. Classic remains
audited and is the recommended choice for non-PQ-sensitive deployments where
avoiding the unaudited trelis dependency outweighs the post-quantum coverage
benefit. See [Default flip to hybrid (v2.2)](#default-flip-to-hybrid-v22).

---

## Key Derivation (Argon2id)

When a user generates a key pair with a passphrase, the passphrase is not used directly. Instead, sss derives a 256-bit wrapping key using Argon2id (variant `ALG_ARGON2ID13` from libsodium `crypto_pwhash`). This wrapping key encrypts the user's private key on disk. [See `docs/CRYPTOGRAPHY.md#key-derivation`](./CRYPTOGRAPHY.md#key-derivation) for the algorithmic specification.

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

1. **Secret content inside `⊠{...}` markers** — The ciphertext payload. Encrypted with XChaCha20-Poly1305 using the repository key and a deterministically derived nonce. See [marker-format.md](./marker-format.md) for the precise binary layout, and [`docs/CRYPTOGRAPHY.md#symmetric-encryption`](./CRYPTOGRAPHY.md#symmetric-encryption) for the AEAD primitive specification.

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
| Ciphertext tampering | Poly1305 MAC authentication; tampered ciphertexts are rejected ([see `docs/CRYPTOGRAPHY.md#symmetric-encryption`](./CRYPTOGRAPHY.md#symmetric-encryption)) |
| Sensitive data in memory after use | `zeroize` crate: keys and plaintext are overwritten when they go out of scope |
| Harvest-now-decrypt-later attack by a quantum-capable adversary | Hybrid suite (opt-in): sntrup761 lattice KEM provides post-quantum security for repo-key wrapping; classic suite does not protect against quantum adversaries ([see `docs/CRYPTOGRAPHY.md#hybrid-suite-v20`](./CRYPTOGRAPHY.md#hybrid-suite-v20)) |

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

## Hybrid Trust Boundaries (v2.0)

The hybrid suite (selected by `version = "2.0"` in `.sss.toml`) extends the v1.0 threat
model along three axes that classic does not cover. This section names the boundaries;
[docs/CRYPTOGRAPHY.md#hybrid-suite-v20](./CRYPTOGRAPHY.md#hybrid-suite-v20) owns the
algorithmic spec, and the [Per-Suite Threat Tables](#per-suite-threat-tables) section
below structures the same material as a side-by-side comparison.

### Agent-protocol suite-dispatch boundary

`sss-agent` mediates per-process key access on behalf of CLI invocations. As of Phase 8
(CR-01 resolution; see [FFI Audit](#ffi-audit-phase-8--harden-03)), the agent-protocol
wire format carries an explicit suite selector:

- `PROTOCOL_VERSION = 2` (`src/agent_protocol.rs`).
- `AgentRequest.suite: Option<u32>` is encoded on the wire as `0xFFFFFFFF`
  (`SUITE_WIRE_ABSENT` — absent / Classic-by-default for v1 back-compat), `0`
  (`SUITE_WIRE_CLASSIC`), or `1` (`SUITE_WIRE_HYBRID`). Any other value is a hard
  wire-format error: the request is rejected before any suite-specific dispatch can
  occur.
- The agent dispatches via `suite_for(request.suite)?` (in `src/bin/sss-agent.rs`), so
  the agent never silently downgrades a v2 hybrid request to classic.
- v1 frames (no suite field present) are accepted with `suite = None`, interpreted as
  Classic; this preserves back-compat with v1 clients during a rolling upgrade.

The boundary's threat-model significance: a malicious or misconfigured client that
sends a hybrid request with the wrong wire-format suite value is rejected at the
agent's parse layer, before the agent attempts to unseal a hybrid `K` with the classic
`crypto_box_seal_open` (which would fail catastrophically on a 1167-byte sealed key
presented to a 80-byte-expecting decryption path).

### Dual-keystore implications

A user with both classic and hybrid keypairs has both private keys encrypted under the
same Argon2id-derived wrapping key (one passphrase per keystore entry; both keys
co-located in `~/.config/sss/keys/<uuid>.toml`). The threat surface this creates:

- **Compromise of the user's passphrase compromises both private keys.** There is no
  cryptographic separation at the keystore-wrapping layer — both are AEAD-sealed under
  the same derived key.
- **Compromise of one private key (e.g. via differential cryptanalysis of one
  primitive) does not directly compromise the other.** Classic relies on X25519 DLP
  hardness; hybrid relies on X448 DLP hardness combined with sntrup761 lattice
  hardness ([see `docs/CRYPTOGRAPHY.md#hybrid-suite-v20`](./CRYPTOGRAPHY.md#hybrid-suite-v20) for the algorithmic detail). A break of X25519 alone leaves the hybrid private key intact; conversely a
  break of either X448 or sntrup761 alone leaves the classic private key intact.
  [See Per-Suite Threat Tables](#per-suite-threat-tables) for the divergent assumptions.
- **Disk-level theft + passphrase compromise = total loss for that user.** This is the
  same model as v1.0; hybrid does not strengthen the keystore-wrapping layer because
  the wrapping key is symmetric (Argon2id → XChaCha20-Poly1305) regardless of which
  asymmetric primitive the wrapped key is for.
- **Both keypair types are zeroised on drop.** `HybridKemKeypair` carries `ZeroizeOnDrop`
  via the trelis upstream type; classic `KeyPair` carries it via the wrapper. See the
  [Zeroisation](#zeroisation-phase-8--harden-04-audit-input) section for the full
  disposition table.

### `sss migrate` safety properties

The `sss migrate` subcommand re-wraps the repository key `K` per user under the hybrid
suite. Its safety properties:

- **In-file ciphertexts are never touched.** The `⊠{...}` markers in source files are
  byte-identical regardless of which suite wrapped `K`, because both suites seal the
  same `K` and the AEAD layer (XChaCha20-Poly1305 with the BLAKE2b-derived
  deterministic nonce) is identical across suites. See
  [docs/CRYPTOGRAPHY.md#byte-identical-ciphertexts-invariant](./CRYPTOGRAPHY.md#byte-identical-ciphertexts-invariant)
  for the algorithmic basis.
- **`--dry-run` is determinism-preserving.** Two `--dry-run` invocations on the same
  repository state produce identical previews; the dry-run never writes to disk.
- **A user without a hybrid public key is a hard error, not a silent skip.** Migration
  that cannot complete for a user (no hybrid public key registered for that user)
  aborts with a clean error before `.sss.toml` is rewritten. The pre-migrate
  `.sss.toml` remains intact on disk.
- **`.sss.toml` rewrites are atomic at the filesystem layer.** The new `.sss.toml` is
  written to a temp file in the same directory and `rename(2)`d into place, so a crash
  mid-migration leaves either the old or the new file complete.
- **Idempotency.** Migrating an already-v2.0 project is a no-op (the version-field
  gate at `src/project.rs` detects v2.0 and returns Ok before any wrap operation runs).

### Default flip to hybrid (v2.2)

As of v2.2, `sss init` (no flags) creates a v2.0 hybrid repository by default.
The flip reflects the convergence of three v2.x hardening tracks:

1. **Internal audit complete (v2.0–v2.1):** the hybrid suite has been
   exercised under fuzz (cargo-fuzz, 7.6 M runs), soak (10-min `soak_agent`
   target), and stress (1000-fan-out `stress_render` target) without
   regression.
2. **Signed envelope (Phase 19, PQSIG-04..06):** every `.sss.toml` envelope
   carries an AND-composition Ed448 + ML-DSA-65 signature with
   domain-separation context bytes `b"sss-toml-envelope-sig-v1"`. Sign-on-write
   at `init` / `users add` / `users remove` / `migrate`; verify-on-read with
   per-leg error reporting. See [Envelope Signatures (v2)](./CRYPTOGRAPHY.md#envelope-signatures-v2).
3. **Keystore entry signatures (Phase 18, PQSIG-01..03):** each keystore entry
   is signed with the same AND-composition under context bytes
   `b"sss-keystore-entry-v1"`. See [Keystore Entry Signatures (v2)](./CRYPTOGRAPHY.md#keystore-entry-signatures-v2).

The `--crypto classic` opt-out remains available and continues to write v1.0
repositories. Existing v1.0 repositories are NOT auto-migrated by the flip;
only NEW `sss init` invocations adopt the v2.0 default.

**Outstanding caveat (AUDIT-01):** the trelis post-quantum dependency
(`trelis-hybrid` / `trelis-primitives`, git rev `5374dff…`) is internal-audit
only and pinned. Third-party audit (AUDIT-01) is tracked for a future
milestone. Deployments that cannot accept this supply-chain risk should pin
`--crypto classic` until AUDIT-01 closes.

---

## Per-Suite Threat Tables

The aggregate [Protects Against](#protects-against) and [Does Not Protect
Against](#does-not-protect-against) tables above describe what the project as a whole
addresses. The two tables in this section break that down per suite, so a reader can
answer "given a v1.0 vs v2.0 project, which mathematical assumptions am I relying on?"
without inferring it from the prose.

The full algorithmic spec for each primitive lives in
[docs/CRYPTOGRAPHY.md](./CRYPTOGRAPHY.md); this table cites the primitive by name and
cross-references the spec.

### Divergent assumptions (per suite)

| Property | Classic (v1.0) | Hybrid (v2.0) |
|----------|----------------|----------------|
| KEM hardness | X25519 ECDH ([Curve25519 DLP](./CRYPTOGRAPHY.md#asymmetric-encryption)) | X448 ECDH (Curve448 DLP) **and** sntrup761 (Streamlined NTRU Prime lattice problem); see [docs/CRYPTOGRAPHY.md#hybrid-suite-v20](./CRYPTOGRAPHY.md#hybrid-suite-v20) |
| Per-message AEAD on the sealed key | XSalsa20-Poly1305 (sealed-box internal; libsodium) | XChaCha20-Poly1305; see [docs/CRYPTOGRAPHY.md#symmetric-encryption](./CRYPTOGRAPHY.md#symmetric-encryption) |
| KDF for repo-key wrapping | Implicit in `crypto_box_seal` (no separate KDF step) | BLAKE3 `derive_key("sss hybrid kem v1", shared)`; see [docs/CRYPTOGRAPHY.md#hybrid-suite-v20](./CRYPTOGRAPHY.md#hybrid-suite-v20) |
| Quantum resistance (KEM layer) | None — broken by Shor's algorithm against X25519 | sntrup761 lattice KEM is believed resistant to known quantum attacks |
| Audit pedigree | libsodium (extensively reviewed; long deployment history) | trelis (vendored at pinned commit `5374dff482ba94a94695794b5e4554f908eb0d4d`; **unaudited** — see [Trelis Attack Surface](#trelis-attack-surface) and `AUDIT-01` in `.planning/REQUIREMENTS.md`) |
| Sealed-key size on disk | 80 bytes per user entry | 1167 bytes per user entry (~1448 base64 chars); see [docs/CRYPTOGRAPHY.md#classic-vs-hybrid-comparison](./CRYPTOGRAPHY.md#classic-vs-hybrid-comparison) |

### Shared assumptions (both suites)

| Shared assumption | Both suites |
|-------------------|-------------|
| In-file AEAD on secret content | XChaCha20-Poly1305 — byte-identical ciphertext invariant; see [docs/CRYPTOGRAPHY.md#byte-identical-ciphertexts-invariant](./CRYPTOGRAPHY.md#byte-identical-ciphertexts-invariant) |
| Nonce derivation for in-file AEAD | BLAKE2b-192 keyed with the repository key, personalisation `"sss_autononce_v1"`; see [Deterministic Nonces](#deterministic-nonces) and [docs/CRYPTOGRAPHY.md#nonce-derivation](./CRYPTOGRAPHY.md#nonce-derivation) |
| Passphrase KDF for keystore wrapping | Argon2id v1.3 with `sensitive` parameters (~4 ops, 256 MiB); see [Key Derivation (Argon2id)](#key-derivation-argon2id) and [docs/CRYPTOGRAPHY.md#key-derivation](./CRYPTOGRAPHY.md#key-derivation) |
| Zeroisation on drop for secret-bearing types | `ZeroizeOnDrop` on `RepositoryKey`, `SecretKey`, `DerivedKey`, `Salt`, plus upstream `trelis_hybrid::HybridKemKeypair` / `HybridSharedSecret`; transient buffers wrapped in `Zeroizing<T>`; see [Zeroisation](#zeroisation-phase-8--harden-04-audit-input) |
| Determinism of in-file AEAD | Same `(K, path, plaintext, timestamp)` → same ciphertext, regardless of suite — load-bearing for clean git diffs |
| DoS protection (marker / file size limits) | `MAX_MARKER_CONTENT_SIZE = 100 MB`, `MAX_FILE_SIZE = 100 MB`; see [DoS Protection](#dos-protection) |

### Reading the tables together

The aggregate tables answer "what does sss protect against?". These per-suite tables
answer "given my chosen suite, on which primitives does that protection rest?". A
reader picking between v1.0 and v2.0 should consult both. A reviewer evaluating sss
against a specific threat (e.g. harvest-now-decrypt-later by a quantum adversary)
should follow the row that touches their threat — that row's "Classic" column will
state where the protection is absent, and the "Hybrid" column will state which
additional assumption is now in play.

---

## Trelis Attack Surface

The hybrid suite (v2.0) introduces an additional supply-chain dependency on the
[trelis](https://github.com/dspearson/trelis) library, which provides the X448 +
sntrup761 hybrid KEM. trelis is in a different audit posture than libsodium and the
classic suite. This section names the trelis-specific facts a reviewer needs to
assess the hybrid suite, and points back at every other place in this document that
touches trelis-related risk.

### Pinned, vendored at a specific commit

Both `trelis-hybrid` and `trelis-primitives` are pinned in `Cargo.toml` to commit
`5374dff482ba94a94695794b5e4554f908eb0d4d`. The pin uses git URL + `rev = "..."`
rather than a published crate version, so updates require an explicit code change to
`Cargo.toml`. The pin is intentional: trelis is experimental and the project does
not consume floating versions.

Re-verifying the pin commit against the v2.0 chain-of-custody (i.e. that the SHA
matches what was reviewed at v2.0 inception) is tracked as
[DEPS-03](../.planning/REQUIREMENTS.md) and lives in Phase 10 — that work has not
happened yet at the time of this writing. The pin commit hash above is cited as a
fact about the build, not a guarantee of provenance.
Verified by Phase 10 (DEPS-03) on 2026-04-29 — pin matches v2.0-inception citation; remote reachable.

### Unaudited

trelis has not undergone a formal third-party security audit at the time of this
writing. The hybrid suite ships with an EXPERIMENTAL warning ([see
docs/CRYPTOGRAPHY.md#hybrid-suite-v20](./CRYPTOGRAPHY.md#hybrid-suite-v20) for the
full WARNING callout) and is opt-in.

Commissioning or tracking a third-party audit of trelis is
[AUDIT-01](../.planning/REQUIREMENTS.md), and the default-flip from classic to
hybrid is gated on it via [AUDIT-02](../.planning/REQUIREMENTS.md). Both items are
deferred to a later milestone — Phase 9 documents the gap, but does not fill it.

The wrapper layer (sss's `unsafe { ... }` blocks that call into trelis APIs) was
audited in Phase 8: [see FFI Audit (Phase 8 /
HARDEN-03)](#ffi-audit-phase-8--harden-03). Result for the wrapper layer:
production sites 17/17 PASS, zero NEEDS-FIX, zero NEEDS-VERIFY. The Phase 8 audit
explicitly excluded trelis's own internal C-FFI bindings into `sntrup761`,
`xeddsa-rs`, etc. — those are the AUDIT-01 surface area.

### Feature-flag gated

The hybrid suite is compiled only when the `hybrid` Cargo feature is enabled. The
default `cargo build` produces a binary with no trelis code linked at all — only
libsodium is on the link line. [See docs/CRYPTOGRAPHY.md#feature-gate](./CRYPTOGRAPHY.md#feature-gate)
for the build-command pair (`cargo build` vs `cargo build --features hybrid`).

The feature flag is the **only** runtime gate. There is no per-invocation toggle, no
environment variable that disables hybrid in a hybrid build, and no policy file that
can override the suite a project's `.sss.toml` requests. The threat-model
consequence: if you build sss with `--features hybrid`, every v2.0 project the
binary opens will use the hybrid suite, including projects you didn't anticipate.

Conversely, a default (classic-only) build is incapable of opening v2.0 projects —
it will emit the SUITE-04 actionable error and exit. This is the recommended
posture for any deployment that has not signed off on the trelis audit gap.

### Mitigation options for teams

Three options exist for teams evaluating whether to enable the hybrid suite:

1. **Classic-only build (recommended default).** Use the default `cargo build` and
   do not enable the `hybrid` feature. v2.0 projects cannot be opened by this
   binary, but no trelis code is linked, the supply-chain surface is libsodium-only,
   and there is no exposure to the AUDIT-01 gap. This is the appropriate posture
   for production deployments that need maturity-of-cryptography assurance today.

2. **Hybrid build with documented acceptance.** Use `cargo build --features hybrid`
   and explicitly record acceptance of the trelis audit gap in the team's threat
   register. This posture is appropriate when post-quantum-readiness for repo-key
   wrapping is a hard requirement and the team has independently reviewed the
   trelis source or is willing to accept the residual risk. Note that the on-disk
   AEAD ciphertexts in `⊠{...}` markers are NOT affected — those use libsodium
   XChaCha20-Poly1305 in both suites ([see byte-identical ciphertexts
   invariant](./CRYPTOGRAPHY.md#byte-identical-ciphertexts-invariant)). The trelis
   exposure is bounded to per-user `.sss.toml` `sealed_key` entries.

3. **Wait for AUDIT-01 + AUDIT-02.** Track
   [AUDIT-01](../.planning/REQUIREMENTS.md) (third-party audit) and
   [AUDIT-02](../.planning/REQUIREMENTS.md) (default flip), and re-evaluate when
   both land. Until then, classic remains the recommended default per the
   [Cryptographic Suite Selection](#cryptographic-suite-selection) recommendation
   and the existing entry in the [Does Not Protect
   Against](#does-not-protect-against) table for "trelis library vulnerabilities or
   supply-chain compromise".

### Where else this is documented

Trelis-specific risk material elsewhere in this document and the algorithmic spec:

- [Cryptographic Suite Selection](#cryptographic-suite-selection) — the
  recommendation that classic remains the default until trelis is audited.
- [Does Not Protect Against](#does-not-protect-against) — the table row "trelis
  library vulnerabilities or supply-chain compromise".
- [FFI Audit (Phase 8 / HARDEN-03)](#ffi-audit-phase-8--harden-03) — Out-of-Scope
  sub-section, naming the vendored trelis source as AUDIT-01 territory.
- [Per-Suite Threat Tables](#per-suite-threat-tables) — Audit pedigree row in the
  Divergent assumptions table.
- [docs/CRYPTOGRAPHY.md#hybrid-suite-v20](./CRYPTOGRAPHY.md#hybrid-suite-v20) — the
  WARNING callout and the full algorithmic spec.
- [docs/CRYPTOGRAPHY.md#classic-vs-hybrid-comparison](./CRYPTOGRAPHY.md#classic-vs-hybrid-comparison)
  — the audit-status row in the comparison table.

---

## Deterministic Nonces

sss uses deterministic nonce derivation rather than random nonces. This is a deliberate design choice to produce clean git diffs.

**How it works:** The 24-byte nonce is derived via BLAKE2b in keyed mode, using the repository key as the BLAKE2b key and the following input ([see `docs/CRYPTOGRAPHY.md#nonce-derivation`](./CRYPTOGRAPHY.md#nonce-derivation) for the algorithmic specification):

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

## FFI Audit (Phase 8 / HARDEN-03)

This section records the wrapper-layer FFI boundary audit performed in
Plan 08-03 (2026-04-28). Scope: every `unsafe { sodium::... }` and
`unsafe { ptr::... }` call site in `src/kdf.rs`, `src/crypto/classic.rs`,
and `src/crypto/hybrid.rs`. Out of scope: the vendored `trelis` source
itself (covered by `AUDIT-01`, deferred to a third-party engagement).

### Properties Audited

For every FFI call site, three properties were verified:

1. **Buffer-size correctness** — every `as_ptr()` / `as_mut_ptr()` argument
   is paired with a length argument that matches the underlying buffer's
   declared size (`SYMMETRIC_KEY_SIZE = 32`, `SYMMETRIC_NONCE_SIZE = 24`,
   `SYMMETRIC_MAC_SIZE = 16`, `PUBLIC_KEY_SIZE = 32`,
   `SECRET_KEY_SIZE = 32`, `SEALED_BOX_OVERHEAD = 48`,
   `SALT_SIZE = 16`, `KEY_SIZE = 32`,
   `HYBRID_REPO_KEY_PLAINTEXT_SIZE = 32`,
   `HYBRID_SEALED_KEY_NONCE_SIZE = 24`, `HYBRID_SECRET_KEY_SIZE = 1819`).
   Every output buffer for a libsodium AEAD/seal call is sized to at
   least `MAC_SIZE + plaintext_len` (or the per-API equivalent) before
   the call, with explicit length-gates on caller-supplied input slices.

2. **Return-code handling** — every libsodium FFI that follows the
   documented `0 / non-zero` contract (`crypto_pwhash`, the
   `crypto_box_*` family, `crypto_secretbox_xchacha20poly1305_*`,
   `crypto_generichash_*`) is paired with an `if ret != 0 { return Err(...) }`
   check propagating an `anyhow!` error with adequate context. Void-return
   helpers (`randombytes_buf`) carry no check; the libsodium contract
   guarantees infallible operation post-`sodium_init`. `sodium_init` is
   guarded by an `assert!(... >= 0, ...)` (HARDEN-01-audited as a
   correct fatal-on-failure pattern).

3. **Lifetime safety** — every buffer passed by raw pointer (`as_ptr`,
   `as_mut_ptr`, `add(n)`) outlives the FFI call, with no early `drop`
   in any unsafe block, no aliased `&mut` / `&`, and no pointer
   arithmetic into uninitialised memory. `Zeroizing<..>` wrappers do
   not affect borrow lifetimes — the wrapper's `Drop` runs *after* the
   unsafe block returns, so the underlying buffer is live throughout.

### Sites Audited

26 unsafe sites total (17 production + 9 test):

| File | Production | Test | All-PASS production | All-PASS test |
|------|-----------:|-----:|:-------------------:|:-------------:|
| `src/kdf.rs` | 3 | 0 | 3/3 | n/a |
| `src/crypto/classic.rs` | 11 | 0 | 11/11 | n/a |
| `src/crypto/hybrid.rs` | 3 | 9 | 3/3 | 9/9 |
| **Total** | **17** | **9** | **17/17** | **9/9** |

### Findings

- **Zero NEEDS-FIX.** Every production FFI call carries the
  libsodium-contract return-code check and operates on a buffer whose
  declared size matches the FFI's expected length.
- **Zero NEEDS-VERIFY.** The Drop-ordering pattern in `hybrid.rs` test
  code (`ManuallyDrop::drop` followed by `read_volatile` to confirm
  zeroisation; threat-register entry `T-08-14`) is verified by manual
  trace: `ManuallyDrop::drop(&mut kp)` runs the inner type's `Drop`
  chain (which drops `Zeroizing<..>` and overwrites bytes with zeros)
  *before* the subsequent post-drop read; the `ManuallyDrop` retains
  the storage so the post-drop `read_volatile` observes the zeroed
  memory. Pattern is correct as written.
- **One documentation gap (not a soundness bug):**
  `src/crypto/classic.rs:91` (`RepositoryKey::new`) lacks a SAFETY
  comment despite the surrounding pattern carrying SAFETY comments at
  every other unsafe block. The block is sound (single libsodium
  void-return call into a stack-local 32-byte array), but a SAFETY
  comment would match the project convention. Tracked as a follow-up
  doc pass; does not meet the bar for `NEEDS-FIX` against the audit's
  three properties.

### CR-01 Resolution

Plan 02-04's deferred CR-01 issue ("sss-agent always uses
`ClassicSuite.open_repo_key`, ignoring the project's actual suite") was
resolved alongside this audit. The fix:

- Bumped `agent_protocol::PROTOCOL_VERSION` from 1 to 2.
- Extended `AgentRequest` with a `suite: Option<u32>` field, encoded on
  the wire as `0xFFFFFFFF` (absent / Classic-by-default for v1
  back-compat), `0` (Classic), or `1` (Hybrid). Unknown values are a
  hard wire-format error.
- Replaced the hardcoded `ClassicSuite.open_repo_key(...)` call in
  `src/bin/sss-agent.rs` with a dispatch through `suite_for(suite)?`,
  which routes to the matching `Box<dyn CryptoSuite>` based on the
  protocol-carried suite selector.
- `AgentClient::unseal_repository_key` and the free `unseal_with_agent`
  helper now take a `Suite` argument; the only production call site
  (`src/config.rs`) already had `suite_enum = config.suite()?` available
  and now passes it through.

The agent retains v1-frame back-compat, treating absent suite as Classic
to preserve the legacy behaviour during the transition.

### Out of Scope

- **Vendored `trelis` source.** The wrapper-layer review covers our
  call sites into `trelis-hybrid` and `trelis-primitives`, but not the
  `trelis` crates' internal C-FFI bindings into `sntrup761`,
  `xeddsa-rs`, etc. Those are the subject of `AUDIT-01` (third-party
  audit, deferred milestone).
- **Production code that does not contain `unsafe { sodium::... }` or
  `unsafe { ptr::... }`.** Files like `src/processor/`, `src/agent.rs`,
  `src/config.rs`, etc. were not in scope for this FFI audit (they hold
  no FFI boundaries).

---

## Zeroisation (Phase 8 / HARDEN-04 audit input)

Phase 8 (Plan 04, HARDEN-04) walked the full secret-bearing surface in `src/`
per Decision D-06 and verified each in-scope type either implements
`ZeroizeOnDrop` (preferred, per D-07) or is wrapped in `Zeroizing<T>` at every
owning call site. Disposition counts:

- **HAS-ZOD:** 7 — `RepositoryKey`, `SecretKey`, `Salt`, `DerivedKey`,
  `SecureString`, `SecureBuffer`, plus upstream `trelis-hybrid::HybridKemKeypair`
  and `HybridSharedSecret`.
- **WRAPPED-ZEROIZING:** 9 — every secret-bearing function-local in
  `src/crypto/hybrid.rs` (AEAD keys, plaintexts) and `src/keystore.rs`
  (rotate/load/decrypt paths) is bound into `Zeroizing<Vec<u8>>` or
  `Zeroizing<[u8; N]>`.
- **GAP-FIXED in Phase 8:** 2 — `keystore.rs::decrypt_stored_keypair` (T-08-16)
  and `askpass.rs::invoke_helper` (T-08-17). Both fixes wrap the previously
  unwrapped plaintext / passphrase buffers in `Zeroizing<...>` so the heap
  pages are cleared on drop.
- **GAP-ACCEPTED (rationale-bearing exclusions):** 4 — see below.

Full audit table lives in
`.planning/phases/08-internal-code-audit/08-04-SUMMARY.md`.

### Accepted exclusions (each carries rationale)

- **`StoredKeyPair.encrypted_secret_key` and `hybrid_encrypted_secret_key`
  fields** — rationale: fields hold base64 of AEAD-encrypted ciphertext, not
  plaintext; ciphertext on disk does not require drop-time zeroise.
- **`AgentRequest.sealed_key: Option<String>`** (in `src/agent_protocol.rs`) —
  rationale: holds base64 of the sealed (AEAD-wrapped) repository key — symmetric
  AEAD output is not plaintext; same disposition as `StoredKeyPair`.
- **`get_passphrase_or_prompt -> String`** (public re-exported helper in
  `src/keystore.rs`) — rationale: changing to `Zeroizing<String>` would drift
  the public re-exported signature (Rule 2 / T-08-23). Callers immediately
  consume the returned String into `Argon2id::derive_with_params(&pw, ...)`
  and drop at end of scope; lifetime is bounded by the calling function.
- **Argon2id input passphrase in `src/kdf.rs::derive_with_params`** —
  rationale: passphrase enters as `&str` (no rust-side copy beyond the
  caller's binding); libsodium's `crypto_pwhash` is responsible for its own
  scratch — D-06's libsodium-internal exclusion holds.

### libsodium-internal scratch

Phase 8 explicitly does not audit libsodium-internal scratch buffers
(Argon2id state machine, AEAD tag computation buffers). libsodium documents
its own `sodium_memzero` discipline. Phase 9 (THREAT-01) is the cross-reference
for that boundary.

Phase 9 (THREAT-01..04) consumes this section as input to the threat model.

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
