# Security Properties

This document is an auditor-checkable record of sss's cryptographic security
properties across every surface where replay or forgery is a meaningful threat.
Every claim cites an existing section of `docs/CRYPTOGRAPHY.md` or
`docs/security-model.md`; no property is invented here. For implementation
detail see those documents; for the threat-model framing see
`docs/security-model.md`.

## Purpose and Scope

**Audience:** External security auditors, threat-model reviewers, and
downstream deployers evaluating sss for use with sensitive secrets.

**What this document provides:**

- A structured replay-resistance matrix across eight cryptographic surfaces,
  with per-row citations to the authoritative spec sections.
- An ASCII trust-anchor diagram showing the full key hierarchy from passphrase
  to sealed in-file markers.
- An explicit record of deliberate non-properties (out-of-scope items), so an
  auditor can quickly identify what sss does NOT claim to protect.

**What is out of scope for this document:** Source code, test coverage, and
runtime behaviour. Those are covered by `docs/CRYPTOGRAPHY.md`,
`docs/security-model.md`, `docs/TESTING.md`, and the per-phase planning
summaries.

**Suite scope:** sss supports two cryptographic suites for per-user repository-
key wrapping: classic (libsodium X25519, `.sss.toml` `version = "1.0"`) and
hybrid (trelis X448+sntrup761, `version = "2.0"`). In-file AEAD ciphertexts
are byte-identical regardless of suite — only the per-user `sealed_key` entries
in `.sss.toml` differ. Scope column in the matrix indicates which rows are
suite-specific.

---

## Replay-Resistance Matrix

Columns: **Surface** | **Threat** | **Property** | **Mechanism** | **Source** | **Scope**

### In-file content encryption (both suites)

The `⊠{...}` marker ciphertexts are XChaCha20-Poly1305 AEAD, encrypted with
repository key `K` and a BLAKE2b-192 keyed deterministic nonce.

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| seal (`encrypt_content`) | Ciphertext forgery or tampering | INT-CTXT: any tampered ciphertext is rejected | Poly1305 128-bit MAC in XChaCha20-Poly1305; `crypto_secretbox_xchacha20poly1305_easy` | CRYPTOGRAPHY.md §Symmetric Encryption | Both |
| seal | Replay of old ciphertext as current content | Replay rejected: nonce is deterministic on (plaintext, path, timestamp, key) | BLAKE2b-192 keyed nonce `NONCE = BLAKE2b(K, timestamp‖NUL‖path‖NUL‖plaintext, personal="sss_autononce_v1")`; same (K, path, plaintext, ts) → same ciphertext; different plaintext → different nonce | CRYPTOGRAPHY.md §Nonce Derivation; security-model.md §Deterministic Nonces | Both |
| seal | Key-confusion (wrong repo key used) | AEAD authentication fails when K does not match | Poly1305 is keyed on K via XChaCha20; wrong K → MAC mismatch → hard error | CRYPTOGRAPHY.md §Symmetric Encryption | Both |
| unseal (`decrypt_content`) | Chosen-ciphertext forgery | IND-CCA2: AEAD rejects forgeries | XChaCha20-Poly1305 `crypto_secretbox_xchacha20poly1305_open_easy` returns -1 on auth failure; sss surfaces `SssError::Crypto` | CRYPTOGRAPHY.md §Symmetric Encryption §Security Properties | Both |
| unseal | Nonce reuse across distinct plaintexts | No meaningful attack: BLAKE2b collision required | Preimage resistance of BLAKE2b-192 (192-bit security against collision in keyed mode) | security-model.md §Deterministic Nonces | Both |

### Classic repo-key wrapping (version 1.0)

The per-user `sealed_key` entry in `.sss.toml` is produced by `crypto_box_seal`
(ephemeral X25519 ECDH + XSalsa20-Poly1305). This surface applies only to
classic-suite (`.sss.toml` `version = "1.0"`) projects.

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| wrap (classic) | Third party unwraps repo key K | Confidentiality: only holder of recipient X25519 secret key can unwrap | `crypto_box_seal` ephemeral X25519 ECDH + XSalsa20-Poly1305 | CRYPTOGRAPHY.md §Asymmetric Encryption; security-model.md §Cryptographic Algorithms | Classic |
| unwrap (classic) | Attacker forges a `sealed_key` entry | Forgery detected via XSalsa20-Poly1305 authentication | Poly1305 MAC; `crypto_box_seal_open` returns -1 on failure | CRYPTOGRAPHY.md §Asymmetric Encryption | Classic |
| wrap/unwrap (classic) | Forward-secrecy concern | Per-message forward secrecy via ephemeral sender key | Each `crypto_box_seal` generates a fresh ephemeral keypair; secret discarded after ECDH | CRYPTOGRAPHY.md §Asymmetric Encryption §Security Properties | Classic |
| wrap (classic) | Quantum adversary (Shor's algorithm) | No protection | X25519 discrete-log is broken by Shor's algorithm; classic suite provides no post-quantum coverage | security-model.md §Per-Suite Threat Tables §Divergent assumptions | Classic |

### Hybrid repo-key wrapping (version 2.0)

The per-user `sealed_key` entry for hybrid projects uses a 1167-byte wire
format: trelis KEM X448+sntrup761 encapsulation (1095 B) + random 24-byte
XChaCha20 nonce + AEAD ciphertext (32 B K + 16 B Poly1305 tag).

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| wrap (hybrid) | Classical adversary unwraps K | Confidentiality under X448 discrete-log hardness | trelis KEM X448 encapsulate + BLAKE3 KDF + XChaCha20-Poly1305 | CRYPTOGRAPHY.md §Hybrid Suite v2.0 | Hybrid |
| wrap (hybrid) | Quantum adversary (Shor's algorithm) | Confidentiality under sntrup761 lattice hardness | sntrup761 Streamlined NTRU Prime; AND-composition with X448 so break requires breaking BOTH | security-model.md §Per-Suite Threat Tables §Divergent assumptions | Hybrid |
| wrap (hybrid) | Wire format size confusion or injection | Hard parse error on malformed `sealed_key` | Exact 1167-byte wire format: `[0..1095)` encap ‖ `[1095..1119)` nonce ‖ `[1119..1167)` ciphertext+tag | CRYPTOGRAPHY.md §Hybrid Suite §Sealed Key Wire Format | Hybrid |
| unwrap (hybrid) | Agent routes hybrid request to classic path | Hard reject at agent wire layer before dispatch | `AgentRequest.suite: Option<u32>` encoded as `SUITE_WIRE_ABSENT=0xFFFFFFFF`; unknown values → wire error before any suite-specific dispatch | security-model.md §Hybrid Trust Boundaries §Agent-protocol suite-dispatch boundary | Hybrid |

### Keystore (private key at rest)

User private keys on disk are encrypted with a key derived from the user's
passphrase via Argon2id. This surface applies to both suites because both
classic and hybrid private keys are wrapped under the same KDF path.

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| wrap (keystore) | Offline brute-force of passphrase | Preimage resistance under Argon2id (sensitive parameters) | Argon2id v1.3, `OPSLIMIT_SENSITIVE` (~4 passes), `MEMLIMIT_SENSITIVE` (256 MiB); ~2 s/guess/core, limited GPU speedup | CRYPTOGRAPHY.md §Key Derivation; security-model.md §Key Derivation Argon2id | Both |
| wrap (keystore) | Salt reuse enabling cross-user rainbow tables | Unique 128-bit CSPRNG salt per key | `randombytes_buf` 16-byte random salt per `Salt::new()` | CRYPTOGRAPHY.md §Key Derivation §Salt Generation | Both |
| unwrap (keystore) | Tampered keystore ciphertext | AEAD authentication failure → hard error | XChaCha20-Poly1305 AEAD wraps the encrypted secret key; `SssError::Crypto` on tag mismatch | CRYPTOGRAPHY.md §Key Derivation | Both |

### Keystore entry signatures (format_version=2)

Phase 18 (PQSIG-01..03) adds Ed448 + ML-DSA-65 AND-composition signatures
over each `~/.config/sss/keys/<uuid>.toml` entry. This surface applies only
when `format_version = 2`.

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| sign/verify (keystore entry) | Tampered public key in stored entry | Hard reject: AND-composition signature fails | Ed448 + ML-DSA-65 over canonical payload (uuid, pubkeys, timestamp) with context `"sss-keystore-entry-sig-v1"` | CRYPTOGRAPHY.md §Keystore Entry Signatures | Hybrid (format_version=2) |
| sign/verify | Single-leg downgrade (break one algorithm) | Both legs required (AND-composition) | `Ed448Standard::verify_with_context` AND `MlDsa65Fips204::verify_with_context` both must pass; single-leg success is rejected | CRYPTOGRAPHY.md §Keystore Entry Signatures §Signature Scheme | Hybrid |
| sign/verify | Cross-context replay (envelope sig reused as keystore sig) | Context-byte domain separation prevents cross-context validity | `KEYSTORE_SIG_CONTEXT = b"sss-keystore-entry-sig-v1"` ≠ `ENVELOPE_SIG_CONTEXT = b"sss-toml-envelope-sig-v1"` | CRYPTOGRAPHY.md §Envelope Signatures v2 §Domain-Separation Context | Hybrid |

### Envelope signatures (format_version=2)

Phase 19 (PQSIG-04..06) adds Ed448 + ML-DSA-65 AND-composition signatures over
the entire `.sss.toml` project envelope (`version`, `created`, sorted `users`
table). This surface applies only when `format_version = 2`.

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| sign/verify (envelope) | Tampered `.sss.toml` user table | Hard reject: signature fails on read | Ed448 + ML-DSA-65 AND-composition over canonical (version, created, sorted users table) | CRYPTOGRAPHY.md §Envelope Signatures v2 | Hybrid (format_version=2) |
| sign/verify | Unsigned envelope written by a mutating verb | Hard error — PQSIG-06 | `require_signed` gate on all mutating verbs; format_version=1 → `"run sss envelope upgrade-sig"` actionable error | CRYPTOGRAPHY.md §Envelope Signatures v2 §format_version Dispatch | Hybrid |
| sign/verify | Seal-key canonicalisation drift (length-extension or boundary-shift) | Length-prefixed payload prevents boundary-shift attacks | u32-BE length prefix before every variable-length field; fixed field order in `build_envelope_payload` | CRYPTOGRAPHY.md §Envelope Signatures v2 §Canonical Signed Payload | Hybrid |
| sign/verify | Timing oracle on per-leg error | Out of scope (at-rest model, not live submission) — see §Properties Explicitly Out of Scope | Documented decision D-V23-03: per-leg error reporting preserved for debuggability; at-rest threat model | security-model.md §Constant-Time Considerations | Hybrid |

### Deterministic nonce / clean-diff property

The BLAKE2b-192 keyed nonce scheme ensures that the same (key, path, plaintext,
timestamp) always produces the same ciphertext, enabling clean git diffs, while
distinct plaintexts produce distinct nonces.

| Surface | Threat | Property | Mechanism | Source | Scope |
|---------|--------|----------|-----------|--------|-------|
| seal (any) | Nonce reuse across different plaintexts | Collision requires BLAKE2b-192 preimage break | BLAKE2b-192 keyed with K, personalisation `"sss_autononce_v1"`; full plaintext in input → different nonces for different plaintexts | security-model.md §Deterministic Nonces; CRYPTOGRAPHY.md §Nonce Derivation | Both |
| seal (any) | Byte-non-identical ciphertext across suite migration | Invariant preserved: same K → same AEAD output | In-file AEAD uses K and BLAKE2b nonce regardless of how K was wrapped (classic or hybrid); `sss migrate` touches only `.sss.toml` sealed_key fields, never file content | security-model.md §sss migrate safety properties; CRYPTOGRAPHY.md §Byte-Identical Ciphertexts Invariant | Both |

---

## Trust-Anchor Diagram

The diagram below traces the full chain from a user's passphrase to an in-file
sealed marker, plus the `.sss.toml` envelope layout.

```
┌─────────────────────────────── Trust Roots ──────────────────────────────────┐
│                                                                               │
│  Per-user Passphrase                                                          │
│       │                                                                       │
│       │ Argon2id v1.3 (sensitive: ~4 passes, 256 MiB)                        │
│       ▼                                                                       │
│  Derived Key (256-bit symmetric)                                              │
│       │                                                                       │
│       │ XChaCha20-Poly1305 (AEAD encrypt)                                    │
│       ▼                                                                       │
│  ┌──────────────────────────── Keystore ────────────────────────────────┐    │
│  │  Encrypted Private Key(s) in ~/.config/sss/keys/<uuid>.toml         │    │
│  │    classic: X25519 secret key (32 B)         ← format_version=1/2   │    │
│  │    hybrid:  X448+sntrup761 secret key (1819 B)  ← hybrid feature    │    │
│  │    sig:     Ed448+ML-DSA-65 signing keys     ← format_version=2     │    │
│  │  [Each entry signed: Ed448+ML-DSA-65 AND-composition]               │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│       │ (passphrase-unlock)                                                   │
│       ▼                                                                       │
│  User Private Key                                                             │
│       │                                                                       │
│       │ classic: crypto_box_seal_open (X25519)                               │
│       │ hybrid:  trelis decapsulate (X448+sntrup761) + BLAKE3 KDF            │
│       ▼                                                                       │
│  Repository Key K (256-bit)  ◀─── sealed per-user in .sss.toml              │
│       │                                                                       │
└───────┼───────────────────────────────────────────────────────────────────────┘
        │
        │ BLAKE2b-192(key=K, input=ts‖NUL‖path‖NUL‖plaintext,
        │             personal="sss_autononce_v1")
        ▼
   Deterministic Nonce (24 B)
        │
        │ XChaCha20-Poly1305 AEAD
        ▼
   ⊠{base64(nonce[24] ‖ ciphertext[N] ‖ mac[16])}  ← in-file sealed markers
   (byte-identical regardless of suite)

─── .sss.toml Envelope ─────────────────────────────────────────────────────────

  [users.alice]
    public = X25519 pubkey (classic identity anchor)
    hybrid_public = X448+sntrup761 pubkey (hybrid)
    sealed_key = crypto_box_seal(K, pubkey)    ← classic: 80 B
               OR trelis_seal(K, hybrid_pubkey)  ← hybrid: 1167 B
    sig_ed448_public, sig_mldsa65_public = signing pubkeys

  [envelope.sig]  ← AND-composition Ed448+ML-DSA-65 over canonical users table
    ed448 = 114 B, mldsa65 = 3309 B
    context: "sss-toml-envelope-sig-v1"
```

---

## Properties Explicitly Out of Scope

The following are deliberate non-properties of sss. Each is documented in
`docs/security-model.md` with explicit rationale; they are listed here so an
auditor can immediately identify what sss does NOT claim.

**1. Per-leg timing channel on envelope-sig verify (D-V23-03)**

The Phase 19 envelope-sig verify path reports per-leg failures (`Ed448 signature
failed` vs `ML-DSA-65 signature failed` vs `both legs failed`). This is not
constant-time. Decision D-V23-03 (locked Phase 23 / MEMSAFE-06) records this as
out of scope for v2.3 and v2.4: envelopes are at rest (committed to git, read
locally), not live-submitted over a network. An attacker cannot repeatedly probe
the timing in the at-rest threat model. If a future deployment moves envelope-sig
verify to a live-submitted RPC, this decision must be revisited.

Source: `security-model.md §Constant-Time Considerations`

**2. trelis third-party audit gap (AUDIT-01 / EXPERIMENTAL)**

The hybrid suite depends on the `trelis` library (X448 + sntrup761), which is
experimental and has **not** undergone a formal third-party security audit. The
CRYPTOGRAPHY.md WARNING callout is preserved verbatim per locked decision
D-V23-06 (no-scrub rule). AUDIT-01 tracks commissioning of a third-party audit;
until it closes, the hybrid suite ships with the EXPERIMENTAL disclaimer and is
opt-in. Classic (libsodium, extensively audited) remains the recommended default
for all production deployments.

Source: `CRYPTOGRAPHY.md §Hybrid Suite v2.0 §WARNING`; `security-model.md §Trelis Attack Surface`

**3. Metadata and git-history exposure**

sss does not encrypt file structure, marker positions, marker counts, filenames,
or surrounding plaintext. The number of secrets in a file and their positions are
visible to anyone with repository access. Git history prior to sealing retains
any plaintext that was committed before `sss seal` was run. Deterministic nonces
reveal whether a specific secret changed between commits (same ciphertext = no
change; different ciphertext = changed), but not the secret value.

Source: `security-model.md §What is NOT Encrypted`; `security-model.md §Deterministic Nonces`

**4. Passphrase compromise**

If a user's passphrase is compromised, the attacker can derive the Argon2id
wrapping key, decrypt the stored private key from disk, and from there unwrap
all repository keys the user is authorised for. Argon2id (sensitive) slows
offline brute-force (~2 s/guess/core, 256 MiB RAM required), but does not
protect against compromise of the passphrase itself. For classic and hybrid
users with both keypairs under the same passphrase, a single passphrase
compromise yields both private keys (no cryptographic separation at the
keystore-wrapping layer).

Source: `security-model.md §Hybrid Trust Boundaries §Dual-keystore implications`; `security-model.md §Does Not Protect Against`

---

## Cross-References

| Document | Relationship |
|----------|-------------|
| [`docs/CRYPTOGRAPHY.md`](./CRYPTOGRAPHY.md) | Authoritative primitive-level spec: XChaCha20-Poly1305, Argon2id, BLAKE2b, Asymmetric Encryption, Hybrid Suite, Keystore Entry Signatures, Envelope Signatures — every matrix row Source column cites a section here |
| [`docs/security-model.md`](./security-model.md) | Threat-model framing: Per-Suite Threat Tables, Deterministic Nonces, Hybrid Trust Boundaries, Constant-Time Considerations, sss migrate safety properties, Trelis Attack Surface, Key Derivation Argon2id |
| [`docs/security-depth.md`](./security-depth.md) | Defence-in-depth posture across six dimensions; audit-readiness package inventory; entry point for external auditors |
