<!-- generated-by: gsd-doc-writer -->
# Vault Usage Guide

This guide describes how to use sss's HashiCorp Vault integration: when to put a secret in Vault versus in native sss markers, how to interpret render exit codes and write robust shell scripts around them, and how to configure a repository that mixes or uses exclusively each approach.

For marker syntax and the full `⊳{}` grammar, see [marker-format.md](./marker-format.md).
For secrets-file interpolation (`⊲{}`), see [SECRETS_FILE_FORMAT.md](./SECRETS_FILE_FORMAT.md).
For the lockfile cryptographic model, see the [Vault Lockfile Integrity](./security-model.md#vault-lockfile-integrity) section of `security-model.md` and [Vault Lockfile Digest (keyed BLAKE2b MAC)](./CRYPTOGRAPHY.md) in `CRYPTOGRAPHY.md`.
For general sss usage, see [usage-guide.md](./usage-guide.md).

---

## Contents

1. [Decision Matrix — Where Should This Secret Live?](#1-decision-matrix--where-should-this-secret-live)
2. [Failure Model and Shell Workflows](#2-failure-model-and-shell-workflows)
3. [Coexistence Model — Worked Examples](#3-coexistence-model--worked-examples)
4. [Command Reference](#4-command-reference)
5. [Mount Semantics](#5-mount-semantics)
6. [Lockfile and Version Pinning](#6-lockfile-and-version-pinning)
7. [Classic (v1) Repository Opt-In](#7-classic-v1-repository-opt-in)

---

## 1. Decision Matrix — Where Should This Secret Live?

The two mechanisms compose cleanly: native sss markers (`⊕{}` / `⊠{}`) store an encrypted value directly in the repository; Vault markers (`⊳{}`) store only a reference and fetch the value from a live Vault instance at render time. The right choice depends on who needs access, how often the secret rotates, and whether the consuming environment can reach Vault.

| Secret characteristic | Recommended mechanism | Rationale |
|---|---|---|
| **Long-lived, infrequently-rotated** (e.g. TLS private key, signing cert) | **Native sss** (`⊠{}`) | Encrypted-in-git; survives Vault outages; no network dependency at render. Rotation requires a new `sss seal` commit, which is appropriate for an infrequent event. |
| **Must render without Vault available** (offline, airgapped, or early-boot) | **Native sss** (`⊠{}`) | Self-contained: only the sss passphrase is required. `sss render` resolves `⊠{}` markers locally; no network contact. |
| **Short-lived or rotated credential** (database password, OAuth secret, API token) | **Vault** (`⊳{}`) | Vault provides dynamic rotation; the repository never holds the value — only the reference. A rotation in Vault takes effect at the next render with no repository commit required. |
| **Requires an audit trail of reads** (PCI, SOC 2, HIPAA) | **Vault** (`⊳{}`) | Vault's audit log captures every read, by which AppRole, at what time. Native sss resolves locally — no audit event is emitted. |
| **Shared across many repositories or services** | **Vault** (`⊳{}`) | A single Vault path is the canonical source; all consumers reference it. Native sss would require the value to be sealed independently into each repository, creating drift risk. |
| **Developer-local or per-developer override** | **Native sss** or **secrets file** (`⊲{}`) | Vault adds network and auth overhead that is unnecessary for purely local secrets. The `.secrets` file with `⊲{}` interpolation covers per-developer overrides without committing any value. |

**Summary:** native sss = encrypted-in-git, self-contained, no network required at render. Vault = centralised, rotatable, audited, but requires Vault reachability and valid auth credentials at render time (unless using the lockfile; see §6).

---

## 2. Failure Model and Shell Workflows

`sss render` defines three success/failure exit codes for vault-related conditions. Understanding them precisely is essential for writing robust CI and deployment scripts.

### 2.1 Exit Code Reference

| Code | Name | Condition | Output written? |
|---|---|---|---|
| **0** | Success | All `⊠{}`, `⊲{}`, and `⊳{}` references resolved. | Yes — full rendered output. |
| **0** | Success (kept unresolved) | `--keep-unresolved` was set and one or more per-ref misses occurred; unresolved markers are left verbatim. | Yes — partial output with verbatim markers. |
| **3** | Per-reference miss | One or more `⊳{}` (Vault) or `⊲{}` (secrets-file) references could not be resolved (path or field absent in Vault / key absent in `.secrets`). stderr names each unresolved reference. Other references still resolve; the unresolved marker is left verbatim in the output. | Yes — partial output emitted to stdout (vault misses) or no output (secrets-file misses). |
| **4** | Whole-operation failure | Vault is unreachable, AppRole authentication failed, or a TLS error occurred. **No output is written** — not even partial. The original file is left untouched. | **No** — output is suppressed entirely. |

`sss vault verify` adds one further exit code:

| Code | Name | Condition |
|---|---|---|
| **2** | Lockfile drift | At least one locked reference's current value in Vault differs from its recorded digest. Distinct from exit 3 (reference gone) and exit 4 (Vault unreachable). |

Source locations: `src/commands/process.rs` (`handle_secrets_render_error` → exit 3; `handle_vault_render_error` → exit 3 / exit 4) and `src/commands/vault.rs` (`vault_verify` → exit 2).

### 2.2 The `--keep-unresolved` Flag — Scope and Limitation

`--keep-unresolved` downgrades a per-ref miss (exit 3) to exit 0. The unresolved `⊳{}` or `⊲{}` marker is left in the output verbatim; all other references still resolve normally.

> **Critical limitation:** `--keep-unresolved` **never** masks an exit-4 whole-operation failure. If Vault is down or authentication fails, `sss render --keep-unresolved` still exits 4 and writes no output. `--keep-unresolved` is strictly a per-reference-miss convenience — it is not a way to tolerate a degraded or unreachable Vault.

Appropriate use: local development workflows where some Vault paths may not yet exist, and the partially-rendered output is consumed only by the developer (never shipped to production).

Inappropriate use: CI/CD pipelines or production deployments. A missing secret in a deployed config is a misconfiguration; `--keep-unresolved` would hide it.

The same flag is available on `sss mount` (FUSE): on a per-ref miss the marker is served verbatim instead of returning EIO, but a whole-operation failure still returns EIO.

### 2.3 Shell Script Examples

#### CI / deployment script — strict mode

```bash
#!/usr/bin/env bash
set -euo pipefail

sss render config/app.toml -o /run/secrets/app.toml
status=$?

if [ $status -eq 0 ]; then
    echo "Render succeeded; config written to /run/secrets/app.toml"
elif [ $status -eq 3 ]; then
    # A specific secret path or field is absent in Vault.
    # stderr already names the unresolved reference(s).
    echo "ERROR: one or more Vault references could not be resolved." >&2
    echo "Check that the secret paths exist and this AppRole has read access." >&2
    exit 1
elif [ $status -eq 4 ]; then
    # Vault is unreachable or authentication failed outright.
    # No output was written; the target file is untouched.
    echo "ERROR: Vault is unreachable or authentication failed." >&2
    echo "Check Vault address, network connectivity, and AppRole credentials." >&2
    exit 1
else
    echo "ERROR: sss render exited with unexpected status $status" >&2
    exit 1
fi
```

Because `-o` uses an atomic write (temp file → rename), the destination is never left in a torn state on failure.

#### Development workflow — partial render with `--keep-unresolved`

```bash
#!/usr/bin/env bash
# For local dev only. NEVER use --keep-unresolved in CI or production.
set -euo pipefail

sss render config/app.toml --keep-unresolved -o /tmp/app-dev.toml
echo "Rendered to /tmp/app-dev.toml (unresolved Vault refs left as ⊳{} markers)"
echo "WARNING: this output is incomplete — do not deploy it."
```

> **Warning:** The output of `--keep-unresolved` contains literal `⊳{}` markers wherever Vault paths were missing. If this file is used anywhere beyond local inspection it will expose placeholder markers in configuration that application code may misread. Never use this output in a deployed environment.

#### Monitoring lockfile drift in CI

```bash
#!/usr/bin/env bash
set -euo pipefail

sss vault verify
status=$?

if [ $status -eq 0 ]; then
    echo "Lockfile clean — no drift detected"
elif [ $status -eq 2 ]; then
    echo "DRIFT DETECTED: one or more Vault secrets have changed since last lock." >&2
    echo "Run: sss vault update && git add .sss.vault.lock && git commit -m 'chore: bump vault lock'" >&2
    exit 1
elif [ $status -eq 4 ]; then
    echo "ERROR: Vault unreachable during verify." >&2
    exit 1
fi
```

---

## 3. Coexistence Model — Worked Examples

### 3.1 Mixed file — native sss and Vault references in the same file

A single file may contain `⊠{}` (native sss, encrypted-in-git) and `⊳{}` (Vault, resolved at render) markers simultaneously. The two passes are independent and compose cleanly: the secrets-file pass resolves `⊲{}`, the decrypt pass resolves `⊠{}`, and the Vault pass resolves `⊳{}`.

**File as stored in git** (`config/database.toml`):

```toml
# Connection string — encrypted in git (native sss)
# The password never leaves the repository in plaintext.
host     = "db.internal"
port     = 5432
name     = "myapp"
password = "⊠{dGhpcyBpcyBhIHBsYWNlaG9sZGVyIGZvciBhIHJlYWwgY2lwaGVydGV4dA==}"

# API token — resolved from Vault at render time (rotatable without a repo commit)
api_token = "⊳{mystore:secret/myapp#api_token}"

# TLS client cert — encrypted in git (infrequently rotated)
tls_cert = "⊠{dGhpcyBpcyBhbm90aGVyIHBsYWNlaG9sZGVyIGNpcGhlcnRleHQ=}"
```

**After `sss render config/database.toml`:**

```toml
host      = "db.internal"
port      = 5432
name      = "myapp"
password  = "correct-horse-battery-staple"   # decrypted from ⊠{} by sss

api_token = "hvs.EXAMPLE_TOKEN_VALUE"         # resolved from Vault ⊳{} ref

tls_cert  = "-----BEGIN CERTIFICATE-----\n..."  # decrypted from ⊠{} by sss
```

All three marker types resolve in one `sss render` invocation. The Vault pass requires reachability and valid auth; the native pass requires only the sss passphrase.

### 3.2 Pure-sss repository — no Vault

A repository with no `[vault]` table in `.sss.toml` and no `⊳{}` markers. This is the original sss model: all secrets are encrypted-in-git.

**`.sss.toml` (abridged):**

```toml
version = "2.0"
format_version = 2

[users.alice]
sealed_key = "..."   # per-user key wrap

# No [vault] table — Vault integration is entirely absent.
```

**Typical file:**

```yaml
# deploy/config.yaml
db_password: "⊠{cGxhY2Vob2xkZXJjaXBoZXJ0ZXh0Zm9yZGVtbw==}"
jwt_secret:  "⊠{YW5vdGhlcnBsYWNlaG9sZGVyZm9yZGVtb3B1cnBvc2Vz}"
```

**Rendering:**

```bash
sss render deploy/config.yaml -o /run/config/config.yaml
# exit 0 on success; no Vault contact; passphrase (or SSS_PASSPHRASE) required.
```

This configuration works offline and in airgapped environments. Rotation requires a `sss open` → edit → `sss seal` → commit cycle.

### 3.3 Pure-Vault repository — all secrets from Vault

A repository where all dynamic secrets come from Vault and none are stored encrypted-in-git.

**`.sss.toml` with a `[vault]` table:**

```toml
version = "3.0"
format_version = 3

[users.alice]
sealed_key = "..."

[vault]
address = "https://vault.example.com:8200"

[vault.auth]
method        = "approle"
role_id       = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
secret_id_secret = "vault_secret_id"   # key in .secrets holding the secret_id

[vault.bindings.mystore]
mount      = "secret"
kv_version = 2
```

The `[vault]` block must be signed at `format_version = 3`. Use `sss project vault set-address` and `sss project vault set-auth` to configure these values — those commands sign the envelope automatically.

**Typical file:**

```yaml
# deploy/config.yaml
db_password: "⊳{mystore:secret/myapp/db#password}"
api_key:     "⊳{mystore:secret/myapp/integrations#api_key}"
smtp_pass:   "⊳{mystore:secret/myapp/email#password}"
```

**Rendering:**

```bash
# Authenticate first (optional — render will authenticate implicitly):
sss vault login

# Render all references from Vault:
sss render deploy/config.yaml -o /run/config/config.yaml
# exit 0: all three ⊳{} refs resolved from Vault.
# exit 3: one or more paths/fields absent.
# exit 4: Vault unreachable or auth failed; no output written.
```

**Locking for reproducible renders:**

```bash
sss vault lock
git add .sss.vault.lock
git commit -m "chore: lock vault references"
```

Once locked, `sss render` verifies each resolved value's keyed BLAKE2b digest against the lockfile, giving a reproducible, tamper-detectable render. See §6 for details.

---

## 4. Command Reference

### 4.1 `sss vault` subcommands

All `sss vault` subcommands accept `--allow-unsigned` (see §7).

| Command | Description | Exit on failure |
|---|---|---|
| `sss vault status` | Print Vault config, active bindings, auth method, and token TTL. No credentials printed. | — (informational) |
| `sss vault login` | Authenticate to Vault and report TTL + renewability. Token is never printed. | anyhow error |
| `sss vault get <ref>` | Resolve a single `⊳{ref}` and print the value to stdout. For debugging. | exit 3 (miss) / exit 4 (whole-op) |
| `sss vault lock` | Resolve all `⊳{}` refs and write `.sss.vault.lock` atomically. All-or-nothing. | exit 3 (any miss) / exit 4 (whole-op) |
| `sss vault update [<ref>]` | Re-resolve all refs (or one specific ref) and bump `.sss.vault.lock`. | exit 3 / exit 4 |
| `sss vault verify` | Re-fetch all refs and compare keyed digests against the lockfile. No values printed. | exit 2 (drift) / exit 3 (miss) / exit 4 (whole-op) |
| `sss vault list` | Walk the project and print every `⊳{}` canonical ref found. Network-free. | — |

**`sss vault get` ref format:** the argument is the inner ref string in the same grammar as the marker body — for example:

```bash
sss vault get "mystore:secret/myapp/db#password"
sss vault get "secret/myapp/db#password"          # uses default binding
sss vault get "mystore:secret/myapp/db#password@3" # pinned version
```

### 4.2 `sss render` flags relevant to Vault

| Flag | Description |
|---|---|
| `-o <file>` / `--output <file>` | Write rendered output atomically to `<file>` instead of stdout. On failure, the target is never written. Conflicts with `--in-place`. |
| `-x` / `--in-place` | Render the file atomically in-place. On failure, the original file is preserved. Conflicts with `-o`. |
| `--keep-unresolved` | On per-ref miss (exit 3), leave unresolved `⊲{}`/`⊳{}` markers verbatim and exit 0 instead. **Does not suppress exit 4.** |
| `--allow-unsigned` | Permit `[vault]` config on unsigned (`format_version=1`) repos. `tls_ca_secret` is mandatory when used. |
| `--project` | Recursively render all files in the project. |

### 4.3 `sss project vault` configuration subcommands

These modify `.sss.toml` and re-sign the envelope to `format_version = 3` automatically.

| Command | Description |
|---|---|
| `sss project vault set-address <url>` | Set the Vault server URL (`https://` only). |
| `sss project vault add-binding <name> [--mount <m>] [--default-field <f>] [--kv-version <v>]` | Add or overwrite a named KV binding. |
| `sss project vault set-auth --method <m> [--role-id <id>] [--secret-id-secret <name>] [--token-secret <name>]` | Set authentication configuration. |

---

## 5. Mount Semantics

`sss mount <source> <mountpoint>` (Linux / macOS, requires the `fuse` build feature) presents a FUSE filesystem that resolves `⊠{}`, `⊲{}`, and `⊳{}` markers transparently on each file read.

Vault-specific behaviours:

- **Resolved at read time.** Each file read resolves `⊳{}` markers against Vault. There is no background refresh; stale values are re-fetched on the next read.
- **Fail-closed by default.** A per-ref miss returns EIO for that file. A whole-operation failure (Vault down) returns EIO always.
- **No page-cache retention.** The mount uses `direct_io`; resolved secret values are never retained in the kernel page cache.
- **`<mnt>/.sss/vault-status`** — reading this virtual file reports the current auth state and lockfile drift status without network contact.

Mount flags for Vault control:

| Flag | Description |
|---|---|
| `--no-vault` | Leave `⊳{}` markers literal (no Vault contact; skips auth and signature verification). |
| `--vault-lazy` | Defer Vault auth to first read. A first-read auth failure returns EIO for that file only, rather than failing at mount time. |
| `--keep-unresolved` | On per-ref miss, serve the `⊳{}` marker verbatim instead of EIO. Whole-operation failures still return EIO. |

> **Note:** Vault-over-9P (`sss serve9p`) is not yet available. When a 9P client attempts to use Vault references, sss logs a clear message explaining that this feature is deferred.

---

## 6. Lockfile and Version Pinning

The lockfile (`.sss.vault.lock`) records a keyed BLAKE2b MAC of each resolved Vault value. It enables:

- **Reproducible renders** — `sss render` verifies the resolved value matches its locked digest. An unexpected value (rotated secret, tampered Vault) causes a mismatch.
- **Drift detection** — `sss vault verify` re-fetches all refs and compares live digests against locked ones, exiting 2 on drift.
- **`@version` pinning** — a `⊳{binding:path#field@3}` reference always fetches KV version 3. The lockfile records whether the source ref was pinned; `sss vault verify` re-fetches the pinned version and confirms its digest has not changed.

For the full cryptographic model (keyed digest, no-plaintext guarantee, all-or-nothing write, bootstrap trust chain), see [security-model.md §Vault Lockfile Integrity](./security-model.md#vault-lockfile-integrity).

**Typical lockfile lifecycle:**

```bash
# 1. First lock (resolves all ⊳{} refs, writes .sss.vault.lock atomically):
sss vault lock

# 2. Commit the lockfile:
git add .sss.vault.lock
git commit -m "chore: lock vault references"

# 3. In CI, verify the lockfile has not drifted:
sss vault verify   # exit 2 on drift, exit 0 if clean

# 4. After a planned secret rotation, update the lockfile:
sss vault update
git add .sss.vault.lock
git commit -m "chore: bump vault lock after rotation"
```

The lockfile never contains a plaintext secret value — only binding coordinates, the KV version, and a keyed digest.

---

## 7. Classic (v1) Repository Opt-In

Repositories with an unsigned (`format_version = 1`) envelope cannot normally carry a `[vault]` table — using Vault config on a v1 repo is a hard error. The rationale is that unsigned config could be tampered with to redirect Vault calls to an attacker-controlled address.

If you must use Vault on a v1 repo (for example, during a migration period), pass `--allow-unsigned` to `sss render` or the relevant `sss vault` subcommand:

```bash
sss render config/app.toml --allow-unsigned -o /run/config/app.toml
sss vault status --allow-unsigned
sss vault lock   --allow-unsigned
```

When `--allow-unsigned` is used, `tls_ca_secret` is mandatory in the `[vault]` config — the pinned CA certificate is the only trust anchor available without an envelope signature.

The recommended path is to upgrade the envelope:

```bash
sss envelope upgrade-sig
```

This re-signs the `.sss.toml` envelope at `format_version = 3` (the minimum required for a `[vault]` section) and eliminates the need for `--allow-unsigned`. The command is idempotent.
