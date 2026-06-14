# Supply Chain Policy

This project enforces a tiered supply-chain contract: `cargo-deny` gates
duplicate-version drift + advisory ledger; `cargo-vet` attests per-dep
review status against curated Mozilla + Google audit imports;
`cargo-geiger` publishes informational unsafe-block surface counts
per-milestone; `cargo-auditable` (Phase 25) will embed the dep manifest
in release binaries. `.github/workflows/supply-chain.yml` runs the gate
suite on a weekly Friday 03:00 UTC cron + workflow_dispatch + pull_request
trigger.

## Policy Overview

- **cargo-deny** (`deny.toml`) gates: duplicate dep versions (deny + curated
  skip list with 30-day refresh SLA); RUSTSEC advisory ignore ledger (each
  entry carries `# Why:` + expiry); permissive-licence allow list;
  registry source allow list.
- **cargo-vet** (`supply-chain/`) attests: which deps have been reviewed
  (via imports from Mozilla + Google + local hand-authored entries) and
  which are first-party (trelis-* + vendored rust-9p via `[policy.<crate>]`
  notes). Currently 38 deps fully audited + 1 partial + 294 exempted;
  reduction is a Phase 27 AUDIT-03 + v2.4 follow-on.
- **cargo-geiger** publishes per-milestone informational snapshots
  (MEMSAFE-07; Phase 23). NOT a CI gate.
- **cargo-auditable** (Phase 25 BUILD-04) embeds the dep manifest in
  release artefacts. Release entry points using `cargo auditable build`:
  `Dockerfile.alpine`, `build-on-arm64-linux.sh`, `rpm-build/build-rpm.sh`,
  `rpm-build/sss.spec`. Local-only entry points follow the same pattern
  on the release operator's host.
- **CycloneDX SBOM** (Phase 25 BUILD-03; Phase 47 VNET-05 vault arm) generated
  by `scripts/release/generate-sbom.sh` using `cargo-cyclonedx 0.5.9+`:
  9 files in `dist/sbom/` matching the 3 platforms × 3 feature arms
  release matrix (default / hybrid / vault). trelis-* + fips204 +
  ed448-goldilocks-plus appear in the hybrid SBOMs only; ureq + rustls +
  ring + related crates appear in the vault SBOMs only.
- **cosign keyless signing** (Phase 25 SIGN-02) via
  `.github/workflows/release.yml`: ephemeral Fulcio cert + Rekor
  transparency log. Releases ship `.sig` + `.pem` + `.intoto.jsonl`
  artefacts alongside binaries. See `docs/RELEASE.md § Verification`
  for the verification command.
- **Release-signing keypair** (Phase 25 SIGN-01 / D-V23-04) generated
  offline by `scripts/release/generate-release-key.sh`. Distinct from
  envelope-sig material (Pitfall 14 mitigation) via domain-separation
  bytes `b"sss-release-artifact-sig-v1"` + algorithm split (Ed25519 vs
  Ed448 + ML-DSA-65). Public key in `docs/release-keys/`; private key
  offline (HSM or air-gapped USB).

## Cargo.lock Policy (Phase 26 / BUILD-01)

As of v2.3, `Cargo.lock` IS committed to git (D-V23-01). Prior to v2.3
the lock was gitignored on the rationale that sss is a binary crate
where the lock isn't strictly required; v2.3 reverses this for
reproducible-build verification (BUILD-05 2-host diff). Bumps happen
via deliberate `cargo update -p <crate>` + commit; CI uses
`cargo build --locked` so any drift between the committed lock and a
resolved state fails the build.

See [`docs/vendoring-policy.md`](vendoring-policy.md) for the
companion policy on non-crates.io deps (vendored rust-9p, git-rev
pinned trelis-*, linked-dynamic libsodium) and
[`docs/RELEASE.md § Reproducible Build`](RELEASE.md) for the build
wrapper script (`scripts/release/build-reproducible.sh`).

## cargo-deny Configuration

The policy is `deny.toml` at repo root. Single source of truth for
strictness; this document is the rationale layer.

- **`[graph] features = ["hybrid", "fuse", "ninep", "vault"]`** — Linux build
  surface. `winfsp` excluded because `winfsp-sys` ships under GPL-3.0
  (incompatible with sss's ISC licence). `vault` added in Phase 47 VNET-05
  so the ureq+rustls+ring dep tree enters the license/bans/advisory graph.
  Primary release targets: Linux x86_64 + macOS arm64 + Linux aarch64;
  Windows is best-effort.
- **`[advisories] yanked = "deny"` + `unsound = "all"`** — every
  RUSTSEC unsoundness advisory across the dep graph fails CI. Two
  current ignores: RUSTSEC-2021-0154 (fuser 0.14 uninit-mem read; fix
  is fuser >=0.16 API migration, deferred to Phase 25) and
  RUSTSEC-2026-0097 (rand 0.9.2 unsound only with custom logger calling
  `rand::rng()` at trace level; sss has no custom logger). Both
  expire 2026-08-19.
- **`[bans] multiple-versions = "deny"` + curated `skip` list** —
  Phase 24 SUPPLY-01 uplift from v2.1 baseline `"warn"`. Each skip
  entry carries `# Why: <reason>. (Refresh by YYYY-MM-DD)` per
  **D-DENY-1 30-day SLA**: the refresh date is 30 days out; the
  past-refresh-date check is INFORMATIONAL in supply-chain.yml's deny
  job for v2.3 (hard-fail-on-stale is v2.4 enhancement).
- **`[bans] allow-wildcard-paths = true`** — sss has path + git deps
  (rust-9p vendored, trelis-* git-rev pinned) that resolve to wildcard
  version requirements. Combined with `publish = false` in Cargo.toml,
  cargo-deny accepts the wildcard-via-path pattern.

Skip-list refresh procedure: each PR that touches `deny.toml`'s skip
block updates the `Refresh by` date in the same change. The intent is
to force a re-review of the duplicate-version rationale every 30 days,
not to discourage edits.

Pitfall mitigation: `[[exemptions.<crate>]]` in cargo-deny does not
exist — duplicates are handled via `skip`. The cargo-vet exemption
ledger is a separate concept (§ cargo-vet Configuration).

## Vault Feature Dependency Surface

Phase 47 / VNET-05 + VDOC-03. The `vault` feature enables HashiCorp Vault
secret resolution via a blocking HTTP client (ureq 3 + rustls 0.23 + ring
0.17). This surface was cleared through the supply-chain gate on 2026-06-12;
the blocking human checkpoint was approved prior to plan execution.

**Net-new crates (12, all from crates.io):**

| Crate | Version | License | Notes |
|-------|---------|---------|-------|
| `ureq` | 3.3.0 | MIT | Blocking HTTP client; `forbid(unsafe_code)` |
| `ureq-proto` | 0.6.0 | MIT | Internal HTTP framing for ureq |
| `rustls` | 0.23.40 | Apache-2.0 / MIT / ISC | TLS 1.2 + 1.3; RUSTSEC-2023-0052 (fixed 0.21.1+) |
| `rustls-webpki` | 0.103.13 | ISC | Certificate verification; RUSTSEC-2023-0053 (fixed 0.101.1+) |
| `rustls-pki-types` | 1.14.1 | MIT / Apache-2.0 | Shared PKI types |
| `ring` | 0.17.14 | ISC AND MIT AND OpenSSL | BoringSSL-derived C+asm; RUSTSEC-2025-0007 history; see clarify stanza |
| `untrusted` | 0.9.0 | ISC | ring input-validation |
| `webpki-roots` | 1.0.7 | CDLA-Permissive-2.0 | Mozilla root CA bundle |
| `http` | 1.4.2 | MIT / Apache-2.0 | HTTP types |
| `httparse` | 1.10.1 | MIT / Apache-2.0 | HTTP/1 parser |
| `percent-encoding` | 2.3.2 | MIT / Apache-2.0 | URL encoding |
| `utf8-zero` | 0.8.1 | MIT / Apache-2.0 | Zero-copy UTF-8 slicing |

**No tokio.** ureq 3 is blocking I/O only; verified by Cargo.lock lockfile
analysis. `vault` and `ninep` are independently activatable features.

**Gzip trim rationale.** An earlier iteration of the vault dep tree included
`flate2 + miniz_oxide + adler2 + crc32fast + simd-adler32` (5 crates) via
ureq's `gzip` feature. These were dropped (commit c1f56a1) because Vault's
REST API does not require content-encoding decompression; removing `gzip`
from the ureq feature set eliminated the 5 crates, reducing the net-new
surface to 12.

**cargo-deny treatment (deny.toml):**

- `"vault"` added to `[graph] features` so the dep tree enters all checks.
- `"OpenSSL"` added to `[licenses] allow` (ring's composite ISC AND MIT AND
  OpenSSL license). ring is additionally covered by a `[[licenses.clarify]]`
  stanza with `hash = 0xbd0eed23` (computed by cargo-deny against ring
  0.17.14's LICENSE file); a wrong hash would fail the gate (fail-closed).
- `"CDLA-Permissive-2.0"` added to `[licenses] allow` (webpki-roots 1.0.7).
  STACK.md listed MPL-2.0 but the published crate uses CDLA-Permissive-2.0;
  this was caught at gate-run time and corrected (Rule 1 auto-fix).
- No `[bans] skip` entries needed: ring 0.17.14 is a single version across
  the graph (no duplicate risk); all other vault crates are also
  single-version.

**cargo-vet treatment (supply-chain/config.toml):**

All 12 vault crates are exempted with `notes = "vault feature — Phase 47
supply-chain review"` (D-VET-1 30-day SLA pattern). The Mozilla and Google
audit imports were checked first; none cover these specific versions. Key
notes on the security-critical subset:

- `ring` — carries C/assembly unsafe code (BoringSSL-derived); RUSTSEC-2025-0007
  history noted in exemption. Manual security review required before
  promoting to a hand-authored `[[audits.ring]]` entry.
- `rustls` — RUSTSEC-2023-0052 (fixed in 0.23.x); current version confirmed
  clear. Uses ring as crypto provider (ureq default).
- `rustls-webpki` — RUSTSEC-2023-0053 (CPU exhaustion in name constraint
  handling; fixed in 0.101.1+); version 0.103.13 is well past the fix.

**SBOM coverage:** `scripts/release/generate-sbom.sh` now generates 3
additional vault-arm SBOMs (linux-x86_64, linux-aarch64, macos-arm64), for a
total of 9 CycloneDX SBOM files per release (was 6). The vault dep surface is
captured in `dist/sbom/sss-*-vault.cdx.json`.

**Human sign-off:** The vault dep tree (12 crates, pinned versions, zero
advisories from `cargo deny check`, crates.io origin confirmed via `cargo deny
check sources`) was reviewed and approved by the maintainer prior to Phase 47
plan execution. This checkpoint is recorded here per VDOC-03.

## cargo-vet Configuration

The cargo-vet store is `supply-chain/` (cargo-vet community default;
Plan 24-02 deviates from earlier `.cargo/` planning for tool-default
alignment).

- **`supply-chain/config.toml`** holds: `[imports.mozilla]` + `[imports.google]`
  (D-VET-1 lock: NO Bytecode Alliance in v2.3 — revisit in v2.4 if dep
  surface grows); `[policy.trelis-hybrid]` + `[policy.trelis-primitives]`
  + `[policy.rust-9p]` (audit-as-crates-io = false; audit-defensible
  `notes` field cites AUDIT-01 / EXPERIMENTAL / `vendor/rust-9p` per
  D-V23-06 no-scrub); `[[exemptions.<crate>]]` × 305 (Phase 47 added 14:
  12 vault crates + fuser 0.16.0 + nix 0.29.0 that were missing from the
  Phase 29 fuser bump; reduction tracked at Phase 27 AUDIT-03).
- **`supply-chain/audits.toml`** holds hand-authored `[[audits.<crate>]]`
  entries (currently empty; v2.4 hand-author campaign will fill the
  security-critical primitives list: subtle, zeroize, base64,
  constant_time_eq, blake3, chacha20poly1305, ed448-goldilocks-plus,
  fips204, ntrulp).
- **`supply-chain/imports.lock`** pins specific revisions of the Mozilla
  + Google registries. Auto-generated by cargo-vet — DO NOT hand-edit.
  Bumped deliberately via `cargo vet regenerate imports` in a reviewed PR.

The 294-exemption deferral is the audit-readiness scar from Phase 24.
It is NOT hidden — supply-chain.yml's `vet` job surfaces the count as a
workflow notice for trend tracking; docs/SUPPLY-CHAIN.md (this file) is
the policy-of-record document. **PITFALLS.md Pitfall 3** explicitly
called out the exemption-ledger pattern as the audit-blocker risk; the
Phase 24 mitigation is: (1) trelis-* + rust-9p are NOT in the exemption
pool — they're `[policy.<crate>]` entries with substantive notes; (2)
the exemption count is publicly tracked + reduction is on the v2.4 +
Phase 27 backlog.

## Vendored Dependencies

Three classes of non-crates.io deps cross the trust boundary into sss:

1. **`vendor/rust-9p/`** — 9P2000.L protocol library, path-dep renamed to
   `rs9p` in Cargo.toml. Tracked via `[policy.rust-9p]` in supply-chain/
   config.toml with `audit-as-crates-io = false` + notes citing
   Phase 26 SUPPLY-06 as the eventual policy-of-record.
2. **`trelis-hybrid` + `trelis-primitives`** — hybrid PQ-classic
   signature suite, git-rev pinned. Tracked via `[policy.trelis-*]` in
   supply-chain/config.toml with notes citing AUDIT-01 (external audit
   backlog) + the EXPERIMENTAL disclaimer (D-V23-06 no-scrub).
3. **`libsodium`** — linked dynamically via `libsodium-sys`; the system
   library boundary is not a vendoring concern.

The full vendoring policy lives in **Phase 26 SUPPLY-06**
(`docs/vendoring-policy.md`, future). This section is the brief
forward-pointer; Phase 26 documents update cadence, divergence-from-
upstream review, and the security-review approach for vendored sources.

## trelis Pin Policy

The trelis git rev `5374dff482ba94a94695794b5e4554f908eb0d4d` is pinned
in `Cargo.toml`. The `.github/workflows/supply-chain.yml` `trelis-pin`
job enforces a grep-count invariant — the SHA must appear with stable
counts across the enumerated files:

- `Cargo.toml`: 3 occurrences
- `docs/security-model.md`: 2
- `docs/CRYPTOGRAPHY.md`: 3
- `supply-chain/config.toml`: 2

Drift in any file fails the build. Drift mitigation procedure: when the
pin itself bumps OR when a deliberate reference is added/removed,
update all four locations + the workflow's `EXPECTED` array in a
single atomic PR. The reviewer checks the diff for: (a) the new SHA
appears with the new EXPECTED counts; (b) every removed/changed
reference is intentional; (c) the EXPERIMENTAL disclaimer is retained
in `supply-chain/config.toml` `[policy.trelis-*]` notes (D-V23-06
no-scrub rule).

A secondary check in the same workflow asserts every `^trelis-* = .* rev =`
line in `Cargo.toml` contains the same pinned SHA — catches the case
where the total count matches but a different SHA was substituted in
one entry.

## Evolution Workflow

Changing this policy is a PR-reviewed event:

1. Open a PR modifying `deny.toml` OR `supply-chain/config.toml` OR
   `supply-chain/audits.toml` OR `.github/workflows/supply-chain.yml`.
2. Update this document in the same PR if the policy intent changes
   (e.g. adding Bytecode Alliance imports = D-VET-1 lock revisit).
3. Require a reviewer sign-off explicitly noting "supply-chain policy
   change reviewed".
4. Avoid tightening mid-milestone — churn drowns out signal.

Loosening (deny → warn, or adding exemptions) requires explicit
rationale because it reduces audit signal. Tightening (removing
exemptions, adding hand-authored audits, dropping skip entries when
upstream consolidates) is welcome any time.

When cargo-deny or cargo-vet surfaces a new finding: triage first
(real issue or upstream churn?), then either fix at the source, add a
documented exemption/ignore with expiry, or update the skip list with
a refreshed `# Why:` rationale. Never silence the gate without a
documented trail.

## Nix Integration-Test Toolchain (Phase 47-05)

The live Vault integration tests (`tests/vault_integration.rs`) require two
additional binaries that are NOT part of the default Rust build; they are
provided by a committed nix flake (`flake.nix` / `flake.lock`) that pins the
exact versions via a content-addressed nixpkgs revision.

**Pinned nixpkgs rev:**
```
8c91a71d13451abc40eb9dae8910f972f979852f
```

narHash: `sha256-fnzKKPvS+oieI/pTzotA5tkoM47EB1NpaBcgk4R97hE=`
lastModified: 2026-06-11

**Toolchain binaries provided by `nix develop .#vault-it`:**

| Binary           | Package         | Version | Licence    | Source          |
|------------------|-----------------|---------|------------|-----------------|
| `bao`            | openbao         | 2.5.4   | MPL-2.0    | Linux Foundation OpenBao fork; Vault-compatible REST API |
| `process-compose`| process-compose | 1.110.0 | Apache-2.0 | F1Bonacc1/process-compose |
| `jq`             | jq              | 1.8.1   | MIT        | jqlang/jq       |

**Dependency policy:**

These tools are **optional dev/CI dependencies** — they are NOT required for:
- Default `cargo test` (all tests skip gracefully when tools are absent)
- Default `cargo build --features vault` production builds
- Any release artefact

They are only required when running the live integration tier explicitly:
```
nix develop .#vault-it --command cargo test --features vault,hybrid --test vault_integration
```

**Supply-chain posture:**

The nix `flake.lock` commits the exact nixpkgs content-addressed revision,
analogous to the digest-pinned base-image convention (REM-45).  A floating,
unlocked input is not acceptable (same rule as trelis pinned by SHA and
rust-9p vendored).  The `vault` Rust feature is NOT enabled by the nix
flake — it stays ambient on the host compiler; only the `bao` + `process-compose`
binaries enter via nix.  Rust/cargo are explicitly excluded from the devShell
to prevent version divergence with the host toolchain.

**Skip-gracefully contract:**

`VaultDevServer::new()` probes `process-compose version` and `bao version` at
test start.  If either probe fails, the test prints a SKIP notice and returns
without failing.  This means default CI (no nix) always sees a passing
`vault_integration` suite.  The live tier is exercised only in environments
that enter `nix develop .#vault-it` first.

## References

- `deny.toml` — cargo-deny policy
- `supply-chain/config.toml` + `supply-chain/audits.toml` +
  `supply-chain/imports.lock` — cargo-vet store
- `.github/workflows/supply-chain.yml` — CI gate suite
- `docs/CRYPTOGRAPHY.md` — trelis pin rationale
- `docs/security-model.md` — full threat model including supply-chain
  threats
- `docs/security-depth.md § Supply Chain` — auditor entry-point summary
- Phase 25 BUILD-03/BUILD-04 — SBOM + cargo-auditable embed
- Phase 26 SUPPLY-06 — vendoring policy document
- Phase 27 AUDIT-03 — final audit closeout
- Phase 47-05 — Nix flake + live integration tier (this section)
