# Vendoring Policy

Single source of truth for how sss treats external dependencies that
DON'T flow through the standard `crates.io` channel: vendored path-deps,
git-rev pinned deps, and dynamically-linked system libraries.

The default channel is `crates.io` (resolved via `Cargo.lock`, gated by
`cargo-deny` strictness in `deny.toml`, attested by `cargo-vet` in
`supply-chain/`). The cases below are exceptions to that default; each
exception carries a documented rationale, a refresh expectation, and an
audit-discoverable trail.

## Vendored path-dep: `vendor/rust-9p/`

**What:** 9P2000.L protocol filesystem library, vendored as a git
subtree-style copy at `vendor/rust-9p/`. Renamed to `rs9p` in
`Cargo.toml` line 70 via `package = "rust-9p"`.

**Why vendored:**

- The upstream crate (`rust-9p` by pfpacket) was last touched in 2018;
  the current ecosystem has moved on (nix 0.30+, tokio 1.0 stable, etc.)
  but the upstream crate is frozen at older versions.
- sss needs the 9P codec for the `ninep` feature; rewriting from
  scratch is out of scope for v2.x.
- Vendoring lets us pin specific behaviour (the `enum_primitive` import
  + the older `nix 0.26` line) without forcing the entire workspace to
  match the upstream crate's exact dep set.

**Refresh expectation:** The vendored copy is treated as effectively
frozen. The only deliberate edits since vendoring have been:

- v2.3 Plan 24-01: `enum_primitive = "*"` → `"0.1"` to satisfy
  `cargo-deny wildcards = "deny"`.
- (no other edits planned through v2.4)

A full upstream-sync (replacing the vendored tree with a newer
`rust-9p` snapshot) is gated on TWO conditions:

1. Upstream publishes a release tag (currently the repo is just `master`
   without semver tags).
2. The new tree passes `cargo build --features ninep` + the existing 9P
   integration tests.

Neither condition holds as of v2.3 close; the next review point is
v2.5 (after AUDIT-01 closes).

**cargo-vet handling:** `[policy.rust-9p]` block in
`supply-chain/config.toml` with `audit-as-crates-io = false` + a notes
field citing this document.

**cargo-deny handling:** `bitflags@1.3.2` + `nix@0.26.4` + `num-traits@0.1.43`
skip entries in `deny.toml` (mechanical follow-on of the older nix line
that vendored rust-9p pulls in).

## Git-rev pinned: `trelis-hybrid` + `trelis-primitives`

**What:** Hybrid PQ-classic signature suite (X448 + ML-DSA-65), pinned
to git rev `5374dff482ba94a94695794b5e4554f908eb0d4d` at
`https://github.com/dspearson/trelis`. Two crates in the workspace:
`trelis-hybrid` (Cargo.toml line 82) + `trelis-primitives` (line 83).

**Why git-rev pinned (not crates.io):**

- trelis is the maintainer's own experimental hybrid signature
  implementation; not on crates.io because it's pre-1.0 (EXPERIMENTAL
  status disclaimer per D-V23-06 no-scrub).
- The pinned SHA gives us a byte-identical dep across rebuilds
  (substantively equivalent to crates.io + Cargo.lock pinning for
  reproducibility purposes — same SHA → same code).
- An external audit (AUDIT-01) is on the v2.3 backlog; when it closes,
  the path forward is either: (a) publish trelis to crates.io with
  audit findings addressed, or (b) keep the git pin with the audit
  report linked from `docs/CRYPTOGRAPHY.md`.

**Refresh expectation:** The pinned SHA does NOT bump on a cadence;
it bumps when:

- AUDIT-01 closes with findings that require code changes.
- A specific upstream feature is needed.

A bump touches all three layers:

1. `Cargo.toml` rev= entries (lines 82 + 83) updated atomically.
2. Every doc reference to the SHA bumped: `docs/security-model.md`
   (2 references), `docs/CRYPTOGRAPHY.md` (3 references),
   `supply-chain/config.toml` (2 references in policy.notes), plus
   this document if the rationale changes.
3. `.github/workflows/supply-chain.yml` `trelis-pin` job EXPECTED
   array updated to match the new SHA + new count if any reference is
   added or removed.

The bump PR carries a `release-engineer` review tag specifically
calling out the cross-file consistency.

**cargo-vet handling:** `[policy.trelis-hybrid]` + `[policy.trelis-primitives]`
blocks in `supply-chain/config.toml` with `audit-as-crates-io = false`
+ notes citing AUDIT-01 + the EXPERIMENTAL retention rule per D-V23-06.

**Drift detection:** `.github/workflows/supply-chain.yml` `trelis-pin`
job runs `grep -c $SHA <file>` against an EXPECTED count per file; any
drift fails the build. Plus a secondary check that every
`^trelis-* = .* rev =` line in `Cargo.toml` contains the pinned SHA
(catches "different SHA substituted in one entry" silently).

## Linked-dynamic system library: `libsodium`

**What:** libsodium is linked dynamically against the system-installed
shared object via `libsodium-sys`. NOT vendored under `vendor/`.

**Why linked-dynamic, not vendored:**

- libsodium is a stable, well-audited cryptographic primitive library
  (Frank Denis et al.) shipped by every major distro (Debian, RHEL,
  Alpine, Homebrew). System packaging is the standard distribution
  channel.
- Vendoring libsodium would mean shipping a copy of the C source tree
  and keeping it in sync with upstream — a substantial maintenance
  burden for a library that distros handle competently.
- The minimum supported libsodium version is whatever ships in Debian
  stable (1.0.18 as of 2024); the `libsodium-sys` build script
  validates the version at link time.

**Refresh expectation:** Tracks distro packaging. sss does NOT pin a
specific libsodium version; the linked-dynamic dep follows whatever
the build host has installed. The release distribution is verified
against the libsodium version present on each release-build host
(arm64-builder, macos-builder, and the CI runners).

**cargo-vet handling:** `libsodium-sys` (the Rust binding crate) IS
in the crates.io trust path (covered by Mozilla / Google imports OR
hand-authored audits in v2.4). libsodium-the-library is OUTSIDE the
cargo-vet trust path entirely (it's a system library, not a crates.io
crate).

**Static-linking exception:** `Dockerfile.alpine`,
`build-macos-static.sh`, and the various `*-static.sh` build scripts
DO statically link libsodium into the produced binary for portability
of the release artefact. The build script bundles libsodium at the
specific version installed on the build host; the build host's
libsodium version is recorded in the release notes per release.

## Refresh Cadence Summary

| Dep | Refresh trigger | Audit handling |
|---|---|---|
| `vendor/rust-9p/` | Upstream tag + integration tests pass | `[policy.rust-9p]` in supply-chain/config.toml |
| `trelis-hybrid` + `trelis-primitives` | AUDIT-01 close / specific feature need | `[policy.trelis-*]` + supply-chain.yml trelis-pin gate |
| `libsodium` (linked-dynamic) | Distro packaging (not pinned in repo) | system-library scope, outside cargo-vet |
| `libsodium` (statically-linked release artefacts) | Per-release; build-host version recorded in notes | System-library scope |

## Should-We-Vendor-X? Decision Framework

When evaluating a new dep for vendoring (vs git-rev / crates.io):

1. **Is it on crates.io with semver releases?** If yes → use crates.io.
   This is the default channel; no exception needed.
2. **Is the upstream actively maintained?** If yes but no crates.io
   release → use a git-rev pin (like trelis); document in this file.
3. **Is the upstream effectively frozen but the code still essential?**
   If yes → vendor under `vendor/<name>/` and document the refresh
   expectation here. Refresh becomes a deliberate PR + review tag.
4. **Is it a system library?** If yes → link dynamically (or
   statically per release artefact policy); document as a
   linked-dynamic dep here.

The decision MUST be recorded in this document at the time of adoption,
not retroactively. The vendoring decision is an audit-discoverable
choice; reviewers reading this doc see what we chose and why for each
non-crates.io dep.

## crates.io-pinned: `vault` feature deps

**What:** 12 crates introduced by the `vault` feature in Phase 47
(`ureq 3.3.0`, `ureq-proto 0.6.0`, `rustls 0.23.40`, `rustls-webpki 0.103.13`,
`rustls-pki-types 1.14.1`, `ring 0.17.14`, `untrusted 0.9.0`, `webpki-roots 1.0.7`,
`http 1.4.2`, `httparse 1.10.1`, `percent-encoding 2.3.2`, `utf8-zero 0.8.1`).

**Why NOT vendored:** All 12 crates are active crates.io releases (not
unmaintained or git-only), and `ureq` + `rustls` + `ring` receive regular
upstream patches. Standard crates.io channel applies — no exception needed.

**Pinned via:** `Cargo.lock` (committed, per BUILD-01) + `cargo-vet`
exemptions in `supply-chain/config.toml` (D-VET-1 30-day SLA).

**Refresh expectation:** Deliberate `cargo update -p ureq` (or equivalent)
with a new supply-chain review. Bumping the rustls crypto backend from `ring`
to `aws-lc-rs` is deferred to v3.1 (per STACK.md §1 rationale).

**cargo-deny handling:** `deny.toml` `[graph] features` includes `"vault"`;
`"OpenSSL"` + `"CDLA-Permissive-2.0"` added to `[licenses] allow`; ring has
a `[[licenses.clarify]]` stanza. See `docs/SUPPLY-CHAIN.md § Vault Feature
Dependency Surface` for the full rationale.

## See Also

- `docs/SUPPLY-CHAIN.md` — broader supply-chain policy (cargo-deny,
  cargo-vet, supply-chain.yml gate suite). See the "Vault Feature Dependency
  Surface" section for vault-specific treatment.
- `docs/CRYPTOGRAPHY.md` — trelis cryptographic primitives reference;
  cross-referenced for the trelis-pin rationale.
- `supply-chain/config.toml` — `[policy.<crate>]` blocks with
  audit-defensible notes for trelis-* + rust-9p.
- `.github/workflows/supply-chain.yml` `trelis-pin` job — drift gate.
- Phase 26 BUILD-01 / BUILD-02 / BUILD-05 — reproducible-build policy
  (committed Cargo.lock + build-reproducible.sh + 2-host diff
  transcript).
- Phase 27 AUDIT-03 — closeout doc that references this policy as part
  of the auditor-readiness package.
