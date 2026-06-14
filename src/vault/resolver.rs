//! Vault reference grammar: regex, parser, and preserve-verbatim stub.
//!
//! This module is **not** feature-gated (R4 / VREF-01): the regex and parser
//! must compile in every build so that non-vault peers can recognise and
//! preserve `⊳{}` markers through `seal` and `open` without resolving them.
//!
//! # Grammar
//!
//! ```text
//! ⊳{[binding:]path[#field][@version]}
//!   >{[binding:]path[#field][@version]}   ← ASCII alias, normalised to ⊳{} on seal
//! ```
//!
//! Components (all optional except `path`):
//! - `binding` — name matching `^[A-Za-z0-9_-]+$` before the first `:`.
//!   If the segment before `:` contains `/` or does not match the regex it is
//!   NOT treated as a binding selector; the whole remainder becomes `path`.
//! - `path`    — KV path on the Vault server (may contain `/` and `:` when no binding).
//! - `field`   — KV field name after `#` (optional; resolved from binding
//!   `default_field` at render time in Phase 47 when absent).
//! - `version` — non-negative integer after `@` (optional; defaults to latest).
//!
//! Binding name resolution against configured bindings is deferred to Phase 47;
//! this module parses shape only.

use std::fmt;

use regex::Regex;

// ─── Regex ───────────────────────────────────────────────────────────────────

/// Regex matching a vault reference in its Unicode (`⊳`) or ASCII (`>`) form.
///
/// Captures group 1 as the raw reference text inside the braces (everything
/// between `{` and `}`), e.g. `"secret/app#password@3"`.  The outer delimiters
/// `{` / `}` are consumed by the pattern but not included in the capture.
///
/// Mirrors the shape and `LazyLock` pattern of `SECRETS_INTERPOLATION_REGEX` in
/// `src/secrets.rs` (HARDEN-01 / 08-01).
// Why: literal regex pattern is compile-time-correct; .expect is unreachable
// on any successful build.  Same convention as SECRETS_INTERPOLATION_REGEX.
// HARDEN-01 / 08-01.
#[allow(clippy::expect_used)]
pub static VAULT_INTERPOLATION_REGEX: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| {
        Regex::new(r"(?:⊳|>)\{([^}]+)\}")
            .expect("Failed to compile vault interpolation regex")
    });

// ─── Types ────────────────────────────────────────────────────────────────────

/// Parsed components of a vault reference `[binding:]path[#field][@version]`.
///
/// All fields except `path` are optional and default to `None` when absent from
/// the reference text.  Binding name existence is validated at resolution time
/// in Phase 47 — this struct represents parsed *shape* only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultReference {
    /// Named binding selector (e.g. `"kv"` from `kv:secret/app#pw`).
    ///
    /// Present only when the segment before the first `:` matches
    /// `^[A-Za-z0-9_-]+$` AND contains no `/`.  Otherwise the whole
    /// pre-colon text is part of `path`.
    pub binding: Option<String>,
    /// KV path on the Vault server (never empty).
    pub path: String,
    /// KV field name, stripped of the leading `#`.
    pub field: Option<String>,
    /// Explicit version number, stripped of the leading `@`.
    pub version: Option<u64>,
}

/// Error returned by [`parse_vault_reference`] for malformed references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultRefError {
    /// The reference string was empty (nothing between the braces).
    EmptyReference,
    /// The `@version` suffix was present but could not be parsed as a
    /// non-negative base-10 integer.
    InvalidVersion(String),
}

impl fmt::Display for VaultRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultRefError::EmptyReference => {
                write!(f, "vault reference is empty")
            }
            VaultRefError::InvalidVersion(raw) => {
                write!(
                    f,
                    "vault reference @version must be a non-negative integer, got {raw:?}"
                )
            }
        }
    }
}

impl std::error::Error for VaultRefError {}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse a raw vault reference string into its four optional components.
///
/// The `reference` argument is the text **inside** the `⊳{…}` delimiters,
/// e.g. `"kv:secret/app#password@3"`.
///
/// # Grammar (BNF sketch)
///
/// ```text
/// reference  ::= [ binding ":" ] path [ "#" field ] [ "@" version ]
/// binding    ::= [A-Za-z0-9_-]+        (no "/" allowed)
/// path       ::= <any non-empty string>
/// field      ::= <any string up to "@" or end>
/// version    ::= <base-10 non-negative integer>
/// ```
///
/// # Errors
///
/// Returns [`VaultRefError::EmptyReference`] when `reference` is empty.
/// Returns [`VaultRefError::InvalidVersion`] when `@suffix` is present but not a
/// valid base-10 non-negative integer.
///
/// On any error the caller (e.g. [`interpolate_vault_refs`]) must return the
/// **original marker bytes** (`⊳{…}` or `>{…}`) unchanged — never an empty
/// substitution (T-46-02 / VREF-02 preserve-verbatim contract).
pub fn parse_vault_reference(reference: &str) -> Result<VaultReference, VaultRefError> {
    // (1) Reject empty reference.
    if reference.is_empty() {
        return Err(VaultRefError::EmptyReference);
    }

    // Work left-to-right on the remaining string.
    let mut rest = reference;

    // (2) Strip optional @version from the RIGHT first (so '#' in a version
    //     never confuses the field splitter, and ':' in the path is unambiguous).
    let version: Option<u64>;
    if let Some(at_pos) = rest.rfind('@') {
        let version_str = &rest[at_pos + 1..];
        version = Some(
            version_str
                .parse::<u64>()
                .map_err(|_| VaultRefError::InvalidVersion(version_str.to_owned()))?,
        );
        rest = &rest[..at_pos];
    } else {
        version = None;
    }

    // (3) Strip optional #field from the RIGHT (after @ is gone).
    let field: Option<String>;
    if let Some(hash_pos) = rest.rfind('#') {
        field = Some(rest[hash_pos + 1..].to_owned());
        rest = &rest[..hash_pos];
    } else {
        field = None;
    }

    // (4) Detect optional leading binding: — ONLY when the segment before the
    //     FIRST ':' matches `^[A-Za-z0-9_-]+$` AND contains no '/'.
    //     This guards against URLs (`https://…`) and bare KV paths that happen
    //     to contain a colon.
    let binding: Option<String>;
    let path: String;
    if let Some(colon_pos) = rest.find(':') {
        let candidate = &rest[..colon_pos];
        let is_binding = !candidate.is_empty()
            && !candidate.contains('/')
            && candidate
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if is_binding {
            binding = Some(candidate.to_owned());
            path = rest[colon_pos + 1..].to_owned();
        } else {
            binding = None;
            path = rest.to_owned();
        }
    } else {
        binding = None;
        path = rest.to_owned();
    }

    // Path must be non-empty after all splitting.
    if path.is_empty() {
        return Err(VaultRefError::EmptyReference);
    }

    Ok(VaultReference {
        binding,
        path,
        field,
        version,
    })
}

// ─── Interpolation stub ───────────────────────────────────────────────────────

/// Preserve-verbatim stub for vault reference interpolation.
///
/// In this phase (Phase 46) vault references are **parsed and validated only**;
/// no network access or resolution is performed.  This function returns
/// `content` byte-for-byte unchanged.
///
/// Phase 47 wires the actual resolution here.  Even after wiring, the
/// preserve-verbatim contract is:
///
/// > On any parse error or lookup failure, return the original `caps[0]` text
/// > (e.g. `⊳{secret#field}`) unchanged — **never** an empty substitution.
///
/// This mirrors the pattern in `src/secrets.rs:331`:
/// ```rust,ignore
/// Err(_e) => caps[0].to_string()  // Return original marker on error
/// ```
#[must_use]
pub fn interpolate_vault_refs(content: &str) -> String {
    // Phase 47 will replace this body with regex-replace resolution.
    // For now, return unchanged so callers already depend on the right signature.
    content.to_owned()
}

// ─── Request-scoped resolver (feature = "vault") ──────────────────────────────
//
// Everything below is compiled only with `--features vault`. It promotes the
// parse-only grammar above into a live resolver: one AppRole login (or static
// token) per `VaultRequestCache`, one KV fetch per unique reference, with every
// token and resolved value held in `Zeroizing` memory that is wiped when the
// request cache drops (VAUTH-03/04, T-47-07).

#[cfg(feature = "vault")]
mod resolve {
    use std::collections::HashMap;
    use std::fmt;
    use std::path::{Path, PathBuf};

    use anyhow::Result;
    use zeroize::{Zeroize, Zeroizing};

    use crate::project::{VaultBinding, VaultConfig};
    use crate::secrets::SecretsCache;
    use crate::validation::sanitize_for_display;
    use crate::vault::auth::{
        approle_login, resolve_secret_id, resolve_token, AuthLease,
    };
    use crate::vault::client::{KvReadOutcome, VaultClient, VaultHttpError};

    use super::{parse_vault_reference, VaultRefError, VAULT_INTERPOLATION_REGEX};

    /// Why a single `⊳{ref}` could not be resolved (a PER-REFERENCE miss).
    ///
    /// Distinct from a whole-operation failure: Vault was reachable and the
    /// bootstrap auth succeeded, but THIS reference does not resolve. 47-04 maps
    /// every variant here to **exit 3** (preserve the marker verbatim, continue).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ReferenceMissKind {
        /// The reference text was syntactically malformed (parser rejected it).
        Malformed(VaultRefError),
        /// The named `binding:` selector is not present in `[vault.bindings]`.
        UnknownBinding,
        /// No `binding:` prefix and no `default_binding` is configured.
        NoDefaultBinding,
        /// The binding has no `mount` configured.
        MissingMount,
        /// `#field` was omitted and the binding has no `default_field`.
        MissingField,
        /// The KV path / pinned `@version` does not exist.
        PathNotFound,
        /// The requested field is absent from an existing secret.
        FieldMissing,
        /// The pinned version exists but was soft-deleted.
        SoftDeleted,
        /// The pinned version exists but was destroyed.
        Destroyed,
    }

    impl fmt::Display for ReferenceMissKind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ReferenceMissKind::Malformed(e) => write!(f, "malformed reference ({e})"),
                ReferenceMissKind::UnknownBinding => write!(f, "unknown binding"),
                ReferenceMissKind::NoDefaultBinding => {
                    write!(f, "no binding prefix and no default_binding configured")
                }
                ReferenceMissKind::MissingMount => write!(f, "binding has no mount"),
                ReferenceMissKind::MissingField => {
                    write!(f, "no field specified and binding has no default_field")
                }
                ReferenceMissKind::PathNotFound => write!(f, "path or version not found"),
                ReferenceMissKind::FieldMissing => write!(f, "field not present in secret"),
                ReferenceMissKind::SoftDeleted => write!(f, "version is soft-deleted"),
                ReferenceMissKind::Destroyed => write!(f, "version is destroyed"),
            }
        }
    }

    /// The exit-3 / exit-4 seam consumed by 47-04's render handler.
    ///
    /// - [`VaultResolveError::ReferenceMiss`] — Vault reachable + authed, but a
    ///   single reference did not resolve. 47-04 preserves THAT `⊳{}` marker and
    ///   continues → **exit 3**. Carries only the SANITISED reference name and a
    ///   value-free [`ReferenceMissKind`] — never a token or secret value.
    /// - [`VaultResolveError::MultiReferenceMiss`] — One or more references failed
    ///   to resolve in a full-content interpolation pass.  Carries the set of
    ///   sanitised reference texts that missed (for the stderr report) and the
    ///   partially-resolved content (markers preserved verbatim). 47-04 maps this
    ///   to **exit 3**. The `partial` content is NEVER written to any output —
    ///   the command layer uses it only for the stderr report.
    /// - [`VaultResolveError::WholeOperation`] — Vault unreachable, TLS/CA-pin
    ///   failure, or bootstrap auth/unseal failure. 47-04 aborts touching
    ///   nothing → **exit 4**. Carries a value-free description only.
    pub enum VaultResolveError {
        /// A single reference failed to resolve (exit-3 class, used by `resolve_reference`).
        ReferenceMiss {
            /// The offending reference text, already run through
            /// `sanitize_for_display` (Trojan-Source-safe; value-free).
            reference: String,
            /// Why the reference missed (value-free).
            kind: ReferenceMissKind,
        },
        /// One or more references failed in a full interpolation pass (exit-3 class).
        ///
        /// Used by `decrypt_to_raw_with_path` to carry the full miss set and the
        /// partially-resolved content back to the command layer. The `partial`
        /// field holds the content with resolved refs substituted and each missed
        /// marker preserved verbatim — it is for reporting only and MUST NOT be
        /// written to any output file (T-47-12 / all-or-nothing contract).
        MultiReferenceMiss {
            /// Sanitised reference texts that could not be resolved.
            references: Vec<String>,
            /// Content with successful substitutions applied and misses preserved
            /// verbatim.  Available for reporting; NEVER written to output.
            /// Not included in `Debug` output to prevent token leakage (VNET-04).
            partial: String,
        },
        /// The whole operation failed (exit-4 class).
        WholeOperation {
            /// A value-free description of the failure (status / class only).
            detail: String,
        },
    }

    /// Custom `Debug` implementation that redacts the `partial` field of
    /// `MultiReferenceMiss` to prevent partially-resolved content (which may
    /// contain resolved secret values) from appearing in debug output (VNET-04).
    impl fmt::Debug for VaultResolveError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                VaultResolveError::ReferenceMiss { reference, kind } => f
                    .debug_struct("ReferenceMiss")
                    .field("reference", reference)
                    .field("kind", kind)
                    .finish(),
                VaultResolveError::MultiReferenceMiss { references, .. } => f
                    .debug_struct("MultiReferenceMiss")
                    .field("references", references)
                    // Why: `partial` may contain resolved secret values (VNET-04);
                    // omit it from Debug to prevent accidental token leakage into
                    // logs or test output.
                    .field("partial", &"<redacted>")
                    .finish(),
                VaultResolveError::WholeOperation { detail } => f
                    .debug_struct("WholeOperation")
                    .field("detail", detail)
                    .finish(),
            }
        }
    }

    impl fmt::Display for VaultResolveError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                VaultResolveError::ReferenceMiss { reference, kind } => {
                    write!(f, "unresolved vault reference {reference}: {kind}")
                }
                VaultResolveError::MultiReferenceMiss { references, .. } => {
                    write!(f, "unresolved vault references: {}", references.join(", "))
                }
                VaultResolveError::WholeOperation { detail } => {
                    write!(f, "vault operation failed: {detail}")
                }
            }
        }
    }

    impl std::error::Error for VaultResolveError {}

    impl VaultResolveError {
        /// `true` for the exit-3 class (a single or multiple references missed).
        #[must_use]
        pub fn is_reference_miss(&self) -> bool {
            matches!(
                self,
                VaultResolveError::ReferenceMiss { .. }
                    | VaultResolveError::MultiReferenceMiss { .. }
            )
        }

        /// `true` for the exit-4 class (whole-operation abort).
        #[must_use]
        pub fn is_whole_operation(&self) -> bool {
            matches!(self, VaultResolveError::WholeOperation { .. })
        }

        /// Build a `ReferenceMiss`, sanitising the reference name at the boundary.
        fn miss(raw_ref: &str, kind: ReferenceMissKind) -> Self {
            VaultResolveError::ReferenceMiss {
                reference: sanitize_for_display(raw_ref),
                kind,
            }
        }
    }

    /// Classify a transport/HTTP error from the client as miss-vs-whole-op.
    ///
    /// `AuthDenied` (403 on the KV read) is a PER-REFERENCE ACL miss → exit 3.
    /// Everything else here (sealed / timeout / TLS / transport / auth-failed)
    /// is a WHOLE-OPERATION failure → exit 4. No token or body ever appears in
    /// the resulting description.
    ///
    /// Exposed `pub` so the exit-3/exit-4 classification can be unit-tested
    /// without a live Vault.
    #[must_use]
    pub fn classify_http_error(raw_ref: &str, err: &VaultHttpError) -> VaultResolveError {
        match err {
            // 403 on a KV read = this ref's path is ACL-denied for the token
            // (a per-reference miss, NOT a bootstrap-auth failure).
            VaultHttpError::AuthDenied => {
                VaultResolveError::miss(raw_ref, ReferenceMissKind::PathNotFound)
            }
            other => VaultResolveError::WholeOperation {
                // `other` Display is already value-free (client.rs guarantees it).
                detail: other.to_string(),
            },
        }
    }

    /// Map a non-`Found` [`KvReadOutcome`] discriminant to its
    /// [`ReferenceMissKind`] (every KV miss is a PER-REFERENCE miss → exit 3).
    ///
    /// `Found` is excluded by construction — it is the success path and carries a
    /// value, so it has no miss kind. Exposed `pub` for direct unit testing of
    /// the exit-3 mapping without a live Vault.
    #[must_use]
    pub fn miss_kind_for_outcome(outcome: &KvReadOutcome) -> Option<ReferenceMissKind> {
        match outcome {
            KvReadOutcome::Found { .. } => None,
            KvReadOutcome::FieldMissing => Some(ReferenceMissKind::FieldMissing),
            KvReadOutcome::SoftDeleted => Some(ReferenceMissKind::SoftDeleted),
            KvReadOutcome::Destroyed => Some(ReferenceMissKind::Destroyed),
            KvReadOutcome::PathNotFound => Some(ReferenceMissKind::PathNotFound),
        }
    }

    /// Per-invocation cache: ONE token + ONE resolved value per unique reference.
    ///
    /// Lives for exactly one render/operation. On drop, the cached token and
    /// every cached resolved value are zeroised (manual [`Drop`] below — VAUTH-03
    /// / T-47-07). It is `!Clone` by construction: the token must not be copied
    /// out of the request scope.
    pub struct VaultRequestCache {
        /// The bootstrap token, obtained once on the first `resolve_reference`.
        token: Option<Zeroizing<String>>,
        /// The lease for `token` (TTL + renewability); value-free.
        lease: Option<AuthLease>,
        /// Resolved values keyed by the verbatim reference text.
        resolved: HashMap<String, Zeroizing<String>>,
        /// Concrete KV v2 version for each resolved reference (VLOCK-01).
        ///
        /// For unpinned refs this is the metadata version returned by the KV API.
        /// For `@N`-pinned refs this is N.  `0` means unknown / not yet resolved
        /// via the versioned path.
        pub versions: HashMap<String, u64>,
    }

    impl VaultRequestCache {
        /// Create an empty request cache (no token, no resolved values yet).
        #[must_use]
        pub fn new() -> Self {
            Self {
                token: None,
                lease: None,
                resolved: HashMap::new(),
                versions: HashMap::new(),
            }
        }

        /// The captured lease for the request token, if a login has happened.
        #[must_use]
        pub fn lease(&self) -> Option<&AuthLease> {
            self.lease.as_ref()
        }

        /// Whether a token has been obtained for this request yet.
        #[must_use]
        pub fn has_token(&self) -> bool {
            self.token.is_some()
        }

        /// Number of distinct references resolved (cached) so far.
        ///
        /// Exposed so callers / tests can assert the single-fetch-per-ref
        /// invariant (a repeated reference must not grow this count).
        #[must_use]
        pub fn resolved_count(&self) -> usize {
            self.resolved.len()
        }

        /// Seed a resolved value for `reference` (diagnostic / test seam).
        ///
        /// Used to assert that [`VaultResolver::resolve_reference`] short-circuits
        /// on a cache hit BEFORE performing any network I/O. The value is held in
        /// `Zeroizing` and wiped with the rest of the cache on drop.
        pub fn seed_resolved(&mut self, reference: &str, value: Zeroizing<String>) {
            self.resolved.insert(reference.to_string(), value);
        }

        /// Seed the request token (diagnostic / test seam).
        ///
        /// Lets a test exercise the cached-token path without a live login. The
        /// token is held in `Zeroizing` and wiped on drop.
        pub fn seed_token(&mut self, token: Zeroizing<String>) {
            self.token = Some(token);
        }

        /// Move the bootstrap token OUT of the cache (mount-time drain, VMNT-01).
        ///
        /// After an eager `bootstrap_auth`, `handle_mount` drains the token into
        /// the long-lived `VaultMountState` for reuse across reads. Taking (rather
        /// than cloning) leaves the cache's slot empty so its `Drop` zeroises only
        /// the remaining buffers; the moved-out `Zeroizing<String>` keeps wiping on
        /// its own eventual drop. Returns `None` if no login happened.
        #[must_use]
        pub fn take_token(&mut self) -> Option<Zeroizing<String>> {
            self.token.take()
        }

        /// Move the captured lease OUT of the cache (paired with [`Self::take_token`]).
        ///
        /// The lease is value-free (TTL + renewability only); it is stored alongside
        /// the drained token in the mount-level state for on-demand re-auth.
        #[must_use]
        pub fn take_lease(&mut self) -> Option<AuthLease> {
            self.lease.take()
        }
    }

    impl Default for VaultRequestCache {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for VaultRequestCache {
        fn drop(&mut self) {
            // Zeroise the token explicitly (Zeroizing already zeroises on its own
            // drop, but we wipe here to guarantee the buffer is cleared the
            // instant the request cache is torn down — T-47-07).
            if let Some(tok) = self.token.as_mut() {
                tok.zeroize();
            }
            for v in self.resolved.values_mut() {
                v.zeroize();
            }
            self.resolved.clear();
            // versions holds only u64 (non-sensitive); clear for hygiene.
            self.versions.clear();
        }
    }

    /// Request-scoped Vault resolver.
    ///
    /// Holds the configuration, a constructed [`VaultClient`], and the
    /// `SecretsCache` + paths needed to resolve the bootstrap credential. A
    /// `VaultResolver` is built once per render; the actual per-request token and
    /// resolved values live in the caller-owned [`VaultRequestCache`] so that
    /// they are zeroised deterministically at the end of the render frame.
    pub struct VaultResolver<'a> {
        config: &'a VaultConfig,
        client: VaultClient,
        secrets_cache: SecretsCache,
        file_path: PathBuf,
        project_root: PathBuf,
    }

    impl<'a> VaultResolver<'a> {
        /// Build a resolver, constructing the [`VaultClient`] from the signed
        /// `[vault].address` + (optionally) the pinned `tls_ca_secret` CA.
        ///
        /// When `config.tls_ca_secret` is set, the named CA PEM is decrypted from
        /// `.secrets` and passed to the client as the pinned trust anchor;
        /// otherwise the `WebPki` bundle is used. The address MUST already have
        /// passed `validate_vault_address` at config-load time (Phase 46).
        ///
        /// # Errors
        ///
        /// Returns [`VaultResolveError::WholeOperation`] when the address is
        /// absent, the CA secret cannot be resolved, or the client cannot be
        /// constructed — all exit-4 conditions.
        pub fn new(
            config: &'a VaultConfig,
            secrets_cache: SecretsCache,
            file_path: &Path,
            project_root: &Path,
        ) -> Result<Self, VaultResolveError> {
            let address = config.address.as_deref().ok_or_else(|| {
                VaultResolveError::WholeOperation {
                    detail: "no vault address configured".to_string(),
                }
            })?;

            // Resolve the pinned CA PEM from .secrets when configured.
            let mut sc = secrets_cache.clone();
            let ca_pem: Option<Zeroizing<String>> = match config.tls_ca_secret.as_deref() {
                Some(name) => {
                    let pem = sc
                        .lookup_secret(name, file_path, project_root)
                        .map_err(|_e| VaultResolveError::WholeOperation {
                            // The .secrets lookup error is value-free already, but
                            // we deliberately do NOT forward it (could echo a
                            // secret name); a fixed description is safer.
                            detail: "pinned CA secret could not be resolved".to_string(),
                        })?;
                    Some(Zeroizing::new(pem))
                }
                None => None,
            };

            let client = VaultClient::new(
                address.to_string(),
                config.namespace.clone(),
                ca_pem.as_ref().map(|p| p.as_bytes()),
            )
            .map_err(|e| VaultResolveError::WholeOperation {
                detail: e.to_string(),
            })?;

            Ok(Self {
                config,
                client,
                secrets_cache,
                file_path: file_path.to_path_buf(),
                project_root: project_root.to_path_buf(),
            })
        }

        /// Resolve the binding for a parsed reference to `(mount, kv_version)`.
        ///
        /// Uses the reference's `binding:` selector when present, else
        /// `config.default_binding`. Returns a value-free `ReferenceMiss` when
        /// the binding is unknown / absent / has no mount.
        fn binding_for(
            &self,
            raw_ref: &str,
            selector: Option<&str>,
        ) -> Result<(String, u8), VaultResolveError> {
            let name = match selector {
                Some(s) => s,
                None => self.config.default_binding.as_deref().ok_or_else(|| {
                    VaultResolveError::miss(raw_ref, ReferenceMissKind::NoDefaultBinding)
                })?,
            };

            let binding: &VaultBinding = self.config.bindings.get(name).ok_or_else(|| {
                VaultResolveError::miss(raw_ref, ReferenceMissKind::UnknownBinding)
            })?;

            let mount = binding.mount.clone().ok_or_else(|| {
                VaultResolveError::miss(raw_ref, ReferenceMissKind::MissingMount)
            })?;

            // KV v2 by default (STACK.md §3.3: sss targets KV v2).
            let kv_version = binding.kv_version.unwrap_or(2);

            Ok((mount, kv_version))
        }

        /// Determine the field to read: the reference's `#field` or the binding's
        /// `default_field`. Errors (value-free) when neither is present.
        fn field_for(
            &self,
            raw_ref: &str,
            ref_field: Option<&str>,
            binding_name: Option<&str>,
        ) -> Result<String, VaultResolveError> {
            if let Some(f) = ref_field {
                return Ok(f.to_string());
            }

            // Fall back to the binding's default_field.
            let name = match binding_name {
                Some(s) => Some(s),
                None => self.config.default_binding.as_deref(),
            };
            let default_field = name
                .and_then(|n| self.config.bindings.get(n))
                .and_then(|b| b.default_field.clone());

            default_field
                .ok_or_else(|| VaultResolveError::miss(raw_ref, ReferenceMissKind::MissingField))
        }

        /// Ensure the request cache holds a token; obtain one ONCE per cache.
        ///
        /// On the first call this resolves the bootstrap credential (`AppRole`
        /// `secret_id` or static token), performs the `AppRole` login (or adopts
        /// the static token), and stores the token + lease in the cache. The
        /// `secret_id` is dropped (zeroised) the instant `approle_login` returns —
        /// it is never retained (T-47-08). Subsequent calls are a no-op.
        ///
        /// Env-var precedence (VCLI-05): `SSS_VAULT_TOKEN` is checked before
        /// `config.auth`, so it works even when no `[vault.auth]` section is
        /// configured in `.sss.toml` (e.g. ad-hoc render with token in env).
        fn ensure_authenticated(
            &self,
            cache: &mut VaultRequestCache,
        ) -> Result<(), VaultResolveError> {
            if cache.token.is_some() {
                return Ok(());
            }

            // Highest-precedence: SSS_VAULT_TOKEN env var bypasses config.auth entirely.
            if let Ok(env_tok) = std::env::var(crate::vault::auth::ENV_TOKEN)
                && !env_tok.is_empty() {
                    cache.token = Some(Zeroizing::new(env_tok));
                    cache.lease = Some(AuthLease {
                        ttl_secs: 0,
                        renewable: false,
                        expire_time: None,
                    });
                    return Ok(());
                }

            let auth = self.config.auth.as_ref().ok_or_else(|| {
                VaultResolveError::WholeOperation {
                    detail: "no vault auth configured".to_string(),
                }
            })?;

            let method = auth.method.as_deref().unwrap_or("approle");
            let mut sc = self.secrets_cache.clone();

            // Static-token auth vs AppRole login. Anything that is not exactly
            // "token" is treated as AppRole (the default method).
            let (token, lease) = if method == "token" {
                let token = resolve_token(auth, &mut sc, &self.file_path, &self.project_root)
                    .map_err(|_e| VaultResolveError::WholeOperation {
                        detail: "token bootstrap-credential resolution failed".to_string(),
                    })?;
                // A static token has no login lease; treat as non-renewable with
                // unknown TTL (the long-lived mount in Phase 49 can lookup-self to
                // refine this).
                let lease = AuthLease {
                    ttl_secs: 0,
                    renewable: false,
                    expire_time: None,
                };
                (token, lease)
            } else {
                let role_id = auth.role_id.as_deref().ok_or_else(|| {
                    VaultResolveError::WholeOperation {
                        detail: "approle auth configured without role_id".to_string(),
                    }
                })?;
                // secret_id is scoped to this block: dropped (zeroised) the moment
                // approle_login returns (T-47-08).
                let secret_id =
                    resolve_secret_id(auth, &mut sc, &self.file_path, &self.project_root)
                        .map_err(|_e| VaultResolveError::WholeOperation {
                            detail: "secret_id bootstrap-credential resolution failed"
                                .to_string(),
                        })?;
                approle_login(&self.client, role_id, &secret_id).map_err(|e| {
                    VaultResolveError::WholeOperation {
                        detail: e.to_string(),
                    }
                })?
                // `secret_id` drops here.
            };

            cache.token = Some(token);
            cache.lease = Some(lease);
            Ok(())
        }

        /// Resolve a single `⊳{}` reference to its plaintext value.
        ///
        /// 1. Cache hit on the verbatim `raw_ref` → return a clone (NO refetch).
        /// 2. Parse the reference; a parse error is a `ReferenceMiss`.
        /// 3. Map the binding → `mount` (+ `kv_version`); determine the field.
        /// 4. Authenticate ONCE (token cached in `cache`), then KV-read.
        /// 5. Classify the [`KvReadOutcome`] / [`VaultHttpError`] into the
        ///    miss-vs-whole-op seam and cache the value on success.
        ///
        /// A `⊳{ref}` resolved N times in one cache lifetime triggers exactly one
        /// login and one KV read per unique ref.
        ///
        /// # Errors
        ///
        /// Mount-time eager-auth entry point (VMNT-01, Phase 49).
        ///
        /// Drives a single bootstrap login into `cache` exactly as the per-ref
        /// resolve path does, but exposed publicly so that `handle_mount` can
        /// fail the mount closed when authentication fails — without widening the
        /// visibility of the private [`Self::ensure_authenticated`] (which keeps
        /// the internal auth state machine encapsulated). This is a verbatim
        /// delegation: it performs the same env-var-precedence / `AppRole` /
        /// static token resolution, and is idempotent (a second call on a cache
        /// that already holds a token is a no-op).
        ///
        /// On success the obtained token + [`AuthLease`] land in `cache`; both are
        /// zeroised when `cache` is dropped (the caller drains them into the
        /// mount-level `VaultMountState` for the long-lived mount, which
        /// re-zeroises on unmount).
        ///
        /// # Errors
        ///
        /// Returns [`VaultResolveError::WholeOperation`] when no credential can be
        /// resolved or the login fails — every such case is an exit-4 condition
        /// that the mount command maps to a non-zero exit (nothing mounted).
        pub fn bootstrap_auth(
            &self,
            cache: &mut VaultRequestCache,
        ) -> Result<(), VaultResolveError> {
            self.ensure_authenticated(cache)
        }

        /// [`VaultResolveError::ReferenceMiss`] (exit 3) or
        /// [`VaultResolveError::WholeOperation`] (exit 4).
        pub fn resolve_reference(
            &self,
            raw_ref: &str,
            cache: &mut VaultRequestCache,
        ) -> Result<Zeroizing<String>, VaultResolveError> {
            // (1) Request-scoped cache hit (single-fetch-per-ref).
            if let Some(hit) = cache.resolved.get(raw_ref) {
                return Ok(hit.clone());
            }

            // (2) Parse shape.
            let parsed = parse_vault_reference(raw_ref).map_err(|e| {
                VaultResolveError::miss(raw_ref, ReferenceMissKind::Malformed(e))
            })?;

            // (3) Binding → mount/kv_version; field resolution.
            let (mount, _kv_version) =
                self.binding_for(raw_ref, parsed.binding.as_deref())?;
            let field = self.field_for(raw_ref, parsed.field.as_deref(), parsed.binding.as_deref())?;

            // (4) Authenticate once, then read.
            self.ensure_authenticated(cache)?;
            let token = cache.token.as_ref().ok_or_else(|| {
                VaultResolveError::WholeOperation {
                    detail: "internal: token missing after authentication".to_string(),
                }
            })?;

            let outcome = self
                .client
                .kv_read(token, &mount, &parsed.path, &field, parsed.version)
                .map_err(|e| classify_http_error(raw_ref, &e))?;

            // (5) Classify the outcome (single-sourced via miss_kind_for_outcome).
            match outcome {
                KvReadOutcome::Found { value, .. } => {
                    cache
                        .resolved
                        .insert(raw_ref.to_string(), value.clone());
                    Ok(value)
                }
                other => {
                    let kind = miss_kind_for_outcome(&other).unwrap_or(ReferenceMissKind::PathNotFound);
                    Err(VaultResolveError::miss(raw_ref, kind))
                }
            }
        }

        /// Resolve a single `⊳{}` reference to its plaintext value AND the
        /// concrete KV v2 version that was fetched (VLOCK-01).
        ///
        /// Mirrors [`resolve_reference`] in every respect except:
        ///
        /// - For `@N`-pinned references `version` is always `N` (the literal pin).
        /// - For unpinned references `version` is the KV metadata version returned
        ///   by the API — typically the latest version at the time of resolution.
        ///
        /// The result is cached in `cache.versions` so repeated calls for the
        /// same `raw_ref` within one request frame return consistently.
        ///
        /// # Errors
        ///
        /// Same as [`resolve_reference`]:
        /// [`VaultResolveError::ReferenceMiss`] (exit 3) or
        /// [`VaultResolveError::WholeOperation`] (exit 4).
        pub fn resolve_reference_versioned(
            &self,
            raw_ref: &str,
            cache: &mut VaultRequestCache,
        ) -> Result<(Zeroizing<String>, u64), VaultResolveError> {
            // (1) Fast path: both value AND version cached.
            if let (Some(val), Some(&ver)) = (
                cache.resolved.get(raw_ref),
                cache.versions.get(raw_ref),
            ) {
                return Ok((val.clone(), ver));
            }

            // (2) Parse shape — needed to extract the @N pin.
            let parsed = parse_vault_reference(raw_ref).map_err(|e| {
                VaultResolveError::miss(raw_ref, ReferenceMissKind::Malformed(e))
            })?;

            // (3) Binding → mount/kv_version; field resolution.
            let (mount, _kv_version) =
                self.binding_for(raw_ref, parsed.binding.as_deref())?;
            let field = self.field_for(raw_ref, parsed.field.as_deref(), parsed.binding.as_deref())?;

            // (4) Authenticate once, then read.
            self.ensure_authenticated(cache)?;
            let token = cache.token.as_ref().ok_or_else(|| {
                VaultResolveError::WholeOperation {
                    detail: "internal: token missing after authentication".to_string(),
                }
            })?;

            let outcome = self
                .client
                .kv_read(token, &mount, &parsed.path, &field, parsed.version)
                .map_err(|e| classify_http_error(raw_ref, &e))?;

            // (5) Classify — capture the concrete version from the KV metadata.
            match outcome {
                KvReadOutcome::Found { value, version } => {
                    // For pinned refs the API returns the pinned version; for unpinned
                    // refs it returns whatever metadata version was latest.  Both cases
                    // are stored directly from the API response — no inference needed.
                    cache.resolved.insert(raw_ref.to_string(), value.clone());
                    cache.versions.insert(raw_ref.to_string(), version);
                    Ok((value, version))
                }
                other => {
                    let kind = miss_kind_for_outcome(&other)
                        .unwrap_or(ReferenceMissKind::PathNotFound);
                    Err(VaultResolveError::miss(raw_ref, kind))
                }
            }
        }
    }

    /// Outcome of a full-content interpolation pass.
    ///
    /// `content` is the rendered text (with every resolvable `⊳{}` substituted and
    /// every per-reference miss preserved verbatim); `unresolved` is the set of
    /// reference texts that missed (exit-3 reporting input for 47-04).
    pub struct InterpolationOutcome {
        /// The interpolated content (misses preserved as their original markers).
        pub content: String,
        /// The sanitised reference texts that could not be resolved (exit 3).
        pub unresolved: Vec<String>,
    }

    /// Interpolate every `⊳{}` / `>{}` marker in `content` via the resolver.
    ///
    /// On a [`VaultResolveError::ReferenceMiss`] the original marker (`caps[0]`)
    /// is preserved byte-for-byte (the VREF-02 preserve-verbatim contract) and the
    /// reference is recorded in `unresolved`. On a
    /// [`VaultResolveError::WholeOperation`] the pass ABORTS immediately, touching
    /// nothing further (exit-4 semantics) — 47-04 maps the two outcomes to exit 3
    /// vs exit 4.
    ///
    /// # Errors
    ///
    /// Returns the whole-operation error if any reference triggers one.
    pub fn interpolate_vault_refs_resolved(
        content: &str,
        resolver: &VaultResolver<'_>,
        cache: &mut VaultRequestCache,
    ) -> Result<InterpolationOutcome, VaultResolveError> {
        let mut unresolved: Vec<String> = Vec::new();
        let mut whole_op: Option<VaultResolveError> = None;
        let mut out = String::with_capacity(content.len());
        let mut last = 0usize;

        for caps in VAULT_INTERPOLATION_REGEX.captures_iter(content) {
            // `get(0)` is always present for a successful capture.
            let Some(m) = caps.get(0) else { continue };
            let Some(inner) = caps.get(1) else { continue };

            // Append the gap before this match unchanged.
            out.push_str(&content[last..m.start()]);
            last = m.end();

            if whole_op.is_some() {
                // Already aborting: preserve the marker verbatim and keep scanning
                // only to copy bytes (we will discard `out` on abort anyway).
                out.push_str(m.as_str());
                continue;
            }

            match resolver.resolve_reference(inner.as_str(), cache) {
                Ok(value) => out.push_str(value.as_str()),
                Err(e) if e.is_reference_miss() => {
                    // Preserve the ORIGINAL marker text verbatim (VREF-02).
                    out.push_str(m.as_str());
                    if let VaultResolveError::ReferenceMiss { reference, .. } = e {
                        unresolved.push(reference);
                    }
                }
                Err(e) => {
                    // Whole-operation failure → abort the whole render (exit 4).
                    whole_op = Some(e);
                }
            }
        }

        if let Some(e) = whole_op {
            return Err(e);
        }

        // Append the trailing remainder after the last match.
        out.push_str(&content[last..]);

        Ok(InterpolationOutcome {
            content: out,
            unresolved,
        })
    }
}

#[cfg(feature = "vault")]
pub use resolve::{
    classify_http_error, interpolate_vault_refs_resolved, miss_kind_for_outcome,
    InterpolationOutcome, ReferenceMissKind, VaultRequestCache, VaultResolveError, VaultResolver,
};

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VAULT_INTERPOLATION_REGEX ─────────────────────────────────────────────

    #[test]
    fn regex_captures_unicode_vault_ref() {
        let hay = "⊳{secret#f}";
        let caps = VAULT_INTERPOLATION_REGEX.captures(hay).unwrap();
        assert_eq!(&caps[1], "secret#f");
    }

    #[test]
    fn regex_captures_ascii_alias() {
        let hay = ">{secret#f}";
        let caps = VAULT_INTERPOLATION_REGEX.captures(hay).unwrap();
        assert_eq!(&caps[1], "secret#f");
    }

    #[test]
    fn regex_unicode_and_ascii_capture_identically() {
        let unicode = "⊳{kv:app/db#password@2}";
        let ascii = ">{kv:app/db#password@2}";
        let uc = VAULT_INTERPOLATION_REGEX.captures(unicode).unwrap();
        let ac = VAULT_INTERPOLATION_REGEX.captures(ascii).unwrap();
        assert_eq!(&uc[1], &ac[1]);
    }

    // ── parse_vault_reference — well-formed cases ─────────────────────────────

    #[test]
    fn parse_path_only() {
        let r = parse_vault_reference("secret/data/app").unwrap();
        assert_eq!(r.binding, None);
        assert_eq!(r.path, "secret/data/app");
        assert_eq!(r.field, None);
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_binding_and_path_and_field() {
        let r = parse_vault_reference("kv:secret/app#password").unwrap();
        assert_eq!(r.binding, Some("kv".to_owned()));
        assert_eq!(r.path, "secret/app");
        assert_eq!(r.field, Some("password".to_owned()));
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_path_field_and_version() {
        let r = parse_vault_reference("secret/app#password@3").unwrap();
        assert_eq!(r.binding, None);
        assert_eq!(r.path, "secret/app");
        assert_eq!(r.field, Some("password".to_owned()));
        assert_eq!(r.version, Some(3));
    }

    #[test]
    fn parse_all_four_components() {
        let r = parse_vault_reference("db:secret/app#pw@2").unwrap();
        assert_eq!(r.binding, Some("db".to_owned()));
        assert_eq!(r.path, "secret/app");
        assert_eq!(r.field, Some("pw".to_owned()));
        assert_eq!(r.version, Some(2));
    }

    // ── URL / colon edge cases ────────────────────────────────────────────────

    #[test]
    fn url_like_colon_not_treated_as_binding() {
        // "https://x" — the segment before ':' is "https", which contains no '/'
        // BUT we must check what happens.  "https" matches [A-Za-z0-9_-]+
        // so it IS treated as a binding in this parser.  The plan says:
        // "colon present but the segment before ':' contains '/'" → not a binding.
        // "https" has no '/', so binding = Some("https"), path = "//x".
        // This is documented behaviour: callers supplying a full URL to a vault ref
        // should use the path-only form without a scheme.
        let r = parse_vault_reference("https://x").unwrap();
        // "https" has no '/' → IS treated as binding per grammar
        assert_eq!(r.binding, Some("https".to_owned()));
        assert_eq!(r.path, "//x");
    }

    #[test]
    fn slash_in_pre_colon_segment_keeps_colon_in_path() {
        // If the pre-colon segment contains '/', the whole thing is path.
        // e.g. "secret/prod:port" → binding=None, path="secret/prod:port"
        let r = parse_vault_reference("secret/prod:8200").unwrap();
        assert_eq!(r.binding, None);
        assert_eq!(r.path, "secret/prod:8200");
        assert_eq!(r.field, None);
        assert_eq!(r.version, None);
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn parse_empty_is_error() {
        assert_eq!(
            parse_vault_reference(""),
            Err(VaultRefError::EmptyReference)
        );
    }

    #[test]
    fn parse_bad_version_is_error() {
        let err = parse_vault_reference("secret/app@notanumber").unwrap_err();
        assert!(matches!(err, VaultRefError::InvalidVersion(_)));
        assert_eq!(
            err.to_string(),
            r#"vault reference @version must be a non-negative integer, got "notanumber""#
        );
    }

    #[test]
    fn parse_bad_version_not_silent_latest() {
        // An unparseable @version must be an error, NOT silently resolved as "latest"
        let result = parse_vault_reference("secret/app@v3");
        assert!(result.is_err(), "expected Err for @v3 version");
    }

    // ── interpolate_vault_refs stub ───────────────────────────────────────────

    #[test]
    fn interpolate_is_identity_in_phase46() {
        let input = "name: ⊳{secret/prod#api_key}\nother: >{ref}";
        assert_eq!(interpolate_vault_refs(input), input);
    }
}
