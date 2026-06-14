//! Vault integration — offline grammar, config types, and (Phase 47+) resolution.
//!
//! This module is **not** feature-gated: `⊳{}` marker constants, the interpolation
//! regex, and `parse_vault_reference` must compile in every build configuration so
//! that peers without `--features vault` can still recognise and preserve vault
//! reference markers byte-for-byte through `seal` and `open` (R4 / VREF-01).
//!
//! # Sub-modules
//!
//! - [`resolver`] — `VAULT_INTERPOLATION_REGEX`, `VaultReference`, `VaultRefError`,
//!   `parse_vault_reference`, and `interpolate_vault_refs`. Parse/validate only;
//!   no network access in this phase.
//! - [`client`] — (feature = "vault") blocking HTTPS transport, KV v2 read,
//!   TLS root selection, response size cap, and typed `VaultHttpError` /
//!   `KvReadOutcome`.  Requires the `vault` Cargo feature.
//! - [`auth`] — (feature = "vault") AppRole login, static-token resolution, and
//!   `lookup-self` / `renew-self`. Turns a sealed/env bootstrap credential into
//!   a short-lived `Zeroizing` token. Requires the `vault` Cargo feature.

pub mod lockfile;
pub mod resolver;

/// Blocking Vault HTTP client: KV v2 read, TLS root selection, typed error/outcome.
/// Only compiled when the `vault` Cargo feature is active.
#[cfg(feature = "vault")]
pub mod client;

/// Vault authentication: AppRole login, static token, lookup-self / renew-self.
/// Only compiled when the `vault` Cargo feature is active.
#[cfg(feature = "vault")]
pub mod auth;

pub use resolver::{
    interpolate_vault_refs, parse_vault_reference, VaultRefError, VaultReference,
    VAULT_INTERPOLATION_REGEX,
};

/// Request-scoped resolver symbols (feature = "vault"): the live `⊳{}` resolver,
/// its per-render cache, and the exit-3/exit-4 error seam consumed by 47-04.
#[cfg(feature = "vault")]
pub use resolver::{
    classify_http_error, interpolate_vault_refs_resolved, miss_kind_for_outcome,
    InterpolationOutcome, ReferenceMissKind, VaultRequestCache, VaultResolveError, VaultResolver,
};

#[cfg(feature = "vault")]
pub use client::{KvReadOutcome, VaultClient, VaultHttpError};

#[cfg(feature = "vault")]
pub use auth::{
    approle_login, resolve_secret_id, resolve_token, token_lookup_self, token_renew_self,
    AuthLease,
};
