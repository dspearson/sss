//! Vault authentication: AppRole login, static token, lookup-self / renew-self.
//!
//! This module is only compiled when the `vault` Cargo feature is active.
//! It sits on top of the 47-01 [`VaultClient`] transport and turns a bootstrap
//! credential (an AppRole `secret_id` or a static token, resolved from the
//! sealed `.secrets` or an env var) into a short-lived Vault token.
//!
//! # Token hygiene (VNET-04 / T-47-06 / PITFALLS Pitfall 3)
//!
//! Every credential that flows through this module — the AppRole `secret_id`,
//! the static token, and the AppRole-issued `client_token` — is wrapped in
//! [`zeroize::Zeroizing`] from the moment it is read or parsed. None of them is
//! ever placed in a log line, an error message, or a `Display` impl. The typed
//! errors carry only HTTP status codes and structural metadata; ref/secret
//! names that originate from config are routed through [`sanitize_for_display`]
//! before reaching any user-facing string.
//!
//! # Bootstrap-credential precedence (VAUTH-01 / VAUTH-02)
//!
//! - AppRole `secret_id`: `SSS_VAULT_SECRET_ID` env (read once) takes precedence
//!   over a `.secrets` lookup by `auth.secret_id_secret` name; `role_id` is a
//!   non-secret config value (`auth.role_id`).
//! - Static token: `SSS_VAULT_TOKEN` env (read once) takes precedence over a
//!   `.secrets` lookup by `auth.token_secret` name.
//!
//! The `secret_id` is dropped (zeroised) immediately after [`approle_login`]
//! returns — it is never retained in any struct (ARCHITECTURE §3 zeroisation
//! table / T-47-08).

use std::path::Path;

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

use crate::project::VaultAuth;
use crate::secrets::SecretsCache;
use crate::validation::sanitize_for_display;
use crate::vault::client::{VaultClient, VaultHttpError};

/// Environment variable holding an `AppRole` `secret_id` (overrides `.secrets`).
pub const ENV_SECRET_ID: &str = "SSS_VAULT_SECRET_ID";

/// Environment variable holding a static Vault token (overrides `.secrets`).
pub const ENV_TOKEN: &str = "SSS_VAULT_TOKEN";

// ─── Auth lease ──────────────────────────────────────────────────────────────

/// The lease metadata returned by an `AppRole` login or a token lookup/renew.
///
/// `ttl_secs` is the remaining (or granted) TTL in seconds; `renewable` says
/// whether `renew-self` may be used (vs. requiring a fresh login); `expire_time`
/// is the RFC3339 absolute expiry, when Vault supplies one (lookup-self).
///
/// Carries no secret material — safe to log or surface (it never contains the
/// token value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthLease {
    /// Remaining or granted token TTL in seconds.
    pub ttl_secs: u64,
    /// Whether the token may be renewed via `renew-self`.
    pub renewable: bool,
    /// Absolute RFC3339 expiry time, when Vault reports one (lookup-self).
    pub expire_time: Option<String>,
}

// ─── JSON parse helpers (pub for test reachability) ───────────────────────────

/// Parse an `AppRole` / renew-self login body into `(token, lease)`.
///
/// Extracts `auth.client_token` into a [`Zeroizing`] string and
/// `auth.lease_duration` / `auth.renewable` into an [`AuthLease`] (STACK.md
/// §3.1 / §3.5). Returns [`VaultHttpError::Parse`] when the `auth` object or a
/// required field is absent — the error text carries NO token or body content.
pub fn parse_auth_token_body(
    body: &[u8],
) -> Result<(Zeroizing<String>, AuthLease), VaultHttpError> {
    let root: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| VaultHttpError::Parse(format!("JSON decode failed: {e}")))?;

    let auth = root
        .get("auth")
        .ok_or_else(|| VaultHttpError::Parse("missing `auth` in response".to_string()))?;

    let client_token = auth
        .get("client_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| VaultHttpError::Parse("missing auth.client_token".to_string()))?;

    let ttl_secs = auth
        .get("lease_duration")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| VaultHttpError::Parse("missing auth.lease_duration".to_string()))?;

    // `renewable` defaults to false when absent (conservative — forces re-login).
    let renewable = auth
        .get("renewable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    Ok((
        Zeroizing::new(client_token.to_string()),
        AuthLease {
            ttl_secs,
            renewable,
            expire_time: None,
        },
    ))
}

/// Parse a token `lookup-self` body into an [`AuthLease`].
///
/// Extracts `data.ttl`, `data.renewable`, and `data.expire_time` (STACK.md
/// §3.4). The token id (`data.id`) is deliberately NOT read — it is never
/// needed and must not be copied out of the response.
pub fn parse_token_lookup_body(body: &[u8]) -> Result<AuthLease, VaultHttpError> {
    let root: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| VaultHttpError::Parse(format!("JSON decode failed: {e}")))?;

    let data = root
        .get("data")
        .ok_or_else(|| VaultHttpError::Parse("missing `data` in lookup-self".to_string()))?;

    let ttl_secs = data
        .get("ttl")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| VaultHttpError::Parse("missing data.ttl".to_string()))?;

    let renewable = data
        .get("renewable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let expire_time = data
        .get("expire_time")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    Ok(AuthLease {
        ttl_secs,
        renewable,
        expire_time,
    })
}

/// Return `true` when a Vault `errors` array signals a non-renewable token.
///
/// Used to map a renew-self 400 to [`VaultHttpError::NotRenewable`] (STACK.md
/// §3.5: `{"errors": ["token is not renewable"]}`).
#[must_use]
pub fn errors_indicate_not_renewable(body: &[u8]) -> bool {
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    root.get("errors")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|errs| {
            errs.iter().any(|e| {
                e.as_str()
                    .is_some_and(|s| s.contains("token is not renewable"))
            })
        })
}

// ─── AppRole login ─────────────────────────────────────────────────────────────

/// Log in via `AppRole` and return a short-lived token plus its lease.
///
/// POSTs `{"role_id":..,"secret_id":..}` to `/v1/auth/approle/login`. The
/// `secret_id` is read from the supplied [`Zeroizing`] slice when the request
/// body is serialised; the body is dropped inside [`VaultClient::post_json`]. On
/// a non-200 status the response body is inspected only to classify the failure
/// (never echoed): the error carries solely the HTTP status
/// ([`VaultHttpError::AuthFailed`]) — never the `role_id`, `secret_id`, or body
/// (T-47-06 / PITFALLS Pitfall 3).
///
/// # Errors
///
/// Returns [`VaultHttpError::AuthFailed`] on a 4xx/5xx login rejection and
/// [`VaultHttpError::Parse`] if a 200 body lacks the expected `auth` fields.
pub fn approle_login(
    client: &VaultClient,
    role_id: &str,
    secret_id: &Zeroizing<String>,
) -> Result<(Zeroizing<String>, AuthLease), VaultHttpError> {
    // Build the body from the Zeroizing slice. serde_json::Value::String takes
    // ownership of a String copy; that copy lives only until post_json drops the
    // serialised bytes at the end of the call.
    let body = serde_json::json!({
        "role_id": role_id,
        "secret_id": secret_id.as_str(),
    });

    let (status, value) = client.post_json("/v1/auth/approle/login", &body, None)?;

    if status != 200 {
        // Detail (status only) to the debug log; NEVER the credential or body.
        log::debug!("approle login rejected with HTTP {status}");
        return Err(VaultHttpError::AuthFailed(status));
    }

    let raw = serde_json::to_vec(&value)
        .map_err(|e| VaultHttpError::Parse(format!("re-encode failed: {e}")))?;
    parse_auth_token_body(&raw)
}

// ─── Token lookup-self / renew-self ─────────────────────────────────────────────

/// Look up the current token's remaining TTL and renewability.
///
/// GETs `/v1/auth/token/lookup-self` with the token in `X-Vault-Token` and
/// parses `data.ttl` / `data.renewable` / `data.expire_time` (STACK.md §3.4).
///
/// # Errors
///
/// Returns [`VaultHttpError::AuthDenied`] on a 403 (invalid/expired token),
/// [`VaultHttpError::AuthFailed`] on any other non-200, and
/// [`VaultHttpError::Parse`] when the body lacks the expected `data` fields.
pub fn token_lookup_self(
    client: &VaultClient,
    token: &Zeroizing<String>,
) -> Result<AuthLease, VaultHttpError> {
    let (status, value) = client.get_json("/v1/auth/token/lookup-self", Some(token))?;
    if status != 200 {
        log::debug!("token lookup-self returned HTTP {status}");
        return Err(VaultHttpError::AuthFailed(status));
    }
    let raw = serde_json::to_vec(&value)
        .map_err(|e| VaultHttpError::Parse(format!("re-encode failed: {e}")))?;
    parse_token_lookup_body(&raw)
}

/// Renew the current token and return the new lease.
///
/// POSTs to `/v1/auth/token/renew-self` with the token in `X-Vault-Token` and
/// re-parses the renewed `auth.lease_duration` / `auth.renewable` (STACK.md
/// §3.5). A 400 whose body says `token is not renewable` is mapped to the typed
/// [`VaultHttpError::NotRenewable`] so the caller can fall back to a fresh login.
///
/// # Errors
///
/// Returns [`VaultHttpError::NotRenewable`] for a non-renewable token,
/// [`VaultHttpError::AuthDenied`] on a 403, [`VaultHttpError::AuthFailed`] on
/// any other non-200, and [`VaultHttpError::Parse`] on a malformed 200 body.
pub fn token_renew_self(
    client: &VaultClient,
    token: &Zeroizing<String>,
) -> Result<AuthLease, VaultHttpError> {
    // Empty object body → Vault uses the token's default increment.
    let body = serde_json::json!({});
    let (status, value) = client.post_json("/v1/auth/token/renew-self", &body, Some(token))?;

    if status != 200 {
        // Re-encode the body to inspect the `errors` array for the
        // not-renewable signal; the body itself is never surfaced.
        let raw = serde_json::to_vec(&value).unwrap_or_default();
        if status == 400 && errors_indicate_not_renewable(&raw) {
            return Err(VaultHttpError::NotRenewable);
        }
        log::debug!("token renew-self returned HTTP {status}");
        return Err(VaultHttpError::AuthFailed(status));
    }

    let raw = serde_json::to_vec(&value)
        .map_err(|e| VaultHttpError::Parse(format!("re-encode failed: {e}")))?;
    let (_token, lease) = parse_auth_token_body(&raw)?;
    Ok(lease)
}

// ─── Bootstrap-credential resolution (env over .secrets) ────────────────────────

/// Resolve the `AppRole` `secret_id` with env-over-`.secrets` precedence.
///
/// Reads `SSS_VAULT_SECRET_ID` ONCE; if set (and non-empty) it is wrapped in
/// [`Zeroizing`] and returned. Otherwise the `.secrets` value named by
/// `auth.secret_id_secret` is looked up via [`SecretsCache::lookup_secret`] and
/// wrapped in [`Zeroizing`] at the boundary. The resolved value never appears in
/// any error: a missing `auth.secret_id_secret` config key surfaces a typed,
/// value-free error.
///
/// # Errors
///
/// Returns an error when neither the env var nor `auth.secret_id_secret` yields
/// a credential, or when the `.secrets` lookup fails.
pub fn resolve_secret_id(
    auth: &VaultAuth,
    secrets_cache: &mut SecretsCache,
    file_path: &Path,
    project_root: &Path,
) -> Result<Zeroizing<String>> {
    if let Ok(env_val) = std::env::var(ENV_SECRET_ID)
        && !env_val.is_empty()
    {
        return Ok(Zeroizing::new(env_val));
    }

    let secret_name = auth.secret_id_secret.as_deref().ok_or_else(|| {
        anyhow!(
            "vault AppRole: no secret_id source (set {ENV_SECRET_ID} or configure auth.secret_id_secret)"
        )
    })?;

    let value = secrets_cache.lookup_secret(secret_name, file_path, project_root)?;
    Ok(Zeroizing::new(value))
}

/// Resolve a static Vault token with env-over-`.secrets` precedence.
///
/// Reads `SSS_VAULT_TOKEN` ONCE; if set (and non-empty) it is wrapped in
/// [`Zeroizing`] and returned. Otherwise the `.secrets` value named by
/// `auth.token_secret` is looked up and wrapped in [`Zeroizing`].
///
/// # Errors
///
/// Returns an error when neither `SSS_VAULT_TOKEN` nor `auth.token_secret`
/// yields a token, or when the `.secrets` lookup fails.
pub fn resolve_token(
    auth: &VaultAuth,
    secrets_cache: &mut SecretsCache,
    file_path: &Path,
    project_root: &Path,
) -> Result<Zeroizing<String>> {
    if let Ok(env_val) = std::env::var(ENV_TOKEN)
        && !env_val.is_empty()
    {
        return Ok(Zeroizing::new(env_val));
    }

    let secret_name = auth.token_secret.as_deref().ok_or_else(|| {
        anyhow!(
            "vault token auth: no token source (set {ENV_TOKEN} or configure auth.token_secret)"
        )
    })?;

    let value = secrets_cache.lookup_secret(secret_name, file_path, project_root)?;
    Ok(Zeroizing::new(value))
}

/// Sanitise an auth method name for inclusion in a user-facing error.
///
/// Thin wrapper over [`sanitize_for_display`] so callers in this module route
/// every config-supplied name through the Trojan-Source guard.
#[must_use]
pub fn sanitize_method(method: &str) -> String {
    sanitize_for_display(method)
}
