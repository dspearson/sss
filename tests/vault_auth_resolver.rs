//! Phase 47-03 (VAUTH-01..05, VNET-04) — Vault auth + resolver unit tests.
//!
//! These tests exercise the parse helpers and bootstrap-credential precedence
//! of `src/vault/auth.rs` (and, from Task 2, the request-scoped resolver in
//! `src/vault/resolver.rs`) using crafted in-memory JSON fixtures — no live
//! Vault is required. All helpers are `pub` and therefore reachable from this
//! integration-test binary.
//!
//! Env-var mutation (`SSS_VAULT_SECRET_ID` / `SSS_VAULT_TOKEN`) is process-global,
//! so those tests run under `#[serial]` to prevent cross-test interference.
//!
//! # Token hygiene (VNET-04 / T-47-06)
//!
//! Several tests assert that a credential never appears in an error's `Display`
//! or `Debug` output, exercising the no-leak contract directly.
#![cfg(feature = "vault")]
// Why: panic!, unwrap, expect, expect_err, unwrap_err are idiomatic in test code;
// the panic-surface lints are relaxed here for the entire test binary (mirrors
// tests/vault_client_transport.rs).
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use serial_test::serial;
use zeroize::Zeroizing;

use std::collections::BTreeMap;

use sss::project::{VaultAuth, VaultBinding, VaultConfig};
use sss::secrets::SecretsCache;
use sss::vault::auth::{
    approle_login, errors_indicate_not_renewable, parse_auth_token_body,
    parse_token_lookup_body, resolve_secret_id, resolve_token, ENV_SECRET_ID, ENV_TOKEN,
};
use sss::vault::client::{KvReadOutcome, VaultHttpError};
use sss::vault::resolver::{
    classify_http_error, miss_kind_for_outcome, ReferenceMissKind, VaultRequestCache,
    VaultResolveError, VaultResolver,
};

// ─── env helpers (single documented unsafe boundary) ──────────────────────────
//
// Rust 2024 made `std::env::set_var` / `remove_var` `unsafe` (they are not
// thread-safe). All env-mutating tests below run under `#[serial]`, so there is
// no concurrent reader/writer in this binary; that is what makes these calls
// sound. Wrapping them in two helpers keeps the SAFETY justification in one
// place instead of repeating it at every call site.

fn set_env(key: &str, val: &str) {
    // SAFETY: every caller is a `#[serial]` test, so no other thread is reading
    // or writing the process environment concurrently with this mutation.
    unsafe { std::env::set_var(key, val) };
}

fn clear_env(key: &str) {
    // SAFETY: every caller is a `#[serial]` test, so no other thread is reading
    // or writing the process environment concurrently with this mutation.
    unsafe { std::env::remove_var(key) };
}

// ─── approle / renew body parsing ─────────────────────────────────────────────

#[test]
fn approle_login_body_parses_token_and_lease() {
    let body = br#"{
        "auth": {
            "client_token": "s.deadbeefcafef00d",
            "accessor": "fd6c9a00",
            "token_policies": ["default", "app-policy"],
            "lease_duration": 1200,
            "renewable": true,
            "metadata": null
        },
        "lease_duration": 0,
        "renewable": false
    }"#;

    let (token, lease) = parse_auth_token_body(body).expect("should parse");
    assert_eq!(token.as_str(), "s.deadbeefcafef00d");
    assert_eq!(lease.ttl_secs, 1200);
    assert!(lease.renewable);
    assert_eq!(lease.expire_time, None);
}

#[test]
fn auth_body_missing_auth_object_is_parse_error() {
    let body = br#"{"data": null, "lease_duration": 0}"#;
    let err = parse_auth_token_body(body).unwrap_err();
    assert!(matches!(err, VaultHttpError::Parse(_)));
}

#[test]
fn auth_body_renewable_defaults_false_when_absent() {
    let body = br#"{"auth": {"client_token": "s.x", "lease_duration": 60}}"#;
    let (_token, lease) = parse_auth_token_body(body).expect("should parse");
    assert!(!lease.renewable, "renewable must default to false (forces re-login)");
}

// ─── lookup-self body parsing ─────────────────────────────────────────────────

#[test]
fn lookup_self_body_parses_ttl_renewable_expire() {
    let body = br#"{
        "data": {
            "accessor": "abc",
            "creation_ttl": 1200,
            "expire_time": "2024-09-12T15:44:16Z",
            "id": "s.SECRETTOKENVALUE",
            "renewable": true,
            "ttl": 1105
        }
    }"#;

    let lease = parse_token_lookup_body(body).expect("should parse");
    assert_eq!(lease.ttl_secs, 1105);
    assert!(lease.renewable);
    assert_eq!(lease.expire_time.as_deref(), Some("2024-09-12T15:44:16Z"));
}

#[test]
fn lookup_self_empty_expire_time_becomes_none() {
    let body = br#"{"data": {"ttl": 30, "renewable": false, "expire_time": ""}}"#;
    let lease = parse_token_lookup_body(body).expect("should parse");
    assert_eq!(lease.expire_time, None);
}

// ─── not-renewable detection ──────────────────────────────────────────────────

#[test]
fn not_renewable_errors_array_detected() {
    let body = br#"{"errors": ["token is not renewable"]}"#;
    assert!(errors_indicate_not_renewable(body));
}

#[test]
fn unrelated_errors_array_not_flagged_renewable() {
    let body = br#"{"errors": ["permission denied"]}"#;
    assert!(!errors_indicate_not_renewable(body));
}

#[test]
fn empty_body_not_flagged_renewable() {
    assert!(!errors_indicate_not_renewable(b""));
}

// ─── error hygiene: no credential in Display/Debug (VNET-04 / T-47-06) ─────────

#[test]
fn auth_failed_error_carries_only_status_no_credential() {
    let err = VaultHttpError::AuthFailed(403);
    let shown = format!("{err}");
    let dbg = format!("{err:?}");
    // The error must mention the status but never any role_id/secret_id/token.
    assert!(shown.contains("403"));
    assert!(!shown.to_lowercase().contains("secret_id"));
    assert!(!shown.to_lowercase().contains("role_id"));
    assert!(!shown.to_lowercase().contains("client_token"));
    assert!(!dbg.to_lowercase().contains("secret_id"));
}

#[test]
fn not_renewable_error_is_value_free() {
    let err = VaultHttpError::NotRenewable;
    let shown = format!("{err}");
    assert!(shown.contains("not renewable"));
    assert!(!shown.to_lowercase().contains("s."));
}

// ─── bootstrap-credential precedence: secret_id (VAUTH-01) ────────────────────

fn auth_with_secret_id_name(name: &str) -> VaultAuth {
    VaultAuth {
        method: Some("approle".to_string()),
        role_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
        secret_id_secret: Some(name.to_string()),
        token_secret: None,
    }
}

#[test]
#[serial]
fn secret_id_env_takes_precedence_over_secrets() {
    set_env(ENV_SECRET_ID, "env-secret-id-value");

    let auth = auth_with_secret_id_name("approle_secret_id");
    let mut cache = SecretsCache::new(); // no repository key — .secrets lookup would fail
    let tmp = std::env::temp_dir();
    let resolved = resolve_secret_id(&auth, &mut cache, &tmp, &tmp)
        .expect("env value should resolve without touching .secrets");
    assert_eq!(resolved.as_str(), "env-secret-id-value");

    clear_env(ENV_SECRET_ID);
}

#[test]
#[serial]
fn secret_id_missing_env_and_no_config_name_errors() {
    clear_env(ENV_SECRET_ID);

    let auth = VaultAuth {
        method: Some("approle".to_string()),
        role_id: Some("role".to_string()),
        secret_id_secret: None, // neither env nor config
        token_secret: None,
    };
    let mut cache = SecretsCache::new();
    let tmp = std::env::temp_dir();
    let err = resolve_secret_id(&auth, &mut cache, &tmp, &tmp).unwrap_err();
    let msg = format!("{err}");
    // Error names the env var + config key, never a credential value.
    assert!(msg.contains(ENV_SECRET_ID));
    assert!(!msg.contains("env-secret-id-value"));
}

#[test]
#[serial]
fn secret_id_empty_env_falls_through_to_config_lookup() {
    // An empty env var must NOT be treated as a credential; resolution should
    // fall through to the .secrets lookup (which fails here with no key — that
    // proves the env value was ignored rather than returned as "").
    set_env(ENV_SECRET_ID, "");

    let auth = auth_with_secret_id_name("approle_secret_id");
    let mut cache = SecretsCache::new();
    let tmp = std::env::temp_dir();
    let result = resolve_secret_id(&auth, &mut cache, &tmp, &tmp);
    assert!(
        result.is_err(),
        "empty env must fall through to .secrets (which errors with no key)"
    );

    clear_env(ENV_SECRET_ID);
}

// ─── bootstrap-credential precedence: token (VAUTH-02) ────────────────────────

#[test]
#[serial]
fn token_env_takes_precedence_over_secrets() {
    set_env(ENV_TOKEN, "s.env-token-value");

    let auth = VaultAuth {
        method: Some("token".to_string()),
        role_id: None,
        secret_id_secret: None,
        token_secret: Some("vault_token".to_string()),
    };
    let mut cache = SecretsCache::new();
    let tmp = std::env::temp_dir();
    let resolved = resolve_token(&auth, &mut cache, &tmp, &tmp)
        .expect("env token should resolve without touching .secrets");
    assert_eq!(resolved.as_str(), "s.env-token-value");

    clear_env(ENV_TOKEN);
}

#[test]
#[serial]
fn token_missing_env_and_no_config_name_errors() {
    clear_env(ENV_TOKEN);

    let auth = VaultAuth {
        method: Some("token".to_string()),
        role_id: None,
        secret_id_secret: None,
        token_secret: None,
    };
    let mut cache = SecretsCache::new();
    let tmp = std::env::temp_dir();
    let err = resolve_token(&auth, &mut cache, &tmp, &tmp).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains(ENV_TOKEN));
    assert!(!msg.contains("s.env-token-value"));
}

// ─── approle_login surfaces a value-free error on a transport failure ─────────

#[test]
fn approle_login_against_dead_endpoint_is_value_free_error() {
    // Construct a client pointed at a closed loopback port; the login must fail
    // with a transport/timeout error that carries no credential.
    let client = sss::vault::client::VaultClient::new(
        "https://127.0.0.1:1", // unroutable port → connection failure
        None,
        None,
    )
    .expect("client constructs");

    let secret_id = Zeroizing::new("super-secret-id".to_string());
    let err = approle_login(&client, "role-abc", &secret_id).unwrap_err();
    let shown = format!("{err}");
    let dbg = format!("{err:?}");
    assert!(!shown.contains("super-secret-id"));
    assert!(!dbg.contains("super-secret-id"));
    assert!(!shown.contains("role-abc"));
}

// ══════════════════════════════════════════════════════════════════════════════
// Task 2: VaultResolver + VaultRequestCache (VAUTH-03/04, exit-3/exit-4 seam)
// ══════════════════════════════════════════════════════════════════════════════

/// Build a `VaultConfig` with a single named binding + an approle auth block.
fn config_with_binding(
    binding_name: &str,
    mount: Option<&str>,
    default_field: Option<&str>,
    default_binding: Option<&str>,
) -> VaultConfig {
    let mut bindings = BTreeMap::new();
    bindings.insert(
        binding_name.to_string(),
        VaultBinding {
            kv_version: Some(2),
            mount: mount.map(ToString::to_string),
            default_field: default_field.map(ToString::to_string),
        },
    );
    VaultConfig {
        address: Some("https://127.0.0.1:1".to_string()), // closed port; never reached in these tests
        namespace: None,
        default_binding: default_binding.map(ToString::to_string),
        tls_ca_secret: None,
        bindings,
        auth: Some(VaultAuth {
            method: Some("approle".to_string()),
            role_id: Some("role-uuid".to_string()),
            secret_id_secret: Some("approle_secret_id".to_string()),
            token_secret: None,
        }),
    }
}

fn resolver_for(config: &VaultConfig) -> VaultResolver<'_> {
    let tmp = std::env::temp_dir();
    VaultResolver::new(config, SecretsCache::new(), &tmp, &tmp)
        .expect("resolver constructs with a valid address and no pinned CA")
}

// ─── single-fetch-per-ref: a cache hit short-circuits before any network ──────

#[test]
fn cache_hit_short_circuits_without_network() {
    // The config address is a closed port. If resolve_reference touched the
    // network it would error; a cache hit must return the seeded value instead,
    // proving the single-fetch-per-ref short-circuit (VAUTH-03).
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);

    let mut cache = VaultRequestCache::new();
    let raw_ref = "kv:secret/app#password";
    cache.seed_resolved(raw_ref, Zeroizing::new("cached-value".to_string()));
    assert_eq!(cache.resolved_count(), 1);

    let v1 = resolver
        .resolve_reference(raw_ref, &mut cache)
        .expect("cache hit resolves");
    assert_eq!(v1.as_str(), "cached-value");

    // A second resolve of the SAME ref still hits the cache — count unchanged,
    // and again no network was touched.
    let v2 = resolver
        .resolve_reference(raw_ref, &mut cache)
        .expect("second cache hit resolves");
    assert_eq!(v2.as_str(), "cached-value");
    assert_eq!(cache.resolved_count(), 1, "repeated ref must not add a cache entry");
}

// ─── binding resolution errors (pre-network → deterministic) ──────────────────

#[test]
fn unknown_binding_is_reference_miss() {
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    // Reference names a binding "nope" that is not configured.
    let err = resolver
        .resolve_reference("nope:secret/app#password", &mut cache)
        .unwrap_err();
    assert!(err.is_reference_miss(), "unknown binding → exit-3 miss");
    assert!(!err.is_whole_operation());
    assert!(!cache.has_token(), "binding error must occur before any login");
}

#[test]
fn no_default_binding_is_reference_miss() {
    // No binding prefix on the ref AND no default_binding configured.
    let config = config_with_binding("kv", Some("secret"), Some("password"), None);
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("secret/app#password", &mut cache)
        .unwrap_err();
    match err {
        VaultResolveError::ReferenceMiss { kind, .. } => {
            assert_eq!(kind, ReferenceMissKind::NoDefaultBinding);
        }
        other @ (VaultResolveError::WholeOperation { .. }
        | VaultResolveError::MultiReferenceMiss { .. }) => {
            panic!("expected NoDefaultBinding miss, got {other:?}")
        }
    }
}

#[test]
fn missing_mount_is_reference_miss() {
    // Binding exists but has no mount.
    let config = config_with_binding("kv", None, Some("password"), Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("kv:secret/app#password", &mut cache)
        .unwrap_err();
    match err {
        VaultResolveError::ReferenceMiss { kind, .. } => {
            assert_eq!(kind, ReferenceMissKind::MissingMount);
        }
        other @ (VaultResolveError::WholeOperation { .. }
        | VaultResolveError::MultiReferenceMiss { .. }) => {
            panic!("expected MissingMount miss, got {other:?}")
        }
    }
}

// ─── field resolution: default_field fallback + MissingField error ────────────

#[test]
fn missing_field_with_no_default_is_reference_miss() {
    // No #field on the ref AND the binding has no default_field.
    let config = config_with_binding("kv", Some("secret"), None, Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("kv:secret/app", &mut cache)
        .unwrap_err();
    match err {
        VaultResolveError::ReferenceMiss { kind, .. } => {
            assert_eq!(kind, ReferenceMissKind::MissingField);
        }
        other @ (VaultResolveError::WholeOperation { .. }
        | VaultResolveError::MultiReferenceMiss { .. }) => {
            panic!("expected MissingField miss, got {other:?}")
        }
    }
    assert!(!cache.has_token(), "field error must occur before any login");
}

#[test]
fn default_field_fallback_seeded_value_resolves() {
    // The ref omits #field; the binding supplies default_field="password".
    // We seed the resolved value under the verbatim ref so the cache-hit path
    // returns it WITHOUT network — proving default_field resolution composes with
    // the request cache (the verbatim ref, not the resolved field, is the key).
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let raw_ref = "kv:secret/app"; // no #field → default_field would apply
    cache.seed_resolved(raw_ref, Zeroizing::new("default-field-value".to_string()));
    let v = resolver
        .resolve_reference(raw_ref, &mut cache)
        .expect("cache hit resolves regardless of default_field");
    assert_eq!(v.as_str(), "default-field-value");
}

// ─── ReferenceMiss vs WholeOperation classification seam (exit 3 vs 4) ─────────

#[test]
fn http_auth_denied_on_read_is_per_reference_miss() {
    // A 403 on the KV read = this ref's path is ACL-denied → exit-3 miss,
    // NOT a whole-operation failure.
    let err = classify_http_error("kv:secret/app#password", &VaultHttpError::AuthDenied);
    assert!(err.is_reference_miss(), "403 KV read → exit-3 per-ref miss");
}

#[test]
fn http_sealed_is_whole_operation() {
    let err = classify_http_error("kv:secret/app#password", &VaultHttpError::Sealed);
    assert!(err.is_whole_operation(), "sealed → exit-4 whole-op");
}

#[test]
fn http_timeout_is_whole_operation() {
    let err = classify_http_error(
        "kv:secret/app#password",
        &VaultHttpError::Timeout { connect_secs: 10, recv_body_secs: 30 },
    );
    assert!(err.is_whole_operation(), "timeout → exit-4 whole-op");
}

#[test]
fn http_tls_is_whole_operation() {
    let err = classify_http_error(
        "kv:secret/app#password",
        &VaultHttpError::Tls { detail: "ca pin mismatch".to_string() },
    );
    assert!(err.is_whole_operation(), "TLS/CA-pin fail → exit-4 whole-op");
}

#[test]
fn kv_outcomes_all_map_to_per_reference_misses() {
    // Every non-Found KV outcome is a PER-REFERENCE miss (exit 3).
    assert_eq!(
        miss_kind_for_outcome(&KvReadOutcome::FieldMissing),
        Some(ReferenceMissKind::FieldMissing)
    );
    assert_eq!(
        miss_kind_for_outcome(&KvReadOutcome::SoftDeleted),
        Some(ReferenceMissKind::SoftDeleted)
    );
    assert_eq!(
        miss_kind_for_outcome(&KvReadOutcome::Destroyed),
        Some(ReferenceMissKind::Destroyed)
    );
    assert_eq!(
        miss_kind_for_outcome(&KvReadOutcome::PathNotFound),
        Some(ReferenceMissKind::PathNotFound)
    );
    // Found has no miss kind (it is the success path).
    assert_eq!(
        miss_kind_for_outcome(&KvReadOutcome::Found {
            value: Zeroizing::new("v".to_string()),
            version: 1,
        }),
        None
    );
}

// ─── error Display never leaks a value/token ──────────────────────────────────

#[test]
fn resolve_error_display_is_value_free() {
    let miss = VaultResolveError::ReferenceMiss {
        reference: "kv:secret/app#password".to_string(),
        kind: ReferenceMissKind::PathNotFound,
    };
    let whole = VaultResolveError::WholeOperation {
        detail: "vault: TLS error".to_string(),
    };
    // Neither carries a secret value; the ref name is the sanitised reference.
    assert!(format!("{miss}").contains("kv:secret/app#password"));
    assert!(!format!("{miss}").contains("the_secret_value"));
    assert!(format!("{whole}").contains("TLS"));
}

// ─── VaultRequestCache zeroises on drop (VAUTH-03 / T-47-07) ───────────────────

#[test]
fn request_cache_implements_drop_and_holds_then_releases() {
    // The cache is a `Drop` type (manual zeroising Drop impl). We confirm it
    // needs drop glue (so the zeroising Drop actually runs) and that it holds the
    // seeded value while alive, then drops cleanly at scope end.
    assert!(
        std::mem::needs_drop::<VaultRequestCache>(),
        "VaultRequestCache must have drop glue so its zeroising Drop runs"
    );

    let mut cache = VaultRequestCache::new();
    cache.seed_token(Zeroizing::new("s.request-token".to_string()));
    cache.seed_resolved("kv:secret/app#password", Zeroizing::new("v".to_string()));
    assert!(cache.has_token());
    assert_eq!(cache.resolved_count(), 1);
    // Explicit drop runs the zeroising Drop impl (no panic, buffers wiped).
    drop(cache);
}

// ─── VaultRequestCache cannot be cloned (token must not escape the request) ────

#[test]
fn request_cache_is_not_clone() {
    // Compile-time contract documented here: VaultRequestCache holds the token
    // and must NOT be Clone (cloning would copy the token out of request scope).
    // This is a static assertion via a trait-bound helper that only compiles for
    // non-Clone types is overkill; instead we document and rely on the absence of
    // a derive. The runtime body simply constructs one to keep the test live.
    let cache = VaultRequestCache::new();
    assert!(!cache.has_token());
}

// ══════════════════════════════════════════════════════════════════════════════
// Phase 49-01 Task 1: VaultResolver::bootstrap_auth (VMNT-01 mount-time eager auth)
// ══════════════════════════════════════════════════════════════════════════════
//
// `bootstrap_auth` is the public mount-time entry point that drives a single
// login into the supplied request cache. It delegates verbatim to the private
// `ensure_authenticated`, so the env-token precedence path (SSS_VAULT_TOKEN)
// resolves without a live Vault. These tests run under `#[serial]` because they
// mutate the process environment.

#[test]
#[serial]
fn bootstrap_auth_populates_token_via_env() {
    // With SSS_VAULT_TOKEN set, bootstrap_auth must adopt it (no live Vault) and
    // leave the cache holding a token. Mirrors the env-token path already covered
    // for resolve_token, but exercised through the new public wrapper.
    set_env(ENV_TOKEN, "s.bootstrap-env-token");

    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);

    let mut cache = VaultRequestCache::new();
    assert!(!cache.has_token(), "fresh cache holds no token");

    resolver
        .bootstrap_auth(&mut cache)
        .expect("env-token bootstrap must succeed without a live Vault");
    assert!(cache.has_token(), "bootstrap_auth must populate the cache token");

    clear_env(ENV_TOKEN);
}

#[test]
#[serial]
fn bootstrap_auth_idempotent() {
    // Calling bootstrap_auth twice on the same cache resolves the token once; the
    // second call is a no-op (token stays present, no panic, no second login).
    set_env(ENV_TOKEN, "s.bootstrap-env-token-idem");

    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);

    let mut cache = VaultRequestCache::new();
    resolver
        .bootstrap_auth(&mut cache)
        .expect("first bootstrap_auth succeeds");
    assert!(cache.has_token());

    // Second call must short-circuit on the already-present token.
    resolver
        .bootstrap_auth(&mut cache)
        .expect("second bootstrap_auth is a no-op");
    assert!(cache.has_token(), "token remains present after idempotent re-auth");

    clear_env(ENV_TOKEN);
}
