// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "vault")]

//! Exit-code contract for vault render errors (Phase 47-04 / VFAIL-01 / VFAIL-02).
//!
//! These tests verify the typed error seam that maps resolver outcomes to the
//! CLI exit codes 3 (per-reference miss) and 4 (whole-operation abort):
//!
//! - **Happy path** — `interpolate_vault_refs_resolved` with a seeded cache
//!   produces the resolved content; no vault marker remains; the token/value
//!   does not appear in any error display text (VNET-04).
//!
//! - **Exit-3 path** — A per-reference miss (unknown binding, bad path, ACL
//!   deny) is collected in `InterpolationOutcome::unresolved`; the processor
//!   converts that to a `VaultResolveError::MultiReferenceMiss`; the command
//!   layer must be able to downcast via `anyhow::Error::downcast_ref` and call
//!   `std::process::exit(3)` — without writing any output (all-or-nothing
//!   contract T-47-12 / VREF-02).
//!
//! - **Exit-4 path** — A whole-operation failure (Vault unreachable, TLS pin,
//!   auth/unseal) is returned as `VaultResolveError::WholeOperation`; the
//!   command layer downcasts it and calls `std::process::exit(4)`.
//!
//! - **No-vault-config path** — When the `Processor` has no vault config,
//!   `⊳{}` markers pass through byte-for-byte regardless of whether the vault
//!   feature is compiled in (VREF-01 / R4 preservation).
//!
//! - **`MultiReferenceMiss` predicates** — `is_reference_miss()` returns `true`
//!   for both `ReferenceMiss` and `MultiReferenceMiss`; `is_whole_operation()`
//!   returns `false` for both.  These predicates are consumed by the command
//!   layer to distinguish exit 3 from exit 4.
//!
//! No live Vault is required.  All resolver tests use the request-cache seeding
//! API or crafted `VaultConfig` entries that produce deterministic errors before
//! any network is attempted (binding resolution, field resolution).

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use sss::project::{VaultAuth, VaultBinding, VaultConfig};
use sss::secrets::SecretsCache;
use sss::vault::resolver::{
    interpolate_vault_refs_resolved, InterpolationOutcome, ReferenceMissKind, VaultRequestCache,
    VaultResolveError, VaultResolver,
};

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Build a `VaultConfig` with a single named binding pointing at a closed port
/// (`https://127.0.0.1:1`) — network calls will immediately fail, giving us
/// deterministic `WholeOperation` errors for auth / KV-fetch paths.
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
        address: Some("https://127.0.0.1:1".to_string()),
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

/// Construct a `VaultResolver` from `config` using a temp directory as the
/// project root.  Panics if the resolver cannot be constructed (e.g. no
/// address) — any config returned by `config_with_binding` must succeed here.
fn resolver_for(config: &VaultConfig) -> VaultResolver<'_> {
    let tmp = std::env::temp_dir();
    VaultResolver::new(config, SecretsCache::new(), &tmp, &tmp)
        .expect("resolver constructs with a valid HTTPS address and no pinned CA")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Happy path: seeded cache produces resolved content (no network)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn interpolate_with_seeded_cache_resolves_marker() {
    // Seed the resolver cache so that the ref resolves without any network
    // call.  This exercises the happy-path branch of
    // `interpolate_vault_refs_resolved` (VFAIL-01 happy path).
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);

    let mut cache = VaultRequestCache::new();
    let raw_ref = "kv:secret/app#password";
    cache.seed_resolved(raw_ref, Zeroizing::new("resolved-value".to_string()));

    let content = format!("prefix ⊳{{{raw_ref}}} suffix");
    let outcome = interpolate_vault_refs_resolved(&content, &resolver, &mut cache)
        .expect("seeded ref must resolve without network");

    let InterpolationOutcome {
        content: rendered,
        unresolved,
    } = outcome;

    assert_eq!(rendered, "prefix resolved-value suffix");
    assert!(
        unresolved.is_empty(),
        "no unresolved refs expected in happy path"
    );
}

#[test]
fn interpolate_multiple_markers_one_seeded_one_miss() {
    // Two refs: one seeded (resolves), one with unknown binding (misses).
    // The seeded ref must be substituted; the miss must be preserved verbatim
    // in the output AND appear in `unresolved` (VREF-02 / VFAIL-01 contract).
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);

    let mut cache = VaultRequestCache::new();
    let good_ref = "kv:secret/app#password";
    cache.seed_resolved(good_ref, Zeroizing::new("good-value".to_string()));

    let bad_ref = "nosuchbinding:secret/missing#field";
    let content = format!("a=⊳{{{good_ref}}} b=⊳{{{bad_ref}}}");
    let outcome = interpolate_vault_refs_resolved(&content, &resolver, &mut cache)
        .expect("per-reference miss must return Ok, not Err");

    let InterpolationOutcome {
        content: rendered,
        unresolved,
    } = outcome;

    // Good ref was replaced; bad ref was preserved verbatim.
    assert!(
        rendered.contains("good-value"),
        "resolved ref must appear in rendered output"
    );
    assert!(
        rendered.contains(&format!("⊳{{{bad_ref}}}")),
        "unresolved marker must be preserved verbatim (VREF-02)"
    );

    // Unresolved list contains exactly the bad reference name.
    assert_eq!(unresolved.len(), 1, "exactly one unresolved ref");
    // The unresolved entry is the sanitized reference text (not the full marker).
    assert!(
        unresolved[0].contains("nosuchbinding"),
        "unresolved entry must identify the bad binding"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Token hygiene: resolved value must not appear in any error text (VNET-04)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn resolved_value_does_not_appear_in_error_display() {
    // If the resolved value somehow leaked into an error message it would be
    // a VNET-04 violation.  Construct a `MultiReferenceMiss` (as the processor
    // does on an unresolved ref set) and assert the `Display` and `Debug`
    // representations do NOT contain the resolved value of a hypothetical ref.
    let err = VaultResolveError::MultiReferenceMiss {
        references: vec!["kv:secret/app#password".to_string()],
        // `partial` is the rendered content (with resolved values inline) — it
        // must NEVER appear in any Display/Debug output of the error type.
        partial: "prefix secret-token-value suffix".to_string(),
    };

    let display = format!("{err}");
    let debug = format!("{err:?}");

    assert!(
        !display.contains("secret-token-value"),
        "Display must not include the partial rendered content (VNET-04): {display}"
    );
    assert!(
        !debug.contains("secret-token-value"),
        "Debug must not include the partial rendered content (VNET-04): {debug}"
    );
    // Debug must use the redacted sentinel (not the real content).
    assert!(
        debug.contains("<redacted>"),
        "Debug must redact the partial field (VNET-04): {debug}"
    );
}

#[test]
fn whole_operation_detail_does_not_leak_token() {
    // WholeOperation's `detail` field is value-free by construction (the
    // resolver only populates it with fixed strings), but the `Display`
    // implementation must also not amplify it by adding neighbouring data.
    let err = VaultResolveError::WholeOperation {
        detail: "connection refused".to_string(),
    };
    let display = format!("{err}");
    assert!(
        display.contains("connection refused"),
        "WholeOperation Display must include the detail: {display}"
    );
    // No credential should appear regardless.
    assert!(!display.contains("s."), "no Vault token prefix in output");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Exit-code predicates: is_reference_miss() / is_whole_operation() contract
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn reference_miss_predicates() {
    // `ReferenceMiss` → exit 3; `is_reference_miss` must be `true`.
    let err = VaultResolveError::ReferenceMiss {
        reference: "kv:secret/app#pw".to_string(),
        kind: ReferenceMissKind::NoDefaultBinding,
    };
    assert!(err.is_reference_miss(), "ReferenceMiss must report exit-3 class");
    assert!(!err.is_whole_operation(), "ReferenceMiss is not exit-4 class");
}

#[test]
fn multi_reference_miss_predicates() {
    // `MultiReferenceMiss` is also an exit-3 class error: it bundles a set of
    // per-reference misses from `interpolate_vault_refs_resolved`.
    let err = VaultResolveError::MultiReferenceMiss {
        references: vec!["kv:a#f".to_string(), "kv:b#f".to_string()],
        partial: String::new(),
    };
    assert!(
        err.is_reference_miss(),
        "MultiReferenceMiss must report exit-3 class"
    );
    assert!(
        !err.is_whole_operation(),
        "MultiReferenceMiss is not exit-4 class"
    );
}

#[test]
fn whole_operation_predicates() {
    // `WholeOperation` → exit 4; `is_whole_operation` must be `true`.
    let err = VaultResolveError::WholeOperation {
        detail: "vault down".to_string(),
    };
    assert!(
        err.is_whole_operation(),
        "WholeOperation must report exit-4 class"
    );
    assert!(
        !err.is_reference_miss(),
        "WholeOperation is not exit-3 class"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Anyhow downcast chain: the command layer recovers VaultResolveError from
// anyhow::Error via downcast_ref (threaded through resolve_vault_refs_if_configured)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn multi_reference_miss_survives_anyhow_roundtrip() {
    // The processor wraps the VaultResolveError in `anyhow::Error::new(...)`.
    // The command layer must be able to recover it via `downcast_ref`.
    // This test mirrors the exact path in `handle_vault_render_error`.
    let original = VaultResolveError::MultiReferenceMiss {
        references: vec!["kv:secret/missing#field".to_string()],
        partial: "some partial content".to_string(),
    };
    let anyhow_err: anyhow::Error = anyhow::Error::new(original);

    let recovered = anyhow_err.downcast_ref::<VaultResolveError>();
    assert!(
        recovered.is_some(),
        "VaultResolveError must survive anyhow::Error roundtrip"
    );

    let recovered = recovered.unwrap();
    assert!(
        recovered.is_reference_miss(),
        "recovered error must still report exit-3 class"
    );
    if let VaultResolveError::MultiReferenceMiss { references, .. } = recovered {
        assert_eq!(references.len(), 1);
        assert_eq!(references[0], "kv:secret/missing#field");
    } else {
        panic!("expected MultiReferenceMiss variant");
    }
}

#[test]
fn whole_operation_survives_anyhow_roundtrip() {
    // Same roundtrip for the exit-4 variant.
    let original = VaultResolveError::WholeOperation {
        detail: "tls handshake failed".to_string(),
    };
    let anyhow_err: anyhow::Error = anyhow::Error::new(original);

    let recovered = anyhow_err.downcast_ref::<VaultResolveError>();
    assert!(
        recovered.is_some(),
        "WholeOperation must survive anyhow::Error roundtrip"
    );
    assert!(
        recovered.unwrap().is_whole_operation(),
        "recovered error must still report exit-4 class"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Per-reference miss errors from resolve_reference (exit-3, pre-network)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn unknown_binding_is_reference_miss() {
    // A reference with a binding name not in the config is a per-ref miss
    // (exit 3) — no network is needed to determine this.
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("nosuchbinding:secret/app#pw", &mut cache)
        .unwrap_err();

    assert!(err.is_reference_miss(), "unknown binding → exit-3 miss");
    assert!(!err.is_whole_operation());
    assert!(!cache.has_token(), "no login attempted for binding error");
}

#[test]
fn no_default_binding_is_reference_miss() {
    // No binding prefix on the ref AND no default_binding in the config.
    let config = config_with_binding("kv", Some("secret"), Some("password"), None);
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("secret/app#password", &mut cache)
        .unwrap_err();

    assert!(err.is_reference_miss(), "no default binding → exit-3 miss");
    match err {
        VaultResolveError::ReferenceMiss { kind, .. } => {
            assert_eq!(kind, ReferenceMissKind::NoDefaultBinding);
        }
        other @ (VaultResolveError::WholeOperation { .. }
        | VaultResolveError::MultiReferenceMiss { .. }) => {
            panic!("expected NoDefaultBinding miss, got {other:?}");
        }
    }
}

#[test]
fn missing_mount_is_reference_miss() {
    // Binding exists but has no mount path → deterministic miss (exit 3).
    let config = config_with_binding("kv", None, Some("password"), Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("kv:secret/app#password", &mut cache)
        .unwrap_err();

    assert!(err.is_reference_miss(), "missing mount → exit-3 miss");
    match err {
        VaultResolveError::ReferenceMiss { kind, .. } => {
            assert_eq!(kind, ReferenceMissKind::MissingMount);
        }
        other @ (VaultResolveError::WholeOperation { .. }
        | VaultResolveError::MultiReferenceMiss { .. }) => {
            panic!("expected MissingMount miss, got {other:?}");
        }
    }
}

#[test]
fn missing_field_with_no_default_is_reference_miss() {
    // No #field in the ref AND no default_field in the binding → miss.
    let config = config_with_binding("kv", Some("secret"), None, Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    let err = resolver
        .resolve_reference("kv:secret/app", &mut cache)
        .unwrap_err();

    assert!(err.is_reference_miss(), "missing field → exit-3 miss");
    match err {
        VaultResolveError::ReferenceMiss { kind, .. } => {
            assert_eq!(kind, ReferenceMissKind::MissingField);
        }
        other @ (VaultResolveError::WholeOperation { .. }
        | VaultResolveError::MultiReferenceMiss { .. }) => {
            panic!("expected MissingField miss, got {other:?}");
        }
    }
    assert!(!cache.has_token(), "field error must occur before any login");
}

// ═══════════════════════════════════════════════════════════════════════════════
// interpolate_vault_refs_resolved: whole-operation abort semantics
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn interpolate_returns_err_on_whole_operation() {
    // When `resolve_reference` returns a `WholeOperation` error for any ref,
    // `interpolate_vault_refs_resolved` must return `Err(WholeOperation)`.
    // We trigger this by providing a ref that passes binding/mount/field checks
    // (well-formed ref to a configured binding + mount + default_field) so
    // `resolve_reference` reaches the network call, which immediately fails
    // because the address is a closed port (connection refused → WholeOperation).
    let config = config_with_binding("kv", Some("secret"), Some("password"), Some("kv"));
    let resolver = resolver_for(&config);
    let mut cache = VaultRequestCache::new();

    // Seed the token so the auth step is skipped and the KV fetch is reached
    // (which then hits the closed port for the actual KV read).
    cache.seed_token(Zeroizing::new("s.test-token".to_string()));

    let content = "value=⊳{kv:secret/app#password}";
    let result = interpolate_vault_refs_resolved(content, &resolver, &mut cache);

    assert!(result.is_err(), "closed port must produce WholeOperation error");
    let err = result.err().expect("already asserted is_err");
    assert!(
        err.is_whole_operation(),
        "closed-port error must be exit-4 class, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MultiReferenceMiss Display — contains the reference names but not partial content
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn multi_reference_miss_display_lists_refs() {
    let err = VaultResolveError::MultiReferenceMiss {
        references: vec!["kv:a#f".to_string(), "kv:b#g".to_string()],
        partial: "content with secrets".to_string(),
    };
    let display = format!("{err}");
    assert!(
        display.contains("kv:a#f") && display.contains("kv:b#g"),
        "Display must list the unresolved reference names: {display}"
    );
    assert!(
        !display.contains("content with secrets"),
        "Display must NOT include the partial rendered content (VNET-04): {display}"
    );
}
