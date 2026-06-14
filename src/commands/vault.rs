// Why: clap-required args use .unwrap() idiomatically (required(true) → always Some);
// each site has a matching INVARIANT comment. HARDEN-01 / 08-01.
#![allow(clippy::unwrap_used)]

//! Top-level `sss vault` command: `status`, `login`, `get`, `lock`, `update`,
//! `verify`, `list`.
//!
//! The module is NOT feature-gated at the `mod` level so that `sss vault --help`
//! lists the subcommands on every build.  The bodies that require the live Vault
//! feature (resolver, auth, client) are wrapped in `#[cfg(feature = "vault")]`;
//! on a non-vault build each subcommand returns an actionable error message
//! mirroring the "rebuild with `--features hybrid`" pattern in project.rs:503.
//!
//! # VCLI-01 / VCLI-02 / VCLI-05 (Phase 47-04)
//!
//! - `status` — print config + active binding + auth method + token TTL; NEVER
//!   the token, `secret_id`, or any credential value (T-47-11 / VNET-04).
//! - `login` — resolve the bootstrap credential, authenticate, print TTL +
//!   renewable flag; NEVER the token (VAUTH-05).
//! - `get <ref>` — resolve one `⊳{ref}` to stdout for explicit debugging
//!   (VCLI-02); on per-reference miss → exit 3; on whole-op abort → exit 4.
//!
//! # VLOCK-01..04 (Phase 48-02)
//!
//! - `lock` — discover every `⊳{}` ref, resolve ALL, write `.sss.vault.lock`
//!   atomically.  ALL-OR-NOTHING: any per-ref miss → exit 3 (lockfile
//!   untouched); whole-op failure → exit 4.
//! - `update` — re-resolve (optionally a single ref) and bump `.sss.vault.lock`.
//! - `verify` — re-fetch refs and compare keyed digests; exit 2 on drift,
//!   exit 4 on whole-op failure; NO secret values in output.
//! - `list` — walk the project tree and print every `⊳{}` canonical ref found;
//!   network-free, compiles without `--features vault`.
//!
//! Env-var precedence (VCLI-05): `SSS_VAULT_TOKEN` or `SSS_VAULT_SECRET_ID`
//! override `.secrets`, both read BELOW project config so the signed address
//! (VCFG-06) is never overridden.  `SSS_VAULT_JWT` is parsed and explicitly
//! reported as deferred (JWT/OIDC auth is a future milestone).

use anyhow::{anyhow, Result};
use clap::ArgMatches;

#[cfg(feature = "vault")]
use crate::validation::sanitize_for_display;

/// Entry point for the top-level `sss vault` command.
///
/// Dispatches to `status`, `login`, or `get` based on the active subcommand.
///
/// # Errors
///
/// Returns an error if no subcommand is given, if the project config is
/// missing or invalid, or if a Vault operation fails with a non-exit error.
/// Per-reference misses and whole-operation failures call `std::process::exit`
/// directly (exit 3 and exit 4 respectively) so they never return here.
pub fn handle_vault(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    // Suppress unused-variable warning on non-vault builds.
    let _ = main_matches;
    // VCFG-05 opt-in: --allow-unsigned is on the parent `vault` command so it applies
    // uniformly to all vault subcommands (status/login/get) when passed as
    // `sss vault --allow-unsigned <sub>`.
    let allow_unsigned = sub_matches.get_flag("allow-unsigned");
    match sub_matches.subcommand() {
        Some(("status", _status_matches)) => {
            vault_status(allow_unsigned)?;
        }
        Some(("login", _login_matches)) => {
            vault_login(allow_unsigned)?;
        }
        Some(("get", get_matches)) => {
            // INVARIANT: clap declares `ref` as required(true). HARDEN-01 / 08-01.
            let vault_ref = get_matches.get_one::<String>("ref").unwrap();
            vault_get(vault_ref, allow_unsigned)?;
        }
        Some(("lock", _)) => {
            vault_lock(allow_unsigned)?;
        }
        Some(("update", update_matches)) => {
            let filter_ref = update_matches.get_one::<String>("ref").map(String::as_str);
            vault_update(filter_ref, allow_unsigned)?;
        }
        Some(("verify", _)) => {
            vault_verify(allow_unsigned)?;
        }
        Some(("list", _)) => {
            vault_list(allow_unsigned)?;
        }
        _ => {
            // No subcommand — print short usage hint.
            eprintln!("Usage: sss vault <status|login|get|lock|update|verify|list>");
            eprintln!("Run `sss vault --help` for full usage.");
            return Err(anyhow!("no vault subcommand specified"));
        }
    }
    Ok(())
}

// ─── sss vault status ────────────────────────────────────────────────────────

/// Print vault configuration + auth method + token TTL.
///
/// Credentials (token, `secret_id`) are NEVER printed (T-47-11 / VNET-04).
///
/// `allow_unsigned`: VCFG-05 opt-in — when `true`, `format_version=1` repos
/// with `[vault]` are accepted (`tls_ca_secret` is still mandatory).
fn vault_status(allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = allow_unsigned;
        // Why: `needless_return` is a false positive under cfg — the
        // `#[cfg(feature = "vault")]` block below follows this statement, so the
        // explicit `return` is required (without it this block becomes a discarded
        // statement and the fn loses its tail expression). Mirrors project.rs:332.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault status` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        use crate::commands::utils::load_project_config_or_fail_opts;
        use crate::config::find_project_root;
        use crate::secrets::SecretsCache;
        use crate::vault::auth::{resolve_token, token_lookup_self, ENV_TOKEN};
        use crate::vault::client::VaultClient;

        let config = load_project_config_or_fail_opts(allow_unsigned)?;
        let vault_cfg = config.vault.as_ref().ok_or_else(|| {
            anyhow!("no vault configuration found in .sss.toml; run `sss project vault set-address` to configure")
        })?;

        // ── Address ──────────────────────────────────────────────────────────
        let address = vault_cfg.address.as_deref().unwrap_or("<not configured>");
        // Why: address is from the signed project config; sanitize_for_display
        // guards against Trojan-Source injection in any echoed config value.
        println!("address:  {}", sanitize_for_display(address));

        // ── Default binding ───────────────────────────────────────────────────
        let default_binding = vault_cfg
            .default_binding
            .as_deref()
            .unwrap_or("<none>");
        println!("default-binding: {}", sanitize_for_display(default_binding));

        // ── Named bindings ────────────────────────────────────────────────────
        if vault_cfg.bindings.is_empty() {
            println!("bindings: (none configured)");
        } else {
            println!("bindings:");
            for (name, binding) in &vault_cfg.bindings {
                let mount = binding.mount.as_deref().unwrap_or("<no mount>");
                let kv_ver = binding.kv_version.unwrap_or(2);
                // Why: binding name comes from project config; sanitize to guard
                // against Trojan-Source injection in logged output.
                println!("  {}: mount={} kv_version={kv_ver}",
                    sanitize_for_display(name),
                    sanitize_for_display(mount));
            }
        }

        // ── Auth method ───────────────────────────────────────────────────────
        let auth_method = vault_cfg
            .auth
            .as_ref()
            .and_then(|a| a.method.as_deref())
            .unwrap_or("<not configured>");
        println!("auth-method: {}", sanitize_for_display(auth_method));

        // ── SSS_VAULT_JWT notice (JWT auth deferred) ──────────────────────────
        if std::env::var("SSS_VAULT_JWT").is_ok_and(|v| !v.is_empty()) {
            println!("note: SSS_VAULT_JWT is set; JWT/OIDC auth is a future milestone — \
                      the env var is recognized but not yet acted upon");
        }

        // ── Token TTL (best-effort; no token printed) ─────────────────────────
        // Attempt to obtain a token and look up its TTL. On any failure, skip
        // the TTL line rather than returning an error — `status` is read-only.
        if let Some(ref vault_address) = vault_cfg.address {
            let project_root = find_project_root().unwrap_or_else(|_| std::env::temp_dir());
            // Pass project_root/.sss.toml as file_path so that find_secrets_file
            // starts its upward search at project_root (not project_root.parent()).
            let secrets_anchor = project_root.join(".sss.toml");
            let mut sc = SecretsCache::new();

            // Resolve CA PEM for the correct trust anchor (VCFG-05 mandatory CA pinning).
            let ca_pem_opt: Option<zeroize::Zeroizing<String>> =
                if let Some(name) = vault_cfg.tls_ca_secret.as_deref() {
                    sc.lookup_secret(name, &secrets_anchor, &project_root)
                        .ok()
                        .map(zeroize::Zeroizing::new)
                } else {
                    None
                };

            if let Ok(client) = VaultClient::new(
                vault_address.clone(),
                vault_cfg.namespace.clone(),
                ca_pem_opt.as_ref().map(|p| p.as_bytes()),
            ) {
                // Env-var precedence: SSS_VAULT_TOKEN first, then .secrets.
                let maybe_token: Option<zeroize::Zeroizing<String>> = if let Ok(t) = std::env::var(ENV_TOKEN)
                    && !t.is_empty()
                {
                    Some(zeroize::Zeroizing::new(t))
                } else if let Some(ref auth) = vault_cfg.auth {
                    resolve_token(auth, &mut sc, &secrets_anchor, &project_root).ok()
                } else {
                    None
                };

                if let Some(ref token) = maybe_token {
                    match token_lookup_self(&client, token) {
                        Ok(lease) => {
                            println!("token-ttl: {}s (renewable: {})",
                                lease.ttl_secs, lease.renewable);
                        }
                        Err(e) => {
                            println!("token-ttl: unavailable ({e})");
                        }
                    }
                } else {
                    println!("token-ttl: no token available");
                }
            }
        }

        Ok(())
    }
}

// ─── sss vault login ─────────────────────────────────────────────────────────

/// Authenticate to Vault and report TTL + renewability.
///
/// The token itself is NEVER printed (VAUTH-05 / VNET-04).
///
/// `allow_unsigned`: VCFG-05 opt-in — when `true`, `format_version=1` repos
/// with `[vault]` are accepted (`tls_ca_secret` is still mandatory).
fn vault_login(allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = allow_unsigned;
        // Why: mirrors vault_status — `needless_return` is a false positive under cfg.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault login` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        use crate::commands::utils::load_project_config_or_fail_opts;
        use crate::config::find_project_root;
        use crate::secrets::SecretsCache;
        use crate::vault::auth::{
            approle_login, resolve_secret_id, resolve_token, sanitize_method, token_lookup_self,
            ENV_TOKEN,
        };
        use crate::vault::client::VaultClient;

        let config = load_project_config_or_fail_opts(allow_unsigned)?;
        let vault_cfg = config.vault.as_ref().ok_or_else(|| {
            anyhow!("no vault configuration found in .sss.toml")
        })?;

        let vault_address = vault_cfg.address.as_deref().ok_or_else(|| {
            anyhow!("vault address not configured; run `sss project vault set-address`")
        })?;

        // SSS_VAULT_JWT notice — parsed, JWT auth deferred.
        if std::env::var("SSS_VAULT_JWT").is_ok_and(|v| !v.is_empty()) {
            eprintln!("note: SSS_VAULT_JWT is set; JWT/OIDC auth is a future milestone — \
                       falling back to configured auth method");
        }

        let project_root = find_project_root()?;
        // Pass project_root/.sss.toml as file_path so that find_secrets_file
        // starts its upward search at project_root (not project_root.parent()).
        let secrets_anchor = project_root.join(".sss.toml");
        let mut sc = SecretsCache::new();

        // Resolve pinned CA PEM before building the client so the TLS handshake
        // uses the correct trust anchor (VCFG-05 mandatory CA pinning).
        let ca_pem_opt: Option<zeroize::Zeroizing<String>> =
            if let Some(name) = vault_cfg.tls_ca_secret.as_deref() {
                sc.lookup_secret(name, &secrets_anchor, &project_root)
                    .ok()
                    .map(zeroize::Zeroizing::new)
            } else {
                None
            };

        let client = VaultClient::new(
            vault_address.to_string(),
            vault_cfg.namespace.clone(),
            ca_pem_opt.as_ref().map(|p| p.as_bytes()),
        )
        .map_err(|e| anyhow!("failed to create vault client: {e}"))?;

        // Resolve and authenticate.
        let auth = vault_cfg.auth.as_ref().ok_or_else(|| {
            anyhow!("no auth configuration in .sss.toml; run `sss project vault set-auth`")
        })?;

        let method = auth.method.as_deref().unwrap_or("token");

        let lease = match sanitize_method(method).as_str() {
            "approle" => {
                let secret_id = resolve_secret_id(auth, &mut sc, &secrets_anchor, &project_root)?;
                let role_id = auth.role_id.as_deref().ok_or_else(|| {
                    anyhow!("AppRole role_id not configured")
                })?;
                let (_token, lease) = approle_login(&client, role_id, &secret_id)
                    .map_err(|e| anyhow!("AppRole login failed: {e}"))?;
                // Token is intentionally NOT stored; we return the lease only.
                lease
            }
            "token" => {
                // SSS_VAULT_TOKEN has highest precedence.
                let token: zeroize::Zeroizing<String> = if let Ok(t) = std::env::var(ENV_TOKEN)
                    && !t.is_empty()
                {
                    zeroize::Zeroizing::new(t)
                } else {
                    resolve_token(auth, &mut sc, &secrets_anchor, &project_root)?
                };
                token_lookup_self(&client, &token)
                    .map_err(|e| anyhow!("token validation failed: {e}"))?
            }
            other => {
                return Err(anyhow!(
                    "unsupported auth method '{}'; supported: approle, token",
                    sanitize_for_display(other)
                ));
            }
        };

        // Print TTL and renewability — NEVER the token itself (VAUTH-05).
        println!("authenticated; token TTL = {}s, renewable = {}",
            lease.ttl_secs, lease.renewable);

        Ok(())
    }
}

// ─── sss vault get ───────────────────────────────────────────────────────────

/// Resolve a single `⊳{ref}` to stdout for explicit debugging.
///
/// On per-reference miss: prints the unresolved-references report to stderr and
/// calls `std::process::exit(3)`.  On whole-operation failure: prints an error
/// to stderr and calls `std::process::exit(4)`.  (VCLI-02 / VFAIL-01 / VFAIL-02)
///
/// The resolved value IS printed to stdout (this is the explicit debugging
/// contract — VCLI-02 — unlike `status`/`login` which never print values).
///
/// `allow_unsigned`: VCFG-05 opt-in — when `true`, `format_version=1` repos
/// with `[vault]` are accepted (`tls_ca_secret` is still mandatory).
fn vault_get(vault_ref: &str, allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = vault_ref;
        let _ = allow_unsigned;
        // Why: mirrors vault_status — `needless_return` is a false positive under cfg.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault get` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        use crate::commands::process::handle_vault_render_error;
        use crate::commands::utils::load_project_config_or_fail_opts;
        use crate::config::find_project_root;
        use crate::secrets::SecretsCache;
        use crate::vault::resolver::{VaultRequestCache, VaultResolveError, VaultResolver};

        let config = load_project_config_or_fail_opts(allow_unsigned)?;
        let vault_cfg = config.vault.as_ref().ok_or_else(|| {
            anyhow!("no vault configuration found in .sss.toml")
        })?;

        let project_root = find_project_root()?;
        // Pass project_root/.sss.toml as file_path so that find_secrets_file
        // starts its upward search at project_root (not project_root.parent()).
        let secrets_anchor = project_root.join(".sss.toml");
        let sc = SecretsCache::new();

        let resolver = VaultResolver::new(vault_cfg, sc, &secrets_anchor, &project_root)
            .map_err(anyhow::Error::new)?;

        let mut cache = VaultRequestCache::new();
        let safe_ref = sanitize_for_display(vault_ref);

        match resolver.resolve_reference(vault_ref, &mut cache) {
            Ok(value) => {
                // Print the resolved value to stdout (VCLI-02 — the one explicit
                // place a vault value is printed, for operator debugging).
                println!("{}", value.as_str());
            }
            Err(e) => {
                // Map to the exit-code seam: exit 3 or exit 4.
                // Wrap as anyhow::Error so handle_vault_render_error can downcast.
                let anyhow_err = if e.is_reference_miss() {
                    // Wrap as MultiReferenceMiss so the handler sees exit-3 class.
                    anyhow::Error::new(VaultResolveError::MultiReferenceMiss {
                        references: vec![safe_ref.clone()],
                        partial: String::new(),
                    })
                } else {
                    anyhow::Error::new(e)
                };
                let remaining = handle_vault_render_error(anyhow_err);
                // If handle_vault_render_error returned (the error was NOT a vault
                // error — should not happen here), propagate it.
                return Err(remaining);
            }
        }

        Ok(())
    }
}

// ─── sss vault list ──────────────────────────────────────────────────────────

/// Walk the project tree and print every `⊳{}` canonical reference found.
///
/// Network-free: uses `discover_vault_references` (in `lockfile.rs`) which
/// compiles and runs on the default build without `--features vault`.  The
/// canonical form matches the lockfile key scheme (`binding:path#field[@N]`).
///
/// Output (stdout) is one canonical reference per line, never a secret value
/// (VLOCK-02 / VNET-04 constraint applies even to list).
///
/// `allow_unsigned`: VCFG-05 opt-in — when `true`, `format_version=1` repos
/// with `[vault]` are accepted.
fn vault_list(allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = allow_unsigned;
        // Why: mirrors vault_status — `needless_return` is a false positive under cfg;
        // the `#[cfg(feature = "vault")]` block follows and the function needs a tail.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault list` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        use crate::config::find_project_root;
        use crate::vault::lockfile::discover_vault_references;
        use crate::vault::parse_vault_reference;
        use crate::vault::VAULT_INTERPOLATION_REGEX;

        let _ = allow_unsigned; // list is network-free; vault config not strictly required.

        let project_root = find_project_root()?;

        let refs = discover_vault_references(&project_root)
            .map_err(|e| anyhow!("vault list walk failed: {e}"))?;

        if refs.is_empty() {
            println!("no \u{22b3}{{}} vault references found in project");
            return Ok(());
        }

        for r in &refs {
            // Strip the ⊳{ } envelope to get the inner ref text, then format.
            let inner = VAULT_INTERPOLATION_REGEX
                .captures(&r.raw_ref)
                .and_then(|c| c.get(1))
                .map_or(r.raw_ref.as_str(), |m| m.as_str());

            let canonical = match parse_vault_reference(inner) {
                Ok(parsed) => {
                    let binding = parsed.binding.as_deref().unwrap_or("<default>");
                    let field = parsed.field.as_deref().unwrap_or("<default>");
                    if let Some(v) = parsed.version {
                        format!("{}:{}#{}@{}", binding, parsed.path, field, v)
                    } else {
                        format!("{}:{}#{}", binding, parsed.path, field)
                    }
                }
                Err(_) => r.raw_ref.clone(),
            };
            println!("{}", sanitize_for_display(&canonical));
        }

        Ok(())
    }
}

// ─── sss vault lock ──────────────────────────────────────────────────────────

/// Resolve all `⊳{}` references and write `.sss.vault.lock` atomically.
///
/// ALL-OR-NOTHING contract (VLOCK-01 / VFAIL-01):
///
/// - Every reference is resolved into memory FIRST.
/// - If any per-ref resolution fails → exit 3 (existing lockfile untouched).
/// - If a whole-operation failure occurs (Vault unreachable / auth / TLS) →
///   exit 4 (existing lockfile untouched).
/// - Only when ALL refs resolved successfully is the lockfile written.
///
/// The lockfile records only `{binding, path, field, version, digest}` — no
/// plaintext secret value is ever written (VLOCK-02 / VNET-04).
///
/// `allow_unsigned`: VCFG-05 opt-in.
fn vault_lock(allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = allow_unsigned;
        // Why: mirrors vault_status — `needless_return` is a false positive under cfg.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault lock` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        vault_lock_or_update(None, allow_unsigned)
    }
}

// ─── sss vault update ────────────────────────────────────────────────────────

/// Re-resolve `⊳{}` references and bump `.sss.vault.lock`.
///
/// When `filter_ref` is `Some(canonical_ref)`, only that one reference is
/// re-resolved; all other entries in the existing lockfile are preserved.
/// When `filter_ref` is `None`, ALL references are re-resolved (full refresh).
///
/// Same ALL-OR-NOTHING semantics as `vault_lock`: the lockfile is never
/// written unless every ref in scope resolves (exit 3 on per-ref miss, exit 4
/// on whole-op failure).
///
/// `allow_unsigned`: VCFG-05 opt-in.
fn vault_update(filter_ref: Option<&str>, allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = filter_ref;
        let _ = allow_unsigned;
        // Why: mirrors vault_status — `needless_return` is a false positive under cfg.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault update` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        vault_lock_or_update(filter_ref, allow_unsigned)
    }
}

// ─── Shared resolve-and-write core (lock + update) ──────────────────────────

/// Filter `discoveries` to the `raw_ref` strings that match `filter_ref` (or all, if `None`).
/// `filter_ref` is a canonical ref string such as `"binding:path#field"`.
/// Returns a deduplicated, sorted list of raw ref strings to resolve.
/// Extracted to keep `vault_lock_or_update` under 100 lines.
#[cfg(feature = "vault")]
fn filter_and_dedup_refs<'a>(
    discoveries: &'a [crate::vault::lockfile::VaultRefDiscovery],
    filter_ref: Option<&str>,
) -> Result<Vec<&'a str>> {
    use crate::vault::parse_vault_reference;
    use crate::vault::VAULT_INTERPOLATION_REGEX;

    let refs_to_resolve: Vec<&str> = if let Some(target_canonical) = filter_ref {
        discoveries
            .iter()
            .filter(|d| {
                let inner = VAULT_INTERPOLATION_REGEX
                    .captures(&d.raw_ref)
                    .and_then(|c| c.get(1))
                    .map_or(d.raw_ref.as_str(), |m| m.as_str());
                if let Ok(parsed) = parse_vault_reference(inner) {
                    let binding = parsed.binding.as_deref().unwrap_or("");
                    let field = parsed.field.as_deref().unwrap_or("");
                    let canonical = if let Some(v) = parsed.version {
                        format!("{}:{}#{}@{}", binding, parsed.path, field, v)
                    } else {
                        format!("{}:{}#{}", binding, parsed.path, field)
                    };
                    canonical == target_canonical
                } else {
                    d.raw_ref == target_canonical
                }
            })
            .map(|d| d.raw_ref.as_str())
            .collect()
    } else {
        discoveries.iter().map(|d| d.raw_ref.as_str()).collect()
    };

    let mut unique: Vec<&str> = refs_to_resolve;
    unique.sort_unstable();
    unique.dedup();
    Ok(unique)
}

/// Build one `VaultLockEntry` from a resolved `(raw_ref, value_bytes, kv_version)` tuple
/// and insert it into `lockfile`.  Extracted to keep `vault_lock_or_update` under 100 lines.
#[cfg(feature = "vault")]
fn build_and_insert_lock_entry(
    raw_ref: &str,
    value_bytes: &[u8],
    kv_version: u64,
    repo_key: &crate::crypto::RepositoryKey,
    vault_cfg: &crate::project::VaultConfig,
    lockfile: &mut crate::vault::lockfile::VaultLockFile,
) -> Result<()> {
    use crate::vault::lockfile::{compute_lockfile_digest, digest_to_hex, VaultLockEntry};
    use crate::vault::lockfile::VaultLockFile;
    use crate::vault::parse_vault_reference;
    use crate::vault::VAULT_INTERPOLATION_REGEX;

    let inner_ref = VAULT_INTERPOLATION_REGEX
        .captures(raw_ref)
        .and_then(|c| c.get(1))
        .map_or(raw_ref, |m| m.as_str());

    let parsed = parse_vault_reference(inner_ref)
        .map_err(|e| anyhow!("failed to parse resolved ref '{inner_ref}': {e}"))?;

    let binding_name = parsed
        .binding
        .as_deref()
        .or(vault_cfg.default_binding.as_deref())
        .unwrap_or("")
        .to_string();
    let field = parsed
        .field
        .as_deref()
        .or_else(|| {
            vault_cfg
                .bindings
                .get(&binding_name)
                .and_then(|b| b.default_field.as_deref())
        })
        .unwrap_or("")
        .to_string();

    let digest_bytes = compute_lockfile_digest(repo_key, value_bytes)
        .map_err(|e| anyhow!("digest computation failed for '{inner_ref}': {e}"))?;
    let digest_hex = digest_to_hex(&digest_bytes);

    let entry = VaultLockEntry {
        binding: binding_name,
        path: parsed.path.clone(),
        field,
        version: kv_version,
        // Pin ORIGIN comes from the SOURCE ref's explicit `@N` (`parsed.version`
        // on the raw inner ref), NEVER from `kv_version` (the resolved KV
        // version, which is the latest metadata version for unpinned refs).
        // Deriving this from the resolved version would re-pin every entry to
        // its immutable locked version and make drift undetectable (VLOCK-05).
        pinned: parsed.version.is_some(),
        digest: digest_hex,
    };
    let key = VaultLockFile::canonical_key(&entry);
    lockfile.entries.insert(key, entry);
    Ok(())
}

/// Shared implementation for `vault lock` and `vault update`.
///
/// When `filter_ref` is `None` → full resolve (all discovered refs).
/// When `filter_ref` is `Some(canonical)` → partial update (one ref only,
/// existing entries for other refs are preserved from the current lockfile).
///
/// Exit codes (via `std::process::exit`):
/// - exit 3 on per-reference miss (any ref fails to resolve).
/// - exit 4 on whole-operation failure (Vault unreachable, auth, TLS).
///
/// On success: `.sss.vault.lock` is written atomically; returns `Ok(())`.
#[cfg(feature = "vault")]
fn vault_lock_or_update(filter_ref: Option<&str>, allow_unsigned: bool) -> Result<()> {
    use crate::commands::process::handle_vault_render_error;
    use crate::config::{get_project_config_path, load_project_config_with_repository_key_opts};
    use crate::secrets::SecretsCache;
    use crate::vault::lockfile::{discover_vault_references, VaultLockFile};
    use crate::vault::resolver::{VaultRequestCache, VaultResolveError, VaultResolver};
    use crate::vault::VAULT_INTERPOLATION_REGEX;

    let config_path = get_project_config_path()?;
    let (config, repo_key, project_root) =
        load_project_config_with_repository_key_opts(&config_path, allow_unsigned)?;
    let vault_cfg = config.vault.as_ref().ok_or_else(|| {
        anyhow!("no vault configuration found in .sss.toml; run `sss project vault set-address`")
    })?;

    let secrets_anchor = project_root.join(".sss.toml");
    let sc = SecretsCache::new();

    let resolver = VaultResolver::new(vault_cfg, sc, &secrets_anchor, &project_root)
        .map_err(anyhow::Error::new)?;

    // ── 1. Discover all ⊳{} references in the project. ─────────────────────
    let discoveries = discover_vault_references(&project_root)
        .map_err(|e| anyhow!("vault lock walk failed: {e}"))?;

    // ── 2. Determine which refs to (re-)resolve (deduplicated). ────────────────
    let unique_refs = filter_and_dedup_refs(&discoveries, filter_ref)?;

    if unique_refs.is_empty() {
        if filter_ref.is_some() {
            return Err(anyhow!(
                "no \u{22b3}{{}} references matching '{}' found in project",
                filter_ref.unwrap_or("")
            ));
        }
        println!("no \u{22b3}{{}} vault references found in project; nothing to lock");
        return Ok(());
    }

    // ── 3. Resolve ALL refs into memory (ALL-OR-NOTHING gate). ──────────────
    let mut cache = VaultRequestCache::new();
    let mut resolved_entries: Vec<(&str, Vec<u8>, u64)> = Vec::new();
    let mut misses: Vec<String> = Vec::new();
    let mut whole_op_err: Option<VaultResolveError> = None;

    for raw_ref in &unique_refs {
        let inner_ref = VAULT_INTERPOLATION_REGEX
            .captures(raw_ref)
            .and_then(|c| c.get(1))
            .map_or(*raw_ref, |m| m.as_str());

        match resolver.resolve_reference_versioned(inner_ref, &mut cache) {
            Ok((value, version)) => {
                resolved_entries.push((raw_ref, value.as_bytes().to_vec(), version));
            }
            Err(e) if e.is_reference_miss() => {
                misses.push(sanitize_for_display(inner_ref));
            }
            Err(e) => {
                whole_op_err = Some(e);
                break;
            }
        }
    }

    // Route failures through Phase-47 exit-code seam (never a second error enum).
    if let Some(wo_err) = whole_op_err {
        let ae = anyhow::Error::new(wo_err);
        let remaining = handle_vault_render_error(ae);
        return Err(remaining);
    }
    if !misses.is_empty() {
        let ae = anyhow::Error::new(VaultResolveError::MultiReferenceMiss {
            references: misses,
            partial: String::new(),
        });
        let remaining = handle_vault_render_error(ae);
        return Err(remaining);
    }

    // ── 4. RepositoryKey is already loaded (from load_project_config_with_repository_key_opts).
    // No additional loading required.

    // ── 5. Build the new lockfile (or load existing for partial update). ─────
    let lockfile_path = project_root.join(".sss.vault.lock");

    let mut lockfile = if filter_ref.is_some() && lockfile_path.exists() {
        VaultLockFile::read(&lockfile_path).unwrap_or_else(|_| VaultLockFile::new())
    } else {
        VaultLockFile::new()
    };

    // ── 6. Compute keyed digests and insert entries. ─────────────────────────
    for (raw_ref, value_bytes, kv_version) in resolved_entries {
        build_and_insert_lock_entry(raw_ref, &value_bytes, kv_version, &repo_key, vault_cfg, &mut lockfile)?;
    }

    // ── 7. Write atomically — only after ALL refs resolved successfully. ─────
    lockfile
        .write_atomic(&lockfile_path)
        .map_err(|e| anyhow!("failed to write lockfile: {e}"))?;

    let entry_count = lockfile.entries.len();
    println!(
        "vault lock: wrote {entry_count} entries to {}",
        lockfile_path.display()
    );

    Ok(())
}

// ─── sss vault verify ────────────────────────────────────────────────────────

/// Re-fetch `⊳{}` references and verify keyed digests against `.sss.vault.lock`.
///
/// Exit codes:
/// - exit 0 on clean (all digests match).
/// - exit 2 on drift (one or more digests do not match the lockfile).
/// - exit 3 on per-reference miss (resolution failed for a ref).
/// - exit 4 on whole-operation failure (Vault unreachable / auth / TLS).
///
/// **NO secret values are ever printed** — output contains only ref coordinates,
/// digest hex strings (truncated for readability), and verdict flags
/// (VLOCK-02 / VLOCK-04 / VNET-04).
///
/// `allow_unsigned`: VCFG-05 opt-in.
fn vault_verify(allow_unsigned: bool) -> Result<()> {
    #[cfg(not(feature = "vault"))]
    {
        let _ = allow_unsigned;
        // Why: mirrors vault_status — `needless_return` is a false positive under cfg.
        #[allow(clippy::needless_return)]
        return Err(anyhow!(
            "`sss vault verify` requires the vault build feature; \
             rebuild sss with `--features vault`"
        ));
    }

    #[cfg(feature = "vault")]
    {
        use crate::commands::process::handle_vault_render_error;
        use crate::config::{get_project_config_path, load_project_config_with_repository_key_opts};
        use crate::secrets::SecretsCache;
        use crate::vault::lockfile::{compute_lockfile_digest, digest_to_hex, VaultLockFile};
        use crate::vault::resolver::{VaultRequestCache, VaultResolveError, VaultResolver};

        let config_path = get_project_config_path()?;
        let (config, repo_key, project_root) =
            load_project_config_with_repository_key_opts(&config_path, allow_unsigned)?;
        let vault_cfg = config.vault.as_ref().ok_or_else(|| {
            anyhow!("no vault configuration found in .sss.toml")
        })?;

        let secrets_anchor = project_root.join(".sss.toml");
        let sc = SecretsCache::new();

        let lockfile_path = project_root.join(".sss.vault.lock");
        if !lockfile_path.exists() {
            return Err(anyhow!(
                ".sss.vault.lock not found; run `sss vault lock` first"
            ));
        }

        let lockfile = VaultLockFile::read(&lockfile_path)
            .map_err(|e| anyhow!("failed to read lockfile: {e}"))?;

        if lockfile.entries.is_empty() {
            println!("vault verify: lockfile has no entries (run `sss vault lock` to populate)");
            return Ok(());
        }

        let resolver = VaultResolver::new(vault_cfg, sc, &secrets_anchor, &project_root)
            .map_err(anyhow::Error::new)?;

        // repo_key already loaded from load_project_config_with_repository_key_opts above.

        // ── Re-resolve each lockfile entry and compare keyed digests. ────────
        let mut cache = VaultRequestCache::new();
        let mut drift_count = 0usize;
        let mut misses: Vec<String> = Vec::new();
        let mut whole_op_err: Option<VaultResolveError> = None;

        for (canonical_key, entry) in &lockfile.entries {
            // Reconstruct the inner ref from the entry's recorded components.
            //
            // Branch on pin ORIGIN, NOT on `entry.version`:
            //
            // - `entry.pinned == true`  → the source ref was `⊳{…@N}`.  Re-resolve
            //   that exact immutable `@N` version.  A pin is an integrity check:
            //   a *newer* KV version existing is NOT drift (VLOCK-01), so the
            //   digest of version N still matches → no false drift.
            // - `entry.pinned == false` → the source ref tracked latest (`⊳{…}`).
            //   Drop the `@N` and re-resolve LATEST so a rotated secret yields a
            //   digest mismatch → drift → exit 2 (VLOCK-05).  Re-pinning to the
            //   recorded immutable version here would re-fetch the exact locked
            //   value and make drift structurally undetectable.
            let inner_ref = if entry.pinned {
                format!(
                    "{}:{}#{}@{}",
                    entry.binding, entry.path, entry.field, entry.version
                )
            } else {
                format!("{}:{}#{}", entry.binding, entry.path, entry.field)
            };

            match resolver.resolve_reference_versioned(&inner_ref, &mut cache) {
                Ok((value, _resolved_version)) => {
                    // Recompute keyed digest with the SAME primitive (VLOCK-04).
                    let fresh_bytes = compute_lockfile_digest(&repo_key, value.as_bytes())
                        .map_err(|e| anyhow!("digest recompute failed: {e}"))?;
                    let fresh_hex = digest_to_hex(&fresh_bytes);

                    if fresh_hex != entry.digest {
                        drift_count += 1;
                        // Print only ref coordinates + digest prefixes; NEVER the value.
                        eprintln!(
                            "DRIFT: {}  locked={:.12}… current={:.12}…",
                            sanitize_for_display(canonical_key),
                            entry.digest,
                            fresh_hex
                        );
                    }
                }
                Err(e) if e.is_reference_miss() => {
                    misses.push(sanitize_for_display(&inner_ref));
                }
                Err(e) => {
                    whole_op_err = Some(e);
                    break;
                }
            }
        }

        // Route failures through Phase-47 exit-code seam.
        if let Some(wo_err) = whole_op_err {
            let ae = anyhow::Error::new(wo_err);
            let remaining = handle_vault_render_error(ae);
            return Err(remaining);
        }
        if !misses.is_empty() {
            let ae = anyhow::Error::new(VaultResolveError::MultiReferenceMiss {
                references: misses,
                partial: String::new(),
            });
            let remaining = handle_vault_render_error(ae);
            return Err(remaining);
        }

        if drift_count > 0 {
            eprintln!("vault verify: {drift_count} entry(ies) have drifted");
            // exit 2 — drift (VLOCK-04 / VFAIL-03).
            // Why: `vault verify` specifies exit 2 for drift so callers can distinguish
            // "secret changed in Vault" (exit 2) from "Vault unreachable" (exit 4) or
            // "reference no longer exists" (exit 3).  Single canonical drift-exit site.
            #[allow(clippy::exit)]
            std::process::exit(2);
        }

        println!("vault verify: all {} entries OK", lockfile.entries.len());
        Ok(())
    }
}
