// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Vault config + envelope-signature v3 integration tests (Phase 46, plan 46-02).
//!
//! Tests cover:
//!   - Classic-v1 gate (VCFG-05): [vault] on unsigned repo without opt-in → error
//!   - Classic-v1 opt-in with `tls_ca_secret` mandatory check
//!   - v2-without-upgrade gate: `[vault]` on a VALID v2-signed repo → error BEFORE verify
//!   - `format_version=3` sign → load round-trip (vault-bearing)
//!   - `format_version=1/2` without `[vault]` (no regression)
//!   - `vault.address` https-only validation at load
//!   - `SSS_VAULT_ADDR` override refusal (VCFG-06)
//!   - Tamper detection for vault fields in a v3-signed envelope

use serial_test::serial;
use tempfile::NamedTempFile;
use std::io::Write as IoWrite;

// Helper: write a TOML string to a NamedTempFile and return it.
fn write_toml(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp file");
    f.write_all(content.as_bytes()).expect("write toml");
    f
}

// ---------------------------------------------------------------------------
// Classic-v1 gate (VCFG-05)
// ---------------------------------------------------------------------------

#[test]
fn test_v1_with_vault_no_opt_in_is_error() {
    let toml = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"

[vault]
address = "https://vault.example.com:8200"
tls_ca_secret = "ca-cert"
"#;
    let f = write_toml(toml);
    let err = sss::project::ProjectConfig::load_from_file(f.path())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("--allow-unsigned-vault-config"),
        "error must name --allow-unsigned-vault-config; got: {err}"
    );
    // Confirm the error is a hard refusal, not just a warning.
    assert!(
        err.contains("unsigned") || err.contains("format_version=1"),
        "error must mention unsigned or format_version=1; got: {err}"
    );
}

#[test]
fn test_v1_with_vault_opt_in_but_no_tls_ca_secret_is_error() {
    let toml = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"

[vault]
address = "https://vault.example.com:8200"
"#;
    // No tls_ca_secret → error even with the opt-in
    let f = write_toml(toml);
    let err = sss::project::ProjectConfig::load_from_file_with_opts(f.path(), true, false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("tls_ca_secret"),
        "error must say tls_ca_secret is mandatory; got: {err}"
    );
}

#[test]
fn test_v1_with_vault_opt_in_and_tls_ca_secret_loads() {
    let toml = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"

[vault]
address = "https://vault.example.com:8200"
tls_ca_secret = "ca-cert"
"#;
    let f = write_toml(toml);
    let cfg = sss::project::ProjectConfig::load_from_file_with_opts(f.path(), true, false)
        .expect("load with opt-in + tls_ca_secret must succeed");
    assert!(cfg.vault.is_some(), "vault must be populated");
}

// ---------------------------------------------------------------------------
// v2-without-upgrade gate (T-46-11)
// ---------------------------------------------------------------------------

/// Build a genuinely valid v2-signed .sss.toml in memory and return its TOML string.
/// The signature is cryptographically valid for the no-vault payload.
#[cfg(feature = "hybrid")]
fn build_valid_v2_toml() -> String {
    use base64::prelude::BASE64_STANDARD;
    use base64::prelude::BASE64_STANDARD as B64;
    use base64::Engine;
    use sss::envelope_sig::{build_envelope_payload, ENVELOPE_SIG_CONTEXT_V2};
    use sss::project::{EnvelopeMeta, EnvelopeSig, HooksConfig, ProjectConfig, RotationMetadata, UserConfig};
    use std::collections::HashMap;
    use trelis_primitives::{Ed448Standard, Ed448Scheme, MlDsa65Fips204, MlDsaScheme};

    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(&Ed448Standard::verifying_key(&ed_sk));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(&MlDsa65Fips204::verifying_key(&pq_sk));

    let mut users = HashMap::new();
    users.insert("alice".to_string(), UserConfig {
        public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        added: "2026-01-01T00:00:00Z".to_string(),
        hybrid_public: None,
        sig_ed448_public: Some(BASE64_STANDARD.encode(ed_pk_bytes)),
        sig_mldsa65_public: Some(BASE64_STANDARD.encode(pq_pk_bytes)),
    });

    let mut cfg = ProjectConfig {
        version: "2.0".to_string(),
        format_version: 2,
        created: "2026-01-01T00:00:00Z".to_string(),
        users,
        hooks: HooksConfig::default(),
        rotation: RotationMetadata::default(),
        secrets_filename: None,
        secrets_suffix: None,
        ignore: None,
        key: None,
        vault: None, // No [vault] for the signed payload
        envelope: None,
    };

    // Sign under the v2 context. sign_envelope uses ENVELOPE_SIG_CONTEXT (v3), so we
    // sign directly with the v2 context constant via the raw primitives.
    let payload = build_envelope_payload(&cfg);

    // Re-derive the signing keys from the stored bytes for direct use.
    // We need to use the v2 context sign path. Use the raw primitives directly.
    let ed448_sig = Ed448Standard::sign_with_context(&ed_sk, &payload, ENVELOPE_SIG_CONTEXT_V2).unwrap();
    let mldsa_sig = MlDsa65Fips204::sign_with_context(&pq_sk, &payload, ENVELOPE_SIG_CONTEXT_V2).unwrap();

    cfg.envelope = Some(EnvelopeMeta {
        sig: Some(EnvelopeSig {
            ed448: B64.encode(Ed448Standard::signature_to_bytes(&ed448_sig)),
            mldsa65: B64.encode(MlDsa65Fips204::signature_to_bytes(&mldsa_sig)),
        }),
    });

    // The signature is cryptographically valid for the v2 payload (no vault).
    // Confirm this (belt-and-suspenders check before we use it in the test).
    sss::envelope_sig::verify_envelope_signature_v2(&cfg, std::path::Path::new("/dev/null"))
        .expect("v2 signature must verify cleanly before we inject [vault]");

    toml::to_string(&cfg).expect("serialise must succeed")
}

#[cfg(feature = "hybrid")]
#[test]
fn test_v2_with_vault_table_injected_is_rejected_even_with_valid_sig() {
    // Build a VALIDLY v2-signed TOML (no [vault]) and inject a [vault] table AFTER signing.
    // The v2 signature is still byte-valid (it was signed over the no-vault payload).
    // load_from_file MUST reject it with an upgrade-sig message, proving the gate fires
    // BEFORE/INDEPENDENT OF signature verification.
    let mut toml_str = build_valid_v2_toml();

    // Inject a [vault] table at the end (after the signature is already baked in).
    toml_str.push_str(
        r#"
[vault]
address = "https://vault.example.com:8200"
tls_ca_secret = "ca-cert"
"#
    );

    let f = write_toml(&toml_str);
    let err = sss::project::ProjectConfig::load_from_file(f.path())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("upgrade-sig") || err.contains("upgrade_sig"),
        "error must direct to sss envelope upgrade-sig; got: {err}"
    );
    // The gate must fire even though the v2 signature itself was valid.
    // (The v2 signature was produced over the no-vault payload — it would actually
    // verify if we reached the verification step, which is exactly what makes this
    // test important: the gate must fire BEFORE, not after, verification.)
}

#[cfg(feature = "hybrid")]
#[test]
fn test_v2_without_vault_still_loads_correctly() {
    // Regression: a v2-signed repo WITHOUT [vault] must still load and verify.
    let toml_str = build_valid_v2_toml();
    let f = write_toml(&toml_str);
    let cfg = sss::project::ProjectConfig::load_from_file(f.path())
        .expect("v2 without [vault] must load successfully (no regression)");
    assert_eq!(cfg.format_version, 2);
    assert!(cfg.vault.is_none(), "vault must be None for a no-vault v2 repo");
}

// ---------------------------------------------------------------------------
// format_version=1 without [vault] — no regression
// ---------------------------------------------------------------------------

#[test]
fn test_v1_without_vault_loads_as_legacy() {
    let toml = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
"#;
    let f = write_toml(toml);
    let cfg = sss::project::ProjectConfig::load_from_file(f.path())
        .expect("v1 without [vault] must load as legacy-unsigned");
    assert_eq!(cfg.format_version, 1);
    assert!(cfg.vault.is_none());
}

// ---------------------------------------------------------------------------
// format_version=3 sign → verify round-trip (vault-bearing)
// ---------------------------------------------------------------------------

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn test_v3_vault_round_trip_sign_and_load() {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use sss::project::{EnvelopeMeta, HooksConfig, ProjectConfig, RotationMetadata, UserConfig, VaultConfig, VaultBinding, VaultAuth};
    use sss::envelope_sig::{build_envelope_payload, sign_envelope};
    use std::collections::{BTreeMap, HashMap};
    use trelis_primitives::{Ed448Standard, Ed448Scheme, MlDsa65Fips204, MlDsaScheme};
    // Ensure SSS_VAULT_ADDR is not set; #[serial] prevents concurrent env mutation.
    let _env_guard = EnvGuard::remove("SSS_VAULT_ADDR");

    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(&Ed448Standard::verifying_key(&ed_sk));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(&MlDsa65Fips204::verifying_key(&pq_sk));

    let mut users = HashMap::new();
    users.insert("alice".to_string(), UserConfig {
        public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        added: "2026-01-01T00:00:00Z".to_string(),
        hybrid_public: None,
        sig_ed448_public: Some(BASE64_STANDARD.encode(ed_pk_bytes)),
        sig_mldsa65_public: Some(BASE64_STANDARD.encode(pq_pk_bytes)),
    });

    let mut bindings = BTreeMap::new();
    bindings.insert("kv".to_string(), VaultBinding {
        kv_version: Some(2),
        mount: Some("secret".to_string()),
        default_field: Some("value".to_string()),
    });

    let mut cfg = ProjectConfig {
        version: "2.0".to_string(),
        format_version: 3,
        created: "2026-01-01T00:00:00Z".to_string(),
        users,
        hooks: HooksConfig::default(),
        rotation: RotationMetadata::default(),
        secrets_filename: None,
        secrets_suffix: None,
        ignore: None,
        key: None,
        vault: Some(VaultConfig {
            address: Some("https://vault.example.com:8200".to_string()),
            namespace: Some("myns".to_string()),
            default_binding: Some("kv".to_string()),
            tls_ca_secret: Some("ca-cert".to_string()),
            bindings,
            auth: Some(VaultAuth {
                method: Some("approle".to_string()),
                role_id: Some("my-role".to_string()),
                secret_id_secret: Some("vault-secret-id".to_string()),
                token_secret: None,
            }),
        }),
        envelope: None,
    };

    let payload = build_envelope_payload(&cfg);
    // fv=3 vault config: sign under the v3 context (context_for_format_version(3)).
    let sig = sign_envelope(&ed_sk, &pq_sk, &payload, cfg.format_version).unwrap();
    cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

    let toml_str = toml::to_string(&cfg).expect("serialise must succeed");
    let f = write_toml(&toml_str);

    // load_from_file_with_opts with allow_insecure_vault_addr_override=true so this test
    // is resilient to SSS_VAULT_ADDR being set by a concurrently-running test. The
    // round-trip test focuses on sign+verify correctness, not the env-override gate.
    let loaded = sss::project::ProjectConfig::load_from_file_with_opts(f.path(), false, true)
        .expect("v3 vault round-trip must load successfully");
    assert_eq!(loaded.format_version, 3);
    let v = loaded.vault.as_ref().expect("vault must survive round-trip");
    assert_eq!(v.address.as_deref(), Some("https://vault.example.com:8200"));
    assert_eq!(v.namespace.as_deref(), Some("myns"));
    let binding = v.bindings.get("kv").expect("binding 'kv' must be present");
    assert_eq!(binding.kv_version, Some(2));
}

// ---------------------------------------------------------------------------
// Tamper detection: flipping a vault field causes load to fail
// ---------------------------------------------------------------------------

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn test_v3_vault_address_tamper_causes_load_failure() {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use sss::project::{EnvelopeMeta, HooksConfig, ProjectConfig, RotationMetadata, UserConfig, VaultConfig};
    use sss::envelope_sig::{build_envelope_payload, sign_envelope};
    use std::collections::{BTreeMap, HashMap};
    use trelis_primitives::{Ed448Standard, Ed448Scheme, MlDsa65Fips204, MlDsaScheme};
    let _env_guard = EnvGuard::remove("SSS_VAULT_ADDR");

    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(&Ed448Standard::verifying_key(&ed_sk));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(&MlDsa65Fips204::verifying_key(&pq_sk));

    let mut users = HashMap::new();
    users.insert("alice".to_string(), UserConfig {
        public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        added: "2026-01-01T00:00:00Z".to_string(),
        hybrid_public: None,
        sig_ed448_public: Some(BASE64_STANDARD.encode(ed_pk_bytes)),
        sig_mldsa65_public: Some(BASE64_STANDARD.encode(pq_pk_bytes)),
    });

    let mut cfg = ProjectConfig {
        version: "2.0".to_string(),
        format_version: 3,
        created: "2026-01-01T00:00:00Z".to_string(),
        users,
        hooks: HooksConfig::default(),
        rotation: RotationMetadata::default(),
        secrets_filename: None,
        secrets_suffix: None,
        ignore: None,
        key: None,
        vault: Some(VaultConfig {
            address: Some("https://vault.example.com:8200".to_string()),
            namespace: None,
            default_binding: None,
            tls_ca_secret: Some("ca-cert".to_string()),
            bindings: BTreeMap::default(),
            auth: None,
        }),
        envelope: None,
    };

    let payload = build_envelope_payload(&cfg);
    // fv=3 vault config: sign under the v3 context (context_for_format_version(3)).
    let sig = sign_envelope(&ed_sk, &pq_sk, &payload, cfg.format_version).unwrap();
    cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

    let original_toml = toml::to_string(&cfg).expect("serialise must succeed");

    // Tamper: change the vault address to a different host.
    let tampered_toml = original_toml.replace(
        "https://vault.example.com:8200",
        "https://evil.attacker.com:8200",
    );
    assert_ne!(original_toml, tampered_toml, "tamper must have changed the toml");

    let f = write_toml(&tampered_toml);
    // Use allow_insecure_vault_addr_override=true so this test is resilient to
    // SSS_VAULT_ADDR being set in the environment (the env-override gate is not
    // what we are testing here). We want to confirm the SIGNATURE mismatch is caught.
    let result = sss::project::ProjectConfig::load_from_file_with_opts(f.path(), false, true);
    assert!(
        result.is_err(),
        "tampered vault.address must cause load to fail (signature mismatch)"
    );
}

// ---------------------------------------------------------------------------
// vault.address https-only validation at load
// ---------------------------------------------------------------------------

#[test]
fn test_http_vault_address_rejected_at_load() {
    let toml = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"

[vault]
address = "http://vault.example.com:8200"
tls_ca_secret = "ca-cert"
"#;
    // With opt-in (to get past the classic-v1 gate), but the address is http → error.
    let f = write_toml(toml);
    let err = sss::project::ProjectConfig::load_from_file_with_opts(f.path(), true, false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("address"),
        "error must name the address field; got: {err}"
    );
    // The value (http://vault.example.com:8200) must NOT appear in the error (T-46-14).
    assert!(
        !err.contains("vault.example.com"),
        "error must not echo the address value; got: {err}"
    );
}

// ---------------------------------------------------------------------------
// SSS_VAULT_ADDR override refusal (VCFG-06)
// Tests use std::env directly; env var is process-global, so these tests must
// not run concurrently with other tests that set SSS_VAULT_ADDR.
// ---------------------------------------------------------------------------

/// A simple RAII guard that restores an env var to its original value on drop.
struct EnvGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var_os(key);
        // Why: set_var is unsafe in Rust 2024 (unsound under multi-thread env mutation);
        // these tests run as single-threaded test functions and the guard restores state.
        // The env var is process-global; tests using EnvGuard must not run concurrently.
        #[allow(unsafe_code)]
        // Safety: single-threaded test context; EnvGuard restores the prior value on drop.
        unsafe { std::env::set_var(key, value) };
        Self { key, original }
    }

    fn remove(key: &'static str) -> Self {
        let original = std::env::var_os(key);
        #[allow(unsafe_code)]
        // Safety: single-threaded test context; EnvGuard restores the prior value on drop.
        unsafe { std::env::remove_var(key) };
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.original {
            #[allow(unsafe_code)]
            // Safety: single-threaded test context; restoring prior env state.
            Some(v) => unsafe { std::env::set_var(self.key, v) },
            #[allow(unsafe_code)]
            // Safety: single-threaded test context; clearing the env var we set.
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

/// Build a valid v3-signed TOML with vault.address set, suitable for VCFG-06 tests.
#[cfg(feature = "hybrid")]
fn build_valid_v3_signed_vault_toml() -> String {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use sss::project::{EnvelopeMeta, HooksConfig, ProjectConfig, RotationMetadata, UserConfig, VaultConfig};
    use sss::envelope_sig::{build_envelope_payload, sign_envelope};
    use std::collections::{BTreeMap, HashMap};
    use trelis_primitives::{Ed448Standard, Ed448Scheme, MlDsa65Fips204, MlDsaScheme};

    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_bytes = Ed448Standard::verifying_key_to_bytes(&Ed448Standard::verifying_key(&ed_sk));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_bytes = MlDsa65Fips204::verifying_key_to_bytes(&MlDsa65Fips204::verifying_key(&pq_sk));

    let mut users = HashMap::new();
    users.insert("alice".to_string(), UserConfig {
        public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        added: "2026-01-01T00:00:00Z".to_string(),
        hybrid_public: None,
        sig_ed448_public: Some(BASE64_STANDARD.encode(ed_pk_bytes)),
        sig_mldsa65_public: Some(BASE64_STANDARD.encode(pq_pk_bytes)),
    });

    let mut cfg = ProjectConfig {
        version: "2.0".to_string(),
        format_version: 3,
        created: "2026-01-01T00:00:00Z".to_string(),
        users,
        hooks: HooksConfig::default(),
        rotation: RotationMetadata::default(),
        secrets_filename: None,
        secrets_suffix: None,
        ignore: None,
        key: None,
        vault: Some(VaultConfig {
            address: Some("https://vault.example.com:8200".to_string()),
            namespace: None,
            default_binding: None,
            tls_ca_secret: Some("ca-cert".to_string()),
            bindings: BTreeMap::default(),
            auth: None,
        }),
        envelope: None,
    };

    let payload = build_envelope_payload(&cfg);
    // fv=3 vault config: sign under the v3 context (context_for_format_version(3)).
    let sig = sign_envelope(&ed_sk, &pq_sk, &payload, cfg.format_version).unwrap();
    cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });
    toml::to_string(&cfg).expect("serialise must succeed")
}

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn test_sss_vault_addr_set_signed_address_no_opt_in_is_error() {
    // The VCFG-06 gate inside load_from_file_with_opts fires when:
    //   - format_version >= 3
    //   - vault.address is present (signed into the envelope)
    //   - SSS_VAULT_ADDR is present in the environment
    //   - allow_insecure_vault_addr_override is false
    //
    // We exercise the gate by setting SSS_VAULT_ADDR in the env AND calling
    // load_from_file (which uses allow_insecure_vault_addr_override=false).
    // EnvGuard restores the original env value on drop.
    //
    // Note: tests that *set* SSS_VAULT_ADDR must not use load_from_file() in
    // other threads at the same time — the set guard races with concurrent
    // removes. This test sets SSS_VAULT_ADDR; the load happens inside this test
    // only, with allow_insecure_vault_addr_override=false matching load_from_file.
    let _guard = EnvGuard::set("SSS_VAULT_ADDR", "https://evil.attacker.com:8200");

    let toml_str = build_valid_v3_signed_vault_toml();
    let f = write_toml(&toml_str);

    // load_from_file delegates to load_from_file_with_opts(false, false).
    // With SSS_VAULT_ADDR set and no opt-in, the gate must fire.
    let err = sss::project::ProjectConfig::load_from_file(f.path())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("SSS_VAULT_ADDR"),
        "error must name SSS_VAULT_ADDR; got: {err}"
    );
    // Must not echo either address value (T-46-04 / T-39-04).
    assert!(
        !err.contains("vault.example.com"),
        "error must not echo the configured address; got: {err}"
    );
    assert!(
        !err.contains("evil.attacker.com"),
        "error must not echo the env-var value; got: {err}"
    );
}

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn test_sss_vault_addr_set_signed_address_with_opt_in_loads() {
    let _guard = EnvGuard::set("SSS_VAULT_ADDR", "https://override.example.com:8200");

    let toml_str = build_valid_v3_signed_vault_toml();
    let f = write_toml(&toml_str);

    // With the insecure opt-in, override is permitted regardless of env.
    sss::project::ProjectConfig::load_from_file_with_opts(f.path(), false, true)
        .expect("insecure opt-in must allow SSS_VAULT_ADDR override");
}

#[cfg(feature = "hybrid")]
#[test]
#[serial]
fn test_sss_vault_addr_unset_signed_address_loads() {
    // Explicitly remove SSS_VAULT_ADDR (guard restores original value on drop).
    // #[serial] ensures this test does not run concurrently with tests that set it.
    let _guard = EnvGuard::remove("SSS_VAULT_ADDR");

    let toml_str = build_valid_v3_signed_vault_toml();
    let f = write_toml(&toml_str);

    sss::project::ProjectConfig::load_from_file(f.path())
        .expect("SSS_VAULT_ADDR unset + signed address must load cleanly");
}

#[test]
#[serial]
fn test_sss_vault_addr_set_no_vault_address_loads() {
    // SSS_VAULT_ADDR is set but the config has no vault.address → gate must not fire.
    let _guard = EnvGuard::set("SSS_VAULT_ADDR", "https://override.example.com:8200");

    // A v1 config with no [vault] at all.
    let toml = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
"#;
    let f = write_toml(toml);
    sss::project::ProjectConfig::load_from_file(f.path())
        .expect("SSS_VAULT_ADDR set but no vault.address must load cleanly");
}
