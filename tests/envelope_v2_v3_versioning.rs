// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "hybrid")]

//! Envelope-signature v2/v3 versioning + backward-compatibility lock tests
//! (Phase 46.1, plan 46.1-01).
//!
//! These tests pin the format_version-versioned payload + signing context that
//! restores backward-compatibility after the Phase 46-02 v3 work:
//!
//!   1. `golden_fv2_fixture_verifies_on_current_binary` — a STATIC COMMITTED
//!      `tests/fixtures/golden_fv2.toml` (signed AHEAD OF TIME under the v2 context
//!      over the legacy no-vault payload) verifies on the current binary via
//!      `verify_envelope_signature_v2` ONLY. The asserting body NEVER calls
//!      `build_envelope_payload` / `sign_envelope` / `sign_with_context`, so it is a
//!      true on-the-wire drift lock: because the signed bytes are frozen in-repo while
//!      the verify side recomputes the payload from the config, ANY future drift in the
//!      pre-vault (fields 1-8 + per-user) layout makes the recompute diverge from the
//!      frozen signature and this test MUST fail (T-46.1-01 / T-46.1-03 regression lock).
//!   2. `fv2_round_trip_signs_and_verifies_under_v2_not_v3` — fv=2 sign under v2 ctx
//!      verifies under v2 and FAILS under v3 (cross-context separation, T-46.1-02).
//!   3. `fv3_vault_round_trip_signs_and_verifies_under_v3_not_v2` — fv=3 vault sign under
//!      v3 ctx verifies under v3 and FAILS under v2.
//!   4. `fv2_payload_emits_no_vault_region` — an fv=2 (vault:None) payload is exactly
//!      36 bytes shorter than the otherwise-identical fv=3 (vault:None) payload (the
//!      all-None vault region), i.e. fv=2 emits NO vault region.

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use sss::envelope_sig::{
    build_envelope_payload, sign_envelope, verify_envelope_signature,
    verify_envelope_signature_v2, ENVELOPE_SIG_CONTEXT_V2,
};
use sss::project::{
    EnvelopeMeta, EnvelopeSig, HooksConfig, ProjectConfig, RotationMetadata, UserConfig,
    VaultAuth, VaultBinding, VaultConfig,
};
use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};

// ---------------------------------------------------------------------------
// Shared constructors (NOT used by the static golden-fixture test below).
// ---------------------------------------------------------------------------

/// Build a fv=2 (no-vault) config with a single user advertising the supplied sig
/// pubkeys. Mirrors the construction shape used in `tests/vault_config_envelope_sig.rs`.
fn fv2_config(ed_pk_b64: String, pq_pk_b64: String) -> ProjectConfig {
    let mut users = HashMap::new();
    users.insert(
        "alice".to_string(),
        UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-01-01T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some(ed_pk_b64),
            sig_mldsa65_public: Some(pq_pk_b64),
        },
    );
    ProjectConfig {
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
        vault: None,
        envelope: None,
    }
}

// ---------------------------------------------------------------------------
// Test 1 (drift lock): STATIC committed golden fv=2 fixture verifies (verify-only).
// ---------------------------------------------------------------------------

/// The committed golden artefact. Frozen bytes: a fv=2 `.sss.toml` whose Ed448 +
/// ML-DSA-65 signatures + signer pubkeys were baked AHEAD OF TIME under
/// `ENVELOPE_SIG_CONTEXT_V2` over the legacy (no-vault) payload by the
/// `#[ignore]`d generator below. `include_str!` embeds it at compile time.
const GOLDEN_FV2_TOML: &str = include_str!("fixtures/golden_fv2.toml");

/// STATIC drift lock. Deserialises the committed bytes and verifies ONLY via
/// `verify_envelope_signature_v2`. The body MUST NOT call `build_envelope_payload`,
/// `sign_envelope`, or `sign_with_context` — re-signing here would lock nothing.
#[test]
fn golden_fv2_fixture_verifies_on_current_binary() {
    let cfg: ProjectConfig =
        toml::from_str(GOLDEN_FV2_TOML).expect("golden fv=2 fixture must deserialise");
    assert_eq!(
        cfg.format_version, 2,
        "golden fixture must be format_version=2"
    );
    assert!(cfg.vault.is_none(), "golden fv=2 fixture must carry no [vault]");

    // The ONLY crypto call in this test: verify the frozen signature over the
    // recomputed legacy payload. If the fields 1-8 + per-user layout ever drifts,
    // the recomputed payload diverges from the frozen signed bytes and this fails.
    sss::envelope_sig::verify_envelope_signature_v2(&cfg, Path::new(".sss.toml"))
        .expect("committed golden fv=2 envelope must verify under the v2 context");
}

// ---------------------------------------------------------------------------
// Test 2: fv=2 round-trip — sign under v2 verifies under v2, FAILS under v3.
// ---------------------------------------------------------------------------

#[test]
fn fv2_round_trip_signs_and_verifies_under_v2_not_v3() {
    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_b64 = BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(
        &Ed448Standard::verifying_key(&ed_sk),
    ));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_b64 = BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(
        &MlDsa65Fips204::verifying_key(&pq_sk),
    ));

    let mut cfg = fv2_config(ed_pk_b64, pq_pk_b64);
    let payload = build_envelope_payload(&cfg);
    // fv=2 -> sign_envelope selects the v2 context via context_for_format_version(2).
    let sig = sign_envelope(&ed_sk, &pq_sk, &payload, cfg.format_version).unwrap();
    cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

    // Verifies under the v2 arm.
    verify_envelope_signature_v2(&cfg, Path::new(".sss.toml"))
        .expect("fv=2 envelope must verify under the v2 context");

    // MUST FAIL under the v3 arm — a v2-context signature cannot be accepted by v3
    // (cross-context separation; no silent fallback).
    assert!(
        verify_envelope_signature(&cfg, Path::new(".sss.toml")).is_err(),
        "fv=2 (v2-context) signature must NOT verify under the v3 arm"
    );
}

// ---------------------------------------------------------------------------
// Test 3: fv=3 vault round-trip — sign under v3 verifies under v3, FAILS under v2.
// ---------------------------------------------------------------------------

#[test]
fn fv3_vault_round_trip_signs_and_verifies_under_v3_not_v2() {
    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_b64 = BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(
        &Ed448Standard::verifying_key(&ed_sk),
    ));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_b64 = BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(
        &MlDsa65Fips204::verifying_key(&pq_sk),
    ));

    let mut users = HashMap::new();
    users.insert(
        "alice".to_string(),
        UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-01-01T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some(ed_pk_b64),
            sig_mldsa65_public: Some(pq_pk_b64),
        },
    );

    let mut bindings = BTreeMap::new();
    bindings.insert(
        "kv".to_string(),
        VaultBinding {
            kv_version: Some(2),
            mount: Some("secret".to_string()),
            default_field: Some("value".to_string()),
        },
    );

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
    // fv=3 -> sign_envelope selects the v3 context via context_for_format_version(3).
    let sig = sign_envelope(&ed_sk, &pq_sk, &payload, cfg.format_version).unwrap();
    cfg.envelope = Some(EnvelopeMeta { sig: Some(sig) });

    // Verifies under the v3 arm.
    verify_envelope_signature(&cfg, Path::new(".sss.toml"))
        .expect("fv=3 vault envelope must verify under the v3 context");

    // MUST FAIL under the v2 arm — a v3-context signature cannot be accepted by v2.
    assert!(
        verify_envelope_signature_v2(&cfg, Path::new(".sss.toml")).is_err(),
        "fv=3 (v3-context) signature must NOT verify under the v2 arm"
    );
}

// ---------------------------------------------------------------------------
// Test 4: fv=2 emits NO vault region (payload-layout assertion).
// ---------------------------------------------------------------------------

#[test]
fn fv2_payload_emits_no_vault_region() {
    // Two configs identical except format_version (2 vs 3), both vault: None.
    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_b64 = BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(
        &Ed448Standard::verifying_key(&ed_sk),
    ));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_b64 = BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(
        &MlDsa65Fips204::verifying_key(&pq_sk),
    ));

    let fv2 = fv2_config(ed_pk_b64.clone(), pq_pk_b64.clone());
    let mut fv3 = fv2_config(ed_pk_b64, pq_pk_b64);
    fv3.format_version = 3;

    let p2 = build_envelope_payload(&fv2);
    let p3 = build_envelope_payload(&fv3);

    // The fv=3 (vault:None) payload carries the all-None vault region, which is exactly
    // 36 bytes: 4×push_lp_opt(None)=16 (address/namespace/default_binding/tls_ca_secret)
    // + 4-byte zero bindings count + 4×push_lp_opt(None)=16 (auth method/role_id/
    // secret_id_secret/token_secret). field 3 (format_version decimal string) is one byte
    // ("2" vs "3") in BOTH, so it contributes no length delta — the ONLY difference is the
    // gated vault region. fv=2 emits NONE of it.
    assert_eq!(
        p3.len() - p2.len(),
        36,
        "fv=3 (vault:None) payload must be exactly 36 bytes (all-None vault region) longer \
         than the fv=2 payload; fv=2 must emit NO vault region"
    );
    assert!(
        p2.len() < p3.len(),
        "fv=2 payload must be strictly shorter than the fv=3 payload"
    );
}

// ---------------------------------------------------------------------------
// One-shot generator for tests/fixtures/golden_fv2.toml — NOT run in CI.
// ---------------------------------------------------------------------------
//
// Run ONCE to (re)bake the static golden fixture:
//   cargo test --features hybrid --test envelope_v2_v3_versioning \
//     -- --ignored generate_golden_fv2_fixture --nocapture
//
// It signs a FIXED fv=2 config under ENVELOPE_SIG_CONTEXT_V2 over the legacy (no-vault)
// payload and writes the resulting .sss.toml to tests/fixtures/golden_fv2.toml. The
// committed file then carries that run's pubkeys + signature as frozen static bytes; the
// asserting test (#1) only verifies those bytes and never re-signs.
#[test]
#[ignore = "one-shot fixture generator; run manually to re-bake tests/fixtures/golden_fv2.toml"]
fn generate_golden_fv2_fixture() {
    let ed_sk = Ed448Standard::generate().unwrap();
    let ed_pk_b64 = BASE64_STANDARD.encode(Ed448Standard::verifying_key_to_bytes(
        &Ed448Standard::verifying_key(&ed_sk),
    ));
    let pq_sk = MlDsa65Fips204::generate().unwrap();
    let pq_pk_b64 = BASE64_STANDARD.encode(MlDsa65Fips204::verifying_key_to_bytes(
        &MlDsa65Fips204::verifying_key(&pq_sk),
    ));

    let mut cfg = fv2_config(ed_pk_b64, pq_pk_b64);

    // Sign under the v2 context via the raw primitives (the legacy schema-v2 domain
    // separator), exactly as an existing v2.x repo would have been signed before the v3
    // context bump. This must match what verify_envelope_signature_v2 expects.
    let payload = build_envelope_payload(&cfg);
    let ed_sig =
        Ed448Standard::sign_with_context(&ed_sk, &payload, ENVELOPE_SIG_CONTEXT_V2).unwrap();
    let pq_sig =
        MlDsa65Fips204::sign_with_context(&pq_sk, &payload, ENVELOPE_SIG_CONTEXT_V2).unwrap();
    cfg.envelope = Some(EnvelopeMeta {
        sig: Some(EnvelopeSig {
            ed448: BASE64_STANDARD.encode(Ed448Standard::signature_to_bytes(&ed_sig)),
            mldsa65: BASE64_STANDARD.encode(MlDsa65Fips204::signature_to_bytes(&pq_sig)),
        }),
    });

    // Self-check before writing: the freshly-signed config must verify under v2.
    verify_envelope_signature_v2(&cfg, Path::new(".sss.toml"))
        .expect("generated golden fixture must verify under v2 before commit");

    let toml_str = toml::to_string(&cfg).expect("serialise golden fixture");
    let out_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden_fv2.toml");
    std::fs::create_dir_all(out_path.parent().unwrap()).expect("create fixtures dir");
    std::fs::write(&out_path, toml_str.as_bytes()).expect("write golden fixture");
    println!("wrote golden fv=2 fixture to {}", out_path.display());
}
