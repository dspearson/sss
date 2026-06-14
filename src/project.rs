use anyhow::{anyhow, Result};
use chrono::Utc;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use crate::crypto::{ClassicSuite, CryptoSuite, PublicKey, RepositoryKey, Suite, suite_for};
use crate::{error_helpers, toml_helpers};

/// A user's configuration in the project
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserConfig {
    /// User's public key (for sealing repository keys)
    pub public: String,
    /// Sealed repository symmetric key (encrypted for this user)
    pub sealed_key: String,
    /// When this user was added to the project
    #[serde(default = "default_created")]
    pub added: String,
    /// Hybrid (X448 + sntrup761) public key, base64-encoded.
    /// None on v1 repos and on users who have not yet registered a hybrid key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub hybrid_public: Option<String>,
    /// Ed448 signing public key (base64) for envelope signature verification (D-06).
    /// None on classic repos and on users who have not yet upgraded their sig keypair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig_ed448_public: Option<String>,
    /// ML-DSA-65 signing public key (base64) for envelope signature verification (D-06).
    /// None on classic repos and on users who have not yet upgraded their sig keypair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig_mldsa65_public: Option<String>,
}

/// Top-level envelope signature container; present iff `format_version=2` (D-07).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct EnvelopeMeta {
    /// Hybrid AND-composition signature over the canonical envelope payload (D-07).
    /// `None` is rendered as no `[envelope.sig]` table at all (`skip_if_none`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub sig: Option<EnvelopeSig>,
}

/// AND-composition envelope signature: BOTH legs must verify (D-07).
///
/// `ed448`   = base64 of 114-byte Ed448 signature.
/// `mldsa65` = base64 of 3309-byte ML-DSA-65 signature.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvelopeSig {
    pub ed448: String,
    pub mldsa65: String,
}

/// Project-level configuration (safe for git)
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Configuration version
    #[serde(default = "default_version")]
    pub version: String,

    /// Project creation timestamp
    #[serde(default = "default_created")]
    pub created: String,

    /// Envelope signing-format version (D-07/D-09).
    /// 1 (default if absent) = legacy unsigned; 2 = signed; >=3 = hard-reject.
    /// Orthogonal to `version` (crypto suite). Only emitted when promoted to 2.
    #[serde(default = "default_envelope_format_version", skip_serializing_if = "is_default_format_version")]
    pub format_version: u32,

    /// Top-level envelope signature container; present iff `format_version=2` (D-07).
    /// Gated on `hybrid` feature — non-hybrid builds never read or write this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "hybrid"), serde(skip))]
    pub envelope: Option<EnvelopeMeta>,

    /// Users who can decrypt/encrypt in this project
    /// Flattened to appear as `[username]` sections in TOML
    #[serde(flatten)]
    pub users: HashMap<String, UserConfig>,

    /// Git hooks configuration
    #[serde(default, skip_serializing_if = "HooksConfig::is_empty")]
    pub hooks: HooksConfig,

    /// Key rotation metadata
    #[serde(default, skip_serializing_if = "RotationMetadata::is_empty")]
    pub rotation: RotationMetadata,

    /// Custom secrets filename (defaults to "secrets" if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_filename: Option<String>,

    /// Custom secrets file suffix (defaults to ".secrets" if not set)
    /// Example: ".sealed" would make "config.yaml.sealed" a valid secrets file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_suffix: Option<String>,

    /// Gitignore-style patterns for files to ignore in project-wide operations
    /// Multiple patterns separated by spaces or commas
    /// Example: "*.log build/ temp*.txt"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore: Option<String>,

    /// Migration: old-style key (should be removed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// Vault resolver configuration (`[vault]` table).
    ///
    /// CRITICAL (R4): must NOT have `#[cfg_attr(not(feature = "vault"), serde(skip))]`.
    /// The field must be present in every build configuration so that
    /// `build_envelope_payload` can encode vault fields unconditionally.
    /// `None` → encodes as 4 zero bytes per field (deterministic, feature-independent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultConfig>,
}

fn default_envelope_format_version() -> u32 {
    1
}

// Why: serde's skip_serializing_if predicate requires `fn(&T) -> bool`
// signature, so &u32 is mandatory here — passing by value would not match
// the trait. See line 73's #[serde(skip_serializing_if = ...)] attribute.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_format_version(v: &u32) -> bool {
    *v == 1
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_created() -> String {
    Utc::now().to_rfc3339()
}

/// Resolve a `.sss.toml` `version` string to a `Suite`.
///
/// `"1.0"` → `Suite::Classic`, `"2.0"` → `Suite::Hybrid`.
/// Any other value produces an actionable error.
///
/// Plan 04-01 gate change: `"2.0"` now returns `Ok(Suite::Hybrid)` so
/// v2 repos are loadable by this binary.  The old SUITE-04 upgrade-prompt
/// error for `"2.0"` is intentionally removed.
fn resolve_suite_from_version(version: &str) -> Result<Suite> {
    match version {
        "1.0" => Ok(Suite::Classic),
        "2.0" => Ok(Suite::Hybrid),
        other => Err(anyhow!(
            "unknown .sss.toml version {other:?}: expected \"1.0\" or \"2.0\""
        )),
    }
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            created: default_created(),
            format_version: default_envelope_format_version(),
            envelope: None,
            users: HashMap::new(),
            hooks: HooksConfig::default(),
            rotation: RotationMetadata::default(),
            secrets_filename: None,
            secrets_suffix: None,
            ignore: None,
            key: None,
            vault: None,
        }
    }
}

/// Git hooks configuration
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct HooksConfig {
    pub git_pre_commit: Option<bool>,
    pub git_post_checkout: Option<bool>,
}

impl HooksConfig {
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.git_pre_commit.is_none() && self.git_post_checkout.is_none()
    }
}

/// Key rotation metadata
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RotationMetadata {
    /// Timestamp of last key rotation
    pub last_rotation: Option<String>,
    /// Number of rotations performed
    #[serde(default)]
    pub rotation_count: u32,
    /// Reason for last rotation
    pub last_rotation_reason: Option<String>,
}

impl RotationMetadata {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last_rotation.is_none()
            && self.rotation_count == 0
            && self.last_rotation_reason.is_none()
    }
}

/// Vault-backed resolver configuration.
///
/// Signed into the envelope payload at `format_version=3`.
/// Fields must mirror the payload encoding order in `build_envelope_payload` (fields 9–16+).
///
/// CRITICAL (R4): this struct must NOT be `#[cfg(feature = "vault")]` gated —
/// it must be present in every build so that `build_envelope_payload` can encode
/// vault fields identically whether or not the vault feature is compiled.
/// The `serde(skip_serializing_if = "Option::is_none")` on each field handles
/// the serialisation-only skip; the struct remains in the payload encoding path.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct VaultConfig {
    /// Vault server address — `https://` only, validated at config load.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Vault Enterprise namespace (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Default binding name for `⊳{path}` references without a `binding:` prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_binding: Option<String>,
    /// Secret name in `.secrets` that holds the TLS CA cert PEM (CA pinning).
    /// Mandatory under `--allow-unsigned-vault-config` (VCFG-05).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca_secret: Option<String>,
    /// Named bindings: `[vault.bindings.<name>]`.
    /// `BTreeMap` for deterministic key-sorted iteration (required by canonical payload encoding).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, VaultBinding>,
    /// Authentication configuration: `[vault.auth]`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<VaultAuth>,
}

/// Per-binding configuration (KV engine + mount + default field).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct VaultBinding {
    /// KV engine version: 1 or 2 (default 2 if absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kv_version: Option<u8>,
    /// KV mount path, e.g. `"secret"` or `"kv"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
    /// Default field name when `#field` is omitted in a `⊳{}` reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_field: Option<String>,
}

/// Vault authentication configuration.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct VaultAuth {
    /// Auth method — `"approle"` is the primary supported method in Phase 46.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// `AppRole` `role_id` (non-secret — safe in git).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    /// Secret name in `.secrets` holding the `AppRole` `secret_id` (sealed, never stored raw).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id_secret: Option<String>,
    /// Secret name in `.secrets` holding a static token (alternative to `AppRole`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_secret: Option<String>,
}

impl ProjectConfig {
    /// Create a new project configuration with a single user
    /// Generates a new repository key and seals it for the user
    pub fn new(username: &str, user_public_key: &PublicKey) -> Result<Self> {
        // Generate a new repository key
        let repository_key = RepositoryKey::new();

        // Dispatch sealing on the key variant.  Classic keys → ClassicSuite;
        // hybrid keys → HybridSuite (via the `hybrid` feature gate so the
        // code is unreachable in non-hybrid builds and the compiler can
        // elide the branch).  This wires the Phase-2 TODO that was deferred
        // in the original comment (Rule 1 fix, 19-02).
        #[cfg(feature = "hybrid")]
        let sealed_key = match user_public_key {
            PublicKey::Classic(_) => ClassicSuite.seal_repo_key(&repository_key, user_public_key)?,
            PublicKey::Hybrid(_) => {
                crate::crypto::HybridCryptoSuite.seal_repo_key(&repository_key, user_public_key)?
            }
        };
        #[cfg(not(feature = "hybrid"))]
        let sealed_key = ClassicSuite.seal_repo_key(&repository_key, user_public_key)?;

        let user_config = UserConfig {
            public: user_public_key.to_base64(),
            sealed_key,
            added: default_created(),
            hybrid_public: None,
            sig_ed448_public: None,
            sig_mldsa65_public: None,
        };

        let mut users = HashMap::new();
        users.insert(username.to_string(), user_config);

        Ok(Self {
            version: default_version(),
            created: default_created(),
            format_version: default_envelope_format_version(),
            envelope: None,
            users,
            hooks: HooksConfig::default(),
            rotation: RotationMetadata::default(),
            secrets_filename: None,
            secrets_suffix: None,
            ignore: None,
            key: None,
            vault: None,
        })
    }

    /// Load project configuration from file.
    ///
    /// Delegates to `load_from_file_with_opts` with all security gates enabled
    /// (`allow_unsigned_vault_config = false`, `allow_insecure_vault_addr_override = false`).
    /// CLI callers that expose `--allow-*` flags call `load_from_file_with_opts` directly.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_from_file_with_opts(path, false, false)
    }

    /// Load project configuration from file with explicit security gate opt-ins.
    ///
    /// - `allow_unsigned_vault_config`: when `true`, a `[vault]` table on a
    ///   `format_version=1` (unsigned) repo is permitted, but `vault.tls_ca_secret`
    ///   becomes mandatory (CA pinning is the only phishing mitigation without a signature).
    ///   Pass `false` for all callers that do not explicitly expose this flag — a `[vault]`
    ///   table on an unsigned repo is a hard error by default (VCFG-05).
    /// - `allow_insecure_vault_addr_override`: when `true`, `SSS_VAULT_ADDR` may override
    ///   a signed vault address. Pass `false` to enforce the default refusal (VCFG-06).
    // Why: this function is long because it implements a sequential gate pipeline (size-check
    // → parse → validate paths → validate vault addr → version gate → format_version dispatch
    // → VCFG-06 gate). Each step is mandatory and order-sensitive; factoring into sub-functions
    // would require threading `path` and `config` through all of them, buying nothing in clarity.
    #[allow(clippy::too_many_lines)]
    pub fn load_from_file_with_opts<P: AsRef<Path>>(
        path: P,
        allow_unsigned_vault_config: bool,
        allow_insecure_vault_addr_override: bool,
    ) -> Result<Self> {
        // REM-32: reject .sss.toml larger than 1 MB before allocating the buffer.
        // NIT-01: this metadata→read is a two-syscall check, so it is best-effort
        // against a local writer that grows the file between stat and read_to_string.
        // Accepted: the threat is local-only Low-severity (PAR-01); no behavioural fix.
        let meta = fs::metadata(&path).map_err(|e| {
            anyhow!(
                "Failed to stat project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;
        if meta.len() > crate::constants::MAX_TOML_SIZE as u64 {
            return Err(anyhow!(
                "{}: project config file too large ({} bytes, max {} bytes)",
                path.as_ref().display(),
                meta.len(),
                crate::constants::MAX_TOML_SIZE,
            ));
        }

        let content = fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Failed to read project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;

        let config: Self = toml_helpers::parse_toml(&content, "project")?;

        // REM-06: validate secrets_filename and secrets_suffix immediately after
        // the TOML parse, BEFORE the format_version dispatch ladder.  Placement
        // here is mandatory so that a v1 (unsigned) TOML with a malicious path
        // is rejected just as a v2 signed one would be — moving these calls
        // inside the `2 =>` arm below would silently skip them for v1 (Pitfall 4).
        // validate_file_path intentionally allows absolute paths and `..` per its
        // own docstring; use the dedicated stricter helper instead.
        if let Some(ref sf) = config.secrets_filename {
            crate::validation::validate_secrets_path(sf, "secrets_filename")
                .map_err(|e| anyhow!("{}: {}", path.as_ref().display(), e))?;
        }
        if let Some(ref ss) = config.secrets_suffix {
            crate::validation::validate_secrets_path(ss, "secrets_suffix")
                .map_err(|e| anyhow!("{}: {}", path.as_ref().display(), e))?;
        }

        // VCFG-02: validate vault.address (https-only, never echoes value — T-46-04).
        // Run BEFORE format_version dispatch so the check applies uniformly regardless
        // of envelope state (mirrors the secrets_path placement rationale above).
        if let Some(ref vc) = config.vault
            && let Some(ref addr) = vc.address
        {
            crate::validation::validate_vault_address(addr)
                .map_err(|e| anyhow!("{}: {}", path.as_ref().display(), e))?;
        }

        // Version gate — run BEFORE envelope dispatch so suite-version errors
        // surface ahead of envelope-version errors (D-15). Emits the SUITE-04
        // actionable error for `version = "2.0"` against this v1 binary.
        resolve_suite_from_version(&config.version)?;

        // D-09 envelope-version dispatch ladder (D-15 ordering: after suite check,
        // before Ok(config)).
        match config.format_version {
            1 => {
                // PAR-13/CRY-08 downgrade closure (Phase 38, REM-01):
                // A genuinely legacy v1 envelope has no [envelope.sig] table.
                // If format_version=1 but a sig table IS present, this signals
                // that an attacker flipped a signed v2/v3 envelope's format_version
                // field to bypass verification — reject with an actionable error.
                // A v1 envelope with no sig table continues to load as legacy-unsigned.
                if config.envelope.as_ref().and_then(|e| e.sig.as_ref()).is_some() {
                    return Err(anyhow!(
                        "{}: envelope declares format_version=1 but carries an [envelope.sig] \
                        table — this indicates tampering (a signed envelope with a \
                        downgraded format_version field) or an interrupted upgrade. \
                        Restore the file from git, or run `sss envelope upgrade-sig` to re-sign.",
                        path.as_ref().display()
                    ));
                }
                // VCFG-05: classic-v1 gate — [vault] on an unsigned repo is a hard error
                // unless the explicit opt-in is supplied (T-46-13).
                if config.vault.is_some() {
                    if !allow_unsigned_vault_config {
                        return Err(anyhow!(
                            "{}: [vault] config is present but this repo is unsigned \
                            (format_version=1). A v1 envelope cannot cover the vault fields, \
                            which opens a credential-phishing gap. Either sign the repo first \
                            (`sss envelope upgrade-sig`) or pass `--allow-unsigned-vault-config` \
                            to acknowledge the risk.",
                            path.as_ref().display()
                        ));
                    }
                    // Opt-in is set: CA pinning is mandatory (the only phishing mitigation
                    // available without a signature — see CONTEXT.md §decisions).
                    if config.vault.as_ref().and_then(|v| v.tls_ca_secret.as_ref()).is_none() {
                        return Err(anyhow!(
                            "{}: [vault] is allowed on an unsigned repo (--allow-unsigned-vault-config) \
                            but `vault.tls_ca_secret` is not set. CA pinning is mandatory when the \
                            vault config is not signature-protected. Set `vault.tls_ca_secret` to the \
                            name of a sealed secret holding the CA certificate.",
                            path.as_ref().display()
                        ));
                    }
                    log::warn!(
                        "{}: [vault] config is unsigned (format_version=1, --allow-unsigned-vault-config \
                        in effect). The vault address and credentials are NOT signature-protected. \
                        Sign the repo with `sss envelope upgrade-sig` when possible.",
                        path.as_ref().display()
                    );
                }
                // Genuine legacy unsigned envelope; return as-is. Callers that mutate
                // the envelope must additionally call `require_signed(path)?`
                // (PQSIG-06 — see require_signed below).
            }
            2 => {
                // VCFG-03 / T-46-11: vault-presence gate MUST fire BEFORE signature verification.
                // A valid v2 signature does not cover vault fields; honouring [vault] under v2
                // reopens the credential-phishing gap (T-46-10). Reject with an actionable
                // upgrade-sig message regardless of whether the v2 signature verifies.
                if config.vault.is_some() {
                    return Err(anyhow!(
                        "{}: [vault] config is present but the envelope is signed under \
                        format_version=2 (the pre-vault signature context). A v2 signature \
                        does not cover the vault fields. Run `sss envelope upgrade-sig` to \
                        re-sign under the v3 context, which includes all [vault] fields.",
                        path.as_ref().display()
                    ));
                }
                // Signed envelope (no [vault]) — verify under the v2 context.
                #[cfg(feature = "hybrid")]
                crate::envelope_sig::verify_envelope_signature_v2(&config, path.as_ref())
                    .map_err(|e| anyhow!(
                        "{}: envelope signature verification failed: {}",
                        path.as_ref().display(),
                        e
                    ))?;
                // On non-hybrid builds, format_version=2 is unreadable: the loader
                // cannot prove the signature. Return an actionable error.
                #[cfg(not(feature = "hybrid"))]
                return Err(anyhow!(
                    "{}: format_version=2 requires the `hybrid` build feature; rebuild sss with `--features hybrid`",
                    path.as_ref().display()
                ));
            }
            3 => {
                // VCFG-03: verify under the v3 context (vault fields included in payload).
                #[cfg(feature = "hybrid")]
                crate::envelope_sig::verify_envelope_signature(&config, path.as_ref())
                    .map_err(|e| anyhow!(
                        "{}: envelope signature verification failed: {}",
                        path.as_ref().display(),
                        e
                    ))?;
                // On non-hybrid builds, format_version=3 is unreadable.
                #[cfg(not(feature = "hybrid"))]
                return Err(anyhow!(
                    "{}: format_version=3 requires the `hybrid` build feature; rebuild sss with `--features hybrid`",
                    path.as_ref().display()
                ));
            }
            other => {
                return Err(anyhow!(
                    "{}: envelope format_version {} is forward-incompatible (this binary supports 1, 2, and 3)",
                    path.as_ref().display(),
                    other
                ));
            }
        }

        // VCFG-06: refuse SSS_VAULT_ADDR override of a signed vault address (T-46-16).
        // Placement: AFTER the format_version dispatch (so the signature is verified for v3)
        // and BEFORE returning to the caller (so the signed address cannot be silently
        // repointed by the environment).
        // Presence-only read via var_os; no network call; no value echo.
        let has_signed_address = config.format_version >= 3
            && config.vault.as_ref().and_then(|v| v.address.as_ref()).is_some();
        if has_signed_address
            && std::env::var_os("SSS_VAULT_ADDR").is_some()
            && !allow_insecure_vault_addr_override
        {
            return Err(anyhow!(
                "{}: SSS_VAULT_ADDR is set but this repo carries a signed vault address \
                (format_version=3, vault.address is present). Overriding a signed address \
                via the environment is refused by default to prevent credential phishing. \
                Either unset SSS_VAULT_ADDR or pass `--allow-insecure-vault-addr-override` \
                to acknowledge the risk.",
                path.as_ref().display()
            ));
        }

        Ok(config)
    }

    /// Helper for PQSIG-06-mandated verbs: returns the D-10 byte-exact actionable
    /// error if the envelope is un-signed (`format_version=1`).
    ///
    /// CRITICAL: the error string is the D-10 verbatim text. NEG-04 in plan 19-05
    /// asserts this byte-for-byte via `assert_eq!`. Any whitespace or punctuation
    /// drift breaks the test contract.
    pub fn require_signed<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        if self.format_version == 1 {
            return Err(anyhow!(
                "{}: unsigned envelope (format_version=1); run `sss envelope upgrade-sig` to sign in place",
                path.as_ref().display()
            ));
        }
        Ok(())
    }

    /// Load project configuration from file **without** running the suite-version
    /// gate that `load_from_file` applies.
    ///
    /// Used exclusively by the sign-on-write sites that need to reload the
    /// on-disk state *after* `RotationManager` has already written the file
    /// (task 19-02-03).  At that point the file is valid TOML but the caller
    /// is about to add the signature and call `write_atomic`, so running the
    /// version gate a second time would be redundant and could fail if the
    /// gate itself changes in plan 19-03.
    ///
    /// **Do not use this for ordinary reads** — it intentionally skips the
    /// SUITE-04 guard that prevents stale binaries from silently corrupting
    /// v2 files.
    pub(crate) fn load_from_file_unverified<P: AsRef<Path>>(path: P) -> Result<Self> {
        // REM-32: reject .sss.toml larger than 1 MB before allocating the buffer.
        // NIT-01: best-effort metadata→read check (two syscalls); a local writer could
        // grow the file between stat and read_to_string. Accepted local-only Low risk.
        let meta = fs::metadata(&path).map_err(|e| {
            anyhow!(
                "Failed to stat project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;
        if meta.len() > crate::constants::MAX_TOML_SIZE as u64 {
            return Err(anyhow!(
                "{}: project config file too large ({} bytes, max {} bytes)",
                path.as_ref().display(),
                meta.len(),
                crate::constants::MAX_TOML_SIZE,
            ));
        }

        let content = fs::read_to_string(&path).map_err(|e| {
            anyhow!(
                "Failed to read project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })?;
        toml_helpers::parse_toml(&content, "project")
    }

    /// Save project configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml_helpers::serialize_toml(self, "project config")?;

        fs::write(&path, content).map_err(|e| {
            anyhow!(
                "Failed to write project config file {}: {}",
                path.as_ref().display(),
                e
            )
        })
    }

    /// Resolve the crypto `Suite` for this project from the `version` field.
    ///
    /// `"1.0"` → `Suite::Classic`, `"2.0"` → `Suite::Hybrid`.
    /// Unknown versions produce an actionable error.
    pub fn suite(&self) -> Result<Suite> {
        resolve_suite_from_version(&self.version)
    }

    /// Add a user to the project
    /// Requires the repository key to seal it for the new user
    pub fn add_user(
        &mut self,
        username: &str,
        user_public_key: &PublicKey,
        repository_key: &RepositoryKey,
    ) -> Result<()> {
        if self.users.contains_key(username) {
            return Err(anyhow!("User '{username}' already exists in project"));
        }

        // Seal via the project's declared suite — ClassicSuite for v1, HybridCryptoSuite for v2.
        let sealed_key = suite_for(self.suite()?)?.seal_repo_key(repository_key, user_public_key)?;

        let user_config = UserConfig {
            public: user_public_key.to_base64(),
            sealed_key,
            added: default_created(),
            hybrid_public: None,
            sig_ed448_public: None,
            sig_mldsa65_public: None,
        };

        self.users.insert(username.to_string(), user_config);
        Ok(())
    }

    /// Get the sealed repository key for a user
    pub fn get_sealed_key_for_user(&self, username: &str) -> Result<String> {
        let user_config = self
            .users
            .get(username)
            .ok_or_else(|| error_helpers::user_not_found_error(username))?;

        Ok(user_config.sealed_key.clone())
    }

    /// Remove a user from the project
    pub fn remove_user(&mut self, username: &str) -> Result<()> {
        if !self.users.contains_key(username) {
            return Err(anyhow!("User '{username}' not found in project"));
        }

        self.users.remove(username);
        Ok(())
    }

    /// Get the public key for a user
    pub fn get_user_public_key(&self, username: &str) -> Result<PublicKey> {
        let user_config = self
            .users
            .get(username)
            .ok_or_else(|| error_helpers::user_not_found_error(username))?;

        // Phase 2 Plan 02-02: decode via the repo's declared suite so a v2
        // config with hybrid-length `public` bytes lands as `PublicKey::Hybrid`
        // (only reachable with the `hybrid` feature compiled in).
        PublicKey::decode_base64_for_suite(&user_config.public, self.suite()?)
    }

    /// List all users in the project
    #[must_use] 
    pub fn list_users(&self) -> Vec<String> {
        let mut users: Vec<String> = self.users.keys().cloned().collect();
        users.sort();
        users
    }

    /// Find username by matching public key
    #[must_use] 
    pub fn find_user_by_public_key(&self, public_key: &PublicKey) -> Option<String> {
        let public_key_str = public_key.to_base64();
        for (username, user_config) in &self.users {
            if user_config.public == public_key_str {
                return Some(username.clone());
            }
        }
        None
    }

    /// Check if this is an old-format config with a raw key
    #[must_use] 
    pub fn is_legacy_format(&self) -> bool {
        self.key.is_some()
    }

    /// Get the legacy key (for migration)
    #[must_use] 
    pub fn legacy_key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// Remove the legacy key (after migration)
    pub fn remove_legacy_key(&mut self) {
        self.key = None;
    }

    /// Check if the project has any users
    #[must_use] 
    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// Get all public keys in the project.
    ///
    /// Phase 2 Plan 02-02: decodes via `self.suite()?` so v2 configs produce
    /// `PublicKey::Hybrid` variants (feature-gated). Decoding once per call
    /// caches the suite lookup so a malformed `version` field is reported
    /// exactly once at the top of the iteration.
    pub fn get_all_public_keys(&self) -> Result<Vec<(String, PublicKey)>> {
        let suite = self.suite()?;
        let mut keys = Vec::new();

        for (username, user_config) in &self.users {
            let public_key = PublicKey::decode_base64_for_suite(&user_config.public, suite)?;
            keys.push((username.clone(), public_key));
        }

        Ok(keys)
    }

    /// Get ignore patterns as a vector of strings
    ///
    /// Returns the individual patterns from the ignore field as a vector,
    /// split by whitespace or commas. Useful for display and editing.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log build/ !important.log".to_string());
    /// let patterns = config.get_ignore_pattern_strings();
    /// assert_eq!(patterns, vec!["*.log", "build/", "!important.log"]);
    /// ```
    #[must_use] 
    pub fn get_ignore_pattern_strings(&self) -> Vec<String> {
        match &self.ignore {
            Some(s) => s
                .split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .map(std::string::ToString::to_string)
                .collect(),
            None => vec![],
        }
    }

    /// Set ignore patterns from a vector of pattern strings
    ///
    /// Joins the patterns with spaces into a single string for storage.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// let mut config = ProjectConfig::default();
    /// config.set_ignore_patterns(vec!["*.log".to_string(), "build/".to_string()]);
    /// assert_eq!(config.ignore, Some("*.log build/".to_string()));
    /// ```
    // Why: Vec ownership consumed for API simplicity; callers typically build the vector at the call site and have no further use for it.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_ignore_patterns(&mut self, patterns: Vec<String>) {
        if patterns.is_empty() {
            self.ignore = None;
        } else {
            self.ignore = Some(patterns.join(" "));
        }
    }

    /// Parse ignore patterns from the config and build a `GlobSet`
    ///
    /// Supports gitignore-style patterns:
    /// - Simple patterns: `*.log`, `build/`, `temp*.txt`
    /// - Negation with `!`: `*.db !important.db` (matches all .db files except important.db)
    /// - Space or comma separated: `*.log build/ *.tmp`
    ///
    /// # Returns
    ///
    /// Returns (`GlobSet`, `GlobSet`) where:
    /// - First `GlobSet` contains positive patterns to match files to ignore
    /// - Second `GlobSet` contains negation patterns that override ignores (files matching these should NOT be ignored)
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log build/ !important.log".to_string());
    /// let (ignore_set, negations) = config.parse_ignore_patterns().unwrap();
    /// ```
    pub fn parse_ignore_patterns(&self) -> Result<(GlobSet, GlobSet)> {
        let Some(ignore_str) = &self.ignore else {
            return Ok((GlobSet::empty(), GlobSet::empty()));
        };

        let mut positive_builder = GlobSetBuilder::new();
        let mut negative_builder = GlobSetBuilder::new();

        // Split by whitespace or commas
        let patterns: Vec<&str> = ignore_str
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .collect();

        for pattern in patterns {
            if let Some(neg_pattern) = pattern.strip_prefix('!') {
                // Negation pattern - files matching this should NOT be ignored
                if !neg_pattern.is_empty() {
                    // Transform directory patterns: "dir/" -> "dir/**"
                    let glob_pattern = if neg_pattern.ends_with('/') {
                        format!("{neg_pattern}**")
                    } else {
                        neg_pattern.to_string()
                    };

                    let glob = Glob::new(&glob_pattern).map_err(|e| {
                        anyhow!("Invalid negation ignore pattern '{neg_pattern}': {e}")
                    })?;
                    negative_builder.add(glob);
                }
            } else {
                // Positive pattern - files matching this should be ignored
                // Transform directory patterns: "dir/" -> "dir/**"
                let glob_pattern = if pattern.ends_with('/') {
                    format!("{pattern}**")
                } else {
                    pattern.to_string()
                };

                let glob =
                    Glob::new(&glob_pattern).map_err(|e| anyhow!("Invalid ignore pattern '{pattern}': {e}"))?;
                positive_builder.add(glob);
            }
        }

        let positive_set = positive_builder
            .build()
            .map_err(|e| anyhow!("Failed to build ignore GlobSet: {e}"))?;
        let negative_set = negative_builder
            .build()
            .map_err(|e| anyhow!("Failed to build negation GlobSet: {e}"))?;

        Ok((positive_set, negative_set))
    }

    /// Check if a file path should be ignored based on the ignore patterns
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to check (can be relative or absolute)
    ///
    /// # Returns
    ///
    /// Returns `true` if the file should be ignored, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// # use sss::project::ProjectConfig;
    /// # use std::path::Path;
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log !important.log".to_string());
    ///
    /// assert!(config.should_ignore(Path::new("debug.log")).unwrap());
    /// assert!(!config.should_ignore(Path::new("important.log")).unwrap());
    /// assert!(!config.should_ignore(Path::new("data.txt")).unwrap());
    /// ```
    pub fn should_ignore(&self, path: &Path) -> Result<bool> {
        let (positive_set, negative_set) = self.parse_ignore_patterns()?;

        // If no patterns, don't ignore
        if positive_set.is_empty() {
            return Ok(false);
        }

        // Check if path matches any ignore pattern (try both full path and filename)
        let matches_ignore = positive_set.is_match(path)
            || path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| positive_set.is_match(name));

        // If doesn't match ignore patterns, don't ignore
        if !matches_ignore {
            return Ok(false);
        }

        // Check if path matches any negation pattern (should NOT be ignored)
        if !negative_set.is_empty() {
            let matches_negation = negative_set.is_match(path)
                || path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| negative_set.is_match(name));

            if matches_negation {
                return Ok(false); // Negation overrides ignore
            }
        }

        // Matches ignore and doesn't match negation
        Ok(true)
    }

    /// Validate the project configuration
    pub fn validate(&self) -> Result<()> {
        let suite = self.suite()?;
        // Validate all user configurations
        for (username, user_config) in &self.users {
            // Validate sealed key is valid base64
            use base64::Engine;
            base64::prelude::BASE64_STANDARD
                .decode(&user_config.sealed_key)
                .map_err(|e| anyhow!("Invalid base64 sealed key for user '{username}': {e}"))?;

            // Validate public key — always classic (32-byte NaCl) regardless of
            // suite version.  The `public` field is the classic identity anchor used
            // by find_user_by_public_key; it never changes during migration.
            // The hybrid public key lives in `hybrid_public` and is validated separately.
            // Using decode_base64_for_suite here with Suite::Hybrid would incorrectly
            // reject classic-length keys in v2 configs as "downgrade attempts".
            let _ = suite; // suite validated above via self.suite()
            PublicKey::from_base64(&user_config.public)
                .map_err(|e| anyhow!("Invalid public key for user '{username}': {e}"))?;
        }

        // Warn about legacy format
        if self.is_legacy_format() {
            eprintln!("WARNING: Project config contains legacy private key. Run 'sss migrate' to upgrade.");
        }

        Ok(())
    }

    /// Update rotation metadata after a key rotation
    pub fn update_rotation_metadata(&mut self, reason: String) {
        self.rotation.last_rotation = Some(Utc::now().to_rfc3339());
        self.rotation.rotation_count += 1;
        self.rotation.last_rotation_reason = Some(reason);
    }

    /// Get rotation history information
    #[must_use] 
    pub fn get_rotation_info(&self) -> String {
        if self.rotation.rotation_count == 0 {
            "No key rotations performed".to_string()
        } else {
            let last_rotation = self.rotation.last_rotation.as_deref().unwrap_or("unknown");
            let reason = self
                .rotation
                .last_rotation_reason
                .as_deref()
                .unwrap_or("unspecified");

            format!(
                "Rotations: {} | Last: {} | Reason: {}",
                self.rotation.rotation_count, last_rotation, reason
            )
        }
    }

    /// Get the secrets filename (defaults to "secrets" if not configured)
    #[must_use] 
    pub fn get_secrets_filename(&self) -> &str {
        self.secrets_filename.as_deref().unwrap_or("secrets")
    }

    /// Set the secrets filename
    pub fn set_secrets_filename(&mut self, filename: String) {
        self.secrets_filename = Some(filename);
    }

    /// Clear the secrets filename (use default)
    pub fn clear_secrets_filename(&mut self) {
        self.secrets_filename = None;
    }

    /// Get the ignore patterns as a single string
    #[must_use] 
    pub fn get_ignore_patterns(&self) -> Option<&str> {
        self.ignore.as_deref()
    }

    /// Clear the ignore patterns
    pub fn clear_ignore_patterns(&mut self) {
        self.ignore = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use tempfile::NamedTempFile;

    #[test]
    fn test_project_config_creation() {
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

        assert_eq!(config.users.len(), 1);
        assert!(config.users.contains_key("alice"));
        assert!(!config.is_legacy_format());
    }

    #[test]
    fn test_add_remove_users() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();

        // We need a repository key to add users - let's get it from the sealed key for alice
        // For testing, we'll create a dummy repository key
        let repository_key = RepositoryKey::new();

        // Add second user
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();
        assert_eq!(config.users.len(), 2);
        assert!(config.users.contains_key("bob"));

        // Cannot add duplicate user
        let result = config.add_user("alice", &keypair1.public_key(), &repository_key);
        assert!(result.is_err());

        // Remove user
        config.remove_user("bob").unwrap();
        assert_eq!(config.users.len(), 1);
        assert!(!config.users.contains_key("bob"));

        // Cannot remove non-existent user
        let result = config.remove_user("charlie");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file_roundtrip() {
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        config.save_to_file(temp_file.path()).unwrap();

        let loaded_config = ProjectConfig::load_from_file(temp_file.path()).unwrap();
        assert_eq!(loaded_config.users.len(), config.users.len());
        assert!(loaded_config.users.contains_key("alice"));
    }

    #[test]
    fn test_legacy_format_detection() {
        let mut config = ProjectConfig::default();
        assert!(!config.is_legacy_format());

        config.key = Some("base64key".to_string());
        assert!(config.is_legacy_format());
        assert_eq!(config.legacy_key(), Some("base64key"));

        config.remove_legacy_key();
        assert!(!config.is_legacy_format());
        assert_eq!(config.legacy_key(), None);
    }

    #[test]
    fn test_config_validation() {
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

        // Valid config should pass
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_format() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();

        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();

        let toml_output = toml::to_string_pretty(&config).unwrap();
        println!("Generated TOML:\n{toml_output}");

        // Should have user sections with key and public fields
        assert!(toml_output.contains("[alice]"));
        assert!(toml_output.contains("[bob]"));
        assert!(toml_output.contains("key ="));
        assert!(toml_output.contains("public ="));
    }

    #[test]
    fn test_get_all_public_keys() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();

        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();

        let keys = config.get_all_public_keys().unwrap();
        assert_eq!(keys.len(), 2);

        let usernames: Vec<&str> = keys.iter().map(|(name, _)| name.as_str()).collect();
        assert!(usernames.contains(&"alice"));
        assert!(usernames.contains(&"bob"));
    }

    // --- SUITE-02 / SUITE-04: .sss.toml version gate ---

    #[test]
    fn test_load_from_file_accepts_v1() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "1.0"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        assert!(ProjectConfig::load_from_file(tmp.path()).is_ok());
    }

    #[test]
    fn test_load_from_file_defaults_missing_version_to_v1() {
        // No `version` field → serde default → "1.0" → loads successfully.
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let cfg = ProjectConfig::load_from_file(tmp.path()).unwrap();
        assert_eq!(cfg.version, "1.0");
    }

    #[test]
    fn test_load_from_file_rejects_unknown_version() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "99.99"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let err = ProjectConfig::load_from_file(tmp.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown .sss.toml version"), "got: {err}");
        assert!(err.contains("99.99"), "got: {err}");
    }

    #[test]
    fn test_project_config_suite_returns_classic_for_v1() {
        let cfg = ProjectConfig { version: "1.0".to_string(), ..Default::default() };
        assert_eq!(cfg.suite().unwrap(), Suite::Classic);
    }

    #[test]
    fn test_project_config_suite_returns_error_for_unknown() {
        let cfg = ProjectConfig { version: "3.14".to_string(), ..Default::default() };
        let err = cfg.suite().unwrap_err().to_string();
        assert!(err.contains("unknown .sss.toml version"));
    }

    // --- SUITE-01 Plan 01-04: ClassicSuite round-trip via production path ---

    #[test]
    fn test_project_new_seals_via_classic_suite_round_trip() {
        // ProjectConfig::new now seals via ClassicSuite (the CryptoSuite trait);
        // this test proves the trait-based open path reads what the trait-based
        // seal path writes, on the wire-format stored in .sss.toml.
        use crate::crypto::CryptoSuite;
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();
        let sealed = config.get_sealed_key_for_user("alice").unwrap();

        let suite = ClassicSuite;
        let opened = suite.open_repo_key(&sealed, &keypair).unwrap();
        // Round-trip check: re-seal with the same key, must be openable.
        let resealed = suite.seal_repo_key(&opened, &keypair.public_key()).unwrap();
        let reopened = suite.open_repo_key(&resealed, &keypair).unwrap();
        assert_eq!(opened.to_base64(), reopened.to_base64());
    }

    // --- Phase 2 Plan 02-02: suite-aware public-key decode path ---

    #[test]
    fn test_get_user_public_key_decodes_via_suite_to_classic_variant_for_v1_config() {
        use crate::crypto::PublicKey;
        let keypair = KeyPair::generate().unwrap();
        let config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();
        // Default ProjectConfig::new stamps version = "1.0" so the decoder
        // routes through Suite::Classic and yields PublicKey::Classic(..)
        let pk = config.get_user_public_key("alice").unwrap();
        match pk {
            PublicKey::Classic(_) => (),
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(_) => {
                panic!("v1.0 config must decode to PublicKey::Classic");
            }
        }
    }

    #[test]
    fn test_get_all_public_keys_routes_through_suite() {
        use crate::crypto::PublicKey;
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let mut config = ProjectConfig::new("alice", &keypair1.public_key()).unwrap();
        let repository_key = RepositoryKey::new();
        config
            .add_user("bob", &keypair2.public_key(), &repository_key)
            .unwrap();

        let keys = config.get_all_public_keys().unwrap();
        assert_eq!(keys.len(), 2);
        for (_, pk) in keys {
            match pk {
                PublicKey::Classic(_) => (),
                #[cfg(feature = "hybrid")]
                PublicKey::Hybrid(_) => {
                    panic!("v1.0 config must decode every public key to PublicKey::Classic");
                }
            }
        }
    }

    // --- Plan 04-01: hybrid_public field + v2 suite gate ---

    #[test]
    fn test_load_from_file_accepts_v2() {
        // After Plan 04-01 gate change, version = "2.0" must load as Ok.
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            r#"version = "2.0"
created = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let cfg = ProjectConfig::load_from_file(tmp.path())
            .expect("v2.0 file must load without error after gate change");
        assert_eq!(
            cfg.suite().unwrap(),
            Suite::Hybrid,
            "v2.0 must resolve to Suite::Hybrid"
        );
    }

    #[test]
    fn test_project_config_suite_returns_hybrid_for_v2() {
        let cfg = ProjectConfig { version: "2.0".to_string(), ..Default::default() };
        assert_eq!(
            cfg.suite().unwrap(),
            Suite::Hybrid,
            "suite() must return Suite::Hybrid for version = \"2.0\""
        );
    }

    // --- Phase 19 Plan 19-01-01: format_version + [envelope.sig] round-trip ---

    #[test]
    #[cfg(feature = "hybrid")]
    fn envelope_round_trip() {
        let keypair = KeyPair::generate().unwrap();
        let mut config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();

        // Promote to format_version=2 and attach an envelope sig table.
        config.format_version = 2;
        config.envelope = Some(EnvelopeMeta {
            sig: Some(EnvelopeSig {
                ed448: "AQIDBA==".to_string(),    // 4-byte placeholder, base64
                mldsa65: "BQYHCA==".to_string(),  // 4-byte placeholder, base64
            }),
        });

        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("format_version = 2"), "missing format_version line:\n{toml}");
        assert!(toml.contains("[envelope.sig]"), "missing [envelope.sig] header:\n{toml}");

        let round: ProjectConfig = toml::from_str(&toml).unwrap();
        assert_eq!(round.format_version, 2);
        assert!(round.envelope.is_some());
        let sig = round.envelope.unwrap().sig.unwrap();
        assert_eq!(sig.ed448, "AQIDBA==");
        assert_eq!(sig.mldsa65, "BQYHCA==");

        // Legacy v1 (no format_version, no envelope) still parses with defaults.
        let legacy_toml = r#"version = "1.0"
created = "2026-05-09T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-05-09T00:00:00Z"
"#;
        let legacy: ProjectConfig = toml::from_str(legacy_toml).unwrap();
        assert_eq!(legacy.format_version, 1, "missing format_version must default to 1 (D-09)");
        assert!(legacy.envelope.is_none());
    }

    // --- Phase 19 Plan 19-01-02: [envelope.sig] table emission ---

    #[test]
    #[cfg(feature = "hybrid")]
    fn envelope_meta_serialises() {
        let keypair = KeyPair::generate().unwrap();
        let mut config = ProjectConfig::new("alice", &keypair.public_key()).unwrap();
        config.format_version = 2;
        config.envelope = Some(EnvelopeMeta {
            sig: Some(EnvelopeSig {
                ed448: "3q2+7w==".to_string(),    // base64 for [0xDE, 0xAD, 0xBE, 0xEF]
                mldsa65: "yv4=".to_string(),      // base64 for [0xCA, 0xFE]
            }),
        });

        let toml = toml::to_string(&config).unwrap();
        // Must produce the nested table header.
        assert!(
            toml.contains("[envelope.sig]"),
            "missing [envelope.sig] table header in:\n{toml}"
        );
        // Both base64 string fields must appear under the table.
        assert!(toml.contains("ed448 = \"3q2+7w==\""), "missing ed448 field in:\n{toml}");
        assert!(toml.contains("mldsa65 = \"yv4=\""), "missing mldsa65 field in:\n{toml}");

        // Round-trip with the base64 strings preserved exactly.
        let round: ProjectConfig = toml::from_str(&toml).unwrap();
        let sig = round.envelope.unwrap().sig.unwrap();
        assert_eq!(sig.ed448, "3q2+7w==");
        assert_eq!(sig.mldsa65, "yv4=");

        // Negative: when sig is None the table header is NOT emitted.
        let mut empty_cfg = ProjectConfig::new("bob", &keypair.public_key()).unwrap();
        empty_cfg.envelope = None;
        let empty_toml = toml::to_string(&empty_cfg).unwrap();
        assert!(
            !empty_toml.contains("[envelope.sig]"),
            "[envelope.sig] must be skipped when envelope = None, got:\n{empty_toml}"
        );
    }

    // --- Phase 19 Plan 19-01-03: UserConfig per-user sig pubkeys skip-if-none ---

    #[test]
    fn user_sig_pubkey_skip_if_none() {
        let user_none = UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: None,
            sig_mldsa65_public: None,
        };
        let toml = toml::to_string(&user_none).unwrap();
        #[cfg(feature = "hybrid")]
        {
            assert!(
                !toml.contains("sig_ed448_public"),
                "None Ed448 sig pubkey must be skipped, got:\n{toml}"
            );
            assert!(
                !toml.contains("sig_mldsa65_public"),
                "None ML-DSA-65 sig pubkey must be skipped, got:\n{toml}"
            );
        }

        // Round-trip preserves None on read-back.
        let round_none: UserConfig = toml::from_str(&toml).unwrap();
        #[cfg(feature = "hybrid")]
        {
            assert!(round_none.sig_ed448_public.is_none());
            assert!(round_none.sig_mldsa65_public.is_none());
        }
        let _ = round_none;

        // With Some(_), keys appear and round-trip exactly.
        let user_some = UserConfig {
            public: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            sealed_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            added: "2026-05-09T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: Some("ZWQ0NDhfcGtfaGVyZQ==".to_string()),
            sig_mldsa65_public: Some("bWxkc2FfcGtfaGVyZQ==".to_string()),
        };
        let toml_some = toml::to_string(&user_some).unwrap();
        #[cfg(feature = "hybrid")]
        {
            assert!(toml_some.contains("sig_ed448_public = \"ZWQ0NDhfcGtfaGVyZQ==\""),
                "missing sig_ed448_public in:\n{toml_some}");
            assert!(toml_some.contains("sig_mldsa65_public = \"bWxkc2FfcGtfaGVyZQ==\""),
                "missing sig_mldsa65_public in:\n{toml_some}");
        }

        let round_some: UserConfig = toml::from_str(&toml_some).unwrap();
        #[cfg(feature = "hybrid")]
        {
            assert_eq!(round_some.sig_ed448_public.as_deref(), Some("ZWQ0NDhfcGtfaGVyZQ=="));
            assert_eq!(round_some.sig_mldsa65_public.as_deref(), Some("bWxkc2FfcGtfaGVyZQ=="));
        }
        let _ = round_some;
    }

    #[test]
    fn test_userconfig_hybrid_public_roundtrips() {
        // A v1-format file (no hybrid_public) deserialises with hybrid_public = None.
        let tmp_none = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp_none.path(),
            r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
"#,
        )
        .unwrap();
        let cfg_none = ProjectConfig::load_from_file(tmp_none.path()).unwrap();
        let alice_none = cfg_none.users.get("alice").unwrap();
        #[cfg(feature = "hybrid")]
        assert!(
            alice_none.hybrid_public.is_none(),
            "hybrid_public must be None when absent in TOML"
        );
        // On non-hybrid builds the field is serde(skip) so it won't appear;
        // we just check the user loaded correctly.
        let _ = alice_none;

        // A file with hybrid_public = "abc123" deserialises correctly.
        let tmp_some = NamedTempFile::new().unwrap();
        std::fs::write(
            tmp_some.path(),
            r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
hybrid_public = "abc123"
"#,
        )
        .unwrap();
        let cfg_some = ProjectConfig::load_from_file(tmp_some.path()).unwrap();
        let alice_some = cfg_some.users.get("alice").unwrap();
        #[cfg(feature = "hybrid")]
        assert_eq!(
            alice_some.hybrid_public.as_deref(),
            Some("abc123"),
            "hybrid_public must round-trip correctly"
        );
        let _ = alice_some;
    }

    #[test]
    fn test_load_from_file_rejects_oversized_toml() {
        // Write a file larger than MAX_TOML_SIZE (1 MB).
        let tmp = NamedTempFile::new().unwrap();
        // 1 MB + 1 byte — exceeds the cap.
        let oversized: Vec<u8> = vec![b'#'; crate::constants::MAX_TOML_SIZE + 1];
        std::fs::write(tmp.path(), &oversized).unwrap();
        let result = ProjectConfig::load_from_file(tmp.path());
        assert!(result.is_err(), "load_from_file must reject a file > 1 MB");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("too large"),
            "Error message must say 'too large', got: {msg}"
        );
    }

    #[test]
    fn test_load_from_file_unverified_rejects_oversized_toml() {
        // Same check on the unverified path (used by rotation.rs).
        let tmp = NamedTempFile::new().unwrap();
        let oversized: Vec<u8> = vec![b'#'; crate::constants::MAX_TOML_SIZE + 1];
        std::fs::write(tmp.path(), &oversized).unwrap();
        let result = ProjectConfig::load_from_file_unverified(tmp.path());
        assert!(
            result.is_err(),
            "load_from_file_unverified must reject a file > 1 MB"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("too large"),
            "Error message must say 'too large', got: {msg}"
        );
    }

    // ── VaultConfig / ProjectConfig.vault parsing ────────────────────────────

    #[test]
    fn test_vault_field_absent_yields_none() {
        // A classic-style TOML with no [vault] table must parse with vault = None.
        let toml_str = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"
"#;
        let cfg: ProjectConfig = toml::from_str(toml_str).expect("parse must succeed");
        assert!(
            cfg.vault.is_none(),
            "vault must be None when [vault] table is absent"
        );
    }

    #[test]
    fn test_vault_config_round_trips() {
        // A TOML with a [vault] section deserialises correctly and re-serialises
        // back to equivalent TOML (round-trip stability, determinism guard).
        let toml_str = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"

[vault]
address = "https://vault.example.com:8200"
namespace = "myns"
default_binding = "kv"

[vault.bindings.kv]
mount = "secret"
kv_version = 2
default_field = "value"

[vault.auth]
method = "approle"
role_id = "my-role-id"
"#;
        let cfg: ProjectConfig = toml::from_str(toml_str).expect("parse must succeed");
        let v = cfg.vault.as_ref().expect("vault must be Some");
        assert_eq!(v.address.as_deref(), Some("https://vault.example.com:8200"));
        assert_eq!(v.namespace.as_deref(), Some("myns"));
        assert_eq!(v.default_binding.as_deref(), Some("kv"));
        let binding = v.bindings.get("kv").expect("binding 'kv' must be present");
        assert_eq!(binding.mount.as_deref(), Some("secret"));
        assert_eq!(binding.kv_version, Some(2));
        assert_eq!(binding.default_field.as_deref(), Some("value"));
        let auth = v.auth.as_ref().expect("auth must be Some");
        assert_eq!(auth.method.as_deref(), Some("approle"));
        assert_eq!(auth.role_id.as_deref(), Some("my-role-id"));
        // Re-serialise and re-parse — must be stable (determinism via BTreeMap).
        let re_serialised = toml::to_string(&cfg).expect("serialise must succeed");
        let cfg2: ProjectConfig = toml::from_str(&re_serialised).expect("re-parse must succeed");
        let v2 = cfg2.vault.as_ref().expect("vault must survive round-trip");
        assert_eq!(v2.address, v.address);
        assert_eq!(v2.namespace, v.namespace);
        assert_eq!(v2.bindings.len(), v.bindings.len());
    }

    #[test]
    fn test_vault_bindings_are_btree_sorted() {
        // bindings must be BTreeMap so iteration order is deterministic (payload
        // encoding is load-bearing — byte-stable canonical form).
        let toml_str = r#"version = "1.0"
created = "2026-01-01T00:00:00Z"

[alice]
public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
sealed_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
added = "2026-01-01T00:00:00Z"

[vault]
[vault.bindings.zzz]
mount = "late"
[vault.bindings.aaa]
mount = "early"
[vault.bindings.mmm]
mount = "mid"
"#;
        let cfg: ProjectConfig = toml::from_str(toml_str).expect("parse must succeed");
        let vault = cfg.vault.as_ref().expect("vault must be Some");
        let keys: Vec<&str> = vault.bindings.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["aaa", "mmm", "zzz"], "bindings must be BTree-sorted");
    }
}
