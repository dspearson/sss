//! Blocking Vault HTTP+TLS client — KV v2 read, timeouts, TLS root selection.
//!
//! This module is only compiled when the `vault` Cargo feature is active.
//! It provides the transport floor for Phase 47 Vault integration:
//!
//! - [`VaultClient`] — blocking ureq HTTPS agent with connect/read timeouts
//!   and an explicit `RootCerts` trust store.
//! - [`KvReadOutcome`] — typed result of a KV v2 read distinguishing found,
//!   field-missing, soft-deleted, destroyed, and path-not-found.
//! - [`VaultHttpError`] — typed transport/HTTP error, never leaking tokens or
//!   response bodies in output (T-47-01 / PITFALLS Pitfall 3).
//!
//! # TLS guarantee
//!
//! `build_root_certs(Some(pem))` trusts ONLY the supplied CA (via
//! `RootCerts::Specific`). `build_root_certs(None)` uses the bundled
//! `RootCerts::WebPki`. There is NO code path that calls
//! `TlsConfigBuilder::disable_verification(true)` or any equivalent
//! (T-47-02 / PITFALLS Pitfall 4).
//!
//! # Timeouts
//!
//! Per-request connect timeout 10s + recv-body timeout 30s (PITFALLS Pitfall 6).
//! An unresponsive endpoint returns `VaultHttpError::Timeout`, never hangs.
//!
//! # Response size cap
//!
//! Response bodies are hard-limited to 1 MiB before `serde_json` parsing,
//! preventing OOM on oversized/attacker-controlled responses (T-47-04).

use std::io::Read as _;
use std::time::Duration;

use thiserror::Error;
use ureq::http;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use zeroize::Zeroizing;

/// Maximum Vault response body size accepted before `serde_json` parsing.
///
/// Mirrors the existing TOML 1 MiB cap to prevent OOM on oversized responses
/// (T-47-04 / PITFALLS: "Vault response size cap").
pub const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Connect timeout for each Vault HTTP request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Recv-body timeout for each Vault HTTP request.
///
/// Used as the read/body-receive timeout per PITFALLS Pitfall 6 (connect 10s + read 30s).
const RECV_BODY_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Error types ─────────────────────────────────────────────────────────────

/// Typed error for Vault HTTP transport operations.
///
/// The `Display` impl intentionally carries only status codes and structural
/// metadata — never a Vault token, response body, or resolved secret value
/// (T-47-01 / PITFALLS Pitfall 3).
#[derive(Debug, Error)]
pub enum VaultHttpError {
    /// HTTP 403 — token is invalid, expired, or ACL-denied.
    #[error("vault: authentication denied (HTTP 403)")]
    AuthDenied,

    /// HTTP 503 — Vault is sealed or in standby.
    #[error("vault: service unavailable / sealed (HTTP 503)")]
    Sealed,

    /// HTTP 400 on token renew-self — the token is not renewable; the caller
    /// must re-login rather than renew (STACK.md §3.5). Carries no token value.
    #[error("vault: token is not renewable")]
    NotRenewable,

    /// `AppRole` login or token operation was rejected by Vault (e.g. invalid
    /// `role_id`/`secret_id`). Carries ONLY the HTTP status — never the
    /// credential or the response body (T-47-06 / PITFALLS Pitfall 3).
    #[error("vault: authentication failed (HTTP {0})")]
    AuthFailed(u16),

    /// Connect or body-recv timeout elapsed.
    #[error("vault: request timed out (connect={connect_secs}s, recv_body={recv_body_secs}s)")]
    Timeout {
        connect_secs: u64,
        recv_body_secs: u64,
    },

    /// TLS handshake or certificate verification failed.
    #[error("vault: TLS error — {detail}")]
    Tls { detail: String },

    /// Response body exceeded the 1 MiB cap.
    #[error("vault: response body exceeded {limit} byte cap", limit = MAX_RESPONSE_BODY_BYTES)]
    ResponseTooLarge,

    /// Non-2xx, non-403, non-503 HTTP status.
    #[error("vault: unexpected HTTP status {0}")]
    Http(u16),

    /// Network or transport error (DNS, TCP, etc.) — no token or body included.
    #[error("vault: transport error — {0}")]
    Transport(String),

    /// Response body was not valid JSON or the expected shape was absent.
    #[error("vault: parse error — {0}")]
    Parse(String),

    /// PEM-encoded CA bytes could not be parsed into a trust anchor.
    #[error("vault: invalid CA PEM — {0}")]
    InvalidCa(String),
}

// ─── KV v2 read outcome ───────────────────────────────────────────────────────

/// Typed outcome of a [`VaultClient::kv_read`] call.
///
/// Distinguishes all semantically distinct Vault KV v2 response states so that
/// callers can implement the exit-3/exit-4 failure model (CONTEXT decisions /
/// STACK.md §3.2).
#[derive(Debug)]
pub enum KvReadOutcome {
    /// The field was found and resolved successfully.
    Found {
        /// The resolved secret value, zeroised on drop.
        value: Zeroizing<String>,
        /// The KV v2 version number from `data.metadata.version`.
        version: u64,
    },
    /// The KV path existed but the requested field was absent from `data.data`.
    FieldMissing,
    /// HTTP 404 with an empty `errors` array — version exists but is soft-deleted.
    SoftDeleted,
    /// HTTP 404 with `errors` containing `"version was destroyed"`.
    Destroyed,
    /// HTTP 404 with a non-empty `errors` array not mentioning destruction —
    /// the path does not exist.
    PathNotFound,
}

// ─── TLS root cert builder ────────────────────────────────────────────────────

/// Build a `RootCerts` value for use in the ureq `TlsConfig`.
///
/// When `ca_pem` is `Some`, ONLY the PEM-encoded CA bytes are loaded as trust
/// anchors via `RootCerts::Specific` (pinned CA mode — T-47-02 / PITFALLS
/// Pitfall 4). The `WebPki` roots are never consulted as a fallback in this branch.
///
/// When `ca_pem` is `None`, `RootCerts::WebPki` (Mozilla bundle) is returned.
///
/// There is deliberately NO call to `TlsConfigBuilder::disable_verification(true)`
/// or any equivalent on any code path through this function.
pub fn build_root_certs(ca_pem: Option<&[u8]>) -> Result<RootCerts, VaultHttpError> {
    match ca_pem {
        Some(pem_bytes) => {
            // Parse PEM bytes into DER certificates using ureq's own PEM parser
            // (rustls_pki_types::pem). Collect all valid certs; fail if none found.
            let certs: Vec<Certificate<'static>> =
                ureq::tls::parse_pem(pem_bytes)
                    .filter_map(|item| {
                        item.ok().and_then(|pem_item| {
                            if let ureq::tls::PemItem::Certificate(cert) = pem_item {
                                Some(cert)
                            } else {
                                None
                            }
                        })
                    })
                    .collect();

            if certs.is_empty() {
                return Err(VaultHttpError::InvalidCa(
                    "no valid DER certificates found in supplied CA PEM".to_string(),
                ));
            }

            Ok(RootCerts::Specific(std::sync::Arc::new(certs)))
        }
        None => Ok(RootCerts::WebPki),
    }
}

// ─── KV v2 response discriminator ────────────────────────────────────────────

/// Map a Vault 404 `errors` array to the correct [`KvReadOutcome`] variant.
///
/// Vault KV v2 semantics (STACK.md §3.2):
/// - `404` + empty `errors` → soft-deleted version.
/// - `404` + `errors` containing `"version was destroyed"` → destroyed.
/// - `404` + non-empty `errors` not mentioning destruction → path not found.
#[must_use]
pub fn discriminate_404(errors: &[serde_json::Value]) -> KvReadOutcome {
    if errors.is_empty() {
        return KvReadOutcome::SoftDeleted;
    }
    let destroyed = errors.iter().any(|e| {
        e.as_str()
            .is_some_and(|s| s.contains("version was destroyed"))
    });
    if destroyed {
        KvReadOutcome::Destroyed
    } else {
        KvReadOutcome::PathNotFound
    }
}

// ─── VaultClient ─────────────────────────────────────────────────────────────

/// Blocking Vault HTTPS client.
///
/// Constructed once per render invocation; holds the ureq `Agent` (which owns
/// the TLS config and connection pool). The `address` field MUST be validated
/// by `validate_vault_address` before constructing a `VaultClient`.
pub struct VaultClient {
    /// The Vault server base URL (e.g. `https://vault.example.com:8200`).
    address: String,
    /// Optional namespace header value (`X-Vault-Namespace`).
    namespace: Option<String>,
    /// The ureq blocking agent with TLS + timeouts configured.
    ///
    /// `http_status_as_error(false)` is set so that 4xx/5xx responses are
    /// returned as `Ok(Response)`, letting us read the error body for 404
    /// discrimination (soft-delete vs destroyed vs path-not-found).
    agent: ureq::Agent,
}

impl VaultClient {
    /// Construct a new `VaultClient`.
    ///
    /// # Parameters
    ///
    /// - `address` — Vault base URL; MUST have been validated by
    ///   `validate_vault_address` before calling this function.
    /// - `namespace` — optional HCP/Enterprise namespace string.
    /// - `ca_pem` — optional PEM-encoded CA bytes. When `Some`, the client
    ///   trusts ONLY that CA (pinned mode). When `None`, `WebPki` roots are used.
    ///
    /// # Errors
    ///
    /// Returns `VaultHttpError::InvalidCa` if `ca_pem` cannot be parsed.
    pub fn new(
        address: impl Into<String>,
        namespace: Option<String>,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, VaultHttpError> {
        let root_certs = build_root_certs(ca_pem)?;

        let tls_config = TlsConfig::builder()
            .root_certs(root_certs)
            // disable_verification is deliberately NOT called; default is false.
            .build();

        let config = ureq::Agent::config_builder()
            .tls_config(tls_config)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_recv_body(Some(RECV_BODY_TIMEOUT))
            // Return all HTTP responses as Ok(Response) so we can read error
            // bodies for the 404 discrimination logic (soft-deleted vs destroyed).
            .http_status_as_error(false)
            .build();

        let agent = config.new_agent();

        Ok(Self {
            address: address.into(),
            namespace,
            agent,
        })
    }

    /// The Vault server base URL this client was constructed with.
    ///
    /// Exposed so the auth layer can construct endpoint paths without holding a
    /// second copy of the address. Carries no secret material.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Send an authenticated `GET {address}{path}` and return `(status, body)`.
    ///
    /// `path` is an absolute Vault API path beginning with `/v1/…` (e.g.
    /// `/v1/auth/token/lookup-self`). The optional `token` is placed in
    /// `X-Vault-Token`; it is NEVER logged or echoed into any error
    /// (T-47-01 / PITFALLS Pitfall 3). The body is read under the 1 MiB cap and
    /// returned as a parsed `serde_json::Value` so the auth layer can extract
    /// fields without re-implementing the transport.
    ///
    /// # Errors
    ///
    /// See [`VaultHttpError`]. A 403 maps to [`VaultHttpError::AuthDenied`], a
    /// 503 to [`VaultHttpError::Sealed`]; other non-2xx statuses are returned as
    /// `(status, body)` so the caller can inspect the typed `errors` array.
    pub fn get_json(
        &self,
        path: &str,
        token: Option<&Zeroizing<String>>,
    ) -> Result<(u16, serde_json::Value), VaultHttpError> {
        let url = format!("{}{}", self.address, path);

        let mut req = self.agent.get(&url);
        if let Some(tok) = token {
            req = req.header("X-Vault-Token", tok.as_str());
        }
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let response = req.call().map_err(|e| classify_ureq_error(&e))?;
        Self::handle_json_response(response)
    }

    /// Send `POST {address}{path}` with a JSON `body` and return `(status, body)`.
    ///
    /// `body` is serialised by the caller (so secret material can be built from a
    /// `Zeroizing` slice and dropped immediately). The optional `token` is placed
    /// in `X-Vault-Token` and is NEVER logged or echoed into an error. The
    /// request body bytes are NOT retained after the call returns.
    ///
    /// # Errors
    ///
    /// See [`VaultHttpError`]. A 403 maps to [`VaultHttpError::AuthDenied`], a
    /// 503 to [`VaultHttpError::Sealed`]; other non-2xx statuses are returned as
    /// `(status, body)` so the caller can inspect the typed `errors` array
    /// (e.g. an `AppRole` `invalid role_id or secret_id`).
    pub fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
        token: Option<&Zeroizing<String>>,
    ) -> Result<(u16, serde_json::Value), VaultHttpError> {
        let url = format!("{}{}", self.address, path);

        // Serialise once; `serde_json::to_vec` produces the request bytes. The
        // body is dropped at the end of this function — never retained.
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| VaultHttpError::Parse(format!("request body encode failed: {e}")))?;

        let mut req = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json");
        if let Some(tok) = token {
            req = req.header("X-Vault-Token", tok.as_str());
        }
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let response = req
            .send(&body_bytes[..])
            .map_err(|e| classify_ureq_error(&e))?;
        Self::handle_json_response(response)
    }

    /// Shared response handler for [`get_json`] / [`post_json`].
    ///
    /// Reads the body under the 1 MiB cap, maps 403→`AuthDenied` and
    /// 503→`Sealed`, parses the body as JSON (empty body → JSON null), and
    /// returns `(status, value)` for every other status so the caller can
    /// inspect `errors`. The body is never echoed into an error message.
    fn handle_json_response(
        response: http::Response<ureq::Body>,
    ) -> Result<(u16, serde_json::Value), VaultHttpError> {
        let status = response.status().as_u16();
        match status {
            403 => Err(VaultHttpError::AuthDenied),
            503 => Err(VaultHttpError::Sealed),
            _ => {
                let body_bytes = read_capped(response)?;
                let value = if body_bytes.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&body_bytes).map_err(|e| {
                        VaultHttpError::Parse(format!("JSON decode failed: {e}"))
                    })?
                };
                Ok((status, value))
            }
        }
    }

    /// Perform a KV v2 read.
    ///
    /// Builds `GET {address}/v1/{mount}/data/{path}?version=N`, sets the
    /// required Vault headers, reads the body with the 1 MiB cap, parses it
    /// with `serde_json`, and returns a typed [`KvReadOutcome`].
    ///
    /// The `token` is placed in `X-Vault-Token`; it is NEVER logged or included
    /// in error messages (T-47-01 / PITFALLS Pitfall 3).
    ///
    /// # Errors
    ///
    /// See [`VaultHttpError`] variants for all failure modes.
    pub fn kv_read(
        &self,
        token: &Zeroizing<String>,
        mount: &str,
        path: &str,
        field: &str,
        version: Option<u64>,
    ) -> Result<KvReadOutcome, VaultHttpError> {
        // Build the URL.
        let base_url = format!("{}/v1/{}/data/{}", self.address, mount, path);
        let url = match version {
            Some(v) => format!("{base_url}?version={v}"),
            None => base_url,
        };

        // Build the request with required headers.
        // token MUST NOT appear in error messages or logs (T-47-01).
        let mut req = self
            .agent
            .get(&url)
            .header("X-Vault-Token", token.as_str());

        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }

        let response = req.call().map_err(|e| classify_ureq_error(&e))?;

        let status = response.status().as_u16();

        match status {
            200..=299 => {
                // Read with size cap before parse (T-47-04 / PITFALLS: response size cap).
                let body_bytes = read_capped(response)?;
                parse_kv_v2_body(&body_bytes, field)
            }
            403 => Err(VaultHttpError::AuthDenied),
            404 => {
                // Read body with cap to discriminate soft-deleted / destroyed / not-found.
                let body_bytes = read_capped(response).unwrap_or_default();
                Ok(parse_404_body(&body_bytes))
            }
            503 => Err(VaultHttpError::Sealed),
            other => Err(VaultHttpError::Http(other)),
        }
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Read from a `http::Response<ureq::Body>` up to `MAX_RESPONSE_BODY_BYTES`.
///
/// Returns `VaultHttpError::ResponseTooLarge` if the byte limit is exceeded
/// BEFORE `serde_json` parsing — preventing OOM on oversized responses (T-47-04).
fn read_capped(response: http::Response<ureq::Body>) -> Result<Vec<u8>, VaultHttpError> {
    let (_, body) = response.into_parts();
    let reader = body.into_reader();
    let mut buf = Vec::with_capacity(4096);
    // Read one byte beyond the cap to detect overflow.
    let cap = MAX_RESPONSE_BODY_BYTES + 1;
    // Why: cast is safe — cap fits in u64 (1 MiB + 1 << 64); no truncation.
    #[allow(clippy::cast_possible_truncation)]
    reader
        .take(cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
            {
                VaultHttpError::Timeout {
                    connect_secs: CONNECT_TIMEOUT.as_secs(),
                    recv_body_secs: RECV_BODY_TIMEOUT.as_secs(),
                }
            } else {
                VaultHttpError::Transport(format!("body read error: {}", e.kind()))
            }
        })?;

    if buf.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(VaultHttpError::ResponseTooLarge);
    }

    Ok(buf)
}

/// Parse a successful (HTTP 200) KV v2 response body.
///
/// Extracts `data.data.{field}` and `data.metadata.version` per STACK.md §3.2.
/// Returns `KvReadOutcome::FieldMissing` when the field key is absent from
/// `data.data` — never panics (T-47-05, clippy panic gate `deny`).
pub fn parse_kv_v2_body(body: &[u8], field: &str) -> Result<KvReadOutcome, VaultHttpError> {
    let root: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| VaultHttpError::Parse(format!("JSON decode failed: {e}")))?;

    // Navigate: root["data"]["data"][field]
    let data_data = root
        .get("data")
        .and_then(|d| d.get("data"))
        .ok_or_else(|| VaultHttpError::Parse("missing data.data in response".to_string()))?;

    let Some(field_value) = data_data.get(field) else {
        return Ok(KvReadOutcome::FieldMissing);
    };

    let value_str = field_value.as_str().ok_or_else(|| {
        VaultHttpError::Parse(format!("field `{field}` is not a string in data.data"))
    })?;

    // Navigate: root["data"]["metadata"]["version"]
    let version = root
        .get("data")
        .and_then(|d| d.get("metadata"))
        .and_then(|m| m.get("version"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            VaultHttpError::Parse("missing or invalid data.metadata.version".to_string())
        })?;

    Ok(KvReadOutcome::Found {
        value: Zeroizing::new(value_str.to_string()),
        version,
    })
}

/// Parse a 404 response body to discriminate soft-deleted / destroyed / not-found.
///
/// Falls back to `KvReadOutcome::PathNotFound` on any parse failure (defensive).
pub fn parse_404_body(body: &[u8]) -> KvReadOutcome {
    if body.is_empty() {
        return KvReadOutcome::PathNotFound;
    }
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(body) else {
        return KvReadOutcome::PathNotFound;
    };
    let errors: Vec<serde_json::Value> = root
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    discriminate_404(&errors)
}

/// Classify a `ureq::Error` into a `VaultHttpError`.
///
/// The error message carries only structural metadata — no token value,
/// URL, or response body (T-47-01 / PITFALLS Pitfall 3).
fn classify_ureq_error(e: &ureq::Error) -> VaultHttpError {
    match e {
        ureq::Error::Timeout(_) => VaultHttpError::Timeout {
            connect_secs: CONNECT_TIMEOUT.as_secs(),
            recv_body_secs: RECV_BODY_TIMEOUT.as_secs(),
        },
        ureq::Error::Tls(_) => VaultHttpError::Tls {
            detail: "TLS handshake or certificate verification failed".to_string(),
        },
        ureq::Error::Rustls(_) => VaultHttpError::Tls {
            detail: "rustls error during TLS negotiation".to_string(),
        },
        ureq::Error::HostNotFound => {
            VaultHttpError::Transport("host not found".to_string())
        }
        ureq::Error::ConnectionFailed => {
            VaultHttpError::Transport("connection failed".to_string())
        }
        ureq::Error::Io(io_err) => {
            if io_err.kind() == std::io::ErrorKind::TimedOut
                || io_err.kind() == std::io::ErrorKind::WouldBlock
            {
                VaultHttpError::Timeout {
                    connect_secs: CONNECT_TIMEOUT.as_secs(),
                    recv_body_secs: RECV_BODY_TIMEOUT.as_secs(),
                }
            } else {
                let msg = io_err.to_string().to_lowercase();
                if msg.contains("tls") || msg.contains("certificate") || msg.contains("handshake") {
                    VaultHttpError::Tls { detail: msg }
                } else {
                    VaultHttpError::Transport(format!("io: {}", io_err.kind()))
                }
            }
        }
        ureq::Error::StatusCode(code) => VaultHttpError::Http(*code),
        // All other variants — never include token or body content
        _ => VaultHttpError::Transport("transport error".to_string()),
    }
}
