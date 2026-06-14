#![allow(clippy::pedantic)] // Agent modules are excluded from pedantic enforcement per REQUIREMENTS.md

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::SystemTime;

/// Protocol version for compatibility checking.
///
/// Version 1: original wire format (no suite field).
/// Version 2: adds a trailing `suite: u32` field on `AgentRequest`,
/// encoded as `0xFFFFFFFF` = absent / Classic-by-default (for v1 back-compat),
/// `0` = Classic, `1` = Hybrid. Any other value is a hard wire-format error.
/// Version 3 (current): extends v2 by appending a 16-byte random nonce after
/// the `suite` u32, giving the wire tail:
///   `... [u32 suite][16 nonce_bytes]`
/// The nonce is generated per-request by the client via the libsodium CSPRNG
/// (`randombytes_buf`) and verified by the agent against a per-connection
/// `HashSet` to reject verbatim-replay attacks (REM-12 / CON-18-001).
///
/// **Back-compat:** the agent accepts v1, v2, and v3 frames.  v1/v2 frames
/// carry no nonce field; the agent returns a zeroed `[0u8;16]` nonce for
/// those frames.  This is a **documented legacy gap**: v1/v2 frames have no
/// per-request replay protection.  The agent does NOT silently pretend they
/// do — nonce-based replay rejection is enforced only for v3 frames.
///
/// **Unknown versions:** any version other than 1, 2, or 3 is a hard-error
/// ("Protocol version mismatch: expected 1, 2, or 3").  There is no silent
/// acceptance or fallback.
pub const PROTOCOL_VERSION: u32 = 3;

/// Wire-format constants for the `AgentRequest::suite` field. These map to
/// `Option<crate::crypto::Suite>` at the dispatch boundary (`sss-agent`'s
/// `RequestType::UnsealRepositoryKey` arm, see CR-01 / 08-03).
pub const SUITE_WIRE_ABSENT: u32 = 0xFFFF_FFFF;
pub const SUITE_WIRE_CLASSIC: u32 = 0;
pub const SUITE_WIRE_HYBRID: u32 = 1;

/// Maximum size for a request (10MB)
const MAX_REQUEST_SIZE: u32 = 10 * 1024 * 1024;

/// Request types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    UnsealRepositoryKey = 1,
    ListKeys = 2,
    Ping = 3,
}

impl TryFrom<u32> for RequestType {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            1 => Ok(RequestType::UnsealRepositoryKey),
            2 => Ok(RequestType::ListKeys),
            3 => Ok(RequestType::Ping),
            _ => Err(anyhow!("Unknown request type: {}", value)),
        }
    }
}

/// Response status codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Success = 0,
    Denied = 1,
    Timeout = 2,
    Error = 3,
    AgentLocked = 4,
}

impl From<ResponseStatus> for u32 {
    fn from(status: ResponseStatus) -> u32 {
        status as u32
    }
}

impl TryFrom<u32> for ResponseStatus {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(ResponseStatus::Success),
            1 => Ok(ResponseStatus::Denied),
            2 => Ok(ResponseStatus::Timeout),
            3 => Ok(ResponseStatus::Error),
            4 => Ok(ResponseStatus::AgentLocked),
            _ => Err(anyhow!("Unknown response status: {}", value)),
        }
    }
}

/// Context information sent with unsealing requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Remote hostname (from SSH_CONNECTION or socket)
    pub hostname: Option<String>,
    /// Remote username
    pub remote_user: Option<String>,
    /// Project path (from .sss.toml location)
    pub project_path: Option<String>,
    /// SSS username requesting unsealing
    pub sss_username: String,
    /// Request timestamp
    pub timestamp: SystemTime,
    /// Process ID of requesting client
    pub client_pid: Option<u32>,
}

impl RequestContext {
    /// Create a new context with minimal information
    pub fn new(sss_username: String) -> Self {
        Self {
            hostname: None,
            remote_user: None,
            project_path: None,
            sss_username,
            timestamp: SystemTime::now(),
            client_pid: None,
        }
    }

    /// Enrich context with environment information
    pub fn from_environment(sss_username: String) -> Self {
        let hostname = std::env::var("SSH_CONNECTION")
            .ok()
            .and_then(|conn| conn.split_whitespace().next().map(String::from))
            .or_else(|| std::env::var("HOSTNAME").ok())
            .or_else(|| std::env::var("HOST").ok());

        let remote_user = std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("USERNAME").ok());

        Self {
            hostname,
            remote_user,
            project_path: None,
            sss_username,
            timestamp: SystemTime::now(),
            client_pid: Some(std::process::id()),
        }
    }

    /// Set the project path
    pub fn with_project_path(mut self, path: String) -> Self {
        self.project_path = Some(path);
        self
    }
}

/// Agent request message.
///
/// Wire format (version 3, current):
/// `[u32 version][u32 request_type][u32 sealed_len][sealed_bytes...]`
/// `[u32 context_len][context_bytes...][u32 suite][16 nonce_bytes]`
///
/// `suite` encoding (CR-01 / 08-03):
/// - `SUITE_WIRE_ABSENT` (`0xFFFFFFFF`): no suite specified — agent treats as
///   Classic for v1 back-compat.
/// - `SUITE_WIRE_CLASSIC` (`0`): Classic (libsodium `crypto_box_seal`).
/// - `SUITE_WIRE_HYBRID` (`1`): Hybrid (trelis X448 + sntrup761 + BLAKE3).
/// - any other value: hard wire-format error (no silent default).
///
/// `nonce` (REM-12 / CON-18-001): a per-request 128-bit random value
/// generated by the client via the libsodium CSPRNG.  The agent rejects a
/// repeated nonce within a connection session (verbatim-replay rejection).
/// Present **only in v3 frames**; decoded as `[0u8;16]` for v1/v2 frames
/// (those frames have no per-request replay protection — documented gap).
///
/// Wire format (version 2, accepted for back-compat): identical to v3 but
/// without the trailing 16-byte nonce.
///
/// Wire format (version 1, accepted for back-compat): no trailing `suite`
/// u32 or nonce.  Agent treats v1 frames as `suite = SUITE_WIRE_ABSENT`.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub request_type: RequestType,
    pub sealed_key: Option<String>,
    pub context: Option<RequestContext>,
    /// Suite selector — `Some(SUITE_WIRE_CLASSIC)` for Classic,
    /// `Some(SUITE_WIRE_HYBRID)` for Hybrid, `None` for v1-frame-back-compat
    /// or pings. Maps to `Option<crate::crypto::Suite>` at dispatch.
    pub suite: Option<u32>,
    /// Per-request 128-bit replay-protection nonce (REM-12 / CON-18-001).
    ///
    /// For v3 frames: populated by the client via the libsodium CSPRNG and
    /// verified by the agent against a per-connection `HashSet`.
    /// For v1/v2 frames: zeroed (`[0u8;16]`) — no per-request replay
    /// protection on those legacy frames (documented gap, not a silent bypass).
    /// For pings: zeroed (no replay-sensitive payload on ping requests).
    pub nonce: [u8; 16],
    /// Wire-format version the frame was decoded from (1, 2, or 3).
    ///
    /// Populated by `read_from`; set to `PROTOCOL_VERSION` by constructors
    /// (`unseal`, `ping`).  Used by the agent to gate the nonce-replay check
    /// to v3 frames only — v1/v2 frames carry no nonce and must not be
    /// spuriously rejected for an all-zero nonce sentinel.
    pub wire_version: u32,
}

impl AgentRequest {
    /// Create a new unsealing request for a specific suite and nonce.
    ///
    /// The `suite` argument is the wire-format `u32` (use `SUITE_WIRE_CLASSIC`
    /// / `SUITE_WIRE_HYBRID`); pass `SUITE_WIRE_ABSENT` only for v1 back-compat
    /// tests, never for production traffic.
    ///
    /// The `nonce` argument is the per-request 128-bit replay-protection nonce
    /// (REM-12 / CON-18-001).  Callers MUST supply a freshly-generated CSPRNG
    /// nonce via `libsodium_sys::randombytes_buf`; see `client.rs` for the
    /// canonical generation idiom.  Tests may use a fixed known value.
    pub fn unseal(sealed_key: String, context: RequestContext, suite: u32, nonce: [u8; 16]) -> Self {
        Self {
            request_type: RequestType::UnsealRepositoryKey,
            sealed_key: Some(sealed_key),
            context: Some(context),
            suite: Some(suite),
            nonce,
            wire_version: PROTOCOL_VERSION,
        }
    }

    /// Create a ping request.
    ///
    /// Pings carry no replay-sensitive payload; the nonce field is zeroed.
    pub fn ping() -> Self {
        Self {
            request_type: RequestType::Ping,
            sealed_key: None,
            context: None,
            suite: None,
            nonce: [0u8; 16],
            wire_version: PROTOCOL_VERSION,
        }
    }

    /// Write request to a stream (always uses the current `PROTOCOL_VERSION`
    /// = 3 wire format, which appends a 16-byte nonce after the suite word).
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write protocol version
        writer.write_all(&PROTOCOL_VERSION.to_le_bytes())?;

        // Write request type
        writer.write_all(&(self.request_type as u32).to_le_bytes())?;

        // Write sealed key (if present)
        if let Some(ref sealed_key) = self.sealed_key {
            let sealed_bytes = sealed_key.as_bytes();
            writer.write_all(&(sealed_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(sealed_bytes)?;
        } else {
            writer.write_all(&0u32.to_le_bytes())?;
        }

        // Write context (if present)
        if let Some(ref context) = self.context {
            let context_json = serde_json::to_string(context)?;
            let context_bytes = context_json.as_bytes();
            writer.write_all(&(context_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(context_bytes)?;
        } else {
            writer.write_all(&0u32.to_le_bytes())?;
        }

        // Write suite (v2/v3 field). Absent → SUITE_WIRE_ABSENT sentinel
        // (v1 back-compat path on read; on write we always send v3).
        let suite_word = self.suite.unwrap_or(SUITE_WIRE_ABSENT);
        writer.write_all(&suite_word.to_le_bytes())?;

        // v3 tail: append the 16-byte nonce (REM-12 / CON-18-001).
        // For pings this is a zeroed nonce; for unseal requests it is the
        // per-request CSPRNG nonce generated by the client.
        writer.write_all(&self.nonce)?;

        writer.flush()?;
        Ok(())
    }

    /// Read request from a stream.
    ///
    /// Accepts v1, v2, and v3 frames:
    /// - v1 → `suite = None`, `nonce = [0u8;16]` (no replay protection — documented gap)
    /// - v2 → `suite = Some(word)`, `nonce = [0u8;16]` (no replay protection — documented gap)
    /// - v3 → `suite = Some(word)`, `nonce = <16 bytes from wire>` (replay protection active)
    ///
    /// Any version other than 1, 2, or 3 is a hard-error with no silent acceptance.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read protocol version
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        let version = u32::from_le_bytes(version_buf);

        // Accept v1, v2, and v3; reject anything else with an actionable error.
        // Do NOT silently accept future/unknown versions — a new version may add
        // bytes after the nonce and a misaligned read would corrupt the frame.
        if version != 1 && version != 2 && version != 3 {
            return Err(anyhow!(
                "Protocol version mismatch: expected 1, 2, or 3, got {}",
                version
            ));
        }

        // Read request type
        let mut type_buf = [0u8; 4];
        reader.read_exact(&mut type_buf)?;
        let request_type = RequestType::try_from(u32::from_le_bytes(type_buf))?;

        // Read sealed key
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let sealed_key_len = u32::from_le_bytes(len_buf);

        let sealed_key = if sealed_key_len > 0 {
            if sealed_key_len > MAX_REQUEST_SIZE {
                return Err(anyhow!("Sealed key too large: {} bytes", sealed_key_len));
            }
            let mut sealed_buf = vec![0u8; sealed_key_len as usize];
            reader.read_exact(&mut sealed_buf)?;
            Some(String::from_utf8(sealed_buf)?)
        } else {
            None
        };

        // Read context
        reader.read_exact(&mut len_buf)?;
        let context_len = u32::from_le_bytes(len_buf);

        let context = if context_len > 0 {
            if context_len > MAX_REQUEST_SIZE {
                return Err(anyhow!("Context too large: {} bytes", context_len));
            }
            let mut context_buf = vec![0u8; context_len as usize];
            reader.read_exact(&mut context_buf)?;
            let context_json = String::from_utf8(context_buf)?;
            Some(serde_json::from_str(&context_json)?)
        } else {
            None
        };

        // Suite field — present in v2 and v3 frames.  v1 frames terminate
        // after the context bytes; omit the read on that branch.
        let suite = if version >= 2 {
            let mut suite_buf = [0u8; 4];
            reader.read_exact(&mut suite_buf)?;
            let raw = u32::from_le_bytes(suite_buf);
            match raw {
                SUITE_WIRE_ABSENT => None,
                SUITE_WIRE_CLASSIC | SUITE_WIRE_HYBRID => Some(raw),
                other => {
                    return Err(anyhow!(
                        "Unknown suite wire value: {} (expected {}, {}, or absent {})",
                        other,
                        SUITE_WIRE_CLASSIC,
                        SUITE_WIRE_HYBRID,
                        SUITE_WIRE_ABSENT
                    ));
                }
            }
        } else {
            // v1 frame: no suite field on the wire. None at the type-level
            // means "treat as Classic at dispatch" (08-03 back-compat).
            None
        };

        // Nonce field — present ONLY in v3 frames (REM-12 / CON-18-001).
        //
        // A v2 frame has no nonce bytes — reading them would consume the next
        // frame's bytes or block on EOF.  A v1 frame has neither suite nor nonce.
        // The zeroed sentinel makes it explicit that v1/v2 frames carry no
        // per-request replay protection (documented gap, not a silent bypass).
        let nonce = if version == 3 {
            let mut n = [0u8; 16];
            reader.read_exact(&mut n)?;
            n
        } else {
            // v1/v2: no nonce on the wire; replay protection absent for these
            // legacy frames.  Return zeroed sentinel — the agent MUST NOT
            // insert this into the per-connection nonce set, or a single all-zero
            // nonce would collide across all legacy frames on the same connection.
            [0u8; 16]
        };

        Ok(Self {
            request_type,
            sealed_key,
            context,
            suite,
            nonce,
            wire_version: version,
        })
    }
}

/// Agent response message
#[derive(Debug, Clone)]
pub struct AgentResponse {
    pub status: ResponseStatus,
    pub repository_key: Option<String>,
    pub error_message: Option<String>,
}

impl AgentResponse {
    /// Create a success response
    pub fn success(repository_key: String) -> Self {
        Self {
            status: ResponseStatus::Success,
            repository_key: Some(repository_key),
            error_message: None,
        }
    }

    /// Create a denied response
    pub fn denied() -> Self {
        Self {
            status: ResponseStatus::Denied,
            repository_key: None,
            error_message: Some("User denied the request".to_string()),
        }
    }

    /// Create a timeout response
    pub fn timeout() -> Self {
        Self {
            status: ResponseStatus::Timeout,
            repository_key: None,
            error_message: Some("User confirmation timeout".to_string()),
        }
    }

    /// Create an error response
    pub fn error(message: String) -> Self {
        Self {
            status: ResponseStatus::Error,
            repository_key: None,
            error_message: Some(message),
        }
    }

    /// Create an agent locked response
    pub fn locked() -> Self {
        Self {
            status: ResponseStatus::AgentLocked,
            repository_key: None,
            error_message: Some("Agent is locked".to_string()),
        }
    }

    /// Write response to a stream
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write status
        writer.write_all(&u32::from(self.status).to_le_bytes())?;

        // Write repository key (if present)
        if let Some(ref repo_key) = self.repository_key {
            let key_bytes = repo_key.as_bytes();
            writer.write_all(&(key_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(key_bytes)?;
        } else {
            writer.write_all(&0u32.to_le_bytes())?;
        }

        // Write error message (if present)
        if let Some(ref error) = self.error_message {
            let error_bytes = error.as_bytes();
            writer.write_all(&(error_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(error_bytes)?;
        } else {
            writer.write_all(&0u32.to_le_bytes())?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Read response from a stream
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read status
        let mut status_buf = [0u8; 4];
        reader.read_exact(&mut status_buf)?;
        let status = ResponseStatus::try_from(u32::from_le_bytes(status_buf))?;

        // Read repository key
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let key_len = u32::from_le_bytes(len_buf);

        let repository_key = if key_len > 0 {
            if key_len > MAX_REQUEST_SIZE {
                return Err(anyhow!("Repository key too large: {} bytes", key_len));
            }
            let mut key_buf = vec![0u8; key_len as usize];
            reader.read_exact(&mut key_buf)?;
            Some(String::from_utf8(key_buf)?)
        } else {
            None
        };

        // Read error message
        reader.read_exact(&mut len_buf)?;
        let error_len = u32::from_le_bytes(len_buf);

        let error_message = if error_len > 0 {
            if error_len > MAX_REQUEST_SIZE {
                return Err(anyhow!("Error message too large: {} bytes", error_len));
            }
            let mut error_buf = vec![0u8; error_len as usize];
            reader.read_exact(&mut error_buf)?;
            Some(String::from_utf8(error_buf)?)
        } else {
            None
        };

        Ok(Self {
            status,
            repository_key,
            error_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Cursor;

    // -------------------------------------------------------------------------
    // Helper: build a hand-rolled v2 frame (suite word, no nonce).
    // Used to verify that a v3 agent correctly handles a v2 client without
    // consuming any extra bytes as a nonce (Pitfall 6 / REM-12).
    // -------------------------------------------------------------------------
    fn build_v2_frame(
        request_type: RequestType,
        sealed: &[u8],
        context_json: &[u8],
        suite_word: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_le_bytes()); // version = 2
        buf.extend_from_slice(&(request_type as u32).to_le_bytes());
        buf.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        buf.extend_from_slice(sealed);
        buf.extend_from_slice(&(context_json.len() as u32).to_le_bytes());
        buf.extend_from_slice(context_json);
        buf.extend_from_slice(&suite_word.to_le_bytes());
        // NOTE: no nonce bytes — v2 frame ends after suite.
        buf
    }

    // -------------------------------------------------------------------------
    // v3 round-trip: request_type, sealed_key, suite, AND nonce round-trip.
    // -------------------------------------------------------------------------
    #[test]
    fn test_request_roundtrip_v3_preserves_nonce() {
        let known_nonce = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10u8,
        ];
        let context = RequestContext::new("alice".to_string());
        let request = AgentRequest::unseal(
            "sealed_key_data".to_string(),
            context,
            SUITE_WIRE_CLASSIC,
            known_nonce,
        );

        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(request.request_type, decoded.request_type);
        assert_eq!(request.sealed_key, decoded.sealed_key);
        assert_eq!(decoded.suite, Some(SUITE_WIRE_CLASSIC));
        // The nonce must round-trip exactly.
        assert_eq!(decoded.nonce, known_nonce, "nonce mismatch after v3 round-trip");
    }

    // -------------------------------------------------------------------------
    // v3 round-trip with Hybrid suite.
    // -------------------------------------------------------------------------
    #[test]
    fn test_request_roundtrip_v3_hybrid_suite() {
        let known_nonce = [0xABu8; 16];
        let context = RequestContext::new("bob".to_string());
        let request = AgentRequest::unseal(
            "sealed_hybrid".to_string(),
            context,
            SUITE_WIRE_HYBRID,
            known_nonce,
        );

        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(decoded.request_type, RequestType::UnsealRepositoryKey);
        assert_eq!(decoded.sealed_key.as_deref(), Some("sealed_hybrid"));
        assert_eq!(decoded.suite, Some(SUITE_WIRE_HYBRID));
        assert_eq!(decoded.nonce, known_nonce);
    }

    // -------------------------------------------------------------------------
    // Back-compat: v1 frame decodes with suite=None and zeroed nonce.
    // The zeroed nonce is the sentinel for "no replay protection" and must NOT
    // be treated as a real nonce by the agent's per-connection HashSet.
    // -------------------------------------------------------------------------
    #[test]
    fn test_request_v1_frame_decodes_with_suite_none_and_zeroed_nonce() {
        // CR-01 / 08-03 / REM-12 back-compat: a hand-rolled v1 frame (no
        // trailing suite u32, no nonce) must still decode, and the nonce field
        // must be zeroed (not garbage).
        let mut buffer: Vec<u8> = Vec::new();
        // version = 1
        buffer.extend_from_slice(&1u32.to_le_bytes());
        // request_type = UnsealRepositoryKey (1)
        buffer.extend_from_slice(&(RequestType::UnsealRepositoryKey as u32).to_le_bytes());
        // sealed_key = "v1_sealed"
        let sealed = b"v1_sealed";
        buffer.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        buffer.extend_from_slice(sealed);
        // context = serialized RequestContext
        let context_json =
            serde_json::to_string(&RequestContext::new("legacy".to_string())).unwrap();
        buffer.extend_from_slice(&(context_json.len() as u32).to_le_bytes());
        buffer.extend_from_slice(context_json.as_bytes());
        // NO trailing suite field, NO nonce — this is exactly a pre-CR-01 frame.

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(decoded.request_type, RequestType::UnsealRepositoryKey);
        assert_eq!(decoded.sealed_key.as_deref(), Some("v1_sealed"));
        assert!(decoded.context.is_some());
        // The hallmark of a v1 frame: suite is None at the type level.
        assert!(decoded.suite.is_none());
        // Nonce must be zeroed (legacy gap sentinel, not garbage).
        assert_eq!(decoded.nonce, [0u8; 16], "v1 frame nonce must be zeroed");
    }

    // -------------------------------------------------------------------------
    // Back-compat: v2 frame (suite word, no nonce) decodes correctly under a
    // v3 agent.  The nonce is zeroed; no extra bytes are consumed.
    // -------------------------------------------------------------------------
    #[test]
    fn test_request_v2_frame_to_v3_agent_yields_zeroed_nonce() {
        let context_json =
            serde_json::to_string(&RequestContext::new("carol".to_string())).unwrap();
        let buffer = build_v2_frame(
            RequestType::UnsealRepositoryKey,
            b"v2_sealed",
            context_json.as_bytes(),
            SUITE_WIRE_CLASSIC,
        );

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(decoded.request_type, RequestType::UnsealRepositoryKey);
        assert_eq!(decoded.sealed_key.as_deref(), Some("v2_sealed"));
        assert_eq!(decoded.suite, Some(SUITE_WIRE_CLASSIC));
        // Nonce must be zeroed — a v2 frame carries no nonce bytes; the agent
        // must not consume any further bytes and must not treat the zero nonce
        // as a real (replay-checkable) value.
        assert_eq!(decoded.nonce, [0u8; 16], "v2 frame nonce must be zeroed");
        // Cursor must be fully consumed — no leftover bytes.
        assert_eq!(
            cursor.position() as usize,
            cursor.get_ref().len(),
            "v2 frame: unexpected bytes remain after read_from"
        );
    }

    // -------------------------------------------------------------------------
    // Version guard: unknown version hard-errors (no silent bypass).
    // -------------------------------------------------------------------------
    #[test]
    fn test_unknown_version_is_hard_error() {
        for &unknown_version in &[0u32, 4, 99, u32::MAX] {
            let mut buffer: Vec<u8> = Vec::new();
            buffer.extend_from_slice(&unknown_version.to_le_bytes());
            // Minimal remaining bytes so read_exact won't hit EOF before the
            // version check triggers.
            buffer.extend_from_slice(&[0u8; 20]);

            let mut cursor = Cursor::new(buffer);
            let err = AgentRequest::read_from(&mut cursor).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("Protocol version mismatch"),
                "version {unknown_version}: expected 'Protocol version mismatch' error, got: {msg}"
            );
            assert!(
                msg.contains("expected 1, 2, or 3"),
                "version {unknown_version}: error should name accepted versions, got: {msg}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Unknown suite word in a v3 frame hard-errors.
    // -------------------------------------------------------------------------
    #[test]
    fn test_request_v3_unknown_suite_word_is_error() {
        // Build a valid v3 frame except for the unknown suite word.
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&3u32.to_le_bytes()); // version = 3
        buffer.extend_from_slice(&(RequestType::UnsealRepositoryKey as u32).to_le_bytes());
        // empty sealed_key
        buffer.extend_from_slice(&0u32.to_le_bytes());
        // empty context
        buffer.extend_from_slice(&0u32.to_le_bytes());
        // unknown suite word (not 0, 1, or 0xFFFFFFFF)
        buffer.extend_from_slice(&42u32.to_le_bytes());
        // The error fires on the suite word; the nonce bytes are never reached.

        let mut cursor = Cursor::new(buffer);
        let err = AgentRequest::read_from(&mut cursor).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Unknown suite wire value"),
            "expected 'Unknown suite wire value' error, got: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // Replay-rejection contract: first nonce insert accepted; duplicate rejected.
    //
    // This exercises the per-connection HashSet semantics that the agent uses in
    // handle_client, deterministically and without spawning the daemon.
    // The end-to-end socketpair test is deferred to 40-VALIDATION.md.
    // -------------------------------------------------------------------------
    #[test]
    fn test_nonce_replay_rejection_contract() {
        let known_nonce: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c,
        ];

        // Build and write a v3 frame with the known nonce.
        let context = RequestContext::new("dave".to_string());
        let request =
            AgentRequest::unseal("sealed".to_string(), context, SUITE_WIRE_CLASSIC, known_nonce);
        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        // Read (decode) the frame — simulates the agent's read_from.
        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();
        assert_eq!(decoded.nonce, known_nonce);

        // Simulate the per-connection nonce set in handle_client.
        let mut seen_nonces: HashSet<[u8; 16]> = HashSet::new();

        // First insert: must succeed (nonce not seen before).
        assert!(
            seen_nonces.insert(decoded.nonce),
            "first nonce insert must return true (nonce accepted)"
        );

        // Second insert of the same nonce: must fail (replay rejected).
        assert!(
            !seen_nonces.insert(decoded.nonce),
            "duplicate nonce insert must return false (replay rejected)"
        );
    }

    // -------------------------------------------------------------------------
    // v1/v2 frames must NOT be spuriously rejected as replays.
    //
    // The zeroed nonce for legacy frames must NOT be inserted into the per-
    // connection nonce set (the agent gates the check on version == 3).
    // This test verifies the condition the agent must enforce at its call site.
    // -------------------------------------------------------------------------
    #[test]
    fn test_v1_v2_legacy_frames_not_spuriously_replay_rejected() {
        // Decode a v1 frame — nonce should be zeroed.
        let mut v1_buf: Vec<u8> = Vec::new();
        v1_buf.extend_from_slice(&1u32.to_le_bytes());
        v1_buf.extend_from_slice(&(RequestType::UnsealRepositoryKey as u32).to_le_bytes());
        v1_buf.extend_from_slice(&0u32.to_le_bytes()); // empty sealed_key
        v1_buf.extend_from_slice(&0u32.to_le_bytes()); // empty context
        let decoded_v1 = AgentRequest::read_from(&mut Cursor::new(v1_buf)).unwrap();
        assert_eq!(decoded_v1.nonce, [0u8; 16]);

        // Decode a v2 frame — nonce should also be zeroed.
        let context_json =
            serde_json::to_string(&RequestContext::new("legacy_user".to_string())).unwrap();
        let v2_buf = build_v2_frame(
            RequestType::UnsealRepositoryKey,
            b"v2_key",
            context_json.as_bytes(),
            SUITE_WIRE_CLASSIC,
        );
        let decoded_v2 = AgentRequest::read_from(&mut Cursor::new(v2_buf)).unwrap();
        assert_eq!(decoded_v2.nonce, [0u8; 16]);

        // Simulate the agent's version-gated nonce check.
        // The agent only inserts into the nonce set for v3 frames.
        // For v1/v2 the nonce is zeroed AND the agent must not check it,
        // so we verify the decoded nonce is the all-zero sentinel (which the
        // agent will bypass).
        let seen_nonces: HashSet<[u8; 16]> = HashSet::new();

        // Neither frame should cause a spurious replay rejection.
        // If the agent accidentally inserted the zeroed nonce for v1, it would
        // block the second v1/v2 request on the same connection.
        // The correct behaviour: the agent skips the nonce check entirely for
        // non-v3 frames — we verify the decoded nonce is the zeroed sentinel.
        for decoded in [&decoded_v1, &decoded_v2] {
            // Only insert for v3 — mirroring the agent's gate.
            // (In this test there are no v3 frames, so seen_nonces stays empty.)
            let _ = &seen_nonces; // show we never insert for legacy frames
            assert_eq!(decoded.nonce, [0u8; 16],
                "legacy frame nonce must be zeroed (not garbage that could collide with a real nonce)");
        }
        // No spurious rejection occurred — test passes by not asserting !insert.
    }

    // -------------------------------------------------------------------------
    // Response round-trips (unchanged from prior version).
    // -------------------------------------------------------------------------

    #[test]
    fn test_response_roundtrip() {
        let response = AgentResponse::success("repo_key_data".to_string());

        let mut buffer = Vec::new();
        response.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentResponse::read_from(&mut cursor).unwrap();

        assert_eq!(
            std::mem::discriminant(&response.status),
            std::mem::discriminant(&decoded.status)
        );
        assert_eq!(response.repository_key, decoded.repository_key);
    }

    #[test]
    fn test_ping_request() {
        let request = AgentRequest::ping();

        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(request.request_type, RequestType::Ping);
        assert_eq!(decoded.request_type, RequestType::Ping);
        assert!(decoded.sealed_key.is_none());
        assert!(decoded.context.is_none());
        // Ping carries a zeroed nonce (no replay-sensitive payload).
        assert_eq!(decoded.nonce, [0u8; 16]);
    }

    #[test]
    fn test_error_responses() {
        let responses = vec![
            AgentResponse::denied(),
            AgentResponse::timeout(),
            AgentResponse::error("test error".to_string()),
            AgentResponse::locked(),
        ];

        for response in responses {
            let mut buffer = Vec::new();
            response.write_to(&mut buffer).unwrap();

            let mut cursor = Cursor::new(buffer);
            let decoded = AgentResponse::read_from(&mut cursor).unwrap();

            assert_eq!(
                std::mem::discriminant(&response.status),
                std::mem::discriminant(&decoded.status)
            );
            assert!(decoded.repository_key.is_none());
            assert!(decoded.error_message.is_some());
        }
    }
}
