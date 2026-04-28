#![allow(clippy::pedantic)] // Agent modules are excluded from pedantic enforcement per REQUIREMENTS.md

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::SystemTime;

/// Protocol version for compatibility checking.
///
/// Version 1: original wire format (no suite field).
/// Version 2 (current): adds a trailing `suite: u32` field on `AgentRequest`,
/// encoded as `0xFFFFFFFF` = absent / Classic-by-default (for v1 back-compat),
/// `0` = Classic, `1` = Hybrid. Any other value is a hard wire-format error.
///
/// The agent accepts both v1 and v2 frames so older clients keep working
/// during the transition (08-03 / CR-01). New clients always send v2.
pub const PROTOCOL_VERSION: u32 = 2;

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
/// Wire format (version 2):
/// `[u32 version][u32 request_type][u32 sealed_len][sealed_bytes...]`
/// `[u32 context_len][context_bytes...][u32 suite]`
///
/// `suite` encoding (CR-01 / 08-03):
/// - `SUITE_WIRE_ABSENT` (`0xFFFFFFFF`): no suite specified — agent treats as
///   Classic for v1 back-compat.
/// - `SUITE_WIRE_CLASSIC` (`0`): Classic (libsodium `crypto_box_seal`).
/// - `SUITE_WIRE_HYBRID` (`1`): Hybrid (trelis X448 + sntrup761 + BLAKE3).
/// - any other value: hard wire-format error (no silent default).
///
/// Wire format (version 1, accepted for back-compat): identical to v2 but
/// without the trailing `suite` u32. Agent treats v1 frames as
/// `suite = SUITE_WIRE_ABSENT` at dispatch.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub request_type: RequestType,
    pub sealed_key: Option<String>,
    pub context: Option<RequestContext>,
    /// Suite selector — `Some(SUITE_WIRE_CLASSIC)` for Classic,
    /// `Some(SUITE_WIRE_HYBRID)` for Hybrid, `None` for v1-frame-back-compat
    /// or pings. Maps to `Option<crate::crypto::Suite>` at dispatch.
    pub suite: Option<u32>,
}

impl AgentRequest {
    /// Create a new unsealing request for a specific suite. The `suite`
    /// argument is the wire-format `u32` (use `SUITE_WIRE_CLASSIC` /
    /// `SUITE_WIRE_HYBRID`); pass `SUITE_WIRE_ABSENT` only for v1
    /// back-compat tests, never for production traffic.
    pub fn unseal(sealed_key: String, context: RequestContext, suite: u32) -> Self {
        Self {
            request_type: RequestType::UnsealRepositoryKey,
            sealed_key: Some(sealed_key),
            context: Some(context),
            suite: Some(suite),
        }
    }

    /// Create a ping request
    pub fn ping() -> Self {
        Self {
            request_type: RequestType::Ping,
            sealed_key: None,
            context: None,
            suite: None,
        }
    }

    /// Write request to a stream (always uses the current `PROTOCOL_VERSION`
    /// = 2 wire format).
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

        // Write suite (v2 trailing field). Absent → SUITE_WIRE_ABSENT sentinel
        // (v1 back-compat path on read; on write we always send v2).
        let suite_word = self.suite.unwrap_or(SUITE_WIRE_ABSENT);
        writer.write_all(&suite_word.to_le_bytes())?;

        writer.flush()?;
        Ok(())
    }

    /// Read request from a stream. Accepts both v1 and v2 frames; v1 frames
    /// produce `suite = None` (CR-01 / 08-03 back-compat).
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read protocol version
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        let version = u32::from_le_bytes(version_buf);

        // Accept v1 and v2; reject anything else with an actionable error.
        if version != 1 && version != PROTOCOL_VERSION {
            return Err(anyhow!(
                "Protocol version mismatch: expected 1 or {}, got {}",
                PROTOCOL_VERSION,
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

        // Suite field — only present in v2 frames. v1 frames terminate after
        // the context bytes, so we simply omit the read in that branch.
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

        Ok(Self {
            request_type,
            sealed_key,
            context,
            suite,
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
    use std::io::Cursor;

    #[test]
    fn test_request_roundtrip() {
        let context = RequestContext::new("alice".to_string());
        let request = AgentRequest::unseal(
            "sealed_key_data".to_string(),
            context,
            SUITE_WIRE_CLASSIC,
        );

        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(request.request_type, decoded.request_type);
        assert_eq!(request.sealed_key, decoded.sealed_key);
        assert_eq!(decoded.suite, Some(SUITE_WIRE_CLASSIC));
    }

    #[test]
    fn test_request_roundtrip_v2_hybrid_suite() {
        // CR-01 / 08-03: v2 frame carries the Hybrid suite selector.
        let context = RequestContext::new("bob".to_string());
        let request = AgentRequest::unseal(
            "sealed_hybrid".to_string(),
            context,
            SUITE_WIRE_HYBRID,
        );

        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(decoded.request_type, RequestType::UnsealRepositoryKey);
        assert_eq!(decoded.sealed_key.as_deref(), Some("sealed_hybrid"));
        assert_eq!(decoded.suite, Some(SUITE_WIRE_HYBRID));
    }

    #[test]
    fn test_request_v1_frame_decodes_with_suite_none() {
        // CR-01 / 08-03 back-compat: a hand-rolled v1 frame (no trailing suite
        // u32) must still decode, and the dispatch boundary treats `suite=None`
        // as Classic.
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
        // NO trailing suite field — this is exactly a pre-CR-01 frame.

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(decoded.request_type, RequestType::UnsealRepositoryKey);
        assert_eq!(decoded.sealed_key.as_deref(), Some("v1_sealed"));
        assert!(decoded.context.is_some());
        // The hallmark of a v1 frame: suite is None at the type level.
        assert!(decoded.suite.is_none());
    }

    #[test]
    fn test_request_v2_unknown_suite_word_is_error() {
        // CR-01 / 08-03: unknown suite word must hard-error rather than
        // silently default to Classic.
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        buffer.extend_from_slice(&(RequestType::UnsealRepositoryKey as u32).to_le_bytes());
        // empty sealed_key
        buffer.extend_from_slice(&0u32.to_le_bytes());
        // empty context
        buffer.extend_from_slice(&0u32.to_le_bytes());
        // unknown suite word (not 0, 1, or 0xFFFFFFFF)
        buffer.extend_from_slice(&42u32.to_le_bytes());

        let mut cursor = Cursor::new(buffer);
        let err = AgentRequest::read_from(&mut cursor).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Unknown suite wire value"),
            "expected 'Unknown suite wire value' error, got: {msg}"
        );
    }

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
