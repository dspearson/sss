use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::SystemTime;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

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

/// Agent request message
#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub request_type: RequestType,
    pub sealed_key: Option<String>,
    pub context: Option<RequestContext>,
}

impl AgentRequest {
    /// Create a new unsealing request
    pub fn unseal(sealed_key: String, context: RequestContext) -> Self {
        Self {
            request_type: RequestType::UnsealRepositoryKey,
            sealed_key: Some(sealed_key),
            context: Some(context),
        }
    }

    /// Create a ping request
    pub fn ping() -> Self {
        Self {
            request_type: RequestType::Ping,
            sealed_key: None,
            context: None,
        }
    }

    /// Write request to a stream
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

        writer.flush()?;
        Ok(())
    }

    /// Read request from a stream
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        // Read protocol version
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        let version = u32::from_le_bytes(version_buf);

        if version != PROTOCOL_VERSION {
            return Err(anyhow!(
                "Protocol version mismatch: expected {}, got {}",
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

        Ok(Self {
            request_type,
            sealed_key,
            context,
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
        let request = AgentRequest::unseal("sealed_key_data".to_string(), context);

        let mut buffer = Vec::new();
        request.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let decoded = AgentRequest::read_from(&mut cursor).unwrap();

        assert_eq!(request.request_type, decoded.request_type);
        assert_eq!(request.sealed_key, decoded.sealed_key);
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
