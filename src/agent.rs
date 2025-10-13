use anyhow::{anyhow, Result};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::agent_protocol::{AgentRequest, AgentResponse, RequestContext, ResponseStatus};
use crate::crypto::RepositoryKey;

/// Agent client for communicating with sss-agent
pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    /// Create a new agent client
    pub fn new() -> Result<Self> {
        let socket_path = Self::get_socket_path()?;
        Ok(Self { socket_path })
    }

    /// Create an agent client with a custom socket path
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Check if the agent is available
    pub fn is_available(&self) -> bool {
        self.socket_path.exists() && self.ping().is_ok()
    }

    /// Ping the agent to check if it's responsive
    pub fn ping(&self) -> Result<()> {
        let mut stream = self.connect()?;
        let request = AgentRequest::ping();
        request.write_to(&mut stream)?;

        let response = AgentResponse::read_from(&mut stream)?;
        match response.status {
            ResponseStatus::Success => Ok(()),
            _ => Err(anyhow!("Agent ping failed")),
        }
    }

    /// Request the agent to unseal a repository key
    pub fn unseal_repository_key(
        &self,
        sealed_key: &str,
        context: RequestContext,
    ) -> Result<RepositoryKey> {
        let mut stream = self.connect()?;

        // Send request
        let request = AgentRequest::unseal(sealed_key.to_string(), context);
        request.write_to(&mut stream)?;

        // Receive response
        let response = AgentResponse::read_from(&mut stream)?;

        match response.status {
            ResponseStatus::Success => {
                let repo_key_base64 = response
                    .repository_key
                    .ok_or_else(|| anyhow!("Agent returned success but no repository key"))?;

                RepositoryKey::from_base64(&repo_key_base64)
            }
            ResponseStatus::Denied => Err(anyhow!("User denied the unsealing request")),
            ResponseStatus::Timeout => Err(anyhow!("User confirmation timeout")),
            ResponseStatus::AgentLocked => Err(anyhow!("Agent is locked")),
            ResponseStatus::Error => {
                let error_msg = response
                    .error_message
                    .unwrap_or_else(|| "Unknown error".to_string());
                Err(anyhow!("Agent error: {}", error_msg))
            }
        }
    }

    /// Get the socket path from environment or default location
    fn get_socket_path() -> Result<PathBuf> {
        // Check environment variable first
        if let Ok(path) = std::env::var("SSS_AUTH_SOCK") {
            return Ok(PathBuf::from(path));
        }

        // Default location: ~/.sss-agent.sock
        let home =
            std::env::var("HOME").map_err(|_| anyhow!("HOME environment variable not set"))?;
        Ok(PathBuf::from(home).join(".sss-agent.sock"))
    }

    /// Connect to the agent socket
    fn connect(&self) -> Result<UnixStream> {
        if !self.socket_path.exists() {
            return Err(anyhow!("Agent socket not found: {:?}", self.socket_path));
        }

        let stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| anyhow!("Failed to connect to agent: {}", e))?;

        // Set reasonable timeout
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(stream)
    }
}

impl Default for AgentClient {
    fn default() -> Self {
        Self::new().expect("Failed to create agent client")
    }
}

/// Check if the agent is available
pub fn is_agent_available() -> bool {
    AgentClient::new()
        .map(|client| client.is_available())
        .unwrap_or(false)
}

/// Unseal a repository key using the agent
pub fn unseal_with_agent(sealed_key: &str, context: RequestContext) -> Result<RepositoryKey> {
    let client = AgentClient::new()?;
    client.unseal_repository_key(sealed_key, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_socket_path() {
        // Should not panic
        let _ = AgentClient::get_socket_path();
    }

    #[test]
    fn test_agent_client_creation() {
        // Should create client even if agent isn't running
        let _client = AgentClient::new();
    }

    #[test]
    fn test_is_available_no_agent() {
        let client = AgentClient::with_socket_path(PathBuf::from("/nonexistent/socket"));
        assert!(!client.is_available());
    }
}
