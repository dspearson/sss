#![allow(clippy::pedantic)] // Agent modules are excluded from pedantic enforcement per REQUIREMENTS.md

use anyhow::{anyhow, Result};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

// libsodium bindings — used for CSPRNG nonce generation (REM-12 / CON-18-001).
use libsodium_sys as sodium;

use crate::agent::protocol::{
    AgentRequest, AgentResponse, RequestContext, ResponseStatus, SUITE_WIRE_CLASSIC,
    SUITE_WIRE_HYBRID,
};
use crate::crypto::{RepositoryKey, Suite};

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

    /// Check if the agent is available.
    ///
    /// For an `@`-prefixed abstract socket address, `Path::exists()` always
    /// returns false — we use a ping attempt instead.  For a filesystem socket
    /// we keep the `exists()` fast-path before attempting to connect.
    pub fn is_available(&self) -> bool {
        let addr = self.socket_path.to_string_lossy();
        if addr.starts_with('@') {
            // Abstract socket: no filesystem path to test.
            self.ping().is_ok()
        } else {
            self.socket_path.exists() && self.ping().is_ok()
        }
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

    /// Request the agent to unseal a repository key for the caller's suite.
    ///
    /// CR-01 / 08-03: the suite is threaded through the protocol so the agent
    /// dispatches via `suite_for(suite)` instead of hardcoding `ClassicSuite`.
    ///
    /// REM-12 / CON-18-001: a fresh 128-bit nonce is generated per request via
    /// the libsodium CSPRNG and included in the v3 wire frame.  The agent
    /// verifies the nonce against a per-connection `HashSet` to reject verbatim
    /// replay attacks.
    pub fn unseal_repository_key(
        &self,
        sealed_key: &str,
        context: RequestContext,
        suite: Suite,
    ) -> Result<RepositoryKey> {
        let mut stream = self.connect()?;

        // Generate a fresh per-request 128-bit nonce via the libsodium CSPRNG
        // (REM-12 / CON-18-001).  A fresh nonce on every call ensures that a
        // captured request frame cannot be replayed verbatim to the agent.
        //
        // Pattern established by src/crypto/classic.rs (RepositoryKey::new at
        // line 102-116) and src/crypto/kdf.rs.  The same Miri-stub guard is
        // applied: randombytes_buf is FFI and cannot run under Miri; the stub
        // leaves the buffer zero-initialised, which is acceptable in test
        // environments (not production).
        let mut nonce = [0u8; 16];
        #[cfg(not(miri))]
        {
            crate::crypto::classic::ensure_sodium_init();
            // SAFETY: `nonce` is a valid 16-byte stack buffer; libsodium's
            // `randombytes_buf` writes exactly 16 bytes into it and performs no
            // reads.  `ensure_sodium_init()` guarantees libsodium is
            // initialised before this call.
            unsafe {
                sodium::randombytes_buf(nonce.as_mut_ptr().cast::<std::ffi::c_void>(), 16);
            }
        }
        // Miri stub: randombytes_buf is FFI; AddressSanitizer (Phase 23 MEMSAFE-03)
        // covers this path under non-miri builds. Under miri `nonce` stays
        // zero-initialised.
        #[cfg(miri)]
        let _ = &nonce; // suppress unused-mut under miri

        // Send request — map Suite to its wire-format word.
        let suite_word = match suite {
            Suite::Classic => SUITE_WIRE_CLASSIC,
            Suite::Hybrid => SUITE_WIRE_HYBRID,
        };
        let request = AgentRequest::unseal(sealed_key.to_string(), context, suite_word, nonce);
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

    /// Connect to the agent socket.
    ///
    /// If the stored socket address starts with `@` it is a Linux abstract
    /// socket.  Strip the prefix and use `SocketAddr::from_abstract_name` +
    /// `UnixStream::connect_addr`.  On non-Linux platforms abstract sockets are
    /// not supported and a clear error is returned.
    ///
    /// For a plain filesystem path the original `UnixStream::connect` path is
    /// used, with the pre-existing existence check preserved.
    fn connect(&self) -> Result<UnixStream> {
        let addr_str = self.socket_path.to_string_lossy();

        let stream = if let Some(name) = addr_str.strip_prefix('@') {
            // Abstract socket — no filesystem path to check.
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::SocketAddr;
                let saddr = SocketAddr::from_abstract_name(name.as_bytes())
                    .map_err(|e| anyhow!("invalid abstract socket name '{}': {}", name, e))?;
                UnixStream::connect_addr(&saddr)
                    .map_err(|e| anyhow!("Failed to connect to abstract socket @{}: {}", name, e))?
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                return Err(anyhow!("abstract sockets are not supported on this platform"));
            }
        } else {
            // Filesystem socket — check existence first.
            if !self.socket_path.exists() {
                return Err(anyhow!("Agent socket not found: {:?}", self.socket_path));
            }
            UnixStream::connect(&self.socket_path)
                .map_err(|e| anyhow!("Failed to connect to agent: {}", e))?
        };

        // Preserve existing read/write timeouts on both branches.
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(stream)
    }
}

/// Check if the agent is available
pub fn is_agent_available() -> bool {
    AgentClient::new()
        .map(|client| client.is_available())
        .unwrap_or(false)
}

/// Unseal a repository key using the agent.
///
/// CR-01 / 08-03: callers must pass the project's resolved `Suite` so the
/// agent routes through `suite_for(suite)` instead of the legacy hardcoded
/// `ClassicSuite`.
pub fn unseal_with_agent(
    sealed_key: &str,
    context: RequestContext,
    suite: Suite,
) -> Result<RepositoryKey> {
    let client = AgentClient::new()?;
    client.unseal_repository_key(sealed_key, context, suite)
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
