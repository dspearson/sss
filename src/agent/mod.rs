// Agent component modules
//
// This module organizes the sss-agent client + protocol + policy implementation:
// - `client`: AgentClient — Unix-socket client API for talking to a running sss-agent daemon
// - `peer_cred`: OS peer-credential verification helpers (REM-09 / CON-02-001)
// - `protocol`: wire format (AgentRequest / AgentResponse / RequestContext / ResponseStatus)
// - `policy`: PolicyManager — per-request allow/deny/prompt decisions with PolicyDecision + UserDecision

pub mod client;
#[cfg(unix)]
pub mod peer_cred;
pub mod policy;
pub mod protocol;
