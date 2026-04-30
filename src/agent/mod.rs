// Agent component modules
//
// This module organizes the sss-agent client + protocol + policy implementation:
// - `client`: AgentClient — Unix-socket client API for talking to a running sss-agent daemon
// - `protocol`: wire format (AgentRequest / AgentResponse / RequestContext / ResponseStatus)
// - `policy`: PolicyManager — per-request allow/deny/prompt decisions with PolicyDecision + UserDecision

pub mod client;
pub mod policy;
pub mod protocol;
