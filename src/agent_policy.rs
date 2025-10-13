use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::agent_protocol::RequestContext;

/// Policy decision for a request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Automatically allow this request
    Allow,
    /// Automatically deny this request
    Deny,
    /// Ask the user for confirmation
    AskUser,
}

/// User's decision from confirmation prompt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDecision {
    /// Deny this single request
    DenyOnce,
    /// Block all future requests from this host for this project
    DenyAll,
    /// Allow this single request
    AllowOnce,
    /// Allow all future requests from this host
    AllowAlways,
}

/// Policy for a specific host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPolicy {
    /// Hostname or IP address
    pub hostname: String,
    /// When this policy was added
    pub added_at: SystemTime,
    /// Optional: restrict to specific projects
    pub projects: Option<Vec<String>>,
}

/// Blocked host entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedHost {
    /// Hostname or IP address
    pub hostname: String,
    /// Reason for blocking
    pub reason: String,
    /// When this host was blocked
    pub blocked_at: SystemTime,
    /// Optional: restrict block to specific projects
    pub projects: Option<Vec<String>>,
}

/// Agent policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentPolicyConfig {
    /// Global settings
    #[serde(default)]
    pub settings: PolicySettings,
    /// Allowed hosts (from "Allow Always")
    #[serde(default)]
    pub allowed_hosts: Vec<HostPolicy>,
    /// Blocked hosts (from "Deny" or manual blocking)
    #[serde(default)]
    pub blocked_hosts: Vec<BlockedHost>,
}

/// Global policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    /// Require confirmation for requests (default: true)
    #[serde(default = "default_require_confirmation")]
    pub require_confirmation: bool,
    /// Timeout for confirmation prompts in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Default action if no policy matches
    #[serde(default = "default_action")]
    pub default_action: String, // "deny" or "allow"
}

fn default_require_confirmation() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

fn default_action() -> String {
    "deny".to_string()
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            require_confirmation: true,
            timeout_seconds: 30,
            default_action: "deny".to_string(),
        }
    }
}

/// Policy manager for agent decisions
pub struct PolicyManager {
    config: AgentPolicyConfig,
    config_path: PathBuf,
    locked: bool,
}

impl PolicyManager {
    /// Create a new policy manager
    pub fn new(config_path: PathBuf) -> Result<Self> {
        let config = if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            toml::from_str(&content)?
        } else {
            AgentPolicyConfig::default()
        };

        Ok(Self {
            config,
            config_path,
            locked: false,
        })
    }

    /// Check if the agent is locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Lock the agent (deny all requests)
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the agent
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// Evaluate a request and determine the policy decision
    pub fn evaluate(&self, context: &RequestContext) -> PolicyDecision {
        // If agent is locked, always deny
        if self.locked {
            return PolicyDecision::Deny;
        }

        // If no hostname, can't apply host-based policies
        let hostname = match &context.hostname {
            Some(h) => h,
            None => {
                // No hostname, use default behavior
                if self.config.settings.require_confirmation {
                    return PolicyDecision::AskUser;
                } else {
                    return match self.config.settings.default_action.as_str() {
                        "allow" => PolicyDecision::Allow,
                        _ => PolicyDecision::Deny,
                    };
                }
            }
        };

        // Check if host is blocked (with project-specific blocks)
        if let Some(blocked) = self.find_blocked_host(hostname) {
            // If block has project restrictions, check them
            if let Some(ref projects) = blocked.projects {
                if let Some(ref project_path) = context.project_path {
                    if projects.iter().any(|p| project_path.contains(p)) {
                        // This host is blocked for this project
                        return PolicyDecision::Deny;
                    }
                }
                // Host is blocked but not for this project, continue evaluation
            } else {
                // Host is blocked globally
                return PolicyDecision::Deny;
            }
        }

        // Check if host is in allowed list
        if let Some(policy) = self.find_host_policy(hostname) {
            // If policy has project restrictions, check them
            if let Some(ref projects) = policy.projects {
                if let Some(ref project_path) = context.project_path {
                    if projects.iter().any(|p| project_path.contains(p)) {
                        return PolicyDecision::Allow;
                    }
                }
                // Host is allowed but project doesn't match
                return PolicyDecision::AskUser;
            }
            // Host is allowed without restrictions
            return PolicyDecision::Allow;
        }

        // No specific policy, use default behavior
        if self.config.settings.require_confirmation {
            PolicyDecision::AskUser
        } else {
            match self.config.settings.default_action.as_str() {
                "allow" => PolicyDecision::Allow,
                _ => PolicyDecision::Deny,
            }
        }
    }

    /// Apply a user decision
    pub fn apply_decision(
        &mut self,
        decision: UserDecision,
        context: &RequestContext,
    ) -> Result<()> {
        match decision {
            UserDecision::DenyOnce => {
                // Nothing to persist
                Ok(())
            }
            UserDecision::DenyAll => {
                // Block this host for this project
                if let Some(hostname) = &context.hostname {
                    self.add_blocked_host_with_project(
                        hostname.clone(),
                        "Blocked by user".to_string(),
                        context.project_path.clone(),
                    )?;
                    self.save()?;
                }
                Ok(())
            }
            UserDecision::AllowOnce => {
                // Nothing to persist
                Ok(())
            }
            UserDecision::AllowAlways => {
                // Add host to allowed list
                if let Some(hostname) = &context.hostname {
                    self.add_allowed_host(hostname.clone(), context.project_path.clone())?;
                    self.save()?;
                }
                Ok(())
            }
        }
    }

    /// Add a host to the allowed list
    pub fn add_allowed_host(
        &mut self,
        hostname: String,
        project_path: Option<String>,
    ) -> Result<()> {
        // Remove from blocked list if present
        self.config.blocked_hosts.retain(|h| h.hostname != hostname);

        // Check if already in allowed list
        if !self
            .config
            .allowed_hosts
            .iter()
            .any(|h| h.hostname == hostname)
        {
            let projects = project_path.map(|p| vec![p]);
            self.config.allowed_hosts.push(HostPolicy {
                hostname,
                added_at: SystemTime::now(),
                projects,
            });
        }

        Ok(())
    }

    /// Add a host to the blocked list
    pub fn add_blocked_host(&mut self, hostname: String, reason: String) -> Result<()> {
        self.add_blocked_host_with_project(hostname, reason, None)
    }

    /// Add a host to the blocked list with optional project restriction
    pub fn add_blocked_host_with_project(
        &mut self,
        hostname: String,
        reason: String,
        project_path: Option<String>,
    ) -> Result<()> {
        // Don't remove from allowed list - let allowed take precedence if both exist

        // Convert single project path to Vec if provided
        let projects = project_path.map(|p| vec![p]);

        // Check if already in blocked list for this project
        let already_blocked = self
            .config
            .blocked_hosts
            .iter()
            .any(|h| h.hostname == hostname && h.projects == projects);

        if !already_blocked {
            self.config.blocked_hosts.push(BlockedHost {
                hostname,
                reason,
                blocked_at: SystemTime::now(),
                projects,
            });
        }

        Ok(())
    }

    /// Remove a host from the allowed list
    pub fn remove_allowed_host(&mut self, hostname: &str) -> Result<()> {
        let original_len = self.config.allowed_hosts.len();
        self.config.allowed_hosts.retain(|h| h.hostname != hostname);

        if self.config.allowed_hosts.len() == original_len {
            return Err(anyhow!("Host not found in allowed list: {}", hostname));
        }

        self.save()
    }

    /// Remove a host from the blocked list
    pub fn remove_blocked_host(&mut self, hostname: &str) -> Result<()> {
        let original_len = self.config.blocked_hosts.len();
        self.config.blocked_hosts.retain(|h| h.hostname != hostname);

        if self.config.blocked_hosts.len() == original_len {
            return Err(anyhow!("Host not found in blocked list: {}", hostname));
        }

        self.save()
    }

    /// Clear all policies
    pub fn clear_all(&mut self) -> Result<()> {
        self.config.allowed_hosts.clear();
        self.config.blocked_hosts.clear();
        self.save()
    }

    /// Get all allowed hosts
    pub fn list_allowed_hosts(&self) -> &[HostPolicy] {
        &self.config.allowed_hosts
    }

    /// Get all blocked hosts
    pub fn list_blocked_hosts(&self) -> &[BlockedHost] {
        &self.config.blocked_hosts
    }

    /// Get timeout setting
    pub fn get_timeout_seconds(&self) -> u64 {
        self.config.settings.timeout_seconds
    }

    /// Save configuration to disk
    pub fn save(&self) -> Result<()> {
        let content = toml::to_string_pretty(&self.config)?;

        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.config_path, content)?;

        // Set secure permissions on the config file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.config_path)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(&self.config_path, perms)?;
        }

        Ok(())
    }

    /// Find a blocked host entry
    fn find_blocked_host(&self, hostname: &str) -> Option<&BlockedHost> {
        self.config
            .blocked_hosts
            .iter()
            .find(|h| h.hostname == hostname)
    }

    /// Find a host policy
    fn find_host_policy(&self, hostname: &str) -> Option<&HostPolicy> {
        self.config
            .allowed_hosts
            .iter()
            .find(|h| h.hostname == hostname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_policy_evaluation_locked() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        manager.lock();

        let context = RequestContext::new("alice".to_string());
        assert_eq!(manager.evaluate(&context), PolicyDecision::Deny);
    }

    #[test]
    fn test_policy_evaluation_allowed_host() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        manager
            .add_allowed_host("trusted.example.com".to_string(), None)
            .unwrap();

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("trusted.example.com".to_string());

        assert_eq!(manager.evaluate(&context), PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_evaluation_blocked_host() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        manager
            .add_blocked_host("evil.example.com".to_string(), "User denied".to_string())
            .unwrap();

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("evil.example.com".to_string());

        assert_eq!(manager.evaluate(&context), PolicyDecision::Deny);
    }

    #[test]
    fn test_policy_evaluation_ask_user() {
        let temp_file = NamedTempFile::new().unwrap();
        let manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("unknown.example.com".to_string());

        // Default behavior is to ask
        assert_eq!(manager.evaluate(&context), PolicyDecision::AskUser);
    }

    #[test]
    fn test_apply_decision_allow_always() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("new.example.com".to_string());

        manager
            .apply_decision(UserDecision::AllowAlways, &context)
            .unwrap();

        assert_eq!(manager.list_allowed_hosts().len(), 1);
        assert_eq!(manager.list_allowed_hosts()[0].hostname, "new.example.com");
    }

    #[test]
    fn test_apply_decision_deny_all() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("spam.example.com".to_string());
        context.project_path = Some("/home/user/project".to_string());

        manager
            .apply_decision(UserDecision::DenyAll, &context)
            .unwrap();

        // Should add to blocked list, not lock agent
        assert!(!manager.is_locked());
        assert_eq!(manager.list_blocked_hosts().len(), 1);
        assert_eq!(manager.list_blocked_hosts()[0].hostname, "spam.example.com");
    }

    #[test]
    fn test_remove_hosts() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut manager = PolicyManager::new(temp_file.path().to_path_buf()).unwrap();

        manager
            .add_allowed_host("host1.example.com".to_string(), None)
            .unwrap();
        manager
            .add_blocked_host("host2.example.com".to_string(), "test".to_string())
            .unwrap();

        assert_eq!(manager.list_allowed_hosts().len(), 1);
        assert_eq!(manager.list_blocked_hosts().len(), 1);

        manager.remove_allowed_host("host1.example.com").unwrap();
        manager.remove_blocked_host("host2.example.com").unwrap();

        assert_eq!(manager.list_allowed_hosts().len(), 0);
        assert_eq!(manager.list_blocked_hosts().len(), 0);
    }

    #[test]
    fn test_persistence() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        {
            let mut manager = PolicyManager::new(path.clone()).unwrap();
            manager
                .add_allowed_host("persistent.example.com".to_string(), None)
                .unwrap();
            manager.save().unwrap();
        }

        // Load again
        let manager = PolicyManager::new(path).unwrap();
        assert_eq!(manager.list_allowed_hosts().len(), 1);
        assert_eq!(
            manager.list_allowed_hosts()[0].hostname,
            "persistent.example.com"
        );
    }
}
