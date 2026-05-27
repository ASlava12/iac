//! Phase 7db.2: external-process provider config.
//!
//! Operators describe an external-process provider in `agent.toml`:
//!
//! ```toml
//! [[external_providers]]
//! kind = "k8s.deployment"          # required
//! binary = "/usr/local/bin/iac-k8s-plugin"
//! args = ["--cluster", "prod"]     # optional, prepended to argv
//! env = ["KUBECONFIG=/etc/iac/kc"] # optional
//! restart_on_crash = true          # default true
//! handshake_timeout_secs = 5       # default 5
//! call_timeout_secs = 60           # default 60
//! ```
//!
//! `kind` must match the announce message the plugin emits at startup
//! — the agent fails closed on mismatch (catches binary-vs-config
//! drift before any request is dispatched).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalProviderSpec {
    /// Resource kind handled by this plugin. Must match the kind the
    /// plugin's hello message reports (defence in depth).
    pub kind: String,

    /// Absolute path to the plugin binary.
    pub binary: PathBuf,

    /// CLI args prepended to the plugin invocation.
    #[serde(default)]
    pub args: Vec<String>,

    /// Extra env vars (`KEY=VALUE` entries). Inherited env preserved.
    #[serde(default)]
    pub env: Vec<String>,

    /// If `true` (default) and the plugin crashes mid-session, the
    /// next call respawns it. Operators with strict "fail loud"
    /// preferences can set this to `false` to surface the crash.
    #[serde(default = "default_true")]
    pub restart_on_crash: bool,

    /// Time the agent waits for the plugin's hello message before
    /// declaring the spawn dead. Default 5s.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,

    /// Time the agent waits for any single method response before
    /// killing and (optionally) respawning the plugin. Default 60s
    /// — much longer than shellout because plugins maintain state
    /// (caches, connections) across calls.
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,

    /// Phase 7dh.4: optional content-hash pin (lowercase 64-char
    /// hex SHA-256) on the plugin binary. When set, the agent
    /// hashes the file at first spawn and refuses to launch the
    /// process on mismatch. `None` keeps the historical
    /// "trust the path" behaviour. Recommended for production.
    #[serde(default)]
    pub binary_sha256: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_handshake_timeout() -> u64 {
    5
}
fn default_call_timeout() -> u64 {
    60
}

impl ExternalProviderSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.kind.is_empty() {
            return Err("kind must not be empty".into());
        }
        if self.kind.chars().any(|c| c.is_whitespace()) {
            return Err(format!("kind {:?} contains whitespace", self.kind));
        }
        if !self.binary.is_absolute() {
            return Err(format!("binary {} must be absolute", self.binary.display()));
        }
        if !(1..=60).contains(&self.handshake_timeout_secs) {
            return Err(format!(
                "handshake_timeout_secs {} out of range (1..=60)",
                self.handshake_timeout_secs
            ));
        }
        if !(1..=3600).contains(&self.call_timeout_secs) {
            return Err(format!(
                "call_timeout_secs {} out of range (1..=3600)",
                self.call_timeout_secs
            ));
        }
        if let Some(h) = &self.binary_sha256 {
            crate::sha256_pin::validate_sha256_hex(h, "binary_sha256")?;
        }
        Ok(())
    }

    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }

    pub fn call_timeout(&self) -> Duration {
        Duration::from_secs(self.call_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_spec() -> ExternalProviderSpec {
        ExternalProviderSpec {
            kind: "k.kind".into(),
            binary: "/usr/local/bin/p".into(),
            args: vec![],
            env: vec![],
            restart_on_crash: true,
            handshake_timeout_secs: 5,
            call_timeout_secs: 60,
            binary_sha256: None,
        }
    }

    #[test]
    fn validate_rejects_empty_kind() {
        let mut s = ok_spec();
        s.kind = String::new();
        assert!(s.validate().is_err());
    }

    #[test]
    fn validate_rejects_relative_binary() {
        let mut s = ok_spec();
        s.binary = "p".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_timeouts() {
        let mut s = ok_spec();
        s.handshake_timeout_secs = 0;
        assert!(s.validate().is_err());
        let mut s = ok_spec();
        s.call_timeout_secs = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn parses_minimal_toml() {
        let toml = r#"
kind = "k8s.deployment"
binary = "/usr/local/bin/iac-k8s"
"#;
        let s: ExternalProviderSpec = toml::from_str(toml).unwrap();
        s.validate().unwrap();
        assert!(s.restart_on_crash);
        assert_eq!(s.handshake_timeout_secs, 5);
    }
}
