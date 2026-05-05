//! Phase 7db.1: declarative shell-out provider config.
//!
//! Operators describe a custom provider in `agent.toml` like:
//!
//! ```toml
//! [[shellout_providers]]
//! kind = "ufw.rule"
//! observe = "/usr/local/bin/iac-ufw observe"
//! apply = "/usr/local/bin/iac-ufw apply"
//! verify = "/usr/local/bin/iac-ufw verify"   # optional
//! rollback = "/usr/local/bin/iac-ufw rollback"  # optional
//! capability_keys = ["{{ name }}"]
//! env = ["UFW_DEBUG=1"]
//! timeout_secs = 30
//! ```
//!
//! Each command receives a JSON object on stdin and must emit a JSON
//! object on stdout. The exact contract is documented on
//! [`super::ShellOutProvider`].
//!
//! Why TOML config and not a YAML manifest: this lives next to the
//! agent's static settings, not its declarative resources. Reusing the
//! existing `agent.toml` keeps onboarding to one file.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShellOutSpec {
    /// Resource kind handled by this provider — must be unique across
    /// all providers (built-ins + other shellout entries).
    pub kind: String,

    /// Shell command for `observe`. Whitespace-split into argv (no
    /// shell metacharacters); first token is the executable, rest are
    /// args. Receives a JSON envelope on stdin (see crate docs); must
    /// print one JSON object to stdout.
    pub observe: String,

    /// Shell command for `apply`. Same argv splitting + JSON contract.
    pub apply: String,

    /// Optional `verify` command. Falls back to a re-`observe` when
    /// absent — the shellout provider derives a match-or-not result
    /// from the observed state.
    #[serde(default)]
    pub verify: Option<String>,

    /// Optional `rollback` command. Falls back to re-`apply`-ing the
    /// pre-apply observed state when absent. For providers that can't
    /// roll back (one-way operations like "delete user account"), set
    /// this to an explicit no-op script.
    #[serde(default)]
    pub rollback: Option<String>,

    /// Capability-key templates. Each entry is either a literal string
    /// or a `{{ field }}` placeholder that pulls from the resource's
    /// `spec` (top-level scalar fields only — keep it simple). The
    /// agent's allowlist matches each key against per-kind glob rules.
    /// Default: empty → unrestricted.
    #[serde(default)]
    pub capability_keys: Vec<String>,

    /// Extra env vars for child processes (e.g. `["UFW_DEBUG=1"]`).
    /// Inherited env is preserved; these are additive overrides.
    #[serde(default)]
    pub env: Vec<String>,

    /// Per-command timeout. Default: 30 seconds. Slow underlying
    /// CLIs (large `apt update`, ACME challenges) need a longer
    /// budget — operators can bump this. Hard cap is 600 seconds:
    /// anything longer should be a real provider, not shellout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    30
}

impl ShellOutSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.kind.is_empty() {
            return Err("kind must not be empty".into());
        }
        // Reject names that look like protocol noise. We don't want
        // an operator's typo (`kind = "..."`) to silently shadow a
        // built-in.
        if self.kind.chars().any(|c| c.is_whitespace()) {
            return Err(format!("kind {:?} contains whitespace", self.kind));
        }
        if self.observe.trim().is_empty() {
            return Err("observe command must not be empty".into());
        }
        if self.apply.trim().is_empty() {
            return Err("apply command must not be empty".into());
        }
        if !(1..=600).contains(&self.timeout_secs) {
            return Err(format!(
                "timeout_secs {} out of range (1..=600)",
                self.timeout_secs
            ));
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

/// Split `cmd` into argv. Whitespace-only — no shell metacharacters,
/// no quotes, no escapes. Operators who need shell features wrap
/// their command with `sh -c "..."` themselves; we keep the parser
/// trivial because misparsing here turns into RCE-shaped surprises.
pub fn split_argv(cmd: &str) -> Vec<String> {
    cmd.split_whitespace().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(kind: &str) -> ShellOutSpec {
        ShellOutSpec {
            kind: kind.into(),
            observe: "/bin/true".into(),
            apply: "/bin/true".into(),
            verify: None,
            rollback: None,
            capability_keys: vec![],
            env: vec![],
            timeout_secs: 30,
        }
    }

    #[test]
    fn rejects_empty_kind() {
        let mut spec = s("ok");
        spec.kind = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_whitespace_in_kind() {
        let mut spec = s("ok");
        spec.kind = "two words".into();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_blank_commands() {
        let mut spec = s("ok");
        spec.observe = "  ".into();
        assert!(spec.validate().is_err());
        let mut spec = s("ok");
        spec.apply = String::new();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_zero_or_huge_timeout() {
        let mut spec = s("ok");
        spec.timeout_secs = 0;
        assert!(spec.validate().is_err());
        let mut spec = s("ok");
        spec.timeout_secs = 601;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn split_argv_basic() {
        assert_eq!(
            split_argv("/usr/bin/foo --flag value"),
            vec!["/usr/bin/foo", "--flag", "value"]
        );
        assert_eq!(split_argv(""), Vec::<String>::new());
    }

    #[test]
    fn parses_minimal_toml() {
        let toml = r#"
kind = "ufw.rule"
observe = "/bin/observe"
apply = "/bin/apply"
"#;
        let spec: ShellOutSpec = toml::from_str(toml).unwrap();
        spec.validate().unwrap();
        assert_eq!(spec.kind, "ufw.rule");
        assert_eq!(spec.timeout_secs, 30);
        assert!(spec.capability_keys.is_empty());
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = r#"
kind = "x"
observe = "/o"
apply = "/a"
junk = "no"
"#;
        assert!(toml::from_str::<ShellOutSpec>(toml).is_err());
    }
}
