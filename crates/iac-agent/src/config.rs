//! Agent configuration: TOML file + flag overrides + sensible defaults.

use anyhow::{Context, Result};
use iac_providers::process::ExternalProviderSpec;
use iac_providers::shellout::ShellOutSpec;
#[cfg(feature = "wasm")]
use iac_providers::wasm::WasmProviderSpec;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Resolved agent configuration. Always fully populated.
#[derive(Debug, Clone)]
pub struct Config {
    /// Persistent state root: SQLite db, status file, applied-state cache, checkpoints.
    pub state_dir: PathBuf,
    /// Directory whose `*.yaml` files are read each observe cycle.
    pub manifests_dir: PathBuf,
    /// Latest agent status snapshot, written after each cycle.
    pub status_file: PathBuf,
    /// SQLite database path.
    pub db_path: PathBuf,
    /// Observe loop period.
    pub observe_interval: Duration,
    /// Environment label written to operations / runs.
    pub environment: String,
    /// Actor label recorded in operation audit logs.
    pub actor: String,
    /// Optional control-plane base URL, e.g. `http://controlplane:8443`.
    /// When `None`, agent operates standalone (Phase 0/1 behavior).
    pub server_url: Option<String>,
    /// Where the agent persists its `(agent_id, token)` after registration.
    pub identity_file: PathBuf,
    /// Hostname used as default agent name on first registration.
    pub agent_name: String,
    /// Optional path to a capability allowlist YAML. When the file exists,
    /// resources outside the declared allow/deny rules are rejected before
    /// they reach the executor. When the file is absent, the agent runs
    /// unrestricted (Phase 0/1 behavior).
    pub capabilities_file: PathBuf,
    /// Phase 7ak: optional mTLS settings for the agent → control-plane
    /// connection. `None` keeps the existing plain-HTTP / HTTPS-without-
    /// client-cert behavior.
    pub tls: AgentTlsConfig,
    /// Phase 7db.1: declarative shell-out providers loaded at startup.
    /// Each entry adds one resource kind to the provider registry by
    /// wrapping a small set of shell commands. Empty by default.
    pub shellout_providers: Vec<ShellOutSpec>,
    /// Phase 7db.2: external-process plugin providers. Each entry
    /// names a long-running plugin binary that speaks NDJSON-RPC.
    /// Empty by default.
    pub external_providers: Vec<ExternalProviderSpec>,
    /// Phase 7dc: sandboxed WebAssembly plugin providers. Each entry
    /// is a `.wasm` module run inside wasmtime with hard memory and
    /// fuel limits and no I/O imports. Empty by default. Phase 10:
    /// gated behind the `wasm` feature so MIPS / OpenWrt builds
    /// (which can't link cranelift) skip this field.
    #[cfg(feature = "wasm")]
    pub wasm_providers: Vec<WasmProviderSpec>,
}

/// Phase 7ak: agent-side TLS settings. All paths are PEM-encoded.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTlsConfig {
    /// Path to a CA-bundle PEM. When set, the agent verifies the
    /// control-plane's TLS cert against this CA instead of the
    /// system trust store. Required for self-signed PKIs.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Path to the agent's client cert (PEM). When set together with
    /// `client_key_file`, the agent presents this cert during the TLS
    /// handshake. Required when the server runs in `mode = mutual`.
    #[serde(default)]
    pub client_cert_file: Option<PathBuf>,
    /// Path to the agent's client private key (PEM). Paired with
    /// `client_cert_file`.
    #[serde(default)]
    pub client_key_file: Option<PathBuf>,
}

impl AgentTlsConfig {
    pub fn has_client_cert(&self) -> bool {
        self.client_cert_file.is_some() && self.client_key_file.is_some()
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct RawConfig {
    state_dir: Option<PathBuf>,
    manifests_dir: Option<PathBuf>,
    status_file: Option<PathBuf>,
    db_path: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    capabilities_file: Option<PathBuf>,
    /// Observe interval in seconds.
    observe_interval_secs: Option<u64>,
    environment: Option<String>,
    actor: Option<String>,
    server_url: Option<String>,
    agent_name: Option<String>,
    #[serde(default)]
    tls: AgentTlsConfig,
    #[serde(default)]
    shellout_providers: Vec<ShellOutSpec>,
    #[serde(default)]
    external_providers: Vec<ExternalProviderSpec>,
    #[cfg(feature = "wasm")]
    #[serde(default)]
    wasm_providers: Vec<WasmProviderSpec>,
}

#[derive(Debug, Default)]
pub struct ConfigOverrides {
    pub state_dir: Option<PathBuf>,
    pub manifests_dir: Option<PathBuf>,
    pub observe_interval_secs: Option<u64>,
    pub environment: Option<String>,
    pub actor: Option<String>,
    pub server_url: Option<String>,
    pub agent_name: Option<String>,
    pub capabilities_file: Option<PathBuf>,
}

impl Config {
    /// Load `Config` from an optional TOML file, then apply CLI overrides on top.
    /// Missing file is fine; defaults kick in.
    pub fn load(path: Option<&Path>, overrides: ConfigOverrides) -> Result<Self> {
        let raw = if let Some(p) = path {
            if p.exists() {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                toml::from_str::<RawConfig>(&text)
                    .with_context(|| format!("parsing config {}", p.display()))?
            } else {
                RawConfig::default()
            }
        } else {
            RawConfig::default()
        };

        let state_dir = overrides
            .state_dir
            .or(raw.state_dir)
            .unwrap_or_else(default_state_dir);
        let manifests_dir = overrides
            .manifests_dir
            .or(raw.manifests_dir)
            .unwrap_or_else(default_manifests_dir);
        let status_file = raw
            .status_file
            .unwrap_or_else(|| state_dir.join("status.json"));
        let db_path = raw.db_path.unwrap_or_else(|| state_dir.join("agent.db"));
        let observe_interval_secs = overrides
            .observe_interval_secs
            .or(raw.observe_interval_secs)
            .unwrap_or(60);
        let environment = overrides
            .environment
            .or(raw.environment)
            .unwrap_or_else(|| "default".to_string());
        let actor = overrides
            .actor
            .or(raw.actor)
            .unwrap_or_else(|| "iac-agent".to_string());
        let server_url = overrides.server_url.or(raw.server_url);
        let identity_file = raw
            .identity_file
            .unwrap_or_else(|| state_dir.join("identity.json"));
        let agent_name = overrides
            .agent_name
            .or(raw.agent_name)
            .unwrap_or_else(default_hostname);
        let capabilities_file = overrides
            .capabilities_file
            .or(raw.capabilities_file)
            .unwrap_or_else(|| state_dir.join("capabilities.yaml"));

        // Validate dynamic-provider configs eagerly so misconfiguration
        // surfaces at startup, not at first observe.
        for p in &raw.shellout_providers {
            p.validate()
                .map_err(|e| anyhow::anyhow!("shellout_providers[{}]: {e}", p.kind))?;
        }
        for p in &raw.external_providers {
            p.validate()
                .map_err(|e| anyhow::anyhow!("external_providers[{}]: {e}", p.kind))?;
        }
        #[cfg(feature = "wasm")]
        for p in &raw.wasm_providers {
            p.validate()
                .map_err(|e| anyhow::anyhow!("wasm_providers[{}]: {e}", p.kind))?;
        }
        // Reject duplicate kinds across all dynamic-provider sources —
        // late-binding shadows are a debugging trap.
        let mut seen = std::collections::HashSet::new();
        let kinds_iter = raw
            .shellout_providers
            .iter()
            .map(|p| &p.kind)
            .chain(raw.external_providers.iter().map(|p| &p.kind));
        #[cfg(feature = "wasm")]
        let kinds_iter = kinds_iter.chain(raw.wasm_providers.iter().map(|p| &p.kind));
        for k in kinds_iter {
            if !seen.insert(k.clone()) {
                anyhow::bail!(
                    "duplicate provider kind {k:?} declared more than once across \
                     shellout_providers / external_providers / wasm_providers"
                );
            }
        }

        Ok(Self {
            state_dir,
            manifests_dir,
            status_file,
            db_path,
            observe_interval: Duration::from_secs(observe_interval_secs),
            environment,
            actor,
            server_url,
            identity_file,
            agent_name,
            capabilities_file,
            tls: raw.tls,
            shellout_providers: raw.shellout_providers,
            external_providers: raw.external_providers,
            #[cfg(feature = "wasm")]
            wasm_providers: raw.wasm_providers,
        })
    }

    /// Ensure all needed directories exist.
    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("creating state_dir {}", self.state_dir.display()))?;
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db dir {}", parent.display()))?;
        }
        if let Some(parent) = self.status_file.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating status dir {}", parent.display()))?;
        }
        Ok(())
    }
}

fn default_state_dir() -> PathBuf {
    if cfg!(unix) && nix_is_root() {
        PathBuf::from("/var/lib/iac-agent")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".iac-agent").join("state")
    } else {
        PathBuf::from("/tmp/iac-agent")
    }
}

fn default_manifests_dir() -> PathBuf {
    if cfg!(unix) && nix_is_root() {
        PathBuf::from("/etc/iac-agent/manifests.d")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".iac-agent").join("manifests.d")
    } else {
        PathBuf::from("/etc/iac-agent/manifests.d")
    }
}

fn default_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "iac-agent".to_string())
}

fn nix_is_root() -> bool {
    // Rust std has no "is root" check. We use the absence of HOME and the
    // effective uid via the libc-less approximation: only root reads /proc/1/root
    // without permission errors. In practice, this is good enough for picking
    // a default state dir; users always have --state-dir to override.
    // Avoiding `libc` dependency here keeps the agent's tree small.
    matches!(std::env::var("USER").as_deref(), Ok("root"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn defaults_when_no_file() {
        let cfg = Config::load(None, ConfigOverrides::default()).unwrap();
        assert_eq!(cfg.observe_interval, Duration::from_secs(60));
        assert_eq!(cfg.environment, "default");
        assert_eq!(cfg.actor, "iac-agent");
    }

    #[test]
    #[cfg(feature = "wasm")]
    fn loads_dynamic_provider_specs() {
        let dir = TempDir::new().unwrap();
        let toml_path = dir.path().join("agent.toml");
        std::fs::write(
            &toml_path,
            r#"
[[shellout_providers]]
kind = "ufw.rule"
observe = "/usr/local/bin/iac-ufw observe"
apply = "/usr/local/bin/iac-ufw apply"
capability_keys = ["{{ name }}"]

[[external_providers]]
kind = "k8s.deployment"
binary = "/usr/local/bin/iac-k8s"

[[wasm_providers]]
kind = "policy.engine"
module = "/srv/iac/policy.wasm"
"#,
        )
        .unwrap();
        let cfg = Config::load(Some(&toml_path), ConfigOverrides::default()).unwrap();
        assert_eq!(cfg.shellout_providers.len(), 1);
        assert_eq!(cfg.shellout_providers[0].kind, "ufw.rule");
        assert_eq!(cfg.external_providers.len(), 1);
        assert_eq!(cfg.external_providers[0].kind, "k8s.deployment");
        assert_eq!(cfg.wasm_providers.len(), 1);
        assert_eq!(cfg.wasm_providers[0].kind, "policy.engine");
    }

    #[test]
    fn rejects_duplicate_provider_kinds() {
        let dir = TempDir::new().unwrap();
        let toml_path = dir.path().join("agent.toml");
        std::fs::write(
            &toml_path,
            r#"
[[shellout_providers]]
kind = "x"
observe = "/o"
apply = "/a"

[[external_providers]]
kind = "x"
binary = "/usr/local/bin/p"
"#,
        )
        .unwrap();
        let err = Config::load(Some(&toml_path), ConfigOverrides::default()).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    #[cfg(feature = "wasm")]
    fn rejects_duplicate_kind_across_wasm_and_shellout() {
        let dir = TempDir::new().unwrap();
        let toml_path = dir.path().join("agent.toml");
        std::fs::write(
            &toml_path,
            r#"
[[shellout_providers]]
kind = "policy"
observe = "/o"
apply = "/a"

[[wasm_providers]]
kind = "policy"
module = "/srv/policy.wasm"
"#,
        )
        .unwrap();
        let err = Config::load(Some(&toml_path), ConfigOverrides::default()).unwrap_err();
        assert!(format!("{err}").contains("duplicate"));
    }

    #[test]
    fn overrides_take_precedence() {
        let dir = TempDir::new().unwrap();
        let toml_path = dir.path().join("agent.toml");
        std::fs::write(
            &toml_path,
            r#"
observe_interval_secs = 120
environment = "from-file"
"#,
        )
        .unwrap();

        let overrides = ConfigOverrides {
            environment: Some("override".into()),
            observe_interval_secs: None,
            ..Default::default()
        };
        let cfg = Config::load(Some(&toml_path), overrides).unwrap();
        assert_eq!(cfg.observe_interval, Duration::from_secs(120));
        assert_eq!(cfg.environment, "override");
    }
}
