use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub state_dir: PathBuf,
    /// Maximum bytes accepted in a single push (observations or drift batch).
    pub max_body_bytes: usize,
    /// Optional admin token in plaintext. Used by the operator-facing
    /// endpoints (submit operation, fetch operation status). When `None`,
    /// those endpoints return 503: server is in agent-only mode. Phase 6
    /// replaces this with a real RBAC + login flow.
    pub admin_token: Option<String>,
    /// Phase 6d: operator-defined policies. Operations matching a policy with
    /// `requires_approval=true` enter `pending_approval` until an admin token
    /// holder calls `.../approve`.
    pub policies: Vec<crate::policy::Policy>,
    /// Phase 6g: retention windows for the periodic pruner. Conservative
    /// defaults (30-90d) keep forensic data unless operators opt into
    /// shorter windows.
    pub retention: crate::retention::RetentionConfig,
    /// Phase 7h: per-environment rate limit on operation submissions.
    /// Defaults to disabled. When set, exceeding the cap returns 429 with
    /// a `Retry-After` header.
    pub rate_limit: crate::rate_limit::RateLimitConfig,
    /// Phase 7i: absolute-time maintenance windows. Submissions during
    /// an active window are rejected with 503. Empty list = no windows.
    pub maintenance_windows: Vec<crate::maintenance::MaintenanceWindow>,
    /// Phase 7s: weekly-recurring maintenance windows (UTC, HH:MM
    /// resolution). Same submission-blocking semantics as
    /// `maintenance_windows` but easier to express "every Monday 02:00-04:00."
    pub recurring_maintenance_windows: Vec<crate::maintenance::RecurringMaintenanceWindow>,
    /// Phase 7t: outbound webhooks for audit events.
    pub webhooks: crate::webhook::WebhooksConfig,
    /// Phase 7ak: TLS / mTLS termination. Default `mode = "none"`
    /// keeps the existing plain-HTTP behavior for tests and dev.
    pub tls: crate::tls::TlsConfig,
    /// Phase 7am: secret-resolver registry config. The `env` resolver is
    /// always available; `vault` is opt-in via the `[secrets.vault]` block.
    pub secrets: SecretsConfig,
    /// Phase 7br: format used when emitting `Retry-After` headers from
    /// the server (rate-limit 429s, maintenance 503s). RFC 7231 §7.1.3
    /// allows two forms: `delta-seconds` (a non-negative integer) and
    /// `HTTP-date` (IMF-fixdate). Default `delta-seconds` preserves
    /// pre-7br behavior. Operators talking to legacy clients that
    /// prefer date form can opt into `http-date`. Inbound parsing
    /// (Phase 7au) already accepts both forms regardless of this knob.
    pub retry_after_format: RetryAfterFormat,
    /// Phase 7bv: operator-defined composite expanders. Loaded from
    /// the `[[modules]]` array in the TOML config; validated at
    /// startup. Empty by default — built-in composites (service,
    /// cron-job-bundle, web-with-monitoring) cover the common case;
    /// modules let operators define their own kinds without
    /// recompiling the server.
    pub modules: Vec<crate::modules::Module>,
    /// Phase 7cc: TTL for newly-issued agent bearer tokens, in
    /// seconds. `None` (default) keeps pre-7cc semantics — new tokens
    /// are issued without expiry. `Some(N)` makes the server stamp
    /// `now + N` as the expiry on every register / rotate; auth
    /// rejects expired tokens with 401. Existing agents registered
    /// before the operator opted into TTL keep their grandfathered
    /// tokens (NULL `token_expires_at`) until manually rotated.
    ///
    /// Recommended values: 24h (86400) for balanced security; 7d
    /// (604800) for low-rotation environments. Going below 1h is
    /// generally too aggressive — agents that miss a rotation window
    /// (network blip during half-life) lose their token and need
    /// re-registration.
    pub agent_token_ttl_secs: Option<u64>,
    /// Phase 7ck: SSH push targets. Each entry registers a virtual
    /// agent with `kind = 'ssh'`. The control plane's push worker
    /// pool dispatches assignments to these via `ssh` instead of
    /// waiting for them to poll. Empty list (default) preserves
    /// pre-7ck pull-only behavior.
    pub ssh_targets: Vec<SshTargetConfig>,
    /// Phase 9-F1: how often the background WAL-truncate task runs,
    /// in seconds. Default 60. The task issues
    /// `PRAGMA wal_checkpoint(TRUNCATE)` against the SQLite store —
    /// SQLite's own `wal_autocheckpoint` (every 1000 frames) only
    /// pages back to the main DB, it doesn't shrink the WAL file,
    /// so under sustained mixed read/write load the WAL grows
    /// unboundedly. This task forces a TRUNCATE periodically so the
    /// disk usage stays bounded.
    ///
    /// `0` disables the task. No effect on Postgres deployments —
    /// the method is a no-op there. Recommended values: 30–120 s
    /// for fleet-class deployments; lower for tiny-disk targets,
    /// higher when latency budget cares more than disk usage. Going
    /// below 5 s is wasteful — checkpoint overhead dominates.
    pub wal_checkpoint_interval_secs: u64,
    /// Phase 9-F6 follow-up: how long the HTTP server will keep
    /// draining in-flight connections after a SIGTERM before being
    /// forcibly aborted, in seconds. F6 rolling-upgrade saw a 332 s
    /// graceful-shutdown when the burst of 50 in-flight ops kept
    /// the server busy; under systemd's TimeoutStopSec=90 (default)
    /// that means SIGKILL during graceful shutdown — not great. The
    /// timeout caps drain at a known bound so operators get a clean
    /// SIGTERM exit even under load.
    ///
    /// Default 10 s (matches the TLS path's previously-hardcoded
    /// `handle.graceful_shutdown(Some(10 s))`). Set higher (30–60 s)
    /// if your service unit's TimeoutStopSec is also higher and
    /// you want more time for clean shutdown.
    pub shutdown_timeout_secs: u64,
    /// Phase 9 follow-up: list of IP addresses that, when seen as the
    /// raw socket peer, are treated as trusted reverse proxies. For
    /// requests originating from these, the per-IP rate-limit buckets
    /// (login, register) read the leftmost entry in the
    /// `X-Forwarded-For` header instead of the socket peer's IP, so a
    /// single proxy fronting many real clients doesn't squash them
    /// all into one bucket.
    ///
    /// Empty by default — pre-Phase-9 behaviour, no header trust, all
    /// rate limits keyed by raw socket IP. Operators behind a known
    /// proxy populate this with their proxy's egress IPs; requests
    /// from any other peer keep using socket IP regardless of header
    /// presence (so a malicious client can't spoof X-Forwarded-For to
    /// dodge a bucket).
    pub trusted_proxies: Vec<std::net::IpAddr>,
}

/// Phase 7ck: declarative SSH push target. Validated at server
/// startup — bad host string, missing identity file, or invalid
/// port surface as a config error before the server binds.
///
/// Auth model: SSH key only. The key must already be on the server
/// box and accepted by the target's `~/.ssh/authorized_keys`.
/// Operators relying on `ssh-agent` can omit `identity_file` and
/// set `SSH_AUTH_SOCK` in the server's environment.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshTargetConfig {
    /// Logical name. Routed to via `spec.hostSelector.name` in
    /// manifests, exactly like a pull-mode agent.
    pub name: String,
    pub environment: String,
    /// Hostname or IP. SSH `User@Host` semantics — should resolve.
    pub host: String,
    /// SSH user. Defaults to `root`.
    #[serde(default = "default_ssh_user")]
    pub user: String,
    /// SSH port. Defaults to 22.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Path to private key on the server box (must be 0600 / 0400
    /// readable by the iac-controlplane process). When `None`, the
    /// server's ssh-agent (`SSH_AUTH_SOCK`) is consulted instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<PathBuf>,
    /// Path to the `iac` (or `iac-applier`) binary on the target.
    /// Defaults to `/usr/local/bin/iac`. Must be pre-installed —
    /// auto-staging on push is a Phase 7cl future iteration.
    #[serde(default = "default_remote_iac_path")]
    pub remote_iac_path: String,
    /// Capabilities allowlist for this target — kinds it's allowed
    /// to receive. Empty list = allow all (no restriction). Used
    /// the same way pull-agent capabilities work: protect a target
    /// from being asked to apply something it shouldn't.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Per-target connection timeout in seconds. Default 10. Bounds
    /// `ssh -o ConnectTimeout=N`.
    #[serde(default = "default_ssh_connect_timeout")]
    pub connect_timeout_secs: u32,
    /// Phase 7cp.1 (security fix #4.4): server-side host key policy.
    /// Default `strict` rejects unknown host keys — protects against
    /// MITM at first push. Operator must pre-populate `known_hosts`
    /// (via the `known_hosts_file` field below or the system default
    /// `~/.ssh/known_hosts`) before the worker can connect.
    ///
    /// `accept_new` mirrors the pre-7cp behavior: trust on first
    /// contact, log+pin. **DANGEROUS** for daemon push paths because
    /// an MITM at the very first push silently pins their key, and
    /// every subsequent push runs through the attacker. Provided for
    /// dev / homelab convenience only — never set in production.
    #[serde(default)]
    pub host_key_policy: SshHostKeyPolicy,
    /// Optional explicit `known_hosts` file for this target. When
    /// `None`, ssh uses the system defaults (`~/.ssh/known_hosts`,
    /// `/etc/ssh/ssh_known_hosts`). Operators running iac-controlplane
    /// as a sandboxed `DynamicUser=true` systemd unit need this
    /// because the daemon has no real `~`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_hosts_file: Option<PathBuf>,
}

/// Phase 7cp.1: see `SshTargetConfig::host_key_policy` for semantics.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshHostKeyPolicy {
    /// Reject unknown host keys (`StrictHostKeyChecking=yes`).
    /// Default — production-safe.
    #[default]
    Strict,
    /// Trust on first connect (`StrictHostKeyChecking=accept-new`).
    /// Subject to MITM at first push. Operator-acknowledged opt-in.
    AcceptNew,
}

fn default_ssh_user() -> String {
    "root".into()
}
fn default_ssh_port() -> u16 {
    22
}
fn default_remote_iac_path() -> String {
    "/usr/local/bin/iac".into()
}
fn default_ssh_connect_timeout() -> u32 {
    10
}

impl SshTargetConfig {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("ssh_targets[].name must not be empty");
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            anyhow::bail!(
                "ssh_targets[].name {:?} must be alphanumeric with -_.",
                self.name
            );
        }
        if self.environment.is_empty() {
            anyhow::bail!("ssh_targets[{}].environment must not be empty", self.name);
        }
        if self.host.is_empty() {
            anyhow::bail!("ssh_targets[{}].host must not be empty", self.name);
        }
        // Defensive: reject control chars in host/user — these end up
        // in shell args via `ssh user@host`.
        for (field, value) in [("host", &self.host), ("user", &self.user)] {
            if value
                .chars()
                .any(|c| c.is_control() || c == ' ' || c == '\'' || c == '"')
            {
                anyhow::bail!(
                    "ssh_targets[{}].{} contains unsafe characters: {:?}",
                    self.name,
                    field,
                    value
                );
            }
        }
        if self.port == 0 {
            anyhow::bail!("ssh_targets[{}].port must be 1..=65535", self.name);
        }
        if let Some(p) = &self.identity_file
            && !p.exists()
        {
            anyhow::bail!(
                "ssh_targets[{}].identity_file {} does not exist",
                self.name,
                p.display()
            );
        }
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 300 {
            anyhow::bail!(
                "ssh_targets[{}].connect_timeout_secs {} out of range 1..=300",
                self.name,
                self.connect_timeout_secs
            );
        }
        // Phase 7cz.15: when host_key_policy=strict, require an
        // explicit known_hosts_file. Otherwise `ssh` falls back to
        // `~/.ssh/known_hosts` of the server-process uid — content
        // the operator may not actually control. Fail-closed at
        // config-load is louder than a successful push to the wrong
        // host on first contact.
        if self.host_key_policy == SshHostKeyPolicy::Strict && self.known_hosts_file.is_none() {
            anyhow::bail!(
                "ssh_targets[{}]: host_key_policy=strict requires known_hosts_file to be set \
                 (otherwise ssh uses ~/.ssh/known_hosts of the server process, which may not \
                 contain a pinned entry for {host:?})",
                self.name,
                host = self.host,
            );
        }
        if let Some(p) = &self.known_hosts_file
            && !p.exists()
        {
            anyhow::bail!(
                "ssh_targets[{}].known_hosts_file {} does not exist",
                self.name,
                p.display()
            );
        }
        Ok(())
    }
}

/// Phase 7br: outbound `Retry-After` rendering format. Matches the
/// two RFC 7231 §7.1.3 forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetryAfterFormat {
    /// Numeric `Retry-After: 30`. Pre-7br default.
    #[default]
    DeltaSeconds,
    /// RFC 7231 IMF-fixdate `Retry-After: Sun, 06 Nov 1994 08:49:37 GMT`.
    HttpDate,
}

/// `[secrets]` block — wires which resolvers are available at submission
/// time. `env` is always on (it has no credentials of its own, just reads
/// the server process's environment). `vault` and `sops` are opt-in.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct SecretsConfig {
    /// Optional Vault backend.
    #[serde(default)]
    pub vault: Option<VaultConfig>,
    /// Optional Mozilla SOPS backend (Phase 7ct).
    #[serde(default)]
    pub sops: Option<SopsConfig>,
}

/// `[secrets.sops]` — Mozilla SOPS resolver. Decrypts age/PGP-encrypted
/// YAML/JSON files in a sandboxed directory by shelling out to the
/// system `sops` binary.
///
/// `base_dir` is the sandbox root: every `${secret://sops/<rel>#<field>}`
/// reference resolves `<rel>` against this directory and refuses to
/// escape it. Operators must place their `*.enc.yaml` files here.
///
/// `binary` is the path to the `sops` executable. If unset, defaults to
/// `$IAC_SOPS_BIN` if that is set, otherwise plain `"sops"` (resolved
/// via `$PATH`).
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct SopsConfig {
    pub base_dir: PathBuf,
    #[serde(default)]
    pub binary: Option<String>,
}

impl SopsConfig {
    /// Resolve the binary path, preferring config → env → "sops".
    pub fn resolve_binary(&self) -> String {
        if let Some(b) = self.binary.as_deref() {
            return b.to_string();
        }
        if let Ok(b) = std::env::var("IAC_SOPS_BIN")
            && !b.is_empty()
        {
            return b;
        }
        "sops".into()
    }
}

/// `[secrets.vault]` — connection params for the HashiCorp Vault resolver.
/// Either `token` (inline, fine for dev) or `token_env` (recommended for
/// production: load from a process-scope env var) must be set.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct VaultConfig {
    /// Vault root URL (e.g. `http://127.0.0.1:8200`). No trailing slash.
    pub addr: String,
    /// Inline token. Avoid in production — leaks via config-file backups.
    #[serde(default)]
    pub token: Option<String>,
    /// Name of the env var holding the token. Read once at startup.
    #[serde(default)]
    pub token_env: Option<String>,
}

impl VaultConfig {
    /// Resolve the configured token, preferring an explicit inline value
    /// and falling back to `token_env`. Returns `None` if neither is set.
    pub fn resolve_token(&self) -> Option<String> {
        if let Some(t) = self.token.as_deref() {
            return Some(t.to_string());
        }
        if let Some(var) = self.token_env.as_deref() {
            return std::env::var(var).ok().filter(|s| !s.is_empty());
        }
        None
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct RawConfig {
    bind: Option<String>,
    database_url: Option<String>,
    state_dir: Option<PathBuf>,
    max_body_bytes: Option<usize>,
    admin_token: Option<String>,
    #[serde(default, rename = "policies")]
    policies: Vec<crate::policy::Policy>,
    #[serde(default)]
    retention: crate::retention::RetentionConfig,
    #[serde(default)]
    rate_limit: crate::rate_limit::RateLimitConfig,
    #[serde(default)]
    maintenance_windows: Vec<crate::maintenance::MaintenanceWindow>,
    #[serde(default)]
    recurring_maintenance_windows: Vec<crate::maintenance::RecurringMaintenanceWindow>,
    #[serde(default)]
    webhooks: crate::webhook::WebhooksConfig,
    #[serde(default)]
    tls: crate::tls::TlsConfig,
    #[serde(default)]
    secrets: SecretsConfig,
    #[serde(default)]
    retry_after_format: RetryAfterFormat,
    #[serde(default)]
    modules: Vec<crate::modules::Module>,
    #[serde(default)]
    agent_token_ttl_secs: Option<u64>,
    #[serde(default)]
    ssh_targets: Vec<SshTargetConfig>,
    #[serde(default = "default_wal_checkpoint_interval")]
    wal_checkpoint_interval_secs: u64,
    #[serde(default = "default_shutdown_timeout")]
    shutdown_timeout_secs: u64,
    #[serde(default)]
    trusted_proxies: Vec<std::net::IpAddr>,
}

fn default_wal_checkpoint_interval() -> u64 {
    60
}

fn default_shutdown_timeout() -> u64 {
    10
}

#[derive(Debug, Default)]
pub struct Overrides {
    pub bind: Option<String>,
    pub database_url: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub admin_token: Option<String>,
}

impl Config {
    pub fn load(path: Option<&Path>, overrides: Overrides) -> Result<Self> {
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

        let bind_str = overrides
            .bind
            .or(raw.bind)
            .unwrap_or_else(|| "127.0.0.1:8443".to_string());
        let bind: SocketAddr = bind_str
            .parse()
            .with_context(|| format!("invalid bind address {bind_str}"))?;

        let state_dir = overrides
            .state_dir
            .or(raw.state_dir)
            .unwrap_or_else(default_state_dir);

        let database_url = overrides
            .database_url
            .or(raw.database_url)
            .unwrap_or_else(|| {
                format!(
                    "sqlite://{}?mode=rwc",
                    state_dir.join("controlplane.db").display()
                )
            });

        let max_body_bytes = raw.max_body_bytes.unwrap_or(8 * 1024 * 1024);

        // Admin token preference order: CLI override > config file > env var.
        let admin_token = overrides
            .admin_token
            .or(raw.admin_token)
            .or_else(|| std::env::var("IAC_ADMIN_TOKEN").ok())
            .filter(|s| !s.is_empty());

        let policies = raw.policies;
        let retention = raw.retention;
        let rate_limit = raw.rate_limit;
        let maintenance_windows = raw.maintenance_windows;
        let recurring_maintenance_windows = raw.recurring_maintenance_windows;
        let webhooks = raw.webhooks;
        // Phase 7cz.5: SSRF guard — refuse webhook URLs pointing at
        // loopback / private / cloud-metadata targets unless the
        // operator explicitly opted in. Failing here at config-load
        // is much louder than failing at first dispatch.
        webhooks
            .validate()
            .map_err(|e| anyhow::anyhow!("[webhooks] {e}"))?;
        let tls = raw.tls;
        let secrets = raw.secrets;
        let retry_after_format = raw.retry_after_format;
        // Phase 7bv: validate each operator-defined module at config
        // load. Surfacing typos / collisions / undeclared template
        // vars at startup beats failing on first apply.
        let modules = raw.modules;
        let mut module_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for m in &modules {
            m.validate()
                .map_err(|e| anyhow::anyhow!("module {:?}: {e}", m.name))?;
            if !module_names.insert(m.name.as_str()) {
                anyhow::bail!("module name {:?} declared twice", m.name);
            }
        }
        // Phase 7cc: validate agent_token_ttl_secs is sensible.
        // Phase 7dh.12 (invariant audit): also enforce an upper bound.
        // The expiry is computed via `now.checked_add(Span::seconds(ttl))`
        // with `.unwrap_or(now)` fallback (see `store::register_agent`
        // / `rotate_agent_token`). A `ttl` near `i64::MAX` overflows
        // the span addition, the fallback fires, and tokens expire
        // *immediately* — every agent gets 401 on its next request,
        // turning a typo'd config into a fleet-wide DoS. Cap at
        // 10 years; anyone configuring longer is doing something
        // unusual and should hit the validate gate.
        const TTL_UPPER_BOUND_SECS: u64 = 10 * 365 * 24 * 60 * 60; // 10y
        if let Some(ttl) = raw.agent_token_ttl_secs {
            if ttl < 60 {
                anyhow::bail!(
                    "agent_token_ttl_secs {ttl} too short (minimum 60); below this, \
                     rotation can't keep up with normal agent poll intervals"
                );
            }
            if ttl > TTL_UPPER_BOUND_SECS {
                anyhow::bail!(
                    "agent_token_ttl_secs {ttl} exceeds 10-year upper bound \
                     ({TTL_UPPER_BOUND_SECS}); larger values overflow the \
                     expiry-timestamp arithmetic and silently produce \
                     immediately-expired tokens"
                );
            }
        }
        // Phase 7ck: validate ssh_targets at startup.
        let ssh_targets = raw.ssh_targets;
        let mut target_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for t in &ssh_targets {
            t.validate()
                .map_err(|e| anyhow::anyhow!("ssh_targets[{}]: {e}", t.name))?;
            if !target_names.insert(t.name.as_str()) {
                anyhow::bail!("ssh_targets name {:?} declared twice", t.name);
            }
        }
        Ok(Self {
            bind,
            database_url,
            state_dir,
            max_body_bytes,
            admin_token,
            policies,
            retention,
            rate_limit,
            maintenance_windows,
            recurring_maintenance_windows,
            webhooks,
            tls,
            secrets,
            retry_after_format,
            modules,
            agent_token_ttl_secs: raw.agent_token_ttl_secs,
            ssh_targets,
            wal_checkpoint_interval_secs: raw.wal_checkpoint_interval_secs,
            shutdown_timeout_secs: raw.shutdown_timeout_secs,
            trusted_proxies: raw.trusted_proxies,
        })
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("creating state_dir {}", self.state_dir.display()))?;
        Ok(())
    }
}

fn default_state_dir() -> PathBuf {
    if matches!(std::env::var("USER").as_deref(), Ok("root")) {
        PathBuf::from("/var/lib/iac-controlplane")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".iac-controlplane").join("state")
    } else {
        PathBuf::from("/tmp/iac-controlplane")
    }
}
