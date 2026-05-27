//! Phase 7cm: inventory file parser.
//!
//! Operators describe groups of hosts in a YAML file:
//!
//! ```yaml
//! defaults:
//!   user: deploy
//!   identity_file: ~/.ssh/id_ed25519
//! groups:
//!   prod-web:
//!     - host: 10.0.1.10
//!     - host: 10.0.1.11
//!   edge:
//!     - host: 192.168.50.1
//!       user: admin
//!       identity_file: /etc/iac/keys/edge.key
//!       remote_iac: /usr/local/bin/iac
//!       port: 2222
//! ```
//!
//! `iac apply manifest.yaml --inventory inv.yaml --group prod-web`
//! resolves to a `Vec<SshTarget>` with all overrides layered (per-host
//! beats group-level beats `defaults`). The same parser feeds
//! `iac run` (Phase 7cn).
//!
//! Why YAML and not the same TOML the server uses: operators
//! frequently come from Ansible inventories and expect this shape.
//! YAML also handles list-of-host-records more naturally than TOML's
//! nested-table syntax. Both formats can be added later if there's
//! demand — the parsed shape is the same.

use crate::ssh_dispatch::SshTarget;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct InventoryFile {
    #[serde(default)]
    pub defaults: HostOverrides,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<HostEntry>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HostOverrides {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    #[serde(default)]
    pub remote_iac: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    pub host: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    #[serde(default)]
    pub remote_iac: Option<String>,
    /// Optional friendly label. Surfaces in fan-out output instead
    /// of `user@host` if set. Useful when hosts are differentiated
    /// by IP — operator labels them `web-01`, `web-02`, etc.
    #[serde(default)]
    pub label: Option<String>,
}

impl InventoryFile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading inventory {}", path.display()))?;
        let inv: InventoryFile = serde_yaml_ng::from_str(&text)
            .with_context(|| format!("parsing inventory {}", path.display()))?;
        inv.validate()?;
        Ok(inv)
    }

    fn validate(&self) -> Result<()> {
        for (group, hosts) in &self.groups {
            if group.is_empty() {
                anyhow::bail!("group name must not be empty");
            }
            if hosts.is_empty() {
                anyhow::bail!("group {group:?} has no hosts");
            }
            for h in hosts {
                if h.host.is_empty() {
                    anyhow::bail!("group {group:?}: a host entry has empty `host`");
                }
            }
        }
        Ok(())
    }

    /// Resolve hosts in `group` into concrete `SshTarget`s. Per-host
    /// overrides win; group has no level of its own; `defaults` fills
    /// gaps. Returns `Err` if the group doesn't exist.
    ///
    /// `limit` filters hosts by the LimitExpr grammar (Phase 7da.2):
    /// * `web-01` — exact match on `host` or `label`
    /// * `web-*` — glob (`*` matches any chars except `,`)
    /// * `!web-03` — negation (exclude this host)
    /// * `web-01,web-02` — comma-separated list of any of the above;
    ///   inclusion patterns are OR'd, negations subtract
    /// * `*,!web-03` — everything except web-03
    ///
    /// Empty `limit` (or `None`) returns the full group.
    pub fn resolve(&self, group: &str, limit: Option<&str>) -> Result<Vec<SshTarget>> {
        let hosts = self
            .groups
            .get(group)
            .with_context(|| format!("group {group:?} not found in inventory"))?;
        let expr = LimitExpr::parse(limit)?;
        let mut out = Vec::with_capacity(hosts.len());
        for h in hosts {
            if expr.matches(h) {
                out.push(self.materialize(h));
            }
        }
        if let Some(lim) = limit
            && out.is_empty()
        {
            anyhow::bail!("no host in group {group:?} matched --limit {lim:?}");
        }
        Ok(out)
    }

    fn materialize(&self, h: &HostEntry) -> SshTarget {
        let user = h
            .user
            .clone()
            .or_else(|| self.defaults.user.clone())
            .unwrap_or_else(|| {
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".into())
            });
        let port = h.port.or(self.defaults.port).unwrap_or(22);
        let identity_file = h
            .identity_file
            .clone()
            .or_else(|| self.defaults.identity_file.clone())
            .map(expand_tilde);
        let remote_iac = h
            .remote_iac
            .clone()
            .or_else(|| self.defaults.remote_iac.clone());
        let label = h
            .label
            .clone()
            .unwrap_or_else(|| format!("{user}@{}", h.host));
        SshTarget {
            label,
            user,
            host: h.host.clone(),
            port,
            identity_file,
            remote_iac,
            control_dir: None,
        }
    }
}

/// Phase 7da.2: parsed `--limit` expression. Modeled on Ansible's
/// `--limit` syntax — a comma-separated list where each entry is
/// either an inclusion pattern or a `!`-prefixed exclusion. A host
/// matches when at least one inclusion matches AND no exclusion
/// matches. Empty list (or `None`) matches everything.
#[derive(Debug, Clone, Default)]
struct LimitExpr {
    include: Vec<Pattern>,
    exclude: Vec<Pattern>,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// `web-01` — must equal `host` or `label`.
    Exact(String),
    /// `web-*` — glob; only `*` is special (matches any chars except `,`).
    Glob(String),
}

impl LimitExpr {
    fn parse(limit: Option<&str>) -> Result<Self> {
        let Some(s) = limit.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(Self::default());
        };
        let mut include = Vec::new();
        let mut exclude = Vec::new();
        for raw in s.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(rest) = token.strip_prefix('!') {
                let rest = rest.trim();
                if rest.is_empty() {
                    anyhow::bail!("--limit: empty pattern after `!`");
                }
                exclude.push(Pattern::from_token(rest));
            } else {
                include.push(Pattern::from_token(token));
            }
        }
        // No inclusion patterns means "everything"; preserves the
        // common `*,!web-03` shorthand.
        if include.is_empty() && !exclude.is_empty() {
            include.push(Pattern::Glob("*".into()));
        }
        Ok(Self { include, exclude })
    }

    fn matches(&self, h: &HostEntry) -> bool {
        // Empty expression — match all (caller passed limit=None).
        if self.include.is_empty() && self.exclude.is_empty() {
            return true;
        }
        let included = self.include.iter().any(|p| p.matches_host(h));
        if !included {
            return false;
        }
        !self.exclude.iter().any(|p| p.matches_host(h))
    }
}

impl Pattern {
    fn from_token(s: &str) -> Self {
        if s.contains('*') {
            Self::Glob(s.to_string())
        } else {
            Self::Exact(s.to_string())
        }
    }

    fn matches_host(&self, h: &HostEntry) -> bool {
        let label = h.label.as_deref();
        match self {
            Self::Exact(want) => h.host == *want || label == Some(want.as_str()),
            Self::Glob(pattern) => {
                glob_match(pattern, &h.host) || label.is_some_and(|l| glob_match(pattern, l))
            }
        }
    }
}

/// Minimal glob matcher: only `*` is special (matches any sequence of
/// chars). No `?`, no character classes. Simpler than the `globset`
/// crate (which we already use elsewhere) and avoids pulling regex
/// machinery into the CLI.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pat: &[u8], text: &[u8]) -> bool {
    // Iterative algorithm with backtracking — handles patterns like
    // `*-prod-*` correctly without recursion blowing the stack.
    let mut i = 0; // pat index
    let mut j = 0; // text index
    let mut star_pat: Option<usize> = None;
    let mut star_text: usize = 0;
    while j < text.len() {
        if i < pat.len() && pat[i] == b'*' {
            star_pat = Some(i);
            star_text = j;
            i += 1;
        } else if i < pat.len() && pat[i] == text[j] {
            i += 1;
            j += 1;
        } else if let Some(sp) = star_pat {
            i = sp + 1;
            star_text += 1;
            j = star_text;
        } else {
            return false;
        }
    }
    while i < pat.len() && pat[i] == b'*' {
        i += 1;
    }
    i == pat.len()
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn loads_minimal_inventory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web:
    - host: 10.0.0.1
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let targets = inv.resolve("prod-web", None).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[0].port, 22);
    }

    #[test]
    fn defaults_layered_with_overrides() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
defaults:
  user: deploy
  port: 2222
groups:
  prod-web:
    - host: 10.0.0.1
    - host: 10.0.0.2
      user: admin
      port: 22
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let targets = inv.resolve("prod-web", None).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].user, "deploy");
        assert_eq!(targets[0].port, 2222);
        assert_eq!(targets[1].user, "admin"); // per-host override wins
        assert_eq!(targets[1].port, 22);
    }

    #[test]
    fn limit_filters_by_host_or_label() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web:
    - host: 10.0.0.1
      label: web-01
    - host: 10.0.0.2
      label: web-02
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let by_label = inv.resolve("prod-web", Some("web-02")).unwrap();
        assert_eq!(by_label.len(), 1);
        assert_eq!(by_label[0].host, "10.0.0.2");
        let by_host = inv.resolve("prod-web", Some("10.0.0.1")).unwrap();
        assert_eq!(by_host.len(), 1);
        assert_eq!(by_host[0].host, "10.0.0.1");
    }

    #[test]
    fn limit_glob_matches_label_or_host() {
        // Phase 7da.2: `web-*` glob matches both label `web-01` and a
        // host `web-prod` (no label).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod:
    - host: 10.0.0.1
      label: web-01
    - host: 10.0.0.2
      label: web-02
    - host: db-master
    - host: web-spare
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let r = inv.resolve("prod", Some("web-*")).unwrap();
        let labels: Vec<&str> = r.iter().map(|t| t.label.as_str()).collect();
        // Both web-* labels + the web-spare host (no label, host matches)
        assert_eq!(labels.len(), 3, "got: {labels:?}");
        assert!(labels.iter().any(|l| l.contains("web-01")));
        assert!(labels.iter().any(|l| l.contains("web-02")));
        assert!(labels.iter().any(|l| l.contains("web-spare")));
    }

    #[test]
    fn limit_negation_subtracts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod:
    - host: 10.0.0.1
      label: web-01
    - host: 10.0.0.2
      label: web-02
    - host: 10.0.0.3
      label: web-03
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        // `*,!web-03` — everything except web-03.
        let r = inv.resolve("prod", Some("*,!web-03")).unwrap();
        let labels: Vec<&str> = r.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(labels.len(), 2);
        assert!(!labels.iter().any(|l| l.contains("web-03")));
    }

    #[test]
    fn limit_comma_list_includes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod:
    - host: 10.0.0.1
      label: web-01
    - host: 10.0.0.2
      label: web-02
    - host: 10.0.0.3
      label: web-03
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let r = inv.resolve("prod", Some("web-01,web-03")).unwrap();
        let labels: Vec<&str> = r.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(labels.len(), 2);
        assert!(labels.iter().any(|l| l.contains("web-01")));
        assert!(labels.iter().any(|l| l.contains("web-03")));
    }

    #[test]
    fn limit_glob_internal_test() {
        assert!(glob_match("web-*", "web-01"));
        assert!(glob_match("web-*", "web-"));
        assert!(!glob_match("web-*", "wob-01"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*-prod-*", "us-prod-east"));
        assert!(!glob_match("*-prod-*", "no-staging-east"));
        assert!(glob_match("**a", "ba"));
    }

    #[test]
    fn limit_no_match_errors_clearly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web:
    - host: 10.0.0.1
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let err = inv.resolve("prod-web", Some("does-not-exist")).unwrap_err();
        assert!(err.to_string().contains("no host"), "{err}");
    }

    #[test]
    fn missing_group_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web:
    - host: 10.0.0.1
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        assert!(inv.resolve("nonexistent", None).is_err());
    }

    #[test]
    fn empty_group_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web: []
"#,
        );
        assert!(InventoryFile::load(&path).is_err());
    }

    #[test]
    fn unknown_field_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web:
    - host: 10.0.0.1
      bogus: oops
"#,
        );
        assert!(InventoryFile::load(&path).is_err());
    }

    #[test]
    fn label_resolves_to_friendly_name() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("inv.yaml");
        write(
            &path,
            r#"
groups:
  prod-web:
    - host: 10.0.0.1
      label: web-01
      user: deploy
"#,
        );
        let inv = InventoryFile::load(&path).unwrap();
        let targets = inv.resolve("prod-web", None).unwrap();
        assert_eq!(targets[0].label, "web-01");
    }
}
