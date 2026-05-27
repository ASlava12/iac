//! Agent-side capability allowlist.
//!
//! When a `capabilities.yaml` file exists at `config.capabilities_file`, the
//! agent enforces per-kind allow/deny rules on every resource it would apply
//! — both manifests it reads from disk and assignments it pulls from the
//! control-plane. Resources outside the allowlist are rejected at apply time
//! and the assignment is reported back as failed with a `capability_denied`
//! reason; the agent never invokes the underlying provider.
//!
//! Soft-start semantics: missing file → no enforcement (agent runs as in
//! Phase 0/1). Empty per-kind sections → that kind is unrestricted. Operators
//! opt in by declaring rules.
//!
//! Phase 6a introduced this module with hardcoded per-kind extractors.
//! Phase 7ao moved key extraction onto `Provider::capability_keys`, so this
//! module is now glue: dispatch by kind to the matching `*Rules` block,
//! ask the provider for the identifier(s) governing the resource, and
//! glob-match against operator-declared rules.

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use iac_core::{ProviderRegistry, Resource};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level fall-through policy for kinds the capabilities file doesn't
/// declare rules for.
///
/// Phase 7cz.6: default flipped from `Allow` to `Deny`. Pre-7cz the agent
/// silently accepted any new resource kind a future agent version
/// introduced, even on hosts the operator had locked down for one
/// purpose. The new default fails-closed: an operator who wants the
/// permissive behaviour spells it out — `default_kind_policy: allow`.
/// (Pre-production: no migration burden; existing test fixtures use
/// `Allow` explicitly via the new flip-the-other-way knob.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultKindPolicy {
    Allow,
    #[default]
    Deny,
}

/// Loaded + compiled capability rules. Matchers are pre-built, so per-resource
/// checks are O(1)-ish across the rule set.
#[derive(Debug, Default)]
pub struct Capabilities {
    default_kind_policy: DefaultKindPolicy,
    files: PathRules,
    nginx_vhost: PathRules,
    systemd: NameRules,
    docker: NameRules,
    packages: NameRules,
    cron: NameRules,
}

#[derive(Debug, Default)]
pub struct PathRules {
    allow: Option<GlobSet>,
    deny: Option<GlobSet>,
}

#[derive(Debug, Default)]
pub struct NameRules {
    allow: Option<GlobSet>,
}

#[derive(Debug, Clone)]
pub struct DenyReason {
    pub resource_id: String,
    pub kind: String,
    pub identifier: String,
    pub reason: String,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "capability_denied[{}]: {} ({}: {})",
            self.kind, self.resource_id, self.identifier, self.reason
        )
    }
}

#[derive(Debug, Default, Deserialize)]
struct RawCapabilities {
    #[serde(default)]
    default_kind_policy: DefaultKindPolicy,
    #[serde(default)]
    files: RawPathRules,
    #[serde(default)]
    nginx_vhost: RawPathRules,
    #[serde(default)]
    systemd: RawNameRules,
    #[serde(default)]
    docker: RawNameRules,
    #[serde(default)]
    packages: RawNameRules,
    #[serde(default)]
    cron: RawNameRules,
}

#[derive(Debug, Default, Deserialize)]
struct RawPathRules {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawNameRules {
    #[serde(default)]
    allow: Vec<String>,
}

impl Capabilities {
    /// Load from a YAML file. Returns `Ok(None)` when the file doesn't exist
    /// (soft-start: unrestricted). Returns `Err` for parse / glob errors so
    /// the agent fails closed if its policy file is malformed.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading capabilities file {}", path.display()))?;
        let raw: RawCapabilities = serde_yaml_ng::from_str(&text)
            .with_context(|| format!("parsing capabilities file {}", path.display()))?;
        Ok(Some(raw.compile()?))
    }

    /// Returns `Err(DenyReason)` if the resource is rejected; `Ok(())`
    /// otherwise. Phase 7ao: each provider returns its own capability key
    /// via `Provider::capability_keys`, so adding a new provider doesn't
    /// require editing this match. The per-kind glob rules (`files`,
    /// `nginx_vhost`, …) stay here because the YAML schema is still
    /// per-kind. Unknown kinds — no provider registered, OR provider has
    /// no rules section here — fall through to `default_kind_policy`:
    /// `Allow` for soft-start, `Deny` for strict mode.
    pub fn check(
        &self,
        registry: &ProviderRegistry,
        resource: &Resource,
    ) -> std::result::Result<(), DenyReason> {
        let id = resource.id().to_string();
        let provider = match registry.get(&resource.kind) {
            Some(p) => p,
            None => {
                return match self.default_kind_policy {
                    DefaultKindPolicy::Allow => Ok(()),
                    DefaultKindPolicy::Deny => Err(DenyReason {
                        resource_id: id,
                        kind: resource.kind.clone(),
                        identifier: "<unknown-kind>".into(),
                        reason: "default_kind_policy=deny and no provider registered \
                                 for this kind"
                            .into(),
                    }),
                };
            }
        };
        let keys = provider.capability_keys(resource).map_err(|e| DenyReason {
            resource_id: id.clone(),
            kind: resource.kind.clone(),
            identifier: "<spec-error>".into(),
            reason: format!("could not extract capability key: {e}"),
        })?;
        if keys.is_empty() {
            // Provider declared no capability key for this resource —
            // unrestricted regardless of `default_kind_policy`. The
            // provider author opted out explicitly.
            return Ok(());
        }
        for key in &keys {
            match resource.kind.as_str() {
                "file" => self.files.check(&id, "file", key)?,
                "nginx.vhost" => self.nginx_vhost.check(&id, "nginx.vhost", key)?,
                "systemd.unit" => self.systemd.check(&id, "systemd.unit", key)?,
                "docker.container" => self.docker.check(&id, "docker.container", key)?,
                "package" => self.packages.check(&id, "package", key)?,
                "cron.job" => self.cron.check(&id, "cron.job", key)?,
                _ => match self.default_kind_policy {
                    DefaultKindPolicy::Allow => {}
                    DefaultKindPolicy::Deny => {
                        return Err(DenyReason {
                            resource_id: id,
                            kind: resource.kind.clone(),
                            identifier: key.clone(),
                            reason: "default_kind_policy=deny and no rules block declared \
                                     for this kind"
                                .into(),
                        });
                    }
                },
            }
        }
        Ok(())
    }
}

impl PathRules {
    fn check(
        &self,
        resource_id: &str,
        kind: &str,
        path: &str,
    ) -> std::result::Result<(), DenyReason> {
        // Deny takes precedence so an `/etc/shadow` deny can't be bypassed
        // by an over-broad `/etc/**` allow.
        if let Some(deny) = &self.deny
            && deny.is_match(path)
        {
            return Err(DenyReason {
                resource_id: resource_id.into(),
                kind: kind.into(),
                identifier: path.into(),
                reason: "matched deny pattern".into(),
            });
        }
        if let Some(allow) = &self.allow {
            if allow.is_match(path) {
                Ok(())
            } else {
                Err(DenyReason {
                    resource_id: resource_id.into(),
                    kind: kind.into(),
                    identifier: path.into(),
                    reason: "no allow pattern matched".into(),
                })
            }
        } else {
            // No allowlist declared for this kind → unrestricted.
            Ok(())
        }
    }
}

impl NameRules {
    fn check(
        &self,
        resource_id: &str,
        kind: &str,
        name: &str,
    ) -> std::result::Result<(), DenyReason> {
        if let Some(allow) = &self.allow {
            if allow.is_match(name) {
                Ok(())
            } else {
                Err(DenyReason {
                    resource_id: resource_id.into(),
                    kind: kind.into(),
                    identifier: name.into(),
                    reason: "no allow pattern matched".into(),
                })
            }
        } else {
            Ok(())
        }
    }
}

impl RawCapabilities {
    fn compile(self) -> Result<Capabilities> {
        Ok(Capabilities {
            default_kind_policy: self.default_kind_policy,
            files: self.files.compile("files")?,
            nginx_vhost: self.nginx_vhost.compile("nginx_vhost")?,
            systemd: self.systemd.compile("systemd")?,
            docker: self.docker.compile("docker")?,
            packages: self.packages.compile("packages")?,
            cron: self.cron.compile("cron")?,
        })
    }
}

impl RawPathRules {
    fn compile(self, section: &str) -> Result<PathRules> {
        Ok(PathRules {
            allow: build_set(&self.allow, &format!("{section}.allow"))?,
            deny: build_set(&self.deny, &format!("{section}.deny"))?,
        })
    }
}

impl RawNameRules {
    fn compile(self, section: &str) -> Result<NameRules> {
        Ok(NameRules {
            allow: build_set(&self.allow, &format!("{section}.allow"))?,
        })
    }
}

fn build_set(patterns: &[String], section: &str) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(p).with_context(|| format!("invalid glob in {section}: {p:?}"))?;
        builder.add(glob);
    }
    let set = builder
        .build()
        .with_context(|| format!("building globset for {section}"))?;
    Ok(Some(set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
    use indexmap::IndexMap;
    use serde_yaml_ng::{Mapping, Value as YamlValue};
    use tempfile::TempDir;

    /// Per-test registry pre-loaded with the built-in providers. Phase 7ao
    /// dispatches capability-key extraction through the provider, so every
    /// test that calls `caps.check(&registry, …)` needs one.
    fn registry() -> ProviderRegistry {
        let mut r = ProviderRegistry::new();
        iac_providers::register_builtins(&mut r);
        r
    }

    fn write_caps(text: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("capabilities.yaml");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    fn mk_resource(kind: &str, name: &str, spec_value: YamlValue) -> Resource {
        Resource {
            api_version: API_VERSION.into(),
            kind: kind.into(),
            metadata: Metadata {
                name: name.into(),
                environment: "test".into(),
                owner: None,
                labels: IndexMap::new(),
                annotations: IndexMap::new(),
            },
            spec: spec_value,
            policy: YamlValue::Null,
            source: SourceLocation::default(),
        }
    }

    fn file_spec(path: &str) -> YamlValue {
        let mut m = Mapping::new();
        m.insert("path".into(), YamlValue::String(path.into()));
        YamlValue::Mapping(m)
    }

    // Phase 7ao: capability_keys runs through `Provider::parse_spec`, so
    // fixtures must be valid specs. These helpers build minimal-but-valid
    // specs for kinds that need more than just `{ name: ... }`.

    fn docker_spec(name: &str) -> YamlValue {
        let mut m = Mapping::new();
        m.insert("name".into(), YamlValue::String(name.into()));
        m.insert("image".into(), YamlValue::String("nginx:latest".into()));
        YamlValue::Mapping(m)
    }

    fn package_spec(name: &str) -> YamlValue {
        let mut m = Mapping::new();
        m.insert("name".into(), YamlValue::String(name.into()));
        m.insert("state".into(), YamlValue::String("present".into()));
        YamlValue::Mapping(m)
    }

    fn cron_spec(name: &str) -> YamlValue {
        let mut m = Mapping::new();
        m.insert("name".into(), YamlValue::String(name.into()));
        m.insert("schedule".into(), YamlValue::String("0 3 * * *".into()));
        m.insert(
            "command".into(),
            YamlValue::String("/usr/local/bin/x".into()),
        );
        YamlValue::Mapping(m)
    }

    fn nginx_spec(config_path: &str) -> YamlValue {
        let mut m = Mapping::new();
        m.insert("config_path".into(), YamlValue::String(config_path.into()));
        m.insert(
            "server_names".into(),
            YamlValue::Sequence(vec![YamlValue::String("app.example.com".into())]),
        );
        m.insert(
            "upstream".into(),
            YamlValue::String("http://127.0.0.1:8080".into()),
        );
        YamlValue::Mapping(m)
    }

    #[test]
    fn missing_file_means_unrestricted() {
        let opt =
            Capabilities::load(&std::path::PathBuf::from("/tmp/does-not-exist.yaml")).unwrap();
        assert!(opt.is_none());
    }

    #[test]
    fn empty_kinds_are_unrestricted() {
        let registry = registry();
        let (_dir, path) = write_caps("files:\n  allow: []\n");
        let caps = Capabilities::load(&path).unwrap().unwrap();
        let r = mk_resource("file", "x", file_spec("/anywhere"));
        assert!(caps.check(&registry, &r).is_ok());
    }

    #[test]
    fn file_allowlist_enforced() {
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
files:
  allow:
    - /etc/nginx/**
    - /etc/cron.d/**
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();
        assert!(
            caps.check(
                &registry,
                &mk_resource("file", "ok", file_spec("/etc/nginx/conf.d/app.conf"))
            )
            .is_ok()
        );
        assert!(
            caps.check(
                &registry,
                &mk_resource("file", "ok", file_spec("/etc/cron.d/backup"))
            )
            .is_ok()
        );
        let denial = caps
            .check(
                &registry,
                &mk_resource("file", "denied", file_spec("/etc/passwd")),
            )
            .unwrap_err();
        assert_eq!(denial.kind, "file");
        assert_eq!(denial.identifier, "/etc/passwd");
    }

    #[test]
    fn unresolved_secret_token_in_path_is_denied() {
        // Phase 7cz.7: the control plane substitutes `${secret://...}`
        // tokens BEFORE signing the assignment envelope, so by the
        // time the agent runs `caps.check()` the path field holds the
        // resolved string. This test pins the defense-in-depth: even
        // if substitution is bypassed somehow (bug, future refactor,
        // local-manifest path that skips the resolver), the literal
        // token `${secret://...}` doesn't pass the spec validator —
        // the file provider rejects it at `capability_keys()` parse
        // time because it's not an absolute path. The denial bubbles
        // up as a `<spec-error>` with the offending token surfaced
        // in the message.
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
files:
  allow:
    - /etc/nginx/**
    - /var/lib/iac/**
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();
        let denial = caps
            .check(
                &registry,
                &mk_resource(
                    "file",
                    "secret-bypass",
                    file_spec("${secret://env/EVIL_PATH}"),
                ),
            )
            .unwrap_err();
        assert_eq!(denial.kind, "file");
        // Spec-validate path catches it before the allowlist even
        // gets to look at the value. Either way, the resource never
        // makes it past the agent's policy gate.
        assert!(
            denial.reason.contains("secret://") || denial.identifier.contains("secret://"),
            "denial should reference the literal token: {denial:?}"
        );
    }

    #[test]
    fn deny_takes_priority_over_allow() {
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
files:
  allow: ["/etc/**"]
  deny: ["/etc/shadow", "/etc/sudoers", "/root/.ssh/**"]
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();
        // Allow is broad, deny carves out the dangerous bits.
        assert!(
            caps.check(
                &registry,
                &mk_resource("file", "ok", file_spec("/etc/nginx/x"))
            )
            .is_ok()
        );
        let denial = caps
            .check(
                &registry,
                &mk_resource("file", "shadow", file_spec("/etc/shadow")),
            )
            .unwrap_err();
        assert!(denial.reason.contains("deny"));
        let denial = caps
            .check(
                &registry,
                &mk_resource("file", "ssh", file_spec("/root/.ssh/authorized_keys")),
            )
            .unwrap_err();
        assert!(denial.reason.contains("deny"));
    }

    #[test]
    fn systemd_unit_name_built_from_spec_name_and_type() {
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
systemd:
  allow: ["nginx.service", "app-*.service"]
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();

        let mut spec = Mapping::new();
        spec.insert("name".into(), YamlValue::String("nginx".into()));
        let r = mk_resource("systemd.unit", "nginx", YamlValue::Mapping(spec));
        assert!(caps.check(&registry, &r).is_ok());

        let mut spec = Mapping::new();
        spec.insert("name".into(), YamlValue::String("app-web".into()));
        let r = mk_resource("systemd.unit", "app-web", YamlValue::Mapping(spec));
        assert!(caps.check(&registry, &r).is_ok());

        let mut spec = Mapping::new();
        spec.insert("name".into(), YamlValue::String("backup".into()));
        spec.insert("type".into(), YamlValue::String("timer".into()));
        let r = mk_resource("systemd.unit", "backup", YamlValue::Mapping(spec));
        // backup.timer is NOT in the allowlist → denied.
        let denial = caps.check(&registry, &r).unwrap_err();
        assert_eq!(denial.identifier, "backup.timer");
    }

    #[test]
    fn docker_container_allowlist_with_wildcards() {
        let registry = registry();
        let (_dir, path) = write_caps("docker:\n  allow: [\"web-*\", \"api\"]\n");
        let caps = Capabilities::load(&path).unwrap().unwrap();
        assert!(
            caps.check(
                &registry,
                &mk_resource("docker.container", "x", docker_spec("web-prod"))
            )
            .is_ok()
        );
        assert!(
            caps.check(
                &registry,
                &mk_resource("docker.container", "x", docker_spec("api"))
            )
            .is_ok()
        );
        let denial = caps
            .check(
                &registry,
                &mk_resource("docker.container", "x", docker_spec("worker")),
            )
            .unwrap_err();
        assert_eq!(denial.identifier, "worker");
    }

    #[test]
    fn package_and_cron_allowlists() {
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
packages:
  allow: ["nginx", "postgresql-client", "htop"]
cron:
  allow: ["backup-*", "cleanup-*"]
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();
        assert!(
            caps.check(
                &registry,
                &mk_resource("package", "x", package_spec("nginx"))
            )
            .is_ok()
        );
        assert!(
            caps.check(&registry, &mk_resource("package", "x", package_spec("vim")))
                .is_err()
        );
        assert!(
            caps.check(
                &registry,
                &mk_resource("cron.job", "x", cron_spec("backup-db"))
            )
            .is_ok()
        );
        assert!(
            caps.check(
                &registry,
                &mk_resource("cron.job", "x", cron_spec("evil-script"))
            )
            .is_err()
        );
    }

    #[test]
    fn nginx_uses_config_path_field() {
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
nginx_vhost:
  allow: ["/etc/nginx/conf.d/**"]
  deny: ["/etc/nginx/conf.d/admin.conf"]
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();

        let r = mk_resource(
            "nginx.vhost",
            "app",
            nginx_spec("/etc/nginx/conf.d/app.conf"),
        );
        assert!(caps.check(&registry, &r).is_ok());

        let r = mk_resource(
            "nginx.vhost",
            "admin",
            nginx_spec("/etc/nginx/conf.d/admin.conf"),
        );
        assert!(caps.check(&registry, &r).is_err());
    }

    #[test]
    fn unknown_kind_passes_through_under_default_allow() {
        // Phase 7cz.6: default flipped from Allow → Deny. To keep this
        // test exercising the Allow branch, the operator has to spell
        // it out explicitly.
        let registry = registry();
        let (_dir, path) =
            write_caps("default_kind_policy: allow\nfiles:\n  allow: [\"/never\"]\n");
        let caps = Capabilities::load(&path).unwrap().unwrap();
        let r = mk_resource("totally.new.kind", "x", YamlValue::Null);
        assert!(caps.check(&registry, &r).is_ok());
    }

    #[test]
    fn default_policy_is_deny() {
        // Phase 7cz.6: implicit default (no `default_kind_policy:` in
        // the file) is now Deny — fail-closed for unknown kinds.
        let registry = registry();
        let (_dir, path) = write_caps("files:\n  allow: [\"/etc/**\"]\n");
        let caps = Capabilities::load(&path).unwrap().unwrap();
        let denial = caps
            .check(
                &registry,
                &mk_resource("totally.new.kind", "x", YamlValue::Null),
            )
            .unwrap_err();
        assert!(denial.reason.contains("default_kind_policy=deny"));
    }

    #[test]
    fn unknown_kind_denied_under_default_deny() {
        let registry = registry();
        let (_dir, path) = write_caps(
            r#"
default_kind_policy: deny
files:
  allow: ["/etc/nginx/**"]
"#,
        );
        let caps = Capabilities::load(&path).unwrap().unwrap();
        // Known kind with matching rule → allowed.
        assert!(
            caps.check(
                &registry,
                &mk_resource("file", "ok", file_spec("/etc/nginx/x"))
            )
            .is_ok()
        );
        // Unknown kind → denied with explicit reason.
        let denial = caps
            .check(
                &registry,
                &mk_resource("totally.new.kind", "x", YamlValue::Null),
            )
            .unwrap_err();
        assert_eq!(denial.kind, "totally.new.kind");
        assert!(denial.reason.contains("default_kind_policy=deny"));
    }

    #[test]
    fn missing_required_spec_field_is_denied() {
        let registry = registry();
        let (_dir, path) = write_caps("files:\n  allow: [\"/etc/**\"]\n");
        let caps = Capabilities::load(&path).unwrap().unwrap();
        // file resource without spec.path → provider's parse_spec fails;
        // capabilities surfaces that as a deny with the parse error in
        // the reason. We only assert the wrapper text since the exact
        // parse error text is the provider's concern, not ours.
        let r = mk_resource("file", "x", YamlValue::Null);
        let denial = caps.check(&registry, &r).unwrap_err();
        assert_eq!(denial.identifier, "<spec-error>");
        assert!(
            denial.reason.contains("could not extract capability key"),
            "expected wrapper text, got {:?}",
            denial.reason
        );
    }

    #[test]
    fn invalid_glob_fails_to_load() {
        let (_dir, path) = write_caps("files:\n  allow: [\"[bad\"]\n");
        let err = Capabilities::load(&path).unwrap_err();
        assert!(
            err.to_string().contains("invalid glob") || err.to_string().contains("files.allow")
        );
    }
}
