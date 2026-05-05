// Phase 7cz.16: this spec module uses .chars().next/last().expect()
// patterns where the validate() function already proved the string is
// non-empty. The invariant is local to the module.
#![allow(clippy::expect_used)]

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum DockerState {
    #[default]
    Present,
    Absent,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum RestartPolicy {
    No,
    Always,
    #[default]
    UnlessStopped,
    OnFailure,
}


impl RestartPolicy {
    pub fn as_docker(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Always => "always",
            Self::UnlessStopped => "unless-stopped",
            Self::OnFailure => "on-failure",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "" | "no" => Self::No,
            "always" => Self::Always,
            "unless-stopped" => Self::UnlessStopped,
            "on-failure" => Self::OnFailure,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerContainerSpec {
    /// Container name. Must be a valid Docker name (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`).
    pub name: String,
    /// Image reference, e.g. `nginx:1.27-alpine` or `ghcr.io/foo/bar:v1.2`.
    /// Required when `state == Present`.
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub state: DockerState,
    /// Environment variables. Insertion order is preserved on the wire so
    /// re-applying with the same map doesn't show as a diff.
    #[serde(default)]
    pub env: IndexMap<String, String>,
    /// Port bindings in `host:container[/proto]` form, e.g. `"8080:80"` or
    /// `"127.0.0.1:5432:5432/tcp"`.
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    /// Phase 7ax: container labels. Rendered as `--label key=value` on
    /// `docker run`. Useful for operator-driven inventory ("which iac
    /// version applied this", "which env it belongs to") and for
    /// integration with monitoring stacks that filter on labels.
    /// Diff is subset-style (like `env`) — Docker can inject labels of
    /// its own and we don't fight those, only require the desired set
    /// to be present on the running container.
    #[serde(default)]
    pub labels: IndexMap<String, String>,
    /// Phase 7ay: container command. Replaces the image's `CMD`. Each
    /// element is one argv slot (no shell parsing). `None` (or absent
    /// from the manifest) means "use the image's default CMD" — the
    /// observed `.Config.Cmd` is left alone in that case.
    ///
    /// Diff is exact-match (vs the env / labels subset semantics):
    /// adding, removing, or reordering arguments triggers drift, and
    /// blank-vs-image-default is preserved by the `Option`. Persisted
    /// in the rollback checkpoint as `previous_command`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Phase 7az: optional container healthcheck. `None` / absent means
    /// "use image default" (and never claim drift against whatever the
    /// running container's healthcheck looks like). When `Some`, the
    /// renderer emits `--health-cmd` + the optional tuning flags, and
    /// diff is exact-match against the observed config.
    #[serde(default)]
    pub healthcheck: Option<DockerHealthcheck>,
    /// Phase 7ba: bind / volume mounts in `host:container[:ro]` form,
    /// e.g. `"/var/data:/app/data"` (bind, rw), `"/etc/conf:/conf:ro"`
    /// (bind, read-only), or `"myvol:/data"` (named volume). Diff is
    /// set-based — ordering on disk doesn't matter, so re-arranging
    /// the list in a manifest doesn't trigger drift. Validated for
    /// shell-safety + absolute container paths.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Phase 7bb: primary docker network the container attaches to.
    /// `None` (default) leaves Docker on the default `bridge` network.
    /// Singular — `docker run` only accepts one `--network` flag at
    /// create time. Phase 7bm extends this with `extra_networks` for
    /// additional attachments via `docker network connect` post-create.
    #[serde(default)]
    pub network: Option<String>,
    /// Phase 7bm: additional docker networks attached to the container
    /// after creation. The primary `network` (above) is set at `docker
    /// run` time; each entry here triggers one `docker network connect
    /// <name> <container>` call after the container is running. Common
    /// use case: a container needing to reach two isolated networks
    /// (e.g. one for app traffic, one for monitoring).
    ///
    /// Validation: each name passes the same character + non-empty
    /// checks as `network`. Duplicates and the same name as `network`
    /// are rejected — would produce an error from docker at apply time
    /// anyway and confuses the diff path's set comparison.
    #[serde(default)]
    pub extra_networks: Vec<String>,
    /// Phase 7bn: long-form `--mount type=...,source=...,target=...`
    /// entries. Coexists with `volumes` (short-form `-v` syntax); both
    /// canonicalize to the same internal representation for diff. The
    /// long form supports types short-form can't express (`tmpfs`),
    /// makes the source/target distinction unambiguous, and is the
    /// recommended form per Docker's own docs. Bind/volume entries
    /// canonicalize to the same `source:target[:ro]` shape as
    /// `volumes` so the two fields are interchangeable in manifests.
    #[serde(default)]
    pub mounts: Vec<DockerMount>,
}

/// Phase 7bn: structured mount declaration corresponding to Docker's
/// long-form `--mount` flag. Three types are supported: `bind` (host
/// path → container), `volume` (named volume → container), and `tmpfs`
/// (in-memory filesystem at container path; no source). Operators
/// preferring the older short-form `-v host:container[:ro]` should keep
/// using `volumes`; the two forms are equivalent for bind/volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerMount {
    /// `"bind"` | `"volume"` | `"tmpfs"`. Required — long-form
    /// `--mount` always specifies the type explicitly.
    pub r#type: String,
    /// Bind: absolute host path. Volume: volume name. Tmpfs: must be
    /// absent (`None`).
    #[serde(default)]
    pub source: Option<String>,
    /// Container path. Always absolute. Required.
    pub target: String,
    /// Read-only flag. Maps to `,readonly` in the long-form. Tmpfs
    /// supports it too (the underlying tmpfs is mounted ro).
    #[serde(default)]
    pub readonly: bool,
}

/// Phase 7az: subset of Docker's `--health-*` flags. We support the
/// CMD-SHELL form only — `command` is run via `/bin/sh -c`. Operators
/// who need argv-style `CMD` form, `--no-healthcheck`, or `start_period`
/// hit the existing "stuck with hand-managed containers" footnote;
/// expand here when the need shows up.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerHealthcheck {
    /// Shell command run via `/bin/sh -c`. Docker maps this to the
    /// `["CMD-SHELL", "<command>"]` `Test` array on the container.
    pub command: String,
    /// `--health-interval`. Duration string, e.g. `"30s"`.
    #[serde(default)]
    pub interval: Option<String>,
    /// `--health-timeout`. Duration string.
    #[serde(default)]
    pub timeout: Option<String>,
    /// `--health-retries`. Number of consecutive failures before the
    /// container is marked unhealthy.
    #[serde(default)]
    pub retries: Option<u32>,
}

impl DockerContainerSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        validate_container_name(&self.name).map_err(|e| format!("name: {e}"))?;
        match self.state {
            DockerState::Present => {
                if self.image.as_deref().unwrap_or_default().trim().is_empty() {
                    return Err("image is required when state=present".into());
                }
                if let Some(img) = &self.image {
                    validate_image_ref(img).map_err(|e| format!("image: {e}"))?;
                }
            }
            DockerState::Absent => {
                if self.image.is_some()
                    || !self.env.is_empty()
                    || !self.ports.is_empty()
                    || !self.labels.is_empty()
                    || self.command.is_some()
                    || self.healthcheck.is_some()
                    || !self.volumes.is_empty()
                    || self.network.is_some()
                    || !self.extra_networks.is_empty()
                    || !self.mounts.is_empty()
                {
                    return Err(
                        "state=absent forbids image/env/ports/labels/command/healthcheck/volumes/network/extra_networks/mounts"
                            .into(),
                    );
                }
            }
        }
        for (k, _) in &self.env {
            if k.is_empty() || k.contains('=') || k.contains('\0') {
                return Err(format!("env key {k:?} must be non-empty and contain no '=' or NUL"));
            }
        }
        for p in &self.ports {
            validate_port_spec(p).map_err(|e| format!("port {p:?}: {e}"))?;
        }
        // Phase 7ax: label keys must be non-empty and shell-safe; values
        // can be anything except NUL (Docker accepts arbitrary UTF-8 in
        // values). The `=` separator is the only structural concern in
        // keys — values can contain `=` freely.
        for (k, v) in &self.labels {
            if k.is_empty() || k.contains('=') || k.contains('\0') {
                return Err(format!(
                    "label key {k:?} must be non-empty and contain no '=' or NUL"
                ));
            }
            if v.contains('\0') {
                return Err(format!("label value for {k:?} contains NUL"));
            }
        }
        // Phase 7ay: command args. NUL is the only structural concern —
        // Docker exec'v doesn't go through a shell, so spaces, quotes,
        // and shell metas in args are passed through verbatim. A
        // `Some(vec![])` is treated as "explicit empty" and rejected to
        // avoid an ambiguous "no CMD" state vs "image default" — use
        // `command: ~` (None) for "image default."
        if let Some(cmd) = &self.command {
            if cmd.is_empty() {
                return Err("command must not be empty; omit the field or set it to null".into());
            }
            for (i, arg) in cmd.iter().enumerate() {
                if arg.contains('\0') {
                    return Err(format!("command[{i}] contains NUL"));
                }
            }
        }
        // Phase 7ba: validate each volume entry. Shell-safety on both
        // sides + absolute container path + at most one `:ro|rw` flag.
        for v in &self.volumes {
            validate_volume_spec(v).map_err(|e| format!("volume {v:?}: {e}"))?;
        }
        // Phase 7bn: validate each long-form mount. Type required;
        // bind/volume need source; tmpfs forbids it. Target must be
        // absolute. Cross-field check: a `bind`/`volume` mount whose
        // canonical short-form duplicates an entry already in
        // `volumes` is rejected — would produce a docker error at run
        // time and breaks the diff's set comparison.
        let mut canonical_seen: std::collections::BTreeSet<String> = self
            .volumes
            .iter()
            .filter_map(|v| {
                let (s, d, ro) = parse_volume_spec(v).ok()?;
                Some(normalize_volume_spec(s, d, ro))
            })
            .collect();
        for (i, m) in self.mounts.iter().enumerate() {
            validate_mount(m).map_err(|e| format!("mounts[{i}]: {e}"))?;
            if let Some(canon) = mount_to_short_form(m)
                && !canonical_seen.insert(canon.clone()) {
                    return Err(format!(
                        "mounts[{i}] {canon:?} duplicates an entry in volumes/mounts"
                    ));
                }
        }
        // Phase 7bb: network name. Docker accepts the same character set
        // as container names + a few special predefined names (`host`,
        // `none`, `bridge`). We reject empty strings and shell metas;
        // the rest is the operator's call.
        if let Some(n) = &self.network {
            validate_network_name(n).map_err(|e| format!("network {n:?}: {e}"))?;
        }
        // Phase 7bm: each `extra_networks` entry. Reuses the `network`
        // validator. Reject duplicates within `extra_networks` AND
        // overlap with the primary `network` — docker would error out
        // at apply time, and the diff path's set comparison treats
        // "same name twice" as malformed.
        for n in &self.extra_networks {
            validate_network_name(n).map_err(|e| format!("extra_networks {n:?}: {e}"))?;
        }
        let mut seen_extras: std::collections::BTreeSet<&str> =
            std::collections::BTreeSet::new();
        for n in &self.extra_networks {
            if !seen_extras.insert(n.as_str()) {
                return Err(format!("extra_networks contains duplicate {n:?}"));
            }
            if let Some(primary) = &self.network
                && primary == n {
                    return Err(format!(
                        "extra_networks {n:?} duplicates primary network; remove from extra_networks"
                    ));
                }
        }
        // Phase 7az: healthcheck validation. Command is required when the
        // block is present; durations + retries get range-checked.
        if let Some(hc) = &self.healthcheck {
            if hc.command.trim().is_empty() {
                return Err("healthcheck.command must not be empty".into());
            }
            if hc.command.contains('\0') {
                return Err("healthcheck.command contains NUL".into());
            }
            if let Some(s) = &hc.interval {
                parse_health_duration_secs(s).map_err(|e| format!("healthcheck.interval: {e}"))?;
            }
            if let Some(s) = &hc.timeout {
                parse_health_duration_secs(s).map_err(|e| format!("healthcheck.timeout: {e}"))?;
            }
            if let Some(r) = hc.retries
                && r == 0 {
                    return Err("healthcheck.retries must be > 0".into());
                }
        }
        Ok(())
    }
}

fn validate_container_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("must not be empty".into());
    }
    let first = name.chars().next().expect("non-empty");
    if !(first.is_ascii_alphanumeric()) {
        return Err("must start with [a-zA-Z0-9]".into());
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
            return Err(format!("character {c:?} is not allowed"));
        }
    }
    Ok(())
}

fn validate_image_ref(image: &str) -> Result<(), String> {
    if image.is_empty() {
        return Err("must not be empty".into());
    }
    if image.contains(char::is_whitespace) {
        return Err("must not contain whitespace".into());
    }
    // Conservative: registry/path/component:tag@digest. Disallow shell metas.
    let bad = image.chars().any(|c| {
        matches!(c, ' ' | '\t' | '\n' | ';' | '|' | '&' | '$' | '`' | '"' | '\'' | '\\')
    });
    if bad {
        return Err("contains a shell metacharacter".into());
    }
    Ok(())
}

fn validate_port_spec(p: &str) -> Result<(), String> {
    // Accepted forms:
    //   "host:container"
    //   "host:container/proto"
    //   "ip:host:container"
    //   "ip:host:container/proto"
    let (binding, proto) = match p.split_once('/') {
        Some((b, proto)) => (b, Some(proto)),
        None => (p, None),
    };
    let parts: Vec<&str> = binding.split(':').collect();
    let (host, container) = match parts.len() {
        2 => (parts[0], parts[1]),
        3 => (parts[1], parts[2]),
        _ => return Err("expected host:container[/proto] or ip:host:container[/proto]".into()),
    };
    host.parse::<u16>().map_err(|_| format!("host port {host:?} not a valid u16"))?;
    container.parse::<u16>().map_err(|_| format!("container port {container:?} not a valid u16"))?;
    if let Some(proto) = proto
        && !matches!(proto, "tcp" | "udp" | "sctp") {
            return Err(format!("protocol {proto:?} not in (tcp,udp,sctp)"));
        }
    Ok(())
}

/// Encode env into the canonical `KEY=VALUE` form Docker emits.
pub fn env_kv(env: &IndexMap<String, String>) -> Vec<String> {
    env.iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// Phase 7ba: parse a `host:container[:ro|rw]` volume entry into its
/// three logical fields. Returns `(source, destination, read_only)`.
/// `source` is either an absolute filesystem path (bind mount) or a
/// non-slash name (named volume).
pub(crate) fn parse_volume_spec(s: &str) -> Result<(&str, &str, bool), String> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    let (source, dest, mode) = match parts.len() {
        2 => (parts[0], parts[1], None),
        3 => (parts[0], parts[1], Some(parts[2])),
        _ => return Err("expected host:container[:ro|rw]".into()),
    };
    let read_only = match mode {
        None | Some("rw") => false,
        Some("ro") => true,
        Some(other) => return Err(format!("mode {other:?} must be 'ro' or 'rw'")),
    };
    Ok((source, dest, read_only))
}

/// Phase 7ba: validation. Shell-safety + structural rules:
///   * source is either absolute path OR a non-slash name (named volume).
///   * destination must be absolute (Docker container paths are always
///     absolute; relative paths break with confusing errors).
///   * no `..` traversal, no shell metas, no whitespace.
fn validate_volume_spec(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("must not be empty".into());
    }
    if s.contains([' ', '\t', '\n', ';', '"', '\'', '`'].as_slice()) {
        return Err("must not contain whitespace or shell metacharacters".into());
    }
    let (source, dest, _ro) = parse_volume_spec(s)?;
    if source.is_empty() {
        return Err("source must not be empty".into());
    }
    if dest.is_empty() {
        return Err("destination must not be empty".into());
    }
    if !dest.starts_with('/') {
        return Err(format!("destination must be absolute, got {dest:?}"));
    }
    if source.contains("..") || dest.contains("..") {
        return Err("must not contain '..'".into());
    }
    // Source is either absolute path (bind) or a name (named volume).
    if !source.starts_with('/') && source.contains('/') {
        return Err(format!(
            "source {source:?} looks like a relative path; bind mounts must be absolute"
        ));
    }
    Ok(())
}

/// Phase 7ba: render in canonical form for diff. Trailing `:rw` is
/// dropped (it's the default); `:ro` is preserved.
pub(crate) fn normalize_volume_spec(source: &str, dest: &str, read_only: bool) -> String {
    if read_only {
        format!("{source}:{dest}:ro")
    } else {
        format!("{source}:{dest}")
    }
}

/// Phase 7bn: validate a structured `--mount` declaration.
///   * type ∈ {bind, volume, tmpfs}
///   * target absolute, non-empty, no shell metas, no `..`
///   * bind: source absolute path; volume: source non-slash name;
///     tmpfs: source must be absent.
fn validate_mount(m: &DockerMount) -> Result<(), String> {
    if !matches!(m.r#type.as_str(), "bind" | "volume" | "tmpfs") {
        return Err(format!(
            "type {:?} must be 'bind', 'volume', or 'tmpfs'",
            m.r#type
        ));
    }
    if m.target.trim().is_empty() {
        return Err("target must not be empty".into());
    }
    if !m.target.starts_with('/') {
        return Err(format!(
            "target {:?} must be absolute",
            m.target
        ));
    }
    if m.target.contains([' ', '\t', '\n', ';', '"', '\'', '`'].as_slice())
        || m.target.contains("..")
    {
        return Err(format!(
            "target {:?} contains a disallowed character or '..'",
            m.target
        ));
    }
    match m.r#type.as_str() {
        "tmpfs" => {
            if m.source.is_some() {
                return Err("type=tmpfs must not set source".into());
            }
        }
        "bind" => {
            let s = m
                .source
                .as_deref()
                .ok_or("type=bind requires source (absolute host path)")?;
            if !s.starts_with('/') {
                return Err(format!("bind source {s:?} must be absolute"));
            }
            if s.contains([' ', '\t', '\n', ';', '"', '\'', '`'].as_slice())
                || s.contains("..")
            {
                return Err(format!(
                    "bind source {s:?} contains a disallowed character or '..'"
                ));
            }
        }
        "volume" => {
            let s = m
                .source
                .as_deref()
                .ok_or("type=volume requires source (volume name)")?;
            if s.trim().is_empty() {
                return Err("volume source must not be empty".into());
            }
            if s.contains([' ', '\t', '\n', ';', '"', '\'', '`', '/'].as_slice()) {
                return Err(format!(
                    "volume source {s:?} contains a disallowed character (whitespace, ';', quotes, '`', '/')"
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Phase 7bn: project a bind/volume mount onto the equivalent
/// `source:target[:ro]` short-form so it can be merged with `volumes`
/// for diff comparison. Tmpfs has no short-form — returns `None`
/// (those entries diff against the docker-inspect tmpfs section, which
/// we don't observe yet, so they always trigger drift on a re-apply
/// against a freshly-inspected container; acceptable until a TODO is
/// addressed below).
pub(crate) fn mount_to_short_form(m: &DockerMount) -> Option<String> {
    match m.r#type.as_str() {
        "bind" | "volume" => {
            let source = m.source.as_deref()?;
            Some(normalize_volume_spec(source, &m.target, m.readonly))
        }
        _ => None,
    }
}

/// Phase 7bn: render a `DockerMount` as a `--mount` argument string.
/// Format: comma-separated `key=value` pairs. Order is fixed for
/// reproducibility (`type`, `source` if present, `target`, `readonly`).
pub(crate) fn mount_to_cli_arg(m: &DockerMount) -> String {
    let mut parts: Vec<String> = vec![format!("type={}", m.r#type)];
    if let Some(s) = &m.source {
        parts.push(format!("source={s}"));
    }
    parts.push(format!("target={}", m.target));
    if m.readonly {
        parts.push("readonly".to_string());
    }
    parts.join(",")
}

/// Phase 7bb / 7bm: validate a docker network name. Rejects whitespace
/// and common shell-meta; must be non-empty after trim. Used for both
/// the primary `network` field and each `extra_networks` entry.
fn validate_network_name(n: &str) -> Result<(), String> {
    if n.trim().is_empty() {
        return Err("must not be empty; omit the field for default bridge".into());
    }
    if n.contains([' ', '\t', '\n', ';', '"', '\'', '`', '/'].as_slice()) {
        return Err(
            "contains a disallowed character (whitespace, ';', quotes, '`', '/')".into(),
        );
    }
    Ok(())
}

/// Phase 7az: parse a Docker-style healthcheck duration into total
/// seconds. Accepts the small subset operators actually use:
/// `<n>s` / `<n>m` / `<n>h`, plus bare integer (= seconds). Pure
/// integer math — duration values that overflow `u64` seconds reject
/// before they reach the Docker CLI.
pub(crate) fn parse_health_duration_secs(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("must not be empty".into());
    }
    // Bare integer = seconds.
    if let Ok(n) = t.parse::<u64>() {
        return Ok(n);
    }
    let last = t.chars().last().expect("non-empty");
    let scale = match last {
        's' => 1u64,
        'm' => 60,
        'h' => 3600,
        _ => return Err(format!("suffix must be one of s/m/h or a bare integer; got {t:?}")),
    };
    let digits = &t[..t.len() - 1];
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("numeric part {digits:?} is not a u64"))?;
    n.checked_mul(scale)
        .ok_or_else(|| format!("duration overflow: {t:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal() {
        let v: Value = serde_yaml_ng::from_str("name: web\nimage: nginx:alpine").unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.name, "web");
        assert_eq!(s.image.as_deref(), Some("nginx:alpine"));
        assert_eq!(s.state, DockerState::Present);
        assert_eq!(s.restart_policy, RestartPolicy::UnlessStopped);
    }

    #[test]
    fn rejects_present_without_image() {
        let v: Value = serde_yaml_ng::from_str("name: x").unwrap();
        assert!(DockerContainerSpec::from_value(&v).is_err());
    }

    #[test]
    fn rejects_shell_metas_in_image() {
        let v: Value =
            serde_yaml_ng::from_str("name: x\nimage: \"a;rm -rf /\"").unwrap();
        assert!(DockerContainerSpec::from_value(&v).is_err());
    }

    #[test]
    fn validates_port_specs() {
        assert!(validate_port_spec("8080:80").is_ok());
        assert!(validate_port_spec("127.0.0.1:5432:5432/tcp").is_ok());
        assert!(validate_port_spec("80").is_err());
        assert!(validate_port_spec("80:abc").is_err());
        assert!(validate_port_spec("80:80/foo").is_err());
    }

    #[test]
    fn validates_container_name() {
        assert!(validate_container_name("web").is_ok());
        assert!(validate_container_name("web-1.test").is_ok());
        assert!(validate_container_name("").is_err());
        assert!(validate_container_name("-leading-dash").is_err());
        assert!(validate_container_name("space in name").is_err());
    }

    #[test]
    fn rejects_absent_with_extras() {
        let v: Value = serde_yaml_ng::from_str("name: x\nstate: absent\nimage: foo").unwrap();
        assert!(DockerContainerSpec::from_value(&v).is_err());
    }

    #[test]
    fn parses_labels_and_preserves_order() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx:alpine
labels:
  app: web
  managed-by: iac
  version: "1.2.3"
"#,
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.labels.len(), 3);
        // IndexMap preserves insertion order from the YAML.
        let keys: Vec<&String> = s.labels.keys().collect();
        assert_eq!(keys, vec!["app", "managed-by", "version"]);
        assert_eq!(s.labels.get("version").map(String::as_str), Some("1.2.3"));
    }

    #[test]
    fn rejects_label_key_with_equals() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nlabels:\n  \"a=b\": value",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("label key"), "got: {err}");
    }

    #[test]
    fn rejects_empty_label_key() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nlabels:\n  \"\": value",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("non-empty"), "got: {err}");
    }

    #[test]
    fn absent_state_forbids_labels() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nstate: absent\nlabels:\n  app: web",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("labels"), "got: {err}");
    }

    #[test]
    fn command_optional_defaults_to_none() {
        let v: Value = serde_yaml_ng::from_str("name: x\nimage: nginx").unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert!(s.command.is_none(), "absent command should be None");
    }

    #[test]
    fn parses_command_argv() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
command: ["nginx", "-g", "daemon off;"]
"#,
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        let cmd = s.command.expect("command should parse to Some");
        assert_eq!(cmd, vec!["nginx", "-g", "daemon off;"]);
    }

    #[test]
    fn rejects_empty_command_array() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\ncommand: []",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn parses_healthcheck_minimal() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
healthcheck:
  command: "curl -f http://localhost/ || exit 1"
"#,
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        let hc = s.healthcheck.expect("healthcheck should parse");
        assert_eq!(hc.command, "curl -f http://localhost/ || exit 1");
        assert!(hc.interval.is_none());
        assert!(hc.timeout.is_none());
        assert!(hc.retries.is_none());
    }

    #[test]
    fn parses_healthcheck_with_tunings() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
healthcheck:
  command: "curl -f http://localhost/"
  interval: "30s"
  timeout: "10s"
  retries: 5
"#,
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        let hc = s.healthcheck.unwrap();
        assert_eq!(hc.interval.as_deref(), Some("30s"));
        assert_eq!(hc.timeout.as_deref(), Some("10s"));
        assert_eq!(hc.retries, Some(5));
    }

    #[test]
    fn rejects_empty_healthcheck_command() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
healthcheck:
  command: "   "
"#,
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_zero_retries() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
healthcheck:
  command: "true"
  retries: 0
"#,
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("retries must be > 0"), "got: {err}");
    }

    #[test]
    fn rejects_bad_health_duration_suffix() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
healthcheck:
  command: "true"
  interval: "5x"
"#,
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("interval"), "got: {err}");
    }

    #[test]
    fn parse_health_duration_secs_accepts_known_units() {
        assert_eq!(parse_health_duration_secs("30").unwrap(), 30);
        assert_eq!(parse_health_duration_secs("30s").unwrap(), 30);
        assert_eq!(parse_health_duration_secs("2m").unwrap(), 120);
        assert_eq!(parse_health_duration_secs("1h").unwrap(), 3600);
        assert!(parse_health_duration_secs("").is_err());
        assert!(parse_health_duration_secs("5x").is_err());
        assert!(parse_health_duration_secs("xs").is_err());
    }

    #[test]
    fn absent_state_forbids_healthcheck() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: x
state: absent
healthcheck:
  command: "true"
"#,
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("healthcheck"), "got: {err}");
    }

    #[test]
    fn parses_network_basic() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nnetwork: my-app-net",
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.network.as_deref(), Some("my-app-net"));
    }

    #[test]
    fn rejects_empty_network() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nnetwork: \"   \"",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_network_with_shell_metas() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nnetwork: \"net;evil\"",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("disallowed"), "got: {err}");
    }

    #[test]
    fn rejects_network_with_slash() {
        // Network names can't contain slashes — that'd look like a
        // docker-compose-style stack/network reference we don't support.
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nnetwork: \"stack/net\"",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("disallowed"), "got: {err}");
    }

    #[test]
    fn absent_state_forbids_network() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nstate: absent\nnetwork: my-net",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("network"), "got: {err}");
    }

    // Phase 7bm: extra_networks for multi-network attach.

    #[test]
    fn parses_extra_networks() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nnetwork: primary\nextra_networks:\n  - mon\n  - audit",
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.network.as_deref(), Some("primary"));
        assert_eq!(s.extra_networks, vec!["mon".to_string(), "audit".to_string()]);
    }

    #[test]
    fn extra_networks_accepts_no_primary() {
        // Edge case: operator wants extras but no primary; primary stays
        // None (default bridge gets the create-time slot).
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nextra_networks:\n  - extra-only",
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.network, None);
        assert_eq!(s.extra_networks, vec!["extra-only".to_string()]);
    }

    #[test]
    fn rejects_extra_networks_duplicate_within_list() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nextra_networks:\n  - mon\n  - mon",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn rejects_extra_networks_overlap_with_primary() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nnetwork: app\nextra_networks:\n  - app",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(
            err.contains("duplicates primary network"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_extra_networks_with_shell_metas() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nextra_networks:\n  - \"net;evil\"",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("disallowed"), "got: {err}");
    }

    #[test]
    fn absent_state_forbids_extra_networks() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nstate: absent\nextra_networks:\n  - mon",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("extra_networks"), "got: {err}");
    }

    // Phase 7bn: long-form `--mount` syntax tests.

    #[test]
    fn parses_long_form_bind_mount() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nmounts:\n  - type: bind\n    source: /var/data\n    target: /app/data",
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.mounts.len(), 1);
        assert_eq!(s.mounts[0].r#type, "bind");
        assert_eq!(s.mounts[0].source.as_deref(), Some("/var/data"));
        assert_eq!(s.mounts[0].target, "/app/data");
        assert!(!s.mounts[0].readonly);
    }

    #[test]
    fn parses_long_form_volume_with_readonly() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nmounts:\n  - type: volume\n    source: appdata\n    target: /data\n    readonly: true",
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.mounts.len(), 1);
        assert_eq!(s.mounts[0].r#type, "volume");
        assert!(s.mounts[0].readonly);
    }

    #[test]
    fn parses_long_form_tmpfs_no_source() {
        let v: Value = serde_yaml_ng::from_str(
            "name: web\nimage: nginx\nmounts:\n  - type: tmpfs\n    target: /tmp/cache",
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.mounts[0].r#type, "tmpfs");
        assert!(s.mounts[0].source.is_none());
    }

    #[test]
    fn rejects_unknown_mount_type() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nmounts:\n  - type: bogus\n    target: /a",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("must be 'bind'"), "got: {err}");
    }

    #[test]
    fn rejects_bind_without_source() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nmounts:\n  - type: bind\n    target: /a",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("requires source"), "got: {err}");
    }

    #[test]
    fn rejects_tmpfs_with_source() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nmounts:\n  - type: tmpfs\n    source: /something\n    target: /tmp/x",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("tmpfs must not set source"), "got: {err}");
    }

    #[test]
    fn rejects_relative_target() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nmounts:\n  - type: bind\n    source: /h\n    target: rel/path",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("must be absolute"), "got: {err}");
    }

    #[test]
    fn rejects_relative_bind_source_in_long_form() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nmounts:\n  - type: bind\n    source: rel/path\n    target: /a",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("must be absolute"), "got: {err}");
    }

    #[test]
    fn rejects_mount_duplicating_volume_entry() {
        // Same canonical form on both sides — would produce two
        // `--volume` / `--mount` for the same logical mount, which
        // docker would error on at apply time.
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
volumes:
  - "/var/data:/app/data"
mounts:
  - type: bind
    source: /var/data
    target: /app/data
"#,
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("duplicates"), "got: {err}");
    }

    #[test]
    fn absent_state_forbids_mounts() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nstate: absent\nmounts:\n  - type: bind\n    source: /a\n    target: /b",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("mounts"), "got: {err}");
    }

    #[test]
    fn mount_to_short_form_round_trips_bind() {
        let m = DockerMount {
            r#type: "bind".into(),
            source: Some("/host".into()),
            target: "/cont".into(),
            readonly: false,
        };
        assert_eq!(mount_to_short_form(&m).as_deref(), Some("/host:/cont"));
    }

    #[test]
    fn mount_to_short_form_includes_ro_flag() {
        let m = DockerMount {
            r#type: "volume".into(),
            source: Some("data".into()),
            target: "/data".into(),
            readonly: true,
        };
        assert_eq!(mount_to_short_form(&m).as_deref(), Some("data:/data:ro"));
    }

    #[test]
    fn mount_to_short_form_returns_none_for_tmpfs() {
        let m = DockerMount {
            r#type: "tmpfs".into(),
            source: None,
            target: "/tmp/cache".into(),
            readonly: false,
        };
        assert!(mount_to_short_form(&m).is_none());
    }

    #[test]
    fn mount_to_cli_arg_orders_keys_predictably() {
        let m = DockerMount {
            r#type: "bind".into(),
            source: Some("/h".into()),
            target: "/c".into(),
            readonly: true,
        };
        assert_eq!(mount_to_cli_arg(&m), "type=bind,source=/h,target=/c,readonly");

        let tmpfs = DockerMount {
            r#type: "tmpfs".into(),
            source: None,
            target: "/cache".into(),
            readonly: false,
        };
        assert_eq!(mount_to_cli_arg(&tmpfs), "type=tmpfs,target=/cache");
    }

    #[test]
    fn parses_volumes_bind_and_named() {
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: web
image: nginx
volumes:
  - "/var/data:/app/data"
  - "/etc/conf:/conf:ro"
  - "myvol:/data"
"#,
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.volumes.len(), 3);
    }

    #[test]
    fn rejects_relative_destination() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nvolumes: [\"/host:relative/path\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn rejects_volume_traversal() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nvolumes: [\"/etc/../etc:/c\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains(".."), "got: {err}");
    }

    #[test]
    fn rejects_volume_shell_metas() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nvolumes: [\"/data:/app;rm -rf /\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("shell"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_volume_mode() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nvolumes: [\"/data:/app:weird\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("'ro' or 'rw'"), "got: {err}");
    }

    #[test]
    fn rejects_relative_bind_source() {
        // Source with '/' but not absolute → operator probably meant a
        // relative path, which docker-compose accepts but we don't.
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nimage: nginx\nvolumes: [\"./local:/app\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("relative path"), "got: {err}");
    }

    #[test]
    fn parse_volume_spec_canonicalizes_default_mode() {
        // Default mode = rw; normalize_volume_spec drops the trailing
        // `:rw` so observed-vs-desired comparisons don't false-flag.
        let (src, dst, ro) = parse_volume_spec("/data:/app").unwrap();
        assert!(!ro);
        assert_eq!(normalize_volume_spec(src, dst, ro), "/data:/app");
        // Explicit `:rw` normalizes the same way.
        let (src, dst, ro) = parse_volume_spec("/data:/app:rw").unwrap();
        assert!(!ro);
        assert_eq!(normalize_volume_spec(src, dst, ro), "/data:/app");
        // `:ro` is preserved.
        let (src, dst, ro) = parse_volume_spec("/data:/app:ro").unwrap();
        assert!(ro);
        assert_eq!(normalize_volume_spec(src, dst, ro), "/data:/app:ro");
    }

    #[test]
    fn absent_state_forbids_volumes() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nstate: absent\nvolumes: [\"/data:/app\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("volumes"), "got: {err}");
    }

    #[test]
    fn absent_state_forbids_command() {
        let v: Value = serde_yaml_ng::from_str(
            "name: x\nstate: absent\ncommand: [\"sh\"]",
        )
        .unwrap();
        let err = DockerContainerSpec::from_value(&v).unwrap_err();
        assert!(err.contains("command"), "got: {err}");
    }

    #[test]
    fn label_values_can_contain_equals() {
        // Only the key is the structural separator; values are arbitrary.
        let v: Value = serde_yaml_ng::from_str(
            r#"
name: x
image: nginx
labels:
  app: "name=web&env=prod"
"#,
        )
        .unwrap();
        let s = DockerContainerSpec::from_value(&v).unwrap();
        assert_eq!(s.labels.get("app").map(String::as_str), Some("name=web&env=prod"));
    }
}
