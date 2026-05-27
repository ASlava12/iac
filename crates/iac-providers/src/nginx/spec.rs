// Phase 7cz.16: this spec module uses .chars().next/last().expect()
// patterns where the validate() function already proved the string is
// non-empty. The invariant is local to the module.
#![allow(clippy::expect_used)]

use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum NginxState {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NginxVhostSpec {
    /// Absolute path to the nginx config snippet, e.g.
    /// `/etc/nginx/conf.d/app.conf`. The provider does NOT pick this for you;
    /// being explicit avoids surprises across distros that use different
    /// include paths.
    pub config_path: PathBuf,

    #[serde(default)]
    pub state: NginxState,

    /// `server_name` directive value(s). Required when state=present.
    #[serde(default)]
    pub server_names: Vec<String>,

    /// `listen` ports. Defaults to `[80]`. Port 443 (or any of the
    /// well-known TLS ports — 8443/4443) requires `tls:` to be set;
    /// otherwise we'd render an `nginx listen 443;` plain-HTTP block,
    /// which is the kind of silent-footgun we explicitly refuse to
    /// emit (Phase 7cz.12).
    #[serde(default = "default_listen")]
    pub listen: Vec<u16>,

    /// `proxy_pass` upstream URL, e.g. `http://127.0.0.1:8080`. Required
    /// when state=present. Phase 5b ships only `proxy_pass` upstreams; static
    /// roots / fastcgi land later.
    #[serde(default)]
    pub upstream: Option<String>,

    /// Raw `client_max_body_size` value, e.g. `"10M"`.
    #[serde(default)]
    pub client_max_body_size: Option<String>,

    /// Raw `proxy_read_timeout` value, e.g. `"60s"`.
    #[serde(default)]
    pub proxy_read_timeout: Option<String>,

    /// TLS configuration. When `Some`, the renderer emits an `ssl`-listening
    /// server block; if `redirect_http` is true and port 80 is in `listen`,
    /// it also emits a 301 redirect server block on port 80. When `None`,
    /// the rendered config is plain HTTP.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Phase 7aw: additional `location` blocks beyond the default `/`
    /// proxy_pass. Common uses: `/static/` → root path, `/metrics/`
    /// proxied to a different upstream, `/healthz` returning a static
    /// 200. Rendered in declared order, AFTER the default `/` block —
    /// so a more specific path lookup wins per nginx's prefix-matching
    /// rules.
    ///
    /// Each entry must specify exactly one of `proxy_pass` or `root`;
    /// future-incompatible "neither" / "both" reject at parse time.
    #[serde(default)]
    pub extra_locations: Vec<ExtraLocation>,
}

/// Phase 7aw: secondary location block. Validation focuses on shell-safety
/// (no `;`, no whitespace in path/proxy_pass/root) — operators write the
/// path expression themselves, so we trust the syntax but lock the
/// arguments down.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraLocation {
    /// Location pattern. Common forms:
    ///   `/static/`             — prefix match
    ///   `= /healthz`           — exact match
    ///   `~ \.php$`             — regex
    ///   `^~ /assets/`          — preferential prefix
    /// We don't introspect the form; we just require the leading char
    /// to be one of `/=~^` so a malformed manifest rejects loudly.
    pub path: String,

    /// `proxy_pass` upstream URL. Mutually exclusive with `root`.
    #[serde(default)]
    pub proxy_pass: Option<String>,

    /// Filesystem root for static-file serving. Mutually exclusive with
    /// `proxy_pass`. Must be an absolute path with no traversal.
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Absolute path to the fullchain PEM, e.g.
    /// `/etc/letsencrypt/live/app.example.com/fullchain.pem`.
    pub certificate: PathBuf,
    /// Absolute path to the private key PEM.
    pub key: PathBuf,
    /// When true and port 80 is in `spec.listen`, render a separate 301
    /// redirect block on port 80 → `https://$host$request_uri`. Default true.
    #[serde(default = "default_redirect_http")]
    pub redirect_http: bool,
}

fn default_redirect_http() -> bool {
    true
}

fn default_listen() -> Vec<u16> {
    vec![80]
}

impl NginxVhostSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.config_path.is_absolute() {
            return Err(format!(
                "config_path must be absolute, got {}",
                self.config_path.display()
            ));
        }
        let path_str = self.config_path.to_string_lossy();
        if path_str.contains("..") {
            return Err("config_path must not contain '..'".into());
        }

        match self.state {
            NginxState::Absent => {
                if !self.server_names.is_empty()
                    || self.upstream.is_some()
                    || self.client_max_body_size.is_some()
                    || self.proxy_read_timeout.is_some()
                    || self.tls.is_some()
                {
                    return Err("state=absent forbids vhost fields".into());
                }
            }
            NginxState::Present => {
                if self.server_names.is_empty() {
                    return Err("server_names is required when state=present".into());
                }
                for n in &self.server_names {
                    validate_server_name(n)?;
                }
                let upstream = self
                    .upstream
                    .as_deref()
                    .ok_or_else(|| "upstream is required when state=present".to_string())?;
                validate_upstream(upstream)?;
                if let Some(s) = &self.client_max_body_size {
                    validate_size(s, "client_max_body_size")?;
                }
                if let Some(s) = &self.proxy_read_timeout {
                    validate_duration(s, "proxy_read_timeout")?;
                }
                if let Some(tls) = &self.tls {
                    validate_tls(tls)?;
                }
                // Phase 7cz.12: refuse `listen 443` (or 8443/4443)
                // without `tls:`. Pre-7cz the renderer silently
                // emitted plain HTTP on 443 — operator pointed
                // browsers at https://… and got connection-refused
                // or, worse, downgrade attacks if a proxy in front
                // was already terminating TLS and forwarding to
                // this nginx.
                if self.tls.is_none() {
                    for &port in &self.listen {
                        if matches!(port, 443 | 4443 | 8443) {
                            return Err(format!(
                                "listen port {port} requires tls: section; \
                                 plain HTTP on a well-known TLS port is rejected"
                            ));
                        }
                    }
                }
                for (i, loc) in self.extra_locations.iter().enumerate() {
                    validate_extra_location(loc)
                        .map_err(|e| format!("extra_locations[{i}]: {e}"))?;
                }
            }
        }
        Ok(())
    }

    /// Effective listen ports. When TLS is configured, 443 is auto-added
    /// (deduped) so callers don't have to remember to set both `listen` and
    /// `tls`.
    pub fn effective_listen(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.listen.clone();
        if self.tls.is_some() && !ports.contains(&443) {
            ports.push(443);
        }
        ports
    }
}

fn validate_extra_location(loc: &ExtraLocation) -> Result<(), String> {
    let path = loc.path.trim();
    if path.is_empty() {
        return Err("path must not be empty".into());
    }
    if path.contains(';') || path.contains('\n') || path.contains('"') {
        return Err("path must not contain ';', '\"', or newlines".into());
    }
    let leading = path.chars().next().expect("non-empty");
    if !matches!(leading, '/' | '=' | '~' | '^') {
        return Err(format!(
            "path must start with '/', '=', '~', or '^~'; got {path:?}"
        ));
    }

    match (&loc.proxy_pass, &loc.root) {
        (None, None) => {
            return Err("must set exactly one of proxy_pass or root".into());
        }
        (Some(_), Some(_)) => {
            return Err("proxy_pass and root are mutually exclusive".into());
        }
        (Some(upstream), None) => {
            // Reuse the same upstream validation as the default `/` block.
            validate_upstream(upstream)?;
        }
        (None, Some(root)) => {
            if !root.starts_with('/') {
                return Err(format!("root must be absolute, got {root:?}"));
            }
            if root.contains("..") {
                return Err("root must not contain '..'".into());
            }
            if root.contains([';', ' ', '\t', '\n', '"', '\''].as_slice()) {
                return Err("root must not contain shell metacharacters".into());
            }
        }
    }
    Ok(())
}

fn validate_tls(tls: &TlsConfig) -> Result<(), String> {
    validate_pem_path(&tls.certificate, "tls.certificate")?;
    validate_pem_path(&tls.key, "tls.key")?;
    Ok(())
}

fn validate_pem_path(path: &std::path::Path, field: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{field} must be absolute, got {}", path.display()));
    }
    let s = path.to_string_lossy();
    if s.contains("..") {
        return Err(format!("{field} must not contain '..'"));
    }
    if s.contains([';', ' ', '\t', '\n', '"', '\''].as_slice()) {
        return Err(format!("{field} must not contain shell metacharacters"));
    }
    Ok(())
}

fn validate_server_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("server_name must not be empty".into());
    }
    // Allow standard host chars + nginx wildcard '*' and regex prefix '~'.
    let bad = name.chars().any(|c| {
        !(c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.' | '_' | '*' | '~' | '^' | '$' | '/' | ':' | '+' | '?' | '|'
            ))
    });
    if bad {
        return Err(format!(
            "server_name {name:?} contains disallowed characters"
        ));
    }
    if name.contains(';') {
        return Err(format!("server_name {name:?} contains ';'"));
    }
    Ok(())
}

fn validate_upstream(upstream: &str) -> Result<(), String> {
    if upstream.is_empty() {
        return Err("upstream must not be empty".into());
    }
    if upstream.contains(char::is_whitespace) {
        return Err("upstream must not contain whitespace".into());
    }
    if upstream.contains(';') {
        return Err("upstream must not contain ';'".into());
    }
    // Conservative: must start with http://, https://, or unix: prefix.
    if !(upstream.starts_with("http://")
        || upstream.starts_with("https://")
        || upstream.starts_with("unix:"))
    {
        return Err("upstream must start with http://, https://, or unix:".into());
    }
    Ok(())
}

fn validate_size(value: &str, field: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    let suffix = value.chars().last().expect("non-empty");
    let allowed_suffixes = ['k', 'K', 'm', 'M', 'g', 'G'];
    if suffix.is_ascii_digit() {
        // Plain number is allowed (bytes).
    } else if !allowed_suffixes.contains(&suffix) {
        return Err(format!(
            "{field}: suffix must be one of {allowed_suffixes:?}"
        ));
    }
    let digits = if suffix.is_ascii_digit() {
        value
    } else {
        &value[..value.len() - 1]
    };
    if digits.parse::<u64>().is_err() {
        return Err(format!("{field}: numeric part {digits:?} is not a u64"));
    }
    Ok(())
}

fn validate_duration(value: &str, field: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    let suffix = value.chars().last().expect("non-empty");
    let allowed = ['s', 'm', 'h', 'd', 'w', 'M', 'y'];
    if suffix.is_ascii_digit() {
        // Plain number is allowed (seconds).
    } else if !allowed.contains(&suffix) {
        return Err(format!("{field}: suffix must be one of {allowed:?}"));
    }
    let digits = if suffix.is_ascii_digit() {
        value
    } else {
        &value[..value.len() - 1]
    };
    if digits.parse::<u64>().is_err() {
        return Err(format!("{field}: numeric part {digits:?} is not a u64"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<NginxVhostSpec, String> {
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        NginxVhostSpec::from_value(&v)
    }

    #[test]
    fn parses_minimal_present() {
        let s = parse(
            r#"
config_path: /etc/nginx/conf.d/app.conf
server_names: [app.example.com]
upstream: http://127.0.0.1:8080
"#,
        )
        .unwrap();
        assert_eq!(s.listen, vec![80]);
        assert_eq!(s.server_names, vec!["app.example.com"]);
    }

    #[test]
    fn rejects_listen_443_without_tls() {
        // Phase 7cz.12: silent footgun — pre-7cz the renderer would
        // emit `listen 443;` with no `ssl` keyword.
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/app.conf
server_names: [app.example.com]
upstream: http://127.0.0.1:8080
listen: [80, 443]
"#,
        )
        .unwrap_err();
        assert!(err.contains("443"), "{err}");
        assert!(err.contains("tls:"), "{err}");
    }

    #[test]
    fn accepts_listen_443_with_tls() {
        let s = parse(
            r#"
config_path: /etc/nginx/conf.d/app.conf
server_names: [app.example.com]
upstream: http://127.0.0.1:8080
listen: [80, 443]
tls:
  certificate: /etc/iac/certs/app/fullchain.pem
  key: /etc/iac/certs/app/key.pem
"#,
        )
        .unwrap();
        assert!(s.listen.contains(&443));
        assert!(s.tls.is_some());
    }

    #[test]
    fn rejects_relative_config_path() {
        let err =
            parse("config_path: rel.conf\nserver_names: [a]\nupstream: http://x").unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn rejects_missing_upstream() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
"#,
        )
        .unwrap_err();
        assert!(err.contains("upstream"));
    }

    #[test]
    fn rejects_semicolon_in_server_name() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: ["evil.com;evil"]
upstream: http://127.0.0.1
"#,
        )
        .unwrap_err();
        assert!(err.contains(';') || err.contains("disallowed"));
    }

    #[test]
    fn rejects_unsafe_upstream() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [a]
upstream: "http://x; rm -rf /"
"#,
        )
        .unwrap_err();
        assert!(err.contains("whitespace") || err.contains(';'));
    }

    #[test]
    fn validates_size_and_duration_units() {
        let ok = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [a]
upstream: http://127.0.0.1
client_max_body_size: 10M
proxy_read_timeout: 60s
"#,
        )
        .unwrap();
        assert_eq!(ok.client_max_body_size.as_deref(), Some("10M"));

        assert!(
            parse(
                r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [a]
upstream: http://127.0.0.1
client_max_body_size: 10X
"#,
            )
            .is_err()
        );
    }

    #[test]
    fn parses_tls_config() {
        let s = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1:8080
tls:
  certificate: /etc/letsencrypt/live/x/fullchain.pem
  key: /etc/letsencrypt/live/x/privkey.pem
"#,
        )
        .unwrap();
        let tls = s.tls.as_ref().unwrap();
        assert!(tls.redirect_http);
        // effective_listen auto-adds 443.
        assert_eq!(s.effective_listen(), vec![80, 443]);
    }

    #[test]
    fn rejects_relative_cert_path() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
tls:
  certificate: relative.pem
  key: /etc/key.pem
"#,
        )
        .unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn rejects_traversal_in_cert() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
tls:
  certificate: /etc/../etc/cert.pem
  key: /etc/key.pem
"#,
        )
        .unwrap_err();
        assert!(err.contains(".."));
    }

    #[test]
    fn parses_extra_location_with_proxy_pass() {
        let s = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1:8080
extra_locations:
  - path: /metrics
    proxy_pass: http://127.0.0.1:9090
"#,
        )
        .unwrap();
        assert_eq!(s.extra_locations.len(), 1);
        assert_eq!(s.extra_locations[0].path, "/metrics");
    }

    #[test]
    fn extra_location_rejects_neither_proxy_nor_root() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1:8080
extra_locations:
  - path: /static/
"#,
        )
        .unwrap_err();
        assert!(err.contains("exactly one of"), "got: {err}");
    }

    #[test]
    fn extra_location_rejects_both_proxy_and_root() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1:8080
extra_locations:
  - path: /both
    proxy_pass: http://127.0.0.1:9090
    root: /var/www
"#,
        )
        .unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn extra_location_rejects_relative_root() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
extra_locations:
  - path: /static/
    root: var/www
"#,
        )
        .unwrap_err();
        assert!(err.contains("absolute"), "got: {err}");
    }

    #[test]
    fn extra_location_rejects_traversal_in_root() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
extra_locations:
  - path: /static/
    root: /var/../etc
"#,
        )
        .unwrap_err();
        assert!(err.contains(".."), "got: {err}");
    }

    #[test]
    fn extra_location_rejects_bad_path_prefix() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
extra_locations:
  - path: "metrics"
    proxy_pass: http://127.0.0.1:9090
"#,
        )
        .unwrap_err();
        assert!(err.contains("must start with"), "got: {err}");
    }

    #[test]
    fn extra_location_rejects_semicolon_in_path() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
extra_locations:
  - path: "/x; root /etc"
    proxy_pass: http://127.0.0.1:9090
"#,
        )
        .unwrap_err();
        assert!(err.contains(';') || err.contains("newlines"), "got: {err}");
    }

    #[test]
    fn extra_location_proxy_pass_validated_like_main() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
server_names: [x.example.com]
upstream: http://127.0.0.1
extra_locations:
  - path: /api
    proxy_pass: "ftp://x"
"#,
        )
        .unwrap_err();
        assert!(
            err.contains("http://") || err.contains("upstream"),
            "got: {err}"
        );
    }

    #[test]
    fn absent_forbids_vhost_fields() {
        let err = parse(
            r#"
config_path: /etc/nginx/conf.d/x.conf
state: absent
server_names: [a]
"#,
        )
        .unwrap_err();
        assert!(err.contains("absent"));
    }
}
