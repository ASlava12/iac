// Phase 7cz.16: this spec module uses .chars().next/last().expect()
// patterns where the validate() function already proved the string is
// non-empty. The single `unwrap()` on `strip_prefix("http://")` is
// guaranteed by the preceding `starts_with("http://")` check.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Phase 7ca: `monitoring.check` spec — active health check as an
//! asserted invariant.
//!
//! ```yaml
//! apiVersion: iac.example/v1
//! kind: monitoring.check
//! metadata: { name: web-healthz, environment: prod }
//! spec:
//!   type: http              # http | tcp
//!   target: http://localhost:8080/healthz
//!   # tcp: target = host:port (e.g. 10.0.0.5:5432)
//!   expected_status: 200    # http only; default 200
//!   timeout_secs: 5
//!   state: present          # present (default) | absent (skip)
//! ```
//!
//! Semantics: the desired state is "this endpoint responds healthily."
//! `observe` runs the check; success → present, failure → drift.
//! `apply` re-runs the check and reports the result. The provider
//! never *writes* state — it asserts an invariant.
//!
//! Cross-platform: pure `std::net` for both HTTP and TCP. No HTTPS in
//! v1 (would require rustls dep + cert chain config); operators check
//! /healthz over plain HTTP from the agent's network namespace, which
//! is the standard pattern. v2 may add HTTPS via the workspace
//! reqwest feature.

use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    /// Active: run the check, succeed iff it passes.
    #[default]
    Present,
    /// Disabled: skip the check entirely; observe always reports
    /// converged. Useful for temporarily silencing a flapping check
    /// without removing it from the manifest.
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckType {
    /// HTTP/1.0 GET to a full URL. Status code compared against
    /// `expected_status`. No HTTPS in v1.
    Http,
    /// TCP connect to `host:port`. Success = port accepts the
    /// connection within `timeout_secs`.
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MonitoringCheckSpec {
    /// Operator-readable name. Surfaces in the Prometheus / audit
    /// output. Required, alphanumeric + `-`/`_`/`.`.
    pub name: String,
    /// Check protocol. `http` runs an HTTP/1.0 GET; `tcp` runs a
    /// connect attempt.
    #[serde(rename = "type")]
    pub check_type: CheckType,
    /// HTTP: full URL like `http://host:port/path`. TCP: `host:port`.
    /// Validated for shell-meta safety + protocol-specific shape.
    pub target: String,
    /// HTTP only: expected response status code. Default 200.
    /// TCP rejects this (no semantics).
    #[serde(default)]
    pub expected_status: Option<u16>,
    /// Connect + read timeout in seconds. Default 5. 1..=60.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub state: CheckState,
    /// Phase 7cj: how many additional times to retry a failing
    /// probe before giving up. Default 0 (single attempt). When set,
    /// the provider sleeps `retry_interval_secs` between attempts —
    /// this is what makes a `monitoring.check` resource usable as a
    /// canary health gate, since real services need a few seconds
    /// between deployment and steady-state readiness.
    ///
    /// `apply` succeeds on the first passing probe; subsequent
    /// retries are skipped. So `retries: 5` + `retry_interval_secs: 2`
    /// gives you up to 12 seconds of grace. The total budget is
    /// bounded by `(retries + 1) * timeout_secs + retries *
    /// retry_interval_secs`, so the apply doesn't run away
    /// indefinitely on a perpetually-broken target.
    #[serde(default)]
    pub retries: u32,
    /// Sleep between retry attempts in seconds. Ignored when
    /// `retries == 0`. 0..=60. Default 1.
    #[serde(default = "default_retry_interval_secs")]
    pub retry_interval_secs: u64,
}

fn default_timeout_secs() -> u64 {
    5
}

fn default_retry_interval_secs() -> u64 {
    1
}

impl MonitoringCheckSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        validate_name(&self.name)?;
        if !(1..=60).contains(&self.timeout_secs) {
            return Err(format!(
                "timeout_secs {} out of range 1..=60",
                self.timeout_secs
            ));
        }
        // Phase 7cj: cap retries so a misconfigured manifest can't
        // hang an apply for hours. 30 retries at 60s interval is
        // already 30 minutes — past that, operators should fix the
        // upstream service rather than wait longer.
        if self.retries > 30 {
            return Err(format!("retries {} exceeds cap (30)", self.retries));
        }
        if self.retry_interval_secs > 60 {
            return Err(format!(
                "retry_interval_secs {} out of range 0..=60",
                self.retry_interval_secs
            ));
        }
        if self.target.is_empty() {
            return Err("target must not be empty".into());
        }
        if self.target.contains(['\n', '\r', '\0', '\t']) {
            return Err("target must not contain control characters".into());
        }
        match self.check_type {
            CheckType::Http => {
                let url = &self.target;
                if !url.starts_with("http://") {
                    return Err(format!(
                        "http target {url:?} must start with http:// (https is not supported in v1)"
                    ));
                }
                // Smell-test: must have a host portion after http://.
                let after = url.strip_prefix("http://").unwrap();
                let host_part = after.split('/').next().unwrap_or("");
                if host_part.is_empty() {
                    return Err(format!("http target {url:?} has no host"));
                }
                if let Some(code) = self.expected_status
                    && !(100..=599).contains(&code) {
                        return Err(format!(
                            "expected_status {code} not a valid HTTP status (100..=599)"
                        ));
                    }
            }
            CheckType::Tcp => {
                if self.expected_status.is_some() {
                    return Err(
                        "expected_status forbidden for tcp checks (no HTTP-style status)".into(),
                    );
                }
                let target = &self.target;
                let (host, port) = target
                    .rsplit_once(':')
                    .ok_or_else(|| format!("tcp target {target:?} must be host:port"))?;
                if host.is_empty() {
                    return Err(format!("tcp target {target:?} has no host"));
                }
                let port: u16 = port
                    .parse()
                    .map_err(|_| format!("tcp target {target:?} port {port:?} not a number"))?;
                if port == 0 {
                    return Err(format!("tcp target {target:?} port must be 1..=65535"));
                }
                if host.contains(' ') {
                    return Err(format!("tcp target {target:?} host contains whitespace"));
                }
            }
        }
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "name {:?} must be alphanumeric with optional '-', '_', '.'",
            name
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<MonitoringCheckSpec, String> {
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        MonitoringCheckSpec::from_value(&v)
    }

    #[test]
    fn parses_minimal_http() {
        let s = parse(
            "name: web-healthz\ntype: http\ntarget: http://localhost:8080/healthz",
        )
        .unwrap();
        assert_eq!(s.name, "web-healthz");
        assert_eq!(s.check_type, CheckType::Http);
        assert_eq!(s.target, "http://localhost:8080/healthz");
        assert_eq!(s.timeout_secs, 5); // default
        assert_eq!(s.expected_status, None);
    }

    #[test]
    fn parses_minimal_tcp() {
        let s = parse("name: db-port\ntype: tcp\ntarget: 10.0.0.5:5432").unwrap();
        assert_eq!(s.check_type, CheckType::Tcp);
        assert_eq!(s.target, "10.0.0.5:5432");
    }

    #[test]
    fn parses_with_expected_status_and_timeout() {
        let s = parse(
            "name: c\ntype: http\ntarget: http://x/\nexpected_status: 204\ntimeout_secs: 10",
        )
        .unwrap();
        assert_eq!(s.expected_status, Some(204));
        assert_eq!(s.timeout_secs, 10);
    }

    #[test]
    fn rejects_https_in_v1() {
        let err = parse("name: c\ntype: http\ntarget: https://x/").unwrap_err();
        assert!(err.contains("https"), "got: {err}");
    }

    #[test]
    fn rejects_http_target_without_host() {
        let err = parse("name: c\ntype: http\ntarget: http:///").unwrap_err();
        assert!(err.contains("no host"), "got: {err}");
    }

    #[test]
    fn rejects_tcp_target_without_port() {
        let err = parse("name: c\ntype: tcp\ntarget: just-host").unwrap_err();
        assert!(err.contains("host:port"), "got: {err}");
    }

    #[test]
    fn rejects_tcp_with_expected_status() {
        let err = parse(
            "name: c\ntype: tcp\ntarget: x:80\nexpected_status: 200",
        )
        .unwrap_err();
        assert!(err.contains("expected_status forbidden"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_status_code() {
        let err = parse(
            "name: c\ntype: http\ntarget: http://x/\nexpected_status: 999",
        )
        .unwrap_err();
        assert!(err.contains("100..=599"), "got: {err}");
    }

    #[test]
    fn rejects_zero_timeout() {
        let err = parse("name: c\ntype: http\ntarget: http://x/\ntimeout_secs: 0")
            .unwrap_err();
        assert!(err.contains("timeout_secs"), "got: {err}");
    }

    #[test]
    fn rejects_oversized_timeout() {
        let err = parse(
            "name: c\ntype: http\ntarget: http://x/\ntimeout_secs: 120",
        )
        .unwrap_err();
        assert!(err.contains("timeout_secs"), "got: {err}");
    }

    #[test]
    fn rejects_empty_target() {
        let err = parse("name: c\ntype: http\ntarget: ''").unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_control_chars_in_target() {
        let err = parse("name: c\ntype: http\ntarget: \"http://x/\\n\"").unwrap_err();
        assert!(err.contains("control"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_name_chars() {
        let err = parse("name: 'evil; rm'\ntype: http\ntarget: http://x/").unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = parse(
            "name: c\ntype: http\ntarget: http://x/\nbogus: 1",
        )
        .unwrap_err();
        assert!(err.contains("bogus") || err.contains("unknown"), "got: {err}");
    }

    #[test]
    fn parses_absent_state() {
        let s = parse("name: c\ntype: http\ntarget: http://x/\nstate: absent").unwrap();
        assert_eq!(s.state, CheckState::Absent);
    }

    #[test]
    fn rejects_tcp_port_zero() {
        let err = parse("name: c\ntype: tcp\ntarget: x:0").unwrap_err();
        assert!(err.contains("port"), "got: {err}");
    }
}
