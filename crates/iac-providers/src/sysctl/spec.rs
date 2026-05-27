//! Phase 7cb: `sysctl.setting` spec — declarative kernel parameters.
//!
//! ```yaml
//! apiVersion: iac.example/v1
//! kind: sysctl.setting
//! metadata: { name: ip-forward, environment: prod }
//! spec:
//!   key: net.ipv4.ip_forward
//!   value: "1"
//!   state: present       # present (default) | absent (revert to default)
//! ```
//!
//! Network-gear specific, but useful broadly: enable IP forwarding,
//! tune conntrack table size, set TCP buffer windows. The provider
//! reads `/proc/sys/<key-with-slashes>` for observe and writes via
//! the same path for apply — no shell-out, no third-party deps.
//!
//! Persistence: this provider only sets the *runtime* value. To make
//! the setting survive reboot, operators pair it with a `file`
//! resource writing `/etc/sysctl.d/iac-<name>.conf`. The split is
//! intentional — runtime tuning vs. boot-time persistence are
//! different ops concerns and operators want to control them
//! separately (e.g., test a value at runtime before persisting).

use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

/// Phase 7cb v1 ships only Present state — the model is "this kernel
/// param must equal this value." Reverting is done by removing the
/// resource from the manifest (operation orchestrator handles drop)
/// or running rollback explicitly. A future v2 may add Absent with
/// captured-default semantics; the design needs a checkpoint surface
/// in `ApplyContext` that doesn't exist in v1.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SysctlState {
    /// Set the parameter to `value`. Idempotent — apply only writes
    /// when the current runtime value differs.
    #[default]
    Present,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SysctlSettingSpec {
    /// Dotted-path kernel parameter, e.g. `net.ipv4.ip_forward`.
    /// Validated for shell-safety and kernel namespace shape (must
    /// not start/end with a dot, no double dots, alphanumeric +
    /// `_` + `-` + `.`). The `/` separator used by `/proc/sys` is
    /// produced internally — operators write dots only.
    pub key: String,
    /// Value to set. String form (kernel always exposes as text).
    /// Required (the only state in v1 is Present).
    /// Validated for control-character safety; otherwise opaque.
    pub value: String,
    #[serde(default)]
    pub state: SysctlState,
}

impl SysctlSettingSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    /// Dotted key → slash-separated path under /proc/sys.
    /// Pure mapping, no I/O.
    pub fn proc_path(&self) -> String {
        format!("/proc/sys/{}", self.key.replace('.', "/"))
    }

    fn validate(&self) -> Result<(), String> {
        validate_key(&self.key)?;
        validate_value(&self.value)?;
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("key must not be empty".into());
    }
    if key.starts_with('.') || key.ends_with('.') || key.contains("..") {
        return Err(format!(
            "key {key:?} must not start/end with '.' or contain '..'"
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "key {key:?} must be alphanumeric with optional '.', '_', '-'"
        ));
    }
    // Defense-in-depth: reject `/` even though we use replace_dots.
    // Catches operator confusion ("net/ipv4/ip_forward" instead of
    // dotted form).
    if key.contains('/') {
        return Err(format!(
            "key {key:?} must use dots, not slashes (kernel uses dotted form)"
        ));
    }
    // Length cap matches the longest known sysctl path with margin.
    if key.len() > 256 {
        return Err(format!("key {key:?} length {} exceeds 256", key.len()));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), String> {
    if value.contains(['\0', '\n', '\r']) {
        // Sysctl values are written verbatim to /proc/sys/<key>.
        // Newlines / NULs in the value would either truncate or
        // confuse the kernel's value parser.
        return Err("value must not contain control characters (NUL, LF, CR)".into());
    }
    if value.len() > 4096 {
        return Err(format!(
            "value length {} exceeds 4096 (kernel write buffer limit)",
            value.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<SysctlSettingSpec, String> {
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        SysctlSettingSpec::from_value(&v)
    }

    #[test]
    fn parses_minimal() {
        let s = parse("key: net.ipv4.ip_forward\nvalue: \"1\"").unwrap();
        assert_eq!(s.key, "net.ipv4.ip_forward");
        assert_eq!(s.value, "1");
        assert_eq!(s.state, SysctlState::Present);
    }

    #[test]
    fn proc_path_replaces_dots_with_slashes() {
        let s = parse("key: net.ipv4.tcp_window_scaling\nvalue: \"1\"").unwrap();
        assert_eq!(s.proc_path(), "/proc/sys/net/ipv4/tcp_window_scaling");
    }

    #[test]
    fn rejects_missing_value() {
        // value is now required (no Absent state in v1).
        let err = parse("key: net.ipv4.ip_forward").unwrap_err();
        assert!(
            err.contains("value") || err.contains("missing"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_empty_key() {
        let err = parse("key: ''\nvalue: '1'").unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_key_with_slashes() {
        // Slashes are caught by the general alphanumeric check — the
        // explicit "use dots not slashes" message only fires for keys
        // that pass the alphanumeric check (which is impossible with
        // a slash). Either rejection path is fine; the key is
        // rejected.
        let err = parse("key: net/ipv4/ip_forward\nvalue: '1'").unwrap_err();
        assert!(
            err.contains("alphanumeric") || err.contains("dots, not slashes"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_key_with_invalid_chars() {
        let err = parse("key: 'net.ipv4.ip_forward; rm'\nvalue: '1'").unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn rejects_key_with_double_dots() {
        let err = parse("key: net..ipv4\nvalue: '1'").unwrap_err();
        assert!(err.contains("'..'") || err.contains(".."), "got: {err}");
    }

    #[test]
    fn rejects_key_starting_with_dot() {
        let err = parse("key: .net.ipv4\nvalue: '1'").unwrap_err();
        assert!(err.contains("start/end"), "got: {err}");
    }

    #[test]
    fn rejects_value_with_newline() {
        let err = parse("key: a.b\nvalue: \"1\\n2\"").unwrap_err();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = parse("key: a.b\nvalue: '1'\nbogus: 1").unwrap_err();
        assert!(
            err.contains("bogus") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_oversize_value() {
        let big = "x".repeat(5000);
        let err = parse(&format!("key: a.b\nvalue: \"{big}\"")).unwrap_err();
        assert!(err.contains("4096"), "got: {err}");
    }

    #[test]
    fn rejects_oversize_key() {
        let big = "a".repeat(300);
        let err = parse(&format!("key: \"{big}\"\nvalue: '1'")).unwrap_err();
        assert!(err.contains("256"), "got: {err}");
    }
}
