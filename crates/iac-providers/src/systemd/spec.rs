use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum UnitType {
    #[default]
    Service,
    Socket,
    Timer,
    Target,
    Path,
    Mount,
}

impl UnitType {
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Socket => "socket",
            Self::Timer => "timer",
            Self::Target => "target",
            Self::Path => "path",
            Self::Mount => "mount",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnitSpec {
    /// Unit name without the suffix, e.g. `nginx`. The suffix comes from
    /// `unit_type` (default: `service`). Users may also write the full
    /// `nginx.service` and we accept it.
    pub name: String,
    #[serde(default, rename = "type")]
    pub unit_type: UnitType,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

impl SystemdUnitSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("name must not be empty".into());
        }
        if self.name.contains(char::is_whitespace) {
            return Err("name must not contain whitespace".into());
        }
        // Argument-injection guard: a name like `--root=/x.service` or
        // `--global` passes the whitespace check and would be parsed by
        // `systemctl` as an OPTION, not a unit, redirecting a
        // root-privileged operation. Reject leading `-` and restrict to
        // the systemd unit-name charset.
        if self.name.starts_with('-') {
            return Err("name must not start with '-' (parsed as a systemctl option)".into());
        }
        if let Some(c) = self.name.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '@' | '-' | '\\'))
        }) {
            return Err(format!(
                "unsafe character {c:?} in unit name {:?}",
                self.name
            ));
        }
        Ok(())
    }

    /// Full unit name with suffix.
    pub fn unit_name(&self) -> String {
        if self.name.contains('.') {
            self.name.clone()
        } else {
            format!("{}.{}", self.name, self.unit_type.suffix())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let v: Value = serde_yaml_ng::from_str("name: nginx").unwrap();
        let s = SystemdUnitSpec::from_value(&v).unwrap();
        assert_eq!(s.unit_name(), "nginx.service");
        assert!(s.enabled);
        assert!(s.active);
    }

    #[test]
    fn timer_with_explicit_suffix() {
        let v: Value =
            serde_yaml_ng::from_str("name: backup.timer\ntype: timer\nactive: false").unwrap();
        let s = SystemdUnitSpec::from_value(&v).unwrap();
        assert_eq!(s.unit_name(), "backup.timer");
        assert!(!s.active);
    }

    #[test]
    fn rejects_option_injecting_unit_names() {
        // Argument-injection guard: names that systemctl would parse as
        // options must be refused before reaching the backend.
        for bad in ["--global", "-.mount", "--root=/tmp/x.service", "a b", "x;y"] {
            let v: Value = serde_yaml_ng::from_str(&format!("name: {bad:?}")).unwrap();
            assert!(
                SystemdUnitSpec::from_value(&v).is_err(),
                "should reject unit name {bad:?}"
            );
        }
    }

    #[test]
    fn accepts_normal_unit_names() {
        for ok in [
            "nginx",
            "backup.timer",
            "foo@bar.service",
            "my-svc_1.service",
        ] {
            let v: Value = serde_yaml_ng::from_str(&format!("name: {ok:?}")).unwrap();
            assert!(
                SystemdUnitSpec::from_value(&v).is_ok(),
                "should accept unit name {ok:?}"
            );
        }
    }
}
