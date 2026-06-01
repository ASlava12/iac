use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum PackageState {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSpec {
    pub name: String,
    #[serde(default)]
    pub state: PackageState,
    /// Pin a specific version. Only meaningful when `state == Present`.
    /// Behavior with apt: passes `<name>=<version>` to `apt-get install`.
    #[serde(default)]
    pub version: Option<String>,
    /// Backend identifier. For Phase 0 only `apt` is supported; defaulted.
    #[serde(default = "default_backend")]
    pub backend: String,
}

fn default_backend() -> String {
    "apt".to_string()
}

impl PackageSpec {
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
        // Argument-injection guard: a name like `--reinstall` is all
        // in-charset below but would be parsed by `apt-get` as an OPTION,
        // changing the semantics of a root-privileged install/remove.
        if self.name.starts_with('-') {
            return Err("name must not start with '-' (parsed as an apt-get option)".into());
        }
        // Restrict to safe characters: shell-out resistance for Phase 0.
        // Apt allows letters, digits, +, -, ., : (epoch in version), but the
        // name itself shouldn't include `:` (architecture suffix is allowed).
        let bad = self
            .name
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | ':')));
        if bad {
            return Err(format!("unsafe character in package name: {:?}", self.name));
        }
        if let Some(v) = &self.version {
            let bad = v
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | ':' | '~')));
            if bad {
                return Err(format!("unsafe character in version: {v:?}"));
            }
        }
        if self.state == PackageState::Absent && self.version.is_some() {
            return Err("state=absent forbids version".into());
        }
        if self.backend != "apt" {
            return Err(format!(
                "unsupported backend {:?}; only 'apt' is implemented in Phase 0",
                self.backend
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let v: Value = serde_yaml_ng::from_str("name: nginx").unwrap();
        let s = PackageSpec::from_value(&v).unwrap();
        assert_eq!(s.name, "nginx");
        assert_eq!(s.state, PackageState::Present);
    }

    #[test]
    fn rejects_unsafe_name() {
        let v: Value = serde_yaml_ng::from_str("name: \"nginx; rm -rf /\"").unwrap();
        assert!(PackageSpec::from_value(&v).is_err());
    }

    #[test]
    fn rejects_option_injecting_package_names() {
        // `--reinstall` / `-y` are all in-charset but would be parsed by
        // apt-get as options — reject leading-dash names.
        for bad in ["--reinstall", "-y", "--purge", "-oAPT"] {
            let v: Value = serde_yaml_ng::from_str(&format!("name: {bad:?}")).unwrap();
            assert!(
                PackageSpec::from_value(&v).is_err(),
                "should reject package name {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_absent_with_version() {
        let v: Value = serde_yaml_ng::from_str("name: nginx\nstate: absent\nversion: 1.0").unwrap();
        assert!(PackageSpec::from_value(&v).is_err());
    }
}
