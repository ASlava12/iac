use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum FileState {
    #[default]
    Present,
    Absent,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSpec {
    pub path: PathBuf,
    #[serde(default)]
    pub state: FileState,
    /// Octal mode string like "0644". `None` means "leave unmanaged".
    #[serde(default)]
    pub mode: Option<String>,
    /// User name or numeric uid. `None` means "leave unmanaged".
    #[serde(default)]
    pub owner: Option<String>,
    /// Group name or numeric gid. `None` means "leave unmanaged".
    #[serde(default)]
    pub group: Option<String>,
    /// Inline UTF-8 content. `None` with `state: present` means
    /// "content not managed" — only metadata is enforced.
    #[serde(default)]
    pub content: Option<String>,
}

impl FileSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.path.is_absolute() {
            return Err(format!("path must be absolute, got {}", self.path.display()));
        }
        match self.state {
            FileState::Absent => {
                if self.content.is_some() {
                    return Err("state=absent forbids content".to_string());
                }
                if self.mode.is_some() || self.owner.is_some() || self.group.is_some() {
                    return Err("state=absent forbids mode/owner/group".to_string());
                }
            }
            FileState::Present => {}
        }
        if let Some(m) = &self.mode {
            parse_mode(m).map_err(|e| format!("invalid mode {m:?}: {e}"))?;
        }
        Ok(())
    }

    pub fn parsed_mode(&self) -> Option<u32> {
        self.mode.as_deref().and_then(|s| parse_mode(s).ok())
    }
}

pub fn parse_mode(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let s = s.strip_prefix("0o").unwrap_or(s);
    u32::from_str_radix(s, 8).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_spec() {
        let yaml = r#"
path: /etc/foo
mode: "0644"
owner: root
group: root
content: hello
"#;
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        let s = FileSpec::from_value(&v).unwrap();
        assert_eq!(s.path.to_str(), Some("/etc/foo"));
        assert_eq!(s.parsed_mode(), Some(0o644));
        assert_eq!(s.content.as_deref(), Some("hello"));
    }

    #[test]
    fn rejects_relative_path() {
        let yaml = "path: foo";
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(FileSpec::from_value(&v).is_err());
    }

    #[test]
    fn rejects_absent_with_content() {
        let yaml = r#"
path: /etc/foo
state: absent
content: hi
"#;
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(FileSpec::from_value(&v).is_err());
    }

    #[test]
    fn parse_mode_octal() {
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("644").unwrap(), 0o644);
        assert_eq!(parse_mode("0o755").unwrap(), 0o755);
    }
}
