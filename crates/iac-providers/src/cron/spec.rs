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
pub enum CronState {
    #[default]
    Present,
    Absent,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CronJobSpec {
    /// Filename component dropped under `/etc/cron.d/`. Restricted to
    /// `[a-zA-Z0-9._-]+` so we can build a safe path.
    pub name: String,
    #[serde(default)]
    pub state: CronState,
    /// 5-field crontab schedule: `min hour dom mon dow`. Required when
    /// `state=present`.
    #[serde(default)]
    pub schedule: Option<String>,
    /// Shell command to run. Single line (newlines are forbidden because
    /// `/etc/cron.d` lines are newline-terminated).
    #[serde(default)]
    pub command: Option<String>,
    /// User to run as. Default: `root`. Anchored to a safe charset to keep us
    /// from emitting fields that would confuse cron's parser.
    #[serde(default = "default_user")]
    pub user: String,
    /// Optional environment variables to emit at the top of the file
    /// (`KEY=VALUE` lines). Standard cron features only — no shell expansion.
    #[serde(default)]
    pub env: indexmap::IndexMap<String, String>,
    /// Override the directory `/etc/cron.d`. Useful in tests; in production
    /// don't touch.
    #[serde(default)]
    pub cron_dir: Option<PathBuf>,
}

fn default_user() -> String {
    "root".to_string()
}

impl CronJobSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        validate_name(&self.name).map_err(|e| format!("name: {e}"))?;
        validate_user(&self.user).map_err(|e| format!("user: {e}"))?;
        if let Some(dir) = &self.cron_dir
            && !dir.is_absolute() {
                return Err(format!("cron_dir must be absolute, got {}", dir.display()));
            }
        for (k, v) in &self.env {
            validate_env_key(k).map_err(|e| format!("env key {k:?}: {e}"))?;
            if v.contains('\n') {
                return Err(format!("env {k:?}: value must not contain newline"));
            }
        }
        match self.state {
            CronState::Absent => {
                if self.schedule.is_some() || self.command.is_some() || !self.env.is_empty() {
                    return Err("state=absent forbids schedule/command/env".into());
                }
            }
            CronState::Present => {
                let schedule = self
                    .schedule
                    .as_deref()
                    .ok_or_else(|| "schedule is required when state=present".to_string())?;
                validate_schedule(schedule).map_err(|e| format!("schedule {schedule:?}: {e}"))?;
                let command = self
                    .command
                    .as_deref()
                    .ok_or_else(|| "command is required when state=present".to_string())?;
                if command.contains('\n') {
                    return Err("command must be a single line (no newline)".into());
                }
                if command.trim().is_empty() {
                    return Err("command must not be empty".into());
                }
            }
        }
        Ok(())
    }

    /// Final on-disk path for this job. `<cron_dir>/<name>`. The `cron_dir`
    /// override exists for tests; production uses `/etc/cron.d`.
    pub fn config_path(&self) -> PathBuf {
        let dir = self.cron_dir.clone().unwrap_or_else(|| PathBuf::from("/etc/cron.d"));
        dir.join(&self.name)
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("must not be empty".into());
    }
    // Linux's `run-parts` (which scans `/etc/cron.d`) ignores files whose
    // names contain anything outside `[A-Za-z0-9_-]`. Our restriction is a
    // superset of that with `.` allowed for cosmetic stems.
    let bad = name.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')));
    if bad {
        return Err(format!(
            "must match [a-zA-Z0-9._-]+, got {name:?} (run-parts would skip it)"
        ));
    }
    if name == "." || name == ".." || name.contains('/') {
        return Err("must not be '.', '..', or contain '/'".into());
    }
    Ok(())
}

fn validate_user(user: &str) -> Result<(), String> {
    if user.is_empty() {
        return Err("must not be empty".into());
    }
    let bad = user.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')));
    if bad {
        return Err(format!("must match [a-zA-Z0-9._-]+, got {user:?}"));
    }
    Ok(())
}

fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("must not be empty".into());
    }
    let first = key.chars().next().expect("non-empty");
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err("must start with [A-Za-z_]".into());
    }
    let bad = key.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '_'));
    if bad {
        return Err("must match [A-Za-z_][A-Za-z0-9_]*".into());
    }
    Ok(())
}

/// Validate a 5-field crontab schedule. We don't fully evaluate ranges /
/// step values — just shape: exactly five whitespace-separated tokens, each
/// matching a permissive but safe character set.
fn validate_schedule(schedule: &str) -> Result<(), String> {
    let trimmed = schedule.trim();
    if trimmed.is_empty() {
        return Err("must not be empty".into());
    }
    // Vixie cron supports a few @-shorthands; allow them.
    if let Some(rest) = trimmed.strip_prefix('@') {
        let tag = rest.split_whitespace().next().unwrap_or("");
        let allowed = [
            "yearly", "annually", "monthly", "weekly", "daily", "midnight", "hourly", "reboot",
        ];
        if !allowed.contains(&tag) {
            return Err(format!("@-shorthand must be one of {allowed:?}"));
        }
        if rest.split_whitespace().count() != 1 {
            return Err("@-shorthand must be standalone".into());
        }
        return Ok(());
    }
    let fields: Vec<&str> = trimmed.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!("expected 5 fields, got {}", fields.len()));
    }
    for f in &fields {
        let bad = f.chars().any(|c| {
            !(c.is_ascii_alphanumeric() || matches!(c, '*' | ',' | '-' | '/'))
        });
        if bad {
            return Err(format!("field {f:?} contains disallowed characters"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<CronJobSpec, String> {
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        CronJobSpec::from_value(&v)
    }

    #[test]
    fn parses_minimal_present() {
        let s = parse(
            r#"
name: backup-db
schedule: "0 3 * * *"
command: /usr/local/bin/backup.sh
"#,
        )
        .unwrap();
        assert_eq!(s.name, "backup-db");
        assert_eq!(s.user, "root");
        assert!(s.command.is_some());
    }

    #[test]
    fn accepts_at_shorthand() {
        let s = parse(
            r#"
name: weekly
schedule: "@weekly"
command: /usr/bin/true
"#,
        );
        assert!(s.is_ok(), "{s:?}");
    }

    #[test]
    fn rejects_bad_at_shorthand() {
        assert!(parse(
            r#"
name: x
schedule: "@bogus"
command: /usr/bin/true
"#,
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_field_count() {
        assert!(parse(
            r#"
name: x
schedule: "0 3 * *"
command: /usr/bin/true
"#,
        )
        .is_err());
        assert!(parse(
            r#"
name: x
schedule: "0 3 * * * *"
command: /usr/bin/true
"#,
        )
        .is_err());
    }

    #[test]
    fn rejects_unsafe_name() {
        assert!(parse(
            r#"
name: "../../etc/passwd"
schedule: "0 3 * * *"
command: /usr/bin/true
"#,
        )
        .is_err());
        assert!(parse(
            r#"
name: "with space"
schedule: "0 3 * * *"
command: /usr/bin/true
"#,
        )
        .is_err());
    }

    #[test]
    fn rejects_newline_in_command() {
        let err = parse(
            r#"
name: x
schedule: "0 3 * * *"
command: |
  multi
  line
"#,
        )
        .unwrap_err();
        assert!(err.contains("newline"));
    }

    #[test]
    fn rejects_present_without_schedule_or_command() {
        assert!(parse("name: x\ncommand: /bin/true").is_err());
        assert!(parse("name: x\nschedule: \"0 3 * * *\"").is_err());
    }

    #[test]
    fn absent_forbids_extras() {
        assert!(parse(
            r#"
name: x
state: absent
schedule: "0 3 * * *"
"#,
        )
        .is_err());
    }

    #[test]
    fn rejects_bad_env_key() {
        let err = parse(
            r#"
name: x
schedule: "0 3 * * *"
command: /bin/true
env:
  "1BAD": "v"
"#,
        )
        .unwrap_err();
        assert!(err.contains("env"));
    }

    #[test]
    fn config_path_under_cron_d_by_default() {
        let s = parse(
            r#"
name: backup
schedule: "0 3 * * *"
command: /bin/true
"#,
        )
        .unwrap();
        assert_eq!(s.config_path().to_string_lossy(), "/etc/cron.d/backup");
    }

    #[test]
    fn config_path_respects_override() {
        let s = parse(
            r#"
name: backup
schedule: "0 3 * * *"
command: /bin/true
cron_dir: /tmp/cron
"#,
        )
        .unwrap();
        assert_eq!(s.config_path().to_string_lossy(), "/tmp/cron/backup");
    }
}
