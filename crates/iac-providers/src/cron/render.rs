//! Pure renderer: turn a [`CronJobSpec`] into the on-disk `/etc/cron.d/<name>`
//! content. Deterministic output keeps observe/diff stable across re-applies.

use super::spec::CronJobSpec;
use std::fmt::Write as _;

pub const HEADER: &str = "# Managed by iac. Do not edit by hand.\n";

pub fn render(spec: &CronJobSpec) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    for (k, v) in &spec.env {
        let _ = writeln!(out, "{k}={v}");
    }
    if !spec.env.is_empty() {
        out.push('\n');
    }
    let schedule = spec.schedule.as_deref().unwrap_or("");
    let command = spec.command.as_deref().unwrap_or("");
    let _ = writeln!(out, "{schedule}\t{user}\t{command}", user = spec.user);
    out
}

#[cfg(test)]
mod tests {
    use super::super::spec::{CronJobSpec, CronState};
    use super::*;
    use indexmap::IndexMap;

    fn base() -> CronJobSpec {
        CronJobSpec {
            name: "backup".into(),
            state: CronState::Present,
            schedule: Some("0 3 * * *".into()),
            command: Some("/usr/local/bin/backup.sh".into()),
            user: "root".into(),
            env: IndexMap::new(),
            cron_dir: None,
        }
    }

    #[test]
    fn renders_minimal() {
        let out = render(&base());
        let expected =
            "# Managed by iac. Do not edit by hand.\n0 3 * * *\troot\t/usr/local/bin/backup.sh\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn renders_with_env() {
        let mut s = base();
        s.env
            .insert("PATH".into(), "/usr/local/bin:/usr/bin".into());
        s.env.insert("MAILTO".into(), "ops@example.com".into());
        let out = render(&s);
        assert!(out.contains("PATH=/usr/local/bin:/usr/bin\n"));
        assert!(out.contains("MAILTO=ops@example.com\n"));
        // env block separated from schedule line by a blank line.
        assert!(out.contains("\n\n0 3"));
    }

    #[test]
    fn renders_at_shorthand_in_schedule_field() {
        let mut s = base();
        s.schedule = Some("@daily".into());
        let out = render(&s);
        assert!(out.contains("@daily\troot\t"));
    }
}
