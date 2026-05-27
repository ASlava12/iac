// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Phase 7bz: firewall backend — iptables wrapper with mock for tests.
//!
//! Backend trait abstracts "find an iptables rule by iac comment tag,
//! create one matching this spec, delete one matching this spec." The
//! provider doesn't care whether the underlying implementation is
//! `iptables` or `ip6tables` — the trait handles family selection
//! internally. Operators on systems with only `nftables-translate`
//! (very modern distros) need wrap-around scripts; that's a Phase 5d+
//! follow-up.

use super::spec::{Family, FirewallRuleSpec};
use crate::subprocess::run_with_status;
use iac_core::{Error, Result};
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.2: iptables operations should complete in under a
// second on a healthy host. 30 s is a generous outer cap that
// catches a hung iptables (kernel netfilter lock contention,
// stuck `iptables-save` on a 100k-rule table) without making
// operators wait minutes for a clearly-broken host.
const IPTABLES_TIMEOUT: Duration = Duration::from_secs(30);
use std::sync::Mutex;

/// Snapshot of an existing rule discovered by `query`. Compared
/// field-by-field against the desired `FirewallRuleSpec` for diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRule {
    pub name: String,
    pub table: String,
    pub chain: String,
    pub protocol: String,
    pub port: Option<u16>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub action: String,
    pub family: Family,
}

pub trait FirewallBackend: Send + Sync + std::fmt::Debug {
    /// Look up the rule tagged `iac:<name>`. Returns `None` if no
    /// matching rule exists.
    fn query(&self, name: &str, family: Family) -> Result<Option<ObservedRule>>;

    /// Install the rule. Idempotent: if a rule with the same `name`
    /// tag already exists, replace it (delete + add).
    fn ensure_present(&self, spec: &FirewallRuleSpec) -> Result<()>;

    /// Delete the rule tagged `iac:<name>`. Idempotent: missing rule
    /// is success.
    fn ensure_absent(&self, name: &str, table: &str, chain: &str, family: Family) -> Result<()>;
}

/// Real backend — shells out to `iptables` / `ip6tables`. Each method
/// builds the argv list defensively so user-supplied fields
/// (validated upstream) never end up in a shell.
#[derive(Debug, Default)]
pub struct IptablesBackend;

impl IptablesBackend {
    fn binary(family: Family) -> &'static str {
        match family {
            Family::Ipv4 => "iptables",
            Family::Ipv6 => "ip6tables",
        }
    }

    /// Build the argv slice for "match this spec" — used for both
    /// add (-A) and delete (-D). Does NOT include the leading `-A` /
    /// `-D` flag; the caller prepends.
    fn build_match(spec: &FirewallRuleSpec) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        a.push(spec.chain.clone());
        if spec.protocol != "all" {
            a.push("-p".into());
            a.push(spec.protocol.clone());
        }
        if let Some(p) = spec.port {
            a.push("--dport".into());
            a.push(p.to_string());
        }
        if let Some(s) = &spec.source {
            a.push("-s".into());
            a.push(s.clone());
        }
        if let Some(d) = &spec.destination {
            a.push("-d".into());
            a.push(d.clone());
        }
        a.push("-m".into());
        a.push("comment".into());
        a.push("--comment".into());
        a.push(format!("iac:{}", spec.name));
        a.push("-j".into());
        a.push(spec.action.clone());
        a
    }

    fn run(argv: &[&str]) -> Result<(bool, String, String)> {
        let mut cmd = Command::new(argv[0]);
        cmd.args(&argv[1..])
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Phase 7dh.10: shared `run_with_status` returns the exit
        // success bool + captured streams unchanged; transport-shape
        // failures (timeout/spawn/wait) get truncated-on-leak error
        // messages courtesy of the wrapper.
        run_with_status(cmd, b"", IPTABLES_TIMEOUT, "firewall", argv[0])
    }
}

impl FirewallBackend for IptablesBackend {
    fn query(&self, name: &str, family: Family) -> Result<Option<ObservedRule>> {
        // Use `iptables-save` (or ip6tables-save) — produces parseable
        // output we can grep for the comment tag. Single -t check
        // would be faster but iptables-save is portable across
        // tables, and for our managed-rule count (low double digits
        // typical) the parse cost is negligible.
        let bin_save = match family {
            Family::Ipv4 => "iptables-save",
            Family::Ipv6 => "ip6tables-save",
        };
        let (ok, stdout, stderr) = Self::run(&[bin_save])?;
        if !ok {
            // Most likely cause: no permissions / iptables not
            // installed. Surface clearly so operators know which
            // capability is missing.
            return Err(Error::provider(
                "firewall",
                format!("{bin_save} failed: {}", stderr.trim()),
            ));
        }
        let needle = format!("--comment \"iac:{name}\"");
        let needle2 = format!("--comment iac:{name}");
        for line in stdout.lines() {
            if line.contains(&needle) || line.contains(&needle2) {
                return Ok(Some(parse_save_line(line, name, family)?));
            }
        }
        Ok(None)
    }

    fn ensure_present(&self, spec: &FirewallRuleSpec) -> Result<()> {
        // Idempotent: if a rule with this tag exists, delete it first.
        // iptables's append (-A) doesn't dedupe, so without this an
        // operator running apply twice would end up with duplicates.
        let bin = Self::binary(spec.family);
        // Best-effort delete; ignore "no rule" error.
        let _ = self.ensure_absent(&spec.name, &spec.table, &spec.chain, spec.family);
        let mut argv: Vec<String> = vec!["-t".into(), spec.table.clone(), "-A".into()];
        argv.extend(Self::build_match(spec));
        let argv_strs: Vec<&str> = std::iter::once(bin)
            .chain(argv.iter().map(String::as_str))
            .collect();
        let (ok, _stdout, stderr) = Self::run(&argv_strs)?;
        if !ok {
            return Err(Error::provider(
                "firewall",
                format!("{bin} -A failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }

    fn ensure_absent(&self, name: &str, table: &str, chain: &str, family: Family) -> Result<()> {
        // We don't know the full match expression for an arbitrary
        // pre-existing rule, so iterate through `-S` output to find
        // the line tagged `iac:<name>` in the right table+chain, then
        // delete by index.
        let bin = Self::binary(family);
        let (ok, stdout, _stderr) = Self::run(&[bin, "-t", table, "-S", chain])?;
        if !ok {
            // Chain may not exist (filter table always has built-ins;
            // custom chains don't). Treat as "no rule to delete."
            return Ok(());
        }
        let needle1 = format!("--comment \"iac:{name}\"");
        let needle2 = format!("--comment iac:{name}");
        let mut rule_index = 0u32;
        for line in stdout.lines() {
            if line.starts_with("-A ") {
                rule_index += 1;
                if line.contains(&needle1) || line.contains(&needle2) {
                    let idx_str = rule_index.to_string();
                    let argv = [bin, "-t", table, "-D", chain, &idx_str];
                    let (ok, _stdout, stderr) = Self::run(&argv)?;
                    if !ok {
                        return Err(Error::provider(
                            "firewall",
                            format!("{bin} -D {chain} failed: {}", stderr.trim()),
                        ));
                    }
                    return Ok(());
                }
            }
        }
        // No rule found — idempotent success.
        Ok(())
    }
}

/// Best-effort parse of an `iptables-save` line into an ObservedRule.
/// iptables-save emits canonical form: `-A CHAIN -p tcp --dport 22 -s
/// 10.0.0.0/8 -m comment --comment "iac:<name>" -j ACCEPT`. We don't
/// try to handle every possible match extension; out-of-scope fields
/// are simply not surfaced (the diff path treats them as unmanaged
/// surprises and reports drift).
pub(crate) fn parse_save_line(
    line: &str,
    expected_name: &str,
    family: Family,
) -> Result<ObservedRule> {
    let tokens = tokenize_iptables(line);
    // Walk tokens. We expect `-A <chain>` first, then optional flags.
    let mut chain = String::new();
    let mut protocol = "all".to_string();
    let mut port: Option<u16> = None;
    let mut source: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut action = String::new();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-A" if i + 1 < tokens.len() => {
                chain = tokens[i + 1].clone();
                i += 2;
                continue;
            }
            "-p" if i + 1 < tokens.len() => {
                protocol = tokens[i + 1].clone();
                i += 2;
                continue;
            }
            "--dport" if i + 1 < tokens.len() => {
                port = tokens[i + 1].parse().ok();
                i += 2;
                continue;
            }
            "-s" if i + 1 < tokens.len() => {
                source = Some(strip_default_prefix(&tokens[i + 1]));
                i += 2;
                continue;
            }
            "-d" if i + 1 < tokens.len() => {
                destination = Some(strip_default_prefix(&tokens[i + 1]));
                i += 2;
                continue;
            }
            "-j" if i + 1 < tokens.len() => {
                action = tokens[i + 1].clone();
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(ObservedRule {
        name: expected_name.to_string(),
        // iptables-save lines are scoped to the table by the
        // surrounding `*<table>` directive in the dump; the per-line
        // grep approach above doesn't capture that. Operators can rely
        // on the spec's `table` for matching — observe surfaces it
        // unchanged.
        table: "filter".into(), // placeholder; real table propagated separately
        chain,
        protocol,
        port,
        source,
        destination,
        action,
        family,
    })
}

/// iptables-save emits `10.0.0.0/8` for explicit prefixes but
/// `0.0.0.0/0` (or omits) for "any". Strip the `/32` (IPv4) /`/128`
/// (IPv6) suffix the kernel adds for single-host matches so it
/// round-trips against the operator's input.
fn strip_default_prefix(s: &str) -> String {
    if let Some(rest) = s.strip_suffix("/32")
        && !rest.contains(':')
    {
        return rest.to_string();
    }
    if let Some(rest) = s.strip_suffix("/128")
        && rest.contains(':')
    {
        return rest.to_string();
    }
    s.to_string()
}

/// Minimal whitespace-aware tokenizer that respects double-quoted
/// strings (so `--comment "iac:<name>"` survives as one token). Good
/// enough for iptables-save output, which is mechanical.
fn tokenize_iptables(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    for c in line.chars() {
        if c == '"' {
            in_quote = !in_quote;
            continue;
        }
        if !in_quote && c.is_whitespace() {
            if !buf.is_empty() {
                out.push(std::mem::take(&mut buf));
            }
        } else {
            buf.push(c);
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

/// Mock backend for unit tests. In-memory rule store keyed by
/// (table, name). Operators don't see this; tests build with
/// `MockFirewall::new()` and inspect `rules()` to verify state.
#[derive(Debug, Default)]
pub struct MockFirewall {
    rules: Mutex<Vec<ObservedRule>>,
}

impl MockFirewall {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rules(&self) -> Vec<ObservedRule> {
        self.rules.lock().unwrap().clone()
    }
}

impl FirewallBackend for MockFirewall {
    fn query(&self, name: &str, family: Family) -> Result<Option<ObservedRule>> {
        Ok(self
            .rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.name == name && r.family == family)
            .cloned())
    }

    fn ensure_present(&self, spec: &FirewallRuleSpec) -> Result<()> {
        let mut rules = self.rules.lock().unwrap();
        rules.retain(|r| !(r.name == spec.name && r.family == spec.family));
        rules.push(ObservedRule {
            name: spec.name.clone(),
            table: spec.table.clone(),
            chain: spec.chain.clone(),
            protocol: spec.protocol.clone(),
            port: spec.port,
            source: spec.source.clone(),
            destination: spec.destination.clone(),
            action: spec.action.clone(),
            family: spec.family,
        });
        Ok(())
    }

    fn ensure_absent(&self, name: &str, _table: &str, _chain: &str, family: Family) -> Result<()> {
        let mut rules = self.rules.lock().unwrap();
        rules.retain(|r| !(r.name == name && r.family == family));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::spec::FirewallState;
    use super::*;

    fn spec(name: &str) -> FirewallRuleSpec {
        FirewallRuleSpec {
            name: name.into(),
            table: "filter".into(),
            chain: "INPUT".into(),
            protocol: "tcp".into(),
            port: Some(22),
            source: None,
            destination: None,
            action: "ACCEPT".into(),
            family: Family::Ipv4,
            state: FirewallState::Present,
        }
    }

    #[test]
    fn build_match_emits_iac_comment() {
        let s = spec("test");
        let argv = IptablesBackend::build_match(&s);
        let joined = argv.join(" ");
        assert!(joined.contains("--comment iac:test"), "joined: {joined}");
        assert!(joined.contains("-p tcp"));
        assert!(joined.contains("--dport 22"));
        assert!(joined.contains("-j ACCEPT"));
    }

    #[test]
    fn build_match_omits_proto_when_all() {
        let mut s = spec("test");
        s.protocol = "all".into();
        s.port = None;
        let argv = IptablesBackend::build_match(&s);
        let joined = argv.join(" ");
        assert!(!joined.contains("-p"), "all proto must omit -p: {joined}");
        assert!(!joined.contains("--dport"));
    }

    #[test]
    fn parse_save_line_extracts_fields() {
        let line = r#"-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 22 -m comment --comment "iac:allow-ssh" -j ACCEPT"#;
        let r = parse_save_line(line, "allow-ssh", Family::Ipv4).unwrap();
        assert_eq!(r.chain, "INPUT");
        assert_eq!(r.protocol, "tcp");
        assert_eq!(r.port, Some(22));
        assert_eq!(r.source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(r.action, "ACCEPT");
    }

    #[test]
    fn strip_default_prefix_drops_32_for_ipv4() {
        assert_eq!(strip_default_prefix("192.168.1.1/32"), "192.168.1.1");
    }

    #[test]
    fn strip_default_prefix_keeps_other_prefixes() {
        assert_eq!(strip_default_prefix("10.0.0.0/8"), "10.0.0.0/8");
    }

    #[test]
    fn tokenize_respects_quoted_comment() {
        let toks = tokenize_iptables(r#"-A INPUT --comment "iac:my rule" -j ACCEPT"#);
        // "iac:my rule" comes through as a single token despite the space.
        assert_eq!(toks[2], "--comment");
        assert_eq!(toks[3], "iac:my rule");
    }

    #[test]
    fn mock_ensure_present_replaces_existing() {
        let m = MockFirewall::new();
        let mut s = spec("a");
        m.ensure_present(&s).unwrap();
        s.action = "DROP".into();
        m.ensure_present(&s).unwrap();
        let rules = m.rules();
        assert_eq!(rules.len(), 1, "existing rule replaced not duplicated");
        assert_eq!(rules[0].action, "DROP");
    }

    #[test]
    fn mock_ensure_absent_is_idempotent() {
        let m = MockFirewall::new();
        m.ensure_absent("ghost", "filter", "INPUT", Family::Ipv4)
            .unwrap();
        // No error, no rules.
        assert!(m.rules().is_empty());
    }
}
