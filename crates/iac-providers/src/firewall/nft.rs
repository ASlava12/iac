// Phase 9 follow-up: shells out to the `nft` CLI for distros that
// no longer ship iptables (RHEL 9+, recent Debian/Fedora) — closes
// the trigger-bound backlog row "Operator running on RHEL with
// firewalld | Add nftables-native firewall provider."
//
// Conforms to the same `FirewallBackend` trait the iptables-shelling
// backend uses, so the provider stays agnostic. Selection is via the
// `IAC_FIREWALL_BACKEND` env var read in `FirewallProvider::new()`.
//
// Scope kept narrow on purpose:
//   - Each rule carries the same `iac:<name>` comment marker used by
//     the iptables backend, so observe/diff/rollback discover them
//     identically.
//   - Family `ipv4` → `nft ... ip ...`, `ipv6` → `nft ... ip6 ...`.
//   - Table + chain come from spec.{table,chain}; the operator is
//     expected to have pre-created them (`nft add table ip filter;
//     nft add chain ip filter input ...`). This matches the
//     iptables backend's assumption that built-in chains exist.
//   - Match expressions use nft's high-level syntax (`tcp dport`,
//     `ip saddr`, etc.) since those round-trip with the spec's
//     existing iptables-CLI vocabulary cleanly.
//
// Mock-style integration tests are deferred — exercising real `nft`
// needs root + nftables installed, and the iptables backend's
// MockFirewall already covers the trait-level behaviour the provider
// relies on. Argv-shape tests (no exec) live here so refactors that
// break the command construction surface immediately.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::backend::{FirewallBackend, ObservedRule};
use super::spec::{Family, FirewallRuleSpec};
use crate::subprocess::run_with_status;
use iac_core::{Error, Result};
use std::process::{Command, Stdio};
use std::time::Duration;

const NFT_BIN: &str = "nft";
const NFT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct NftablesBackend;

impl NftablesBackend {
    fn family_str(family: Family) -> &'static str {
        match family {
            Family::Ipv4 => "ip",
            Family::Ipv6 => "ip6",
        }
    }

    /// Lowercase action for nft (`accept` / `drop` / `reject`). The
    /// spec already validates action ∈ {ACCEPT, DROP, REJECT}.
    fn action_str(spec_action: &str) -> String {
        spec_action.to_ascii_lowercase()
    }

    /// Build the match-expression string for a spec. nft's high-level
    /// syntax mirrors iptables clearly enough that operators reading
    /// `nft list ruleset` won't be confused by what landed.
    ///
    /// Returns the body of the rule (everything between `add rule
    /// <fam> <table> <chain>` and the trailing action + comment).
    pub(crate) fn build_match_body(spec: &FirewallRuleSpec) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(s) = &spec.source {
            parts.push(format!("{} saddr {s}", Self::family_str(spec.family)));
        }
        if let Some(d) = &spec.destination {
            parts.push(format!("{} daddr {d}", Self::family_str(spec.family)));
        }
        if spec.protocol == "tcp" || spec.protocol == "udp" {
            if let Some(p) = spec.port {
                parts.push(format!("{} dport {p}", spec.protocol));
            } else {
                // protocol=tcp/udp with no port still narrows to
                // that L4 protocol; spec.validate forbids this
                // shape (port is required for tcp/udp) so we
                // shouldn't actually reach here, but be defensive.
                parts.push(format!("ip protocol {}", spec.protocol));
            }
        } else if spec.protocol == "icmp" {
            // icmp on ipv4 is `icmp type echo-request`-style, but
            // the spec doesn't model type yet — passthrough by
            // protocol only, matching iptables's `-p icmp` shape.
            parts.push("ip protocol icmp".into());
        }
        // protocol == "all" → no L3/L4 narrowing
        parts.join(" ")
    }

    /// Build the full argv for `nft add rule ...`. Separated from
    /// the exec path so unit tests can assert the surface without
    /// requiring root or nftables on PATH.
    pub(crate) fn build_add_rule_argv(spec: &FirewallRuleSpec) -> Vec<String> {
        let family = Self::family_str(spec.family);
        let body = Self::build_match_body(spec);
        let action = Self::action_str(&spec.action);
        let mut rule = format!("add rule {family} {} {} ", spec.table, spec.chain);
        if !body.is_empty() {
            rule.push_str(&body);
            rule.push(' ');
        }
        rule.push_str(&format!("{action} comment \"iac:{}\"", spec.name));
        vec![NFT_BIN.into(), "-e".into(), rule]
    }

    /// Build argv for `nft -a list table <fam> <table>`. Used to find
    /// the handle of an existing iac-tagged rule so we can delete it
    /// without re-parsing the whole match expression.
    pub(crate) fn build_list_table_argv(family: Family, table: &str) -> Vec<String> {
        vec![
            NFT_BIN.into(),
            "-a".into(),
            "list".into(),
            "table".into(),
            Self::family_str(family).into(),
            table.into(),
        ]
    }

    /// Build argv for `nft delete rule <fam> <table> <chain> handle <N>`.
    pub(crate) fn build_delete_handle_argv(
        family: Family,
        table: &str,
        chain: &str,
        handle: u64,
    ) -> Vec<String> {
        vec![
            NFT_BIN.into(),
            "delete".into(),
            "rule".into(),
            Self::family_str(family).into(),
            table.into(),
            chain.into(),
            "handle".into(),
            handle.to_string(),
        ]
    }

    fn run(argv: &[&str]) -> Result<(bool, String, String)> {
        let mut cmd = Command::new(argv[0]);
        cmd.args(&argv[1..])
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_with_status(cmd, b"", NFT_TIMEOUT, "firewall", argv[0])
    }
}

impl FirewallBackend for NftablesBackend {
    fn query(&self, name: &str, family: Family) -> Result<Option<ObservedRule>> {
        // We list every iac-managed rule via the catch-all
        // `nft -a list ruleset` and then filter for the comment
        // marker. Listing per-table would be slightly cheaper but
        // requires knowing which tables we manage; the operator
        // pattern keeps state in many tables.
        let (ok, stdout, stderr) = Self::run(&[NFT_BIN, "-a", "list", "ruleset"])?;
        if !ok {
            return Err(Error::provider(
                "firewall",
                format!("nft list failed: {}", stderr.trim()),
            ));
        }
        let needle = format!("comment \"iac:{name}\"");
        for line in stdout.lines() {
            if line.contains(&needle) {
                return Ok(Some(parse_nft_rule_line(line, name, family)));
            }
        }
        Ok(None)
    }

    fn ensure_present(&self, spec: &FirewallRuleSpec) -> Result<()> {
        // Idempotent: delete any pre-existing iac:<name> first.
        // Errors deleting a non-existent rule are swallowed (matches
        // iptables backend semantics).
        let _ = self.ensure_absent(&spec.name, &spec.table, &spec.chain, spec.family);
        let argv = Self::build_add_rule_argv(spec);
        let argv_strs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let (ok, _stdout, stderr) = Self::run(&argv_strs)?;
        if !ok {
            return Err(Error::provider(
                "firewall",
                format!("nft add rule failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }

    fn ensure_absent(
        &self,
        name: &str,
        table: &str,
        chain: &str,
        family: Family,
    ) -> Result<()> {
        // Find the handle by scanning `nft -a list table <fam> <table>`.
        // We could parse the structured output of `nft -j` (JSON), but
        // text-grep keeps the dep footprint small and the output is
        // mechanical enough that one comment-string match is
        // unambiguous.
        let list_argv = Self::build_list_table_argv(family, table);
        let list_argv_strs: Vec<&str> = list_argv.iter().map(String::as_str).collect();
        let (ok, stdout, _stderr) = Self::run(&list_argv_strs)?;
        if !ok {
            // Table may not exist yet — operator hasn't run
            // `nft add table` yet. Treat as "no rule to delete."
            // (We can't disambiguate "table missing" from other
            // errors without more parsing, but the most common
            // cause in our flow is the missing table.)
            return Ok(());
        }
        let needle = format!("comment \"iac:{name}\"");
        for line in stdout.lines() {
            if !line.contains(&needle) {
                continue;
            }
            let Some(handle) = parse_handle_annotation(line) else { continue; };
            let del_argv = Self::build_delete_handle_argv(family, table, chain, handle);
            let del_argv_strs: Vec<&str> = del_argv.iter().map(String::as_str).collect();
            let (ok, _stdout, stderr) = Self::run(&del_argv_strs)?;
            if !ok {
                return Err(Error::provider(
                    "firewall",
                    format!("nft delete rule failed: {}", stderr.trim()),
                ));
            }
            return Ok(());
        }
        // No rule found — idempotent success.
        Ok(())
    }
}

/// Parse a single rule line from `nft -a list ...` output to an
/// ObservedRule. nft's output is whitespace-delimited tokens; we
/// recognise the few we care about (saddr/daddr/dport/protocol/action).
/// Best-effort — unknown tokens propagate as drift if the operator's
/// nft version emits different shapes.
fn parse_nft_rule_line(line: &str, expected_name: &str, family: Family) -> ObservedRule {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut protocol = "all".to_string();
    let mut port: Option<u16> = None;
    let mut source: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut action = String::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if (t == "ip" || t == "ip6") && i + 2 < tokens.len() {
            match tokens[i + 1] {
                "saddr" => {
                    source = Some(tokens[i + 2].to_string());
                    i += 3;
                    continue;
                }
                "daddr" => {
                    destination = Some(tokens[i + 2].to_string());
                    i += 3;
                    continue;
                }
                "protocol" => {
                    protocol = tokens[i + 2].to_string();
                    i += 3;
                    continue;
                }
                _ => {}
            }
        }
        if (t == "tcp" || t == "udp") && i + 2 < tokens.len() && tokens[i + 1] == "dport" {
            protocol = t.to_string();
            port = tokens[i + 2].parse().ok();
            i += 3;
            continue;
        }
        if t == "accept" || t == "drop" || t == "reject" {
            action = t.to_ascii_uppercase();
            i += 1;
            continue;
        }
        i += 1;
    }
    ObservedRule {
        name: expected_name.to_string(),
        table: String::new(),
        chain: String::new(),
        protocol,
        port,
        source,
        destination,
        action,
        family,
    }
}

/// Extract the `# handle <N>` suffix from a `nft -a` output line.
/// Returns None if no handle is present (e.g. an operator
/// configured nft without -a).
fn parse_handle_annotation(line: &str) -> Option<u64> {
    let idx = line.rfind("# handle ")?;
    let rest = &line[idx + "# handle ".len()..];
    let token = rest.split_whitespace().next()?;
    token.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::spec::FirewallState;

    fn sample_spec() -> FirewallRuleSpec {
        FirewallRuleSpec {
            name: "allow-ssh".into(),
            table: "filter".into(),
            chain: "input".into(),
            protocol: "tcp".into(),
            port: Some(22),
            source: Some("10.0.0.0/8".into()),
            destination: None,
            action: "ACCEPT".into(),
            family: Family::Ipv4,
            state: FirewallState::default(),
        }
    }

    #[test]
    fn add_rule_argv_is_well_formed() {
        let argv = NftablesBackend::build_add_rule_argv(&sample_spec());
        assert_eq!(argv[0], "nft");
        assert_eq!(argv[1], "-e");
        let rule = &argv[2];
        assert!(rule.starts_with("add rule ip filter input "), "got {rule}");
        assert!(rule.contains("ip saddr 10.0.0.0/8"));
        assert!(rule.contains("tcp dport 22"));
        assert!(rule.contains("accept"));
        assert!(rule.contains(r#"comment "iac:allow-ssh""#));
    }

    #[test]
    fn list_table_argv_uses_family_prefix() {
        let v4 = NftablesBackend::build_list_table_argv(Family::Ipv4, "filter");
        assert_eq!(v4, vec!["nft", "-a", "list", "table", "ip", "filter"]);
        let v6 = NftablesBackend::build_list_table_argv(Family::Ipv6, "filter");
        assert_eq!(v6, vec!["nft", "-a", "list", "table", "ip6", "filter"]);
    }

    #[test]
    fn delete_handle_argv_shape() {
        let argv = NftablesBackend::build_delete_handle_argv(Family::Ipv4, "filter", "input", 42);
        assert_eq!(
            argv,
            vec!["nft", "delete", "rule", "ip", "filter", "input", "handle", "42"]
        );
    }

    #[test]
    fn parse_handle_annotation_extracts_id() {
        let line = "\t\tip saddr 10.0.0.0/8 tcp dport 22 counter accept comment \"iac:allow-ssh\" # handle 7";
        assert_eq!(parse_handle_annotation(line), Some(7));

        // No handle (operator ran nft without -a) → None
        let line2 = "\t\tip saddr 10.0.0.0/8 tcp dport 22 counter accept comment \"iac:allow-ssh\"";
        assert_eq!(parse_handle_annotation(line2), None);
    }

    #[test]
    fn parse_nft_rule_line_extracts_fields() {
        let line = "\t\tip saddr 10.0.0.0/8 tcp dport 22 counter accept comment \"iac:allow-ssh\" # handle 7";
        let r = parse_nft_rule_line(line, "allow-ssh", Family::Ipv4);
        assert_eq!(r.name, "allow-ssh");
        assert_eq!(r.protocol, "tcp");
        assert_eq!(r.port, Some(22));
        assert_eq!(r.source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(r.action, "ACCEPT");
        assert_eq!(r.family, Family::Ipv4);
    }

    #[test]
    fn build_match_body_omits_l4_when_protocol_all() {
        let mut spec = sample_spec();
        spec.protocol = "all".into();
        spec.port = None;
        let body = NftablesBackend::build_match_body(&spec);
        assert!(body.contains("ip saddr 10.0.0.0/8"));
        assert!(!body.contains("tcp"));
        assert!(!body.contains("dport"));
    }
}
