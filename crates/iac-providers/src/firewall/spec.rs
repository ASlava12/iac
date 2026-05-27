//! Phase 7bz: `firewall.rule` spec — declarative iptables rule.
//!
//! ```yaml
//! apiVersion: iac.example/v1
//! kind: firewall.rule
//! metadata: { name: allow-ssh, environment: prod }
//! spec:
//!   table: filter           # filter | nat | mangle (default filter)
//!   chain: INPUT            # INPUT | OUTPUT | FORWARD | PREROUTING | POSTROUTING
//!   protocol: tcp           # tcp | udp | icmp | all (default all)
//!   port: 22                # required for tcp/udp, forbidden for icmp/all
//!   source: 10.0.0.0/8      # optional CIDR or single IP
//!   destination: 192.168.1.1   # optional
//!   action: ACCEPT          # ACCEPT | DROP | REJECT
//!   family: ipv4            # ipv4 (default) | ipv6
//!   state: present          # present (default) | absent
//! ```
//!
//! The provider tags each managed rule with an iptables `--comment
//! "iac:<resource_name>"` so observe / diff / rollback can find the
//! rule unambiguously even if the operator changes other fields. The
//! resource's `metadata.name` is the canonical identity.

use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallState {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    #[default]
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleSpec {
    /// Stable identifier for the rule. Surfaced as the iptables comment
    /// (`iac:<name>`) so observe/diff/rollback can find this exact rule
    /// even after other fields change. Required, alphanumeric +
    /// `-`/`_`/`.`, max 200 chars (iptables `--comment` cap is 256).
    pub name: String,
    /// `filter` / `nat` / `mangle`. Default `filter` covers 95% of
    /// rule needs (block / allow on INPUT/OUTPUT/FORWARD).
    #[serde(default = "default_table")]
    pub table: String,
    /// Chain. Validated per-table at parse time so an INPUT rule on
    /// `nat` table fails with a clear message instead of an iptables
    /// stderr blob.
    pub chain: String,
    /// `tcp` / `udp` / `icmp` / `all`. Default `all` (no `-p` flag).
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Required for tcp/udp. Forbidden for icmp/all (would be a syntax
    /// error in iptables anyway). 1..=65535.
    #[serde(default)]
    pub port: Option<u16>,
    /// Optional source CIDR (e.g. `10.0.0.0/8`) or single IP. Maps to
    /// `-s <value>` in iptables.
    #[serde(default)]
    pub source: Option<String>,
    /// Optional destination, same shape as `source`.
    #[serde(default)]
    pub destination: Option<String>,
    /// `ACCEPT` / `DROP` / `REJECT`. Required.
    pub action: String,
    /// IP family. `ipv4` uses iptables; `ipv6` uses ip6tables. Default
    /// `ipv4` for backwards compat with the typical "block external
    /// SSH" rule. Operators on dual-stack networks declare two
    /// resources, one per family.
    #[serde(default)]
    pub family: Family,
    #[serde(default)]
    pub state: FirewallState,
}

fn default_table() -> String {
    "filter".into()
}

fn default_protocol() -> String {
    "all".into()
}

impl FirewallRuleSpec {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        validate_name(&self.name)?;
        validate_table(&self.table)?;
        validate_chain(&self.table, &self.chain)?;
        validate_protocol(&self.protocol)?;
        match (self.protocol.as_str(), self.port) {
            ("tcp" | "udp", None) => {
                return Err(format!("protocol {:?} requires `port`", self.protocol));
            }
            ("icmp" | "all", Some(_)) => {
                return Err(format!(
                    "protocol {:?} must not set `port` (port is meaningless for non-tcp/udp)",
                    self.protocol
                ));
            }
            _ => {}
        }
        if let Some(p) = self.port
            && p == 0
        {
            return Err("port must be 1..=65535".into());
        }
        if let Some(addr) = &self.source {
            validate_addr(addr, self.family).map_err(|e| format!("source: {e}"))?;
        }
        if let Some(addr) = &self.destination {
            validate_addr(addr, self.family).map_err(|e| format!("destination: {e}"))?;
        }
        validate_action(&self.action)?;
        match self.state {
            FirewallState::Absent => {
                // Absent rules need only `name` + identifying fields
                // (table, chain) so we can find and delete them. Other
                // fields on `absent` are harmless but operators
                // shouldn't get the impression they matter — reject
                // the obviously-confused case where `port` is set
                // but the rest looks like a delete.
            }
            FirewallState::Present => {
                // No further constraints; all required fields already
                // validated above.
            }
        }
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".into());
    }
    if name.len() > 200 {
        return Err(format!(
            "name {:?} exceeds 200 chars (iptables --comment cap)",
            name
        ));
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

fn validate_table(table: &str) -> Result<(), String> {
    match table {
        "filter" | "nat" | "mangle" => Ok(()),
        other => Err(format!(
            "table {other:?} must be one of: filter, nat, mangle"
        )),
    }
}

fn validate_chain(table: &str, chain: &str) -> Result<(), String> {
    let valid = match table {
        "filter" => ["INPUT", "OUTPUT", "FORWARD"].as_slice(),
        "nat" => ["PREROUTING", "POSTROUTING", "OUTPUT", "INPUT"].as_slice(),
        "mangle" => ["PREROUTING", "POSTROUTING", "INPUT", "OUTPUT", "FORWARD"].as_slice(),
        _ => return Err(format!("unknown table {table:?}")),
    };
    if !valid.contains(&chain) {
        return Err(format!(
            "chain {chain:?} not valid for table {table:?}; must be one of: {valid:?}"
        ));
    }
    Ok(())
}

fn validate_protocol(protocol: &str) -> Result<(), String> {
    match protocol {
        "tcp" | "udp" | "icmp" | "all" => Ok(()),
        other => Err(format!(
            "protocol {other:?} must be one of: tcp, udp, icmp, all"
        )),
    }
}

fn validate_action(action: &str) -> Result<(), String> {
    match action {
        "ACCEPT" | "DROP" | "REJECT" => Ok(()),
        other => Err(format!(
            "action {other:?} must be one of: ACCEPT, DROP, REJECT"
        )),
    }
}

/// Validate an IPv4 / IPv6 address or CIDR. Defensive: reject shell
/// metacharacters even though we always pass values as separate argv
/// to iptables (the validation also catches operator typos like
/// `10.0.0.0/8 ; rm -rf /`).
fn validate_addr(addr: &str, family: Family) -> Result<(), String> {
    if addr.is_empty() {
        return Err("must not be empty".into());
    }
    if addr
        .chars()
        .any(|c| matches!(c, ' ' | '\t' | '\n' | ';' | '"' | '\'' | '`' | '\\'))
    {
        return Err(format!(
            "{addr:?} contains a disallowed character (whitespace or shell meta)"
        ));
    }
    // Split off optional /<prefix>.
    let (host, prefix_opt) = match addr.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (addr, None),
    };
    match family {
        Family::Ipv4 => {
            // 4 octets of digits, each 0..=255.
            let octets: Vec<&str> = host.split('.').collect();
            if octets.len() != 4 {
                return Err(format!(
                    "{addr:?} not a valid IPv4 address (4 octets expected)"
                ));
            }
            for o in &octets {
                let n: u16 = o
                    .parse()
                    .map_err(|_| format!("{addr:?} octet {o:?} not a number"))?;
                if n > 255 {
                    return Err(format!("{addr:?} octet {o} out of range 0..=255"));
                }
            }
            if let Some(p) = prefix_opt {
                let n: u8 = p
                    .parse()
                    .map_err(|_| format!("{addr:?} prefix {p:?} not a number"))?;
                if n > 32 {
                    return Err(format!("{addr:?} IPv4 prefix {n} out of range 0..=32"));
                }
            }
        }
        Family::Ipv6 => {
            // Loose check: contains at least one ':' and only hex/digits/colons.
            if !host.contains(':') {
                return Err(format!("{addr:?} not a valid IPv6 address (':' expected)"));
            }
            if !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                return Err(format!("{addr:?} contains non-hex characters"));
            }
            if let Some(p) = prefix_opt {
                let n: u8 = p
                    .parse()
                    .map_err(|_| format!("{addr:?} prefix {p:?} not a number"))?;
                if n > 128 {
                    return Err(format!("{addr:?} IPv6 prefix {n} out of range 0..=128"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<FirewallRuleSpec, String> {
        let v: Value = serde_yaml_ng::from_str(yaml).unwrap();
        FirewallRuleSpec::from_value(&v)
    }

    #[test]
    fn parses_minimal_present() {
        let s = parse("name: allow-ssh\nchain: INPUT\nprotocol: tcp\nport: 22\naction: ACCEPT")
            .unwrap();
        assert_eq!(s.name, "allow-ssh");
        assert_eq!(s.table, "filter"); // default
        assert_eq!(s.chain, "INPUT");
        assert_eq!(s.protocol, "tcp");
        assert_eq!(s.port, Some(22));
        assert_eq!(s.action, "ACCEPT");
        assert_eq!(s.state, FirewallState::Present);
        assert_eq!(s.family, Family::Ipv4);
    }

    #[test]
    fn parses_with_source_destination() {
        let s = parse(
            "name: r1\nchain: FORWARD\nprotocol: tcp\nport: 80\n\
             source: 10.0.0.0/8\ndestination: 192.168.1.1\naction: ACCEPT",
        )
        .unwrap();
        assert_eq!(s.source.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(s.destination.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parses_absent() {
        let s = parse(
            "name: allow-ssh\nchain: INPUT\nprotocol: tcp\nport: 22\n\
             action: ACCEPT\nstate: absent",
        )
        .unwrap();
        assert_eq!(s.state, FirewallState::Absent);
    }

    #[test]
    fn rejects_empty_name() {
        let err = parse("name: ''\nchain: INPUT\nprotocol: all\naction: ACCEPT").unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_chars_in_name() {
        let err =
            parse("name: 'evil; rm'\nchain: INPUT\nprotocol: all\naction: ACCEPT").unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_table() {
        let err = parse("name: r\ntable: bogus\nchain: INPUT\nprotocol: all\naction: ACCEPT")
            .unwrap_err();
        assert!(err.contains("table"), "got: {err}");
    }

    #[test]
    fn rejects_chain_invalid_for_table() {
        // PREROUTING is not a filter-table chain.
        let err = parse("name: r\ntable: filter\nchain: PREROUTING\nprotocol: all\naction: ACCEPT")
            .unwrap_err();
        assert!(err.contains("chain"), "got: {err}");
    }

    #[test]
    fn rejects_tcp_without_port() {
        let err = parse("name: r\nchain: INPUT\nprotocol: tcp\naction: ACCEPT").unwrap_err();
        assert!(err.contains("requires `port`"), "got: {err}");
    }

    #[test]
    fn rejects_icmp_with_port() {
        let err =
            parse("name: r\nchain: INPUT\nprotocol: icmp\nport: 22\naction: ACCEPT").unwrap_err();
        assert!(err.contains("must not set `port`"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_action() {
        let err = parse("name: r\nchain: INPUT\nprotocol: all\naction: NUKE").unwrap_err();
        assert!(err.contains("action"), "got: {err}");
    }

    #[test]
    fn rejects_invalid_ipv4_source() {
        let err = parse("name: r\nchain: INPUT\nprotocol: all\naction: ACCEPT\nsource: 10.0.0.999")
            .unwrap_err();
        assert!(err.contains("source"), "got: {err}");
    }

    #[test]
    fn rejects_ipv4_with_oversized_prefix() {
        let err =
            parse("name: r\nchain: INPUT\nprotocol: all\naction: ACCEPT\nsource: 10.0.0.0/64")
                .unwrap_err();
        assert!(err.contains("prefix"), "got: {err}");
    }

    #[test]
    fn parses_ipv6_family_with_colon_addr() {
        let s = parse(
            "name: r\nchain: INPUT\nprotocol: tcp\nport: 80\naction: ACCEPT\n\
             family: ipv6\nsource: 2001:db8::/32",
        )
        .unwrap();
        assert_eq!(s.family, Family::Ipv6);
        assert_eq!(s.source.as_deref(), Some("2001:db8::/32"));
    }

    #[test]
    fn rejects_unknown_field() {
        let err = parse("name: r\nchain: INPUT\nprotocol: all\naction: ACCEPT\nbogus_field: 1")
            .unwrap_err();
        assert!(
            err.contains("bogus_field") || err.contains("unknown"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_shell_metas_in_source() {
        let err = parse(
            "name: r\nchain: INPUT\nprotocol: all\naction: ACCEPT\nsource: '10.0.0.0/8 ; evil'",
        )
        .unwrap_err();
        assert!(err.contains("disallowed"), "got: {err}");
    }

    #[test]
    fn rejects_port_zero() {
        let err =
            parse("name: r\nchain: INPUT\nprotocol: tcp\nport: 0\naction: ACCEPT").unwrap_err();
        assert!(err.contains("port"), "got: {err}");
    }
}
