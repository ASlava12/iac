//! Phase 7cx: spec for `dns.record`.
//!
//! Pluggable provider shape. Operators choose a backend (currently only
//! `cloudflare`); each backend has its own credentials sub-block.
//!
//! ```yaml
//! kind: dns.record
//! spec:
//!   zone: example.com
//!   name: app                         # relative to zone, or FQDN
//!   type: A                           # A | AAAA | CNAME | TXT | MX
//!   value: "1.2.3.4"
//!   ttl: 300                          # default 300
//!   state: present                    # default present
//!   provider: cloudflare              # required
//!   cloudflare:
//!     api_token: "${secret://env/CF_API_TOKEN}"
//! ```
//!
//! Identity for upserts is `(zone, name, type)` — a record's value
//! changes over time, but the trio identifies which record to mutate.
//! Multiple records with the same name+type (round-robin A records,
//! multiple TXT entries) are out of scope for Phase 7cx; the
//! single-record model covers 95% of operator needs.

use serde::Deserialize;
use serde_yaml_ng::Value as YamlValue;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsRecordSpec {
    pub zone: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub state: RecordState,
    pub provider: DnsBackendKind,
    /// Per-backend credentials block. Currently only `cloudflare` is
    /// recognised. Required when `provider == cloudflare`.
    #[serde(default)]
    pub cloudflare: Option<CloudflareCreds>,
}

fn default_ttl() -> u32 {
    300
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
}

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::TXT => "TXT",
            Self::MX => "MX",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsBackendKind {
    Cloudflare,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudflareCreds {
    pub api_token: String,
}

impl DnsRecordSpec {
    pub fn from_value(v: &YamlValue) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone())
            .map_err(|e| format!("parse: {e}"))?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        if self.zone.is_empty() {
            return Err("zone must not be empty".into());
        }
        if self.name.is_empty() {
            return Err("name must not be empty".into());
        }
        if self.ttl < 30 {
            return Err(format!(
                "ttl {} too low; most providers reject values below 30",
                self.ttl
            ));
        }
        if self.state == RecordState::Present && self.value.as_deref().unwrap_or("").is_empty() {
            return Err("value must be set when state=present".into());
        }
        match self.provider {
            DnsBackendKind::Cloudflare => {
                let cf = self.cloudflare.as_ref().ok_or_else(|| {
                    "cloudflare provider requires `cloudflare:` block".to_string()
                })?;
                if cf.api_token.is_empty() {
                    return Err(
                        "cloudflare.api_token must not be empty (use ${secret://env/CF_API_TOKEN})".into(),
                    );
                }
            }
        }
        // Type-specific value sanity checks. Cheap and catches the
        // most common misconfiguration: pointing an A record at a
        // hostname instead of an IP.
        if self.state == RecordState::Present
            && let Some(v) = self.value.as_deref()
        {
            match self.record_type {
                RecordType::A => {
                    if v.parse::<std::net::Ipv4Addr>().is_err() {
                        return Err(format!(
                            "A record value {v:?} is not a valid IPv4 address"
                        ));
                    }
                }
                RecordType::AAAA => {
                    if v.parse::<std::net::Ipv6Addr>().is_err() {
                        return Err(format!(
                            "AAAA record value {v:?} is not a valid IPv6 address"
                        ));
                    }
                }
                RecordType::CNAME => {
                    if v.contains(' ') || !v.contains('.') {
                        return Err(format!(
                            "CNAME record value {v:?} should be a hostname"
                        ));
                    }
                }
                RecordType::TXT | RecordType::MX => {
                    // Less strict; operators write structured strings.
                }
            }
        }
        Ok(())
    }

    /// Compute the FQDN form of this record's name (`name + zone`),
    /// stripping a trailing dot and avoiding double-zoning when the
    /// operator already wrote `app.example.com`. Used by backends as
    /// the actual record identifier sent over the wire.
    pub fn fqdn(&self) -> String {
        let zone = self.zone.trim_end_matches('.');
        let name = self.name.trim_end_matches('.');
        if name == zone {
            return zone.to_string();
        }
        if name.ends_with(&format!(".{zone}")) {
            return name.to_string();
        }
        if name == "@" {
            return zone.to_string();
        }
        format!("{name}.{zone}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> YamlValue {
        serde_yaml_ng::from_str(s).unwrap()
    }

    #[test]
    fn parses_minimal_a_record() {
        let v = yaml(
            r#"
zone: example.com
name: app
type: A
value: "1.2.3.4"
provider: cloudflare
cloudflare:
  api_token: secret-token
"#,
        );
        let s = DnsRecordSpec::from_value(&v).unwrap();
        assert_eq!(s.zone, "example.com");
        assert_eq!(s.name, "app");
        assert_eq!(s.record_type, RecordType::A);
        assert_eq!(s.ttl, 300);
        assert_eq!(s.state, RecordState::Present);
    }

    #[test]
    fn rejects_invalid_ipv4_for_a() {
        let v = yaml(
            r#"
zone: example.com
name: app
type: A
value: "not-an-ip"
provider: cloudflare
cloudflare:
  api_token: t
"#,
        );
        let err = DnsRecordSpec::from_value(&v).unwrap_err();
        assert!(err.contains("IPv4"), "{err}");
    }

    #[test]
    fn rejects_invalid_ipv6_for_aaaa() {
        let v = yaml(
            r#"
zone: example.com
name: app
type: AAAA
value: "1.2.3.4"
provider: cloudflare
cloudflare:
  api_token: t
"#,
        );
        let err = DnsRecordSpec::from_value(&v).unwrap_err();
        assert!(err.contains("IPv6"));
    }

    #[test]
    fn cname_requires_hostname_shape() {
        let v = yaml(
            r#"
zone: example.com
name: www
type: CNAME
value: "no-dot"
provider: cloudflare
cloudflare:
  api_token: t
"#,
        );
        let err = DnsRecordSpec::from_value(&v).unwrap_err();
        assert!(err.contains("hostname"));
    }

    #[test]
    fn requires_cloudflare_creds() {
        let v = yaml(
            r#"
zone: example.com
name: app
type: A
value: "1.2.3.4"
provider: cloudflare
"#,
        );
        let err = DnsRecordSpec::from_value(&v).unwrap_err();
        assert!(err.contains("cloudflare:"));
    }

    #[test]
    fn allows_absent_without_value() {
        let v = yaml(
            r#"
zone: example.com
name: app
type: A
state: absent
provider: cloudflare
cloudflare:
  api_token: t
"#,
        );
        let s = DnsRecordSpec::from_value(&v).unwrap();
        assert_eq!(s.state, RecordState::Absent);
    }

    #[test]
    fn rejects_too_low_ttl() {
        let v = yaml(
            r#"
zone: example.com
name: app
type: A
value: "1.2.3.4"
ttl: 10
provider: cloudflare
cloudflare:
  api_token: t
"#,
        );
        let err = DnsRecordSpec::from_value(&v).unwrap_err();
        assert!(err.contains("ttl"));
    }

    #[test]
    fn fqdn_handles_relative_name() {
        let v = yaml("zone: example.com\nname: app\ntype: A\nvalue: '1.2.3.4'\nprovider: cloudflare\ncloudflare: {api_token: t}\n");
        let s = DnsRecordSpec::from_value(&v).unwrap();
        assert_eq!(s.fqdn(), "app.example.com");
    }

    #[test]
    fn fqdn_handles_at_apex() {
        let v = yaml("zone: example.com\nname: '@'\ntype: A\nvalue: '1.2.3.4'\nprovider: cloudflare\ncloudflare: {api_token: t}\n");
        let s = DnsRecordSpec::from_value(&v).unwrap();
        assert_eq!(s.fqdn(), "example.com");
    }

    #[test]
    fn fqdn_doesnt_double_zone() {
        let v = yaml("zone: example.com\nname: app.example.com\ntype: A\nvalue: '1.2.3.4'\nprovider: cloudflare\ncloudflare: {api_token: t}\n");
        let s = DnsRecordSpec::from_value(&v).unwrap();
        assert_eq!(s.fqdn(), "app.example.com");
    }
}
