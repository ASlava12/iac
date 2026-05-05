//! Phase 7cy: spec for `acme.certificate`.
//!
//! ```yaml
//! kind: acme.certificate
//! spec:
//!   domains: ["example.com", "www.example.com"]
//!   email: ops@example.com
//!   cert_dir: /etc/iac/certs/example.com
//!   state: present | absent          # default: present
//!   renew_window_days: 30            # renew when expiring within N days
//!   staging: false                   # use Let's Encrypt staging endpoint
//!   challenge: http-01               # http-01 | dns-01-cloudflare
//!   webroot: /var/www/html           # required for http-01
//!   cloudflare_api_token: "${secret://env/CF_API_TOKEN}"  # required for dns-01-cloudflare
//! ```
//!
//! Identity: the first domain (CN). Multiple SANs are supported via
//! the `domains` list.
//!
//! No support for self-managed CSRs / EAB (External Account Binding) /
//! arbitrary ACME clients beyond what the backend trait knows about.
//! Operators with exotic setups bring their own provider.

use serde::Deserialize;
use serde_yaml_ng::Value as YamlValue;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeCertSpec {
    /// Domains for the certificate. First entry is the CN; rest are SANs.
    pub domains: Vec<String>,
    pub email: String,
    pub cert_dir: PathBuf,
    #[serde(default)]
    pub state: AcmeState,
    #[serde(default = "default_renew_window")]
    pub renew_window_days: u32,
    #[serde(default)]
    pub staging: bool,
    pub challenge: ChallengeKind,
    #[serde(default)]
    pub webroot: Option<PathBuf>,
    #[serde(default)]
    pub cloudflare_api_token: Option<String>,
    /// Phase 7de: optional ACME directory URL to override the
    /// hardcoded Let's Encrypt prod / staging endpoints. Operators
    /// point this at a local Pebble or step-ca for integration
    /// tests, or at a self-hosted internal CA. Mutually exclusive
    /// with `staging = true` — set one or the other.
    ///
    /// Validation: must start with `https://` or `http://localhost`
    /// (loopback-only HTTP for dev fixtures). Public-network HTTP
    /// is rejected — credential-bearing ACME flows over plain HTTP
    /// is the kind of footgun we don't want operators to step on
    /// by accident.
    #[serde(default)]
    pub server_url: Option<String>,
}

fn default_renew_window() -> u32 {
    30
}

fn is_loopback_host(host: &str) -> bool {
    // String-only check — we don't want to do DNS at config-load
    // time. The set of loopback shapes is bounded: localhost,
    // 127.0.0.0/8, ::1.
    host == "localhost"
        || host == "::1"
        || host == "[::1]"
        || host.starts_with("127.")
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AcmeState {
    #[default]
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum ChallengeKind {
    /// HTTP-01: ACME server fetches a token from
    /// `http://<domain>/.well-known/acme-challenge/<token>`. Requires a
    /// pre-existing HTTP listener on port 80 for each domain. The
    /// `webroot` directory is where we drop the challenge file.
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 via Cloudflare: ACME server checks a TXT record at
    /// `_acme-challenge.<domain>`. Requires a Cloudflare API token
    /// scoped to the matching zone with `Zone.DNS:Edit`. Works for
    /// wildcard certs (HTTP-01 doesn't).
    #[serde(rename = "dns-01-cloudflare")]
    Dns01Cloudflare,
}

impl AcmeCertSpec {
    pub fn from_value(v: &YamlValue) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone())
            .map_err(|e| format!("parse: {e}"))?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        if self.domains.is_empty() {
            return Err("domains must not be empty".into());
        }
        for d in &self.domains {
            if d.is_empty() {
                return Err("domain entries must not be empty".into());
            }
            if d.contains(' ') {
                return Err(format!("domain {d:?} contains whitespace"));
            }
        }
        if self.email.is_empty() || !self.email.contains('@') {
            return Err(format!("email {:?} is not a valid address", self.email));
        }
        if !self.cert_dir.is_absolute() {
            return Err(format!(
                "cert_dir {} must be absolute",
                self.cert_dir.display()
            ));
        }
        if self.renew_window_days == 0 || self.renew_window_days > 89 {
            return Err(format!(
                "renew_window_days {} out of sane range (1..=89; Let's Encrypt certs last 90d)",
                self.renew_window_days
            ));
        }
        match self.challenge {
            ChallengeKind::Http01 => {
                let webroot = self.webroot.as_ref().ok_or_else(|| {
                    "challenge=http-01 requires webroot".to_string()
                })?;
                if !webroot.is_absolute() {
                    return Err(format!(
                        "webroot {} must be absolute",
                        webroot.display()
                    ));
                }
                // Wildcard domains don't work with HTTP-01 — the ACME
                // server would have to fetch from the literal '*.x.com'
                // hostname, which doesn't resolve. Catch this here.
                for d in &self.domains {
                    if d.starts_with('*') {
                        return Err(format!(
                            "wildcard domain {d:?} requires challenge=dns-01-*"
                        ));
                    }
                }
            }
            ChallengeKind::Dns01Cloudflare => {
                if self.cloudflare_api_token.as_deref().unwrap_or("").is_empty() {
                    return Err(
                        "challenge=dns-01-cloudflare requires cloudflare_api_token".into(),
                    );
                }
            }
        }
        // Phase 7de: server_url validation. Public-network HTTP is a
        // footgun — ACME flows carry account-level auth, plain HTTP
        // exposes them. Permit https:// freely; permit http:// only
        // when the host is loopback (dev fixtures: Pebble, step-ca).
        if let Some(url) = &self.server_url {
            if self.staging {
                return Err(
                    "server_url and staging=true are mutually exclusive".into(),
                );
            }
            if let Some(rest) = url.strip_prefix("https://") {
                if rest.is_empty() {
                    return Err(format!("server_url {url:?} has no host"));
                }
            } else if let Some(rest) = url.strip_prefix("http://") {
                let host = rest.split(['/', ':']).next().unwrap_or("");
                if !is_loopback_host(host) {
                    return Err(format!(
                        "server_url {url:?} uses plain http on non-loopback host; refuse"
                    ));
                }
            } else {
                return Err(format!(
                    "server_url {url:?} must start with https:// or http://localhost"
                ));
            }
        }
        Ok(())
    }

    /// Path to the issued certificate PEM. Convention matches `lego`:
    /// `<cert_dir>/<primary>.crt` for the cert chain, `<primary>.key`
    /// for the private key, `<primary>.issuer.crt` for the issuer chain.
    pub fn cert_file(&self) -> PathBuf {
        self.cert_dir.join(format!("{}.crt", self.primary_domain()))
    }

    pub fn key_file(&self) -> PathBuf {
        self.cert_dir.join(format!("{}.key", self.primary_domain()))
    }

    pub fn primary_domain(&self) -> &str {
        // Validation already guarantees domains is non-empty.
        self.domains[0].trim_start_matches('*').trim_start_matches('.')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> YamlValue {
        serde_yaml_ng::from_str(s).unwrap()
    }

    #[test]
    fn parses_minimal_http01() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
"#,
        );
        let s = AcmeCertSpec::from_value(&v).unwrap();
        assert_eq!(s.primary_domain(), "example.com");
        assert_eq!(s.cert_file().to_string_lossy(), "/etc/iac/certs/example.com/example.com.crt");
        assert_eq!(s.renew_window_days, 30);
        assert_eq!(s.state, AcmeState::Present);
    }

    #[test]
    fn parses_dns01_cloudflare() {
        let v = yaml(
            r#"
domains: ["*.example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: dns-01-cloudflare
cloudflare_api_token: cf-token
"#,
        );
        let s = AcmeCertSpec::from_value(&v).unwrap();
        assert_eq!(s.challenge, ChallengeKind::Dns01Cloudflare);
        assert_eq!(s.primary_domain(), "example.com");
    }

    #[test]
    fn rejects_wildcard_with_http01() {
        let v = yaml(
            r#"
domains: ["*.example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("wildcard"));
    }

    #[test]
    fn rejects_http01_without_webroot() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("webroot"));
    }

    #[test]
    fn rejects_dns01_without_cf_token() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: dns-01-cloudflare
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("cloudflare_api_token"));
    }

    #[test]
    fn rejects_relative_cert_dir() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: ./certs
challenge: http-01
webroot: /var/www/html
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn rejects_invalid_email() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: not-an-email
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("email"));
    }

    #[test]
    fn rejects_out_of_range_renew_window() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
renew_window_days: 100
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("renew_window_days"));
    }

    #[test]
    fn accepts_https_server_url() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
server_url: "https://acme.internal/acme/directory"
"#,
        );
        let s = AcmeCertSpec::from_value(&v).unwrap();
        assert_eq!(
            s.server_url.as_deref(),
            Some("https://acme.internal/acme/directory")
        );
    }

    #[test]
    fn accepts_http_localhost_for_pebble() {
        // Pebble — Let's Encrypt's reference test CA — listens on
        // http://localhost:14000/dir by default. Allow it.
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
server_url: "http://localhost:14000/dir"
"#,
        );
        let s = AcmeCertSpec::from_value(&v).unwrap();
        assert!(s.server_url.is_some());
    }

    #[test]
    fn rejects_http_on_public_host() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
server_url: "http://acme.example.com/dir"
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("plain http"), "{err}");
    }

    #[test]
    fn rejects_url_without_scheme() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
server_url: "acme.example.com/dir"
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("https://") || err.contains("http://"), "{err}");
    }

    #[test]
    fn rejects_server_url_with_staging() {
        let v = yaml(
            r#"
domains: ["example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: http-01
webroot: /var/www/html
staging: true
server_url: "https://acme.internal/dir"
"#,
        );
        let err = AcmeCertSpec::from_value(&v).unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn primary_domain_strips_wildcard_prefix() {
        let v = yaml(
            r#"
domains: ["*.example.com"]
email: ops@example.com
cert_dir: /etc/iac/certs/example.com
challenge: dns-01-cloudflare
cloudflare_api_token: t
"#,
        );
        let s = AcmeCertSpec::from_value(&v).unwrap();
        assert_eq!(s.primary_domain(), "example.com");
    }
}
