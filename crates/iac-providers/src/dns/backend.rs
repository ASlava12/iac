//! Phase 7cx: backend trait + Cloudflare implementation for `dns.record`.
//!
//! Same shell-out pattern as docker/git/sops: `curl` is the operator's
//! HTTPS+TLS toolkit. No reqwest in iac-providers — that would bloat
//! the static binary and pull in an entirely separate TLS path. The
//! tradeoff is that `curl` must be on PATH on the agent host, which it
//! is on virtually every Linux distribution.
//!
//! Mock backend for tests records every call so the test can assert the
//! exact backend interactions.

use super::spec::{CloudflareCreds, DnsRecordSpec, RecordType};
use crate::subprocess::run_capture_stdout;
use iac_core::{Error, Result};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.1: hard outer cap on a single Cloudflare API call.
// curl already enforces `--max-time 20s` of its own (kept below as
// a defence-in-depth in case curl's parser ever silently drops the
// flag); the host-level cap kills curl itself if it gets stuck on
// e.g. DNS resolution or a hung TLS handshake. 30 s comfortably
// envelopes curl's 20 s.
const DNS_API_TIMEOUT: Duration = Duration::from_secs(30);

/// One DNS record as observed via the backend's API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Provider-specific record id (Cloudflare's UUID-like string).
    pub id: String,
    pub fqdn: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

pub trait DnsBackend: std::fmt::Debug + Send + Sync {
    /// Find the first record matching `(fqdn, type)` in `zone`. Returns
    /// `None` if no such record exists.
    fn find_record(
        &self,
        zone: &str,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<Option<DnsRecord>>;

    /// Create a new DNS record. Returns the new record's id.
    fn create_record(
        &self,
        zone: &str,
        fqdn: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> Result<String>;

    /// Update an existing record's value/ttl.
    fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        fqdn: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> Result<()>;

    fn delete_record(&self, zone: &str, record_id: &str) -> Result<()>;
}

/// Cloudflare backend. Authenticates with a scoped API token (Bearer auth),
/// resolves the zone id once per call, then talks to `/zones/{id}/dns_records`.
///
/// Why scoped token: cf_api_keys (the legacy global key) can do anything on
/// any zone; a scoped token can be limited to `Zone.DNS:Edit` for one zone.
/// We use `Authorization: Bearer <token>`, which Cloudflare auto-routes to
/// the scoped-token path.
#[derive(Debug)]
pub struct CloudflareCli {
    pub creds: CloudflareCreds,
}

impl CloudflareCli {
    pub fn new(creds: CloudflareCreds) -> Self {
        Self { creds }
    }

    fn auth_header(&self) -> String {
        format!("Authorization: Bearer {}", self.creds.api_token)
    }

    fn zone_id(&self, zone: &str) -> Result<String> {
        // GET https://api.cloudflare.com/client/v4/zones?name=<zone>
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            url_encode(zone),
        );
        let resp = curl_get(&url, &self.auth_header())?;
        let body: serde_json::Value = serde_json::from_str(&resp).map_err(|e| {
            Error::provider("dns.record", format!("zone lookup parse: {e}: {resp}"))
        })?;
        let id = body
            .get("result")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first())
            .and_then(|z| z.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::provider(
                    "dns.record",
                    format!("zone {zone:?} not found in Cloudflare account"),
                )
            })?;
        Ok(id.to_string())
    }
}

impl DnsBackend for CloudflareCli {
    fn find_record(
        &self,
        zone: &str,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<Option<DnsRecord>> {
        let zid = self.zone_id(zone)?;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zid}/dns_records?type={}&name={}",
            record_type.as_str(),
            url_encode(fqdn),
        );
        let resp = curl_get(&url, &self.auth_header())?;
        let body: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| Error::provider("dns.record", format!("list parse: {e}: {resp}")))?;
        let records = body
            .get("result")
            .and_then(|r| r.as_array())
            .ok_or_else(|| {
                Error::provider(
                    "dns.record",
                    format!("Cloudflare list response missing `result`: {resp}"),
                )
            })?;
        // Defense: the list URL filters by name+type, but don't trust the
        // API to honour it — match explicitly before returning a record we
        // might then UPDATE or DELETE. Acting on `.first()` blindly risks
        // mutating the wrong record if the API ever returns a fuzzy/partial
        // match or extra rows.
        let wanted_type = record_type.as_str();
        let matching = records.iter().find(|rec| {
            let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let rtype = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
            name.eq_ignore_ascii_case(fqdn) && rtype.eq_ignore_ascii_case(wanted_type)
        });
        if let Some(rec) = matching {
            return Ok(Some(DnsRecord {
                id: rec.get("id").and_then(|v| v.as_str()).unwrap_or("").into(),
                fqdn: rec
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
                record_type: rec
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
                value: rec
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
                // Phase 7cz.17: saturating cast — TTL above u32::MAX is
                // implausible (>136 yrs), but we'd rather clamp than wrap.
                ttl: rec
                    .get("ttl")
                    .and_then(|v| v.as_u64())
                    .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
                    .unwrap_or(0),
            }));
        }
        Ok(None)
    }

    fn create_record(
        &self,
        zone: &str,
        fqdn: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> Result<String> {
        let zid = self.zone_id(zone)?;
        let url = format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records");
        let payload = serde_json::json!({
            "type": record_type.as_str(),
            "name": fqdn,
            "content": value,
            "ttl": ttl,
        });
        let resp = curl_post(&url, &self.auth_header(), &payload.to_string())?;
        let body: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| Error::provider("dns.record", format!("create parse: {e}: {resp}")))?;
        let id = body
            .get("result")
            .and_then(|r| r.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::provider(
                    "dns.record",
                    format!("Cloudflare create response missing id: {resp}"),
                )
            })?;
        Ok(id.to_string())
    }

    fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        fqdn: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        let zid = self.zone_id(zone)?;
        let url =
            format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records/{record_id}");
        let payload = serde_json::json!({
            "type": record_type.as_str(),
            "name": fqdn,
            "content": value,
            "ttl": ttl,
        });
        let resp = curl_put(&url, &self.auth_header(), &payload.to_string())?;
        // Validate that success was indicated.
        let body: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| Error::provider("dns.record", format!("update parse: {e}: {resp}")))?;
        if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(Error::provider(
                "dns.record",
                format!("Cloudflare update returned success=false: {resp}"),
            ));
        }
        Ok(())
    }

    fn delete_record(&self, zone: &str, record_id: &str) -> Result<()> {
        let zid = self.zone_id(zone)?;
        let url =
            format!("https://api.cloudflare.com/client/v4/zones/{zid}/dns_records/{record_id}");
        let resp = curl_delete(&url, &self.auth_header())?;
        let body: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| Error::provider("dns.record", format!("delete parse: {e}: {resp}")))?;
        if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(Error::provider(
                "dns.record",
                format!("Cloudflare delete returned success=false: {resp}"),
            ));
        }
        Ok(())
    }
}

// ---- curl shell-out helpers ------------------------------------------------

fn curl_get(url: &str, auth: &str) -> Result<String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "--max-time",
        "20",
        "--fail-with-body",
        // Read the Authorization header from a config on stdin (`-K -`)
        // so the Bearer token never lands in argv / `ps` /
        // `/proc/<pid>/cmdline` (mirrors the ACME provider's _FILE
        // approach). The non-secret Content-Type stays inline.
        "-K",
        "-",
        "-H",
        "Content-Type: application/json",
        url,
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_capture_stdout(
        cmd,
        curl_auth_config(auth).as_bytes(),
        DNS_API_TIMEOUT,
        "dns.record",
        &format!("curl GET {url}"),
    )
}

/// Build a one-line curl config (`-K`) carrying the auth header, fed via
/// stdin so the token stays out of the process argv.
fn curl_auth_config(auth: &str) -> String {
    // Cloudflare tokens are `[A-Za-z0-9_-]`; no quote-escaping needed, but
    // strip any stray `"`/newline defensively so a malformed token can't
    // inject extra config directives.
    let safe: String = auth
        .chars()
        .filter(|c| *c != '"' && *c != '\n' && *c != '\r')
        .collect();
    format!("header = \"{safe}\"\n")
}

fn curl_request(method: &str, url: &str, auth: &str, body: Option<&str>) -> Result<String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "--max-time",
        "20",
        "--fail-with-body",
        "-X",
        method,
        // Auth header via stdin config (`-K -`); token stays out of argv.
        "-K",
        "-",
        "-H",
        "Content-Type: application/json",
    ]);
    if let Some(b) = body {
        cmd.arg("--data").arg(b);
    }
    cmd.arg(url);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_capture_stdout(
        cmd,
        curl_auth_config(auth).as_bytes(),
        DNS_API_TIMEOUT,
        "dns.record",
        &format!("curl {method} {url}"),
    )
}

fn curl_post(url: &str, auth: &str, body: &str) -> Result<String> {
    curl_request("POST", url, auth, Some(body))
}

fn curl_put(url: &str, auth: &str, body: &str) -> Result<String> {
    curl_request("PUT", url, auth, Some(body))
}

fn curl_delete(url: &str, auth: &str) -> Result<String> {
    curl_request("DELETE", url, auth, None)
}

/// Percent-encode a query-string value per RFC 3986: every byte outside
/// the unreserved set (`A-Za-z0-9-_.~`) is `%XX`-escaped. This is the
/// full encoding, not a two-character shortcut — it keeps domain names /
/// record types safe even if they contain reserved characters. Avoids
/// pulling in the `urlencoding` crate.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                use std::fmt::Write;
                let mut buf = [0u8; 4];
                let bytes = c.encode_utf8(&mut buf).as_bytes();
                for b in bytes {
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
    }
    out
}

// ---- mock backend for unit tests ------------------------------------------

/// Phase 7cz.18: bookkeeping shared via [`MockJournal`]. Provider-
/// specific state (records map + id counter) lives in [`DnsMockState`].
#[derive(Debug, Default)]
pub struct MockDns {
    journal: crate::mock_journal::MockJournal<DnsMockState>,
}

#[derive(Debug, Default)]
struct DnsMockState {
    /// (zone, fqdn, type) → record
    records: BTreeMap<(String, String, String), DnsRecord>,
    next_id: u64,
}

impl MockDns {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<String> {
        self.journal.calls()
    }

    pub fn pre_insert(&self, zone: &str, rec: DnsRecord) {
        self.journal.with_state_mut(|s| {
            s.records.insert(
                (zone.to_string(), rec.fqdn.clone(), rec.record_type.clone()),
                rec,
            );
        });
    }
}

impl DnsBackend for MockDns {
    fn find_record(
        &self,
        zone: &str,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<Option<DnsRecord>> {
        Ok(self.journal.with_state(|s| {
            s.records
                .get(&(
                    zone.to_string(),
                    fqdn.to_string(),
                    record_type.as_str().to_string(),
                ))
                .cloned()
        }))
    }

    fn create_record(
        &self,
        zone: &str,
        fqdn: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> Result<String> {
        let line = format!(
            "create zone={zone} fqdn={fqdn} type={} value={value} ttl={ttl}",
            record_type.as_str()
        );
        self.journal
            .record("create", line, |s| {
                s.next_id += 1;
                let id = format!("rec-{:x}", s.next_id);
                s.records.insert(
                    (
                        zone.to_string(),
                        fqdn.to_string(),
                        record_type.as_str().to_string(),
                    ),
                    DnsRecord {
                        id: id.clone(),
                        fqdn: fqdn.to_string(),
                        record_type: record_type.as_str().to_string(),
                        value: value.to_string(),
                        ttl,
                    },
                );
                id
            })
            .map_err(|m| Error::provider("dns.record", m))
    }

    fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        fqdn: &str,
        record_type: RecordType,
        value: &str,
        ttl: u32,
    ) -> Result<()> {
        let line = format!(
            "update zone={zone} id={record_id} fqdn={fqdn} type={} value={value} ttl={ttl}",
            record_type.as_str()
        );
        self.journal
            .record("update", line, |s| {
                let key = (
                    zone.to_string(),
                    fqdn.to_string(),
                    record_type.as_str().to_string(),
                );
                if let Some(r) = s.records.get_mut(&key) {
                    r.value = value.to_string();
                    r.ttl = ttl;
                }
            })
            .map_err(|m| Error::provider("dns.record", m))
    }

    fn delete_record(&self, zone: &str, record_id: &str) -> Result<()> {
        self.journal
            .record(
                "delete",
                format!("delete zone={zone} id={record_id}"),
                |s| {
                    s.records.retain(|_, v| v.id != record_id);
                },
            )
            .map_err(|m| Error::provider("dns.record", m))
    }
}

/// Construct the right backend based on the spec's `provider` field.
/// Returns a boxed `dyn DnsBackend` so callers don't need to know the
/// concrete type. The agent runs this once per resource, so the small
/// allocation is fine.
pub fn pick_backend(spec: &DnsRecordSpec) -> Result<Box<dyn DnsBackend>> {
    use super::spec::DnsBackendKind;
    match spec.provider {
        DnsBackendKind::Cloudflare => {
            let cf = spec.cloudflare.clone().ok_or_else(|| {
                Error::provider(
                    "dns.record",
                    "cloudflare backend requested but `cloudflare:` block missing",
                )
            })?;
            Ok(Box::new(CloudflareCli::new(cf)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_handles_dots_and_slashes() {
        assert_eq!(url_encode("example.com"), "example.com");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a+b"), "a%2Bb");
    }

    #[test]
    fn mock_round_trip() {
        let m = MockDns::new();
        assert_eq!(
            m.find_record("example.com", "app.example.com", RecordType::A)
                .unwrap(),
            None
        );
        let id = m
            .create_record(
                "example.com",
                "app.example.com",
                RecordType::A,
                "1.2.3.4",
                300,
            )
            .unwrap();
        let r = m
            .find_record("example.com", "app.example.com", RecordType::A)
            .unwrap()
            .unwrap();
        assert_eq!(r.value, "1.2.3.4");
        m.update_record(
            "example.com",
            &id,
            "app.example.com",
            RecordType::A,
            "5.6.7.8",
            60,
        )
        .unwrap();
        let r2 = m
            .find_record("example.com", "app.example.com", RecordType::A)
            .unwrap()
            .unwrap();
        assert_eq!(r2.value, "5.6.7.8");
        assert_eq!(r2.ttl, 60);
        m.delete_record("example.com", &id).unwrap();
        assert_eq!(
            m.find_record("example.com", "app.example.com", RecordType::A)
                .unwrap(),
            None
        );
    }
}
