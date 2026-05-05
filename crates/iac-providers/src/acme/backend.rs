//! Phase 7cy: backend trait + Lego implementation for `acme.certificate`.
//!
//! Why `lego`:
//!   * Single static Go binary, easy to drop on agents.
//!   * Speaks the full ACMEv2 protocol including HTTP-01 webroot mode
//!     and DNS-01 with the major providers (Cloudflare bundled).
//!   * Stable on-disk layout (`<cert_dir>/<primary>.crt` etc.) we can
//!     rely on for observation.
//!
//! Operators on debian boxes typically have certbot — we don't bundle
//! a certbot backend in 7cy because its on-disk layout differs and its
//! account-state directory has more knobs. Adding a `CertbotBackend`
//! later is a one-trait-impl change.
//!
//! `MockAcme` for tests records calls and writes a synthetic cert PEM
//! into `cert_dir` so the observe path has something to read.

use super::spec::{AcmeCertSpec, ChallengeKind};
use iac_core::{Error, Result};
use crate::subprocess::run_check_status;
use iac_core::subprocess::run_with_timeout;
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.8: ACME challenges (especially DNS-01) take real
// time — the validating CA polls the challenge record and the
// time-to-propagate dominates. 5 minutes covers Let's Encrypt's
// own retry envelope; longer than that is a clear signal of a
// stuck issuance.
const LEGO_TIMEOUT: Duration = Duration::from_secs(300);

// Phase 7di.6.8: openssl x509 parses a small file — should be
// near-instant. 10 s is a generous outer cap.
const OPENSSL_TIMEOUT: Duration = Duration::from_secs(10);

pub trait AcmeBackend: std::fmt::Debug + Send + Sync {
    /// Issue a fresh certificate for `spec.domains` into `spec.cert_dir`.
    fn issue(&self, spec: &AcmeCertSpec) -> Result<()>;

    /// Renew the existing certificate. ACME backends often have a
    /// distinct "renew" code path that reuses the account key but
    /// requests a fresh cert; same end state from the operator's view.
    fn renew(&self, spec: &AcmeCertSpec) -> Result<()>;

    /// Revoke + delete on-disk files. Best-effort.
    fn revoke(&self, spec: &AcmeCertSpec) -> Result<()>;
}

/// Read PEM cert and return its `notAfter` date as Unix-epoch seconds.
/// Shells out to `openssl x509 -enddate -noout` — present on virtually
/// every Linux distro. Returns `None` if the file doesn't exist or
/// can't be parsed (treat as "expired" for renewal logic).
pub fn read_cert_expiry_unix(cert_path: &std::path::Path) -> Option<i64> {
    if !cert_path.exists() {
        return None;
    }
    let mut cmd = Command::new("openssl");
    cmd.args(["x509", "-in"])
        .arg(cert_path)
        .args(["-enddate", "-noout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let out = run_with_timeout(cmd, b"", OPENSSL_TIMEOUT).ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    // Output: `notAfter=Apr 12 23:59:59 2026 GMT`
    let date = s.trim().strip_prefix("notAfter=")?.trim().to_string();
    parse_openssl_date_to_unix(&date)
}

/// Parse openssl's `notAfter=` date format (`Apr 12 23:59:59 2026 GMT`)
/// into a unix timestamp. Returns `None` on malformed input. Pure-stdlib
/// — we deliberately don't pull in chrono/jiff for this one parse since
/// jiff is already in the dep tree but its strict parsers don't accept
/// the openssl format directly.
fn parse_openssl_date_to_unix(s: &str) -> Option<i64> {
    // Try jiff with a custom parse.
    let parsed = jiff::civil::DateTime::strptime("%b %e %H:%M:%S %Y GMT", s).ok()?;
    parsed
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()?
        .timestamp()
        .as_second()
        .into()
}

#[derive(Debug, Default)]
pub struct LegoCli;

/// Phase 7cz.4: secret-passing strategy for `lego`.
///
/// Pre-7cz, the Cloudflare API token was passed via the
/// `CLOUDFLARE_DNS_API_TOKEN` environment variable. `lego` would then
/// inherit it, but the env block of the child process is readable
/// through `/proc/<pid>/environ` by any process running as the same
/// uid (or via `ps eww`), which is a real exposure on multi-tenant
/// servers or sloppy local dev setups.
///
/// Lego ≥ v4 supports the `_FILE` env-var convention: instead of
/// `FOO=secret` you set `FOO_FILE=/path/to/file` and lego reads the
/// secret from disk. We materialise the token into a `TempDir` with
/// mode 0600, hand the path through `CLOUDFLARE_DNS_API_TOKEN_FILE`,
/// and drop the TempDir after the command exits — `/proc/.../environ`
/// then reveals only a path, and the path itself is unreadable to
/// any non-owner.
struct SecretFile {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

impl SecretFile {
    fn new(secret: &str) -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("iac-acme-secret-")
            .tempdir()
            .map_err(|e| {
                Error::provider("acme.certificate", format!("temp dir for secret: {e}"))
            })?;
        let path = dir.path().join("token");
        std::fs::write(&path, secret).map_err(|e| {
            Error::provider("acme.certificate", format!("write secret: {e}"))
        })?;
        // Tighten perms (Unix only — providers crate is *nix-targeted).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                Error::provider("acme.certificate", format!("chmod 0600: {e}"))
            })?;
        Ok(Self { _dir: dir, path })
    }
}

impl LegoCli {
    /// Returns `(Command, optional SecretFile to keep alive for the
    /// command's lifetime)`. The caller is responsible for keeping the
    /// `SecretFile` alive until `cmd.output()` completes — drop it
    /// after, and the temp file vanishes.
    fn build_command(
        &self,
        spec: &AcmeCertSpec,
        action: &str,
    ) -> Result<(Command, Option<SecretFile>)> {
        let mut cmd = Command::new("lego");
        cmd.arg("--accept-tos")
            .arg("--email").arg(&spec.email)
            .arg("--path").arg(&spec.cert_dir);
        for d in &spec.domains {
            cmd.arg("--domains").arg(d);
        }
        // Phase 7de: an explicit `server_url` (e.g. a local Pebble or
        // self-hosted CA) wins. Otherwise honour `staging` for the
        // Let's Encrypt staging endpoint. Spec validation guarantees
        // these aren't both set.
        if let Some(url) = spec.server_url.as_deref() {
            cmd.arg("--server").arg(url);
        } else if spec.staging {
            cmd.arg("--server")
                .arg("https://acme-staging-v02.api.letsencrypt.org/directory");
        }
        let mut secret = None;
        match spec.challenge {
            ChallengeKind::Http01 => {
                // SAFETY: AcmeCertSpec::validate() requires webroot to
                // be Some when challenge=http-01. Phase 7cz.16 keeps
                // the expect for clarity but tags it for clippy.
                #[allow(clippy::expect_used)]
                let webroot = spec.webroot.as_deref().expect("validated");
                cmd.arg("--http").arg("--http.webroot").arg(webroot);
            }
            ChallengeKind::Dns01Cloudflare => {
                cmd.arg("--dns").arg("cloudflare");
                let token = spec.cloudflare_api_token.as_deref().unwrap_or("");
                let sf = SecretFile::new(token)?;
                // Lego ≥ v4 reads the secret from this file when the
                // `_FILE` env-var is set. The literal token never
                // touches the child process's env block.
                cmd.env("CLOUDFLARE_DNS_API_TOKEN_FILE", &sf.path);
                secret = Some(sf);
            }
        }
        cmd.arg(action);
        Ok((cmd, secret))
    }
}

impl AcmeBackend for LegoCli {
    fn issue(&self, spec: &AcmeCertSpec) -> Result<()> {
        let (mut cmd, _secret) = self.build_command(spec, "run")?;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_check_status(cmd, b"", LEGO_TIMEOUT, "acme.certificate", "lego run")
    }

    fn renew(&self, spec: &AcmeCertSpec) -> Result<()> {
        let (mut cmd, _secret) = self.build_command(spec, "renew")?;
        // `lego renew` only fires if the cert is within its --days
        // window; pass the operator's choice through.
        cmd.arg("--days")
            .arg(spec.renew_window_days.to_string());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_check_status(cmd, b"", LEGO_TIMEOUT, "acme.certificate", "lego renew")
    }

    fn revoke(&self, spec: &AcmeCertSpec) -> Result<()> {
        let (mut cmd, _secret) = self.build_command(spec, "revoke")?;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Phase 7di.6.8: revoke is best-effort — log non-fatal
        // failures but don't propagate. Use `run_with_timeout`
        // directly because we want the captured stderr regardless
        // of exit code.
        match run_with_timeout(cmd, b"", LEGO_TIMEOUT) {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                tracing_warn(&format!("lego revoke non-fatal failure: {stderr}"));
            }
            Err(e) => {
                // Even spawn / timeout failures are non-fatal here.
                tracing_warn(&format!("lego revoke subprocess error: {e}"));
            }
        }
        // Best-effort cleanup of the on-disk pair.
        let _ = std::fs::remove_file(spec.cert_file());
        let _ = std::fs::remove_file(spec.key_file());
        Ok(())
    }
}

/// Phase 7cz.18: bookkeeping shared via [`MockJournal`].
#[derive(Debug, Default)]
pub struct MockAcme {
    journal: crate::mock_journal::MockJournal<AcmeMockState>,
}

#[derive(Debug, Default)]
struct AcmeMockState {
    /// notAfter unix timestamp the next issue/renew will write into the
    /// synthetic cert PEM. Lets tests simulate "fresh cert" vs "stale".
    next_not_after: Option<i64>,
}

impl MockAcme {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<String> {
        self.journal.calls()
    }

    pub fn fail_next_issue(&self, msg: impl Into<String>) {
        self.journal.fail_next("issue", msg);
    }

    pub fn set_next_not_after(&self, unix_secs: i64) {
        self.journal.with_state_mut(|s| s.next_not_after = Some(unix_secs));
    }

    fn write_synthetic_cert(spec: &AcmeCertSpec, not_after_unix: i64) -> Result<()> {
        std::fs::create_dir_all(&spec.cert_dir).map_err(|e| {
            Error::provider(
                "acme.certificate",
                format!(
                    "mock create_dir_all {}: {e}",
                    spec.cert_dir.display()
                ),
            )
        })?;
        // We don't need a valid X.509 — just the file's *existence*
        // and a marker file the test can decode the expiry from.
        std::fs::write(spec.cert_file(), b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n")
            .map_err(|e| Error::provider("acme.certificate", format!("write cert: {e}")))?;
        std::fs::write(spec.key_file(), b"-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n")
            .map_err(|e| Error::provider("acme.certificate", format!("write key: {e}")))?;
        // Sidecar with the expiry — the Mock observe path reads this
        // instead of shelling out to openssl on a non-real cert.
        let sidecar = spec.cert_dir.join(format!("{}.expiry", spec.primary_domain()));
        std::fs::write(&sidecar, not_after_unix.to_string())
            .map_err(|e| Error::provider("acme.certificate", format!("write sidecar: {e}")))?;
        Ok(())
    }
}

/// Phase 7cz.18 helper: synthetic-cert helper takes the resolved
/// not-after timestamp; reading it from the journal stays in the
/// mock impl.
fn default_not_after_secs() -> i64 {
    // Default: 90 days from now (Let's Encrypt's standard lifetime).
    let now: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    now.saturating_add(90 * 86400)
}

impl AcmeBackend for MockAcme {
    fn issue(&self, spec: &AcmeCertSpec) -> Result<()> {
        let line = format!(
            "issue domains={} cert_dir={}",
            spec.domains.join(","),
            spec.cert_dir.display(),
        );
        // record() returns Err if `issue` is armed via fail_next.
        let not_after = self
            .journal
            .record("issue", line, |s| s.next_not_after.unwrap_or_else(default_not_after_secs))
            .map_err(|m| Error::provider("acme.certificate", m))?;
        Self::write_synthetic_cert(spec, not_after)
    }

    fn renew(&self, spec: &AcmeCertSpec) -> Result<()> {
        let line = format!("renew domains={}", spec.domains.join(","));
        let not_after = self
            .journal
            .record("renew", line, |s| {
                s.next_not_after.take().unwrap_or_else(default_not_after_secs)
            })
            .map_err(|m| Error::provider("acme.certificate", m))?;
        Self::write_synthetic_cert(spec, not_after)
    }

    fn revoke(&self, spec: &AcmeCertSpec) -> Result<()> {
        let _ = self.journal.record(
            "revoke",
            format!("revoke domains={}", spec.domains.join(",")),
            |_| (),
        );
        let _ = std::fs::remove_file(spec.cert_file());
        let _ = std::fs::remove_file(spec.key_file());
        let _ = std::fs::remove_file(
            spec.cert_dir.join(format!("{}.expiry", spec.primary_domain())),
        );
        Ok(())
    }
}

/// Mock-aware expiry reader. For real certs, falls back to openssl;
/// for tests, reads the `<primary>.expiry` sidecar file.
pub fn read_expiry_with_fallback(spec: &AcmeCertSpec) -> Option<i64> {
    let sidecar = spec
        .cert_dir
        .join(format!("{}.expiry", spec.primary_domain()));
    if let Ok(s) = std::fs::read_to_string(&sidecar)
        && let Ok(n) = s.trim().parse::<i64>()
    {
        return Some(n);
    }
    read_cert_expiry_unix(&spec.cert_file())
}

fn tracing_warn(msg: &str) {
    // We don't pull tracing into iac-providers (kept dep-light); use
    // stderr directly. Operators see this on the agent's journal.
    eprintln!("[acme.certificate] {msg}");
}

/// Construct the right backend. Phase 7cy ships only `lego`; future
/// backends plug in here.
pub fn pick_backend() -> Box<dyn AcmeBackend> {
    Box::new(LegoCli)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_issue_writes_files_and_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.set_next_not_after(1_900_000_000);
        m.issue(&spec).unwrap();
        assert!(spec.cert_file().exists());
        assert!(spec.key_file().exists());
        let exp = read_expiry_with_fallback(&spec).unwrap();
        assert_eq!(exp, 1_900_000_000);
    }

    #[test]
    fn mock_renew_overwrites() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.set_next_not_after(1_800_000_000);
        m.issue(&spec).unwrap();
        m.set_next_not_after(2_000_000_000);
        m.renew(&spec).unwrap();
        let exp = read_expiry_with_fallback(&spec).unwrap();
        assert_eq!(exp, 2_000_000_000);
    }

    #[test]
    fn mock_revoke_clears_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.issue(&spec).unwrap();
        m.revoke(&spec).unwrap();
        assert!(!spec.cert_file().exists());
        assert!(!spec.key_file().exists());
    }

    #[test]
    fn mock_fail_next_issue_propagates() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.fail_next_issue("rate limited");
        let err = m.issue(&spec).unwrap_err();
        assert!(err.to_string().contains("rate limited"));
    }
}
