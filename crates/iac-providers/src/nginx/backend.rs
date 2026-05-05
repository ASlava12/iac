// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `nginx` filesystem + control-plane operations behind a trait so we can
//! mock them in unit tests. The real backend is intentionally minimal: it
//! shells out to `nginx -t` for validation and `systemctl reload nginx`
//! for reload, so it works on any distro that ships nginx via systemd.

use iac_core::{Error, Result};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use crate::subprocess::run_check_status;
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.4: `nginx -t` and `systemctl reload nginx` both
// complete in well under a second on a healthy host. 30 s is the
// outer cap that catches a hung reload (e.g. blocking on a
// stuck worker) without making operators wait for ages.
const NGINX_TIMEOUT: Duration = Duration::from_secs(30);
use std::sync::Mutex;

pub trait NginxBackend: Send + Sync + std::fmt::Debug {
    fn read_config(&self, path: &Path) -> Result<Option<String>>;
    /// Atomic write: temp file + rename. Sets mode 0644.
    fn write_config(&self, path: &Path, content: &str) -> Result<()>;
    fn remove_config(&self, path: &Path) -> Result<()>;
    /// Run `nginx -t`. Returns Ok(()) iff the system config is valid.
    fn validate(&self) -> Result<()>;
    /// Run `systemctl reload nginx`.
    fn reload(&self) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct NginxCli;

impl NginxCli {
    fn run(cmd: &str, args: &[&str]) -> Result<()> {
        let mut command = Command::new(cmd);
        command
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_check_status(
            command,
            b"",
            NGINX_TIMEOUT,
            "nginx",
            &format!("{cmd} {args:?}"),
        )
    }
}

impl NginxBackend for NginxCli {
    fn read_config(&self, path: &Path) -> Result<Option<String>> {
        match fs::read_to_string(path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io { path: path.into(), source: e }),
        }
    }

    fn write_config(&self, path: &Path, content: &str) -> Result<()> {
        let parent = path.parent().ok_or_else(|| {
            Error::provider("nginx", format!("config path has no parent: {}", path.display()))
        })?;
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| Error::Io { path: parent.into(), source: e })?;
        }
        let tmp = temp_path_in(parent, path);
        fs::write(&tmp, content).map_err(|e| Error::Io { path: tmp.clone(), source: e })?;
        let perms = fs::Permissions::from_mode(0o644);
        fs::set_permissions(&tmp, perms)
            .map_err(|e| Error::Io { path: tmp.clone(), source: e })?;
        fs::rename(&tmp, path).map_err(|e| Error::Io { path: path.into(), source: e })?;
        Ok(())
    }

    fn remove_config(&self, path: &Path) -> Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io { path: path.into(), source: e }),
        }
    }

    fn validate(&self) -> Result<()> {
        Self::run("nginx", &["-t"])
    }

    fn reload(&self) -> Result<()> {
        Self::run("systemctl", &["reload", "nginx"])
    }
}

fn temp_path_in(dir: &Path, target: &Path) -> PathBuf {
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    let ulid = ulid::Ulid::new();
    dir.join(format!(".{stem}.iac.{ulid}.tmp"))
}

// ---- mock ------------------------------------------------------------------

/// Deterministic in-memory backend. Tests can pre-seed `valid_after_writes`
/// to simulate `nginx -t` accepting / rejecting whatever was last written.
#[derive(Debug, Default)]
pub struct MockNginx {
    pub configs: Mutex<HashMap<PathBuf, String>>,
    pub calls: Mutex<Vec<String>>,
    /// If set, `validate()` returns this error once (then resets).
    pub validate_error: Mutex<Option<String>>,
    /// If set, `reload()` returns this error once.
    pub reload_error: Mutex<Option<String>>,
}

impl MockNginx {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub fn fail_validate_once(&self, msg: &str) {
        *self.validate_error.lock().unwrap() = Some(msg.into());
    }

    pub fn fail_reload_once(&self, msg: &str) {
        *self.reload_error.lock().unwrap() = Some(msg.into());
    }

    fn record(&self, action: &str, target: &str) {
        self.calls.lock().unwrap().push(format!("{action} {target}"));
    }
}

impl NginxBackend for MockNginx {
    fn read_config(&self, path: &Path) -> Result<Option<String>> {
        self.record("read", &path.display().to_string());
        Ok(self.configs.lock().unwrap().get(path).cloned())
    }

    fn write_config(&self, path: &Path, content: &str) -> Result<()> {
        self.record("write", &path.display().to_string());
        self.configs.lock().unwrap().insert(path.to_path_buf(), content.to_string());
        Ok(())
    }

    fn remove_config(&self, path: &Path) -> Result<()> {
        self.record("remove", &path.display().to_string());
        self.configs.lock().unwrap().remove(path);
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        self.record("validate", "");
        if let Some(err) = self.validate_error.lock().unwrap().take() {
            return Err(Error::provider("nginx", err));
        }
        Ok(())
    }

    fn reload(&self) -> Result<()> {
        self.record("reload", "");
        if let Some(err) = self.reload_error.lock().unwrap().take() {
            return Err(Error::provider("nginx", err));
        }
        Ok(())
    }
}
