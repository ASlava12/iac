// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Apt backend with a trait for testability.

use crate::subprocess::run_with_status;
use iac_core::{Error, Result};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.5: package operations are the slowest in the
// provider catalog. `apt-get install <large-package>` over a
// slow network can legitimately take many minutes; setting
// the cap below covers the realistic worst case (Debian
// package fetch on a 1 Mbps link, e.g. low-end VPS or
// satellite uplink) while still bounding genuinely-hung
// operations (lock contention against another apt run).
const APT_TIMEOUT: Duration = Duration::from_secs(600);
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStatus {
    NotInstalled,
    /// dpkg's `Status` field. The `version` is `${Version}` from dpkg-query.
    Installed {
        status: String,
        version: String,
    },
}

impl InstallStatus {
    pub fn is_installed(&self) -> bool {
        match self {
            Self::Installed { status, .. } => status.contains("install ok installed"),
            Self::NotInstalled => false,
        }
    }

    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Installed { version, .. } => Some(version.as_str()),
            Self::NotInstalled => None,
        }
    }
}

pub trait PackageBackend: Send + Sync + std::fmt::Debug {
    fn query(&self, name: &str) -> Result<InstallStatus>;
    fn install(&self, name: &str, version: Option<&str>) -> Result<()>;
    fn remove(&self, name: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct AptBackend;

impl AptBackend {
    fn run(args: &[&str]) -> Result<(bool, String, String)> {
        let mut cmd = Command::new(args[0]);
        cmd.args(&args[1..])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Phase 7dh.10: shared wrapper.
        run_with_status(cmd, b"", APT_TIMEOUT, "package", args[0])
    }
}

impl PackageBackend for AptBackend {
    fn query(&self, name: &str) -> Result<InstallStatus> {
        let (ok, stdout, _stderr) =
            Self::run(&["dpkg-query", "-W", "-f=${Status}\\t${Version}", name])?;
        if !ok {
            // dpkg-query exits 1 when the package is not known. Treat any
            // non-success as "not installed".
            return Ok(InstallStatus::NotInstalled);
        }
        let mut parts = stdout.splitn(2, '\t');
        let status = parts.next().unwrap_or("").to_string();
        let version = parts.next().unwrap_or("").to_string();
        Ok(InstallStatus::Installed { status, version })
    }

    fn install(&self, name: &str, version: Option<&str>) -> Result<()> {
        let target = match version {
            Some(v) => format!("{name}={v}"),
            None => name.to_string(),
        };
        let (ok, _stdout, stderr) = Self::run(&[
            "apt-get",
            "install",
            "--yes",
            "--no-install-recommends",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
            // `--` ends option parsing: the package atom can never be
            // read as an apt-get flag (belt-and-suspenders with the
            // spec-level leading-dash rejection).
            "--",
            target.as_str(),
        ])?;
        if !ok {
            return Err(Error::provider(
                "package",
                format!("apt-get install {target} failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<()> {
        let (ok, _stdout, stderr) = Self::run(&["apt-get", "remove", "--yes", "--", name])?;
        if !ok {
            return Err(Error::provider(
                "package",
                format!("apt-get remove {name} failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }
}

// --- mock --------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MockPackageBackend {
    pub installed: Mutex<HashMap<String, String>>,
    pub calls: Mutex<Vec<String>>,
    /// Optional knob: returned for the next call to `install` if non-empty.
    pub install_failures: Mutex<HashMap<String, String>>,
}

impl MockPackageBackend {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn preinstall(&self, name: &str, version: &str) {
        self.installed
            .lock()
            .unwrap()
            .insert(name.into(), version.into());
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn record(&self, action: &str, name: &str) {
        self.calls.lock().unwrap().push(format!("{action} {name}"));
    }
    pub fn fail_install(&self, name: &str, error: &str) {
        self.install_failures
            .lock()
            .unwrap()
            .insert(name.into(), error.into());
    }
}

impl PackageBackend for MockPackageBackend {
    fn query(&self, name: &str) -> Result<InstallStatus> {
        self.record("query", name);
        match self.installed.lock().unwrap().get(name) {
            Some(version) => Ok(InstallStatus::Installed {
                status: "install ok installed".into(),
                version: version.clone(),
            }),
            None => Ok(InstallStatus::NotInstalled),
        }
    }
    fn install(&self, name: &str, version: Option<&str>) -> Result<()> {
        self.record("install", name);
        if let Some(err) = self.install_failures.lock().unwrap().remove(name) {
            return Err(Error::provider("package", err));
        }
        let v = version.unwrap_or("1.0-mock").to_string();
        self.installed.lock().unwrap().insert(name.into(), v);
        Ok(())
    }
    fn remove(&self, name: &str) -> Result<()> {
        self.record("remove", name);
        self.installed.lock().unwrap().remove(name);
        Ok(())
    }
}
