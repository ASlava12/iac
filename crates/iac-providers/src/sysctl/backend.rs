// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Phase 7cb: sysctl backend — direct /proc/sys read+write.
//!
//! No `sysctl(8)` shell-out, no third-party deps. /proc/sys is a
//! plain VFS: read the file = current value, write the file = set.
//! Kernel handles validation (rejects values it doesn't understand).
//! For testing we use a Mock backend that mimics the kernel's
//! "write replaces value" semantics.

use super::spec::SysctlSettingSpec;
use iac_core::{Error, Result};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

pub trait SysctlBackend: Send + Sync + std::fmt::Debug {
    /// Read the current value at the given /proc/sys path. Returns
    /// `None` if the path doesn't exist (key isn't a kernel parameter
    /// on this system) — apply will then surface a clear error.
    fn read(&self, path: &str) -> Result<Option<String>>;
    /// Write `value` to the given /proc/sys path. Errors propagate.
    fn write(&self, path: &str, value: &str) -> Result<()>;
}

/// Real backend — direct VFS access to /proc/sys.
#[derive(Debug, Default)]
pub struct ProcfsBackend;

impl SysctlBackend for ProcfsBackend {
    fn read(&self, path: &str) -> Result<Option<String>> {
        let p = PathBuf::from(path);
        match fs::read_to_string(&p) {
            Ok(s) => {
                // Kernel files end with newline; trim for canonical
                // value comparison ("1\n" vs "1").
                Ok(Some(s.trim_end_matches(['\n', '\r']).to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::provider("sysctl", format!("reading {path}: {e}"))),
        }
    }

    fn write(&self, path: &str, value: &str) -> Result<()> {
        // /proc/sys writes are atomic — the kernel parses the entire
        // payload in one go. We use `fs::write` (single syscall) to
        // ensure we don't accidentally split the value across
        // multiple writes.
        fs::write(path, value)
            .map_err(|e| Error::provider("sysctl", format!("writing {path}: {e}")))?;
        Ok(())
    }
}

/// In-memory mock for tests. Stores `path → value` and serves the
/// same trait. Operators don't see this; tests build with
/// `MockSysctl::new()` and pre-populate via `seed`.
#[derive(Debug, Default)]
pub struct MockSysctl {
    values: Mutex<HashMap<String, String>>,
    /// When true, `read` returns None for paths not yet seeded —
    /// simulating "kernel parameter doesn't exist on this system."
    /// When false, missing paths return Some("0") so tests don't
    /// have to seed every key.
    pub strict: Mutex<bool>,
    pub writes: Mutex<Vec<(String, String)>>,
}

impl MockSysctl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, path: &str, value: &str) {
        self.values
            .lock()
            .unwrap()
            .insert(path.into(), value.into());
    }

    pub fn writes(&self) -> Vec<(String, String)> {
        self.writes.lock().unwrap().clone()
    }

    pub fn current(&self, path: &str) -> Option<String> {
        self.values.lock().unwrap().get(path).cloned()
    }

    pub fn set_strict(&self, strict: bool) {
        *self.strict.lock().unwrap() = strict;
    }
}

impl SysctlBackend for MockSysctl {
    fn read(&self, path: &str) -> Result<Option<String>> {
        let values = self.values.lock().unwrap();
        if let Some(v) = values.get(path) {
            return Ok(Some(v.clone()));
        }
        if *self.strict.lock().unwrap() {
            Ok(None)
        } else {
            Ok(Some("0".into()))
        }
    }

    fn write(&self, path: &str, value: &str) -> Result<()> {
        self.writes
            .lock()
            .unwrap()
            .push((path.into(), value.into()));
        self.values
            .lock()
            .unwrap()
            .insert(path.into(), value.into());
        Ok(())
    }
}

/// Helper used by ops: read current value for a spec. Returns
/// `Ok(None)` for "key doesn't exist on this system" — apply handles
/// this with a clear error.
pub(crate) fn read_current(
    backend: &dyn SysctlBackend,
    spec: &SysctlSettingSpec,
) -> Result<Option<String>> {
    backend.read(&spec.proc_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_read_after_seed_returns_seeded() {
        let m = MockSysctl::new();
        m.seed("/proc/sys/net/ipv4/ip_forward", "1");
        assert_eq!(
            m.read("/proc/sys/net/ipv4/ip_forward").unwrap(),
            Some("1".into())
        );
    }

    #[test]
    fn mock_read_unstrict_default_zero_for_unseeded() {
        let m = MockSysctl::new();
        assert_eq!(
            m.read("/proc/sys/net/ipv4/some_param").unwrap(),
            Some("0".into())
        );
    }

    #[test]
    fn mock_read_strict_returns_none_for_unseeded() {
        let m = MockSysctl::new();
        m.set_strict(true);
        assert_eq!(m.read("/proc/sys/missing/path").unwrap(), None);
    }

    #[test]
    fn mock_write_records_and_updates() {
        let m = MockSysctl::new();
        m.write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        assert_eq!(
            m.current("/proc/sys/net/ipv4/ip_forward").as_deref(),
            Some("1")
        );
        let writes = m.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "/proc/sys/net/ipv4/ip_forward");
        assert_eq!(writes[0].1, "1");
    }
}
