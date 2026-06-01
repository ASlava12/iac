// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Indirection over `systemctl` so tests can run without a live systemd.

use crate::subprocess::run_capture_stdout;
use iac_core::{Error, Result};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.3: `systemctl start nginx` can legitimately take
// up to ~30 s on a slow host (waiting for `Type=notify` services
// to ready). 90 s caps the worst case while still bounding a
// truly hung systemctl (e.g. waiting for d-bus reconnection).
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(90);
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitInfo {
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub unit_file_state: String,
}

impl UnitInfo {
    /// True if unit-file is enabled in either persistent or runtime form.
    pub fn is_enabled(&self) -> bool {
        matches!(
            self.unit_file_state.as_str(),
            "enabled" | "enabled-runtime" | "alias"
        )
    }

    pub fn is_active(&self) -> bool {
        self.active_state == "active"
    }

    pub fn is_loaded(&self) -> bool {
        self.load_state == "loaded"
    }

    pub fn is_masked(&self) -> bool {
        self.load_state == "masked" || self.unit_file_state == "masked"
    }

    pub fn is_static(&self) -> bool {
        self.unit_file_state == "static"
    }
}

pub trait Systemctl: Send + Sync + std::fmt::Debug {
    fn show(&self, unit: &str) -> Result<UnitInfo>;
    fn enable(&self, unit: &str) -> Result<()>;
    fn disable(&self, unit: &str) -> Result<()>;
    fn start(&self, unit: &str) -> Result<()>;
    fn stop(&self, unit: &str) -> Result<()>;
    fn restart(&self, unit: &str) -> Result<()>;
    fn reload(&self, unit: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct RealSystemctl;

impl RealSystemctl {
    fn run(args: &[&str]) -> Result<String> {
        let mut cmd = Command::new("systemctl");
        cmd.args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_capture_stdout(
            cmd,
            b"",
            SYSTEMCTL_TIMEOUT,
            "systemd",
            &format!("systemctl {args:?}"),
        )
    }
}

impl Systemctl for RealSystemctl {
    fn show(&self, unit: &str) -> Result<UnitInfo> {
        let output = Self::run(&[
            "show",
            unit,
            "--no-page",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
        ])?;
        Ok(parse_show(&output))
    }

    // `--` ends option parsing so a unit name can never be read as a
    // `systemctl` flag (defense-in-depth alongside the spec-level
    // leading-dash rejection).
    fn enable(&self, unit: &str) -> Result<()> {
        Self::run(&["enable", "--", unit])?;
        Ok(())
    }

    fn disable(&self, unit: &str) -> Result<()> {
        Self::run(&["disable", "--", unit])?;
        Ok(())
    }

    fn start(&self, unit: &str) -> Result<()> {
        Self::run(&["start", "--", unit])?;
        Ok(())
    }

    fn stop(&self, unit: &str) -> Result<()> {
        Self::run(&["stop", "--", unit])?;
        Ok(())
    }

    fn restart(&self, unit: &str) -> Result<()> {
        Self::run(&["restart", "--", unit])?;
        Ok(())
    }

    fn reload(&self, unit: &str) -> Result<()> {
        Self::run(&["reload", "--", unit])?;
        Ok(())
    }
}

pub fn parse_show(output: &str) -> UnitInfo {
    let mut props: HashMap<&str, &str> = HashMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            props.insert(k.trim(), v.trim());
        }
    }
    UnitInfo {
        load_state: props
            .get("LoadState")
            .copied()
            .unwrap_or("unknown")
            .to_string(),
        active_state: props
            .get("ActiveState")
            .copied()
            .unwrap_or("unknown")
            .to_string(),
        sub_state: props
            .get("SubState")
            .copied()
            .unwrap_or("unknown")
            .to_string(),
        unit_file_state: props
            .get("UnitFileState")
            .copied()
            .unwrap_or("static")
            .to_string(),
    }
}

// --- mock --------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MockSystemctl {
    pub units: Mutex<HashMap<String, UnitInfo>>,
    pub calls: Mutex<Vec<String>>,
}

impl MockSystemctl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, unit: &str, info: UnitInfo) {
        self.units.lock().unwrap().insert(unit.to_string(), info);
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, action: &str, unit: &str) {
        self.calls.lock().unwrap().push(format!("{action} {unit}"));
    }

    fn mutate(&self, unit: &str, f: impl FnOnce(&mut UnitInfo)) -> Result<()> {
        let mut g = self.units.lock().unwrap();
        let info = g.get_mut(unit).ok_or_else(|| {
            Error::provider("systemd", format!("mock: unit {unit} not registered"))
        })?;
        f(info);
        Ok(())
    }
}

impl Systemctl for MockSystemctl {
    fn show(&self, unit: &str) -> Result<UnitInfo> {
        self.record("show", unit);
        self.units
            .lock()
            .unwrap()
            .get(unit)
            .cloned()
            .ok_or_else(|| {
                // Mimic systemd's "not-found" loaded state for unknown units.
                Error::provider("systemd", format!("mock: unit {unit} not registered"))
            })
    }
    fn enable(&self, unit: &str) -> Result<()> {
        self.record("enable", unit);
        self.mutate(unit, |i| i.unit_file_state = "enabled".into())
    }
    fn disable(&self, unit: &str) -> Result<()> {
        self.record("disable", unit);
        self.mutate(unit, |i| i.unit_file_state = "disabled".into())
    }
    fn start(&self, unit: &str) -> Result<()> {
        self.record("start", unit);
        self.mutate(unit, |i| {
            i.active_state = "active".into();
            i.sub_state = "running".into();
        })
    }
    fn stop(&self, unit: &str) -> Result<()> {
        self.record("stop", unit);
        self.mutate(unit, |i| {
            i.active_state = "inactive".into();
            i.sub_state = "dead".into();
        })
    }
    fn restart(&self, unit: &str) -> Result<()> {
        self.record("restart", unit);
        self.mutate(unit, |i| {
            i.active_state = "active".into();
            i.sub_state = "running".into();
        })
    }
    fn reload(&self, unit: &str) -> Result<()> {
        self.record("reload", unit);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemctl_show_output() {
        let raw = "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n";
        let info = parse_show(raw);
        assert!(info.is_loaded());
        assert!(info.is_active());
        assert!(info.is_enabled());
    }

    #[test]
    fn handles_static_units() {
        let raw = "LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=static\n";
        let info = parse_show(raw);
        assert!(info.is_static());
        assert!(!info.is_enabled());
    }
}
