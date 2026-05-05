// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Docker backend trait + real CLI implementation + in-memory mock for tests.
//!
//! We shell out to the `docker` CLI rather than depend on a Docker SDK. That
//! keeps the dep tree small, avoids pulling a TLS stack in for IPC, and gives
//! the operator a clear breadcrumb in process listings.

use super::spec::{DockerContainerSpec, RestartPolicy};
use iac_core::{Error, Result};
use std::collections::HashMap;
use crate::subprocess::run_with_status;
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.6: per-operation timeouts. `docker inspect` /
// `image_id` should respond near-instantly; `docker pull` can
// take many minutes for large images on slow networks; `docker
// run` and `rm` are quick. Pick the longest cap for `pull`,
// shorter for everything else so a misbehaving daemon (lock
// contention, hung healthcheck) surfaces quickly.
const DOCKER_FAST_TIMEOUT: Duration = Duration::from_secs(60);
const DOCKER_PULL_TIMEOUT: Duration = Duration::from_secs(600);
use std::sync::Mutex;

/// Snapshot of a container as observed via `docker inspect`. `None` from
/// `inspect_container` means the container does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub running: bool,
    pub status: String,
    /// `.Config.Image` — the reference (e.g. `nginx:1.27`) the container was started with.
    pub image_ref: String,
    /// `.Image` — the image content digest (`sha256:...`).
    pub image_id: String,
    /// `KEY=VALUE` lines from `.Config.Env`.
    pub env: Vec<String>,
    /// Normalized `host:container[/proto]` strings derived from `.HostConfig.PortBindings`.
    pub ports: Vec<String>,
    pub restart_policy: String,
    /// Phase 7ax: `.Config.Labels` flattened to `KEY=VALUE` lines so the
    /// diff path can reuse the existing subset comparison helper. Docker
    /// auto-injects `org.opencontainers.image.*` labels from the image
    /// itself; subset comparison ignores those.
    pub labels: Vec<String>,
    /// Phase 7ay: `.Config.Cmd`. `None` means "image default CMD"
    /// (i.e., the operator hasn't overridden it via the spec); a
    /// `Some(empty)` is impossible in practice but the spec layer
    /// rejects it explicitly.
    pub command: Option<Vec<String>>,
    /// Phase 7az: `.Config.Healthcheck`. `None` means the container
    /// has no healthcheck configured (whether inherited from the image
    /// or explicitly disabled). The diff path only acts on this when
    /// the spec declares `healthcheck:`; `None` desired never claims
    /// drift against image-default observed.
    pub healthcheck: Option<ContainerHealthcheck>,
    /// Phase 7ba: normalized `source:destination[:ro]` strings parsed
    /// from `.Mounts[]`. Sorted so observe output is canonical.
    pub volumes: Vec<String>,
    /// Phase 7bb: every network the container is currently attached to,
    /// extracted from `.NetworkSettings.Networks` keys. Sorted. The
    /// diff path checks set-equality with the singleton `[spec.network]`
    /// when the operator declared one; otherwise no comparison.
    pub networks: Vec<String>,
    /// Phase 7bo: target paths from `.HostConfig.Tmpfs` (a docker-inspect
    /// object whose keys are container paths and values are mount-options
    /// strings). Sorted. The diff path matches the desired tmpfs target
    /// set against this. Options strings (`size=64m,rw`) are not yet
    /// compared — too noisy and most operators don't care; if they do
    /// later, extend ContainerInfo to store the parsed options too.
    pub tmpfs_mounts: Vec<String>,
}

/// Phase 7az: parsed `.Config.Healthcheck` fields. Durations are kept
/// as total seconds (Docker reports nanoseconds; we normalize for
/// straightforward comparison against the spec's seconds-form
/// duration string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHealthcheck {
    /// CMD-SHELL command — the second element of `Test` when the first
    /// is `"CMD-SHELL"`. `None` for `["CMD", argv...]` form (which we
    /// don't support yet) or `["NONE"]`.
    pub command: Option<String>,
    pub interval_secs: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub retries: Option<u32>,
}

pub trait DockerBackend: Send + Sync + std::fmt::Debug {
    /// Return Some(info) if the container exists, None otherwise.
    fn inspect_container(&self, name: &str) -> Result<Option<ContainerInfo>>;
    /// Return the local image digest for `image`, or None if not pulled.
    fn image_id(&self, image: &str) -> Result<Option<String>>;
    fn pull(&self, image: &str) -> Result<()>;
    fn run(&self, spec: &DockerContainerSpec) -> Result<()>;
    fn stop(&self, name: &str) -> Result<()>;
    fn remove(&self, name: &str, force: bool) -> Result<()>;
    /// Phase 7bm: attach a running container to an additional network.
    /// Used post-`run` for each `spec.extra_networks` entry. The primary
    /// `--network` flag at create time still goes through `run`. Default
    /// impl is `Ok(())` so existing test backends that don't implement
    /// it keep compiling — but the real `DockerCli` overrides this.
    fn connect_network(&self, _container: &str, _network: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct DockerCli;

impl DockerCli {
    fn run_capture(args: &[&str]) -> Result<(bool, String, String)> {
        Self::run_capture_with_timeout(args, DOCKER_FAST_TIMEOUT)
    }

    fn run_capture_with_timeout(
        args: &[&str],
        timeout: Duration,
    ) -> Result<(bool, String, String)> {
        let mut cmd = Command::new("docker");
        cmd.args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Phase 7dh.10: routed through shared wrapper for unified
        // truncation + transport-error mapping.
        run_with_status(
            cmd,
            b"",
            timeout,
            "docker",
            &format!("docker {args:?}"),
        )
    }
}

impl DockerBackend for DockerCli {
    fn inspect_container(&self, name: &str) -> Result<Option<ContainerInfo>> {
        let (ok, stdout, stderr) =
            Self::run_capture(&["inspect", "--type", "container", "--format", "{{json .}}", name])?;
        if !ok {
            // `No such object` is the canonical "doesn't exist" case.
            if stderr.contains("No such") {
                return Ok(None);
            }
            return Err(Error::provider(
                "docker",
                format!("inspect {name} failed: {}", stderr.trim()),
            ));
        }
        let line = stdout.lines().next().unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| Error::provider("docker", format!("parsing inspect json: {e}")))?;
        Ok(Some(parse_inspect_json(&v)))
    }

    fn image_id(&self, image: &str) -> Result<Option<String>> {
        let (ok, stdout, stderr) =
            Self::run_capture(&["inspect", "--type", "image", "--format", "{{.Id}}", image])?;
        if !ok {
            if stderr.contains("No such") {
                return Ok(None);
            }
            return Err(Error::provider(
                "docker",
                format!("image inspect {image} failed: {}", stderr.trim()),
            ));
        }
        let id = stdout.trim();
        if id.is_empty() {
            Ok(None)
        } else {
            Ok(Some(id.to_string()))
        }
    }

    fn pull(&self, image: &str) -> Result<()> {
        // Phase 7di.6.6: pull gets the long timeout — image fetch
        // over a slow network is the realistic worst case.
        let (ok, _stdout, stderr) =
            Self::run_capture_with_timeout(&["pull", image], DOCKER_PULL_TIMEOUT)?;
        if !ok {
            return Err(Error::provider(
                "docker",
                format!("pull {image} failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }

    fn run(&self, spec: &DockerContainerSpec) -> Result<()> {
        let mut args: Vec<String> = vec![
            "run".into(),
            "--detach".into(),
            "--name".into(),
            spec.name.clone(),
            "--restart".into(),
            spec.restart_policy.as_docker().to_string(),
        ];
        for (k, v) in &spec.env {
            args.push("--env".into());
            args.push(format!("{k}={v}"));
        }
        for p in &spec.ports {
            args.push("--publish".into());
            args.push(p.clone());
        }
        // Phase 7ba: --volume host:container[:ro] per declared mount.
        for vol in &spec.volumes {
            args.push("--volume".into());
            args.push(vol.clone());
        }
        // Phase 7bn: --mount type=...,source=...,target=...[,readonly]
        // for each long-form entry. Validated upstream so unwraps are
        // safe for the bind/volume cases. tmpfs entries skip `source`.
        for m in &spec.mounts {
            args.push("--mount".into());
            args.push(super::spec::mount_to_cli_arg(m));
        }
        // Phase 7bb: --network <name>. Only the primary network is set
        // at create time; multi-network operators need `docker network
        // connect` post-create (not yet modeled).
        if let Some(net) = &spec.network {
            args.push("--network".into());
            args.push(net.clone());
        }
        // Phase 7ax: --label key=value per declared label.
        for (k, v) in &spec.labels {
            args.push("--label".into());
            args.push(format!("{k}={v}"));
        }
        // Phase 7az: --health-* flags. Only emit when the operator
        // declared a healthcheck block; otherwise leave the image's
        // default in place.
        if let Some(hc) = &spec.healthcheck {
            args.push("--health-cmd".into());
            args.push(hc.command.clone());
            if let Some(s) = &hc.interval {
                args.push("--health-interval".into());
                args.push(s.clone());
            }
            if let Some(s) = &hc.timeout {
                args.push("--health-timeout".into());
                args.push(s.clone());
            }
            if let Some(r) = hc.retries {
                args.push("--health-retries".into());
                args.push(r.to_string());
            }
        }
        let image = spec
            .image
            .as_deref()
            .ok_or_else(|| Error::provider("docker", "run requires image"))?;
        args.push(image.to_string());
        // Phase 7ay: append CMD-override args AFTER the image. Docker's
        // run syntax is `docker run [opts] IMAGE [ARGS...]`. Each `arg`
        // is one argv slot — no shell parsing.
        if let Some(cmd) = &spec.command {
            for arg in cmd {
                args.push(arg.clone());
            }
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let (ok, _stdout, stderr) = Self::run_capture(&argv)?;
        if !ok {
            return Err(Error::provider(
                "docker",
                format!("run {} failed: {}", spec.name, stderr.trim()),
            ));
        }
        Ok(())
    }

    fn stop(&self, name: &str) -> Result<()> {
        let (ok, _stdout, stderr) = Self::run_capture(&["stop", "-t", "10", name])?;
        if !ok {
            // Stopping a non-existent container is fine for our caller.
            if stderr.contains("No such") {
                return Ok(());
            }
            return Err(Error::provider(
                "docker",
                format!("stop {name} failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }

    fn remove(&self, name: &str, force: bool) -> Result<()> {
        let mut argv: Vec<&str> = vec!["rm"];
        if force {
            argv.push("-f");
        }
        argv.push(name);
        let (ok, _stdout, stderr) = Self::run_capture(&argv)?;
        if !ok {
            if stderr.contains("No such") {
                return Ok(());
            }
            return Err(Error::provider(
                "docker",
                format!("rm {name} failed: {}", stderr.trim()),
            ));
        }
        Ok(())
    }

    fn connect_network(&self, container: &str, network: &str) -> Result<()> {
        let (ok, _stdout, stderr) =
            Self::run_capture(&["network", "connect", network, container])?;
        if !ok {
            // Idempotency: docker errors with "is already attached to network"
            // (or similar) when the container is already on the network. Treat
            // as success so reapply doesn't churn.
            let s = stderr.to_lowercase();
            if s.contains("already") {
                return Ok(());
            }
            return Err(Error::provider(
                "docker",
                format!(
                    "network connect {network} {container} failed: {}",
                    stderr.trim()
                ),
            ));
        }
        Ok(())
    }
}

pub fn parse_inspect_json(v: &serde_json::Value) -> ContainerInfo {
    let state = v.get("State");
    let running = state
        .and_then(|s| s.get("Running"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let status = state
        .and_then(|s| s.get("Status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let image_ref = v
        .pointer("/Config/Image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let image_id = v
        .get("Image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let env: Vec<String> = v
        .pointer("/Config/Env")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let restart_policy = v
        .pointer("/HostConfig/RestartPolicy/Name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("no")
        .to_string();
    let ports = parse_port_bindings(v.pointer("/HostConfig/PortBindings"));
    // Phase 7ax: flatten `.Config.Labels` (object with string values) into
    // sorted `KEY=VALUE` lines. Sort so `parse_inspect_json` returns a
    // canonical form independent of JSON object ordering.
    let mut labels: Vec<String> = v
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| val.as_str().map(|v| format!("{k}={v}")))
                .collect()
        })
        .unwrap_or_default();
    labels.sort();
    // Phase 7ay: `.Config.Cmd` is `null | []` for "use image default" or a
    // non-empty array of argv strings. Docker reports `null` when the
    // container started with the image's CMD, and an explicit array when
    // the operator overrode it. Encode that as `None | Some(non-empty)`.
    let command: Option<Vec<String>> = v
        .pointer("/Config/Cmd")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());
    let healthcheck = parse_healthcheck(v.pointer("/Config/Healthcheck"));
    let volumes = parse_mounts(v.get("Mounts"));
    let mut networks: Vec<String> = v
        .pointer("/NetworkSettings/Networks")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    networks.sort();
    // Phase 7bo: tmpfs targets from `.HostConfig.Tmpfs`. Docker reports
    // this as `{"/path": "rw,size=65536k", ...}`; we keep just the keys
    // (target paths) and ignore options for the diff comparison.
    let mut tmpfs_mounts: Vec<String> = v
        .pointer("/HostConfig/Tmpfs")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    tmpfs_mounts.sort();
    ContainerInfo {
        running,
        status,
        image_ref,
        image_id,
        env,
        ports,
        restart_policy,
        labels,
        command,
        healthcheck,
        volumes,
        networks,
        tmpfs_mounts,
    }
}

/// Phase 7ba: parse `.Mounts[]` into normalized `source:destination[:ro]`
/// strings. Each entry has `Type` (`bind` | `volume`), `Source`,
/// `Destination`, and `RW: true|false`. We canonicalize:
///
///   * bind:    `/host/path:/container/path[:ro]`
///   * volume:  `volname:/container/path[:ro]`
///
/// Sort the result so the observe output is deterministic regardless
/// of Docker's iteration order.
fn parse_mounts(v: Option<&serde_json::Value>) -> Vec<String> {
    let Some(arr) = v.and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for m in arr {
        // For bind mounts, `Source` is an absolute host path. For named
        // volumes, `Name` carries the volume name and `Source` is the
        // resolved /var/lib/docker path — operators care about the name,
        // not the resolved path.
        let kind = m
            .get("Type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let source = match kind {
            "volume" => m
                .get("Name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            _ => m
                .get("Source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        };
        let dest = m
            .get("Destination")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let rw = m
            .get("RW")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if source.is_empty() || dest.is_empty() {
            continue;
        }
        out.push(super::spec::normalize_volume_spec(source, dest, !rw));
    }
    out.sort();
    out
}

/// Phase 7az: extract the healthcheck block from `.Config.Healthcheck`.
/// Returns `None` when absent, `["NONE"]` (operator-disabled), or
/// non-CMD-SHELL Test form (we don't support argv form yet — silently
/// drop into `None` so the diff path doesn't claim drift on what we
/// can't represent).
fn parse_healthcheck(v: Option<&serde_json::Value>) -> Option<ContainerHealthcheck> {
    let v = v?;
    if v.is_null() {
        return None;
    }
    let test = v.get("Test").and_then(serde_json::Value::as_array)?;
    let kind = test.first().and_then(serde_json::Value::as_str)?;
    let command = match kind {
        "CMD-SHELL" => test
            .get(1)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        // CMD argv form / NONE — we don't model these explicitly. Surface
        // the rest of the block (interval/timeout/retries) anyway so
        // the diff path can warn on a partially-renderable healthcheck.
        _ => None,
    };
    let interval_secs = v
        .get("Interval")
        .and_then(serde_json::Value::as_u64)
        .filter(|n| *n > 0)
        .map(|ns| ns / 1_000_000_000);
    let timeout_secs = v
        .get("Timeout")
        .and_then(serde_json::Value::as_u64)
        .filter(|n| *n > 0)
        .map(|ns| ns / 1_000_000_000);
    let retries = v
        .get("Retries")
        .and_then(serde_json::Value::as_u64)
        .filter(|n| *n > 0)
        .and_then(|n| u32::try_from(n).ok());
    Some(ContainerHealthcheck {
        command,
        interval_secs,
        timeout_secs,
        retries,
    })
}

/// `.HostConfig.PortBindings` is `{"<container>/<proto>": [{"HostIp":"","HostPort":"<host>"}]}`.
/// Normalize into the same `host:container[/proto]` form we accept in spec.
fn parse_port_bindings(v: Option<&serde_json::Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(v) = v else { return out };
    let Some(map) = v.as_object() else { return out };
    for (key, bindings) in map {
        // key is "container/proto", e.g. "80/tcp".
        let (container, proto) = match key.split_once('/') {
            Some((c, p)) => (c, p),
            None => (key.as_str(), "tcp"),
        };
        let Some(arr) = bindings.as_array() else { continue };
        for b in arr {
            let host_ip = b.get("HostIp").and_then(serde_json::Value::as_str).unwrap_or("");
            let host_port = b.get("HostPort").and_then(serde_json::Value::as_str).unwrap_or("");
            if host_port.is_empty() {
                continue;
            }
            let s = if host_ip.is_empty() || host_ip == "0.0.0.0" {
                format!("{host_port}:{container}/{proto}")
            } else {
                format!("{host_ip}:{host_port}:{container}/{proto}")
            };
            out.push(s);
        }
    }
    out.sort();
    out
}

/// Best-effort: when comparing observed ports against desired, normalize
/// "8080:80" (no proto) to "8080:80/tcp" so Docker's auto-tcp doesn't show
/// as a diff.
pub fn normalize_port_spec(p: &str) -> String {
    if p.contains('/') {
        p.to_string()
    } else {
        format!("{p}/tcp")
    }
}

// ---- mock ------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct MockContainer {
    pub running: bool,
    pub image_ref: String,
    pub image_id: String,
    pub env: Vec<String>,
    pub ports: Vec<String>,
    pub restart_policy: String,
    /// Phase 7ax: `KEY=VALUE` lines, sorted to match the real-docker
    /// path's output canonicalization.
    pub labels: Vec<String>,
    /// Phase 7ay: argv override. `None` mirrors real Docker's "image
    /// default CMD" reporting.
    pub command: Option<Vec<String>>,
    /// Phase 7az: healthcheck snapshot.
    pub healthcheck: Option<ContainerHealthcheck>,
    /// Phase 7ba: normalized mount strings.
    pub volumes: Vec<String>,
    /// Phase 7bb: attached networks (sorted).
    pub networks: Vec<String>,
    /// Phase 7bo: tmpfs target paths declared in spec.mounts. Mirrors
    /// what real docker would store under `.HostConfig.Tmpfs`. Sorted.
    pub tmpfs_mounts: Vec<String>,
}

#[derive(Debug, Default)]
pub struct MockDocker {
    pub containers: Mutex<HashMap<String, MockContainer>>,
    /// `image_ref` → digest. `pull` returns existing digest or generates one.
    pub images: Mutex<HashMap<String, String>>,
    pub calls: Mutex<Vec<String>>,
}

impl MockDocker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub fn set_image_digest(&self, image: &str, digest: &str) {
        self.images.lock().unwrap().insert(image.to_string(), digest.to_string());
    }

    fn record(&self, action: &str, target: &str) {
        self.calls.lock().unwrap().push(format!("{action} {target}"));
    }

    fn ensure_image(&self, image: &str) -> String {
        let mut images = self.images.lock().unwrap();
        images
            .entry(image.to_string())
            .or_insert_with(|| format!("sha256:mock-{}", image.replace([':', '/'], "_")))
            .clone()
    }
}

impl DockerBackend for MockDocker {
    fn inspect_container(&self, name: &str) -> Result<Option<ContainerInfo>> {
        self.record("inspect", name);
        let g = self.containers.lock().unwrap();
        Ok(g.get(name).map(|c| ContainerInfo {
            running: c.running,
            status: if c.running { "running".into() } else { "exited".into() },
            image_ref: c.image_ref.clone(),
            image_id: c.image_id.clone(),
            env: c.env.clone(),
            ports: c.ports.clone(),
            restart_policy: c.restart_policy.clone(),
            labels: c.labels.clone(),
            command: c.command.clone(),
            healthcheck: c.healthcheck.clone(),
            volumes: c.volumes.clone(),
            networks: c.networks.clone(),
            tmpfs_mounts: c.tmpfs_mounts.clone(),
        }))
    }

    fn image_id(&self, image: &str) -> Result<Option<String>> {
        self.record("image_id", image);
        Ok(self.images.lock().unwrap().get(image).cloned())
    }

    fn pull(&self, image: &str) -> Result<()> {
        self.record("pull", image);
        self.ensure_image(image);
        Ok(())
    }

    fn run(&self, spec: &DockerContainerSpec) -> Result<()> {
        self.record("run", &spec.name);
        let image = spec.image.clone().unwrap_or_default();
        let digest = self.ensure_image(&image);
        let env = super::spec::env_kv(&spec.env);
        let ports: Vec<String> = spec.ports.iter().map(|p| normalize_port_spec(p)).collect();
        let restart_policy = match spec.restart_policy {
            RestartPolicy::No => "no",
            RestartPolicy::Always => "always",
            RestartPolicy::UnlessStopped => "unless-stopped",
            RestartPolicy::OnFailure => "on-failure",
        }
        .to_string();
        let mut labels: Vec<String> =
            spec.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        labels.sort();
        // Phase 7ay: clone the spec's command into MockContainer so the
        // observe path returns the same Option<Vec<String>> shape the
        // real-docker path produces.
        let command = spec.command.clone();
        // Phase 7az: same for healthcheck — convert the spec's
        // duration strings into seconds so the mock-vs-real comparison
        // is canonical.
        let healthcheck = spec.healthcheck.as_ref().map(|hc| ContainerHealthcheck {
            command: Some(hc.command.clone()),
            interval_secs: hc
                .interval
                .as_deref()
                .and_then(|s| super::spec::parse_health_duration_secs(s).ok()),
            timeout_secs: hc
                .timeout
                .as_deref()
                .and_then(|s| super::spec::parse_health_duration_secs(s).ok()),
            retries: hc.retries,
        });
        // Phase 7ba: normalize each spec volume into the same canonical
        // form the real-docker path produces from `.Mounts[]`. Sort so
        // the mock observe output matches the real one byte-for-byte.
        // Phase 7bn: long-form `mounts` entries that have a short-form
        // equivalent (bind/volume) get folded into the same set so the
        // mock reflects what real docker would observe after `docker
        // run --mount ...`. Tmpfs mounts have no short form — they
        // don't appear in `volumes` and don't affect this comparison.
        let mut volumes: Vec<String> = spec
            .volumes
            .iter()
            .filter_map(|s| {
                let (src, dst, ro) = super::spec::parse_volume_spec(s).ok()?;
                Some(super::spec::normalize_volume_spec(src, dst, ro))
            })
            .chain(spec.mounts.iter().filter_map(super::spec::mount_to_short_form))
            .collect();
        volumes.sort();
        // Phase 7bb: track the primary network as a singleton list to
        // mirror the real-docker `.NetworkSettings.Networks` shape.
        // `None` defaults to ["bridge"], matching what real Docker
        // attaches a no-`--network` container to.
        let networks = match &spec.network {
            Some(n) => vec![n.clone()],
            None => vec!["bridge".to_string()],
        };
        // Phase 7bo: tmpfs target paths derived from spec.mounts entries
        // of type=tmpfs. Mirrors what real docker stores under
        // `.HostConfig.Tmpfs`. Sorted to match the parse_inspect_json
        // canonical form.
        let mut tmpfs_mounts: Vec<String> = spec
            .mounts
            .iter()
            .filter(|m| m.r#type == "tmpfs")
            .map(|m| m.target.clone())
            .collect();
        tmpfs_mounts.sort();
        self.containers.lock().unwrap().insert(
            spec.name.clone(),
            MockContainer {
                running: true,
                image_ref: image,
                image_id: digest,
                env,
                ports,
                restart_policy,
                labels,
                command,
                healthcheck,
                volumes,
                networks,
                tmpfs_mounts,
            },
        );
        Ok(())
    }

    fn stop(&self, name: &str) -> Result<()> {
        self.record("stop", name);
        if let Some(c) = self.containers.lock().unwrap().get_mut(name) {
            c.running = false;
        }
        Ok(())
    }

    fn remove(&self, name: &str, _force: bool) -> Result<()> {
        self.record("remove", name);
        self.containers.lock().unwrap().remove(name);
        Ok(())
    }

    fn connect_network(&self, container: &str, network: &str) -> Result<()> {
        self.record("connect_network", &format!("{container} {network}"));
        if let Some(c) = self.containers.lock().unwrap().get_mut(container) {
            // Idempotent — match the real CLI path's behavior. A
            // duplicate `connect` is treated as success, no second entry.
            if !c.networks.iter().any(|n| n == network) {
                c.networks.push(network.to_string());
                c.networks.sort();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_inspect_json() {
        let raw = json!({
            "Image": "sha256:abc",
            "State": { "Running": true, "Status": "running" },
            "Config": {
                "Image": "nginx:1.27",
                "Env": ["PATH=/usr/bin", "FOO=bar"],
            },
            "HostConfig": {
                "RestartPolicy": { "Name": "unless-stopped" },
                "PortBindings": {
                    "80/tcp": [{ "HostIp": "", "HostPort": "8080" }],
                    "443/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "8443" }]
                }
            }
        });
        let info = parse_inspect_json(&raw);
        assert!(info.running);
        assert_eq!(info.image_ref, "nginx:1.27");
        assert_eq!(info.image_id, "sha256:abc");
        assert_eq!(info.env, vec!["PATH=/usr/bin", "FOO=bar"]);
        assert_eq!(info.restart_policy, "unless-stopped");
        // Sorted, so 127.0.0.1 binding comes first.
        assert_eq!(
            info.ports,
            vec!["127.0.0.1:8443:443/tcp", "8080:80/tcp"]
        );
    }

    // Phase 7bo: tmpfs round-trip through observe + diff.

    #[test]
    fn parses_tmpfs_targets_from_inspect_host_config() {
        let raw = json!({
            "Image": "sha256:abc",
            "State": { "Running": true, "Status": "running" },
            "Config": { "Image": "nginx:1.27" },
            "HostConfig": {
                "RestartPolicy": { "Name": "no" },
                "Tmpfs": {
                    "/cache": "size=64m,rw",
                    "/run": ""
                }
            }
        });
        let info = parse_inspect_json(&raw);
        // Sorted; we drop the options string and keep just the targets.
        assert_eq!(info.tmpfs_mounts, vec!["/cache", "/run"]);
    }

    #[test]
    fn missing_tmpfs_object_yields_empty_list() {
        let raw = json!({
            "Image": "sha256:abc",
            "State": { "Running": true, "Status": "running" },
            "Config": { "Image": "nginx:1.27" },
            "HostConfig": { "RestartPolicy": { "Name": "no" } }
        });
        let info = parse_inspect_json(&raw);
        assert!(info.tmpfs_mounts.is_empty());
    }
}
