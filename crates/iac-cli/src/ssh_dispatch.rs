//! SSH transport primitives shared between the operator-facing
//! commands that talk to remote hosts:
//!   * `iac apply --ssh user@host` (Phase 7cl)
//!   * `iac apply --inventory inv.yaml --group <name>` (Phase 7cm)
//!   * `iac run --inventory inv.yaml -- '<cmd>'` (Phase 7cn)
//!
//! All three converge on the same wire format: pipe an
//! `AssignmentPayload` (or a raw shell command) to a remote
//! `iac apply --assignment-stdin` invocation, parse the result.
//!
//! Why this is its own module:
//!   * Keeps `main.rs` from growing unbounded as we add more SSH-
//!     using subcommands.
//!   * Makes the SSH machinery unit-testable in isolation
//!     (parameter parsing, exit-code mapping, error renderring).
//!   * Concentrates the "we shell out to system ssh on purpose"
//!     architecture decision into one place — same model as the
//!     gitops module.
//!
//! Why we don't link `russh` or similar:
//!   * Operators have `~/.ssh/config`, `known_hosts`, ssh-agent,
//!     `GIT_SSH_COMMAND`, GitHub-Actions GITHUB_TOKEN semantics
//!     already wired into their environment. Reinventing that is
//!     needless code + advisory surface.
//!   * Static-binary story stays clean (no openssl/libssh2 native
//!     deps; cross-compile to musl works trivially).

use anyhow::{Context, Result};
use iac_core::protocol::v1::{
    AssignmentPayload, AssignmentResultRequest, AssignmentResultStatus,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One SSH target — `user@host:port` plus auth + remote-binary
/// hints. Matches the per-host shape an inventory file describes
/// (Phase 7cm).
#[derive(Debug, Clone)]
pub struct SshTarget {
    /// Display label. Used in stdout/stderr prefixes when fanning
    /// out across many hosts. Defaults to `user@host` if no label
    /// was supplied (e.g. CLI-only `--ssh user@host` form).
    pub label: String,
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
    /// Path to the remote `iac` binary. `None` triggers a `command -v iac`
    /// probe + auto-bootstrap fallback (Phase 7cl-followup).
    pub remote_iac: Option<String>,
    /// Phase 7da.1: ControlMaster socket directory. When set, every
    /// `ssh`/`scp` invocation to this target shares one TCP+SSH
    /// session, dropping per-command cost from ~500 ms to ~5 ms.
    /// `None` disables pooling (one fresh session per command —
    /// the pre-7da.1 behaviour). The dispatcher sets this once at
    /// the start of a multi-command run; callers don't touch it.
    pub control_dir: Option<PathBuf>,
}

impl SshTarget {
    /// Parse an `[user@]host[:port]` form into the structured target.
    /// `--ssh-key` / `--ssh-port` from the CLI override the defaults
    /// if supplied separately.
    pub fn parse(spec: &str) -> Result<Self> {
        let (user, host) = match spec.split_once('@') {
            Some((u, h)) => (u.to_string(), h.to_string()),
            None => (
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "root".into()),
                spec.to_string(),
            ),
        };
        // Allow `host:port` form. SSH accepts brackets for IPv6
        // (`[::1]:22`); we punt on full IPv6 parsing for now and
        // tell operators to use `--ssh-port` instead.
        let (host, port) = match host.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && !h.contains('[') => {
                let port: u16 = p
                    .parse()
                    .with_context(|| format!("invalid port {p:?} in {spec:?}"))?;
                (h.to_string(), port)
            }
            _ => (host, 22),
        };
        if host.is_empty() {
            anyhow::bail!("empty host in {spec:?}");
        }
        Ok(Self {
            label: format!("{user}@{host}"),
            user,
            host,
            port,
            identity_file: None,
            remote_iac: None,
            control_dir: None,
        })
    }

    /// Same as `parse` but also applies CLI overrides for key + port +
    /// remote_iac. Lets callers parse `[user@]host` once and layer the
    /// flag values on top.
    pub fn with_overrides(
        mut self,
        ssh_key: Option<&Path>,
        ssh_port: Option<u16>,
        ssh_remote_iac: Option<&str>,
    ) -> Self {
        if let Some(k) = ssh_key {
            self.identity_file = Some(k.to_path_buf());
        }
        if let Some(p) = ssh_port {
            self.port = p;
        }
        if let Some(r) = ssh_remote_iac {
            self.remote_iac = Some(r.to_string());
        }
        self
    }

    fn user_at_host(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// Augment a `Command` with the standard SSH options + auth +
    /// port. Returns the command ready to take target + remote
    /// invocation arguments.
    pub fn ssh_command(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.arg("-o").arg("BatchMode=yes")
            .arg("-o").arg("StrictHostKeyChecking=accept-new")
            .arg("-o").arg("ConnectTimeout=10")
            .arg("-p").arg(self.port.to_string());
        self.add_control_master_args(&mut cmd);
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd.arg(self.user_at_host());
        cmd
    }

    fn scp_command(&self) -> Command {
        let mut cmd = Command::new("scp");
        cmd.arg("-o").arg("BatchMode=yes")
            .arg("-o").arg("StrictHostKeyChecking=accept-new")
            .arg("-o").arg("ConnectTimeout=10")
            .arg("-P").arg(self.port.to_string());
        self.add_control_master_args(&mut cmd);
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd
    }

    /// Phase 7da.1: append `ControlMaster` options when the dispatcher
    /// has set up a `control_dir`. The `%C` token expands to a hash
    /// of `(user, host, port)` so each unique target gets its own
    /// socket. `ControlPersist=60s` keeps the master alive 60 s after
    /// the last command — long enough that subsequent commands in the
    /// same `iac apply` invocation reuse it, short enough that an
    /// orphaned dispatcher leaves no long-lived sockets behind.
    fn add_control_master_args(&self, cmd: &mut Command) {
        if let Some(dir) = &self.control_dir {
            let path = dir.join("%C");
            cmd.arg("-o").arg("ControlMaster=auto")
                .arg("-o").arg(format!("ControlPath={}", path.display()))
                .arg("-o").arg("ControlPersist=60s");
        }
    }
}

/// Phase 7da.1: SSH connection pool. Owns a `TempDir` for ControlMaster
/// sockets; `apply()` flips a target into pooled mode by setting its
/// `control_dir`. The TempDir lives for the lifetime of the pool —
/// drop it after all SSH dispatch calls complete. The kernel keeps the
/// socket file alive while the master process holds it open, so
/// shorter-lived `ControlPersist` windows don't matter.
///
/// One pool per `iac apply --inventory` / `iac run` invocation: every
/// target shares the same pool dir; the `%C` ControlPath hash
/// distinguishes per-target sockets. Multi-host fan-out gets per-host
/// pooling for free.
pub struct SshConnectionPool {
    /// Held to keep the dir alive; not exposed.
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl SshConnectionPool {
    /// Create a fresh pool. The TempDir is created under the system
    /// temp dir with mode 0700 (tempfile default) so other users
    /// can't peek at the socket file.
    pub fn new() -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("iac-ssh-cp-")
            .tempdir()
            .context("creating SSH ControlMaster temp dir")?;
        let path = dir.path().to_path_buf();
        Ok(Self { _dir: dir, path })
    }

    /// Flip a target into pooled mode. Subsequent `ssh_command()` /
    /// `scp_command()` calls on the target will use ControlMaster.
    pub fn apply_to(&self, target: &mut SshTarget) {
        target.control_dir = Some(self.path.clone());
    }
}

/// Outcome of one SSH apply or run. Generic enough to drive both
/// declarative apply (`AssignmentResultStatus`) and ad-hoc command
/// execution (exit-code-based).
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub label: String,
    pub status: AssignmentResultStatus,
    pub summary: String,
    pub stdout: String,
    pub stderr: String,
}

impl DispatchOutcome {
    pub fn is_terminal_failure(&self) -> bool {
        matches!(self.status, AssignmentResultStatus::Failed)
    }
}

/// Phase 7cl: probe the target for an `iac` binary. Returns the
/// path. When missing, the caller can either bail with an install
/// hint or fall back to `bootstrap_iac_binary` (Phase 7cl-followup).
pub fn probe_remote_iac(target: &SshTarget) -> Result<Option<String>> {
    let mut cmd = target.ssh_command();
    cmd.arg("--").arg("sh -c 'command -v iac || echo MISSING'");
    let output = cmd.output().context("running ssh probe")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ssh probe to {} failed: {stderr}", target.label);
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path == "MISSING" || path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}

/// Phase 7cl-followup: scp the locally-running `iac` binary to the
/// target if architectures match. Caches via sha256 in
/// `/tmp/iac-applier-<sha8>` on the remote so re-pushes skip the
/// upload. Returns the resulting remote path.
///
/// When architectures differ, returns `Err` with a clear message
/// pointing at the curl install one-liner — cross-arch staging is
/// out of scope for v1 (would need bundled multi-arch binaries or
/// a cross-compile toolchain on the dev box).
pub fn bootstrap_iac_binary(target: &SshTarget) -> Result<String> {
    let local_arch = local_arch_uname()?;
    let remote_arch = remote_arch(target)?;
    if local_arch != remote_arch {
        anyhow::bail!(
            "cannot auto-bootstrap iac on {label}: \
             local arch is {local_arch}, target arch is {remote_arch}. \
             Pre-install via:\n\
             \n\
             curl -L https://github.com/<your-fork>/iac/releases/latest/download/iac-{remote_arch} \\\n\
                 | ssh {label} 'sudo tee /usr/local/bin/iac >/dev/null && sudo chmod +x /usr/local/bin/iac'\n\
             \n\
             Or pass --ssh-remote-iac /path/to/iac-on-target if you've already installed it elsewhere.",
            label = target.label,
        );
    }

    // Phase 7cp.2 (security fix #4.5): the binary we're about to ship
    // to root on the target must be intentional. Two layers of opt-in:
    //
    //   1. `IAC_BOOTSTRAP_BINARY_PATH` lets the operator point at a
    //      release artefact downloaded out-of-band (e.g. from GitHub
    //      releases with a verified signature). When unset, we fall
    //      back to `current_exe()` — the running binary — which makes
    //      a poisoned operator dev box a fleet-wide RCE channel.
    //   2. `IAC_BOOTSTRAP_BINARY_SHA256` is the operator's
    //      acknowledgement of *what* is being staged. The function
    //      computes the local sha256 and refuses if it doesn't match.
    //      When unset, we proceed but print the sha256 prominently +
    //      a one-line warning so an unattended `--auto-bootstrap`
    //      run leaves a paper trail.
    //
    // Both env vars together = ergonomic CI: download a pinned
    // release, set both vars, rerun until each target has it.
    let local_iac = match std::env::var("IAC_BOOTSTRAP_BINARY_PATH") {
        Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => local_iac_path()?,
    };
    let sha_full = file_sha256_full(&local_iac)?;
    if let Ok(expected) = std::env::var("IAC_BOOTSTRAP_BINARY_SHA256") {
        let expected = expected.trim().to_lowercase();
        if !expected.is_empty() && expected != sha_full {
            anyhow::bail!(
                "iac bootstrap binary {} sha256 mismatch:\n  expected: {expected}\n    actual: {sha_full}\n\
                 Refusing to ship an unverified binary to {label}.",
                local_iac.display(),
                label = target.label,
            );
        }
    } else {
        eprintln!(
            "[!] auto-bootstrap: about to ship {} (sha256 {}) to {} as {}. \
             Set IAC_BOOTSTRAP_BINARY_SHA256 to suppress this warning + enforce the hash on every push.",
            local_iac.display(),
            sha_full,
            target.label,
            target.user,
        );
    }
    let sha = sha_full[..8].to_string();
    let remote_path = format!("/tmp/iac-applier-{sha}");

    // Skip the upload if the cached binary already exists with the
    // right sha. Operators repeatedly pushing the same dev binary
    // shouldn't pay the scp cost every time.
    let mut check = target.ssh_command();
    check.arg("--").arg(format!(
        "test -x {remote_path} && {remote_path} --version 2>/dev/null"
    ));
    if check
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Ok(remote_path);
    }

    // Upload + chmod. The bash here is portable to busybox sh —
    // network gear and minimal alpine images get covered.
    let mut scp = target.scp_command();
    scp.arg(&local_iac)
        .arg(format!("{}:{remote_path}", target.user_at_host()));
    let scp_output = scp.output().context("scp")?;
    if !scp_output.status.success() {
        anyhow::bail!(
            "scp to {} failed: {}",
            target.label,
            String::from_utf8_lossy(&scp_output.stderr)
        );
    }
    let mut chmod = target.ssh_command();
    chmod
        .arg("--")
        .arg(format!("chmod +x {remote_path}"));
    let chmod_output = chmod.output().context("chmod via ssh")?;
    if !chmod_output.status.success() {
        anyhow::bail!(
            "chmod on {} failed: {}",
            target.label,
            String::from_utf8_lossy(&chmod_output.stderr)
        );
    }

    Ok(remote_path)
}

/// Phase 7cl: ssh-pipe an assignment payload to the remote applier
/// and parse the result. Single-host primitive — fan-out (Phase 7cm)
/// loops over multiple targets calling this.
///
/// Auto-bootstrap behaviour: when `target.remote_iac` is `None`,
/// probes via `command -v iac`. If still missing AND `auto_bootstrap`
/// is true, scp's the local binary. Otherwise returns a clear error
/// with install instructions.
pub fn dispatch_apply(
    target: &SshTarget,
    payload: &AssignmentPayload,
    auto_bootstrap: bool,
) -> Result<DispatchOutcome> {
    let remote_iac = resolve_remote_iac(target, auto_bootstrap)?;

    let payload_str = serde_json::to_string(payload)?;
    let mut cmd = target.ssh_command();
    cmd.arg("--")
        .arg(&remote_iac)
        .arg("apply")
        .arg("--assignment-stdin")
        .arg("--yes")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .context("spawning ssh (is the binary in PATH?)")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .context("ssh process has no stdin handle")?;
        stdin
            .write_all(payload_str.as_bytes())
            .context("piping payload to ssh stdin")?;
    }
    let output = child.wait_with_output().context("ssh process exit")?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Ok(DispatchOutcome {
            label: target.label.clone(),
            status: AssignmentResultStatus::Failed,
            summary: format!(
                "ssh exit={:?}; stderr_tail={}",
                output.status.code(),
                tail_chars(&stderr, 500)
            ),
            stdout,
            stderr,
        });
    }
    let result: AssignmentResultRequest = match serde_json::from_str(stdout.trim()) {
        Ok(r) => r,
        Err(e) => {
            return Ok(DispatchOutcome {
                label: target.label.clone(),
                status: AssignmentResultStatus::PartiallyApplied,
                summary: format!("ssh exited 0 but result JSON malformed: {e}"),
                stdout,
                stderr,
            });
        }
    };
    Ok(DispatchOutcome {
        label: target.label.clone(),
        status: result.status,
        summary: result.summary.unwrap_or_else(|| "(no summary)".into()),
        stdout,
        stderr,
    })
}

/// Phase 7cn: ad-hoc shell command on a target. The command runs
/// under the target's login shell; operators escape quoting per
/// shell convention. Captures stdout/stderr/exit code.
pub fn dispatch_run(
    target: &SshTarget,
    shell_command: &str,
) -> Result<DispatchOutcome> {
    let mut cmd = target.ssh_command();
    cmd.arg("--").arg(shell_command);
    let output = cmd
        .output()
        .with_context(|| format!("ssh to {} for ad-hoc run", target.label))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let status = if output.status.success() {
        AssignmentResultStatus::Succeeded
    } else {
        AssignmentResultStatus::Failed
    };
    let summary = format!("exit={:?}", output.status.code());
    Ok(DispatchOutcome {
        label: target.label.clone(),
        status,
        summary,
        stdout,
        stderr,
    })
}

fn resolve_remote_iac(target: &SshTarget, auto_bootstrap: bool) -> Result<String> {
    if let Some(p) = &target.remote_iac {
        return Ok(p.clone());
    }
    if let Some(p) = probe_remote_iac(target)? {
        return Ok(p);
    }
    if auto_bootstrap {
        return bootstrap_iac_binary(target);
    }
    anyhow::bail!(
        "no `iac` binary found on {target}. Install it once via:\n\
         \n\
         curl -L https://github.com/<your-fork>/iac/releases/latest/download/iac-$(uname -m) \\\n\
             | ssh {target} 'sudo tee /usr/local/bin/iac >/dev/null && sudo chmod +x /usr/local/bin/iac'\n\
         \n\
         Or pass --auto-bootstrap to scp the local binary (when arches match).",
        target = target.label,
    );
}

fn local_arch_uname() -> Result<String> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .context("running local uname -m")?;
    if !output.status.success() {
        anyhow::bail!("local uname -m failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn remote_arch(target: &SshTarget) -> Result<String> {
    let mut cmd = target.ssh_command();
    cmd.arg("--").arg("uname -m");
    let output = cmd
        .output()
        .with_context(|| format!("ssh to {} for uname", target.label))?;
    if !output.status.success() {
        anyhow::bail!(
            "remote uname -m failed on {}: {}",
            target.label,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn local_iac_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating own binary")?;
    Ok(exe)
}

fn file_sha256_full(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening {} for sha256", path.display()))?;
    iac_core::hash::sha256_hex_reader(file)
        .with_context(|| format!("hashing {}", path.display()))
}

fn tail_chars(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    s.chars()
        .rev()
        .take(n)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_at_host() {
        let t = SshTarget::parse("admin@10.0.0.1").unwrap();
        assert_eq!(t.user, "admin");
        assert_eq!(t.host, "10.0.0.1");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn parse_host_only_uses_user_env() {
        let t = SshTarget::parse("10.0.0.1").unwrap();
        assert_eq!(t.host, "10.0.0.1");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn parse_host_with_port() {
        let t = SshTarget::parse("admin@10.0.0.1:2222").unwrap();
        assert_eq!(t.user, "admin");
        assert_eq!(t.host, "10.0.0.1");
        assert_eq!(t.port, 2222);
    }

    #[test]
    fn parse_rejects_empty_host() {
        assert!(SshTarget::parse("admin@").is_err());
    }

    #[test]
    fn overrides_apply_in_order() {
        let t = SshTarget::parse("admin@host")
            .unwrap()
            .with_overrides(
                Some(Path::new("/tmp/key")),
                Some(2222),
                Some("/usr/local/bin/iac"),
            );
        assert_eq!(t.identity_file.as_deref(), Some(Path::new("/tmp/key")));
        assert_eq!(t.port, 2222);
        assert_eq!(t.remote_iac.as_deref(), Some("/usr/local/bin/iac"));
    }

    #[test]
    fn tail_chars_preserves_short_strings() {
        assert_eq!(tail_chars("hello", 100), "hello");
    }

    #[test]
    fn tail_chars_truncates_long() {
        let s: String = (0..1000).map(|i| char::from((i % 26) as u8 + b'a')).collect();
        let tail = tail_chars(&s, 50);
        assert_eq!(tail.len(), 50);
        assert!(s.ends_with(&tail));
    }
}
