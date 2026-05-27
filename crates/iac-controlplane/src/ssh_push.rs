//! Phase 7ck: SSH push deployment.
//!
//! Some targets can't run a long-running pull-mode agent: embedded
//! network gear, vendor appliances, contractor environments where
//! daemon installation is forbidden by policy. The control plane
//! reaches these via SSH push: it pops the next pending assignment
//! addressed to a `kind = 'ssh'` agent, pipes the payload to a
//! remote `iac apply --assignment-stdin` invocation over SSH, parses
//! the JSON result the remote prints, and calls `complete_assignment`.
//!
//! Why we shell out to system `ssh` instead of linking `russh`:
//!   * Same model as the GitOps integration — operators have `ssh`
//!     installed, with `~/.ssh/config`, `known_hosts`, and ssh-agent
//!     already wired up. Reinventing that is needless complexity.
//!   * Static-binary story stays clean: no openssl / libssh2 native
//!     deps, easy cross-compile to musl.
//!   * Inherits the system's already-patched advisory surface; we
//!     don't add a new SSH protocol implementation surface.
//!
//! Trade-off: requires `ssh` on the server box. Containerized
//! deployments need a base image with openssh-client (alpine ships
//! it as a 1-line package).
//!
//! Per-target worker model:
//!   * One Tokio task per SSH target, started at server boot.
//!   * Loop: claim next pending assignment for this target → SSH →
//!     report result. Sleep `poll_interval` between attempts when
//!     there's nothing to do.
//!   * No fan-out within a target: assignments are serialized so a
//!     single dead host can't queue up parallel SSH connections.
//!     Cross-target parallelism is implicit (each task runs
//!     independently in the Tokio scheduler).

use crate::config::{SshHostKeyPolicy, SshTargetConfig};
use crate::store::{AuditRecord, Store};
use iac_core::protocol::v1::{AssignmentPayload, AssignmentResultRequest, AssignmentResultStatus};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Notify;

/// How often a worker re-checks the queue when nothing's pending.
/// Keeping this short (1s) means SSH pushes feel responsive without
/// hammering SQLite — claim_ssh_pending is a single indexed SELECT.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Hard cap on a single push duration. Above this we kill the SSH
/// process and mark the assignment failed. Operators with genuinely
/// long-running applies (large package install) can bump this via
/// future config knob; 5min covers most realistic cases.
const MAX_PUSH_DURATION: Duration = Duration::from_secs(300);

/// Spawn one push worker per configured SSH target. Each worker
/// runs until `shutdown` is notified. Returns the join handles so
/// the server can `await` them on graceful shutdown.
///
/// Production callers use the system `ssh` binary discovered via
/// PATH. Tests override via [`spawn_ssh_workers_with_bin`].
pub fn spawn_ssh_workers(
    store: Store,
    targets: Vec<SshTargetConfig>,
    target_ids: Vec<String>,
    shutdown: Arc<Notify>,
) -> Vec<tokio::task::JoinHandle<()>> {
    spawn_ssh_workers_with_bin(store, targets, target_ids, shutdown, None)
}

/// As [`spawn_ssh_workers`] but takes an explicit `ssh` binary
/// path. `None` falls back to the system `ssh` (looked up via
/// PATH at command-spawn time). Used by integration tests to
/// inject a fake `ssh` shim without mutating process env (which
/// would require unsafe blocks).
pub fn spawn_ssh_workers_with_bin(
    store: Store,
    targets: Vec<SshTargetConfig>,
    target_ids: Vec<String>,
    shutdown: Arc<Notify>,
    ssh_bin: Option<std::path::PathBuf>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let ssh_bin = Arc::new(ssh_bin);
    targets
        .into_iter()
        .zip(target_ids)
        .map(|(target, agent_id)| {
            let store = store.clone();
            let shutdown = shutdown.clone();
            let ssh_bin = ssh_bin.clone();
            tokio::spawn(async move {
                run_worker(store, target, agent_id, shutdown, ssh_bin).await;
            })
        })
        .collect()
}

async fn run_worker(
    store: Store,
    target: SshTargetConfig,
    agent_id: String,
    shutdown: Arc<Notify>,
    ssh_bin: Arc<Option<std::path::PathBuf>>,
) {
    // Phase 7da.1: per-worker TempDir for ControlMaster sockets. The
    // worker pushes many assignments to the same host over time;
    // pooling the SSH session collapses the per-push handshake cost.
    // Lives for the worker's lifetime; cleaned up on shutdown.
    let control_dir = match tempfile::Builder::new()
        .prefix("iac-ssh-push-cp-")
        .tempdir()
    {
        Ok(d) => Some(d),
        Err(e) => {
            tracing::warn!(error = %e, "couldn't create ControlMaster dir; pooling disabled");
            None
        }
    };
    let control_path = control_dir.as_ref().map(|d| d.path().to_path_buf());
    tracing::info!(
        target = %target.name,
        host = %target.host,
        host_key_policy = ?target.host_key_policy,
        control_master = control_path.is_some(),
        "ssh push worker started"
    );
    // Phase 7cp.1: shout about insecure host key policy. Operator
    // had to opt in via config — but a fresh-eyed log line at startup
    // is the last reminder before a daemon-driven push trusts an
    // unknown host on first contact.
    if target.host_key_policy == SshHostKeyPolicy::AcceptNew {
        tracing::warn!(
            target = %target.name,
            host = %target.host,
            "ssh target uses accept-new host-key policy; first push is MITM-able. \
             Pre-populate known_hosts and switch to host_key_policy = \"strict\" \
             before this worker handles real assignments."
        );
    }
    loop {
        // Stop ASAP when shutdown is signaled.
        if let Ok(claim) = tokio::time::timeout(
            IDLE_POLL_INTERVAL,
            wait_for_work(&store, &agent_id, &shutdown),
        )
        .await
        {
            match claim {
                WorkResult::Claimed {
                    assignment_id,
                    payload_json,
                } => {
                    if let Err(e) = process_assignment(
                        &store,
                        &target,
                        &agent_id,
                        &assignment_id,
                        &payload_json,
                        ssh_bin.as_ref().as_ref(),
                        control_path.as_deref(),
                    )
                    .await
                    {
                        tracing::error!(
                            target = %target.name,
                            assignment = %assignment_id,
                            error = %e,
                            "ssh push failed"
                        );
                    }
                }
                WorkResult::Shutdown => break,
                WorkResult::Idle => {}
            }
        }
    }
    tracing::info!(target = %target.name, "ssh push worker stopped");
}

enum WorkResult {
    Claimed {
        assignment_id: String,
        payload_json: String,
    },
    Idle,
    Shutdown,
}

async fn wait_for_work(store: &Store, agent_id: &str, shutdown: &Arc<Notify>) -> WorkResult {
    let target_ids = vec![agent_id.to_string()];
    tokio::select! {
        _ = shutdown.notified() => WorkResult::Shutdown,
        claim = store.claim_ssh_pending(&target_ids) => {
            match claim {
                Ok(Some((id, _agent_id, payload))) => WorkResult::Claimed {
                    assignment_id: id,
                    payload_json: payload,
                },
                Ok(None) => WorkResult::Idle,
                Err(e) => {
                    tracing::warn!(error = %e, "ssh worker queue scan failed");
                    WorkResult::Idle
                }
            }
        }
    }
}

async fn process_assignment(
    store: &Store,
    target: &SshTargetConfig,
    agent_id: &str,
    assignment_id: &str,
    payload_json: &str,
    ssh_bin: Option<&std::path::PathBuf>,
    control_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    // Capabilities allowlist: if non-empty, every kind in the
    // payload must be in the list. Defense in depth — operator
    // setting `capabilities = ["file"]` on a router target ensures
    // an accidentally-routed `package` resource fails before the
    // SSH connection even happens.
    let payload: AssignmentPayload = serde_json::from_str(payload_json)
        .map_err(|e| anyhow::anyhow!("decoding assignment payload: {e}"))?;
    if !target.capabilities.is_empty() {
        for resource in &payload.resources {
            let kind = resource
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            if !target.capabilities.iter().any(|c| c == kind) {
                let msg = format!(
                    "ssh target {} capabilities allowlist rejects kind {kind:?}",
                    target.name
                );
                report_result(
                    store,
                    target,
                    agent_id,
                    assignment_id,
                    AssignmentResultStatus::Failed,
                    &msg,
                )
                .await?;
                return Ok(());
            }
        }
    }

    // Build the ssh command. We pass the assignment payload as JSON
    // on stdin to avoid shell-escaping pitfalls. The remote runs:
    //   <remote_iac_path> apply --assignment-stdin --yes
    // which reads payload JSON from stdin, applies, prints
    // AssignmentResultRequest as JSON to stdout.
    let ssh_program = ssh_bin
        .map(|p| p.as_os_str().to_os_string())
        .unwrap_or_else(|| "ssh".into());
    let mut cmd = Command::new(ssh_program);
    cmd.arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg(host_key_check_arg(target.host_key_policy))
        .arg("-o")
        .arg(format!("ConnectTimeout={}", target.connect_timeout_secs))
        .arg("-p")
        .arg(target.port.to_string());
    if let Some(known) = &target.known_hosts_file {
        cmd.arg("-o")
            .arg(format!("UserKnownHostsFile={}", known.display()));
    }
    // Phase 7da.1: per-worker ControlMaster — every push to this
    // target reuses the same TCP+SSH session, dropping per-push
    // handshake cost from ~500 ms to ~5 ms once the master is up.
    // Long ControlPersist matches the agent's polling cadence.
    if let Some(cp_dir) = control_path {
        cmd.arg("-o")
            .arg("ControlMaster=auto")
            .arg("-o")
            .arg(format!("ControlPath={}/%C", cp_dir.display()))
            .arg("-o")
            .arg("ControlPersist=300s");
    }
    if let Some(key) = &target.identity_file {
        cmd.arg("-i").arg(key);
    }
    cmd.arg(format!("{}@{}", target.user, target.host))
        .arg("--")
        .arg(&target.remote_iac_path)
        .arg("apply")
        .arg("--assignment-stdin")
        .arg("--yes")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawning ssh: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload_json.as_bytes())
            .await
            .map_err(|e| anyhow::anyhow!("writing payload to ssh stdin: {e}"))?;
        // Drop stdin → EOF → remote starts processing.
        drop(stdin);
    }

    // Bound the wait. SSH targets that hang shouldn't pin a worker.
    let output = match tokio::time::timeout(MAX_PUSH_DURATION, child.wait_with_output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            let msg = format!("ssh wait_with_output: {e}");
            report_result(
                store,
                target,
                agent_id,
                assignment_id,
                AssignmentResultStatus::Failed,
                &msg,
            )
            .await?;
            return Ok(());
        }
        Err(_elapsed) => {
            let msg = format!("ssh push exceeded {MAX_PUSH_DURATION:?}; killed");
            // child was killed via kill_on_drop on the timeout's
            // future drop. Mark failure and move on.
            report_result(
                store,
                target,
                agent_id,
                assignment_id,
                AssignmentResultStatus::Failed,
                &msg,
            )
            .await?;
            return Ok(());
        }
    };

    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !status.success() {
        let summary = format!(
            "ssh exit={:?} stderr_tail={}",
            status.code(),
            stderr
                .chars()
                .rev()
                .take(500)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        );
        report_result(
            store,
            target,
            agent_id,
            assignment_id,
            AssignmentResultStatus::Failed,
            &summary,
        )
        .await?;
        return Ok(());
    }

    // Successful exit code → parse the JSON result the remote
    // applier emitted. If it's malformed, mark partial: the SSH
    // succeeded so something probably ran, but we can't trust the
    // verdict.
    match serde_json::from_str::<AssignmentResultRequest>(stdout.trim()) {
        Ok(result) => {
            // Phase 7dg: stage the SSH-push audit alongside the
            // status transition (same tx) so observers waiting for
            // operation-terminal can't race ahead of the audit row.
            // We preserve the per-item detail the remote applier
            // reported (unlike `report_result`, which is for cases
            // where we have no items because something went wrong
            // before the remote even ran).
            let actor = format!("ssh-push:{}", target.name);
            let extra = build_push_audit(target, &actor, agent_id, assignment_id, &result.status);
            store
                .complete_assignment_with_extra_audit(agent_id, assignment_id, &result, Some(extra))
                .await?;
        }
        Err(e) => {
            let summary = format!(
                "ssh exited 0 but result JSON malformed: {e}; stdout_tail={}",
                stdout
                    .chars()
                    .rev()
                    .take(500)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            );
            report_result(
                store,
                target,
                agent_id,
                assignment_id,
                AssignmentResultStatus::PartiallyApplied,
                &summary,
            )
            .await?;
        }
    }
    Ok(())
}

/// Phase 7cp.1: render the `StrictHostKeyChecking=...` value
/// matching the policy. Centralized so the call sites can't drift.
fn host_key_check_arg(policy: SshHostKeyPolicy) -> String {
    match policy {
        SshHostKeyPolicy::Strict => "StrictHostKeyChecking=yes".into(),
        SshHostKeyPolicy::AcceptNew => "StrictHostKeyChecking=accept-new".into(),
    }
}

async fn report_result(
    store: &Store,
    target: &SshTargetConfig,
    agent_id: &str,
    assignment_id: &str,
    status: AssignmentResultStatus,
    summary: &str,
) -> anyhow::Result<()> {
    let req = AssignmentResultRequest {
        status,
        items: vec![],
        summary: Some(summary.to_string()),
    };
    // Phase 7dg: status transition + ssh.push audit commit in one
    // tx — closes the race where `wait_terminal` could observe
    // the operation finishing before the audit row landed.
    // `AuditRecord<'a>` borrows its `actor` field, so the caller
    // owns the formatted string for the duration of the call.
    let actor = format!("ssh-push:{}", target.name);
    let extra = build_push_audit(target, &actor, agent_id, assignment_id, &req.status);
    store
        .complete_assignment_with_extra_audit(agent_id, assignment_id, &req, Some(extra))
        .await?;
    Ok(())
}

/// Phase 7dg: shared `ssh.push_*` audit-record builder. The caller
/// owns `actor` (typically `"ssh-push:<target.name>"`) — we borrow
/// it because `AuditRecord<'a>` is a thin borrowed view.
fn build_push_audit<'a>(
    target: &'a SshTargetConfig,
    actor: &'a str,
    agent_id: &'a str,
    assignment_id: &'a str,
    status: &AssignmentResultStatus,
) -> AuditRecord<'a> {
    let kind = match status {
        AssignmentResultStatus::Succeeded => "ssh.push_succeeded",
        AssignmentResultStatus::PartiallyApplied => "ssh.push_partial",
        AssignmentResultStatus::Failed => "ssh.push_failed",
    };
    let severity = match status {
        AssignmentResultStatus::Succeeded => "info",
        _ => "warning",
    };
    AuditRecord::new(actor, kind)
        .agent(agent_id)
        .severity(severity)
        .payload(serde_json::json!({
            "assignment_id": assignment_id,
            "target": target.name,
            "host": target.host,
        }))
}
