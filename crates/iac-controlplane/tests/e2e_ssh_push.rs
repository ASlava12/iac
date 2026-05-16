// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7ck: end-to-end tests for SSH push deployment.
//!
//! We don't spin up a real `sshd` here — that requires root + a
//! container harness. Instead we shadow `ssh` via a per-test
//! temp-dir prepended to PATH inside a child Tokio runtime. The
//! fake `ssh` is a shell script with hardcoded behaviour: succeed,
//! fail, partial, etc. No environment mutation in tests (the
//! workspace forbids unsafe blocks; std::env::set_var is unsafe in
//! the 2024 edition).
//!
//! Coverage:
//! 1. SSH targets land in agents table on server start with kind='ssh'.
//! 2. Submit op routed to ssh target → push worker dispatches →
//!    fake ssh succeeds → assignment + op marked succeeded.
//! 3. Failed SSH (non-zero exit) → assignment marked failed.
//! 4. Capability allowlist rejects disallowed kinds without
//!    invoking ssh.
//! 5. Audit events recorded with target name in actor.
//! 6. Partial result from remote → op partially_applied.

use iac_controlplane::config::SshTargetConfig;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{
    OperationStatus, OperationView, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "ssh-push-admin";

#[derive(Clone, Copy)]
enum FakeSshBehaviour {
    Succeed,
    Fail,
    Partial,
}

/// Build a fake `ssh` shim with hardcoded behaviour. The shim's
/// directory is the only thing we prepend to PATH — done per-process
/// via Command's `env` argument when spawning `ssh`, NOT via
/// std::env::set_var (forbidden by workspace lints).
fn build_fake_ssh(dir: &std::path::Path, behaviour: FakeSshBehaviour) -> PathBuf {
    let path = dir.join("ssh");
    let script: &str = match behaviour {
        FakeSshBehaviour::Succeed => {
            r#"#!/bin/sh
cat >/dev/null
echo '{"status":"succeeded","items":[],"summary":"fake ssh ok"}'
exit 0
"#
        }
        FakeSshBehaviour::Fail => {
            r#"#!/bin/sh
cat >/dev/null
echo "fake ssh: simulated failure" >&2
exit 5
"#
        }
        FakeSshBehaviour::Partial => {
            r#"#!/bin/sh
cat >/dev/null
echo '{"status":"partially_applied","items":[],"summary":"fake ssh partial"}'
exit 0
"#
        }
    };
    std::fs::write(&path, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Wrap `tokio::process::Command::new("ssh", …)` so it picks up the
/// per-test fake from `shim_dir`. We inject this by prepending
/// `shim_dir` to PATH for the *server process* — but the server is
/// in-process, so the easiest knob is: write the fake to a
/// well-known global location, with a name that wins lookup before
/// the system `ssh`. We actually just put the shim_dir at the front
/// of PATH for the entire test process by using std::env::join_paths
/// + the test's own PATH var via a small inherited env.
///
/// Since we can't mutate env, the trick: make the server invoke the
/// shim via PATH ordering that's set by the launching test process'
/// initial environment. Cargo's test harness runs each test in the
/// same process by default, so we set PATH ONCE before any test, by
/// using a `sync::OnceLock` — but that still needs unsafe.
///
/// Workaround: build the fake-ssh shim in `/tmp/iac-ssh-push-tests/`
/// and ensure that's already on PATH. We can manipulate this via a
/// build.rs or just by checking whether $PATH already has it — but
/// the cleanest portable solution is to NOT prepend PATH and
/// instead override `ssh` via a wrapper module.
///
/// Final design: we put the fake-ssh under `/tmp/<unique>/ssh` and
/// the test sets `IAC_SSH_BIN_OVERRIDE` env at process launch. The
/// production `ssh_push.rs` reads this env (only at startup, via
/// `std::env::var`) and uses it instead of bare `ssh`.
fn ensure_path_prefixed(shim_dir: &std::path::Path) {
    // No-op stub — see comment above. We rely on
    // `IAC_SSH_BIN_OVERRIDE` instead.
    let _ = shim_dir;
}

struct TestServer {
    addr: SocketAddr,
    store: Store,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    ssh_shutdown: Arc<Notify>,
    ssh_handles: Vec<tokio::task::JoinHandle<()>>,
    _shim_dir: TempDir,
    _server_dir: TempDir,
}

impl TestServer {
    async fn spawn(targets: Vec<SshTargetConfig>, behaviour: FakeSshBehaviour) -> Self {
        let shim_dir = TempDir::new().unwrap();
        let shim_path = build_fake_ssh(shim_dir.path(), behaviour);
        ensure_path_prefixed(shim_dir.path());

        let dir = TempDir::new().unwrap();
        let db = dir.path().join("server.db");
        // Stamp the fake-ssh path into each target's identity_file
        // field — no, that's auth. Instead use the override knob.
        // We'll set IAC_SSH_BIN inside the targets via remote_iac_path?
        // No, that's the *remote* binary. We need to override the
        // *local* `ssh` invocation.
        //
        // Plan: feed shim_path into a NEW TestServer field and have
        // the worker pool pick it up. But we also can't mutate env.
        //
        // Simplest workaround: create the shim with a non-`ssh`
        // name, then route through it by setting
        // `target.host = "<absolute-path-to-shim>"` — no, that won't
        // work either.
        //
        // OK: rebuild ssh_push to accept a `ssh_bin: Option<PathBuf>`
        // injected at worker spawn time. The production main.rs
        // passes None (uses system ssh); tests pass Some(shim_path).
        let cfg = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: format!("sqlite://{}?mode=rwc", db.display()),
            state_dir: dir.path().to_path_buf(),
            max_body_bytes: 1 << 20,
            admin_token: Some(ADMIN_TOKEN.to_string()),
            policies: vec![],
            retention: iac_controlplane::retention::RetentionConfig::default(),
            rate_limit: iac_controlplane::rate_limit::RateLimitConfig::default(),
            maintenance_windows: vec![],
            recurring_maintenance_windows: vec![],
            webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
            tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: targets.clone(),
            wal_checkpoint_interval_secs: 0,
            shutdown_timeout_secs: 1,
        };
        let store = Store::connect(&cfg.database_url).await.unwrap();

        let mut target_ids = Vec::new();
        for t in &targets {
            let id = store.upsert_ssh_target(&t.name, &t.environment).await.unwrap();
            target_ids.push(id);
        }

        let signer = std::sync::Arc::new(
            iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
        );
        let state = AppState {
            store: store.clone(),
            live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
            signer,
            rate_limiter: Arc::new(iac_controlplane::rate_limit::RateLimiter::from_config(
                &cfg.rate_limit,
            )),
            webhook_dispatcher: None,
            maintenance_metrics: Arc::new(
                iac_controlplane::maintenance::MaintenanceMetrics::default(),
            ),
            secret_registry: None,
        };
        let app = iac_controlplane::server::router(state);
        let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(Notify::new());
        let signal = shutdown.clone();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(async move { signal.notified().await })
                .await
                .unwrap();
        });

        let ssh_shutdown = Arc::new(Notify::new());
        let ssh_handles = iac_controlplane::ssh_push::spawn_ssh_workers_with_bin(
            store.clone(),
            targets,
            target_ids,
            ssh_shutdown.clone(),
            Some(shim_path),
        );

        Self {
            addr,
            store,
            shutdown,
            handle,
            ssh_shutdown,
            ssh_handles,
            _shim_dir: shim_dir,
            _server_dir: dir,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        self.ssh_shutdown.notify_waiters();
        // Abort instead of awaiting graceful shutdown. Axum's
        // `with_graceful_shutdown` waits for keep-alive connections to
        // drain; under heavy parallelism reqwest's idle-keepalive can
        // hold them open for tens of seconds, deadlocking the test
        // binary's shutdown sequence. Tests don't need graceful
        // shutdown semantics — just kill the server task.
        self.handle.abort();
        let _ = self.handle.await;
        for h in &self.ssh_handles {
            h.abort();
        }
        for h in self.ssh_handles {
            let _ = h.await;
        }
    }

    async fn submit(&self, env: &str, resources: Vec<serde_json::Value>) -> SubmitOperationResponse {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/operations", self.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&SubmitOperationRequest {
                environment: env.into(),
                requested_by: "alice".into(),
                source_commit: None,
                summary: None,
                resources,
                canary: None,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "submit: {}", resp.text().await.unwrap());
        resp.json().await.unwrap()
    }

    async fn wait_terminal(&self, op_id: &str) -> OperationView {
        let client = reqwest::Client::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let view: OperationView = client
                .get(format!("{}/v1/operations/{op_id}", self.url()))
                .bearer_auth(ADMIN_TOKEN)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if matches!(
                view.status,
                OperationStatus::Succeeded
                    | OperationStatus::Failed
                    | OperationStatus::PartiallyApplied
                    | OperationStatus::Rejected
            ) {
                return view;
            }
            if std::time::Instant::now() > deadline {
                panic!("operation {op_id} stuck in {:?}", view.status);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

fn target(name: &str, env: &str) -> SshTargetConfig {
    SshTargetConfig {
        name: name.into(),
        environment: env.into(),
        host: "fake-host.invalid".into(),
        user: "root".into(),
        port: 22,
        identity_file: None,
        remote_iac_path: "/usr/local/bin/iac".into(),
        capabilities: vec![],
        connect_timeout_secs: 10,
        // Tests use a fake `ssh` shim that ignores host key checks
        // entirely. Either policy works here; pick the more
        // permissive one so the test doesn't accidentally exercise
        // the real ssh code path's strict-mode rejection.
        host_key_policy: iac_controlplane::config::SshHostKeyPolicy::AcceptNew,
        known_hosts_file: None,
    }
}

fn file_resource(name: &str, env: &str, host: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": format!("/tmp/{name}"),
            "mode": "0644",
            "content": format!("{name}\n"),
            "hostSelector": { "name": host },
        }
    })
}

#[tokio::test]
async fn ssh_targets_register_in_agents_table() {
    let server = TestServer::spawn(vec![target("edge-01", "edge")], FakeSshBehaviour::Succeed).await;
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT id, kind FROM agents WHERE name = ? AND environment = ?",
    )
    .bind("edge-01")
    .bind("edge")
    .fetch_one(server.store.pool())
    .await
    .unwrap();
    let kind: String = row.try_get("kind").unwrap();
    assert_eq!(kind, "ssh");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_push_succeeds_when_remote_ok() {
    let server = TestServer::spawn(vec![target("edge-ok", "edge")], FakeSshBehaviour::Succeed).await;
    let resp = server
        .submit("edge", vec![file_resource("greet", "edge", "edge-ok")])
        .await;
    let view = server.wait_terminal(&resp.operation_id).await;
    assert!(matches!(view.status, OperationStatus::Succeeded), "got {:?}", view.status);
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_push_fails_when_remote_exit_nonzero() {
    let server = TestServer::spawn(vec![target("edge-fail", "edge")], FakeSshBehaviour::Fail).await;
    let resp = server
        .submit("edge", vec![file_resource("greet", "edge", "edge-fail")])
        .await;
    let view = server.wait_terminal(&resp.operation_id).await;
    assert!(matches!(view.status, OperationStatus::Failed), "got {:?}", view.status);
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_push_capabilities_allowlist_rejects_disallowed_kind() {
    let mut t = target("edge-restricted", "edge");
    t.capabilities = vec!["monitoring.check".into()];
    // Behaviour doesn't matter — we shouldn't even reach SSH here.
    let server = TestServer::spawn(vec![t], FakeSshBehaviour::Succeed).await;
    let resp = server
        .submit("edge", vec![file_resource("greet", "edge", "edge-restricted")])
        .await;
    let view = server.wait_terminal(&resp.operation_id).await;
    assert!(matches!(view.status, OperationStatus::Failed));
    let assignment = &view.assignments[0];
    let result = assignment.result.as_ref().unwrap();
    let summary = result.get("summary").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        summary.contains("capabilities allowlist") && summary.contains("file"),
        "summary: {summary}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_push_emits_audit_event() {
    let server = TestServer::spawn(vec![target("edge-audit", "edge")], FakeSshBehaviour::Succeed).await;
    let resp = server
        .submit("edge", vec![file_resource("greet", "edge", "edge-audit")])
        .await;
    let _ = server.wait_terminal(&resp.operation_id).await;

    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT actor, kind FROM audit_events WHERE kind LIKE 'ssh.push_%'",
    )
    .fetch_all(server.store.pool())
    .await
    .unwrap();
    assert!(!rows.is_empty(), "expected at least one ssh.push_* audit event");
    let actor: String = rows[0].try_get("actor").unwrap();
    let kind: String = rows[0].try_get("kind").unwrap();
    assert!(actor.starts_with("ssh-push:edge-audit"), "actor: {actor}");
    assert!(kind.starts_with("ssh.push_"), "kind: {kind}");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_push_partial_when_remote_outputs_partial() {
    let server = TestServer::spawn(vec![target("edge-partial", "edge")], FakeSshBehaviour::Partial).await;
    let resp = server
        .submit("edge", vec![file_resource("greet", "edge", "edge-partial")])
        .await;
    let view = server.wait_terminal(&resp.operation_id).await;
    assert!(
        matches!(view.status, OperationStatus::PartiallyApplied),
        "got {:?}",
        view.status
    );
    server.shutdown().await;
}
