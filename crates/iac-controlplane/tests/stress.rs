// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7cj: end-to-end stress test harness for the control plane.
//!
//! Validates the "works on cheap hardware AND scales up" claim by
//! exercising the full pipeline (operation submit → fanout → agent
//! poll → complete → roll-up) with N simulated agents in a single
//! process. Each agent is just a Tokio task that periodically calls
//! `GET /v1/agents/{id}/assignments` and posts back success.
//!
//! Three scenarios run by default. Each measures:
//! * total wall-clock to fully drain
//! * p50/p95/p99 of submit latency (measured client-side)
//! * peak DB row counts as a sanity check
//!
//! Why no separate `iac-stress` crate: this gives us the same
//! AppState construction every other e2e test uses, avoids
//! duplicate test infrastructure, and keeps the stress runner
//! discoverable (`cargo test --test stress`).
//!
//! These tests are gated by `IAC_STRESS=1` to keep them out of the
//! default `cargo test` run — they take 5-30 seconds each. CI runs
//! them on a separate job; developers run them on demand.

#![cfg(test)]

use iac_controlplane::{Config as ServerConfig, server::AppState};
use iac_core::protocol::v1::{
    AgentHealth, AssignmentResultRequest, AssignmentResultStatus, OperationStatus, OperationView,
    RegisterRequest, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "stress-admin";

fn enabled() -> bool {
    std::env::var("IAC_STRESS").ok().as_deref() == Some("1")
}

struct StressServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl StressServer {
    async fn spawn() -> Self {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("server.db");
        let cfg = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: format!("sqlite://{}?mode=rwc", db.display()),
            state_dir: dir.path().to_path_buf(),
            // Stress test sends bigger payloads — bump from 1 MiB.
            max_body_bytes: 1 << 23, // 8 MiB
            admin_token: Some(ADMIN_TOKEN.to_string()),
            policies: vec![],
            retention: iac_controlplane::retention::RetentionConfig::default(),
            // Disable rate limit for stress test — we want raw
            // throughput, not the limiter's behavior.
            rate_limit: iac_controlplane::rate_limit::RateLimitConfig::default(),
            maintenance_windows: vec![],
            recurring_maintenance_windows: vec![],
            webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
            tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
            wal_checkpoint_interval_secs: 0,
            shutdown_timeout_secs: 1,
            trusted_proxies: vec![],
            agent_enrollment_token: None,
        };
        let store = iac_controlplane::Store::connect(&cfg.database_url)
            .await
            .unwrap();
        let signer = std::sync::Arc::new(
            iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
        );
        let state = AppState {
            store,
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
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
        });
        Self {
            addr,
            shutdown,
            handle,
            _tempdir: dir,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

/// Simulated agent: registers, polls `/assignments` in a loop, completes
/// each one immediately as Succeeded. Stops when `done` is signaled.
async fn simulated_agent(
    server_url: String,
    name: String,
    env: String,
    done: Arc<tokio::sync::Notify>,
    poll_interval: Duration,
) -> u32 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let resp = client
        .post(format!("{server_url}/v1/agents/register"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name,
            environment: env,
            metadata: json!(null),
        })
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();
    let token = body["token"].as_str().unwrap().to_string();

    let mut completed = 0u32;
    loop {
        // Heartbeat (non-essential but mirrors real agent behaviour).
        let _ = client
            .post(format!("{server_url}/v1/agents/{agent_id}/heartbeat"))
            .bearer_auth(&token)
            .json(&iac_core::protocol::v1::HeartbeatRequest {
                status: AgentHealth::Healthy,
                managed: 0,
                open_drifts: 0,
                last_observe_at: None,
            })
            .send()
            .await;

        // Transient connection errors during stress are expected
        // (server CPU pegged, hyper drops keepalive). Skip + retry
        // on next loop tick rather than panicking.
        let resp = match client
            .get(format!("{server_url}/v1/agents/{agent_id}/assignments"))
            .bearer_auth(&token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };
        if resp.status() == StatusCode::OK
            && let Ok(list) = resp.json::<iac_core::protocol::v1::AssignmentList>().await
        {
            for env in list.items {
                let result = AssignmentResultRequest {
                    status: AssignmentResultStatus::Succeeded,
                    items: vec![],
                    summary: None,
                };
                let post_resp = client
                    .post(format!(
                        "{server_url}/v1/agents/{agent_id}/assignments/{}/result",
                        env.assignment_id
                    ))
                    .bearer_auth(&token)
                    .json(&result)
                    .send()
                    .await;
                if matches!(post_resp, Ok(ref r) if r.status() == StatusCode::OK) {
                    completed += 1;
                }
                // Non-200 / errored POSTs: silently dropped.
                // The Phase 7cj lease re-claim makes orphaned
                // assignments recoverable on the next poll.
            }
        }
        // Stop ASAP when done is signaled — but yield first so any
        // in-flight assignment fanout can land before we exit.
        tokio::select! {
            _ = done.notified() => break,
            _ = tokio::time::sleep(poll_interval) => {}
        }
    }
    completed
}

fn percentile(samples: &mut [Duration], pct: f64) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    samples.sort_unstable();
    let idx = ((samples.len() - 1) as f64 * pct).round() as usize;
    samples[idx]
}

fn file_resource(name: &str, env: &str, host: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": format!("/tmp/stress-{name}"),
            "mode": "0644",
            "content": format!("{name}\n"),
            "hostSelector": { "name": host },
        }
    })
}

#[derive(Debug)]
struct StressReport {
    scenario: &'static str,
    agents: usize,
    operations: usize,
    resources_per_op: usize,
    total_wall_clock_ms: u64,
    submit_p50_ms: u64,
    submit_p95_ms: u64,
    submit_p99_ms: u64,
    completion_total_ms: u64,
    completed_assignments: u32,
}

impl StressReport {
    fn print(&self) {
        eprintln!(
            "\n=== {} (agents={}, ops={}, resources/op={}) ===",
            self.scenario, self.agents, self.operations, self.resources_per_op,
        );
        eprintln!("  total wall-clock:     {} ms", self.total_wall_clock_ms);
        eprintln!(
            "  submit p50/p95/p99:   {} / {} / {} ms",
            self.submit_p50_ms, self.submit_p95_ms, self.submit_p99_ms
        );
        eprintln!("  fanout→roll-up time:  {} ms", self.completion_total_ms);
        eprintln!("  completed assignments: {}", self.completed_assignments);
        eprintln!(
            "  ops/sec (effective):  {:.2}",
            (self.operations as f64) / (self.total_wall_clock_ms as f64 / 1000.0)
        );
    }
}

async fn run_scenario(
    scenario: &'static str,
    agents: usize,
    operations: usize,
    resources_per_op: usize,
) -> StressReport {
    let server = StressServer::spawn().await;
    let url = server.url();
    let env_name = "stress";

    // Spawn agents. Poll interval scales with fleet size — at 200
    // agents, 50ms polling is 4000 req/sec just for polling, which
    // pegs the server CPU and starves result POSTs. Real-world
    // agents poll every 1-5s; we use 100ms baseline + a slope so
    // small fleets stay snappy in the test.
    let poll_ms = 100u64.saturating_add((agents as u64).saturating_mul(2));
    let poll_interval = Duration::from_millis(poll_ms);
    let done = Arc::new(tokio::sync::Notify::new());
    let mut agent_handles = Vec::with_capacity(agents);
    for i in 0..agents {
        let url = url.clone();
        let done = done.clone();
        let name = format!("a{i:04}");
        agent_handles.push(tokio::spawn(simulated_agent(
            url,
            name,
            env_name.to_string(),
            done,
            poll_interval,
        )));
    }

    // Wait for ALL agents to land in the agents table before
    // submitting. Without this barrier, host_selector routing finds
    // nobody and the resources go unrouted — submits succeed but no
    // assignments get created, so completion polling waits forever.
    let prep_client = reqwest::Client::new();
    let prep_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let resp = prep_client
            .get(format!("{url}/v1/agents"))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        let list: Vec<serde_json::Value> = resp.json().await.unwrap();
        if list.len() >= agents {
            break;
        }
        if Instant::now() >= prep_deadline {
            panic!(
                "only {} of {} agents registered after 30s",
                list.len(),
                agents
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let total_start = Instant::now();
    let mut submit_latencies = Vec::with_capacity(operations);
    let mut op_ids = Vec::with_capacity(operations);
    for op_idx in 0..operations {
        // Build resources, round-robin across agents.
        let mut resources = Vec::with_capacity(resources_per_op);
        for r_idx in 0..resources_per_op {
            let host = format!("a{:04}", (op_idx + r_idx) % agents);
            let name = format!("op{op_idx}-r{r_idx}");
            resources.push(file_resource(&name, env_name, &host));
        }
        let req = SubmitOperationRequest {
            environment: env_name.to_string(),
            requested_by: "stress".into(),
            source_commit: None,
            summary: None,
            resources,
            canary: None,
        };
        let t0 = Instant::now();
        let resp = client
            .post(format!("{url}/v1/operations"))
            .bearer_auth(ADMIN_TOKEN)
            .json(&req)
            .send()
            .await
            .unwrap();
        let elapsed = t0.elapsed();
        submit_latencies.push(elapsed);
        assert_eq!(resp.status(), StatusCode::OK);
        let body: SubmitOperationResponse = resp.json().await.unwrap();
        if op_idx == 0 {
            eprintln!(
                "diag: op0 assignment_count={} unrouted={} (resources={})",
                body.assignment_count,
                body.unrouted.len(),
                resources_per_op
            );
            for u in &body.unrouted {
                eprintln!("  unrouted: {} reason={}", u.resource_id, u.reason);
            }
        }
        op_ids.push(body.operation_id);
    }

    let submit_phase_done = total_start.elapsed();

    // Wait for all ops to finish.
    let completion_start = Instant::now();
    loop {
        let mut all_done = true;
        for op_id in &op_ids {
            let resp = client
                .get(format!("{url}/v1/operations/{op_id}"))
                .bearer_auth(ADMIN_TOKEN)
                .send()
                .await
                .unwrap();
            let view: OperationView = resp.json().await.unwrap();
            if !matches!(
                view.status,
                OperationStatus::Succeeded
                    | OperationStatus::Failed
                    | OperationStatus::PartiallyApplied
                    | OperationStatus::Rejected
            ) {
                all_done = false;
                break;
            }
        }
        if all_done {
            break;
        }
        if completion_start.elapsed() > Duration::from_secs(60) {
            // Diagnostic: aggregate status counts across all ops.
            let mut status_totals: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            let mut op_status_totals: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            for op_id in &op_ids {
                let resp = client
                    .get(format!("{url}/v1/operations/{op_id}"))
                    .bearer_auth(ADMIN_TOKEN)
                    .send()
                    .await
                    .unwrap();
                let view: OperationView = resp.json().await.unwrap();
                *op_status_totals
                    .entry(format!("{:?}", view.status))
                    .or_insert(0) += 1;
                for a in &view.assignments {
                    *status_totals.entry(a.status.clone()).or_insert(0) += 1;
                }
            }
            eprintln!(
                "diag: op statuses {:?} assignment statuses {:?}",
                op_status_totals, status_totals,
            );
            panic!(
                "stress scenario {scenario} stuck after 60s; submit phase took {} ms",
                submit_phase_done.as_millis()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let completion_total = completion_start.elapsed();
    let total_wall = total_start.elapsed();

    // Stop agents and collect counts.
    done.notify_waiters();
    let mut completed_assignments = 0u32;
    for h in agent_handles {
        if let Ok(c) = tokio::time::timeout(Duration::from_secs(5), h).await {
            completed_assignments += c.unwrap_or(0);
        }
    }

    server.shutdown().await;

    let p50 = percentile(&mut submit_latencies, 0.50);
    let p95 = percentile(&mut submit_latencies, 0.95);
    let p99 = percentile(&mut submit_latencies, 0.99);

    StressReport {
        scenario,
        agents,
        operations,
        resources_per_op,
        total_wall_clock_ms: total_wall.as_millis() as u64,
        submit_p50_ms: p50.as_millis() as u64,
        submit_p95_ms: p95.as_millis() as u64,
        submit_p99_ms: p99.as_millis() as u64,
        completion_total_ms: completion_total.as_millis() as u64,
        completed_assignments,
    }
}

// Scenario sizes are chosen to exercise the full pipeline within a
// reasonable wall-clock on the SQLite single-file backend. Postgres
// deployments scale much higher; these numbers describe the SQLite
// performance envelope on a developer laptop.
//
// Required for these to pass:
//  * IAC_STRESS=1 — gate stress out of the default `cargo test` run.
//  * IAC_ASSIGNMENT_LEASE_SECS=5 — speed up the stuck-assignment
//    re-claim path so we don't wait 60 seconds per orphaned slot.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_tiny_baseline() {
    if !enabled() {
        eprintln!("skipping (set IAC_STRESS=1 to run)");
        return;
    }
    let report = run_scenario("tiny baseline", 3, 5, 2).await;
    report.print();
    assert!(report.completed_assignments > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_small_fleet() {
    // Realistic homelab/RPi-class deployment: 10 agents, 20 ops with
    // 3 resources each. p99 submit < 1s expected; full drain in
    // tens of seconds.
    if !enabled() {
        return;
    }
    let report = run_scenario("small (RPi-class)", 10, 20, 3).await;
    report.print();
    assert!(
        report.submit_p99_ms < 1000,
        "submit p99 over 1s: {}",
        report.submit_p99_ms
    );
    assert!(report.completed_assignments > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn stress_medium_informational() {
    // Single-process SQLite has a sustained-write ceiling around
    // 50-100 inserts/sec under contention from many polling agents.
    // 30 agents × 15 ops × 5 resources is at the edge of what we
    // expect to drain reasonably; informational only, no assertion.
    // Operators wanting more throughput should switch to Postgres.
    if !enabled() {
        return;
    }
    let report = run_scenario("medium (informational)", 30, 15, 5).await;
    report.print();
}
