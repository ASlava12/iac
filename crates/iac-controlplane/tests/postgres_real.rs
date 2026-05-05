// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7al: real Postgres integration test for `Store`.
//!
//! Spins up `postgres:16-alpine` in Docker, runs the migrations against it,
//! exercises a register → observe → drift → query path, then tears the
//! container down. Skipped unless `IAC_POSTGRES_INTEGRATION=1` AND the local
//! Docker daemon is reachable.
//!
//! Pattern mirrors `iac-providers/tests/docker_real.rs`: gate on env var,
//! shell out to `docker`, take care to clean up via a Drop guard so a panic
//! mid-test still removes the container.

use iac_controlplane::{Dialect, Store};
use iac_core::id::ResourceId;
use iac_core::protocol::v1::{HeartbeatRequest, ObservationItem, RegisterRequest};
use std::process::Command;
use std::time::{Duration, Instant};

fn integration_enabled() -> bool {
    std::env::var("IAC_POSTGRES_INTEGRATION").as_deref() == Ok("1")
}

fn docker_reachable() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Owns a running container; removes it on Drop even if a test panics.
struct PgContainer {
    name: String,
    host_port: u16,
}

impl PgContainer {
    fn start() -> Self {
        let name = format!("iac-pg-test-{}", std::process::id());
        // Best-effort cleanup of a leftover from a prior crashed run.
        let _ = Command::new("docker")
            .args(["rm", "-f", &name])
            .output();

        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "-e",
                "POSTGRES_PASSWORD=iac",
                "-e",
                "POSTGRES_USER=iac",
                "-e",
                "POSTGRES_DB=iac",
                "-p",
                "127.0.0.1::5432",
                "postgres:16-alpine",
                "-c",
                "fsync=off",
                "-c",
                "synchronous_commit=off",
                "-c",
                "full_page_writes=off",
            ])
            .output()
            .expect("docker run");
        if !out.status.success() {
            panic!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // `docker port` reports the host-side mapping for the published port.
        let port_out = Command::new("docker")
            .args(["port", &name, "5432/tcp"])
            .output()
            .expect("docker port");
        let port_str = String::from_utf8_lossy(&port_out.stdout);
        let host_port = port_str
            .lines()
            .find_map(|line| line.rsplit(':').next().and_then(|s| s.trim().parse().ok()))
            .unwrap_or_else(|| panic!("could not parse `docker port` output: {port_str:?}"));

        let pg = Self { name, host_port };
        pg.wait_ready();
        pg
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let out = Command::new("docker")
                .args([
                    "exec",
                    &self.name,
                    "pg_isready",
                    "-U",
                    "iac",
                    "-d",
                    "iac",
                ])
                .output();
            if matches!(out, Ok(o) if o.status.success()) {
                // pg_isready can return "accepting connections" while the
                // server is still finishing internal startup. A connection
                // attempt during that window gets reset (os error 104).
                // Sleep once after the first OK to let the listener settle.
                std::thread::sleep(Duration::from_millis(400));
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("postgres in {} did not become ready within 30s", self.name);
    }

    fn url(&self) -> String {
        format!("postgres://iac:iac@127.0.0.1:{}/iac", self.host_port)
    }
}

impl Drop for PgContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

#[tokio::test]
async fn postgres_round_trip() {
    if !integration_enabled() || !docker_reachable() {
        eprintln!("skipping: set IAC_POSTGRES_INTEGRATION=1 and start Docker");
        return;
    }

    let pg = PgContainer::start();
    let store = Store::connect(&pg.url())
        .await
        .expect("connect to dockerised postgres");
    assert_eq!(store.dialect(), Dialect::Postgres);

    // 1. Register an agent. Verifies migrations applied + token issuance.
    let creds = store
        .register_agent(
            &RegisterRequest {
                name: "pg-integration".into(),
                environment: "test".into(),
                metadata: serde_json::json!({"hostname": "ci"}),
            },
            None,
        )
        .await
        .expect("register_agent");
    assert!(!creds.agent_id.is_empty());

    // 2. Heartbeat. Tests UPDATE on agents and the bool→i64 bind path.
    store
        .record_heartbeat(
            &creds.agent_id,
            &HeartbeatRequest {
                status: iac_core::protocol::v1::AgentHealth::Healthy,
                managed: 7,
                open_drifts: 2,
                last_observe_at: None,
            },
        )
        .await
        .expect("record_heartbeat");

    // 3. Insert an observation. Exercises the present-as-int bind and the
    //    BIGSERIAL id round-trip.
    store
        .record_observations(
            &creds.agent_id,
            &[ObservationItem {
                resource_id: ResourceId::new("file", "test", "x"),
                observed_at: jiff::Timestamp::now().to_string(),
                present: true,
                spec: serde_json::json!({"path": "/tmp/x"}),
                facts: serde_json::json!({"checksum": "abc"}),
            }],
        )
        .await
        .expect("ingest_observations");

    // 4. List agents — exercises the SELECT path with multi-column
    //    deserialization across an `AnyRow` from postgres.
    let agents = store.list_agents().await.expect("list_agents");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name, "pg-integration");
    assert_eq!(agents[0].managed, 7);
    assert_eq!(agents[0].open_drifts, 2);

    // 5. Phase 7an: exercise the window-function path (`ROW_NUMBER() OVER
    //    PARTITION BY`) against real Postgres. The SQL is identical to
    //    the SQLite path; this proves the planner accepts it through
    //    `sqlx::Any` placeholder translation.
    for i in 0..4 {
        store
            .record_observations(
                &creds.agent_id,
                &[ObservationItem {
                    resource_id: ResourceId::new("file", "test", "x"),
                    observed_at: jiff::Timestamp::now()
                        .checked_sub(jiff::Span::new().try_minutes(4 - i).unwrap())
                        .unwrap()
                        .to_string(),
                    present: true,
                    spec: serde_json::json!({"path": "/tmp/x"}),
                    facts: serde_json::json!({"i": i}),
                }],
            )
            .await
            .expect("observation insert");
    }
    // Earlier in the test we already inserted one row for `file/test/x`.
    // After 4 more, total is 5 rows for that resource.
    let cfg = iac_controlplane::retention::RetentionConfig {
        observation_days: 0,
        observation_max_per_resource: 2,
        ..iac_controlplane::retention::RetentionConfig::default()
    };
    let stats = iac_controlplane::retention::prune_once(&store, &cfg)
        .await
        .expect("per-resource cap on PG");
    assert_eq!(
        stats.observations_per_resource, 3,
        "should drop 3 of the 5 rows"
    );
}
