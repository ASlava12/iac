// Phase 7da.5: end-to-end test for the audit-log Merkle chain.
//
// We exercise the full path: real audit-emitting requests populate
// `audit_events` with chained `prev_hash`/`row_hash` columns; the
// `/v1/audit/chain-tip` and `/v1/audit/verify` endpoints expose the
// state; an out-of-band UPDATE simulates a compromised admin / DB
// tampering and the verify endpoint surfaces the broken row id.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{RegisterRequest, RegisterResponse};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "audit-chain-admin";

#[derive(Debug, Deserialize)]
struct ChainTip {
    last_id: i64,
    last_hash: String,
}

#[derive(Debug, Deserialize)]
struct VerifyResp {
    ok: bool,
    broken_id: Option<i64>,
}

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    db_path: std::path::PathBuf,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn() -> Self {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("server.db");
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
            ssh_targets: vec![],
        };
        let store = Store::connect(&cfg.database_url).await.unwrap();
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
            rate_limiter: std::sync::Arc::new(
                iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit),
            ),
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
            axum::serve(listener, app)
                .with_graceful_shutdown(async move { signal.notified().await })
                .await
                .unwrap();
        });
        Self {
            addr,
            shutdown,
            handle,
            db_path: db,
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

async fn register_agent(server: &TestServer, name: &str) -> RegisterResponse {
    reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .json(&RegisterRequest {
            name: name.into(),
            environment: "chain".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn fetch_tip(server: &TestServer) -> ChainTip {
    reqwest::Client::new()
        .get(format!("{}/v1/audit/chain-tip", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn verify(server: &TestServer) -> VerifyResp {
    reqwest::Client::new()
        .get(format!("{}/v1/audit/verify", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn chain_grows_with_each_audit_event() {
    let server = TestServer::spawn().await;

    // Empty chain on a fresh server.
    let tip0 = fetch_tip(&server).await;
    assert_eq!(tip0.last_id, 0);
    assert_eq!(tip0.last_hash, "");

    let _ = register_agent(&server, "vm-1").await;
    let tip1 = fetch_tip(&server).await;
    assert!(tip1.last_id > 0, "tip should advance after first audit event");
    assert!(!tip1.last_hash.is_empty());
    assert_eq!(tip1.last_hash.len(), 64, "sha256 hex is 64 chars");

    let _ = register_agent(&server, "vm-2").await;
    let tip2 = fetch_tip(&server).await;
    assert!(tip2.last_id > tip1.last_id);
    assert_ne!(tip2.last_hash, tip1.last_hash, "chain should advance");

    // Verify endpoint reports clean.
    let v = verify(&server).await;
    assert!(v.ok);
    assert!(v.broken_id.is_none());

    server.shutdown().await;
}

#[tokio::test]
async fn endpoints_require_approver_role() {
    let server = TestServer::spawn().await;

    for path in ["/v1/audit/chain-tip", "/v1/audit/verify"] {
        // No auth.
        let resp = reqwest::Client::new()
            .get(format!("{}{}", server.url(), path))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "path={path}");

        // Bad token.
        let resp = reqwest::Client::new()
            .get(format!("{}{}", server.url(), path))
            .bearer_auth("nope")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "path={path}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn tampering_is_detected_by_verify() {
    let server = TestServer::spawn().await;

    // Build up a few-row chain.
    for n in 0..5 {
        let _ = register_agent(&server, &format!("vm-{n}")).await;
    }
    let v = verify(&server).await;
    assert!(v.ok);

    // Open a side connection and silently mutate one of the audit
    // rows, simulating a compromised DBA / direct-SQL tampering.
    // We change the actor field — every column is fed into the row
    // hash, so any change must be caught.
    let url = format!("sqlite://{}?mode=rwc", server.db_path.display());
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let row = sqlx::query("SELECT id FROM audit_events ORDER BY id ASC LIMIT 1 OFFSET 2")
        .fetch_one(&pool)
        .await
        .unwrap();
    let target_id: i64 = row.try_get("id").unwrap();
    sqlx::query("UPDATE audit_events SET actor = ? WHERE id = ?")
        .bind("attacker")
        .bind(target_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // Verify must now flag the tampered row. Since we changed the
    // row's own contents (not its prev_hash) the row's stored hash
    // no longer matches the recomputed hash → broken_id == target.
    let v = verify(&server).await;
    assert!(!v.ok, "verify should fail after tampering");
    assert_eq!(
        v.broken_id,
        Some(target_id),
        "verify should report the tampered row"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn deleting_a_row_breaks_chain_at_next_row() {
    let server = TestServer::spawn().await;

    for n in 0..4 {
        let _ = register_agent(&server, &format!("h-{n}")).await;
    }
    assert!(verify(&server).await.ok);

    // Drop a middle row. The next row's stored prev_hash now
    // refers to a deleted predecessor, so the walking verifier
    // detects the break at the *successor*'s id.
    let url = format!("sqlite://{}?mode=rwc", server.db_path.display());
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let mid = sqlx::query("SELECT id FROM audit_events ORDER BY id ASC LIMIT 1 OFFSET 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mid_id: i64 = mid.try_get("id").unwrap();
    let next = sqlx::query("SELECT id FROM audit_events WHERE id > ? ORDER BY id ASC LIMIT 1")
        .bind(mid_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let next_id: i64 = next.try_get("id").unwrap();
    sqlx::query("DELETE FROM audit_events WHERE id = ?")
        .bind(mid_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let v = verify(&server).await;
    assert!(!v.ok);
    assert_eq!(v.broken_id, Some(next_id));

    server.shutdown().await;
}
