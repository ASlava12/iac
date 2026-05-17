// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7cf: agent-side multi-pubkey verification. Closes the
//! rotation loop opened by Phase 7ce — agents pinned before rotation
//! must keep working after the server picks a new active key, as
//! long as the old key remains in the accepted set.
//!
//! What we test:
//! 1. Agent on first contact pins the entire bundle.
//! 2. After server rotation: agent's existing pinned set is still
//!    valid, but a *fresh* connect picks up the new key too.
//! 3. `refresh_signing_keys` updates the pinned set without breaking
//!    in-flight envelopes.
//! 4. Bundle with no overlap (server identity changed) is refused.
//! 5. End-to-end: rotate server → submit op → agent fetches
//!    assignment signed by new key → applies it cleanly.
//! 6. Pre-7cf identity files (legacy single-key fields only) are
//!    auto-migrated to the new pubkey set.

use iac_agent::remote::{Client, Identity};
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{RegisterRequest, SigningPubkeyBundle};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "multi-pubkey-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    signer: Arc<iac_controlplane::signing::ServerSigner>,
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
            wal_checkpoint_interval_secs: 0,
            shutdown_timeout_secs: 1,
            trusted_proxies: vec![],
        };
        let store = Store::connect(&cfg.database_url).await.unwrap();
        let signer = Arc::new(
            iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
        );
        let state = AppState {
            store: store.clone(),
            live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
            signer: signer.clone(),
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
        Self { addr, shutdown, handle, signer, _tempdir: dir }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

fn register_req(name: &str) -> RegisterRequest {
    RegisterRequest {
        name: name.into(),
        environment: "prod".into(),
        metadata: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn first_contact_pins_full_bundle() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let client = Client::connect(&server.url(), &identity_file, register_req("a1"))
        .await
        .unwrap();

    assert_eq!(client.identity().server_pubkeys.len(), 1);
    let pinned = &client.identity().server_pubkeys[0];
    assert_eq!(pinned.key_id, server.signer.key_id());

    server.shutdown().await;
}

#[tokio::test]
async fn fresh_connect_after_rotation_pins_both_keys() {
    let server = TestServer::spawn().await;
    let initial_id = server.signer.key_id();

    // Operator rotates BEFORE the agent ever connects.
    let new_id = server.signer.rotate().unwrap();

    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");
    let client = Client::connect(&server.url(), &identity_file, register_req("a2"))
        .await
        .unwrap();

    assert_eq!(client.identity().server_pubkeys.len(), 2);
    let ids: Vec<&str> = client
        .identity()
        .server_pubkeys
        .iter()
        .map(|k| k.key_id.as_str())
        .collect();
    assert!(ids.contains(&initial_id.as_str()));
    assert!(ids.contains(&new_id.as_str()));

    server.shutdown().await;
}

#[tokio::test]
async fn legacy_identity_file_is_migrated() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    // Agent registers + pins.
    let client = Client::connect(&server.url(), &identity_file, register_req("legacy"))
        .await
        .unwrap();
    let agent_id = client.identity().agent_id.clone();
    let token = client.identity().token.clone();
    let active_key_id = server.signer.key_id();
    let active_pubkey = server.signer.public_key_b64().unwrap();
    drop(client);

    // Hand-craft a pre-7cf identity file: only legacy fields, no
    // `server_pubkeys` array. Tests that loading + reconnecting still
    // works (auto-migration path).
    let legacy = serde_json::json!({
        "agent_id": agent_id,
        "token": token,
        "server_url": server.url(),
        "registered_at": "2026-05-01T00:00:00Z",
        "server_key_id": active_key_id,
        "server_public_key": active_pubkey,
    });
    std::fs::write(&identity_file, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

    // Re-load through `Client::connect` — should migrate + pin the
    // bundle.
    let reloaded = Client::connect(&server.url(), &identity_file, register_req("legacy"))
        .await
        .expect("legacy identity must auto-migrate");
    assert!(
        !reloaded.identity().server_pubkeys.is_empty(),
        "pubkey set must be populated post-migration"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_picks_up_rotated_active_key() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(&server.url(), &identity_file, register_req("refresh"))
        .await
        .unwrap();
    let initial_id = server.signer.key_id();
    assert_eq!(client.identity().server_pubkeys.len(), 1);

    // Server rotates.
    let new_id = server.signer.rotate().unwrap();

    // Agent refreshes — should now pin both keys.
    client.refresh_signing_keys(&identity_file).await.unwrap();
    let ids: Vec<&str> = client
        .identity()
        .server_pubkeys
        .iter()
        .map(|k| k.key_id.as_str())
        .collect();
    assert!(ids.contains(&initial_id.as_str()));
    assert!(ids.contains(&new_id.as_str()));

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_drops_retired_key_via_rotation_window() {
    // Realistic operator flow: rotate, give agents time to refresh
    // (so they pin both keys), then retire the old one. After that
    // second refresh, the retired key disappears from the agent's set.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(&server.url(), &identity_file, register_req("retire"))
        .await
        .unwrap();
    let initial_id = server.signer.key_id();

    // Operator rotates. Bundle now has [initial_id, new_id]. Agent
    // refreshes — pinned set becomes both. This is the rotation
    // window: both keys remain valid for verification.
    let _new_id = server.signer.rotate().unwrap();
    client.refresh_signing_keys(&identity_file).await.unwrap();
    assert_eq!(client.identity().server_pubkeys.len(), 2);

    // After the rotation window expires, operator retires the old
    // key. Bundle now has [new_id] only. Agent refreshes — overlap
    // is {new_id}, so the update is accepted and initial_id drops
    // out of the pinned set.
    let removed = server.signer.retire(&initial_id).unwrap();
    assert!(removed);
    client.refresh_signing_keys(&identity_file).await.unwrap();
    let ids: Vec<&str> = client
        .identity()
        .server_pubkeys
        .iter()
        .map(|k| k.key_id.as_str())
        .collect();
    assert!(!ids.contains(&initial_id.as_str()), "retired key dropped");
    assert_eq!(ids.len(), 1, "only the new active remains");

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_refuses_when_rotation_window_expired_too_fast() {
    // Pathological case: operator rotates AND retires before any
    // agent has had a chance to refresh. Result: agent's pinned set
    // (old key) and server's bundle (new key only) have no overlap.
    // This is the exact tampering signature we want to catch — so
    // refuse rather than silently accept the new bundle. Operator
    // recovery: clear `server_pubkeys` on the agent + reconnect,
    // which is a deliberate trust decision.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(&server.url(), &identity_file, register_req("toofast"))
        .await
        .unwrap();
    let initial_id = server.signer.key_id();

    let _new_id = server.signer.rotate().unwrap();
    let removed = server.signer.retire(&initial_id).unwrap();
    assert!(removed);

    let result = client.refresh_signing_keys(&identity_file).await;
    assert!(result.is_err(), "no-overlap refresh must be refused");
    // Pinned set unchanged.
    assert_eq!(client.identity().server_pubkeys.len(), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn connect_refuses_no_overlap_bundle() {
    // First contact succeeds. Then tamper with the on-disk identity so
    // it pins only a forged key. Re-connecting must bail — the server's
    // bundle has no overlap with the (forged) pinned set, which is the
    // exact tampering signal we want to catch.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let _ = Client::connect(&server.url(), &identity_file, register_req("noove"))
        .await
        .unwrap();

    // Replace pinned set with a key the server has never heard of.
    let mut id: Identity =
        serde_json::from_slice(&std::fs::read(&identity_file).unwrap()).unwrap();
    id.server_pubkeys = vec![iac_agent::remote::ServerPubkey {
        key_id: "01FORGED".into(),
        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
    }];
    // Clear legacy fields too — otherwise migrate_legacy_pubkey adds
    // a real key back in and overlap is restored.
    id.server_key_id = None;
    id.server_public_key = None;
    std::fs::write(&identity_file, serde_json::to_vec_pretty(&id).unwrap()).unwrap();

    let result = Client::connect(&server.url(), &identity_file, register_req("noove")).await;
    assert!(
        result.is_err(),
        "connect must refuse when pinned set has no overlap with server bundle"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn end_to_end_agent_apply_after_rotation() {
    use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
    use iac_core::protocol::v1::SubmitOperationRequest;

    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let manifests = dir.path().join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let cfg = AgentConfig::load(
        None,
        ConfigOverrides {
            state_dir: Some(dir.path().join("state")),
            manifests_dir: Some(manifests),
            observe_interval_secs: Some(1),
            environment: Some("rotation".into()),
            actor: Some("test".into()),
            server_url: Some(server.url()),
            agent_name: Some("rotagent".into()),
            capabilities_file: None,
        },
    )
    .unwrap();
    let agent = Agent::new(cfg).unwrap();
    assert!(agent.connect_remote().await);

    // Server rotates (after agent already pinned the original key).
    server.signer.rotate().unwrap();

    // Submit an op — server signs the new assignment with the new
    // active key. The agent's pinned set still contains the original
    // (and now must learn the new one). We force a re-connect by
    // building a fresh Agent instance pointing at the same state dir.
    let target = dir.path().join("rotated.txt");
    let body = SubmitOperationRequest {
        environment: "rotation".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![serde_json::json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "rot", "environment": "rotation" },
            "spec": {
                "path": target.display().to_string(),
                "mode": "0644",
                "content": "rotated\n",
            }
        })], canary: None,
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "submit op: {:?}", resp.status());

    // Re-build the agent (simulating an agent restart that picks up
    // the new bundle on next connect).
    let cfg2 = AgentConfig::load(
        None,
        ConfigOverrides {
            state_dir: Some(dir.path().join("state")),
            manifests_dir: Some(dir.path().join("manifests.d")),
            observe_interval_secs: Some(1),
            environment: Some("rotation".into()),
            actor: Some("test".into()),
            server_url: Some(server.url()),
            agent_name: Some("rotagent".into()),
            capabilities_file: None,
        },
    )
    .unwrap();
    let agent2 = Agent::new(cfg2).unwrap();
    assert!(
        agent2.connect_remote().await,
        "agent must reconnect after rotation"
    );
    agent2.observe_once().await.unwrap();
    assert!(target.exists(), "agent applied envelope signed by new active key");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "rotated\n");

    server.shutdown().await;
}

#[tokio::test]
async fn bundle_endpoint_is_consistent_with_pubkey() {
    // Sanity: GET /v1/signing-pubkey.key_id == bundle.active_key_id.
    let server = TestServer::spawn().await;
    let bundle: SigningPubkeyBundle = reqwest::Client::new()
        .get(format!("{}/v1/signing-keys", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let single: iac_core::protocol::v1::SigningPubkey = reqwest::Client::new()
        .get(format!("{}/v1/signing-pubkey", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bundle.active_key_id, single.key_id);
    server.shutdown().await;
}
