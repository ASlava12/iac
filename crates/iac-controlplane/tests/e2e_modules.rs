// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7bv: end-to-end test for operator-defined modules.
//! Spins up a server with a `[[modules]]` block in config, registers
//! an agent, submits a manifest using the custom kind, and verifies
//! the operation expanded into the declared primitive resources.

use iac_controlplane::config::RetryAfterFormat;
use iac_controlplane::modules::{Module, ModuleParameter};
use iac_controlplane::rate_limit::{RateLimitConfig, RateLimiter};
use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest, SubmitOperationResponse};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "modules-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

fn marker_module() -> Module {
    Module {
        name: "marker-bundle".into(),
        description: "Drops two marker files for ops verification".into(),
        emits: vec!["file".into(), "file".into()],
        parameters: vec![
            ModuleParameter {
                name: "tag".into(),
                r#type: "string".into(),
                required: true,
                default: None,
                description: "Marker tag".into(),
            },
            ModuleParameter {
                name: "mode".into(),
                r#type: "string".into(),
                required: false,
                default: Some(json!("0644")),
                description: "Marker file mode".into(),
            },
        ],
        template: r#"
- apiVersion: iac.example/v1
  kind: file
  metadata:
    name: {{ name }}-primary
    environment: {{ environment }}
  spec:
    path: /tmp/{{ name }}-primary.txt
    state: present
    content: "{{ tag }}"
    mode: "{{ mode }}"
- apiVersion: iac.example/v1
  kind: file
  metadata:
    name: {{ name }}-secondary
    environment: {{ environment }}
  spec:
    path: /tmp/{{ name }}-secondary.txt
    state: present
    content: "{{ tag }}-secondary"
    mode: "{{ mode }}"
"#
        .into(),
    }
}

impl TestServer {
    async fn spawn(modules: Vec<Module>) -> Self {
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
            rate_limit: RateLimitConfig::default(),
            maintenance_windows: vec![],
            recurring_maintenance_windows: vec![],
            webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
            tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: RetryAfterFormat::default(),
            modules,
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
            wal_checkpoint_interval_secs: 0,
            shutdown_timeout_secs: 1,
            trusted_proxies: vec![],
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
            rate_limiter: Arc::new(RateLimiter::from_config(&cfg.rate_limit)),
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

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }

    async fn register_agent(&self, name: &str, env: &str) {
        reqwest::Client::new()
            .post(self.url("/v1/agents/register"))
            .bearer_auth(ADMIN_TOKEN)
            .json(&RegisterRequest {
                name: name.into(),
                environment: env.into(),
                metadata: serde_json::Value::Null,
            })
            .send()
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn module_appears_in_expanders_catalog() {
    let server = TestServer::spawn(vec![marker_module()]).await;
    let resp = reqwest::Client::new()
        .get(server.url("/v1/expanders"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<serde_json::Value> = resp.json().await.unwrap();
    let kinds: Vec<&str> = body.iter().filter_map(|d| d["kind"].as_str()).collect();
    assert!(
        kinds.contains(&"service"),
        "built-ins still present: {kinds:?}"
    );
    assert!(
        kinds.contains(&"marker-bundle"),
        "operator-defined module surfaced in catalog: {kinds:?}"
    );
    let module_entry = body.iter().find(|d| d["kind"] == "marker-bundle").unwrap();
    assert_eq!(
        module_entry["description"],
        "Drops two marker files for ops verification"
    );
    let fields = module_entry["spec_fields"].as_array().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["name"], "tag");
    assert_eq!(fields[0]["required"], true);
    assert_eq!(fields[1]["name"], "mode");
    assert_eq!(fields[1]["required"], false);

    server.shutdown().await;
}

#[tokio::test]
async fn module_show_returns_descriptor() {
    let server = TestServer::spawn(vec![marker_module()]).await;
    let resp = reqwest::Client::new()
        .get(server.url("/v1/expanders/marker-bundle"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["kind"], "marker-bundle");
    assert!(body["spec_fields"].is_array());
    server.shutdown().await;
}

#[tokio::test]
async fn submitting_module_kind_expands_to_primitives() {
    let server = TestServer::spawn(vec![marker_module()]).await;
    server.register_agent("vm-1", "prod").await;

    let resp = reqwest::Client::new()
        .post(server.url("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: Some("deadbeef".into()),
            summary: Some("deploy markers".into()),
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "marker-bundle",
                "metadata": { "name": "alpha", "environment": "prod" },
                "spec": { "tag": "v1" }
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: SubmitOperationResponse = resp.json().await.unwrap();
    // Blast radius is computed AFTER expansion but BEFORE routing —
    // perfect for verifying the module produced two `file` primitives.
    assert_eq!(body.blast_radius.resource_count, 2);
    assert_eq!(body.blast_radius.kinds, vec!["file".to_string()]);
    // Composite kind must not leak into the blast radius.
    assert!(
        !body
            .blast_radius
            .kinds
            .contains(&"marker-bundle".to_string()),
        "composite kind must not appear: {:?}",
        body.blast_radius.kinds
    );

    server.shutdown().await;
}

#[tokio::test]
async fn submitting_module_with_missing_required_param_is_400() {
    let server = TestServer::spawn(vec![marker_module()]).await;
    server.register_agent("vm-1", "prod").await;

    // Omit `tag` (required, no default).
    let resp = reqwest::Client::new()
        .post(server.url("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "marker-bundle",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": {}
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("spec.tag"),
        "error must mention missing param: {detail:?}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn submitting_module_with_unknown_field_is_400() {
    let server = TestServer::spawn(vec![marker_module()]).await;
    server.register_agent("vm-1", "prod").await;

    let resp = reqwest::Client::new()
        .post(server.url("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "marker-bundle",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": { "tag": "v1", "ghost": "boom" }
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("ghost"),
        "error must mention unknown field: {detail:?}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn module_emitting_another_module_recursively_expands() {
    // Phase 7bw: module composition. `outer` emits `marker-bundle`,
    // which expands to two file resources. Final blast radius should
    // contain only primitive kinds (file, file).
    let outer = Module {
        name: "outer-wrapper".into(),
        description: "Wraps marker-bundle".into(),
        emits: vec!["marker-bundle".into()],
        parameters: vec![ModuleParameter {
            name: "tag".into(),
            r#type: "string".into(),
            required: true,
            default: None,
            description: "Tag".into(),
        }],
        template: r#"
- apiVersion: iac.example/v1
  kind: marker-bundle
  metadata:
    name: {{ name }}
    environment: {{ environment }}
  spec:
    tag: {{ tag }}
"#
        .into(),
    };
    let server = TestServer::spawn(vec![outer, marker_module()]).await;
    server.register_agent("vm-1", "prod").await;

    let resp = reqwest::Client::new()
        .post(server.url("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "outer-wrapper",
                "metadata": { "name": "alpha", "environment": "prod" },
                "spec": { "tag": "v1" }
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: SubmitOperationResponse = resp.json().await.unwrap();
    // outer-wrapper → marker-bundle → 2× file. Final kinds list must
    // contain only primitives.
    assert_eq!(body.blast_radius.resource_count, 2);
    assert_eq!(body.blast_radius.kinds, vec!["file".to_string()]);
    assert!(
        !body
            .blast_radius
            .kinds
            .contains(&"outer-wrapper".to_string()),
        "intermediate composite must not leak"
    );
    assert!(
        !body
            .blast_radius
            .kinds
            .contains(&"marker-bundle".to_string()),
        "intermediate composite must not leak"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn module_recursive_cycle_rejected() {
    // Phase 7bw: cycle detection. A module that emits itself (directly
    // or through a chain) hits MAX_EXPANSION_DEPTH and produces a
    // clear error instead of an infinite loop.
    let cyclic = Module {
        name: "self-cycle".into(),
        description: "Emits itself — should hit depth limit".into(),
        emits: vec!["self-cycle".into()],
        parameters: vec![],
        template: r#"
- apiVersion: iac.example/v1
  kind: self-cycle
  metadata:
    name: {{ name }}
    environment: {{ environment }}
  spec: {}
"#
        .into(),
    };
    let server = TestServer::spawn(vec![cyclic]).await;
    server.register_agent("vm-1", "prod").await;

    let resp = reqwest::Client::new()
        .post(server.url("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "self-cycle",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": {}
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("MAX_EXPANSION_DEPTH") || detail.contains("cycle"),
        "error must mention depth/cycle: {detail:?}"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn unknown_kind_passes_through_when_no_module_matches() {
    // No modules registered. Submitting an unknown kind passes through
    // expansion unchanged; routing without an agent that has the
    // capability produces zero assignments. Operation accepted but no
    // agent picks it up — same as Phase 7a's "unknown primitive"
    // behavior.
    let server = TestServer::spawn(vec![]).await;
    server.register_agent("vm-1", "prod").await;

    let resp = reqwest::Client::new()
        .post(server.url("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "unknown-thing",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": {}
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: SubmitOperationResponse = resp.json().await.unwrap();
    // Unknown kind survives expansion and ends up in the blast radius
    // unchanged. Routing produces zero assignments since no agent
    // claims it.
    assert_eq!(body.blast_radius.resource_count, 1);
    assert_eq!(body.blast_radius.kinds, vec!["unknown-thing".to_string()]);
    server.shutdown().await;
}
