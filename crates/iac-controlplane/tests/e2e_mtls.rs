// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7ak: end-to-end mTLS — agent registers + heartbeats over a
//! self-signed CA-issued PKI. Three scenarios:
//!
//!   1. `mode = mutual` with valid client cert → agent connects + writes.
//!   2. `mode = mutual` without a client cert → server refuses the
//!      handshake at the TLS layer.
//!   3. `mode = server` with no client cert required → agent connects
//!      with just the CA bundle (no client identity).
//!
//! The CA + certs are generated in-test via `rcgen` so we don't need
//! an external PKI.

use iac_agent::config::AgentTlsConfig;
use iac_agent::remote::{build_http_client, Client};
use iac_controlplane::tls::{generate_self_signed_pki, TlsConfig};
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::RegisterRequest;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "mtls-admin";

struct PkiDir {
    _dir: TempDir,
    ca_path: std::path::PathBuf,
    server_cert: std::path::PathBuf,
    server_key: std::path::PathBuf,
    /// Per-client (cert, key) PEM paths.
    client_certs: Vec<(String, std::path::PathBuf, std::path::PathBuf)>,
}

fn write_pki(client_names: &[&str]) -> PkiDir {
    let dir = TempDir::new().unwrap();
    let pki = generate_self_signed_pki(
        &["localhost", "iac-test"],
        &["127.0.0.1".parse::<IpAddr>().unwrap()],
        client_names,
    )
    .unwrap();
    let ca_path = dir.path().join("ca.pem");
    let server_cert = dir.path().join("server.pem");
    let server_key = dir.path().join("server.key");
    std::fs::write(&ca_path, &pki.ca_cert_pem).unwrap();
    std::fs::write(&server_cert, &pki.server_cert_pem).unwrap();
    std::fs::write(&server_key, &pki.server_key_pem).unwrap();
    let mut client_certs = Vec::new();
    for c in &pki.client_certs {
        let cp = dir.path().join(format!("{}-cert.pem", c.name));
        let kp = dir.path().join(format!("{}-key.pem", c.name));
        std::fs::write(&cp, &c.cert_pem).unwrap();
        std::fs::write(&kp, &c.key_pem).unwrap();
        client_certs.push((c.name.clone(), cp, kp));
    }
    PkiDir { _dir: dir, ca_path, server_cert, server_key, client_certs }
}

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn(tls: TlsConfig) -> Self {
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
            tls,
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
            store: store.clone(),
            live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
            signer,
            rate_limiter: Arc::new(
                iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit),
            ),
            webhook_dispatcher: None,
            maintenance_metrics: Arc::new(
                iac_controlplane::maintenance::MaintenanceMetrics::default(),
            ),
            secret_registry: None,
        };
        let app = iac_controlplane::server::router(state);

        // Bind on a free port then serve via axum-server with TLS.
        let listener = std::net::TcpListener::bind(cfg.bind).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(Notify::new());
        let signal = shutdown.clone();

        let rustls_cfg =
            iac_controlplane::tls::build_rustls_config(&cfg.tls).expect("build rustls config");
        let server_cfg = axum_server::tls_rustls::RustlsConfig::from_config(rustls_cfg);
        let handle = axum_server::Handle::new();
        let handle_for_shutdown = handle.clone();
        tokio::spawn(async move {
            signal.notified().await;
            handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
        });
        let serve_handle = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, server_cfg)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        // Give the listener a moment to start accepting before tests
        // start their connect attempts.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Self { addr, shutdown, handle: serve_handle, _tempdir: dir }
    }

    fn url(&self) -> String {
        format!("https://{}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

#[tokio::test]
async fn mutual_tls_full_round_trip() {
    let pki = write_pki(&["agent-a"]);
    let tls = TlsConfig {
        mode: "mutual".into(),
        cert_file: Some(pki.server_cert.clone()),
        key_file: Some(pki.server_key.clone()),
        client_ca_file: Some(pki.ca_path.clone()),
    };
    let server = TestServer::spawn(tls).await;

    // Client cert in agent config.
    let (_name, cert, key) = pki.client_certs.first().unwrap();
    let agent_tls = AgentTlsConfig {
        ca_file: Some(pki.ca_path.clone()),
        client_cert_file: Some(cert.clone()),
        client_key_file: Some(key.clone()),
    };

    let id_dir = TempDir::new().unwrap();
    let id_file = id_dir.path().join("identity.json");
    let req = RegisterRequest {
        name: "agent-a".into(),
        environment: "test".into(),
        metadata: serde_json::Value::Null,
    };
    let client = Client::connect_with_tls(&server.url(), &id_file, req, &agent_tls)
        .await
        .expect("agent should register over mTLS");
    let agent_id = client.identity().agent_id.clone();
    assert!(!agent_id.is_empty(), "agent registered");

    // Sanity: a follow-up call (heartbeat) succeeds too.
    use iac_core::protocol::v1::AgentHealth;
    client
        .heartbeat(AgentHealth::Healthy, 0, 0, None)
        .await
        .expect("heartbeat ok over mTLS");

    server.shutdown().await;
}

#[tokio::test]
async fn mutual_mode_rejects_client_without_cert() {
    let pki = write_pki(&["agent-a"]);
    let tls = TlsConfig {
        mode: "mutual".into(),
        cert_file: Some(pki.server_cert.clone()),
        key_file: Some(pki.server_key.clone()),
        client_ca_file: Some(pki.ca_path.clone()),
    };
    let server = TestServer::spawn(tls).await;

    // Build an HTTP client with the CA but NO client cert.
    let agent_tls = AgentTlsConfig {
        ca_file: Some(pki.ca_path.clone()),
        client_cert_file: None,
        client_key_file: None,
    };
    let http = build_http_client(&agent_tls).expect("build http client");

    // Hitting any endpoint should fail at the TLS handshake.
    let result = http
        .get(format!("{}/v1/health", server.url()))
        .send()
        .await;
    assert!(
        result.is_err(),
        "server in mutual mode must refuse a client with no cert; got {:?}",
        result.map(|r| r.status())
    );

    server.shutdown().await;
}

#[tokio::test]
async fn server_mode_works_without_client_cert() {
    // Phase 7ak: `mode = server` accepts plain TLS (no client auth).
    // Useful for read-only deployments where bearer tokens already
    // identify the caller and operators just want transport encryption.
    let pki = write_pki(&[]);
    let tls = TlsConfig {
        mode: "server".into(),
        cert_file: Some(pki.server_cert.clone()),
        key_file: Some(pki.server_key.clone()),
        client_ca_file: None,
    };
    let server = TestServer::spawn(tls).await;

    let agent_tls = AgentTlsConfig {
        ca_file: Some(pki.ca_path.clone()),
        client_cert_file: None,
        client_key_file: None,
    };
    let http = build_http_client(&agent_tls).expect("build http client");

    let resp = http
        .get(format!("{}/v1/health", server.url()))
        .send()
        .await
        .expect("server-mode TLS should accept clients without certs");
    assert!(resp.status().is_success(), "got {}", resp.status());

    server.shutdown().await;
}

#[tokio::test]
async fn agent_rejects_unknown_server_ca() {
    // Generate two independent PKIs. The server uses one, the agent
    // is configured with the other's CA → handshake fails.
    let server_pki = write_pki(&[]);
    let other_pki = write_pki(&[]);
    let tls = TlsConfig {
        mode: "server".into(),
        cert_file: Some(server_pki.server_cert.clone()),
        key_file: Some(server_pki.server_key.clone()),
        client_ca_file: None,
    };
    let server = TestServer::spawn(tls).await;

    let agent_tls = AgentTlsConfig {
        ca_file: Some(other_pki.ca_path.clone()),
        client_cert_file: None,
        client_key_file: None,
    };
    let http = build_http_client(&agent_tls).expect("build http client");

    let result = http
        .get(format!("{}/v1/health", server.url()))
        .send()
        .await;
    assert!(
        result.is_err(),
        "agent with wrong CA must reject server's cert; got {:?}",
        result.map(|r| r.status())
    );

    server.shutdown().await;
}
