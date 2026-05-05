// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7l: `GET /v1/expanders` discovery. Returns the catalog of
//! composite kinds the server expands. Open to Viewer+ — operators
//! shouldn't need elevated roles to discover what they can submit.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_controlplane::expansion::ExpanderDescriptor;
use iac_controlplane::identity::Role;
use iac_controlplane::store::CreateUser;
use iac_core::protocol::v1::{LoginRequest, LoginResponse};
use reqwest::StatusCode;


#[tokio::test]
async fn admin_lists_expanders() {
    let server = TestServer::spawn().await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/expanders", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let list: Vec<ExpanderDescriptor> = r.json().await.unwrap();
    let kinds: Vec<&str> = list.iter().map(|d| d.kind.as_str()).collect();
    // Order matters — list_expanders returns a stable order.
    assert_eq!(kinds, vec!["service", "cron-job-bundle", "web-with-monitoring"]);
    // Each descriptor names primitives it emits.
    let svc = list.iter().find(|d| d.kind == "service").unwrap();
    assert!(svc.emits.contains(&"docker.container".to_string()));
    assert!(svc.emits.contains(&"nginx.vhost".to_string()));
    // Phase 7p: spec_fields populated.
    assert!(svc.spec_fields.iter().any(|f| f.name == "image" && f.required));
    assert!(svc.spec_fields.iter().any(|f| f.name == "port" && f.required));
    assert!(svc.spec_fields.iter().any(|f| f.name == "domain" && f.required));
    assert!(svc.spec_fields.iter().any(|f| f.name == "internal_port" && !f.required));
    server.shutdown().await;
}

#[tokio::test]
async fn show_returns_single_expander_with_spec_fields() {
    let server = TestServer::spawn().await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/expanders/web-with-monitoring", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let d: ExpanderDescriptor = r.json().await.unwrap();
    assert_eq!(d.kind, "web-with-monitoring");
    let names: Vec<&str> = d.spec_fields.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"image"));
    assert!(names.contains(&"port"));
    assert!(names.contains(&"domain"));
    assert!(names.contains(&"health_path"));
    assert!(names.contains(&"check_interval_minutes"));
    // Required vs. optional matches the deserialization rules in
    // expand_web_with_monitoring.
    let image = d.spec_fields.iter().find(|f| f.name == "image").unwrap();
    assert!(image.required);
    let health = d.spec_fields.iter().find(|f| f.name == "health_path").unwrap();
    assert!(!health.required);
    server.shutdown().await;
}

#[tokio::test]
async fn show_unknown_kind_returns_404() {
    let server = TestServer::spawn().await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/expanders/totally-fictional", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    server.shutdown().await;
}

#[tokio::test]
async fn show_requires_authentication() {
    let server = TestServer::spawn().await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/expanders/service", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    server.shutdown().await;
}

#[tokio::test]
async fn viewer_can_list_expanders() {
    let server = TestServer::spawn().await;
    server
        .store
        .create_user(CreateUser {
            username: "vince",
            password: "p",
            roles: vec![Role::Viewer],
        })
        .await
        .unwrap();
    let token = reqwest::Client::new()
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest { username: "vince".into(), password: "p".into() })
        .send()
        .await
        .unwrap()
        .json::<LoginResponse>()
        .await
        .unwrap()
        .token;

    let r = reqwest::Client::new()
        .get(format!("{}/v1/expanders", server.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    server.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_request_rejected() {
    let server = TestServer::spawn().await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/expanders", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    server.shutdown().await;
}
