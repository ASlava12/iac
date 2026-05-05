// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] doesn't reach here. Apply locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end HTTP tests against a live axum server bound to 127.0.0.1:0.

mod common;

use common::{client, TestServer};
use iac_core::diff::{Diff, DiffKind};
use iac_core::protocol::v1::{
    AgentHealth, AgentSummary, DriftAck, DriftBatch, DriftItem, DriftSummary, HeartbeatRequest,
    ObservationAck, ObservationBatch, ObservationItem, RegisterRequest, RegisterResponse,
};
use iac_core::ResourceId;
use reqwest::StatusCode;
use serde_json::json;

async fn register(server: &TestServer, name: &str, env: &str) -> RegisterResponse {
    let resp = client()
        .post(server.endpoint("/v1/agents/register"))
        .json(&RegisterRequest {
            name: name.into(),
            environment: env.into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register failed: {}", resp.text().await.unwrap());
    resp.json().await.unwrap()
}

#[tokio::test]
async fn health_endpoint_ok() {
    let server = TestServer::spawn().await;
    let resp = client().get(server.endpoint("/v1/health")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    server.shutdown().await;
}

#[tokio::test]
async fn register_then_heartbeat() {
    let server = TestServer::spawn().await;
    let creds = register(&server, "vm14", "prod").await;
    assert!(!creds.token.is_empty());

    // Heartbeat with valid token.
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/heartbeat", creds.agent_id)))
        .bearer_auth(&creds.token)
        .json(&HeartbeatRequest {
            status: AgentHealth::Healthy,
            managed: 5,
            open_drifts: 1,
            last_observe_at: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Heartbeat with wrong token → 401.
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/heartbeat", creds.agent_id)))
        .bearer_auth("bogus")
        .json(&HeartbeatRequest {
            status: AgentHealth::Healthy,
            managed: 5,
            open_drifts: 0,
            last_observe_at: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // No agent with that id → 401 too (don't leak existence).
    let resp = client()
        .post(server.endpoint("/v1/agents/01HQQQQQQQQQQQQQQQQQQQQQQQ/heartbeat"))
        .bearer_auth(&creds.token)
        .json(&HeartbeatRequest {
            status: AgentHealth::Healthy,
            managed: 0,
            open_drifts: 0,
            last_observe_at: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn duplicate_register_returns_conflict() {
    let server = TestServer::spawn().await;
    register(&server, "vm14", "prod").await;
    let resp = client()
        .post(server.endpoint("/v1/agents/register"))
        .json(&RegisterRequest {
            name: "vm14".into(),
            environment: "prod".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    server.shutdown().await;
}

#[tokio::test]
async fn observations_round_trip() {
    let server = TestServer::spawn().await;
    let creds = register(&server, "vm14", "prod").await;

    let item = ObservationItem {
        resource_id: ResourceId::new("file", "prod", "nginx-conf"),
        observed_at: jiff::Timestamp::now().to_string(),
        present: true,
        spec: json!({"path": "/etc/nginx/nginx.conf"}),
        facts: json!({"sha": "abc"}),
    };
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/observations", creds.agent_id)))
        .bearer_auth(&creds.token)
        .json(&ObservationBatch { items: vec![item] })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ack: ObservationAck = resp.json().await.unwrap();
    assert_eq!(ack.accepted, 1);

    // last_observation_at gets bumped on the agents table — verify via list.
    let resp = client()
        .get(server.endpoint("/v1/agents"))
        .bearer_auth("test-admin")
        .send()
        .await
        .unwrap();
    let agents: Vec<AgentSummary> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 1);
    assert!(agents[0].last_observation_at.is_some());

    server.shutdown().await;
}

#[tokio::test]
async fn drift_push_then_list_then_autoclose() {
    let server = TestServer::spawn().await;
    let creds = register(&server, "vm14", "prod").await;

    let r1 = ResourceId::new("file", "prod", "a");
    let r2 = ResourceId::new("file", "prod", "b");

    fn drift_for(rid: &ResourceId) -> DriftItem {
        DriftItem {
            resource_id: rid.clone(),
            severity: "warning".into(),
            detected_at: jiff::Timestamp::now().to_string(),
            diff: Diff {
                kind: DiffKind::Update,
                changes: vec![],
                reasons: vec!["something differs".into()],
                reversible: true,
            },
        }
    }

    // Push two drifts.
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/drift", creds.agent_id)))
        .bearer_auth(&creds.token)
        .json(&DriftBatch { items: vec![drift_for(&r1), drift_for(&r2)] })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ack: DriftAck = resp.json().await.unwrap();
    assert_eq!(ack.accepted, 2);

    // List → 2 open.
    let resp = client().get(server.endpoint("/v1/drift")).bearer_auth("test-admin").send().await.unwrap();
    let rows: Vec<DriftSummary> = resp.json().await.unwrap();
    assert_eq!(rows.len(), 2);

    // Push only r1 → r2 should auto-close.
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/drift", creds.agent_id)))
        .bearer_auth(&creds.token)
        .json(&DriftBatch { items: vec![drift_for(&r1)] })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = client().get(server.endpoint("/v1/drift")).bearer_auth("test-admin").send().await.unwrap();
    let rows: Vec<DriftSummary> = resp.json().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].resource_id.contains("/a"));

    // Push empty → r1 should also close.
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/drift", creds.agent_id)))
        .bearer_auth(&creds.token)
        .json(&DriftBatch { items: vec![] })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = client().get(server.endpoint("/v1/drift")).bearer_auth("test-admin").send().await.unwrap();
    let rows: Vec<DriftSummary> = resp.json().await.unwrap();
    assert_eq!(rows.len(), 0);

    server.shutdown().await;
}

#[tokio::test]
async fn missing_authorization_is_unauthorized() {
    let server = TestServer::spawn().await;
    let creds = register(&server, "vm14", "prod").await;

    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/observations", creds.agent_id)))
        .json(&ObservationBatch { items: vec![] })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn drift_filtering_by_agent_id() {
    let server = TestServer::spawn().await;
    let a = register(&server, "vm-a", "prod").await;
    let b = register(&server, "vm-b", "prod").await;

    fn one_drift(rid: ResourceId) -> DriftItem {
        DriftItem {
            resource_id: rid,
            severity: "warning".into(),
            detected_at: jiff::Timestamp::now().to_string(),
            diff: Diff::no_change(),
        }
    }

    client()
        .post(server.endpoint(&format!("/v1/agents/{}/drift", a.agent_id)))
        .bearer_auth(&a.token)
        .json(&DriftBatch {
            items: vec![one_drift(ResourceId::new("file", "prod", "for-a"))],
        })
        .send()
        .await
        .unwrap();
    client()
        .post(server.endpoint(&format!("/v1/agents/{}/drift", b.agent_id)))
        .bearer_auth(&b.token)
        .json(&DriftBatch {
            items: vec![one_drift(ResourceId::new("file", "prod", "for-b"))],
        })
        .send()
        .await
        .unwrap();

    let resp = client()
        .get(server.endpoint(&format!("/v1/drift?agent_id={}", a.agent_id)))
        .bearer_auth("test-admin")
        .send()
        .await
        .unwrap();
    let rows: Vec<DriftSummary> = resp.json().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].resource_id.contains("for-a"));

    server.shutdown().await;
}
