// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 6c: audit log. The server records key events to `audit_events`
//! and exposes them via `GET /v1/audit` (admin auth).

mod common;

use common::{ADMIN_TOKEN, TestServer};

use iac_core::ResourceId;
use iac_core::diff::{Diff, DiffKind};
use iac_core::protocol::v1::{
    AuditEvent, DriftAcceptRequest, DriftBatch, DriftIgnoreRequest, DriftItem, DriftSummary,
    RegisterRequest, RegisterResponse, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;

async fn fetch_audit(server: &TestServer, qs: &str) -> Vec<AuditEvent> {
    reqwest::Client::new()
        .get(format!("{}/v1/audit?{qs}", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn agent_register_emits_audit_event() {
    let server = TestServer::spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .json(&RegisterRequest {
            name: "vm14".into(),
            environment: "audit".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap();
    let creds: RegisterResponse = resp.json().await.unwrap();

    let events = fetch_audit(&server, "kind=agent.registered").await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.actor, "system");
    assert_eq!(e.agent_id.as_deref(), Some(creds.agent_id.as_str()));
    assert_eq!(e.payload["name"], "vm14");
    assert_eq!(e.payload["environment"], "audit");

    server.shutdown().await;
}

#[tokio::test]
async fn operation_submission_records_admin_audit() {
    let server = TestServer::spawn().await;
    // Register one agent so the resource has somewhere to route.
    let _ = reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .json(&RegisterRequest {
            name: "agent-1".into(),
            environment: "audit".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap();

    let req = SubmitOperationRequest {
        environment: "audit".into(),
        requested_by: "alice".into(),
        source_commit: Some("deadbeef".into()),
        summary: Some("change xyz".into()),
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "x", "environment": "audit" },
            "spec": { "path": "/tmp/x", "mode": "0644", "content": "y\n" }
        })],
        canary: None,
    };
    let submit: SubmitOperationResponse = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let events = fetch_audit(&server, "kind=operation.submitted").await;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.actor, "admin");
    assert_eq!(
        e.operation_id.as_deref(),
        Some(submit.operation_id.as_str())
    );
    assert_eq!(e.payload["requested_by"], "alice");
    assert_eq!(e.payload["source_commit"], "deadbeef");
    assert_eq!(e.payload["resource_count"], 1);

    server.shutdown().await;
}

#[tokio::test]
async fn drift_accept_and_ignore_record_audit_with_payload() {
    let server = TestServer::spawn().await;
    // Register and push a drift event.
    let creds: RegisterResponse = reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .json(&RegisterRequest {
            name: "agent-x".into(),
            environment: "audit".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let item = DriftItem {
        resource_id: ResourceId::new("file", "audit", "x"),
        severity: "warning".into(),
        detected_at: jiff::Timestamp::now().to_string(),
        diff: Diff {
            kind: DiffKind::Update,
            changes: vec![],
            reasons: vec![],
            reversible: true,
        },
    };
    reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/drift",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth(&creds.token)
        .json(&DriftBatch { items: vec![item] })
        .send()
        .await
        .unwrap();

    // Accept it.
    let drifts: Vec<DriftSummary> = reqwest::Client::new()
        .get(format!("{}/v1/drift", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id1 = drifts[0].id;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id1}/accept", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftAcceptRequest {
            reason: "manual hotfix".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let accepted = fetch_audit(&server, "kind=drift.accepted").await;
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].drift_id, Some(id1));
    assert_eq!(accepted[0].payload["reason"], "manual hotfix");

    // Push another drift to test ignore.
    let item = DriftItem {
        resource_id: ResourceId::new("file", "audit", "y"),
        severity: "warning".into(),
        detected_at: jiff::Timestamp::now().to_string(),
        diff: Diff::no_change(),
    };
    reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/drift",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth(&creds.token)
        .json(&DriftBatch { items: vec![item] })
        .send()
        .await
        .unwrap();
    let drifts: Vec<DriftSummary> = reqwest::Client::new()
        .get(format!("{}/v1/drift", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id2 = drifts[0].id;
    let until = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().try_hours(1).unwrap())
        .unwrap()
        .to_string();
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id2}/ignore", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftIgnoreRequest {
            until: until.clone(),
            reason: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ignored = fetch_audit(&server, "kind=drift.ignored").await;
    assert_eq!(ignored.len(), 1);
    assert_eq!(ignored[0].drift_id, Some(id2));

    server.shutdown().await;
}

#[tokio::test]
async fn audit_endpoint_requires_admin() {
    let server = TestServer::spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", server.url()))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn audit_filters_compose() {
    let server = TestServer::spawn().await;
    // Two agents, two operations — verify per-actor and per-operation filters
    // each return only the matching subset.
    for n in ["agent-a", "agent-b"] {
        let _ = reqwest::Client::new()
            .post(format!("{}/v1/agents/register", server.url()))
            .json(&RegisterRequest {
                name: n.into(),
                environment: "audit".into(),
                metadata: json!({}),
            })
            .send()
            .await
            .unwrap();
    }

    // Submit two ops.
    let mut op_ids: Vec<String> = vec![];
    for env in ["audit", "audit"] {
        let resp: SubmitOperationResponse = reqwest::Client::new()
            .post(format!("{}/v1/operations", server.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&SubmitOperationRequest {
                environment: env.into(),
                requested_by: "alice".into(),
                source_commit: None,
                summary: None,
                resources: vec![json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "file",
                    "metadata": { "name": "x", "environment": env },
                    "spec": {
                        "path": "/tmp/x",
                        "mode": "0644",
                        "content": "y\n",
                        "hostSelector": { "name": "agent-a" }
                    }
                })],
                canary: None,
            })
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        op_ids.push(resp.operation_id);
    }

    // Filter by actor=admin: everything operator-initiated.
    let admin_events = fetch_audit(&server, "actor=admin").await;
    assert!(admin_events.iter().all(|e| e.actor == "admin"));

    // Filter by operation_id of the first op.
    let op_events = fetch_audit(&server, &format!("operation_id={}", op_ids[0])).await;
    assert!(
        op_events
            .iter()
            .all(|e| e.operation_id.as_deref() == Some(op_ids[0].as_str()))
    );
    assert!(!op_events.is_empty());

    // Filter by kind.
    let kind_events = fetch_audit(&server, "kind=agent.registered").await;
    assert_eq!(kind_events.len(), 2);
    for e in &kind_events {
        assert_eq!(e.kind, "agent.registered");
    }

    // Limit clamp: ask for absurdly large, get up to 1000 (capped server-side).
    let many = fetch_audit(&server, "limit=99999").await;
    assert!(many.len() <= 1000);

    server.shutdown().await;
}
