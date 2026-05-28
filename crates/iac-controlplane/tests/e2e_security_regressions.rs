// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end regression coverage for three Phase 9 security fixes that were
//! previously validated only at the lib-test level (218/218 controlplane unit
//! tests). Driving each through the live axum router + a real `iac-agent` /
//! HTTP submitter catches anything a future refactor of the SQL or routing
//! layers would silently undo.
//!
//! Covered:
//!   * #4 — `list_desired_state_for_agent` cross-agent leak. Before fea1036
//!     the endpoint joined `desired_states` to `assignments` purely by
//!     `operation_id`, so any agent that had ANY assignment in an operation
//!     would see the WHOLE operation's desired-state — including resources
//!     routed to other agents.
//!   * #6 — observations/drift cross-env spoofing. Before b4b98e1 an
//!     authenticated staging-env agent could push observations / drift events
//!     stamped with a `prod/...` resource_id; the server stored them verbatim,
//!     polluting prod drift views.
//!   * #7 — submit env mismatch. Before b4b98e1 `extract_routing` silently
//!     accepted resources whose `metadata.environment` differed from the
//!     operation's environment, while policy / rate-limit / maintenance
//!     checks ran against the operation's env — effectively a cross-env
//!     routing bypass.

mod common;

use common::{ADMIN_TOKEN, TestServer, client};
use iac_core::ResourceId;
use iac_core::diff::{Diff, DiffKind, FieldChange};
use iac_core::protocol::v1::{
    DesiredStateBatch, DriftBatch, DriftItem, ObservationBatch, ObservationItem, RegisterRequest,
    RegisterResponse, SubmitOperationRequest, SubmitOperationResponse,
};
use jiff::Timestamp;
use reqwest::StatusCode;
use serde_json::json;

/// Register an agent on the test server and return the issued bearer token.
/// All tests use this — the agent crate's own bootstrap is more than we need
/// for these regressions, which only exercise the server-side endpoints.
async fn register(server: &TestServer, name: &str, environment: &str) -> RegisterResponse {
    let resp = client()
        .post(server.endpoint("/v1/agents/register"))
        .json(&RegisterRequest {
            name: name.to_string(),
            environment: environment.to_string(),
            metadata: serde_json::json!({}),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register {name} failed");
    resp.json().await.unwrap()
}

fn file_resource(
    name: &str,
    env: &str,
    path: &str,
    content: &str,
    host: Option<&str>,
) -> serde_json::Value {
    let mut spec = json!({
        "path": path,
        "mode": "0644",
        "content": format!("{content}\n"),
    });
    if let Some(h) = host {
        spec["hostSelector"] = json!({ "name": h });
    }
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": spec,
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  #4 — cross-agent desired-state leak
// ─────────────────────────────────────────────────────────────────────────

/// One operation routes resource X to host-A and resource Y to host-B. Each
/// agent's `GET /v1/agents/{id}/desired-state` must only see ITS resource;
/// pre-fea1036 both agents would see both rows.
#[tokio::test]
async fn desired_state_per_agent_does_not_leak_other_agents_resources() {
    let server = TestServer::spawn().await;

    let a = register(&server, "host-A", "prod").await;
    let b = register(&server, "host-B", "prod").await;

    // Two resources, distinct hostSelector. Server-side routing should drop
    // each into the matching agent's assignment payload.
    let res_a = file_resource("only-on-a", "prod", "/tmp/iac-leak-a", "AAA", Some("host-A"));
    let res_b = file_resource("only-on-b", "prod", "/tmp/iac-leak-b", "BBB", Some("host-B"));

    let resp = client()
        .post(server.endpoint("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "op".into(),
            source_commit: None,
            summary: None,
            resources: vec![res_a, res_b],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _submit: SubmitOperationResponse = resp.json().await.unwrap();

    // Pull host-A's desired-state list.
    let list_a: DesiredStateBatch = client()
        .get(server.endpoint(&format!("/v1/agents/{}/desired-state", a.agent_id)))
        .bearer_auth(&a.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids_a: Vec<String> = list_a
        .items
        .iter()
        .map(|i| i.resource_id.to_string())
        .collect();
    assert!(
        ids_a.contains(&"file/prod/only-on-a".to_string()),
        "host-A must see its own resource: {ids_a:?}"
    );
    assert!(
        !ids_a.contains(&"file/prod/only-on-b".to_string()),
        "host-A must NOT see host-B's resource (regression #4): {ids_a:?}"
    );

    // Pull host-B's desired-state list — mirror assertion.
    let list_b: DesiredStateBatch = client()
        .get(server.endpoint(&format!("/v1/agents/{}/desired-state", b.agent_id)))
        .bearer_auth(&b.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids_b: Vec<String> = list_b
        .items
        .iter()
        .map(|i| i.resource_id.to_string())
        .collect();
    assert!(ids_b.contains(&"file/prod/only-on-b".to_string()));
    assert!(
        !ids_b.contains(&"file/prod/only-on-a".to_string()),
        "host-B must NOT see host-A's resource (regression #4): {ids_b:?}"
    );

    server.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────
//  #6 — agent reports stamped with a cross-env resource_id
// ─────────────────────────────────────────────────────────────────────────

fn parse_rid(s: &str) -> ResourceId {
    ResourceId::parse(s).unwrap()
}

#[tokio::test]
async fn observations_reject_resource_id_in_wrong_env() {
    let server = TestServer::spawn().await;
    let staging = register(&server, "staging-vm", "staging").await;

    // Authenticated staging agent attempts to push an observation stamped
    // with a prod resource_id. Before b4b98e1 this was a clean 200 OK.
    let resp = client()
        .post(server.endpoint(&format!(
            "/v1/agents/{}/observations",
            staging.agent_id
        )))
        .bearer_auth(&staging.token)
        .json(&ObservationBatch {
            items: vec![ObservationItem {
                resource_id: parse_rid("file/prod/sensitive"),
                observed_at: Timestamp::now().to_string(),
                present: true,
                spec: json!({"path": "/etc/sensitive"}),
                facts: json!({}),
            }],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "cross-env observation must be rejected (regression #6); got {}",
        resp.status()
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("env") && body.contains("agent"),
        "rejection should name the env mismatch; got body: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn drift_rejects_resource_id_in_wrong_env() {
    let server = TestServer::spawn().await;
    let staging = register(&server, "staging-vm", "staging").await;

    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/drift", staging.agent_id)))
        .bearer_auth(&staging.token)
        .json(&DriftBatch {
            items: vec![DriftItem {
                resource_id: parse_rid("file/prod/sensitive"),
                severity: "high".into(),
                detected_at: Timestamp::now().to_string(),
                diff: Diff {
                    kind: DiffKind::Update,
                    changes: vec![FieldChange {
                        field: "content".into(),
                        from: None,
                        to: None,
                        sensitive: false,
                    }],
                    reasons: vec!["spoof attempt".into()],
                    reversible: true,
                },
            }],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "cross-env drift must be rejected (regression #6); got {}",
        resp.status()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn observations_with_matching_env_still_pass() {
    // Counter-test: the env check must not reject legitimate same-env
    // observations. A regression that over-rejects would silently break
    // every agent in the fleet, so we lock it down explicitly.
    let server = TestServer::spawn().await;
    let agent = register(&server, "real-vm", "prod").await;
    let resp = client()
        .post(server.endpoint(&format!("/v1/agents/{}/observations", agent.agent_id)))
        .bearer_auth(&agent.token)
        .json(&ObservationBatch {
            items: vec![ObservationItem {
                resource_id: parse_rid("file/prod/legit"),
                observed_at: Timestamp::now().to_string(),
                present: true,
                spec: json!({"path": "/tmp/x"}),
                facts: json!({}),
            }],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    server.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────
//  #7 — operation submit with metadata.environment != operation env
// ─────────────────────────────────────────────────────────────────────────

/// Operator submits `environment: staging` but a resource carries
/// `metadata.environment: prod`. Before b4b98e1 this was silently accepted;
/// the prod resource then rode the staging policy / rate-limit / maintenance
/// channel. Now must 400.
#[tokio::test]
async fn submit_rejects_resource_env_mismatch() {
    let server = TestServer::spawn().await;
    let resource = file_resource("config", "prod", "/tmp/iac-mismatch", "x", None);

    let resp = client()
        .post(server.endpoint("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "staging".into(),
            requested_by: "op".into(),
            source_commit: None,
            summary: None,
            resources: vec![resource],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "env-mismatch submit must be rejected (regression #7); got {}",
        resp.status()
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("environment") && body.contains("prod") && body.contains("staging"),
        "rejection should name both env strings; got: {body}"
    );

    server.shutdown().await;
}

/// Counter-test: omitting `metadata.environment` entirely (inherit op env)
/// still works — the rejection must only fire on EXPLICIT mismatch.
#[tokio::test]
async fn submit_accepts_resource_without_explicit_environment() {
    let server = TestServer::spawn().await;
    let resource = json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": "config" },     // no environment field
        "spec": {
            "path": "/tmp/iac-inherit",
            "mode": "0644",
            "content": "x\n",
        }
    });

    let resp = client()
        .post(server.endpoint("/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "op".into(),
            source_commit: None,
            summary: None,
            resources: vec![resource],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    server.shutdown().await;
}
