// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 4: drift workflow endpoints — accept and ignore (with TTL).

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_core::diff::{Diff, DiffKind, FieldChange};
use iac_core::protocol::v1::{
    DriftAcceptRequest, DriftBatch, DriftIgnoreRequest, DriftItem, DriftSummary, RegisterRequest,
    RegisterResponse,
};
use iac_core::ResourceId;
use reqwest::StatusCode;
use serde_json::json;


async fn register(server: &TestServer) -> RegisterResponse {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/agents/register", server.url()))
        .json(&RegisterRequest {
            name: format!("agent-{}", ulid::Ulid::new()),
            environment: "drift".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.json().await.unwrap()
}

async fn push_drift(
    server: &TestServer,
    creds: &RegisterResponse,
    resource_name: &str,
) {
    let client = reqwest::Client::new();
    let item = DriftItem {
        resource_id: ResourceId::new("file", "drift", resource_name),
        severity: "warning".into(),
        detected_at: jiff::Timestamp::now().to_string(),
        diff: Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "content_sha256".into(),
                from: None,
                to: None,
                sensitive: false,
            }],
            reasons: vec!["content differs".into()],
            reversible: true,
        },
    };
    let resp = client
        .post(format!("{}/v1/agents/{}/drift", server.url(), creds.agent_id))
        .bearer_auth(&creds.token)
        .json(&DriftBatch { items: vec![item] })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn list_open(server: &TestServer) -> Vec<DriftSummary> {
    reqwest::Client::new()
        .get(format!("{}/v1/drift", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn accept_marks_drift_resolved() {
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    push_drift(&server, &creds, "x").await;

    let drifts = list_open(&server).await;
    assert_eq!(drifts.len(), 1);
    let id = drifts[0].id;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/drift/{id}/accept", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftAcceptRequest {
            reason: "expected after manual hotfix".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Open list now empty.
    assert_eq!(list_open(&server).await.len(), 0);

    // GET /v1/drift/{id} still returns it but with `resolved_at` populated.
    let resp = client
        .get(format!("{}/v1/drift/{id}", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let row: DriftSummary = resp.json().await.unwrap();
    assert!(row.resolved_at.is_some());
    assert!(row.resolution.unwrap().starts_with("accepted: "));

    server.shutdown().await;
}

#[tokio::test]
async fn ignore_hides_drift_until_ttl_expires() {
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    push_drift(&server, &creds, "y").await;

    let drifts = list_open(&server).await;
    let id = drifts[0].id;

    // Ignore until 1 hour from now.
    let until = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().try_hours(1).unwrap())
        .unwrap()
        .to_string();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/drift/{id}/ignore", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftIgnoreRequest { until: until.clone(), reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List excludes it now.
    assert_eq!(list_open(&server).await.len(), 0);

    // GET single still exposes ignored_until.
    let row: DriftSummary = client
        .get(format!("{}/v1/drift/{id}", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(row.ignored_until.is_some());
    assert!(row.resolved_at.is_none());

    // Ignore with a past timestamp un-hides it.
    let past = jiff::Timestamp::now()
        .checked_sub(jiff::Span::new().try_hours(1).unwrap())
        .unwrap()
        .to_string();
    let resp = client
        .post(format!("{}/v1/drift/{id}/ignore", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftIgnoreRequest { until: past, reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(list_open(&server).await.len(), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn accept_without_admin_token_is_unauthorized() {
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    push_drift(&server, &creds, "z").await;
    let id = list_open(&server).await[0].id;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id}/accept", server.url()))
        .bearer_auth("wrong")
        .json(&DriftAcceptRequest { reason: "x".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // And without ANY auth header.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id}/accept", server.url()))
        .json(&DriftAcceptRequest { reason: "x".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn empty_reason_is_rejected() {
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    push_drift(&server, &creds, "w").await;
    let id = list_open(&server).await[0].id;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id}/accept", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftAcceptRequest { reason: "  ".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    server.shutdown().await;
}

#[tokio::test]
async fn invalid_until_returns_400() {
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    push_drift(&server, &creds, "v").await;
    let id = list_open(&server).await[0].id;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id}/ignore", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftIgnoreRequest { until: "not-a-time".into(), reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    server.shutdown().await;
}

#[tokio::test]
async fn nonexistent_drift_returns_404() {
    let server = TestServer::spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/9999/accept", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftAcceptRequest { reason: "x".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    server.shutdown().await;
}

#[tokio::test]
async fn revert_creates_a_fresh_operation_for_the_drifted_resource() {
    // Phase 7be: full workflow.
    //   1. Register an agent + submit an operation with one file resource
    //      (so the desired-state row gets stored).
    //   2. Push a drift event for that resource.
    //   3. POST /v1/drift/<id>/revert.
    //   4. Verify the response has a non-empty operation_id + the
    //      original resource_id, and that the new operation exists with
    //      the same desired-state shape.
    use iac_core::protocol::v1::{
        DriftRevertRequest, DriftRevertResponse, OperationDesiredState,
        SubmitOperationRequest, SubmitOperationResponse,
    };
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    let client = reqwest::Client::new();

    // 1. Submit an operation that establishes the desired-state.
    let resource = json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": "config", "environment": "drift" },
        "spec": {
            "path": "/etc/iac/config.toml",
            "mode": "0644",
            "content": "version = 1\n",
        }
    });
    let submit_resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "drift".into(),
            requested_by: "op".into(),
            source_commit: Some("commit-1".into()),
            summary: Some("initial apply".into()),
            resources: vec![resource], canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(submit_resp.status(), StatusCode::OK);
    let submit_body: SubmitOperationResponse = submit_resp.json().await.unwrap();
    let original_op_id = submit_body.operation_id;

    // 2. Push a drift event for the resource we just submitted. The
    //    `register` helper used `agent-<ulid>` and `drift` env, but it
    //    didn't actually wire the agent up to handle the operation —
    //    we don't need that for this test; we only need a drift_event
    //    row tied to the same resource_id that has a desired-state.
    push_drift(&server, &creds, "config").await;
    let drift = list_open(&server).await.into_iter().next().unwrap();

    // 3. Revert.
    let revert_resp = client
        .post(format!("{}/v1/drift/{}/revert", server.url(), drift.id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftRevertRequest {
            source_commit: Some("revert-of-drift".into()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        revert_resp.status(),
        StatusCode::OK,
        "revert failed: {}",
        revert_resp.text().await.unwrap()
    );
    let revert_body: DriftRevertResponse = revert_resp.json().await.unwrap();
    assert!(!revert_body.operation_id.is_empty(), "new op id present");
    assert_ne!(revert_body.operation_id, original_op_id, "must be a NEW op");
    assert_eq!(revert_body.resource_id, "file/drift/config");

    // 4. The new operation should have one desired-state row matching the
    //    original spec. Hit /v1/operations/<id>/desired-state.
    let ds_resp = client
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            revert_body.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ds_resp.status(), StatusCode::OK);
    let ds: OperationDesiredState = ds_resp.json().await.unwrap();
    assert_eq!(ds.items.len(), 1, "single resource on the revert op");
    let item = &ds.items[0];
    assert_eq!(item.resource_id, "file/drift/config");
    assert_eq!(
        item.resource["spec"]["path"].as_str(),
        Some("/etc/iac/config.toml"),
        "spec preserved verbatim from the latest desired-state row"
    );

    // 5. The drift itself remains OPEN — operator must `accept` after
    //    confirming the revert converged.
    let still_open = list_open(&server).await;
    assert!(
        still_open.iter().any(|d| d.id == drift.id),
        "drift must stay open after revert"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn revert_rejects_already_resolved_drift() {
    use iac_core::protocol::v1::DriftRevertRequest;
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    let client = reqwest::Client::new();

    // Set up a desired-state.
    let resource = json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": "x", "environment": "drift" },
        "spec": { "path": "/etc/x.toml", "mode": "0644", "content": "x\n" }
    });
    let submit = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({
            "environment": "drift",
            "requested_by": "op",
            "resources": [resource],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(submit.status(), StatusCode::OK);

    push_drift(&server, &creds, "x").await;
    let drift = list_open(&server).await.into_iter().next().unwrap();

    // Mark it accepted first.
    let accept = client
        .post(format!("{}/v1/drift/{}/accept", server.url(), drift.id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftAcceptRequest { reason: "fixed manually".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(accept.status(), StatusCode::OK);

    // Now revert should refuse.
    let revert = client
        .post(format!("{}/v1/drift/{}/revert", server.url(), drift.id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftRevertRequest { source_commit: None })
        .send()
        .await
        .unwrap();
    assert_eq!(revert.status(), StatusCode::BAD_REQUEST);
    let body = revert.text().await.unwrap();
    assert!(body.contains("already resolved"), "got: {body}");

    server.shutdown().await;
}

#[tokio::test]
async fn accept_bulk_resolves_every_matching_open_drift() {
    // Phase 7bf: push three events spanning two kinds; accept-bulk
    // with `kind=file` resolves only the file events. The non-matching
    // event stays open.
    use iac_core::protocol::v1::{
        DriftBulkAcceptRequest, DriftBulkFilter, DriftBulkResponse,
    };
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    let client = reqwest::Client::new();

    // The agent drift POST auto-closes any open drift NOT in the
    // batch — so we have to push all three in one shot.
    let mk_item = |kind: &str, name: &str| iac_core::protocol::v1::DriftItem {
        resource_id: iac_core::ResourceId::new(kind, "drift", name),
        severity: "warning".into(),
        detected_at: jiff::Timestamp::now().to_string(),
        diff: iac_core::diff::Diff {
            kind: iac_core::diff::DiffKind::Update,
            changes: vec![],
            reasons: vec!["differs".into()],
            reversible: true,
        },
    };
    let resp = client
        .post(format!("{}/v1/agents/{}/drift", server.url(), creds.agent_id))
        .bearer_auth(&creds.token)
        .json(&iac_core::protocol::v1::DriftBatch {
            items: vec![
                mk_item("file", "file-a"),
                mk_item("file", "file-b"),
                mk_item("docker.container", "web"),
            ],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(list_open(&server).await.len(), 3);

    // Bulk-accept only the file kind.
    let resp = client
        .post(format!("{}/v1/drift/accept-bulk", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftBulkAcceptRequest {
            reason: "fixed in commit deadbeef".into(),
            filter: DriftBulkFilter {
                agent_id: None,
                kind: Some("file".into()),
                severity: None,
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "bulk accept failed: {}",
        resp.text().await.unwrap()
    );
    let body: DriftBulkResponse = resp.json().await.unwrap();
    assert_eq!(body.matched, 2, "expected the two file events resolved");

    let still_open = list_open(&server).await;
    assert_eq!(still_open.len(), 1);
    assert_eq!(still_open[0].kind, "docker.container");

    server.shutdown().await;
}

#[tokio::test]
async fn accept_bulk_rejects_empty_filter() {
    // Phase 7bf: an all-None filter would close the entire drift
    // history with one mistyped command. Server returns 400 instead.
    use iac_core::protocol::v1::{DriftBulkAcceptRequest, DriftBulkFilter};
    let server = TestServer::spawn().await;
    let _ = register(&server).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/accept-bulk", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftBulkAcceptRequest {
            reason: "everything".into(),
            filter: DriftBulkFilter::default(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("agent_id, kind, or severity"),
        "expected explanation, got: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn ignore_bulk_silences_matching_for_ttl() {
    // Phase 7bf: silence file-kind drift for 7 days; verify list
    // hides them, then verify other kinds remain visible.
    use iac_core::protocol::v1::{
        DriftBulkFilter, DriftBulkIgnoreRequest, DriftBulkResponse,
    };
    let server = TestServer::spawn().await;
    let creds = register(&server).await;
    let client = reqwest::Client::new();

    let mk_item = |name: &str| iac_core::protocol::v1::DriftItem {
        resource_id: iac_core::ResourceId::new("file", "drift", name),
        severity: "warning".into(),
        detected_at: jiff::Timestamp::now().to_string(),
        diff: iac_core::diff::Diff {
            kind: iac_core::diff::DiffKind::Update,
            changes: vec![],
            reasons: vec!["differs".into()],
            reversible: true,
        },
    };
    let resp = client
        .post(format!("{}/v1/agents/{}/drift", server.url(), creds.agent_id))
        .bearer_auth(&creds.token)
        .json(&iac_core::protocol::v1::DriftBatch {
            items: vec![mk_item("a"), mk_item("b")],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(list_open(&server).await.len(), 2);

    let resp = client
        .post(format!("{}/v1/drift/ignore-bulk", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftBulkIgnoreRequest {
            ttl: "7d".into(),
            filter: DriftBulkFilter {
                agent_id: None,
                kind: Some("file".into()),
                severity: None,
            },
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: DriftBulkResponse = resp.json().await.unwrap();
    assert_eq!(body.matched, 2);

    let still_open = list_open(&server).await;
    assert!(
        still_open.is_empty(),
        "ignored events should not appear in list_open"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn revert_404s_when_no_desired_state_exists() {
    // Phase 7be: pushing drift for a resource the server never had a
    // desired-state for (e.g. a stale event from an old config) must
    // produce a clean 400 explaining the gap, not a 500.
    use iac_core::protocol::v1::DriftRevertRequest;
    let server = TestServer::spawn().await;
    let creds = register(&server).await;

    // Push drift for a resource with no prior submit.
    push_drift(&server, &creds, "ghost").await;
    let drift = list_open(&server).await.into_iter().next().unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{}/revert", server.url(), drift.id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&DriftRevertRequest { source_commit: None })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("no desired-state row"),
        "expected explanatory message, got: {body}"
    );

    server.shutdown().await;
}
