use crate::api::{BearerToken, require_role};
use crate::error::{ApiError, ApiResult};
use crate::identity::Role;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    routing::{get, post},
};
use iac_core::protocol::v1::{
    AgentSummary, AssignmentList, AssignmentResultRequest, DesiredStateBatch, DriftAck, DriftBatch,
    HeartbeatRequest, ObservationAck, ObservationBatch, RegisterRequest, RegisterResponse,
};
use std::net::SocketAddr;

/// Phase 9 follow-up #15: annotation key under `metadata.annotations`
/// whose value is a comma-separated list of JSON pointers whose original
/// value carried a `${secret://...}` reference. The agent-side executor
/// uses this to flip `Diff::FieldChange::sensitive=true` so resolved
/// plaintext doesn't surface in drift reports or local plan/apply output.
/// Kept under the `iac.dev/` namespace so operator-authored annotations
/// can't collide.
pub const SECRET_FIELDS_ANNOTATION: &str = "iac.dev/secret-fields";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/agents", get(list_agents))
        .route("/v1/agents/register", post(register))
        .route("/v1/agents/{agent_id}/heartbeat", post(heartbeat))
        .route("/v1/agents/{agent_id}/observations", post(observations))
        .route("/v1/agents/{agent_id}/drift", post(drift))
        .route("/v1/agents/{agent_id}/assignments", get(list_assignments))
        .route(
            "/v1/agents/{agent_id}/assignments/{assignment_id}/result",
            post(assignment_result),
        )
        .route("/v1/agents/{agent_id}/desired-state", get(desired_state))
        // Phase 7cc: explicit token rotation. Auth via current token;
        // returns the new token; old hash is overwritten so subsequent
        // requests with the old token get 401.
        .route("/v1/agents/{agent_id}/rotate-token", post(rotate_token))
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    // Phase 9-F8 (security fix): per-IP rate-limit. The endpoint is
    // unauthenticated by design (agents need to bootstrap before they
    // have a token), so without this cap a single source could flood
    // both the agents table and the audit chain at line rate. Empirical
    // F8 storm test showed 250+ inserts in 10 s from one host before
    // this fix.
    //
    // Phase 9 follow-up: when the CP is behind a reverse proxy listed
    // in `trusted_proxies`, key by `X-Forwarded-For` so each real
    // client gets its own bucket. Untrusted peers still bucket by
    // socket IP — header is ignored, so a malicious client can't
    // dodge a bucket by setting the header themselves.
    let client_ip =
        crate::api::effective_client_ip(&headers, addr, &state.config().trusted_proxies);
    state
        .rate_limiter
        .check_and_record_register(&client_ip.to_string())
        .await?;
    // Phase 7cc: read TTL config from live snapshot so SIGHUP reload
    // picks up changes for new registrations without a restart.
    let ttl = state.config().agent_token_ttl_secs;
    let creds = state.store.register_agent(&req, ttl).await?;
    Ok(Json(RegisterResponse {
        agent_id: creds.agent_id,
        token: creds.token,
        // Phase 7cd: agent uses expires_at to schedule rotation.
        expires_at: creds.expires_at,
    }))
}

/// Phase 7cc: agent calls this with the current bearer token; server
/// issues a fresh token (with a new expiry computed from current TTL
/// config) and invalidates the old hash. Idempotent only by the
/// caller — repeated calls produce different tokens, but each
/// rotation succeeds independently.
async fn rotate_token(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<RegisterResponse>> {
    // Validate the current token before rotation. Same auth path as
    // every other agent endpoint — expired tokens get 401 and can't
    // self-renew (they need re-registration).
    let _ = state.store.authenticate(&agent_id, &token).await?;
    let ttl = state.config().agent_token_ttl_secs;
    let creds = state.store.rotate_agent_token(&agent_id, ttl).await?;
    Ok(Json(RegisterResponse {
        agent_id: creds.agent_id,
        token: creds.token,
        expires_at: creds.expires_at,
    }))
}

async fn heartbeat(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = state.store.authenticate(&agent_id, &token).await?;
    // Phase 7bh: per-agent rate limit. Auth runs first so 401s aren't
    // masked as 429s — only authenticated agent traffic counts toward
    // the bucket. Same rationale as the operation submit handler.
    state.rate_limiter.check_and_record_agent(&agent_id).await?;
    state.store.record_heartbeat(&agent_id, &req).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn observations(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<ObservationBatch>,
) -> ApiResult<Json<ObservationAck>> {
    let record = state.store.authenticate(&agent_id, &token).await?;
    state.rate_limiter.check_and_record_agent(&agent_id).await?;
    // Phase 9 follow-up: an authenticated staging agent could
    // previously push observations stamped with `resource_id`s in
    // another environment (e.g. `file/prod/...`). Server stored them
    // verbatim, polluting drift views and UI for the wrong env and
    // potentially masking real prod drift. Reject any batch item
    // whose resource_id environment doesn't match the agent's record.
    for item in &req.items {
        if item.resource_id.environment != record.environment {
            return Err(ApiError::BadRequest(format!(
                "observation resource_id env {:?} does not match agent env {:?}; \
                 refusing cross-env observation",
                item.resource_id.environment, record.environment
            )));
        }
    }
    let n = state
        .store
        .record_observations(&agent_id, &req.items)
        .await?;
    Ok(Json(ObservationAck { accepted: n }))
}

async fn drift(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<DriftBatch>,
) -> ApiResult<Json<DriftAck>> {
    let record = state.store.authenticate(&agent_id, &token).await?;
    state.rate_limiter.check_and_record_agent(&agent_id).await?;
    // Phase 9 follow-up: same cross-env guard as observations above.
    // A drift report for `file/prod/...` from a staging agent would
    // page on-call for an env this agent has no business touching.
    for item in &req.items {
        if item.resource_id.environment != record.environment {
            return Err(ApiError::BadRequest(format!(
                "drift resource_id env {:?} does not match agent env {:?}; \
                 refusing cross-env drift report",
                item.resource_id.environment, record.environment
            )));
        }
    }
    let n = state.store.record_drift(&agent_id, &req.items).await?;
    // Auto-close any open drift not in this batch — we treat each drift push
    // as the agent's complete current state.
    let current: Vec<String> = req
        .items
        .iter()
        .map(|i| i.resource_id.to_string())
        .collect();
    state.store.close_drift_not_in(&agent_id, &current).await?;
    Ok(Json(DriftAck { accepted: n }))
}

// Phase 7dh.1 (security audit closure): pre-7dh this endpoint had
// zero auth — any reachable client could enumerate the entire fleet
// (names, environments, health, last_seen). Now gated to `Viewer`,
// matching the rest of the read-side endpoints.
async fn list_agents(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<Vec<AgentSummary>>> {
    require_role(&state, &token, Role::Viewer).await?;
    Ok(Json(state.store.list_agents().await?))
}

async fn list_assignments(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<AssignmentList>> {
    let _ = state.store.authenticate(&agent_id, &token).await?;
    let mut items = state.store.fetch_pending_assignments(&agent_id).await?;
    // Phase 7co: secret resolution happens HERE, not at submit time.
    // The DB stores `${secret://...}` references; the substituted
    // values exist in memory only long enough to sign + ship the
    // envelope. Re-fetching by the same agent (or another agent) gets
    // a fresh resolution against the live registry — rotated secrets
    // propagate without resubmitting the manifest.
    //
    // Order matters: substitute → THEN sign. The signature must
    // cover what the agent actually applies, not the reference token.
    for env in &mut items {
        if let Some(registry) = state.secret_registry.as_deref() {
            for resource in &mut env.payload.resources {
                let (_, secret_pointers) = registry.substitute_with_pointers(resource).await?;
                // Phase 9 follow-up #15: tag the resource with the
                // list of JSON pointers whose original value carried a
                // `${secret://...}` reference. The executor consults
                // this tag when collecting FieldChange entries and
                // flips `sensitive=true` on the whole diff so a drift
                // report or local plan print can't leak the resolved
                // plaintext back through audit-visible channels.
                // We stash it under `metadata.annotations` because
                // that map already rides the wire and providers ignore
                // unknown keys — no protocol change needed.
                if !secret_pointers.is_empty() {
                    let entry = resource
                        .pointer_mut("/metadata/annotations")
                        .filter(|v| v.is_object())
                        .cloned();
                    let mut annotations = match entry {
                        Some(serde_json::Value::Object(map)) => map,
                        _ => serde_json::Map::new(),
                    };
                    annotations.insert(
                        SECRET_FIELDS_ANNOTATION.to_string(),
                        serde_json::Value::String(secret_pointers.join(",")),
                    );
                    if let Some(meta) = resource.pointer_mut("/metadata")
                        && let Some(map) = meta.as_object_mut()
                    {
                        map.insert("annotations".into(), serde_json::Value::Object(annotations));
                    }
                }
            }
        }
        let payload_json = serde_json::to_vec(&env.payload)?;
        env.signature = state
            .signer
            .sign(
                &agent_id,
                &env.assignment_id,
                &env.operation_id,
                &env.created_at,
                &payload_json,
            )
            .map_err(|e| crate::error::ApiError::Internal(format!("signing failed: {e}")))?;
        env.key_id = state.signer.key_id().to_string();
    }
    Ok(Json(AssignmentList { items }))
}

async fn assignment_result(
    State(state): State<AppState>,
    Path((agent_id, assignment_id)): Path<(String, String)>,
    BearerToken(token): BearerToken,
    Json(req): Json<AssignmentResultRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = state.store.authenticate(&agent_id, &token).await?;
    state
        .store
        .complete_assignment(&agent_id, &assignment_id, &req)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn desired_state(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<DesiredStateBatch>> {
    let _ = state.store.authenticate(&agent_id, &token).await?;
    let items = state.store.list_desired_state_for_agent(&agent_id).await?;
    Ok(Json(DesiredStateBatch { items }))
}
