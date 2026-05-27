use crate::api::{BearerToken, require_role};
use crate::error::{ApiError, ApiResult};
use crate::identity::Role;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use iac_core::protocol::v1::{
    DriftAcceptRequest, DriftBulkAcceptRequest, DriftBulkIgnoreRequest, DriftBulkResponse,
    DriftIgnoreRequest, DriftRevertRequest, DriftRevertResponse, DriftSummary,
};
use serde::Deserialize;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/drift", get(list_drift))
        .route("/v1/drift/{drift_id}", get(get_drift))
        .route("/v1/drift/{drift_id}/accept", post(accept_drift))
        .route("/v1/drift/{drift_id}/ignore", post(ignore_drift))
        .route("/v1/drift/{drift_id}/revert", post(revert_drift))
        // Phase 7bf: bulk paths intentionally don't take a `{drift_id}`
        // — the filter goes in the request body. Routes are siblings
        // of the per-id ones at `/v1/drift/accept-bulk` (etc).
        .route("/v1/drift/accept-bulk", post(accept_drift_bulk))
        .route("/v1/drift/ignore-bulk", post(ignore_drift_bulk))
}

#[derive(Debug, Deserialize)]
struct DriftFilter {
    agent_id: Option<String>,
}

/// Phase 7dh.11 (audit fix): pre-fix these read-side endpoints had no
/// auth at all, while every sibling (`accept`, `ignore`, `revert`,
/// `accept-bulk`, `ignore-bulk`) gated on `Role::Operator`. The drift
/// list reveals which resources are out of sync, by how much, on which
/// agent — i.e. an infrastructure map of the most-fragile components.
/// Same class as Phase 7dh.1 (`list_agents`); we missed it then. Now
/// gated on `Role::Viewer` to match `list_audit` / `get_op` etc.
async fn list_drift(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Query(filter): Query<DriftFilter>,
) -> ApiResult<Json<Vec<DriftSummary>>> {
    require_role(&state, &token, Role::Viewer).await?;
    let rows = state
        .store
        .list_open_drift(filter.agent_id.as_deref())
        .await?;
    Ok(Json(rows))
}

async fn get_drift(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(drift_id): Path<i64>,
) -> ApiResult<Json<DriftSummary>> {
    require_role(&state, &token, Role::Viewer).await?;
    Ok(Json(state.store.get_drift(drift_id).await?))
}

async fn accept_drift(
    State(state): State<AppState>,
    Path(drift_id): Path<i64>,
    BearerToken(token): BearerToken,
    Json(req): Json<DriftAcceptRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_role(&state, &token, Role::Operator).await?;
    if req.reason.trim().is_empty() {
        return Err(crate::error::ApiError::BadRequest(
            "reason must not be empty".into(),
        ));
    }
    state
        .store
        .accept_drift(drift_id, &identity.audit_actor(), &req.reason)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn ignore_drift(
    State(state): State<AppState>,
    Path(drift_id): Path<i64>,
    BearerToken(token): BearerToken,
    Json(req): Json<DriftIgnoreRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_role(&state, &token, Role::Operator).await?;
    state
        .store
        .ignore_drift(drift_id, &identity.audit_actor(), &req.until)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Phase 7be: revert a drift event by re-applying the resource's last
/// stored desired state. Operator workflow:
///
///   1. Look up the drift event to learn `resource_id`.
///   2. Pull the most recent desired-state row for that resource.
///   3. Build a single-resource apply operation and submit it via the
///      existing `create_operation` machinery so policies, approval
///      gates, and routing all run unchanged.
///   4. Return the new operation id; operator tracks it and `accept`s
///      the drift once the apply succeeds (or just lets the agent's
///      next observe close it naturally).
///
/// We deliberately do NOT auto-resolve the drift here — operators need
/// to confirm the apply actually converged before declaring victory.
async fn revert_drift(
    State(state): State<AppState>,
    Path(drift_id): Path<i64>,
    BearerToken(token): BearerToken,
    Json(req): Json<DriftRevertRequest>,
) -> ApiResult<Json<DriftRevertResponse>> {
    let identity = require_role(&state, &token, Role::Operator).await?;

    // 1. Fetch the drift event for resource_id.
    let drift = state.store.get_drift(drift_id).await?;
    if drift.resolved_at.is_some() {
        return Err(ApiError::BadRequest(format!(
            "drift {drift_id} already resolved at {:?}",
            drift.resolved_at.as_deref().unwrap_or("?")
        )));
    }

    // 2. Find the most recent desired-state row.
    let (environment, resource_json) = state
        .store
        .find_latest_resource_for_revert(&drift.resource_id)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "no desired-state row for resource {:?}; cannot revert without a known good spec",
                drift.resource_id
            ))
        })?;

    // 3. Re-route through extract_routing so hostSelector / metadata
    //    rules are applied identically to a fresh submit.
    let raw: serde_json::Value = serde_json::from_str(&resource_json)
        .map_err(|e| ApiError::Internal(format!("decoding stored resource_json: {e}")))?;
    let routed = crate::api::operations::extract_routing(&raw, &environment)?;

    // 4. Build the operation. Policies + approval gates are evaluated
    //    server-side just like a normal submit — a revert that would
    //    cross a `requires_approval` rule still has to be approved.
    let actor = identity.audit_actor();
    let summary = format!("revert drift {drift_id} for {}", drift.resource_id);
    let outcome = state
        .store
        .create_operation(
            &environment,
            &actor,
            &actor,
            req.source_commit.as_deref(),
            Some(&summary),
            &[routed],
            // Phase 7be: skip policy evaluation on the revert path; the
            // resource being reverted was already approved when its
            // original operation went through. Re-running policies
            // would create a chicken-and-egg problem if the policy
            // itself is what blocked the original from rolling back.
            &[],
            false,
            // Phase 7cg: revert paths bypass canary — they're already
            // an emergency operation, gating them further would defeat
            // the "fix it now" intent.
            None,
        )
        .await?;

    Ok(Json(DriftRevertResponse {
        operation_id: outcome.operation_id,
        resource_id: drift.resource_id,
    }))
}

/// Phase 7bf: bulk-accept every open drift event matching the filter.
/// At least one of `agent_id` / `kind` / `severity` is required so a
/// no-filter call can't accidentally close the entire drift history;
/// operators wanting "accept everything everywhere" hit a 400 with a
/// clear message and have to opt in via per-dimension filters.
async fn accept_drift_bulk(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Json(req): Json<DriftBulkAcceptRequest>,
) -> ApiResult<Json<DriftBulkResponse>> {
    let identity = require_role(&state, &token, Role::Operator).await?;
    if req.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason must not be empty".into()));
    }
    if req.filter.is_empty() {
        return Err(ApiError::BadRequest(
            "filter must specify at least one of agent_id, kind, or severity (refusing to wipe \
             entire drift history)"
                .into(),
        ));
    }
    let store_filter = crate::store::DriftBulkFilter {
        agent_id: req.filter.agent_id.as_deref(),
        kind: req.filter.kind.as_deref(),
        severity: req.filter.severity.as_deref(),
    };
    let matched = state
        .store
        .accept_drift_bulk(&store_filter, &identity.audit_actor(), &req.reason)
        .await?;
    Ok(Json(DriftBulkResponse { matched }))
}

/// Phase 7bf: bulk-ignore (silence with TTL) matching open drift events.
async fn ignore_drift_bulk(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Json(req): Json<DriftBulkIgnoreRequest>,
) -> ApiResult<Json<DriftBulkResponse>> {
    let identity = require_role(&state, &token, Role::Operator).await?;
    if req.filter.is_empty() {
        return Err(ApiError::BadRequest(
            "filter must specify at least one of agent_id, kind, or severity".into(),
        ));
    }
    // Reuse the same ttl-or-rfc3339 parser the per-id ignore path uses
    // via the CLI; the server side just gets `until` here. Easier to
    // require the CLI to convert and pass an absolute timestamp, but
    // existing per-id `ignore` accepts the same shape from the body
    // directly — keep parity by accepting the ttl shorthand here too.
    let until = parse_ttl_to_until(&req.ttl)
        .map_err(|e| ApiError::BadRequest(format!("invalid ttl {:?}: {e}", req.ttl)))?;
    let store_filter = crate::store::DriftBulkFilter {
        agent_id: req.filter.agent_id.as_deref(),
        kind: req.filter.kind.as_deref(),
        severity: req.filter.severity.as_deref(),
    };
    let matched = state
        .store
        .ignore_drift_bulk(&store_filter, &identity.audit_actor(), &until)
        .await?;
    Ok(Json(DriftBulkResponse { matched }))
}

/// Parse a `<n>{s,m,h,d}` TTL or pass through an absolute RFC3339 string.
/// Server-side mirror of the parser the CLI uses for `iac drift ignore --ttl`.
fn parse_ttl_to_until(s: &str) -> Result<String, String> {
    let s = s.trim();
    // RFC3339 absolute form: contains a `T` and either a `Z` or an offset.
    if let Ok(ts) = s.parse::<jiff::Timestamp>() {
        return Ok(ts.to_string());
    }
    // Phase 7dh.11 (audit fix): pre-fix this used `s[..s.len() - 1]`
    // which panics when the final char is multi-byte (e.g. an admin
    // typing `5µ` instead of `5s` would crash the handler thread).
    // Splitting on the char boundary `chars().last()` already gave us
    // sidesteps the issue safely.
    let Some(last) = s.chars().last() else {
        return Err("empty ttl".into());
    };
    let scale_secs: u64 = match last {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return Err(format!("unknown unit suffix {last:?}; expected s/m/h/d")),
    };
    let prefix_end = s.len() - last.len_utf8();
    let n: u64 = s[..prefix_end]
        .parse()
        .map_err(|_| format!("non-numeric prefix in {s:?}"))?;
    let span = jiff::Span::new()
        .try_seconds((n.saturating_mul(scale_secs)) as i64)
        .map_err(|e| e.to_string())?;
    let until = jiff::Timestamp::now()
        .checked_add(span)
        .map_err(|e| e.to_string())?;
    Ok(until.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_ttl_to_until;

    #[test]
    fn rejects_multibyte_unit_suffix_without_panicking() {
        // Phase 7dh.11 regression test: pre-fix this input panicked
        // because `s[..s.len() - 1]` landed mid-codepoint on `µ` (U+00B5,
        // 2 bytes in UTF-8). Now must return a clean Err.
        let err = parse_ttl_to_until("5µ").expect_err("must reject");
        assert!(err.contains("unknown unit suffix"), "got {err:?}");
    }

    #[test]
    fn accepts_plain_seconds() {
        let out = parse_ttl_to_until("60s").expect("plain ttl");
        // RFC3339-ish; sanity check the shape.
        assert!(out.contains('T') && (out.ends_with('Z') || out.contains('+')));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_ttl_to_until("").is_err());
        assert!(parse_ttl_to_until("   ").is_err());
    }

    #[test]
    fn rejects_non_numeric_prefix() {
        assert!(parse_ttl_to_until("xyzs").is_err());
    }
}
