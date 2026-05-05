//! Read-only audit endpoint. Admin token required — these events expose
//! operator activity and resource identifiers.

use crate::api::{require_role, BearerToken};
use crate::error::ApiResult;
use crate::identity::Role;
use crate::server::AppState;
use crate::store::{AuditChainTip, AuditFilter};
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use iac_core::protocol::v1::AuditEvent;
use serde::{Deserialize, Serialize};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/audit", get(list_audit))
        .route("/v1/audit/chain-tip", get(get_chain_tip))
        .route("/v1/audit/verify", get(verify_chain))
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    since: Option<String>,
    kind: Option<String>,
    actor: Option<String>,
    operation_id: Option<String>,
    agent_id: Option<String>,
    limit: Option<i64>,
}

async fn list_audit(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    // Phase 7co (security fix #4.6): audit log is sensitive-by-default.
    // Pre-fix this required only `Viewer`; that let any read-only
    // user enumerate admins, see who ran what and when, and plan
    // social-engineering targets. Approver is the right floor —
    // anyone reviewing an operation already has approval-level trust.
    require_role(&state, &token, Role::Approver).await?;
    let filter = AuditFilter {
        since: q.since,
        kind: q.kind,
        actor: q.actor,
        operation_id: q.operation_id,
        agent_id: q.agent_id,
        limit: q.limit,
    };
    Ok(Json(state.store.list_audit(filter).await?))
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    ok: bool,
    broken_id: Option<i64>,
}

// Phase 7da.5: out-of-band trust anchor. Operators read this and pin
// it to a tamper-evident log (syslog → S3, immutable storage, signed
// witness). Approver-floor matches `list_audit` — anyone who can read
// audit events can already see the chain by walking it client-side.
async fn get_chain_tip(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<AuditChainTip>> {
    require_role(&state, &token, Role::Approver).await?;
    Ok(Json(state.store.audit_chain_tip().await?))
}

// Phase 7da.5: server-side chain verification. Returns the first
// id whose stored hash disagrees with the recomputed hash, or `ok:
// true` when the chain is intact. Cheaper to call than re-hashing
// client-side because the server already has indexed access.
async fn verify_chain(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<VerifyResponse>> {
    require_role(&state, &token, Role::Approver).await?;
    let broken_id = state.store.audit_verify_chain().await?;
    Ok(Json(VerifyResponse {
        ok: broken_id.is_none(),
        broken_id,
    }))
}
