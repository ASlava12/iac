use crate::api::{BearerToken, require_role};
use crate::depsort::topo_sort_by_depends_on;
use crate::error::{ApiError, ApiResult};
use crate::expansion::expand_resources;
use crate::identity::Role;
use crate::policy::{OperationFacts, evaluate};
use crate::server::AppState;
use crate::store::ResourceForRouting;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};

/// Phase 7j: header an admin sets to bypass an active maintenance
/// window. Lowercased per HTTP norms. Any non-empty value (`yes`,
/// `1`, `true`) opts in; missing or empty header → no bypass.
const MAINT_BYPASS_HEADER: &str = "x-iac-maintenance-bypass";
use iac_core::protocol::v1::{
    BlastRadius, OperationApproveRequest, OperationDesiredState, OperationListItem,
    OperationRejectRequest, OperationView, RollbackOperationRequest, RollbackOperationResponse,
    SubmitOperationRequest, SubmitOperationResponse, UnroutedResource,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/operations", post(submit).get(list_ops))
        .route("/v1/operations/{operation_id}", get(get_op))
        .route(
            "/v1/operations/{operation_id}/desired-state",
            get(get_op_desired_state),
        )
        .route("/v1/operations/{operation_id}/approve", post(approve_op))
        .route("/v1/operations/{operation_id}/reject", post(reject_op))
        // Phase 7ci: server-side rollback. Builds a new operation
        // that re-applies prior desired state for every resource in
        // the target op. Goes through normal create_operation pipeline
        // (policy / approval / canary).
        .route("/v1/operations/{operation_id}/rollback", post(rollback_op))
}

async fn submit(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    headers: HeaderMap,
    Json(req): Json<SubmitOperationRequest>,
) -> ApiResult<Json<SubmitOperationResponse>> {
    let identity = require_role(&state, &token, Role::Operator).await?;
    if req.environment.is_empty() {
        return Err(ApiError::BadRequest("environment must not be empty".into()));
    }
    if req.resources.is_empty() {
        return Err(ApiError::BadRequest("resources must not be empty".into()));
    }

    // Phase 7h: rate-limit. Check happens after auth + basic shape
    // validation so attackers spamming malformed payloads don't fill
    // their bucket; legitimate operators see the budget reflect real
    // submissions only.
    state
        .rate_limiter
        .check_and_record(&req.environment)
        .await?;

    // Phase 7i + 7j: reject during a maintenance window unless the
    // caller is an admin who opted in via the bypass header. Admins
    // need the escape valve for incident response (deploy a fix during
    // a freeze); the audit log captures every bypass for review.
    use std::sync::atomic::Ordering::Relaxed;
    state.maintenance_metrics.checks_total.fetch_add(1, Relaxed);
    let bypass_requested = headers
        .get(MAINT_BYPASS_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if bypass_requested {
        if !identity.has_role(Role::Admin) {
            return Err(ApiError::Forbidden);
        }
        state
            .maintenance_metrics
            .bypassed_total
            .fetch_add(1, Relaxed);
        // Record the bypass even if no window is currently active —
        // the *intent* is what's interesting for review, not whether
        // a window happened to be open. Cheap and useful.
        state
            .store
            .record_audit(
                crate::store::AuditRecord::new(
                    &identity.audit_actor(),
                    "operation.maintenance_bypass",
                )
                .severity("warning")
                .payload(serde_json::json!({
                    "environment": req.environment,
                    "requested_by": req.requested_by,
                })),
            )
            .await?;
    } else {
        let now = jiff::Timestamp::now();
        // Phase 7bx: snapshot — windows are hot-reloadable so we want a
        // single coherent view for both checks below.
        let cfg_for_windows = state.config();
        // Both checks return ServiceUnavailable on match; Phase 7ah
        // splits the blocked counter by window type so dashboards can
        // tell which kind of freeze fired.
        if let Err(e) = crate::maintenance::check(
            &cfg_for_windows.maintenance_windows,
            &req.environment,
            now,
            Some(&state.maintenance_metrics),
        ) {
            state
                .maintenance_metrics
                .blocked_by_absolute_total
                .fetch_add(1, Relaxed);
            return Err(e);
        }
        if let Err(e) = crate::maintenance::check_recurring(
            &cfg_for_windows.recurring_maintenance_windows,
            &req.environment,
            now,
            Some(&state.maintenance_metrics),
        ) {
            state
                .maintenance_metrics
                .blocked_by_recurring_total
                .fetch_add(1, Relaxed);
            return Err(e);
        }
    }

    // Phase 7co (security fix): we keep `${secret://...}` tokens INTACT
    // through submit + storage. Only at agent-fetch time
    // (`api::agents::list_assignments`) does the server substitute them
    // into the dispatched payload. This means:
    //   * `desired_states.spec_json` and `assignments.payload_json` never
    //     contain plaintext secret values — a DB dump / backup / read-only
    //     replica leaks references, not credentials.
    //   * Audit log payloads also reference `${secret://...}` rather than
    //     the resolved value, so historical operations don't preserve
    //     long-since-rotated passwords forever.
    //   * The agent receives a freshly-resolved payload on each fetch,
    //     signed at fetch time — no extra wire surface, no agent-side
    //     resolver required.
    //
    // We still validate at submit: if any resource references a secret
    // and no resolver is configured, fail closed so operators don't
    // ship literal `${secret://...}` strings to agents.
    let resources = req.resources.clone();
    let registry_present = state.secret_registry.is_some();
    let mut any_ref = false;
    for resource in &resources {
        if json_contains_secret_ref(resource) {
            any_ref = true;
            break;
        }
    }
    if any_ref && !registry_present {
        return Err(ApiError::BadRequest(
            "secret reference present but no resolver is configured on the server".into(),
        ));
    }
    // Eager pre-flight: if there ARE refs, smoke-test that they all
    // resolve right now. This catches typos / missing Vault paths at
    // submit time instead of at first agent fetch (when the operator
    // is gone). The result is discarded — we just want to surface the
    // error early.
    if any_ref && let Some(registry) = state.secret_registry.as_deref() {
        for resource in resources.clone() {
            let mut probe = resource;
            registry.substitute_in_value(&mut probe).await?;
        }
    }

    // Phase 7a: expand composite resources (kind: service → docker + nginx)
    // BEFORE routing so the agent capability allowlist still applies to the
    // primitive forms. Operators don't opt in — `kind: service` is a known
    // composite shorthand handled server-side. Non-composite kinds pass
    // through unchanged.
    // Phase 7bx: snapshot the config — modules are hot-reloadable, but a
    // single submission needs a consistent module set across expansion +
    // policy evaluation below.
    let cfg = state.config();
    let expanded = expand_resources(resources, &cfg.modules)?;
    let mut routing: Vec<ResourceForRouting> = Vec::with_capacity(expanded.len());
    for raw in &expanded {
        let routed = extract_routing(raw, &req.environment)?;
        routing.push(routed);
    }

    // Phase 7g: topologically sort the routing list by
    // `metadata.dependsOn`. Each agent's bucket then inherits this
    // global order so resources arrive sequenced. Cycles and unknown
    // references reject as 400.
    topo_sort_by_depends_on(&mut routing)?;

    // Evaluate configured policies. Any match with `requires_approval=true`
    // sends the operation through the approval gate.
    let kinds: Vec<&str> = routing.iter().map(|r| r.kind.as_str()).collect();
    let facts = OperationFacts {
        environment: &req.environment,
        resources: &kinds,
    };
    let matched = evaluate(&cfg.policies, &facts);
    let matched_names: Vec<String> = matched.iter().map(|p| p.name.clone()).collect();
    let requires_approval = matched.iter().any(|p| p.requires_approval);

    // Phase 7n + Phase 9 follow-up: per-policy rate limits. Each
    // matched policy with a `rate_limit_per_minute` cap enforces its
    // own bucket. The earlier `for policy in &matched` loop committed
    // each cap as it iterated, so a submission that ended up rejected
    // by the second policy still consumed budget from the first. The
    // batched call below runs check + record under a single mutex
    // hold: dry-run all caps, then commit all on success. Truly
    // atomic, no partial recording.
    let policy_caps: Vec<(&str, u32)> = matched
        .iter()
        .filter_map(|p| p.rate_limit_per_minute.map(|cap| (p.name.as_str(), cap)))
        .collect();
    if !policy_caps.is_empty() {
        state
            .rate_limiter
            .check_and_record_policies(&policy_caps)
            .await?;
    }

    let outcome = state
        .store
        .create_operation(
            &req.environment,
            &req.requested_by,
            &identity.audit_actor(),
            req.source_commit.as_deref(),
            req.summary.as_deref(),
            &routing,
            &matched_names,
            requires_approval,
            req.canary,
        )
        .await?;
    // Phase 7a: blast radius for the operator's preview / approval gate.
    // Compute from the post-expansion routing list so a `service` shows up
    // as 2 resources, not 1.
    let mut kinds: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in &routing {
        kinds.insert(r.kind.clone());
    }
    let blast_radius = BlastRadius {
        resource_count: u32::try_from(routing.len()).unwrap_or(u32::MAX),
        // assignment_count == distinct routed agents (we always create at
        // most one assignment per (agent, op) pair).
        agent_count: outcome.assignment_count,
        kinds: kinds.into_iter().collect(),
    };

    Ok(Json(SubmitOperationResponse {
        operation_id: outcome.operation_id,
        assignment_count: outcome.assignment_count,
        unrouted: outcome
            .unrouted
            .into_iter()
            .map(|(rid, reason)| UnroutedResource {
                resource_id: rid,
                reason,
            })
            .collect(),
        blast_radius,
    }))
}

async fn approve_op(
    State(state): State<AppState>,
    Path(op_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<OperationApproveRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_role(&state, &token, Role::Approver).await?;

    // Phase 6f: enforce `Policy.approvers`. The op stores names of policies
    // that matched at submit time. For each, look up its approvers list. If
    // any matched policy has a non-empty list, the caller's display_name
    // must be in it (Admin role bypasses for break-glass).
    if !identity.has_role(Role::Admin) {
        let view = state.store.get_operation(&op_id).await?;
        let caller = identity.display_name();
        let mut allowed = true;
        let mut violated: Vec<String> = Vec::new();
        // Phase 7bx: snapshot once across the per-policy loop below.
        let cfg_for_approvers = state.config();
        for matched_name in &view.matched_policies {
            let Some(policy) = cfg_for_approvers
                .policies
                .iter()
                .find(|p| &p.name == matched_name)
            else {
                continue;
            };
            if policy.approvers.is_empty() {
                continue;
            }
            if !policy.approvers.iter().any(|u| u == &caller) {
                allowed = false;
                violated.push(matched_name.clone());
            }
        }
        if !allowed {
            return Err(ApiError::Forbidden);
        }
        // `violated` only populated when allowed=false; ensure no warning.
        let _ = violated;
    }

    let count = state
        .store
        .approve_operation(
            &op_id,
            &identity.display_name(),
            &identity.audit_actor(),
            req.reason.as_deref(),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "assignment_count": count,
    })))
}

async fn reject_op(
    State(state): State<AppState>,
    Path(op_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<OperationRejectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_role(&state, &token, Role::Approver).await?;
    state
        .store
        .reject_operation(
            &op_id,
            &identity.display_name(),
            &identity.audit_actor(),
            &req.reason,
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_op(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(op_id): Path<String>,
) -> ApiResult<Json<OperationView>> {
    require_role(&state, &token, Role::Viewer).await?;
    Ok(Json(state.store.get_operation(&op_id).await?))
}

/// `GET /v1/operations?status=<s>&limit=<n>` — Viewer-gated list.
/// Newest-first. `status` is optional (drop the filter to see all);
/// `limit` defaults to 50, clamped to [1, 1000] in the store layer.
/// Slim shape: id/kind/environment/requested_by/status/timestamps —
/// no assignments. Operators wanting full detail call
/// `GET /v1/operations/{id}`.
#[derive(serde::Deserialize)]
struct ListOpsQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_ops(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    axum::extract::Query(q): axum::extract::Query<ListOpsQuery>,
) -> ApiResult<Json<Vec<OperationListItem>>> {
    require_role(&state, &token, Role::Viewer).await?;
    let limit = q.limit.unwrap_or(50);
    Ok(Json(
        state
            .store
            .list_operations(q.status.as_deref(), limit)
            .await?,
    ))
}

/// Phase 7ci: rollback handler. Builds a new operation whose
/// desired-state is the most-recent-prior desired state per resource
/// in the target op. Resources that were *first-applied* in the
/// target op (no prior state) get reported back as `orphaned` —
/// rolling those back means deleting them, which we don't auto-do
/// (provider-specific, often destructive).
///
/// The new operation goes through the normal `create_operation`
/// pipeline: policy evaluation runs, approval gates fire, canary (if
/// requested) splits batches the same way. So a rollback that
/// touches a `requires_approval` resource still needs an approver
/// just like a forward apply would.
async fn rollback_op(
    State(state): State<AppState>,
    Path(target_op_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<RollbackOperationRequest>,
) -> ApiResult<Json<RollbackOperationResponse>> {
    let identity = require_role(&state, &token, Role::Operator).await?;
    let (mut resources, orphaned, environment) =
        state.store.prepare_rollback(&target_op_id).await?;
    if resources.is_empty() {
        return Err(ApiError::Conflict(format!(
            "no resources have a prior desired state to revert to ({} orphaned). \
             Operator must delete these manually.",
            orphaned.len()
        )));
    }
    // Topo-sort by the prior specs' dependsOn so layered dispatch
    // mirrors the original deploy ordering. Phase 7by handles the
    // actual phasing; we just need consistent input order here.
    topo_sort_by_depends_on(&mut resources)?;
    // Policy evaluation gates the rollback the same way it gates
    // forward applies. The facts list is unique resource kinds —
    // policies match by kind, env, or resource count.
    let kinds: Vec<&str> = resources.iter().map(|r| r.kind.as_str()).collect();
    let policy_facts = OperationFacts {
        environment: &environment,
        resources: &kinds,
    };
    let live = state.config();
    let matched = evaluate(&live.policies, &policy_facts);
    let matched_names: Vec<String> = matched.iter().map(|p| p.name.clone()).collect();
    let requires_approval = matched.iter().any(|p| p.requires_approval);
    let summary = format!(
        "rollback of {target_op_id}{}",
        match &req.reason {
            Some(r) => format!(": {r}"),
            None => String::new(),
        }
    );
    let outcome = state
        .store
        .create_operation(
            &environment,
            &req.requested_by,
            &identity.audit_actor(),
            None,
            Some(&summary),
            &resources,
            &matched_names,
            requires_approval,
            req.canary,
        )
        .await?;

    // Audit the rollback initiation with both ops linked so a reader
    // can navigate "what was rolled back, by whom, why."
    state
        .store
        .record_audit(
            crate::store::AuditRecord::new(&identity.audit_actor(), "operation.rollback_initiated")
                .operation(&outcome.operation_id)
                .severity("warning")
                .payload(serde_json::json!({
                    "target_operation_id": target_op_id,
                    "reason": req.reason,
                    "resources_reverted": resources.len(),
                    "resources_orphaned": orphaned,
                })),
        )
        .await?;

    Ok(Json(RollbackOperationResponse {
        new_operation_id: outcome.operation_id,
        assignment_count: outcome.assignment_count,
        resources_reverted: u32::try_from(resources.len()).unwrap_or(u32::MAX),
        resources_orphaned: orphaned,
    }))
}

/// Phase 7b: surface the desired-state primitives an operation will (or
/// did) write. Reads `desired_states` directly so this works for ops in
/// `pending_approval` — that's the whole point: approvers see exactly
/// what's about to land before they greenlight.
async fn get_op_desired_state(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(op_id): Path<String>,
) -> ApiResult<Json<OperationDesiredState>> {
    require_role(&state, &token, Role::Viewer).await?;
    let items = state.store.list_desired_state_for_operation(&op_id).await?;
    Ok(Json(OperationDesiredState {
        operation_id: op_id,
        items,
    }))
}

/// Pull `(name, environment, kind, hostSelector.name)` plus the canonical
/// resource id from a raw `Resource` JSON value submitted by the operator.
///
/// Phase 7be: visibility raised to `pub(crate)` so the drift-revert path
/// can re-route a stored desired-state through the same logic without
/// duplicating field-extraction.
pub(crate) fn extract_routing(
    raw: &serde_json::Value,
    op_env: &str,
) -> ApiResult<ResourceForRouting> {
    let kind = raw
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("resource missing 'kind'".into()))?
        .to_string();
    let name = raw
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("resource missing 'metadata.name'".into()))?
        .to_string();
    // `metadata.environment` is optional in the manifest; absent =
    // inherit the operation's environment. When present it MUST match
    // the operation's env — Phase 9 follow-up. Previously a mismatch
    // was silently accepted and the resource_id was stored with the
    // manifest's env, while policy/rate-limit/maintenance checks all
    // ran against the request env. A submission against `staging`
    // could thus stash a `prod` resource in the desired_states table
    // and dispatch it through the staging rate budget; mismatch is
    // either a manifest bug or an env-bypass attempt — fail loudly.
    let environment = match raw
        .get("metadata")
        .and_then(|m| m.get("environment"))
        .and_then(|v| v.as_str())
    {
        None => op_env.to_string(),
        Some(env) if env == op_env => env.to_string(),
        Some(env) => {
            return Err(ApiError::BadRequest(format!(
                "resource '{}' declares metadata.environment={env:?} but operation \
                 is for environment {op_env:?}; cross-env submissions are not \
                 permitted — either drop the metadata.environment field or submit \
                 the operation under the matching environment",
                raw.get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>")
            )));
        }
    };
    let host_selector = raw
        .get("spec")
        .and_then(|s| s.get("hostSelector"))
        .and_then(|h| h.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let resource_id = format!("{kind}/{environment}/{name}");
    let resource_json = serde_json::to_string(raw)?;
    Ok(ResourceForRouting {
        resource_id,
        kind,
        environment,
        resource_json,
        name,
        host_selector,
    })
}

/// Walk a JSON value looking for any `${secret://` substring. Used as the
/// fail-closed guard when the operator submits a manifest with secret refs
/// but the server has no registry configured — better to 400 the submission
/// than persist what looks like a secret token to the agent inbox.
fn json_contains_secret_ref(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => s.contains("${secret://"),
        serde_json::Value::Array(arr) => arr.iter().any(json_contains_secret_ref),
        serde_json::Value::Object(map) => map.values().any(json_contains_secret_ref),
        _ => false,
    }
}
