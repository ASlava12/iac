// Phase 7dh.9: `/v1/health` is the only unauthenticated endpoint
// (load-balancer probes need it). Pre-7dh.9 we returned the build
// version too — a free fingerprint for an attacker scanning for
// known-CVE versions to target. Drop it. Authenticated callers
// who genuinely need the version string can read it from
// `/v1/admin/build-info` (gated behind `Viewer`).

use crate::api::{BearerToken, require_role};
use crate::error::ApiResult;
use crate::identity::Role;
use crate::server::AppState;
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct BuildInfo {
    version: &'static str,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/admin/build-info", get(build_info))
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn build_info(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<BuildInfo>> {
    require_role(&state, &token, Role::Viewer).await?;
    Ok(Json(BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
    }))
}
