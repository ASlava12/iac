//! Phase 7l: `GET /v1/expanders` discovery endpoint.
//!
//! Returns the list of composite kinds the server expands and what
//! primitive kinds each one emits. Lets operators see what's available
//! without reading source. Open to any authenticated caller (Viewer
//! role) since the catalog isn't sensitive.

use crate::api::{BearerToken, require_role};
use crate::error::{ApiError, ApiResult};
use crate::expansion::{ExpanderDescriptor, list_all_expanders};
use crate::identity::Role;
use crate::server::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/expanders", get(list))
        .route("/v1/expanders/{kind}", get(show))
}

async fn list(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<Vec<ExpanderDescriptor>>> {
    require_role(&state, &token, Role::Viewer).await?;
    // Phase 7bv: include operator-defined modules alongside built-ins.
    // Phase 7bx: pull from live snapshot so SIGHUP-added modules show up.
    let cfg = state.config();
    Ok(Json(list_all_expanders(&cfg.modules)))
}

/// Phase 7p: detail view for a single expander, including spec fields.
/// Convenient for `iac expanders show <kind>` and for any UI that wants
/// to render a form before submission.
async fn show(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Path(kind): Path<String>,
) -> ApiResult<Json<ExpanderDescriptor>> {
    require_role(&state, &token, Role::Viewer).await?;
    let cfg = state.config();
    list_all_expanders(&cfg.modules)
        .into_iter()
        .find(|d| d.kind == kind)
        .map(Json)
        .ok_or(ApiError::NotFound)
}
