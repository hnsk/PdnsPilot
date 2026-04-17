use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::repositories::audit_repo;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/audit", get(get_audit_log))
}

#[derive(Deserialize)]
struct AuditQuery {
    zone_name: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

async fn get_audit_log(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = q.limit.min(500);
    let user_id_filter = if user.role == "admin" {
        None
    } else {
        Some(user.id)
    };
    let entries = audit_repo::get_audit_log(
        &state.db,
        q.zone_name.as_deref(),
        user_id_filter,
        limit,
        q.offset,
    )
    .await
    .map_err(AppError::Internal)?;
    let total = audit_repo::count_audit_log(
        &state.db,
        q.zone_name.as_deref(),
        user_id_filter,
    )
    .await
    .map_err(AppError::Internal)?;
    Ok(Json(json!({"entries": entries, "total": total})))
}
