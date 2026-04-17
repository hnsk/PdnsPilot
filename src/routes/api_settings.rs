use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AdminUser;
use crate::error::AppError;
use crate::repositories::settings_repo;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/settings/default-record-ttl",
        get(get_default_ttl).put(set_default_ttl),
    )
}

#[derive(Deserialize)]
struct TtlUpdate {
    value: i64,
}

async fn get_default_ttl(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let raw = settings_repo::get_setting(&state.db, "default_record_ttl")
        .await
        .map_err(AppError::Internal)?;
    let value: i64 = raw
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    Ok(Json(json!({"value": value})))
}

async fn set_default_ttl(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
    Json(body): Json<TtlUpdate>,
) -> Result<Json<Value>, AppError> {
    if body.value < 1 {
        return Err(AppError::BadRequest("TTL must be at least 1".into()));
    }
    settings_repo::upsert_setting(&state.db, "default_record_ttl", &body.value.to_string())
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({"value": body.value})))
}
