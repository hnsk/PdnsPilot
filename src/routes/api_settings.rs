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
    Router::new()
        .route(
            "/api/settings/default-record-ttl",
            get(get_default_ttl).put(set_default_ttl),
        )
        .route(
            "/api/settings/auto-notify-on-master",
            get(get_auto_notify).put(set_auto_notify),
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

#[derive(Deserialize)]
struct BoolUpdate {
    value: bool,
}

async fn get_auto_notify(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let raw = settings_repo::get_setting(&state.db, "auto_notify_on_master")
        .await
        .map_err(AppError::Internal)?;
    let value = raw.map(|v| v == "true").unwrap_or(true);
    Ok(Json(json!({"value": value})))
}

async fn set_auto_notify(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
    Json(body): Json<BoolUpdate>,
) -> Result<Json<Value>, AppError> {
    settings_repo::upsert_setting(
        &state.db,
        "auto_notify_on_master",
        if body.value { "true" } else { "false" },
    )
    .await
    .map_err(AppError::Internal)?;
    Ok(Json(json!({"value": body.value})))
}
