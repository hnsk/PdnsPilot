use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AdminUser;
use crate::error::AppError;
use crate::models::zone::CryptoKeyCreate;
use crate::repositories::audit_repo;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/zones/:zone_id/cryptokeys",
            get(list_cryptokeys).post(create_cryptokey),
        )
        .route(
            "/api/zones/:zone_id/cryptokeys/:key_id",
            get(get_cryptokey).put(toggle_cryptokey).delete(delete_cryptokey),
        )
        .route("/api/zones/:zone_id/dnssec/enable", post(enable_dnssec))
        .route("/api/zones/:zone_id/dnssec/disable", post(disable_dnssec))
}

#[derive(Deserialize)]
struct ServerIdQuery {
    server_id: Option<i64>,
}

fn pdns_err(e: &crate::pdns_client::PdnsError) -> AppError {
    AppError::PdnsError {
        status: e.status,
        detail: e.detail.clone(),
    }
}

async fn resolve_client(
    state: &AppState,
    zone_id: &str,
    server_id_query: Option<i64>,
) -> Result<std::sync::Arc<crate::pdns_client::PdnsClient>, AppError> {
    use crate::repositories::pdns_server_repo;
    let srv = if let Some(sid) = server_id_query {
        pdns_server_repo::get_server_for_zone_by_server_id(&state.db, zone_id, sid)
            .await
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::NotFound("Zone not on that server".into()))?
    } else {
        pdns_server_repo::get_server_for_zone_or_fallback(&state.db, zone_id)
            .await
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::NotFound("Zone not mapped to any server".into()))?
    };
    state
        .pdns
        .read()
        .unwrap()
        .get(srv.id)
        .ok_or_else(|| AppError::ServiceUnavailable(format!("Server '{}' not connected", srv.name)))
}

async fn list_cryptokeys(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    client.list_cryptokeys(&zone_id).await.map(Json).map_err(|e| pdns_err(&e))
}

async fn create_cryptokey(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(user): AdminUser,
    Json(body): Json<CryptoKeyCreate>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    let data = json!({
        "keytype": body.keytype,
        "active": body.active,
        "algorithm": body.algorithm,
        "bits": body.bits,
        "published": body.published,
    });
    let key = client.create_cryptokey(&zone_id, data).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "dnssec.key_create",
        Some(&zone_id),
        Some(&json!({"keytype": body.keytype, "algorithm": body.algorithm}).to_string()),
    )
    .await
    .ok();
    Ok((StatusCode::CREATED, Json(key)))
}

async fn get_cryptokey(
    State(state): State<AppState>,
    Path((zone_id, key_id)): Path<(String, i64)>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    client.get_cryptokey(&zone_id, key_id).await.map(Json).map_err(|e| pdns_err(&e))
}

#[derive(Deserialize)]
struct ActiveQuery {
    active: bool,
}

async fn toggle_cryptokey(
    State(state): State<AppState>,
    Path((zone_id, key_id)): Path<(String, i64)>,
    Query(q): Query<ServerIdQuery>,
    Query(aq): Query<ActiveQuery>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    client.toggle_cryptokey(&zone_id, key_id, aq.active).await.map_err(|e| pdns_err(&e))?;
    let action = if aq.active {
        "dnssec.key_activate"
    } else {
        "dnssec.key_deactivate"
    };
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        action,
        Some(&zone_id),
        Some(&json!({"key_id": key_id}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn delete_cryptokey(
    State(state): State<AppState>,
    Path((zone_id, key_id)): Path<(String, i64)>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    client.delete_cryptokey(&zone_id, key_id).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "dnssec.key_delete",
        Some(&zone_id),
        Some(&json!({"key_id": key_id}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn enable_dnssec(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    client.update_zone(&zone_id, json!({"dnssec": true})).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "dnssec.enable",
        Some(&zone_id),
        None,
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn disable_dnssec(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let client = resolve_client(&state, &zone_id, q.server_id).await?;
    client.update_zone(&zone_id, json!({"dnssec": false})).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "dnssec.disable",
        Some(&zone_id),
        None,
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}
