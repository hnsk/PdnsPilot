use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AdminUser;
use crate::error::AppError;
use crate::repositories::{audit_repo, pdns_server_repo, zone_assignment_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/pdns-servers",
            get(list_servers).post(create_server),
        )
        .route(
            "/api/pdns-servers/:server_id",
            get(get_server).put(update_server).delete(delete_server),
        )
        .route("/api/pdns-servers/test", post(test_new_server))
        .route("/api/pdns-servers/:server_id/test", post(test_existing_server))
}

#[derive(Deserialize)]
struct ServerCreate {
    name: String,
    api_url: String,
    api_key: String,
    server_id: String,
}

#[derive(Deserialize)]
struct ServerUpdate {
    name: String,
    api_url: String,
    api_key: String,
    server_id: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

fn default_true() -> bool {
    true
}

fn strip_key(srv: &pdns_server_repo::PdnsServer) -> Value {
    json!({
        "id": srv.id,
        "name": srv.name,
        "api_url": srv.api_url,
        "server_id": srv.server_id,
        "is_active": srv.is_active,
        "created_at": srv.created_at,
        "updated_at": srv.updated_at,
    })
}

async fn list_servers(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let servers = pdns_server_repo::list_servers(&state.db)
        .await
        .map_err(AppError::Internal)?;
    let stripped: Vec<Value> = servers.iter().map(strip_key).collect();
    Ok(Json(json!(stripped)))
}

async fn create_server(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(body): Json<ServerCreate>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if !body.api_url.starts_with("http://") && !body.api_url.starts_with("https://") {
        return Err(AppError::BadRequest(
            "api_url must start with http:// or https://".into(),
        ));
    }
    let srv = pdns_server_repo::create_server(
        &state.db,
        &body.name,
        &body.api_url,
        &body.api_key,
        &body.server_id,
    )
    .await
    .map_err(|e| {
        if let Some(db_err) = e.downcast_ref::<sqlx::Error>() {
            if let sqlx::Error::Database(db_err) = db_err {
                if db_err.message().contains("UNIQUE constraint failed") {
                    return AppError::Conflict("A server with that name already exists".into());
                }
            }
        }
        AppError::Internal(e)
    })?;

    // Try to connect
    if let Err(e) = state
        .pdns
        .write()
        .unwrap()
        .start_server(srv.id, &srv.api_url, &srv.api_key, &srv.server_id)
    {
        tracing::warn!("Failed to connect to {}: {}", srv.name, e);
    }

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "pdns_server.create",
        None,
        Some(&json!({"name": srv.name, "api_url": srv.api_url, "server_id": srv.server_id}).to_string()),
    )
    .await
    .ok();

    Ok((StatusCode::CREATED, Json(strip_key(&srv))))
}

async fn get_server(
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let srv = pdns_server_repo::get_server(&state.db, server_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;
    Ok(Json(strip_key(&srv)))
}

async fn update_server(
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    AdminUser(user): AdminUser,
    Json(body): Json<ServerUpdate>,
) -> Result<Json<Value>, AppError> {
    let existing = pdns_server_repo::get_server(&state.db, server_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;

    let api_key = if body.api_key.is_empty() {
        existing.api_key.clone()
    } else {
        body.api_key.clone()
    };

    let srv = pdns_server_repo::update_server(
        &state.db,
        server_id,
        &body.name,
        &body.api_url,
        &api_key,
        &body.server_id,
        body.is_active,
    )
    .await
    .map_err(AppError::Internal)?
    .ok_or_else(|| AppError::NotFound("Server not found after update".into()))?;

    if body.is_active {
        if let Err(e) = state.pdns.write().unwrap().reconfigure_server(
            server_id,
            &srv.api_url,
            &srv.api_key,
            &srv.server_id,
        ) {
            tracing::warn!("Failed to reconfigure {}: {}", srv.name, e);
        }
    } else {
        state.pdns.write().unwrap().stop_server(server_id);
    }

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "pdns_server.update",
        None,
        Some(
            &json!({"name": srv.name, "api_url": srv.api_url, "server_id": srv.server_id, "is_active": body.is_active})
                .to_string(),
        ),
    )
    .await
    .ok();

    Ok(Json(strip_key(&srv)))
}

#[derive(Deserialize)]
struct CascadeQuery {
    #[serde(default)]
    cascade: bool,
}

async fn delete_server(
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    Query(q): Query<CascadeQuery>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let existing = pdns_server_repo::get_server(&state.db, server_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;

    let zones = pdns_server_repo::list_zones_for_server(&state.db, server_id)
        .await
        .map_err(AppError::Internal)?;

    if !zones.is_empty() && !q.cascade {
        return Err(AppError::Conflict(
            json!({"detail": "Server has mapped zones", "zones": zones}).to_string(),
        ));
    }

    if q.cascade {
        for zone_name in &zones {
            pdns_server_repo::unmap_zone(&state.db, zone_name)
                .await
                .map_err(AppError::Internal)?;
            zone_assignment_repo::delete_zone_assignments(&state.db, zone_name)
                .await
                .map_err(AppError::Internal)?;
        }
    }

    pdns_server_repo::delete_server(&state.db, server_id)
        .await
        .map_err(AppError::Internal)?;
    state.pdns.write().unwrap().stop_server(server_id);

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "pdns_server.delete",
        None,
        Some(&json!({"name": existing.name, "cascade": q.cascade}).to_string()),
    )
    .await
    .ok();

    Ok(Json(json!({"ok": true})))
}

async fn test_new_server(
    AdminUser(_user): AdminUser,
    Json(body): Json<ServerCreate>,
) -> Result<Json<Value>, AppError> {
    test_connection(&body.api_url, &body.api_key, &body.server_id).await
}

async fn test_existing_server(
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let srv = pdns_server_repo::get_server(&state.db, server_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;
    test_connection(&srv.api_url, &srv.api_key, &srv.server_id).await
}

async fn test_connection(api_url: &str, api_key: &str, server_id: &str) -> Result<Json<Value>, AppError> {
    if !api_url.starts_with("http://") && !api_url.starts_with("https://") {
        return Err(AppError::BadRequest("api_url must start with http:// or https://".into()));
    }
    let url = format!("{}/api/v1/servers/{}", api_url.trim_end_matches('/'), server_id);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Internal(e.into()))?;

    match client.get(&url).header("X-API-Key", api_key).send().await {
        Ok(resp) => match resp.status().as_u16() {
            200 => {
                let body: Value = resp.json().await.unwrap_or(json!({}));
                Ok(Json(json!({"status": "ok", "detail": format!("Connected to {}", body.get("type").and_then(|t| t.as_str()).unwrap_or("PowerDNS"))})))
            }
            401 => Err(AppError::PdnsError { status: 401, detail: "Authentication failed — check API key".into() }),
            404 => Err(AppError::PdnsError { status: 404, detail: "Server ID not found — check server ID".into() }),
            s => Err(AppError::PdnsError { status: s, detail: format!("PowerDNS returned {s}") }),
        },
        Err(e) if e.is_connect() => Err(AppError::ServiceUnavailable("Cannot reach PowerDNS — check API URL".into())),
        Err(e) if e.is_timeout() => Err(AppError::ServiceUnavailable("Connection timed out — check API URL".into())),
        Err(e) => Err(AppError::Internal(e.into())),
    }
}
