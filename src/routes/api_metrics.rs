use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use axum_extra::extract::CookieJar;
use serde_json::{json, Value};
use std::time::Duration;

use crate::auth::{get_session_user, AdminUser, AuthUser};
use crate::error::AppError;
use crate::repositories::pdns_server_repo;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/metrics", get(get_metrics_overview))
        .route("/api/metrics/:server_db_id", get(get_server_metrics))
        .route("/api/metrics/ws/:server_db_id", get(ws_metrics))
}

async fn get_metrics_overview(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
) -> Result<Json<Value>, AppError> {
    let servers = pdns_server_repo::list_servers(&state.db)
        .await
        .map_err(AppError::Internal)?;
    let active: Vec<_> = servers.into_iter().filter(|s| s.is_active).collect();

    let mut tasks = Vec::new();
    for srv in active {
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            let mut entry = json!({
                "id": srv.id,
                "name": srv.name,
                "connected": false,
                "version": null,
                "zone_count": 0,
                "dnssec_count": 0,
                "uptime": null,
            });
            let client = state.pdns.read().unwrap().get(srv.id);
            if let Some(client) = client {
                if let (Ok(info), Ok(zones)) =
                    tokio::join!(client.get_server_info(), client.list_zones(None))
                {
                    entry["connected"] = json!(true);
                    entry["version"] = info.get("version").cloned().unwrap_or(json!(null));
                    let zone_count = zones.as_array().map(|a| a.len()).unwrap_or(0);
                    let dnssec_count = zones
                        .as_array()
                        .map(|a| a.iter().filter(|z| z.get("dnssec").and_then(|v| v.as_bool()).unwrap_or(false)).count())
                        .unwrap_or(0);
                    entry["zone_count"] = json!(zone_count);
                    entry["dnssec_count"] = json!(dnssec_count);
                }
            }
            entry
        }));
    }

    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap_or_else(|e| json!({"error": e.to_string()})));
    }
    Ok(Json(json!(results)))
}

async fn get_server_metrics(
    State(state): State<AppState>,
    Path(server_db_id): Path<i64>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let srv = pdns_server_repo::get_server(&state.db, server_db_id)
        .await
        .map_err(AppError::Internal)?
        .filter(|s| s.is_active)
        .ok_or_else(|| AppError::NotFound("Server not found".into()))?;

    let client = state
        .pdns
        .read()
        .unwrap()
        .get(server_db_id)
        .ok_or_else(|| AppError::ServiceUnavailable(format!("Server '{}' not connected", srv.name)))?;

    let (info, stats) = tokio::join!(client.get_server_info(), client.get_statistics());
    let info = info.map_err(|e| AppError::PdnsError { status: e.status, detail: e.detail })?;
    let stats = stats.map_err(|e| AppError::PdnsError { status: e.status, detail: e.detail })?;

    Ok(Json(json!({"server_info": info, "statistics": stats})))
}

async fn ws_metrics(
    State(state): State<AppState>,
    Path(server_db_id): Path<i64>,
    jar: CookieJar,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state, server_db_id, jar))
}

async fn handle_ws(mut socket: WebSocket, state: AppState, server_db_id: i64, jar: CookieJar) {
    // Auth check
    let session_id = jar.get("session_id").map(|c| c.value().to_string());
    let _user = match session_id {
        Some(sid) => match get_session_user(&state.db, &sid).await {
            Ok(Some(u)) if u.is_active && u.role == "admin" => u,
            _ => {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
        },
        None => {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };

    // Server check
    let _srv = match pdns_server_repo::get_server(&state.db, server_db_id).await {
        Ok(Some(s)) if s.is_active => s,
        _ => {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };

    let client = { state.pdns.read().unwrap().get(server_db_id) };
    let client = match client {
        Some(c) => c,
        None => {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };

    loop {
        let payload = match tokio::join!(client.get_server_info(), client.get_statistics()) {
            (Ok(info), Ok(stats)) => json!({"server_info": info, "statistics": stats}),
            (Err(e), _) | (_, Err(e)) => json!({"error": e.detail}),
        };
        if socket
            .send(Message::Text(payload.to_string()))
            .await
            .is_err()
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
