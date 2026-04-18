use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use serde_json::json;

use crate::auth::{
    create_api_key, create_session, delete_api_key, delete_session, list_api_keys, AuthUser,
};
use crate::error::AppError;
use crate::models::user::LoginRequest;
use crate::repositories::{audit_repo, user_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(get_me))
        .route("/api/api-keys", post(create_key).get(list_keys))
        .route("/api/api-keys/:key_id", delete(remove_key))
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Response, AppError> {
    let user = user_repo::verify_password(&state.db, &body.username, &body.password)
        .await
        .map_err(AppError::Internal)?
        .ok_or(AppError::Unauthorized)?;

    let session_id = create_session(&state.db, user.id, state.config.session_lifetime_hours)
        .await
        .map_err(AppError::Internal)?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "auth.login",
        None,
        None,
    )
    .await
    .ok();

    let cookie = format!(
        "session_id={session_id}; HttpOnly; SameSite=Lax; Max-Age={}; Path=/",
        state.config.session_lifetime_hours * 3600
    );
    let body = json!({"ok": true, "user": user});
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(body),
    )
        .into_response())
}

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    AuthUser(user): AuthUser,
) -> Result<Response, AppError> {
    if let Some(sid) = jar.get("session_id") {
        delete_session(&state.db, sid.value())
            .await
            .map_err(AppError::Internal)?;
    }
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "auth.logout",
        None,
        None,
    )
    .await
    .ok();

    let clear_cookie = "session_id=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/";
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie)],
        Json(json!({"ok": true})),
    )
        .into_response())
}

async fn get_me(AuthUser(user): AuthUser) -> Json<serde_json::Value> {
    Json(json!(user))
}

async fn create_key(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let description = params
        .get("description")
        .cloned()
        .unwrap_or_default();
    let key = create_api_key(&state.db, user.id, &description)
        .await
        .map_err(AppError::Internal)?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "apikey.create",
        None,
        Some(&serde_json::json!({"description": description}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"key": key, "description": description})))
}

async fn list_keys(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let keys = list_api_keys(&state.db, user.id)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!(keys)))
}

async fn remove_key(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::extract::Path(key_id): axum::extract::Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    delete_api_key(&state.db, key_id, user.id)
        .await
        .map_err(AppError::Internal)?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "apikey.delete",
        None,
        Some(&format!("{{\"key_id\":{key_id}}}")),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}
