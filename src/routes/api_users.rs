use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{AdminUser, AuthUser};
use crate::error::AppError;
use crate::models::user::{PasswordChange, UserCreate, UserPreferences, UserUpdate};
use crate::repositories::{audit_repo, user_repo, zone_assignment_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/:user_id",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route(
            "/api/users/:user_id/zones",
            get(get_user_zones).put(set_user_zones),
        )
        .route("/api/users/me/preferences", put(update_preferences))
        .route("/api/users/me/password", put(change_password))
}

#[derive(Deserialize)]
struct ZoneAssignmentInput {
    zone_name: String,
    pdns_server_id: i64,
}

async fn list_users(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let users = user_repo::list_users(&state.db)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!(users)))
}

async fn create_user(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(body): Json<UserCreate>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if user_repo::get_user_by_username(&state.db, &body.username)
        .await
        .map_err(AppError::Internal)?
        .is_some()
    {
        return Err(AppError::Conflict("Username already exists".into()));
    }
    if body.role != "admin" && body.role != "operator" {
        return Err(AppError::BadRequest(
            "Role must be 'admin' or 'operator'".into(),
        ));
    }
    let new_user = user_repo::create_user(&state.db, &body.username, &body.password, &body.role)
        .await
        .map_err(AppError::Internal)?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "user.create",
        None,
        Some(&json!({"new_username": body.username, "role": body.role}).to_string()),
    )
    .await
    .ok();
    Ok((StatusCode::CREATED, Json(json!(new_user))))
}

async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let target = user_repo::get_user_by_id(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;
    let zones = zone_assignment_repo::get_user_zone_assignments(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?;
    let mut v = json!(target);
    v["zones"] = json!(zones);
    Ok(Json(v))
}

async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    AdminUser(user): AdminUser,
    Json(body): Json<UserUpdate>,
) -> Result<Json<Value>, AppError> {
    let target = user_repo::get_user_by_id(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;
    if let Some(ref r) = body.role {
        if r != "admin" && r != "operator" {
            return Err(AppError::BadRequest("Role must be 'admin' or 'operator'".into()));
        }
    }
    user_repo::update_user(
        &state.db,
        user_id,
        body.password.as_deref(),
        body.role.as_deref(),
        body.is_active,
    )
    .await
    .map_err(AppError::Internal)?;

    let mut changes = serde_json::Map::new();
    if let Some(ref r) = body.role {
        changes.insert("role".into(), json!(r));
    }
    if let Some(a) = body.is_active {
        changes.insert("is_active".into(), json!(a));
    }
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "user.update",
        None,
        Some(
            &json!({"target_user": target.username, "changes": changes}).to_string(),
        ),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    if user_id == user.id {
        return Err(AppError::BadRequest("Cannot delete yourself".into()));
    }
    let target = user_repo::get_user_by_id(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;
    user_repo::delete_user(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "user.delete",
        None,
        Some(&json!({"deleted_user": target.username}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn set_user_zones(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    AdminUser(user): AdminUser,
    Json(assignments): Json<Vec<ZoneAssignmentInput>>,
) -> Result<Json<Value>, AppError> {
    let target = user_repo::get_user_by_id(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let zone_assignments: Vec<zone_assignment_repo::ZoneAssignment> = assignments
        .iter()
        .map(|a| zone_assignment_repo::ZoneAssignment {
            zone_name: a.zone_name.clone(),
            pdns_server_id: Some(a.pdns_server_id),
        })
        .collect();

    zone_assignment_repo::set_user_zones(&state.db, user_id, &zone_assignments)
        .await
        .map_err(AppError::Internal)?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "user.zones_update",
        None,
        Some(&json!({"target_user": target.username, "zones": assignments.iter().map(|a| json!({"zone_name": a.zone_name, "pdns_server_id": a.pdns_server_id})).collect::<Vec<_>>()}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn get_user_zones(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let zones = zone_assignment_repo::get_user_zone_assignments(&state.db, user_id)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!(zones)))
}

async fn update_preferences(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<UserPreferences>,
) -> Result<Json<Value>, AppError> {
    if let Some(ttl) = body.default_ttl {
        if ttl < 1 {
            return Err(AppError::BadRequest("TTL must be at least 1".into()));
        }
    }
    user_repo::update_user_preferences(&state.db, user.id, body.default_ttl)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({"ok": true})))
}

async fn change_password(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<PasswordChange>,
) -> Result<Json<Value>, AppError> {
    user_repo::verify_password(&state.db, &user.username, &body.current_password)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::BadRequest("Current password is incorrect".into()))?;

    user_repo::update_user(&state.db, user.id, Some(&body.new_password), None, None)
        .await
        .map_err(AppError::Internal)?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "user.password_change",
        None,
        None,
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}
