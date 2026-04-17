use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AdminUser;
use crate::error::AppError;
use crate::repositories::{audit_repo, zone_template_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/zone-templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/api/zone-templates/:template_id",
            put(update_template).delete(delete_template),
        )
        .route(
            "/api/zone-templates/:template_id/set-default",
            post(set_default),
        )
}

#[derive(Deserialize)]
struct TemplateInput {
    name: String,
    #[serde(default)]
    nameservers: Vec<String>,
    #[serde(default)]
    soa_mname: String,
    #[serde(default)]
    soa_rname: String,
    #[serde(default = "default_3600")]
    soa_refresh: i64,
    #[serde(default = "default_900")]
    soa_retry: i64,
    #[serde(default = "default_604800")]
    soa_expire: i64,
    #[serde(default = "default_300")]
    soa_ttl: i64,
    #[serde(default)]
    is_default: bool,
}

fn default_3600() -> i64 { 3600 }
fn default_900() -> i64 { 900 }
fn default_604800() -> i64 { 604800 }
fn default_300() -> i64 { 300 }

async fn list_templates(
    State(state): State<AppState>,
    AdminUser(_user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let templates = zone_template_repo::list_templates(&state.db)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!(templates)))
}

async fn create_template(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(body): Json<TemplateInput>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::BadRequest("Template name cannot be empty".into()));
    }
    let tmpl = zone_template_repo::create_template(
        &state.db,
        zone_template_repo::TemplateData {
            name: &name,
            nameservers: &body.nameservers,
            soa_mname: &body.soa_mname,
            soa_rname: &body.soa_rname,
            soa_refresh: body.soa_refresh,
            soa_retry: body.soa_retry,
            soa_expire: body.soa_expire,
            soa_ttl: body.soa_ttl,
            is_default: body.is_default,
        },
    )
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::Conflict("A template with that name already exists".into())
        } else {
            AppError::Internal(e)
        }
    })?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone_template.create",
        None,
        Some(&json!({"name": name}).to_string()),
    )
    .await
    .ok();
    Ok((StatusCode::CREATED, Json(json!(tmpl))))
}

async fn update_template(
    State(state): State<AppState>,
    Path(template_id): Path<i64>,
    AdminUser(user): AdminUser,
    Json(body): Json<TemplateInput>,
) -> Result<Json<Value>, AppError> {
    zone_template_repo::get_template(&state.db, template_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Template not found".into()))?;

    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::BadRequest("Template name cannot be empty".into()));
    }
    let tmpl = zone_template_repo::update_template(
        &state.db,
        template_id,
        zone_template_repo::TemplateData {
            name: &name,
            nameservers: &body.nameservers,
            soa_mname: &body.soa_mname,
            soa_rname: &body.soa_rname,
            soa_refresh: body.soa_refresh,
            soa_retry: body.soa_retry,
            soa_expire: body.soa_expire,
            soa_ttl: body.soa_ttl,
            is_default: body.is_default,
        },
    )
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::Conflict("A template with that name already exists".into())
        } else {
            AppError::Internal(e)
        }
    })?
    .ok_or_else(|| AppError::NotFound("Template not found after update".into()))?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone_template.update",
        None,
        Some(&json!({"id": template_id, "name": name}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!(tmpl)))
}

async fn set_default(
    State(state): State<AppState>,
    Path(template_id): Path<i64>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    zone_template_repo::get_template(&state.db, template_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Template not found".into()))?;

    zone_template_repo::set_default(&state.db, template_id)
        .await
        .map_err(AppError::Internal)?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone_template.set_default",
        None,
        Some(&json!({"id": template_id}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn delete_template(
    State(state): State<AppState>,
    Path(template_id): Path<i64>,
    AdminUser(user): AdminUser,
) -> Result<StatusCode, AppError> {
    zone_template_repo::get_template(&state.db, template_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::NotFound("Template not found".into()))?;

    zone_template_repo::delete_template(&state.db, template_id)
        .await
        .map_err(AppError::Internal)?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone_template.delete",
        None,
        Some(&json!({"id": template_id}).to_string()),
    )
    .await
    .ok();
    Ok(StatusCode::NO_CONTENT)
}
