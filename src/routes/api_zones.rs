use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::auth::{AdminUser, AuthUser};
use crate::error::AppError;
use crate::models::zone::{RRSet, ZoneCreate, ZoneUpdate};
use crate::repositories::{audit_repo, pdns_server_repo, settings_repo, zone_assignment_repo, zone_template_repo};
use crate::AppState;

const QUOTED_TYPES: &[&str] = &["TXT", "SPF"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/zones", get(list_zones).post(create_zone))
        .route(
            "/api/zones/:zone_id",
            get(get_zone).put(update_zone).delete(delete_zone),
        )
        .route("/api/zones/:zone_id/rrsets", patch(patch_rrsets))
        .route("/api/zones/:zone_id/export", get(export_zone))
        .route("/api/zones/:zone_id/rectify", put(rectify_zone))
        .route("/api/zones/:zone_id/notify", put(notify_zone))
        .route("/api/zones/:zone_id/axfr-retrieve", put(axfr_retrieve))
        .route("/api/zones/:zone_id/metadata", get(list_metadata))
        .route("/api/zones/:zone_id/metadata/:kind", put(set_metadata))
}

fn ensure_quoted(content: &str) -> String {
    let content = content.trim();
    if content.starts_with('"') && content.ends_with('"') && content.len() >= 2 {
        return content.to_string();
    }
    let escaped = content.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn pdns_err(e: &crate::pdns_client::PdnsError) -> AppError {
    AppError::PdnsError {
        status: e.status,
        detail: e.detail.clone(),
    }
}

fn get_pdns_client(
    state: &AppState,
    server_id: i64,
    server_name: &str,
) -> Result<std::sync::Arc<crate::pdns_client::PdnsClient>, AppError> {
    state
        .pdns
        .read()
        .get(server_id)
        .ok_or_else(|| AppError::ServiceUnavailable(format!("Server '{server_name}' not connected")))
}

async fn resolve_zone_server(
    state: &AppState,
    zone_id: &str,
    server_id_query: Option<i64>,
) -> Result<(i64, String, std::sync::Arc<crate::pdns_client::PdnsClient>), AppError> {
    let srv = if let Some(sid) = server_id_query {
        pdns_server_repo::get_or_map_server_for_zone_by_server_id(&state.db, zone_id, sid)
            .await
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::NotFound("Zone not mapped to the specified server".into()))?
    } else {
        pdns_server_repo::get_server_for_zone_or_fallback(&state.db, zone_id)
            .await
            .map_err(AppError::Internal)?
            .ok_or_else(|| AppError::NotFound("Zone not mapped to any server".into()))?
    };
    if !srv.is_active {
        return Err(AppError::ServiceUnavailable(format!(
            "Server '{}' is not active",
            srv.name
        )));
    }
    let client = get_pdns_client(state, srv.id, &srv.name)?;
    Ok((srv.id, srv.name, client))
}

#[derive(Deserialize)]
struct ServerIdQuery {
    server_id: Option<i64>,
}

async fn list_zones(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<Value>, AppError> {
    let servers = pdns_server_repo::list_servers(&state.db)
        .await
        .map_err(AppError::Internal)?;
    let active: Vec<_> = servers.into_iter().filter(|s| s.is_active).collect();

    let clients: Vec<_> = {
        let registry = state.pdns.read();
        active.iter().filter_map(|srv| {
            registry.get(srv.id).map(|c| (srv.id, srv.name.clone(), c))
        }).collect()
    };

    let mut seen: HashMap<String, Value> = HashMap::new();
    for (srv_id, srv_name, client) in &clients {
        match client.list_zones(None).await {
            Ok(zones) => {
                if let Some(arr) = zones.as_array() {
                    for z in arr {
                        let name = z
                            .get("name")
                            .or_else(|| z.get("id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        seen.entry(name).or_insert_with(|| {
                            let mut z = z.clone();
                            z["_server_id"] = json!(srv_id);
                            z["_server_name"] = json!(srv_name);
                            z
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to list zones from {}: {}", srv_name, e);
            }
        }
    }

    let all_zones: Vec<Value> = seen.into_values().collect();

    if user.role == "admin" {
        return Ok(Json(json!(all_zones)));
    }

    let allowed: std::collections::HashSet<String> =
        zone_assignment_repo::get_user_zones(&state.db, user.id)
            .await
            .map_err(AppError::Internal)?
            .into_iter()
            .collect();

    let filtered: Vec<Value> = all_zones
        .into_iter()
        .filter(|z| {
            let id = z.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            allowed.contains(id) || allowed.contains(name)
        })
        .collect();

    Ok(Json(json!(filtered)))
}

struct ZoneRRSetsParams<'a> {
    zone_fqdn: &'a str,
    nameservers: &'a [String],
    soa_mname: &'a str,
    soa_rname: &'a str,
    soa_refresh: i64,
    soa_retry: i64,
    soa_expire: i64,
    soa_ttl: i64,
}

fn build_zone_rrsets(p: ZoneRRSetsParams<'_>) -> Vec<Value> {
    let ZoneRRSetsParams { zone_fqdn, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl } = p;
    let ns_list: Vec<String> = nameservers
        .iter()
        .map(|ns| {
            if ns.ends_with('.') {
                ns.clone()
            } else {
                format!("{ns}.")
            }
        })
        .collect();

    let soa_mname_fqdn = if soa_mname.ends_with('.') {
        soa_mname.to_string()
    } else {
        format!("{soa_mname}.")
    };
    let soa_rname_fqdn = if soa_rname.ends_with('.') {
        soa_rname.to_string()
    } else {
        format!("{soa_rname}.")
    };

    let soa_content = format!(
        "{soa_mname_fqdn} {soa_rname_fqdn} 0 {soa_refresh} {soa_retry} {soa_expire} {soa_ttl}"
    );

    let mut rrsets = vec![json!({
        "name": zone_fqdn,
        "type": "SOA",
        "ttl": soa_ttl,
        "changetype": "REPLACE",
        "records": [{"content": soa_content, "disabled": false}]
    })];

    if !ns_list.is_empty() {
        let ns_records: Vec<Value> = ns_list
            .iter()
            .map(|ns| json!({"content": ns, "disabled": false}))
            .collect();
        rrsets.push(json!({
            "name": zone_fqdn,
            "type": "NS",
            "ttl": 3600,
            "changetype": "REPLACE",
            "records": ns_records
        }));
    }

    rrsets
}

async fn create_zone(
    State(state): State<AppState>,
    AdminUser(user): AdminUser,
    Json(body): Json<ZoneCreate>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let srv = pdns_server_repo::get_server(&state.db, body.server_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::BadRequest("PowerDNS server not found".into()))?;

    if !srv.is_active {
        return Err(AppError::BadRequest("PowerDNS server is not active".into()));
    }

    let client = get_pdns_client(&state, srv.id, &srv.name)?;

    let zone_fqdn = if body.name.ends_with('.') {
        body.name.clone()
    } else {
        format!("{}.", body.name)
    };

    let (nameservers, rrsets, template_name): (Vec<String>, Option<Vec<Value>>, Option<String>) =
        if let Some(tmpl_id) = body.template_id {
            let tmpl = zone_template_repo::get_template(&state.db, tmpl_id)
                .await
                .map_err(AppError::Internal)?
                .ok_or_else(|| AppError::NotFound("Zone template not found".into()))?;
            let rs = build_zone_rrsets(ZoneRRSetsParams {
                zone_fqdn: &zone_fqdn,
                nameservers: &tmpl.nameservers,
                soa_mname: &tmpl.soa_mname,
                soa_rname: &tmpl.soa_rname,
                soa_refresh: tmpl.soa_refresh,
                soa_retry: tmpl.soa_retry,
                soa_expire: tmpl.soa_expire,
                soa_ttl: tmpl.soa_ttl,
            });
            (vec![], Some(rs), Some(tmpl.name))
        } else if let (Some(mname), Some(rname)) = (&body.soa_mname, &body.soa_rname) {
            let rs = build_zone_rrsets(ZoneRRSetsParams {
                zone_fqdn: &zone_fqdn,
                nameservers: &body.nameservers,
                soa_mname: mname,
                soa_rname: rname,
                soa_refresh: body.soa_refresh.unwrap_or(3600),
                soa_retry: body.soa_retry.unwrap_or(900),
                soa_expire: body.soa_expire.unwrap_or(604800),
                soa_ttl: body.soa_ttl.unwrap_or(300),
            });
            (vec![], Some(rs), None)
        } else {
            (body.nameservers.clone(), None, None)
        };

    let mut data = json!({
        "name": zone_fqdn,
        "kind": body.kind,
        "soa_edit_api": "DEFAULT",
        "account": "",
    });

    let ns_fqdn: Vec<String> = nameservers
        .iter()
        .map(|ns| {
            if ns.ends_with('.') {
                ns.clone()
            } else {
                format!("{ns}.")
            }
        })
        .collect();

    if !ns_fqdn.is_empty() {
        data["nameservers"] = json!(ns_fqdn);
    }
    if !body.masters.is_empty() {
        data["masters"] = json!(body.masters);
    }
    if let Some(rs) = rrsets {
        data["rrsets"] = json!(rs);
    }

    let zone = client.create_zone(data).await.map_err(|e| pdns_err(&e))?;

    let zone_name = zone
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(&body.name)
        .to_string();

    pdns_server_repo::map_zone_to_server(&state.db, &zone_name, srv.id)
        .await
        .map_err(AppError::Internal)?;

    let mut detail_obj = json!({"kind": body.kind});
    if let Some(t) = &template_name {
        detail_obj["template"] = json!(t);
    }
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone.create",
        Some(&zone_name),
        Some(&detail_obj.to_string()),
    )
    .await
    .ok();

    if body.kind.to_lowercase() == "slave" {
        let zone_id = zone.get("id").and_then(|v| v.as_str()).unwrap_or(&body.name);
        let _ = client.axfr_retrieve(zone_id).await;
    }

    Ok((StatusCode::CREATED, Json(zone)))
}

async fn get_zone(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
) -> Result<Json<Value>, AppError> {
    // Zone access check
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client.get_zone(&zone_id, true).await.map(Json).map_err(|e| pdns_err(&e))
}

async fn update_zone(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
    Json(body): Json<ZoneUpdate>,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
        if body.kind.is_some() {
            return Err(AppError::Forbidden);
        }
    }

    let mut data = serde_json::Map::new();
    if let Some(k) = &body.kind {
        data.insert("kind".into(), json!(k));
    }
    if let Some(m) = &body.masters {
        data.insert("masters".into(), json!(m));
    }
    if let Some(a) = &body.account {
        data.insert("account".into(), json!(a));
    }
    if let Some(s) = &body.soa_edit {
        data.insert("soa_edit".into(), json!(s));
    }
    if let Some(s) = &body.soa_edit_api {
        data.insert("soa_edit_api".into(), json!(s));
    }
    if data.is_empty() {
        return Err(AppError::BadRequest("No fields to update".into()));
    }

    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client
        .update_zone(&zone_id, Value::Object(data.clone()))
        .await
        .map_err(|e| pdns_err(&e))?;

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone.update",
        Some(&zone_id),
        Some(&Value::Object(data).to_string()),
    )
    .await
    .ok();

    Ok(Json(json!({"ok": true})))
}

async fn delete_zone(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AdminUser(user): AdminUser,
) -> Result<Json<Value>, AppError> {
    let (_srv_id, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client.delete_zone(&zone_id).await.map_err(|e| pdns_err(&e))?;

    if let Some(sid) = q.server_id {
        pdns_server_repo::unmap_zone_from_server(&state.db, &zone_id, sid)
            .await
            .map_err(AppError::Internal)?;
        let remaining = pdns_server_repo::count_zone_servers(&state.db, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if remaining == 0 {
            zone_assignment_repo::delete_zone_assignments(&state.db, &zone_id)
                .await
                .map_err(AppError::Internal)?;
        }
    } else {
        zone_assignment_repo::delete_zone_assignments(&state.db, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        pdns_server_repo::unmap_zone(&state.db, &zone_id)
            .await
            .map_err(AppError::Internal)?;
    }

    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone.delete",
        Some(&zone_id),
        Some(&json!({"server_id": q.server_id}).to_string()),
    )
    .await
    .ok();

    Ok(Json(json!({"ok": true})))
}

async fn patch_rrsets(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
    Json(mut rrsets): Json<Vec<RRSet>>,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }

    for rs in &mut rrsets {
        if QUOTED_TYPES.contains(&rs.rrtype.as_str()) {
            for rec in &mut rs.records {
                rec.content = ensure_quoted(&rec.content);
            }
        }
    }

    let payload: Vec<Value> = rrsets
        .iter()
        .map(|rs| {
            json!({
                "name": rs.name,
                "type": rs.rrtype,
                "ttl": rs.ttl,
                "changetype": rs.changetype,
                "records": rs.records.iter().map(|r| json!({"content": r.content, "disabled": r.disabled})).collect::<Vec<_>>(),
            })
        })
        .collect();

    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client
        .patch_rrsets(&zone_id, json!(payload))
        .await
        .map_err(|e| pdns_err(&e))?;

    for rs in &rrsets {
        let action = format!("record.{}", rs.changetype.to_lowercase());
        let detail = json!({
            "name": rs.name,
            "type": rs.rrtype,
            "ttl": rs.ttl,
            "records": rs.records.iter().map(|r| json!({"content": r.content, "disabled": r.disabled})).collect::<Vec<_>>(),
        });
        audit_repo::log_action(
            &state.db,
            Some(user.id),
            Some(&user.username),
            &action,
            Some(&zone_id),
            Some(&detail.to_string()),
        )
        .await
        .ok();
    }

    // Auto-notify for Master zones after record changes (if setting enabled)
    let auto_notify = settings_repo::get_setting(&state.db, "auto_notify_on_master")
        .await
        .unwrap_or_default()
        .map(|v| v == "true")
        .unwrap_or(true);
    if auto_notify {
        if let Ok(zone_info) = client.get_zone(&zone_id, false).await {
            let kind = zone_info.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind.to_lowercase() == "master" {
                let _ = client.notify_zone(&zone_id).await;
                audit_repo::log_action(
                    &state.db,
                    Some(user.id),
                    Some(&user.username),
                    "zone.notify",
                    Some(&zone_id),
                    Some("{\"auto\":true}"),
                )
                .await
                .ok();
            }
        }
    }

    Ok(Json(json!({"ok": true})))
}

async fn export_zone(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    let text = client.export_zone(&zone_id).await.map_err(|e| pdns_err(&e))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        text,
    ))
}

async fn rectify_zone(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client.rectify_zone(&zone_id).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone.rectify",
        Some(&zone_id),
        None,
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn notify_zone(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client.notify_zone(&zone_id).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone.notify",
        Some(&zone_id),
        None,
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn axfr_retrieve(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client.axfr_retrieve(&zone_id).await.map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "zone.axfr_retrieve",
        Some(&zone_id),
        None,
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}

async fn list_metadata(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client.list_metadata(&zone_id).await.map(Json).map_err(|e| pdns_err(&e))
}

async fn set_metadata(
    State(state): State<AppState>,
    Path((zone_id, kind)): Path<(String, String)>,
    Query(q): Query<ServerIdQuery>,
    AuthUser(user): AuthUser,
    Json(value): Json<Vec<String>>,
) -> Result<Json<Value>, AppError> {
    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .map_err(AppError::Internal)?;
        if !ok {
            return Err(AppError::Forbidden);
        }
    }
    let (_, _, client) = resolve_zone_server(&state, &zone_id, q.server_id).await?;
    client
        .set_metadata(&zone_id, &kind, value.clone())
        .await
        .map_err(|e| pdns_err(&e))?;
    audit_repo::log_action(
        &state.db,
        Some(user.id),
        Some(&user.username),
        "metadata.set",
        Some(&zone_id),
        Some(&json!({"kind": kind, "value": value}).to_string()),
    )
    .await
    .ok();
    Ok(Json(json!({"ok": true})))
}
