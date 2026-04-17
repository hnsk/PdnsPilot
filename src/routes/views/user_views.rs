use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use axum_extra::extract::CookieJar;
use serde_json::json;

use crate::auth::get_session_user;
use crate::repositories::{pdns_server_repo, settings_repo, user_repo, zone_assignment_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(users_list))
        .route("/users/:user_id", get(user_detail))
        .route("/profile", get(profile_page))
        .route("/audit", get(audit_page))
}

fn redirect(url: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response()
}

async fn get_auth_user(state: &AppState, jar: &CookieJar) -> Option<crate::models::user::User> {
    let sid = jar.get("session_id")?.value().to_string();
    get_session_user(&state.db, &sid).await.ok()?.filter(|u| u.is_active)
}

fn render(state: &AppState, name: &str, ctx: minijinja::Value) -> Response {
    match state.templates.get_template(name) {
        Ok(t) => match t.render(ctx) {
            Ok(html) => Html(html).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn users_list(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) if u.role == "admin" => u,
        Some(_) => return redirect("/"),
        None => return redirect("/login"),
    };

    let users = user_repo::list_users(&state.db).await.unwrap_or_default();
    let mut users_with_zones = Vec::new();
    for u in &users {
        let zones = zone_assignment_repo::get_user_zones(&state.db, u.id)
            .await
            .unwrap_or_default();
        let mut v = json!(u);
        v["zone_count"] = json!(zones.len());
        users_with_zones.push(v);
    }

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "users",
        users => users_with_zones,
    };
    render(&state, "users/list.html", ctx)
}

async fn user_detail(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    jar: CookieJar,
) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) if u.role == "admin" => u,
        Some(_) => return redirect("/"),
        None => return redirect("/login"),
    };

    let target = match user_repo::get_user_by_id(&state.db, user_id).await {
        Ok(Some(u)) => u,
        _ => return redirect("/users"),
    };

    let assignments = zone_assignment_repo::get_user_zone_assignments(&state.db, user_id)
        .await
        .unwrap_or_default();

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let active_servers: Vec<_> = servers.iter().filter(|s| s.is_active).collect();
    let server_name_map: std::collections::HashMap<i64, &str> =
        active_servers.iter().map(|s| (s.id, s.name.as_str())).collect();

    let assigned_zones: Vec<_> = assignments
        .iter()
        .map(|a| {
            json!({
                "zone_name": a.zone_name,
                "pdns_server_id": a.pdns_server_id,
                "server_name": a.pdns_server_id
                    .and_then(|id| server_name_map.get(&id))
                    .copied()
                    .unwrap_or("Any"),
            })
        })
        .collect();

    let clients: Vec<_> = {
        let registry = state.pdns.read().unwrap();
        active_servers.iter().map(|srv| (srv.id, srv.name.clone(), registry.get(srv.id))).collect()
    };
    let mut servers_with_zones = Vec::new();
    for (srv_id, srv_name, client_opt) in clients {
        if let Some(client) = client_opt {
            if let Ok(zones) = client.list_zones(None).await {
                let zone_names: Vec<String> = zones
                    .as_array()
                    .map(|a| {
                        let mut names: Vec<String> = a
                            .iter()
                            .filter_map(|z| {
                                z.get("name")
                                    .or_else(|| z.get("id"))
                                    .and_then(|v| v.as_str())
                                    .map(String::from)
                            })
                            .collect();
                        names.sort();
                        names
                    })
                    .unwrap_or_default();
                servers_with_zones.push(json!({
                    "id": srv_id,
                    "name": srv_name,
                    "zones": zone_names,
                }));
            }
        }
    }

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "users",
        target_user => serde_json::to_value(&target).unwrap_or_default(),
        assigned_zones => assigned_zones,
        servers_with_zones => servers_with_zones,
    };
    render(&state, "users/detail.html", ctx)
}

async fn profile_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) => u,
        None => return redirect("/login"),
    };

    let global_default_ttl: i64 = settings_repo::get_setting(&state.db, "default_record_ttl")
        .await
        .unwrap_or_default()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "profile",
        global_default_ttl => global_default_ttl,
    };
    render(&state, "profile.html", ctx)
}

async fn audit_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) if u.role == "admin" => u,
        Some(_) => return redirect("/"),
        None => return redirect("/login"),
    };

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "audit",
    };
    render(&state, "audit.html", ctx)
}
