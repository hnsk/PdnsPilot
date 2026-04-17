use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use axum_extra::extract::CookieJar;
use serde_json::json;

use crate::auth::get_session_user;
use crate::repositories::{pdns_server_repo, zone_assignment_repo};
use crate::routes::views::zone_views::RECORD_TYPES;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/tools", get(tools_page))
}

fn redirect(url: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response()
}

async fn tools_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match jar.get("session_id") {
        Some(c) => match get_session_user(&state.db, c.value()).await {
            Ok(Some(u)) if u.is_active => u,
            _ => return redirect("/login"),
        },
        None => return redirect("/login"),
    };

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let mut active_servers: Vec<_> = servers.into_iter().filter(|s| s.is_active).collect();

    let accessible_zones: Vec<String>;
    if user.role == "admin" {
        let rows = sqlx::query!("SELECT DISTINCT zone_name FROM zone_server_map ORDER BY zone_name")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
        accessible_zones = rows.into_iter().map(|r| r.zone_name).collect();
    } else {
        let assignments = zone_assignment_repo::get_user_zone_assignments(&state.db, user.id)
            .await
            .unwrap_or_default();
        let assigned_server_ids: std::collections::HashSet<i64> = assignments
            .iter()
            .filter_map(|a| a.pdns_server_id)
            .collect();
        active_servers.retain(|s| assigned_server_ids.contains(&s.id));
        let zones: std::collections::HashSet<String> =
            assignments.into_iter().map(|a| a.zone_name).collect();
        accessible_zones = {
            let mut v: Vec<String> = zones.into_iter().collect();
            v.sort();
            v
        };
    }

    let safe_servers: Vec<_> = active_servers
        .iter()
        .map(|s| json!({"id": s.id, "name": s.name, "api_url": s.api_url, "server_id": s.server_id, "is_active": s.is_active}))
        .collect();

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "tools",
        active_servers => safe_servers,
        record_types => RECORD_TYPES,
        accessible_zones => accessible_zones,
    };

    match state.templates.get_template("tools.html") {
        Ok(t) => match t.render(ctx) {
            Ok(html) => Html(html).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
