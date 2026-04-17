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
use crate::repositories::{audit_repo, pdns_server_repo, user_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(dashboard))
}

async fn dashboard(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session_id = jar.get("session_id").map(|c| c.value().to_string());
    let user = match session_id {
        Some(sid) => match get_session_user(&state.db, &sid).await {
            Ok(Some(u)) if u.is_active => u,
            _ => {
                return (StatusCode::FOUND, [(header::LOCATION, "/login")]).into_response();
            }
        },
        None => {
            return (StatusCode::FOUND, [(header::LOCATION, "/login")]).into_response();
        }
    };

    if user.role == "operator" {
        return (StatusCode::FOUND, [(header::LOCATION, "/zones")]).into_response();
    }

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let active_servers: Vec<_> = servers.into_iter().filter(|s| s.is_active).collect();

    let mut zone_count = 0usize;
    let mut dnssec_count = 0usize;
    let mut server_infos = Vec::new();

    let clients: Vec<_> = {
        let registry = state.pdns.read();
        active_servers.iter().map(|srv| {
            (srv.name.clone(), registry.get(srv.id))
        }).collect()
    };

    for (srv_name, client_opt) in clients {
        let mut entry = json!({
            "name": srv_name,
            "connected": false,
            "zone_count": 0,
            "dnssec_count": 0,
            "server_info": {}
        });
        if let Some(client) = client_opt {
            if let (Ok(info), Ok(zones)) =
                tokio::join!(client.get_server_info(), client.list_zones(None))
            {
                let zc = zones.as_array().map(|a| a.len()).unwrap_or(0);
                let dc = zones
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|z| {
                                z.get("dnssec").and_then(|v| v.as_bool()).unwrap_or(false)
                            })
                            .count()
                    })
                    .unwrap_or(0);
                zone_count += zc;
                dnssec_count += dc;
                entry["zone_count"] = json!(zc);
                entry["dnssec_count"] = json!(dc);
                entry["server_info"] = info;
                entry["connected"] = json!(true);
            }
        }
        server_infos.push(entry);
    }

    let mut user_count = 0usize;
    let mut recent_audit = Vec::new();
    if user.role == "admin" {
        user_count = user_repo::list_users(&state.db)
            .await
            .map(|u| u.len())
            .unwrap_or(0);
        recent_audit = audit_repo::get_audit_log(&state.db, None, None, 10, 0)
            .await
            .unwrap_or_default();
    }

    let tmpl = match state.templates.get_template("dashboard.html") {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "dashboard",
        zone_count => zone_count,
        user_count => user_count,
        dnssec_count => dnssec_count,
        recent_audit => serde_json::to_value(&recent_audit).unwrap_or_default(),
        server_infos => server_infos,
    };

    match tmpl.render(ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
