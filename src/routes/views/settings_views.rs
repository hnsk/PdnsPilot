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
use crate::repositories::{pdns_server_repo, settings_repo, zone_template_repo};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/settings", get(settings_page))
}

fn redirect(url: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response()
}

async fn settings_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match jar
        .get("session_id")
        .map(|c| c.value().to_string())
        .and_then(|_| None::<()>)
    {
        _ => {
            let sid = match jar.get("session_id") {
                Some(c) => c.value().to_string(),
                None => return redirect("/login"),
            };
            match get_session_user(&state.db, &sid).await {
                Ok(Some(u)) if u.is_active && u.role == "admin" => u,
                Ok(Some(_)) => return redirect("/"),
                _ => return redirect("/login"),
            }
        }
    };

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let pdns_servers: Vec<_> = servers
        .iter()
        .map(|s| json!({"id": s.id, "name": s.name, "api_url": s.api_url, "server_id": s.server_id, "is_active": s.is_active, "created_at": s.created_at, "updated_at": s.updated_at}))
        .collect();

    let zone_templates = zone_template_repo::list_templates(&state.db).await.unwrap_or_default();
    let default_record_ttl: i64 = settings_repo::get_setting(&state.db, "default_record_ttl")
        .await
        .unwrap_or_default()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let auto_notify_on_master: bool = settings_repo::get_setting(&state.db, "auto_notify_on_master")
        .await
        .unwrap_or_default()
        .map(|v| v == "true")
        .unwrap_or(true);

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "settings",
        pdns_servers => pdns_servers,
        zone_templates => serde_json::to_value(&zone_templates).unwrap_or_default(),
        default_record_ttl => default_record_ttl,
        auto_notify_on_master => auto_notify_on_master,
    };

    match state.templates.get_template("settings.html") {
        Ok(t) => match t.render(ctx) {
            Ok(html) => Html(html).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
