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
use crate::repositories::pdns_server_repo;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(metrics_overview))
        .route("/metrics/:server_db_id", get(metrics_detail))
}

fn redirect(url: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, url.to_string())]).into_response()
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

async fn metrics_overview(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match jar.get("session_id") {
        Some(c) => match get_session_user(&state.db, c.value()).await {
            Ok(Some(u)) if u.is_active => u,
            _ => return redirect("/login"),
        },
        None => return redirect("/login"),
    };

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let active_servers: Vec<_> = servers
        .into_iter()
        .filter(|s| s.is_active)
        .map(|s| json!({"id": s.id, "name": s.name}))
        .collect();

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "metrics",
        servers => active_servers,
    };
    render(&state, "metrics/overview.html", ctx)
}

async fn metrics_detail(
    State(state): State<AppState>,
    Path(server_db_id): Path<i64>,
    jar: CookieJar,
) -> Response {
    let user = match jar.get("session_id") {
        Some(c) => match get_session_user(&state.db, c.value()).await {
            Ok(Some(u)) if u.is_active => u,
            _ => return redirect("/login"),
        },
        None => return redirect("/login"),
    };

    let srv = match pdns_server_repo::get_server(&state.db, server_db_id).await {
        Ok(Some(s)) => s,
        _ => return (StatusCode::NOT_FOUND, "Server not found").into_response(),
    };

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "metrics",
        server => json!({"id": srv.id, "name": srv.name}),
    };
    render(&state, "metrics/detail.html", ctx)
}
