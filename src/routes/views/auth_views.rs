use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use axum_extra::extract::CookieJar;

use crate::auth::delete_session;
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_page))
        .route("/logout", get(logout_page))
}

async fn login_page(State(state): State<AppState>) -> Result<Html<String>, Response> {
    let tmpl = state
        .templates
        .get_template("login.html")
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        })?;
    let ctx = minijinja::context! { user => minijinja::Value::UNDEFINED, error => minijinja::Value::UNDEFINED };
    let html = tmpl.render(ctx).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
    })?;
    Ok(Html(html))
}

async fn logout_page(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    if let Some(sid) = jar.get("session_id") {
        let _ = delete_session(&state.db, sid.value()).await;
    }
    let clear_cookie = "session_id=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/";
    (
        StatusCode::FOUND,
        [(header::LOCATION, "/login"), (header::SET_COOKIE, clear_cookie)],
    )
        .into_response()
}
