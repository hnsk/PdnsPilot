use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;

use crate::auth::get_session_user;
use crate::repositories::{pdns_server_repo, reverse_zone_repo, settings_repo, zone_assignment_repo, zone_template_repo};
use crate::reverse_zones;
use crate::AppState;

pub const RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "AFSDB", "ALIAS", "APL", "CAA", "CDNSKEY", "CDS", "CERT",
    "CNAME", "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48",
    "EUI64", "HINFO", "HTTPS", "IPSECKEY", "KEY", "KX", "LOC", "LUA",
    "MAILA", "MAILB", "MB", "MG", "MINFO", "MR", "MX", "NAPTR", "NS",
    "NSEC", "NSEC3", "NSEC3PARAM", "NXT", "OPENPGPKEY", "PTR", "RP",
    "RRSIG", "SIG", "SMIMEA", "SOA", "SPF", "SRV", "SSHFP", "SVCB",
    "TKEY", "TLSA", "TSIG", "TXT", "URI", "WKS", "ZONEMD",
];

pub const REVERSE_RECORD_TYPES: &[&str] = &[
    "PTR", "NS", "SOA", "CNAME", "TXT", "NSEC", "NSEC3", "NSEC3PARAM", "RRSIG", "DNSKEY",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/zones", get(zones_list))
        .route("/reverse-zones", get(reverse_zones_list))
        .route("/zones/:zone_id", get(zone_detail))
        .route("/zones/:zone_id/export", get(zone_export))
        .route("/zones/:zone_id/dnssec", get(zone_dnssec))
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

#[derive(Deserialize, Default)]
struct ServerIdQuery {
    server_id: Option<i64>,
}

async fn zones_list(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) => u,
        None => return redirect("/login"),
    };

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let active_servers: Vec<_> = servers.into_iter().filter(|s| s.is_active).collect();

    let clients: Vec<_> = {
        let registry = state.pdns.read();
        active_servers.iter().map(|srv| (srv.id, srv.name.clone(), registry.get(srv.id))).collect()
    };

    let mut all_zones = Vec::new();
    for (srv_id, srv_name, client_opt) in &clients {
        if let Some(client) = client_opt {
            if let Ok(zones) = client.list_zones(None).await {
                if let Some(arr) = zones.as_array() {
                    for z in arr {
                        let mut z = z.clone();
                        z["_server_id"] = json!(srv_id);
                        z["_server_name"] = json!(srv_name);
                        all_zones.push(z);
                    }
                }
            }
        }
    }

    // Filter out reverse zones — they appear on /reverse-zones instead.
    all_zones.retain(|z| {
        let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        !reverse_zones::is_reverse_zone(name)
    });

    if user.role != "admin" {
        let assignments = zone_assignment_repo::get_user_zone_assignments(&state.db, user.id)
            .await
            .unwrap_or_default();
        let allowed_pairs: std::collections::HashSet<(String, Option<i64>)> = assignments
            .iter()
            .filter(|a| a.pdns_server_id.is_some())
            .map(|a| (a.zone_name.clone(), a.pdns_server_id))
            .collect();
        let allowed_names: std::collections::HashSet<String> = assignments
            .iter()
            .filter(|a| a.pdns_server_id.is_none())
            .map(|a| a.zone_name.clone())
            .collect();
        all_zones.retain(|z| {
            let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let sid = z.get("_server_id").and_then(|v| v.as_i64());
            allowed_pairs.contains(&(name.clone(), sid))
                || allowed_names.contains(&name)
        });
    }

    let zone_templates = zone_template_repo::list_templates(&state.db).await.unwrap_or_default();

    // For non-admins, only expose servers that have at least one visible zone.
    let visible_server_ids: std::collections::HashSet<i64> = all_zones
        .iter()
        .filter_map(|z| z.get("_server_id").and_then(|v| v.as_i64()))
        .collect();
    let pdns_servers: Vec<_> = active_servers
        .iter()
        .filter(|s| user.role == "admin" || visible_server_ids.contains(&s.id))
        .map(|s| json!({"id": s.id, "name": s.name, "api_url": s.api_url, "server_id": s.server_id, "is_active": s.is_active}))
        .collect();

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "zones",
        zones => all_zones,
        zone_templates => serde_json::to_value(&zone_templates).unwrap_or_default(),
        pdns_servers => pdns_servers,
    };
    render(&state, "zones/list.html", ctx)
}

async fn reverse_zones_list(State(state): State<AppState>, jar: CookieJar) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) => u,
        None => return redirect("/login"),
    };

    let servers = pdns_server_repo::list_servers(&state.db).await.unwrap_or_default();
    let active_servers: Vec<_> = servers.into_iter().filter(|s| s.is_active).collect();

    let clients: Vec<_> = {
        let registry = state.pdns.read();
        active_servers
            .iter()
            .map(|srv| (srv.id, srv.name.clone(), registry.get(srv.id)))
            .collect()
    };

    let mut all_zones = Vec::new();
    for (srv_id, srv_name, client_opt) in &clients {
        if let Some(client) = client_opt {
            if let Ok(zones) = client.list_zones(None).await {
                if let Some(arr) = zones.as_array() {
                    for z in arr {
                        let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                        if reverse_zones::is_reverse_zone(name) {
                            let mut z = z.clone();
                            z["_server_id"] = json!(srv_id);
                            z["_server_name"] = json!(srv_name);
                            all_zones.push(z);
                        }
                    }
                }
            }
        }
    }

    if user.role != "admin" {
        let assignments = zone_assignment_repo::get_user_zone_assignments(&state.db, user.id)
            .await
            .unwrap_or_default();
        let allowed_pairs: std::collections::HashSet<(String, Option<i64>)> = assignments
            .iter()
            .filter(|a| a.pdns_server_id.is_some())
            .map(|a| (a.zone_name.clone(), a.pdns_server_id))
            .collect();
        let allowed_names: std::collections::HashSet<String> = assignments
            .iter()
            .filter(|a| a.pdns_server_id.is_none())
            .map(|a| a.zone_name.clone())
            .collect();
        all_zones.retain(|z| {
            let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let sid = z.get("_server_id").and_then(|v| v.as_i64());
            allowed_pairs.contains(&(name.clone(), sid))
                || allowed_names.contains(&name)
        });
    }

    // Annotate each zone with network string.
    for z in &mut all_zones {
        let name = z.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let network = reverse_zone_repo::get_network(&state.db, &name)
            .await
            .unwrap_or(None)
            .or_else(|| reverse_zones::arpa_to_network(&name));
        if let Some(net) = network {
            z["_network"] = json!(net);
        }
    }

    let visible_server_ids: std::collections::HashSet<i64> = all_zones
        .iter()
        .filter_map(|z| z.get("_server_id").and_then(|v| v.as_i64()))
        .collect();
    let pdns_servers: Vec<_> = active_servers
        .iter()
        .filter(|s| user.role == "admin" || visible_server_ids.contains(&s.id))
        .map(|s| json!({"id": s.id, "name": s.name, "api_url": s.api_url, "server_id": s.server_id, "is_active": s.is_active}))
        .collect();

    let zone_templates = zone_template_repo::list_templates(&state.db).await.unwrap_or_default();

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "reverse-zones",
        zones => all_zones,
        zone_templates => serde_json::to_value(&zone_templates).unwrap_or_default(),
        pdns_servers => pdns_servers,
    };
    render(&state, "zones/reverse_list.html", ctx)
}

async fn zone_detail(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    jar: CookieJar,
) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) => u,
        None => return redirect("/login"),
    };

    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .unwrap_or(false);
        if !ok {
            return redirect("/zones");
        }
    }

    let srv = if let Some(sid) = q.server_id {
        pdns_server_repo::get_or_map_server_for_zone_by_server_id(&state.db, &zone_id, sid)
            .await
            .unwrap_or(None)
    } else {
        match pdns_server_repo::get_server_for_zone_or_fallback(&state.db, &zone_id).await {
            Ok(Some(s)) => {
                return redirect(&format!("/zones/{zone_id}?server_id={}", s.id));
            }
            _ => None,
        }
    };

    let srv = match srv {
        Some(s) => s,
        None => return redirect("/zones"),
    };

    let client = { state.pdns.read().get(srv.id) };
    let client = match client {
        Some(c) => c,
        None => return redirect("/zones"),
    };

    let zone = match client.get_zone(&zone_id, true).await {
        Ok(z) => z,
        Err(_) => return redirect("/zones"),
    };

    let default_ttl = if let Some(ttl) = user.default_ttl {
        ttl
    } else {
        settings_repo::get_setting(&state.db, "default_record_ttl")
            .await
            .unwrap_or_default()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
    };

    let zone_name_str = zone.get("name").and_then(|v| v.as_str()).unwrap_or(&zone_id);
    let is_rev = reverse_zones::is_reverse_zone(zone_name_str);
    let record_types: &[&str] = if is_rev { REVERSE_RECORD_TYPES } else { RECORD_TYPES };

    let network = if is_rev {
        reverse_zone_repo::get_network(&state.db, zone_name_str)
            .await
            .unwrap_or(None)
            .or_else(|| reverse_zones::arpa_to_network(zone_name_str))
    } else {
        None
    };

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => if is_rev { "reverse-zones" } else { "zones" },
        zone => zone,
        record_types => record_types,
        is_reverse_zone => is_rev,
        network => network,
        server_id => q.server_id,
        server_name => srv.name,
        default_ttl => default_ttl,
    };
    render(&state, "zones/detail.html", ctx)
}

async fn zone_export(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    jar: CookieJar,
) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) => u,
        None => return redirect("/login"),
    };

    if user.role != "admin" {
        let ok = zone_assignment_repo::user_has_zone_access(&state.db, user.id, &zone_id)
            .await
            .unwrap_or(false);
        if !ok {
            return redirect("/zones");
        }
    }

    let srv = if let Some(sid) = q.server_id {
        pdns_server_repo::get_server_for_zone_by_server_id(&state.db, &zone_id, sid)
            .await
            .unwrap_or(None)
    } else {
        pdns_server_repo::get_server_for_zone_or_fallback(&state.db, &zone_id)
            .await
            .unwrap_or(None)
    };

    let export_data = if let Some(s) = srv {
        let client = { state.pdns.read().get(s.id) };
        if let Some(client) = client {
            client.export_zone(&zone_id).await.unwrap_or_else(|_| "Failed to export zone".into())
        } else {
            "Server not connected".into()
        }
    } else {
        "Zone not mapped to any server".into()
    };

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "zones",
        zone_id => zone_id,
        export_data => export_data,
        server_id => q.server_id,
    };
    render(&state, "zones/export.html", ctx)
}

async fn zone_dnssec(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(q): Query<ServerIdQuery>,
    jar: CookieJar,
) -> Response {
    let user = match get_auth_user(&state, &jar).await {
        Some(u) => u,
        None => return redirect("/login"),
    };

    if user.role != "admin" {
        return redirect("/zones");
    }

    let srv = if let Some(sid) = q.server_id {
        pdns_server_repo::get_server_for_zone_by_server_id(&state.db, &zone_id, sid)
            .await
            .unwrap_or(None)
    } else {
        pdns_server_repo::get_server_for_zone_or_fallback(&state.db, &zone_id)
            .await
            .unwrap_or(None)
    };

    let srv = match srv {
        Some(s) => s,
        None => return redirect("/zones"),
    };

    let client = { state.pdns.read().get(srv.id) };
    let client = match client {
        Some(c) => c,
        None => return redirect("/zones"),
    };

    let zone = match client.get_zone(&zone_id, false).await {
        Ok(z) => z,
        Err(_) => return redirect("/zones"),
    };

    let dnssec_enabled = zone
        .get("dnssec")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let keys = if dnssec_enabled {
        client.list_cryptokeys(&zone_id).await.unwrap_or(serde_json::json!([]))
    } else {
        serde_json::json!([])
    };

    let ctx = minijinja::context! {
        user => serde_json::to_value(&user).unwrap_or_default(),
        active_page => "zones",
        zone_id => zone_id,
        dnssec_enabled => dnssec_enabled,
        keys => keys,
        server_id => q.server_id,
    };
    render(&state, "dnssec/keys.html", ctx)
}
