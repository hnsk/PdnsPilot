use std::sync::{Arc, RwLock};

use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

mod auth;
mod config;
mod db;
mod error;
mod models;
mod pdns_client;
mod repositories;
mod routes;

use config::Config;
use pdns_client::PdnsRegistry;
use repositories::{pdns_server_repo, settings_repo, user_repo};

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub pdns: Arc<RwLock<PdnsRegistry>>,
    pub templates: Arc<minijinja::Environment<'static>>,
    pub config: Arc<Config>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present
    dotenvy::dotenv().ok();

    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pdns_rustadmin=info,tower_http=debug".into()),
        )
        .init();

    let config = Config::from_env()?;
    tracing::info!("Starting pdns-rustadmin");

    // Database
    let db = db::init_pool(&config.database_path).await?;
    tracing::info!("Database initialized at {}", config.database_path);

    // Seed defaults
    settings_repo::seed_defaults(&db, &[("default_record_ttl", "60")]).await?;

    // Ensure admin user exists
    user_repo::ensure_admin_exists(&db, &config.default_admin_password).await?;

    // PDNS registry
    let registry = Arc::new(RwLock::new(PdnsRegistry::new()));

    // Connect to all active servers
    let servers = pdns_server_repo::list_servers(&db).await?;
    for srv in servers.iter().filter(|s| s.is_active) {
        match registry
            .write()
            .unwrap()
            .start_server(srv.id, &srv.api_url, &srv.api_key, &srv.server_id)
        {
            Ok(_) => tracing::info!("Connected to PDNS server '{}'", srv.name),
            Err(e) => tracing::warn!("Failed to connect to '{}': {}", srv.name, e),
        }
    }

    // MiniJinja templates
    let templates = {
        let mut env = minijinja::Environment::new();
        env.set_loader(minijinja::path_loader("./templates"));
        Arc::new(env)
    };

    let state = AppState {
        db,
        pdns: registry,
        templates,
        config: Arc::new(config),
    };

    // Router
    let app = Router::new()
        // API routes
        .merge(routes::api_auth::router())
        .merge(routes::api_zones::router())
        .merge(routes::api_dnssec::router())
        .merge(routes::api_users::router())
        .merge(routes::api_audit::router())
        .merge(routes::api_settings::router())
        .merge(routes::api_pdns_servers::router())
        .merge(routes::api_zone_templates::router())
        .merge(routes::api_tools::router())
        .merge(routes::api_metrics::router())
        // View routes
        .merge(routes::views::auth_views::router())
        .merge(routes::views::dashboard_views::router())
        .merge(routes::views::zone_views::router())
        .merge(routes::views::user_views::router())
        .merge(routes::views::settings_views::router())
        .merge(routes::views::tools_views::router())
        .merge(routes::views::metrics_views::router())
        // Static files
        .nest_service("/static", ServeDir::new("./static"))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("Listening on {bind_addr}");

    axum::serve(listener, app).await?;
    Ok(())
}
