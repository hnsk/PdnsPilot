use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_path: String,
    pub secret_key: String,
    pub session_lifetime_hours: i64,
    pub default_admin_password: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let secret_key = env::var("PDNSPILOT_SECRET_KEY")
            .unwrap_or_else(|_| "change-this-to-a-random-secret".to_string());

        if secret_key == "change-this-to-a-random-secret" {
            anyhow::bail!(
                "PDNSPILOT_SECRET_KEY is not set. \
                 Set it to a random secret before starting the application."
            );
        }

        let default_admin_password = env::var("PDNSPILOT_DEFAULT_ADMIN_PASSWORD")
            .unwrap_or_else(|_| "admin".to_string());

        if default_admin_password == "admin" {
            tracing::warn!(
                "PDNSPILOT_DEFAULT_ADMIN_PASSWORD is still 'admin'. \
                 Change it after first login."
            );
        }

        Ok(Config {
            database_path: env::var("PDNSPILOT_DATABASE_PATH")
                .unwrap_or_else(|_| "./data/pdnspilot.db".to_string()),
            secret_key,
            session_lifetime_hours: env::var("PDNSPILOT_SESSION_LIFETIME_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            default_admin_password,
        })
    }
}
