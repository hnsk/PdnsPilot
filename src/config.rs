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
        let secret_key = env::var("POWERADMIN_SECRET_KEY")
            .unwrap_or_else(|_| "change-this-to-a-random-secret".to_string());

        if secret_key == "change-this-to-a-random-secret" {
            anyhow::bail!(
                "POWERADMIN_SECRET_KEY is not set. \
                 Set it to a random secret before starting the application."
            );
        }

        let default_admin_password = env::var("POWERADMIN_DEFAULT_ADMIN_PASSWORD")
            .unwrap_or_else(|_| "admin".to_string());

        if default_admin_password == "admin" {
            tracing::warn!(
                "POWERADMIN_DEFAULT_ADMIN_PASSWORD is still 'admin'. \
                 Change it after first login."
            );
        }

        Ok(Config {
            database_path: env::var("POWERADMIN_DATABASE_PATH")
                .unwrap_or_else(|_| "./data/poweradmin.db".to_string()),
            secret_key,
            session_lifetime_hours: env::var("POWERADMIN_SESSION_LIFETIME_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8),
            default_admin_password,
        })
    }
}
