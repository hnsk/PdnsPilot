use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};
use axum_extra::extract::CookieJar;
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::AppError;
use crate::models::user::User;
use crate::repositories::user_repo;
use crate::AppState;

// ─── Session helpers ────────────────────────────────────────────────────────

pub async fn create_session(
    db: &SqlitePool,
    user_id: i64,
    lifetime_hours: i64,
) -> anyhow::Result<String> {
    let session_id: String = {
        let bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen::<u8>()).collect();
        hex::encode(bytes)
    };
    let expires_at = chrono_like_expires(lifetime_hours);
    sqlx::query!(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
        session_id,
        user_id,
        expires_at
    )
    .execute(db)
    .await?;
    Ok(session_id)
}

fn chrono_like_expires(hours: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let future = now + hours * 3600;
    // Format as ISO datetime  (no timezone suffix — same as Python's isoformat)
    epoch_to_iso(future)
}

fn epoch_to_iso(ts: i64) -> String {
    // Simple epoch → ISO 8601 UTC without external deps
    let secs_per_day = 86400i64;
    let mut remaining = ts;
    let days_since_epoch = remaining / secs_per_day;
    remaining %= secs_per_day;
    let h = remaining / 3600;
    remaining %= 3600;
    let m = remaining / 60;
    let s = remaining % 60;

    let (y, mo, d) = days_to_ymd(days_since_epoch);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}")
}

fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub async fn get_session_user(db: &SqlitePool, session_id: &str) -> anyhow::Result<Option<User>> {
    let row = sqlx::query!(
        "SELECT user_id, expires_at FROM sessions WHERE id = ?",
        session_id
    )
    .fetch_optional(db)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    // Check expiry (simple string comparison works for ISO format)
    let now = epoch_to_iso(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    );
    if row.expires_at < now {
        sqlx::query!("DELETE FROM sessions WHERE id = ?", session_id)
            .execute(db)
            .await?;
        return Ok(None);
    }

    user_repo::get_user_by_id(db, row.user_id).await
}

pub async fn delete_session(db: &SqlitePool, session_id: &str) -> anyhow::Result<()> {
    sqlx::query!("DELETE FROM sessions WHERE id = ?", session_id)
        .execute(db)
        .await?;
    Ok(())
}

// ─── API key helpers ─────────────────────────────────────────────────────────

fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn verify_api_key(db: &SqlitePool, key: &str) -> anyhow::Result<Option<User>> {
    let key_hash = hash_key(key);
    let row = sqlx::query!(
        "SELECT user_id FROM api_keys WHERE key_hash = ?",
        key_hash
    )
    .fetch_optional(db)
    .await?;
    match row {
        Some(r) => user_repo::get_user_by_id(db, r.user_id).await,
        None => Ok(None),
    }
}

pub async fn create_api_key(
    db: &SqlitePool,
    user_id: i64,
    description: &str,
) -> anyhow::Result<String> {
    let key_bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen::<u8>()).collect();
    let key = hex::encode(&key_bytes);
    let key_hash = hash_key(&key);
    sqlx::query!(
        "INSERT INTO api_keys (user_id, key_hash, description) VALUES (?, ?, ?)",
        user_id,
        key_hash,
        description
    )
    .execute(db)
    .await?;
    Ok(key)
}

#[derive(serde::Serialize)]
pub struct ApiKeyInfo {
    pub id: i64,
    pub description: Option<String>,
    pub created_at: String,
}

pub async fn list_api_keys(db: &SqlitePool, user_id: i64) -> anyhow::Result<Vec<ApiKeyInfo>> {
    let rows = sqlx::query!(
        "SELECT id, description, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
        user_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ApiKeyInfo {
            id: r.id,
            description: r.description,
            created_at: r.created_at,
        })
        .collect())
}

pub async fn delete_api_key(
    db: &SqlitePool,
    key_id: i64,
    user_id: i64,
) -> anyhow::Result<()> {
    sqlx::query!(
        "DELETE FROM api_keys WHERE id = ? AND user_id = ?",
        key_id,
        user_id
    )
    .execute(db)
    .await?;
    Ok(())
}

// ─── Auth extractors ─────────────────────────────────────────────────────────

/// Authenticated user — checks X-API-Key header first, then session cookie.
pub struct AuthUser(pub User);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let db = &state.db;

        // 1. API key header
        if let Some(api_key) = parts.headers.get("X-API-Key").and_then(|v| v.to_str().ok()) {
            match verify_api_key(db, api_key).await {
                Ok(Some(u)) if u.is_active => return Ok(AuthUser(u)),
                Ok(_) => return Err(AppError::Unauthorized),
                Err(e) => return Err(AppError::Internal(e)),
            }
        }

        // 2. Session cookie
        let jar = CookieJar::from_headers(&parts.headers);
        let session_id = jar
            .get("session_id")
            .map(|c| c.value().to_string());

        match session_id {
            Some(sid) => match get_session_user(db, &sid).await {
                Ok(Some(u)) if u.is_active => Ok(AuthUser(u)),
                Ok(_) => Err(AppError::Unauthorized),
                Err(e) => Err(AppError::Internal(e)),
            },
            None => Err(AppError::Unauthorized),
        }
    }
}

/// Admin-only extractor.
pub struct AdminUser(pub User);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if user.role != "admin" {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}
