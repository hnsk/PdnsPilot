use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub action: String,
    pub zone_name: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

pub async fn log_action(
    db: &SqlitePool,
    user_id: Option<i64>,
    username: Option<&str>,
    action: &str,
    zone_name: Option<&str>,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query!(
        "INSERT INTO audit_log (user_id, username, action, zone_name, detail) VALUES (?, ?, ?, ?, ?)",
        user_id,
        username,
        action,
        zone_name,
        detail
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_audit_log(
    db: &SqlitePool,
    zone_name: Option<&str>,
    user_id: Option<i64>,
    limit: i64,
    offset: i64,
) -> anyhow::Result<Vec<AuditEntry>> {
    // Build dynamic query
    let rows = match (zone_name, user_id) {
        (Some(z), Some(u)) => {
            sqlx::query_as!(
                AuditEntry,
                "SELECT id as \"id!: i64\", user_id, username, action, zone_name, detail, created_at \
                 FROM audit_log WHERE zone_name = ? AND user_id = ? \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?",
                z, u, limit, offset
            )
            .fetch_all(db)
            .await?
        }
        (Some(z), None) => {
            sqlx::query_as!(
                AuditEntry,
                "SELECT id as \"id!: i64\", user_id, username, action, zone_name, detail, created_at \
                 FROM audit_log WHERE zone_name = ? \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?",
                z, limit, offset
            )
            .fetch_all(db)
            .await?
        }
        (None, Some(u)) => {
            sqlx::query_as!(
                AuditEntry,
                "SELECT id as \"id!: i64\", user_id, username, action, zone_name, detail, created_at \
                 FROM audit_log WHERE user_id = ? \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?",
                u, limit, offset
            )
            .fetch_all(db)
            .await?
        }
        (None, None) => {
            sqlx::query_as!(
                AuditEntry,
                "SELECT id as \"id!: i64\", user_id, username, action, zone_name, detail, created_at \
                 FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
                limit, offset
            )
            .fetch_all(db)
            .await?
        }
    };
    Ok(rows)
}

pub async fn count_audit_log(
    db: &SqlitePool,
    zone_name: Option<&str>,
    user_id: Option<i64>,
) -> anyhow::Result<i64> {
    let count = match (zone_name, user_id) {
        (Some(z), Some(u)) => {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM audit_log WHERE zone_name = ? AND user_id = ?",
                z, u
            )
            .fetch_one(db)
            .await?
        }
        (Some(z), None) => {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM audit_log WHERE zone_name = ?",
                z
            )
            .fetch_one(db)
            .await?
        }
        (None, Some(u)) => {
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM audit_log WHERE user_id = ?",
                u
            )
            .fetch_one(db)
            .await?
        }
        (None, None) => {
            sqlx::query_scalar!("SELECT COUNT(*) FROM audit_log")
                .fetch_one(db)
                .await?
        }
    };
    Ok(count as i64)
}
