use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneAssignment {
    pub zone_name: String,
    pub pdns_server_id: Option<i64>,
}

pub async fn get_user_zones(db: &SqlitePool, user_id: i64) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query!(
        "SELECT zone_name FROM zone_assignments WHERE user_id = ?",
        user_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| r.zone_name).collect())
}

pub async fn get_user_zone_assignments(
    db: &SqlitePool,
    user_id: i64,
) -> anyhow::Result<Vec<ZoneAssignment>> {
    let rows = sqlx::query!(
        "SELECT zone_name, pdns_server_id FROM zone_assignments WHERE user_id = ?",
        user_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ZoneAssignment {
            zone_name: r.zone_name,
            pdns_server_id: r.pdns_server_id,
        })
        .collect())
}

pub async fn set_user_zones(
    db: &SqlitePool,
    user_id: i64,
    assignments: &[ZoneAssignment],
) -> anyhow::Result<()> {
    sqlx::query!("DELETE FROM zone_assignments WHERE user_id = ?", user_id)
        .execute(db)
        .await?;
    for a in assignments {
        sqlx::query!(
            "INSERT INTO zone_assignments (user_id, zone_name, pdns_server_id) VALUES (?, ?, ?)",
            user_id,
            a.zone_name,
            a.pdns_server_id
        )
        .execute(db)
        .await?;
    }
    Ok(())
}

pub async fn delete_zone_assignments(db: &SqlitePool, zone_name: &str) -> anyhow::Result<()> {
    sqlx::query!(
        "DELETE FROM zone_assignments WHERE zone_name = ?",
        zone_name
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn user_has_zone_access(
    db: &SqlitePool,
    user_id: i64,
    zone_name: &str,
) -> anyhow::Result<bool> {
    let row = sqlx::query!(
        "SELECT 1 as x FROM zone_assignments WHERE user_id = ? AND zone_name = ?",
        user_id,
        zone_name
    )
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}
