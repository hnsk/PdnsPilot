use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdnsServer {
    pub id: i64,
    pub name: String,
    pub api_url: String,
    pub api_key: String,
    pub server_id: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

pub async fn list_servers(db: &SqlitePool) -> anyhow::Result<Vec<PdnsServer>> {
    let rows = sqlx::query!(
        "SELECT id, name, api_url, api_key, server_id, is_active, created_at, updated_at \
         FROM pdns_servers ORDER BY name ASC"
    )
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|r| -> anyhow::Result<PdnsServer> {
            Ok(PdnsServer {
                id: r.id.ok_or_else(|| anyhow::anyhow!("server id unexpectedly null"))?,
                name: r.name,
                api_url: r.api_url,
                api_key: r.api_key,
                server_id: r.server_id,
                is_active: r.is_active != 0,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

pub async fn get_server(db: &SqlitePool, server_db_id: i64) -> anyhow::Result<Option<PdnsServer>> {
    let row = sqlx::query!(
        "SELECT id, name, api_url, api_key, server_id, is_active, created_at, updated_at \
         FROM pdns_servers WHERE id = ?",
        server_db_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| PdnsServer {
        id: r.id,
        name: r.name,
        api_url: r.api_url,
        api_key: r.api_key,
        server_id: r.server_id,
        is_active: r.is_active != 0,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

pub async fn create_server(
    db: &SqlitePool,
    name: &str,
    api_url: &str,
    api_key: &str,
    server_id: &str,
) -> anyhow::Result<PdnsServer> {
    let result = sqlx::query!(
        "INSERT INTO pdns_servers (name, api_url, api_key, server_id) VALUES (?, ?, ?, ?)",
        name, api_url, api_key, server_id
    )
    .execute(db)
    .await?;
    let inserted_id = result.last_insert_rowid();
    get_server(db, inserted_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Server not found after insert"))
}

pub async fn update_server(
    db: &SqlitePool,
    server_db_id: i64,
    name: &str,
    api_url: &str,
    api_key: &str,
    server_id: &str,
    is_active: bool,
) -> anyhow::Result<Option<PdnsServer>> {
    let v = if is_active { 1i64 } else { 0i64 };
    sqlx::query!(
        "UPDATE pdns_servers SET name=?, api_url=?, api_key=?, server_id=?, is_active=?, \
         updated_at=datetime('now') WHERE id=?",
        name, api_url, api_key, server_id, v, server_db_id
    )
    .execute(db)
    .await?;
    get_server(db, server_db_id).await
}

pub async fn delete_server(db: &SqlitePool, server_db_id: i64) -> anyhow::Result<()> {
    sqlx::query!("DELETE FROM pdns_servers WHERE id = ?", server_db_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn get_server_for_zone(
    db: &SqlitePool,
    zone_name: &str,
) -> anyhow::Result<Option<PdnsServer>> {
    let row = sqlx::query!(
        "SELECT s.id, s.name, s.api_url, s.api_key, s.server_id, s.is_active, s.created_at, s.updated_at \
         FROM pdns_servers s JOIN zone_server_map m ON s.id = m.pdns_server_id \
         WHERE m.zone_name = ? LIMIT 1",
        zone_name
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| PdnsServer {
        id: r.id,
        name: r.name,
        api_url: r.api_url,
        api_key: r.api_key,
        server_id: r.server_id,
        is_active: r.is_active != 0,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

pub async fn map_zone_to_server(
    db: &SqlitePool,
    zone_name: &str,
    pdns_server_id: i64,
) -> anyhow::Result<()> {
    sqlx::query!(
        "INSERT INTO zone_server_map (zone_name, pdns_server_id) VALUES (?, ?) \
         ON CONFLICT(zone_name, pdns_server_id) DO NOTHING",
        zone_name,
        pdns_server_id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn unmap_zone(db: &SqlitePool, zone_name: &str) -> anyhow::Result<()> {
    sqlx::query!("DELETE FROM zone_server_map WHERE zone_name = ?", zone_name)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn unmap_zone_from_server(
    db: &SqlitePool,
    zone_name: &str,
    pdns_server_id: i64,
) -> anyhow::Result<()> {
    sqlx::query!(
        "DELETE FROM zone_server_map WHERE zone_name = ? AND pdns_server_id = ?",
        zone_name,
        pdns_server_id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn count_zone_servers(db: &SqlitePool, zone_name: &str) -> anyhow::Result<i64> {
    let count = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM zone_server_map WHERE zone_name = ?",
        zone_name
    )
    .fetch_one(db)
    .await?;
    Ok(count as i64)
}

pub async fn get_server_for_zone_by_server_id(
    db: &SqlitePool,
    zone_name: &str,
    pdns_server_db_id: i64,
) -> anyhow::Result<Option<PdnsServer>> {
    let row = sqlx::query!(
        "SELECT s.id, s.name, s.api_url, s.api_key, s.server_id, s.is_active, s.created_at, s.updated_at \
         FROM pdns_servers s JOIN zone_server_map m ON s.id = m.pdns_server_id \
         WHERE m.zone_name = ? AND s.id = ?",
        zone_name,
        pdns_server_db_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| PdnsServer {
        id: r.id,
        name: r.name,
        api_url: r.api_url,
        api_key: r.api_key,
        server_id: r.server_id,
        is_active: r.is_active != 0,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }))
}

pub async fn get_or_map_server_for_zone_by_server_id(
    db: &SqlitePool,
    zone_name: &str,
    pdns_server_db_id: i64,
) -> anyhow::Result<Option<PdnsServer>> {
    if let Some(srv) = get_server_for_zone_by_server_id(db, zone_name, pdns_server_db_id).await? {
        return Ok(Some(srv));
    }
    // Zone not mapped yet — auto-map it to the specified server
    if let Some(srv) = get_server(db, pdns_server_db_id).await? {
        if srv.is_active {
            map_zone_to_server(db, zone_name, pdns_server_db_id).await?;
            return Ok(Some(srv));
        }
    }
    Ok(None)
}

pub async fn get_server_for_zone_or_fallback(
    db: &SqlitePool,
    zone_name: &str,
) -> anyhow::Result<Option<PdnsServer>> {
    if let Some(srv) = get_server_for_zone(db, zone_name).await? {
        return Ok(Some(srv));
    }
    let active: Vec<PdnsServer> = list_servers(db)
        .await?
        .into_iter()
        .filter(|s| s.is_active)
        .collect();
    if active.len() == 1 {
        map_zone_to_server(db, zone_name, active[0].id).await?;
        return Ok(Some(active[0].clone()));
    }
    Ok(active.into_iter().next())
}

pub async fn list_zones_for_server(
    db: &SqlitePool,
    server_db_id: i64,
) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query!(
        "SELECT zone_name FROM zone_server_map WHERE pdns_server_id = ?",
        server_db_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| r.zone_name).collect())
}
