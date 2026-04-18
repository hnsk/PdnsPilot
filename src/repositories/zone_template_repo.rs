use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTemplate {
    pub id: i64,
    pub name: String,
    pub nameservers: Vec<String>,
    pub soa_mname: String,
    pub soa_rname: String,
    pub soa_refresh: i64,
    pub soa_retry: i64,
    pub soa_expire: i64,
    pub soa_ttl: i64,
    pub is_default: bool,
    pub created_at: String,
}

#[allow(clippy::too_many_arguments)]
fn parse_template(
    id: i64,
    name: String,
    nameservers: String,
    soa_mname: String,
    soa_rname: String,
    soa_refresh: i64,
    soa_retry: i64,
    soa_expire: i64,
    soa_ttl: i64,
    is_default: i64,
    created_at: String,
) -> ZoneTemplate {
    ZoneTemplate {
        id,
        name,
        nameservers: serde_json::from_str(&nameservers).unwrap_or_default(),
        soa_mname,
        soa_rname,
        soa_refresh,
        soa_retry,
        soa_expire,
        soa_ttl,
        is_default: is_default != 0,
        created_at,
    }
}

pub async fn list_templates(db: &SqlitePool) -> anyhow::Result<Vec<ZoneTemplate>> {
    let rows = sqlx::query!(
        "SELECT id, name, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, \
         soa_expire, soa_ttl, is_default, created_at \
         FROM zone_templates ORDER BY is_default DESC, name ASC"
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            parse_template(
                r.id,
                r.name,
                r.nameservers,
                r.soa_mname,
                r.soa_rname,
                r.soa_refresh,
                r.soa_retry,
                r.soa_expire,
                r.soa_ttl,
                r.is_default,
                r.created_at,
            )
        })
        .collect())
}

pub async fn get_template(
    db: &SqlitePool,
    template_id: i64,
) -> anyhow::Result<Option<ZoneTemplate>> {
    let row = sqlx::query!(
        "SELECT id, name, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, \
         soa_expire, soa_ttl, is_default, created_at \
         FROM zone_templates WHERE id = ?",
        template_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| {
        parse_template(
            r.id,
            r.name,
            r.nameservers,
            r.soa_mname,
            r.soa_rname,
            r.soa_refresh,
            r.soa_retry,
            r.soa_expire,
            r.soa_ttl,
            r.is_default,
            r.created_at,
        )
    }))
}

pub struct TemplateData<'a> {
    pub name: &'a str,
    pub nameservers: &'a [String],
    pub soa_mname: &'a str,
    pub soa_rname: &'a str,
    pub soa_refresh: i64,
    pub soa_retry: i64,
    pub soa_expire: i64,
    pub soa_ttl: i64,
    pub is_default: bool,
}

pub async fn create_template(db: &SqlitePool, data: TemplateData<'_>) -> anyhow::Result<ZoneTemplate> {
    let TemplateData { name, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl, is_default } = data;
    if is_default {
        sqlx::query!("UPDATE zone_templates SET is_default = 0")
            .execute(db)
            .await?;
    }
    let ns_json = serde_json::to_string(nameservers)?;
    let def_val = if is_default { 1i64 } else { 0i64 };
    let row = sqlx::query!(
        "INSERT INTO zone_templates \
         (name, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl, is_default) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
         RETURNING id, name, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl, is_default, created_at",
        name, ns_json, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl, def_val
    )
    .fetch_one(db)
    .await?;
    Ok(parse_template(
        row.id,
        row.name,
        row.nameservers,
        row.soa_mname,
        row.soa_rname,
        row.soa_refresh,
        row.soa_retry,
        row.soa_expire,
        row.soa_ttl,
        row.is_default,
        row.created_at,
    ))
}

pub async fn update_template(
    db: &SqlitePool,
    template_id: i64,
    data: TemplateData<'_>,
) -> anyhow::Result<Option<ZoneTemplate>> {
    let TemplateData { name, nameservers, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl, is_default } = data;
    if is_default {
        sqlx::query!("UPDATE zone_templates SET is_default = 0")
            .execute(db)
            .await?;
    }
    let ns_json = serde_json::to_string(nameservers)?;
    let def_val = if is_default { 1i64 } else { 0i64 };
    sqlx::query!(
        "UPDATE zone_templates SET name=?, nameservers=?, soa_mname=?, soa_rname=?, \
         soa_refresh=?, soa_retry=?, soa_expire=?, soa_ttl=?, is_default=? WHERE id=?",
        name, ns_json, soa_mname, soa_rname, soa_refresh, soa_retry, soa_expire, soa_ttl,
        def_val, template_id
    )
    .execute(db)
    .await?;
    get_template(db, template_id).await
}

pub async fn set_default(db: &SqlitePool, template_id: i64) -> anyhow::Result<()> {
    sqlx::query!("UPDATE zone_templates SET is_default = 0")
        .execute(db)
        .await?;
    sqlx::query!(
        "UPDATE zone_templates SET is_default = 1 WHERE id = ?",
        template_id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_template(db: &SqlitePool, template_id: i64) -> anyhow::Result<()> {
    sqlx::query!("DELETE FROM zone_templates WHERE id = ?", template_id)
        .execute(db)
        .await?;
    Ok(())
}
