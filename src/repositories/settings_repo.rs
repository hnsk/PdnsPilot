use sqlx::SqlitePool;

pub async fn get_setting(db: &SqlitePool, key: &str) -> anyhow::Result<Option<String>> {
    let row = sqlx::query!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.value))
}

pub async fn upsert_setting(db: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query!(
        "INSERT INTO settings (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        key,
        value
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn seed_defaults(
    db: &SqlitePool,
    defaults: &[(&str, &str)],
) -> anyhow::Result<()> {
    for (key, value) in defaults {
        sqlx::query!(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING",
            key,
            value
        )
        .execute(db)
        .await?;
    }
    Ok(())
}
