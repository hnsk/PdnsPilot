use sqlx::SqlitePool;

pub async fn set_network(db: &SqlitePool, zone_name: &str, network: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO reverse_zone_networks (zone_name, network) VALUES (?, ?) \
         ON CONFLICT(zone_name) DO UPDATE SET network = excluded.network",
    )
    .bind(zone_name)
    .bind(network)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_network(db: &SqlitePool, zone_name: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT network FROM reverse_zone_networks WHERE zone_name = ?")
            .bind(zone_name)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(n,)| n))
}

pub async fn delete_network(db: &SqlitePool, zone_name: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM reverse_zone_networks WHERE zone_name = ?")
        .bind(zone_name)
        .execute(db)
        .await?;
    Ok(())
}
