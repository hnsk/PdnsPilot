use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sqlx::SqlitePool;

use crate::models::user::User;

pub async fn get_user_by_id(db: &SqlitePool, user_id: i64) -> anyhow::Result<Option<User>> {
    let row = sqlx::query!(
        "SELECT id, username, role, is_active, default_ttl FROM users WHERE id = ?",
        user_id
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| User {
        id: r.id,
        username: r.username,
        role: r.role,
        is_active: r.is_active != 0,
        default_ttl: r.default_ttl,
    }))
}

pub async fn get_user_by_username(
    db: &SqlitePool,
    username: &str,
) -> anyhow::Result<Option<User>> {
    let row = sqlx::query!(
        "SELECT id, username, role, is_active, default_ttl FROM users WHERE username = ?",
        username
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| User {
        id: r.id.expect("user id is never null"),
        username: r.username,
        role: r.role,
        is_active: r.is_active != 0,
        default_ttl: r.default_ttl,
    }))
}

pub async fn verify_password(
    db: &SqlitePool,
    username: &str,
    password: &str,
) -> anyhow::Result<Option<User>> {
    let row = sqlx::query!(
        "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
        username
    )
    .fetch_optional(db)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    if row.is_active == 0 {
        return Ok(None);
    }

    let parsed = PasswordHash::new(&row.password_hash)
        .map_err(|e| anyhow::anyhow!("Password hash error: {}", e))?;
    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_err()
    {
        return Ok(None);
    }

    Ok(Some(User {
        id: row.id.expect("user id is never null"),
        username: row.username,
        role: row.role,
        is_active: row.is_active != 0,
        default_ttl: None,
    }))
}

pub async fn create_user(
    db: &SqlitePool,
    username: &str,
    password: &str,
    role: &str,
) -> anyhow::Result<User> {
    let salt = SaltString::generate(&mut OsRng);
    let pw_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Hash error: {}", e))?
        .to_string();

    let row = sqlx::query!(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?) RETURNING id",
        username,
        pw_hash,
        role
    )
    .fetch_one(db)
    .await?;

    Ok(User {
        id: row.id,
        username: username.to_string(),
        role: role.to_string(),
        is_active: true,
        default_ttl: None,
    })
}

pub async fn update_user(
    db: &SqlitePool,
    user_id: i64,
    password: Option<&str>,
    role: Option<&str>,
    is_active: Option<bool>,
) -> anyhow::Result<()> {
    if let Some(pw) = password {
        let salt = SaltString::generate(&mut OsRng);
        let pw_hash = Argon2::default()
            .hash_password(pw.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Hash error: {}", e))?
            .to_string();
        sqlx::query!(
            "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
            pw_hash,
            user_id
        )
        .execute(db)
        .await?;
    }
    if let Some(r) = role {
        sqlx::query!(
            "UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
            r,
            user_id
        )
        .execute(db)
        .await?;
    }
    if let Some(active) = is_active {
        let v = if active { 1i64 } else { 0i64 };
        sqlx::query!(
            "UPDATE users SET is_active = ?, updated_at = datetime('now') WHERE id = ?",
            v,
            user_id
        )
        .execute(db)
        .await?;
    }
    Ok(())
}

pub async fn update_user_preferences(
    db: &SqlitePool,
    user_id: i64,
    default_ttl: Option<i64>,
) -> anyhow::Result<()> {
    sqlx::query!(
        "UPDATE users SET default_ttl = ?, updated_at = datetime('now') WHERE id = ?",
        default_ttl,
        user_id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_user(db: &SqlitePool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query!("DELETE FROM users WHERE id = ?", user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_users(db: &SqlitePool) -> anyhow::Result<Vec<User>> {
    let rows = sqlx::query!(
        "SELECT id, username, role, is_active, default_ttl FROM users ORDER BY username"
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| User {
            id: r.id.expect("user id is never null"),
            username: r.username,
            role: r.role,
            is_active: r.is_active != 0,
            default_ttl: r.default_ttl,
        })
        .collect())
}

pub async fn ensure_admin_exists(db: &SqlitePool, default_password: &str) -> anyhow::Result<()> {
    let row = sqlx::query!("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        .fetch_optional(db)
        .await?;
    if row.is_none() {
        create_user(db, "admin", default_password, "admin").await?;
    }
    Ok(())
}
