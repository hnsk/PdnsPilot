use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub default_ttl: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UserCreate {
    pub username: String,
    pub password: String,
    #[serde(default = "default_operator")]
    pub role: String,
}

fn default_operator() -> String {
    "operator".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UserUpdate {
    pub password: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UserPreferences {
    pub default_ttl: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordChange {
    pub current_password: String,
    pub new_password: String,
}
