use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub content: String,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RRSet {
    pub name: String,
    #[serde(rename = "type")]
    pub rrtype: String,
    pub ttl: i64,
    pub records: Vec<Record>,
    #[serde(default = "default_replace")]
    pub changetype: String,
    pub comments: Option<Vec<Value>>,
}

fn default_replace() -> String {
    "REPLACE".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ZoneCreate {
    pub name: String,
    #[serde(default = "default_native")]
    pub kind: String,
    #[serde(default)]
    pub nameservers: Vec<String>,
    #[serde(default)]
    pub masters: Vec<String>,
    pub server_id: i64,
    pub template_id: Option<i64>,
    pub soa_mname: Option<String>,
    pub soa_rname: Option<String>,
    pub soa_refresh: Option<i64>,
    pub soa_retry: Option<i64>,
    pub soa_expire: Option<i64>,
    pub soa_ttl: Option<i64>,
}

fn default_native() -> String {
    "Native".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ZoneUpdate {
    pub kind: Option<String>,
    pub masters: Option<Vec<String>>,
    pub account: Option<String>,
    pub soa_edit: Option<String>,
    pub soa_edit_api: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CryptoKeyCreate {
    #[serde(default = "default_ksk")]
    pub keytype: String,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub bits: i64,
    #[serde(default = "default_true")]
    pub published: bool,
}

fn default_ksk() -> String {
    "ksk".to_string()
}

fn default_true() -> bool {
    true
}

fn default_algorithm() -> String {
    "ECDSAP256SHA256".to_string()
}
