use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
#[error("PowerDNS API error {status}: {detail}")]
pub struct PdnsError {
    pub status: u16,
    pub detail: String,
}

pub struct PdnsClient {
    client: Client,
    base_url: String,
}

impl PdnsClient {
    pub fn new(api_url: &str, api_key: &str, server_id: &str) -> anyhow::Result<Self> {
        let base_url = format!(
            "{}/api/v1/servers/{}",
            api_url.trim_end_matches('/'),
            server_id
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-API-Key",
            reqwest::header::HeaderValue::from_str(api_key)
                .map_err(|e| anyhow::anyhow!("Invalid API key: {}", e))?,
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(PdnsClient { client, base_url })
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        params: Option<&[(&str, &str)]>,
    ) -> Result<reqwest::Response, PdnsError> {
        let url = if path.is_empty() || path == "/" {
            self.base_url.clone()
        } else if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        };

        let mut req = self.client.request(method, &url);
        if let Some(p) = params {
            req = req.query(p);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send().await.map_err(|e| PdnsError {
            status: 502,
            detail: e.to_string(),
        })?;

        if resp.status().is_client_error() || resp.status().is_server_error() {
            let status = resp.status().as_u16();
            let detail = resp
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(PdnsError { status, detail });
        }

        Ok(resp)
    }

    // ─── Server info ─────────────────────────────────────────────────────────

    pub async fn get_server_info(&self) -> Result<Value, PdnsError> {
        let resp = self
            .request(reqwest::Method::GET, "", None, None)
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn get_statistics(&self) -> Result<Value, PdnsError> {
        let resp = self
            .request(reqwest::Method::GET, "/statistics", None, None)
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    // ─── Zones ───────────────────────────────────────────────────────────────

    pub async fn list_zones(&self, dnssec: Option<bool>) -> Result<Value, PdnsError> {
        let resp = if let Some(d) = dnssec {
            let s = if d { "true" } else { "false" };
            let p = vec![("dnssec", s)];
            self.request(reqwest::Method::GET, "/zones", None, Some(&p))
                .await?
        } else {
            self.request(reqwest::Method::GET, "/zones", None, None)
                .await?
        };
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn get_zone(&self, zone_id: &str, rrsets: bool) -> Result<Value, PdnsError> {
        let path = format!("/zones/{zone_id}");
        let resp = if rrsets {
            self.request(reqwest::Method::GET, &path, None, None).await?
        } else {
            let p = vec![("rrsets", "false")];
            self.request(reqwest::Method::GET, &path, None, Some(&p))
                .await?
        };
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn create_zone(&self, data: Value) -> Result<Value, PdnsError> {
        let resp = self
            .request(reqwest::Method::POST, "/zones", Some(data), None)
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn delete_zone(&self, zone_id: &str) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::DELETE,
            &format!("/zones/{zone_id}"),
            None,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn update_zone(&self, zone_id: &str, data: Value) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::PUT,
            &format!("/zones/{zone_id}"),
            Some(data),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn patch_rrsets(&self, zone_id: &str, rrsets: Value) -> Result<(), PdnsError> {
        let body = serde_json::json!({"rrsets": rrsets});
        self.request(
            reqwest::Method::PATCH,
            &format!("/zones/{zone_id}"),
            Some(body),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn export_zone(&self, zone_id: &str) -> Result<String, PdnsError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/export"),
                None,
                None,
            )
            .await?;
        let text = resp.text().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })?;
        // Try JSON {"zone": "..."} first
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if let Some(z) = v.get("zone").and_then(|z| z.as_str()) {
                return Ok(z.to_string());
            }
        }
        Ok(text)
    }

    pub async fn rectify_zone(&self, zone_id: &str) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::PUT,
            &format!("/zones/{zone_id}/rectify"),
            None,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn notify_zone(&self, zone_id: &str) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::PUT,
            &format!("/zones/{zone_id}/notify"),
            None,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn axfr_retrieve(&self, zone_id: &str) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::PUT,
            &format!("/zones/{zone_id}/axfr-retrieve"),
            None,
            None,
        )
        .await?;
        Ok(())
    }

    // ─── DNSSEC / Cryptokeys ─────────────────────────────────────────────────

    pub async fn list_cryptokeys(&self, zone_id: &str) -> Result<Value, PdnsError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/cryptokeys"),
                None,
                None,
            )
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn get_cryptokey(&self, zone_id: &str, key_id: i64) -> Result<Value, PdnsError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/cryptokeys/{key_id}"),
                None,
                None,
            )
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn create_cryptokey(&self, zone_id: &str, data: Value) -> Result<Value, PdnsError> {
        let resp = self
            .request(
                reqwest::Method::POST,
                &format!("/zones/{zone_id}/cryptokeys"),
                Some(data),
                None,
            )
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn toggle_cryptokey(
        &self,
        zone_id: &str,
        key_id: i64,
        active: bool,
    ) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::PUT,
            &format!("/zones/{zone_id}/cryptokeys/{key_id}"),
            Some(serde_json::json!({"active": active})),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn delete_cryptokey(&self, zone_id: &str, key_id: i64) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::DELETE,
            &format!("/zones/{zone_id}/cryptokeys/{key_id}"),
            None,
            None,
        )
        .await?;
        Ok(())
    }

    // ─── Metadata ────────────────────────────────────────────────────────────

    pub async fn list_metadata(&self, zone_id: &str) -> Result<Value, PdnsError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/zones/{zone_id}/metadata"),
                None,
                None,
            )
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

    pub async fn set_metadata(
        &self,
        zone_id: &str,
        kind: &str,
        value: Vec<String>,
    ) -> Result<(), PdnsError> {
        self.request(
            reqwest::Method::PUT,
            &format!("/zones/{zone_id}/metadata/{kind}"),
            Some(serde_json::json!({"metadata": value})),
            None,
        )
        .await?;
        Ok(())
    }

    // ─── Search ──────────────────────────────────────────────────────────────

    pub async fn search(
        &self,
        q: &str,
        max_results: i64,
        object_type: &str,
    ) -> Result<Value, PdnsError> {
        let max_str = max_results.to_string();
        let p = vec![("q", q), ("max", &max_str), ("object_type", object_type)];
        let resp = self
            .request(reqwest::Method::GET, "/search-data", None, Some(&p))
            .await?;
        resp.json().await.map_err(|e| PdnsError {
            status: 500,
            detail: e.to_string(),
        })
    }

}

// ─── Registry ────────────────────────────────────────────────────────────────

pub struct PdnsRegistry {
    pub clients: HashMap<i64, Arc<PdnsClient>>,
}

impl PdnsRegistry {
    pub fn new() -> Self {
        PdnsRegistry {
            clients: HashMap::new(),
        }
    }

    pub fn start_server(
        &mut self,
        server_db_id: i64,
        api_url: &str,
        api_key: &str,
        server_id: &str,
    ) -> anyhow::Result<()> {
        let client = PdnsClient::new(api_url, api_key, server_id)?;
        self.clients.insert(server_db_id, Arc::new(client));
        Ok(())
    }

    pub fn stop_server(&mut self, server_db_id: i64) {
        self.clients.remove(&server_db_id);
    }

    pub fn reconfigure_server(
        &mut self,
        server_db_id: i64,
        api_url: &str,
        api_key: &str,
        server_id: &str,
    ) -> anyhow::Result<()> {
        self.start_server(server_db_id, api_url, api_key, server_id)
    }

    pub fn get(&self, server_db_id: i64) -> Option<Arc<PdnsClient>> {
        self.clients.get(&server_db_id).cloned()
    }

    pub fn all(&self) -> HashMap<i64, Arc<PdnsClient>> {
        self.clients.clone()
    }
}
