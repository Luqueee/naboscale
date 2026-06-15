//! HTTP client for the coord server: register, heartbeat, fetch peers.

use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use naboscale_crypto::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CoordClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: String,
    pub ip: String,
    pub auth_token: String,
    pub derp_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub node_id: String,
    pub wg_pubkey: String,
    pub ip: String,
    pub last_endpoint: Option<String>,
    pub last_seen: Option<i64>,
}

impl CoordClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn health(&self) -> Result<String> {
        let resp = self.http.get(format!("{}/v1/health", self.base_url)).send().await?;
        let text = resp.text().await?;
        Ok(text)
    }

    pub async fn register(
        &self,
        identity: &Identity,
        wg_pubkey: &[u8; 32],
    ) -> Result<RegisterResponse> {
        let timestamp = now_unix();
        let mut msg = Vec::with_capacity(8 + 8 + 32 + 32);
        msg.extend_from_slice(b"register");
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(&identity.public());
        msg.extend_from_slice(wg_pubkey);
        let sig = identity.sign(&msg);

        let body = json!({
            "identity_pubkey": B64.encode(identity.public()),
            "wg_pubkey": B64.encode(wg_pubkey),
            "timestamp": timestamp,
            "signature": B64.encode(sig),
        });

        let resp = self
            .http
            .post(format!("{}/v1/register", self.base_url))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(json!({}));
            return Err(Error::Server(format!("register failed: {status} {body}")));
        }

        let parsed: RegisterResponse = resp.json().await?;
        Ok(parsed)
    }

    pub async fn peers(&self, auth_token: &str) -> Result<Vec<PeerEntry>> {
        let resp = self
            .http
            .get(format!("{}/v1/peers", self.base_url))
            .bearer_auth(auth_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Server(format!("peers failed: {}", resp.status())));
        }
        let body: Value = resp.json().await?;
        let peers = body["peers"]
            .as_array()
            .ok_or_else(|| Error::Server("peers response missing 'peers' field".into()))?
            .clone();
        let parsed: Vec<PeerEntry> = serde_json::from_value(Value::Array(peers))?;
        Ok(parsed)
    }

    pub async fn heartbeat(
        &self,
        identity: &Identity,
        auth_token: &str,
        endpoint: &str,
    ) -> Result<()> {
        let timestamp = now_unix();
        let mut msg = Vec::with_capacity(9 + 8 + endpoint.len());
        msg.extend_from_slice(b"heartbeat");
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(endpoint.as_bytes());
        let sig = identity.sign(&msg);

        let body = json!({
            "endpoint": endpoint,
            "timestamp": timestamp,
            "signature": B64.encode(sig),
        });

        let resp = self
            .http
            .post(format!("{}/v1/heartbeat", self.base_url))
            .bearer_auth(auth_token)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(Error::Server(format!("heartbeat failed: {}", resp.status())));
        }
        Ok(())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs() as i64
}
