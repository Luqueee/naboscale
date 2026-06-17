use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerInfo {
    pub node_id: String,
    pub wg_pubkey_b64: String,
    pub ip: String,
    pub last_endpoint: Option<String>,
    #[serde(default)]
    pub via_relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub node_id: String,
    pub ip: String,
    pub auth_token: String,
    #[serde(default)]
    pub last_endpoint: Option<String>,
    #[serde(default)]
    pub last_handshake_at: Option<i64>,
    #[serde(default)]
    pub known_peers: Vec<PeerInfo>,
}

impl State {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(super::identity::STATE_FILE);
        let text = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(super::identity::STATE_FILE);
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn exists(dir: &Path) -> bool {
        dir.join(super::identity::STATE_FILE).exists()
    }
}
