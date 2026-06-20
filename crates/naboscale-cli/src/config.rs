use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(super::identity::CONFIG_FILE);
        let text = std::fs::read_to_string(&path).map_err(|_| crate::Error::ConfigMissing)?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(super::identity::CONFIG_FILE);
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn default_with_server(url: &str) -> Self {
        Self {
            server: ServerConfig {
                url: url.to_string(),
            },
        }
    }
}
