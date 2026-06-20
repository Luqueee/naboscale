use crate::error::Result;
use naboscale_crypto::{Identity, Keypair};
use std::path::{Path, PathBuf};

pub const IDENTITY_FILE: &str = "identity.key";
pub const WG_KEY_FILE: &str = "wg.key";
pub const CONFIG_FILE: &str = "config.toml";
pub const STATE_FILE: &str = "state.json";
pub const DAEMON_PID_FILE: &str = "naboscale.pid";
pub const DAEMON_LOG_FILE: &str = "naboscale.log";

pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or(crate::Error::NoConfigDir)?;
    Ok(base.join("naboscale"))
}

pub fn ensure_config_dir() -> Result<PathBuf> {
    let dir = config_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

pub fn load_identity(dir: &Path) -> Result<Identity> {
    let path = dir.join(IDENTITY_FILE);
    let bytes = std::fs::read(&path)
        .map_err(|_| crate::Error::NotInitialized(dir.display().to_string()))?;
    if bytes.len() != 32 {
        return Err(crate::Error::BadConfig(
            "identity.key has wrong length".into(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(Identity::from_bytes(key))
}

pub fn save_identity(dir: &Path, identity: &Identity) -> Result<()> {
    let path = dir.join(IDENTITY_FILE);
    std::fs::write(path, identity.private_bytes())?;
    Ok(())
}

pub fn load_wg_key(dir: &Path) -> Result<Keypair> {
    let path = dir.join(WG_KEY_FILE);
    let bytes = std::fs::read(&path)
        .map_err(|_| crate::Error::NotInitialized(dir.display().to_string()))?;
    if bytes.len() != 32 {
        return Err(crate::Error::BadConfig("wg.key has wrong length".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(Keypair::from_bytes(key))
}

pub fn save_wg_key(dir: &Path, keypair: &Keypair) -> Result<()> {
    let path = dir.join(WG_KEY_FILE);
    std::fs::write(path, keypair.secret_bytes())?;
    Ok(())
}

pub fn identity_exists(dir: &Path) -> bool {
    dir.join(IDENTITY_FILE).exists() && dir.join(WG_KEY_FILE).exists()
}
