//! Encrypted on-disk key storage.
//!
//! File layout (binary, all big-endian):
//! ```text
//!   magic    [4]  = b"NAB1"
//!   version  [1]  = 0x02
//!   reserved [3]  = 0x00
//!   salt     [16] Argon2id salt (random per file)
//!   nonce    [24] XChaCha20-Poly1305 nonce (random per file)
//!   ciphertext+tag [N + 16]
//! ```
//!
//! Plaintext `N` bytes = the secret (32 B for identity / WG keys).
//!
//! KDF: Argon2id (m=64 MiB, t=3, p=1, 32 B output). The output is used
//! directly as the XChaCha20-Poly1305 key. AEAD AAD = empty.
//!
//! Legacy detection: a file whose first 4 bytes are not `NAB1` is treated as
//! a v1 raw 32-byte key. The first read of a v1 file logs a loud warning and
//! suggests re-initializing with a passphrase. Writes always emit v2.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::path::{Path, PathBuf};

pub const MAGIC: &[u8; 4] = b"NAB1";
pub const VERSION: u8 = 0x02;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = 4 + 1 + 3 + SALT_LEN + NONCE_LEN; // 48
pub const KEY_LEN: usize = 32;
pub const FILE_LEN: usize = HEADER_LEN + KEY_LEN + 16; // 96 (48 ciphertext + 16 tag)

const PASSPHRASE_ENV: &str = "NABOSCALE_PASSPHRASE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Identity,
    Wg,
}

impl KeyKind {
    fn file_name(self) -> &'static str {
        match self {
            KeyKind::Identity => "identity.key",
            KeyKind::Wg => "wg.key",
        }
    }
}

#[derive(Debug, Clone)]
pub enum PassphraseSource {
    /// Read once from an explicit byte slice (CLI flag, env, file).
    Bytes(Vec<u8>),
    /// Read from the `NABOSCALE_PASSPHRASE` environment variable.
    Env,
    /// Refuse if no passphrase is available (for tests / non-interactive).
    Required,
}

impl PassphraseSource {
    /// Resolve a passphrase from the configured sources. Order:
    ///
    /// 1. `--passphrase-file` (already loaded by caller into Bytes).
    /// 2. `NABOSCALE_PASSPHRASE` env var.
    ///
    /// Returns `None` when source is `Required` and no env var is set.
    pub fn resolve(&self) -> Result<Option<Vec<u8>>> {
        match self {
            PassphraseSource::Bytes(b) => Ok(Some(b.clone())),
            PassphraseSource::Env => match std::env::var(PASSPHRASE_ENV) {
                Ok(s) => Ok(Some(s.into_bytes())),
                Err(_) => Ok(None),
            },
            PassphraseSource::Required => match std::env::var(PASSPHRASE_ENV) {
                Ok(s) => Ok(Some(s.into_bytes())),
                Err(_) => Err(Error::BadConfig(format!(
                    "passphrase required: set {PASSPHRASE_ENV} env var or use --passphrase-file"
                ))),
            },
        }
    }
}

pub fn read_passphrase_file(path: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::BadConfig(format!("reading passphrase file {}: {e}", path.display()))
    })?;
    Ok(text
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .as_bytes()
        .to_vec())
}

/// Detect whether the file at `path` looks like a v2 envelope (starts with `NAB1`).
pub fn is_v2(path: &Path) -> Result<bool> {
    let mut head = [0u8; 4];
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() < 4 {
                return Ok(false);
            }
            head.copy_from_slice(&bytes[..4]);
            Ok(&head == MAGIC)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    // Argon2id 64 MiB / t=3 / p=1 → 32-byte key. This is slow on purpose
    // (~150-300 ms) — only paid on decrypt, not on each packet.
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| Error::BadConfig(format!("argon2 params invalid: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| Error::BadConfig(format!("argon2 KDF failed: {e}")))?;
    // HKDF-Expand with a fixed info tag, so future KDF changes don't break
    // compatibility silently. (Currently a no-op stretch, but keeps the door
    // open for context-bound keys without bumping file version.)
    let hk = Hkdf::<Sha256>::new(Some(salt), &out);
    let mut okm = [0u8; 32];
    hk.expand_multi_info(&[b"naboscale/v2/aead"], &mut okm)
        .map_err(|e| Error::BadConfig(format!("hkdf expand failed: {e}")))?;
    Ok(okm)
}

fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|e| Error::BadConfig(format!("encryption failed: {e}")))?;
    let mut out = Vec::with_capacity(FILE_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), FILE_LEN);
    Ok(out)
}

fn decrypt(envelope: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() != FILE_LEN {
        return Err(Error::BadConfig(format!(
            "envelope length {} != expected {FILE_LEN}",
            envelope.len()
        )));
    }
    if &envelope[..4] != MAGIC {
        return Err(Error::BadConfig("bad magic".into()));
    }
    if envelope[4] != VERSION {
        return Err(Error::BadConfig(format!(
            "unsupported keystore version {}",
            envelope[4]
        )));
    }
    let salt = &envelope[8..8 + SALT_LEN];
    let nonce = &envelope[8 + SALT_LEN..HEADER_LEN];
    let ct = &envelope[HEADER_LEN..];
    let key = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
        .map_err(|_| {
            Error::BadConfig("decryption failed (wrong passphrase or tampered file)".into())
        })
}

fn save_v2(dir: &Path, kind: KeyKind, plaintext: &[u8], passphrase: &[u8]) -> Result<()> {
    let bytes = encrypt(plaintext, passphrase)?;
    let path = dir.join(kind.file_name());
    write_atomic(&path, &bytes)
}

fn read_v2(dir: &Path, kind: KeyKind, passphrase: &[u8]) -> Result<Vec<u8>> {
    let path = dir.join(kind.file_name());
    let bytes = std::fs::read(&path)?;
    decrypt(&bytes, passphrase)
}

fn read_v1(dir: &Path, kind: KeyKind) -> Result<Vec<u8>> {
    let path = dir.join(kind.file_name());
    let bytes = std::fs::read(&path)?;
    if bytes.len() != KEY_LEN {
        return Err(Error::BadConfig(format!(
            "{} has wrong length {} (expected {KEY_LEN})",
            kind.file_name(),
            bytes.len()
        )));
    }
    tracing::warn!(
        file = %path.display(),
        "loaded UNENCRYPTED v1 key file; re-run `naboscale init --force` with a passphrase (set NABOSCALE_PASSPHRASE or use --passphrase-file) to migrate"
    );
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::BadConfig(format!("path {} has no parent", path.display())))?;
    std::fs::create_dir_all(dir)?;
    let tmp: PathBuf = {
        let mut p = path.to_path_buf();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => format!(".{n}.tmp"),
            None => return Err(Error::BadConfig("bad path".into())),
        };
        p.set_file_name(name);
        p
    };
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Write a v2 (encrypted) key to disk.
pub fn save_key(dir: &Path, kind: KeyKind, plaintext: &[u8], passphrase: &[u8]) -> Result<()> {
    if plaintext.len() != KEY_LEN {
        return Err(Error::BadConfig(format!(
            "key has wrong length {} (expected {KEY_LEN})",
            plaintext.len()
        )));
    }
    save_v2(dir, kind, plaintext, passphrase)
}

/// Read a key from disk, transparently handling v1 (unencrypted) and v2.
///
/// - If the file is v2, `passphrase` is required and used to decrypt.
/// - If the file is v1 (legacy, raw 32 bytes), the passphrase is ignored and a
///   warning is emitted. The caller is expected to overwrite the v1 file with
///   `save_key` once a passphrase is available (typically next `init --force`).
pub fn load_key(dir: &Path, kind: KeyKind, passphrase: Option<&[u8]>) -> Result<Vec<u8>> {
    let path = dir.join(kind.file_name());
    if !path.exists() {
        return Err(Error::NotInitialized(dir.display().to_string()));
    }
    if is_v2(&path)? {
        let pp = passphrase.ok_or_else(|| {
            Error::BadConfig(format!(
                "{} is encrypted; set NABOSCALE_PASSPHRASE or pass --passphrase-file",
                kind.file_name()
            ))
        })?;
        read_v2(dir, kind, pp)
    } else {
        read_v1(dir, kind)
    }
}

/// Both keys loaded and ready to use. Holds owned material so the caller can
/// move it across tasks / spawn it into the daemon loop.
#[derive(Clone)]
pub struct OpenedKeys {
    pub identity: naboscale_crypto::Identity,
    pub wg: naboscale_crypto::Keypair,
}

impl OpenedKeys {
    pub fn open(dir: &Path, passphrase: Option<&[u8]>) -> Result<Self> {
        let id_bytes = load_key(dir, KeyKind::Identity, passphrase)?;
        let wg_bytes = load_key(dir, KeyKind::Wg, passphrase)?;
        let mut id_arr = [0u8; KEY_LEN];
        id_arr.copy_from_slice(&id_bytes);
        let mut wg_arr = [0u8; KEY_LEN];
        wg_arr.copy_from_slice(&wg_bytes);
        Ok(Self {
            identity: naboscale_crypto::Identity::from_bytes(id_arr),
            wg: naboscale_crypto::Keypair::from_bytes(wg_arr),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "naboscale-keystore-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn roundtrip_encrypted() {
        let dir = tmp_dir("round");
        let pass = b"correct horse battery staple";
        let secret = [42u8; KEY_LEN];
        save_key(&dir, KeyKind::Identity, &secret, pass).unwrap();
        let got = load_key(&dir, KeyKind::Identity, Some(pass)).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tmp_dir("wrong");
        save_key(&dir, KeyKind::Wg, &[7u8; KEY_LEN], b"right").unwrap();
        let err = load_key(&dir, KeyKind::Wg, Some(b"wrong")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("decryption failed"), "got: {msg}");
    }

    #[test]
    fn missing_passphrase_on_v2_errors() {
        let dir = tmp_dir("nopass");
        save_key(&dir, KeyKind::Identity, &[1u8; KEY_LEN], b"x").unwrap();
        let err = load_key(&dir, KeyKind::Identity, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("encrypted"), "got: {msg}");
    }

    #[test]
    fn tamper_detection() {
        let dir = tmp_dir("tamper");
        let pass = b"p";
        save_key(&dir, KeyKind::Identity, &[9u8; KEY_LEN], pass).unwrap();
        let path = dir.join(KeyKind::Identity.file_name());
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();
        let err = load_key(&dir, KeyKind::Identity, Some(pass)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("decryption failed"), "got: {msg}");
    }

    #[test]
    fn legacy_v1_still_loads() {
        let dir = tmp_dir("v1");
        let secret = [3u8; KEY_LEN];
        std::fs::write(dir.join(KeyKind::Wg.file_name()), secret).unwrap();
        let got = load_key(&dir, KeyKind::Wg, None).unwrap();
        assert_eq!(got, secret);
    }

    #[test]
    fn opened_keys_loads_both() {
        let dir = tmp_dir("opened");
        let pass = b"hello";
        save_key(&dir, KeyKind::Identity, &[11u8; KEY_LEN], pass).unwrap();
        save_key(&dir, KeyKind::Wg, &[22u8; KEY_LEN], pass).unwrap();
        let ks = OpenedKeys::open(&dir, Some(pass)).unwrap();
        assert_eq!(ks.identity.private_bytes(), [11u8; KEY_LEN]);
        assert_eq!(ks.wg.secret_bytes(), [22u8; KEY_LEN]);
    }

    #[test]
    fn passphrase_source_env_and_required() {
        // Serial: these tests touch process-wide env, so they must not run
        // in parallel with anything else that touches the same var.
        std::env::set_var(PASSPHRASE_ENV, "from-env");
        let env_src = PassphraseSource::Env;
        assert_eq!(env_src.resolve().unwrap().unwrap(), b"from-env");
        std::env::remove_var(PASSPHRASE_ENV);
        assert!(env_src.resolve().unwrap().is_none());

        std::env::remove_var(PASSPHRASE_ENV);
        let req_src = PassphraseSource::Required;
        let err = req_src.resolve().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("passphrase required"), "got: {msg}");

        std::env::set_var(PASSPHRASE_ENV, "ok");
        assert_eq!(req_src.resolve().unwrap().unwrap(), b"ok");
        std::env::remove_var(PASSPHRASE_ENV);
    }
}
