//! Encrypted key and sensitive state storage.
//!
//! Uses OS keyring when available and supports fallback key material under explicit
//! runtime constraints.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::nostr;

const KEYRING_SERVICE: &str = "constitute-gateway";
const KEYRING_USER: &str = "master-key";
const KEY_FILE_NAME: &str = "keystore.key";
const STORE_FILE_NAME: &str = "keystore.json";
const KEY_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZoneEntry {
    pub key: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct SecureState {
    pub nostr_pubkey: String,
    pub nostr_sk_hex: String,
    pub identity_id: String,
    pub device_label: String,
    pub zones: Vec<ZoneEntry>,
}

#[derive(Debug, Clone, Copy)]
pub enum KeySourceKind {
    Keyring,
    Passphrase,
    KeyFile,
}

impl std::fmt::Display for KeySourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeySourceKind::Keyring => "keyring",
            KeySourceKind::Passphrase => "passphrase",
            KeySourceKind::KeyFile => "keyfile",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StorePayload {
    nostr_pubkey: String,
    nostr_sk_hex: String,
    identity_id: String,
    device_label: String,
    zones: Vec<ZoneEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedStore {
    version: u8,
    kdf: String,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
}

pub fn load_or_init(data_dir: &str, seed: SecureSeed) -> Result<(SecureState, KeySourceKind)> {
    let dir = PathBuf::from(data_dir);
    std::fs::create_dir_all(&dir)?;
    let store_path = dir.join(STORE_FILE_NAME);

    let (key_source, key_kind) = select_key_source(&dir)?;

    if store_path.exists() {
        let raw = std::fs::read_to_string(&store_path)?;
        let enc: EncryptedStore = serde_json::from_str(&raw)?;
        let key = key_source.derive_key(&enc)?;
        let payload = decrypt_payload(&enc, &key)?;
        return Ok((
            SecureState {
                nostr_pubkey: payload.nostr_pubkey,
                nostr_sk_hex: payload.nostr_sk_hex,
                identity_id: payload.identity_id,
                device_label: payload.device_label,
                zones: payload.zones,
            },
            key_kind,
        ));
    }

    let (pk, sk_hex) = if seed.nostr_sk_hex.trim().is_empty() {
        nostr::generate_keypair()
    } else {
        let pk = if seed.nostr_pubkey.trim().is_empty() {
            nostr::pubkey_from_sk_hex(&seed.nostr_sk_hex)?
        } else {
            seed.nostr_pubkey.clone()
        };
        (pk, seed.nostr_sk_hex.clone())
    };

    let payload = StorePayload {
        nostr_pubkey: pk.clone(),
        nostr_sk_hex: sk_hex.clone(),
        identity_id: seed.identity_id.clone(),
        device_label: seed.device_label.clone(),
        zones: seed.zones.clone(),
    };

    let enc = encrypt_payload(&payload, &key_source)?;
    let raw = serde_json::to_string_pretty(&enc)?;
    std::fs::write(&store_path, raw)?;

    Ok((
        SecureState {
            nostr_pubkey: pk,
            nostr_sk_hex: sk_hex,
            identity_id: seed.identity_id,
            device_label: seed.device_label,
            zones: seed.zones,
        },
        key_kind,
    ))
}

#[derive(Debug, Clone, Default)]
pub struct SecureSeed {
    pub nostr_pubkey: String,
    pub nostr_sk_hex: String,
    pub identity_id: String,
    pub device_label: String,
    pub zones: Vec<ZoneEntry>,
}

fn select_key_source(dir: &Path) -> Result<(KeySource, KeySourceKind)> {
    if std::env::var("CONSTITUTE_GATEWAY_NO_KEYRING")
        .ok()
        .as_deref()
        == Some("1")
    {
        return passphrase_or_file(dir);
    }

    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        if let Ok(secret) = entry.get_password() {
            let bytes = STANDARD_NO_PAD
                .decode(secret.trim())
                .map_err(|_| anyhow!("invalid keyring secret"))?;
            if bytes.len() == KEY_BYTES {
                return Ok((KeySource::RawKey(bytes), KeySourceKind::Keyring));
            }
        }
        let mut key = vec![0u8; KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut key);
        let b64 = STANDARD_NO_PAD.encode(&key);
        if entry.set_password(&b64).is_ok() {
            return Ok((KeySource::RawKey(key), KeySourceKind::Keyring));
        }
    }

    passphrase_or_file(dir)
}

fn passphrase_or_file(dir: &Path) -> Result<(KeySource, KeySourceKind)> {
    if let Ok(pass) = std::env::var("CONSTITUTE_GATEWAY_PASSPHRASE") {
        if !pass.trim().is_empty() {
            return Ok((KeySource::Passphrase(pass), KeySourceKind::Passphrase));
        }
    }

    let key_path = dir.join(KEY_FILE_NAME);
    if key_path.exists() {
        let raw = std::fs::read_to_string(&key_path)?;
        let bytes = STANDARD_NO_PAD
            .decode(raw.trim())
            .map_err(|_| anyhow!("invalid key file"))?;
        if bytes.len() != KEY_BYTES {
            return Err(anyhow!("invalid key file length"));
        }
        return Ok((KeySource::RawKey(bytes), KeySourceKind::KeyFile));
    }

    let mut key = vec![0u8; KEY_BYTES];
    rand::thread_rng().fill_bytes(&mut key);
    let b64 = STANDARD_NO_PAD.encode(&key);
    std::fs::write(&key_path, b64)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok((KeySource::RawKey(key), KeySourceKind::KeyFile))
}

enum KeySource {
    RawKey(Vec<u8>),
    Passphrase(String),
}

impl KeySource {
    fn derive_key(&self, enc: &EncryptedStore) -> Result<Vec<u8>> {
        match self {
            KeySource::RawKey(k) => Ok(k.clone()),
            KeySource::Passphrase(pass) => {
                if enc.kdf != "argon2id" {
                    return Err(anyhow!("passphrase provided but keystore not argon2id"));
                }
                let salt = STANDARD_NO_PAD
                    .decode(enc.salt_b64.trim())
                    .map_err(|_| anyhow!("invalid salt"))?;
                derive_key_from_pass(pass, &salt, enc.mem_kib, enc.iterations, enc.parallelism)
            }
        }
    }
}

fn derive_key_from_pass(
    pass: &str,
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; KEY_BYTES];
    let params = argon2::Params::new(mem_kib, iterations, parallelism, Some(KEY_BYTES))
        .map_err(|_| anyhow!("invalid argon2 params"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| anyhow!("argon2 failed"))?;
    Ok(out)
}

fn encrypt_payload(payload: &StorePayload, key_source: &KeySource) -> Result<EncryptedStore> {
    let plaintext = serde_json::to_vec(payload)?;

    let (key, kdf, salt, mem_kib, iterations, parallelism) = match key_source {
        KeySource::RawKey(k) => (k.clone(), "raw".to_string(), vec![], 0, 0, 0),
        KeySource::Passphrase(pass) => {
            let mut salt = vec![0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let mem_kib = 64 * 1024;
            let iterations = 3;
            let parallelism = 1;
            let key = derive_key_from_pass(pass, &salt, mem_kib, iterations, parallelism)?;
            (
                key,
                "argon2id".to_string(),
                salt,
                mem_kib,
                iterations,
                parallelism,
            )
        }
    };

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow!("encrypt failed"))?;

    Ok(EncryptedStore {
        version: 1,
        kdf,
        salt_b64: STANDARD_NO_PAD.encode(&salt),
        nonce_b64: STANDARD_NO_PAD.encode(&nonce),
        ciphertext_b64: STANDARD_NO_PAD.encode(&ciphertext),
        mem_kib,
        iterations,
        parallelism,
    })
}

fn decrypt_payload(enc: &EncryptedStore, key: &[u8]) -> Result<StorePayload> {
    let nonce = STANDARD_NO_PAD
        .decode(enc.nonce_b64.trim())
        .map_err(|_| anyhow!("invalid nonce"))?;
    let ciphertext = STANDARD_NO_PAD
        .decode(enc.ciphertext_b64.trim())
        .map_err(|_| anyhow!("invalid ciphertext"))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("decrypt failed"))?;

    let payload: StorePayload = serde_json::from_slice(&plaintext)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::{
        decrypt_payload, derive_key_from_pass, encrypt_payload, KeySource, StorePayload, ZoneEntry,
    };

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let payload = StorePayload {
            nostr_pubkey: "pk".to_string(),
            nostr_sk_hex: "sk".to_string(),
            identity_id: "id".to_string(),
            device_label: "label".to_string(),
            zones: vec![ZoneEntry {
                key: "zone".to_string(),
                name: "Zone".to_string(),
            }],
        };
        let pass = "test-pass".to_string();
        let enc = encrypt_payload(&payload, &KeySource::Passphrase(pass.clone())).expect("encrypt");
        let salt = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(enc.salt_b64.trim())
            .expect("salt");
        let key = derive_key_from_pass(&pass, &salt, enc.mem_kib, enc.iterations, enc.parallelism)
            .expect("kdf");
        let out = decrypt_payload(&enc, &key).expect("decrypt");
        assert_eq!(out.nostr_pubkey, "pk");
        assert_eq!(out.nostr_sk_hex, "sk");
        assert_eq!(out.identity_id, "id");
        assert_eq!(out.device_label, "label");
        assert_eq!(out.zones.len(), 1);
    }
}
