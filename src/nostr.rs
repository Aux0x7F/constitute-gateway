use anyhow::{anyhow, Result};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrUnsignedEvent {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u32>>,
    #[serde(rename = "#t", skip_serializing_if = "Option::is_none")]
    pub t: Option<Vec<String>>,
    #[serde(rename = "#z", skip_serializing_if = "Option::is_none")]
    pub z: Option<Vec<String>>,
}

pub fn generate_keypair() -> (String, String) {
    let secp = Secp256k1::new();
    let (sk, _pk) = secp.generate_keypair(&mut rand::thread_rng());
    let sk_hex = bytes_to_hex(&sk.secret_bytes());
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let pk_hex = xonly_pk_hex(&keypair);
    (pk_hex, sk_hex)
}

pub fn pubkey_from_sk_hex(sk_hex: &str) -> Result<String> {
    let sk_bytes = hex_to_bytes(sk_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid nostr sk"))?;
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &sk);
    Ok(xonly_pk_hex(&keypair))
}

pub fn sign_event(unsigned: &NostrUnsignedEvent, sk_hex: &str) -> Result<NostrEvent> {
    let id = event_id_hex(unsigned)?;
    let hash = hex_to_bytes(&id)?;
    let secp = Secp256k1::new();
    let sk_bytes = hex_to_bytes(sk_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| anyhow!("invalid nostr sk"))?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let sig = secp.sign_schnorr(&hash, &keypair);
    let sig_hex = bytes_to_hex(sig.as_ref());

    Ok(NostrEvent {
        id,
        pubkey: unsigned.pubkey.clone(),
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags.clone(),
        content: unsigned.content.clone(),
        sig: sig_hex,
    })
}

pub fn build_unsigned_event(
    pubkey: &str,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    created_at: u64,
) -> NostrUnsignedEvent {
    NostrUnsignedEvent {
        pubkey: pubkey.to_string(),
        created_at,
        kind,
        tags,
        content,
    }
}

pub fn frame_event(ev: &NostrEvent) -> String {
    serde_json::to_string(&json!(["EVENT", ev])).unwrap_or_else(|_| "[]".to_string())
}

pub fn frame_req(sub_id: &str, filters: Vec<NostrFilter>) -> String {
    serde_json::to_string(&json!(["REQ", sub_id, filters])).unwrap_or_else(|_| "[]".to_string())
}

pub fn verify_event(ev: &NostrEvent) -> Result<bool> {
    let unsigned = NostrUnsignedEvent {
        pubkey: ev.pubkey.clone(),
        created_at: ev.created_at,
        kind: ev.kind,
        tags: ev.tags.clone(),
        content: ev.content.clone(),
    };
    let expected_id = event_id_hex(&unsigned)?;
    if expected_id != ev.id {
        return Ok(false);
    }
    let hash = hex_to_bytes(&ev.id)?;
    if hash.len() != 32 {
        return Err(anyhow!("invalid event id"));
    }
    let sig_bytes = hex_to_bytes(&ev.sig)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| anyhow!("invalid signature"))?;
    let pk_bytes = hex_to_bytes(&ev.pubkey)?;
    let pk = XOnlyPublicKey::from_slice(&pk_bytes).map_err(|_| anyhow!("invalid pubkey"))?;
    let secp = Secp256k1::new();
    Ok(secp.verify_schnorr(&sig, &hash, &pk).is_ok())
}
pub fn event_id_hex(unsigned: &NostrUnsignedEvent) -> Result<String> {
    let content = json!([
        0,
        unsigned.pubkey,
        unsigned.created_at,
        unsigned.kind,
        unsigned.tags,
        unsigned.content,
    ]);
    let raw = serde_json::to_string(&content).map_err(|_| anyhow!("event serialize failed"))?;
    let digest = Sha256::digest(raw.as_bytes());
    Ok(bytes_to_hex(digest.as_slice()))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let h = hex.trim();
    if h.len() % 2 != 0 {
        return Err(anyhow!("invalid hex"));
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for i in (0..h.len()).step_by(2) {
        let b = u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| anyhow!("invalid hex"))?;
        out.push(b);
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn xonly_pk_hex(keypair: &Keypair) -> String {
    let (pk, _) = XOnlyPublicKey::from_keypair(keypair);
    bytes_to_hex(&pk.serialize())
}
