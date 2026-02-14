//! In-memory validated store for swarm discovery records.
//!
//! Identity and device records are validated and indexed by zone to support
//! targeted lookup and zone-scoped replication.

use crate::nostr;
use serde_json::Value;
use std::collections::HashMap;

const RECORD_KIND: u32 = 30078;
const RECORD_TAG: &str = "swarm_discovery";
const MAX_SKEW_SEC: u64 = 10 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    Identity,
    Device,
    Dht,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::Identity => "identity",
            RecordType::Device => "device",
            RecordType::Dht => "dht",
        }
    }
}

#[derive(Clone, Debug)]
struct StoredRecord {
    event: nostr::NostrEvent,
    updated_at: u64,
    expires_at: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct SwarmStore {
    identities: HashMap<String, StoredRecord>,
    devices: HashMap<String, StoredRecord>,
    dht: HashMap<String, StoredRecord>,
}

impl SwarmStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_record(&mut self, ev: &nostr::NostrEvent) -> Option<RecordType> {
        let record_type = record_type(ev)?;
        let info = validate_record(ev, record_type)?;
        match record_type {
            RecordType::Identity => {
                if !should_replace(&self.identities, &info) {
                    return None;
                }
                self.identities.insert(
                    info.key.clone(),
                    StoredRecord {
                        event: ev.clone(),
                        updated_at: info.updated_at,
                        expires_at: info.expires_at,
                    },
                );
            }
            RecordType::Device => {
                if !should_replace(&self.devices, &info) {
                    return None;
                }
                self.devices.insert(
                    info.key.clone(),
                    StoredRecord {
                        event: ev.clone(),
                        updated_at: info.updated_at,
                        expires_at: info.expires_at,
                    },
                );
            }
            RecordType::Dht => {
                if !should_replace(&self.dht, &info) {
                    return None;
                }
                self.dht.insert(
                    info.key.clone(),
                    StoredRecord {
                        event: ev.clone(),
                        updated_at: info.updated_at,
                        expires_at: info.expires_at,
                    },
                );
            }
        }
        Some(record_type)
    }

    pub fn list_identity_events(&self) -> Vec<nostr::NostrEvent> {
        self.identities.values().map(|r| r.event.clone()).collect()
    }

    pub fn list_device_events(&self) -> Vec<nostr::NostrEvent> {
        self.devices.values().map(|r| r.event.clone()).collect()
    }

    pub fn get_identity_event(&self, id: &str) -> Option<nostr::NostrEvent> {
        self.identities.get(id).map(|r| r.event.clone())
    }

    pub fn get_device_event(&self, pk: &str) -> Option<nostr::NostrEvent> {
        self.devices.get(pk).map(|r| r.event.clone())
    }

    pub fn list_dht_events(&self) -> Vec<nostr::NostrEvent> {
        self.dht.values().map(|r| r.event.clone()).collect()
    }

    pub fn get_dht_event(&self, scope: &str, key: &str) -> Option<nostr::NostrEvent> {
        self.dht
            .get(&dht_record_key(scope, key))
            .map(|r| r.event.clone())
    }
}

#[derive(Clone, Debug)]
struct RecordInfo {
    key: String,
    updated_at: u64,
    expires_at: Option<u64>,
    event_id: String,
}

fn should_replace(map: &HashMap<String, StoredRecord>, info: &RecordInfo) -> bool {
    if let Some(existing) = map.get(&info.key) {
        if existing.event.id == info.event_id {
            return false;
        }
        if let Some(exp) = existing.expires_at {
            if now_ms() > exp {
                return true;
            }
        }
        return info.updated_at > existing.updated_at;
    }
    true
}

fn record_type(ev: &nostr::NostrEvent) -> Option<RecordType> {
    if ev.kind != RECORD_KIND {
        return None;
    }
    let tags = &ev.tags;
    let has_tag = tags
        .iter()
        .any(|t| t.get(0) == Some(&"t".to_string()) && t.get(1) == Some(&RECORD_TAG.to_string()));
    if !has_tag {
        return None;
    }
    for t in tags {
        if t.len() < 2 {
            continue;
        }
        if t[0] != "type" {
            continue;
        }
        return match t[1].as_str() {
            "identity" => Some(RecordType::Identity),
            "device" => Some(RecordType::Device),
            "dht" => Some(RecordType::Dht),
            _ => None,
        };
    }
    None
}

fn validate_record(ev: &nostr::NostrEvent, expected: RecordType) -> Option<RecordInfo> {
    if !clock_ok(ev.created_at) {
        return None;
    }
    if !nostr::verify_event(ev).ok()? {
        return None;
    }
    let payload: Value = serde_json::from_str(&ev.content).ok()?;
    if payload.is_null() {
        return None;
    }

    let expires_at = payload.get("expiresAt").and_then(|v| v.as_u64());
    if let Some(exp) = expires_at {
        if now_ms() > exp {
            return None;
        }
    }

    let updated_at = payload
        .get("updatedAt")
        .and_then(|v| v.as_u64())
        .unwrap_or(ev.created_at * 1000);

    match expected {
        RecordType::Identity => {
            let identity_id = payload
                .get("identityId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if identity_id.is_empty() {
                return None;
            }
            let device_pks = payload
                .get("devicePks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let has_device = device_pks
                .iter()
                .any(|v| v.as_str() == Some(ev.pubkey.as_str()));
            if !has_device {
                return None;
            }
            Some(RecordInfo {
                key: identity_id.to_string(),
                updated_at,
                expires_at,
                event_id: ev.id.clone(),
            })
        }
        RecordType::Device => {
            let device_pk = payload
                .get("devicePk")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if device_pk.is_empty() || device_pk != ev.pubkey {
                return None;
            }
            Some(RecordInfo {
                key: device_pk.to_string(),
                updated_at,
                expires_at,
                event_id: ev.id.clone(),
            })
        }
        RecordType::Dht => {
            let scope = payload
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let key = payload
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if scope.is_empty() || key.is_empty() {
                return None;
            }
            if payload.get("value").is_none() {
                return None;
            }
            let author_pk = payload
                .get("authorPk")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !author_pk.is_empty() && author_pk != ev.pubkey {
                return None;
            }
            Some(RecordInfo {
                key: dht_record_key(scope, key),
                updated_at,
                expires_at,
                event_id: ev.id.clone(),
            })
        }
    }
}

fn dht_record_key(scope: &str, key: &str) -> String {
    format!("{}:{}", scope.trim(), key.trim())
}

fn clock_ok(created_at: u64) -> bool {
    if created_at == 0 {
        return false;
    }
    let now = now_sec();
    created_at <= now + MAX_SKEW_SEC
}

fn now_sec() -> u64 {
    now_ms() / 1000
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{RecordType, SwarmStore, RECORD_KIND, RECORD_TAG};
    use crate::nostr;
    use serde_json::json;

    fn make_event(
        record_type: &str,
        content: serde_json::Value,
        pk: &str,
        sk: &str,
    ) -> nostr::NostrEvent {
        let tags = vec![
            vec!["t".to_string(), RECORD_TAG.to_string()],
            vec!["type".to_string(), record_type.to_string()],
        ];
        let unsigned =
            nostr::build_unsigned_event(pk, RECORD_KIND, tags, content.to_string(), now_sec());
        nostr::sign_event(&unsigned, sk).expect("sign")
    }

    fn now_sec() -> u64 {
        super::now_sec()
    }

    #[test]
    fn store_accepts_identity_record() {
        let (pk, sk) = nostr::generate_keypair();
        let content = json!({
            "identityId": "id-1",
            "label": "",
            "devicePks": [pk],
            "updatedAt": super::now_ms(),
            "expiresAt": super::now_ms() + 60000,
        });
        let ev = make_event("identity", content, &pk, &sk);
        let mut store = SwarmStore::new();
        let stored = store.put_record(&ev);
        assert_eq!(stored, Some(RecordType::Identity));
        assert_eq!(store.list_identity_events().len(), 1);
    }

    #[test]
    fn store_rejects_device_record_with_wrong_pubkey() {
        let (pk, sk) = nostr::generate_keypair();
        let content = json!({
            "devicePk": "other",
            "identityId": "",
            "deviceLabel": "",
            "updatedAt": super::now_ms(),
            "expiresAt": super::now_ms() + 60000,
        });
        let ev = make_event("device", content, &pk, &sk);
        let mut store = SwarmStore::new();
        let stored = store.put_record(&ev);
        assert!(stored.is_none());
    }

    #[test]
    fn store_accepts_dht_record() {
        let (pk, sk) = nostr::generate_keypair();
        let content = json!({
            "scope": "zone_members",
            "key": "peer-1",
            "value": { "devicePk": pk, "status": "up" },
            "authorPk": pk,
            "updatedAt": super::now_ms(),
            "expiresAt": super::now_ms() + 60000,
        });
        let ev = make_event("dht", content, &pk, &sk);
        let mut store = SwarmStore::new();
        let stored = store.put_record(&ev);
        assert_eq!(stored, Some(RecordType::Dht));
        assert_eq!(store.list_dht_events().len(), 1);
        assert!(store.get_dht_event("zone_members", "peer-1").is_some());
    }
}

#[derive(Clone, Debug, Default)]
pub struct SwarmStoreMap {
    stores: HashMap<String, SwarmStore>,
}

impl SwarmStoreMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_record_in_zone(&mut self, zone: &str, ev: &nostr::NostrEvent) -> Option<RecordType> {
        let key = zone.trim().to_string();
        if key.is_empty() {
            return None;
        }
        let store = self.stores.entry(key).or_insert_with(SwarmStore::new);
        store.put_record(ev)
    }

    pub fn put_record_all(
        &mut self,
        zones: &[String],
        ev: &nostr::NostrEvent,
    ) -> Option<RecordType> {
        let mut stored = None;
        for zone in zones {
            if let Some(rt) = self.put_record_in_zone(zone, ev) {
                stored = Some(rt);
            }
        }
        stored
    }

    pub fn list_identity_events_zone(&self, zone: &str) -> Vec<nostr::NostrEvent> {
        self.stores
            .get(zone)
            .map(|s| s.list_identity_events())
            .unwrap_or_default()
    }

    pub fn list_device_events_zone(&self, zone: &str) -> Vec<nostr::NostrEvent> {
        self.stores
            .get(zone)
            .map(|s| s.list_device_events())
            .unwrap_or_default()
    }

    pub fn list_dht_events_zone(&self, zone: &str) -> Vec<nostr::NostrEvent> {
        self.stores
            .get(zone)
            .map(|s| s.list_dht_events())
            .unwrap_or_default()
    }

    pub fn get_identity_event_zone(&self, zone: &str, id: &str) -> Option<nostr::NostrEvent> {
        self.stores.get(zone).and_then(|s| s.get_identity_event(id))
    }

    pub fn get_device_event_zone(&self, zone: &str, pk: &str) -> Option<nostr::NostrEvent> {
        self.stores.get(zone).and_then(|s| s.get_device_event(pk))
    }

    pub fn get_dht_event_zone(
        &self,
        zone: &str,
        scope: &str,
        key: &str,
    ) -> Option<nostr::NostrEvent> {
        self.stores
            .get(zone)
            .and_then(|s| s.get_dht_event(scope, key))
    }

    pub fn get_identity_event_any(&self, id: &str) -> Option<nostr::NostrEvent> {
        for store in self.stores.values() {
            if let Some(ev) = store.get_identity_event(id) {
                return Some(ev);
            }
        }
        None
    }

    pub fn get_device_event_any(&self, pk: &str) -> Option<nostr::NostrEvent> {
        for store in self.stores.values() {
            if let Some(ev) = store.get_device_event(pk) {
                return Some(ev);
            }
        }
        None
    }

    pub fn get_dht_event_any(&self, scope: &str, key: &str) -> Option<nostr::NostrEvent> {
        for store in self.stores.values() {
            if let Some(ev) = store.get_dht_event(scope, key) {
                return Some(ev);
            }
        }
        None
    }

    pub fn list_identity_events_all(&self) -> Vec<nostr::NostrEvent> {
        let mut out = Vec::new();
        for store in self.stores.values() {
            out.extend(store.list_identity_events());
        }
        unique_events(out)
    }

    pub fn list_device_events_all(&self) -> Vec<nostr::NostrEvent> {
        let mut out = Vec::new();
        for store in self.stores.values() {
            out.extend(store.list_device_events());
        }
        unique_events(out)
    }
}

fn unique_events(list: Vec<nostr::NostrEvent>) -> Vec<nostr::NostrEvent> {
    let mut seen = HashMap::new();
    for ev in list {
        seen.entry(ev.id.clone()).or_insert(ev);
    }
    seen.into_values().collect()
}
