use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::watch;

use crate::nostr;
use crate::relay;
use crate::util;

const DEFAULT_RECORD_KIND: u32 = 30078;
const DEFAULT_RECORD_TAG: &str = "swarm_discovery";
const APP_KIND: u32 = 1;
const APP_TAG: &str = "constitute";
const SUB_ID: &str = "constitute_sub_v2";
const RECORD_TTL_MS: u64 = 24 * 60 * 60 * 1000;

pub fn relay_req_json() -> String {
    let filters = vec![
        nostr::NostrFilter {
            kinds: Some(vec![APP_KIND]),
            t: Some(vec![APP_TAG.to_string()]),
            z: None,
        },
        nostr::NostrFilter {
            kinds: Some(vec![DEFAULT_RECORD_KIND]),
            t: Some(vec![DEFAULT_RECORD_TAG.to_string()]),
            z: None,
        },
    ];
    nostr::frame_req(SUB_ID, filters)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    Relay,
    Gateway,
    Browser,
    Native,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NodeType::Relay => "relay",
            NodeType::Gateway => "gateway",
            NodeType::Browser => "browser",
            NodeType::Native => "native",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GatewayMetrics {
    pub clients: u64,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub load_pct: f32,
    pub ts: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwarmDeviceRecord {
    pub device_pk: String,
    pub identity_id: String,
    pub device_label: String,
    pub updated_at: u64,
    pub expires_at: u64,
    pub role: String,
    #[serde(default)]
    pub relays: Vec<String>,
}

impl SwarmDeviceRecord {
    pub fn new(
        device_pk: &str,
        identity_id: &str,
        device_label: &str,
        role: &str,
        relays: Vec<String>,
    ) -> Self {
        let now = now_ms();
        Self {
            device_pk: device_pk.to_string(),
            identity_id: identity_id.to_string(),
            device_label: device_label.to_string(),
            updated_at: now,
            expires_at: now + RECORD_TTL_MS,
            role: role.to_string(),
            relays,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ZonePresencePayload {
    #[serde(rename = "type")]
    kind: String,
    zone: String,
    device_pk: String,
    swarm: String,
    role: String,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    metrics: Option<GatewayMetrics>,
    ts: u64,
    ttl: u64,
}

#[derive(Clone, Debug)]
pub struct DiscoveryClient {
    pool: relay::RelayPool,
    device_record: SwarmDeviceRecord,
    nostr_pubkey: String,
    nostr_sk_hex: String,
    publish_interval: Duration,
    zones: Vec<String>,
    swarm_endpoint_rx: watch::Receiver<String>,
    metrics_rx: watch::Receiver<GatewayMetrics>,
}

impl DiscoveryClient {
    pub fn new(
        pool: relay::RelayPool,
        device_record: SwarmDeviceRecord,
        nostr_pubkey: String,
        nostr_sk_hex: String,
        publish_interval: Duration,
        zones: Vec<String>,
        swarm_endpoint_rx: watch::Receiver<String>,
        metrics_rx: watch::Receiver<GatewayMetrics>,
    ) -> Self {
        Self {
            pool,
            device_record,
            nostr_pubkey,
            nostr_sk_hex,
            publish_interval,
            zones,
            swarm_endpoint_rx,
            metrics_rx,
        }
    }

    pub async fn run(self) -> Result<()> {
        if self.pool.is_empty() {
            return Ok(());
        }

        let mut ticker = tokio::time::interval(self.publish_interval);
        loop {
            ticker.tick().await;
            if let Ok(payload) = self.device_record_json() {
                self.pool.broadcast(&payload);
            }

            for zone in &self.zones {
                if let Ok(msg) = self.zone_presence_json(zone) {
                    self.pool.broadcast(&msg);
                }
            }
        }
    }
    #[allow(dead_code)]
    pub fn test_envelope_json(&self) -> String {
        self.device_record_json()
            .unwrap_or_else(|_| "[]".to_string())
    }
    #[allow(dead_code)]
    pub fn test_zone_presence_json(&self, zone: &str) -> String {
        self.zone_presence_json(zone)
            .unwrap_or_else(|_| "[]".to_string())
    }

    fn device_record_json(&self) -> Result<String> {
        let tags = vec![
            vec!["t".to_string(), DEFAULT_RECORD_TAG.to_string()],
            vec!["type".to_string(), "device".to_string()],
            vec!["role".to_string(), self.device_record.role.clone()],
        ];
        let content = self.device_record.to_json();
        let unsigned = nostr::build_unsigned_event(
            &self.nostr_pubkey,
            DEFAULT_RECORD_KIND,
            tags,
            content,
            util::now_unix_seconds(),
        );
        let ev = nostr::sign_event(&unsigned, &self.nostr_sk_hex)?;
        Ok(nostr::frame_event(&ev))
    }

    fn zone_presence_json(&self, zone: &str) -> Result<String> {
        let swarm_endpoint = self.swarm_endpoint_rx.borrow().clone();
        let payload = ZonePresencePayload {
            kind: "zone_presence".to_string(),
            zone: zone.to_string(),
            device_pk: self.nostr_pubkey.clone(),
            swarm: swarm_endpoint,
            role: self.device_record.role.clone(),
            relays: self.device_record.relays.clone(),
            metrics: Some(self.metrics_rx.borrow().clone()),
            ts: util::now_unix_seconds() * 1000,
            ttl: 120,
        };
        let content = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        let tags = vec![
            vec!["t".to_string(), APP_TAG.to_string()],
            vec!["z".to_string(), zone.to_string()],
        ];
        let unsigned = nostr::build_unsigned_event(
            &self.nostr_pubkey,
            APP_KIND,
            tags,
            content,
            util::now_unix_seconds(),
        );
        let ev = nostr::sign_event(&unsigned, &self.nostr_sk_hex)?;
        Ok(nostr::frame_event(&ev))
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn default_record_kind() -> u32 {
    DEFAULT_RECORD_KIND
}

pub fn default_record_tag() -> String {
    DEFAULT_RECORD_TAG.to_string()
}
