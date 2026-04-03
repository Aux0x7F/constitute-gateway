//! Discovery schemas and publication helpers for gateway presence and device records.
//!
//! This module builds signed Nostr envelopes used for bootstrap discovery and
//! zone-scoped gateway presence signaling.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
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

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HostedServiceRecord {
    pub device_pk: String,
    pub device_label: String,
    pub device_kind: String,
    pub service: String,
    pub host_gateway_pk: String,
    pub service_version: String,
    pub updated_at: u64,
    #[serde(default)]
    pub freshness_ms: u64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub camera_count: u64,
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
    #[serde(default = "default_device_kind")]
    pub device_kind: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub host_gateway_pk: String,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub host_platform: String,
    #[serde(default = "default_service_version")]
    pub service_version: String,
    #[serde(default = "default_release_channel")]
    pub release_channel: String,
    #[serde(default = "default_release_track")]
    pub release_track: String,
    #[serde(default)]
    pub release_branch: String,
    #[serde(default)]
    pub freshness_ms: u64,
    #[serde(default)]
    pub hosted_services: Vec<HostedServiceRecord>,
}

impl SwarmDeviceRecord {
    pub fn new(
        device_pk: &str,
        identity_id: &str,
        device_label: &str,
        role: &str,
        relays: Vec<String>,
        host_platform: &str,
        release_channel: &str,
        release_track: &str,
        release_branch: &str,
    ) -> Self {
        let now = now_ms();
        Self {
            device_pk: device_pk.to_string(),
            identity_id: identity_id.to_string(),
            device_label: device_label.to_string(),
            updated_at: now,
            expires_at: now + RECORD_TTL_MS,
            role: role.to_string(),
            device_kind: default_device_kind(),
            service: String::new(),
            host_gateway_pk: String::new(),
            relays,
            host_platform: host_platform.to_string(),
            service_version: service_version(),
            release_channel: release_channel.to_string(),
            release_track: release_track.to_string(),
            release_branch: release_branch.to_string(),
            freshness_ms: 0,
            hosted_services: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.as_json_value()).unwrap_or_else(|_| "{}".to_string())
    }

    fn as_json_value(&self) -> serde_json::Value {
        json!({
            "devicePk": self.device_pk,
            "identityId": self.identity_id,
            "deviceLabel": self.device_label,
            "updatedAt": self.updated_at,
            "expiresAt": self.expires_at,
            "role": self.role,
            "deviceKind": self.device_kind,
            "service": self.service,
            "hostGatewayPk": self.host_gateway_pk,
            "relays": self.relays,
            "hostPlatform": self.host_platform,
            "serviceVersion": self.service_version,
            "releaseChannel": self.release_channel,
            "releaseTrack": self.release_track,
            "releaseBranch": self.release_branch,
            "freshnessMs": self.freshness_ms,
            "hostedServices": self
                .hosted_services
                .iter()
                .map(HostedServiceRecord::as_json_value)
                .collect::<Vec<_>>(),
        })
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
    host_platform: String,
    #[serde(default = "default_service_version")]
    service_version: String,
    #[serde(default = "default_release_channel")]
    release_channel: String,
    #[serde(default = "default_release_track")]
    release_track: String,
    #[serde(default)]
    release_branch: String,
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
    hosted_services_rx: watch::Receiver<Vec<HostedServiceRecord>>,
}

impl HostedServiceRecord {
    fn as_json_value(&self) -> serde_json::Value {
        json!({
            "devicePk": self.device_pk,
            "deviceLabel": self.device_label,
            "deviceKind": self.device_kind,
            "service": self.service,
            "hostGatewayPk": self.host_gateway_pk,
            "serviceVersion": self.service_version,
            "updatedAt": self.updated_at,
            "freshnessMs": self.freshness_ms,
            "status": self.status,
            "cameraCount": self.camera_count,
        })
    }
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
        hosted_services_rx: watch::Receiver<Vec<HostedServiceRecord>>,
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
            hosted_services_rx,
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
        let mut record = self.device_record.clone();
        let now = now_ms();
        record.updated_at = now;
        record.expires_at = now + RECORD_TTL_MS;
        record.hosted_services = self.hosted_services_rx.borrow().clone();
        let tags = vec![
            vec!["t".to_string(), DEFAULT_RECORD_TAG.to_string()],
            vec!["type".to_string(), "device".to_string()],
            vec!["role".to_string(), record.role.clone()],
        ];
        let content = record.to_json();
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
            host_platform: self.device_record.host_platform.clone(),
            service_version: self.device_record.service_version.clone(),
            release_channel: self.device_record.release_channel.clone(),
            release_track: self.device_record.release_track.clone(),
            release_branch: self.device_record.release_branch.clone(),
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

fn default_service_version() -> String {
    service_version()
}

fn default_device_kind() -> String {
    "service".to_string()
}

fn default_release_channel() -> String {
    "release".to_string()
}

fn default_release_track() -> String {
    "latest".to_string()
}

pub fn service_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::{HostedServiceRecord, SwarmDeviceRecord};

    #[test]
    fn device_record_json_keeps_device_kind_and_hosted_services() {
        let mut record = SwarmDeviceRecord::new(
            "gateway-pk",
            "identity-id",
            "DevGateway",
            "gateway",
            vec!["ws://gateway.example:7447".to_string()],
            "linux",
            "release",
            "latest",
            "",
        );
        record.hosted_services.push(HostedServiceRecord {
            device_pk: "service-pk".to_string(),
            device_label: "Constitute NVR".to_string(),
            device_kind: "service".to_string(),
            service: "nvr".to_string(),
            host_gateway_pk: "gateway-pk".to_string(),
            service_version: "0.1.0".to_string(),
            updated_at: 123,
            freshness_ms: 0,
            status: "online".to_string(),
            camera_count: 1,
        });

        let json = record.to_json();
        assert!(json.contains("\"deviceKind\":\"service\""));
        assert!(json.contains("\"hostedServices\":["));
        assert!(json.contains("\"service\":\"nvr\""));
    }
}
