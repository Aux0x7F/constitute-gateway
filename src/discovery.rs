//! Discovery schemas and publication helpers for gateway presence and device records.
//!
//! This module builds signed Nostr envelopes used for bootstrap discovery and
//! zone-scoped gateway presence signaling.

use anyhow::Result;
use constitute_protocol::{
    validate_host_fabric_fulfillment_plan, validate_host_fabric_member_contribution,
    validate_lifecycle_plan_posture, validate_substrate_association_handoff,
    HostFabricFulfillmentPlan, HostFabricMemberContribution, LifecyclePhasePosture,
    LifecyclePlanPosture, SubstrateAssociationHandoff, FABRIC_ASSOCIATION_HANDOFF_HANDED_OFF,
    FABRIC_FULFILLMENT_PLAN_READY, FABRIC_LIFECYCLE_PHASE_OBSERVE, FABRIC_LIFECYCLE_PHASE_READY,
    FABRIC_LIFECYCLE_PHASE_RUN, FABRIC_LIFECYCLE_PHASE_RUNNING, FABRIC_LIFECYCLE_PHASE_SOURCE,
    FABRIC_LIFECYCLE_PLAN_READY, FABRIC_MEMBER_CONTRIBUTION_RUNNING,
    FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION, RECORD_HOST_FABRIC_FULFILLMENT_PLAN,
    RECORD_HOST_FABRIC_MEMBER_CONTRIBUTION, RECORD_LIFECYCLE_PLAN_POSTURE,
    RECORD_SUBSTRATE_ASSOCIATION_HANDOFF,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAssociationPosture {
    pub substrate_association_handoff: SubstrateAssociationHandoff,
    pub gateway_association_contribution: HostFabricMemberContribution,
    pub lifecycle_plan: LifecyclePlanPosture,
    pub fulfillment_plan: HostFabricFulfillmentPlan,
}

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
    #[serde(default)]
    pub service_pk: String,
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
    #[serde(default)]
    pub facts: Value,
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
    pub swarm_edge_endpoint: String,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_pk: &str,
        identity_id: &str,
        device_label: &str,
        role: &str,
        relays: Vec<String>,
        swarm_edge_endpoint: &str,
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
            swarm_edge_endpoint: swarm_edge_endpoint.trim().to_string(),
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
        let mut value = json!({
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
            "swarmEdgeEndpoint": self.swarm_edge_endpoint,
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
        });
        if let Ok(posture) = gateway_association_posture(self, self.updated_at) {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "gatewayAssociationPosture".to_string(),
                    serde_json::to_value(posture).unwrap_or(Value::Null),
                );
            }
        }
        value
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
            "servicePk": self.service_pk,
            "deviceLabel": self.device_label,
            "deviceKind": self.device_kind,
            "service": self.service,
            "hostGatewayPk": self.host_gateway_pk,
            "serviceVersion": self.service_version,
            "updatedAt": self.updated_at,
            "freshnessMs": self.freshness_ms,
            "status": self.status,
            "cameraCount": self.camera_count,
            "facts": self.facts,
        })
    }
}

impl DiscoveryClient {
    #[allow(clippy::too_many_arguments)]
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
        append_gateway_service_surface(&mut record);
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

pub fn append_gateway_service_surface(record: &mut SwarmDeviceRecord) {
    let gateway_service = gateway_service_surface_record(record);
    let gateway_service_pk = gateway_service.service_pk.trim();
    record.hosted_services.retain(|service| {
        service.service_pk.trim() != gateway_service_pk || service.service.trim() != "gateway"
    });
    record.hosted_services.push(gateway_service);
}

fn gateway_service_surface_record(record: &SwarmDeviceRecord) -> HostedServiceRecord {
    HostedServiceRecord {
        device_pk: record.device_pk.clone(),
        service_pk: record.device_pk.clone(),
        device_label: if record.device_label.trim().is_empty() {
            "Gateway".to_string()
        } else {
            record.device_label.clone()
        },
        device_kind: "service".to_string(),
        service: "gateway".to_string(),
        host_gateway_pk: record.device_pk.clone(),
        service_version: record.service_version.clone(),
        updated_at: record.updated_at,
        freshness_ms: 0,
        status: "online".to_string(),
        camera_count: 0,
        facts: json!({
            "surfaceChannel": "gateway.surface",
            "aliases": ["Gateway", record.device_label],
            "summary": "Gateway routing, hosted-service, zone, and device observation.",
            "health": { "status": "online" },
            "locationId": record.device_label,
            "hostGatewayLabel": record.device_label,
            "nodes": ["health", "devices", "hostedServices", "zones", "routingDiagnostics"],
        }),
    }
}

pub fn gateway_association_posture(
    record: &SwarmDeviceRecord,
    observed_at: u64,
) -> Result<GatewayAssociationPosture> {
    let fabric_ref = gateway_fabric_ref(record);
    let host_ref = gateway_host_ref(record);
    let gateway_association_ref = gateway_association_ref(record);
    let handoff = SubstrateAssociationHandoff {
        kind: Some(RECORD_SUBSTRATE_ASSOCIATION_HANDOFF.to_string()),
        handoff_id: format!(
            "handoff:gateway:{}:initial-owner",
            short_ref(&record.device_pk)
        ),
        substrate_ref: "substrate:first-trust:gateway".to_string(),
        host_ref: host_ref.clone(),
        owner_ref: record.identity_id.clone(),
        fabric_ref: fabric_ref.clone(),
        state: FABRIC_ASSOCIATION_HANDOFF_HANDED_OFF.to_string(),
        initial_association_refs: vec![format!(
            "association:substrate:{}:{}",
            record.identity_id,
            short_ref(&record.device_pk)
        )],
        gateway_association_refs: vec![gateway_association_ref.clone()],
        evidence_refs: vec![format!("evidence:gateway-association:{}", record.device_pk)],
        blocked_reasons: vec![],
        safe_facts: json!({
            "handoff": "substrate-to-gateway-association",
            "role": record.role,
            "hostPlatform": record.host_platform
        }),
        issued_at: observed_at.saturating_sub(1),
        handed_off_at: Some(observed_at),
        expires_at: Some(observed_at + RECORD_TTL_MS),
    };
    validate_substrate_association_handoff(&handoff)?;

    let contribution = HostFabricMemberContribution {
        kind: Some(RECORD_HOST_FABRIC_MEMBER_CONTRIBUTION.to_string()),
        contribution_id: format!(
            "fabric-contribution:gateway-association:{}",
            short_ref(&record.device_pk)
        ),
        fabric_ref: fabric_ref.clone(),
        host_ref: host_ref.clone(),
        member_ref: record.device_pk.clone(),
        role: FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION.to_string(),
        state: FABRIC_MEMBER_CONTRIBUTION_RUNNING.to_string(),
        contract_ref: "contract:gateway-association@0.1.0".to_string(),
        subject_ref: gateway_association_ref.clone(),
        capability_refs: vec!["gateway.association.fulfill".to_string()],
        grant_refs: vec![format!("grant:gateway-association:{}", record.identity_id)],
        input_refs: vec![handoff.handoff_id.clone()],
        output_refs: vec![format!(
            "projection:gateway-association:{}",
            record.device_pk
        )],
        evidence_refs: vec![format!("evidence:gateway-presence:{}", record.device_pk)],
        lifecycle_plan_refs: vec![format!(
            "lifecycle-plan:gateway-association:{}",
            short_ref(&record.device_pk)
        )],
        release_refs: vec![format!("release:gateway:{}", record.service_version)],
        resource_posture: None,
        blocked_reasons: vec![],
        safe_facts: json!({
            "role": FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION,
            "serviceVersion": record.service_version,
            "releaseTrack": record.release_track
        }),
        observed_at,
        expires_at: Some(observed_at + RECORD_TTL_MS),
    };
    validate_host_fabric_member_contribution(&contribution)?;

    let lifecycle_plan = LifecyclePlanPosture {
        kind: Some(RECORD_LIFECYCLE_PLAN_POSTURE.to_string()),
        lifecycle_plan_id: contribution.lifecycle_plan_refs[0].clone(),
        subject_ref: gateway_association_ref.clone(),
        contract_ref: "contract:lifecycle.gateway-association@0.1.0".to_string(),
        state: FABRIC_LIFECYCLE_PLAN_READY.to_string(),
        lifecycle_contract_refs: vec!["contract:lifecycle.gateway-association@0.1.0".to_string()],
        phase_postures: vec![
            LifecyclePhasePosture {
                phase: FABRIC_LIFECYCLE_PHASE_SOURCE.to_string(),
                state: FABRIC_LIFECYCLE_PHASE_READY.to_string(),
                evidence_refs: vec![format!("evidence:gateway-source:{}", record.device_pk)],
                output_refs: vec![format!("source:gateway:{}", record.service_version)],
                blocked_reasons: vec![],
                safe_facts: Value::Null,
            },
            LifecyclePhasePosture {
                phase: FABRIC_LIFECYCLE_PHASE_RUN.to_string(),
                state: FABRIC_LIFECYCLE_PHASE_RUNNING.to_string(),
                evidence_refs: vec![format!("evidence:gateway-running:{}", record.device_pk)],
                output_refs: vec![gateway_association_ref.clone()],
                blocked_reasons: vec![],
                safe_facts: Value::Null,
            },
            LifecyclePhasePosture {
                phase: FABRIC_LIFECYCLE_PHASE_OBSERVE.to_string(),
                state: FABRIC_LIFECYCLE_PHASE_READY.to_string(),
                evidence_refs: vec![format!("evidence:gateway-observed:{}", record.device_pk)],
                output_refs: vec!["projection:gateway-association:hot".to_string()],
                blocked_reasons: vec![],
                safe_facts: Value::Null,
            },
        ],
        member_contribution_refs: vec![contribution.contribution_id.clone()],
        evidence_refs: vec![format!(
            "evidence:lifecycle:gateway-association:{}",
            record.device_pk
        )],
        release_refs: contribution.release_refs.clone(),
        blocked_reasons: vec![],
        safe_facts: Value::Null,
        observed_at,
        expires_at: Some(observed_at + RECORD_TTL_MS),
    };
    validate_lifecycle_plan_posture(&lifecycle_plan)?;

    let fulfillment_plan = HostFabricFulfillmentPlan {
        kind: Some(RECORD_HOST_FABRIC_FULFILLMENT_PLAN.to_string()),
        plan_id: format!(
            "fabric-plan:gateway-association:{}",
            short_ref(&record.device_pk)
        ),
        fabric_ref,
        host_ref,
        contract_ref: "contract:gateway-association@0.1.0".to_string(),
        state: FABRIC_FULFILLMENT_PLAN_READY.to_string(),
        required_role_refs: vec![format!("role:{FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION}")],
        member_contribution_refs: vec![contribution.contribution_id.clone()],
        missing_role_refs: vec![],
        lifecycle_plan_refs: vec![lifecycle_plan.lifecycle_plan_id.clone()],
        materialization_budget_refs: vec!["materialization-budget:gateway-association".to_string()],
        association_handoff_ref: Some(handoff.handoff_id.clone()),
        evidence_refs: vec![format!("evidence:fabric-plan:{}", record.device_pk)],
        blocked_reasons: vec![],
        safe_facts: Value::Null,
        observed_at,
        expires_at: Some(observed_at + RECORD_TTL_MS),
    };
    validate_host_fabric_fulfillment_plan(&fulfillment_plan)?;

    Ok(GatewayAssociationPosture {
        substrate_association_handoff: handoff,
        gateway_association_contribution: contribution,
        lifecycle_plan,
        fulfillment_plan,
    })
}

fn gateway_fabric_ref(record: &SwarmDeviceRecord) -> String {
    format!("fabric:gateway:{}", short_ref(&record.device_pk))
}

fn gateway_host_ref(record: &SwarmDeviceRecord) -> String {
    format!("host:gateway:{}", short_ref(&record.device_pk))
}

fn gateway_association_ref(record: &SwarmDeviceRecord) -> String {
    format!(
        "association:gateway:{}:ongoing",
        short_ref(&record.device_pk)
    )
}

fn short_ref(value: &str) -> String {
    let trimmed = value.trim();
    trimmed.chars().take(12).collect()
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
    use super::{gateway_association_posture, HostedServiceRecord, SwarmDeviceRecord};
    use serde_json::json;

    #[test]
    fn device_record_json_keeps_device_kind_and_hosted_services() {
        let mut record = SwarmDeviceRecord::new(
            "gateway-pk",
            "identity-id",
            "DevGateway",
            "gateway",
            vec!["ws://gateway.example:7447".to_string()],
            "ws://gateway.example:7448",
            "linux",
            "release",
            "latest",
            "",
        );
        record.hosted_services.push(HostedServiceRecord {
            device_pk: "service-pk".to_string(),
            service_pk: "service-pk".to_string(),
            device_label: "Constitute NVR".to_string(),
            device_kind: "service".to_string(),
            service: "nvr".to_string(),
            host_gateway_pk: "gateway-pk".to_string(),
            service_version: "0.1.0".to_string(),
            updated_at: 123,
            freshness_ms: 0,
            status: "online".to_string(),
            camera_count: 1,
            facts: json!({
                "configuredSources": 1,
            }),
        });
        record
            .hosted_services
            .push(super::gateway_service_surface_record(&record));

        let json = record.to_json();
        assert!(json.contains("\"deviceKind\":\"service\""));
        assert!(json.contains("\"relays\":[\"ws://gateway.example:7447\"]"));
        assert!(json.contains("\"swarmEdgeEndpoint\":\"ws://gateway.example:7448\""));
        assert!(json.contains("\"hostedServices\":["));
        assert!(json.contains("\"service\":\"nvr\""));
        assert!(json.contains("\"service\":\"gateway\""));
        assert!(json.contains("\"surfaceChannel\":\"gateway.surface\""));
    }

    #[test]
    fn gateway_record_projects_association_handoff_and_fabric_contribution() {
        let gateway_pk = "4a29ff60c5c3837e9e20555bfeb2a046be3eb140818144628691fcf7efb1d2f1";
        let record = SwarmDeviceRecord::new(
            gateway_pk,
            "identity:aux",
            "DevGateway",
            "gateway",
            vec!["ws://gateway.example:7447".to_string()],
            "ws://gateway.example:7448",
            "linux",
            "release",
            "latest",
            "",
        );
        let posture = gateway_association_posture(&record, 1_700_000_000).expect("posture");

        assert_eq!(
            posture.substrate_association_handoff.state,
            constitute_protocol::FABRIC_ASSOCIATION_HANDOFF_HANDED_OFF
        );
        assert_eq!(
            posture.gateway_association_contribution.role,
            constitute_protocol::FABRIC_MEMBER_ROLE_GATEWAY_ASSOCIATION
        );
        assert_eq!(
            posture.fulfillment_plan.state,
            constitute_protocol::FABRIC_FULFILLMENT_PLAN_READY
        );
        assert_eq!(
            posture.fulfillment_plan.association_handoff_ref,
            Some(posture.substrate_association_handoff.handoff_id.clone())
        );

        let json = record.to_json();
        assert!(json.contains("\"gatewayAssociationPosture\""));
        assert!(json.contains("\"hostFabric.member.contribution\""));
        assert!(json.contains("\"substrate.association.handoff\""));
    }
}
