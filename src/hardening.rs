use crate::mitigation::gateway_mitigation_consumer_posture;
use anyhow::Result;
use constitute_protocol::{
    validate_cybersec_mitigation_recommendation, validate_hardening_signal_observation,
    validate_network_exposure_posture, CybersecMitigationConsumerPostureRecord,
    CybersecMitigationRecommendationRecord, HardeningSignalObservationRecord,
    NetworkExposurePostureRecord, RECORD_CYBERSEC_MITIGATION_RECOMMENDATION,
    RECORD_HARDENING_SIGNAL_OBSERVATION, RECORD_NETWORK_EXPOSURE_POSTURE,
};
use serde_json::json;

pub const GATEWAY_HARDENING_OBSERVER_REF: &str = "constitute-gateway";
pub const GATEWAY_HARDENING_AUTHORITY_REF: &str = "authority:gateway-hardening";
pub const GATEWAY_MITIGATION_AUTHORITY_REF: &str = "authority:gateway-mitigation";
pub const GATEWAY_NETWORK_SUBJECT_REF: &str = "gateway:route:edge";
pub const GATEWAY_CYBERSEC_PROCESSOR_REF: &str = "processor:constitute-cybersec";

#[derive(Clone, Debug)]
pub struct GatewayHardeningSignalInput {
    pub subject_ref: String,
    pub signal_kind: String,
    pub state: String,
    pub severity: String,
    pub authority_refs: Vec<String>,
    pub event_refs: Vec<String>,
    pub detail_refs: Vec<String>,
    pub storage_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub blocked_reasons: Vec<String>,
    pub observed_at: u64,
    pub expires_at: Option<u64>,
}

pub fn gateway_hardening_signal_observation(
    input: GatewayHardeningSignalInput,
) -> Result<HardeningSignalObservationRecord> {
    let posture = HardeningSignalObservationRecord {
        kind: Some(RECORD_HARDENING_SIGNAL_OBSERVATION.to_string()),
        observation_id: format!(
            "hardening:signal:gateway:{}:{}",
            input.signal_kind, input.observed_at
        ),
        observer_ref: GATEWAY_HARDENING_OBSERVER_REF.to_string(),
        subject_ref: input.subject_ref,
        signal_kind: input.signal_kind,
        state: input.state,
        severity: input.severity,
        authority_refs: input.authority_refs,
        event_refs: input.event_refs,
        detail_refs: input.detail_refs,
        storage_refs: input.storage_refs,
        evidence_refs: input.evidence_refs,
        safe_facts: json!({
            "observer": GATEWAY_HARDENING_OBSERVER_REF,
            "signalClass": "gatewayHardening"
        }),
        blocked_reasons: input.blocked_reasons,
        observed_at: input.observed_at,
        expires_at: input.expires_at,
    };
    validate_hardening_signal_observation(&posture)?;
    Ok(posture)
}

pub fn gateway_network_exposure_posture(
    subject_ref: &str,
    route_refs: Vec<String>,
    exposed_port_refs: Vec<String>,
    firewall_posture_refs: Vec<String>,
    ingress_refs: Vec<String>,
    signal_observation_refs: Vec<String>,
    evidence_refs: Vec<String>,
    observed_at: u64,
    expires_at: Option<u64>,
) -> Result<NetworkExposurePostureRecord> {
    let state = if !firewall_posture_refs.is_empty() {
        "guarded"
    } else if !exposed_port_refs.is_empty() {
        "exposed"
    } else {
        "observed"
    };

    let posture = NetworkExposurePostureRecord {
        kind: Some(RECORD_NETWORK_EXPOSURE_POSTURE.to_string()),
        posture_id: format!("network-exposure:gateway:{subject_ref}:{observed_at}"),
        observer_ref: GATEWAY_HARDENING_OBSERVER_REF.to_string(),
        subject_ref: subject_ref.to_string(),
        state: state.to_string(),
        route_refs,
        exposed_port_refs,
        firewall_posture_refs,
        ingress_refs,
        signal_observation_refs,
        evidence_refs,
        safe_facts: json!({
            "observer": GATEWAY_HARDENING_OBSERVER_REF,
            "exposureOwner": "gateway.route",
            "firewallPostureOwner": "operator.proofSubstrate"
        }),
        blocked_reasons: Vec::new(),
        observed_at,
        expires_at,
    };
    validate_network_exposure_posture(&posture)?;
    Ok(posture)
}

#[derive(Clone, Debug)]
pub struct GatewayHardeningObservationFixture {
    pub signal: HardeningSignalObservationRecord,
    pub network_exposure: NetworkExposurePostureRecord,
    pub mitigation_recommendation: CybersecMitigationRecommendationRecord,
    pub mitigation_consumer: CybersecMitigationConsumerPostureRecord,
}

pub fn gateway_hardening_observation_fixture(
    observed_at: u64,
) -> Result<GatewayHardeningObservationFixture> {
    let expires_at = observed_at.saturating_add(3_600);
    let signal = gateway_hardening_signal_observation(GatewayHardeningSignalInput {
        subject_ref: GATEWAY_NETWORK_SUBJECT_REF.to_string(),
        signal_kind: "firewall".to_string(),
        state: "observed".to_string(),
        severity: "info".to_string(),
        authority_refs: vec![GATEWAY_HARDENING_AUTHORITY_REF.to_string()],
        event_refs: vec![format!("event:gateway:firewall:{observed_at}")],
        detail_refs: Vec::new(),
        storage_refs: Vec::new(),
        evidence_refs: vec![format!("evidence:gateway:firewall:{observed_at}")],
        blocked_reasons: Vec::new(),
        observed_at,
        expires_at: Some(expires_at),
    })?;

    let network_exposure = gateway_network_exposure_posture(
        GATEWAY_NETWORK_SUBJECT_REF,
        vec!["route:gateway:quic".to_string()],
        vec!["udp:7447".to_string(), "ws:7448".to_string()],
        vec!["firewall:gateway:local".to_string()],
        vec!["ingress:gateway:edge".to_string()],
        vec![signal.observation_id.clone()],
        vec![format!("evidence:gateway:network:{observed_at}")],
        observed_at.saturating_add(1),
        Some(expires_at),
    )?;

    let mitigation_recommendation = CybersecMitigationRecommendationRecord {
        kind: Some(RECORD_CYBERSEC_MITIGATION_RECOMMENDATION.to_string()),
        recommendation_id: format!("cybersec:recommendation:gateway-hardening:{observed_at}"),
        finding_ref: signal.observation_id.clone(),
        processor_report_ref: "event-fabric-report:gateway-hardening".to_string(),
        recommender_ref: GATEWAY_CYBERSEC_PROCESSOR_REF.to_string(),
        action_kind: "requestEvidence".to_string(),
        target_ref: network_exposure.posture_id.clone(),
        state: "recommended".to_string(),
        authority_refs: vec!["authority:cybersec-recommendation".to_string()],
        consumer_refs: vec![GATEWAY_HARDENING_OBSERVER_REF.to_string()],
        evidence_refs: vec![
            signal.observation_id.clone(),
            network_exposure.posture_id.clone(),
        ],
        safe_facts: json!({
            "recommendationOnly": true,
            "targetClass": "gatewayHardeningObservation",
            "enforcementOwner": "gateway.consumer"
        }),
        blocked_reasons: Vec::new(),
        issued_at: observed_at.saturating_add(2),
        expires_at: Some(expires_at),
    };
    validate_cybersec_mitigation_recommendation(&mitigation_recommendation)?;

    let mitigation_consumer = gateway_mitigation_consumer_posture(
        &mitigation_recommendation,
        vec![GATEWAY_MITIGATION_AUTHORITY_REF.to_string()],
        observed_at.saturating_add(3),
    )?;

    Ok(GatewayHardeningObservationFixture {
        signal,
        network_exposure,
        mitigation_recommendation,
        mitigation_consumer,
    })
}
