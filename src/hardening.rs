use anyhow::Result;
use constitute_protocol::{
    validate_hardening_signal_observation, validate_network_exposure_posture,
    HardeningSignalObservationRecord, NetworkExposurePostureRecord,
    RECORD_HARDENING_SIGNAL_OBSERVATION, RECORD_NETWORK_EXPOSURE_POSTURE,
};
use serde_json::json;

pub const GATEWAY_HARDENING_OBSERVER_REF: &str = "constitute-gateway";

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
