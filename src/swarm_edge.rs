//! In-memory swarm edge intake and propagation planning.
//!
//! This module is intentionally transport-neutral. HTTP, WebSocket, Nostr, UDP,
//! and QUIC callers can adapt bytes into protocol records, but swarm frames are
//! the semantic runtime boundary handled here.

use anyhow::{anyhow, Result};
use constitute_protocol::{
    swarm_frame_id, validate_swarm_edge_hello, validate_swarm_edge_resume, validate_swarm_frame,
    SwarmAck, SwarmEdgeAccept, SwarmEdgeHello, SwarmEdgeResume, SwarmFrame, SwarmFrameBody,
    SwarmFrameKind, SwarmRecordRef, ZoneScope, CAPABILITY_PROJECTION_OBSERVE,
    CAPABILITY_SWARM_EDGE_ATTACH, SWARM_FRAME_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwarmEdgeStatus {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwarmEdgeReject {
    pub reason_code: String,
    pub detail: String,
    pub correlation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SwarmFrameReceipt {
    pub status: SwarmEdgeStatus,
    pub response: SwarmFrame,
    pub propagation: Vec<PropagationTarget>,
    pub route_observations: Vec<RouteObservation>,
    pub route_observation_frames: Vec<SwarmFrame>,
    pub bridge: Option<ServiceBridgeRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgeSession {
    pub session_id: String,
    pub member_kind: String,
    pub member_ref: String,
    pub zone_scope: ZoneScope,
    pub last_acked_frame_id: Option<String>,
    pub last_projection_revisions: Value,
    pub capability_refs: Vec<String>,
    pub channel_refs: Vec<String>,
    pub promise_refs: Vec<String>,
    pub accepted_version: u32,
    #[serde(default)]
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SwarmEdgeAttach {
    pub accept: SwarmEdgeAccept,
    pub session: SwarmEdgeSession,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SwarmEdgeAttachResult {
    Accepted(SwarmEdgeAttach),
    Rejected(SwarmEdgeReject),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwarmEdgeResumeResult {
    Accepted(SwarmEdgeSession),
    Rejected(SwarmEdgeReject),
}

#[derive(Clone, Debug, Default)]
pub struct SwarmReplayGuard {
    seen_frame_ids: HashSet<String>,
    seen_nonces: HashSet<String>,
}

impl SwarmReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_note_frame(&mut self, frame: &SwarmFrame) -> Result<()> {
        let frame_id = frame.frame_id.trim();
        let nonce = frame.nonce.trim();
        if frame_id.is_empty() || nonce.is_empty() {
            return Err(anyhow!("missing replay material"));
        }
        if self.seen_frame_ids.contains(frame_id) || self.seen_nonces.contains(nonce) {
            return Err(anyhow!("replayed swarm frame"));
        }
        self.seen_frame_ids.insert(frame_id.to_string());
        self.seen_nonces.insert(nonce.to_string());
        Ok(())
    }

    pub fn check_and_note_nonce(&mut self, nonce: &str) -> Result<()> {
        let nonce = nonce.trim();
        if nonce.is_empty() {
            return Err(anyhow!("missing replay nonce"));
        }
        if self.seen_nonces.contains(nonce) {
            return Err(anyhow!("replayed nonce"));
        }
        self.seen_nonces.insert(nonce.to_string());
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmRouteMember {
    pub member_ref: String,
    pub zone_id: String,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    #[serde(default)]
    pub audience_refs: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub interested: bool,
    #[serde(default)]
    pub replicator: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteObservationState {
    Delivered,
    MemberWritten,
    ObservingUnreachable,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RouteFailedPredicate {
    MissingZone,
    TtlExhausted,
    HopBudgetExhausted,
    NoMemberInZone,
    NoMemberForChannel,
    NoMemberForCapability,
    AudienceMemberMismatch,
    NoInterestedMember,
    UnknownSession,
    InvalidFrame,
    ExpiredFrame,
    ReplayedFrame,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteObservation {
    pub observation_id: String,
    pub frame_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub state: RouteObservationState,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(default)]
    pub delivered_to: Vec<String>,
    #[serde(default)]
    pub failed_predicates: Vec<RouteFailedPredicate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_authority_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_members: Vec<RouteCandidateDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteCandidateDiagnostic {
    pub member_ref: String,
    pub zone_id: String,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub audience_refs: Vec<String>,
    pub zone_match: bool,
    pub channel_match: bool,
    pub capability_match: bool,
    pub audience_match: bool,
    pub interested: bool,
    pub replicator: bool,
    pub member_source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_authority_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_predicates: Vec<RouteFailedPredicate>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SwarmEdgeMemberKind {
    Browser,
    Service,
    Cli,
    Gateway,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgeMember {
    pub member_kind: SwarmEdgeMemberKind,
    #[serde(flatten)]
    pub member: SwarmRouteMember,
}

impl SwarmEdgeMember {
    pub fn new(member_kind: SwarmEdgeMemberKind, member: SwarmRouteMember) -> Self {
        Self {
            member_kind,
            member,
        }
    }

    pub fn member_ref(&self) -> &str {
        self.member.member_ref.trim()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PropagationTarget {
    pub member_ref: String,
    pub zone_id: String,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PropagationPlanner {
    members: Vec<RouteMemberContribution>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteMemberContribution {
    source_id: String,
    source_kind: String,
    member: SwarmRouteMember,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropagationPlan {
    pub targets: Vec<PropagationTarget>,
    pub failed_predicates: Vec<RouteFailedPredicate>,
    pub candidate_members: Vec<RouteCandidateDiagnostic>,
    pub exhausted: bool,
}

impl PropagationPlanner {
    pub fn new(members: Vec<SwarmRouteMember>) -> Self {
        Self {
            members: members
                .into_iter()
                .enumerate()
                .map(|(index, member)| RouteMemberContribution {
                    source_id: format!("record:{}:{index}", member.member_ref.trim()),
                    source_kind: "recordBackedMembership".to_string(),
                    member,
                })
                .collect(),
        }
    }

    pub fn add_member_contribution(
        &mut self,
        source_id: impl Into<String>,
        source_kind: impl Into<String>,
        member: SwarmRouteMember,
    ) {
        let contribution = RouteMemberContribution {
            source_id: source_id.into(),
            source_kind: source_kind.into(),
            member,
        };
        if self
            .members
            .iter()
            .any(|existing| existing == &contribution)
        {
            return;
        }
        self.members.push(contribution);
    }

    pub fn remove_member_contributions(&mut self, source_id: &str) {
        let source_id = source_id.trim();
        self.members
            .retain(|contribution| contribution.source_id.trim() != source_id);
    }

    pub fn plan(&self, frame: &SwarmFrame, hop_count: u8) -> Vec<PropagationTarget> {
        self.plan_with_diagnostics(frame, hop_count).targets
    }

    pub fn plan_with_diagnostics(&self, frame: &SwarmFrame, hop_count: u8) -> PropagationPlan {
        let Some(scope) = frame.zone_scope.as_ref() else {
            return PropagationPlan {
                targets: vec![],
                failed_predicates: vec![RouteFailedPredicate::MissingZone],
                candidate_members: vec![],
                exhausted: false,
            };
        };
        let candidate_members = self.candidate_diagnostics(frame, scope);
        let mut failed_predicates = Vec::new();
        if scope.ttl == Some(0) || scope.ttl.is_some_and(|ttl| ttl <= hop_count as u64) {
            failed_predicates.push(RouteFailedPredicate::TtlExhausted);
        }
        if scope.max_hops == Some(0) || scope.max_hops.is_some_and(|max| max <= hop_count) {
            failed_predicates.push(RouteFailedPredicate::HopBudgetExhausted);
        }
        if !failed_predicates.is_empty() {
            return PropagationPlan {
                targets: vec![],
                failed_predicates,
                candidate_members,
                exhausted: true,
            };
        }

        let channel_id = frame
            .channel_id
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        let capability = frame
            .capability
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        let audience_refs = audience_refs(&frame.audience);

        let zone_members = self
            .members
            .iter()
            .filter(|contribution| contribution.member.zone_id.trim() == scope.zone_id.trim())
            .collect::<Vec<_>>();
        if zone_members.is_empty() {
            return PropagationPlan {
                targets: vec![],
                failed_predicates: vec![RouteFailedPredicate::NoMemberInZone],
                candidate_members,
                exhausted: false,
            };
        }

        let channel_members = zone_members
            .into_iter()
            .filter(|contribution| {
                channel_id.is_empty()
                    || contribution
                        .member
                        .channel_ids
                        .iter()
                        .any(|ch| ch.trim() == channel_id)
            })
            .collect::<Vec<_>>();
        if channel_members.is_empty() {
            return PropagationPlan {
                targets: vec![],
                failed_predicates: vec![RouteFailedPredicate::NoMemberForChannel],
                candidate_members,
                exhausted: false,
            };
        }

        let capability_members = channel_members
            .into_iter()
            .filter(|contribution| {
                capability.is_empty()
                    || contribution
                        .member
                        .capabilities
                        .iter()
                        .any(|cap| cap.trim() == capability)
            })
            .collect::<Vec<_>>();
        if capability_members.is_empty() {
            return PropagationPlan {
                targets: vec![],
                failed_predicates: vec![RouteFailedPredicate::NoMemberForCapability],
                candidate_members,
                exhausted: false,
            };
        }

        let interested_members = capability_members
            .into_iter()
            .filter(|contribution| {
                contribution.member.interested
                    || contribution.member.replicator
                    || !channel_id.is_empty()
            })
            .collect::<Vec<_>>();
        if interested_members.is_empty() {
            return PropagationPlan {
                targets: vec![],
                failed_predicates: vec![RouteFailedPredicate::NoInterestedMember],
                candidate_members,
                exhausted: false,
            };
        }

        let audience_members = interested_members
            .into_iter()
            .filter(|contribution| {
                audience_refs.is_empty()
                    || audience_refs.contains(contribution.member.member_ref.trim())
                    || contribution
                        .member
                        .audience_refs
                        .iter()
                        .any(|reference| audience_refs.contains(reference.trim()))
            })
            .collect::<Vec<_>>();
        if audience_members.is_empty() {
            return PropagationPlan {
                targets: vec![],
                failed_predicates: vec![RouteFailedPredicate::AudienceMemberMismatch],
                candidate_members,
                exhausted: false,
            };
        }

        let mut targets = audience_members
            .into_iter()
            .map(|contribution| PropagationTarget {
                member_ref: contribution.member.member_ref.clone(),
                zone_id: contribution.member.zone_id.clone(),
                channel_ids: contribution.member.channel_ids.clone(),
                capabilities: contribution.member.capabilities.clone(),
            })
            .collect::<Vec<_>>();

        targets.sort_by(|a, b| a.member_ref.cmp(&b.member_ref));
        targets.dedup_by(|a, b| a.member_ref == b.member_ref);
        PropagationPlan {
            targets,
            failed_predicates: vec![],
            candidate_members,
            exhausted: false,
        }
    }

    fn candidate_diagnostics(
        &self,
        frame: &SwarmFrame,
        scope: &ZoneScope,
    ) -> Vec<RouteCandidateDiagnostic> {
        let channel_id = frame
            .channel_id
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        let capability = frame
            .capability
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        let audience_refs = audience_refs(&frame.audience);
        let mut candidates = self
            .members
            .iter()
            .map(|contribution| {
                let member = &contribution.member;
                let zone_match = member.zone_id.trim() == scope.zone_id.trim();
                let channel_match = channel_id.is_empty()
                    || member.channel_ids.iter().any(|ch| ch.trim() == channel_id);
                let capability_match = capability.is_empty()
                    || member
                        .capabilities
                        .iter()
                        .any(|cap| cap.trim() == capability);
                let audience_match = audience_refs.is_empty()
                    || audience_refs.contains(member.member_ref.trim())
                    || member
                        .audience_refs
                        .iter()
                        .any(|reference| audience_refs.contains(reference.trim()));
                let mut failed_predicates = Vec::new();
                if !zone_match {
                    failed_predicates.push(RouteFailedPredicate::NoMemberInZone);
                }
                if zone_match && !channel_match {
                    failed_predicates.push(RouteFailedPredicate::NoMemberForChannel);
                }
                if zone_match && channel_match && !capability_match {
                    failed_predicates.push(RouteFailedPredicate::NoMemberForCapability);
                }
                if zone_match && channel_match && capability_match && !audience_match {
                    failed_predicates.push(RouteFailedPredicate::AudienceMemberMismatch);
                }
                if zone_match
                    && channel_match
                    && capability_match
                    && audience_match
                    && !(member.interested || member.replicator || !channel_id.is_empty())
                {
                    failed_predicates.push(RouteFailedPredicate::NoInterestedMember);
                }
                let failed_authority_domains = failed_authority_domains(&failed_predicates);
                RouteCandidateDiagnostic {
                    member_ref: member.member_ref.clone(),
                    zone_id: member.zone_id.clone(),
                    channel_ids: member.channel_ids.clone(),
                    capabilities: member.capabilities.clone(),
                    audience_refs: member.audience_refs.clone(),
                    zone_match,
                    channel_match,
                    capability_match,
                    audience_match,
                    interested: member.interested,
                    replicator: member.replicator,
                    member_source: contribution.source_kind.clone(),
                    authority_domains: route_authority_domains(),
                    failed_authority_domains,
                    failed_predicates,
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| a.member_ref.cmp(&b.member_ref));
        candidates
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServiceBridgeRecord {
    ServiceIntent(ServiceFrameBridge),
    Projection(ProjectionBridge),
    StoragePin(StoragePinBridge),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceFrameBridge {
    pub frame_id: String,
    pub service_ref: String,
    pub channel_id: Option<String>,
    pub capability: Option<String>,
    pub adapter_kind: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionBridge {
    pub frame_id: String,
    pub channel_id: Option<String>,
    pub projection_ref: Option<String>,
    pub delta: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoragePinBridge {
    pub frame_id: String,
    pub channel_id: Option<String>,
    pub pin_ref: Option<String>,
    pub attestation: bool,
}

pub fn bridge_service_frame(frame: &SwarmFrame) -> Option<ServiceBridgeRecord> {
    match frame.kind {
        SwarmFrameKind::ServiceIntent => {
            Some(ServiceBridgeRecord::ServiceIntent(ServiceFrameBridge {
                frame_id: frame.frame_id.clone(),
                service_ref: audience_ref(&frame.audience, "serviceRef")
                    .or_else(|| audience_ref(&frame.audience, "servicePk"))
                    .or_else(|| audience_ref(&frame.audience, "recipientServicePk"))
                    .unwrap_or_default(),
                channel_id: frame.channel_id.clone(),
                capability: frame.capability.clone(),
                adapter_kind: "edge-member".to_string(),
            }))
        }
        SwarmFrameKind::ProjectionSnapshot | SwarmFrameKind::ProjectionDelta => {
            Some(ServiceBridgeRecord::Projection(ProjectionBridge {
                frame_id: frame.frame_id.clone(),
                channel_id: frame.channel_id.clone(),
                projection_ref: frame.record_ref.as_ref().map(|record| record.id.clone()),
                delta: matches!(frame.kind, SwarmFrameKind::ProjectionDelta),
            }))
        }
        SwarmFrameKind::StoragePinIntent | SwarmFrameKind::StoragePinAttestation => {
            Some(ServiceBridgeRecord::StoragePin(StoragePinBridge {
                frame_id: frame.frame_id.clone(),
                channel_id: frame.channel_id.clone(),
                pin_ref: frame.record_ref.as_ref().map(|record| record.id.clone()),
                attestation: matches!(frame.kind, SwarmFrameKind::StoragePinAttestation),
            }))
        }
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct SwarmEdgeCore {
    gateway_pk: String,
    sessions: HashMap<String, SwarmEdgeSession>,
    replay: SwarmReplayGuard,
    planner: PropagationPlanner,
    responses: VecDeque<SwarmFrame>,
    nonce_seq: u64,
}

impl SwarmEdgeCore {
    pub fn new(gateway_pk: impl Into<String>, planner: PropagationPlanner) -> Self {
        Self {
            gateway_pk: gateway_pk.into(),
            sessions: HashMap::new(),
            replay: SwarmReplayGuard::new(),
            planner,
            responses: VecDeque::new(),
            nonce_seq: 0,
        }
    }

    pub fn attach(&mut self, hello: SwarmEdgeHello, now: u64) -> SwarmEdgeAttachResult {
        if let Err(err) = validate_swarm_edge_hello(&hello) {
            return SwarmEdgeAttachResult::Rejected(reject_result("invalid_hello", err));
        }
        if !hello
            .capability_refs
            .iter()
            .any(|capability| capability == CAPABILITY_SWARM_EDGE_ATTACH)
        {
            return SwarmEdgeAttachResult::Rejected(reject_result(
                "missing_swarm_edge_capability",
                anyhow!("swarm edge attach capability is required"),
            ));
        }
        if let Err(err) = self.replay.check_and_note_nonce(&hello.nonce) {
            return SwarmEdgeAttachResult::Rejected(reject_result("replay", err));
        }

        let session_id = format!("edge-{}-{}", hello.member_ref, hello.nonce);
        let session = SwarmEdgeSession {
            session_id: session_id.clone(),
            member_kind: hello.member_kind.clone(),
            member_ref: hello.member_ref.clone(),
            zone_scope: hello.zone_scope.clone(),
            last_acked_frame_id: hello.last_acked_frame_id.clone(),
            last_projection_revisions: hello.last_projection_revisions.clone(),
            capability_refs: hello.capability_refs.clone(),
            channel_refs: hello.channel_refs.clone(),
            promise_refs: hello.promise_refs.clone(),
            accepted_version: SWARM_FRAME_VERSION as u32,
            issued_at: hello.issued_at,
            expires_at: hello.expires_at,
        };
        self.nonce_seq += 1;
        let accept = SwarmEdgeAccept {
            session_id: session_id.clone(),
            member_kind: hello.member_kind,
            member_ref: hello.member_ref,
            zone_scope: hello.zone_scope,
            accepted_version: SWARM_FRAME_VERSION as u32,
            last_acked_frame_id: session.last_acked_frame_id.clone(),
            last_projection_revisions: session.last_projection_revisions.clone(),
            capability_refs: session.capability_refs.clone(),
            channel_refs: session.channel_refs.clone(),
            promise_refs: session.promise_refs.clone(),
            nonce: format!("edge-accept-{}", self.nonce_seq),
            issued_at: now,
            expires_at: session.expires_at,
            sealed_claims: hello.sealed_claims,
        };
        self.sessions.insert(session_id, session.clone());
        SwarmEdgeAttachResult::Accepted(SwarmEdgeAttach { accept, session })
    }

    pub fn resume(&mut self, resume: SwarmEdgeResume) -> SwarmEdgeResumeResult {
        if let Err(err) = validate_swarm_edge_resume(&resume) {
            return SwarmEdgeResumeResult::Rejected(reject_result("invalid_resume", err));
        }
        if let Err(err) = self.replay.check_and_note_nonce(&resume.nonce) {
            return SwarmEdgeResumeResult::Rejected(reject_result("replay", err));
        }
        let Some(session) = self.sessions.get_mut(&resume.session_id) else {
            return SwarmEdgeResumeResult::Rejected(reject_result(
                "unknown_session",
                anyhow!("swarm edge session is unknown"),
            ));
        };
        if session.member_kind != resume.member_kind || session.member_ref != resume.member_ref {
            return SwarmEdgeResumeResult::Rejected(reject_result(
                "member_mismatch",
                anyhow!("swarm edge resume member mismatch"),
            ));
        }
        session.last_acked_frame_id = resume.last_acked_frame_id;
        session.last_projection_revisions = resume.last_projection_revisions;
        session.zone_scope = resume.zone_scope;
        session.capability_refs = resume.capability_refs;
        session.channel_refs = resume.channel_refs;
        session.promise_refs = resume.promise_refs;
        session.issued_at = resume.issued_at;
        session.expires_at = resume.expires_at;
        SwarmEdgeResumeResult::Accepted(session.clone())
    }

    pub fn ingest_frame(
        &mut self,
        session_id: &str,
        frame: SwarmFrame,
        now: u64,
        hop_count: u8,
    ) -> SwarmFrameReceipt {
        if !self.sessions.contains_key(session_id) {
            return self.reject_frame(
                frame,
                now,
                "unknown_session",
                "swarm edge session is unknown",
            );
        }
        if let Err(err) = validate_swarm_frame(&frame, now) {
            return self.reject_frame(frame, now, "invalid_frame", &err.to_string());
        }
        if let Err(err) = self.replay.check_and_note_frame(&frame) {
            return self.reject_frame(frame, now, "replay", &err.to_string());
        }

        let plan = self.planner.plan_with_diagnostics(&frame, hop_count);
        let route_observation = route_observation_for_plan(
            &frame,
            now,
            &plan.targets,
            &plan.failed_predicates,
            &plan.candidate_members,
            plan.exhausted,
        );
        let route_observation_frames =
            vec![self.route_observation_frame(&frame, &route_observation, now)];
        let bridge = bridge_service_frame(&frame);
        let response = self.ack_frame(&frame, now);
        self.responses.push_back(response.clone());
        SwarmFrameReceipt {
            status: SwarmEdgeStatus::Accepted,
            response,
            propagation: plan.targets,
            route_observations: vec![route_observation],
            route_observation_frames,
            bridge,
        }
    }

    pub fn pop_response(&mut self) -> Option<SwarmFrame> {
        self.responses.pop_front()
    }

    pub fn session(&self, session_id: &str) -> Option<&SwarmEdgeSession> {
        self.sessions.get(session_id)
    }

    fn ack_frame(&mut self, frame: &SwarmFrame, now: u64) -> SwarmFrame {
        self.nonce_seq += 1;
        let mut response = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::Ack,
            issuer: self.gateway_pk.clone(),
            audience: json!({ "actorRef": frame.issuer }),
            zone_scope: None,
            issued_at: now,
            expires_at: None,
            nonce: format!("gateway-ack-{}", self.nonce_seq),
            correlation_id: Some(frame.frame_id.clone()),
            channel_id: frame.channel_id.clone(),
            record_ref: None,
            capability: None,
            body: sealed_runtime_body("ack"),
            ack: Some(SwarmAck {
                acked_frame_id: Some(frame.frame_id.clone()),
                retry_after_ms: None,
                gap_after_frame_ids: vec![],
                reason_code: None,
            }),
        };
        response.frame_id = swarm_frame_id(&response)
            .unwrap_or_else(|_| format!("ack-{}-{}", frame.frame_id, self.nonce_seq));
        response
    }

    fn reject_frame(
        &mut self,
        frame: SwarmFrame,
        now: u64,
        reason_code: &str,
        detail: &str,
    ) -> SwarmFrameReceipt {
        let route_observation = rejected_route_observation(&frame, now, reason_code, detail);
        let route_observation_frames = frame
            .zone_scope
            .as_ref()
            .map(|_| self.route_observation_frame(&frame, &route_observation, now))
            .into_iter()
            .collect::<Vec<_>>();
        self.nonce_seq += 1;
        let mut response = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::Reject,
            issuer: self.gateway_pk.clone(),
            audience: json!({ "actorRef": frame.issuer }),
            zone_scope: None,
            issued_at: now,
            expires_at: None,
            nonce: format!("gateway-reject-{}", self.nonce_seq),
            correlation_id: Some(frame.frame_id.clone()),
            channel_id: frame.channel_id.clone(),
            record_ref: None,
            capability: None,
            body: sealed_runtime_body("reject"),
            ack: Some(SwarmAck {
                acked_frame_id: None,
                retry_after_ms: None,
                gap_after_frame_ids: vec![],
                reason_code: Some(reason_code.to_string()),
            }),
        };
        response.frame_id = swarm_frame_id(&response)
            .unwrap_or_else(|_| format!("reject-{}-{}", frame.frame_id, self.nonce_seq));
        self.responses.push_back(response.clone());
        SwarmFrameReceipt {
            status: SwarmEdgeStatus::Rejected,
            response,
            propagation: vec![],
            route_observations: vec![route_observation],
            route_observation_frames,
            bridge: None,
        }
    }

    fn route_observation_frame(
        &mut self,
        source: &SwarmFrame,
        observation: &RouteObservation,
        now: u64,
    ) -> SwarmFrame {
        self.nonce_seq += 1;
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::RecordPublish,
            issuer: self.gateway_pk.clone(),
            audience: json!({ "actorRef": source.issuer }),
            zone_scope: source.zone_scope.clone(),
            issued_at: now,
            expires_at: Some(now.saturating_add(60_000)),
            nonce: format!("gateway-route-observation-{}", self.nonce_seq),
            correlation_id: Some(source.frame_id.clone()),
            channel_id: Some("swarm.route".to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: "route.observation".to_string(),
                id: observation.observation_id.clone(),
                revision: Some(now),
            }),
            capability: Some("route.observation.publish".to_string()),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: Some(json!({
                    "classification": "safe-route-observation",
                    "notCryptographicallySealed": true
                })),
                public_bootstrap: false,
                payload: Some(json!({ "record": observation })),
                signature: None,
            },
            ack: None,
        };
        frame.frame_id = swarm_frame_id(&frame)
            .unwrap_or_else(|_| format!("route-observation-{}", self.nonce_seq));
        frame
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmEdgePropagationTarget {
    pub member_ref: String,
    pub member_kind: SwarmEdgeMemberKind,
    pub zone_id: String,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SwarmEdgeFrameReceipt {
    pub status: SwarmEdgeStatus,
    pub response: SwarmFrame,
    pub propagation: Vec<SwarmEdgePropagationTarget>,
    pub route_observations: Vec<RouteObservation>,
    pub route_observation_frames: Vec<SwarmFrame>,
    pub bridge: Option<ServiceBridgeRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SwarmEdgeRecord {
    Frame(SwarmFrame),
    Unsupported { record_kind: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum SwarmEdgeIngressResult {
    Routed(SwarmEdgeFrameReceipt),
    Rejected(SwarmEdgeReject),
}

#[derive(Clone, Debug)]
pub struct SwarmEdgeHub {
    core: SwarmEdgeCore,
    member_kinds: HashMap<String, SwarmEdgeMemberKind>,
    session_kinds: HashMap<String, SwarmEdgeMemberKind>,
    active_sessions: HashSet<String>,
}

impl SwarmEdgeHub {
    pub fn new(gateway_pk: impl Into<String>, members: Vec<SwarmEdgeMember>) -> Self {
        let member_kinds = members
            .iter()
            .map(|member| (member.member_ref().to_string(), member.member_kind))
            .collect::<HashMap<_, _>>();
        let planner = PropagationPlanner::new(
            members
                .into_iter()
                .map(|member| member.member)
                .collect::<Vec<_>>(),
        );
        Self {
            core: SwarmEdgeCore::new(gateway_pk, planner),
            member_kinds,
            session_kinds: HashMap::new(),
            active_sessions: HashSet::new(),
        }
    }

    pub fn attach_member(
        &mut self,
        member_kind: SwarmEdgeMemberKind,
        hello: SwarmEdgeHello,
        now: u64,
    ) -> SwarmEdgeAttachResult {
        self.prune_expired_sessions(now);
        let route_member = SwarmRouteMember {
            member_ref: hello.member_ref.trim().to_string(),
            zone_id: hello.zone_scope.zone_id.trim().to_string(),
            channel_ids: hello.channel_refs.clone(),
            audience_refs: edge_member_audience_refs(hello.member_ref.trim(), &hello.promise_refs),
            capabilities: hello.capability_refs.clone(),
            interested: true,
            replicator: matches!(
                member_kind,
                SwarmEdgeMemberKind::Service | SwarmEdgeMemberKind::Gateway
            ),
        };
        match self.core.attach(hello, now) {
            SwarmEdgeAttachResult::Accepted(attach) => {
                self.retire_member_sessions_except(
                    route_member.member_ref.trim(),
                    attach.session.session_id.trim(),
                );
                self.member_kinds
                    .insert(route_member.member_ref.clone(), member_kind);
                self.core.planner.add_member_contribution(
                    format!("session:{}", attach.session.session_id.trim()),
                    "attachedSessionAdvertisement",
                    route_member,
                );
                self.session_kinds
                    .insert(attach.session.session_id.clone(), member_kind);
                self.active_sessions
                    .insert(attach.session.session_id.clone());
                SwarmEdgeAttachResult::Accepted(attach)
            }
            SwarmEdgeAttachResult::Rejected(reject) => SwarmEdgeAttachResult::Rejected(reject),
        }
    }

    pub fn resume_member(
        &mut self,
        member_kind: SwarmEdgeMemberKind,
        resume: SwarmEdgeResume,
    ) -> SwarmEdgeResumeResult {
        self.prune_expired_sessions(resume.issued_at);
        if let Some(existing) = self.session_kinds.get(&resume.session_id) {
            if *existing != member_kind {
                return SwarmEdgeResumeResult::Rejected(SwarmEdgeReject {
                    reason_code: "member_kind_mismatch".to_string(),
                    detail: "swarm edge resume member kind does not match attached session"
                        .to_string(),
                    correlation_id: Some(resume.session_id),
                });
            }
        }
        if self
            .core
            .session(&resume.session_id)
            .is_some_and(|session| session_is_expired(session, resume.issued_at))
        {
            return SwarmEdgeResumeResult::Rejected(SwarmEdgeReject {
                reason_code: "expired_session".to_string(),
                detail: "swarm edge resume cannot renew an expired session".to_string(),
                correlation_id: Some(resume.session_id),
            });
        }
        let session_id = resume.session_id.clone();
        let result = self.core.resume(resume);
        if let SwarmEdgeResumeResult::Accepted(session) = &result {
            self.core.planner.add_member_contribution(
                format!("session:{}", session.session_id.trim()),
                "attachedSessionAdvertisement",
                route_member_from_session(session, member_kind),
            );
            self.session_kinds.insert(session_id.clone(), member_kind);
            self.active_sessions.insert(session_id);
        }
        result
    }

    pub fn disconnect_session(&mut self, session_id: &str) {
        let session_id = session_id.trim();
        self.active_sessions.remove(session_id);
        self.core
            .planner
            .remove_member_contributions(&format!("session:{session_id}"));
    }

    fn retire_member_sessions_except(&mut self, member_ref: &str, keep_session_id: &str) {
        let member_ref = member_ref.trim();
        let keep_session_id = keep_session_id.trim();
        let retired = self
            .core
            .sessions
            .values()
            .filter(|session| session.member_ref.trim() == member_ref)
            .map(|session| session.session_id.clone())
            .filter(|session_id| session_id.trim() != keep_session_id)
            .collect::<Vec<_>>();
        for session_id in retired {
            self.active_sessions.remove(session_id.trim());
            self.session_kinds.remove(session_id.trim());
            self.core
                .planner
                .remove_member_contributions(&format!("session:{}", session_id.trim()));
        }
    }

    fn prune_expired_sessions(&mut self, now: u64) {
        let expired = self
            .core
            .sessions
            .values()
            .filter(|session| session_is_expired(session, now))
            .map(|session| session.session_id.clone())
            .collect::<Vec<_>>();
        for session_id in expired {
            self.disconnect_session(&session_id);
        }
    }

    pub fn is_active_session_for_member_at(
        &self,
        session_id: &str,
        member_ref: &str,
        now: u64,
    ) -> bool {
        let session_id = session_id.trim();
        let member_ref = member_ref.trim();
        self.active_sessions.contains(session_id)
            && self.core.session(session_id).is_some_and(|session| {
                session.member_ref.trim() == member_ref && !session_is_expired(session, now)
            })
    }

    pub fn is_active_session_for_member(&self, session_id: &str, member_ref: &str) -> bool {
        self.is_active_session_for_member_at(session_id, member_ref, 0)
    }

    pub fn ingest_swarm_frame(
        &mut self,
        session_id: &str,
        frame: SwarmFrame,
        now: u64,
        hop_count: u8,
    ) -> SwarmEdgeFrameReceipt {
        self.prune_expired_sessions(now);
        let receipt = self.core.ingest_frame(session_id, frame, now, hop_count);
        self.map_receipt(receipt)
    }

    pub fn ingest_record(
        &mut self,
        session_id: &str,
        record: SwarmEdgeRecord,
        now: u64,
        hop_count: u8,
    ) -> SwarmEdgeIngressResult {
        match record {
            SwarmEdgeRecord::Frame(frame) => SwarmEdgeIngressResult::Routed(
                self.ingest_swarm_frame(session_id, frame, now, hop_count),
            ),
            SwarmEdgeRecord::Unsupported { record_kind } => {
                SwarmEdgeIngressResult::Rejected(SwarmEdgeReject {
                    reason_code: "unsupported_edge_record".to_string(),
                    detail: format!(
                        "swarm edge hub routes SwarmFrame records only, got {record_kind}"
                    ),
                    correlation_id: None,
                })
            }
        }
    }

    pub fn pop_response(&mut self) -> Option<SwarmFrame> {
        self.core.pop_response()
    }

    pub fn session(&self, session_id: &str) -> Option<&SwarmEdgeSession> {
        self.core.session(session_id)
    }

    pub fn session_member_kind(&self, session_id: &str) -> Option<SwarmEdgeMemberKind> {
        self.session_kinds.get(session_id).copied()
    }

    pub fn directory_value(&self, now: u64) -> Value {
        let mut definitions = BTreeMap::<String, Value>::new();
        let mut channels = BTreeMap::<String, Value>::new();
        let mut policies = BTreeMap::<String, Value>::new();
        let mut advertisements = Vec::<Value>::new();
        let mut entries = Vec::<Value>::new();
        let mut sessions = self
            .core
            .sessions
            .values()
            .filter(|session| {
                self.active_sessions.contains(session.session_id.trim())
                    && !session_is_expired(session, now)
            })
            .cloned()
            .collect::<Vec<_>>();
        sessions.sort_by(|a, b| a.member_ref.cmp(&b.member_ref));

        for session in sessions {
            let member_ref = session.member_ref.trim();
            if member_ref.is_empty() {
                continue;
            }
            let promise_refs = unique_non_empty_strings(&session.promise_refs);
            let service_ref = promise_refs
                .iter()
                .find(|reference| reference.trim().starts_with("service:"))
                .cloned();
            let service_pk = service_pk_from_member_ref(member_ref);
            let mut capability_refs = session
                .capability_refs
                .iter()
                .map(|capability| capability.trim().to_string())
                .filter(|capability| !capability.is_empty())
                .collect::<Vec<_>>();
            capability_refs.sort();
            capability_refs.dedup();
            let mut channel_refs = session
                .channel_refs
                .iter()
                .map(|channel| channel.trim().to_string())
                .filter(|channel| !channel.is_empty())
                .collect::<Vec<_>>();
            channel_refs.sort();
            channel_refs.dedup();

            for capability in &capability_refs {
                definitions.entry(capability.clone()).or_insert_with(|| {
                    json!({
                        "capability": capability,
                        "definitionId": format!("capability-def-{}", slug(capability)),
                        "summary": format!("Live edge-advertised capability {capability}."),
                        "schema": {},
                        "authorityRefs": [format!("zone:{}", session.zone_scope.zone_id.trim())],
                        "authorityDomains": ["gateway", "service"],
                        "contractTruthSource": "attachedSessionAdvertisement",
                    })
                });
                advertisements.push(json!({
                    "advertisementId": format!("ad-{}-{}", slug(member_ref), slug(capability)),
                    "capability": capability,
                    "memberRef": member_ref,
                    "serviceRef": service_ref.as_deref(),
                    "servicePk": service_pk.as_deref(),
                    "promiseRefs": &promise_refs,
                    "zoneScope": &session.zone_scope,
                    "channelRefs": channel_refs,
                    "memberSource": "attachedSessionAdvertisement",
                    "authorityDomains": ["gateway", "service"],
                    "recordBackedMembership": false,
                    "issuedAt": now,
                    "expiresAt": now.saturating_add(90_000),
                }));
            }

            for channel_id in &channel_refs {
                let policy_id = format!("policy-{}", slug(channel_id));
                channels.entry(channel_id.clone()).or_insert_with(|| {
                    json!({
                        "channelId": channel_id,
                        "kind": "edge",
                        "displayName": channel_id,
                        "capabilities": capability_refs,
                        "recordKinds": ["swarm.frame"],
                        "ownerRefs": [member_ref],
                        "policyRef": policy_id,
                        "createdAt": now,
                    })
                });
                policies.entry(policy_id.clone()).or_insert_with(|| {
                    json!({
                        "policyId": policy_id,
                        "observe": [member_ref],
                        "write": [member_ref],
                        "set": [member_ref],
                        "invoke": [member_ref],
                        "pin": [member_ref],
                        "attest": [member_ref],
                        "run": [member_ref],
                    })
                });
                for capability in &capability_refs {
                    entries.push(json!({
                        "entryId": format!("entry-{}-{}-{}", slug(member_ref), slug(capability), slug(channel_id)),
                        "capability": capability,
                        "channelId": channel_id,
                        "memberRef": member_ref,
                        "serviceRef": service_ref.as_deref(),
                        "servicePk": service_pk.as_deref(),
                        "promiseRefs": &promise_refs,
                        "zoneScope": &session.zone_scope,
                        "memberSource": "attachedSessionAdvertisement",
                        "authorityDomains": ["gateway", "service"],
                        "recordBackedMembership": false,
                        "priority": 10,
                    }));
                }
            }
        }

        json!({
            "classification": {
                "directoryTruthSource": "attachedSessionAdvertisement",
                "attachedHelloBoundary": "attachedSessionObservation",
                "recordBackedMembership": false,
                "nostrBoundary": "bootstrapFallback",
            },
            "membershipTruth": [],
            "definitions": definitions.into_values().collect::<Vec<_>>(),
            "advertisements": advertisements,
            "entries": entries,
            "channels": channels.into_values().collect::<Vec<_>>(),
            "policies": policies.into_values().collect::<Vec<_>>(),
        })
    }

    pub fn directory_snapshot_frame(&self, request: &SwarmFrame, now: u64) -> SwarmFrame {
        let directory = self.directory_value(now);
        let directory_entry_count = directory["entries"]
            .as_array()
            .map(|entries| entries.len())
            .unwrap_or_default();
        let mut frame = SwarmFrame {
            version: SWARM_FRAME_VERSION,
            frame_id: String::new(),
            kind: SwarmFrameKind::BootstrapGatewayHint,
            issuer: self.core.gateway_pk.clone(),
            audience: json!({ "actorRef": request.issuer }),
            zone_scope: None,
            issued_at: now,
            expires_at: Some(now.saturating_add(60_000)),
            nonce: format!("gateway-directory-{}-{}", now, request.frame_id),
            correlation_id: request
                .correlation_id
                .clone()
                .or_else(|| Some(request.frame_id.clone())),
            channel_id: Some("swarm.directory".to_string()),
            record_ref: Some(SwarmRecordRef {
                kind: "structural.diagnostic".to_string(),
                id: "swarm.directory".to_string(),
                revision: Some(now),
            }),
            capability: Some(CAPABILITY_PROJECTION_OBSERVE.to_string()),
            body: SwarmFrameBody {
                encoding: "public".to_string(),
                envelope: None,
                public_bootstrap: true,
                payload: Some(json!({
                    "classification": "structuralDiagnostic",
                    "publicBootstrapSafe": true,
                    "membershipTruthSource": "none",
                    "attachedHelloBoundary": "attachedSessionObservation",
                    "snapshot": {
                        "projectionId": "swarm.directory",
                        "policyId": "swarm.directory.live",
                        "revision": now,
                        "state": { "directory": directory.clone() },
                        "coverage": {
                            "materializedCount": directory_entry_count,
                            "targetCount": directory_entry_count,
                            "completionRatio": 1,
                            "syncState": "completeEnough"
                        },
                        "freshness": { "state": "fresh", "updatedAt": now },
                        "sourceRefs": [self.core.gateway_pk.clone()],
                        "issuedAt": now,
                    }
                })),
                signature: None,
            },
            ack: None,
        };
        frame.frame_id =
            swarm_frame_id(&frame).unwrap_or_else(|_| format!("gateway-directory-{now}"));
        frame
    }

    pub fn member_written_observation_frame(
        &mut self,
        source: &SwarmFrame,
        target_member_ref: &str,
        now: u64,
    ) -> SwarmFrame {
        let observation = route_observation_for_member_write(source, target_member_ref, now);
        self.core.route_observation_frame(source, &observation, now)
    }

    fn map_receipt(&self, receipt: SwarmFrameReceipt) -> SwarmEdgeFrameReceipt {
        let propagation = receipt
            .propagation
            .into_iter()
            .map(|target| {
                let member_kind = *self
                    .member_kinds
                    .get(target.member_ref.trim())
                    .expect("swarm edge propagation target missing member kind");
                SwarmEdgePropagationTarget {
                    member_ref: target.member_ref,
                    member_kind,
                    zone_id: target.zone_id,
                    channel_ids: target.channel_ids,
                    capabilities: target.capabilities,
                }
            })
            .collect();
        SwarmEdgeFrameReceipt {
            status: receipt.status,
            response: receipt.response,
            propagation,
            route_observations: receipt.route_observations,
            route_observation_frames: receipt.route_observation_frames,
            bridge: receipt.bridge,
        }
    }
}

fn route_observation_for_plan(
    frame: &SwarmFrame,
    now: u64,
    targets: &[PropagationTarget],
    failed_predicates: &[RouteFailedPredicate],
    candidate_members: &[RouteCandidateDiagnostic],
    exhausted: bool,
) -> RouteObservation {
    let delivered_to = targets
        .iter()
        .map(|target| target.member_ref.clone())
        .collect::<Vec<_>>();
    let state = if !delivered_to.is_empty() {
        RouteObservationState::Delivered
    } else if exhausted {
        RouteObservationState::Expired
    } else {
        RouteObservationState::ObservingUnreachable
    };
    RouteObservation {
        observation_id: format!("route-observation-{}-{}", frame.frame_id, now),
        frame_id: frame.frame_id.clone(),
        correlation_id: frame.correlation_id.clone(),
        state,
        issued_at: now,
        channel_id: frame.channel_id.clone(),
        capability: frame.capability.clone(),
        delivered_to,
        failed_predicates: failed_predicates.to_vec(),
        authority_domains: route_authority_domains(),
        failed_authority_domains: failed_authority_domains(failed_predicates),
        candidate_members: candidate_members.to_vec(),
        detail: (!failed_predicates.is_empty())
            .then(|| "route predicates did not match a live member".to_string()),
    }
}

fn route_observation_for_member_write(
    frame: &SwarmFrame,
    target_member_ref: &str,
    now: u64,
) -> RouteObservation {
    RouteObservation {
        observation_id: format!("route-member-written-{}-{}", frame.frame_id, now),
        frame_id: frame.frame_id.clone(),
        correlation_id: frame.correlation_id.clone(),
        state: RouteObservationState::MemberWritten,
        issued_at: now,
        channel_id: frame.channel_id.clone(),
        capability: frame.capability.clone(),
        delivered_to: vec![target_member_ref.trim().to_string()]
            .into_iter()
            .filter(|entry| !entry.is_empty())
            .collect(),
        failed_predicates: vec![],
        authority_domains: route_authority_domains(),
        failed_authority_domains: vec![],
        candidate_members: vec![],
        detail: Some("gateway wrote frame to selected member socket".to_string()),
    }
}

fn rejected_route_observation(
    frame: &SwarmFrame,
    now: u64,
    reason_code: &str,
    detail: &str,
) -> RouteObservation {
    let predicates = rejection_failed_predicates(reason_code, detail);
    let failed_authority_domains = failed_authority_domains(&predicates);
    let state = if predicates
        .iter()
        .any(|predicate| matches!(predicate, RouteFailedPredicate::ExpiredFrame))
    {
        RouteObservationState::Expired
    } else {
        RouteObservationState::Rejected
    };
    RouteObservation {
        observation_id: format!("route-observation-{}-{}", frame.frame_id, now),
        frame_id: frame.frame_id.clone(),
        correlation_id: frame.correlation_id.clone(),
        state,
        issued_at: now,
        channel_id: frame.channel_id.clone(),
        capability: frame.capability.clone(),
        delivered_to: vec![],
        failed_predicates: predicates,
        authority_domains: route_authority_domains(),
        failed_authority_domains,
        candidate_members: vec![],
        detail: Some(format!("{reason_code}: {detail}")),
    }
}

fn route_authority_domains() -> Vec<String> {
    ["identity", "gateway", "service", "runtime"]
        .into_iter()
        .map(ToString::to_string)
        .collect()
}

fn failed_authority_domains(predicates: &[RouteFailedPredicate]) -> Vec<String> {
    let mut domains = predicates
        .iter()
        .map(route_failed_predicate_authority_domain)
        .filter(|domain| !domain.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

fn route_failed_predicate_authority_domain(predicate: &RouteFailedPredicate) -> &'static str {
    match predicate {
        RouteFailedPredicate::MissingZone
        | RouteFailedPredicate::TtlExhausted
        | RouteFailedPredicate::HopBudgetExhausted
        | RouteFailedPredicate::NoMemberInZone
        | RouteFailedPredicate::UnknownSession
        | RouteFailedPredicate::InvalidFrame
        | RouteFailedPredicate::ExpiredFrame
        | RouteFailedPredicate::ReplayedFrame => "gateway",
        RouteFailedPredicate::NoMemberForChannel
        | RouteFailedPredicate::NoMemberForCapability
        | RouteFailedPredicate::NoInterestedMember => "service",
        RouteFailedPredicate::AudienceMemberMismatch => "identity",
    }
}

fn rejection_failed_predicates(reason_code: &str, detail: &str) -> Vec<RouteFailedPredicate> {
    match reason_code {
        "unknown_session" => vec![RouteFailedPredicate::UnknownSession],
        "replay" => vec![RouteFailedPredicate::ReplayedFrame],
        "invalid_frame" if detail.contains("expired") => vec![RouteFailedPredicate::ExpiredFrame],
        "invalid_frame" if detail.contains("missing zoneScope") => {
            vec![RouteFailedPredicate::MissingZone]
        }
        "invalid_frame" => vec![RouteFailedPredicate::InvalidFrame],
        _ => vec![RouteFailedPredicate::InvalidFrame],
    }
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn reject_result(reason_code: &str, err: anyhow::Error) -> SwarmEdgeReject {
    SwarmEdgeReject {
        reason_code: reason_code.to_string(),
        detail: err.to_string(),
        correlation_id: None,
    }
}

fn sealed_runtime_body(envelope_id: &str) -> SwarmFrameBody {
    SwarmFrameBody {
        encoding: "caac".to_string(),
        envelope: Some(json!({ "envelopeId": envelope_id })),
        public_bootstrap: false,
        payload: None,
        signature: None,
    }
}

fn session_is_expired(session: &SwarmEdgeSession, now: u64) -> bool {
    session
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
}

fn route_member_from_session(
    session: &SwarmEdgeSession,
    member_kind: SwarmEdgeMemberKind,
) -> SwarmRouteMember {
    SwarmRouteMember {
        member_ref: session.member_ref.trim().to_string(),
        zone_id: session.zone_scope.zone_id.trim().to_string(),
        channel_ids: session.channel_refs.clone(),
        audience_refs: edge_member_audience_refs(session.member_ref.trim(), &session.promise_refs),
        capabilities: session.capability_refs.clone(),
        interested: true,
        replicator: matches!(
            member_kind,
            SwarmEdgeMemberKind::Service | SwarmEdgeMemberKind::Gateway
        ),
    }
}

fn edge_member_audience_refs(member_ref: &str, promise_refs: &[String]) -> Vec<String> {
    let mut refs = Vec::new();
    push_unique_audience_ref(&mut refs, member_ref);
    for promise_ref in promise_refs {
        push_unique_audience_ref(&mut refs, promise_ref);
    }
    refs
}

fn service_pk_from_member_ref(member_ref: &str) -> Option<String> {
    let text = member_ref.trim();
    let candidate = text
        .strip_prefix("service:")
        .unwrap_or(text)
        .rsplit(':')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    (!candidate.is_empty()).then(|| candidate.to_string())
}

fn push_unique_audience_ref(refs: &mut Vec<String>, value: &str) {
    push_unique_text(refs, value);
}

fn unique_non_empty_strings(values: &[String]) -> Vec<String> {
    let mut refs = Vec::new();
    for value in values {
        push_unique_text(&mut refs, value);
    }
    refs
}

fn push_unique_text(refs: &mut Vec<String>, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() || refs.iter().any(|existing| existing == trimmed) {
        return;
    }
    refs.push(trimmed.to_string());
}

fn audience_refs(value: &Value) -> HashSet<&str> {
    let mut refs = HashSet::new();
    collect_audience_refs(value, &mut refs);
    refs
}

fn collect_audience_refs<'a>(value: &'a Value, refs: &mut HashSet<&'a str>) {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                refs.insert(trimmed);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_audience_refs(item, refs);
            }
        }
        Value::Object(map) => {
            for key in [
                "actorRef",
                "memberRef",
                "serviceRef",
                "servicePk",
                "recipientServicePk",
                "deviceRef",
            ] {
                if let Some(Value::String(text)) = map.get(key) {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        refs.insert(trimmed);
                    }
                }
            }
            if let Some(refs_value) = map.get("refs") {
                collect_audience_refs(refs_value, refs);
            }
        }
        _ => {}
    }
}

fn audience_ref(value: &Value, key: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|map| map.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}
