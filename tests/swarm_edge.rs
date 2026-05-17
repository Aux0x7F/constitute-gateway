use constitute_gateway::swarm_edge::{
    PropagationPlanner, RouteFailedPredicate, RouteObservationState, ServiceBridgeRecord,
    SwarmEdgeAttachResult, SwarmEdgeCore, SwarmEdgeHub, SwarmEdgeIngressResult, SwarmEdgeMember,
    SwarmEdgeMemberKind, SwarmEdgeRecord, SwarmEdgeResumeResult, SwarmEdgeStatus, SwarmRouteMember,
};
use constitute_protocol::{
    swarm_frame_id, SwarmEdgeAccept, SwarmEdgeHello, SwarmEdgeResume, SwarmFrame, SwarmFrameBody,
    SwarmFrameKind, SwarmRecordRef, ZoneScope, CAPABILITY_MEDIA_STREAM_PREVIEW,
    CAPABILITY_PROJECTION_OBSERVE, CAPABILITY_SERVICE_INTENT_INVOKE,
    CAPABILITY_STREAM_SESSION_OFFER, CAPABILITY_SWARM_EDGE_ATTACH, SWARM_FRAME_VERSION,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::time::Duration;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const NOW: u64 = 1_700_000_001_000;
const BROWSER_PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SERVICE_PK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CLI_PK: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const AUTHORIZED_PK: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const WRONG_ZONE_PK: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const WRONG_CHANNEL_PK: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const WRONG_CAPABILITY_PK: &str =
    "9999999999999999999999999999999999999999999999999999999999999999";
const LOGGING_SERVICE_PK: &str = "7777777777777777777777777777777777777777777777777777777777777777";
const OTHER_SERVICE_REF: &str = "service:other";
const SERVICE_REF: &str =
    "service:nvr:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const LOGGING_SERVICE_REF: &str =
    "service:logging:7777777777777777777777777777777777777777777777777777777777777777";

fn sealed_body() -> SwarmFrameBody {
    SwarmFrameBody {
        encoding: "caac".to_string(),
        envelope: Some(json!({ "envelopeId": "env-1" })),
        public_bootstrap: false,
        payload: None,
        signature: None,
    }
}

fn hello() -> SwarmEdgeHello {
    SwarmEdgeHello {
        member_kind: "browser-runtime".to_string(),
        member_ref: BROWSER_PK.to_string(),
        zone_scope: ZoneScope {
            zone_id: "zone-a".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(4),
            max_hops: Some(2),
        },
        supported_versions: vec![SWARM_FRAME_VERSION as u32],
        last_acked_frame_id: None,
        last_projection_revisions: json!({}),
        capability_refs: vec![CAPABILITY_SWARM_EDGE_ATTACH.to_string()],
        channel_refs: vec!["nvr.control".to_string()],
        promise_refs: vec![],
        nonce: "hello-nonce-1".to_string(),
        issued_at: NOW,
        expires_at: Some(NOW + 90_000),
        sealed_claims: sealed_body(),
    }
}

fn hello_for(member_kind: &str, member_pk: &str, nonce: &str) -> SwarmEdgeHello {
    let mut hello = hello();
    hello.member_kind = member_kind.to_string();
    hello.member_ref = member_pk.to_string();
    hello.nonce = nonce.to_string();
    hello
}

fn resume_for(
    session_id: &str,
    member_kind: &str,
    member_ref: &str,
    nonce: &str,
) -> SwarmEdgeResume {
    SwarmEdgeResume {
        session_id: session_id.to_string(),
        member_kind: member_kind.to_string(),
        member_ref: member_ref.to_string(),
        zone_scope: ZoneScope {
            zone_id: "zone-a".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(4),
            max_hops: Some(2),
        },
        last_acked_frame_id: Some("frame-before-resume".to_string()),
        last_projection_revisions: json!({ "gateway.health": 4 }),
        capability_refs: vec![CAPABILITY_SWARM_EDGE_ATTACH.to_string()],
        channel_refs: vec!["nvr.control".to_string()],
        promise_refs: vec![],
        nonce: nonce.to_string(),
        issued_at: NOW + 1,
        expires_at: Some(NOW + 90_000),
        sealed_claims: sealed_body(),
    }
}

fn valid_frame(frame_id: &str, nonce: &str) -> SwarmFrame {
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ServiceIntent,
        issuer: BROWSER_PK.to_string(),
        audience: json!({ "serviceRef": SERVICE_REF }),
        zone_scope: Some(ZoneScope {
            zone_id: "zone-a".to_string(),
            privacy: Some("rawIds".to_string()),
            ttl: Some(4),
            max_hops: Some(2),
        }),
        issued_at: NOW - 1,
        expires_at: Some(NOW + 60_000),
        nonce: nonce.to_string(),
        correlation_id: Some(format!("corr-{frame_id}")),
        channel_id: Some("nvr.control".to_string()),
        record_ref: None,
        capability: Some(CAPABILITY_SERVICE_INTENT_INVOKE.to_string()),
        body: sealed_body(),
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame).unwrap_or_else(|_| frame_id.to_string());
    frame
}

fn observation_frame(receipt: &constitute_gateway::swarm_edge::SwarmFrameReceipt) -> &SwarmFrame {
    receipt
        .route_observation_frames
        .first()
        .expect("route observation frame")
}

fn refresh_frame_id(frame: &mut SwarmFrame) {
    frame.frame_id = swarm_frame_id(frame).expect("frame id");
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn harness() -> (SwarmEdgeCore, String) {
    let planner = PropagationPlanner::new(vec![
        SwarmRouteMember {
            member_ref: AUTHORIZED_PK.to_string(),
            zone_id: "zone-a".to_string(),
            channel_ids: vec!["nvr.control".to_string()],
            audience_refs: vec![SERVICE_REF.to_string()],
            capabilities: vec![CAPABILITY_SERVICE_INTENT_INVOKE.to_string()],
            interested: true,
            replicator: false,
        },
        SwarmRouteMember {
            member_ref: WRONG_ZONE_PK.to_string(),
            zone_id: "zone-b".to_string(),
            channel_ids: vec!["nvr.control".to_string()],
            audience_refs: vec![SERVICE_REF.to_string()],
            capabilities: vec![CAPABILITY_SERVICE_INTENT_INVOKE.to_string()],
            interested: true,
            replicator: false,
        },
        SwarmRouteMember {
            member_ref: WRONG_CHANNEL_PK.to_string(),
            zone_id: "zone-a".to_string(),
            channel_ids: vec!["logging.events".to_string()],
            audience_refs: vec![SERVICE_REF.to_string()],
            capabilities: vec![CAPABILITY_SERVICE_INTENT_INVOKE.to_string()],
            interested: true,
            replicator: false,
        },
        SwarmRouteMember {
            member_ref: WRONG_CAPABILITY_PK.to_string(),
            zone_id: "zone-a".to_string(),
            channel_ids: vec!["nvr.control".to_string()],
            audience_refs: vec![SERVICE_REF.to_string()],
            capabilities: vec!["projection.observe".to_string()],
            interested: true,
            replicator: false,
        },
    ]);
    let mut harness = SwarmEdgeCore::new("gateway-1", planner);
    let attach = harness.attach(hello(), NOW);
    let session_id = match attach {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("attach rejected: {reject:?}"),
    };
    (harness, session_id)
}

#[test]
fn accepts_valid_caac_swarm_frame_and_returns_ack() {
    let (mut harness, session_id) = harness();
    let frame = valid_frame("frame-1", "nonce-1");
    let expected_frame_id = frame.frame_id.clone();
    let receipt = harness.ingest_frame(&session_id, frame, NOW, 0);

    assert_eq!(receipt.status, SwarmEdgeStatus::Accepted);
    assert_eq!(receipt.response.kind, SwarmFrameKind::Ack);
    assert_eq!(
        receipt.response.correlation_id.as_deref(),
        Some(expected_frame_id.as_str())
    );
    assert_eq!(
        receipt
            .response
            .ack
            .as_ref()
            .and_then(|ack| ack.acked_frame_id.as_deref()),
        Some(expected_frame_id.as_str())
    );
}

#[test]
fn rejects_expired_missing_nonce_missing_zone_plaintext_and_replay() {
    let (mut harness, session_id) = harness();

    let mut expired = valid_frame("expired", "nonce-expired");
    expired.expires_at = Some(NOW - 1);
    let rejected = harness.ingest_frame(&session_id, expired, NOW, 0);
    assert_reject(rejected.clone(), "invalid_frame");
    assert_eq!(
        rejected.route_observations[0].state,
        RouteObservationState::Expired
    );
    assert_eq!(
        rejected.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::ExpiredFrame]
    );

    let mut missing_nonce = valid_frame("missing-nonce", "");
    missing_nonce.nonce.clear();
    refresh_frame_id(&mut missing_nonce);
    let rejected = harness.ingest_frame(&session_id, missing_nonce, NOW, 0);
    assert_reject(rejected.clone(), "invalid_frame");
    assert_eq!(
        rejected.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::InvalidFrame]
    );

    let mut missing_zone = valid_frame("missing-zone", "nonce-missing-zone");
    missing_zone.zone_scope = None;
    refresh_frame_id(&mut missing_zone);
    let rejected = harness.ingest_frame(&session_id, missing_zone, NOW, 0);
    assert_reject(rejected.clone(), "invalid_frame");
    assert_eq!(
        rejected.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::MissingZone]
    );

    let mut plaintext = valid_frame("plaintext", "nonce-plaintext");
    plaintext.body = SwarmFrameBody {
        encoding: "public".to_string(),
        envelope: None,
        public_bootstrap: false,
        payload: Some(json!({ "plain": true })),
        signature: None,
    };
    refresh_frame_id(&mut plaintext);
    let rejected = harness.ingest_frame(&session_id, plaintext, NOW, 0);
    assert_reject(rejected.clone(), "invalid_frame");
    assert_eq!(
        rejected.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::InvalidFrame]
    );

    let replay = valid_frame("frame-replay", "nonce-replay");
    assert_eq!(
        harness
            .ingest_frame(&session_id, replay.clone(), NOW, 0)
            .status,
        SwarmEdgeStatus::Accepted
    );
    let replay_reject = harness.ingest_frame(&session_id, replay, NOW, 0);
    assert_reject(replay_reject.clone(), "replay");
    assert_eq!(
        replay_reject.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::ReplayedFrame]
    );

    let repeated_nonce = valid_frame("frame-repeated-nonce", "nonce-replay");
    assert_reject(
        harness.ingest_frame(&session_id, repeated_nonce, NOW, 0),
        "replay",
    );
}

#[test]
fn planner_returns_only_authorized_members_and_respects_hop_budget() {
    let (mut harness, session_id) = harness();
    let receipt =
        harness.ingest_frame(&session_id, valid_frame("frame-plan", "nonce-plan"), NOW, 0);

    assert_eq!(receipt.status, SwarmEdgeStatus::Accepted);
    assert_eq!(receipt.propagation.len(), 1);
    assert_eq!(receipt.propagation[0].member_ref, AUTHORIZED_PK);
    assert_eq!(receipt.route_observations.len(), 1);
    assert_eq!(
        receipt.route_observations[0].state,
        RouteObservationState::Delivered
    );
    assert_eq!(
        receipt.route_observations[0].delivered_to,
        vec![AUTHORIZED_PK.to_string()]
    );
    assert_eq!(
        observation_frame(&receipt)
            .record_ref
            .as_ref()
            .map(|record| record.kind.as_str()),
        Some("route.observation")
    );

    let mut exhausted_frame = valid_frame("frame-plan-ttl", "nonce-plan-ttl");
    exhausted_frame.zone_scope.as_mut().unwrap().ttl = Some(2);
    refresh_frame_id(&mut exhausted_frame);
    let exhausted = harness.ingest_frame(&session_id, exhausted_frame, NOW, 2);
    assert_eq!(exhausted.status, SwarmEdgeStatus::Accepted);
    assert!(exhausted.propagation.is_empty());
    assert_eq!(
        exhausted.route_observations[0].state,
        RouteObservationState::Expired
    );
    assert!(exhausted.route_observations[0]
        .failed_predicates
        .contains(&RouteFailedPredicate::TtlExhausted));
    assert!(exhausted.route_observations[0]
        .failed_predicates
        .contains(&RouteFailedPredicate::HopBudgetExhausted));
}

#[test]
fn zero_propagation_emits_observing_unreachable_with_predicate_diagnostics() {
    let (mut harness, session_id) = harness();

    let mut no_zone_member = valid_frame("no-zone", "nonce-no-zone");
    no_zone_member.zone_scope.as_mut().unwrap().zone_id = "missing-zone".to_string();
    refresh_frame_id(&mut no_zone_member);
    let receipt = harness.ingest_frame(&session_id, no_zone_member, NOW, 0);
    assert_eq!(receipt.status, SwarmEdgeStatus::Accepted);
    assert!(receipt.propagation.is_empty());
    assert_eq!(
        receipt.route_observations[0].state,
        RouteObservationState::ObservingUnreachable
    );
    assert_eq!(
        receipt.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::NoMemberInZone]
    );
    assert!(receipt.route_observations[0]
        .authority_domains
        .contains(&"gateway".to_string()));
    assert_eq!(
        receipt.route_observations[0].failed_authority_domains,
        vec!["gateway".to_string()]
    );
    assert!(receipt.route_observations[0]
        .candidate_members
        .iter()
        .any(|candidate| candidate.member_ref == AUTHORIZED_PK
            && candidate.member_source == "recordBackedMembership"
            && candidate
                .failed_authority_domains
                .contains(&"gateway".to_string())
            && candidate
                .failed_predicates
                .contains(&RouteFailedPredicate::NoMemberInZone)));
    assert_eq!(receipt.response.kind, SwarmFrameKind::Ack);

    let mut wrong_channel = valid_frame("wrong-channel", "nonce-wrong-channel");
    wrong_channel.channel_id = Some("missing.channel".to_string());
    refresh_frame_id(&mut wrong_channel);
    let receipt = harness.ingest_frame(&session_id, wrong_channel, NOW, 0);
    assert_eq!(
        receipt.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::NoMemberForChannel]
    );
    assert_eq!(
        receipt.route_observations[0].failed_authority_domains,
        vec!["service".to_string()]
    );
    assert!(receipt.route_observations[0]
        .candidate_members
        .iter()
        .any(|candidate| candidate.member_ref == AUTHORIZED_PK
            && candidate
                .failed_predicates
                .contains(&RouteFailedPredicate::NoMemberForChannel)));

    let mut wrong_capability = valid_frame("wrong-capability", "nonce-wrong-capability");
    wrong_capability.capability = Some("missing.capability".to_string());
    refresh_frame_id(&mut wrong_capability);
    let receipt = harness.ingest_frame(&session_id, wrong_capability, NOW, 0);
    assert_eq!(
        receipt.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::NoMemberForCapability]
    );
    assert_eq!(
        receipt.route_observations[0].failed_authority_domains,
        vec!["service".to_string()]
    );
    assert!(receipt.route_observations[0]
        .candidate_members
        .iter()
        .any(|candidate| candidate.member_ref == AUTHORIZED_PK
            && candidate
                .failed_predicates
                .contains(&RouteFailedPredicate::NoMemberForCapability)));

    let mut wrong_audience = valid_frame("wrong-audience", "nonce-wrong-audience");
    wrong_audience.audience = json!({ "serviceRef": OTHER_SERVICE_REF });
    refresh_frame_id(&mut wrong_audience);
    let receipt = harness.ingest_frame(&session_id, wrong_audience, NOW, 0);
    assert_eq!(
        receipt.route_observations[0].failed_predicates,
        vec![RouteFailedPredicate::AudienceMemberMismatch]
    );
    assert_eq!(
        receipt.route_observations[0].failed_authority_domains,
        vec!["identity".to_string()]
    );
    assert!(receipt.route_observations[0]
        .candidate_members
        .iter()
        .any(|candidate| candidate.member_ref == AUTHORIZED_PK
            && candidate
                .failed_predicates
                .contains(&RouteFailedPredicate::AudienceMemberMismatch)));
}

#[test]
fn service_projection_and_storage_frames_emit_adapter_bridge_records() {
    let (mut harness, session_id) = harness();

    let service = harness.ingest_frame(&session_id, valid_frame("svc", "nonce-svc"), NOW, 0);
    match service.bridge {
        Some(ServiceBridgeRecord::ServiceIntent(bridge)) => {
            assert_eq!(bridge.service_ref, SERVICE_REF);
            assert_eq!(bridge.adapter_kind, "edge-member");
        }
        other => panic!("unexpected service bridge: {other:?}"),
    }

    let mut projection = valid_frame("projection", "nonce-projection");
    projection.kind = SwarmFrameKind::ProjectionDelta;
    projection.record_ref = Some(SwarmRecordRef {
        kind: "projection.delta".to_string(),
        id: "nvr.status".to_string(),
        revision: Some(7),
    });
    refresh_frame_id(&mut projection);
    let projection_receipt = harness.ingest_frame(&session_id, projection, NOW, 0);
    match projection_receipt.bridge {
        Some(ServiceBridgeRecord::Projection(bridge)) => {
            assert!(bridge.delta);
            assert_eq!(bridge.projection_ref.as_deref(), Some("nvr.status"));
        }
        other => panic!("unexpected projection bridge: {other:?}"),
    }

    let mut storage = valid_frame("pin", "nonce-pin");
    storage.kind = SwarmFrameKind::StoragePinIntent;
    storage.record_ref = Some(SwarmRecordRef {
        kind: "storage.pin.intent".to_string(),
        id: "pin-1".to_string(),
        revision: None,
    });
    refresh_frame_id(&mut storage);
    let storage_receipt = harness.ingest_frame(&session_id, storage, NOW, 0);
    match storage_receipt.bridge {
        Some(ServiceBridgeRecord::StoragePin(bridge)) => {
            assert!(!bridge.attestation);
            assert_eq!(bridge.pin_ref.as_deref(), Some("pin-1"));
        }
        other => panic!("unexpected storage bridge: {other:?}"),
    }
}

#[test]
fn swarm_edge_attach_rejects_replayed_nonce() {
    let planner = PropagationPlanner::default();
    let mut harness = SwarmEdgeCore::new("gateway-1", planner);

    assert!(matches!(
        harness.attach(hello(), NOW),
        SwarmEdgeAttachResult::Accepted(_)
    ));
    match harness.attach(hello(), NOW) {
        SwarmEdgeAttachResult::Rejected(reject) => assert_eq!(reject.reason_code, "replay"),
        SwarmEdgeAttachResult::Accepted(_) => panic!("expected replayed hello to reject"),
    }
}

#[test]
fn swarm_edge_hub_accepts_browser_service_cli_and_routes_only_swarm_frames() {
    let members = vec![
        SwarmEdgeMember::new(
            SwarmEdgeMemberKind::Browser,
            SwarmRouteMember {
                member_ref: BROWSER_PK.to_string(),
                zone_id: "zone-a".to_string(),
                channel_ids: vec!["nvr.control".to_string()],
                audience_refs: vec![BROWSER_PK.to_string()],
                capabilities: vec![CAPABILITY_SERVICE_INTENT_INVOKE.to_string()],
                interested: true,
                replicator: false,
            },
        ),
        SwarmEdgeMember::new(
            SwarmEdgeMemberKind::Service,
            SwarmRouteMember {
                member_ref: SERVICE_PK.to_string(),
                zone_id: "zone-a".to_string(),
                channel_ids: vec!["nvr.control".to_string()],
                audience_refs: vec![SERVICE_REF.to_string()],
                capabilities: vec![CAPABILITY_SERVICE_INTENT_INVOKE.to_string()],
                interested: true,
                replicator: false,
            },
        ),
        SwarmEdgeMember::new(
            SwarmEdgeMemberKind::Cli,
            SwarmRouteMember {
                member_ref: CLI_PK.to_string(),
                zone_id: "zone-a".to_string(),
                channel_ids: vec!["nvr.control".to_string()],
                audience_refs: vec![SERVICE_REF.to_string()],
                capabilities: vec![CAPABILITY_SERVICE_INTENT_INVOKE.to_string()],
                interested: true,
                replicator: true,
            },
        ),
    ];
    let mut hub = SwarmEdgeHub::new("gateway-1", members);

    let browser_session = match hub.attach_member(
        SwarmEdgeMemberKind::Browser,
        hello_for("browser-runtime", BROWSER_PK, "hello-browser"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("browser attach rejected: {reject:?}"),
    };
    let service_session = match hub.attach_member(
        SwarmEdgeMemberKind::Service,
        hello_for("service-runtime", SERVICE_PK, "hello-service"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("service attach rejected: {reject:?}"),
    };
    let cli_session = match hub.attach_member(
        SwarmEdgeMemberKind::Cli,
        hello_for("cli-runtime", CLI_PK, "hello-cli"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("cli attach rejected: {reject:?}"),
    };
    assert_eq!(
        hub.session_member_kind(&service_session),
        Some(SwarmEdgeMemberKind::Service)
    );
    assert!(hub.is_active_session_for_member(&service_session, SERVICE_PK));
    let next_service_session = match hub.attach_member(
        SwarmEdgeMemberKind::Service,
        hello_for("service-runtime", SERVICE_PK, "hello-service-next"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => {
            panic!("replacement service attach rejected: {reject:?}")
        }
    };
    assert!(!hub.is_active_session_for_member(&service_session, SERVICE_PK));
    assert!(hub.is_active_session_for_member(&next_service_session, SERVICE_PK));

    let resumed = hub.resume_member(
        SwarmEdgeMemberKind::Cli,
        resume_for(&cli_session, "cli-runtime", CLI_PK, "resume-cli"),
    );
    let resumed_session = match resumed {
        SwarmEdgeResumeResult::Accepted(session) => session,
        SwarmEdgeResumeResult::Rejected(reject) => panic!("resume rejected: {reject:?}"),
    };
    assert_eq!(
        resumed_session.last_acked_frame_id.as_deref(),
        Some("frame-before-resume")
    );

    let frame = valid_frame("hub-frame", "hub-frame-nonce");
    let frame_id = frame.frame_id.clone();
    let routed = hub.ingest_record(
        &browser_session,
        SwarmEdgeRecord::Frame(frame.clone()),
        NOW,
        0,
    );
    let receipt = match routed {
        SwarmEdgeIngressResult::Routed(receipt) => receipt,
        SwarmEdgeIngressResult::Rejected(reject) => panic!("frame rejected: {reject:?}"),
    };
    assert_eq!(receipt.status, SwarmEdgeStatus::Accepted);
    assert_eq!(receipt.response.kind, SwarmFrameKind::Ack);
    assert_eq!(
        receipt.response.correlation_id.as_deref(),
        Some(frame_id.as_str())
    );
    assert!(receipt.propagation.iter().any(|target| {
        target.member_ref == SERVICE_PK && target.member_kind == SwarmEdgeMemberKind::Service
    }));
    assert!(receipt.propagation.iter().any(|target| {
        target.member_ref == CLI_PK && target.member_kind == SwarmEdgeMemberKind::Cli
    }));
    match receipt.bridge {
        Some(ServiceBridgeRecord::ServiceIntent(bridge)) => {
            assert_eq!(bridge.adapter_kind, "edge-member");
        }
        other => panic!("unexpected bridge: {other:?}"),
    }

    let replay = hub.ingest_swarm_frame(&browser_session, frame, NOW, 0);
    assert_reject(replay.into_swarm_core_like(), "replay");

    let mut invalid = valid_frame("hub-invalid", "hub-invalid-nonce");
    invalid.zone_scope = None;
    refresh_frame_id(&mut invalid);
    let rejected = hub.ingest_swarm_frame(&browser_session, invalid, NOW, 0);
    assert_reject(rejected.into_swarm_core_like(), "invalid_frame");

    let unsupported = hub.ingest_record(
        &browser_session,
        SwarmEdgeRecord::Unsupported {
            record_kind: "nostr.event".to_string(),
        },
        NOW,
        0,
    );
    match unsupported {
        SwarmEdgeIngressResult::Rejected(reject) => {
            assert_eq!(reject.reason_code, "unsupported_edge_record");
            assert!(reject.detail.contains("SwarmFrame"));
        }
        SwarmEdgeIngressResult::Routed(_) => panic!("unsupported record routed"),
    }
}

#[test]
fn service_edge_member_routes_raw_service_pk_audience() {
    let mut hub = SwarmEdgeHub::new("gateway-1", vec![]);
    let browser_session = match hub.attach_member(
        SwarmEdgeMemberKind::Browser,
        hello_for("browser-runtime", BROWSER_PK, "hello-browser-raw-service"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("browser attach rejected: {reject:?}"),
    };
    let mut service_hello = hello_for("service", SERVICE_PK, "hello-service-raw-service");
    service_hello.promise_refs = vec![SERVICE_REF.to_string()];
    service_hello.capability_refs = vec![
        CAPABILITY_SWARM_EDGE_ATTACH.to_string(),
        CAPABILITY_SERVICE_INTENT_INVOKE.to_string(),
    ];
    let _service_session = match hub.attach_member(SwarmEdgeMemberKind::Service, service_hello, NOW)
    {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("service attach rejected: {reject:?}"),
    };
    let mut frame = valid_frame("raw-service-pk", "raw-service-pk-nonce");
    frame.audience = json!({ "servicePk": SERVICE_PK });
    refresh_frame_id(&mut frame);

    let routed = hub.ingest_record(&browser_session, SwarmEdgeRecord::Frame(frame), NOW, 0);
    let receipt = match routed {
        SwarmEdgeIngressResult::Routed(receipt) => receipt,
        SwarmEdgeIngressResult::Rejected(reject) => panic!("frame rejected: {reject:?}"),
    };
    assert!(receipt.propagation.iter().any(|target| {
        target.member_ref == SERVICE_PK && target.member_kind == SwarmEdgeMemberKind::Service
    }));
}

#[test]
fn service_edge_member_expires_by_attach_lease() {
    let mut hub = SwarmEdgeHub::new("gateway-1", vec![]);
    let browser_session = match hub.attach_member(
        SwarmEdgeMemberKind::Browser,
        hello_for("browser-runtime", BROWSER_PK, "hello-browser-expiry"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("browser attach rejected: {reject:?}"),
    };
    let mut service_hello = hello_for("service", SERVICE_PK, "hello-service-expiry");
    service_hello.expires_at = Some(NOW + 10);
    service_hello.promise_refs = vec![SERVICE_REF.to_string()];
    service_hello.capability_refs = vec![
        CAPABILITY_SWARM_EDGE_ATTACH.to_string(),
        CAPABILITY_SERVICE_INTENT_INVOKE.to_string(),
    ];
    let service_session = match hub.attach_member(SwarmEdgeMemberKind::Service, service_hello, NOW)
    {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("service attach rejected: {reject:?}"),
    };
    assert!(hub.is_active_session_for_member_at(&service_session, SERVICE_PK, NOW));
    assert!(!hub.is_active_session_for_member_at(&service_session, SERVICE_PK, NOW + 11));

    let routed = hub.ingest_record(
        &browser_session,
        SwarmEdgeRecord::Frame(valid_frame("expired-service", "expired-service-nonce")),
        NOW + 11,
        0,
    );
    let receipt = match routed {
        SwarmEdgeIngressResult::Routed(receipt) => receipt,
        SwarmEdgeIngressResult::Rejected(reject) => panic!("frame rejected: {reject:?}"),
    };
    assert!(!receipt
        .propagation
        .iter()
        .any(|target| target.member_ref == SERVICE_PK));
    assert!(receipt
        .route_observations
        .iter()
        .any(|observation| observation.state == RouteObservationState::ObservingUnreachable));
}

#[test]
fn service_edge_member_routes_by_typed_service_pk_for_namespaced_member_ref() {
    let mut hub = SwarmEdgeHub::new("gateway-1", vec![]);
    let browser_session = match hub.attach_member(
        SwarmEdgeMemberKind::Browser,
        hello_for(
            "browser-runtime",
            BROWSER_PK,
            "hello-browser-namespaced-service",
        ),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("browser attach rejected: {reject:?}"),
    };
    let mut service_hello = hello_for(
        "service",
        LOGGING_SERVICE_PK,
        "hello-service-namespaced-service",
    );
    service_hello.promise_refs = vec![LOGGING_SERVICE_REF.to_string()];
    service_hello.capability_refs = vec![
        CAPABILITY_SWARM_EDGE_ATTACH.to_string(),
        CAPABILITY_SERVICE_INTENT_INVOKE.to_string(),
    ];
    service_hello.channel_refs = vec!["logging.events".to_string()];
    match hub.attach_member(SwarmEdgeMemberKind::Service, service_hello, NOW) {
        SwarmEdgeAttachResult::Accepted(_) => {}
        SwarmEdgeAttachResult::Rejected(reject) => panic!("service attach rejected: {reject:?}"),
    };
    let mut frame = valid_frame("namespaced-service-pk", "namespaced-service-pk-nonce");
    frame.channel_id = Some("logging.events".to_string());
    frame.audience = json!({ "servicePk": LOGGING_SERVICE_PK });
    refresh_frame_id(&mut frame);

    let routed = hub.ingest_record(&browser_session, SwarmEdgeRecord::Frame(frame), NOW, 0);
    let receipt = match routed {
        SwarmEdgeIngressResult::Routed(receipt) => receipt,
        SwarmEdgeIngressResult::Rejected(reject) => panic!("frame rejected: {reject:?}"),
    };
    assert!(receipt.propagation.iter().any(|target| {
        target.member_ref == LOGGING_SERVICE_PK
            && target.member_kind == SwarmEdgeMemberKind::Service
    }));
}

#[test]
fn live_directory_omits_disconnected_edge_sessions() {
    let mut hub = SwarmEdgeHub::new("gateway-1", vec![]);
    let cli_session = match hub.attach_member(
        SwarmEdgeMemberKind::Cli,
        hello_for("cli", CLI_PK, "hello-cli-live"),
        NOW,
    ) {
        SwarmEdgeAttachResult::Accepted(accepted) => accepted.session.session_id,
        SwarmEdgeAttachResult::Rejected(reject) => panic!("cli attach rejected: {reject:?}"),
    };
    let before = hub.directory_value(NOW);
    assert_eq!(
        before["classification"]["attachedHelloBoundary"],
        "attachedSessionObservation"
    );
    assert_eq!(
        before["classification"]["directoryTruthSource"],
        "attachedSessionAdvertisement"
    );
    assert_eq!(before["classification"]["recordBackedMembership"], false);
    assert!(before["membershipTruth"].as_array().unwrap().is_empty());
    assert!(before["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|ad| ad["memberRef"] == CLI_PK));
    assert!(before["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|ad| ad["memberRef"] == CLI_PK && ad["zoneScope"]["zoneId"] == "zone-a"));
    assert!(before["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|ad| ad["memberRef"] == CLI_PK
            && ad["memberSource"] == "attachedSessionAdvertisement"
            && ad["recordBackedMembership"] == false));
    assert!(before["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["memberRef"] == CLI_PK
            && entry["memberSource"] == "attachedSessionAdvertisement"
            && entry["authorityDomains"]
                .as_array()
                .unwrap()
                .iter()
                .any(|domain| domain == "gateway")));

    hub.disconnect_session(&cli_session);
    let after = hub.directory_value(NOW + 1);
    assert!(!after["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|ad| ad["memberRef"] == CLI_PK));

    let resumed = hub.resume_member(
        SwarmEdgeMemberKind::Cli,
        resume_for(&cli_session, "cli", CLI_PK, "resume-cli-live"),
    );
    assert!(matches!(resumed, SwarmEdgeResumeResult::Accepted(_)));
    let resumed_directory = hub.directory_value(NOW + 2);
    assert!(resumed_directory["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|ad| ad["memberRef"] == CLI_PK));
}

#[tokio::test]
async fn live_swarm_edge_socket_attaches_members_and_routes_frames() {
    let handle = constitute_gateway::swarm_edge_server::start(
        "127.0.0.1:0".to_string(),
        "gateway-1".to_string(),
    )
    .await
    .expect("edge server");
    let url = format!("ws://{}", handle.bind());

    let (service_ws, _) = connect_async(&url).await.expect("service connect");
    let (mut service_tx, mut service_rx) = service_ws.split();
    let mut service_hello = hello_for("service", SERVICE_PK, "hello-service");
    let service_issued_at = now_ms();
    service_hello.issued_at = service_issued_at;
    service_hello.expires_at = Some(service_issued_at + 60_000);
    service_hello.promise_refs = vec![SERVICE_REF.to_string()];
    service_hello
        .capability_refs
        .push(CAPABILITY_SERVICE_INTENT_INVOKE.to_string());
    service_tx
        .send(Message::Text(
            json!({ "type": "swarm.edge.hello", "hello": service_hello }).to_string(),
        ))
        .await
        .expect("service hello");
    let service_accept = service_rx
        .next()
        .await
        .expect("service response")
        .expect("service message")
        .into_text()
        .expect("service text");
    let service_accept_value = serde_json::from_str::<serde_json::Value>(&service_accept).unwrap();
    assert_eq!(service_accept_value["type"], "swarm.edge.accept");
    let service_accept_record: SwarmEdgeAccept =
        serde_json::from_value(service_accept_value["accept"].clone()).expect("service accept");
    let service_resume_issued_at = now_ms();
    let service_resume = SwarmEdgeResume {
        session_id: service_accept_record.session_id.clone(),
        member_kind: service_accept_record.member_kind.clone(),
        member_ref: service_accept_record.member_ref.clone(),
        zone_scope: service_accept_record.zone_scope.clone(),
        last_acked_frame_id: service_accept_record.last_acked_frame_id.clone(),
        last_projection_revisions: service_accept_record.last_projection_revisions.clone(),
        capability_refs: service_accept_record.capability_refs.clone(),
        channel_refs: service_accept_record.channel_refs.clone(),
        promise_refs: service_accept_record.promise_refs.clone(),
        nonce: "resume-service-live".to_string(),
        issued_at: service_resume_issued_at,
        expires_at: Some(service_resume_issued_at + 60_000),
        sealed_claims: sealed_body(),
    };
    service_tx
        .send(Message::Text(
            json!({ "type": "swarm.edge.resume", "resume": service_resume }).to_string(),
        ))
        .await
        .expect("service resume");
    let service_resume_accept = service_rx
        .next()
        .await
        .expect("service resume response")
        .expect("service resume message")
        .into_text()
        .expect("service resume text");
    let service_resume_accept_value =
        serde_json::from_str::<serde_json::Value>(&service_resume_accept).unwrap();
    assert_eq!(service_resume_accept_value["type"], "swarm.edge.accept");
    assert!(service_resume_accept_value.get("accept").is_some());
    assert!(service_resume_accept_value.get("session").is_some());
    assert_eq!(
        service_resume_accept_value["accept"]["sessionId"],
        json!(service_accept_record.session_id)
    );

    let (browser_ws, _) = connect_async(&url).await.expect("browser connect");
    let (mut browser_tx, mut browser_rx) = browser_ws.split();
    let mut browser_hello = hello();
    let browser_issued_at = now_ms();
    browser_hello.issued_at = browser_issued_at;
    browser_hello.expires_at = Some(browser_issued_at + 60_000);
    browser_tx
        .send(Message::Text(
            json!({ "type": "swarm.edge.hello", "hello": browser_hello }).to_string(),
        ))
        .await
        .expect("browser hello");
    let browser_accept = browser_rx
        .next()
        .await
        .expect("browser response")
        .expect("browser message")
        .into_text()
        .expect("browser text");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&browser_accept).unwrap()["type"],
        "swarm.edge.accept"
    );

    let mut directory_frame = valid_frame("live-directory", "live-directory-nonce");
    let directory_issued_at = now_ms();
    directory_frame.kind = SwarmFrameKind::ChannelObserve;
    directory_frame.audience = json!({ "directory": "capability" });
    directory_frame.channel_id = Some("swarm.directory".to_string());
    directory_frame.record_ref = Some(SwarmRecordRef {
        kind: "projection".to_string(),
        id: "swarm.directory".to_string(),
        revision: None,
    });
    directory_frame.capability = Some(CAPABILITY_PROJECTION_OBSERVE.to_string());
    directory_frame.issued_at = directory_issued_at;
    directory_frame.expires_at = Some(directory_issued_at + 60_000);
    refresh_frame_id(&mut directory_frame);
    browser_tx
        .send(Message::Text(
            json!({ "type": "swarm.frame", "frame": directory_frame }).to_string(),
        ))
        .await
        .expect("send directory observe");
    let directory_ack = browser_rx
        .next()
        .await
        .expect("browser directory ack")
        .expect("directory ack message")
        .into_text()
        .expect("directory ack text");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&directory_ack).unwrap()["frame"]["kind"],
        "ack"
    );
    let directory_observation = browser_rx
        .next()
        .await
        .expect("browser directory route observation")
        .expect("directory route observation message")
        .into_text()
        .expect("directory route observation text");
    let directory_observation_value: serde_json::Value =
        serde_json::from_str(&directory_observation).unwrap();
    assert_eq!(directory_observation_value["type"], "swarm.frame");
    assert_eq!(
        directory_observation_value["frame"]["recordRef"]["kind"],
        "route.observation"
    );
    let directory_delivery = browser_rx
        .next()
        .await
        .expect("browser directory delivery")
        .expect("directory delivery message")
        .into_text()
        .expect("directory delivery text");
    let directory_value: serde_json::Value = serde_json::from_str(&directory_delivery).unwrap();
    assert_eq!(directory_value["type"], "swarm.frame");
    assert_eq!(directory_value["frame"]["kind"], "bootstrap.gatewayHint");
    assert_eq!(
        directory_value["frame"]["body"]["encoding"], "public",
        "directory diagnostic must not use a CAAC-looking placeholder envelope"
    );
    assert_eq!(
        directory_value["frame"]["body"]["payload"]["classification"],
        "structuralDiagnostic"
    );
    let directory = &directory_value["frame"]["body"]["payload"]["snapshot"]["state"]["directory"];
    assert!(directory["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .any(|ad| ad["memberRef"] == SERVICE_PK));
    assert!(directory["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["channelId"] == "nvr.control"));

    let issued_at = now_ms();
    let mut frame = valid_frame("live-frame", "live-frame-nonce");
    frame.issuer = BROWSER_PK.to_string();
    frame.issued_at = issued_at;
    frame.expires_at = Some(issued_at + 60_000);
    refresh_frame_id(&mut frame);

    browser_tx
        .send(Message::Text(
            json!({ "type": "swarm.frame", "frame": frame }).to_string(),
        ))
        .await
        .expect("send frame");
    let browser_ack = browser_rx
        .next()
        .await
        .expect("browser ack")
        .expect("ack message")
        .into_text()
        .expect("ack text");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&browser_ack).unwrap()["frame"]["kind"],
        "ack"
    );
    let route_selected = browser_rx
        .next()
        .await
        .expect("browser route observation")
        .expect("route observation message")
        .into_text()
        .expect("route observation text");
    let route_selected_value: serde_json::Value = serde_json::from_str(&route_selected).unwrap();
    assert_eq!(route_selected_value["type"], "swarm.frame");
    assert_eq!(
        route_selected_value["frame"]["recordRef"]["kind"],
        "route.observation"
    );

    let service_delivery = service_rx
        .next()
        .await
        .expect("service delivery")
        .expect("delivery message")
        .into_text()
        .expect("delivery text");
    let value: serde_json::Value = serde_json::from_str(&service_delivery).unwrap();
    assert_eq!(value["type"], "swarm.frame");
    assert_eq!(value["frame"]["kind"], "service.intent");
    assert_eq!(value["frame"]["audience"]["serviceRef"], SERVICE_REF);
    let member_write = browser_rx
        .next()
        .await
        .expect("browser member write observation")
        .expect("member write observation message")
        .into_text()
        .expect("member write observation text");
    let member_write_value: serde_json::Value = serde_json::from_str(&member_write).unwrap();
    assert_eq!(member_write_value["type"], "swarm.frame");
    assert_eq!(
        member_write_value["frame"]["recordRef"]["kind"],
        "route.observation"
    );
    assert_eq!(
        member_write_value["frame"]["body"]["payload"]["record"]["state"],
        "memberWritten"
    );
    assert_eq!(
        member_write_value["frame"]["body"]["payload"]["record"]["deliveredTo"][0],
        SERVICE_PK
    );
}

#[tokio::test]
async fn live_swarm_edge_closes_silent_stream_member_after_write_witness_timeout() {
    let handle = constitute_gateway::swarm_edge_server::start(
        "127.0.0.1:0".to_string(),
        "gateway-1".to_string(),
    )
    .await
    .expect("edge server");
    let url = format!("ws://{}", handle.bind());

    let (service_ws, _) = connect_async(&url).await.expect("service connect");
    let (mut service_tx, mut service_rx) = service_ws.split();
    let mut service_hello = hello_for("service", SERVICE_PK, "hello-service-silent");
    let service_issued_at = now_ms();
    service_hello.issued_at = service_issued_at;
    service_hello.expires_at = Some(service_issued_at + 60_000);
    service_hello.promise_refs = vec![SERVICE_REF.to_string()];
    service_hello.channel_refs.push("nvr.streams".to_string());
    service_hello
        .capability_refs
        .push(CAPABILITY_STREAM_SESSION_OFFER.to_string());
    service_hello
        .capability_refs
        .push(CAPABILITY_MEDIA_STREAM_PREVIEW.to_string());
    service_tx
        .send(Message::Text(
            json!({ "type": "swarm.edge.hello", "hello": service_hello }).to_string(),
        ))
        .await
        .expect("service hello");
    let service_accept = service_rx
        .next()
        .await
        .expect("service response")
        .expect("service message")
        .into_text()
        .expect("service text");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&service_accept).unwrap()["type"],
        "swarm.edge.accept"
    );

    let (browser_ws, _) = connect_async(&url).await.expect("browser connect");
    let (mut browser_tx, mut browser_rx) = browser_ws.split();
    let mut browser_hello = hello();
    let browser_issued_at = now_ms();
    browser_hello.issued_at = browser_issued_at;
    browser_hello.expires_at = Some(browser_issued_at + 60_000);
    browser_hello.channel_refs.push("nvr.streams".to_string());
    browser_tx
        .send(Message::Text(
            json!({ "type": "swarm.edge.hello", "hello": browser_hello }).to_string(),
        ))
        .await
        .expect("browser hello");
    let browser_accept = browser_rx
        .next()
        .await
        .expect("browser response")
        .expect("browser message")
        .into_text()
        .expect("browser text");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&browser_accept).unwrap()["type"],
        "swarm.edge.accept"
    );

    let issued_at = now_ms();
    let mut frame = valid_frame("silent-stream-frame", "silent-stream-frame-nonce");
    frame.kind = SwarmFrameKind::StreamIntent;
    frame.issuer = BROWSER_PK.to_string();
    frame.issued_at = issued_at;
    frame.expires_at = Some(issued_at + 60_000);
    frame.channel_id = Some("nvr.streams".to_string());
    frame.record_ref = Some(SwarmRecordRef {
        kind: "stream.session.offer".to_string(),
        id: "silent-stream-offer".to_string(),
        revision: None,
    });
    frame.capability = Some(CAPABILITY_STREAM_SESSION_OFFER.to_string());
    refresh_frame_id(&mut frame);

    browser_tx
        .send(Message::Text(
            json!({ "type": "swarm.frame", "frame": frame }).to_string(),
        ))
        .await
        .expect("send stream frame");

    let browser_ack = browser_rx
        .next()
        .await
        .expect("browser ack")
        .expect("ack message")
        .into_text()
        .expect("ack text");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&browser_ack).unwrap()["frame"]["kind"],
        "ack"
    );
    let _route_observation = browser_rx
        .next()
        .await
        .expect("browser route observation")
        .expect("route observation message");

    let service_delivery = service_rx
        .next()
        .await
        .expect("service delivery")
        .expect("delivery message")
        .into_text()
        .expect("delivery text");
    let service_value: serde_json::Value = serde_json::from_str(&service_delivery).unwrap();
    assert_eq!(service_value["type"], "swarm.frame");
    assert_eq!(
        service_value["frame"]["capability"],
        CAPABILITY_STREAM_SESSION_OFFER
    );

    let member_write = browser_rx
        .next()
        .await
        .expect("browser member write observation")
        .expect("member write observation message")
        .into_text()
        .expect("member write observation text");
    let member_write_value: serde_json::Value = serde_json::from_str(&member_write).unwrap();
    assert_eq!(
        member_write_value["frame"]["body"]["payload"]["record"]["state"],
        "memberWritten"
    );

    let closed = tokio::time::timeout(Duration::from_millis(8_000), service_rx.next()).await;
    assert!(
        closed.is_ok(),
        "silent stream execution member should be closed after missing read witness"
    );
    match closed.expect("timeout already checked") {
        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
        Some(Ok(other)) => panic!("expected service socket close, got {other:?}"),
    }
}

#[test]
fn managed_retired_forwarding_urls_are_absent() {
    let managed = include_str!("../src/managed.rs");
    let swarm_edge = include_str!("../src/swarm_edge.rs");
    let probe = include_str!("../src/bin/swarm_edge_probe.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    let retired_access = ["/service", "-access/"].join("");
    let retired_exchange = ["/service", "-exchange"].join("");
    let retired_capability = ["service", "Capability"].join("");
    assert!(!managed.contains(&retired_access));
    assert!(!managed.contains(&retired_exchange));
    assert!(!managed.contains(&format!("\"{retired_capability}\"")));
    assert!(!swarm_edge.contains(&retired_exchange));
    assert!(!probe.contains(&retired_capability));
    assert!(!root.join("src/bin/mission_probe.rs").exists());
}

#[test]
fn nostr_shaped_records_are_quarantined_to_bootstrap_fallback_boundaries() {
    assert_eq!(
        constitute_gateway::swarm_store::SWARM_STORE_RECORD_BOUNDARY,
        "bootstrap-fallback"
    );
    assert_eq!(
        constitute_gateway::transport::MESH_RECORD_BOUNDARY,
        "bootstrap-fallback"
    );
    let swarm_edge = include_str!("../src/swarm_edge.rs");
    let swarm_edge_server = include_str!("../src/swarm_edge_server.rs");
    assert!(!swarm_edge.contains("NostrEvent"));
    assert!(!swarm_edge_server.contains("NostrEvent"));
}

fn assert_reject(receipt: constitute_gateway::swarm_edge::SwarmFrameReceipt, reason: &str) {
    assert_eq!(receipt.status, SwarmEdgeStatus::Rejected);
    assert_eq!(
        receipt
            .response
            .ack
            .as_ref()
            .and_then(|ack| ack.reason_code.as_deref()),
        Some(reason)
    );
}

trait SwarmCoreLikeReceipt {
    fn into_swarm_core_like(self) -> constitute_gateway::swarm_edge::SwarmFrameReceipt;
}

impl SwarmCoreLikeReceipt for constitute_gateway::swarm_edge::SwarmEdgeFrameReceipt {
    fn into_swarm_core_like(self) -> constitute_gateway::swarm_edge::SwarmFrameReceipt {
        constitute_gateway::swarm_edge::SwarmFrameReceipt {
            status: self.status,
            response: self.response,
            propagation: vec![],
            route_observations: self.route_observations,
            route_observation_frames: self.route_observation_frames,
            bridge: self.bridge,
        }
    }
}
