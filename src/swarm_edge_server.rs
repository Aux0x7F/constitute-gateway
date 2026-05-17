//! WebSocket binding for the generic swarm edge hub.
//!
//! The wire protocol accepts only edge control records and `SwarmFrame` records.
//! Service semantics stay inside attached edge members.

use anyhow::{anyhow, Context, Result};
use constitute_protocol::{
    SwarmEdgeAccept, SwarmEdgeHello, SwarmEdgeResume, SwarmFrame, CAPABILITY_MEDIA_STREAM_PREVIEW,
    CAPABILITY_STREAM_SESSION_OFFER,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};
use tokio::time::{interval, timeout, Duration, Instant, MissedTickBehavior};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use crate::swarm_edge::{
    SwarmEdgeAttachResult, SwarmEdgeHub, SwarmEdgeIngressResult, SwarmEdgeMemberKind,
    SwarmEdgeRecord, SwarmEdgeReject, SwarmEdgeResumeResult, SwarmEdgeSession,
};

const EDGE_WRITE_TIMEOUT_MS: u64 = 5_000;
const EDGE_READ_WITNESS_TIMEOUT_MS: u64 = 5_000;
const EDGE_READ_WITNESS_TICK_MS: u64 = 250;

#[derive(Clone)]
pub struct SwarmEdgeServerHandle {
    bind: SocketAddr,
    hub: Arc<Mutex<SwarmEdgeHub>>,
    deliveries: broadcast::Sender<EdgeDelivery>,
}

impl SwarmEdgeServerHandle {
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn hub(&self) -> Arc<Mutex<SwarmEdgeHub>> {
        Arc::clone(&self.hub)
    }

    pub fn delivery_count(&self) -> usize {
        self.deliveries.receiver_count()
    }
}

#[derive(Clone, Debug)]
struct EdgeDelivery {
    target_member_ref: String,
    frame: SwarmFrame,
    source_member_ref: Option<String>,
}

#[derive(Clone, Debug)]
struct PendingReadWitness {
    frame_id: String,
    started_at: Instant,
}

pub async fn start(bind: String, gateway_pk: String) -> Result<SwarmEdgeServerHandle> {
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind swarm edge on {bind}"))?;
    let local_addr = listener.local_addr()?;
    let hub = Arc::new(Mutex::new(SwarmEdgeHub::new(gateway_pk, vec![])));
    let (deliveries, _) = broadcast::channel(1024);
    spawn_listener(listener, local_addr, Arc::clone(&hub), deliveries.clone());
    Ok(SwarmEdgeServerHandle {
        bind: local_addr,
        hub,
        deliveries,
    })
}

fn spawn_listener(
    listener: TcpListener,
    bind: SocketAddr,
    hub: Arc<Mutex<SwarmEdgeHub>>,
    deliveries: broadcast::Sender<EdgeDelivery>,
) {
    tracing::info!(bind = %bind, "swarm edge ready");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let hub = Arc::clone(&hub);
                    let deliveries = deliveries.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_client(stream, addr, hub, deliveries).await {
                            tracing::warn!(client = %addr, error = %err, "swarm edge client error");
                        }
                    });
                }
                Err(err) => tracing::warn!(error = %err, "swarm edge accept failed"),
            }
        }
    });
}

async fn handle_client(
    stream: TcpStream,
    addr: SocketAddr,
    hub: Arc<Mutex<SwarmEdgeHub>>,
    deliveries: broadcast::Sender<EdgeDelivery>,
) -> Result<()> {
    let ws = accept_async(stream).await?;
    let (mut write, mut read) = ws.split();
    let mut inbound = deliveries.subscribe();
    let mut session_id = String::new();
    let mut member_ref = String::new();
    let mut member_kind = None;
    let mut pending_read_witness: Option<PendingReadWitness> = None;
    let mut read_witness_tick = interval(Duration::from_millis(EDGE_READ_WITNESS_TICK_MS));
    read_witness_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    tracing::info!(client = %addr, "swarm edge client connected");

    loop {
        tokio::select! {
            _ = read_witness_tick.tick(), if pending_read_witness.is_some() => {
                if let Some(pending) = pending_read_witness.as_ref() {
                    if pending.started_at.elapsed()
                        >= Duration::from_millis(EDGE_READ_WITNESS_TIMEOUT_MS)
                    {
                        tracing::warn!(
                            client = %addr,
                            member_ref = %member_ref,
                            session_id = %session_id,
                            frame_id = %pending.frame_id,
                            timeout_ms = EDGE_READ_WITNESS_TIMEOUT_MS,
                            "swarm edge delivery lacked member-read witness; closing stale session"
                        );
                        break;
                    }
                }
            }
            msg = read.next() => {
                let Some(msg) = msg else { break; };
                let msg = msg?;
                let Message::Text(text) = msg else {
                    if matches!(msg, Message::Close(_)) {
                        break;
                    }
                    continue;
                };
                if matches!(edge_record_type(&text).as_deref(), Some("swarm.frame")) {
                    if let Some(pending) = pending_read_witness.as_ref() {
                        if edge_frame_correlates_to(&text, &pending.frame_id) {
                            let pending = pending_read_witness.take().expect("pending witness exists");
                            tracing::debug!(
                                client = %addr,
                                member_ref = %member_ref,
                                session_id = %session_id,
                                frame_id = %pending.frame_id,
                                "swarm edge member-read witness observed"
                            );
                        }
                    }
                }
                let response = handle_wire_message(
                    &text,
                    &hub,
                    &deliveries,
                    &mut session_id,
                    &mut member_ref,
                    &mut member_kind,
                ).await;
                if let Some(response) = response {
                    match timeout(
                        Duration::from_millis(EDGE_WRITE_TIMEOUT_MS),
                        write.send(Message::Text(response.to_string())),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err.into()),
                        Err(_) => {
                            tracing::warn!(
                                client = %addr,
                                member_ref = %member_ref,
                                session_id = %session_id,
                                timeout_ms = EDGE_WRITE_TIMEOUT_MS,
                                "swarm edge control write timed out; closing session"
                            );
                            break;
                        }
                    }
                }
            }
            delivery = inbound.recv() => {
                match delivery {
                    Ok(delivery) if delivery.target_member_ref == member_ref => {
                        let now = now_millis();
                        let active_for_member = hub
                            .lock()
                            .await
                            .is_active_session_for_member_at(&session_id, &member_ref, now);
                        if !active_for_member {
                            tracing::info!(
                                client = %addr,
                                member_ref = %member_ref,
                                session_id = %session_id,
                                "swarm edge session superseded before delivery; closing stale writer"
                            );
                            break;
                        }
                        let outbound = json!({
                            "type": "swarm.frame",
                            "frame": delivery.frame,
                        });
                        match timeout(
                            Duration::from_millis(EDGE_WRITE_TIMEOUT_MS),
                            write.send(Message::Text(outbound.to_string())),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                if let Some(source_member_ref) = delivery.source_member_ref.as_deref() {
                                    if !source_member_ref.trim().is_empty()
                                        && source_member_ref.trim() != delivery.target_member_ref.trim()
                                    {
                                        let mut guard = hub.lock().await;
                                        let observation_frame = guard.member_written_observation_frame(
                                            &delivery.frame,
                                            &delivery.target_member_ref,
                                            now_millis(),
                                        );
                                        let _ = deliveries.send(EdgeDelivery {
                                            target_member_ref: source_member_ref.trim().to_string(),
                                            frame: observation_frame,
                                            source_member_ref: None,
                                        });
                                        if pending_read_witness.is_none()
                                            && frame_requires_member_read_witness(&delivery.frame)
                                        {
                                            pending_read_witness = Some(PendingReadWitness {
                                                frame_id: delivery.frame.frame_id.clone(),
                                                started_at: Instant::now(),
                                            });
                                        }
                                    }
                                }
                            }
                            Ok(Err(err)) => return Err(err.into()),
                            Err(_) => {
                                tracing::warn!(
                                    client = %addr,
                                    member_ref = %member_ref,
                                    session_id = %session_id,
                                    timeout_ms = EDGE_WRITE_TIMEOUT_MS,
                                    "swarm edge delivery write timed out; closing backpressured session"
                                );
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        }
    }

    if !session_id.trim().is_empty() {
        hub.lock().await.disconnect_session(&session_id);
    }
    tracing::info!(client = %addr, "swarm edge client disconnected");
    Ok(())
}

async fn handle_wire_message(
    text: &str,
    hub: &Arc<Mutex<SwarmEdgeHub>>,
    deliveries: &broadcast::Sender<EdgeDelivery>,
    session_id: &mut String,
    member_ref: &mut String,
    member_kind: &mut Option<SwarmEdgeMemberKind>,
) -> Option<Value> {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(err) => return Some(reject_value("invalid_json", err.into(), None)),
    };
    let record_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    match record_type {
        "swarm.edge.hello" => {
            let hello: SwarmEdgeHello = match parse_record_field(&value, "hello") {
                Ok(hello) => hello,
                Err(err) => return Some(reject_value("invalid_hello", err, None)),
            };
            let kind = edge_member_kind(&hello.member_kind);
            let mut guard = hub.lock().await;
            match guard.attach_member(kind, hello, now_millis()) {
                SwarmEdgeAttachResult::Accepted(attach) => {
                    *session_id = attach.session.session_id.clone();
                    *member_ref = attach.session.member_ref.clone();
                    *member_kind = Some(kind);
                    Some(json!({
                        "type": "swarm.edge.accept",
                        "accept": attach.accept,
                    }))
                }
                SwarmEdgeAttachResult::Rejected(reject) => {
                    Some(reject_wire_value("swarm.edge.reject", reject))
                }
            }
        }
        "swarm.edge.resume" => {
            let resume: SwarmEdgeResume = match parse_record_field(&value, "resume") {
                Ok(resume) => resume,
                Err(err) => return Some(reject_value("invalid_resume", err, None)),
            };
            let resume_accept_source = resume.clone();
            let kind = edge_member_kind(&resume.member_kind);
            let mut guard = hub.lock().await;
            match guard.resume_member(kind, resume) {
                SwarmEdgeResumeResult::Accepted(session) => {
                    let accept = accept_from_resumed_session(&session, resume_accept_source);
                    *session_id = session.session_id.clone();
                    *member_ref = session.member_ref.clone();
                    *member_kind = Some(kind);
                    Some(json!({
                        "type": "swarm.edge.accept",
                        "sessionId": session.session_id,
                        "accept": accept,
                        "session": session,
                    }))
                }
                SwarmEdgeResumeResult::Rejected(reject) => {
                    Some(reject_wire_value("swarm.edge.reject", reject))
                }
            }
        }
        "swarm.frame" => {
            if session_id.trim().is_empty() {
                return Some(reject_value(
                    "missing_session",
                    anyhow!("swarm edge hello required"),
                    None,
                ));
            }
            let frame: SwarmFrame = match parse_record_field(&value, "frame") {
                Ok(frame) => frame,
                Err(err) => return Some(reject_value("invalid_frame", err, None)),
            };
            let frame_for_delivery = frame.clone();
            let mut guard = hub.lock().await;
            let directory_observe = is_directory_observe(&frame_for_delivery);
            match guard.ingest_record(session_id, SwarmEdgeRecord::Frame(frame), now_millis(), 0) {
                SwarmEdgeIngressResult::Routed(receipt) => {
                    for target in &receipt.propagation {
                        let _ = deliveries.send(EdgeDelivery {
                            target_member_ref: target.member_ref.clone(),
                            frame: frame_for_delivery.clone(),
                            source_member_ref: Some(member_ref.clone()),
                        });
                    }
                    for observation_frame in &receipt.route_observation_frames {
                        let _ = deliveries.send(EdgeDelivery {
                            target_member_ref: member_ref.clone(),
                            frame: observation_frame.clone(),
                            source_member_ref: None,
                        });
                    }
                    if directory_observe {
                        let _ = deliveries.send(EdgeDelivery {
                            target_member_ref: member_ref.clone(),
                            frame: guard
                                .directory_snapshot_frame(&frame_for_delivery, now_millis()),
                            source_member_ref: None,
                        });
                    }
                    Some(json!({
                        "type": "swarm.frame",
                        "frame": receipt.response,
                        "propagation": receipt.propagation,
                        "routeObservations": receipt.route_observations,
                        "routeObservationFrames": receipt.route_observation_frames,
                        "bridge": receipt.bridge,
                    }))
                }
                SwarmEdgeIngressResult::Rejected(reject) => {
                    Some(reject_wire_value("swarm.edge.reject", reject))
                }
            }
        }
        other => Some(reject_value(
            "unsupported_edge_record",
            anyhow!(
                "swarm edge routes edge control records and SwarmFrame records only, got {other}"
            ),
            None,
        )),
    }
}

fn edge_record_type(text: &str) -> Option<String> {
    serde_json::from_str::<Value>(text).ok().and_then(|value| {
        value
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn edge_frame_correlates_to(text: &str, pending_frame_id: &str) -> bool {
    let pending_frame_id = pending_frame_id.trim();
    if pending_frame_id.is_empty() {
        return false;
    }
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return false;
    };
    let frame = value.get("frame").and_then(Value::as_object);
    let mut candidates = Vec::new();
    if let Some(frame) = frame {
        candidates.push(frame.get("correlationId"));
        candidates.push(frame.get("correlation_id"));
    }
    candidates
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .any(|candidate| candidate == pending_frame_id)
}

fn frame_requires_member_read_witness(frame: &SwarmFrame) -> bool {
    matches!(
        frame.capability.as_deref().map(str::trim),
        Some(CAPABILITY_STREAM_SESSION_OFFER | CAPABILITY_MEDIA_STREAM_PREVIEW)
    )
}

fn accept_from_resumed_session(
    session: &SwarmEdgeSession,
    resume: SwarmEdgeResume,
) -> SwarmEdgeAccept {
    SwarmEdgeAccept {
        session_id: session.session_id.clone(),
        member_kind: session.member_kind.clone(),
        member_ref: session.member_ref.clone(),
        zone_scope: session.zone_scope.clone(),
        accepted_version: session.accepted_version,
        last_acked_frame_id: session.last_acked_frame_id.clone(),
        last_projection_revisions: session.last_projection_revisions.clone(),
        capability_refs: session.capability_refs.clone(),
        channel_refs: session.channel_refs.clone(),
        promise_refs: session.promise_refs.clone(),
        nonce: format!("edge-resume-accept-{}", resume.nonce),
        issued_at: resume.issued_at,
        expires_at: session.expires_at,
        sealed_claims: resume.sealed_claims,
    }
}

fn is_directory_observe(frame: &SwarmFrame) -> bool {
    frame.channel_id.as_deref().map(str::trim) == Some("swarm.directory")
        || frame
            .record_ref
            .as_ref()
            .is_some_and(|record| record.id.trim() == "swarm.directory")
        || frame
            .audience
            .get("directory")
            .and_then(Value::as_str)
            .is_some_and(|value| value.trim() == "capability")
}

fn parse_record_field<T: serde::de::DeserializeOwned>(value: &Value, field: &str) -> Result<T> {
    let record = value
        .get(field)
        .cloned()
        .ok_or_else(|| anyhow!("wire record missing {field}"))?;
    serde_json::from_value(record).map_err(anyhow::Error::from)
}

fn edge_member_kind(value: &str) -> SwarmEdgeMemberKind {
    match value.trim() {
        "service" => SwarmEdgeMemberKind::Service,
        "cli" => SwarmEdgeMemberKind::Cli,
        "gateway" => SwarmEdgeMemberKind::Gateway,
        _ => SwarmEdgeMemberKind::Browser,
    }
}

fn reject_value(reason_code: &str, err: anyhow::Error, correlation_id: Option<String>) -> Value {
    reject_wire_value(
        "swarm.edge.reject",
        SwarmEdgeReject {
            reason_code: reason_code.to_string(),
            detail: err.to_string(),
            correlation_id,
        },
    )
}

fn reject_wire_value(record_type: &str, reject: SwarmEdgeReject) -> Value {
    json!({
        "type": record_type,
        "reasonCode": reject.reason_code,
        "detail": reject.detail,
        "correlationId": reject.correlation_id,
    })
}

fn now_millis() -> u64 {
    crate::util::now_unix_seconds().saturating_mul(1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use constitute_protocol::{SwarmFrameBody, SwarmFrameKind};

    fn test_frame(capability: Option<&str>) -> SwarmFrame {
        SwarmFrame {
            version: 1,
            frame_id: "offer-frame".to_string(),
            kind: SwarmFrameKind::StreamIntent,
            issuer: "issuer".to_string(),
            audience: json!({}),
            zone_scope: None,
            issued_at: 1,
            expires_at: None,
            nonce: "nonce".to_string(),
            correlation_id: None,
            channel_id: Some("nvr.streams".to_string()),
            record_ref: None,
            capability: capability.map(ToOwned::to_owned),
            body: SwarmFrameBody {
                encoding: "caac".to_string(),
                envelope: None,
                public_bootstrap: false,
                payload: None,
                signature: None,
            },
            ack: None,
        }
    }

    #[test]
    fn stream_execution_frames_require_member_read_witness() {
        assert!(frame_requires_member_read_witness(&test_frame(Some(
            CAPABILITY_STREAM_SESSION_OFFER
        ))));
        assert!(frame_requires_member_read_witness(&test_frame(Some(
            CAPABILITY_MEDIA_STREAM_PREVIEW
        ))));
        assert!(!frame_requires_member_read_witness(&test_frame(Some(
            "stream.session.answer"
        ))));
        assert!(!frame_requires_member_read_witness(&test_frame(None)));
    }

    #[test]
    fn edge_frame_witness_requires_matching_correlation() {
        let unrelated = json!({
            "type": "swarm.frame",
            "frame": {
                "frameId": "projection-frame",
                "correlationId": "projection-repair"
            }
        });
        let admission = json!({
            "type": "swarm.frame",
            "frame": {
                "frameId": "admission-frame",
                "correlationId": "offer-frame"
            }
        });

        assert!(!edge_frame_correlates_to(
            &unrelated.to_string(),
            "offer-frame"
        ));
        assert!(edge_frame_correlates_to(
            &admission.to_string(),
            "offer-frame"
        ));
    }
}
