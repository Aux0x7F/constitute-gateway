//! UDP transport primitives for gateway-to-gateway signaling.
//!
//! Includes peer handshake, zone-scoped record gossip, targeted record requests,
//! and bounded request forwarding (fanout + max hops).

use crate::nostr::NostrEvent;
use anyhow::Result;
use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint as QuinnEndpoint,
    ServerConfig as QuinnServerConfig,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Once};
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{interval, Duration, Instant};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const UDP_PROTOCOL_VERSION: u8 = 1;

#[derive(Clone, Debug, Default)]
pub struct UdpConfig {
    pub node_id: String,
    pub device_pk: String,
    pub zones: Vec<String>,
    pub peers: Vec<String>,
    pub handshake_interval: Duration,
    pub peer_timeout: Duration,
    pub max_packet_bytes: usize,
    pub rate_limit_per_sec: u32,
    pub request_fanout: usize,
    pub request_max_hops: u8,
    pub stun_servers: Vec<String>,
    pub stun_interval: Duration,
    pub swarm_endpoint_tx: Option<watch::Sender<String>>,
    pub inbound_tx: Option<mpsc::UnboundedSender<UdpInbound>>,
}

#[derive(Clone, Debug, Default)]
pub struct QuicConfig {
    pub node_id: String,
    pub device_pk: String,
    pub zones: Vec<String>,
    pub peers: Vec<String>,
    pub handshake_interval: Duration,
    pub peer_timeout: Duration,
    pub max_packet_bytes: usize,
    pub rate_limit_per_sec: u32,
    pub request_fanout: usize,
    pub request_max_hops: u8,
    pub inbound_tx: Option<mpsc::UnboundedSender<UdpInbound>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum UdpMessage {
    Hello {
        v: u8,
        node_id: String,
        device_pk: String,
        zones: Vec<String>,
        ts: u64,
    },
    Ack {
        v: u8,
        node_id: String,
        device_pk: String,
        zones: Vec<String>,
        ts: u64,
    },
    Record {
        v: u8,
        zone: String,
        record_type: String,
        event: NostrEvent,
        ts: u64,
    },
    RecordRequest {
        v: u8,
        zone: String,
        types: Vec<String>,
        #[serde(default)]
        identity_id: Option<String>,
        #[serde(default)]
        device_pk: Option<String>,
        #[serde(default)]
        dht_scope: Option<String>,
        #[serde(default)]
        dht_key: Option<String>,
        #[serde(default)]
        hops: u8,
        ts: u64,
    },
}

#[derive(Clone, Debug)]
pub enum UdpInbound {
    Record {
        zone: String,
        record_type: String,
        event: NostrEvent,
        from: SocketAddr,
    },
    RecordRequest {
        zone: String,
        types: Vec<String>,
        identity_id: Option<String>,
        device_pk: Option<String>,
        dht_scope: Option<String>,
        dht_key: Option<String>,
        hops: u8,
        from: SocketAddr,
    },
}

#[derive(Clone, Debug)]
enum UdpOutbound {
    Broadcast(UdpMessage),
    SendTo(SocketAddr, UdpMessage),
}

#[derive(Clone, Debug)]
struct PeerInfo {
    node_id: String,
    device_pk: String,
    zones: Vec<String>,
    last_seen: Instant,
    confirmed: bool,
    rate_window_start: Instant,
    rate_count: u32,
}

pub struct UdpHandle {
    table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    outbound: mpsc::UnboundedSender<UdpOutbound>,
    #[allow(dead_code)]
    task: tokio::task::JoinHandle<Result<()>>,
    request_fanout: usize,
    request_max_hops: u8,
}

impl UdpHandle {
    // === Peer and record operations used by main orchestration ===
    #[allow(dead_code)]
    pub fn stop(self) {
        self.task.abort();
    }
    #[allow(dead_code)]
    pub fn request_max_hops(&self) -> u8 {
        self.request_max_hops
    }
    #[allow(dead_code)]
    pub async fn confirmed_count(&self) -> usize {
        let guard = self.table.lock().await;
        guard.values().filter(|p| p.confirmed).count()
    }
    #[allow(dead_code)]
    pub async fn confirmed_peers(&self) -> Vec<SocketAddr> {
        let guard = self.table.lock().await;
        guard
            .iter()
            .filter_map(|(addr, info)| if info.confirmed { Some(*addr) } else { None })
            .collect()
    }

    pub async fn set_peers(&self, next: Vec<SocketAddr>) {
        let mut guard = self.peers.lock().await;
        *guard = next;
    }

    pub fn broadcast_record(&self, zone: &str, record_type: &str, event: NostrEvent) {
        let msg = UdpMessage::Record {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            record_type: record_type.to_string(),
            event,
            ts: now_ms(),
        };
        let _ = self.outbound.send(UdpOutbound::Broadcast(msg));
    }

    pub fn send_record_to(
        &self,
        addr: SocketAddr,
        zone: &str,
        record_type: &str,
        event: NostrEvent,
    ) {
        let msg = UdpMessage::Record {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            record_type: record_type.to_string(),
            event,
            ts: now_ms(),
        };
        let _ = self.outbound.send(UdpOutbound::SendTo(addr, msg));
    }

    pub fn request_records(&self, zone: &str, types: Vec<String>) {
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types,
            identity_id: None,
            device_pk: None,
            dht_scope: None,
            dht_key: None,
            hops: 0,
            ts: now_ms(),
        };
        let _ = self.outbound.send(UdpOutbound::Broadcast(msg));
    }

    pub async fn request_identity_record(&self, zone: &str, identity_id: &str) {
        let peers = self.select_peers(zone, Some(identity_id), None).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types: vec!["identity".to_string()],
            identity_id: Some(identity_id.to_string()),
            device_pk: None,
            dht_scope: None,
            dht_key: None,
            hops: 0,
            ts: now_ms(),
        };
        for peer in peers {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    pub async fn request_device_record(&self, zone: &str, device_pk: &str) {
        let peers = self.select_peers(zone, Some(device_pk), None).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types: vec!["device".to_string()],
            identity_id: None,
            device_pk: Some(device_pk.to_string()),
            dht_scope: None,
            dht_key: None,
            hops: 0,
            ts: now_ms(),
        };
        for peer in peers {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    pub async fn request_dht_record(&self, zone: &str, scope: &str, key: &str) {
        let lookup = format!("{}:{}", scope, key);
        let peers = self.select_peers(zone, Some(&lookup), None).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types: vec!["dht".to_string()],
            identity_id: None,
            device_pk: None,
            dht_scope: Some(scope.to_string()),
            dht_key: Some(key.to_string()),
            hops: 0,
            ts: now_ms(),
        };
        for peer in peers {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    pub async fn forward_record_request(
        &self,
        zone: &str,
        types: Vec<String>,
        identity_id: Option<String>,
        device_pk: Option<String>,
        dht_scope: Option<String>,
        dht_key: Option<String>,
        hops: u8,
        exclude: Option<SocketAddr>,
    ) {
        if hops > self.request_max_hops {
            return;
        }
        let dht_lookup = match (&dht_scope, &dht_key) {
            (Some(scope), Some(key)) if !scope.is_empty() && !key.is_empty() => {
                Some(format!("{}:{}", scope, key))
            }
            _ => None,
        };
        let key = identity_id
            .as_deref()
            .or(device_pk.as_deref())
            .or(dht_lookup.as_deref());
        let mut peers = self.select_peers(zone, key, exclude).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types,
            identity_id,
            device_pk,
            dht_scope,
            dht_key,
            hops,
            ts: now_ms(),
        };
        for peer in peers.drain(..) {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    // Same-zone peer preference with deterministic scoring for targeted lookups.
    async fn select_peers(
        &self,
        zone: &str,
        key: Option<&str>,
        exclude: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut scored: Vec<(SocketAddr, [u8; 32])> = {
            let guard = self.table.lock().await;
            guard
                .iter()
                .filter_map(|(addr, info)| {
                    if !info.confirmed || !info.zones.iter().any(|z| z == zone) {
                        return None;
                    }
                    if let Some(ex) = exclude {
                        if *addr == ex {
                            return None;
                        }
                    }
                    let score = if let Some(k) = key {
                        xor_distance(&key_bytes(k), &peer_bytes(&info.device_pk))
                    } else {
                        let zero = [0u8; 32];
                        zero
                    };
                    Some((*addr, score))
                })
                .collect()
        };

        if scored.is_empty() {
            let mut fallback = self.peers.lock().await.clone();
            if let Some(ex) = exclude {
                fallback.retain(|p| *p != ex);
            }
            if fallback.is_empty() {
                return Vec::new();
            }
            fallback.sort_by_key(|addr| addr.to_string());
            let fanout = self.request_fanout;
            if fanout == 0 || fanout >= fallback.len() {
                return fallback;
            }
            return fallback.into_iter().take(fanout).collect();
        }

        scored.sort_by(|a, b| a.1.cmp(&b.1));

        let fanout = self.request_fanout;
        let mut out = Vec::new();
        for (addr, _) in scored.into_iter() {
            out.push(addr);
            if fanout != 0 && out.len() >= fanout {
                break;
            }
        }
        out
    }
    #[allow(dead_code)]
    pub async fn broadcast_from_zone(&self, zone: &str, record_type: &str, event: NostrEvent) {
        let snapshot = { self.peers.lock().await.clone() };
        for addr in snapshot {
            self.send_record_to(addr, zone, record_type, event.clone());
        }
    }
}

#[allow(dead_code)]
pub async fn start_udp(bind: &str, cfg: UdpConfig) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    tracing::info!(bind = %bind, "udp listener ready");

    let resolved = resolve_peers(&cfg.peers).await;
    let peers = Arc::new(Mutex::new(resolved));
    let table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let (_out_tx, out_rx) = mpsc::unbounded_channel();

    run_udp_loop(socket, cfg, peers, table, out_rx).await
}

pub async fn start_udp_with_handle(bind: &str, cfg: UdpConfig) -> Result<UdpHandle> {
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    tracing::info!(bind = %bind, "udp listener ready");

    let resolved = resolve_peers(&cfg.peers).await;
    let peers = Arc::new(Mutex::new(resolved));
    let table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let table_clone = table.clone();
    let peers_clone = peers.clone();
    let socket_clone = socket.clone();
    let (out_tx, out_rx) = mpsc::unbounded_channel();

    let request_fanout = cfg.request_fanout;
    let request_max_hops = cfg.request_max_hops;
    let task = tokio::spawn(async move {
        run_udp_loop(socket_clone, cfg, peers_clone, table_clone, out_rx).await
    });

    Ok(UdpHandle {
        table,
        peers,
        outbound: out_tx,
        task,
        request_fanout,
        request_max_hops,
    })
}

// Main UDP loop: outbound send path, periodic tasks, and inbound dispatch.
async fn run_udp_loop(
    socket: Arc<UdpSocket>,
    cfg: UdpConfig,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    mut outbound_rx: mpsc::UnboundedReceiver<UdpOutbound>,
) -> Result<()> {
    let max_packet_bytes = cfg.max_packet_bytes.max(256).min(65507);
    let mut buf = vec![0u8; max_packet_bytes];
    let mut hello_tick = interval(cfg.handshake_interval.max(Duration::from_secs(1)));
    let mut prune_tick = interval(Duration::from_secs(5));
    let mut stun_tick = interval(cfg.stun_interval.max(Duration::from_secs(10)));

    let stun_addrs = resolve_stun_servers(&cfg.stun_servers).await;
    let mut stun_txid = random_txid();
    let mut last_public: Option<SocketAddr> = None;

    loop {
        tokio::select! {
            out = outbound_rx.recv() => {
                if let Some(msg) = out {
                    handle_outbound(&socket, &peers, msg, max_packet_bytes).await;
                }
            }
            _ = hello_tick.tick(), if cfg.handshake_interval.as_secs() > 0 => {
                let snapshot = {
                    let guard = peers.lock().await;
                    guard.clone()
                };
                if snapshot.is_empty() {
                    continue;
                }
                let msg = UdpMessage::Hello {
                    v: UDP_PROTOCOL_VERSION,
                    node_id: cfg.node_id.clone(),
                    device_pk: cfg.device_pk.clone(),
                    zones: cfg.zones.clone(),
                    ts: now_ms(),
                };
                let payload = serde_json::to_vec(&msg).unwrap_or_default();
                for peer in &snapshot {
                    if let Err(err) = socket.send_to(&payload, peer).await {
                        tracing::debug!(peer = %peer, error = %err, "udp hello send failed");
                    } else {
                        note_peer_outbound(&table, *peer, &cfg.node_id, &cfg.device_pk, &cfg.zones).await;
                    }
                }
            }
            _ = stun_tick.tick(), if cfg.stun_interval.as_secs() > 0 && !stun_addrs.is_empty() => {
                stun_txid = random_txid();
                let req = build_stun_request(stun_txid);
                for addr in &stun_addrs {
                    if let Err(err) = socket.send_to(&req, addr).await {
                        tracing::debug!(stun = %addr, error = %err, "stun request failed");
                    }
                }
            }
            _ = prune_tick.tick(), if cfg.peer_timeout.as_secs() > 0 => {
                let mut guard = table.lock().await;
                guard.retain(|_, info| info.last_seen.elapsed() <= cfg.peer_timeout);
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, from) = recv?;
                if len >= max_packet_bytes {
                    tracing::debug!(from = %from, len, "udp packet dropped (too large)");
                    continue;
                }
                let payload = &buf[..len];

                if let Some(mapped) = parse_stun_response(payload, stun_txid) {
                    if last_public != Some(mapped) {
                        last_public = Some(mapped);
                        if let Some(tx) = cfg.swarm_endpoint_tx.as_ref() {
                            let _ = tx.send(mapped.to_string());
                        }
                        tracing::info!(endpoint = %mapped, "stun mapped address");
                    }
                    continue;
                }

                if let Ok(msg) = serde_json::from_slice::<UdpMessage>(payload) {
                    handle_message(&socket, &table, from, msg, &cfg).await;
                } else {
                    tracing::debug!(from = %from, len, "udp packet ignored (non-json)");
                }
            }
        }
    }
}

async fn resolve_stun_servers(raw: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in raw {
        let s = server.trim();
        if s.is_empty() {
            continue;
        }
        let host = s.strip_prefix("stun:").unwrap_or(s);
        let host = host.strip_prefix("stuns:").unwrap_or(host);
        match lookup_host(host).await {
            Ok(addrs) => out.extend(addrs),
            Err(err) => tracing::warn!(stun = %server, error = %err, "stun resolve failed"),
        }
    }
    out
}

pub async fn probe_stun(stun_servers: &[String], timeout: Duration) -> Result<Option<SocketAddr>> {
    let addrs = resolve_stun_servers(stun_servers).await;
    if addrs.is_empty() {
        return Ok(None);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let txid = random_txid();
    let req = build_stun_request(txid);
    for addr in &addrs {
        let _ = socket.send_to(&req, addr).await;
    }

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _from))) => {
                if let Some(mapped) = parse_stun_response(&buf[..len], txid) {
                    return Ok(Some(mapped));
                }
            }
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => return Ok(None),
        }
    }
}

// Resolve configured peers defensively; invalid entries are logged and skipped.
pub async fn resolve_peers(raw: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for peer in raw {
        match lookup_host(peer).await {
            Ok(addrs) => out.extend(addrs),
            Err(err) => tracing::warn!(peer = %peer, error = %err, "udp peer resolve failed"),
        }
    }
    out
}

// Handles only version-compatible UDP messages and applies zone/rate checks.
async fn handle_message(
    socket: &UdpSocket,
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    from: SocketAddr,
    msg: UdpMessage,
    cfg: &UdpConfig,
) {
    match msg {
        UdpMessage::Hello {
            v,
            node_id,
            device_pk,
            zones,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            if !note_peer_inbound(
                table,
                from,
                node_id.clone(),
                device_pk.clone(),
                zones.clone(),
                false,
                cfg.rate_limit_per_sec,
            )
            .await
            {
                return;
            }
            let reply = UdpMessage::Ack {
                v: UDP_PROTOCOL_VERSION,
                node_id: cfg.node_id.clone(),
                device_pk: cfg.device_pk.clone(),
                zones: cfg.zones.clone(),
                ts: now_ms(),
            };
            send_message(
                socket,
                from,
                &reply,
                cfg.max_packet_bytes.max(256).min(65507),
            )
            .await;
        }
        UdpMessage::Ack {
            v,
            node_id,
            device_pk,
            zones,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            let _ = note_peer_inbound(
                table,
                from,
                node_id,
                device_pk,
                zones,
                true,
                cfg.rate_limit_per_sec,
            )
            .await;
        }
        UdpMessage::Record {
            v,
            zone,
            record_type,
            event,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            if !cfg.zones.iter().any(|z| z == &zone) {
                return;
            }
            if !crate::nostr::verify_event(&event).unwrap_or(false) {
                return;
            }
            if !note_peer_activity(table, from, cfg.rate_limit_per_sec).await {
                return;
            }
            if let Some(tx) = cfg.inbound_tx.as_ref() {
                let _ = tx.send(UdpInbound::Record {
                    zone,
                    record_type,
                    event,
                    from,
                });
            }
        }
        UdpMessage::RecordRequest {
            v,
            zone,
            types,
            identity_id,
            device_pk,
            dht_scope,
            dht_key,
            hops,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            if !cfg.zones.iter().any(|z| z == &zone) {
                return;
            }
            if !note_peer_activity(table, from, cfg.rate_limit_per_sec).await {
                return;
            }
            if let Some(tx) = cfg.inbound_tx.as_ref() {
                let _ = tx.send(UdpInbound::RecordRequest {
                    zone,
                    types,
                    identity_id,
                    device_pk,
                    dht_scope,
                    dht_key,
                    hops,
                    from,
                });
            }
        }
    }
}

async fn handle_outbound(
    socket: &UdpSocket,
    peers: &Arc<Mutex<Vec<SocketAddr>>>,
    msg: UdpOutbound,
    max_packet_bytes: usize,
) {
    match msg {
        UdpOutbound::Broadcast(inner) => {
            let snapshot = { peers.lock().await.clone() };
            for peer in snapshot {
                send_message(socket, peer, &inner, max_packet_bytes).await;
            }
        }
        UdpOutbound::SendTo(addr, inner) => {
            send_message(socket, addr, &inner, max_packet_bytes).await;
        }
    }
}

async fn send_message(
    socket: &UdpSocket,
    addr: SocketAddr,
    msg: &UdpMessage,
    max_packet_bytes: usize,
) {
    if let Ok(payload) = serde_json::to_vec(msg) {
        if payload.len() > max_packet_bytes {
            tracing::debug!(peer = %addr, len = payload.len(), "udp send skipped (too large)");
            return;
        }
        if let Err(err) = socket.send_to(&payload, addr).await {
            tracing::debug!(peer = %addr, error = %err, "udp send failed");
        }
    }
}

async fn note_peer_outbound(
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    addr: SocketAddr,
    node_id: &str,
    device_pk: &str,
    zones: &[String],
) {
    let mut guard = table.lock().await;
    let now = Instant::now();
    let entry = guard.entry(addr).or_insert_with(|| PeerInfo {
        node_id: node_id.to_string(),
        device_pk: device_pk.to_string(),
        zones: zones.to_vec(),
        last_seen: now,
        confirmed: false,
        rate_window_start: now,
        rate_count: 0,
    });
    entry.last_seen = Instant::now();
}

async fn note_peer_activity(
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    addr: SocketAddr,
    rate_limit_per_sec: u32,
) -> bool {
    let mut guard = table.lock().await;
    let now = Instant::now();
    let entry = guard.entry(addr).or_insert_with(|| PeerInfo {
        node_id: String::new(),
        device_pk: String::new(),
        zones: Vec::new(),
        last_seen: now,
        confirmed: false,
        rate_window_start: now,
        rate_count: 0,
    });

    if rate_limit_per_sec > 0 {
        if now.duration_since(entry.rate_window_start) >= Duration::from_secs(1) {
            entry.rate_window_start = now;
            entry.rate_count = 0;
        }
        entry.rate_count += 1;
        if entry.rate_count > rate_limit_per_sec {
            return false;
        }
    }

    entry.last_seen = now;
    true
}

async fn note_peer_inbound(
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    addr: SocketAddr,
    node_id: String,
    device_pk: String,
    zones: Vec<String>,
    confirmed: bool,
    rate_limit_per_sec: u32,
) -> bool {
    let mut guard = table.lock().await;
    let now = Instant::now();
    let entry = guard.entry(addr).or_insert_with(|| PeerInfo {
        node_id: node_id.clone(),
        device_pk: device_pk.clone(),
        zones: zones.clone(),
        last_seen: now,
        confirmed: false,
        rate_window_start: now,
        rate_count: 0,
    });

    if rate_limit_per_sec > 0 {
        if now.duration_since(entry.rate_window_start) >= Duration::from_secs(1) {
            entry.rate_window_start = now;
            entry.rate_count = 0;
        }
        entry.rate_count += 1;
        if entry.rate_count > rate_limit_per_sec {
            return false;
        }
    }

    let was_confirmed = entry.confirmed;
    entry.node_id = node_id;
    entry.device_pk = device_pk;
    entry.zones = zones;
    entry.last_seen = now;
    if confirmed {
        entry.confirmed = true;
    }

    if !was_confirmed && entry.confirmed {
        tracing::info!(peer = %addr, "udp peer confirmed");
    }
    true
}

fn build_stun_request(txid: [u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&txid);
    out
}

fn parse_stun_response(payload: &[u8], txid: [u8; 12]) -> Option<SocketAddr> {
    if payload.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
    let msg_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }
    if msg_type != STUN_BINDING_SUCCESS {
        return None;
    }
    if payload.len() < 20 + msg_len {
        return None;
    }
    if payload[8..20] != txid {
        return None;
    }

    let mut offset = 20;
    while offset + 4 <= payload.len() {
        let attr_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let attr_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        if offset + attr_len > payload.len() {
            break;
        }
        let attr = &payload[offset..offset + attr_len];
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            if let Some(addr) = parse_mapped_address(attr, true, txid) {
                return Some(addr);
            }
        }
        if attr_type == STUN_ATTR_MAPPED_ADDRESS {
            if let Some(addr) = parse_mapped_address(attr, false, txid) {
                return Some(addr);
            }
        }
        offset += attr_len;
        let pad = (4 - (attr_len % 4)) % 4;
        offset += pad;
    }
    None
}

fn parse_mapped_address(attr: &[u8], xor: bool, txid: [u8; 12]) -> Option<SocketAddr> {
    if attr.len() < 4 {
        return None;
    }
    let family = attr[1];
    let mut port = u16::from_be_bytes([attr[2], attr[3]]);
    if xor {
        port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
    }

    match family {
        0x01 => {
            if attr.len() < 8 {
                return None;
            }
            let mut addr = [attr[4], attr[5], attr[6], attr[7]];
            if xor {
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    addr[i] ^= cookie[i];
                }
            }
            let ip = IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            Some(SocketAddr::new(ip, port))
        }
        0x02 => {
            if attr.len() < 20 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&attr[4..20]);
            if xor {
                let mut mask = [0u8; 16];
                mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                mask[4..16].copy_from_slice(&txid);
                for i in 0..16 {
                    addr[i] ^= mask[i];
                }
            }
            let ip = IpAddr::V6(Ipv6Addr::from(addr));
            Some(SocketAddr::new(ip, port))
        }
        _ => None,
    }
}

fn random_txid() -> [u8; 12] {
    let mut txid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut txid);
    txid
}

fn version_ok(v: u8) -> bool {
    v == UDP_PROTOCOL_VERSION
}

fn key_bytes(key: &str) -> [u8; 32] {
    hex_32_bytes(key).unwrap_or_else(|| hash_bytes(key))
}

fn peer_bytes(pk: &str) -> [u8; 32] {
    hex_32_bytes(pk).unwrap_or_else(|| hash_bytes(pk))
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn hex_32_bytes(hex: &str) -> Option<[u8; 32]> {
    let h = hex.trim();
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = h.as_bytes();
    for i in 0..32 {
        let hi = from_hex(bytes[i * 2])?;
        let lo = from_hex(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn hash_bytes(input: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..]);
    out
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[allow(dead_code)]
pub struct QuicHandle {
    table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    outbound: mpsc::UnboundedSender<UdpOutbound>,
    #[allow(dead_code)]
    task: tokio::task::JoinHandle<Result<()>>,
    request_fanout: usize,
    request_max_hops: u8,
}

#[allow(dead_code)]
impl QuicHandle {
    #[allow(dead_code)]
    pub fn stop(self) {
        self.task.abort();
    }

    #[allow(dead_code)]
    pub fn request_max_hops(&self) -> u8 {
        self.request_max_hops
    }

    #[allow(dead_code)]
    pub async fn confirmed_count(&self) -> usize {
        let guard = self.table.lock().await;
        guard.values().filter(|p| p.confirmed).count()
    }

    #[allow(dead_code)]
    pub async fn confirmed_peers(&self) -> Vec<SocketAddr> {
        let guard = self.table.lock().await;
        guard
            .iter()
            .filter_map(|(addr, info)| if info.confirmed { Some(*addr) } else { None })
            .collect()
    }

    pub async fn set_peers(&self, next: Vec<SocketAddr>) {
        let mut guard = self.peers.lock().await;
        *guard = next;
    }

    pub fn broadcast_record(&self, zone: &str, record_type: &str, event: NostrEvent) {
        let msg = UdpMessage::Record {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            record_type: record_type.to_string(),
            event,
            ts: now_ms(),
        };
        let _ = self.outbound.send(UdpOutbound::Broadcast(msg));
    }

    pub fn send_record_to(
        &self,
        addr: SocketAddr,
        zone: &str,
        record_type: &str,
        event: NostrEvent,
    ) {
        let msg = UdpMessage::Record {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            record_type: record_type.to_string(),
            event,
            ts: now_ms(),
        };
        let _ = self.outbound.send(UdpOutbound::SendTo(addr, msg));
    }

    pub fn request_records(&self, zone: &str, types: Vec<String>) {
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types,
            identity_id: None,
            device_pk: None,
            dht_scope: None,
            dht_key: None,
            hops: 0,
            ts: now_ms(),
        };
        let _ = self.outbound.send(UdpOutbound::Broadcast(msg));
    }

    pub async fn request_identity_record(&self, zone: &str, identity_id: &str) {
        let peers = self.select_peers(zone, Some(identity_id), None).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types: vec!["identity".to_string()],
            identity_id: Some(identity_id.to_string()),
            device_pk: None,
            dht_scope: None,
            dht_key: None,
            hops: 0,
            ts: now_ms(),
        };
        for peer in peers {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    pub async fn request_device_record(&self, zone: &str, device_pk: &str) {
        let peers = self.select_peers(zone, Some(device_pk), None).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types: vec!["device".to_string()],
            identity_id: None,
            device_pk: Some(device_pk.to_string()),
            dht_scope: None,
            dht_key: None,
            hops: 0,
            ts: now_ms(),
        };
        for peer in peers {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    pub async fn request_dht_record(&self, zone: &str, scope: &str, key: &str) {
        let lookup = format!("{}:{}", scope, key);
        let peers = self.select_peers(zone, Some(&lookup), None).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types: vec!["dht".to_string()],
            identity_id: None,
            device_pk: None,
            dht_scope: Some(scope.to_string()),
            dht_key: Some(key.to_string()),
            hops: 0,
            ts: now_ms(),
        };
        for peer in peers {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    pub async fn forward_record_request(
        &self,
        zone: &str,
        types: Vec<String>,
        identity_id: Option<String>,
        device_pk: Option<String>,
        dht_scope: Option<String>,
        dht_key: Option<String>,
        hops: u8,
        exclude: Option<SocketAddr>,
    ) {
        if hops > self.request_max_hops {
            return;
        }
        let dht_lookup = match (&dht_scope, &dht_key) {
            (Some(scope), Some(key)) if !scope.is_empty() && !key.is_empty() => {
                Some(format!("{}:{}", scope, key))
            }
            _ => None,
        };
        let key = identity_id
            .as_deref()
            .or(device_pk.as_deref())
            .or(dht_lookup.as_deref());
        let mut peers = self.select_peers(zone, key, exclude).await;
        if peers.is_empty() {
            return;
        }
        let msg = UdpMessage::RecordRequest {
            v: UDP_PROTOCOL_VERSION,
            zone: zone.to_string(),
            types,
            identity_id,
            device_pk,
            dht_scope,
            dht_key,
            hops,
            ts: now_ms(),
        };
        for peer in peers.drain(..) {
            let _ = self.outbound.send(UdpOutbound::SendTo(peer, msg.clone()));
        }
    }

    async fn select_peers(
        &self,
        zone: &str,
        key: Option<&str>,
        exclude: Option<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut scored: Vec<(SocketAddr, [u8; 32])> = {
            let guard = self.table.lock().await;
            guard
                .iter()
                .filter_map(|(addr, info)| {
                    if !info.confirmed || !info.zones.iter().any(|z| z == zone) {
                        return None;
                    }
                    if let Some(ex) = exclude {
                        if *addr == ex {
                            return None;
                        }
                    }
                    let score = if let Some(k) = key {
                        xor_distance(&key_bytes(k), &peer_bytes(&info.device_pk))
                    } else {
                        [0u8; 32]
                    };
                    Some((*addr, score))
                })
                .collect()
        };

        if scored.is_empty() {
            let mut fallback = self.peers.lock().await.clone();
            if let Some(ex) = exclude {
                fallback.retain(|p| *p != ex);
            }
            if fallback.is_empty() {
                return Vec::new();
            }
            fallback.sort_by_key(|addr| addr.to_string());
            let fanout = self.request_fanout;
            if fanout == 0 || fanout >= fallback.len() {
                return fallback;
            }
            return fallback.into_iter().take(fanout).collect();
        }

        scored.sort_by(|a, b| a.1.cmp(&b.1));
        let fanout = self.request_fanout;
        let mut out = Vec::new();
        for (addr, _) in scored {
            out.push(addr);
            if fanout != 0 && out.len() >= fanout {
                break;
            }
        }
        out
    }
}

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn start_quic_with_handle(bind: &str, cfg: QuicConfig) -> Result<QuicHandle> {
    ensure_rustls_provider();
    let bind_addr = resolve_bind_addr(bind).await?;
    let mut endpoint = build_quic_server_endpoint(bind_addr)?;
    endpoint.set_default_client_config(build_quic_client_config()?);

    let resolved = resolve_peers(&cfg.peers).await;
    let peers = Arc::new(Mutex::new(resolved));
    let table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let connections: Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let table_clone = table.clone();
    let peers_clone = peers.clone();
    let connections_clone = connections.clone();
    let (out_tx, out_rx) = mpsc::unbounded_channel();

    let request_fanout = cfg.request_fanout;
    let request_max_hops = cfg.request_max_hops;
    let task = tokio::spawn(async move {
        run_quic_loop(
            endpoint,
            cfg,
            peers_clone,
            table_clone,
            connections_clone,
            out_rx,
        )
        .await
    });

    Ok(QuicHandle {
        table,
        peers,
        outbound: out_tx,
        task,
        request_fanout,
        request_max_hops,
    })
}

async fn run_quic_loop(
    endpoint: QuinnEndpoint,
    cfg: QuicConfig,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    connections: Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>>,
    mut outbound_rx: mpsc::UnboundedReceiver<UdpOutbound>,
) -> Result<()> {
    let max_packet_bytes = cfg.max_packet_bytes.max(256).min(65507);
    let mut hello_tick = interval(cfg.handshake_interval.max(Duration::from_secs(1)));
    let mut prune_tick = interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            out = outbound_rx.recv() => {
                if let Some(msg) = out {
                    handle_outbound_quic(&endpoint, &connections, &peers, &table, &cfg, msg, max_packet_bytes).await;
                }
            }
            _ = hello_tick.tick(), if cfg.handshake_interval.as_secs() > 0 => {
                let snapshot = {
                    let guard = peers.lock().await;
                    guard.clone()
                };
                if snapshot.is_empty() {
                    continue;
                }
                let msg = UdpMessage::Hello {
                    v: UDP_PROTOCOL_VERSION,
                    node_id: cfg.node_id.clone(),
                    device_pk: cfg.device_pk.clone(),
                    zones: cfg.zones.clone(),
                    ts: now_ms(),
                };
                for peer in snapshot {
                    let endpoint = endpoint.clone();
                    let connections = connections.clone();
                    let table = table.clone();
                    let cfg_clone = cfg.clone();
                    let msg_clone = msg.clone();
                    tokio::spawn(async move {
                        if quic_send_message(
                            &endpoint,
                            &connections,
                            &table,
                            &cfg_clone,
                            peer,
                            &msg_clone,
                            max_packet_bytes,
                        )
                        .await
                        {
                            note_peer_outbound(
                                &table,
                                peer,
                                &cfg_clone.node_id,
                                &cfg_clone.device_pk,
                                &cfg_clone.zones,
                            )
                            .await;
                        }
                    });
                }
            }
            _ = prune_tick.tick(), if cfg.peer_timeout.as_secs() > 0 => {
                let mut stale = Vec::new();
                {
                    let mut guard = table.lock().await;
                    let timeout = cfg.peer_timeout;
                    guard.retain(|addr, info| {
                        let keep = info.last_seen.elapsed() <= timeout;
                        if !keep {
                            stale.push(*addr);
                        }
                        keep
                    });
                }
                if !stale.is_empty() {
                    let mut conn_guard = connections.lock().await;
                    for addr in stale {
                        conn_guard.remove(&addr);
                    }
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    tracing::warn!("quic accept stream ended");
                    break;
                };
                let table_clone = table.clone();
                let connections_clone = connections.clone();
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_quic_incoming(
                        incoming,
                        table_clone,
                        connections_clone,
                        cfg_clone,
                        max_packet_bytes,
                    ).await {
                        tracing::debug!(error = %err, "quic connection handler failed");
                    }
                });
            }
        }
    }

    tracing::warn!("quic loop exited");
    Ok(())
}

async fn handle_quic_incoming(
    incoming: quinn::Incoming,
    table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    connections: Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>>,
    cfg: QuicConfig,
    max_packet_bytes: usize,
) -> Result<()> {
    let conn = incoming.await?;
    handle_quic_connected(conn, table, connections, cfg, max_packet_bytes).await
}

async fn handle_quic_connected(
    conn: QuinnConnection,
    table: Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    connections: Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>>,
    cfg: QuicConfig,
    max_packet_bytes: usize,
) -> Result<()> {
    let remote = conn.remote_address();
    {
        let mut guard = connections.lock().await;
        guard.insert(remote, conn.clone());
    }

    loop {
        match conn.read_datagram().await {
            Ok(payload) => {
                if payload.len() >= max_packet_bytes {
                    tracing::debug!(from = %remote, len = payload.len(), "quic datagram dropped (too large)");
                    continue;
                }
                match serde_json::from_slice::<UdpMessage>(&payload) {
                    Ok(msg) => {
                        handle_quic_message(&conn, &table, remote, msg, &cfg, max_packet_bytes)
                            .await;
                    }
                    Err(_) => {
                        tracing::debug!(from = %remote, len = payload.len(), "quic datagram ignored (non-json)");
                    }
                }
            }
            Err(err) => {
                tracing::debug!(peer = %remote, error = %err, "quic datagram read ended");
                break;
            }
        }
    }

    {
        let mut guard = connections.lock().await;
        guard.remove(&remote);
    }

    Ok(())
}

async fn handle_quic_message(
    conn: &QuinnConnection,
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    from: SocketAddr,
    msg: UdpMessage,
    cfg: &QuicConfig,
    max_packet_bytes: usize,
) {
    match msg {
        UdpMessage::Hello {
            v,
            node_id,
            device_pk,
            zones,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            if !note_peer_inbound(
                table,
                from,
                node_id,
                device_pk,
                zones,
                false,
                cfg.rate_limit_per_sec,
            )
            .await
            {
                return;
            }
            let reply = UdpMessage::Ack {
                v: UDP_PROTOCOL_VERSION,
                node_id: cfg.node_id.clone(),
                device_pk: cfg.device_pk.clone(),
                zones: cfg.zones.clone(),
                ts: now_ms(),
            };
            send_quic_message(conn, &reply, max_packet_bytes);
        }
        UdpMessage::Ack {
            v,
            node_id,
            device_pk,
            zones,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            let _ = note_peer_inbound(
                table,
                from,
                node_id,
                device_pk,
                zones,
                true,
                cfg.rate_limit_per_sec,
            )
            .await;
        }
        UdpMessage::Record {
            v,
            zone,
            record_type,
            event,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            if !cfg.zones.iter().any(|z| z == &zone) {
                return;
            }
            if !crate::nostr::verify_event(&event).unwrap_or(false) {
                return;
            }
            if !note_peer_activity(table, from, cfg.rate_limit_per_sec).await {
                return;
            }
            if let Some(tx) = cfg.inbound_tx.as_ref() {
                let _ = tx.send(UdpInbound::Record {
                    zone,
                    record_type,
                    event,
                    from,
                });
            }
        }
        UdpMessage::RecordRequest {
            v,
            zone,
            types,
            identity_id,
            device_pk,
            dht_scope,
            dht_key,
            hops,
            ..
        } => {
            if !version_ok(v) {
                return;
            }
            if !cfg.zones.iter().any(|z| z == &zone) {
                return;
            }
            if !note_peer_activity(table, from, cfg.rate_limit_per_sec).await {
                return;
            }
            if let Some(tx) = cfg.inbound_tx.as_ref() {
                let _ = tx.send(UdpInbound::RecordRequest {
                    zone,
                    types,
                    identity_id,
                    device_pk,
                    dht_scope,
                    dht_key,
                    hops,
                    from,
                });
            }
        }
    }
}

async fn handle_outbound_quic(
    endpoint: &QuinnEndpoint,
    connections: &Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>>,
    peers: &Arc<Mutex<Vec<SocketAddr>>>,
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    cfg: &QuicConfig,
    msg: UdpOutbound,
    max_packet_bytes: usize,
) {
    match msg {
        UdpOutbound::Broadcast(inner) => {
            let snapshot = { peers.lock().await.clone() };
            for peer in snapshot {
                let endpoint = endpoint.clone();
                let connections = connections.clone();
                let table = table.clone();
                let cfg_clone = cfg.clone();
                let inner = inner.clone();
                tokio::spawn(async move {
                    let _ = quic_send_message(
                        &endpoint,
                        &connections,
                        &table,
                        &cfg_clone,
                        peer,
                        &inner,
                        max_packet_bytes,
                    )
                    .await;
                });
            }
        }
        UdpOutbound::SendTo(addr, inner) => {
            let endpoint = endpoint.clone();
            let connections = connections.clone();
            let table = table.clone();
            let cfg_clone = cfg.clone();
            tokio::spawn(async move {
                let _ = quic_send_message(
                    &endpoint,
                    &connections,
                    &table,
                    &cfg_clone,
                    addr,
                    &inner,
                    max_packet_bytes,
                )
                .await;
            });
        }
    }
}

async fn quic_send_message(
    endpoint: &QuinnEndpoint,
    connections: &Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>>,
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    cfg: &QuicConfig,
    addr: SocketAddr,
    msg: &UdpMessage,
    max_packet_bytes: usize,
) -> bool {
    let Ok(payload) = serde_json::to_vec(msg) else {
        return false;
    };
    if payload.len() > max_packet_bytes {
        tracing::debug!(peer = %addr, len = payload.len(), "quic send skipped (too large)");
        return false;
    }

    if let Some(conn) =
        quic_get_or_connect(endpoint, connections, table, cfg, addr, max_packet_bytes).await
    {
        return send_quic_payload(&conn, payload, addr);
    }

    false
}

fn send_quic_message(conn: &QuinnConnection, msg: &UdpMessage, max_packet_bytes: usize) {
    let Ok(payload) = serde_json::to_vec(msg) else {
        return;
    };
    if payload.len() > max_packet_bytes {
        return;
    }
    let _ = conn.send_datagram(Bytes::from(payload));
}

fn send_quic_payload(conn: &QuinnConnection, payload: Vec<u8>, addr: SocketAddr) -> bool {
    match conn.send_datagram(Bytes::from(payload)) {
        Ok(()) => true,
        Err(err) => {
            tracing::debug!(peer = %addr, error = %err, "quic send failed");
            false
        }
    }
}

async fn quic_get_or_connect(
    endpoint: &QuinnEndpoint,
    connections: &Arc<Mutex<HashMap<SocketAddr, QuinnConnection>>>,
    table: &Arc<Mutex<HashMap<SocketAddr, PeerInfo>>>,
    cfg: &QuicConfig,
    addr: SocketAddr,
    max_packet_bytes: usize,
) -> Option<QuinnConnection> {
    {
        let guard = connections.lock().await;
        if let Some(conn) = guard.get(&addr) {
            if conn.close_reason().is_none() {
                return Some(conn.clone());
            }
        }
    }

    let connecting = match endpoint.connect(addr, "constitute-gateway") {
        Ok(connecting) => connecting,
        Err(err) => {
            tracing::debug!(peer = %addr, error = %err, "quic connect create failed");
            return None;
        }
    };

    let conn = match tokio::time::timeout(Duration::from_secs(2), connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            tracing::debug!(peer = %addr, error = %err, "quic connect failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(peer = %addr, "quic connect timed out");
            return None;
        }
    };

    {
        let mut guard = connections.lock().await;
        guard.insert(addr, conn.clone());
    }

    let table_clone = table.clone();
    let connections_clone = connections.clone();
    let cfg_clone = cfg.clone();
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        if let Err(err) = handle_quic_connected(
            conn_clone,
            table_clone,
            connections_clone,
            cfg_clone,
            max_packet_bytes,
        )
        .await
        {
            tracing::debug!(error = %err, "quic outbound reader failed");
        }
    });

    Some(conn)
}

fn build_quic_server_endpoint(bind: SocketAddr) -> Result<QuinnEndpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["constitute-gateway".to_string()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = QuinnServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
    if let Some(transport) = Arc::get_mut(&mut server_config.transport) {
        transport.max_concurrent_uni_streams(0_u8.into());
        transport.max_concurrent_bidi_streams(0_u8.into());
    }

    let endpoint = QuinnEndpoint::server(server_config, bind)?;
    Ok(endpoint)
}

fn build_quic_client_config() -> Result<QuinnClientConfig> {
    let rustls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    let mut cfg = QuinnClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_cfg)?));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(0_u8.into());
    transport.max_concurrent_bidi_streams(0_u8.into());
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

async fn resolve_bind_addr(bind: &str) -> Result<SocketAddr> {
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = lookup_host(bind).await?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("unable to resolve bind address: {}", bind))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
