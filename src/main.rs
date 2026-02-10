mod discovery;
mod keystore;
mod nostr;
mod platform;
mod relay;
mod local_relay;
mod transport;
mod swarm_store;
mod util;

use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::swarm_store::{RecordType, SwarmStoreMap};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{System, SystemExt, CpuExt};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{timeout, Instant};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "constitute-gateway", version, about = "Constitute native gateway (skeleton)")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "warn")]
    log_level: String,
    #[arg(long, action = ArgAction::SetTrue)]
    stun_check: bool,
    #[arg(long, default_value = "5")]
    stun_timeout_secs: u64,
    #[arg(long, action = ArgAction::Append)]
    zone: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct ZoneConfig {
    key: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct Config {
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    node_type: Option<discovery::NodeType>,
    #[serde(default = "default_bind")]
    bind: String,
    #[serde(default = "default_data_dir")]
    data_dir: String,
    #[serde(default)]
    nostr_relays: Vec<String>,
    #[serde(default)]
    advertise_relays: Vec<String>,
    #[serde(default = "default_nostr_kind")]
    nostr_kind: u32,
    #[serde(default = "default_nostr_tag")]
    nostr_tag: String,
    #[serde(default = "default_publish_interval_secs")]
    nostr_publish_interval_secs: u64,
    #[serde(default = "default_metrics_interval_secs")]
    metrics_interval_secs: u64,
    #[serde(default = "default_self_test_enabled")]
    self_test: bool,
    #[serde(default = "default_self_test_timeout_secs")]
    self_test_timeout_secs: u64,
    #[serde(default)]
    swarm_endpoint: String,
    #[serde(default)]
    udp_peers: Vec<String>,
    #[serde(default = "default_udp_handshake_interval_secs")]
    udp_handshake_interval_secs: u64,
    #[serde(default = "default_udp_peer_timeout_secs")]
    udp_peer_timeout_secs: u64,
    #[serde(default = "default_udp_max_packet_bytes")]
    udp_max_packet_bytes: u64,
    #[serde(default = "default_udp_rate_limit_per_sec")]
    udp_rate_limit_per_sec: u32,
    #[serde(default = "default_udp_sync_interval_secs")]
    udp_sync_interval_secs: u64,
    #[serde(default = "default_stun_interval_secs")]
    stun_interval_secs: u64,
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default)]
    turn_servers: Vec<String>,
    #[serde(default = "default_relay_bind")]
    relay_bind: String,
    #[serde(default)]
    relay_bind_tls: String,
    #[serde(default)]
    relay_tls_cert_path: String,
    #[serde(default)]
    relay_tls_key_path: String,
    #[serde(default = "default_relay_rebroadcast")]
    relay_rebroadcast: bool,
    #[serde(default = "default_relay_replay_window_secs")]
    relay_replay_window_secs: u64,
    #[serde(default = "default_relay_replay_skew_secs")]
    relay_replay_skew_secs: u64,
    #[serde(default)]
    zones: Vec<ZoneConfig>,
    #[serde(default)]
    identity_id: String,
    #[serde(default)]
    device_label: String,
    #[serde(default)]
    nostr_pubkey: String,
    #[serde(default)]
    nostr_sk_hex: String,
}

#[derive(Debug, Deserialize)]
struct ZonePresencePayload {
    #[serde(rename = "type")]
    kind: String,
    zone: String,
    device_pk: String,
    swarm: String,
    #[serde(default)]
    metrics: Option<discovery::GatewayMetrics>,
}

fn default_bind() -> String {
    "0.0.0.0:4040".to_string()
}

fn default_data_dir() -> String {
    platform::default_data_dir()
}

fn default_node_type() -> discovery::NodeType {
    discovery::NodeType::Gateway
}

fn default_nostr_kind() -> u32 {
    discovery::default_record_kind()
}

fn default_nostr_tag() -> String {
    discovery::default_record_tag()
}

fn default_publish_interval_secs() -> u64 {
    30
}

fn default_metrics_interval_secs() -> u64 {
    10
}

fn default_self_test_enabled() -> bool {
    true
}

fn default_self_test_timeout_secs() -> u64 {
    8
}

fn default_udp_handshake_interval_secs() -> u64 {
    5
}

fn default_udp_peer_timeout_secs() -> u64 {
    60
}

fn default_udp_max_packet_bytes() -> u64 {
    2048
}

fn default_udp_rate_limit_per_sec() -> u32 {
    60
}

fn default_udp_sync_interval_secs() -> u64 {
    90
}

fn default_stun_interval_secs() -> u64 {
    30
}

fn default_relay_bind() -> String {
    "0.0.0.0:7447".to_string()
}

fn default_relay_rebroadcast() -> bool {
    true
}

fn default_relay_replay_window_secs() -> u64 {
    600
}

fn default_relay_replay_skew_secs() -> u64 {
    120
}

fn normalize_zone_name(name: &str) -> String {
    let n = name.trim();
    if n.is_empty() {
        "Default".to_string()
    } else {
        n.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if std::env::var("RUST_LOG").is_err() {
        let level = util::normalize_log_level(&args.log_level)
            .ok_or_else(|| anyhow!("invalid log level: {}", args.log_level))?;
        std::env::set_var("RUST_LOG", level);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_path = args.config.unwrap_or_else(platform::default_config_path);
    let mut cfg = load_config(&config_path).unwrap_or_default();

    if args.stun_check {
        let timeout = Duration::from_secs(args.stun_timeout_secs.max(1));
        if cfg.stun_servers.is_empty() {
            println!("stun: no servers configured");
            return Ok(());
        }
        match transport::probe_stun(&cfg.stun_servers, timeout).await? {
            Some(addr) => println!("stun endpoint: {}", addr),
            None => println!("stun endpoint: not found"),
        }
        return Ok(());
    }

    if cfg.zones.is_empty() {
        cfg.zones = collect_seed_zones(&cfg.data_dir, &args.zone);
    }

    let mut dirty = false;

    if cfg.zones.is_empty() {
        let name = "Default".to_string();
        let key = util::derive_zone_key(&name);
        cfg.zones.push(ZoneConfig { key, name });
        dirty = true;
    }

    for z in &mut cfg.zones {
        if z.name.trim().is_empty() {
            z.name = normalize_zone_name(&z.name);
            dirty = true;
        }
        if !util::is_valid_zone_key(&z.key) {
            let name = normalize_zone_name(&z.name);
            z.name = name.clone();
            z.key = util::derive_zone_key(&name);
            dirty = true;
        }
    }

    let seed = keystore::SecureSeed {
        nostr_pubkey: cfg.nostr_pubkey.clone(),
        nostr_sk_hex: cfg.nostr_sk_hex.clone(),
        identity_id: cfg.identity_id.clone(),
        device_label: cfg.device_label.clone(),
        zones: cfg
            .zones
            .iter()
            .map(|z| keystore::ZoneEntry {
                key: z.key.clone(),
                name: z.name.clone(),
            })
            .collect(),
    };

    let (secure, key_source) = keystore::load_or_init(&cfg.data_dir, seed)
        .map_err(|e| anyhow!("keystore error: {}", e))?;

    cfg.nostr_pubkey = secure.nostr_pubkey.clone();
    cfg.nostr_sk_hex = secure.nostr_sk_hex.clone();
    cfg.identity_id = secure.identity_id.clone();
    cfg.device_label = secure.device_label.clone();
    cfg.zones = secure
        .zones
        .iter()
        .map(|z| ZoneConfig {
            key: z.key.clone(),
            name: z.name.clone(),
        })
        .collect();

    info!(key_source = %key_source, "keystore ready");

    if cfg.nostr_pubkey.is_empty() || cfg.nostr_sk_hex.is_empty() {
        warn!("nostr keys missing; discovery events will fail to sign");
    }

    if cfg.node_id.is_empty() {
        warn!("node_id not set; using nostr pubkey as identity");
        cfg.node_id = cfg.nostr_pubkey.clone();
        dirty = true;
    }

    if dirty {
        // Do not persist secure fields into config.json for safety.
        cfg.nostr_sk_hex.clear();
        cfg.identity_id.clear();
        cfg.device_label.clear();
        cfg.zones.clear();
        let _ = save_config(&config_path, &cfg);
    }

    if cfg.nostr_relays.is_empty() {
        warn!("nostr_relays empty; discovery bootstrap disabled (placeholder)");
    }

    let node_type = cfg.node_type.clone().unwrap_or_else(default_node_type);
    let advertise_relays = if cfg.advertise_relays.is_empty() {
        cfg.nostr_relays.clone()
    } else {
        cfg.advertise_relays.clone()
    };
    if advertise_relays.is_empty() {
        warn!("advertise_relays empty; gateway relay endpoint will not be advertised");
    }

    info!(
        bind = %cfg.bind,
        data_dir = %cfg.data_dir,
        node_type = %node_type,
        zones = cfg.zones.len(),
        "gateway starting (skeleton)"
    );
    info!(stun = cfg.stun_servers.len(), turn = cfg.turn_servers.len(), "stun/turn config");
    info!(relays = advertise_relays.len(), "advertised relays");
    info!("build target is intended for Ubuntu Core (linux)");

    platform::init();

    if cfg.self_test {
        if cfg.nostr_pubkey.is_empty() || cfg.nostr_sk_hex.is_empty() {
            warn!("self-test skipped; nostr keys not available");
        } else if cfg.nostr_relays.is_empty() {
            warn!("self-test skipped; no nostr_relays configured");
        } else {
            let timeout_secs = cfg.self_test_timeout_secs.max(3);
            let mut ok = false;
            for relay_url in &cfg.nostr_relays {
                match run_self_test(
                    relay_url,
                    &cfg.nostr_pubkey,
                    &cfg.nostr_sk_hex,
                    cfg.nostr_kind,
                    &cfg.nostr_tag,
                    Duration::from_secs(timeout_secs),
                )
                .await
                {
                    Ok(true) => {
                        info!(relay = %relay_url, "self-test ok");
                        ok = true;
                        break;
                    }
                    Ok(false) => {
                        warn!(relay = %relay_url, "self-test timeout/no-ack");
                    }
                    Err(err) => {
                        warn!(relay = %relay_url, error = %err, "self-test failed");
                    }
                }
            }
            if !ok {
                warn!("self-test failed on all relays; continuing");
            }
        }
    }

    if cfg.swarm_endpoint.trim().is_empty() {
        warn!("swarm_endpoint not set; zone_presence will not advertise UDP endpoint until STUN resolves");
    }

    let zones = cfg.zones.iter().map(|z| z.key.clone()).collect::<Vec<_>>();
    let zone_keys: HashSet<String> = zones.iter().cloned().collect();
    let device_pk = cfg.nostr_pubkey.clone();
    let identity_id = cfg.identity_id.clone();
    let device_label = cfg.device_label.clone();
    let device_record = discovery::SwarmDeviceRecord::new(
        &device_pk,
        &identity_id,
        &device_label,
        "gateway",
        advertise_relays.clone(),
    );

    let (swarm_tx, swarm_rx) = watch::channel(cfg.swarm_endpoint.clone());
    let (metrics_tx, metrics_rx) = watch::channel(discovery::GatewayMetrics::default());
    let relay_req = discovery::relay_req_json();
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<String>();
    let (local_in_tx, mut local_in_rx) = mpsc::unbounded_channel::<Value>();
    let store = Arc::new(Mutex::new(SwarmStoreMap::new()));
    let (udp_in_tx, mut udp_in_rx) = mpsc::unbounded_channel::<transport::UdpInbound>();
    if !cfg.nostr_pubkey.is_empty() && !cfg.nostr_sk_hex.is_empty() {
        if let Ok(ev) = build_device_record_event(&cfg.nostr_pubkey, &cfg.nostr_sk_hex, &device_record) {
            let _ = store.lock().await.put_record_all(&zones, &ev);
        }
    }
    let relay_pool = relay::RelayPool::new(cfg.nostr_relays.clone(), relay_req, Some(inbound_tx)).await;
    let discovery_client = discovery::DiscoveryClient::new(
        relay_pool.clone(),
        device_record,
        cfg.nostr_pubkey.clone(),
        cfg.nostr_sk_hex.clone(),
        Duration::from_secs(cfg.nostr_publish_interval_secs),
        zones.clone(),
        swarm_rx,
        metrics_rx,
    );
    tokio::spawn(async move {
        if let Err(err) = discovery_client.run().await {
            tracing::warn!(error = %err, "nostr discovery loop failed");
        }
    });

    let ws_bind = if cfg.relay_bind.trim().is_empty() { None } else { Some(cfg.relay_bind.clone()) };
    let wss_bind = if cfg.relay_bind_tls.trim().is_empty() { None } else { Some(cfg.relay_bind_tls.clone()) };
    let tls = if cfg.relay_tls_cert_path.trim().is_empty() || cfg.relay_tls_key_path.trim().is_empty() {
        None
    } else {
        Some(local_relay::TlsConfig {
            cert_path: cfg.relay_tls_cert_path.clone(),
            key_path: cfg.relay_tls_key_path.clone(),
        })
    };
    let validation = local_relay::ValidationConfig {
        replay_window: Duration::from_secs(cfg.relay_replay_window_secs.max(60)),
        replay_skew: Duration::from_secs(cfg.relay_replay_skew_secs.min(cfg.relay_replay_window_secs)),
    };

    let local_relay = match local_relay::start_relays(ws_bind, wss_bind, tls, relay_pool.clone(), validation.clone(), Some(local_in_tx)).await {
        Ok(handle) => {
            if handle.is_some() {
                info!("local relay online");
            }
            handle
        }
        Err(err) => {
            warn!(error = %err, "local relay failed to start");
            None
        }
    };

    if cfg.metrics_interval_secs > 0 {
        let interval = Duration::from_secs(cfg.metrics_interval_secs.max(5));
        let metrics_tx = metrics_tx.clone();
        let local_relay = local_relay.clone();
        tokio::spawn(async move {
            let mut sys = System::new();
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                sys.refresh_cpu();
                sys.refresh_memory();
                let clients = local_relay.as_ref().map(|r| r.client_count()).unwrap_or(0);
                let metrics = build_metrics(&sys, clients);
                let _ = metrics_tx.send(metrics);
            }
        });
    }

    let bind = cfg.bind.clone();
    let udp_cfg = transport::UdpConfig {
        node_id: cfg.node_id.clone(),
        device_pk: cfg.nostr_pubkey.clone(),
        zones: zones.clone(),
        peers: cfg.udp_peers.clone(),
        handshake_interval: Duration::from_secs(cfg.udp_handshake_interval_secs),
        peer_timeout: Duration::from_secs(cfg.udp_peer_timeout_secs),
        max_packet_bytes: cfg.udp_max_packet_bytes.max(512).min(65507) as usize,
        rate_limit_per_sec: cfg.udp_rate_limit_per_sec,
        udp_sync_interval_secs: cfg.udp_sync_interval_secs,
        stun_servers: cfg.stun_servers.clone(),
        stun_interval: Duration::from_secs(cfg.stun_interval_secs),
        swarm_endpoint_tx: Some(swarm_tx.clone()),
        inbound_tx: Some(udp_in_tx),
    };
    let udp_handle = Arc::new(transport::start_udp_with_handle(&bind, udp_cfg).await?);

    let seen_cache = Arc::new(Mutex::new(SeenCache::new()));
    let peer_set = Arc::new(Mutex::new(cfg.udp_peers.iter().cloned().collect::<HashSet<String>>()));

    let inbound_ctx = InboundContext {
        self_pk: cfg.nostr_pubkey.clone(),
        self_sk: cfg.nostr_sk_hex.clone(),
        rebroadcast: cfg.relay_rebroadcast,
        relay_pool: relay_pool.clone(),
        local_relay: local_relay.clone(),
        store: store.clone(),
        udp_handle: udp_handle.clone(),
        zones: zones.clone(),
        zone_keys: zone_keys.clone(),
        peer_set: peer_set.clone(),
        seen: seen_cache.clone(),
        seen_ttl: validation.replay_window,
        seen_max: 4096,
    };

    let ctx_nostr = inbound_ctx.clone();
    tokio::spawn(async move {
        while let Some(frame) = inbound_rx.recv().await {
            let ev = match extract_event(&frame) {
                Some(ev) => ev,
                None => continue,
            };
            process_inbound_event(ev, Some(frame), InboundSource::Nostr, ctx_nostr.clone()).await;
        }
    });

    let ctx_local = inbound_ctx.clone();
    tokio::spawn(async move {
        while let Some(ev) = local_in_rx.recv().await {
            process_inbound_event(ev, None, InboundSource::Local, ctx_local.clone()).await;
        }
    });

    for zone in &zones {
        udp_handle.request_records(zone, vec!["identity".to_string(), "device".to_string()]);
    }

    let store_for_udp = store.clone();
    let udp_handle_for_udp = udp_handle.clone();
    let local_relay_for_udp = local_relay.clone();
    let self_pk_udp = cfg.nostr_pubkey.clone();
    let self_sk_udp = cfg.nostr_sk_hex.clone();
    let zones_for_udp = zones.clone();
    tokio::spawn(async move {
        while let Some(msg) = udp_in_rx.recv().await {
            match msg {
                transport::UdpInbound::Record { record_type: _, event, zone, .. } => {
                    if !zones_for_udp.contains(&zone) {
                        continue;
                    }
                    let stored = {
                        let mut guard = store_for_udp.lock().await;
                        guard.put_record_in_zone(&zone, &event)
                    };
                    if let Some(record_type) = stored {
                        if let Some(local) = local_relay_for_udp.as_ref() {
                            if let Ok(app_ev) = build_record_app_event(&self_pk_udp, &self_sk_udp, record_type, &event) {
                                if let Ok(val) = serde_json::to_value(app_ev) {
                                    local.publish_event(val).await;
                                }
                            }
                        }
                    }
                }
                transport::UdpInbound::RecordRequest { zone, types, from } => {
                    let want_identity = types.is_empty() || types.iter().any(|t| t == "identity");
                    let want_device = types.is_empty() || types.iter().any(|t| t == "device");
                    let guard = store_for_udp.lock().await;
                    if want_identity {
                        for record in guard.list_identity_events_zone(&zone) {
                            udp_handle_for_udp.send_record_to(from, &zone, "identity", record);
                        }
                    }
                    if want_device {
                        for record in guard.list_device_events_zone(&zone) {
                            udp_handle_for_udp.send_record_to(from, &zone, "device", record);
                        }
                    }
                }
            }
        }
    });

    let sync_interval = Duration::from_secs(cfg.udp_sync_interval_secs.max(30));
    let udp_handle_for_sync = udp_handle.clone();
    let zones_for_sync = zones.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(sync_interval);
        loop {
            ticker.tick().await;
            for zone in &zones_for_sync {
                udp_handle_for_sync.request_records(zone, vec!["identity".to_string(), "device".to_string()]);
            }
        }
    });

    tokio::spawn(async move {
        if let Err(err) = transport::start_quic_stub().await {
            tracing::warn!(error = %err, "quic stub failed");
        }
    });

    // TODO: discovery bootstrap (nostr) and relay service
    // TODO: auth/envelope verification

    tokio::signal::ctrl_c().await?;
    info!("shutdown");
    Ok(())
}

fn has_tag(tags: &[Vec<String>], key: &str, value: &str) -> bool {
    tags.iter().any(|t| t.get(0).map(|v| v.as_str()) == Some(key) && t.get(1).map(|v| v.as_str()) == Some(value))
}

fn parse_app_payload(ev: &nostr::NostrEvent) -> Option<Value> {
    if ev.kind != 1 {
        return None;
    }
    if !has_tag(&ev.tags, "t", "constitute") {
        return None;
    }
    serde_json::from_str(&ev.content).ok()
}

fn wants_type(payload: &Value, kind: &str) -> bool {
    match payload.get("want").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().any(|v| v.as_str() == Some(kind)),
        None => true,
    }
}

fn build_app_event(pubkey: &str, sk_hex: &str, payload: &Value) -> Result<nostr::NostrEvent> {
    let tags = vec![vec!["t".to_string(), "constitute".to_string()]];
    let unsigned = nostr::build_unsigned_event(
        pubkey,
        1,
        tags,
        payload.to_string(),
        util::now_unix_seconds(),
    );
    nostr::sign_event(&unsigned, sk_hex)
}

fn build_record_app_event(
    pubkey: &str,
    sk_hex: &str,
    record_type: RecordType,
    record: &nostr::NostrEvent,
) -> Result<nostr::NostrEvent> {
    let payload = match record_type {
        RecordType::Identity => serde_json::json!({
            "type": "swarm_identity_record",
            "record": record,
        }),
        RecordType::Device => serde_json::json!({
            "type": "swarm_device_record",
            "record": record,
        }),
    };
    build_app_event(pubkey, sk_hex, &payload)
}

async fn publish_record_app_event(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    record_type: RecordType,
    record: &nostr::NostrEvent,
) -> Result<()> {
    if pubkey.is_empty() || sk_hex.is_empty() {
        return Ok(());
    }
    let app_ev = build_record_app_event(pubkey, sk_hex, record_type, record)?;
    relay_pool.broadcast(&nostr::frame_event(&app_ev));
    if let Some(local) = local_relay.as_ref() {
        if let Ok(val) = serde_json::to_value(app_ev) {
            local.publish_event(val).await;
        }
    }
    Ok(())
}

fn build_device_record_event(
    pubkey: &str,
    sk_hex: &str,
    record: &discovery::SwarmDeviceRecord,
) -> Result<nostr::NostrEvent> {
    let tags = vec![
        vec!["t".to_string(), discovery::default_record_tag()],
        vec!["type".to_string(), "device".to_string()],
        vec!["role".to_string(), record.role.clone()],
    ];
    let unsigned = nostr::build_unsigned_event(
        pubkey,
        discovery::default_record_kind(),
        tags,
        record.to_json(),
        util::now_unix_seconds(),
    );
    nostr::sign_event(&unsigned, sk_hex)
}

async fn run_self_test(
    relay_url: &str,
    pubkey: &str,
    sk_hex: &str,
    kind: u32,
    tag: &str,
    timeout_duration: Duration,
) -> Result<bool> {
    let (ws, _) = connect_async(relay_url).await?;
    let (mut write, mut read) = ws.split();
    let nonce = random_hex(8);
    let content = format!("selftest:{}", nonce);
    let tags = vec![
        vec!["t".to_string(), tag.to_string()],
        vec!["type".to_string(), "gateway".to_string()],
        vec!["selftest".to_string(), nonce],
    ];
    let unsigned = nostr::build_unsigned_event(pubkey, kind, tags, content, util::now_unix_seconds());
    let ev = nostr::sign_event(&unsigned, sk_hex)?;
    let frame = nostr::frame_event(&ev);

    write.send(Message::Text(frame)).await?;

    let deadline = Instant::now() + timeout_duration;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let remaining = deadline - now;
        let msg = match timeout(remaining, read.next()).await {
            Ok(m) => m,
            Err(_) => return Ok(false),
        };
        match msg {
            Some(Ok(Message::Text(txt))) => {
                if is_self_test_ack(&txt, &ev.id) {
                    return Ok(true);
                }
            }
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(anyhow!("relay read failed: {}", err)),
            None => return Ok(false),
        }
    }
}

fn is_self_test_ack(frame: &str, event_id: &str) -> bool {
    let v: Value = match serde_json::from_str(frame) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return false,
    };
    if arr.is_empty() {
        return false;
    }
    match arr[0].as_str() {
        Some("OK") => {
            let id = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let ok = arr.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
            ok && id == event_id
        }
        Some("EVENT") => {
            let ev = arr.get(1).and_then(|v| v.as_object());
            match ev.and_then(|o| o.get("id")).and_then(|v| v.as_str()) {
                Some(id) if id == event_id => true,
                _ => false,
            }
        }
        _ => false,
    }
}

fn extract_event(frame: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(frame).ok()?;
    let arr = v.as_array()?;
    if arr.is_empty() {
        return None;
    }
    if arr.get(0)?.as_str()? != "EVENT" {
        return None;
    }
    let ev_val = if arr.len() >= 3 { &arr[2] } else { &arr[1] };
    Some(ev_val.clone())
}

fn event_id(ev: &Value) -> Option<String> {
    ev.get("id")?.as_str().map(|s| s.to_string())
}

fn event_pubkey(ev: &Value) -> Option<String> {
    ev.get("pubkey")?.as_str().map(|s| s.to_string())
}

fn event_has_tag(ev: &Value, key: &str, value: &str) -> bool {
    let tags = match ev.get("tags").and_then(|v| v.as_array()) {
        Some(t) => t,
        None => return false,
    };
    for tag in tags {
        let arr = match tag.as_array() {
            Some(a) => a,
            None => continue,
        };
        if arr.len() < 2 {
            continue;
        }
        let k = arr[0].as_str().unwrap_or("");
        let v = arr[1].as_str().unwrap_or("");
        if k == key && v == value {
            return true;
        }
    }
    false
}

fn is_allowed_event(ev: &Value) -> bool {
    event_has_tag(ev, "t", "constitute") || event_has_tag(ev, "t", "swarm_discovery")
}

#[derive(Clone)]
struct InboundContext {
    self_pk: String,
    self_sk: String,
    rebroadcast: bool,
    relay_pool: relay::RelayPool,
    local_relay: Option<local_relay::LocalRelayHandle>,
    store: Arc<Mutex<SwarmStoreMap>>,
    udp_handle: Arc<transport::UdpHandle>,
    zones: Vec<String>,
    zone_keys: HashSet<String>,
    peer_set: Arc<Mutex<HashSet<String>>>,
    seen: Arc<Mutex<SeenCache>>,
    seen_ttl: Duration,
    seen_max: usize,
}

#[derive(Clone, Copy)]
enum InboundSource {
    Nostr,
    Local,
}

#[derive(Default)]
struct SeenCache {
    events: HashMap<String, Instant>,
    order: VecDeque<String>,
}

impl SeenCache {
    fn new() -> Self {
        Self { events: HashMap::new(), order: VecDeque::new() }
    }
}

async fn seen_or_insert(id: &str, cache: &Arc<Mutex<SeenCache>>, ttl: Duration, max: usize) -> bool {
    let mut guard = cache.lock().await;
    if let Some(ts) = guard.events.get(id) {
        if ts.elapsed() <= ttl {
            return true;
        }
    }
    remember_event(id.to_string(), &mut guard, ttl, max);
    false
}

async fn process_inbound_event(
    ev: Value,
    raw_frame: Option<String>,
    source: InboundSource,
    ctx: InboundContext,
) {
    if let Some(id) = event_id(&ev) {
        if seen_or_insert(&id, &ctx.seen, ctx.seen_ttl, ctx.seen_max).await {
            return;
        }
    }

    let nostr_ev: nostr::NostrEvent = match serde_json::from_value(ev.clone()) {
        Ok(ev) => ev,
        Err(_) => return,
    };
    if !nostr::verify_event(&nostr_ev).unwrap_or(false) {
        return;
    }

    let frame = raw_frame.unwrap_or_else(|| nostr::frame_event(&nostr_ev));

    if is_allowed_event(&ev) {
        if matches!(source, InboundSource::Nostr) {
            if let Some(local) = ctx.local_relay.as_ref() {
                local.publish_event(ev.clone()).await;
            }
        }
        if ctx.rebroadcast {
            let from_self = event_pubkey(&ev).map(|pk| pk == ctx.self_pk).unwrap_or(false);
            if !from_self {
                ctx.relay_pool.broadcast(&frame);
            }
        }
    }

    if let Some(record_type) = {
        let mut guard = ctx.store.lock().await;
        guard.put_record_all(&ctx.zones, &nostr_ev)
    } {
        for zone in &ctx.zones {
            ctx.udp_handle.broadcast_record(zone, record_type.as_str(), nostr_ev.clone());
        }
        if let Some(local) = ctx.local_relay.as_ref() {
            if let Ok(app_ev) = build_record_app_event(&ctx.self_pk, &ctx.self_sk, record_type, &nostr_ev) {
                if let Ok(val) = serde_json::to_value(app_ev) {
                    local.publish_event(val).await;
                }
            }
        }
    }

    if let Some(payload) = parse_app_payload(&nostr_ev) {
        let kind = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if (kind == "swarm_identity_record" || kind == "swarm_device_record") && payload.get("record").is_some() {
            if let Ok(record_ev) = serde_json::from_value::<nostr::NostrEvent>(payload["record"].clone()) {
                if let Some(record_type) = {
                    let mut guard = ctx.store.lock().await;
                    guard.put_record_all(&ctx.zones, &record_ev)
                } {
                    for zone in &ctx.zones {
                        ctx.udp_handle.broadcast_record(zone, record_type.as_str(), record_ev.clone());
                    }
                }
            }
        }
        if kind == "swarm_discovery_request" {
            let want_identity = wants_type(&payload, "identity");
            let want_device = wants_type(&payload, "device");
            let guard = ctx.store.lock().await;
            if want_identity {
                for record in guard.list_identity_events_all() {
                    let _ = publish_record_app_event(
                        &ctx.relay_pool,
                        &ctx.local_relay,
                        &ctx.self_pk,
                        &ctx.self_sk,
                        RecordType::Identity,
                        &record,
                    ).await;
                }
            }
            if want_device {
                for record in guard.list_device_events_all() {
                    let _ = publish_record_app_event(
                        &ctx.relay_pool,
                        &ctx.local_relay,
                        &ctx.self_pk,
                        &ctx.self_sk,
                        RecordType::Device,
                        &record,
                    ).await;
                }
            }
        }
    }

    if let Some(endpoint) = parse_zone_presence(&ev, &ctx.zone_keys, &ctx.self_pk) {
        let mut inserted = false;
        let mut all: Vec<String> = Vec::new();
        {
            let mut guard = ctx.peer_set.lock().await;
            if guard.insert(endpoint.clone()) {
                inserted = true;
                all = guard.iter().cloned().collect();
            }
        }
        if inserted {
            all.sort();
            let addrs = transport::resolve_peers(&all).await;
            ctx.udp_handle.set_peers(addrs).await;
            for zone in &ctx.zones {
                ctx.udp_handle.request_records(zone, vec!["identity".to_string(), "device".to_string()]);
            }
            tracing::info!(endpoint = %endpoint, "udp peer discovered from zone presence");
        }
    }
}

fn remember_event(id: String, cache: &mut SeenCache, ttl: Duration, max: usize) {
    let now = Instant::now();
    cache.events.insert(id.clone(), now);
    cache.order.push_back(id);
    while let Some(front) = cache.order.front() {
        let expired = cache.events.get(front).map(|t| t.elapsed() > ttl).unwrap_or(true);
        let over = cache.events.len() > max;
        if !expired && !over {
            break;
        }
        let old = cache.order.pop_front().unwrap();
        if let Some(ts) = cache.events.get(&old) {
            if !over && ts.elapsed() <= ttl {
                continue;
            }
        }
        cache.events.remove(&old);
    }
}

fn parse_zone_presence(ev: &Value, zones: &HashSet<String>, self_pk: &str) -> Option<String> {
    let kind = ev.get("kind")?.as_u64()?;
    if kind != 1 {
        return None;
    }
    let tags = ev.get("tags")?.as_array()?;
    let mut has_app = false;
    let mut zone_tag = None;
    for tag in tags {
        let tag_arr = tag.as_array()?;
        if tag_arr.len() < 2 {
            continue;
        }
        let k = tag_arr[0].as_str().unwrap_or("");
        let v = tag_arr[1].as_str().unwrap_or("");
        if k == "t" && v == "constitute" {
            has_app = true;
        }
        if k == "z" {
            zone_tag = Some(v.to_string());
        }
    }
    if !has_app {
        return None;
    }
    let zone = zone_tag?;
    if !zones.contains(&zone) {
        return None;
    }
    let content = ev.get("content")?.as_str()?;
    let payload: ZonePresencePayload = serde_json::from_str(content).ok()?;
    if payload.zone != zone {
        return None;
    }
    if payload.kind != "zone_presence" {
        return None;
    }
    if payload.device_pk == self_pk {
        return None;
    }
    let swarm = payload.swarm.trim().to_string();
    if swarm.is_empty() {
        return None;
    }
    Some(swarm)
}

fn build_metrics(system: &System, clients: usize) -> discovery::GatewayMetrics {
    let cpu = round_pct(system.global_cpu_info().cpu_usage());
    let total_kb = system.total_memory();
    let used_kb = system.used_memory();
    let mem_pct_raw = if total_kb > 0 {
        (used_kb as f32 / total_kb as f32) * 100.0
    } else {
        0.0
    };
    let mem_pct = round_pct(mem_pct_raw);
    let load_pct = round_pct(cpu.max(mem_pct));
    discovery::GatewayMetrics {
        clients: clients as u64,
        cpu_pct: cpu,
        mem_pct,
        mem_used_mb: used_kb / 1024,
        mem_total_mb: total_kb / 1024,
        load_pct,
        ts: util::now_unix_seconds() * 1000,
    }
}

fn round_pct(value: f32) -> f32 {
    if !value.is_finite() {
        return 0.0;
    }
    let clamped = value.max(0.0).min(100.0);
    (clamped * 10.0).round() / 10.0
}
fn random_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn load_config(path: &PathBuf) -> Option<Config> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_config(path: &PathBuf, cfg: &Config) -> Option<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    let raw = serde_json::to_string_pretty(cfg).ok()?;
    std::fs::write(path, raw).ok()?;
    Some(())
}

fn collect_seed_zones(data_dir: &str, args_zones: &[String]) -> Vec<ZoneConfig> {
    let mut zones: Vec<ZoneConfig> = Vec::new();

    if let Some(k) = read_zone_seed_snapctl() {
        if util::is_valid_zone_key(&k) {
            zones.push(ZoneConfig { key: k, name: "Joined".to_string() });
        }
    }

    if zones.is_empty() {
        if let Some(k) = read_zone_seed_file(data_dir) {
            if util::is_valid_zone_key(&k) {
                zones.push(ZoneConfig { key: k, name: "Joined".to_string() });
            }
        }
    }

    if zones.is_empty() {
        if let Ok(k) = std::env::var("CONSTITUTE_GATEWAY_ZONE") {
            let key = k.trim().to_string();
            if util::is_valid_zone_key(&key) {
                zones.push(ZoneConfig { key: key, name: "Joined".to_string() });
            }
        }
    }

    if zones.is_empty() {
        for k in args_zones {
            let key = k.trim().to_string();
            if util::is_valid_zone_key(&key) {
                zones.push(ZoneConfig { key: key, name: "Joined".to_string() });
            }
        }
    }

    zones
}

fn read_zone_seed_file(data_dir: &str) -> Option<String> {
    let path = PathBuf::from(data_dir).join("zone.seed");
    let raw = std::fs::read_to_string(&path).ok()?;
    let key = raw.trim().to_string();
    let _ = std::fs::remove_file(&path);
    if key.is_empty() { None } else { Some(key) }
}

fn read_zone_seed_snapctl() -> Option<String> {
    if std::env::var("SNAP").is_err() && std::env::var("SNAP_NAME").is_err() {
        return None;
    }
    let out = Command::new("snapctl").arg("get").arg("zone").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if raw.is_empty() || raw == "null" {
        return None;
    }
    let _ = Command::new("snapctl").arg("unset").arg("zone").output();
    Some(raw)
}


