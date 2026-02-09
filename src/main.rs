mod discovery;
mod keystore;
mod nostr;
mod platform;
mod relay;
mod transport;
mod util;

use anyhow::{anyhow, Result};
use clap::{ArgAction, Parser};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
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
    #[serde(default = "default_self_test_enabled")]
    self_test: bool,
    #[serde(default = "default_self_test_timeout_secs")]
    self_test_timeout_secs: u64,
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default)]
    turn_servers: Vec<String>,
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

fn default_self_test_enabled() -> bool {
    true
}

fn default_self_test_timeout_secs() -> u64 {
    8
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

    let zones = cfg.zones.iter().map(|z| z.key.clone()).collect::<Vec<_>>();
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

    let discovery_client = discovery::DiscoveryClient::new(
        cfg.nostr_relays.clone(),
        device_record,
        cfg.nostr_pubkey.clone(),
        cfg.nostr_sk_hex.clone(),
        Duration::from_secs(cfg.nostr_publish_interval_secs),
        zones,
    );
    tokio::spawn(async move {
        if let Err(err) = discovery_client.run().await {
            tracing::warn!(error = %err, "nostr discovery loop failed");
        }
    });

    let bind = cfg.bind.clone();
    tokio::spawn(async move {
        if let Err(err) = transport::start_udp(&bind).await {
            tracing::warn!(error = %err, "udp listener failed");
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
                zones.push(ZoneConfig { key, name: "Joined".to_string() });
            }
        }
    }

    if zones.is_empty() {
        for k in args_zones {
            let key = k.trim().to_string();
            if util::is_valid_zone_key(&key) {
                zones.push(ZoneConfig { key, name: "Joined".to_string() });
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
