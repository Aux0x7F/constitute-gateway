mod discovery;
mod nostr;
mod platform;
mod relay;
mod transport;
mod util;

use anyhow::Result;
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
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
    #[serde(default)]
    nostr_pubkey: String,
    #[serde(default)]
    nostr_sk_hex: String,
    #[serde(default)]
    identity_id: String,
    #[serde(default)]
    device_label: String,
    #[serde(default = "default_nostr_kind")]
    nostr_kind: u32,
    #[serde(default = "default_nostr_tag")]
    nostr_tag: String,
    #[serde(default = "default_publish_interval_secs")]
    nostr_publish_interval_secs: u64,
    #[serde(default)]
    stun_servers: Vec<String>,
    #[serde(default)]
    turn_servers: Vec<String>,
    #[serde(default)]
    zones: Vec<ZoneConfig>,
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
            .ok_or_else(|| anyhow::anyhow!("invalid log level: {}", args.log_level))?;
        std::env::set_var("RUST_LOG", level);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_path = args.config.unwrap_or_else(platform::default_config_path);
    let mut cfg = load_config(&config_path).unwrap_or_default();

    if cfg.zones.is_empty() && !args.zone.is_empty() {
        cfg.zones = args
            .zone
            .iter()
            .map(|k| ZoneConfig {
                key: k.trim().to_string(),
                name: "Joined".to_string(),
            })
            .collect();
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

    if cfg.nostr_sk_hex.trim().is_empty() {
        let (pk, sk) = nostr::generate_keypair();
        cfg.nostr_pubkey = pk;
        cfg.nostr_sk_hex = sk;
        dirty = true;
    } else if cfg.nostr_pubkey.trim().is_empty() {
        if let Ok(pk) = nostr::pubkey_from_sk_hex(&cfg.nostr_sk_hex) {
            cfg.nostr_pubkey = pk;
            dirty = true;
        }
    }

    if dirty {
        let _ = save_config(&config_path, &cfg);
    }

    if cfg.node_id.is_empty() {
        warn!("node_id not set; using nostr pubkey as identity");
        cfg.node_id = cfg.nostr_pubkey.clone();
    }

    if cfg.nostr_relays.is_empty() {
        warn!("nostr_relays empty; discovery bootstrap disabled (placeholder)");
    }

    if cfg.nostr_pubkey.is_empty() || cfg.nostr_sk_hex.is_empty() {
        warn!("nostr keys missing; discovery events will fail to sign");
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
