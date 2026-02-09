mod discovery;
mod platform;

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "constitute-gateway", version, about = "Constitute native gateway (skeleton)")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "warn")]
    log_level: String,
}

#[derive(Debug, Deserialize, Default)]
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
    stun_servers: Vec<String>,
    #[serde(default)]
    turn_servers: Vec<String>,
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

fn normalize_log_level(level: &str) -> Option<&'static str> {
    match level.to_lowercase().as_str() {
        "trace" => Some("trace"),
        "debug" => Some("debug"),
        "info" => Some("info"),
        "warn" | "warning" => Some("warn"),
        "error" => Some("error"),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if std::env::var("RUST_LOG").is_err() {
        let level = normalize_log_level(&args.log_level)
            .ok_or_else(|| anyhow::anyhow!("invalid log level: {}", args.log_level))?;
        std::env::set_var("RUST_LOG", level);
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_path = args.config.unwrap_or_else(platform::default_config_path);
    let cfg = load_config(&config_path).unwrap_or_default();

    if cfg.node_id.is_empty() {
        warn!("node_id not set; using ephemeral identity (placeholder)");
    }

    if cfg.nostr_relays.is_empty() {
        warn!("nostr_relays empty; discovery bootstrap disabled (placeholder)");
    }

    let node_type = cfg.node_type.clone().unwrap_or_else(default_node_type);
    let record = discovery::DiscoveryRecord::new(&cfg.node_id, node_type.clone());

    info!(
        bind = %cfg.bind,
        data_dir = %cfg.data_dir,
        node_type = %node_type,
        "gateway starting (skeleton)"
    );
    info!("build target is intended for Ubuntu Core (linux)");
    info!(record = %record.to_json(), "discovery record (placeholder)");

    platform::init();

    // TODO: QUIC/UDP listener
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
