use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use constitute_protocol::{
    swarm_frame_id, validate_swarm_frame, SwarmFrame, SwarmFrameBody, SwarmFrameKind, ZoneScope,
    CAPABILITY_SERVICE_INTENT_INVOKE, SWARM_FRAME_VERSION,
};
use serde_json::json;
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(name = "swarm_edge_probe")]
#[command(about = "Small swarm-edge diagnostic for SwarmFrame routing records", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    ExampleFrame {
        #[arg(long, default_value = "gateway-local")]
        gateway_pk: String,
        #[arg(long, default_value = "actor-local")]
        issuer: String,
        #[arg(long, default_value = "svc-nvr")]
        service_ref: String,
        #[arg(long, default_value = "zone-local")]
        zone_id: String,
        #[arg(long, default_value = "nvr.control")]
        channel_id: String,
    },
    ValidateFrame {
        #[arg(long)]
        frame: Option<String>,
        #[arg(long = "frame-file")]
        frame_file: Option<PathBuf>,
    },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn caac_body(label: &str) -> SwarmFrameBody {
    SwarmFrameBody {
        encoding: "caac".to_string(),
        envelope: Some(json!({ "diagnostic": label })),
        public_bootstrap: false,
        payload: None,
        signature: None,
    }
}

fn build_example_frame(
    gateway_pk: String,
    issuer: String,
    service_ref: String,
    zone_id: String,
    channel_id: String,
) -> Result<SwarmFrame> {
    let now = now_ms();
    let mut frame = SwarmFrame {
        version: SWARM_FRAME_VERSION,
        frame_id: String::new(),
        kind: SwarmFrameKind::ServiceIntent,
        issuer,
        audience: json!({
            "gatewayRef": gateway_pk,
            "serviceRef": service_ref,
        }),
        zone_scope: Some(ZoneScope {
            zone_id,
            privacy: Some("rawIds".to_string()),
            ttl: Some(4),
            max_hops: Some(2),
        }),
        issued_at: now,
        expires_at: Some(now + 60_000),
        nonce: format!("swarm-edge-probe-{now}"),
        correlation_id: Some(format!("swarm-edge-probe-{now}")),
        channel_id: Some(channel_id),
        record_ref: None,
        capability: Some(CAPABILITY_SERVICE_INTENT_INVOKE.to_string()),
        body: caac_body("example"),
        ack: None,
    };
    frame.frame_id = swarm_frame_id(&frame).context("build swarm frame id")?;
    Ok(frame)
}

fn read_frame_arg(frame: Option<String>, frame_file: Option<PathBuf>) -> Result<String> {
    if let Some(frame) = frame {
        return Ok(frame);
    }
    if let Some(path) = frame_file {
        return fs::read_to_string(&path)
            .with_context(|| format!("read frame file {}", path.display()));
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("read frame json from stdin")?;
    Ok(input)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ExampleFrame {
            gateway_pk,
            issuer,
            service_ref,
            zone_id,
            channel_id,
        } => {
            let frame = build_example_frame(gateway_pk, issuer, service_ref, zone_id, channel_id)?;
            println!("{}", serde_json::to_string_pretty(&frame)?);
        }
        Command::ValidateFrame { frame, frame_file } => {
            let input = read_frame_arg(frame, frame_file)?;
            let frame: SwarmFrame = serde_json::from_str(&input).context("parse swarm frame")?;
            validate_swarm_frame(&frame, now_ms()).context("validate swarm frame")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "valid": true,
                    "frameId": frame.frame_id,
                    "kind": frame.kind,
                    "channelId": frame.channel_id,
                    "correlationId": frame.correlation_id,
                }))?
            );
        }
    }
    Ok(())
}
