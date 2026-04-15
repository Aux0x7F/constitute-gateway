use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use constitute_gateway::nostr::{self, NostrEvent};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Parser)]
#[command(name = "mission_probe")]
#[command(about = "Small live-mission helper for managed launch probing", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    RecoverSk {
        #[arg(long)]
        partial: String,
        #[arg(long = "expected-pk")]
        expected_pk: String,
    },
    RequestLaunch {
        #[arg(long)]
        relay: String,
        #[arg(long)]
        sk: String,
        #[arg(long)]
        pk: String,
        #[arg(long = "identity-id")]
        identity_id: String,
        #[arg(long = "identity-label", default_value = "Aux")]
        identity_label: String,
        #[arg(long = "device-pk")]
        device_pk: String,
        #[arg(long = "gateway-pk")]
        gateway_pk: String,
        #[arg(long = "service-pk")]
        service_pk: String,
        #[arg(long, default_value = "nvr")]
        service: String,
        #[arg(long, default_value = "nvr.view")]
        capability: String,
        #[arg(long = "app-repo", default_value = "Aux0x7F/constitute-nvr-ui")]
        app_repo: String,
    },
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_sec() -> u64 {
    now_ms() / 1000
}

fn hexish(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn random_suffix() -> String {
    let raw = now_ms();
    format!("{raw:x}")
}

async fn recover_sk(partial: &str, expected_pk: &str) -> Result<()> {
    let partial = hexish(partial);
    let expected_pk = expected_pk.trim().to_ascii_lowercase();
    if partial.len() != 63 {
        return Err(anyhow!("expected a 63-hex partial secret, got {}", partial.len()));
    }
    for nibble in "0123456789abcdef".chars() {
        let candidate = format!("{nibble}{partial}");
        let pk = nostr::pubkey_from_sk_hex(&candidate)?;
        if pk == expected_pk {
            println!("{candidate}");
            return Ok(());
        }
    }
    Err(anyhow!("no matching secret key prefix found"))
}

async fn request_launch(args: &RequestLaunchArgs) -> Result<()> {
    let (mut socket, _) = connect_async(args.relay.trim())
        .await
        .with_context(|| format!("connect relay {}", args.relay.trim()))?;

    let sub_id = format!("mission-probe-{}", random_suffix());
    let req_frame = serde_json::to_string(&json!([
        "REQ",
        sub_id,
        {
            "kinds": [1],
            "#t": ["constitute"],
            "limit": 200
        }
    ]))?;
    socket.send(Message::Text(req_frame.into())).await?;

    let request_id = format!("gw-launch-{}", random_suffix());
    let payload = json!({
        "type": "gateway_managed_launch_request",
        "requestId": request_id,
        "toDevicePk": args.gateway_pk,
        "identityId": args.identity_id,
        "devicePk": args.device_pk,
        "servicePk": args.service_pk,
        "service": args.service,
        "capability": args.capability,
        "appRepo": args.app_repo,
        "display": {
            "shell": "constitute",
            "surface": args.app_repo,
        },
        "ts": now_ms(),
        "ttl": 120,
    });
    let unsigned = nostr::build_unsigned_event(
        &args.pk,
        1,
        vec![
            vec!["t".to_string(), "constitute".to_string()],
            vec!["i".to_string(), args.identity_label.clone()],
            vec!["p".to_string(), args.gateway_pk.clone()],
        ],
        payload.to_string(),
        now_sec(),
    );
    let event = nostr::sign_event(&unsigned, &args.sk)?;
    let event_frame = serde_json::to_string(&json!(["EVENT", event]))?;
    socket.send(Message::Text(event_frame.into())).await?;

    let timeout = tokio::time::sleep(std::time::Duration::from_secs(25));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => return Err(anyhow!("timed out waiting for gateway_managed_launch_status")),
            next = socket.next() => {
                let Some(next) = next else {
                    return Err(anyhow!("relay closed before launch status arrived"));
                };
                let message = next?;
                let Message::Text(text) = message else { continue };
                let Ok(frame) = serde_json::from_str::<Value>(&text) else { continue };
                let Some(kind) = frame.get(0).and_then(Value::as_str) else { continue };
                if kind != "EVENT" {
                    continue;
                }
                let Some(event_value) = frame.get(1) else { continue };
                let Ok(event) = serde_json::from_value::<NostrEvent>(event_value.clone()) else { continue };
                let Ok(content) = serde_json::from_str::<Value>(&event.content) else { continue };
                if content.get("type").and_then(Value::as_str) != Some("gateway_managed_launch_status") {
                    continue;
                }
                if content.get("requestId").and_then(Value::as_str) != Some(request_id.as_str()) {
                    continue;
                }
                let launch_id = format!("launch-{}", random_suffix());
                let launch_context = json!({
                    "launchId": launch_id,
                    "app": "constitute-nvr-ui",
                    "repo": args.app_repo,
                    "identityId": args.identity_id,
                    "devicePk": args.device_pk,
                    "gatewayPk": args.gateway_pk,
                    "servicePk": args.service_pk,
                    "service": args.service,
                    "launchToken": content.get("launchToken").cloned().unwrap_or(Value::String(String::new())),
                    "display": content.get("display").cloned().unwrap_or(Value::Null),
                    "createdAt": now_ms(),
                    "expiresAt": content.get("expiresAt").cloned().unwrap_or(Value::from(now_ms() + 60_000)),
                });
                let output = json!({
                    "requestId": request_id,
                    "status": content,
                    "launchContext": launch_context,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            }
        }
    }
}

struct RequestLaunchArgs {
    relay: String,
    sk: String,
    pk: String,
    identity_id: String,
    identity_label: String,
    device_pk: String,
    gateway_pk: String,
    service_pk: String,
    service: String,
    capability: String,
    app_repo: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::RecoverSk { partial, expected_pk } => recover_sk(&partial, &expected_pk).await,
        Command::RequestLaunch {
            relay,
            sk,
            pk,
            identity_id,
            identity_label,
            device_pk,
            gateway_pk,
            service_pk,
            service,
            capability,
            app_repo,
        } => {
            let args = RequestLaunchArgs {
                relay,
                sk,
                pk,
                identity_id,
                identity_label,
                device_pk,
                gateway_pk,
                service_pk,
                service,
                capability,
                app_repo,
            };
            request_launch(&args).await
        }
    }
}
