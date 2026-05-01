use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use constitute_gateway::nostr::{self, NostrEvent};
use constitute_protocol::{
    open_envelope, seal_envelope, CaacEnvelope, CAAC_KIND_SERVICE_ACCESS_REQUEST,
    CAAC_KIND_SERVICE_ACCESS_STATUS,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Parser)]
#[command(name = "mission_probe")]
#[command(about = "Small live-mission helper for service access probing", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    RecoverSk {
        #[arg(long)]
        partial: String,
        #[arg(long = "expected-pk")]
        expected_pk: String,
    },
    RequestServiceAccess {
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
        return Err(anyhow!(
            "expected a 63-hex partial secret, got {}",
            partial.len()
        ));
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

async fn request_service_access(args: &RequestServiceAccessArgs) -> Result<()> {
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
    socket.send(Message::Text(req_frame)).await?;

    let request_id = format!("gw-service-access-{}", random_suffix());
    let issued_at = now_ms();
    let request_claims = json!({
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
        "ts": issued_at,
        "ttl": 90,
    });
    let request_envelope = seal_envelope(
        CAAC_KIND_SERVICE_ACCESS_REQUEST,
        &request_claims,
        &args.sk,
        &[args.gateway_pk.clone()],
        issued_at,
        issued_at + 90_000,
    )?;
    let payload = json!({
        "type": "gateway_service_access_request",
        "requestId": request_id,
        "toDevicePk": args.gateway_pk,
        "requestEnvelope": request_envelope,
        "ts": issued_at,
        "ttl": 90,
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
    socket.send(Message::Text(event_frame)).await?;

    let timeout = tokio::time::sleep(std::time::Duration::from_secs(25));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => return Err(anyhow!("timed out waiting for gateway_service_access_status")),
            next = socket.next() => {
                let Some(next) = next else {
                    return Err(anyhow!("relay closed before service access status arrived"));
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
                if content.get("type").and_then(Value::as_str) != Some("gateway_service_access_status") {
                    continue;
                }
                let Some(envelope_value) = content.get("statusEnvelope") else {
                    continue;
                };
                let Ok(envelope) = serde_json::from_value::<CaacEnvelope>(envelope_value.clone()) else { continue };
                if envelope.kind != CAAC_KIND_SERVICE_ACCESS_STATUS {
                    continue;
                }
                let Ok(status) = open_envelope(&envelope, &args.sk, now_ms(), None) else { continue };
                if status.get("requestId").and_then(Value::as_str) != Some(request_id.as_str()) {
                    continue;
                }
                let service_access_id = format!("service-access-{}", random_suffix());
                let service_access_context = json!({
                    "contextId": service_access_id,
                    "app": "constitute-nvr-ui",
                    "repo": args.app_repo,
                    "identityId": args.identity_id,
                    "devicePk": args.device_pk,
                    "gatewayPk": args.gateway_pk,
                    "servicePk": args.service_pk,
                    "service": args.service,
                    "serviceCapability": status.get("serviceCapability").cloned().unwrap_or(Value::String(String::new())),
                    "display": status.get("display").cloned().unwrap_or(Value::Null),
                    "createdAt": now_ms(),
                    "expiresAt": status.get("expiresAt").cloned().unwrap_or(Value::from(now_ms() + 60_000)),
                });
                let output = json!({
                    "requestId": request_id,
                    "status": status,
                    "serviceAccessContext": service_access_context,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            }
        }
    }
}

struct RequestServiceAccessArgs {
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
        Command::RecoverSk {
            partial,
            expected_pk,
        } => recover_sk(&partial, &expected_pk).await,
        Command::RequestServiceAccess {
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
            let args = RequestServiceAccessArgs {
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
            request_service_access(&args).await
        }
    }
}
