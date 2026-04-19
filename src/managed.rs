use super::*;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct HostedNvrManifest {
    #[serde(default)]
    service: String,
    #[serde(default)]
    service_pk: String,
    #[serde(default)]
    device_label: String,
    #[serde(default)]
    service_version: String,
    #[serde(default)]
    host_gateway_pk: String,
    #[serde(default)]
    api_bind: String,
    #[serde(default)]
    api_base_url: String,
    #[serde(default)]
    health_url: String,
    #[serde(default)]
    camera_devices: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct HostedNvrConfig {
    #[serde(default)]
    service_version: String,
    #[serde(default)]
    nostr_pubkey: String,
    #[serde(default)]
    device_label: String,
    #[serde(default)]
    camera_devices: Vec<Value>,
    #[serde(default)]
    api: HostedNvrApiConfig,
    #[serde(default)]
    gateway: HostedNvrGatewayConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct HostedNvrApiConfig {
    #[serde(default)]
    bind: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct HostedNvrGatewayConfig {
    #[serde(default, rename = "host_gateway_pk")]
    host_gateway_pk: String,
    #[serde(default, rename = "hostGatewayPk")]
    host_gateway_pk_camel: String,
}

#[derive(Debug, Clone)]
pub(super) struct HostedNvrService {
    pub record: discovery::HostedServiceRecord,
    pub api_base_url: String,
    pub health: Value,
    pub config: HostedNvrConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedLaunchTokenPayload {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "gatewayPk")]
    gateway_pk: String,
    #[serde(rename = "servicePk")]
    service_pk: String,
    service: String,
    #[serde(rename = "identityId")]
    identity_id: String,
    #[serde(rename = "devicePk")]
    device_pk: String,
    capability: String,
    #[serde(default)]
    owner: bool,
    #[serde(rename = "viewSources", default)]
    view_sources: Vec<String>,
    #[serde(rename = "controlSources", default)]
    control_sources: Vec<String>,
    #[serde(rename = "launchNonce")]
    launch_nonce: String,
    #[serde(rename = "issuedAt")]
    issued_at: u64,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

fn normalize_gateway_managed_launch_request(req: &mut GatewayManagedLaunchRequest) {
    req.request_id = trim_nonempty(&req.request_id);
    if req.request_id.is_empty() {
        req.request_id = make_install_request_id();
    }
    req.to_device_pk = trim_nonempty(&req.to_device_pk);
    req.identity_id = trim_nonempty(&req.identity_id);
    req.device_pk = trim_nonempty(&req.device_pk);
    req.service_pk = trim_nonempty(&req.service_pk);
    req.service = trim_nonempty(&req.service).to_ascii_lowercase();
    req.capability = trim_nonempty(&req.capability).to_ascii_lowercase();
    req.launch_nonce = trim_nonempty(&req.launch_nonce);
    req.zone = trim_nonempty(&req.zone);
    req.app_repo = trim_nonempty(&req.app_repo);
}

fn normalize_gateway_signal_request(req: &mut GatewaySignalRequest) {
    req.request_id = trim_nonempty(&req.request_id);
    if req.request_id.is_empty() {
        req.request_id = make_install_request_id();
    }
    req.to_device_pk = trim_nonempty(&req.to_device_pk);
    req.identity_id = trim_nonempty(&req.identity_id);
    req.device_pk = trim_nonempty(&req.device_pk);
    req.service_pk = trim_nonempty(&req.service_pk);
    req.service = trim_nonempty(&req.service).to_ascii_lowercase();
    req.signal_type = trim_nonempty(&req.signal_type).to_ascii_lowercase();
    req.launch_token = trim_nonempty(&req.launch_token);
}

pub(super) fn gateway_offer_candidates(payload: &Value) -> Value {
    let mut items = Vec::new();
    let mut push_array = |value: Option<&Value>| {
        if let Some(Value::Array(candidates)) = value {
            for candidate in candidates {
                if !items.contains(candidate) {
                    items.push(candidate.clone());
                }
            }
        }
    };
    push_array(payload.get("candidates"));
    push_array(payload.get("offer").and_then(|value| value.get("candidates")));
    Value::Array(items)
}

fn nvr_config_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(PathBuf::from("/etc/constitute-nvr/config.json"));
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        out.push(
            PathBuf::from(local_appdata)
                .join("Constitute")
                .join("nvr")
                .join("config.json"),
        );
    }
    out
}

fn nvr_manifest_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(PathBuf::from("/data/constitute-nvr/hosted-service.json"));
    out.push(PathBuf::from("/run/constitute/nvr-hosted-service.json"));
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        out.push(
            PathBuf::from(local_appdata)
                .join("Constitute")
                .join("nvr")
                .join("hosted-service.json"),
        );
    }
    out
}

fn nvr_local_base_url(bind: &str) -> Option<String> {
    let mut raw = bind.trim().to_string();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains(':') {
        raw = format!("127.0.0.1:{raw}");
    }
    let addr: SocketAddr = raw.parse().ok()?;
    Some(format!("http://127.0.0.1:{}", addr.port()))
}

async fn load_hosted_nvr_service_from_manifest(
    client: &HttpClient,
    gateway_pk: &str,
    manifest: &HostedNvrManifest,
) -> Option<HostedNvrService> {
    let service_pk = manifest.service_pk.trim().to_string();
    if service_pk.is_empty() {
        return None;
    }
    let api_base_url = if !manifest.api_base_url.trim().is_empty() {
        manifest.api_base_url.trim().to_string()
    } else {
        nvr_local_base_url(&manifest.api_bind)?
    };
    let health_url = if !manifest.health_url.trim().is_empty() {
        manifest.health_url.trim().to_string()
    } else {
        format!("{api_base_url}/health")
    };
    let fallback_cfg = HostedNvrConfig {
        service_version: manifest.service_version.trim().to_string(),
        nostr_pubkey: service_pk.clone(),
        device_label: manifest.device_label.trim().to_string(),
        camera_devices: manifest.camera_devices.clone(),
        api: HostedNvrApiConfig {
            bind: manifest.api_bind.trim().to_string(),
        },
        gateway: HostedNvrGatewayConfig {
            host_gateway_pk: manifest.host_gateway_pk.trim().to_string(),
            host_gateway_pk_camel: String::new(),
        },
    };

    let now = util::now_unix_seconds() * 1000;
    let mut status = "configured".to_string();
    let mut camera_count = fallback_cfg.camera_devices.len() as u64;
    if let Ok(resp) = client
        .get(&health_url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<Value>().await {
                status = "online".to_string();
                let health = body.clone();
                camera_count = body
                    .get("configuredSources")
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        body.get("sources")
                            .and_then(|v| v.as_array())
                            .map(|v| v.len() as u64)
                    })
                    .unwrap_or(camera_count);
                return Some(HostedNvrService {
                    record: discovery::HostedServiceRecord {
                        device_pk: service_pk,
                        device_label: if manifest.device_label.trim().is_empty() {
                            "Constitute NVR".to_string()
                        } else {
                            manifest.device_label.trim().to_string()
                        },
                        device_kind: "service".to_string(),
                        service: if manifest.service.trim().is_empty() {
                            "nvr".to_string()
                        } else {
                            manifest.service.trim().to_string()
                        },
                        host_gateway_pk: if manifest.host_gateway_pk.trim().is_empty() {
                            gateway_pk.trim().to_string()
                        } else {
                            manifest.host_gateway_pk.trim().to_string()
                        },
                        service_version: if manifest.service_version.trim().is_empty() {
                            env!("CARGO_PKG_VERSION").to_string()
                        } else {
                            manifest.service_version.trim().to_string()
                        },
                        updated_at: now,
                        freshness_ms: 0,
                        status,
                        camera_count,
                    },
                    api_base_url,
                    health,
                    config: fallback_cfg,
                });
            }
        } else {
            status = "offline".to_string();
        }
    } else {
        status = "offline".to_string();
    }

    Some(HostedNvrService {
        record: discovery::HostedServiceRecord {
            device_pk: service_pk,
            device_label: if manifest.device_label.trim().is_empty() {
                "Constitute NVR".to_string()
            } else {
                manifest.device_label.trim().to_string()
            },
            device_kind: "service".to_string(),
            service: if manifest.service.trim().is_empty() {
                "nvr".to_string()
            } else {
                manifest.service.trim().to_string()
            },
            host_gateway_pk: if manifest.host_gateway_pk.trim().is_empty() {
                gateway_pk.trim().to_string()
            } else {
                manifest.host_gateway_pk.trim().to_string()
            },
            service_version: if manifest.service_version.trim().is_empty() {
                env!("CARGO_PKG_VERSION").to_string()
            } else {
                manifest.service_version.trim().to_string()
            },
            updated_at: now,
            freshness_ms: 0,
            status,
            camera_count,
        },
        api_base_url,
        health: json!({}),
        config: fallback_cfg,
    })
}

async fn load_hosted_nvr_service(client: &HttpClient, gateway_pk: &str) -> Option<HostedNvrService> {
    for path in nvr_manifest_candidates() {
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let manifest: HostedNvrManifest = match serde_json::from_str(&raw) {
            Ok(manifest) => manifest,
            Err(_) => continue,
        };
        if let Some(service) = load_hosted_nvr_service_from_manifest(client, gateway_pk, &manifest).await {
            return Some(service);
        }
    }
    for path in nvr_config_candidates() {
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let cfg: HostedNvrConfig = match serde_json::from_str(&raw) {
            Ok(cfg) => cfg,
            Err(_) => continue,
        };
        let service_pk = cfg.nostr_pubkey.trim().to_string();
        if service_pk.is_empty() {
            continue;
        }
        let api_base_url = match nvr_local_base_url(&cfg.api.bind) {
            Some(url) => url,
            None => continue,
        };

        let now = util::now_unix_seconds() * 1000;
        let mut status = "configured".to_string();
        let mut camera_count = cfg.camera_devices.len() as u64;
        if let Ok(resp) = client
            .get(format!("{api_base_url}/health"))
            .timeout(Duration::from_secs(3))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<Value>().await {
                    status = "online".to_string();
                    let health = body.clone();
                    camera_count = body
                        .get("configuredSources")
                        .and_then(|v| v.as_u64())
                        .or_else(|| {
                            body.get("sources")
                                .and_then(|v| v.as_array())
                                .map(|v| v.len() as u64)
                        })
                        .unwrap_or(camera_count);
                    return Some(HostedNvrService {
                        record: discovery::HostedServiceRecord {
                            device_pk: service_pk,
                            device_label: if cfg.device_label.trim().is_empty() {
                                "Constitute NVR".to_string()
                            } else {
                                cfg.device_label.trim().to_string()
                            },
                            device_kind: "service".to_string(),
                            service: "nvr".to_string(),
                            host_gateway_pk: {
                                let explicit = cfg.gateway.host_gateway_pk.trim();
                                if explicit.is_empty() {
                                    let alt = cfg.gateway.host_gateway_pk_camel.trim();
                                    if alt.is_empty() {
                                        gateway_pk.trim()
                                    } else {
                                        alt
                                    }
                                } else {
                                    explicit
                                }
                            }
                            .to_string(),
                            service_version: if cfg.service_version.trim().is_empty() {
                                env!("CARGO_PKG_VERSION").to_string()
                            } else {
                                cfg.service_version.trim().to_string()
                            },
                            updated_at: now,
                            freshness_ms: 0,
                            status,
                            camera_count,
                        },
                        api_base_url,
                        health,
                        config: cfg.clone(),
                    });
                }
            } else {
                status = "offline".to_string();
            }
        } else {
            status = "offline".to_string();
        }
        let host_gateway_pk = {
            let explicit = cfg.gateway.host_gateway_pk.trim();
            if explicit.is_empty() {
                let alt = cfg.gateway.host_gateway_pk_camel.trim();
                if alt.is_empty() {
                    gateway_pk.trim()
                } else {
                    alt
                }
            } else {
                explicit
            }
        }
        .to_string();

        return Some(HostedNvrService {
            record: discovery::HostedServiceRecord {
                device_pk: service_pk,
                device_label: if cfg.device_label.trim().is_empty() {
                    "Constitute NVR".to_string()
                } else {
                    cfg.device_label.trim().to_string()
                },
                device_kind: "service".to_string(),
                service: "nvr".to_string(),
                host_gateway_pk,
                service_version: if cfg.service_version.trim().is_empty() {
                    env!("CARGO_PKG_VERSION").to_string()
                } else {
                    cfg.service_version.trim().to_string()
                },
                updated_at: now,
                freshness_ms: 0,
                status,
                camera_count,
            },
            api_base_url,
            health: json!({}),
            config: cfg.clone(),
        });
    }
    None
}

pub(super) async fn load_hosted_services_snapshot(
    client: &HttpClient,
    gateway_pk: &str,
) -> Vec<discovery::HostedServiceRecord> {
    match load_hosted_nvr_service(client, gateway_pk).await {
        Some(service) => vec![service.record],
        None => Vec::new(),
    }
}

async fn is_requester_authorized_for_service_install(
    ctx: &InboundContext,
    requester_pk: &str,
    identity_id: &str,
) -> bool {
    let requester = requester_pk.trim();
    let identity = identity_id.trim();
    if requester.is_empty() || identity.is_empty() {
        return false;
    }

    if !ctx.authorized_control_device_pks.is_empty()
        && !ctx.authorized_control_device_pks.contains(requester)
    {
        return false;
    }

    let guard = ctx.store.lock().await;
    let rec = match guard.get_device_event_any(requester) {
        Some(rec) => rec,
        None => return false,
    };
    match record_identity_id(&rec) {
        Some(id) => id.trim() == identity,
        None => false,
    }
}

fn build_managed_launch_token(
    pubkey: &str,
    sk_hex: &str,
    payload: &ManagedLaunchTokenPayload,
) -> Result<String> {
    let tags = vec![
        vec!["t".to_string(), "constitute".to_string()],
        vec!["type".to_string(), "managed_launch_token".to_string()],
        vec!["service".to_string(), payload.service.clone()],
        vec!["p".to_string(), payload.device_pk.clone()],
        vec!["p".to_string(), payload.service_pk.clone()],
    ];
    let unsigned = nostr::build_unsigned_event(
        pubkey,
        27235,
        tags,
        serde_json::to_string(payload)?,
        util::now_unix_seconds(),
    );
    let ev = nostr::sign_event(&unsigned, sk_hex)?;
    Ok(serde_json::to_string(&ev)?)
}

fn parse_managed_launch_token(token: &str) -> Result<(nostr::NostrEvent, ManagedLaunchTokenPayload)> {
    let ev: nostr::NostrEvent = serde_json::from_str(token).context("invalid launch token json")?;
    if !nostr::verify_event(&ev)? {
        return Err(anyhow!("invalid launch token signature"));
    }
    let payload: ManagedLaunchTokenPayload =
        serde_json::from_str(&ev.content).context("invalid launch token payload")?;
    Ok((ev, payload))
}

async fn publish_gateway_service_install_status(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    payload: &GatewayServiceInstallStatusPayload,
) -> Result<()> {
    if pubkey.is_empty() || sk_hex.is_empty() {
        return Ok(());
    }
    let value = serde_json::to_value(payload)?;
    let ev = build_app_event(pubkey, sk_hex, &value)?;
    relay_pool.broadcast(&nostr::frame_event(&ev));
    if let Some(local) = local_relay.as_ref() {
        if let Ok(val) = serde_json::to_value(ev) {
            local.publish_event(val).await;
        }
    }
    Ok(())
}

async fn publish_gateway_zone_sync_status(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    payload: &GatewayZoneSyncStatusPayload,
) -> Result<()> {
    if pubkey.is_empty() || sk_hex.is_empty() {
        return Ok(());
    }
    let value = serde_json::to_value(payload)?;
    let ev = build_app_event(pubkey, sk_hex, &value)?;
    relay_pool.broadcast(&nostr::frame_event(&ev));
    if let Some(local) = local_relay.as_ref() {
        if let Ok(val) = serde_json::to_value(ev) {
            local.publish_event(val).await;
        }
    }
    Ok(())
}

async fn publish_gateway_managed_launch_status(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    payload: &GatewayManagedLaunchStatusPayload,
) -> Result<()> {
    if pubkey.is_empty() || sk_hex.is_empty() {
        return Ok(());
    }
    warn!(
        request_id = %payload.request_id,
        status = %payload.status,
        gateway_pk = %payload.gateway_pk,
        device_pk = %payload.device_pk,
        service_pk = %payload.service_pk,
        "publishing managed launch status"
    );
    let value = serde_json::to_value(payload)?;
    let ev = build_app_event(pubkey, sk_hex, &value)?;
    relay_pool.broadcast(&nostr::frame_event(&ev));
    if let Some(local) = local_relay.as_ref() {
        if let Ok(val) = serde_json::to_value(ev) {
            local.publish_event(val).await;
        }
    }
    Ok(())
}

async fn publish_gateway_signal_status(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    payload: &GatewaySignalStatusPayload,
) -> Result<()> {
    if pubkey.is_empty() || sk_hex.is_empty() {
        return Ok(());
    }
    let value = serde_json::to_value(payload)?;
    let ev = build_app_event(pubkey, sk_hex, &value)?;
    relay_pool.broadcast(&nostr::frame_event(&ev));
    if let Some(local) = local_relay.as_ref() {
        if let Ok(val) = serde_json::to_value(ev) {
            local.publish_event(val).await;
        }
    }
    Ok(())
}

async fn publish_gateway_signal(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    payload: &GatewaySignalPayload,
) -> Result<()> {
    if pubkey.is_empty() || sk_hex.is_empty() {
        return Ok(());
    }
    let value = serde_json::to_value(payload)?;
    let ev = build_app_event(pubkey, sk_hex, &value)?;
    relay_pool.broadcast(&nostr::frame_event(&ev));
    if let Some(local) = local_relay.as_ref() {
        if let Ok(val) = serde_json::to_value(ev) {
            local.publish_event(val).await;
        }
    }
    Ok(())
}

fn build_managed_service_display(
    hosted: &HostedNvrService,
    req: &GatewayManagedLaunchRequest,
    scope: &grants::GrantScope,
    stun_servers: &[String],
    turn_servers: &[String],
) -> Value {
    let fallback_sources = {
        let live = service_sources_from_health(&hosted.health);
        if live.is_empty() {
            service_sources_from_config(&hosted.config.camera_devices)
        } else {
            live
        }
    };
    let sources = if scope.view_sources.is_empty() {
        fallback_sources
    } else {
        scope.view_sources.clone()
    };
    let source_runtime = hosted
        .health
        .get("sourceRuntime")
        .and_then(|value| value.as_array())
        .map(|entries| {
            Value::Array(
                entries
                    .iter()
                    .filter(|entry| {
                        let source_id = entry
                            .get("sourceId")
                            .or_else(|| entry.get("source_id"))
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .trim();
                        !source_id.is_empty() && sources.iter().any(|allowed| allowed == source_id)
                    })
                    .cloned()
                    .collect(),
            )
        })
        .unwrap_or_else(|| json!([]));
    json!({
        "gatewayPk": hosted.record.host_gateway_pk.clone(),
        "servicePk": hosted.record.device_pk.clone(),
        "serviceLabel": hosted.record.device_label.clone(),
        "serviceVersion": hosted.record.service_version.clone(),
        "service": hosted.record.service.clone(),
        "status": hosted.record.status.clone(),
        "cameraCount": sources.len(),
        "sources": sources,
        "cameras": scope.cameras.clone(),
        "sourceRuntime": source_runtime,
        "configuredSources": hosted.health.get("configuredSources").cloned().unwrap_or_else(|| json!(hosted.record.camera_count)),
        "grantedScope": {
            "owner": scope.owner,
            "viewSources": scope.view_sources.clone(),
            "controlSources": scope.control_sources.clone(),
            "grantIds": scope.grant_ids.clone(),
        },
        "iceServers": {
            "stun": stun_servers,
            "turn": turn_servers,
        },
        "appRepo": req.app_repo.clone(),
        "requestDisplay": req.display.clone(),
    })
}

pub(super) fn camera_resources_from_hosted(hosted: &HostedNvrService) -> Vec<grants::CameraResource> {
    let mut resources = Vec::new();
    let mut seen = HashSet::new();

    if let Some(cameras) = hosted
        .health
        .get("cameraDevices")
        .and_then(|value| value.as_array())
    {
        for camera in cameras {
            let source_id = camera
                .get("sourceId")
                .or_else(|| camera.get("source_id"))
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if source_id.is_empty() || !seen.insert(source_id.clone()) {
                continue;
            }
            let name = camera
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or(&source_id)
                .trim()
                .to_string();
            let ptz_capable = camera
                .get("ptzCapable")
                .or_else(|| camera.get("ptz_capable"))
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            resources.push(grants::CameraResource {
                source_id,
                name,
                ptz_capable,
            });
        }
    }

    for camera in &hosted.config.camera_devices {
        let source_id = camera
            .get("sourceId")
            .or_else(|| camera.get("source_id"))
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if source_id.is_empty() || !seen.insert(source_id.clone()) {
            continue;
        }
        let name = camera
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or(&source_id)
            .trim()
            .to_string();
        let ptz_capable = camera
            .get("ptzCapable")
            .or_else(|| camera.get("ptz_capable"))
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        resources.push(grants::CameraResource {
            source_id,
            name,
            ptz_capable,
        });
    }

    resources
}

pub(super) async fn load_target_hosted_service(
    ctx: &InboundContext,
    service_pk: &str,
    service: &str,
) -> Result<HostedNvrService> {
    let service_slug = service.trim().to_ascii_lowercase();
    if service_slug != "nvr" {
        return Err(anyhow!("unsupported managed service"));
    }
    let hosted = load_hosted_nvr_service(&ctx.http_client, &ctx.self_pk)
        .await
        .ok_or_else(|| anyhow!("hosted nvr service not configured"))?;
    if !service_pk.trim().is_empty() && hosted.record.device_pk.trim() != service_pk.trim() {
        return Err(anyhow!("requested service pk does not match hosted service"));
    }
    Ok(hosted)
}

fn validate_managed_launch_token_for_request(
    ctx: &InboundContext,
    req: &GatewaySignalRequest,
) -> Result<ManagedLaunchTokenPayload> {
    let (event, token) = parse_managed_launch_token(&req.launch_token)?;
    if event.pubkey.trim() != ctx.self_pk.trim() {
        return Err(anyhow!("launch token not signed by this gateway"));
    }
    let now_ms = util::now_unix_seconds() * 1000;
    if token.expires_at < now_ms {
        return Err(anyhow!("launch token expired"));
    }
    if token.gateway_pk.trim() != ctx.self_pk.trim() {
        return Err(anyhow!("launch token gateway mismatch"));
    }
    if token.identity_id.trim() != req.identity_id.trim() {
        return Err(anyhow!("launch token identity mismatch"));
    }
    if token.device_pk.trim() != req.device_pk.trim() {
        return Err(anyhow!("launch token device mismatch"));
    }
    if token.service_pk.trim() != req.service_pk.trim() {
        return Err(anyhow!("launch token service mismatch"));
    }
    if token.service.trim() != req.service.trim() {
        return Err(anyhow!("launch token service slug mismatch"));
    }
    Ok(token)
}

pub(super) async fn handle_gateway_service_install_request(
    ctx: &InboundContext,
    nostr_ev: &nostr::NostrEvent,
    payload: &Value,
) {
    let mut req: GatewayServiceInstallRequest = match serde_json::from_value(payload.clone()) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "invalid gateway_service_install_request payload");
            return;
        }
    };
    normalize_gateway_service_install_request(&mut req);

    if req.to_device_pk != ctx.self_pk {
        return;
    }

    let zone = if req.zone.is_empty() {
        payload_zone(payload)
    } else {
        Some(req.zone.clone())
    };

    let publish_status = |status: &str, reason: Option<String>, detail: Option<String>| {
        build_gateway_service_install_status_payload(
            &req,
            &ctx.self_pk,
            status,
            reason,
            detail,
            zone.clone(),
        )
    };

    if !ctx.remote_service_install_enabled {
        let status = publish_status(
            "rejected",
            Some("remote_install_disabled".to_string()),
            Some("gateway remote service install is disabled".to_string()),
        );
        let _ = publish_gateway_service_install_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.service != "nvr" || req.action != "install" {
        let status = publish_status(
            "rejected",
            Some("unsupported_action".to_string()),
            Some("only nvr install is supported".to_string()),
        );
        let _ = publish_gateway_service_install_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let gateway_identity = ctx.gateway_identity_id.trim();
    if gateway_identity.is_empty() {
        let status = publish_status(
            "rejected",
            Some("gateway_identity_missing".to_string()),
            Some("gateway identity is not configured".to_string()),
        );
        let _ = publish_gateway_service_install_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.identity_id.trim() != gateway_identity {
        let status = publish_status(
            "rejected",
            Some("identity_mismatch".to_string()),
            Some("request identity does not match gateway identity".to_string()),
        );
        let _ = publish_gateway_service_install_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.pair_identity.is_empty() || req.pair_code.is_empty() || req.pair_code_hash.is_empty() {
        let status = publish_status(
            "rejected",
            Some("missing_pairing_material".to_string()),
            Some("pairIdentity/pairCode/pairCodeHash are required".to_string()),
        );
        let _ = publish_gateway_service_install_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let requester_pk = nostr_ev.pubkey.clone();
    if !is_requester_authorized_for_service_install(ctx, &requester_pk, &req.identity_id).await {
        let status = publish_status(
            "rejected",
            Some("unauthorized_requester".to_string()),
            Some("requester is not authorized for this identity".to_string()),
        );
        let _ = publish_gateway_service_install_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.zone_keys.is_empty() {
        if let Some(z) = zone.clone() {
            req.zone_keys.push(z);
        } else {
            req.zone_keys = ctx.zones.clone();
        }
    }
    if req.swarm_peers.is_empty() {
        req.swarm_peers.push("127.0.0.1:4040".to_string());
    }
    if req.public_ws_url.is_empty() {
        req.public_ws_url = "ws://127.0.0.1:8456/session".to_string();
    }
    if !req.authorized_device_pks.contains(&requester_pk) {
        req.authorized_device_pks.push(requester_pk.clone());
    }

    let timeout_secs = req
        .timeout_secs
        .unwrap_or(ctx.remote_service_install_timeout_secs)
        .max(60)
        .min(7200);

    let accepted = build_gateway_service_install_status_payload(
        &req,
        &ctx.self_pk,
        "accepted",
        None,
        None,
        zone.clone(),
    );
    let _ = publish_gateway_service_install_status(
        &ctx.relay_pool,
        &ctx.local_relay,
        &ctx.self_pk,
        &ctx.self_sk,
        &accepted,
    )
    .await;

    let relay_pool = ctx.relay_pool.clone();
    let local_relay = ctx.local_relay.clone();
    let self_pk = ctx.self_pk.clone();
    let self_sk = ctx.self_sk.clone();
    let zone_copy = zone.clone();
    let req_for_task = req.clone();

    tokio::spawn(async move {
        let started = build_gateway_service_install_status_payload(
            &req_for_task,
            &self_pk,
            "started",
            None,
            None,
            zone_copy.clone(),
        );
        let _ = publish_gateway_service_install_status(
            &relay_pool,
            &local_relay,
            &self_pk,
            &self_sk,
            &started,
        )
        .await;

        let run_req = req_for_task.clone();
        let result = tokio::task::spawn_blocking(move || {
            execute_nvr_install_request(&run_req, timeout_secs)
        })
        .await;

        match result {
            Ok(Ok(detail)) => {
                let status = build_gateway_service_install_status_payload(
                    &req_for_task,
                    &self_pk,
                    "complete",
                    None,
                    if detail.is_empty() {
                        None
                    } else {
                        Some(detail)
                    },
                    zone_copy.clone(),
                );
                let _ = publish_gateway_service_install_status(
                    &relay_pool,
                    &local_relay,
                    &self_pk,
                    &self_sk,
                    &status,
                )
                .await;
            }
            Ok(Err(err)) => {
                let status = build_gateway_service_install_status_payload(
                    &req_for_task,
                    &self_pk,
                    "failed",
                    Some("install_failed".to_string()),
                    Some(err.to_string()),
                    zone_copy.clone(),
                );
                let _ = publish_gateway_service_install_status(
                    &relay_pool,
                    &local_relay,
                    &self_pk,
                    &self_sk,
                    &status,
                )
                .await;
            }
            Err(err) => {
                let status = build_gateway_service_install_status_payload(
                    &req_for_task,
                    &self_pk,
                    "failed",
                    Some("install_task_join_failed".to_string()),
                    Some(err.to_string()),
                    zone_copy.clone(),
                );
                let _ = publish_gateway_service_install_status(
                    &relay_pool,
                    &local_relay,
                    &self_pk,
                    &self_sk,
                    &status,
                )
                .await;
            }
        }
    });
}

pub(super) async fn handle_gateway_zone_sync_request(
    ctx: &InboundContext,
    nostr_ev: &nostr::NostrEvent,
    payload: &Value,
) {
    let mut req: GatewayZoneSyncRequest = match serde_json::from_value(payload.clone()) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "invalid gateway_zone_sync_request payload");
            return;
        }
    };
    normalize_gateway_zone_sync_request(&mut req);

    if req.to_device_pk != ctx.self_pk {
        return;
    }

    let zone = if req.zone.is_empty() {
        payload_zone(payload)
    } else {
        Some(req.zone.clone())
    };

    let publish_status = |status: &str,
                          reason: Option<String>,
                          detail: Option<String>,
                          restart_required: bool,
                          zone_keys: Vec<String>,
                          extra_zone_keys: Vec<String>| {
        build_gateway_zone_sync_status_payload(
            &req,
            &ctx.self_pk,
            status,
            reason,
            detail,
            zone.clone(),
            restart_required,
            zone_keys,
            extra_zone_keys,
        )
    };

    if !ctx.remote_service_install_enabled {
        let status = publish_status(
            "rejected",
            Some("remote_install_disabled".to_string()),
            Some("gateway remote control is disabled".to_string()),
            false,
            req.zone_keys.clone(),
            req.extra_zone_keys.clone(),
        );
        let _ = publish_gateway_zone_sync_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let gateway_identity = ctx.gateway_identity_id.trim();
    if gateway_identity.is_empty() {
        let status = publish_status(
            "rejected",
            Some("gateway_identity_missing".to_string()),
            Some("gateway identity is not configured".to_string()),
            false,
            req.zone_keys.clone(),
            req.extra_zone_keys.clone(),
        );
        let _ = publish_gateway_zone_sync_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.identity_id.trim() != gateway_identity {
        let status = publish_status(
            "rejected",
            Some("identity_mismatch".to_string()),
            Some("request identity does not match gateway identity".to_string()),
            false,
            req.zone_keys.clone(),
            req.extra_zone_keys.clone(),
        );
        let _ = publish_gateway_zone_sync_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let requester_pk = nostr_ev.pubkey.clone();
    if !is_requester_authorized_for_service_install(ctx, &requester_pk, &req.identity_id).await {
        let status = publish_status(
            "rejected",
            Some("unauthorized_requester".to_string()),
            Some("requester is not authorized for this identity".to_string()),
            false,
            req.zone_keys.clone(),
            req.extra_zone_keys.clone(),
        );
        let _ = publish_gateway_zone_sync_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let mut identity_zone_keys = req.zone_keys.clone();
    if identity_zone_keys.is_empty() {
        if let Some(z) = zone.clone() {
            if util::is_valid_zone_key(&z) {
                identity_zone_keys.push(z);
            }
        }
    }

    let mut effective_zone_keys = identity_zone_keys.clone();
    for z in &req.extra_zone_keys {
        if !effective_zone_keys.contains(z) {
            effective_zone_keys.push(z.clone());
        }
    }
    effective_zone_keys = dedup_valid_zone_keys(&effective_zone_keys, 64);

    if effective_zone_keys.is_empty() {
        let status = publish_status(
            "rejected",
            Some("missing_zones".to_string()),
            Some("at least one valid zone key is required".to_string()),
            false,
            identity_zone_keys.clone(),
            req.extra_zone_keys.clone(),
        );
        let _ = publish_gateway_zone_sync_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let seed = keystore::SecureSeed {
        nostr_pubkey: ctx.self_pk.clone(),
        nostr_sk_hex: ctx.self_sk.clone(),
        identity_id: ctx.gateway_identity_id.clone(),
        device_label: String::new(),
        zones: Vec::new(),
    };

    let (secure, _) = match keystore::load_or_init(&ctx.data_dir, seed) {
        Ok(v) => v,
        Err(err) => {
            let status = publish_status(
                "failed",
                Some("keystore_error".to_string()),
                Some(err.to_string()),
                false,
                identity_zone_keys.clone(),
                req.extra_zone_keys.clone(),
            );
            let _ = publish_gateway_zone_sync_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };

    let mut names: HashMap<String, String> = HashMap::new();
    for z in secure.zones {
        let key = z.key.trim().to_string();
        if key.is_empty() {
            continue;
        }
        let name = z.name.trim().to_string();
        if !names.contains_key(&key) {
            names.insert(
                key,
                if name.is_empty() {
                    "Joined".to_string()
                } else {
                    name
                },
            );
        }
    }

    let zone_entries: Vec<keystore::ZoneEntry> = effective_zone_keys
        .iter()
        .map(|key| keystore::ZoneEntry {
            key: key.clone(),
            name: names
                .get(key)
                .cloned()
                .unwrap_or_else(|| "Joined".to_string()),
        })
        .collect();

    match keystore::update_zones(&ctx.data_dir, zone_entries) {
        Ok(()) => {
            let detail = format!(
                "stored {} zones ({} identity + {} extra); restart gateway service to apply runtime transport scope",
                effective_zone_keys.len(),
                identity_zone_keys.len(),
                req.extra_zone_keys.len()
            );
            let status = publish_status(
                "complete",
                None,
                Some(detail),
                true,
                effective_zone_keys,
                req.extra_zone_keys.clone(),
            );
            let _ = publish_gateway_zone_sync_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
        }
        Err(err) => {
            let status = publish_status(
                "failed",
                Some("zone_persist_failed".to_string()),
                Some(err.to_string()),
                false,
                req.zone_keys.clone(),
                req.extra_zone_keys.clone(),
            );
            let _ = publish_gateway_zone_sync_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
        }
    }
}

pub(super) async fn handle_gateway_managed_launch_request(
    ctx: &InboundContext,
    nostr_ev: &nostr::NostrEvent,
    payload: &Value,
) {
    let mut req: GatewayManagedLaunchRequest = match serde_json::from_value(payload.clone()) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "invalid gateway_managed_launch_request payload");
            return;
        }
    };
    normalize_gateway_managed_launch_request(&mut req);

    if req.to_device_pk != ctx.self_pk {
        return;
    }

    if req.service.is_empty() {
        req.service = "nvr".to_string();
    }
    if req.capability.is_empty() {
        req.capability = "nvr.view".to_string();
    }
    if req.app_repo.is_empty() {
        req.app_repo = "constitute-nvr-ui".to_string();
    }

    let requester_pk = nostr_ev.pubkey.trim().to_string();
    if req.device_pk.is_empty() {
        req.device_pk = requester_pk.clone();
    }

    warn!(
        request_id = %req.request_id,
        requester_pk = %requester_pk,
        target_gateway_pk = %req.to_device_pk,
        device_pk = %req.device_pk,
        service_pk = %req.service_pk,
        service = %req.service,
        capability = %req.capability,
        "received managed launch request"
    );

    let publish_status =
        |status: &str,
         launch_token: Option<String>,
         expires_at: Option<u64>,
         display: Option<Value>,
         reason: Option<String>,
         detail: Option<String>| {
            build_gateway_managed_launch_status_payload(
                &req,
                &ctx.self_pk,
                status,
                launch_token,
                expires_at,
                display,
                reason,
                detail,
            )
        };

    if requester_pk != req.device_pk {
        let status = publish_status(
            "rejected",
            None,
            None,
            None,
            Some("requester_device_mismatch".to_string()),
            Some("requesting event pubkey does not match devicePk".to_string()),
        );
        let _ = publish_gateway_managed_launch_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let hosted = match load_target_hosted_service(ctx, &req.service_pk, &req.service).await {
        Ok(service) => service,
        Err(err) => {
            let status = publish_status(
                "failed",
                None,
                None,
                None,
                Some("service_unavailable".to_string()),
                Some(err.to_string()),
            );
            let _ = publish_gateway_managed_launch_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };
    let cameras = camera_resources_from_hosted(&hosted);
    let scope = match grants::resolve_scope_for_request(
        ctx,
        &requester_pk,
        &req.identity_id,
        &hosted.record.device_pk,
        &hosted.record.service,
        &req.capability,
        &cameras,
    )
    .await
    {
        Ok(scope) => scope,
        Err(err) => {
            let detail = err.to_string();
            let status = publish_status(
                "rejected",
                None,
                None,
                None,
                Some("launch_not_granted".to_string()),
                Some(detail),
            );
            let _ = publish_gateway_managed_launch_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };

    let mut launch_req = req.clone();
    launch_req.service_pk = hosted.record.device_pk.clone();
    if launch_req.launch_nonce.is_empty() {
        launch_req.launch_nonce = random_hex(8);
    }

    let issued_at = util::now_unix_seconds() * 1000;
    let expires_at = issued_at + 120_000;
    let token_payload = ManagedLaunchTokenPayload {
        kind: "managed_launch_token".to_string(),
        gateway_pk: ctx.self_pk.clone(),
        service_pk: launch_req.service_pk.clone(),
        service: launch_req.service.clone(),
        identity_id: launch_req.identity_id.clone(),
        device_pk: launch_req.device_pk.clone(),
        capability: launch_req.capability.clone(),
        owner: scope.owner,
        view_sources: scope.view_sources.clone(),
        control_sources: scope.control_sources.clone(),
        launch_nonce: launch_req.launch_nonce.clone(),
        issued_at,
        expires_at,
    };
    let launch_token = match build_managed_launch_token(&ctx.self_pk, &ctx.self_sk, &token_payload) {
        Ok(token) => token,
        Err(err) => {
            let status = publish_status(
                "failed",
                None,
                None,
                None,
                Some("token_build_failed".to_string()),
                Some(err.to_string()),
            );
            let _ = publish_gateway_managed_launch_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };

    let display = build_managed_service_display(
        &hosted,
        &launch_req,
        &scope,
        &ctx.stun_servers,
        &ctx.turn_servers,
    );
    let status = build_gateway_managed_launch_status_payload(
        &launch_req,
        &ctx.self_pk,
        "complete",
        Some(launch_token),
        Some(expires_at),
        Some(display),
        None,
        None,
    );
    let _ = publish_gateway_managed_launch_status(
        &ctx.relay_pool,
        &ctx.local_relay,
        &ctx.self_pk,
        &ctx.self_sk,
        &status,
    )
    .await;
}

pub(super) async fn handle_gateway_signal_request(
    ctx: &InboundContext,
    nostr_ev: &nostr::NostrEvent,
    payload: &Value,
) {
    let mut req: GatewaySignalRequest = match serde_json::from_value(payload.clone()) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "invalid gateway_signal_request payload");
            return;
        }
    };
    normalize_gateway_signal_request(&mut req);

    if req.to_device_pk != ctx.self_pk {
        return;
    }

    if req.service.is_empty() {
        req.service = "nvr".to_string();
    }
    let requester_pk = nostr_ev.pubkey.trim().to_string();
    if req.device_pk.is_empty() {
        req.device_pk = requester_pk.clone();
    }

    warn!(
        request_id = %req.request_id,
        requester_pk = %requester_pk,
        target_gateway_pk = %req.to_device_pk,
        device_pk = %req.device_pk,
        service_pk = %req.service_pk,
        service = %req.service,
        signal_type = %req.signal_type,
        "received gateway signal request"
    );

    let publish_status = |status: &str, reason: Option<String>, detail: Option<String>| {
        build_gateway_signal_status_payload(&req, &ctx.self_pk, status, reason, detail)
    };

    if requester_pk != req.device_pk {
        let status = publish_status(
            "rejected",
            Some("requester_device_mismatch".to_string()),
            Some("requesting event pubkey does not match devicePk".to_string()),
        );
        let _ = publish_gateway_signal_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let token = match validate_managed_launch_token_for_request(ctx, &req) {
        Ok(token) => token,
        Err(err) => {
            let status = publish_status(
                "rejected",
                Some("invalid_launch_token".to_string()),
                Some(err.to_string()),
            );
            let _ = publish_gateway_signal_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };

    if !grants::requester_matches_identity(ctx, &requester_pk, &req.identity_id).await {
        let status = publish_status(
            "rejected",
            Some("unauthorized_requester".to_string()),
            Some("requester is not authorized for this identity".to_string()),
        );
        let _ = publish_gateway_signal_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    let hosted = match load_target_hosted_service(ctx, &req.service_pk, &req.service).await {
        Ok(service) => service,
        Err(err) => {
            let status = publish_status(
                "failed",
                Some("service_unavailable".to_string()),
                Some(err.to_string()),
            );
            let _ = publish_gateway_signal_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };
    let cameras = camera_resources_from_hosted(&hosted);

    let accepted = publish_status("accepted", None, None);
    let _ = publish_gateway_signal_status(
        &ctx.relay_pool,
        &ctx.local_relay,
        &ctx.self_pk,
        &ctx.self_sk,
        &accepted,
    )
    .await;

    let url = match req.signal_type.as_str() {
        "offer" => format!("{}/managed/offer", hosted.api_base_url),
        "control" => format!("{}/managed/control", hosted.api_base_url),
        "admin" => format!("{}/managed/admin", hosted.api_base_url),
        "session_close" => format!("{}/managed/close", hosted.api_base_url),
        _ => {
            let status = publish_status(
                "rejected",
                Some("unsupported_signal".to_string()),
                Some("only offer, control, admin, and session_close are supported".to_string()),
            );
            let _ = publish_gateway_signal_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };

    let mut active_scope = None;
    if req.signal_type == "admin" && !token.owner {
        let status = publish_status(
            "rejected",
            Some("admin_requires_owner".to_string()),
            Some("owner launch is required for camera administration".to_string()),
        );
        let _ = publish_gateway_signal_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.signal_type != "session_close" && req.signal_type != "admin" {
        let scope = match grants::resolve_scope_for_request(
            ctx,
            &requester_pk,
            &req.identity_id,
            &hosted.record.device_pk,
            &hosted.record.service,
            &token.capability,
            &cameras,
        )
        .await
        {
            Ok(scope) => scope,
            Err(err) => {
                let status = publish_status(
                    "rejected",
                    Some("signal_not_granted".to_string()),
                    Some(err.to_string()),
                );
                let _ = publish_gateway_signal_status(
                    &ctx.relay_pool,
                    &ctx.local_relay,
                    &ctx.self_pk,
                    &ctx.self_sk,
                    &status,
                )
                .await;
                return;
            }
        };
        active_scope = Some(scope);
    }

    let mut lease_acquired = false;
    let request_body = match req.signal_type.as_str() {
        "offer" => {
            let scope = active_scope.as_ref().expect("offer scope");
            let mut forwarded_offer = req.payload.clone();
            if let Some(map) = forwarded_offer.as_object_mut() {
                map.insert("sourceIds".to_string(), json!(scope.view_sources.clone()));
            }
            let offer_candidates = gateway_offer_candidates(&forwarded_offer);
            json!({
                "launchToken": req.launch_token.clone(),
                "offer": forwarded_offer,
                "candidates": offer_candidates,
                "iceServers": {
                    "stun": ctx.stun_servers.clone(),
                    "turn": ctx.turn_servers.clone(),
                }
            })
        }
        "control" => {
            let scope = active_scope.as_ref().expect("control scope");
            let source_id = req
                .payload
                .get("sourceId")
                .or_else(|| req.payload.get("source_id"))
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if source_id.is_empty() {
                let status = publish_status(
                    "rejected",
                    Some("missing_source".to_string()),
                    Some("control request is missing sourceId".to_string()),
                );
                let _ = publish_gateway_signal_status(
                    &ctx.relay_pool,
                    &ctx.local_relay,
                    &ctx.self_pk,
                    &ctx.self_sk,
                    &status,
                )
                .await;
                return;
            }
            let lease = match grants::acquire_control_lease(
                ctx,
                scope,
                &req.identity_id,
                &req.device_pk,
                &hosted.record.device_pk,
                &source_id,
            )
            .await
            {
                Ok(lease) => lease,
                Err(err) => {
                    let status = publish_status(
                        "rejected",
                        Some("control_denied".to_string()),
                        Some(err.to_string()),
                    );
                    let _ = publish_gateway_signal_status(
                        &ctx.relay_pool,
                        &ctx.local_relay,
                        &ctx.self_pk,
                        &ctx.self_sk,
                        &status,
                    )
                    .await;
                    return;
                }
            };
            lease_acquired = true;
            json!({
                "launchToken": req.launch_token.clone(),
                "payload": req.payload.clone(),
                "controlLease": lease.lease,
                "preempted": lease.preempted,
            })
        }
        "admin" => {
            let action = req
                .payload
                .get("action")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            let payload = req
                .payload
                .get("payload")
                .cloned()
                .unwrap_or_else(|| json!({}));
            json!({
                "launchToken": req.launch_token.clone(),
                "action": action,
                "payload": payload,
            })
        }
        _ => json!({
            "launchToken": req.launch_token.clone(),
            "payload": req.payload.clone(),
        }),
    };

    let request_timeout = match req.signal_type.as_str() {
        // PTZ control can legitimately take longer now that Reolink control may degrade through
        // an observed-step fulfillment loop instead of returning after a single blind pulse.
        "control" => Duration::from_secs(45),
        "admin" => Duration::from_secs(120),
        _ => Duration::from_secs(5),
    };
    let response = ctx
        .http_client
        .post(&url)
        .timeout(request_timeout)
        .json(&request_body)
        .send()
        .await;
    let response = match response {
        Ok(resp) => resp,
        Err(err) => {
            warn!(
                request_id = %req.request_id,
                signal_type = %req.signal_type,
                url = %url,
                error = %err,
                "gateway signal forward failed"
            );
            if lease_acquired {
                grants::release_control_leases_for_holder(
                    ctx,
                    &req.identity_id,
                    &req.device_pk,
                    &hosted.record.device_pk,
                )
                .await;
            }
            let status = publish_status(
                "failed",
                Some("service_signal_failed".to_string()),
                Some(err.to_string()),
            );
            let _ = publish_gateway_signal_status(
                &ctx.relay_pool,
                &ctx.local_relay,
                &ctx.self_pk,
                &ctx.self_sk,
                &status,
            )
            .await;
            return;
        }
    };

    let response_status = response.status();
    if !response_status.is_success() {
        if lease_acquired {
            grants::release_control_leases_for_holder(
                ctx,
                &req.identity_id,
                &req.device_pk,
                &hosted.record.device_pk,
            )
            .await;
        }
        let detail = match response.text().await {
            Ok(text) if !text.trim().is_empty() => text,
            _ => format!("status {}", response_status),
        };
        warn!(
            request_id = %req.request_id,
            signal_type = %req.signal_type,
            url = %url,
            status = %response_status,
            detail = %detail,
            "gateway signal service rejected request"
        );
        let status = publish_status(
            "failed",
            Some("service_signal_rejected".to_string()),
            Some(detail),
        );
        let _ = publish_gateway_signal_status(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &status,
        )
        .await;
        return;
    }

    if req.signal_type == "offer" || req.signal_type == "control" || req.signal_type == "admin" {
        warn!(
            request_id = %req.request_id,
            signal_type = %req.signal_type,
            url = %url,
            status = %response_status,
            "gateway signal service accepted request"
        );
        let body: Value = match response.json().await {
            Ok(body) => body,
            Err(err) => {
                warn!(
                    request_id = %req.request_id,
                    signal_type = %req.signal_type,
                    url = %url,
                    error = %err,
                    "gateway signal response json parse failed"
                );
                if lease_acquired {
                    grants::release_control_leases_for_holder(
                        ctx,
                        &req.identity_id,
                        &req.device_pk,
                        &hosted.record.device_pk,
                    )
                    .await;
                }
                let status = publish_status(
                    "failed",
                    Some("invalid_service_signal_response".to_string()),
                    Some(err.to_string()),
                );
                let _ = publish_gateway_signal_status(
                    &ctx.relay_pool,
                    &ctx.local_relay,
                    &ctx.self_pk,
                    &ctx.self_sk,
                    &status,
                )
                .await;
                return;
            }
        };
        let signal_type = body
            .get("signalType")
            .and_then(|v| v.as_str())
            .unwrap_or(if req.signal_type == "offer" {
                "answer"
            } else if req.signal_type == "control" {
                "control_ack"
            } else {
                "admin_result"
            })
            .trim()
            .to_ascii_lowercase();
        let payload_value = if body.is_object() {
            body.clone()
        } else {
            body.get("payload")
                .cloned()
                .or_else(|| body.get("answer").cloned())
                .unwrap_or_else(|| json!({}))
        };
        let signal = GatewaySignalPayload {
            signal_type,
            ..build_gateway_signal_payload(&req, &ctx.self_pk, payload_value)
        };
        let _ = publish_gateway_signal(
            &ctx.relay_pool,
            &ctx.local_relay,
            &ctx.self_pk,
            &ctx.self_sk,
            &signal,
        )
        .await;
    }

    if req.signal_type == "session_close" {
        grants::release_control_leases_for_holder(
            ctx,
            &req.identity_id,
            &req.device_pk,
            &hosted.record.device_pk,
        )
        .await;
    }

    let status = publish_status("complete", None, None);
    let _ = publish_gateway_signal_status(
        &ctx.relay_pool,
        &ctx.local_relay,
        &ctx.self_pk,
        &ctx.self_sk,
        &status,
    )
    .await;
}

