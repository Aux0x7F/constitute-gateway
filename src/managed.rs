use super::*;
use constitute_protocol::ServiceProjectionRequest;
use url::Url;

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
    aliases: Vec<String>,
    #[serde(default)]
    surface_channel: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    nodes: Vec<Value>,
    #[serde(default)]
    retired: Value,
    #[serde(default)]
    camera_devices: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct HostedStorageManifest {
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
    app_url: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    surface_channel: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    nodes: Vec<Value>,
    #[serde(default)]
    retired: Value,
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
    pub health: Value,
    pub config: HostedNvrConfig,
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

fn object_string(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    for key in keys {
        let text = object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty());
        if let Some(text) = text {
            return Some(text.to_string());
        }
    }
    None
}

fn object_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    let object = value.as_object()?;
    for key in keys {
        if let Some(next) = object.get(*key).and_then(Value::as_bool) {
            return Some(next);
        }
    }
    None
}

fn object_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    let object = value.as_object()?;
    for key in keys {
        if let Some(next) = object.get(*key).and_then(Value::as_u64) {
            return Some(next);
        }
    }
    None
}

fn push_unique_source_id(out: &mut Vec<String>, source_id: &str) {
    let source_id = source_id.trim();
    if source_id.is_empty() || out.iter().any(|existing| existing == source_id) {
        return;
    }
    out.push(source_id.to_string());
}

fn sanitize_nvr_camera_device(camera: &Value) -> Option<Value> {
    let source_id = object_string(camera, &["sourceId", "source_id", "id"])?;
    let mut safe = serde_json::Map::new();
    safe.insert("sourceId".to_string(), json!(source_id));

    if let Some(name) = object_string(camera, &["name", "displayName", "display_name", "label"]) {
        safe.insert("name".to_string(), json!(name.clone()));
        safe.insert("displayName".to_string(), json!(name));
    }
    if let Some(driver_id) = object_string(camera, &["driverId", "driver_id"]) {
        safe.insert("driverId".to_string(), json!(driver_id));
    }
    if let Some(vendor) = object_string(camera, &["vendor"]) {
        safe.insert("vendor".to_string(), json!(vendor));
    }
    if let Some(model) = object_string(camera, &["model"]) {
        safe.insert("model".to_string(), json!(model));
    }
    if let Some(enabled) = object_bool(camera, &["enabled"]) {
        safe.insert("enabled".to_string(), json!(enabled));
    }
    if let Some(rtsp_configured) = object_bool(camera, &["rtspConfigured", "rtsp_configured"]) {
        safe.insert("rtspConfigured".to_string(), json!(rtsp_configured));
    }
    if let Some(onvif_host) = object_string(camera, &["onvifHost", "onvif_host"]) {
        safe.insert("onvifHost".to_string(), json!(onvif_host));
    }
    if let Some(onvif_port) = object_u64(camera, &["onvifPort", "onvif_port"]) {
        safe.insert("onvifPort".to_string(), json!(onvif_port));
    }
    if let Some(segment_secs) = object_u64(camera, &["segmentSecs", "segment_secs"]) {
        safe.insert("segmentSecs".to_string(), json!(segment_secs));
    }
    if let Some(ptz_capable) = object_bool(camera, &["ptzCapable", "ptz_capable"]) {
        safe.insert("ptzCapable".to_string(), json!(ptz_capable));
    }

    Some(Value::Object(safe))
}

fn sanitized_nvr_camera_devices(health: Option<&Value>, fallback: &[Value]) -> Vec<Value> {
    let from_health = health
        .and_then(|body| body.get("cameraDevices"))
        .and_then(Value::as_array)
        .map(|entries| entries.as_slice())
        .unwrap_or(&[]);
    let source = if from_health.is_empty() {
        fallback
    } else {
        from_health
    };
    source
        .iter()
        .filter_map(sanitize_nvr_camera_device)
        .collect()
}

fn nvr_source_ids(health: Option<&Value>, camera_devices: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(entries) = health
        .and_then(|body| body.get("sources"))
        .and_then(Value::as_array)
    {
        for entry in entries {
            if let Some(source_id) = entry.as_str() {
                push_unique_source_id(&mut out, source_id);
            }
        }
    }
    for camera in camera_devices {
        if let Some(source_id) = camera.get("sourceId").and_then(Value::as_str) {
            push_unique_source_id(&mut out, source_id);
        }
    }
    out
}

fn nvr_safe_media_projection(health: &Value) -> Option<Value> {
    let media = health.get("mediaProjection")?.as_object()?;
    let mut safe = serde_json::Map::new();
    if let Some(state) = media
        .get("state")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|state| !state.is_empty())
    {
        safe.insert("state".to_string(), json!(state));
    }
    if let Some(enabled) = media.get("enabled").and_then(Value::as_bool) {
        safe.insert("enabled".to_string(), json!(enabled));
    }
    if safe.is_empty() {
        None
    } else {
        Some(Value::Object(safe))
    }
}

fn nvr_base_facts(
    camera_count: u64,
    health: Option<&Value>,
    fallback_camera_devices: &[Value],
) -> Value {
    let camera_devices = sanitized_nvr_camera_devices(health, fallback_camera_devices);
    let sources = nvr_source_ids(health, &camera_devices);
    let mut facts = json!({
        "configuredSources": camera_count,
    });
    if !sources.is_empty() {
        facts["sources"] = json!(sources);
    }
    if !camera_devices.is_empty() {
        facts["cameraDevices"] = json!(camera_devices);
    }
    if let Some(health) = health {
        let mut safe_health = serde_json::Map::new();
        if let Some(status) = health
            .get("status")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|status| !status.is_empty())
        {
            safe_health.insert("status".to_string(), json!(status));
        }
        if let Some(ok) = health.get("ok").and_then(Value::as_bool) {
            safe_health.insert("ok".to_string(), json!(ok));
        }
        safe_health.insert("configuredSources".to_string(), json!(camera_count));
        if !sources.is_empty() {
            safe_health.insert("sources".to_string(), json!(sources.clone()));
        }
        if !camera_devices.is_empty() {
            safe_health.insert("cameraDevices".to_string(), json!(camera_devices.clone()));
        }
        if let Some(media_projection) = nvr_safe_media_projection(health) {
            facts["mediaProjection"] = media_projection.clone();
            safe_health.insert("mediaProjection".to_string(), media_projection);
        }
        if !safe_health.is_empty() {
            facts["health"] = Value::Object(safe_health);
        }
    }
    facts
}

fn nvr_manifest_facts(
    manifest: &HostedNvrManifest,
    camera_count: u64,
    health: Option<&Value>,
) -> Value {
    let mut facts = nvr_base_facts(camera_count, health, &manifest.camera_devices);
    if !manifest.surface_channel.trim().is_empty() {
        facts["surfaceChannel"] = json!(manifest.surface_channel.trim());
    }
    if !manifest.aliases.is_empty() {
        facts["aliases"] = json!(manifest.aliases.clone());
    }
    if !manifest.summary.trim().is_empty() {
        facts["summary"] = json!(manifest.summary.trim());
    }
    if !manifest.nodes.is_empty() {
        facts["nodes"] = json!(manifest.nodes.clone());
    }
    if !manifest.retired.is_null() {
        facts["retired"] = manifest.retired.clone();
    }
    facts
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
                        device_pk: service_pk.clone(),
                        service_pk: service_pk.clone(),
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
                        facts: nvr_manifest_facts(manifest, camera_count, Some(&health)),
                    },
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
            device_pk: service_pk.clone(),
            service_pk: service_pk.clone(),
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
            facts: nvr_manifest_facts(manifest, camera_count, None),
        },
        health: json!({}),
        config: fallback_cfg,
    })
}

async fn load_hosted_nvr_service(
    client: &HttpClient,
    gateway_pk: &str,
) -> Option<HostedNvrService> {
    for path in nvr_manifest_candidates() {
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let manifest: HostedNvrManifest = match serde_json::from_str(&raw) {
            Ok(manifest) => manifest,
            Err(_) => continue,
        };
        if let Some(service) =
            load_hosted_nvr_service_from_manifest(client, gateway_pk, &manifest).await
        {
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
                            device_pk: service_pk.clone(),
                            service_pk: service_pk.clone(),
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
                            facts: nvr_base_facts(camera_count, Some(&health), &cfg.camera_devices),
                        },
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
                device_pk: service_pk.clone(),
                service_pk: service_pk.clone(),
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
                facts: nvr_base_facts(camera_count, None, &cfg.camera_devices),
            },
            health: json!({}),
            config: cfg.clone(),
        });
    }
    None
}

fn storage_manifest_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(PathBuf::from(
        "/data/constitute-storage/hosted-service.json",
    ));
    out.push(PathBuf::from("/run/constitute/storage-hosted-service.json"));
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        out.push(
            PathBuf::from(local_appdata)
                .join("Constitute")
                .join("storage")
                .join("hosted-service.json"),
        );
    }
    out
}

fn logging_manifest_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(PathBuf::from(
        "/data/constitute-logging/hosted-service.json",
    ));
    out.push(PathBuf::from("/run/constitute/logging-hosted-service.json"));
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        out.push(
            PathBuf::from(local_appdata)
                .join("Constitute")
                .join("logging")
                .join("hosted-service.json"),
        );
    }
    out
}

fn storage_local_base_url(bind: &str) -> Option<String> {
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

fn hosted_service_health_url(api_base_url: &str, health_url: &str) -> String {
    let base = api_base_url.trim().trim_end_matches('/');
    let raw = health_url.trim();
    if raw.is_empty() {
        return format!("{base}/health");
    }
    if Url::parse(raw).is_ok() {
        return raw.to_string();
    }
    format!("{base}/{}", raw.trim_start_matches('/'))
}

fn storage_probe_base_urls() -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(raw) = std::env::var("CONSTITUTE_STORAGE_URL") {
        let value = raw.trim().trim_end_matches('/').to_string();
        if !value.is_empty() {
            urls.push(value);
        }
    }
    urls.push("http://127.0.0.1:7478".to_string());
    urls.sort();
    urls.dedup();
    urls
}

fn logging_probe_base_urls() -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(raw) = std::env::var("CONSTITUTE_LOGGING_URL") {
        let value = raw.trim().trim_end_matches('/').to_string();
        if !value.is_empty() {
            urls.push(value);
        }
    }
    urls.push("http://127.0.0.1:7480".to_string());
    urls.sort();
    urls.dedup();
    urls
}

async fn fetch_json(client: &HttpClient, url: &str) -> Option<Value> {
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

fn storage_capabilities(manifest: &HostedStorageManifest) -> Value {
    if manifest.capabilities.is_empty() {
        json!([
            "encrypted_objects",
            "content_addressed_chunks",
            "encrypted_index_shards",
            "key_grants",
            "pin_leases",
            constitute_protocol::CAPABILITY_SURFACE_APP_DISTRIBUTION_PIN,
            "prune",
            "local_search",
            "watch"
        ])
    } else {
        json!(manifest.capabilities)
    }
}

fn logging_capabilities(manifest: &HostedStorageManifest) -> Value {
    if manifest.capabilities.is_empty() {
        json!([
            "blind_observation",
            "safe_fact_index",
            "cursor_outbox",
            "live_watch",
            "storage_archive"
        ])
    } else {
        json!(manifest.capabilities)
    }
}

fn storage_record_from_parts(
    gateway_pk: &str,
    manifest: &HostedStorageManifest,
    api_base_url: Option<&str>,
    health: Option<&Value>,
) -> discovery::HostedServiceRecord {
    let now = util::now_unix_seconds() * 1000;
    let service = if manifest.service.trim().is_empty() {
        "storage".to_string()
    } else {
        manifest.service.trim().to_ascii_lowercase()
    };
    let host_gateway_pk = if manifest.host_gateway_pk.trim().is_empty() {
        gateway_pk.trim().to_string()
    } else {
        manifest.host_gateway_pk.trim().to_string()
    };
    let health_status = health
        .and_then(|body| body.get("status").and_then(|value| value.as_str()))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if api_base_url.is_some() {
                "offline"
            } else {
                "configured"
            }
        })
        .to_ascii_lowercase();
    let status = if health_status == "ok" {
        "online".to_string()
    } else {
        health_status
    };
    let mut facts = json!({
        "capabilities": if service == "logging" {
            logging_capabilities(manifest)
        } else {
            storage_capabilities(manifest)
        },
    });
    if !manifest.surface_channel.trim().is_empty() {
        facts["surfaceChannel"] = json!(manifest.surface_channel.trim());
    }
    if !manifest.aliases.is_empty() {
        facts["aliases"] = json!(manifest.aliases.clone());
    }
    if !manifest.summary.trim().is_empty() {
        facts["summary"] = json!(manifest.summary.trim());
    }
    if !manifest.nodes.is_empty() {
        facts["nodes"] = json!(manifest.nodes.clone());
    }
    if !manifest.retired.is_null() {
        facts["retired"] = manifest.retired.clone();
    }
    if let Some(base) = api_base_url.filter(|_| service != "logging") {
        facts["apiBaseUrl"] = json!(base);
        facts["healthUrl"] = json!(if manifest.health_url.trim().is_empty() {
            format!("{}/health", base.trim_end_matches('/'))
        } else {
            manifest.health_url.trim().to_string()
        });
    }
    if let Some(body) = health {
        facts["health"] = json!({
            "status": body
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown"),
            "objects": body.get("objects").and_then(|value| value.as_u64()).unwrap_or(0),
            "chunks": body.get("chunks").and_then(|value| value.as_u64()).unwrap_or(0),
            "indexShards": body.get("indexShards").and_then(|value| value.as_u64()).unwrap_or(0),
            "keyGrants": body.get("keyGrants").and_then(|value| value.as_u64()).unwrap_or(0),
            "pinLeases": body.get("pinLeases").and_then(|value| value.as_u64()).unwrap_or(0),
            "materializedEntries": body
                .get("materializedEntries")
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
        });
    }
    if service == "logging" {
        facts["appUrl"] = json!(if manifest.app_url.trim().is_empty() {
            "/constitute-logging-ui/".to_string()
        } else {
            manifest.app_url.trim().to_string()
        });
        if let Some(body) = health {
            facts["health"] = json!({
                "status": body
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown"),
                "events": body.get("events").and_then(|value| value.as_u64()).unwrap_or(0),
                "producers": body.get("producers").and_then(|value| value.as_u64()).unwrap_or(0),
                "storageStatus": body
                    .get("storageStatus")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown"),
                "archiveContainerId": body
                    .get("archiveContainerId")
                    .and_then(|value| value.as_str())
                    .unwrap_or(""),
            });
        }
    }
    let manifest_service_pk = manifest.service_pk.trim().to_string();
    let service_member_pk = manifest_service_pk.clone();
    let record_device_pk = format!("{}:{}", service, host_gateway_pk);

    discovery::HostedServiceRecord {
        device_pk: record_device_pk,
        service_pk: service_member_pk,
        device_label: if manifest.device_label.trim().is_empty() {
            if service == "logging" {
                "Constitute Logging".to_string()
            } else {
                "Constitute Storage".to_string()
            }
        } else {
            manifest.device_label.trim().to_string()
        },
        device_kind: "service".to_string(),
        service,
        host_gateway_pk,
        service_version: if manifest.service_version.trim().is_empty() {
            "unknown".to_string()
        } else {
            manifest.service_version.trim().to_string()
        },
        updated_at: now,
        freshness_ms: 0,
        status,
        camera_count: 0,
        facts,
    }
}

async fn load_hosted_storage_from_manifest(
    client: &HttpClient,
    gateway_pk: &str,
    manifest: &HostedStorageManifest,
) -> Option<discovery::HostedServiceRecord> {
    let api_base_url = if !manifest.api_base_url.trim().is_empty() {
        Some(
            manifest
                .api_base_url
                .trim()
                .trim_end_matches('/')
                .to_string(),
        )
    } else {
        storage_local_base_url(&manifest.api_bind)
    };
    let health_url = if !manifest.health_url.trim().is_empty() {
        manifest.health_url.trim().to_string()
    } else {
        api_base_url
            .as_ref()
            .map(|base| format!("{}/health", base.trim_end_matches('/')))
            .unwrap_or_default()
    };
    let health = if health_url.is_empty() {
        None
    } else {
        fetch_json(client, &health_url).await
    };
    Some(storage_record_from_parts(
        gateway_pk,
        manifest,
        api_base_url.as_deref(),
        health.as_ref(),
    ))
}

async fn load_hosted_storage_from_base_url(
    client: &HttpClient,
    gateway_pk: &str,
    api_base_url: &str,
) -> Option<discovery::HostedServiceRecord> {
    let base = api_base_url.trim().trim_end_matches('/').to_string();
    if base.is_empty() {
        return None;
    }
    let manifest = fetch_json(client, &format!("{base}/hosted-service.json"))
        .await
        .and_then(|body| serde_json::from_value::<HostedStorageManifest>(body).ok())
        .unwrap_or_default();
    let health = fetch_json(client, &format!("{base}/health")).await?;
    Some(storage_record_from_parts(
        gateway_pk,
        &manifest,
        Some(&base),
        Some(&health),
    ))
}

async fn load_hosted_logging_managed_from_manifest(
    client: &HttpClient,
    gateway_pk: &str,
    manifest: &HostedStorageManifest,
) -> Option<HostedNvrService> {
    let mut manifest = manifest.clone();
    manifest.service = "logging".to_string();
    if manifest.service_pk.trim().is_empty() {
        return None;
    }
    let api_base_url = if !manifest.api_base_url.trim().is_empty() {
        Some(
            manifest
                .api_base_url
                .trim()
                .trim_end_matches('/')
                .to_string(),
        )
    } else {
        storage_local_base_url(&manifest.api_bind)
    }?;
    let health_url = hosted_service_health_url(&api_base_url, &manifest.health_url);
    let health = fetch_json(client, &health_url)
        .await
        .unwrap_or_else(|| json!({ "status": "unknown" }));
    let record =
        storage_record_from_parts(gateway_pk, &manifest, Some(&api_base_url), Some(&health));
    Some(HostedNvrService {
        record,
        health,
        config: HostedNvrConfig::default(),
    })
}

async fn load_hosted_logging_managed_from_base_url(
    client: &HttpClient,
    gateway_pk: &str,
    api_base_url: &str,
) -> Option<HostedNvrService> {
    let base = api_base_url.trim().trim_end_matches('/').to_string();
    if base.is_empty() {
        return None;
    }
    let mut manifest = fetch_json(client, &format!("{base}/hosted-service.json"))
        .await
        .and_then(|body| serde_json::from_value::<HostedStorageManifest>(body).ok())
        .unwrap_or_default();
    manifest.service = "logging".to_string();
    if manifest.api_base_url.trim().is_empty() {
        manifest.api_base_url = base.clone();
    }
    load_hosted_logging_managed_from_manifest(client, gateway_pk, &manifest).await
}

async fn load_hosted_storage_service(
    client: &HttpClient,
    gateway_pk: &str,
) -> Option<discovery::HostedServiceRecord> {
    for path in storage_manifest_candidates() {
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let manifest: HostedStorageManifest = match serde_json::from_str(&raw) {
            Ok(manifest) => manifest,
            Err(_) => continue,
        };
        if let Some(record) = load_hosted_storage_from_manifest(client, gateway_pk, &manifest).await
        {
            return Some(record);
        }
    }
    for base in storage_probe_base_urls() {
        if let Some(record) = load_hosted_storage_from_base_url(client, gateway_pk, &base).await {
            return Some(record);
        }
    }
    None
}

async fn load_hosted_logging_service(
    client: &HttpClient,
    gateway_pk: &str,
) -> Option<discovery::HostedServiceRecord> {
    load_hosted_logging_managed_service(client, gateway_pk)
        .await
        .map(|service| service.record)
}

async fn load_hosted_logging_managed_service(
    client: &HttpClient,
    gateway_pk: &str,
) -> Option<HostedNvrService> {
    for path in logging_manifest_candidates() {
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let mut manifest: HostedStorageManifest = match serde_json::from_str(&raw) {
            Ok(manifest) => manifest,
            Err(_) => continue,
        };
        if manifest.service.trim().is_empty() {
            manifest.service = "logging".to_string();
        }
        if let Some(service) =
            load_hosted_logging_managed_from_manifest(client, gateway_pk, &manifest).await
        {
            return Some(service);
        }
    }
    for base in logging_probe_base_urls() {
        if let Some(service) =
            load_hosted_logging_managed_from_base_url(client, gateway_pk, &base).await
        {
            return Some(service);
        }
    }
    None
}

pub(super) async fn load_hosted_services_snapshot(
    client: &HttpClient,
    gateway_pk: &str,
) -> Vec<discovery::HostedServiceRecord> {
    let mut services = Vec::new();
    if let Some(service) = load_hosted_nvr_service(client, gateway_pk).await {
        services.push(service.record);
    }
    if let Some(service) = load_hosted_storage_service(client, gateway_pk).await {
        services.push(service);
    }
    if let Some(service) = load_hosted_logging_service(client, gateway_pk).await {
        services.push(service);
    }
    services
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

pub(super) fn camera_resources_from_hosted(
    hosted: &HostedNvrService,
) -> Vec<grants::CameraResource> {
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
    let hosted = match service_slug.as_str() {
        "nvr" => load_hosted_nvr_service(&ctx.http_client, &ctx.self_pk)
            .await
            .ok_or_else(|| anyhow!("hosted nvr service not configured"))?,
        "logging" => load_hosted_logging_managed_service(&ctx.http_client, &ctx.self_pk)
            .await
            .ok_or_else(|| anyhow!("hosted logging service not configured"))?,
        _ => return Err(anyhow!("unsupported managed service")),
    };
    if !service_pk.trim().is_empty() && hosted.record.service_pk.trim() != service_pk.trim() {
        return Err(anyhow!(
            "requested service pk does not match hosted service"
        ));
    }
    Ok(hosted)
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
    if req.swarm_edge_endpoint.is_empty() {
        req.swarm_edge_endpoint = "ws://127.0.0.1:7448".to_string();
    }
    if !req.authorized_device_pks.contains(&requester_pk) {
        req.authorized_device_pks.push(requester_pk.clone());
    }

    let timeout_secs = req
        .timeout_secs
        .unwrap_or(ctx.remote_service_install_timeout_secs)
        .clamp(60, 7200);

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
        names.entry(key).or_insert_with(|| {
            if name.is_empty() {
                "Joined".to_string()
            } else {
                name
            }
        });
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

fn gateway_projection_base(
    ctx: &InboundContext,
    req: &ServiceProjectionRequest,
    payload_schema: &str,
    payload: Value,
    safe_facts: Value,
) -> Value {
    let now = util::now_unix_seconds();
    let scope = req
        .policy
        .as_ref()
        .and_then(|policy| serde_json::to_value(policy).ok())
        .unwrap_or_else(|| json!({}));
    json!({
        "requestId": req.request_id.clone(),
        "channelId": req.channel_id.clone(),
        "service": "gateway",
        "servicePk": ctx.self_pk.clone(),
        "producer": {
            "service": "gateway",
            "component": "service-surface",
            "gatewayPk": ctx.self_pk.clone(),
        },
        "freshness": {
            "state": "fresh",
            "updatedAt": now,
            "staleAfter": now + 60,
        },
        "scope": scope,
        "payloadSchema": payload_schema,
        "payload": payload,
        "safeFacts": safe_facts,
        "encryptedDetailRefs": [],
        "diagnostics": [],
    })
}

async fn gateway_surface_projection(ctx: &InboundContext, req: &ServiceProjectionRequest) -> Value {
    let now = util::now_unix_seconds();
    gateway_projection_base(
        ctx,
        req,
        "constitute.service.surface.v1",
        json!({
            "surface": {
                "surfaceId": "gateway.surface",
                "schemaVersion": 1,
                "service": "gateway",
                "servicePk": ctx.self_pk.clone(),
                "hostGatewayPk": ctx.self_pk.clone(),
                "location": {
                    "locationId": ctx.self_pk.clone(),
                    "label": "Gateway",
                    "gatewayPk": ctx.self_pk.clone(),
                },
                "aliases": ["Gateway"],
                "summary": "Gateway routing, hosted-service, zone, and device observation.",
                "healthNode": "health",
                "updatedAt": now,
                "nodes": [
                    {
                        "nodeId": "gateway.health",
                        "path": "health",
                        "label": "Health",
                        "description": "Gateway one-line and detailed runtime health.",
                        "backingChannel": "gateway.health",
                        "fields": [
                            { "fieldId": "status", "label": "Status", "valueKind": "string", "capabilities": ["read", "observe"] },
                            { "fieldId": "zones", "label": "Zones", "valueKind": "array", "capabilities": ["read", "observe"] },
                            { "fieldId": "hostedServiceCount", "label": "Hosted Services", "valueKind": "number", "capabilities": ["read", "observe"] }
                        ]
                    },
                    {
                        "nodeId": "gateway.devices",
                        "path": "devices",
                        "label": "Devices",
                        "description": "Zone-scoped device presence observed by this gateway.",
                        "backingChannel": "gateway.devices",
                        "fields": [
                            { "fieldId": "devices", "label": "Devices", "valueKind": "array", "capabilities": ["read", "observe"] }
                        ]
                    },
                    {
                        "nodeId": "gateway.hostedServices",
                        "path": "hostedServices",
                        "label": "Hosted Services",
                        "description": "Hosted service bootstrap descriptors and freshness.",
                        "backingChannel": "gateway.hostedServices",
                        "fields": [
                            { "fieldId": "services", "label": "Services", "valueKind": "array", "capabilities": ["read", "observe"] }
                        ]
                    },
                    {
                        "nodeId": "gateway.zones",
                        "path": "zones",
                        "label": "Zones",
                        "description": "Gateway zone membership.",
                        "backingChannel": "gateway.zones",
                        "fields": [
                            { "fieldId": "zones", "label": "Zones", "valueKind": "array", "capabilities": ["read", "observe"] }
                        ]
                    },
                    {
                        "nodeId": "gateway.routingDiagnostics",
                        "path": "routingDiagnostics",
                        "label": "Routing Diagnostics",
                        "description": "Safe routing and relay diagnostics.",
                        "backingChannel": "gateway.routingDiagnostics",
                        "fields": [
                            { "fieldId": "relayConfigured", "label": "Relay Configured", "valueKind": "boolean", "capabilities": ["read", "observe"] },
                            { "fieldId": "localRelayClients", "label": "Local Relay Clients", "valueKind": "number", "capabilities": ["read", "observe"] }
                        ]
                    }
                ],
                "diagnostics": []
            }
        }),
        json!({
            "nodeCount": 5,
            "surfaceChannel": "gateway.surface",
        }),
    )
}

async fn gateway_health_projection(ctx: &InboundContext, req: &ServiceProjectionRequest) -> Value {
    let hosted_services = load_hosted_services_snapshot(&ctx.http_client, &ctx.self_pk).await;
    gateway_projection_base(
        ctx,
        req,
        "constitute.gateway.health.v1",
        json!({
            "nodePath": "health",
            "fields": {
                "status": "online",
                "zones": ctx.zones.clone(),
                "hostedServiceCount": hosted_services.len(),
                "localRelayClients": ctx.local_relay.as_ref().map(|relay| relay.client_count()).unwrap_or(0),
            },
            "health": {
                "status": "online",
            }
        }),
        json!({
            "status": "online",
            "hostedServiceCount": hosted_services.len(),
        }),
    )
}

async fn gateway_devices_projection(ctx: &InboundContext, req: &ServiceProjectionRequest) -> Value {
    let now_ms = util::now_unix_seconds() * 1000;
    let events = {
        let guard = ctx.store.lock().await;
        guard.list_device_events_all()
    };
    let devices = events
        .iter()
        .filter_map(|event| serde_json::from_str::<Value>(&event.content).ok())
        .map(|record| {
            let expires_at = record.get("expiresAt").and_then(Value::as_u64).unwrap_or(0);
            json!({
                "devicePk": record.get("devicePk").cloned().unwrap_or_else(|| json!("")),
                "deviceLabel": record.get("deviceLabel").cloned().unwrap_or_else(|| json!("")),
                "role": record.get("role").cloned().unwrap_or_else(|| json!("")),
                "deviceKind": record.get("deviceKind").cloned().unwrap_or_else(|| json!("")),
                "updatedAt": record.get("updatedAt").cloned().unwrap_or_else(|| json!(0)),
                "expiresAt": expires_at,
                "online": expires_at == 0 || expires_at > now_ms,
            })
        })
        .collect::<Vec<_>>();
    let device_count = devices.len();
    gateway_projection_base(
        ctx,
        req,
        "constitute.gateway.devices.v1",
        json!({
            "nodePath": "devices",
            "fields": {
                "devices": devices,
            }
        }),
        json!({
            "deviceCount": device_count,
        }),
    )
}

async fn gateway_hosted_services_projection(
    ctx: &InboundContext,
    req: &ServiceProjectionRequest,
) -> Value {
    let services = load_hosted_services_snapshot(&ctx.http_client, &ctx.self_pk).await;
    let service_count = services.len();
    gateway_projection_base(
        ctx,
        req,
        "constitute.gateway.hostedServices.v1",
        json!({
            "nodePath": "hostedServices",
            "fields": {
                "services": services,
            }
        }),
        json!({
            "serviceCount": service_count,
        }),
    )
}

async fn gateway_zones_projection(ctx: &InboundContext, req: &ServiceProjectionRequest) -> Value {
    gateway_projection_base(
        ctx,
        req,
        "constitute.gateway.zones.v1",
        json!({
            "nodePath": "zones",
            "fields": {
                "zones": ctx.zones.clone(),
            }
        }),
        json!({
            "zoneCount": ctx.zones.len(),
        }),
    )
}

async fn gateway_routing_diagnostics_projection(
    ctx: &InboundContext,
    req: &ServiceProjectionRequest,
) -> Value {
    let pending_count = ctx.pending.lock().await.len();
    let peer_count = ctx.peer_set.lock().await.len();
    gateway_projection_base(
        ctx,
        req,
        "constitute.gateway.routingDiagnostics.v1",
        json!({
            "nodePath": "routingDiagnostics",
            "fields": {
                "relayConfigured": !ctx.relay_pool.is_empty(),
                "localRelayClients": ctx.local_relay.as_ref().map(|relay| relay.client_count()).unwrap_or(0),
                "pendingRequests": pending_count,
                "udpPeers": peer_count,
                "zones": ctx.zones.clone(),
            }
        }),
        json!({
            "relayConfigured": !ctx.relay_pool.is_empty(),
            "pendingRequests": pending_count,
            "udpPeers": peer_count,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvr_facts_include_sanitized_live_camera_sources() {
        let manifest = HostedNvrManifest {
            service_pk: "nvr-service".to_string(),
            surface_channel: "nvr.surface".to_string(),
            camera_devices: vec![json!({
                "sourceId": "fallback-cam",
                "name": "Fallback",
                "rtspUrl": "rtsp://secret"
            })],
            ..Default::default()
        };
        let health = json!({
            "status": "ready",
            "ok": true,
            "configuredSources": 2,
            "sources": ["reolink-ec-71-db-32-0a-8f", "xm-192-168-0-201"],
            "mediaProjection": { "state": "ready", "internalUrl": "http://secret" },
            "cameraDevices": [
                {
                    "sourceId": "reolink-ec-71-db-32-0a-8f",
                    "name": "Carport",
                    "vendor": "reolink",
                    "model": "E1 Outdoor SE",
                    "enabled": true,
                    "rtspConfigured": true,
                    "rtspUrl": "rtsp://operator:secret@camera",
                    "ptzCapable": true
                },
                {
                    "sourceId": "xm-192-168-0-201",
                    "name": "Front Door",
                    "model": "40E",
                    "enabled": true,
                    "ptzCapable": false
                }
            ]
        });

        let facts = nvr_manifest_facts(&manifest, 2, Some(&health));

        assert_eq!(facts["configuredSources"], 2);
        assert_eq!(facts["sources"][0], "reolink-ec-71-db-32-0a-8f");
        assert_eq!(facts["cameraDevices"][0]["name"], "Carport");
        assert_eq!(facts["cameraDevices"][0]["ptzCapable"], true);
        assert_eq!(facts["health"]["sources"][1], "xm-192-168-0-201");
        assert_eq!(facts["mediaProjection"]["state"], "ready");
        let rendered = facts.to_string();
        assert!(!rendered.contains("rtsp://"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("internalUrl"));
    }

    #[test]
    fn default_storage_capabilities_advertise_app_distribution_pinning() {
        let manifest = HostedStorageManifest::default();
        let capabilities = storage_capabilities(&manifest);
        assert!(capabilities
            .as_array()
            .expect("capability array")
            .iter()
            .any(|value| value.as_str()
                == Some(constitute_protocol::CAPABILITY_SURFACE_APP_DISTRIBUTION_PIN)));
    }
}
