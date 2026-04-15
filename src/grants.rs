use super::*;

const GRANTS_FILE_NAME: &str = "managed-grants.json";
const CONTROL_LEASE_TTL_MS: u64 = 8_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct CameraResource {
    pub source_id: String,
    pub name: String,
    #[serde(default)]
    pub ptz_capable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct CameraGrantView {
    pub source_id: String,
    pub name: String,
    #[serde(default)]
    pub view_granted: bool,
    #[serde(default)]
    pub control_granted: bool,
    #[serde(default)]
    pub ptz_capable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct GrantScope {
    #[serde(default)]
    pub owner: bool,
    #[serde(default)]
    pub view_sources: Vec<String>,
    #[serde(default)]
    pub control_sources: Vec<String>,
    #[serde(default)]
    pub cameras: Vec<CameraGrantView>,
    #[serde(default)]
    pub grant_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct GatewayGrantRecord {
    pub grant_id: String,
    pub owner_identity_id: String,
    pub grantee_identity_id: String,
    pub gateway_pk: String,
    pub service_pk: String,
    pub service: String,
    #[serde(default)]
    pub view_sources: Vec<String>,
    #[serde(default)]
    pub control_sources: Vec<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub revoked_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct ControlLease {
    pub service_pk: String,
    pub source_id: String,
    pub holder_identity_id: String,
    pub holder_device_pk: String,
    #[serde(default)]
    pub owner: bool,
    #[serde(default)]
    pub acquired_at: u64,
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Debug, Default)]
pub(super) struct GrantState {
    pub grants: Vec<GatewayGrantRecord>,
    pub control_leases: HashMap<String, ControlLease>,
}

#[derive(Debug, Clone, Deserialize)]
struct GatewayGrantRequest {
    #[serde(rename = "requestId", default)]
    request_id: String,
    #[serde(rename = "toDevicePk", default)]
    to_device_pk: String,
    #[serde(rename = "identityId", default)]
    identity_id: String,
    #[serde(rename = "devicePk", default)]
    device_pk: String,
    #[serde(rename = "servicePk", default)]
    service_pk: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    action: String,
    #[serde(rename = "granteeIdentityId", default)]
    grantee_identity_id: String,
    #[serde(rename = "grantId", default)]
    grant_id: String,
    #[serde(rename = "viewSources", default)]
    view_sources: Vec<String>,
    #[serde(rename = "controlSources", default)]
    control_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct GatewayGrantStatusPayload {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "requestId")]
    request_id: String,
    status: String,
    #[serde(rename = "toDevicePk")]
    to_device_pk: String,
    #[serde(rename = "gatewayPk")]
    gateway_pk: String,
    #[serde(rename = "identityId")]
    identity_id: String,
    #[serde(rename = "devicePk")]
    device_pk: String,
    #[serde(rename = "servicePk")]
    service_pk: String,
    service: String,
    action: String,
    #[serde(rename = "grant", skip_serializing_if = "Option::is_none")]
    grant: Option<Value>,
    #[serde(rename = "grants", skip_serializing_if = "Option::is_none")]
    grants: Option<Value>,
    #[serde(rename = "sharedResources", skip_serializing_if = "Option::is_none")]
    shared_resources: Option<Value>,
    #[serde(rename = "availableCameras", skip_serializing_if = "Option::is_none")]
    available_cameras: Option<Value>,
    #[serde(rename = "controlLease", skip_serializing_if = "Option::is_none")]
    control_lease: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    ts: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ControlLeaseDecision {
    pub lease: ControlLease,
    pub preempted: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SharedResourceProjection {
    gateway_pk: String,
    service_pk: String,
    service: String,
    service_label: String,
    service_version: String,
    status: String,
    view_sources: Vec<String>,
    control_sources: Vec<String>,
    cameras: Vec<CameraGrantView>,
    camera_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantView {
    grant_id: String,
    grantee_identity_id: String,
    view_sources: Vec<String>,
    control_sources: Vec<String>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CameraListItem {
    source_id: String,
    name: String,
    ptz_capable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedGrantStore {
    #[serde(default)]
    grants: Vec<GatewayGrantRecord>,
}

fn grants_file_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join(GRANTS_FILE_NAME)
}

fn dedup_source_ids(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_string();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn active_grant(grant: &GatewayGrantRecord) -> bool {
    grant.revoked_at == 0
}

fn lease_key(service_pk: &str, source_id: &str) -> String {
    format!("{}:{}", service_pk.trim(), source_id.trim())
}

fn cleanup_control_leases(state: &mut GrantState) {
    let now_ms = util::now_unix_seconds() * 1000;
    state.control_leases.retain(|_, lease| lease.expires_at > now_ms);
}

fn persist_grants(data_dir: &str, state: &GrantState) -> Result<()> {
    let path = grants_file_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating grant directory {}", parent.display()))?;
    }
    let payload = PersistedGrantStore {
        grants: state.grants.clone(),
    };
    fs::write(&path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing grants file {}", path.display()))?;
    Ok(())
}

pub(super) fn load_grant_state(data_dir: &str) -> GrantState {
    let path = grants_file_path(data_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return GrantState::default(),
    };
    let parsed: PersistedGrantStore = serde_json::from_str(&raw).unwrap_or(PersistedGrantStore { grants: Vec::new() });
    GrantState {
        grants: parsed.grants,
        control_leases: HashMap::new(),
    }
}

fn normalize_gateway_grant_request(req: &mut GatewayGrantRequest) {
    req.request_id = trim_nonempty(&req.request_id);
    if req.request_id.is_empty() {
        req.request_id = make_install_request_id();
    }
    req.to_device_pk = trim_nonempty(&req.to_device_pk);
    req.identity_id = trim_nonempty(&req.identity_id);
    req.device_pk = trim_nonempty(&req.device_pk);
    req.service_pk = trim_nonempty(&req.service_pk);
    req.service = trim_nonempty(&req.service).to_ascii_lowercase();
    req.action = trim_nonempty(&req.action).to_ascii_lowercase();
    req.grantee_identity_id = trim_nonempty(&req.grantee_identity_id);
    req.grant_id = trim_nonempty(&req.grant_id);
    req.view_sources = dedup_source_ids(req.view_sources.drain(..));
    req.control_sources = dedup_source_ids(req.control_sources.drain(..));
}

async fn publish_gateway_grant_status(
    relay_pool: &relay::RelayPool,
    local_relay: &Option<local_relay::LocalRelayHandle>,
    pubkey: &str,
    sk_hex: &str,
    payload: &GatewayGrantStatusPayload,
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

pub(super) async fn requester_matches_identity(
    ctx: &InboundContext,
    requester_pk: &str,
    identity_id: &str,
) -> bool {
    let requester = requester_pk.trim();
    let identity = identity_id.trim();
    if requester.is_empty() || identity.is_empty() {
        return false;
    }

    let is_owner_identity = identity == ctx.gateway_identity_id.trim();
    if is_owner_identity
        && !ctx.authorized_control_device_pks.is_empty()
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

pub(super) async fn scope_for_identity(
    ctx: &InboundContext,
    identity_id: &str,
    service_pk: &str,
    service: &str,
    cameras: &[CameraResource],
) -> Result<GrantScope> {
    let identity = identity_id.trim();
    let gateway_identity = ctx.gateway_identity_id.trim();
    if identity.is_empty() {
        return Err(anyhow!("missing identity"));
    }

    let available_view = dedup_source_ids(cameras.iter().map(|camera| camera.source_id.clone()));
    let available_control = dedup_source_ids(
        cameras
            .iter()
            .filter(|camera| camera.ptz_capable)
            .map(|camera| camera.source_id.clone()),
    );

    if identity == gateway_identity {
        let cameras = cameras
            .iter()
            .map(|camera| CameraGrantView {
                source_id: camera.source_id.clone(),
                name: camera.name.clone(),
                view_granted: true,
                control_granted: available_control.contains(&camera.source_id),
                ptz_capable: camera.ptz_capable,
            })
            .collect::<Vec<_>>();
        return Ok(GrantScope {
            owner: true,
            view_sources: available_view,
            control_sources: available_control,
            cameras,
            grant_ids: Vec::new(),
        });
    }

    let service_slug = service.trim().to_ascii_lowercase();
    let mut view_sources = Vec::new();
    let mut control_sources = Vec::new();
    let mut grant_ids = Vec::new();
    {
        let mut state = ctx.grant_state.lock().await;
        cleanup_control_leases(&mut state);
        for grant in &state.grants {
            if !active_grant(grant) {
                continue;
            }
            if grant.gateway_pk.trim() != ctx.self_pk.trim() {
                continue;
            }
            if grant.service_pk.trim() != service_pk.trim() {
                continue;
            }
            if grant.service.trim().to_ascii_lowercase() != service_slug {
                continue;
            }
            if grant.grantee_identity_id.trim() != identity {
                continue;
            }
            grant_ids.push(grant.grant_id.clone());
            for source in &grant.view_sources {
                if available_view.contains(source) && !view_sources.contains(source) {
                    view_sources.push(source.clone());
                }
            }
            for source in &grant.control_sources {
                if available_control.contains(source) && !control_sources.contains(source) {
                    control_sources.push(source.clone());
                }
            }
        }
    }

    if view_sources.is_empty() {
        return Err(anyhow!("no active grant for requested service"));
    }

    control_sources.retain(|source| view_sources.contains(source));

    let cameras = cameras
        .iter()
        .filter(|camera| view_sources.contains(&camera.source_id))
        .map(|camera| CameraGrantView {
            source_id: camera.source_id.clone(),
            name: camera.name.clone(),
            view_granted: true,
            control_granted: control_sources.contains(&camera.source_id),
            ptz_capable: camera.ptz_capable,
        })
        .collect::<Vec<_>>();

    Ok(GrantScope {
        owner: false,
        view_sources,
        control_sources,
        cameras,
        grant_ids,
    })
}

pub(super) async fn resolve_scope_for_request(
    ctx: &InboundContext,
    requester_pk: &str,
    identity_id: &str,
    service_pk: &str,
    service: &str,
    capability: &str,
    cameras: &[CameraResource],
) -> Result<GrantScope> {
    if !matches!((service.trim(), capability.trim()), ("nvr", "nvr.view") | ("nvr", "nvr.manage") | ("nvr", "gateway.launch_managed_app")) {
        return Err(anyhow!("unsupported capability"));
    }
    if !requester_matches_identity(ctx, requester_pk, identity_id).await {
        return Err(anyhow!("requester is not authorized for this identity"));
    }
    scope_for_identity(ctx, identity_id, service_pk, service, cameras).await
}

pub(super) async fn acquire_control_lease(
    ctx: &InboundContext,
    scope: &GrantScope,
    identity_id: &str,
    device_pk: &str,
    service_pk: &str,
    source_id: &str,
) -> Result<ControlLeaseDecision> {
    let source = source_id.trim();
    if source.is_empty() {
        return Err(anyhow!("missing sourceId"));
    }
    if !scope.control_sources.iter().any(|entry| entry == source) {
        return Err(anyhow!("control is not granted for this camera"));
    }

    let now_ms = util::now_unix_seconds() * 1000;
    let expires_at = now_ms + CONTROL_LEASE_TTL_MS;
    let key = lease_key(service_pk, source);
    let mut grant_state = ctx.grant_state.lock().await;
    cleanup_control_leases(&mut grant_state);
    let mut preempted = false;

    if let Some(existing) = grant_state.control_leases.get(&key) {
        let same_holder = existing.holder_identity_id.trim() == identity_id.trim()
            && existing.holder_device_pk.trim() == device_pk.trim();
        if !same_holder {
            if scope.owner {
                preempted = true;
            } else if existing.owner {
                return Err(anyhow!("owner is currently controlling this camera"));
            } else {
                return Err(anyhow!("camera control is already held by another session"));
            }
        }
    }

    let lease = ControlLease {
        service_pk: service_pk.trim().to_string(),
        source_id: source.to_string(),
        holder_identity_id: identity_id.trim().to_string(),
        holder_device_pk: device_pk.trim().to_string(),
        owner: scope.owner,
        acquired_at: now_ms,
        expires_at,
    };
    grant_state.control_leases.insert(key, lease.clone());
    Ok(ControlLeaseDecision { lease, preempted })
}

pub(super) async fn release_control_leases_for_holder(
    ctx: &InboundContext,
    identity_id: &str,
    device_pk: &str,
    service_pk: &str,
) {
    let mut grant_state = ctx.grant_state.lock().await;
    cleanup_control_leases(&mut grant_state);
    grant_state.control_leases.retain(|_, lease| {
        !(lease.service_pk.trim() == service_pk.trim()
            && lease.holder_identity_id.trim() == identity_id.trim()
            && lease.holder_device_pk.trim() == device_pk.trim())
    });
}

fn grant_view(grant: &GatewayGrantRecord) -> Value {
    json!(GrantView {
        grant_id: grant.grant_id.clone(),
        grantee_identity_id: grant.grantee_identity_id.clone(),
        view_sources: grant.view_sources.clone(),
        control_sources: grant.control_sources.clone(),
        created_at: grant.created_at,
        updated_at: grant.updated_at,
    })
}

fn camera_list_items(cameras: &[CameraResource]) -> Value {
    Value::Array(
        cameras
            .iter()
            .map(|camera| {
                json!(CameraListItem {
                    source_id: camera.source_id.clone(),
                    name: camera.name.clone(),
                    ptz_capable: camera.ptz_capable,
                })
            })
            .collect(),
    )
}

pub(super) fn build_shared_resource_projection(
    hosted: &managed::HostedNvrService,
    scope: &GrantScope,
) -> Value {
    json!(SharedResourceProjection {
        gateway_pk: hosted.record.host_gateway_pk.clone(),
        service_pk: hosted.record.device_pk.clone(),
        service: hosted.record.service.clone(),
        service_label: hosted.record.device_label.clone(),
        service_version: hosted.record.service_version.clone(),
        status: hosted.record.status.clone(),
        view_sources: scope.view_sources.clone(),
        control_sources: scope.control_sources.clone(),
        cameras: scope.cameras.clone(),
        camera_count: scope.view_sources.len(),
    })
}

pub(super) async fn handle_gateway_grant_request(
    ctx: &InboundContext,
    nostr_ev: &nostr::NostrEvent,
    payload: &Value,
) {
    let mut req: GatewayGrantRequest = match serde_json::from_value(payload.clone()) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, "invalid gateway_grant_request payload");
            return;
        }
    };
    normalize_gateway_grant_request(&mut req);

    if req.to_device_pk != ctx.self_pk {
        return;
    }
    if req.service.is_empty() {
        req.service = "nvr".to_string();
    }
    if req.action.is_empty() {
        req.action = "list_shared".to_string();
    }

    let requester_pk = nostr_ev.pubkey.trim().to_string();
    if req.device_pk.is_empty() {
        req.device_pk = requester_pk.clone();
    }

    let publish_status = |status: &str,
                          grant: Option<Value>,
                          grants: Option<Value>,
                          shared_resources: Option<Value>,
                          available_cameras: Option<Value>,
                          reason: Option<String>,
                          detail: Option<String>| GatewayGrantStatusPayload {
        kind: "gateway_grant_status".to_string(),
        request_id: req.request_id.clone(),
        status: status.to_string(),
        to_device_pk: req.to_device_pk.clone(),
        gateway_pk: ctx.self_pk.clone(),
        identity_id: req.identity_id.clone(),
        device_pk: req.device_pk.clone(),
        service_pk: req.service_pk.clone(),
        service: req.service.clone(),
        action: req.action.clone(),
        grant,
        grants,
        shared_resources,
        available_cameras,
        control_lease: None,
        reason,
        detail,
        ts: util::now_unix_seconds() * 1000,
    };

    if requester_pk != req.device_pk {
        let status = publish_status("rejected", None, None, None, None, Some("requester_device_mismatch".to_string()), Some("requesting event pubkey does not match devicePk".to_string()));
        let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        return;
    }

    if !requester_matches_identity(ctx, &requester_pk, &req.identity_id).await {
        let status = publish_status("rejected", None, None, None, None, Some("unauthorized_requester".to_string()), Some("requester is not authorized for this identity".to_string()));
        let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        return;
    }

    let hosted = match managed::load_target_hosted_service(ctx, &req.service_pk, &req.service).await {
        Ok(service) => service,
        Err(err) => {
            if req.action == "list_shared" {
                let status = publish_status("complete", None, None, Some(json!([])), Some(json!([])), None, None);
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            let status = publish_status("failed", None, None, None, None, Some("service_unavailable".to_string()), Some(err.to_string()));
            let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
            return;
        }
    };
    let cameras = managed::camera_resources_from_hosted(&hosted);

    match req.action.as_str() {
        "list_shared" => {
            let shared_resources = match scope_for_identity(ctx, &req.identity_id, &hosted.record.device_pk, &hosted.record.service, &cameras).await {
                Ok(scope) if !scope.owner => json!([build_shared_resource_projection(&hosted, &scope)]),
                _ => json!([]),
            };
            let status = publish_status("complete", None, None, Some(shared_resources), Some(camera_list_items(&cameras)), None, None);
            let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        }
        "list_grants" => {
            if req.identity_id.trim() != ctx.gateway_identity_id.trim() {
                let status = publish_status("rejected", None, None, None, None, Some("owner_required".to_string()), Some("only the gateway owner can list grants".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            let grants_value = {
                let mut grant_state = ctx.grant_state.lock().await;
                cleanup_control_leases(&mut grant_state);
                Value::Array(
                    grant_state
                        .grants
                        .iter()
                        .filter(|grant| active_grant(grant))
                        .filter(|grant| grant.gateway_pk.trim() == ctx.self_pk.trim())
                        .filter(|grant| grant.service_pk.trim() == hosted.record.device_pk.trim())
                        .filter(|grant| grant.service.trim().eq_ignore_ascii_case(&hosted.record.service))
                        .map(grant_view)
                        .collect(),
                )
            };
            let status = publish_status("complete", None, Some(grants_value), None, Some(camera_list_items(&cameras)), None, None);
            let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        }
        "upsert" => {
            if req.identity_id.trim() != ctx.gateway_identity_id.trim() {
                let status = publish_status("rejected", None, None, None, None, Some("owner_required".to_string()), Some("only the gateway owner can modify grants".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            if req.grantee_identity_id.is_empty() {
                let status = publish_status("rejected", None, None, None, None, Some("missing_grantee".to_string()), Some("granteeIdentityId is required".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            if req.grantee_identity_id.trim() == ctx.gateway_identity_id.trim() {
                let status = publish_status("rejected", None, None, None, None, Some("invalid_grantee".to_string()), Some("owner does not need an explicit grant".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            let available_view = dedup_source_ids(cameras.iter().map(|camera| camera.source_id.clone()));
            let available_control = dedup_source_ids(cameras.iter().filter(|camera| camera.ptz_capable).map(|camera| camera.source_id.clone()));
            let mut view_sources = dedup_source_ids(req.view_sources.iter().filter(|source| available_view.contains(source)).cloned());
            let control_sources = dedup_source_ids(req.control_sources.iter().filter(|source| available_control.contains(source)).cloned());
            for source in &control_sources {
                if !view_sources.contains(source) {
                    view_sources.push(source.clone());
                }
            }
            if view_sources.is_empty() {
                let status = publish_status("rejected", None, None, None, Some(camera_list_items(&cameras)), Some("missing_view_sources".to_string()), Some("select at least one camera to grant live view".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            let now_ms = util::now_unix_seconds() * 1000;
            let grant = {
                let mut grant_state = ctx.grant_state.lock().await;
                cleanup_control_leases(&mut grant_state);
                let existing_idx = grant_state.grants.iter().position(|grant| {
                    active_grant(grant)
                        && grant.gateway_pk.trim() == ctx.self_pk.trim()
                        && grant.service_pk.trim() == hosted.record.device_pk.trim()
                        && grant.service.trim().eq_ignore_ascii_case(&hosted.record.service)
                        && grant.grantee_identity_id.trim() == req.grantee_identity_id.trim()
                });
                let grant = if let Some(index) = existing_idx {
                    let grant = &mut grant_state.grants[index];
                    grant.view_sources = view_sources.clone();
                    grant.control_sources = control_sources.clone();
                    grant.updated_at = now_ms;
                    grant.revoked_at = 0;
                    grant.clone()
                } else {
                    let grant = GatewayGrantRecord {
                        grant_id: if req.grant_id.is_empty() { format!("grant-{}", random_hex(8)) } else { req.grant_id.clone() },
                        owner_identity_id: ctx.gateway_identity_id.clone(),
                        grantee_identity_id: req.grantee_identity_id.clone(),
                        gateway_pk: ctx.self_pk.clone(),
                        service_pk: hosted.record.device_pk.clone(),
                        service: hosted.record.service.clone(),
                        view_sources: view_sources.clone(),
                        control_sources: control_sources.clone(),
                        created_at: now_ms,
                        updated_at: now_ms,
                        revoked_at: 0,
                    };
                    grant_state.grants.push(grant.clone());
                    grant
                };
                if let Err(err) = persist_grants(&ctx.data_dir, &grant_state) {
                    warn!(error = %err, "failed persisting gateway grants");
                }
                grant
            };
            let status = publish_status("complete", Some(grant_view(&grant)), None, None, Some(camera_list_items(&cameras)), None, None);
            let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        }
        "revoke" => {
            if req.identity_id.trim() != ctx.gateway_identity_id.trim() {
                let status = publish_status("rejected", None, None, None, None, Some("owner_required".to_string()), Some("only the gateway owner can revoke grants".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            }
            let revoked = {
                let mut grant_state = ctx.grant_state.lock().await;
                cleanup_control_leases(&mut grant_state);
                let now_ms = util::now_unix_seconds() * 1000;
                let mut out = None;
                for grant in &mut grant_state.grants {
                    let matches_service = grant.gateway_pk.trim() == ctx.self_pk.trim()
                        && grant.service_pk.trim() == hosted.record.device_pk.trim()
                        && grant.service.trim().eq_ignore_ascii_case(&hosted.record.service);
                    let matches_grant = (!req.grant_id.is_empty() && grant.grant_id.trim() == req.grant_id.trim())
                        || (!req.grantee_identity_id.is_empty() && grant.grantee_identity_id.trim() == req.grantee_identity_id.trim());
                    if active_grant(grant) && matches_service && matches_grant {
                        grant.revoked_at = now_ms;
                        grant.updated_at = now_ms;
                        out = Some(grant.clone());
                        break;
                    }
                }
                if out.is_some() {
                    if let Err(err) = persist_grants(&ctx.data_dir, &grant_state) {
                        warn!(error = %err, "failed persisting gateway grants");
                    }
                }
                out
            };
            let Some(revoked) = revoked else {
                let status = publish_status("rejected", None, None, None, Some(camera_list_items(&cameras)), Some("grant_not_found".to_string()), Some("matching active grant was not found".to_string()));
                let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
                return;
            };
            let status = publish_status("complete", Some(grant_view(&revoked)), None, None, Some(camera_list_items(&cameras)), None, None);
            let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        }
        _ => {
            let status = publish_status("rejected", None, None, None, None, Some("unsupported_action".to_string()), Some("unsupported gateway grant action".to_string()));
            let _ = publish_gateway_grant_status(&ctx.relay_pool, &ctx.local_relay, &ctx.self_pk, &ctx.self_sk, &status).await;
        }
    }
}
