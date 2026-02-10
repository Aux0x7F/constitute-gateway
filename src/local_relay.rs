use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::{Duration, Instant};
use tokio_rustls::rustls::{pki_types::{CertificateDer, PrivateKeyDer}, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

use crate::relay::RelayPool;
use crate::nostr;

const CACHE_MAX: usize = 512;
const DEDUPE_MAX: usize = 4096;

pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug)]
pub struct ValidationConfig {
    pub replay_window: Duration,
    pub replay_skew: Duration,
}

#[derive(Clone)]
pub struct LocalRelayHandle {
    sender: broadcast::Sender<Value>,
    cache: Arc<Mutex<EventCache>>,
    dedupe: Arc<Mutex<Deduper>>,
    client_count: Arc<AtomicUsize>,
    validation: ValidationConfig,
}

impl LocalRelayHandle {
    pub async fn publish_event(&self, ev: Value) {
        let _ = publish_event(ev, &self.sender, &self.cache, &self.dedupe, &self.validation).await;
    }

    pub fn client_count(&self) -> usize {
        self.client_count.load(Ordering::Relaxed)
    }
}

pub async fn start_relays(
    ws_bind: Option<String>,
    wss_bind: Option<String>,
    tls: Option<TlsConfig>,
    upstream: RelayPool,
    validation: ValidationConfig,
    inbound_tx: Option<mpsc::UnboundedSender<Value>>,
) -> Result<Option<LocalRelayHandle>> {
    let (sender, _rx) = broadcast::channel(1024);
    let cache = Arc::new(Mutex::new(EventCache::new(CACHE_MAX)));
    let dedupe = Arc::new(Mutex::new(Deduper::new(validation.replay_window, DEDUPE_MAX)));
    let client_count = Arc::new(AtomicUsize::new(0));

    let mut started = false;

    if let Some(bind) = ws_bind {
        let listener = TcpListener::bind(&bind).await?;
        spawn_ws_listener(
            listener,
            bind.clone(),
            sender.clone(),
            cache.clone(),
            dedupe.clone(),
            upstream.clone(),
            client_count.clone(),
            validation.clone(),
            inbound_tx.clone(),
        );
        started = true;
    }

    if let Some(bind) = wss_bind {
        if let Some(tls_cfg) = tls.as_ref() {
            let acceptor = load_tls_acceptor(&tls_cfg.cert_path, &tls_cfg.key_path)?;
            let listener = TcpListener::bind(&bind).await?;
            spawn_wss_listener(
                listener,
                bind.clone(),
                acceptor,
                sender.clone(),
                cache.clone(),
                dedupe.clone(),
                upstream.clone(),
                client_count.clone(),
                validation.clone(),
                inbound_tx.clone(),
            );
            started = true;
        } else {
            tracing::warn!(bind = %bind, "wss bind requested but tls config missing");
        }
    }

    if !started {
        return Ok(None);
    }

    Ok(Some(LocalRelayHandle { sender, cache, dedupe, client_count, validation }))
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("invalid tls cert"))?;

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("invalid tls key"))?
        .into_iter()
        .map(PrivateKeyDer::from)
        .collect();

    if keys.is_empty() {
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        keys = rsa_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow!("invalid tls key"))?
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();
    }

    let key = keys.into_iter().next().ok_or_else(|| anyhow!("no tls key found"))?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls config error: {}", e))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

fn spawn_ws_listener(
    listener: TcpListener,
    bind: String,
    sender: broadcast::Sender<Value>,
    cache: Arc<Mutex<EventCache>>,
    dedupe: Arc<Mutex<Deduper>>,
    upstream: RelayPool,
    client_count: Arc<AtomicUsize>,
    validation: ValidationConfig,
    inbound_tx: Option<mpsc::UnboundedSender<Value>>,
) {
    tracing::info!(bind = %bind, "gateway relay ready (ws)");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let tx = sender.clone();
                    let upstream = upstream.clone();
                    let cache = cache.clone();
                    let dedupe = dedupe.clone();
                    let client_count = client_count.clone();
                    let validation = validation.clone();
                    let inbound_tx = inbound_tx.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_client(stream, addr, tx, upstream, cache, dedupe, client_count, validation, inbound_tx).await {
                            tracing::warn!(client = %addr, error = %err, "relay client error");
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!(error = %err, "relay accept failed");
                }
            }
        }
    });
}

fn spawn_wss_listener(
    listener: TcpListener,
    bind: String,
    acceptor: TlsAcceptor,
    sender: broadcast::Sender<Value>,
    cache: Arc<Mutex<EventCache>>,
    dedupe: Arc<Mutex<Deduper>>,
    upstream: RelayPool,
    client_count: Arc<AtomicUsize>,
    validation: ValidationConfig,
    inbound_tx: Option<mpsc::UnboundedSender<Value>>,
) {
    tracing::info!(bind = %bind, "gateway relay ready (wss)");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let acceptor = acceptor.clone();
                    let tx = sender.clone();
                    let upstream = upstream.clone();
                    let cache = cache.clone();
                    let dedupe = dedupe.clone();
                    let client_count = client_count.clone();
                    let validation = validation.clone();
                    let inbound_tx = inbound_tx.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(err) = handle_client(tls_stream, addr, tx, upstream, cache, dedupe, client_count, validation, inbound_tx).await {
                                    tracing::warn!(client = %addr, error = %err, "relay client error");
                                }
                            }
                            Err(err) => {
                                tracing::warn!(client = %addr, error = %err, "tls accept failed");
                            }
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!(error = %err, "relay accept failed");
                }
            }
        }
    });
}

#[derive(Clone, Debug)]
struct Subscription {
    id: String,
    filters: Vec<Filter>,
}

#[derive(Clone, Debug, Default)]
struct Filter {
    kinds: Option<Vec<u64>>,
    authors: Option<Vec<String>>,
    since: Option<u64>,
    until: Option<u64>,
    tags: HashMap<String, Vec<String>>,
}

impl Filter {
    fn from_value(val: &Value) -> Option<Self> {
        let obj = val.as_object()?;
        let kinds = obj.get("kinds").and_then(|v| v.as_array()).map(|arr| {
            arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>()
        });
        let authors = obj.get("authors").and_then(|v| v.as_array()).map(|arr| {
            arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<_>>()
        });
        let since = obj.get("since").and_then(|v| v.as_u64());
        let until = obj.get("until").and_then(|v| v.as_u64());
        let mut tags: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in obj {
            if !k.starts_with('#') {
                continue;
            }
            let key = k.trim_start_matches('#').to_string();
            let vals = v.as_array().map(|arr| {
                arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<_>>()
            }).unwrap_or_default();
            tags.insert(key, vals);
        }
        Some(Self { kinds, authors, since, until, tags })
    }

    fn matches(&self, ev: &Value) -> bool {
        let kind = ev.get("kind").and_then(|v| v.as_u64()).unwrap_or(0);
        if let Some(kinds) = &self.kinds {
            if !kinds.contains(&kind) {
                return false;
            }
        }
        let pubkey = ev.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(authors) = &self.authors {
            if !authors.iter().any(|a| a == pubkey) {
                return false;
            }
        }
        let created_at = ev.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        if let Some(since) = self.since {
            if created_at < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if created_at > until {
                return false;
            }
        }
        for (tag, values) in &self.tags {
            if !event_has_tag_any(ev, tag, values) {
                return false;
            }
        }
        true
    }
}

struct EventCache {
    entries: VecDeque<Value>,
    max: usize,
}

impl EventCache {
    fn new(max: usize) -> Self {
        Self { entries: VecDeque::new(), max }
    }

    fn push(&mut self, ev: Value) {
        self.entries.push_back(ev);
        while self.entries.len() > self.max {
            self.entries.pop_front();
        }
    }

    fn snapshot(&self) -> Vec<Value> {
        self.entries.iter().cloned().collect()
    }
}

struct Deduper {
    seen: HashMap<String, Instant>,
    order: VecDeque<String>,
    ttl: Duration,
    max: usize,
}

impl Deduper {
    fn new(ttl: Duration, max: usize) -> Self {
        Self { seen: HashMap::new(), order: VecDeque::new(), ttl, max }
    }

    fn seen_or_insert(&mut self, id: &str) -> bool {
        if let Some(ts) = self.seen.get(id) {
            if ts.elapsed() <= self.ttl {
                return true;
            }
        }
        let now = Instant::now();
        self.seen.insert(id.to_string(), now);
        self.order.push_back(id.to_string());
        while let Some(front) = self.order.front() {
            let expired = self.seen.get(front).map(|t| t.elapsed() > self.ttl).unwrap_or(true);
            let over = self.seen.len() > self.max;
            if !expired && !over {
                break;
            }
            let old = self.order.pop_front().unwrap();
            if let Some(ts) = self.seen.get(&old) {
                if !over && ts.elapsed() <= self.ttl {
                    continue;
                }
            }
            self.seen.remove(&old);
        }
        false
    }
}

struct ClientGuard {
    counter: Arc<AtomicUsize>,
}

impl ClientGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self { counter }
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}


fn validate_event(ev: &Value, cfg: &ValidationConfig) -> bool {
    let event: nostr::NostrEvent = match serde_json::from_value(ev.clone()) {
        Ok(ev) => ev,
        Err(_) => return false,
    };
    if !created_at_ok(event.created_at, cfg) {
        return false;
    }
    match nostr::verify_event(&event) {
        Ok(true) => {}
        _ => return false,
    }
    payload_time_ok(&event.content, cfg)
}

fn created_at_ok(created_at: u64, cfg: &ValidationConfig) -> bool {
    if created_at == 0 {
        return false;
    }
    let now = crate::util::now_unix_seconds();
    let window = cfg.replay_window.as_secs();
    let skew = cfg.replay_skew.as_secs();
    if created_at > now + skew {
        return false;
    }
    if created_at + window < now {
        return false;
    }
    true
}

fn payload_time_ok(content: &str, cfg: &ValidationConfig) -> bool {
    let payload: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let ts = payload.get("ts").and_then(|v| v.as_i64());
    if ts.is_none() {
        return true;
    }
    let ts_ms = ts.unwrap().max(0) as i64;
    let now_ms = (crate::util::now_unix_seconds() as i64) * 1000;
    let window_ms = (cfg.replay_window.as_secs() as i64) * 1000;
    let skew_ms = (cfg.replay_skew.as_secs() as i64) * 1000;
    if ts_ms > now_ms + skew_ms {
        return false;
    }
    if ts_ms < now_ms - window_ms {
        return false;
    }
    if let Some(ttl) = payload.get("ttl").and_then(|v| v.as_i64()) {
        if ttl > 0 {
            let ttl_ms = ttl * 1000;
            if now_ms > ts_ms + ttl_ms {
                return false;
            }
        }
    }
    true
}

async fn publish_event(
    ev: Value,
    sender: &broadcast::Sender<Value>,
    cache: &Arc<Mutex<EventCache>>,
    dedupe: &Arc<Mutex<Deduper>>,
    validation: &ValidationConfig,
) -> bool {
    if !validate_event(&ev, validation) {
        return false;
    }
    if let Some(id) = event_id(&ev) {
        let mut guard = dedupe.lock().await;
        if guard.seen_or_insert(&id) {
            return false;
        }
    }
    {
        let mut guard = cache.lock().await;
        guard.push(ev.clone());
    }
    let _ = sender.send(ev);
    true
}

async fn handle_client<S>(
    stream: S,
    addr: SocketAddr,
    sender: broadcast::Sender<Value>,
    upstream: RelayPool,
    cache: Arc<Mutex<EventCache>>,
    dedupe: Arc<Mutex<Deduper>>,
    client_count: Arc<AtomicUsize>,
    validation: ValidationConfig,
    inbound_tx: Option<mpsc::UnboundedSender<Value>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws = accept_async(stream).await?;
    let _guard = ClientGuard::new(client_count);
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut subs: Vec<Subscription> = Vec::new();
    let mut rx = sender.subscribe();

    tracing::info!(client = %addr, "relay client connected");

    loop {
        tokio::select! {
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        if handle_req(&txt, &mut subs, &cache, &mut ws_tx).await? {
                            continue;
                        }
                        if handle_close(&txt, &mut subs).await {
                            continue;
                        }
                        if let Some(ev) = parse_event_frame(&txt) {
                            if !is_allowed_event(&ev) {
                                continue;
                            }
                            if publish_event(ev.clone(), &sender, &cache, &dedupe, &validation).await {
                                if let Some(tx) = inbound_tx.as_ref() {
                                    let _ = tx.send(ev.clone());
                                }
                                let frame = json!(["EVENT", ev]).to_string();
                                upstream.broadcast(&frame);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        tracing::warn!(client = %addr, error = %err, "relay client ws error");
                        break;
                    }
                    None => break,
                }
            }
            evt = rx.recv() => {
                match evt {
                    Ok(ev) => {
                        if subs.is_empty() {
                            continue;
                        }
                        for sub in &subs {
                            if sub.filters.iter().any(|f| f.matches(&ev)) {
                                let frame = json!(["EVENT", sub.id, ev]).to_string();
                                if ws_tx.send(Message::Text(frame)).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        }
    }

    tracing::info!(client = %addr, "relay client disconnected");
    Ok(())
}

async fn handle_req<S>(
    raw: &str,
    subs: &mut Vec<Subscription>,
    cache: &Arc<Mutex<EventCache>>,
    ws_tx: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<S>, Message>,
) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return Ok(false),
    };
    if arr.len() < 3 {
        return Ok(false);
    }
    if arr[0].as_str() != Some("REQ") {
        return Ok(false);
    }
    let sub_id = match arr[1].as_str() {
        Some(s) => s.to_string(),
        None => return Ok(true),
    };
    let mut filters: Vec<Filter> = Vec::new();
    for f in arr.iter().skip(2) {
        if let Some(filter) = Filter::from_value(f) {
            filters.push(filter);
        }
    }
    if filters.is_empty() {
        filters.push(Filter::default());
    }
    subs.retain(|s| s.id != sub_id);
    subs.push(Subscription { id: sub_id.clone(), filters: filters.clone() });

    let snapshot = {
        let guard = cache.lock().await;
        guard.snapshot()
    };
    for ev in snapshot {
        if filters.iter().any(|f| f.matches(&ev)) {
            let frame = json!(["EVENT", sub_id, ev]).to_string();
            ws_tx.send(Message::Text(frame)).await?;
        }
    }
    let eose = json!(["EOSE", sub_id]).to_string();
    ws_tx.send(Message::Text(eose)).await?;
    Ok(true)
}

async fn handle_close(raw: &str, subs: &mut Vec<Subscription>) -> bool {
    let v: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return false,
    };
    if arr.len() < 2 {
        return false;
    }
    if arr[0].as_str() != Some("CLOSE") {
        return false;
    }
    if let Some(id) = arr[1].as_str() {
        subs.retain(|s| s.id != id);
    }
    true
}

fn parse_event_frame(raw: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let arr = v.as_array()?;
    if arr.is_empty() {
        return None;
    }
    if arr[0].as_str()? != "EVENT" {
        return None;
    }
    let ev_val = if arr.len() >= 3 { &arr[2] } else { &arr[1] };
    Some(ev_val.clone())
}

fn event_id(ev: &Value) -> Option<String> {
    ev.get("id")?.as_str().map(|s| s.to_string())
}

fn event_has_tag_any(ev: &Value, key: &str, values: &[String]) -> bool {
    let tags = ev.get("tags").and_then(|v| v.as_array());
    let tags = match tags {
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
        if k != key {
            continue;
        }
        let v = arr[1].as_str().unwrap_or("");
        if values.iter().any(|x| x == v) {
            return true;
        }
    }
    false
}

fn is_allowed_event(ev: &Value) -> bool {
    event_has_tag_any(ev, "t", &vec!["constitute".to_string()])
        || event_has_tag_any(ev, "t", &vec!["swarm_discovery".to_string()])
}

#[cfg(test)]
mod tests {
    use super::{Deduper, EventCache, Filter, ValidationConfig, event_has_tag_any, spawn_ws_listener, validate_event};
    use crate::nostr;
    use crate::relay::RelayPool;
    use futures_util::SinkExt;
    use serde_json::{json, Value};
    use std::sync::{Arc, atomic::AtomicUsize};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::{broadcast, Mutex};
    use tokio_tungstenite::tungstenite::Message;

    #[test]
    fn filter_matches_kind_and_tag() {
        let filter = Filter::from_value(&json!({
            "kinds": [1],
            "#t": ["constitute"],
        })).expect("filter");
        let ev = json!({
            "kind": 1,
            "pubkey": "pk",
            "created_at": 100,
            "tags": [["t", "constitute"]],
        });
        assert!(filter.matches(&ev));
    }

    #[test]
    fn filter_rejects_missing_tag() {
        let filter = Filter::from_value(&json!({
            "#t": ["constitute"],
        })).expect("filter");
        let ev = json!({
            "kind": 1,
            "pubkey": "pk",
            "created_at": 100,
            "tags": [["t", "other"]],
        });
        assert!(!filter.matches(&ev));
    }

    #[test]
    fn event_has_tag_any_accepts_match() {
        let ev = json!({
            "tags": [["t", "constitute"], ["z", "zone"]]
        });
        assert!(event_has_tag_any(&ev, "t", &["constitute".to_string()]));
    }


fn build_signed_event(content: &str, created_at: u64) -> nostr::NostrEvent {
    let (pk, sk) = nostr::generate_keypair();
    let tags = vec![vec!["t".to_string(), "constitute".to_string()]];
    let unsigned = nostr::build_unsigned_event(&pk, 1, tags, content.to_string(), created_at);
    nostr::sign_event(&unsigned, &sk).expect("sign event")
}

#[test]
fn reject_invalid_signature() {
    let cfg = ValidationConfig {
        replay_window: Duration::from_secs(600),
        replay_skew: Duration::from_secs(120),
    };
    let now = crate::util::now_unix_seconds();
    let content = json!({"type":"swarm_signal","ts": now * 1000, "ttl": 120}).to_string();
    let mut ev = build_signed_event(&content, now);
    ev.sig = "00".to_string();
    let val = serde_json::to_value(ev).expect("event to value");
    assert!(!validate_event(&val, &cfg));
}

#[test]
fn reject_expired_ttl() {
    let cfg = ValidationConfig {
        replay_window: Duration::from_secs(600),
        replay_skew: Duration::from_secs(120),
    };
    let now = crate::util::now_unix_seconds();
    let old_ts = (now.saturating_sub(700) as i64) * 1000;
    let content = json!({"type":"swarm_signal","ts": old_ts, "ttl": 120}).to_string();
    let ev = build_signed_event(&content, now);
    let val = serde_json::to_value(ev).expect("event to value");
    assert!(!validate_event(&val, &cfg));
}

#[test]
fn accept_valid_signed_event() {
    let cfg = ValidationConfig {
        replay_window: Duration::from_secs(600),
        replay_skew: Duration::from_secs(120),
    };
    let now = crate::util::now_unix_seconds();
    let content = json!({"type":"swarm_signal","ts": now * 1000, "ttl": 120}).to_string();
    let ev = build_signed_event(&content, now);
    let val = serde_json::to_value(ev).expect("event to value");
    assert!(validate_event(&val, &cfg));
}

#[tokio::test]
async fn relay_forwards_valid_event_between_two_local_clients() {
    use futures_util::StreamExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let bind = addr.to_string();

    let (sender, _rx) = broadcast::channel(32);
    let cache = Arc::new(Mutex::new(EventCache::new(64)));
    let dedupe = Arc::new(Mutex::new(Deduper::new(Duration::from_secs(600), 128)));
    let client_count = Arc::new(AtomicUsize::new(0));
    let validation = ValidationConfig {
        replay_window: Duration::from_secs(600),
        replay_skew: Duration::from_secs(120),
    };

    spawn_ws_listener(
        listener,
        bind.clone(),
        sender.clone(),
        cache.clone(),
        dedupe.clone(),
        RelayPool::empty(),
        client_count.clone(),
        validation.clone(),
        None,
    );

    let url = format!("ws://{}", bind);
    let (ws1, _) = tokio_tungstenite::connect_async(&url).await.expect("ws1");
    let (mut w1_tx, _w1_rx) = ws1.split();

    let (ws2, _) = tokio_tungstenite::connect_async(&url).await.expect("ws2");
    let (mut w2_tx, mut w2_rx) = ws2.split();

    let req = json!(["REQ", "sub", {}]).to_string();
    w2_tx.send(Message::Text(req)).await.expect("req");

    let now = crate::util::now_unix_seconds();
    let content = json!({"type":"swarm_signal","ts": now * 1000, "ttl": 120}).to_string();
    let ev = build_signed_event(&content, now);
    let ev_id = ev.id.clone();
    let frame = json!(["EVENT", ev]).to_string();
    w1_tx.send(Message::Text(frame)).await.expect("send event");

    let mut received = false;
    let deadline = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            msg = w2_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        let v: Value = match serde_json::from_str(&txt) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let arr = match v.as_array() {
                            Some(a) => a,
                            None => continue,
                        };
                        if arr.get(0).and_then(|v| v.as_str()) != Some("EVENT") {
                            continue;
                        }
                        let ev_val = if arr.len() >= 3 { &arr[2] } else { &arr[1] };
                        let id = ev_val.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        if id == ev_id {
                            received = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(received, "expected forwarded event");
}
}








