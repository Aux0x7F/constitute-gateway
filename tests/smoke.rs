use serde_json::Value;
use std::time::Duration;

#[test]
fn discovery_envelope_shape() {
    let record = constitute_gateway::discovery::SwarmDeviceRecord::new(
        "pk-test",
        "",
        "",
        "gateway",
        vec!["wss://relay.example".to_string()],
    );
    let (_tx, rx) = tokio::sync::watch::channel("".to_string());
    let (_metrics_tx, metrics_rx) = tokio::sync::watch::channel(constitute_gateway::discovery::GatewayMetrics::default());
    let client = constitute_gateway::discovery::DiscoveryClient::new(
        constitute_gateway::relay::RelayPool::empty(),
        record,
        "pubkey".to_string(),
        "11".repeat(32),
        Duration::from_secs(30),
        vec!["zonekey".to_string()],
        rx,
        metrics_rx,
    );
    let json = client.test_envelope_json();
    let v: Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(v[0], "EVENT");
    let ev = &v[1];
    assert_eq!(ev["kind"], constitute_gateway::discovery::default_record_kind());
    assert_eq!(ev["pubkey"], "pubkey");
    assert!(ev["created_at"].is_number());

    let tags = ev["tags"].as_array().expect("tags array");
    let has_record_tag = tags.iter().any(|t| t.get(0) == Some(&Value::String("t".to_string())) && t.get(1) == Some(&Value::String("swarm_discovery".to_string())));
    let has_type = tags.iter().any(|t| t.get(0) == Some(&Value::String("type".to_string())) && t.get(1) == Some(&Value::String("device".to_string())));
    assert!(has_record_tag);
    assert!(has_type);

    let content = ev["content"].as_str().expect("content");
    let payload: Value = serde_json::from_str(content).expect("payload json");
    assert_eq!(payload["devicePk"], "pk-test");
}

#[test]
fn zone_presence_envelope_shape() {
    let record = constitute_gateway::discovery::SwarmDeviceRecord::new(
        "pk-test",
        "",
        "",
        "gateway",
        vec!["wss://relay.example".to_string()],
    );
    let (_tx, rx) = tokio::sync::watch::channel("".to_string());
    let (_metrics_tx, metrics_rx) = tokio::sync::watch::channel(constitute_gateway::discovery::GatewayMetrics::default());
    let client = constitute_gateway::discovery::DiscoveryClient::new(
        constitute_gateway::relay::RelayPool::empty(),
        record,
        "pubkey".to_string(),
        "11".repeat(32),
        Duration::from_secs(30),
        vec!["zonekey".to_string()],
        rx,
        metrics_rx,
    );
    let json = client.test_zone_presence_json("zonekey");
    let v: Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(v[0], "EVENT");
    let ev = &v[1];
    assert_eq!(ev["kind"], 1);
    let tags = ev["tags"].as_array().expect("tags array");
    let has_t = tags.iter().any(|t| t.get(0) == Some(&Value::String("t".to_string())) && t.get(1) == Some(&Value::String("constitute".to_string())));
    let has_z = tags.iter().any(|t| t.get(0) == Some(&Value::String("z".to_string())) && t.get(1) == Some(&Value::String("zonekey".to_string())));
    assert!(has_t);
    assert!(has_z);
    let content = ev["content"].as_str().expect("content");
    let payload: Value = serde_json::from_str(content).expect("payload json");
    assert_eq!(payload["type"], "zone_presence");
    assert_eq!(payload["zone"], "zonekey");
    assert_eq!(payload["devicePk"], "pubkey");
    assert!(payload.get("metrics").is_some());
    assert!(payload["metrics"]["clients"].is_number());
}

#[tokio::test]
async fn udp_listener_binds_and_receives() {
    let bind = "127.0.0.1:0";
    let socket = tokio::net::UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (len, _from) = socket.recv_from(&mut buf).await.unwrap();
        tx.send(len).await.unwrap();
    });

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"ping";
    sender.send_to(payload, addr).await.unwrap();

    let len = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, payload.len());
}

#[test]
fn zone_key_generation_uses_expected_length() {
    let k = constitute_gateway::util::derive_zone_key("Zone");
    assert_eq!(k.len(), 20);
}

#[tokio::test]
async fn udp_handshake_confirms_peer() {
    let cfg_a = constitute_gateway::transport::UdpConfig {
        node_id: "node-a".to_string(),
        device_pk: "pk-a".to_string(),
        zones: vec!["zone".to_string()],
        peers: vec!["127.0.0.1:45101".to_string()],
        handshake_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(10),
        max_packet_bytes: 2048,
        rate_limit_per_sec: 0,
        udp_sync_interval_secs: 0,
        stun_servers: vec![],
        stun_interval: Duration::from_secs(0),
        swarm_endpoint_tx: None,
        inbound_tx: None,
    };
    let cfg_b = constitute_gateway::transport::UdpConfig {
        node_id: "node-b".to_string(),
        device_pk: "pk-b".to_string(),
        zones: vec!["zone".to_string()],
        peers: vec!["127.0.0.1:45100".to_string()],
        handshake_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(10),
        max_packet_bytes: 2048,
        rate_limit_per_sec: 0,
        udp_sync_interval_secs: 0,
        stun_servers: vec![],
        stun_interval: Duration::from_secs(0),
        swarm_endpoint_tx: None,
        inbound_tx: None,
    };

    let handle_a = constitute_gateway::transport::start_udp_with_handle("127.0.0.1:45100", cfg_a)
        .await
        .expect("start udp a");
    let handle_b = constitute_gateway::transport::start_udp_with_handle("127.0.0.1:45101", cfg_b)
        .await
        .expect("start udp b");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let count_a = handle_a.confirmed_count().await;
    let count_b = handle_b.confirmed_count().await;

    handle_a.stop();
    handle_b.stop();

    assert!(count_a >= 1, "expected peer confirmed on A");
    assert!(count_b >= 1, "expected peer confirmed on B");
}




#[tokio::test]
async fn udp_record_gossip_zone_scoped() {
    let (pk_a, sk_a) = constitute_gateway::nostr::generate_keypair();
    let (pk_b, _sk_b) = constitute_gateway::nostr::generate_keypair();

    let (tx_a, _rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();

    let cfg_a = constitute_gateway::transport::UdpConfig {
        node_id: "node-a".to_string(),
        device_pk: pk_a.clone(),
        zones: vec!["zone-a".to_string()],
        peers: vec!["127.0.0.1:45201".to_string()],
        handshake_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(10),
        max_packet_bytes: 2048,
        rate_limit_per_sec: 0,
        udp_sync_interval_secs: 0,
        stun_servers: vec![],
        stun_interval: Duration::from_secs(0),
        swarm_endpoint_tx: None,
        inbound_tx: Some(tx_a),
    };

    let cfg_b = constitute_gateway::transport::UdpConfig {
        node_id: "node-b".to_string(),
        device_pk: pk_b.clone(),
        zones: vec!["zone-a".to_string()],
        peers: vec!["127.0.0.1:45200".to_string()],
        handshake_interval: Duration::from_secs(1),
        peer_timeout: Duration::from_secs(10),
        max_packet_bytes: 2048,
        rate_limit_per_sec: 0,
        udp_sync_interval_secs: 0,
        stun_servers: vec![],
        stun_interval: Duration::from_secs(0),
        swarm_endpoint_tx: None,
        inbound_tx: Some(tx_b),
    };

    let handle_a = constitute_gateway::transport::start_udp_with_handle("127.0.0.1:45200", cfg_a)
        .await
        .expect("start udp a");
    let _handle_b = constitute_gateway::transport::start_udp_with_handle("127.0.0.1:45201", cfg_b)
        .await
        .expect("start udp b");

    tokio::time::sleep(Duration::from_secs(1)).await;

    let tags = vec![vec!["t".to_string(), "swarm_discovery".to_string()], vec!["type".to_string(), "device".to_string()]];
    let payload = serde_json::json!({
        "devicePk": pk_a,
        "identityId": "",
        "deviceLabel": "",
        "updatedAt": 1,
        "expiresAt": 999999999999u64,
    });
    let unsigned = constitute_gateway::nostr::build_unsigned_event(&pk_a, 30078, tags, payload.to_string(), 1);
    let ev = constitute_gateway::nostr::sign_event(&unsigned, &sk_a).expect("sign");

    handle_a.broadcast_record("zone-a", "device", ev);

    let msg = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();

    match msg {
        constitute_gateway::transport::UdpInbound::Record { zone, record_type, .. } => {
            assert_eq!(zone, "zone-a");
            assert_eq!(record_type, "device");
        }
        _ => panic!("unexpected udp inbound"),
    }

    // ensure zone mismatch is ignored
    handle_a.broadcast_record("zone-b", "device", constitute_gateway::nostr::sign_event(&unsigned, &sk_a).expect("sign"));
    let msg = tokio::time::timeout(Duration::from_millis(500), rx_b.recv()).await;
    assert!(msg.is_err(), "expected no message for wrong zone");
}
