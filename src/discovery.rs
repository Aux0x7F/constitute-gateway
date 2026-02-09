use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    Relay,
    Gateway,
    Browser,
    Native,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NodeType::Relay => "relay",
            NodeType::Gateway => "gateway",
            NodeType::Browser => "browser",
            NodeType::Native => "native",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiscoveryRecord {
    pub node_id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub ts: u64,
}

impl DiscoveryRecord {
    pub fn new(node_id: &str, node_type: NodeType) -> Self {
        Self {
            node_id: node_id.to_string(),
            node_type,
            ts: now_ms(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
