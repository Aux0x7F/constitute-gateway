use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn normalize_log_level(level: &str) -> Option<&'static str> {
    match level.to_lowercase().as_str() {
        "trace" => Some("trace"),
        "debug" => Some("debug"),
        "info" => Some("info"),
        "warn" | "warning" => Some("warn"),
        "error" => Some("error"),
        _ => None,
    }
}

pub fn now_unix_seconds() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn derive_zone_key(label: &str) -> String {
    let mut seed = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut seed);
    let seed_b64 = URL_SAFE_NO_PAD.encode(seed);
    let raw = format!("{}|{}", label.trim(), seed_b64);
    let digest = Sha256::digest(raw.as_bytes());
    let b64 = URL_SAFE_NO_PAD.encode(digest);
    b64.chars().take(20).collect()
}

pub fn is_valid_zone_key(key: &str) -> bool {
    let k = key.trim();
    if k.len() != 20 {
        return false;
    }
    k.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::{derive_zone_key, is_valid_zone_key, normalize_log_level, now_unix_seconds};

    #[test]
    fn normalize_log_level_accepts_known_levels() {
        assert_eq!(normalize_log_level("trace"), Some("trace"));
        assert_eq!(normalize_log_level("DEBUG"), Some("debug"));
        assert_eq!(normalize_log_level("info"), Some("info"));
        assert_eq!(normalize_log_level("warning"), Some("warn"));
        assert_eq!(normalize_log_level("error"), Some("error"));
    }

    #[test]
    fn normalize_log_level_rejects_unknown() {
        assert_eq!(normalize_log_level("nope"), None);
    }

    #[test]
    fn now_unix_seconds_is_nonzero() {
        assert!(now_unix_seconds() > 0);
    }

    #[test]
    fn derive_zone_key_has_expected_length() {
        let k = derive_zone_key("Zone");
        assert_eq!(k.len(), 20);
    }

    #[test]
    fn zone_key_validation_accepts_urlsafe_base64() {
        let k = derive_zone_key("Zone");
        assert!(is_valid_zone_key(&k));
        assert!(!is_valid_zone_key("short"));
        assert!(!is_valid_zone_key("invalid!invalid!invalid!"));
    }
}
