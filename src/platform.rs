use std::path::PathBuf;

#[cfg(feature = "platform-linux")]
pub fn init() {
    tracing::info!("platform init: linux (ubuntu core)");
}

#[cfg(feature = "platform-windows")]
pub fn init() {
    tracing::info!("platform init: windows");
}

#[cfg(all(not(feature = "platform-linux"), not(feature = "platform-windows")))]
pub fn init() {
    tracing::warn!("platform init: no platform feature set");
}

#[cfg(feature = "platform-linux")]
pub fn default_data_dir() -> String {
    "/var/snap/constitute-gateway/common/data".to_string()
}

#[cfg(feature = "platform-windows")]
pub fn default_data_dir() -> String {
    std::env::var("ProgramData")
        .map(|root| format!("{}\\Constitute\\Gateway\\data", root))
        .unwrap_or_else(|_| ".\\data".to_string())
}

#[cfg(all(not(feature = "platform-linux"), not(feature = "platform-windows")))]
pub fn default_data_dir() -> String {
    "./data".to_string()
}

#[cfg(feature = "platform-linux")]
pub fn default_config_path() -> PathBuf {
    "/var/snap/constitute-gateway/common/config.json".into()
}

#[cfg(feature = "platform-windows")]
pub fn default_config_path() -> PathBuf {
    std::env::var("ProgramData")
        .map(|root| PathBuf::from(format!("{}\\Constitute\\Gateway\\config.json", root)))
        .unwrap_or_else(|_| PathBuf::from(".\\config.json"))
}

#[cfg(all(not(feature = "platform-linux"), not(feature = "platform-windows")))]
pub fn default_config_path() -> PathBuf {
    "./config.json".into()
}
