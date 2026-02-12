use serde::Deserialize;
use std::path::Path;

/// Root configuration loaded from `config.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub redis: RedisConfig,
    pub api: ApiConfig,
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub screenshots: ScreenshotConfig,
    #[serde(default)]
    pub streaming: StreamingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub key_prefix: String,
    /// Seconds between heartbeat pushes.
    pub heartbeat_interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorConfig {
    /// Seconds between process/DNS scans.
    pub scan_interval: u64,
    pub banned_processes: BanList,
    pub banned_domains: BanList,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScreenshotConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_quality")]
    pub quality: u8,
    #[serde(default = "default_max_dimension")]
    pub max_dimension: u32,
}

impl Default for ScreenshotConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval: default_interval(),
            quality: default_quality(),
            max_dimension: default_max_dimension(),
        }
    }
}

fn default_enabled() -> bool { true }
fn default_interval() -> u64 { 60 }
fn default_quality() -> u8 { 75 }
fn default_max_dimension() -> u32 { 1920 }

// ── Live screen streaming config (WebSocket to teacher) ─────────

#[derive(Debug, Clone, Deserialize)]
pub struct StreamingConfig {
    /// Enable live WebSocket screen streaming to the teacher server.
    #[serde(default = "streaming_default_enabled")]
    pub enabled: bool,
    /// WebSocket URL of the teacher server (e.g. ws://192.168.8.151:8080/ws/screen)
    #[serde(default = "streaming_default_url")]
    pub server_url: String,
    /// JPEG quality for streaming frames (1-100). Lower = less bandwidth.
    #[serde(default = "streaming_default_quality")]
    pub quality: u8,
    /// Max dimension (width/height) for streamed frames.
    #[serde(default = "streaming_default_max_dim")]
    pub max_dimension: u32,
    /// Milliseconds between frames (~1-2 FPS = 500-1000ms).
    #[serde(default = "streaming_default_interval_ms")]
    pub interval_ms: u64,
    /// Seconds to wait before reconnecting after a disconnect.
    #[serde(default = "streaming_default_reconnect_secs")]
    pub reconnect_secs: u64,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: streaming_default_enabled(),
            server_url: streaming_default_url(),
            quality: streaming_default_quality(),
            max_dimension: streaming_default_max_dim(),
            interval_ms: streaming_default_interval_ms(),
            reconnect_secs: streaming_default_reconnect_secs(),
        }
    }
}

fn streaming_default_enabled() -> bool { true }
fn streaming_default_url() -> String { "ws://192.168.8.151:8080/ws/screen".into() }
fn streaming_default_quality() -> u8 { 60 }
fn streaming_default_max_dim() -> u32 { 1280 }
fn streaming_default_interval_ms() -> u64 { 700 }
fn streaming_default_reconnect_secs() -> u64 { 4 }

#[derive(Debug, Clone, Deserialize)]
pub struct BanList {
    pub names: Vec<String>,
}

impl AppConfig {
    /// Load and parse the config file. Falls back to `./config.toml` next to
    /// the executable if no explicit path is given.
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let path = match path {
            Some(p) => std::path::PathBuf::from(p),
            None => {
                // Look next to the executable first, then CWD
                let exe_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(Path::to_path_buf));

                if let Some(dir) = exe_dir {
                    let candidate = dir.join("config.toml");
                    if candidate.exists() {
                        candidate
                    } else {
                        std::path::PathBuf::from("config.toml")
                    }
                } else {
                    std::path::PathBuf::from("config.toml")
                }
            }
        };

        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read config at {}: {e}", path.display()))?;

        let config: AppConfig = toml::from_str(&raw)?;
        Ok(config)
    }
}
