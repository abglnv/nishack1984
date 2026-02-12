use serde::Deserialize;
use std::path::Path;

/// Root configuration loaded from `config.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub redis: RedisConfig,
    pub api: ApiConfig,
    pub monitor: MonitorConfig,
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
