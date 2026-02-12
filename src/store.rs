use chrono::Utc;
use redis::AsyncCommands;
use tracing::{error, info, warn};

use crate::config::RedisConfig;
use crate::models::{Heartbeat, Violation};

/// Thin async wrapper around a Redis connection.
#[derive(Clone)]
pub struct Store {
    client: redis::Client,
    prefix: String,
}

impl Store {
    /// Create a new store (does **not** open a connection yet).
    pub fn new(cfg: &RedisConfig) -> anyhow::Result<Self> {
        let client = redis::Client::open(cfg.url.as_str())?;
        Ok(Self {
            client,
            prefix: cfg.key_prefix.clone(),
        })
    }

    // ── helpers ─────────────────────────────────────────────────

    fn key(&self, parts: &[&str]) -> String {
        let mut k = self.prefix.clone();
        for p in parts {
            k.push(':');
            k.push_str(p);
        }
        k
    }

    async fn conn(&self) -> Option<redis::aio::MultiplexedConnection> {
        match self.client.get_multiplexed_async_connection().await {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("Redis connection failed (will retry): {e}");
                None
            }
        }
    }

    // ── public API ──────────────────────────────────────────────

    /// Push a heartbeat. Key: `{prefix}:heartbeat:{hostname}`
    /// The key auto-expires so stale agents disappear from the dashboard.
    pub async fn push_heartbeat(&self, hostname: &str, ip: &str, port: u16) {
        let Some(mut con) = self.conn().await else {
            return;
        };

        let hb = Heartbeat {
            hostname: hostname.to_owned(),
            ip: ip.to_owned(),
            port,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            timestamp: Utc::now(),
        };

        let key = self.key(&["heartbeat", hostname]);
        let payload = match serde_json::to_string(&hb) {
            Ok(p) => p,
            Err(e) => {
                error!("Heartbeat serialization error: {e}");
                return;
            }
        };

        // SET with 90-second TTL (3× heartbeat interval)
        let result: redis::RedisResult<()> = con.set_ex(&key, &payload, 90).await;
        if let Err(e) = result {
            warn!("Failed to push heartbeat: {e}");
        } else {
            info!("Heartbeat pushed → {key}");
        }
    }

    /// Record a violation. Stored in a Redis list so we keep history.
    /// Key: `{prefix}:violations:{hostname}`
    pub async fn record_violation(&self, v: &Violation) {
        let Some(mut con) = self.conn().await else {
            return;
        };

        let key = self.key(&["violations", &v.hostname]);
        let payload = match serde_json::to_string(v) {
            Ok(p) => p,
            Err(e) => {
                error!("Violation serialization error: {e}");
                return;
            }
        };

        let result: redis::RedisResult<()> = con.lpush(&key, &payload).await;
        if let Err(e) = result {
            warn!("Failed to record violation: {e}");
        }

        // Also increment a quick counter for the dashboard
        let counter_key = self.key(&["violation_count", &v.hostname]);
        let _: redis::RedisResult<()> = con.incr(&counter_key, 1i64).await;
    }

    /// Fetch the last `n` violations for a host.
    pub async fn recent_violations(
        &self,
        hostname: &str,
        count: isize,
    ) -> Vec<Violation> {
        let Some(mut con) = self.conn().await else {
            return Vec::new();
        };

        let key = self.key(&["violations", hostname]);
        let raw: Vec<String> = con.lrange(&key, 0, count - 1).await.unwrap_or_default();

        raw.iter()
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect()
    }

    /// Register the machine's IP in a Redis set for easy discovery.
    /// Key: `{prefix}:agents`
    pub async fn register_agent(&self, hostname: &str, ip: &str, port: u16) {
        let Some(mut con) = self.conn().await else {
            return;
        };

        let value = format!("{hostname}|{ip}|{port}");
        let key = self.key(&["agents"]);
        let _: redis::RedisResult<()> = con.sadd(&key, &value).await;
    }

    /// Store a screenshot (base64-encoded) for a host.
    /// Key: `{prefix}:screenshot:{hostname}` with metadata
    /// Also pushes to a list for history: `{prefix}:screenshot_history:{hostname}`
    pub async fn push_screenshot(&self, hostname: &str, screenshot_base64: &str) {
        let Some(mut con) = self.conn().await else {
            return;
        };

        let timestamp = Utc::now();
        let metadata = serde_json::json!({
            "hostname": hostname,
            "timestamp": timestamp,
            "data": screenshot_base64,
            "size": screenshot_base64.len(),
        });

        let payload = match serde_json::to_string(&metadata) {
            Ok(p) => p,
            Err(e) => {
                error!("Screenshot serialization error: {e}");
                return;
            }
        };

        // Store latest screenshot with TTL
        let latest_key = self.key(&["screenshot", hostname]);
        let result: redis::RedisResult<()> = con.set_ex(&latest_key, &payload, 120).await;
        if let Err(e) = result {
            warn!("Failed to push latest screenshot: {e}");
        } else {
            info!("Screenshot pushed → {latest_key}");
        }

        // Also store in history (keep last 10)
        let history_key = self.key(&["screenshot_history", hostname]);
        let _: redis::RedisResult<()> = con.lpush(&history_key, &payload).await;
        let _: redis::RedisResult<()> = con.ltrim(&history_key, 0, 9).await;
    }

    /// Fetch the latest screenshot for a host.
    pub async fn latest_screenshot(&self, hostname: &str) -> Option<String> {
        let Some(mut con) = self.conn().await else {
            return None;
        };

        let key = self.key(&["screenshot", hostname]);
        con.get(&key).await.ok()
    }
}
