use chrono::Utc;
use redis::AsyncCommands;
use tracing::{error, info, warn};

use crate::config::RedisConfig;
use crate::models::{Heartbeat, Violation, ViolationKind};

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
    pub async fn push_heartbeat(&self, hostname: &str, ip: &str, port: u16, username: &str) {
        let Some(mut con) = self.conn().await else {
            return;
        };

        // Gather live system metrics
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();
        // small sleep so CPU reading isn't 0 on first sample
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        sys.refresh_cpu_all();
        sys.refresh_memory();

        let cpu_usage = sys.global_cpu_usage();
        let total_mem = sys.total_memory() as f64;
        let used_mem = sys.used_memory() as f64;
        let ram_usage = if total_mem > 0.0 {
            (used_mem / total_mem * 100.0) as f32
        } else {
            0.0
        };

        let os_name = sysinfo::System::name().unwrap_or_default();
        let os_ver = sysinfo::System::os_version().unwrap_or_default();
        let os = format!("{os_name} {os_ver}");

        let uptime_secs = sysinfo::System::uptime();

        let hb = Heartbeat {
            hostname: hostname.to_owned(),
            ip: ip.to_owned(),
            port,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            os,
            username: username.to_owned(),
            cpu_usage,
            ram_usage,
            uptime_secs,
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
    ///
    /// We serialise into the **teacher-backend** schema so the dashboard can
    /// deserialise it directly:  { hostname, rule, detail, severity, timestamp }
    pub async fn record_violation(&self, v: &Violation) {
        let Some(mut con) = self.conn().await else {
            return;
        };

        // Map student model → teacher-compatible JSON
        let rule = match v.kind {
            ViolationKind::Process => "banned_process",
            ViolationKind::Domain  => "banned_domain",
        };
        let severity = match v.kind {
            ViolationKind::Process => "high",
            ViolationKind::Domain  => "medium",
        };
        let detail = format!(
            "{}: {} ({})",
            match v.kind {
                ViolationKind::Process => "Запрещённый процесс",
                ViolationKind::Domain  => "Запрещённый домен",
            },
            v.target,
            if v.action_taken { "заблокировано" } else { "не удалось заблокировать" }
        );

        let payload = serde_json::json!({
            "hostname": v.hostname,
            "rule": rule,
            "detail": detail,
            "severity": severity,
            "timestamp": v.timestamp.to_rfc3339(),
        });

        let key = self.key(&["violations", &v.hostname]);
        let result: redis::RedisResult<()> = con.lpush(&key, payload.to_string()).await;
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

    /// Fetch the centrally-managed ban config from Redis.
    /// Returns (banned_processes, banned_domains) or None if unavailable.
    pub async fn fetch_ban_config(&self) -> Option<(Vec<String>, Vec<String>)> {
        let mut con = self.conn().await?;
        let key = self.key(&["ban_config"]);
        let val: Option<String> = con.get(&key).await.ok()?;
        let json: serde_json::Value = serde_json::from_str(&val?).ok()?;
        let procs = json["banned_processes"]
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let domains = json["banned_domains"]
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        Some((procs, domains))
    }

    /// Discover the teacher server address from Redis.
    /// Returns `Some("IP:PORT")` if the teacher has published its address.
    pub async fn discover_teacher_address(&self) -> Option<String> {
        let mut con = self.conn().await?;
        // Teacher publishes its IP to {prefix}:server:ip (no port).
        // Default teacher port is 8080.
        let key = self.key(&["server", "ip"]);
        let ip: Option<String> = con.get(&key).await.ok()?;
        ip.map(|addr| format!("{addr}:8080"))
    }

    /// Forward a violation to the teacher backend via REST API.
    /// This makes the violation appear on the teacher dashboard in real-time.
    pub async fn push_violation_to_teacher(&self, v: &Violation) {
        // Resolve teacher address
        let address = match self.discover_teacher_address().await {
            Some(addr) => addr,
            None => {
                warn!("Cannot forward violation to teacher — address not discovered");
                return;
            }
        };

        let url = format!("http://{address}/api/agent/violation");

        // Map student violation model → teacher expected format
        let payload = serde_json::json!({
            "hostname": v.hostname,
            "rule": match v.kind {
                ViolationKind::Process => "banned_process",
                ViolationKind::Domain => "banned_domain",
            },
            "detail": format!("{}: {} ({})",
                match v.kind {
                    ViolationKind::Process => "Запрещённый процесс",
                    ViolationKind::Domain => "Запрещённый домен",
                },
                v.target,
                if v.action_taken { "заблокировано" } else { "не удалось заблокировать" }
            ),
            "severity": match v.kind {
                ViolationKind::Process => "high",
                ViolationKind::Domain => "medium",
            },
            "timestamp": v.timestamp.to_rfc3339(),
        });

        // Fire-and-forget HTTP POST
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to create HTTP client: {e}");
                return;
            }
        };

        match client.post(&url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("✅ Violation forwarded to teacher: {}", v.target);
            }
            Ok(resp) => {
                warn!("Teacher API returned {}: {}", resp.status(), v.target);
            }
            Err(e) => {
                warn!("Failed to forward violation to teacher: {e}");
            }
        }
    }
}
