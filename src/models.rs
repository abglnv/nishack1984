use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Violation record ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Machine hostname
    pub hostname: String,
    /// What was caught (process name or domain)
    pub target: String,
    /// "process" | "domain"
    pub kind: ViolationKind,
    /// Was the process successfully killed / DNS flushed?
    pub action_taken: bool,
    /// Username of the logged-in Windows user
    pub username: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    Process,
    Domain,
}

// ── System info snapshot ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub username: String,
    pub cpu_usage: f32,
    pub total_memory_mb: u64,
    pub used_memory_mb: u64,
    pub uptime_secs: u64,
    pub process_count: usize,
    pub timestamp: DateTime<Utc>,
}

// ── Heartbeat payload ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub version: String,
    pub timestamp: DateTime<Utc>,
}

// ── API responses ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub hostname: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct ViolationsResponse {
    pub total: usize,
    pub violations: Vec<Violation>,
}
