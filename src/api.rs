use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use sysinfo::System;
use tower_http::cors::CorsLayer;

use crate::config::AppConfig;
use crate::models::{HealthResponse, SystemSnapshot, ViolationsResponse};
use crate::store::Store;

// ── Shared state ────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: AppConfig,
    pub hostname: String,
    pub ip: String,
    pub start_time: std::time::Instant,
}

// ── Router ──────────────────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(system_info))
        .route("/violations", get(violations))
        .route("/config", get(show_config))
        .route("/screenshot", get(get_screenshot))
        .layer(CorsLayer::permissive())
        .with_state(Arc::new(state))
}

// ── Handlers ────────────────────────────────────────────────────

async fn health(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        hostname: s.hostname.clone(),
        uptime_secs: s.start_time.elapsed().as_secs(),
    })
}

async fn system_info(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Build a quick snapshot — runs in a blocking task because sysinfo
    // does synchronous work.
    let hostname = s.hostname.clone();
    let ip = s.ip.clone();

    let snap = tokio::task::spawn_blocking(move || {
        let mut sys = System::new_all();
        sys.refresh_all();

        SystemSnapshot {
            hostname,
            ip,
            os: System::long_os_version().unwrap_or_default(),
            username: whoami(),
            cpu_usage: sys.global_cpu_usage(),
            total_memory_mb: sys.total_memory() / 1_048_576,
            used_memory_mb: sys.used_memory() / 1_048_576,
            uptime_secs: System::uptime(),
            process_count: sys.processes().len(),
            timestamp: chrono::Utc::now(),
        }
    })
    .await
    .unwrap();

    Json(snap)
}

#[derive(Deserialize)]
struct ViolationQuery {
    #[serde(default = "default_count")]
    count: isize,
}

fn default_count() -> isize {
    50
}

async fn violations(
    State(s): State<Arc<AppState>>,
    Query(q): Query<ViolationQuery>,
) -> impl IntoResponse {
    let list = s.store.recent_violations(&s.hostname, q.count).await;
    Json(ViolationsResponse {
        total: list.len(),
        violations: list,
    })
}

async fn show_config(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    // Return the ban lists only — not secrets
    let cfg = &s.config.monitor;
    Json(serde_json::json!({
        "scan_interval": cfg.scan_interval,
        "banned_processes": cfg.banned_processes.names,
        "banned_domains": cfg.banned_domains.names,
    }))
}

async fn get_screenshot(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    match s.store.latest_screenshot(&s.hostname).await {
        Some(data) => Json(serde_json::json!({
            "success": true,
            "screenshot": data,
        })),
        None => Json(serde_json::json!({
            "success": false,
            "error": "No screenshot available",
        })),
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn whoami() -> String {
    std::env::var("USERNAME") // Windows
        .or_else(|_| std::env::var("USER")) // Unix fallback
        .unwrap_or_else(|_| "unknown".into())
}
