use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
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
        .route("/apps", get(list_apps))
        .route("/lock/:mode", post(lock_handler))
        .route("/open-url", post(open_url_handler))
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

// ── Apps handler ────────────────────────────────────────────────

#[derive(Serialize)]
struct ProcessInfo {
    name: String,
    pid: u32,
    cpu_usage: f32,
    memory_mb: u64,
}

/// GET /apps — top user-facing processes sorted by memory usage
async fn list_apps(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let hostname = s.hostname.clone();

    let apps = tokio::task::spawn_blocking(move || {
        let mut sys = System::new_all();
        sys.refresh_all();
        // Second refresh for accurate CPU readings
        std::thread::sleep(std::time::Duration::from_millis(200));
        sys.refresh_all();

        // Windows system / background noise to hide
        const HIDDEN: &[&str] = &[
            "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "lsaiso.exe", "fontdrvhost.exe",
            "dwm.exe", "conhost.exe", "sihost.exe", "taskhostw.exe",
            "ctfmon.exe", "dllhost.exe", "wuauserv.exe", "spoolsv.exe",
            "audiodg.exe", "dasHost.exe", "WmiPrvSE.exe", "RuntimeBroker.exe",
            "SearchHost.exe", "SearchIndexer.exe", "StartMenuExperienceHost.exe",
            "ShellExperienceHost.exe", "TextInputHost.exe", "ShellHost.exe",
            "ApplicationFrameHost.exe", "backgroundTaskHost.exe",
            "SecurityHealthSystray.exe", "SecurityHealthService.exe",
            "MsMpEng.exe", "NisSrv.exe", "SecHealthUI.exe",
            "MicrosoftSecurityApp.exe",
            "OfficeClickToRun.exe", "OneDrive.Sync.Service.exe",
            "PhoneExperienceHost.exe", "WidgetBoard.exe",
            "LockApp.exe", "Copilot.exe", "EdgeGameAssist.exe",
            "System", "Secure System", "Registry", "Memory Compression",
            "Idle", "explorer.exe", "SystemSettings.exe",
            "CompPkgSrv.exe", "uhssvc.exe", "SgrmBroker.exe",
            "SearchProtocolHost.exe", "SearchFilterHost.exe",
            "OpenWith.exe",
        ];

        let hidden_lower: Vec<String> = HIDDEN.iter().map(|s| s.to_lowercase()).collect();

        let mut procs: Vec<ProcessInfo> = sys
            .processes()
            .values()
            .filter(|p| {
                let name = p.name().to_string_lossy().to_string();
                let mem = p.memory() / 1_048_576;
                mem > 5 && !hidden_lower.contains(&name.to_lowercase())
            })
            .map(|p| ProcessInfo {
                name: p.name().to_string_lossy().to_string(),
                pid: p.pid().as_u32(),
                cpu_usage: p.cpu_usage(),
                memory_mb: p.memory() / 1_048_576,
            })
            .collect();

        // Sort by memory descending, take top 30
        procs.sort_by(|a, b| b.memory_mb.cmp(&a.memory_mb));
        procs.truncate(30);
        procs
    })
    .await
    .unwrap_or_default();

    Json(serde_json::json!({
        "hostname": hostname,
        "applications": apps,
        "browser_tabs": [],
        "timestamp": chrono::Utc::now(),
    }))
}

// ── Helpers ─────────────────────────────────────────────────────

fn whoami() -> String {
    std::env::var("USERNAME") // Windows
        .or_else(|_| std::env::var("USER")) // Unix fallback
        .unwrap_or_else(|_| "unknown".into())
}

// ── Lock / open-url handlers ────────────────────────────────────

/// POST /lock/{mode}  where mode = "soft" | "hard"
async fn lock_handler(
    axum::extract::Path(mode): axum::extract::Path<String>,
) -> impl IntoResponse {
    match mode.as_str() {
        "soft" => {
            tracing::info!("🔒 Soft-lock: minimising all windows");
            let ok = tokio::task::spawn_blocking(soft_lock).await.unwrap_or(false);
            if ok {
                Json(serde_json::json!({ "status": "ok" }))
            } else {
                Json(serde_json::json!({ "status": "error", "error": "soft lock failed" }))
            }
        }
        "hard" => {
            tracing::info!("🔒 Hard-lock: locking workstation");
            let ok = tokio::task::spawn_blocking(hard_lock).await.unwrap_or(false);
            if ok {
                Json(serde_json::json!({ "status": "ok" }))
            } else {
                Json(serde_json::json!({ "status": "error", "error": "hard lock failed" }))
            }
        }
        _ => {
            Json(serde_json::json!({ "status": "error", "error": "invalid mode, use soft or hard" }))
        }
    }
}

#[derive(Deserialize)]
struct OpenUrlBody {
    url: String,
}

/// POST /open-url   body: { "url": "https://..." }
async fn open_url_handler(Json(body): Json<OpenUrlBody>) -> impl IntoResponse {
    let url = body.url.clone();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Json(serde_json::json!({ "status": "error", "error": "URL must start with http(s)://" }));
    }
    tracing::info!("🌐 Opening URL: {url}");
    let ok = tokio::task::spawn_blocking(move || open_url_in_browser(&url))
        .await
        .unwrap_or(false);
    if ok {
        Json(serde_json::json!({ "status": "ok" }))
    } else {
        Json(serde_json::json!({ "status": "error", "error": "failed to open URL" }))
    }
}

// ── Platform-specific implementations ───────────────────────────

/// Soft lock: minimize all windows (Win: Win+D, macOS: AppleScript, Linux: wmctrl)
fn soft_lock() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Use the Shell.Application COM object to toggle desktop (minimise all)
        std::process::Command::new("powershell")
            .args(["-WindowStyle", "Hidden", "-Command",
                   "(New-Object -ComObject Shell.Application).MinimizeAll()"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("osascript")
            .args(["-e", r#"tell application "System Events" to keystroke "m" using {command down, option down}"#])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("wmctrl")
            .args(["-k", "on"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Hard lock: lock the workstation
fn hard_lock() -> bool {
    #[cfg(target_os = "windows")]
    {
        // LockWorkStation via rundll32
        std::process::Command::new("rundll32.exe")
            .args(["user32.dll,LockWorkStation"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("pmset")
            .args(["displaysleepnow"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        // Try loginctl first (systemd), fallback to xdg-screensaver
        std::process::Command::new("loginctl")
            .args(["lock-session"])
            .status()
            .map(|s| s.success())
            .unwrap_or_else(|_| {
                std::process::Command::new("xdg-screensaver")
                    .args(["lock"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            })
    }
}

/// Open a URL in the OS default browser
fn open_url_in_browser(url: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}
