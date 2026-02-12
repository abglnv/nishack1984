mod api;
mod config;
mod models;
mod monitor;
mod store;
mod screenshot;
mod ws_stream;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::api::{build_router, AppState};
use crate::config::AppConfig;
use crate::monitor::Monitor;
use crate::store::Store;

const BANNER: &str = r#"
  _   _ _     _   _            _
 | \ | (_)___| | | | __ _  ___| | __
 |  \| | / __| |_| |/ _` |/ __| |/ /
 | |\  | \__ \  _  | (_| | (__|   <
 |_| \_|_|___/_| |_|\__,_|\___|_|\_\
  School PC Monitoring Agent
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ─────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nishack=info".into()),
        )
        .compact()
        .init();

    println!("{BANNER}");

    // ── Config ──────────────────────────────────────────────────
    let cfg = AppConfig::load(None)?;
    info!("Config loaded — scan every {}s, API on :{}", cfg.monitor.scan_interval, cfg.api.port);

    // ── Identity ────────────────────────────────────────────────
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown-pc".into());

    let ip = local_ip_address::local_ip()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "127.0.0.1".into());

    let username = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into());

    info!("Host: {hostname} | IP: {ip} | User: {username}");

    // ── Redis store ─────────────────────────────────────────────
    let store = Store::new(&cfg.redis)?;
    info!("Redis client ready ({})", cfg.redis.url);

    // ── Shared state for the API ────────────────────────────────
    let state = AppState {
        store: store.clone(),
        config: cfg.clone(),
        hostname: hostname.clone(),
        ip: ip.clone(),
        start_time: std::time::Instant::now(),
    };

    // ── Spawn: HTTP API ─────────────────────────────────────────
    let api_port = cfg.api.port;
    let router = build_router(state);
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{api_port}");
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind API port");
        info!("API listening on http://{addr}");
        axum::serve(listener, router).await.expect("API server crashed");
    });

    // ── Spawn: Heartbeat loop ───────────────────────────────────
    {
        let store = store.clone();
        let hostname = hostname.clone();
        let ip = ip.clone();
        let port = cfg.api.port;
        let interval = Duration::from_secs(cfg.redis.heartbeat_interval);

        tokio::spawn(async move {
            loop {
                store.push_heartbeat(&hostname, &ip, port).await;
                store.register_agent(&hostname, &ip, port).await;
                tokio::time::sleep(interval).await;
            }
        });
    }

    // ── Spawn: Screenshot capture loop ──────────────────────────
    if cfg.screenshots.enabled {
        let store = store.clone();
        let hostname = hostname.clone();
        let quality = cfg.screenshots.quality;
        let max_dimension = cfg.screenshots.max_dimension;
        let interval = Duration::from_secs(cfg.screenshots.interval);

        info!("Screenshot capture enabled — every {}s", cfg.screenshots.interval);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                
                // Capture screenshot in blocking task
                let screenshot_result = tokio::task::spawn_blocking(move || {
                    crate::screenshot::try_capture_screenshot(quality, max_dimension)
                })
                .await;

                match screenshot_result {
                    Ok(Some(data)) => {
                        store.push_screenshot(&hostname, &data).await;
                    }
                    Ok(None) => {
                        // Error already logged in try_capture_screenshot
                    }
                    Err(e) => {
                        error!("Screenshot task panicked: {e}");
                    }
                }
            }
        });
    } else {
        info!("Screenshot capture disabled in config");
    }

    // ── Spawn: Live screen streaming (WebSocket to teacher) ─────
    if cfg.streaming.enabled {
        let streaming_cfg = cfg.streaming.clone();
        let streaming_hostname = hostname.clone();

        info!(
            "Live streaming enabled — server: {}, interval: {}ms",
            streaming_cfg.server_url, streaming_cfg.interval_ms
        );

        tokio::spawn(async move {
            ws_stream::run_streaming_loop(streaming_cfg, streaming_hostname).await;
        });
    } else {
        info!("Live screen streaming disabled in config");
    }

    // ── Main loop: Process & domain monitoring ──────────────────
    let scan_interval = Duration::from_secs(cfg.monitor.scan_interval);

    info!("Monitor started — scanning every {}s", cfg.monitor.scan_interval);
    let monitor = Arc::new(Mutex::new(
        Monitor::new(&cfg.monitor, hostname.clone(), username),
    ));

    loop {
        // Run the blocking scan on a dedicated thread so we don't starve
        // the async runtime.
        let mon = Arc::clone(&monitor);
        let violations = tokio::task::spawn_blocking(move || {
            let mut guard = mon.lock().expect("Monitor mutex poisoned");
            guard.full_scan()
        })
        .await;

        match violations {
            Ok(viols) => {
                if !viols.is_empty() {
                    info!("Detected {} violation(s) this cycle", viols.len());
                    for v in &viols {
                        store.record_violation(v).await;
                    }
                }
            }
            Err(e) => {
                error!("Monitor task panicked: {e}");
            }
        }

        tokio::time::sleep(scan_interval).await;
    }
}
