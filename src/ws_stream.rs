// ─────────────────────────────────────────────────────────────────
//  ws_stream.rs — Live screen streaming over WebSocket
//
//  Connects to the teacher server's /ws/screen endpoint,
//  sends a JSON handshake, then streams JPEG frames.
//  Automatically reconnects on disconnect.
// ─────────────────────────────────────────────────────────────────

use std::io::Cursor;
use std::time::Duration;

use futures_util::SinkExt;
use image::codecs::jpeg::JpegEncoder;
use image::DynamicImage;
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

use crate::config::StreamingConfig;

/// Capture the primary screen using xcap and return a DynamicImage.
fn capture_screen() -> anyhow::Result<DynamicImage> {
    let monitors = xcap::Monitor::all()?;
    let monitor = monitors
        .into_iter()
        .find(|m| m.is_primary())
        .or_else(|| xcap::Monitor::all().ok().and_then(|m| m.into_iter().next()))
        .ok_or_else(|| anyhow::anyhow!("No monitors found"))?;

    let raw = monitor.capture_image()?;
    Ok(DynamicImage::ImageRgba8(raw))
}

/// Compress a DynamicImage to JPEG bytes in memory, optionally resizing.
fn compress_to_jpeg(img: &DynamicImage, quality: u8, max_dim: u32) -> anyhow::Result<Vec<u8>> {
    let img = if img.width() > max_dim || img.height() > max_dim {
        let ratio = max_dim as f32 / img.width().max(img.height()) as f32;
        let new_w = (img.width() as f32 * ratio) as u32;
        let new_h = (img.height() as f32 * ratio) as u32;
        img.resize(new_w, new_h, image::imageops::FilterType::Triangle)
    } else {
        img.clone()
    };

    let rgb = img.to_rgb8();
    let mut buf = Cursor::new(Vec::new());
    let encoder = JpegEncoder::new_with_quality(&mut buf, quality);
    rgb.write_with_encoder(encoder)?;
    Ok(buf.into_inner())
}

/// SHA-256 hash to detect unchanged frames.
fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Spawn the screen-streaming loop as a background task.
/// This function runs forever — it reconnects automatically on failure.
pub async fn run_streaming_loop(cfg: StreamingConfig, hostname: String) {
    info!(
        "🎬 Screen streaming enabled — server: {}, interval: {}ms, quality: {}",
        cfg.server_url, cfg.interval_ms, cfg.quality
    );

    loop {
        info!("Connecting to teacher server for screen streaming...");

        match connect_and_stream(&cfg, &hostname).await {
            Ok(()) => {
                warn!("Screen stream connection closed gracefully. Reconnecting in {}s...", cfg.reconnect_secs);
            }
            Err(e) => {
                error!("Screen stream error: {e}. Reconnecting in {}s...", cfg.reconnect_secs);
            }
        }

        sleep(Duration::from_secs(cfg.reconnect_secs)).await;
    }
}

/// Establish a WebSocket connection, send handshake, then stream frames.
async fn connect_and_stream(cfg: &StreamingConfig, hostname: &str) -> anyhow::Result<()> {
    let (ws_stream, _response) = connect_async(&cfg.server_url).await?;
    info!("✅ WebSocket connected to {}", cfg.server_url);

    let (mut write, _read) = ws_stream.split();

    // ── Step 1: JSON handshake ──────────────────────────────
    let handshake = serde_json::json!({
        "role": "student",
        "hostname": hostname,
    });
    write
        .send(Message::Text(handshake.to_string().into()))
        .await?;
    info!("Handshake sent: {handshake}");

    // ── Step 2: Stream JPEG frames ──────────────────────────
    let mut last_hash = String::new();
    let frame_interval = Duration::from_millis(cfg.interval_ms);
    let quality = cfg.quality;
    let max_dim = cfg.max_dimension;

    loop {
        sleep(frame_interval).await;

        // Capture screen on a blocking thread
        let screenshot = tokio::task::spawn_blocking(move || capture_screen()).await?;

        let img = match screenshot {
            Ok(img) => img,
            Err(e) => {
                warn!("Screen capture failed: {e}");
                continue;
            }
        };

        // Compress to JPEG
        let jpeg_bytes = match compress_to_jpeg(&img, quality, max_dim) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("JPEG compression failed: {e}");
                continue;
            }
        };

        // Skip if frame is identical to previous (save bandwidth)
        let hash = sha256_hash(&jpeg_bytes);
        if hash == last_hash {
            continue;
        }
        last_hash = hash;

        // Send binary frame
        let size_kb = jpeg_bytes.len() as f64 / 1024.0;
        if let Err(e) = write.send(Message::Binary(jpeg_bytes.into())).await {
            error!("Failed to send frame ({size_kb:.1} KB): {e}");
            return Err(e.into()); // Triggers reconnection
        }

        info!("📸 Frame sent: {size_kb:.1} KB");
    }
}
